import atexit
import threading
import time

from pick import pick
from rich.console import Console
from rich.live import Live
from rich.panel import Panel

from wifi_cut import camera_scan
from wifi_cut.session import SessionManager
from wifi_cut.ui_helpers import (
    make_device_table, make_status_panel, format_device_choice,
    make_camera_table, make_camera_summary_panel,
)

console = Console()

MENU_CHOICES = [
    "Scan Network          掃描網路",
    "View Devices          查看裝置",
    "Camera Detection      攝影機偵測",
    "Block Devices         封鎖裝置",
    "Unblock Devices       解除封鎖",
    "Throttle Devices      限速裝置",
    "Unthrottle Devices    解除限速",
    "Bandwidth Test        頻寬測試",
    "Pulse Block           脈衝封鎖",
    "Status Dashboard      狀態面板",
    "Quit                  離開",
]


def _pick_multi(title: str, options: list[str]) -> list[int]:
    """多選選單，回傳選中的索引列表。空選按 Enter 回傳空列表。"""
    if not options:
        return []
    selected = pick(
        options,
        title + "\n(↑↓ 移動, 空格 選擇, Enter 確認)",
        multiselect=True,
        min_selection_count=0,
    )
    return [idx for _, idx in selected]


def _pick_single(title: str, options: list[str], default: int = 0) -> int:
    """單選選單，回傳選中的索引。"""
    _, idx = pick(options, title, default_index=default)
    return idx


def _input_text(prompt: str, default: str = "") -> str:
    """簡單文字輸入。"""
    if default:
        raw = input(f"{prompt} [{default}]: ").strip()
        return raw or default
    return input(f"{prompt}: ").strip()


def _input_confirm(prompt: str, default: bool = True) -> bool:
    """簡單 Y/N 確認。"""
    suffix = "(Y/n)" if default else "(y/N)"
    raw = input(f"{prompt} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def _wait_for_enter(stop_event: threading.Event) -> None:
    """背景 thread：等待 Enter 鍵，設定 stop_event。"""
    try:
        input()
    except EOFError:
        pass
    stop_event.set()


def run_tui(timeout: int = 3, interval: float = 1.5) -> None:
    session = SessionManager()

    console.print("[bold cyan]wifi-cut[/bold cyan] Interactive Mode\n")

    try:
        session.initialize(interval=interval)
    except (RuntimeError, SystemExit) as e:
        console.print(f"[red]初始化失敗: {e}[/red]")
        return

    assert session.gateway is not None
    console.print(f"[dim]Gateway:[/dim] {session.gateway.ip} ({session.gateway.mac})")
    console.print(f"[dim]Network:[/dim] {session.cidr}")
    console.print(f"[dim]Local IP:[/dim] {session.local_ip}\n")

    def cleanup(*_args):
        console.print("\n[yellow]正在清理...[/yellow]")
        session.cleanup()
        console.print("[green]已還原所有設定。[/green]")

    atexit.register(cleanup)

    try:
        _main_loop(session, timeout)
    except KeyboardInterrupt:
        pass
    finally:
        atexit.unregister(cleanup)
        cleanup()


def _main_loop(session: SessionManager, timeout: int) -> None:
    handlers = [
        lambda: _handle_scan(session, timeout),
        lambda: _handle_view(session),
        lambda: _handle_camera_scan(session, timeout),
        lambda: _handle_cut(session, timeout),
        lambda: _handle_uncut(session),
        lambda: _handle_throttle(session, timeout),
        lambda: _handle_unthrottle(session),
        lambda: _handle_bw_test(session, timeout),
        lambda: _handle_pulse_block(session, timeout),
        lambda: _handle_status(session),
        None,  # Quit
    ]

    while True:
        idx = _pick_single("wifi-cut", MENU_CHOICES)
        if handlers[idx] is None:
            return
        handlers[idx]()
        console.print()


def _handle_scan(session: SessionManager, timeout: int) -> None:
    assert session.gateway is not None
    console.print(f"[dim]掃描 {session.cidr} ...[/dim]")
    devices = session.scan(timeout=timeout)
    table = make_device_table(
        devices, session.gateway.ip, session.local_ip,
        session.blocked_ips, session.throttled_ips,
    )
    console.print(table)
    console.print(f"找到 {len(devices)} 個裝置")
    input("\n按 Enter 返回主選單...")


def _handle_view(session: SessionManager) -> None:
    assert session.gateway is not None
    if not session.devices:
        console.print("[yellow]尚未掃描，請先掃描網路。[/yellow]")
        return
    table = make_device_table(
        session.devices, session.gateway.ip, session.local_ip,
        session.blocked_ips, session.throttled_ips,
    )
    console.print(table)
    input("\n按 Enter 返回主選單...")


def _handle_camera_scan(session: SessionManager, timeout: int) -> None:
    """攝影機偵測：對掃描到的裝置做連接埠掃描 + 指紋，再做網段 ONVIF/SSDP 主動發現。"""
    assert session.gateway is not None
    if not session.devices:
        console.print("[dim]自動掃描中...[/dim]")
        session.scan(timeout=timeout)

    targets = [
        d for d in session.devices
        if d.ip != session.gateway.ip and d.ip != session.local_ip
    ]
    if not targets:
        console.print("[yellow]沒有可偵測的裝置。[/yellow]")
        return

    console.print(f"[dim]連接埠掃描 + 指紋辨識 {len(targets)} 台裝置...[/dim]")
    results = camera_scan.scan_devices(targets)
    console.print(make_camera_table(results))

    console.print("[dim]ONVIF / SSDP 主動發現中（找出無開放埠的攝影機）...[/dim]")
    onvif = camera_scan.discover_onvif(local_ip=session.local_ip)
    ssdp_cams = [d for d in camera_scan.discover_ssdp(local_ip=session.local_ip) if d.camera_like]

    if onvif:
        console.print("[red]ONVIF 攝影機發現:[/red]")
        for cam in onvif:
            console.print(f"  {cam.ip}  XAddrs={cam.xaddrs}")
    else:
        console.print("[green]ONVIF 探測: 未發現 IP 攝影機。[/green]")
    if ssdp_cams:
        console.print("[red]SSDP 疑似攝影機:[/red]")
        for d in ssdp_cams:
            console.print(f"  {d.ip}  {d.descriptions[:2]}")

    console.print(make_camera_summary_panel(results))
    input("\n按 Enter 返回主選單...")


def _device_options(devices, gateway_ip):
    return [format_device_choice(d, gateway_ip) for d in devices]


def _handle_cut(session: SessionManager, timeout: int) -> None:
    assert session.gateway is not None
    if not session.devices:
        console.print("[dim]自動掃描中...[/dim]")
        session.scan(timeout=timeout)

    selectable = [
        d for d in session.selectable_devices()
        if d.ip not in session.blocked_ips
    ]
    if not selectable:
        console.print("[yellow]沒有可封鎖的裝置。[/yellow]")
        return

    indices = _pick_multi("選擇要封鎖的裝置", _device_options(selectable, session.gateway.ip))
    if not indices:
        console.print("[dim]未選擇任何裝置。[/dim]")
        return

    selected = [selectable[i].ip for i in indices]
    added = session.cut(selected)
    for ip in added:
        console.print(f"[red]已封鎖:[/red] {ip}")


def _handle_uncut(session: SessionManager) -> None:
    if not session.blocked_ips:
        console.print("[yellow]目前沒有封鎖中的裝置。[/yellow]")
        return

    ips = sorted(session.blocked_ips)
    indices = _pick_multi("選擇要解除封鎖的裝置", ips)
    if not indices:
        return

    selected = [ips[i] for i in indices]
    removed = session.uncut(selected)
    for ip in removed:
        console.print(f"[green]已解除封鎖:[/green] {ip}")


def _handle_throttle(session: SessionManager, timeout: int) -> None:
    assert session.gateway is not None
    if not session.devices:
        console.print("[dim]自動掃描中...[/dim]")
        session.scan(timeout=timeout)

    selectable = [
        d for d in session.selectable_devices()
        if d.ip not in session.throttled_ips
    ]
    if not selectable:
        console.print("[yellow]沒有可限速的裝置。[/yellow]")
        return

    indices = _pick_multi("選擇要限速的裝置", _device_options(selectable, session.gateway.ip))
    if not indices:
        console.print("[dim]未選擇任何裝置。[/dim]")
        return

    selected = [selectable[i].ip for i in indices]
    bw_num = _input_text("頻寬限制 (Kbit/s，只需輸入數字)", "100")
    if not bw_num:
        return
    bw = f"{bw_num}Kbit/s"

    added = session.throttle(selected, bw)
    for ip in added:
        console.print(f"[yellow]已限速:[/yellow] {ip} @ {bw}")


def _handle_unthrottle(session: SessionManager) -> None:
    if not session.throttled_ips:
        console.print("[yellow]目前沒有限速中的裝置。[/yellow]")
        return

    items = sorted(session.throttled_ips.items())
    options = [f"{ip} ({bw})" for ip, bw in items]
    indices = _pick_multi("選擇要解除限速的裝置", options)
    if not indices:
        return

    selected = [items[i][0] for i in indices]
    removed = session.unthrottle(selected)
    for ip in removed:
        console.print(f"[green]已解除限速:[/green] {ip}")


def _handle_bw_test(session: SessionManager, timeout: int) -> None:
    assert session.gateway is not None
    if not session.devices:
        console.print("[dim]自動掃描中...[/dim]")
        session.scan(timeout=timeout)

    selectable = session.selectable_devices()
    if not selectable:
        console.print("[yellow]沒有可測試的裝置。[/yellow]")
        return

    indices = _pick_multi("選擇要測試的裝置", _device_options(selectable, session.gateway.ip))
    if not indices:
        console.print("[dim]未選擇任何裝置。[/dim]")
        return

    selected = [selectable[i].ip for i in indices]

    try:
        start_bw = int(_input_text("起始頻寬 (Kbit/s)", "100"))
        end_bw = int(_input_text("結束頻寬 (Kbit/s)", "10"))
        step_bw = int(_input_text("每步遞減 (Kbit/s)", "10"))
        step_duration = int(_input_text("每步持續時間 (秒)", "120"))
    except ValueError:
        return

    last_online_bw = None
    offline_bw = None
    current_bw = start_bw

    console.print(f"\n[bold cyan]開始頻寬測試: {start_bw}Kbit/s → {end_bw}Kbit/s[/bold cyan]\n")

    try:
        step_num = 0
        total_steps = max(1, (start_bw - end_bw) // step_bw + 1)

        while current_bw >= end_bw:
            step_num += 1
            bw_str = f"{current_bw}Kbit/s"

            if step_num == 1:
                session.throttle(selected, bw_str)
            else:
                session.update_throttle_bandwidth(selected, bw_str)

            console.print(f"[cyan]Step {step_num}/{total_steps}:[/cyan] 限速 {bw_str}")

            ping_ok = True
            try:
                with Live(console=console, refresh_per_second=1) as live:
                    for remaining in range(step_duration, 0, -1):
                        if remaining % 30 == 0:
                            ping_ok = session.ping_target(selected[0])

                        mins, secs = divmod(remaining, 60)
                        ping_status = "[green]Online[/green]" if ping_ok else "[red]WiFi Lost![/red]"
                        panel = Panel(
                            f"[cyan]頻寬:[/cyan]     {bw_str}\n"
                            f"[dim]剩餘:[/dim]     {mins:02d}:{secs:02d}\n"
                            f"[dim]ARP Ping:[/dim] {ping_status}\n"
                            f"[dim]進度:[/dim]     Step {step_num}/{total_steps}",
                            title="Bandwidth Test",
                            border_style="cyan",
                        )
                        live.update(panel)
                        time.sleep(1)
            except KeyboardInterrupt:
                console.print("[yellow]測試中斷。[/yellow]")
                break

            if not ping_ok:
                console.print(f"[red]警告: 裝置在 {bw_str} 時 WiFi 連線中斷！[/red]")
                offline_bw = current_bw
                break

            still_online = _input_confirm(f"請檢查 App，裝置在 {bw_str} 下是否仍在線？")

            if still_online:
                last_online_bw = current_bw
                current_bw -= step_bw
            else:
                offline_bw = current_bw
                break
    finally:
        session.unthrottle(selected)

    console.print()
    if last_online_bw is not None:
        result_text = (
            f"[green]最後在線頻寬:[/green]  {last_online_bw}Kbit/s\n"
            f"[red]首次離線頻寬:[/red]  {offline_bw}Kbit/s\n"
            f"\n[bold]建議使用頻寬:  {last_online_bw}Kbit/s[/bold]"
        )
    elif offline_bw is not None:
        result_text = (
            f"[red]起始頻寬 {start_bw}Kbit/s 就離線了。[/red]\n"
            f"[dim]建議提高起始頻寬重新測試。[/dim]"
        )
    else:
        result_text = (
            f"[green]測試完成，裝置在 {end_bw}Kbit/s 下仍在線。[/green]\n"
            f"[bold]建議使用頻寬:  {end_bw}Kbit/s[/bold]"
        )
    console.print(Panel(result_text, title="Bandwidth Test Result", border_style="bright_green"))


def _handle_pulse_block(session: SessionManager, timeout: int) -> None:
    assert session.gateway is not None
    if not session.devices:
        console.print("[dim]自動掃描中...[/dim]")
        session.scan(timeout=timeout)

    selectable = [
        d for d in session.selectable_devices()
        if d.ip not in session.throttled_ips and d.ip not in session.blocked_ips
    ]
    if not selectable:
        console.print("[yellow]沒有可用的裝置。[/yellow]")
        return

    indices = _pick_multi("選擇目標裝置", _device_options(selectable, session.gateway.ip))
    if not indices:
        console.print("[dim]未選擇任何裝置。[/dim]")
        return

    selected = [selectable[i].ip for i in indices]
    bw_num = _input_text("基礎限速頻寬 (Kbit/s，只需輸入數字)", "40")
    if not bw_num:
        return
    bw = f"{bw_num}Kbit/s"

    try:
        block_secs = float(_input_text("封鎖時長 (秒)", "2"))
        allow_secs = float(_input_text("放行間隔 (秒)", "5"))
    except ValueError:
        return

    session.start_pulse_block(selected, bw, block_secs, allow_secs)
    console.print(f"[bold magenta]Pulse Block 啟動[/bold magenta]")
    console.print(f"  限速: {bw} | 封鎖: {block_secs}s | 間隔: {allow_secs}s")
    console.print("[dim]按 Enter 返回主選單（Pulse Block 持續運行）[/dim]\n")

    stop = threading.Event()
    t = threading.Thread(target=_wait_for_enter, args=(stop,), daemon=True)
    t.start()
    try:
        with Live(console=console, refresh_per_second=1) as live:
            while not stop.is_set():
                ping_ok = session.ping_target(selected[0])
                ping_status = "[green]Online[/green]" if ping_ok else "[red]Offline![/red]"
                panel = Panel(
                    f"[magenta]模式:[/magenta]     Pulse Block\n"
                    f"[cyan]限速:[/cyan]     {bw}\n"
                    f"[dim]週期:[/dim]     封鎖 {block_secs}s / 放行 {allow_secs}s\n"
                    f"[dim]ARP Ping:[/dim] {ping_status}\n"
                    f"[dim]Packets:[/dim]  {session.packet_count}",
                    title="Pulse Block Status",
                    border_style="magenta",
                )
                live.update(panel)
                time.sleep(3)
    except KeyboardInterrupt:
        pass

    if _input_confirm("要停止 Pulse Block 嗎？", default=False):
        session.stop_pulse_block()
        session.unthrottle(selected)
        console.print("[green]Pulse Block 已停止。[/green]")


def _handle_status(session: SessionManager) -> None:
    console.print("[dim]按 Enter 返回主選單[/dim]\n")
    stop = threading.Event()
    t = threading.Thread(target=_wait_for_enter, args=(stop,), daemon=True)
    t.start()
    try:
        with Live(console=console, refresh_per_second=1) as live:
            while not stop.is_set():
                panel = make_status_panel(
                    blocked_count=len(session.blocked_ips),
                    throttled_count=len(session.throttled_ips),
                    packet_count=session.packet_count,
                    elapsed_seconds=session.elapsed,
                )
                live.update(panel)
                time.sleep(1)
    except KeyboardInterrupt:
        pass
