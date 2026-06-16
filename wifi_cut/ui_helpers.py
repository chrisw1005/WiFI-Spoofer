from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from wifi_cut.scanner import Device
from wifi_cut.camera_scan import CameraScanResult


def make_device_table(
    devices: list[Device],
    gateway_ip: str,
    local_ip: str,
    blocked_ips: set[str] | None = None,
    throttled_ips: dict[str, str] | None = None,
) -> Table:
    blocked_ips = blocked_ips or set()
    throttled_ips = throttled_ips or {}

    table = Table(title="Network Devices", show_lines=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("IP", min_width=16)
    table.add_column("MAC", min_width=18)
    table.add_column("Vendor", min_width=15)
    table.add_column("Hostname", min_width=20)
    table.add_column("Note", min_width=10)
    table.add_column("Status", min_width=12)

    for i, d in enumerate(devices, 1):
        note = ""
        if d.ip == gateway_ip:
            note = "[blue]Gateway[/blue]"
        elif d.ip == local_ip:
            note = "[green]You[/green]"

        vendor = d.vendor or "--"
        hostname = d.hostname or "--"

        if d.ip in blocked_ips:
            status = "[red]Blocked[/red]"
        elif d.ip in throttled_ips:
            bw = throttled_ips[d.ip]
            status = f"[yellow]Throttled ({bw})[/yellow]"
        else:
            status = ""

        table.add_row(str(i), d.ip, d.mac, vendor, hostname, note, status)

    return table


def make_status_panel(
    blocked_count: int,
    throttled_count: int,
    packet_count: int,
    elapsed_seconds: int,
) -> Panel:
    mins, secs = divmod(elapsed_seconds, 60)
    hours, mins = divmod(mins, 60)

    lines = []
    lines.append(f"[red]Blocked:[/red]    {blocked_count} device(s)")
    lines.append(f"[yellow]Throttled:[/yellow]  {throttled_count} device(s)")
    lines.append(f"[cyan]Packets:[/cyan]    {packet_count}")
    if hours:
        lines.append(f"[dim]Elapsed:[/dim]    {hours:02d}:{mins:02d}:{secs:02d}")
    else:
        lines.append(f"[dim]Elapsed:[/dim]    {mins:02d}:{secs:02d}")

    content = "\n".join(lines)
    return Panel(content, title="wifi-cut Status", border_style="bright_blue")


_VERDICT_STYLE = {
    "LIKELY_CAMERA": ("red", "高度疑似攝影機"),
    "OPEN_UNCLEAR": ("yellow", "有開放埠待確認"),
    "INDETERMINATE_CLOUD": ("cyan", "雲端裝置/需流量分析"),
    "IDENTIFIED_BENIGN": ("green", "已辨識非攝影機"),
}

_LEVEL_STYLE = {
    "high": "[red]高[/red]",
    "medium": "[yellow]中[/yellow]",
    "low": "[dim]低[/dim]",
    "none": "[green]無[/green]",
}


def make_camera_table(results: list[CameraScanResult]) -> Table:
    """攝影機偵測結果表。依判定嚴重度由高到低排序顯示。"""
    order = {"LIKELY_CAMERA": 0, "OPEN_UNCLEAR": 1, "INDETERMINATE_CLOUD": 2,
             "IDENTIFIED_BENIGN": 3}
    rows = sorted(results, key=lambda r: order.get(r.verdict, 9))

    table = Table(title="攝影機偵測結果 (Camera Detection)", show_lines=True)
    table.add_column("IP", min_width=14)
    table.add_column("廠商可疑度", justify="center", min_width=6)
    table.add_column("Hostname/廠商", min_width=16)
    table.add_column("開放埠", min_width=14)
    table.add_column("判定", min_width=20)

    for r in rows:
        color, verdict_label = _VERDICT_STYLE.get(r.verdict, ("white", r.verdict))
        ports = ", ".join(f"{p.port}/{p.kind}" for p in r.open_ports) or "—"
        name = r.identity or r.hostname or r.vendor or "--"
        table.add_row(
            r.ip,
            _LEVEL_STYLE.get(r.vendor_level, r.vendor_level),
            name[:28],
            ports[:32],
            f"[{color}]{verdict_label}[/{color}]",
        )
    return table


def make_camera_summary_panel(results: list[CameraScanResult]) -> Panel:
    """攝影機偵測總結面板（含建議）。"""
    likely = [r for r in results if r.verdict == "LIKELY_CAMERA"]
    unclear = [r for r in results if r.verdict == "OPEN_UNCLEAR"]
    cloud = [r for r in results if r.verdict == "INDETERMINATE_CLOUD"]

    lines = [
        f"[red]高度疑似攝影機:[/red] {len(likely)} 台",
        f"[yellow]待確認:[/yellow] {len(unclear)} 台",
        f"[cyan]雲端裝置(無法由埠判定):[/cyan] {len(cloud)} 台",
    ]
    if likely:
        lines.append("\n[red]→ 立即處理:[/red] " + ", ".join(r.ip for r in likely))
    if cloud:
        lines.append(
            "\n[dim]雲端裝置無開放埠，無法由連接埠判定是否為攝影機。\n"
            "  建議: 1) 查路由器/App 裝置清單  2) 用本工具『頻寬測試』觀察上傳流量\n"
            "        (攝影機會持續高流量上傳影像)  3) 檢查獨立 IoT/訪客 SSID[/dim]"
        )
    return Panel("\n".join(lines), title="偵測總結", border_style="bright_yellow")


def format_device_choice(device: Device, gateway_ip: str) -> str:
    name = device.hostname or device.vendor or "--"
    label = f"{device.ip:<16} {device.mac:<18} {name}"
    if device.ip == gateway_ip:
        label += "  (Gateway)"
    return label
