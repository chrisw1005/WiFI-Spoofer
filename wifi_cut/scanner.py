import ipaddress
import socket
import subprocess
import sys
import re
import concurrent.futures as cf
from dataclasses import dataclass
from typing import Optional

from scapy.all import Ether, ARP, srp
from mac_vendor_lookup import MacLookup, VendorNotFoundError

_mac_lookup = MacLookup()


@dataclass
class Device:
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool = False


def calculate_cidr(ip: str, mask: str) -> str:
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(network)


def _netmask_from_routes(ip: str, routes) -> str:
    """從 scapy 路由表找出 ip 所在介面的直連子網路遮罩。

    routes 為 scapy ``conf.route.routes``，每列為
    (network:int, netmask:int, gateway:str, iface, output_ip:str, metric:int)。
    只取與本機 IP 同介面、閘道為 0.0.0.0 的直連路由，排除預設路由 (mask 0)、
    /32 主機與廣播路由、以及不包含本機 IP 的多播路由，取最長前綴者。
    """
    ip_int = int(ipaddress.IPv4Address(ip))
    best_prefix = -1
    best_mask = None
    for net, mask, gw, _iface, outip, _metric in routes:
        if gw != "0.0.0.0" or outip != ip:
            continue
        if mask in (0, 0xFFFFFFFF):
            continue
        if (ip_int & mask) != (net & mask):
            continue
        prefix = bin(mask).count("1")
        if prefix > best_prefix:
            best_prefix = prefix
            best_mask = mask
    if best_mask is None:
        raise RuntimeError("無法從路由表取得子網路遮罩")
    return str(ipaddress.IPv4Address(best_mask))


def get_local_ip_and_mask(interface) -> tuple[str, str]:
    """取得本機 IP 和子網路遮罩（跨平台）。"""
    if sys.platform == "win32":
        # 直接取用 scapy 實際掃描所用介面 (conf.iface) 的 IP 與遮罩，
        # 避免解析 ipconfig 時誤抓到 VPN / WSL 等虛擬介面（例如 Tailscale 的
        # 100.x.x.x/32），導致掃描網段錯誤而掃到 0 個裝置。
        from scapy.all import conf
        iface = interface if hasattr(interface, "ip") else conf.iface
        ip = iface.ip
        if not ip:
            raise RuntimeError("無法取得本機 IP 位址（網路介面沒有 IPv4）")
        mask = _netmask_from_routes(ip, conf.route.routes)
        return ip, mask
    else:
        result = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True
        )
        ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        mask_match = re.search(r"netmask\s+(0x[0-9a-f]+)", result.stdout)
        if not ip_match or not mask_match:
            raise RuntimeError(f"無法從 {interface} 取得 IP 資訊")

        ip = ip_match.group(1)
        hex_mask = int(mask_match.group(1), 16)
        mask = str(ipaddress.IPv4Address(hex_mask))
        return ip, mask


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_vendor(mac: str) -> Optional[str]:
    try:
        return _mac_lookup.lookup(mac)
    except (VendorNotFoundError, KeyError):
        return None


def arp_ping(ip: str, interface: str, timeout: int = 2) -> bool:
    """ARP ping 單一 IP，回傳是否在線。"""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=interface, timeout=timeout, verbose=False
    )
    return len(ans) > 0


def scan_network(cidr: str, interface: str, timeout: int = 3) -> list[Device]:
    """ARP 掃描子網路，回傳所有活躍裝置。"""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
        iface=interface, timeout=timeout, verbose=False
    )

    devices = []
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        hostname = resolve_hostname(ip)
        vendor = resolve_vendor(mac)
        devices.append(Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor))

    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return devices


# --------------------------------------------------------------------------- #
# 免系統管理員權限的裝置發現
#
# 主動 ARP 掃描 (scan_network) 需要 admin：它用 scapy 在 L2 直接注入原始封包，
# Windows 上經由 Npcap 注入封包預設需要系統管理員權限。
#
# 但「發現同網段裝置」本身不必提權。作法：
#   1. 對整個網段每台主機嘗試送出一個 TCP 封包——核心在送 SYN 前必須先用 ARP
#      解析同網段目標的 MAC，無論對方那個埠開不開、回不回應，ARP 交握都會發生
#      並寫入系統鄰居/ARP 快取。
#   2. 讀取系統 ARP / 鄰居快取 (Get-NetNeighbor / arp -a) 取得 IP+MAC。
# 一台裝置會不會被發現，取決於它回不回應 ARP，而非回不回應 ping/連接埠，因此對
# 「同網段、開機中」的裝置，完整度與主動 ARP 掃描基本相同。
# --------------------------------------------------------------------------- #
_INVALID_MACS = {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def _normalize_mac(mac: str) -> str:
    return mac.strip().replace("-", ":").lower()


def is_usable_mac(mac: str) -> bool:
    """是否為可用的單點 (unicast) MAC：排除空值、全 0、廣播與多播位址。"""
    m = _normalize_mac(mac)
    if m in _INVALID_MACS:
        return False
    if len(m.split(":")) != 6:
        return False
    if m.startswith("01:00:5e") or m.startswith("33:33"):  # IPv4/IPv6 multicast
        return False
    return True


_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?"  # \)? 容納 macOS 的 (ip) 格式
    r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


def parse_arp_table(output: str) -> list[tuple[str, str]]:
    """解析 `arp -a` 輸出（Windows 與 macOS 格式皆可），回傳 (ip, mac) 清單。"""
    out: list[tuple[str, str]] = []
    for ip, mac in _ARP_LINE.findall(output):
        if is_usable_mac(mac):
            out.append((ip, _normalize_mac(mac)))
    return out


def parse_netneighbor_csv(output: str) -> list[tuple[str, str]]:
    """解析 Get-NetNeighbor 的 CSV 輸出，回傳狀態可用的 (ip, mac) 清單。"""
    import csv
    import io

    out: list[tuple[str, str]] = []
    for row in csv.DictReader(io.StringIO(output)):
        state = (row.get("State") or "").strip()
        if state not in ("Reachable", "Stale", "Permanent"):
            continue
        ip = (row.get("IPAddress") or "").strip()
        mac = (row.get("LinkLayerAddress") or "").strip()
        if ip and is_usable_mac(mac):
            out.append((ip, _normalize_mac(mac)))
    return out


def _run_get_netneighbor() -> Optional[str]:
    """執行 Get-NetNeighbor（僅 Windows），失敗回傳 None 以便改用 arp -a。"""
    if sys.platform != "win32":
        return None
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress,LinkLayerAddress,State | "
        "ConvertTo-Csv -NoTypeInformation",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _run_arp() -> str:
    try:
        return subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=15
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read_neighbor_table() -> list[tuple[str, str]]:
    """讀取系統鄰居 / ARP 快取，回傳 (ip, mac) 清單（不需 admin）。"""
    csv_out = _run_get_netneighbor()
    if csv_out:
        pairs = parse_netneighbor_csv(csv_out)
        if pairs:
            return pairs
    return parse_arp_table(_run_arp())


def populate_arp_cache(cidr: str, rounds: int = 2, port: int = 80,
                       timeout: float = 0.3, max_workers: int = 128) -> None:
    """對網段每台主機嘗試 TCP 連線以觸發作業系統的 ARP 解析，填充鄰居快取。

    不需要任何特殊權限；連線成功與否不重要，重點是核心會先做 ARP 解析。
    掃 rounds 輪以涵蓋無線環境的偶發丟包。
    """
    hosts = [str(h) for h in ipaddress.IPv4Network(cidr, strict=False).hosts()]

    def _touch(ip: str) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect_ex((ip, port))
        except OSError:
            pass
        finally:
            s.close()

    for _ in range(rounds):
        with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(ex.map(_touch, hosts))


def discover_neighbors(cidr: str, rounds: int = 2) -> list[Device]:
    """免系統管理員權限的裝置發現：sweep 觸發 ARP → 讀系統快取 → 過濾本網段。"""
    host_set = {str(h) for h in ipaddress.IPv4Network(cidr, strict=False).hosts()}

    populate_arp_cache(cidr, rounds=rounds)

    seen: dict[str, str] = {}
    for ip, mac in read_neighbor_table():
        if ip in host_set and ip not in seen:
            seen[ip] = mac

    devices = [
        Device(ip=ip, mac=mac, hostname=resolve_hostname(ip), vendor=resolve_vendor(mac))
        for ip, mac in seen.items()
    ]
    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return devices
