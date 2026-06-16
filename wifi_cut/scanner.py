import ipaddress
import socket
import subprocess
import sys
import re
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
