import re
import sys
import subprocess
from dataclasses import dataclass

from scapy.all import Ether, ARP, srp


@dataclass
class GatewayInfo:
    ip: str
    mac: str
    interface: str


def parse_route_output(output: str) -> tuple[str, str]:
    """解析 macOS route -n get default 的輸出，回傳 (gateway_ip, interface)。"""
    gw_match = re.search(r"gateway:\s+(\S+)", output)
    if_match = re.search(r"interface:\s+(\S+)", output)
    if not gw_match or not if_match:
        raise RuntimeError("無法解析閘道器資訊")
    return gw_match.group(1), if_match.group(1)


def parse_ipconfig_gateway(output: str) -> str:
    """從 Windows ipconfig 輸出解析預設閘道器 IP。"""
    match = re.search(r"Default Gateway[.\s]*:\s+(\d+\.\d+\.\d+\.\d+)", output)
    if not match:
        raise RuntimeError("無法從 ipconfig 解析閘道器")
    return match.group(1)


def _default_gateway_from_routes(iface_name: str, routes) -> str:
    """從 scapy 路由表找出指定介面的預設閘道。

    routes 為 scapy ``conf.route.routes``，每列為
    (network:int, netmask:int, gateway:str, iface, output_ip:str, metric:int)。
    只取該介面的預設路由 (net==0, mask==0) 且閘道非 0.0.0.0 者，取 metric 最小的。
    """
    best_metric = None
    best_gw = None
    for net, mask, gw, route_iface, _outip, metric in routes:
        if net != 0 or mask != 0:
            continue
        if route_iface != iface_name:
            continue
        if gw in ("0.0.0.0", "::"):
            continue
        if best_metric is None or metric < best_metric:
            best_metric = metric
            best_gw = gw
    if best_gw is None:
        raise RuntimeError("無法從路由表取得預設閘道")
    return best_gw


def get_gateway_ip_and_interface() -> tuple[str, str]:
    if sys.platform == "win32":
        # 閘道與介面都取自 scapy 的路由表 (conf.iface 的預設路由)，與掃描所用的
        # 介面同源，避免解析 ipconfig 時誤抓到 VPN / 虛擬介面的閘道。
        from scapy.all import conf
        iface = conf.iface
        ip = _default_gateway_from_routes(iface.network_name, conf.route.routes)
        return ip, iface
    else:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True
        )
        return parse_route_output(result.stdout)


def get_mac_by_ip(ip: str, interface: str, timeout: int = 2) -> str:
    """透過 ARP request 取得指定 IP 的 MAC。"""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=interface, timeout=timeout, verbose=False
    )
    if not ans:
        raise RuntimeError(f"無法取得 {ip} 的 MAC 位址")
    return ans[0][1].hwsrc


def get_gateway_info() -> GatewayInfo:
    ip, interface = get_gateway_ip_and_interface()
    mac = get_mac_by_ip(ip, interface)
    return GatewayInfo(ip=ip, mac=mac, interface=interface)
