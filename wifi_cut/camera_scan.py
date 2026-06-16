"""攝影機 / 針孔攝影機偵測模組。

對網路上的裝置做兩階段判斷：

1. 廠商判斷 (``classify_vendor``)：依 MAC 廠商字串與 hostname 給出「攝影機可疑度」。
   針孔／隱藏式攝影機絕大多數使用少數幾種 Wi-Fi 晶片平台 (Espressif、Tuya、
   HiSilicon…) 或出自特定攝影機品牌 (Hikvision、Dahua、Reolink…)。

2. 連接埠掃描 + 服務指紋 (``scan_device``)：對裝置做併發 TCP 連接埠掃描，
   對開放埠抓取服務 banner，並針對攝影機常見協定 (RTSP)、廉價 DVR 私有埠
   (Xiongmai 34567 / Dahua 37777) 與已知裝置 (Google Cast、Samsung Tizen)
   做指紋辨識，最後綜合出判定 (``assess``)。

設計重點：純判斷函式 (classify_vendor / match_http_signature / assess) 不碰網路，
方便單元測試；只有 ``scan_ports`` / ``scan_device`` 會實際連線。本模組只用標準
函式庫，且不需 root 權限。

重要限制：現代雲端攝影機 (Tuya、Nest、多數廉價 Wi-Fi 攝影機) 通常**不開放任何
inbound 連接埠**，只對外連雲端上傳影像。因此「沒有開放埠」**無法**排除攝影機，
這種情況會回報為「需流量分析」而非「安全」。
"""

import socket
import ssl
import gzip
import json
import re
import concurrent.futures as cf
from dataclasses import dataclass, field
from typing import Optional

from wifi_cut.scanner import Device


# --------------------------------------------------------------------------- #
# 連接埠分類
# --------------------------------------------------------------------------- #
RTSP_PORTS = {554, 8554, 10554}                 # 即時串流協定，攝影機強指標
DVR_PORTS = {34567, 37777, 8899, 8000, 7001}    # 廉價 DVR/NVR 私有協定 (Xiongmai/Dahua/Hikvision)
RTMP_PORTS = {1935}                             # 串流上傳
HTTP_PORTS = {80, 81, 88, 8080, 8081, 8082, 8888, 9000, 9999, 49152, 5000, 8000}
TLS_PORTS = {443, 8443}
CAST_PORTS = {8008, 8009}                       # Google Cast / Nest
SAMSUNG_PORTS = {8001, 8002}                    # Samsung Tizen TV/Monitor
TELNET_PORTS = {23}                             # 廉價攝影機常開 telnet

# 實際掃描的 TCP 埠 (攝影機相關 + 用於辨識常見非攝影機裝置)
CAMERA_PORTS = sorted(
    RTSP_PORTS | DVR_PORTS | RTMP_PORTS | HTTP_PORTS | TLS_PORTS
    | CAST_PORTS | SAMSUNG_PORTS | TELNET_PORTS
)

# 開放即視為攝影機強指標的埠 / 對應的 _port_kind 種類
STRONG_CAMERA_PORTS = RTSP_PORTS | DVR_PORTS | RTMP_PORTS
STRONG_CAMERA_KINDS = {"rtsp", "dvr", "rtmp"}


# --------------------------------------------------------------------------- #
# 廠商 / hostname 可疑度判斷
# --------------------------------------------------------------------------- #
# 攝影機品牌 (出現幾乎就是攝影機/監控設備) -> 高度可疑
_CAMERA_BRANDS = [
    "hikvision", "dahua", "xiongmai", "reolink", "amcrest", "foscam",
    "wansview", "vstarcam", "sricam", "wyze", "axis communications",
    "hanwha", "wisenet", "lorex", "annke", "ezviz", "uniview", "tp-link tapo",
    "anjvision", "jovision", "mobotix", "vivotek", "geovision", "swann",
]

# 攝影機常用晶片平台 (也大量用於非攝影機 IoT) -> 中度可疑，需配合掃描
_CAMERA_PLATFORMS = [
    "espressif", "tuya", "hisilicon", "ingenic", "grain media", "anyka",
    "fullhan", "novatek",
]

# 可能含攝影機但也有大量非攝影機產品的廠商 -> 低度，需指紋辨識
_AMBIGUOUS_VENDORS = [
    "google", "xiaomi", "amazon", "ubiquiti", "realtek", "samsung",
]

# hostname 關鍵字 -> 直接拉高可疑度。
# 只用「明確」的關鍵字 (避免 'cam' 誤命中 'campus')；'cam' 僅在有分隔符邊界時計入。
_CAMERA_HOSTNAME_HINTS = [
    "camera", "webcam", "ipcam", "ipcamera", "nestcam", "doorbell",
    "hikvision", "dahua", "reolink", "wyze", "foscam",
    "-cam", "_cam", "cam-", "cam_",
]


@dataclass
class VendorAssessment:
    level: str          # "high" | "medium" | "low" | "none"
    label: str          # 中文說明


_LEVEL_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _max_level(a: str, b: str) -> str:
    return a if _LEVEL_RANK[a] >= _LEVEL_RANK[b] else b


def classify_vendor(vendor: Optional[str], hostname: Optional[str] = None) -> VendorAssessment:
    """依 MAC 廠商字串與 hostname 判斷攝影機可疑度（純函式，不碰網路）。"""
    v = (vendor or "").lower()
    h = (hostname or "").lower()

    level = "none"
    labels: list[str] = []

    for brand in _CAMERA_BRANDS:
        if brand in v:
            level = _max_level(level, "high")
            labels.append(f"攝影機品牌 ({vendor})")
            break

    for plat in _CAMERA_PLATFORMS:
        if plat in v:
            level = _max_level(level, "medium")
            labels.append(f"攝影機常用晶片平台 ({plat})")
            break

    if level == "none":
        for amb in _AMBIGUOUS_VENDORS:
            if amb in v:
                level = _max_level(level, "low")
                labels.append(f"廠商產品線含攝影機，需指紋辨識 ({amb})")
                break

    # hostname 命中關鍵字 -> 直接視為高度可疑 (含已知攝影機如 Nest Doorbell)
    for hint in _CAMERA_HOSTNAME_HINTS:
        if hint in h:
            level = _max_level(level, "high")
            labels.append(f"hostname 含攝影機關鍵字 ('{hint}')")
            break

    if not labels:
        labels.append("非攝影機相關廠商")
    return VendorAssessment(level=level, label="；".join(labels))


# --------------------------------------------------------------------------- #
# HTTP banner 攝影機特徵
# --------------------------------------------------------------------------- #
# 強特徵：幾乎可確定是攝影機/監控裝置
_HTTP_STRONG = [
    "uc-httpd", "netsurveillance", "dvrdvs", "hipcam", "ipcamera",
    "ip camera", "network camera", "mjpg-streamer", "hikvision", "dahua",
    "onvif", "rtsp", "webcamxp", "jaws/1.0", "h264dvr", "axis",
]
# 弱特徵：常見於攝影機，但路由器/印表機也可能用 (僅作參考)
_HTTP_WEAK = ["boa/", "goahead", "thttpd", "webs", "mini_httpd", "lighttpd"]


def match_http_signature(banner: str) -> tuple[Optional[str], Optional[str]]:
    """比對 HTTP banner，回傳 (強特徵, 弱特徵)，未命中為 None（純函式）。"""
    b = (banner or "").lower()
    strong = next((s for s in _HTTP_STRONG if s in b), None)
    weak = next((w for w in _HTTP_WEAK if w in b), None)
    return strong, weak


# --------------------------------------------------------------------------- #
# 掃描結果資料結構
# --------------------------------------------------------------------------- #
@dataclass
class PortResult:
    port: int
    kind: str           # "rtsp" | "dvr" | "http" | "tls" | "cast" | "samsung" | "telnet" | "raw"
    info: str           # 抓到的 banner / 指紋摘要


@dataclass
class CameraScanResult:
    ip: str
    mac: str = ""
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    vendor_level: str = "none"
    vendor_label: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    identity: Optional[str] = None   # 已辨識的裝置身分 (e.g. "Google Nest 智慧螢幕: Bedroom Display")
    verdict: str = ""                # 機器判定碼
    confidence: str = ""             # "high" | "medium" | "low"
    summary: str = ""                # 中文結論


# --------------------------------------------------------------------------- #
# 低階探測
# --------------------------------------------------------------------------- #
def _connect(ip: str, port: int, timeout: float) -> Optional[socket.socket]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            return s
    except OSError:
        pass
    s.close()
    return None


def _http_get(sock: socket.socket, ip: str, path: str = "/", timeout: float = 2.5) -> str:
    sock.settimeout(timeout)
    sock.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: wifi-cut-camscan\r\n"
        f"Connection: close\r\n\r\n".encode()
    )
    buf = b""
    while len(buf) < 16384:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    # gzip body 解壓 (部分嵌入式裝置會 gzip 整頁)
    if b"content-encoding: gzip" in buf.lower():
        idx = buf.find(b"\r\n\r\n")
        if idx != -1:
            try:
                head = buf[:idx].decode("latin-1", "replace")
                body = gzip.decompress(buf[idx + 4:]).decode("utf-8", "replace")
                return head + "\r\n\r\n" + body
            except Exception:
                pass
    return buf.decode("latin-1", "replace")


def _parse_http(text: str) -> str:
    server = title = auth = ""
    for line in text.splitlines():
        lo = line.lower()
        if lo.startswith("server:"):
            server = line.split(":", 1)[1].strip()
        elif lo.startswith("www-authenticate:"):
            auth = line.split(":", 1)[1].strip()
    m = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if m:
        title = m.group(1).strip()[:60]
    parts = []
    if server:
        parts.append(f"Server={server}")
    if title:
        parts.append(f"Title='{title}'")
    if auth:
        parts.append(f"Auth={auth}")
    return " ".join(parts) or "(HTTP 無 banner)"


def _probe_cast(ip: str, timeout: float) -> Optional[str]:
    """Google Cast / Nest：讀 eureka_info 取得裝置名稱。"""
    s = _connect(ip, 8008, timeout)
    if not s:
        return None
    try:
        text = _http_get(s, ip, "/setup/eureka_info?options=detail", timeout)
    finally:
        s.close()
    idx = text.find("{")
    if idx == -1:
        return None
    try:
        data = json.loads(text[idx:])
    except (json.JSONDecodeError, ValueError):
        return None
    name = data.get("name") or "(未命名)"
    return f"Google Cast/Nest 裝置: {name}"


def _probe_samsung(ip: str, timeout: float) -> Optional[str]:
    """Samsung Tizen TV/Monitor：讀 /api/v2/ 取得型號。"""
    for port in (8001, 8002):
        s = _connect(ip, port, timeout)
        if not s:
            continue
        try:
            text = _http_get(s, ip, "/api/v2/", timeout)
        finally:
            s.close()
        idx = text.find("{")
        if idx == -1:
            continue
        try:
            data = json.loads(text[idx:])
        except (json.JSONDecodeError, ValueError):
            continue
        dev = data.get("device", {})
        model = dev.get("modelName") or dev.get("model") or ""
        name = dev.get("name", "")
        if model or name:
            return f"Samsung Tizen 顯示器/電視: {model} {name}".strip()
    return None


def _grab_rtsp(sock: socket.socket, ip: str, port: int, timeout: float) -> str:
    sock.settimeout(timeout)
    sock.sendall(
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
        f"User-Agent: wifi-cut-camscan\r\n\r\n".encode()
    )
    try:
        data = sock.recv(2048).decode("latin-1", "replace")
    except OSError:
        return "(RTSP 無回應)"
    first = data.splitlines()[0] if data else "(RTSP 無回應)"
    extra = ""
    for line in data.splitlines():
        lo = line.lower()
        if lo.startswith("server:") or lo.startswith("public:"):
            extra += " " + line.strip()
    return (first + extra).strip()


def _grab_tls(ip: str, port: int, timeout: float) -> str:
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ss:
                cn = ""
                cert = ss.getpeercert()
                if cert:
                    for tup in cert.get("subject", ()):
                        for k, val in tup:
                            if k == "commonName":
                                cn = val
                return f"TLS (cert CN='{cn}')"
    except Exception:
        return "TLS (handshake 失敗)"


def _port_kind(port: int) -> str:
    if port in RTSP_PORTS:
        return "rtsp"
    if port in DVR_PORTS:
        return "dvr"
    if port in RTMP_PORTS:
        return "rtmp"
    if port in CAST_PORTS:
        return "cast"
    if port in SAMSUNG_PORTS:
        return "samsung"
    if port in TLS_PORTS:
        return "tls"
    if port in TELNET_PORTS:
        return "telnet"
    if port in HTTP_PORTS:
        return "http"
    return "raw"


def _scan_one_port(ip: str, port: int, timeout: float) -> Optional[PortResult]:
    kind = _port_kind(port)
    sock = _connect(ip, port, timeout)
    if sock is None:
        return None
    try:
        if kind == "tls":
            sock.close()  # 確認開放後另建 TLS 連線抓憑證
            info = _grab_tls(ip, port, timeout)
        elif kind == "rtsp":
            info = _grab_rtsp(sock, ip, port, timeout)
        elif kind in ("http", "cast", "samsung"):
            info = _parse_http(_http_get(sock, ip, "/", timeout))
        else:
            info = "open"
    except Exception as e:  # noqa: BLE001 - 探測失敗不應中斷整體掃描
        info = f"open (探測錯誤: {e})"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return PortResult(port, kind, info)


def scan_ports(ip: str, ports: Optional[list[int]] = None,
               timeout: float = 1.5, max_workers: int = 64) -> list[PortResult]:
    """併發 TCP 連接埠掃描 + banner 抓取，回傳開放埠列表。"""
    ports = ports or CAMERA_PORTS
    results: list[PortResult] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_scan_one_port, ip, p, timeout) for p in ports]
        for fut in cf.as_completed(futures):
            r = fut.result()
            if r is not None:
                results.append(r)
    results.sort(key=lambda r: r.port)
    return results


# --------------------------------------------------------------------------- #
# 綜合判定
# --------------------------------------------------------------------------- #
def assess(vendor_level: str, open_ports: list[PortResult],
           identity: Optional[str]) -> tuple[str, str, str]:
    """綜合廠商可疑度、開放埠、身分辨識，回傳 (verdict, confidence, summary)。純函式。"""
    kinds = {p.kind for p in open_ports}
    strong_camera_kinds = kinds & STRONG_CAMERA_KINDS
    strong_http = any(match_http_signature(p.info)[0] for p in open_ports if p.kind == "http")
    weak_http = any(match_http_signature(p.info)[1] for p in open_ports if p.kind == "http")

    # 1) 已辨識為已知非攝影機裝置 (Google 智慧螢幕 / Samsung 顯示器)
    if identity and not strong_camera_kinds and not strong_http:
        note = ""
        if "Cast" in identity or "Nest" in identity:
            note = "（註：若為 Nest Hub Max 等含鏡頭機種，仍具視訊鏡頭，但屬已知裝置）"
        return ("IDENTIFIED_BENIGN", "high", f"已辨識為非針孔攝影機裝置 → {identity}{note}")

    # 2) 攝影機強指標：RTSP / DVR 私有埠 / RTMP / 強 HTTP 特徵
    if strong_camera_kinds or strong_http:
        hits = []
        if "rtsp" in kinds:
            hits.append("RTSP 串流埠")
        if "dvr" in kinds:
            hits.append("DVR/NVR 私有埠")
        if "rtmp" in kinds:
            hits.append("RTMP 串流埠")
        if strong_http:
            hits.append("攝影機 HTTP 特徵")
        return ("LIKELY_CAMERA", "high",
                f"高度疑似攝影機：偵測到 {'、'.join(hits)}。建議實體檢查並隔離。")

    # 3) 有 Web 介面但無攝影機特徵
    if "http" in kinds or "telnet" in kinds:
        conf = "medium" if vendor_level in ("high", "medium") or weak_http else "low"
        extra = "（廠商為攝影機常用平台，建議進一步確認）" if vendor_level in ("high", "medium") else ""
        return ("OPEN_UNCLEAR", conf,
                f"有開放 Web/服務埠但無典型攝影機特徵，需人工確認其用途{extra}。")

    # 4) 在線但無任何開放埠 -> 雲端裝置（雲端攝影機也屬此類，無法由 port 判定）
    if vendor_level in ("high", "medium"):
        return ("INDETERMINATE_CLOUD", "medium",
                "在線但無開放埠：屬雲端型裝置。廠商為攝影機常用平台，"
                "無法由連接埠判定是否為攝影機 → 需用流量/頻寬分析或檢查 App 裝置清單。")
    return ("INDETERMINATE_CLOUD", "low",
            "在線但無開放埠（雲端裝置）。未由廠商或連接埠偵測到攝影機特徵，"
            "但雲端攝影機本來就可能不開任何埠，必要時以流量分析或檢查 App 確認。")


def scan_device(device: Device | str, timeout: float = 1.5,
                ports: Optional[list[int]] = None) -> CameraScanResult:
    """對單一裝置 (Device 或 IP 字串) 做完整攝影機偵測。"""
    if isinstance(device, str):
        ip, mac, vendor, hostname = device, "", None, None
    else:
        ip, mac, vendor, hostname = device.ip, device.mac, device.vendor, device.hostname

    va = classify_vendor(vendor, hostname)
    result = CameraScanResult(
        ip=ip, mac=mac, vendor=vendor, hostname=hostname,
        vendor_level=va.level, vendor_label=va.label,
    )
    result.open_ports = scan_ports(ip, ports=ports, timeout=timeout)

    kinds = {p.kind for p in result.open_ports}
    if "cast" in kinds:
        result.identity = _probe_cast(ip, timeout) or result.identity
    if "samsung" in kinds and not result.identity:
        result.identity = _probe_samsung(ip, timeout) or result.identity

    result.verdict, result.confidence, result.summary = assess(
        va.level, result.open_ports, result.identity
    )
    return result


def scan_devices(devices: list[Device | str], timeout: float = 1.5,
                 max_workers: int = 8) -> list[CameraScanResult]:
    """併發掃描多個裝置（每個裝置內部仍會併發掃埠）。"""
    results: list[CameraScanResult] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(scan_device, d, timeout) for d in devices]
        for fut in cf.as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: tuple(int(x) for x in r.ip.split(".")))
    return results


# --------------------------------------------------------------------------- #
# 網路主動發現 (UDP) — 找出「無開放 TCP 埠」也找得到的攝影機
#
# 雲端/無埠裝置無法用 TCP 掃描判定，但攝影機若支援標準發現協定，會主動回應：
#   - ONVIF WS-Discovery (UDP 3702)：IP 攝影機標準協定，回報 RTSP 服務位址
#   - SSDP / UPnP        (UDP 1900)：裝置回報型號/製造商，可比對攝影機特徵
# 這些是 multicast 探測，一次涵蓋整個網段，不需逐一掃描，也不需 root。
# --------------------------------------------------------------------------- #
_MCAST_ADDR = "239.255.255.250"

_ONVIF_PROBE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    '<e:Header><w:MessageID>uuid:00000000-0000-0000-0000-000000000123</w:MessageID>'
    '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
    '<w:Action e:mustUnderstand="true">'
    'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
    '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>'
    '</e:Body></e:Envelope>'
).encode()

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
).encode()

# SSDP SERVER/LOCATION/ST 中代表攝影機的關鍵字。
# 注意：避免過短關鍵字 (如 'ipc' 會誤命中路由器的 'WANIPConnection')。
_SSDP_CAMERA_HINTS = [
    "camera", "ipcam", "rtsp", "onvif", "hikvision", "dahua",
    "reolink", "amcrest", "foscam", "wisenet", "networkvideotransmitter",
]


def ssdp_looks_like_camera(description: str) -> bool:
    """SSDP 描述字串是否含攝影機特徵（純函式，方便測試）。"""
    d = (description or "").lower()
    return any(h in d for h in _SSDP_CAMERA_HINTS)


def default_local_ip() -> str:
    """取得本機對外 IPv4（不需 root，用一個假連線探測）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def _discovery_socket(local_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        s.bind((local_ip, 0))
    except OSError:
        s.bind(("", 0))
    s.settimeout(0.8)
    return s


def _collect(sock: socket.socket, seconds: float) -> list[tuple[str, bytes]]:
    import time
    out: list[tuple[str, bytes]] = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            data, addr = sock.recvfrom(8192)
            out.append((addr[0], data))
        except socket.timeout:
            continue
        except OSError:
            break
    return out


@dataclass
class OnvifCamera:
    ip: str
    xaddrs: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)


def discover_onvif(local_ip: Optional[str] = None, timeout: float = 4.0) -> list[OnvifCamera]:
    """ONVIF WS-Discovery：找出網段上所有 ONVIF IP 攝影機（回報 RTSP/服務位址）。"""
    local_ip = local_ip or default_local_ip()
    sock = _discovery_socket(local_ip)
    try:
        for _ in range(2):
            sock.sendto(_ONVIF_PROBE, (_MCAST_ADDR, 3702))
        responses = _collect(sock, timeout)
    finally:
        sock.close()

    cams: dict[str, OnvifCamera] = {}
    for ip, data in responses:
        text = data.decode("latin-1", "replace")
        xaddrs = re.findall(r"https?://[^\s<]+", text)
        scopes = re.findall(r"onvif://www\.onvif\.org/\S+", text)
        cam = cams.setdefault(ip, OnvifCamera(ip=ip))
        cam.xaddrs = sorted(set(cam.xaddrs) | set(xaddrs))
        cam.scopes = sorted(set(cam.scopes) | set(scopes))
    return list(cams.values())


@dataclass
class SsdpDevice:
    ip: str
    descriptions: list[str] = field(default_factory=list)
    camera_like: bool = False


def discover_ssdp(local_ip: Optional[str] = None, timeout: float = 4.0) -> list[SsdpDevice]:
    """SSDP/UPnP M-SEARCH：列出網段上回應的 UPnP 裝置，並標記疑似攝影機者。"""
    local_ip = local_ip or default_local_ip()
    sock = _discovery_socket(local_ip)
    try:
        for _ in range(2):
            sock.sendto(_SSDP_MSEARCH, (_MCAST_ADDR, 1900))
        responses = _collect(sock, timeout)
    finally:
        sock.close()

    devices: dict[str, SsdpDevice] = {}
    for ip, data in responses:
        text = data.decode("latin-1", "replace")
        fields = []
        for key in ("SERVER", "LOCATION", "ST"):
            m = re.search(rf"(?im)^{key}:\s*(.+)$", text)
            if m:
                fields.append(m.group(1).strip())
        if not fields:
            continue
        dev = devices.setdefault(ip, SsdpDevice(ip=ip))
        desc = "; ".join(fields)
        if desc not in dev.descriptions:
            dev.descriptions.append(desc)
        if ssdp_looks_like_camera(desc):
            dev.camera_like = True
    return list(devices.values())
