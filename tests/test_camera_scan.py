from wifi_cut.camera_scan import (
    classify_vendor,
    match_http_signature,
    assess,
    ssdp_looks_like_camera,
    PortResult,
    RTSP_PORTS,
)


# --------------------------- 廠商可疑度判斷 --------------------------- #
def test_camera_brand_is_high():
    assert classify_vendor("Hangzhou Hikvision Digital Technology").level == "high"
    assert classify_vendor("Dahua Technology").level == "high"


def test_camera_platform_is_medium():
    assert classify_vendor("Espressif Inc.").level == "medium"
    assert classify_vendor("Tuya Smart Inc.").level == "medium"


def test_ambiguous_vendor_is_low():
    assert classify_vendor("Google, Inc.").level == "low"


def test_non_camera_vendor_is_none():
    assert classify_vendor("Intel Corporate").level == "none"
    assert classify_vendor("Apple, Inc.").level == "none"


def test_hostname_hint_raises_to_high():
    # 廠商本身不可疑，但 hostname 含攝影機關鍵字 -> 拉高到 high
    assert classify_vendor("Google, Inc.", "Nest-Doorbell-Battery").level == "high"
    assert classify_vendor(None, "living-room-ipcam").level == "high"


def test_hostname_hint_avoids_false_positive():
    # 'cam' 不應誤命中 'webcam-unrelated' 之外的一般字 (如 'campus')
    assert classify_vendor("Intel Corporate", "campus-laptop").level == "none"


# --------------------------- HTTP 特徵比對 --------------------------- #
def test_strong_http_signature():
    strong, _ = match_http_signature("Server: uc-httpd 1.0.0")
    assert strong == "uc-httpd"


def test_weak_http_signature():
    strong, weak = match_http_signature("Server: GoAhead-Webs")
    assert strong is None
    assert weak == "goahead"


def test_no_signature():
    strong, weak = match_http_signature("Server: nginx/1.20")
    assert strong is None and weak is None


# --------------------------- 綜合判定 --------------------------- #
def test_rtsp_port_means_likely_camera():
    ports = [PortResult(port=next(iter(RTSP_PORTS)), kind="rtsp", info="RTSP/1.0 200 OK")]
    verdict, conf, _ = assess("medium", ports, None)
    assert verdict == "LIKELY_CAMERA"
    assert conf == "high"


def test_dvr_port_means_likely_camera():
    ports = [PortResult(port=34567, kind="dvr", info="open")]
    verdict, _, _ = assess("none", ports, None)
    assert verdict == "LIKELY_CAMERA"


def test_strong_http_means_likely_camera():
    ports = [PortResult(port=80, kind="http", info="Server=uc-httpd 1.0.0")]
    verdict, _, _ = assess("medium", ports, None)
    assert verdict == "LIKELY_CAMERA"


def test_identified_benign_overrides_when_no_camera_ports():
    ports = [PortResult(port=8008, kind="cast", info="HTTP/1.1 200 OK")]
    verdict, conf, _ = assess("low", ports, "Google Cast/Nest 裝置: Bedroom Display")
    assert verdict == "IDENTIFIED_BENIGN"
    assert conf == "high"


def test_no_ports_camera_platform_is_indeterminate_cloud():
    verdict, conf, summary = assess("medium", [], None)
    assert verdict == "INDETERMINATE_CLOUD"
    assert "流量" in summary  # 提示需流量分析


def test_open_http_no_signature_is_unclear():
    ports = [PortResult(port=80, kind="http", info="Server=nginx")]
    verdict, _, _ = assess("none", ports, None)
    assert verdict == "OPEN_UNCLEAR"


# --------------------------- SSDP 攝影機判斷 --------------------------- #
def test_ssdp_camera_match():
    assert ssdp_looks_like_camera("Hikvision-Webs/1.0; urn:onvif:service") is True
    assert ssdp_looks_like_camera("ipcamera MediaServer") is True


def test_ssdp_router_is_not_camera():
    # 回歸測試：路由器的 WANIPConnection 服務含 'ipc'，不應誤判為攝影機
    desc = ("AsusWRT/388 UPnP/1.1 MiniUPnPd/2.2.0; "
            "urn:schemas-upnp-org:service:WANIPConnection:1")
    assert ssdp_looks_like_camera(desc) is False
