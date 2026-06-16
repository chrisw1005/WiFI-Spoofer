from wifi_cut.scanner import calculate_cidr, _netmask_from_routes


def test_calculate_cidr_24():
    assert calculate_cidr("192.168.1.50", "255.255.255.0") == "192.168.1.0/24"


def test_calculate_cidr_16():
    assert calculate_cidr("10.0.5.100", "255.255.0.0") == "10.0.0.0/16"


# Real scapy route table captured on a machine running Tailscale (a /32 VPN
# adapter) + WSL vEthernet alongside the active Ethernet LAN. The old code
# parsed `ipconfig` and grabbed Tailscale's 100.83.192.11/32, scanning a
# single-host network and finding 0 devices. The mask must come from the
# interface actually being scanned. Rows: (net, mask, gw, iface, outip, metric).
_ROUTES_WITH_VPN = [
    (0, 0, "192.168.50.1", r"\Device\NPF_ETH", "192.168.50.64", 35),       # default route
    (1681969273, 4294967295, "0.0.0.0", r"\Device\NPF_TS", "100.83.192.11", 5),  # Tailscale /32
    (1682501144, 4294967295, "0.0.0.0", r"\Device\NPF_TS", "100.83.192.11", 5),  # Tailscale /32
    (3232248320, 4294967040, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),  # 192.168.50.0/24
    (3232248384, 4294967295, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),  # host /32
    (3232248575, 4294967295, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),  # broadcast /32
    (3758096384, 4026531840, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),  # 224.0.0.0/4 multicast
    (2886815744, 4294963200, "0.0.0.0", r"\Device\NPF_WSL", "172.17.80.1", 5256),   # WSL /20
    (4294967295, 4294967295, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),  # 255.255.255.255/32
]


def test_netmask_from_routes_ignores_vpn_and_picks_connected_subnet():
    # Must return the Ethernet /24, NOT Tailscale's /32 that the old parser hit.
    assert _netmask_from_routes("192.168.50.64", _ROUTES_WITH_VPN) == "255.255.255.0"


def test_netmask_from_routes_clean_24():
    routes = [
        (0, 0, "10.0.0.1", "if0", "10.0.0.5", 25),
        (167772160, 4294967040, "0.0.0.0", "if0", "10.0.0.5", 25),  # 10.0.0.0/24
    ]
    assert _netmask_from_routes("10.0.0.5", routes) == "255.255.255.0"


def test_netmask_from_routes_raises_when_only_host_routes():
    routes = [
        (1681969273, 4294967295, "0.0.0.0", "ts", "100.83.192.11", 5),  # only a /32
    ]
    try:
        _netmask_from_routes("100.83.192.11", routes)
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError when no connected subnet exists")
