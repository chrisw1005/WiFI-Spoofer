from wifi_cut.gateway import (
    parse_route_output,
    parse_ipconfig_gateway,
    _default_gateway_from_routes,
)


def test_parse_route_output():
    mock_output = """\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,AUTOCONF>
"""
    ip, iface = parse_route_output(mock_output)
    assert ip == "192.168.1.1"
    assert iface == "en0"


def test_parse_route_output_different_gateway():
    mock_output = """\
   route to: default
    gateway: 10.0.0.1
  interface: en1
"""
    ip, iface = parse_route_output(mock_output)
    assert ip == "10.0.0.1"
    assert iface == "en1"


def test_parse_ipconfig_gateway():
    mock_output = """\
Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.50.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.1
"""
    assert parse_ipconfig_gateway(mock_output) == "192.168.50.1"


def test_parse_ipconfig_gateway_different():
    mock_output = """\
Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 10.0.0.50
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.0.1
"""
    assert parse_ipconfig_gateway(mock_output) == "10.0.0.1"


# Real scapy route table shape: (net, mask, gw, iface, outip, metric).
# Default routes have net == 0 and mask == 0. The gateway must come from the
# default route belonging to the scanning interface (conf.iface), not from the
# first "Default Gateway" line in ipconfig (which could belong to a VPN/virtual
# adapter listed earlier).
def test_default_gateway_from_routes_picks_iface_default():
    routes = [
        (3232248320, 4294967040, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),  # connected
        (1681969273, 4294967295, "0.0.0.0", r"\Device\NPF_TS", "100.83.192.11", 5),     # Tailscale /32
        (0, 0, "192.168.50.1", r"\Device\NPF_ETH", "192.168.50.64", 35),                # our default
        (0, 0, "192.168.0.1", r"\Device\NPF_ETH2", "192.168.0.11", 50),                 # other iface default
    ]
    assert _default_gateway_from_routes(r"\Device\NPF_ETH", routes) == "192.168.50.1"


def test_default_gateway_from_routes_lowest_metric_wins():
    routes = [
        (0, 0, "10.0.0.254", "ifA", "10.0.0.5", 100),
        (0, 0, "10.0.0.1", "ifA", "10.0.0.5", 20),
    ]
    assert _default_gateway_from_routes("ifA", routes) == "10.0.0.1"


def test_default_gateway_from_routes_raises_when_no_default():
    routes = [
        (3232248320, 4294967040, "0.0.0.0", r"\Device\NPF_ETH", "192.168.50.64", 291),
    ]
    try:
        _default_gateway_from_routes(r"\Device\NPF_ETH", routes)
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError when interface has no default route")
