from unittest.mock import patch

from wifi_cut import scanner
from wifi_cut.scanner import (
    is_usable_mac,
    parse_arp_table,
    parse_netneighbor_csv,
    discover_neighbors,
)


# --------------------------------------------------------------------------- #
# is_usable_mac
# --------------------------------------------------------------------------- #
def test_is_usable_mac_accepts_unicast():
    assert is_usable_mac("aa:bb:cc:dd:ee:ff")
    assert is_usable_mac("AA-BB-CC-DD-EE-FF")  # 大寫 + 連字號也可


def test_is_usable_mac_rejects_broadcast_zero_multicast():
    assert not is_usable_mac("")
    assert not is_usable_mac("00:00:00:00:00:00")
    assert not is_usable_mac("ff:ff:ff:ff:ff:ff")
    assert not is_usable_mac("01:00:5e:7f:ff:fa")  # IPv4 multicast
    assert not is_usable_mac("33:33:00:00:00:01")  # IPv6 multicast
    assert not is_usable_mac("aa:bb:cc")           # 長度不對


# --------------------------------------------------------------------------- #
# parse_arp_table — Windows 與 macOS 兩種格式
# --------------------------------------------------------------------------- #
WINDOWS_ARP = """
Interface: 192.168.50.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.50.1          aa-bb-cc-dd-ee-ff     dynamic
  192.168.50.23         11-22-33-44-55-66     dynamic
  192.168.50.255        ff-ff-ff-ff-ff-ff     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
"""

MACOS_ARP = """
gateway (192.168.50.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.50.23) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (192.168.50.99) at (incomplete) on en0 ifscope [ethernet]
broadcasthost (192.168.50.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""


def test_parse_arp_table_windows():
    pairs = parse_arp_table(WINDOWS_ARP)
    assert pairs == [
        ("192.168.50.1", "aa:bb:cc:dd:ee:ff"),
        ("192.168.50.23", "11:22:33:44:55:66"),
    ]


def test_parse_arp_table_macos_skips_incomplete():
    pairs = parse_arp_table(MACOS_ARP)
    assert pairs == [
        ("192.168.50.1", "aa:bb:cc:dd:ee:ff"),
        ("192.168.50.23", "11:22:33:44:55:66"),
    ]


# --------------------------------------------------------------------------- #
# parse_netneighbor_csv — 依狀態與 MAC 合法性過濾
# --------------------------------------------------------------------------- #
NETNEIGHBOR_CSV = (
    '"IPAddress","LinkLayerAddress","State"\r\n'
    '"192.168.50.1","AA-BB-CC-DD-EE-FF","Reachable"\r\n'
    '"192.168.50.23","11-22-33-44-55-66","Stale"\r\n'
    '"192.168.50.50","","Unreachable"\r\n'
    '"192.168.50.77","00-00-00-00-00-00","Incomplete"\r\n'
    '"239.255.255.250","01-00-5E-7F-FF-FA","Permanent"\r\n'
)


def test_parse_netneighbor_csv_filters_state_and_mac():
    pairs = parse_netneighbor_csv(NETNEIGHBOR_CSV)
    assert pairs == [
        ("192.168.50.1", "aa:bb:cc:dd:ee:ff"),
        ("192.168.50.23", "11:22:33:44:55:66"),
    ]


# --------------------------------------------------------------------------- #
# discover_neighbors — 過濾本網段、去重、補 hostname/vendor
# --------------------------------------------------------------------------- #
def test_discover_neighbors_filters_subnet_and_dedups():
    neighbors = [
        ("192.168.50.1", "aa:bb:cc:dd:ee:ff"),
        ("192.168.50.23", "11:22:33:44:55:66"),
        ("192.168.50.23", "11:22:33:44:55:66"),  # 重複
        ("10.0.0.5", "99:88:77:66:55:44"),        # 不在本網段
        ("192.168.50.0", "aa:aa:aa:aa:aa:aa"),    # 網路位址（非主機）
        ("192.168.50.255", "bb:bb:bb:bb:bb:bb"),  # 廣播位址（非主機）
    ]
    with patch.object(scanner, "populate_arp_cache"), \
         patch.object(scanner, "read_neighbor_table", return_value=neighbors), \
         patch.object(scanner, "resolve_hostname", return_value=None), \
         patch.object(scanner, "resolve_vendor", return_value="ACME"):
        devices = discover_neighbors("192.168.50.0/24")

    assert [d.ip for d in devices] == ["192.168.50.1", "192.168.50.23"]
    assert devices[0].mac == "aa:bb:cc:dd:ee:ff"
    assert devices[0].vendor == "ACME"
