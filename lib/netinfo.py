"""Detect which local addresses to listen on and to send outbound traffic from.

We want the WiFi/hotspot address so that clients know what IP to use, and the
non-WiFi (cellular or VPN) address so that we can force outbound traffic onto
that network. This lets the proxy forward traffic to the cell network even when
the WiFi network is internet-enabled but limited (e.g. firewalled).

iOS changes the cellular address from time to time (handover, reconnects,
IPv6 temporary address rotation), so detection is cheap and can be re-run
periodically; see `watch_outbound_addresses` in socks5.py.
"""

import ipaddress
import socket
from collections import defaultdict
from dataclasses import dataclass, field

IPV6_PROBE_HOST = "2606:4700:4700::1111"
IPV6_PROBE_TIMEOUT = 5

_NON_ROUTABLE_IPV6 = [
    ipaddress.ip_network(net)
    for net in (
        "ff00::/8",  # Multicast address range
        "fe80::/10",  # Link-local address range
        "fc00::/7",  # Unique local address range
        "::/8",  # Unspecified address range
        "2001:db8::/32",  # Documentation address range
        "2001::/32",  # Teredo address range
        "2002::/16",  # 6to4 address range
        "ff02::/16",  # Link-local multicast address range
    )
]


def is_globally_routable(ipv6_address: str) -> bool:
    addr = ipaddress.ip_address(ipv6_address.split("%", 1)[0])
    return not any(addr in network for network in _NON_ROUTABLE_IPV6)


@dataclass
class NetworkInfo:
    # Address clients should use to reach the proxy, if one was found.
    proxy_host: str | None = None
    proxy_host_message: str = ""
    # Outbound (cellular/VPN) addresses.
    ipv4: str | None = None
    ipv4_iface: str | None = None
    ipv6_candidate: str | None = None
    ipv6_iface: str | None = None
    messages: list[str] = field(default_factory=list)


def detect(use_phone_vpn: bool) -> NetworkInfo:
    """Classify interfaces. Does not touch the network (no IPv6 probe)."""
    from . import ifaddrs

    info = NetworkInfo()
    iftypes = defaultdict(list)
    for iface in ifaddrs.get_interfaces():
        if not iface.addr:
            continue
        if iface.name.startswith("lo"):
            continue
        # XXX implement better classification of interfaces
        if iface.name.startswith("en"):
            iftypes["en"].append(iface)
        elif iface.name.startswith("bridge"):
            iftypes["bridge"].append(iface)
        elif iface.name.startswith("utun"):
            iftypes["vpn"].append(iface)
        else:
            iftypes["cell"].append(iface)

    if iftypes["vpn"] and use_phone_vpn:
        info.messages.append("VPN use enabled (change with USE_PHONE_VPN)")
        iftypes["cell"] = iftypes["vpn"] + iftypes["cell"]

    def first_ipv4(ifaces):
        return next((i for i in ifaces if i.addr.family == socket.AF_INET), None)

    if iftypes["bridge"]:
        iface = first_ipv4(iftypes["bridge"])
        if iface:
            info.proxy_host = iface.addr.address
            info.proxy_host_message = (
                "Assuming proxy will be accessed over hotspot (%s) at %s"
                % (iface.name, iface.addr.address)
            )
    elif iftypes["en"]:
        iface = first_ipv4(iftypes["en"])
        if iface:
            info.proxy_host = iface.addr.address
            info.proxy_host_message = (
                "Assuming proxy will be accessed over WiFi (%s) at %s"
                % (iface.name, iface.addr.address)
            )

    if not iftypes["cell"]:
        return info

    iface_ipv4 = first_ipv4(iftypes["cell"])
    iface_ipv6 = None
    is_vpn = bool(iface_ipv4 and iface_ipv4.name.startswith("utun"))

    def ipv6_list(require_routable, name=None):
        return [
            i
            for i in iftypes["cell"]
            if i.addr.family == socket.AF_INET6
            and i.addr.address
            and (not require_routable or is_globally_routable(i.addr.address))
            and (name is None or i.name == name)
        ]

    if iface_ipv4:
        info.ipv4 = iface_ipv4.addr.address
        info.ipv4_iface = iface_ipv4.name
        # Prefer IPv6 addresses on the same interface as the IPv4 address. Take
        # the last one: that is the temporary address, for reduced tracking.
        candidates = ipv6_list(not is_vpn, iface_ipv4.name)
        iface_ipv6 = candidates[-1] if candidates else None

    if iface_ipv6 is None and not is_vpn:
        candidates = ipv6_list(True)
        iface_ipv6 = candidates[-1] if candidates else None

    if iface_ipv6:
        info.ipv6_candidate = iface_ipv6.addr.address
        info.ipv6_iface = iface_ipv6.name
    return info


def probe_ipv6(address: str) -> str | None:
    """Check that IPv6 works from `address`. Blocking; returns an error or None."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(IPV6_PROBE_TIMEOUT)
            sock.bind((address, 0))
            sock.connect((IPV6_PROBE_HOST, 80))
    except Exception as e:
        return "Failed to connect to %s over IPv6 due to: %s" % (IPV6_PROBE_HOST, e)
    return None
