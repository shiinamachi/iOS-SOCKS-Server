#!python3
# Socks5/HTTP Proxy server for Pythonista by @nneonneo
# Pretty statistics view and IPv6 support added by @philrosenthal

import logging
import socket
import threading

from lib.socks5_server import AsyncSocks5Handler
from lib.http_proxy_server import AsyncHTTPProxyHandler
from lib.proxy_server import AsyncProxyServer
from lib.status import StatusMonitor

logging.basicConfig(level=logging.ERROR)

## Configuration
"""
Typical modes of operation:
- If you have a VPN turned on and want to send traffic via the VPN, set USE_PHONE_VPN = True, USE_SYSTEM_DNS = True.
  Otherwise, set USE_PHONE_VPN = False and USE_SYSTEM_DNS = False.
- If you are using tethering, connect all clients to the hotspot and set PROXY_HOST = "172.20.10.1".
- If you are connecting this phone and clients to some other WiFi network, set PROXY_HOST to this phone's address
  on that WiFi network and set USE_SYSTEM_DNS = False.
"""

# IP over which the proxy will be available (default: iOS tethering IP; set to a WiFi IP address if this will be accessed over WiFi)
PROXY_HOST = "172.20.10.1"
# IP over which the proxy will attempt to connect to the Internet (will be autodetected from available networks)
CONNECT_HOST_IPV4 = "0.0.0.0"
CONNECT_HOST_IPV6 = None
# How often to check whether the outbound (cellular/VPN) address changed (seconds)
ADDRESS_CHECK_INTERVAL = 5
# Time out connections after being idle for this long (in seconds; None to disable)
IDLE_TIMEOUT = 1800
# Host to listen on - 0.0.0.0 to listen on all interfaces
LISTEN_HOST = "0.0.0.0"
# Port numbers to listen on
SOCKS_PORT = 9876 # SOCKS5 server
HTTP_PORT = 9877 # HTTP Proxy server
WPAD_PORT = 8088 # WPAD proxy autodiscovery server

# Keep the screen from auto-locking while running (Pythonista and a-Shell).
# When the screen locks, iOS suspends the app and every connection stalls.
DISABLE_AUTO_LOCK = True

USE_PHONE_VPN = True
# VPNs tend to ship their own DNS resolvers; since iOS will send all traffic
# via the VPN by default, we can trust the system DNS if using the phone VPN.
USE_SYSTEM_DNS = USE_PHONE_VPN
CUSTOM_RESOLVERS = []

## End of configuration

DEFAULT_RESOLVERS = [
    "1.0.0.1",
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8844",
]



def make_resolver():
    """Return a dnspython resolver, or None to use the system resolver."""
    if USE_SYSTEM_DNS:
        return None
    try:
        # TODO: configurable DNS (or find a way to use the cell network's own DNS)
        from dns import asyncresolver
    except ImportError:
        # pip install dnspython
        print("Warning: dnspython not available; falling back to system DNS")
        return None
    resolver = asyncresolver.Resolver(configure=False)
    resolver.nameservers += CUSTOM_RESOLVERS or DEFAULT_RESOLVERS
    return resolver


initial_output = ""
# Outbound addresses are re-detected while running (see watch_outbound_addresses)
AUTODETECT_ADDRESSES = False
IPV6_CANDIDATE = None
try:
    from lib import netinfo

    net = netinfo.detect(USE_PHONE_VPN)
    if net.proxy_host:
        PROXY_HOST = net.proxy_host
        initial_output += net.proxy_host_message + "\n"
    else:
        initial_output += "Warning: could not get WiFi address; assuming %s\n" % PROXY_HOST
    for message in net.messages:
        initial_output += message + "\n"

    if net.ipv4:
        CONNECT_HOST_IPV4 = net.ipv4
        initial_output += "Will connect to IPv4 servers over interface %s at %s\n" % (
            net.ipv4_iface,
            net.ipv4,
        )
    if net.ipv6_candidate:
        IPV6_CANDIDATE = net.ipv6_candidate
        initial_output += "Will connect to IPv6 servers over interface %s at %s\n" % (
            net.ipv6_iface,
            net.ipv6_candidate,
        )
        error = netinfo.probe_ipv6(net.ipv6_candidate)
        if error:
            initial_output += error + "\n"
            CONNECT_HOST_IPV6 = None
        else:
            CONNECT_HOST_IPV6 = net.ipv6_candidate
    AUTODETECT_ADDRESSES = True
    print(initial_output)
except Exception as e:
    logging.error("Address detection failed: %s: %s", type(e).__name__, e)
    import traceback

    traceback.print_exc()


async def watch_outbound_addresses(servers, address_error):
    """Follow changes of the cellular/VPN address.

    Outbound sockets are bound to a specific local address. When iOS changes
    it, every new connection would fail until the script is restarted.
    """
    import asyncio

    from lib import netinfo

    loop = asyncio.get_running_loop()
    ipv4, ipv6, candidate = CONNECT_HOST_IPV4, CONNECT_HOST_IPV6, IPV6_CANDIDATE
    ticks = 0
    while True:
        try:
            await asyncio.wait_for(address_error.wait(), ADDRESS_CHECK_INTERVAL)
        except asyncio.TimeoutError:
            pass
        address_error.clear()
        ticks += 1
        try:
            net = netinfo.detect(USE_PHONE_VPN)
        except Exception as e:
            logging.info("Address detection failed: %s: %s", type(e).__name__, e)
            continue

        new_ipv4 = net.ipv4 or "0.0.0.0"
        new_ipv6 = ipv6
        # Re-probe IPv6 when the address changed, and now and then if it failed.
        if net.ipv6_candidate != candidate or (
            candidate and ipv6 is None and ticks % 12 == 0
        ):
            candidate = net.ipv6_candidate
            new_ipv6 = None
            if candidate:
                error = await loop.run_in_executor(None, netinfo.probe_ipv6, candidate)
                new_ipv6 = None if error else candidate

        if (new_ipv4, new_ipv6) != (ipv4, ipv6):
            logging.warning(
                "Outbound address changed: IPv4 %s -> %s, IPv6 %s -> %s",
                ipv4,
                new_ipv4,
                ipv6,
                new_ipv6,
            )
            ipv4, ipv6 = new_ipv4, new_ipv6
            for server in servers:
                server.set_connect_hosts(ipv4, ipv6)


def create_wpad_server(hhost, hport, phost, pport):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class HTTPHandler(BaseHTTPRequestHandler):
        def do_HEAD(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()

        def do_GET(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()
            s.wfile.write(
                (
                    """
function FindProxyForURL(url, host)
{
   if (isInNet(host, "192.168.0.0", "255.255.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "172.16.0.0", "255.240.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
      return "DIRECT";
   } else {
      return "SOCKS5 %s:%d; SOCKS %s:%d";
   }
}
"""
                    % (phost, pport, phost, pport)
                )
                .lstrip()
                .encode()
            )

    HTTPServer.allow_reuse_address = True
    server = HTTPServer((hhost, hport), HTTPHandler)
    return server


def run_wpad_server(server):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    import asyncio
    import sys

    if sys.platform == "win32":
        # The UDP relay needs loop.add_reader(), which the default Windows
        # (proactor) loop lacks. Only relevant when testing on Windows.
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    wpad_server = create_wpad_server(LISTEN_HOST, WPAD_PORT, PROXY_HOST, SOCKS_PORT)

    initial_output += "PAC URL: http://{}:{}/wpad.dat\n".format(PROXY_HOST, WPAD_PORT)
    initial_output += "SOCKS Address: {}:{}\n".format(
        PROXY_HOST or LISTEN_HOST, SOCKS_PORT
    )
    initial_output += "HTTP Proxy Address: {}:{}\n".format(
        PROXY_HOST or LISTEN_HOST, HTTP_PORT
    )
    # Keep the screen from locking: once it locks, iOS suspends the app and
    # all proxied connections stall.
    from lib import ios

    if DISABLE_AUTO_LOCK and ios.set_idle_timer_disabled(True):
        initial_output += "Screen auto-lock is disabled while the proxy runs.\n"
    stats = StatusMonitor(initial_output)
    logging.getLogger().addHandler(stats)

    thread = threading.Thread(target=run_wpad_server, args=(wpad_server,))
    thread.daemon = True
    thread.start()

    async def main():
        address_error = asyncio.Event()
        servers = [
            AsyncProxyServer(
                handler_class,
                listen_hosts=LISTEN_HOST,
                listen_port=port,
                traffic_stats=stats,
                resolver=make_resolver(),
                connect_host_ipv4=CONNECT_HOST_IPV4,
                connect_host_ipv6=CONNECT_HOST_IPV6,
                idle_timeout=IDLE_TIMEOUT,
                address_error=address_error,
            )
            for handler_class, port in (
                (AsyncSocks5Handler, SOCKS_PORT),
                (AsyncHTTPProxyHandler, HTTP_PORT),
            )
        ]
        # Keep references to the tasks so they are not garbage collected.
        tasks = [asyncio.create_task(server.run()) for server in servers]
        if AUTODETECT_ADDRESSES:
            tasks.append(
                asyncio.create_task(watch_outbound_addresses(servers, address_error))
            )
        try:
            await stats.render_forever()
        finally:
            for server in servers:
                server.close()
            for task in tasks:
                task.cancel()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down.")
    finally:
        if DISABLE_AUTO_LOCK:
            ios.set_idle_timer_disabled(False)
        wpad_server.shutdown()
        # Release the listening socket; otherwise it leaks inside a-Shell's
        # process and the next run cannot bind the WPAD port.
        wpad_server.server_close()
