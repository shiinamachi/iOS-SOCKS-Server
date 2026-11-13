"""SOCKS5 UDP relay (UDP ASSOCIATE).

Design notes:

* Clients send SOCKS5-encapsulated datagrams to one shared UDP socket bound to
  a fixed port (by default the same number as the SOCKS TCP port). Because the
  port does not change between runs, clients that keep using an association
  across a proxy restart (ProxiFyre only notices a dead control connection
  when the FIN/RST reaches it and otherwise keeps a session for 5 minutes)
  keep working as soon as the proxy is back, instead of sending into a port
  that no longer exists. If the port is taken, we fall back to one random
  port per association, which is what the original implementation did.

* Every client address (ip, port) gets its own session with its own outbound
  sockets, so replies from the Internet are mapped back to the right client.
  Replies are only accepted from addresses the session has sent to.

* Sockets are driven with loop.add_reader() and drained in batches into one
  reusable buffer. This avoids an asyncio Task and several copies per
  datagram, which matters for VPN tunnels (WireGuard/MASQUE) running over the
  relay at thousands of packets per second.
"""

import asyncio
import errno
import ipaddress
import logging
import socket
import time
from collections import Counter
from typing import Optional

logger = logging.getLogger("socks5.udp")

# Drop client sessions idle for this long (seconds). Matches ProxiFyre.
SESSION_TIMEOUT = 300.0
SWEEP_INTERVAL = 30.0
MAX_SESSIONS = 2048
MAX_REMOTES_PER_SESSION = 4096
# Datagrams handled per readiness callback before yielding to the loop.
RECV_BATCH = 64
SOCKET_BUFFER = 2 * 1024 * 1024
MAX_DATAGRAM = 65535

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

HAS_SENDMSG = hasattr(socket.socket, "sendmsg")
_TRANSIENT = (BlockingIOError, InterruptedError)


def unmap_ipv4(host: str) -> str:
    """'::ffff:1.2.3.4' -> '1.2.3.4'."""
    if host.startswith("::ffff:") and "." in host:
        return host[7:]
    return host


def _family_of(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _tune(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, SOCKET_BUFFER)
        except OSError:
            pass


def _reply_header(addr: tuple[str, int]) -> bytes:
    host, port = addr
    if ":" in host:
        return b"\0\0\0\x04" + socket.inet_pton(socket.AF_INET6, host) + port.to_bytes(2, "big")
    return b"\0\0\0\x01" + socket.inet_pton(socket.AF_INET, host) + port.to_bytes(2, "big")


class UdpSession:
    """Outbound side for one client address."""

    def __init__(self, endpoint: "UdpEndpoint", client_addr: tuple[str, int]):
        self.endpoint = endpoint
        self.relay = endpoint.relay
        self.client_addr = client_addr
        # family -> (socket, local address it is bound to)
        self.socks: dict[int, tuple[socket.socket, str]] = {}
        # remote (host, port) -> SOCKS5 reply header for datagrams from it
        self.remotes: dict[tuple[str, int], bytes] = {}
        self.last_active = time.monotonic()

    def send(self, family: int, payload, dst: tuple[str, int]) -> None:
        local = self.relay.local_host(family)
        if local is None:
            return  # no outbound route for this address family
        entry = self.socks.get(family)
        if entry is None or entry[1] != local:
            # First use, or the outbound address changed: (re)bind.
            self._close_socket(family)
            entry = self._open_socket(family, local)
        header = self.remotes.get(dst)
        if header is None:
            if len(self.remotes) >= MAX_REMOTES_PER_SESSION:
                self.remotes.clear()
            header = self.remotes[dst] = _reply_header(dst)
        try:
            entry[0].sendto(payload, dst)
        except _TRANSIENT:
            pass  # socket buffer full: drop, like a congested link would
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL:
                self._close_socket(family)
                self.relay.address_error()
            logger.debug("udp send to %s failed: %s", dst, e)

    def _open_socket(self, family: int, local: str) -> tuple[socket.socket, str]:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            _tune(sock)
            sock.bind((local, 0))
        except OSError as e:
            sock.close()
            if e.errno == errno.EADDRNOTAVAIL:
                self.relay.address_error()
            raise
        self.relay.loop.add_reader(sock.fileno(), self._on_readable, sock)
        entry = self.socks[family] = (sock, local)
        return entry

    def _close_socket(self, family: int) -> None:
        entry = self.socks.pop(family, None)
        if entry is not None:
            self.relay.loop.remove_reader(entry[0].fileno())
            entry[0].close()

    def _on_readable(self, sock: socket.socket) -> None:
        relay = self.relay
        buf, mv = relay.buf, relay.mv
        remotes = self.remotes
        received = 0
        for _ in range(RECV_BATCH):
            try:
                n, addr = sock.recvfrom_into(buf)
            except _TRANSIENT:
                break
            except OSError:
                break
            header = remotes.get(addr[:2])
            if header is None:
                continue  # not a host this client talked to
            received += n
            self.endpoint.send_to_client(header, mv[:n], self.client_addr)
        if received:
            self.last_active = time.monotonic()
            relay.stats.add_inbound(received)

    def close(self) -> None:
        for family in list(self.socks):
            self._close_socket(family)


class UdpEndpoint:
    """Client-facing UDP socket: shared (fixed port) or per association."""

    def __init__(self, relay: "UdpRelay", sock: socket.socket, client_ip: Optional[str]):
        self.relay = relay
        self.sock = sock
        # None for the shared socket; else the only client IP accepted.
        self.client_ip = client_ip
        self.port = sock.getsockname()[1]
        self.sessions: dict[tuple[str, int], UdpSession] = {}
        self._full_warned = False
        relay.loop.add_reader(sock.fileno(), self._on_readable)

    def send_to_client(self, header: bytes, data, client_addr) -> None:
        try:
            if HAS_SENDMSG:
                self.sock.sendmsg([header, data], (), 0, client_addr)
            else:
                self.sock.sendto(header + bytes(data), client_addr)
        except OSError:
            pass  # buffer full or client gone: drop

    def _session_for(self, addr: tuple[str, int]) -> Optional[UdpSession]:
        session = self.sessions.get(addr)
        if session is not None:
            return session
        if self.client_ip is not None:
            if unmap_ipv4(addr[0]) != self.client_ip:
                return None
        elif not self.relay.client_allowed(unmap_ipv4(addr[0])):
            return None
        if len(self.sessions) >= MAX_SESSIONS:
            if not self._full_warned:
                logger.warning("too many UDP sessions; dropping new ones")
                self._full_warned = True
            return None
        session = self.sessions[addr] = UdpSession(self, addr)
        return session

    def _on_readable(self) -> None:
        relay = self.relay
        buf, mv = relay.buf, relay.mv
        sent = 0
        now = None
        for _ in range(RECV_BATCH):
            try:
                n, addr = self.sock.recvfrom_into(buf)
            except _TRANSIENT:
                break
            except OSError:
                break
            session = self._session_for(addr[:2])
            if session is None:
                continue
            # SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
            if n < 10 or mv[2] != 0:
                continue  # too short, or fragmented (unsupported)
            atyp = mv[3]
            try:
                if atyp == ATYP_IPV4:
                    family = socket.AF_INET
                    dst = (socket.inet_ntop(family, mv[4:8]), (mv[8] << 8) | mv[9])
                    offset = 10
                elif atyp == ATYP_IPV6:
                    if n < 22:
                        continue
                    family = socket.AF_INET6
                    dst = (socket.inet_ntop(family, mv[4:20]), (mv[20] << 8) | mv[21])
                    offset = 22
                elif atyp == ATYP_DOMAIN:
                    length = mv[4]
                    offset = 5 + length + 2
                    if n < offset:
                        continue
                    host = bytes(mv[5 : 5 + length]).decode()
                    port = (mv[offset - 2] << 8) | mv[offset - 1]
                    relay.send_via_domain(session, host, port, bytes(mv[offset:n]))
                    continue
                else:
                    continue
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            if now is None:
                now = time.monotonic()
            session.last_active = now
            sent += n - offset
            try:
                session.send(family, mv[offset:n], dst)
            except OSError as e:
                logger.debug("udp: cannot open outbound socket: %s", e)
        if sent:
            relay.stats.add_outbound(sent)

    def sweep(self, now: float) -> None:
        for addr, session in list(self.sessions.items()):
            if now - session.last_active > SESSION_TIMEOUT:
                session.close()
                del self.sessions[addr]

    def close(self) -> None:
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()
        self.relay.loop.remove_reader(self.sock.fileno())
        self.sock.close()


class UdpRelay:
    """All UDP associations of one AsyncProxyServer."""

    def __init__(self, server, port: int):
        self.server = server
        self.port = port
        self.loop = asyncio.get_running_loop()
        self.stats = server.traffic_stats
        self.buf = bytearray(MAX_DATAGRAM)
        self.mv = memoryview(self.buf)
        self.shared: dict[int, UdpEndpoint] = {}
        self._shared_failed: set[int] = set()
        self._private: set[UdpEndpoint] = set()
        self._associated: Counter[str] = Counter()
        self._allowed_cache: dict[str, bool] = {}
        self._tasks: set[asyncio.Task] = set()
        self._sweeper: Optional[asyncio.TimerHandle] = None

    # Policy

    def local_host(self, family: int) -> Optional[str]:
        """Local address to send from, or None if the family is disabled."""
        ipv4 = self.server.connect_host_ipv4
        ipv6 = self.server.connect_host_ipv6
        if ipv4 is None and ipv6 is None:
            return "0.0.0.0" if family == socket.AF_INET else "::"
        return ipv4 if family == socket.AF_INET else ipv6

    def client_allowed(self, ip: str) -> bool:
        """Accept datagrams without a live association from local networks
        (e.g. the hotspot) and from clients that associated in this run."""
        if ip in self._associated:
            return True
        allowed = self._allowed_cache.get(ip)
        if allowed is None:
            try:
                allowed = not ipaddress.ip_address(ip).is_global
            except ValueError:
                allowed = False
            if len(self._allowed_cache) > 4096:
                self._allowed_cache.clear()
            self._allowed_cache[ip] = allowed
        return allowed

    def address_error(self) -> None:
        event = getattr(self.server, "address_error", None)
        if event is not None:
            event.set()

    # Associations

    def open_shared(self, family: int) -> Optional[UdpEndpoint]:
        """Bind the fixed-port socket for `family`. Done when the server starts
        so that datagrams of associations from before a restart are accepted
        right away."""
        endpoint = self.shared.get(family)
        if endpoint is None and self.port and family not in self._shared_failed:
            try:
                endpoint = self.shared[family] = self._open_endpoint(
                    family, "::" if family == socket.AF_INET6 else "0.0.0.0", self.port, None
                )
                self._ensure_sweeper()
            except OSError as e:
                logger.warning(
                    "UDP port %d unavailable (%s); using a random port per association",
                    self.port,
                    e,
                )
                self._shared_failed.add(family)
        return endpoint

    def associate(self, local_ip: str, client_ip: str) -> UdpEndpoint:
        family = _family_of(local_ip)
        endpoint = self.open_shared(family)
        if endpoint is None:
            endpoint = self._open_endpoint(family, local_ip, 0, client_ip)
            self._private.add(endpoint)
        self._associated[client_ip] += 1
        self._ensure_sweeper()
        return endpoint

    def release(self, endpoint: UdpEndpoint, client_ip: str) -> None:
        self._associated[client_ip] -= 1
        if self._associated[client_ip] <= 0:
            del self._associated[client_ip]
        if endpoint in self._private:
            self._private.discard(endpoint)
            endpoint.close()

    def _open_endpoint(self, family, host, port, client_ip) -> UdpEndpoint:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            _tune(sock)
            sock.bind((host, port))
        except OSError:
            sock.close()
            raise
        return UdpEndpoint(self, sock, client_ip)

    # Domain destinations (rare; ProxiFyre and most clients send IPs)

    def send_via_domain(self, session: UdpSession, host: str, port: int, payload: bytes) -> None:
        task = self.loop.create_task(self._send_via_domain(session, host, port, payload))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send_via_domain(self, session, host, port, payload) -> None:
        try:
            resolved = await self.server.resolve_address(ATYP_DOMAIN, (host, port))
        except Exception as e:
            logger.info("udp: cannot resolve %s: %s", host, e)
            return
        if resolved.ipv6 and self.local_host(socket.AF_INET6) is not None:
            family, dst = socket.AF_INET6, resolved.ipv6
        elif resolved.ipv4 and self.local_host(socket.AF_INET) is not None:
            family, dst = socket.AF_INET, resolved.ipv4
        else:
            return
        try:
            session.send(family, payload, dst)
            self.stats.add_outbound(len(payload))
        except OSError as e:
            logger.debug("udp: cannot open outbound socket: %s", e)

    # Housekeeping

    def _endpoints(self):
        return list(self.shared.values()) + list(self._private)

    def _ensure_sweeper(self) -> None:
        if self._sweeper is None:
            self._sweeper = self.loop.call_later(SWEEP_INTERVAL, self._sweep)

    def _sweep(self) -> None:
        now = time.monotonic()
        for endpoint in self._endpoints():
            endpoint.sweep(now)
        self._sweeper = self.loop.call_later(SWEEP_INTERVAL, self._sweep)

    def close(self) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            self._sweeper = None
        for task in self._tasks:
            task.cancel()
        for endpoint in self._endpoints():
            endpoint.close()
        self.shared.clear()
        self._private.clear()
