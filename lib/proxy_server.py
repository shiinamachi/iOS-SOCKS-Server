""" General base class for proxies """

import asyncio
import errno
import logging
import random
import socket
from asyncio.staggered import staggered_race
from dataclasses import dataclass
from enum import IntEnum
from typing import Sequence, Type, Optional

from . import status
from .relay import RelayProtocol, adopt_transport, relay

logger = logging.getLogger("proxy")

SocketAddress = tuple[str, int]
# An established, not yet relayed, upstream connection.
Connection = RelayProtocol


def af_by_address(domain: str) -> int | None:
    try:
        socket.inet_pton(socket.AF_INET, domain)
        return socket.AF_INET
    except Exception:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, domain)
        return socket.AF_INET6
    except Exception:
        return None


@dataclass
class GenericAddress:
    ipv4: SocketAddress | None = None
    ipv6: SocketAddress | None = None


HAPPY_EYEBALLS_DELAY = 0.05  # seconds
CONNECT_TIMEOUT = 75  # seconds
RESOLVE_TIMEOUT = 10  # seconds
BIND_RETRY_INTERVAL = 2  # seconds


# XXX: should make this a more generic address type enum and convert from socks5
class Socks5AddressType(IntEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


class CustomSourceAddressResolver:
    def __init__(self, resolver: "dns.asyncresolver.Resolver", connect_host_ipv4: str | None, connect_host_ipv6: str | None):
        self.resolver = resolver
        self.all_nameservers = list(resolver.nameservers)
        self.resolver_source: str | None = None
        self.set_source(connect_host_ipv4, connect_host_ipv6)

    def set_source(self, connect_host_ipv4: str | None, connect_host_ipv6: str | None) -> None:
        if connect_host_ipv4 is None and connect_host_ipv6 is None:
            self.resolver_source = None
            self.resolver.nameservers = self.all_nameservers
            return

        resolvers_by_af: dict[int, list[str]] = {socket.AF_INET: [], socket.AF_INET6: []}
        for ns in self.all_nameservers:
            resolvers_by_af[af_by_address(ns)].append(ns)

        if resolvers_by_af[socket.AF_INET] and connect_host_ipv4 is not None:
            self.resolver_source = connect_host_ipv4
            self.resolver.nameservers = resolvers_by_af[socket.AF_INET]
        elif resolvers_by_af[socket.AF_INET6] and connect_host_ipv6 is not None:
            self.resolver_source = connect_host_ipv6
            self.resolver.nameservers = resolvers_by_af[socket.AF_INET6]
        else:
            raise Exception("Resolver does not have any suitable nameservers!")

    async def resolve_ipv4(self, domain):
        answer = await self.resolver.resolve(
            domain, "A", source=self.resolver_source
        )
        return [rr.address for rr in answer]

    async def resolve_ipv6(self, domain):
        answer = await self.resolver.resolve(
            domain, "AAAA", source=self.resolver_source
        )
        return [rr.address for rr in answer]


class DefaultAddressResolver:
    """Resolve with the system resolver (getaddrinfo in a worker thread)."""

    async def _resolve(self, addr, family):
        # getaddrinfo cannot be cancelled, but don't let a stuck lookup (e.g.
        # while the phone switches networks) hold the connection forever.
        info = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                addr, None, family=family, type=socket.SOCK_STREAM
            ),
            timeout=RESOLVE_TIMEOUT,
        )
        return list({item[4][0] for item in info})

    async def resolve_ipv4(self, addr):
        return await self._resolve(addr, socket.AF_INET)

    async def resolve_ipv6(self, addr):
        return await self._resolve(addr, socket.AF_INET6)


class AsyncProxyHandler:
    # Whether the server should bind the SOCKS5 UDP relay port on startup.
    uses_udp_relay = False

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        server: "AsyncProxyServer",
    ):
        self.reader = reader
        self.writer = writer
        self.server = server

        peer_addr = writer.get_extra_info("peername")
        if peer_addr is None:
            self.log_tag = "<unknown>"
        elif len(peer_addr) == 2:
            # IPv4
            self.log_tag = "%s:%s" % peer_addr
        elif len(peer_addr) == 4:
            # IPv6
            self.log_tag = "[%s]:%s" % peer_addr[:2]
        else:
            self.log_tag = "[%s]" % (peer_addr,)

    async def tcp_forward(self, upstream: Connection) -> None:
        """Relay data between the client and `upstream` until both close."""
        server = self.server
        transport = self.writer.transport
        if transport.is_closing():
            # The client went away while we were connecting.
            upstream.transport.abort()
            return

        # Take the client connection over from asyncio streams. Anything the
        # client already sent (e.g. a TLS ClientHello sent right after the
        # CONNECT request) is still in the StreamReader buffer.
        buffered = bytes(self.reader._buffer)
        self.reader._buffer.clear()
        client = adopt_transport(
            transport,
            server.traffic_stats.add_outbound,
            buffered=buffered,
            eof=self.reader.at_eof(),
        )
        server.track_transport(upstream.transport)
        try:
            await relay(client, upstream, server.idle_timeout)
        finally:
            server.untrack_transport(upstream.transport)

    async def handle(self) -> None:
        pass


class AsyncProxyServer:
    def __init__(
        self,
        handler_class: Type[AsyncProxyHandler],
        listen_hosts: str | Sequence[str] = ("::", "0.0.0.0"),
        listen_port: int = 9876,
        traffic_stats: status.TrafficStats | None = None,
        resolver: Optional["dns.asyncresolver.Resolver"] = None,
        connect_host_ipv4: str | None = None,
        connect_host_ipv6: str | None = None,
        idle_timeout: float | None = None,
        address_error: asyncio.Event | None = None,
    ):
        self.handler_class = handler_class
        self.idle_timeout = idle_timeout
        # Set when binding to the outbound address fails, so that the address
        # watcher re-checks the interfaces right away.
        self.address_error = address_error
        self.listen_hosts = listen_hosts
        self.listen_port = listen_port
        self.traffic_stats = traffic_stats or status.SimpleTrafficStats()
        self.resolver: DefaultAddressResolver | CustomSourceAddressResolver
        if resolver:
            self.resolver = CustomSourceAddressResolver(resolver, connect_host_ipv4, connect_host_ipv6)
        else:
            self.resolver = DefaultAddressResolver()
        self.connect_host_ipv4 = connect_host_ipv4
        self.connect_host_ipv6 = connect_host_ipv6
        self._server: asyncio.AbstractServer | None = None
        self._udp_relay = None
        self._transports: set[asyncio.BaseTransport] = set()

    async def _listen(self) -> asyncio.AbstractServer:
        """Bind the listening socket, retrying while the port is busy.

        A failed bind used to end this task silently, so the proxy looked
        alive but accepted nothing. A previous run that is still shutting
        down (or a socket leaked inside a-Shell's process) can hold the port
        for a while; keep retrying and say so on the status screen.
        """
        warned = False
        while True:
            try:
                server = await asyncio.start_server(
                    self.client_connected,
                    host=self.listen_hosts,
                    port=self.listen_port,
                    reuse_address=True,
                )
            except OSError as e:
                if e.errno != errno.EADDRINUSE:
                    logger.error("Cannot listen on port %d: %s", self.listen_port, e)
                    raise
                if not warned:
                    logger.error(
                        "Port %d is in use (previous run still open?); retrying...",
                        self.listen_port,
                    )
                    warned = True
                await asyncio.sleep(BIND_RETRY_INTERVAL)
                continue
            if warned:
                logger.warning("Listening on port %d", self.listen_port)
            return server

    async def run(self) -> None:
        self._server = await self._listen()
        if self.handler_class.uses_udp_relay:
            hosts = (
                [self.listen_hosts]
                if isinstance(self.listen_hosts, str)
                else self.listen_hosts
            )
            for family in {af_by_address(host) for host in hosts}:
                if family is not None:
                    self.udp_relay.open_shared(family)
        try:
            await self._server.serve_forever()
        finally:
            self.close()

    def set_connect_hosts(self, ipv4: str | None, ipv6: str | None) -> None:
        """Switch outbound traffic to new local addresses (e.g. after the
        cellular address changed). Existing connections are not affected."""
        if isinstance(self.resolver, CustomSourceAddressResolver):
            try:
                self.resolver.set_source(ipv4, ipv6)
            except Exception as e:
                logger.warning("Keeping old DNS source address: %s", e)
        self.connect_host_ipv4 = ipv4
        self.connect_host_ipv6 = ipv6

    @property
    def udp_relay(self) -> "UdpRelay":
        """UDP ASSOCIATE relay, created on first use. Its fixed UDP port is the
        same number as our TCP port."""
        if self._udp_relay is None:
            from .udp_relay import UdpRelay

            self._udp_relay = UdpRelay(self, self.listen_port)
        return self._udp_relay

    def close(self) -> None:
        """Stop listening and drop every open connection.

        a-Shell runs Python inside the app process, so anything left open here
        survives the script and keeps the ports busy until the app is killed.
        """
        if self._server is not None:
            self._server.close()
            self._server = None
        for transport in list(self._transports):
            transport.abort()
        self._transports.clear()
        if self._udp_relay is not None:
            self._udp_relay.close()
            self._udp_relay = None

    def track_transport(self, transport: asyncio.BaseTransport) -> None:
        self._transports.add(transport)

    def untrack_transport(self, transport: asyncio.BaseTransport) -> None:
        self._transports.discard(transport)

    async def client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        handler = self.handler_class(reader, writer, server=self)
        self.traffic_stats.add_connection()
        self.track_transport(writer.transport)
        try:
            await handler.handle()
        finally:
            self.untrack_transport(writer.transport)
            self.traffic_stats.remove_connection()

    async def _open_connection(
        self, address: SocketAddress, local_host: str | None
    ) -> Connection:
        loop = asyncio.get_running_loop()
        local_addr = (local_host, 0) if local_host is not None else None
        try:
            _, protocol = await asyncio.wait_for(
                loop.create_connection(
                    lambda: RelayProtocol(self.traffic_stats.add_inbound),
                    address[0],
                    address[1],
                    local_addr=local_addr,
                ),
                timeout=CONNECT_TIMEOUT,
            )
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL and self.address_error is not None:
                # Our outbound address is gone; have it re-detected now.
                self.address_error.set()
            raise
        return protocol

    async def ipv4_connect(self, address: SocketAddress) -> Connection:
        return await self._open_connection(address, self.connect_host_ipv4)

    async def ipv6_connect(self, address: SocketAddress) -> Connection:
        return await self._open_connection(address, self.connect_host_ipv6)

    async def tcp_connect(
        self, address_type: int, address: SocketAddress
    ) -> Connection:
        resolved = await self.resolve_address(address_type, address)

        if resolved.ipv4 is not None and resolved.ipv6 is not None:
            ipv6_addr = resolved.ipv6
            ipv4_addr = resolved.ipv4
            # happy eyeballs
            result, result_index, exceptions = await staggered_race(
                [
                    lambda: self.ipv6_connect(ipv6_addr),
                    lambda: self.ipv4_connect(ipv4_addr),
                ],
                delay=HAPPY_EYEBALLS_DELAY,
            )
            if not result:
                raise exceptions[0]
            return result
        elif resolved.ipv4 is not None:
            return await self.ipv4_connect(resolved.ipv4)
        elif resolved.ipv6 is not None:
            return await self.ipv6_connect(resolved.ipv6)
        else:
            raise Exception("Host %s could not be resolved" % (address,))

    async def dummy_resolve(self):
        raise Exception("address family not supported")

    async def _resolve_domain(self, address: SocketAddress) -> GenericAddress:
        domain, port = address

        result = GenericAddress()
        af = af_by_address(domain)
        if af == socket.AF_INET:
            result.ipv4 = address
            return result
        elif af == socket.AF_INET6:
            result.ipv6 = address
            return result

        if self.connect_host_ipv4 is None and self.connect_host_ipv6 is not None:
            ipv4_resolver = self.dummy_resolve()
        else:
            ipv4_resolver = self.resolver.resolve_ipv4(domain)

        if self.connect_host_ipv4 is not None and self.connect_host_ipv6 is None:
            ipv6_resolver = self.dummy_resolve()
        else:
            ipv6_resolver = self.resolver.resolve_ipv6(domain)

        ipv4, ipv6 = await asyncio.gather(
            ipv4_resolver,
            ipv6_resolver,
            return_exceptions=True,
        )
        if not isinstance(ipv4, BaseException) and ipv4:
            result.ipv4 = (random.choice(ipv4), port)
        if not isinstance(ipv6, BaseException) and ipv6:
            result.ipv6 = (random.choice(ipv6), port)
        return result

    async def resolve_address(
        self, address_type: int, address: SocketAddress
    ) -> GenericAddress:
        if address_type == Socks5AddressType.IPV4:
            result = GenericAddress(ipv4=address)
        elif address_type == Socks5AddressType.DOMAIN:
            result = await self._resolve_domain(address)
        elif address_type == Socks5AddressType.IPV6:
            result = GenericAddress(ipv6=address)

        if self.connect_host_ipv4 is None and self.connect_host_ipv6 is not None:
            result.ipv4 = None
        elif self.connect_host_ipv4 is not None and self.connect_host_ipv6 is None:
            result.ipv6 = None

        return result
