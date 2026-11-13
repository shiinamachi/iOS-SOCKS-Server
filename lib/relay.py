"""Fast bidirectional TCP relay built directly on asyncio protocols.

Compared to a StreamReader/StreamWriter copy loop this avoids an extra buffer
copy, a task switch and a drain() round trip for every chunk: received data is
handed straight to the other side's transport. Back-pressure is implemented by
pausing reads on one side while the other side's write buffer is full.

TCP half-close is preserved: when one side sends EOF, the EOF is forwarded and
data keeps flowing in the other direction until that side finishes too.
"""

import asyncio
from typing import Callable, Optional

# Per-direction user-space buffer before reading from the other side pauses.
WRITE_BUFFER_HIGH = 256 * 1024
# How often idle connections are checked (seconds, upper bound).
IDLE_CHECK_INTERVAL = 30.0


class RelayProtocol(asyncio.Protocol):
    """One side of a relay; forwards everything it receives to its peer."""

    def __init__(self, stat_fn: Callable[[int], None]):
        self._stat_fn = stat_fn
        self.transport: Optional[asyncio.Transport] = None
        self.peer: Optional["RelayProtocol"] = None
        self.got_eof = False
        self.activity = 0
        self._pending: list[bytes] = []
        self._pending_eof = False
        self.closed: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    # asyncio.Protocol API

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self.transport = transport
        transport.set_write_buffer_limits(high=WRITE_BUFFER_HIGH)

    def data_received(self, data: bytes) -> None:
        self.activity += 1
        self._stat_fn(len(data))
        if self.peer is None:
            # Server-speaks-first protocols may send data before the relay is
            # wired up; keep it until then.
            self._pending.append(data)
        else:
            self.peer.transport.write(data)

    def eof_received(self) -> bool:
        self.got_eof = True
        if self.peer is None:
            self._pending_eof = True
        else:
            self._forward_eof()
        # Keep the transport open so the other direction can finish.
        return True

    def pause_writing(self) -> None:
        if self.peer is not None:
            self.peer.transport.pause_reading()

    def resume_writing(self) -> None:
        if self.peer is not None:
            self.peer.transport.resume_reading()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if not self.closed.done():
            self.closed.set_result(None)
        peer = self.peer
        if peer is not None and not peer.transport.is_closing():
            if exc is None:
                peer.transport.close()
            else:
                peer.transport.abort()

    # Relay plumbing

    def _forward_eof(self) -> None:
        peer = self.peer
        if (
            peer.got_eof
            or peer.transport.is_closing()
            or not peer.transport.can_write_eof()
        ):
            # Both directions are finished: close (buffered data is flushed).
            self.transport.close()
            peer.transport.close()
        else:
            peer.transport.write_eof()

    def attach(self, peer: "RelayProtocol") -> None:
        self.peer = peer
        pending, self._pending = self._pending, []
        for data in pending:
            peer.transport.write(data)
        if self._pending_eof:
            self._forward_eof()


def adopt_transport(
    transport: asyncio.Transport,
    stat_fn: Callable[[int], None],
    buffered: bytes = b"",
    eof: bool = False,
) -> RelayProtocol:
    """Move an already-connected transport (e.g. from asyncio streams) onto a
    RelayProtocol. `buffered`/`eof` carry over what the old protocol had
    already read but not consumed."""
    protocol = RelayProtocol(stat_fn)
    transport.set_protocol(protocol)
    protocol.connection_made(transport)
    if buffered:
        protocol.data_received(buffered)
    if eof:
        protocol.eof_received()
    # The previous protocol may have paused reading when its buffer filled up.
    transport.resume_reading()
    return protocol


async def relay(
    a: RelayProtocol, b: RelayProtocol, idle_timeout: Optional[float] = None
) -> None:
    """Wire two sides together and wait until both are closed."""
    a.attach(b)
    b.attach(a)
    for side in (a, b):
        # A side that disconnected before the relay was wired up.
        if side.closed.done() and not side.peer.transport.is_closing():
            side.peer.transport.close()

    timer: Optional[asyncio.TimerHandle] = None
    if idle_timeout:
        loop = asyncio.get_running_loop()
        interval = min(idle_timeout, IDLE_CHECK_INTERVAL)
        state = {"last": -1, "idle": 0.0}

        def check() -> None:
            nonlocal timer
            activity = a.activity + b.activity
            if activity == state["last"]:
                state["idle"] += interval
                if state["idle"] >= idle_timeout:
                    a.transport.abort()
                    b.transport.abort()
                    return
            else:
                state["last"] = activity
                state["idle"] = 0.0
            timer = loop.call_later(interval, check)

        timer = loop.call_later(interval, check)

    try:
        await asyncio.gather(a.closed, b.closed)
    finally:
        if timer is not None:
            timer.cancel()
        for side in (a, b):
            if not side.transport.is_closing():
                side.transport.abort()
