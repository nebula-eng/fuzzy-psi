"""Transport layer: byte-counted in-memory channels and a real TCP loopback.

The protocol code never touches sockets directly.  It writes framed byte
strings into a Channel and reads framed byte strings back.  Two
implementations exist:

* LocalChannel  - two queues, used by the benchmark harness.  It counts the
  exact same bytes that would hit the wire, including the 4-byte frame
  length, but avoids syscall noise in the timings.
* SocketChannel - a blocking TCP socket on 127.0.0.1 with length-prefixed
  framing, used by the `demo` command and by the end-to-end test so that the
  reported byte counts come from a real socket.

Framing is a 4-byte big-endian length followed by the payload.  Both
directions count framed bytes, so `bytes_sent` is what a packet capture
would show for a single connection (modulo Ethernet/IP/TCP headers, which we
do not count and say so in docs/EVALUATION.md).
"""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
from abc import ABC, abstractmethod

FRAME_HEADER_BYTES = 4
MAX_FRAME_BYTES = 1 << 28
DEFAULT_TIMEOUT = 120.0


class TransportError(RuntimeError):
    pass


def frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME_BYTES:
        raise TransportError("frame too large")
    return struct.pack(">I", len(payload)) + payload


class Channel(ABC):
    """A bidirectional message channel with byte counters."""

    def __init__(self) -> None:
        self.bytes_sent = 0
        self.bytes_recv = 0

    @abstractmethod
    def send(self, payload: bytes) -> None: ...

    @abstractmethod
    def recv(self) -> bytes: ...

    def close(self) -> None:  # pragma: no cover - trivial
        pass


class LocalChannel(Channel):
    def __init__(
        self,
        outbox: "queue.Queue[bytes]",
        inbox: "queue.Queue[bytes]",
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__()
        self._outbox = outbox
        self._inbox = inbox
        self._timeout = timeout
        self._closed = False

    def send(self, payload: bytes) -> None:
        if self._closed:
            raise TransportError("channel closed")
        blob = frame(payload)
        self.bytes_sent += len(blob)
        self._outbox.put(blob)

    def recv(self) -> bytes:
        if self._closed:
            raise TransportError("channel closed")
        try:
            blob = self._inbox.get(timeout=self._timeout)
        except queue.Empty as exc:
            raise TransportError("timed out waiting for a message") from exc
        self.bytes_recv += len(blob)
        return blob[FRAME_HEADER_BYTES:]

    def close(self) -> None:
        self._closed = True


def local_pair() -> tuple[LocalChannel, LocalChannel]:
    """Two connected in-memory channels (returns client, server)."""
    client_to_server: "queue.Queue[bytes]" = queue.Queue()
    server_to_client: "queue.Queue[bytes]" = queue.Queue()
    client = LocalChannel(client_to_server, server_to_client)
    server = LocalChannel(server_to_client, client_to_server)
    return client, server


class SocketChannel(Channel):
    def __init__(self, sock: socket.socket, timeout: float = DEFAULT_TIMEOUT) -> None:
        super().__init__()
        self._sock = sock
        self._sock.settimeout(timeout)
        try:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self._closed = False

    def _recv_exact(self, count: int) -> bytes:
        chunks = []
        remaining = count
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise TransportError("peer closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def send(self, payload: bytes) -> None:
        if self._closed:
            raise TransportError("channel closed")
        blob = frame(payload)
        self._sock.sendall(blob)
        self.bytes_sent += len(blob)

    def recv(self) -> bytes:
        if self._closed:
            raise TransportError("channel closed")
        header = self._recv_exact(FRAME_HEADER_BYTES)
        (length,) = struct.unpack(">I", header)
        if length > MAX_FRAME_BYTES:
            raise TransportError("frame too large")
        payload = self._recv_exact(length) if length else b""
        self.bytes_recv += FRAME_HEADER_BYTES + length
        return payload

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            self._sock.close()


class LoopbackServer:
    """One-shot TCP server bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self, handler, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._handler = handler
        self._timeout = timeout
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(timeout)
        self.port = self._listener.getsockname()[1]
        self.channel: SocketChannel | None = None
        self.error: BaseException | None = None
        self._finished = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="fpsi-server", daemon=True)

    def _serve(self) -> None:
        try:
            conn, _peer = self._listener.accept()
            self.channel = SocketChannel(conn, timeout=self._timeout)
            try:
                self._handler(self.channel)
            finally:
                self.channel.close()
        except BaseException as exc:  # recorded and re-raised in join()
            self.error = exc
        finally:
            try:
                self._listener.close()
            except OSError:
                pass
            self._finished.set()

    def start(self) -> "LoopbackServer":
        self._thread.start()
        return self

    def join(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        if not self._finished.wait(timeout):
            raise TransportError("server did not finish in time")
        if self.error is not None:
            raise TransportError(f"server failed: {self.error!r}") from self.error

    def stop(self) -> None:
        try:
            self._listener.close()
        except OSError:
            pass


def connect(port: int, host: str = "127.0.0.1", timeout: float = DEFAULT_TIMEOUT,
            attempts: int = 50) -> SocketChannel:
    last: OSError | None = None
    for _ in range(attempts):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            return SocketChannel(sock, timeout=timeout)
        except OSError as exc:  # listener may not be up yet
            last = exc
            time.sleep(0.02)
    raise TransportError(f"could not connect to {host}:{port}: {last}")
