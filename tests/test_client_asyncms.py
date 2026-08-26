"""Client handling of an unsolicited kXR_attn(asyncms) (parity-audit §7.18).

A stock XRootD server may push an asynchronous message (kXR_attn with
actnum=kXR_asyncms, outer streamid {0,0}) at any moment — including while the
client is waiting for an operation's reply.  BriX's receive loop fell through
to the "unexpected response status" default and FAILED the whole operation.
It now surfaces the message (printable-sanitised, to stderr) and keeps
reading the real reply.

(Of the historical attn action codes, only asyncms and asynresp are still
active in the 5.6.9 baseline — verified in the stock XProtocol.hh; the rest
are marked "No longer supported".  asynresp already has its own waitresp
path, so asyncms is the one live unsolicited action this closes.)

The fault is injected by a transparent MITM proxy that splices the client to
the real anon server and, just before the first operation reply, prepends one
synthetic kXR_attn(asyncms) frame.

  * success   — the operation still succeeds through the injected attn frame
  * observability — the message text is surfaced on stderr, printable-only
  * security  — a message carrying terminal escape / control bytes is
                stripped to printable ASCII before it reaches the tty

Run:
    PYTHONPATH=tests pytest tests/test_client_asyncms.py -v
"""

import os
import socket
import struct
import subprocess
import threading

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")

kXR_attn = 4001
kXR_asyncms = 5002

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
    pytest.mark.skipif(not os.path.exists(XRDFS),
                       reason="brix-xrdfs not built (client/bin/xrdfs)"),
]


def _attn_frame(message: bytes) -> bytes:
    """A kXR_attn(asyncms) frame: streamid {0,0}, actnum + message body."""
    body = struct.pack("!i", kXR_asyncms) + message
    return struct.pack("!2sHI", b"\x00\x00", kXR_attn, len(body)) + body


class _AttnInjector(threading.Thread):
    """Transparent MITM: client <-> real anon server, injecting ONE
    kXR_attn(asyncms) frame into the downstream just before the first
    operation reply (first server frame with streamid >= 2)."""

    def __init__(self, backend, message):
        super().__init__(daemon=True)
        self._backend = backend
        self._frame = _attn_frame(message)
        self.injected = False
        self._stop = threading.Event()
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", 0))  # net-literal-allow: mock shim binds loopback ephemeral by design
        self._lsock.listen(4)
        self._lsock.settimeout(0.2)
        self.port = self._lsock.getsockname()[1]

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()
        self._lsock.close()

    def _serve(self, conn):
        try:
            back = socket.create_connection(self._backend, timeout=10)
        except OSError:
            conn.close()
            return
        # upstream client->server: raw passthrough
        threading.Thread(target=self._raw, args=(conn, back), daemon=True).start()
        # downstream server->client: frame-parse + inject
        try:
            self._downstream(back, conn)
        except OSError:
            pass
        for s in (conn, back):
            try:
                s.close()
            except OSError:
                pass

    @staticmethod
    def _raw(src, dst):
        try:
            while True:
                b = src.recv(65536)
                if not b:
                    break
                dst.sendall(b)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _recv_exact(self, sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def _downstream(self, back, conn):
        while True:
            hdr = self._recv_exact(back, 8)
            if hdr is None:
                break
            sid, _status, dlen = struct.unpack("!HHI", hdr)
            body = self._recv_exact(back, dlen) if dlen else b""
            if body is None:
                break
            if not self.injected and sid >= 2:
                conn.sendall(self._frame)   # push the async message first
                self.injected = True
            conn.sendall(hdr + body)

    def stop(self):
        self._stop.set()


def _stat_through(shim_port):
    return subprocess.run(
        [XRDFS, f"root://127.0.0.1:{shim_port}", "stat", "/"],  # net-literal-allow: URL targets the loopback mock shim
        capture_output=True, text=True, timeout=30)


class TestAsyncMs:

    def test_operation_survives_and_surfaces(self):
        """(success + observability) the stat completes through the injected
        message, and the message text appears on stderr."""
        shim = _AttnInjector((SERVER_HOST, NGINX_ANON_PORT),
                             b"BriX test: scheduled maintenance in 5 minutes")
        shim.start()
        try:
            res = _stat_through(shim.port)
            assert res.returncode == 0, (res.returncode, res.stderr)
            assert shim.injected, "shim never injected the attn frame"
            assert "scheduled maintenance in 5 minutes" in res.stderr, \
                res.stderr
        finally:
            shim.stop()

    def test_control_bytes_stripped(self):
        """(security-neg) a message with terminal-escape and control bytes is
        reduced to printable ASCII before it reaches the tty."""
        shim = _AttnInjector((SERVER_HOST, NGINX_ANON_PORT),
                             b"clean\x1b]0;pwned\x07\x00\x1b[31mRED text")
        shim.start()
        try:
            res = _stat_through(shim.port)
            assert res.returncode == 0, res.stderr
            # the server-message line carries no ESC / BEL / NUL
            line = [ln for ln in res.stderr.splitlines()
                    if "xrootd server message:" in ln]
            assert line, res.stderr
            assert all(("\x1b" not in line[0], "\x07" not in line[0]))
            assert all(("clean" in line[0], "RED text" in line[0]))
        finally:
            shim.stop()
