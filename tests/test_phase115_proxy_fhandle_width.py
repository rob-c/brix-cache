"""
tests/test_phase115_proxy_fhandle_width.py — Phase-115 W2.6: the proxy's
file-handle map is four bytes wide.

An XRootD fhandle is four OPAQUE bytes (``kXR_char fhandle[4]``).  The brix
proxy used to keep only ``body[0]`` of it in an ``int``, and carved two
sentinels — ``-1`` free, ``255`` open-pending — out of that same value space.
Nothing caught it because both ends of every existing proxy test are brix:
``BRIX_MAX_FILES`` is 16, so a brix data server's handles always fit in byte 0
and always leave bytes 1..3 zero.  Against a foreign server (dCache, EOS, the
stock xrootd daemon) all three consequences below are reachable, so every
server here issues handles a brix server never would.

Covered (3-per-change rule: success + error + security-negative):
  success       an upstream fhandle with all four bytes significant is
                relayed back byte-exact on read and on close
  security-neg  two upstream handles differing only OUTSIDE byte 0 must not
                alias: a read on the second file must not be answered with
                the first file's bytes
  security-neg  an upstream handle whose first byte is 0xff — the old
                open-pending sentinel — still counts as an open file, so the
                session cannot be re-pinned out from under it
  error         a kXR_ok open answering with fewer than four body bytes must
                not be written past (resp_body is ngx_alloc(dlen + 1)), and
                the unusable slot must be refused rather than guessed

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_phase115_proxy_fhandle_width.py -v
"""

import socket
import struct
import threading
import time

import pytest

from ephemeral_port import free_port
from settings import SERVER_HOST
from test_cms_locate_have import _CmsNode
from test_pgwrite_checksum import _handshake_login
from test_phase115_cms_select_proxy import (
    _FakeDataServer, _cms_port, _close, _open, _settle, gateway,  # noqa: F401
    kXR_error, kXR_login, kXR_ok, kXR_open, kXR_open_read, kXR_protocol,
)
from test_unix_auth_wire import _read

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-cms-select")]

H = SERVER_HOST

kXR_close = 3003
kXR_read = 3013
kXR_FileNotOpen = 3004          # XErrorCode, opcodes.h:153


# ---------------------------------------------------------------------------
# A data server that issues handles a brix server never would
# ---------------------------------------------------------------------------

class _FhServer:
    """Enough xrootd to bootstrap a proxy session, with SCRIPTED file handles.

    ``handles`` is a list of ``(fhandle_bytes, payload)`` consumed one entry
    per kXR_open.  Reads and closes are matched on the FULL four bytes — an
    exact-match server, which is what the wire protocol says the client must
    return — and every handle the proxy sends is recorded for assertion.  An
    unknown handle is answered kXR_error rather than served, so a truncated
    relay is visible to the client as well as to the test.

    ``short_open_dlen``, when set, makes kXR_open answer kXR_ok with a body of
    that many bytes: a malformed (or hostile) upstream.
    """

    def __init__(self, handles, short_open_dlen=None):
        self._handles = list(handles)
        self._short = short_open_dlen
        self._opened = 0
        self.seen_read = []
        self.seen_close = []
        self.accepted = 0
        self._lock = threading.Lock()
        self._closing = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = free_port(H)
        self._srv.bind((H, self.port))
        self._srv.listen(8)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def connections(self):
        with self._lock:
            return self.accepted

    def payload_of(self, fh):
        for handle, payload in self._handles:
            if handle == fh:
                return payload
        return None

    # -- wire ---------------------------------------------------------------

    @staticmethod
    def _exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    def _open_reply(self):
        with self._lock:
            idx = self._opened
            self._opened += 1
        if self._short is not None:
            return kXR_ok, b"\x5a" * self._short
        if idx >= len(self._handles):
            return kXR_error, (struct.pack(">I", kXR_FileNotOpen)
                               + b"out of handles\x00")
        return kXR_ok, self._handles[idx][0] + b"\x00" * 8   # fh, cpsize, cptype

    def _read_reply(self, fh):
        with self._lock:
            self.seen_read.append(fh)
        payload = self.payload_of(fh)
        if payload is None:
            return kXR_error, (struct.pack(">I", kXR_FileNotOpen)
                               + b"no such file handle\x00")
        return kXR_ok, payload

    def _reply_for(self, hdr):
        reqid = struct.unpack(">H", hdr[2:4])[0]
        if reqid == kXR_protocol:
            return kXR_ok, struct.pack(">II", 0x00000310, 0)
        if reqid == kXR_login:
            return kXR_ok, b"\x00" * 16
        if reqid == kXR_open:
            return self._open_reply()
        if reqid == kXR_read:
            return self._read_reply(hdr[4:8])
        if reqid == kXR_close:
            with self._lock:
                self.seen_close.append(hdr[4:8])
            if self.payload_of(hdr[4:8]) is None and self._short is None:
                return kXR_error, (struct.pack(">I", kXR_FileNotOpen)
                                   + b"no such file handle\x00")
            return kXR_ok, b""
        return kXR_ok, b""

    def _serve(self, conn):
        conn.settimeout(5)
        try:
            self._exact(conn, 20)                          # client hello
            conn.sendall(struct.pack(">HHI", 0, 0, 8)
                         + struct.pack(">II", 0x00000310, 1))
            while not self._closing:
                hdr = self._exact(conn, 24)
                dlen = struct.unpack(">I", hdr[20:24])[0]
                if dlen:
                    self._exact(conn, dlen)
                status, body = self._reply_for(hdr)
                conn.sendall(hdr[:2] + struct.pack(">HI", status, len(body))
                             + body)
        except (OSError, ConnectionError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _accept_loop(self):
        while not self._closing:
            try:
                conn, _peer = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.accepted += 1
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def close(self):
        self._closing = True
        try:
            self._srv.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def _pinned(gw, server, paths=b"r /fh"):
    """Register ``server`` as the CMS node owning ``paths`` and return it."""
    node = _CmsNode(_cms_port(gw), server.port, paths=paths)
    _settle(node)
    return node


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

def test_upstream_fhandle_round_trips_all_four_bytes(gateway):
    """success: a handle with every byte significant comes back to the server
    byte-exact on both read and close.  With a one-byte map the server saw
    b"\\x2a\\x00\\x00\\x00" — a handle it never issued."""
    payload = b"four significant bytes\n"
    fh = b"\x2a\x13\x37\x07"
    server = _FhServer([(fh, payload)])
    node = None
    try:
        node = _pinned(gateway, server)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/fh/a.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            client_fh = body[:4]

            status, data = _read(sock, client_fh, len(payload))
            assert status == kXR_ok and data == payload, (status, data)
            assert server.seen_read == [fh], \
                f"upstream saw {server.seen_read!r}, issued {fh!r}"

            assert _close(sock, client_fh)[0] == kXR_ok
            assert server.seen_close == [fh], \
                f"close relayed {server.seen_close!r}, issued {fh!r}"
        finally:
            sock.close()
    finally:
        if node is not None:
            node.close()
        server.close()


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def test_handles_differing_outside_byte_zero_do_not_alias(gateway):
    """security-neg: an upstream handle is a capability naming ONE open file,
    granted after the upstream authorized that path.  Two handles that share
    byte 0 must stay distinct on the wire — under the one-byte map a read on
    the second file was relayed with the FIRST file's exact handle, and this
    exact-match server answered it with the first file's bytes."""
    first = b"\x07\x00\x00\x00"
    second = b"\x07\x00\x00\x09"
    bytes_a = b"the file the client opened first\n"
    bytes_b = b"the file the client opened second\n"
    server = _FhServer([(first, bytes_a), (second, bytes_b)])
    node = None
    try:
        node = _pinned(gateway, server)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/fh/a.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            fh_a = body[:4]
            status, body = _open(sock, b"/fh/b.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            fh_b = body[:4]
            assert fh_a != fh_b, "the proxy handed out one handle for two files"

            status, data = _read(sock, fh_b, len(bytes_b))
            assert status == kXR_ok, (status, data)
            assert data != bytes_a, \
                "the second handle was relayed as the first file's handle"
            assert data == bytes_b, (status, data)
            assert server.seen_read == [second], \
                f"upstream saw {server.seen_read!r}, expected {second!r}"

            status, data = _read(sock, fh_a, len(bytes_a))
            assert status == kXR_ok and data == bytes_a, (status, data)
            assert server.seen_read == [second, first], server.seen_read
        finally:
            sock.close()
    finally:
        if node is not None:
            node.close()
        server.close()


def test_handle_starting_ff_still_holds_the_session_on_its_node(gateway):
    """security-neg: 0xff was the open-pending sentinel, so an upstream handle
    of b"\\xff..." made proxy_has_open_handles() report NO open file and the
    W2.1 re-pin moved the session to another data server — abandoning a live
    handle and re-using its bytes in a different server's handle namespace.
    A session holding a 0xff handle must refuse to move."""
    fh = b"\xff\x00\x00\x01"
    payload = b"open on the node the session is pinned to\n"
    server = _FhServer([(fh, payload)])
    other = _FakeDataServer("serve")
    here = there = None
    try:
        here = _pinned(gateway, server)
        there = _CmsNode(_cms_port(gateway), other.port, paths=b"r /elsewhere")
        _settle(there)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/fh/a.bin", kXR_open_read)
            assert status == kXR_ok, (status, body)
            held = body[:4]

            status, body = _open(sock, b"/elsewhere/x", kXR_open_read)
            assert status == kXR_error, \
                f"session moved while a 0xff handle was open: {status} {body!r}"
            time.sleep(0.2)
            assert other.connections() == 0, \
                "a session with an open file must not change node"

            status, data = _read(sock, held, len(payload))
            assert status == kXR_ok and data == payload, (status, data)
            assert server.seen_read == [fh], server.seen_read

            assert _close(sock, held)[0] == kXR_ok
            status, body = _open(sock, b"/elsewhere/x", kXR_open_read)
            assert status == kXR_ok, f"open after close: {status} {body!r}"
            assert other.connections() == 1
        finally:
            sock.close()
    finally:
        for node in (here, there):
            if node is not None:
                node.close()
        other.close()
        server.close()


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dlen", [1, 2, 3])
def test_short_open_response_is_refused_not_guessed(gateway, dlen):
    """error: resp_body is ngx_alloc(dlen + 1), so the old unconditional
    four-byte rewrite of the client-facing handle wrote past it whenever a
    kXR_ok open answered with 1..3 body bytes — a heap write whose length the
    UPSTREAM chose.  Such a body carries no usable handle either, so the slot
    is released: the session survives, and any request naming that handle is
    refused rather than translated against a zero-padded guess."""
    server = _FhServer([], short_open_dlen=dlen)
    node = None
    try:
        node = _pinned(gateway, server)
        sock = _handshake_login(H, gateway.port)
        try:
            status, body = _open(sock, b"/fh/short.bin", kXR_open_read)
            assert len(body) == dlen, (status, body)

            if status == kXR_ok:
                status, data = _read(sock, (body + b"\x00" * 4)[:4], 16)
                assert status == kXR_error, \
                    f"a handle-less open was honoured: {status} {data!r}"
                assert server.seen_read == [], \
                    f"a guessed handle reached the upstream: {server.seen_read!r}"

            # the worker is still alive and still serving this session
            status, body = _open(sock, b"/fh/again.bin", kXR_open_read)
            assert status in (kXR_ok, kXR_error), (status, body)
        finally:
            sock.close()
    finally:
        if node is not None:
            node.close()
        server.close()
