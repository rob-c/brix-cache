"""tests/test_fuzz_binary_conformance.py — malformed-packet conformance for the
binary wire surfaces: the root:// / roots:// XRootD stream parser and the TLS
record layer fronting every roots:// / https:// / httpg:// listener.

XRootD leg — each frame from ``fuzz_corpus.xrootd_cases`` is replayed on a
fresh connection.  Frames tagged ``("raw", …)`` are sent verbatim in place of
the 20-byte handshake (handshake fuzzing); every other case is sent *after* a
valid handshake, exercising the frame reader, opcode dispatch and pre-auth
gate.  Robust-liveness invariant:

  * any reply the server frames must carry a sane ``dlen`` — a response header
    claiming a multi-gigabyte body is the signature of a length/sign-extension
    parser bug, so we cap it hard;
  * the server never crashes — a fresh connection per case (a refusal on a
    previously-up port fails loudly), plus a teardown handshake probe per port;
  * a clean close/reset or an empty reply is fine for a truncated frame.

TLS leg — junk records are pushed at each TLS listener; the server must reject
(alert or close) and stay up, never crash on a malformed ClientHello / record.

Runs against the always-on ``main`` fleet; collect-only works offline; each
port column skips if unreachable.

Run:
    PYTHONPATH=tests pytest tests/test_fuzz_binary_conformance.py -q
"""

from __future__ import annotations

import socket
import ssl
import struct

import pytest

import fuzz_corpus as fc
from settings import (
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_TOKEN_PORT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_WEBDAV_PORT,
    SERVER_HOST,
)

# Cleartext XRootD stream listeners (all begin with the same 20-byte handshake).
XRD_ENDPOINTS = [
    ("anon", NGINX_ANON_PORT),
    ("token", NGINX_TOKEN_PORT),
    ("gsi", NGINX_GSI_PORT),
]

# TLS listeners for record-layer junk.
TLS_ENDPOINTS = [
    ("roots", NGINX_GSI_TLS_PORT),
    ("webdav", NGINX_WEBDAV_PORT),
    ("httpg", NGINX_WEBDAV_GSI_TLS_PORT),
]

HANDSHAKE = struct.pack("!IIIII", 0, 0, 0, 4, 2012)
_CONNECT_TIMEOUT = 3.0
_READ_TIMEOUT = 0.6
_SANE_DLEN = 16 << 20  # server responses never legitimately exceed 16 MiB

_TLS_CTX = ssl._create_unverified_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE

_UP_CACHE: dict = {}


def _endpoint_up(port: int) -> bool:
    if port not in _UP_CACHE:
        try:
            s = socket.create_connection((SERVER_HOST, port), timeout=_CONNECT_TIMEOUT)
            s.close()
            _UP_CACHE[port] = True
        except OSError:
            _UP_CACHE[port] = False
    return _UP_CACHE[port]


def _skip_if_down(port: int):
    if not _endpoint_up(port):
        pytest.skip(f"listener {SERVER_HOST}:{port} unreachable")


def _drain(sock: socket.socket, limit: int = 4096) -> bytes:
    data = bytearray()
    try:
        while len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
        pass
    return bytes(data)


def _xrd_exchange(port: int, spec) -> bytes | None:
    """Replay one XRootD case; returns bytes read or None if torn down mid-send.
    ``ConnectionRefusedError`` propagates (endpoint was up → server died)."""
    sock = socket.create_connection((SERVER_HOST, port), timeout=_CONNECT_TIMEOUT)
    sock.settimeout(_READ_TIMEOUT)
    try:
        if isinstance(spec, tuple) and spec[0] == "raw":
            payload = spec[1]
        else:
            try:
                sock.sendall(HANDSHAKE)
                _drain(sock, limit=16)  # handshake reply
            except (BrokenPipeError, ConnectionResetError, OSError):
                return None
            payload = spec
        try:
            sock.sendall(payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return None
        # Half-close: a frame whose declared dlen exceeds the bytes we sent
        # would otherwise leave the server blocking for the missing body until
        # our read timeout.  The FIN makes it decide (error/close) at once.
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return _drain(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _tls_exchange(port: int, raw: bytes):
    """Push junk at a TLS listener; the connection completing without raising an
    unexpected error (alert/close/reset are all fine) is the liveness signal.

    We deliberately do *not* wait to read the peer's alert: a malformed/partial
    record legitimately leaves the server blocked awaiting more bytes, so a read
    would just burn the timeout on correct behaviour.  Server survival is proven
    by the fresh connection each case opens and by the module teardown probe."""
    sock = socket.create_connection((SERVER_HOST, port), timeout=_CONNECT_TIMEOUT)
    sock.settimeout(_READ_TIMEOUT)
    try:
        try:
            sock.sendall(raw)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _require_and_verify():
    ports = [p for _, p in XRD_ENDPOINTS + TLS_ENDPOINTS]
    if not any(_endpoint_up(p) for p in ports):
        pytest.skip("no binary/TLS fleet listener reachable")
    yield
    # Teardown: a stream port must still complete a handshake after the corpus.
    for name, port in XRD_ENDPOINTS:
        if not _endpoint_up(port):
            continue
        sock = socket.create_connection((SERVER_HOST, port), timeout=_CONNECT_TIMEOUT)
        sock.settimeout(_READ_TIMEOUT)
        try:
            sock.sendall(HANDSHAKE)
            reply = _drain(sock, limit=16)
        finally:
            sock.close()
        assert len(reply) >= 8, f"{name}:{port} did not survive the fuzz corpus"
    for name, port in TLS_ENDPOINTS:
        if not _endpoint_up(port):
            continue
        socket.create_connection((SERVER_HOST, port),
                                 timeout=_CONNECT_TIMEOUT).close()


# ---------------------------------------------------------------------------
# XRootD binary corpus × every cleartext stream endpoint
# ---------------------------------------------------------------------------

_XRD = fc.xrootd_cases()


@pytest.mark.parametrize("ep", XRD_ENDPOINTS, ids=lambda e: e[0])
@pytest.mark.parametrize("case", _XRD, ids=lambda c: c[0])
def test_xrootd_frame(case, ep):
    _name, port = ep
    _skip_if_down(port)
    data = _xrd_exchange(port, case[1])
    if data and len(data) >= 8:
        _sid, _status, dlen = struct.unpack("!2sHI", data[:8])
        assert dlen <= _SANE_DLEN, (
            f"response header claims insane dlen={dlen}: {data[:16]!r}"
        )


# ---------------------------------------------------------------------------
# TLS record junk × every TLS endpoint
# ---------------------------------------------------------------------------

_TLS = fc.tls_junk_cases()


@pytest.mark.parametrize("ep", TLS_ENDPOINTS, ids=lambda e: e[0])
@pytest.mark.parametrize("case", _TLS, ids=lambda c: c[0])
def test_tls_record(case, ep):
    _name, port = ep
    _skip_if_down(port)
    _tls_exchange(port, case[1])
