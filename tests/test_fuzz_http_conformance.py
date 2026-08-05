"""tests/test_fuzz_http_conformance.py — malformed-packet conformance for every
HTTP-family protocol surface: plain HTTP/WebDAV, HTTPS/WebDAV (roots of the
https:// and webdav:// clients), httpg:// (HTTP over GSI TLS) and the S3
gateway.

Each case from ``fuzz_corpus`` is replayed over a fresh connection.  We assert
the *robust liveness* invariant, not a fragile per-case status:

  * the server never emits a corrupt reply — an ``HTTP/1.x`` answer must carry a
    well-formed status line, and a body-only answer (nginx serves a request line
    with no valid ``HTTP/x.y`` token as spec-correct HTTP/0.9) must be coherent
    text; binary garbage or a mangled status line is the crash/heap-scribble
    fingerprint we reject;
  * the server never crashes — every case opens a fresh connection (a dead
    worker pool would refuse it, failing loudly rather than skipping), and a
    module-teardown probe issues one last valid request per endpoint;
  * the server never wedges the accept path — a clean close, reset, or the
    absence of a reply is all acceptable for a truncated/partial frame.

Runs against the always-on ``main`` fleet (all four listeners are served from
the one shared nginx).  Collect-only works with no server up; each endpoint
column skips cleanly if that listener is unreachable.

Run:
    PYTHONPATH=tests pytest tests/test_fuzz_http_conformance.py -q
"""

from __future__ import annotations

import re
import socket
import ssl

import pytest

import fuzz_corpus as fc
from settings import (
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_WEBDAV_PORT,
    SERVER_HOST,
)

# name, port, tls?
EP_HTTP = ("http", NGINX_HTTP_WEBDAV_PORT, False)
EP_HTTPS = ("https", NGINX_WEBDAV_PORT, True)
EP_HTTPG = ("httpg", NGINX_WEBDAV_GSI_TLS_PORT, True)
EP_S3 = ("s3", NGINX_S3_PORT, False)

HTTP_ENDPOINTS = [EP_HTTP, EP_HTTPS, EP_HTTPG, EP_S3]
DAV_ENDPOINTS = [EP_HTTP, EP_HTTPS, EP_HTTPG]

_READ_TIMEOUT = 0.6
_CONNECT_TIMEOUT = 3.0
_MAX_READ = 1 << 16

_TLS_CTX = ssl._create_unverified_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE

# A well-formed HTTP/1.x status line: version, 3-digit code, optional reason.
_STATUS_LINE = re.compile(rb"^HTTP/\d\.\d [1-5]\d\d(?: |\r\n)")

_UP_CACHE: dict = {}


def _endpoint_up(port: int) -> bool:
    """TCP-reachability probe, cached once per port so --collect-only stays
    offline-safe and a down listener skips its whole column."""
    if port not in _UP_CACHE:
        try:
            s = socket.create_connection((SERVER_HOST, port), timeout=_CONNECT_TIMEOUT)
            s.close()
            _UP_CACHE[port] = True
        except OSError:
            _UP_CACHE[port] = False
    return _UP_CACHE[port]


def _exchange(port: int, tls: bool, raw: bytes) -> bytes | None:
    """Send ``raw`` and drain the reply.  Returns the bytes read (possibly
    empty) or ``None`` if the peer tore down the connection while we were still
    writing (a fast rejection — acceptable).

    ``ConnectionRefusedError`` is *not* swallowed: the endpoint passed its
    liveness probe, so a refusal now means the server died on a prior case."""
    sock = socket.create_connection((SERVER_HOST, port), timeout=_CONNECT_TIMEOUT)
    sock.settimeout(_READ_TIMEOUT)
    conn = _TLS_CTX.wrap_socket(sock, server_hostname="localhost") if tls else sock  # net-literal-allow: SNI must match the fixture cert subject
    try:
        try:
            conn.sendall(raw)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            return None
        # Half-close the underlying TCP socket (works under TLS too): nginx sees
        # the FIN and decides at once instead of blocking on a partial frame.  A
        # truncated request the server never answered draws a fatal TLS alert or
        # a clean close, either of which yields an empty read here — acceptable.
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        data = bytearray()
        try:
            while len(data) < _MAX_READ:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            pass
        return bytes(data)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _assert_liveness(port: int, tls: bool, raw: bytes):
    data = _exchange(port, tls, raw)
    if not data:
        # Empty read: a clean close/reset/alert for a truncated frame — fine.
        return
    if data.startswith(b"HTTP/"):
        # An HTTP/1.x reply must carry a *well-formed* status line; a corrupt or
        # truncated one would be the fingerprint of a response-framing bug.
        assert _STATUS_LINE.match(data), (
            f"malformed HTTP status line ({len(data)} bytes): {data[:48]!r}"
        )
        return
    # No status line: nginx answers a request line that carries no valid
    # ``HTTP/x.y`` token (e.g. ``GET / \r\n`` or a bare-LF-terminated line) as
    # HTTP/0.9 — a body-only reply with no status line or headers, which is
    # spec-correct, not a parser fault.  A genuine crash/heap-scribble would
    # instead leak binary garbage, so we require the body be coherent text
    # (decodable, no NUL bytes) before accepting it.
    assert b"\x00" not in data, (
        f"non-HTTP response with NUL bytes ({len(data)} bytes): {data[:48]!r}"
    )
    try:
        data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise AssertionError(
            f"non-HTTP, non-text response ({len(data)} bytes): {data[:48]!r}"
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _require_and_verify():
    """Skip the module if no HTTP listener is up; after all cases, probe each
    up endpoint once with a valid request to catch a crash on the final case."""
    if not any(_endpoint_up(p) for _, p, _ in HTTP_ENDPOINTS):
        pytest.skip("no HTTP-family fleet listener reachable")
    yield
    for name, port, tls in HTTP_ENDPOINTS:
        if not _endpoint_up(port):
            continue
        data = _exchange(port, tls, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")  # net-literal-allow: probe payload Host header
        assert data and data[:5] == b"HTTP/", (
            f"{name}:{port} did not survive the fuzz corpus (teardown probe)"
        )


def _skip_if_down(port: int):
    if not _endpoint_up(port):
        pytest.skip(f"listener {SERVER_HOST}:{port} unreachable")


# ---------------------------------------------------------------------------
# Generic HTTP corpus × every HTTP-family endpoint
# ---------------------------------------------------------------------------

_GENERIC = fc.http_generic_cases()


@pytest.mark.parametrize("ep", HTTP_ENDPOINTS, ids=lambda e: e[0])
@pytest.mark.parametrize("case", _GENERIC, ids=lambda c: c[0])
def test_http_generic(case, ep):
    _name, port, tls = ep
    _skip_if_down(port)
    _assert_liveness(port, tls, case[1])


# ---------------------------------------------------------------------------
# S3 SigV4 / x-amz corpus × the S3 gateway
# ---------------------------------------------------------------------------

_S3 = fc.s3_cases()


@pytest.mark.parametrize("case", _S3, ids=lambda c: c[0])
def test_s3(case):
    _name, port, tls = EP_S3
    _skip_if_down(port)
    _assert_liveness(port, tls, case[1])


# ---------------------------------------------------------------------------
# WebDAV verb/header/XML corpus × every WebDAV-capable endpoint
# ---------------------------------------------------------------------------

_DAV = fc.webdav_cases()


@pytest.mark.parametrize("ep", DAV_ENDPOINTS, ids=lambda e: e[0])
@pytest.mark.parametrize("case", _DAV, ids=lambda c: c[0])
def test_webdav(case, ep):
    _name, port, tls = ep
    _skip_if_down(port)
    _assert_liveness(port, tls, case[1])
