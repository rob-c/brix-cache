"""
tests/test_ipv6_tpc.py — Phase-36 §7.2.6: native + WebDAV third-party-copy (TPC)
over IPv6, plus the SSRF negatives that prove the IPv6 re-bracket round-trip does
not open an SSRF bypass.

Why this file exists
--------------------
Phase-36 fixed a recurring "bracket-on-emit" defect: an IPv6 literal source host
is stored *bare* (the TPC opaque parser strips the brackets off "[::1]" into
tpc_src_host="::1", see src/tpc/engine/parse.c::tpc_parse_src_spec), and the native-TPC
launch path then *rebuilds* a "root://host:port/path" display/registry URL.  Before
the fix that rebuild emitted a bare, unparseable "root://::1:port/path"; the fix
re-brackets via brix_format_host_port() at src/tpc/engine/launch.c:182 →
"root://[::1]:port/path".  These tests prove the parse→rebuild round-trip accepts a
bracketed IPv6 source and that the SSRF gate (src/tpc/outbound/connect.c::
brix_tpc_check_src_policy → src/core/compat/net_target.c) is still applied to the bare
host BEFORE any rebuild, so the round-trip cannot be used to smuggle a loopback /
v4-mapped-loopback source past the local-deny policy.

Client caveat (CRITICAL)
------------------------
The PyXRootD high-level client mishandles root://[::1] literals in this environment
("[FATAL] Invalid address"), so every native-TPC / root:// assertion here is driven
over RAW SOCKETS with hand-built kXR frames (handshake → kXR_login → kXR_open with a
TPC opaque → kXR_sync arm/run), copied from tests/test_tpc_ssrf_policy.py and
tests/test_handshake_protocol_wire.py.  WebDAV HTTP-TPC uses curl, which handles the
RFC-3986 bracket syntax https://[::1]:port natively.

Topology reused (no new config in this file)
--------------------------------------------
  * ipv6-stream   (root://[::1]:IPV6_STREAM_PORT) — writable native-TPC dest, also
                   acts as the IPv6 *source* for v6→v6 transfers.  Seeded test.txt.
  * ipv6-webdav   (http(s)://[::1]:IPV6_WEBDAV_PORT) — WebDAV HTTP-TPC dest.
  * tpc-ssrf-default (root://127.0.0.1:TPC_SSRF_DEFAULT_PORT, allow_local=off) — an
                   IPv4-listening server used ONLY for the SSRF negatives: the SSRF
                   gate resolves the *source host string* regardless of the
                   listener's address family, so a bracketed [::1] / [::ffff:..]
                   source is rejected as "prohibited" here deterministically,
                   independent of whatever allow_local the ipv6-stream sibling chose.

Skip discipline
---------------
Every test depends on the session fixture `requires_ipv6_loopback` (conftest.py;
skips when ::1 is unusable) AND on a per-instance reachable6(port) probe (skips when
the dedicated instance is down).  No IPv6-absent / instance-down condition ever
fails the suite.

Tagging
-------
  GATING       — proves a bracket fix (asserts "[::1]" on the wire / a bracketed
                 source round-trips parse→rebuild without a parse error).
  SECURITY-NEG — proves the SSRF/local-deny policy still rejects loopback and
                 v4-mapped-loopback IPv6 sources through the re-bracket round-trip.
  REGRESSION   — works today against the already-clean socket/resolution layer.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ipv6_tpc.py -v
"""

import os
import shutil
import socket
import struct
import subprocess

import pytest

from settings import (
    CA_CERT,
    HOST,
    HOST6,
    IPV6_STREAM_PORT,
    IPV6_STREAM_DATA_ROOT,
    IPV6_WEBDAV_PORT,
    TPC_SSRF_DEFAULT_PORT,
    url_host,
)

pytestmark = pytest.mark.timeout(60)


# ---------------------------------------------------------------------------
# Wire constants (mirror tests/test_tpc_ssrf_policy.py + test_handshake_*).
# Verified against /tmp/brix-src/src/XProtocol/XProtocol.hh and
# src/protocols/root/protocol/opcodes.h (kXR_open=3010=0x0bc2, kXR_sync=3016).
# ---------------------------------------------------------------------------

# IPv6 client host the test reaches (default ::1; env TEST_HOST6). All uses are
# client connect / reachability probes / TPC source-URL authorities, so this is
# the client-side HOST6, never a server bind host.
IPV6_LOOPBACK = HOST6

kXR_login = 3007
kXR_open = 0x0BC2          # 3010
kXR_sync = 3016
kXR_OK = 0
kXR_error = 4003

# ClientOpenRequest::options
kXR_open_updt = 0x0020     # open for read+write
kXR_new = 0x0008           # create new file

_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# Raw-socket framing helpers — connect via getaddrinfo(AF_INET6) so "::1"
# yields an AF_INET6 socket unambiguously (never an AF_UNSPEC IPv4 fallback).
# ---------------------------------------------------------------------------

def _connect6(port):
    """Open an AF_INET6 TCP connection to [::1]:port."""
    infos = socket.getaddrinfo(
        IPV6_LOOPBACK, port, socket.AF_INET6, socket.SOCK_STREAM
    )
    family, socktype, proto, _canon, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(_TIMEOUT)
    sock.connect(sockaddr)
    return sock


def _connect4(host, port):
    sock = socket.create_connection((host, port), timeout=_TIMEOUT)
    sock.settimeout(_TIMEOUT)
    return sock


def reachable6(port, timeout=2.0):
    """[::1]:port accepting connections?  Mirrors test_open_flags_lifecycle.
    _reachable for AF_INET6 (the helper the phase-36 doc §7.1.2 describes; the
    shared conftest exposes only the requires_ipv6_loopback fixture, so the
    per-instance probe lives here)."""
    try:
        socket.create_connection((IPV6_LOOPBACK, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed reading %d bytes" % n)
        data += chunk
    return data


def _read_response(sock):
    """One ServerResponseHdr (streamid[2] status[2] dlen[4]) + its body."""
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _err_text(body):
    """kXR_error body is [errnum:4B][msg]; return the trailing message text."""
    if len(body) < 4:
        return ""
    return body[4:].rstrip(b"\x00").decode("utf-8", errors="replace")


def _handshake(sock):
    """20-byte ClientInitHandShake; consume the 8-byte-body server reply."""
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _body = _read_response(sock)
    return status


def _login(sock):
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        b"\x00\x01", kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, _body = _read_response(sock)
    return status


def _open_tpc_pull(sock, dst_path, src_url, streamid=b"\x00\x02"):
    """kXR_open for a TPC-destination pull from src_url (a full root:// URL).

    Body is the NUL-terminated "path?opaque" with the tpc.src / tpc.key / tpc.dst
    opaque keys parsed by src/tpc/engine/parse.c.  Options request create+write so the
    open is routed through brix_tpc_prepare_pull (is_write=1)."""
    opaque = "tpc.src=%s&tpc.key=ipv6key&tpc.dst=root://%s//%s" % (
        src_url, url_host(HOST6), dst_path.lstrip("/"),
    )
    path_with_opaque = ("%s?%s" % (dst_path, opaque)).encode() + b"\x00"
    dlen = len(path_with_opaque)

    # ClientOpenRequest: streamid(2) requestid(2) mode(2) options(2)
    #                    optiont(2) reserved(6) fhtemplt(4) dlen(4) = 24 bytes
    header = struct.pack(
        "!2sHHHH6s4sI",
        streamid,
        kXR_open,
        0o644,                        # mode
        kXR_open_updt | kXR_new,      # options: create+write
        0,                            # optiont
        b"\x00" * 6,                  # reserved
        b"\x00" * 4,                  # fhtemplt
        dlen,
    )
    sock.sendall(header + path_with_opaque)
    return _read_response(sock)


def _sync_tpc_pull(sock, streamid, fhandle0):
    """Arm then run a native TPC pull — the two-step kXR_sync of src/protocols/root/write/sync.c
    (first sync arms, second sync triggers brix_tpc_start_pull → the registry
    URL rebuild at launch.c:182)."""
    fh = bytes([fhandle0 & 0xFF, 0, 0, 0])
    req = struct.pack("!2sH4s12sI", streamid, kXR_sync, fh, b"\x00" * 12, 0)
    sock.sendall(req)
    status_arm, _body_arm = _read_response(sock)
    if status_arm != kXR_OK:
        return status_arm, b""

    sock.sendall(req)
    return _read_response(sock)


def _native_tpc_open(connect_fn, dst_filename, src_url):
    """connect → handshake → login → kXR_open(TPC pull). Returns (status, err)."""
    sock = connect_fn()
    try:
        assert _handshake(sock) == kXR_OK, "handshake failed"
        assert _login(sock) == kXR_OK, "login failed"
        status, body = _open_tpc_pull(sock, dst_filename, src_url)
        return status, _err_text(body), body
    finally:
        sock.close()


def _native_tpc_open_and_sync(connect_fn, dst_filename, src_url):
    """Full open + sync arm/run.  Returns (final_status, err_text)."""
    sock = connect_fn()
    try:
        assert _handshake(sock) == kXR_OK, "handshake failed"
        assert _login(sock) == kXR_OK, "login failed"
        status, body = _open_tpc_pull(sock, dst_filename, src_url)
        if status != kXR_OK or len(body) < 1:
            return status, _err_text(body)
        fh0 = body[0]
        status, body = _sync_tpc_pull(sock, b"\x00\x02", fh0)
        return status, _err_text(body)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# curl helper for WebDAV HTTP-TPC (handles https://[::1]:port natively).
# ---------------------------------------------------------------------------

def _curl_copy(method_url, *headers, timeout=30):
    """COPY against method_url with the given extra -H headers.  Returns the
    CompletedProcess with stdout == the http_code (via -w)."""
    args = ["curl", "-s", "-X", "COPY", method_url, "-w", "%{http_code}",
            "-o", "/dev/null"]
    if method_url.startswith("https://"):
        # -k: the IPv6 dedicated WebDAV instance may use a self-signed/test cert;
        # we are asserting bracket handling + status, not TLS trust.
        args.insert(1, "-k")
        if os.path.exists(CA_CERT):
            args.extend(["--cacert", CA_CERT])
    for h in headers:
        args.extend(["-H", h])
    return subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )


def _curl_code(proc):
    out = proc.stdout.decode(errors="replace").strip()
    try:
        return int(out)
    except ValueError:
        return -1


# ---------------------------------------------------------------------------
# Module-scoped gate: skip the whole file cleanly when ::1 is unusable.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _ipv6_gate(requires_ipv6_loopback):
    """Every test in this module depends on a usable IPv6 loopback."""
    yield


def _require_ipv6_stream():
    if not reachable6(IPV6_STREAM_PORT):
        pytest.skip(
            f"ipv6-stream dedicated instance not up on [{HOST6}]:{IPV6_STREAM_PORT}"
        )


def _require_ssrf_default():
    try:
        with socket.create_connection((HOST, TPC_SSRF_DEFAULT_PORT),
                                       timeout=3):
            pass
    except OSError:
        pytest.skip(
            f"tpc-ssrf-default instance not up on {HOST}:{TPC_SSRF_DEFAULT_PORT}"
        )


def _require_ipv6_webdav():
    if not reachable6(IPV6_WEBDAV_PORT):
        pytest.skip(
            f"ipv6-webdav dedicated instance not up on [{HOST6}]:{IPV6_WEBDAV_PORT}"
        )
    if shutil.which("curl") is None:
        pytest.skip("curl not found")


def _webdav_base_url():
    """Probe whether ipv6-webdav speaks HTTPS or plain HTTP on its port and
    return the correct base URL (bracketed IPv6 authority)."""
    # Try HTTPS first (the §7 reference topology is davs://); fall back to HTTP.
    https = f"https://{url_host(HOST6)}:{IPV6_WEBDAV_PORT}"
    http = f"http://{url_host(HOST6)}:{IPV6_WEBDAV_PORT}"
    try:
        probe = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "-X", "OPTIONS", https + "/", "--max-time", "4"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8,
        )
        if probe.returncode == 0 and probe.stdout.strip() not in (b"", b"000"):
            return https
    except subprocess.TimeoutExpired:
        pass
    return http


# ===========================================================================
# (a) Native root:// TPC with an IPv6 source — GATING
# ===========================================================================
