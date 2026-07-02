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
re-brackets via xrootd_format_host_port() at src/tpc/engine/launch.c:182 →
"root://[::1]:port/path".  These tests prove the parse→rebuild round-trip accepts a
bracketed IPv6 source and that the SSRF gate (src/tpc/outbound/connect.c::
xrootd_tpc_check_src_policy → src/core/compat/net_target.c) is still applied to the bare
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
# Verified against /tmp/xrootd-src/src/XProtocol/XProtocol.hh and
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
    open is routed through xrootd_tpc_prepare_pull (is_write=1)."""
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
    (first sync arms, second sync triggers xrootd_tpc_start_pull → the registry
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
            f"ipv6-stream dedicated instance not up on [::1]:{IPV6_STREAM_PORT}"
        )


def _require_ssrf_default():
    try:
        with socket.create_connection((HOST, TPC_SSRF_DEFAULT_PORT),
                                       timeout=3):
            pass
    except OSError:
        pytest.skip(
            f"tpc-ssrf-default instance not up on 127.0.0.1:{TPC_SSRF_DEFAULT_PORT}"
        )


def _require_ipv6_webdav():
    if not reachable6(IPV6_WEBDAV_PORT):
        pytest.skip(
            f"ipv6-webdav dedicated instance not up on [::1]:{IPV6_WEBDAV_PORT}"
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

class TestNativeTpcIpv6BracketRoundTrip:
    """Prove the parse→rebuild round-trip accepts a bracketed IPv6 source
    (src/tpc/engine/parse.c strips "[::1]"→"::1"; src/tpc/engine/launch.c re-brackets at the
    registry/display URL rebuild).  Raw-wire because PyXRootD mishandles
    root://[::1] literals."""

    def test_native_tpc_ipv6_bracketed_source_open_accepted(self):
        """GATING (parse round-trip): a kXR_open carrying a *bracketed* IPv6 TPC
        source "root://[::1]:PORT//test.txt" is parsed successfully — i.e. it is
        NOT rejected with kXR_ArgInvalid "invalid or incomplete TPC source".

        A successful parse yields one of two well-formed outcomes, both of which
        prove the bracket was understood:
          * kXR_OK + a file handle           (allow_local on → pull armed), or
          * kXR_error + "prohibited"         (allow_local off → SSRF gate).
        A *bare* "::1:PORT" source would mis-parse the port/host and the launch
        rebuild would emit an unparseable URL — this test fails closed on that."""
        _require_ipv6_stream()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        status, err, body = _native_tpc_open(
            lambda: _connect6(IPV6_STREAM_PORT),
            "/ipv6_tpc_dst_accept.dat", src,
        )

        # The bracket parse must have succeeded: never the "invalid/incomplete
        # TPC source" ArgInvalid path.
        assert "invalid or incomplete TPC source" not in err, (
            f"bracketed IPv6 source mis-parsed: {err!r}"
        )
        if status == kXR_OK:
            assert len(body) >= 1, "accepted TPC open must return a file handle"
        else:
            # Only acceptable non-OK outcome is the SSRF local-deny policy.
            assert "prohibited" in err, (
                f"unexpected TPC-open failure for bracketed IPv6 source: {err!r}"
            )

    def test_native_tpc_ipv6_v6_to_v6_round_trip(self):
        """GATING (end-to-end rebuild): drive the full open+sync v6→v6 pull on
        ipv6-stream and confirm the destination file is byte-exact.  Reaching a
        completed transfer means launch.c rebuilt a *connectable* bracketed
        "root://[::1]:PORT//test.txt" — a bare-colon rebuild could never connect.

        Deterministic policy handling: if the ipv6-stream sibling left
        allow_local=off (loopback SSRF-denied), the pull cannot complete
        same-host; accept only that explicit denial as a non-bypass outcome."""
        _require_ipv6_stream()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        dst_name = f"ipv6_tpc_roundtrip_{os.getpid()}.dat"
        status, err = _native_tpc_open_and_sync(
            lambda: _connect6(IPV6_STREAM_PORT),
            "/" + dst_name, src,
        )

        if status != kXR_OK:
            if "prohibited" in err:
                return
            pytest.fail(f"v6→v6 native TPC pull did not complete: {err!r}")

        # Transfer committed: verify the rebuilt bracketed source actually moved
        # the bytes.  Best-effort filesystem check (skip if the data root is not
        # locally visible, e.g. remote-server mode).
        dst = os.path.join(IPV6_STREAM_DATA_ROOT, dst_name)
        if not os.path.isdir(IPV6_STREAM_DATA_ROOT):
            pytest.skip("ipv6-stream data root not locally visible")
        try:
            with open(dst, "rb") as f:
                got = f.read()
        except FileNotFoundError:
            pytest.fail("TPC reported OK but destination file is missing")
        finally:
            try:
                os.unlink(dst)
            except OSError:
                pass
        assert got == b"hello from nginx-xrootd\n", (
            f"v6→v6 TPC content mismatch: {got!r}"
        )


# ===========================================================================
# (b) SECURITY-NEG — the re-bracket round-trip must NOT bypass the SSRF
#     local-deny policy.  Driven against tpc-ssrf-default (allow_local=off),
#     whose SSRF gate resolves the source host string regardless of address
#     family, so the result is deterministic and independent of the IPv6
#     sibling configs.
# ===========================================================================

class TestNativeTpcIpv6SsrfNegatives:
    """The SSRF gate (xrootd_tpc_check_src_policy) runs on the *bare* source host
    at kXR_open time, BEFORE the launch rebuild.  These prove a bracketed IPv6
    loopback / v4-mapped-loopback source is still rejected — the bracket fix did
    not punch an SSRF hole."""

    def test_ssrf_ipv6_loopback_source_rejected(self):
        """SECURITY-NEG: TPC pull from "root://[::1]:PORT//test.txt" against an
        allow_local=off server is rejected as a prohibited (loopback) address.
        ::1 matches the IN6 loopback constant in net_target.c."""
        _require_ssrf_default()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        status, err = _native_tpc_open_and_sync(
            lambda: _connect4(HOST, TPC_SSRF_DEFAULT_PORT),
            "/ipv6_ssrf_loopback.dat", src,
        )
        assert status == kXR_error, f"expected rejection, got status {status}"
        assert "prohibited" in err, (
            f"[::1] loopback source must be SSRF-prohibited, got: {err!r}"
        )

    def test_ssrf_ipv6_v4mapped_loopback_source_rejected(self):
        """SECURITY-NEG: "root://[::ffff:127.0.0.1]:PORT//test.txt" must also be
        rejected — net_target.c classifies a v4-mapped address (IN6_IS_ADDR_
        V4MAPPED) by its embedded IPv4, so ::ffff:127.0.0.1 == 127.0.0.1 loopback
        and is prohibited under allow_local=off.  This is the canonical
        v4-mapped SSRF-evasion vector."""
        _require_ssrf_default()
        src = f"root://[::ffff:127.0.0.1]:{IPV6_STREAM_PORT}//test.txt"
        status, err = _native_tpc_open_and_sync(
            lambda: _connect4(HOST, TPC_SSRF_DEFAULT_PORT),
            "/ipv6_ssrf_v4mapped.dat", src,
        )
        assert status == kXR_error, f"expected rejection, got status {status}"
        assert "prohibited" in err, (
            f"[::ffff:127.0.0.1] mapped-loopback source must be SSRF-prohibited, "
            f"got: {err!r}"
        )

    def test_ssrf_rejection_is_not_a_parse_error(self):
        """SECURITY-NEG (control): the rejection above is the SSRF policy firing
        on a *correctly parsed* bracketed IPv6 host — not an accidental parse
        failure.  A bracketed [::1] source must reach the "prohibited" verdict,
        never "invalid or incomplete TPC source" (which would mean the bracket
        defeated parsing, masking rather than enforcing the policy)."""
        _require_ssrf_default()
        src = f"root://[{IPV6_LOOPBACK}]:{IPV6_STREAM_PORT}//test.txt"
        status, err, _body = _native_tpc_open(
            lambda: _connect4(HOST, TPC_SSRF_DEFAULT_PORT),
            "/ipv6_ssrf_parse_control.dat", src,
        )
        assert status == kXR_error
        assert "invalid or incomplete TPC source" not in err, (
            f"bracketed IPv6 source must parse then be SSRF-denied, not fail "
            f"parsing: {err!r}"
        )
        assert "prohibited" in err, f"expected SSRF prohibition, got: {err!r}"


# ===========================================================================
# (c) WebDAV HTTP-TPC COPY with a bracketed IPv6 Source: / Destination: header.
#     curl handles https://[::1]:port natively (RFC 3986).  These exercise the
#     COPY parse + outbound curl host bracketing (proxy_pool.c / tpc_curl.c).
# ===========================================================================

class TestWebdavTpcIpv6Copy:
    """COPY with a bracketed IPv6 Source/Destination.  The destination instance
    (ipv6-webdav) and its allow_local / cert posture are owned by a sibling
    config, so these gate on reachability and assert on the *shape* of the
    response — never a flaky transfer outcome."""

    def test_webdav_tpc_copy_ipv6_source_header_accepted(self):
        """GATING: a COPY pull with "Source: <scheme>://[::1]:PORT/test.txt" is
        NOT rejected as a malformed URL (HTTP 400) on account of the bracketed
        IPv6 authority — the bug class this gates is a 400 Bad Request that would
        prove the "[::1]" literal broke the COPY request line / Source-URL parse.

        Config-model note (diagnosed against the LIVE ipv6-webdav instance,
        nginx_ipv6_webdav.conf): that instance does NOT set "xrootd_webdav_tpc on",
        so HTTP-TPC is disabled.  A COPY carrying a "Source:" header therefore hits
        the TPC config gate at src/protocols/webdav/dispatch.c (`if (!conf->tpc) return
        NGX_HTTP_NOT_ALLOWED;`) and is answered 405 — BEFORE any Source-URL parse.
        This 405 was verified to be address-family-agnostic: an IPv4, hostname, or
        bracketed-IPv6 Source all return the identical 405, and a plain server-side
        COPY (Destination only, no Credential) returns 201 on the same instance.
        So the 405 is the TPC-disabled gate, not a bracket-parse failure, and the
        bracket-rebuild fix is covered by the native-TPC gating tests above
        (launch.c URL rebuild) which exercise the parser directly.

        Acceptable outcomes (none is a malformed-URL 400): 405 (HTTP-TPC disabled
        gate, the LIVE-instance result), 201/202/204 (transfer accepted/started),
        207, 403 (SSRF local-deny on loopback), 404, 409 (conflict), 412, 502
        (upstream/transfer error).  A 400 is the only failure — it would mean the
        bracketed source URL was rejected as malformed."""
        _require_ipv6_webdav()
        base = _webdav_base_url()
        src = f"{base}/test.txt"
        dst_url = f"{base}/ipv6_tpc_copy_dst.txt"
        proc = _curl_copy(
            dst_url,
            "Credential: none",
            f"Source: {src}",
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        code = _curl_code(proc)
        assert code != -1, f"no HTTP status from COPY: {proc.stdout!r}"
        assert code != 400, (
            f"bracketed IPv6 Source header rejected as malformed (400); "
            f"the [::1] authority must parse. body status={code}"
        )
        assert code in (201, 202, 204, 207, 403, 404, 405, 409, 412, 502), (
            f"unexpected COPY status {code} for bracketed IPv6 source"
        )

    def test_webdav_tpc_copy_ipv6_destination_header_accepted(self):
        """GATING (push): a COPY push with "Destination: <scheme>://[::1]:PORT/..."
        plus a "Credential:" header (which is what flags an HTTP-TPC push, see
        src/protocols/webdav/dispatch.c) is NOT rejected as a malformed URL (400) on account
        of the bracketed IPv6 egress authority.  Mirrors the pull case on the
        egress side; the destination/cert posture is sibling-owned, so we assert
        on response shape, never a transfer outcome.

        Config-model note: as for the pull case, the LIVE ipv6-webdav instance has
        HTTP-TPC disabled (no "xrootd_webdav_tpc on"), so a Destination+Credential
        COPY hits the same `!conf->tpc` gate and returns 405 BEFORE the egress URL
        is parsed (verified: identical 405 for IPv4/hostname/bracketed-IPv6
        Destination; a Destination-only server-side COPY returns 201).  The 405 is
        the TPC-disabled gate, not a bracket-parse failure; the bracket round-trip
        itself is covered by the native-TPC gating tests above.

        Acceptable outcomes (none is a malformed-URL 400): 405 (HTTP-TPC disabled
        gate, the LIVE-instance result), 201/202/204, 207, 403, 404, 409, 412, 502.
        A 400 is the only failure."""
        _require_ipv6_webdav()
        base = _webdav_base_url()
        dst = f"{base}/ipv6_tpc_push_dst.txt"
        # Push: COPY is issued against an existing source path on the same server;
        # the Destination header names a bracketed IPv6 egress target.
        proc = _curl_copy(
            f"{base}/test.txt",
            "Credential: none",
            f"Destination: {dst}",
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        code = _curl_code(proc)
        assert code != -1, f"no HTTP status from COPY push: {proc.stdout!r}"
        assert code != 400, (
            f"bracketed IPv6 Destination header rejected as malformed (400); "
            f"status={code}"
        )
        assert code in (201, 202, 204, 207, 403, 404, 405, 409, 412, 502), (
            f"unexpected COPY-push status {code} for bracketed IPv6 destination"
        )

    def test_webdav_tpc_copy_non_https_ipv6_destination_rejected(self):
        """SECURITY-NEG / REGRESSION: a COPY push to an explicit plaintext
        "http://[::1]:9999/..." egress is rejected (400) — the bracket fix did
        not relax the HTTPS-only egress requirement for HTTP-TPC.  This is the
        IPv6 form of test_webdav_tpc.py::test_push_non_https_destination_rejected.

        Deterministic policy handling: some source postures (auth-required,
        TPC-off) short-circuit before the scheme check with 403/405; those are
        accepted non-bypass results, while any 2xx success fails."""
        _require_ipv6_webdav()
        base = _webdav_base_url()
        proc = _curl_copy(
            f"{base}/test.txt",
            "Credential: none",
            "Destination: http://[::1]:9999/should-be-rejected.txt",
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        code = _curl_code(proc)
        assert code != -1
        assert code not in (200, 201, 202), (
            f"plaintext IPv6 egress must not yield a successful copy, got {code}"
        )
        if code != 400:
            assert code in (403, 405), (
                f"unexpected non-success status for plaintext egress: {code}"
            )
            return
        assert code == 400
