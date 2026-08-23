"""
tests/test_tpc_source_egress_guard.py

Online coverage for the phase-93 TPC source-host egress allowlist guard
(brix_tpc_source_guard / brix_tpc_source_allow) on the XRootD stream module.

The guard is a NAMING allowlist that complements the pre-existing
address-range SSRF gate (brix_tpc_allow_local / brix_tpc_allow_private,
covered in test_tpc_ssrf_policy.py). It fires in
src/tpc/engine/launch_prepare.c: tpc_prepare_check_preconditions() —
BEFORE the range gate and BEFORE any outbound connection is dialed — and
refuses with kXR_NotAuthorized + "TPC source host not permitted: <host>".
Refusals emit a fail2ban signal=tpc_egress line and bump the labelless
brix_stream_tpc_egress_refused_total metric.

Because the guard runs ahead of the range gate, an allowlisted host that
would otherwise be range-refused is still refused, and a non-allowlisted
host that the range gate would otherwise ALLOW (e.g. an RFC-1918 address,
private-allowed by default) is refused by the naming guard instead. That
asymmetry is exactly what these tests pin down.

The dedicated "tpc-source-guard" server (port 11218) is configured with:
    brix_tpc_source_guard on;
    brix_tpc_source_allow 10.255.255.1 .example.com;

Run:
    pytest tests/test_tpc_source_egress_guard.py -v
"""

import os
import socket
import struct

import pytest

from settings import (
    HOST,
    TPC_SRC_GUARD_PORT,
    TPC_SSRF_DEFAULT_PORT,
)

pytestmark = pytest.mark.timeout(60)

# ---------------------------------------------------------------------------
# Wire protocol constants (subset shared with test_tpc_ssrf_policy.py)
# ---------------------------------------------------------------------------

kXR_login     = 0x0bbf
kXR_open      = 0x0bc2
kXR_sync      = 3016
kXR_OK        = 0
kXR_error     = 4003

kXR_open_updt = 0x0020   # open for read+write
kXR_new       = 0x0008   # create new file

_TIMEOUT = 20.0
_NOT_PERMITTED = "not permitted"   # substring of the guard's refusal text


# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed reading %d bytes" % n)
        data += chunk
    return data


def _read_response(sock):
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session(host, port):
    sock = socket.create_connection((host, port), timeout=_TIMEOUT)
    sock.settimeout(_TIMEOUT)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _body = _read_response(sock)
    return sock, status


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


def _sync_tpc_pull(sock, streamid, fhandle0):
    """Arm then run the native TPC pull (two-step, matches root/write/sync.c)."""
    fh = bytes([fhandle0 & 0xFF, 0, 0, 0])
    req = struct.pack("!2sH4s12sI", streamid, kXR_sync, fh, b"\x00" * 12, 0)
    sock.sendall(req)
    status_arm, _body_arm = _read_response(sock)
    if status_arm != kXR_OK:
        return status_arm, b""
    sock.sendall(req)
    return _read_response(sock)


def _open_tpc_pull(sock, dst_path, src_url, streamid=b"\x00\x02"):
    opaque = "tpc.src=%s&tpc.key=testkey&tpc.dst=root://localhost//%s" % (  # net-literal-allow: loopback TPC destination, guard is about the SOURCE
        src_url, dst_path.lstrip("/"),
    )
    path_with_opaque = ("%s?%s" % (dst_path, opaque)).encode() + b"\x00"
    dlen = len(path_with_opaque)
    header = struct.pack(
        "!2sHHHH6s4sI",
        streamid, kXR_open,
        0o644,
        kXR_open_updt | kXR_new,
        0,
        b"\x00" * 6,
        b"\x00" * 4,
        dlen,
    )
    sock.sendall(header + path_with_opaque)
    return _read_response(sock)


def _drain_extra_frame(sock, wait=2.0):
    """Return the next XRootD frame if one arrives, else None.

    A refusal that is answered but not acted on leaves a SECOND frame behind:
    the kXR_ok open response, carrying a live fhandle for the transfer the gate
    just refused. Either a read timeout or a clean EOF means the refusal was the
    server's last word; anything else is returned for the caller to indict.
    """
    sock.settimeout(wait)
    try:
        return _read_response(sock)
    except (socket.timeout, ConnectionError, OSError):
        return None


def _open_leg(port, src_url, dst_filename):
    """Drive handshake + login + a single kXR_open; return (sock, status, body).

    Deliberately stops at the open leg — the caller owns the socket so it can ask
    what else, if anything, the server had to say.
    """
    sock, hs_status = _raw_session(HOST, port)
    assert hs_status == kXR_OK, "handshake failed: %d" % hs_status
    assert _login(sock) == kXR_OK, "login failed"
    status, body = _open_tpc_pull(sock, dst_filename, src_url)
    return sock, status, body


def _tpc_attempt(port, src_url, dst_filename="/tpc_guard_dst.dat"):
    """Connect + login + drive a TPC pull; return (status, err_text)."""
    sock, hs_status = _raw_session(HOST, port)
    assert hs_status == kXR_OK, "handshake failed: %d" % hs_status
    login_status = _login(sock)
    assert login_status == kXR_OK, "login failed: %d" % login_status
    status, body = _open_tpc_pull(sock, dst_filename, src_url)
    if status == kXR_OK and len(body) >= 1:
        status, body = _sync_tpc_pull(sock, b"\x00\x02", body[0])
    sock.close()
    err_text = ""
    if len(body) >= 4:
        err_text = body[4:].rstrip(b"\x00").decode("utf-8", errors="replace")
    return status, err_text


# ---------------------------------------------------------------------------
# Fixtures: reachability probes for the two servers this module leans on
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def guard_on():
    try:
        with socket.create_connection((HOST, TPC_SRC_GUARD_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"TPC source-guard server not reachable at port {TPC_SRC_GUARD_PORT}")
    return {"port": TPC_SRC_GUARD_PORT}


@pytest.fixture(scope="module")
def guard_off():
    try:
        with socket.create_connection((HOST, TPC_SSRF_DEFAULT_PORT), timeout=5):
            pass
    except OSError:
        pytest.skip(f"TPC guard-off (ssrf-default) server not reachable at port {TPC_SSRF_DEFAULT_PORT}")
    return {"port": TPC_SSRF_DEFAULT_PORT}


# ---------------------------------------------------------------------------
# Guard ON: allowlist = {10.255.255.1, .example.com}
# ---------------------------------------------------------------------------

class TestSourceGuardRefuse:
    """Hosts NOT on the allowlist are refused before any connection is made."""

    @pytest.mark.registry_server("tpc-source-guard")
    def test_nonallowlisted_rfc1918_refused(self, guard_on):
        # 192.168.1.1 is RFC-1918 — the range gate would ALLOW it by default,
        # but the naming guard refuses it because it is not on the allowlist.
        status, err = _tpc_attempt(guard_on["port"], "root://192.168.1.1//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        assert _NOT_PERMITTED in err, "expected naming-guard refusal, got: %r" % err

    @pytest.mark.registry_server("tpc-source-guard")
    def test_nonmatching_suffix_refused(self, guard_on):
        # .example.org does not match the .example.com suffix rule.
        status, err = _tpc_attempt(guard_on["port"], "root://host.example.org//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        assert _NOT_PERMITTED in err, "sibling TLD must not match suffix: %r" % err

    @pytest.mark.registry_server("tpc-source-guard")
    def test_suffix_bare_apex_refused(self, guard_on):
        # A leading-'.' rule is a strict suffix: the bare apex "example.com"
        # must NOT satisfy ".example.com" (host must be strictly longer).
        status, err = _tpc_attempt(guard_on["port"], "root://example.com//test.txt")
        assert status == kXR_error, "expected kXR_error, got %d" % status
        assert _NOT_PERMITTED in err, "bare apex must not match .suffix: %r" % err


class TestSourceGuardAllow:
    """Allowlisted hosts pass the naming guard and fall through to later stages."""

    @pytest.mark.registry_server("tpc-source-guard")
    def test_allowlisted_ip_falls_through(self, guard_on):
        # 10.255.255.1 is on the allowlist; the naming guard permits it. It then
        # reaches the range gate (RFC-1918 private-allowed by default) and finally
        # a connection attempt that fails — but never with the naming refusal.
        status, err = _tpc_attempt(guard_on["port"], "root://10.255.255.1//test.txt")
        assert status == kXR_error, "expected downstream error, got %d" % status
        assert _NOT_PERMITTED not in err, (
            "allowlisted IP must pass the naming guard: %r" % err
        )
        assert "prohibited" not in err, (
            "allowlisted RFC-1918 IP must also pass the range gate: %r" % err
        )

    @pytest.mark.registry_server("tpc-source-guard")
    def test_allowlisted_suffix_falls_through(self, guard_on):
        # host.example.com matches the .example.com suffix rule; the naming guard
        # permits it and it fails later (DNS/connect), never with "not permitted".
        status, err = _tpc_attempt(guard_on["port"], "root://host.example.com//test.txt")
        assert status == kXR_error, "expected downstream error, got %d" % status
        assert _NOT_PERMITTED not in err, (
            "suffix-matched host must pass the naming guard: %r" % err
        )


# ---------------------------------------------------------------------------
# Guard OFF control: the naming guard never fires when disabled
# ---------------------------------------------------------------------------

class TestSourceGuardDisabled:
    """With brix_tpc_source_guard off (default), the naming guard is inert."""

    @pytest.mark.registry_server("tpc-ssrf-default")
    def test_guard_off_does_not_refuse(self, guard_off):
        # Same non-allowlisted RFC-1918 host as the refuse case, but here the
        # guard is off, so the request falls straight through to the range gate
        # (private allowed) and fails only on the absent server — never with the
        # naming refusal.
        status, err = _tpc_attempt(guard_off["port"], "root://192.168.1.1//test.txt")
        assert status == kXR_error, "expected downstream error, got %d" % status
        assert _NOT_PERMITTED not in err, (
            "guard off must not emit the naming refusal: %r" % err
        )


# ---------------------------------------------------------------------------
# A refusal must also STOP the request, not merely answer it
# ---------------------------------------------------------------------------

class TestRefusalStopsTheRequest:
    """One refusal, one frame, no handle.

    Every gate in tpc_prepare_check_preconditions ends by sending a kXR_error.
    brix_send_error() reports NGX_OK once that error is on the wire, so a gate
    that returns it verbatim tells its caller the check PASSED — and the caller
    carries on: allocates the fhandle, opens the destination, and queues a second
    kXR_ok response carrying a usable handle for the transfer just refused. A
    client that reads past the error gets everything the gate denied it.

    The class-level tests above all stop at the first frame, so none of them can
    see that. These do: they assert what the server says NEXT.
    """

    @pytest.mark.registry_server("tpc-source-guard")
    def test_naming_refusal_is_the_last_word(self, guard_on):
        # Security-negative: the allowlist refuses, and nothing follows it.
        sock, status, body = _open_leg(guard_on["port"],
                                       "root://192.168.1.1//test.txt",
                                       "/tpc_guard_lastword.dat")
        try:
            assert status == kXR_error, "expected kXR_error, got %d" % status
            assert _NOT_PERMITTED in body[4:].decode("utf-8", "replace")
            extra = _drain_extra_frame(sock)
            assert extra is None, (
                "the refused open was answered a second time — status=%d "
                "body=%r; a kXR_ok here hands the client the fhandle the "
                "egress guard just denied" % (extra[0], extra[1][:64])
                if extra else ""
            )
        finally:
            sock.close()

    @pytest.mark.registry_server("tpc-ssrf-default")
    def test_range_gate_refusal_is_the_last_word(self, guard_off):
        # Error path, and a DIFFERENT gate: with the allowlist off, an
        # unresolvable source falls to the SSRF range gate, which cannot classify
        # what it cannot resolve and refuses. .invalid is reserved by RFC 2606
        # precisely so that it never resolves anywhere. The point is that the
        # one-frame contract is a property of the ladder, not of one rung.
        sock, status, body = _open_leg(guard_off["port"],
                                       "root://tpc-egress.invalid//test.txt",
                                       "/tpc_guard_rangefail.dat")
        try:
            assert status == kXR_error, "expected kXR_error, got %d" % status
            assert "DNS resolution failed" in body[4:].decode("utf-8", "replace")
            extra = _drain_extra_frame(sock)
            assert extra is None, (
                "the range gate answered twice: status=%d body=%r"
                % (extra[0], extra[1][:64]) if extra else ""
            )
        finally:
            sock.close()

    @pytest.mark.registry_server("tpc-source-guard")
    def test_permitted_source_answers_exactly_once_too(self, guard_on):
        # Success path: the same one-frame contract holds when the gates PASS.
        # The open is accepted and the outbound connection is deferred to
        # kXR_sync, so the accepted open is also the server's last word here —
        # which is what makes the two assertions above a difference in kind and
        # not just a difference in timing.
        sock, status, _body = _open_leg(guard_on["port"],
                                        "root://10.255.255.1//test.txt",
                                        "/tpc_guard_permitted.dat")
        try:
            assert status == kXR_OK, "allowlisted source must open: %d" % status
            extra = _drain_extra_frame(sock)
            assert extra is None, (
                "accepted open answered twice: status=%d body=%r"
                % (extra[0], extra[1][:64]) if extra else ""
            )
        finally:
            sock.close()
