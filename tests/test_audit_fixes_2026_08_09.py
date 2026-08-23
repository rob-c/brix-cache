"""
Dedicated coverage for the 2026-08-09 audit-fix wave
(docs/refactor/xrootd-feature-parity-audit-2026-08-04.md).

One file, one class per fix, because each is small and they share the stub /
harness plumbing:

  §7.4  TestTriedEmission      — the client tells a redirector WHICH endpoint
                                 died (tried=/triedrc=) when it falls back to
                                 the manager. Server-side parsing existed;
                                 nothing ever emitted it.
  §7.5  TestTpcDelegate        — `--tpc delegate` emits tpc.dlgon=1 (it emitted
                                 a hardcoded 0, so the mode was a silent no-op)
                                 AND arms the client to answer the destination's
                                 X.509 delegation round.
  §4.4  TestOnlyIfCached       — brix_cache_only_if_cached serves cache hits and
                                 refuses misses instead of pulling from origin.
  §4.2  TestColdFilePurge      — brix_cache_cold_max_age purges a CLEAN
                                 read-through fill by age, independent of
                                 occupancy.
  §5.2  TestSigningFailClosed  — brix_security_level is no longer silently
                                 unenforced on a session that cannot sign;
                                 brix_signing_required makes it refuse.

The kXR error constants (§1 gap 5) are covered by the C unit
client/tests/c/kxr_errors_unit.c — they are pure vocabulary with no wire
behaviour to drive from here.

TPC push egress (§6.3/§9.2) is covered by the pre-existing
tests/test_webdav_tpc_source_egress_guard.py::TestWebdavPushGuardRefuse; the
audit row was stale, not the code.

Run:
    PYTHONPATH=tests pytest tests/test_audit_fixes_2026_08_09.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

from ephemeral_port import free_port
from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")
_XRDFS = os.path.join(_REPO, "client", "bin", "xrdfs")

pytestmark = [
    pytest.mark.timeout(180),
    pytest.mark.xdist_group("lc-audit-fixes"),
]

# ---------------------------------------------------------------------------
# Wire constants + stub helpers (same shapes as upstream_protocol_stubs.py)
# ---------------------------------------------------------------------------
kXR_ok        = 0
kXR_error     = 4003
kXR_redirect  = 4004
kXR_stat      = 3017
kXR_open      = 3010
kXR_NotFound  = 3011


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed wanting {n}, got {len(buf)}")
        buf += chunk
    return buf


def _hdr(streamid, status, dlen):
    return struct.pack(">2sHI", streamid, status, dlen)


def _bootstrap_login_ok(conn):
    """Handshake + kXR_protocol + kXR_login → kXR_ok (anonymous session)."""
    _recv_exact(conn, 20)
    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _recv_exact(conn, 24)
    conn.sendall(_hdr(hdr[:2], kXR_ok, 8))
    conn.sendall(struct.pack(">II", 0x00000520, 1))

    hdr = _recv_exact(conn, 24)
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    conn.sendall(_hdr(hdr[:2], kXR_ok, 16))
    conn.sendall(b"\x01" * 16)


def _read_request(conn):
    """Read one request; return (streamid, reqid, payload)."""
    hdr = _recv_exact(conn, 24)
    reqid = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[20:24])[0]
    payload = _recv_exact(conn, dlen) if dlen else b""
    return hdr[:2], reqid, payload


def _send_error(conn, sid, code, msg):
    body = struct.pack(">I", code) + msg.encode() + b"\x00"
    conn.sendall(_hdr(sid, kXR_error, len(body)))
    conn.sendall(body)


class _StubServer:
    """A minimal root:// server driven by a per-connection handler.

    Each accepted connection is bootstrapped through the anonymous handshake and
    then handed to `handler(conn, captured)`, where `captured` is a shared list
    the handler appends request payloads to for the test to assert on.
    """

    def __init__(self, handler):
        self.handler = handler
        self.captured = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        from ephemeral_port import free_port
        self.sock.bind(("127.0.0.1", free_port("127.0.0.1")))  # net-literal-allow: local test stub
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()  # net-literal-allow: local test stub
        except OSError:
            pass
        self.sock.close()
        self._thread.join(timeout=5)
        return False

    def _serve(self):
        self.sock.settimeout(1.0)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            if self._stop:
                conn.close()
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            conn.settimeout(20)
            _bootstrap_login_ok(conn)
            self.handler(conn, self.captured)
        except (OSError, ConnectionResetError, AssertionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ===========================================================================
# §7.4 — tried= / triedrc= emission
# ===========================================================================
@pytest.mark.skipif(not os.path.exists(_XRDFS),
                    reason="brix-xrdfs not built (client/bin/xrdfs)")
class TestTriedEmission:
    """A redirector that hands out a DEAD data server must be told so.

    Flow the stub drives: the client stats a path against the stub (its `home`
    manager), the stub redirects to a port with nothing listening, the client's
    reconnect to that port fails and it falls back to home — and THAT replay is
    the request that must now carry tried=<dead-endpoint>&triedrc=<reason>.

    Without the feedback the manager can only re-select blindly and may hand
    back the same dead server, which the client then rejects as a redirect loop
    (a confusing error for what is really "that replica is down").
    """

    @staticmethod
    def _redirect_then_capture(dead_port):
        """Handler: first session → redirect to dead_port; later → capture."""
        state = {"redirected": False}

        def handler(conn, captured):
            sid, _reqid, payload = _read_request(conn)
            if not state["redirected"]:
                state["redirected"] = True
                body = struct.pack(">I", dead_port) + b"127.0.0.1"  # net-literal-allow: redirect wire payload
                conn.sendall(_hdr(sid, kXR_redirect, len(body)))
                conn.sendall(body)
                return
            captured.append(payload)
            _send_error(conn, sid, kXR_NotFound, "stub: done capturing")

        return handler

    def test_dead_redirect_target_reported_to_manager(self):
        """The manager-fallback replay carries tried= and triedrc=."""
        dead = free_port()
        with _StubServer(self._redirect_then_capture(dead)) as stub:
            res = subprocess.run(
                [_XRDFS, f"root://127.0.0.1:{stub.port}/", "stat", "/probe.bin"],  # net-literal-allow: local stub URL
                capture_output=True, text=True, timeout=60)
            # The stub always ends with NotFound, so the command fails; what is
            # under test is the payload it captured on the way there.
            assert res.returncode != 0, res.stdout

            assert stub.captured, (
                "the client never replayed against the manager after the "
                "redirect target died")
            replay = stub.captured[-1].decode("latin-1")
            assert "tried=" in replay, f"no tried= in replay: {replay!r}"
            assert "triedrc=" in replay, f"no triedrc= in replay: {replay!r}"
            # It must name the endpoint that actually died, not a placeholder.
            assert f"127.0.0.1:{dead}" in replay, (  # net-literal-allow: redirect wire payload
                f"tried= does not name the dead target: {replay!r}")

    def test_triedrc_uses_a_stock_reason_token(self):
        """triedrc= carries one of the reference spellings, not an invention.

        A redirector may weight re-selection on the reason, so an ad-hoc token
        would be noise on the wire. An unreachable endpoint is an I/O failure
        from the redirector's point of view.
        """
        dead = free_port()
        with _StubServer(self._redirect_then_capture(dead)) as stub:
            subprocess.run(
                [_XRDFS, f"root://127.0.0.1:{stub.port}/", "stat", "/probe.bin"],  # net-literal-allow: local stub URL
                capture_output=True, text=True, timeout=60)
            assert stub.captured
            replay = stub.captured[-1].decode("latin-1")
            rc = replay.split("triedrc=", 1)[1].split("&")[0].split("\x00")[0]
            assert rc in ("enoent", "ioerr", "fserr", "srverr"), (
                f"triedrc={rc!r} is not a reference token")
            assert rc == "ioerr", (
                f"an unreachable endpoint should report ioerr, got {rc!r}")

    def test_no_redirect_means_no_tried_cgi(self):
        """A request that never fails over must go out byte-identical.

        The feedback is failure-driven: emitting tried= on a first attempt would
        tell a redirector this client had already visited servers it had not.
        """
        def handler(conn, captured):
            sid, _reqid, payload = _read_request(conn)
            captured.append(payload)
            _send_error(conn, sid, kXR_NotFound, "stub: first attempt")

        with _StubServer(handler) as stub:
            subprocess.run(
                [_XRDFS, f"root://127.0.0.1:{stub.port}/", "stat", "/probe.bin"],  # net-literal-allow: local stub URL
                capture_output=True, text=True, timeout=60)
            assert stub.captured
            first = stub.captured[0].decode("latin-1")
            assert "tried=" not in first, f"unsolicited tried=: {first!r}"
            assert "triedrc=" not in first


# ===========================================================================
# §7.5 — --tpc delegate must actually request delegation
# ===========================================================================
@pytest.mark.skipif(not os.path.exists(_XRDCP),
                    reason="brix-xrdcp not built (client/bin/xrdcp)")
class TestTpcDelegate:
    """`--tpc delegate` used to emit a hardcoded tpc.dlgon=0.

    That made it byte-identical to `--tpc first` on the wire: a destination that
    honours dlgon never ran the delegated flow, so the mode silently did
    nothing. These tests read the destination-open opaque off the wire.
    """

    @staticmethod
    def _capture_dst_opaque():
        """Handler: answer the placement stat, capture the destination open."""
        def handler(conn, captured):
            while True:
                sid, reqid, payload = _read_request(conn)
                if reqid == kXR_stat:
                    # Minimal ASCII stat body: id size flags mtime.
                    body = b"0 1024 0 0\x00"
                    conn.sendall(_hdr(sid, kXR_ok, len(body)))
                    conn.sendall(body)
                    continue
                if reqid == kXR_open:
                    captured.append(payload)
                    _send_error(conn, sid, kXR_NotFound, "stub: captured open")
                    return
                _send_error(conn, sid, kXR_NotFound, "stub: unexpected op")
                return

        return handler

    def _run_tpc(self, mode, stub_port):
        src = f"root://127.0.0.1:{stub_port}//src.bin"  # net-literal-allow: local stub URL
        dst = f"root://127.0.0.1:{stub_port}//dst.bin"  # net-literal-allow: local stub URL
        return subprocess.run(
            [_XRDCP, "-s", "--tpc", mode, src, dst],
            capture_output=True, text=True, timeout=90)

    def _opaque_for(self, mode):
        with _StubServer(self._capture_dst_opaque()) as stub:
            self._run_tpc(mode, stub.port)
            opens = [p.decode("latin-1") for p in stub.captured]
            assert opens, f"--tpc {mode}: stub captured no open"
            dst_opens = [o for o in opens if "tpc.dlgon=" in o]
            assert dst_opens, f"--tpc {mode}: no destination open: {opens!r}"
            return dst_opens[0]

    def test_delegate_sets_dlgon_1(self):
        """--tpc delegate asks the destination to read the source AS the user."""
        assert "tpc.dlgon=1" in self._opaque_for("delegate")

    def test_first_keeps_dlgon_0(self):
        """--tpc first must NOT ask for delegation — the flag is what differs."""
        opaque = self._opaque_for("first")
        assert "tpc.dlgon=0" in opaque
        assert "tpc.dlgon=1" not in opaque

    def test_only_keeps_dlgon_0(self):
        """--tpc only is a non-delegating mode too."""
        assert "tpc.dlgon=0" in self._opaque_for("only")

    def test_delegation_refusal_names_the_flag(self):
        """A session that did not opt in refuses the delegation round clearly.

        Security-negative: signing a peer's proxy request hands it a credential
        that speaks as this user, so it must never happen implicitly — and the
        refusal must tell the operator how to opt in rather than failing with a
        bare auth error.
        """
        src = os.path.join(_REPO, "client", "lib", "auth", "sec", "sec_gsi.c")
        text = Path(src).read_text()
        assert "gsi_delegation_enabled" in text, (
            "the advertise-vs-honour rule must live in ONE predicate")
        assert "--tpc delegate" in text and "XRDC_GSI_DELEGATE" in text, (
            "the refusal must name both ways to enable delegation")


# ===========================================================================
# §4.4 — brix_cache_only_if_cached
# ===========================================================================
@pytest.mark.skipif(not os.path.exists(_XRDFS),
                    reason="brix-xrdfs not built (client/bin/xrdfs)")
class TestOnlyIfCached:
    """A cache-only node serves what it holds and refuses what it does not."""

    @pytest.fixture(scope="class")
    def instance(self, tmp_path_factory):
        base = tmp_path_factory.mktemp("audit-oic")
        data = base / "data"
        cache = base / "cache"
        export = base / "export"
        for p in (data, cache, export, export / "oic", cache / "oic"):
            p.mkdir(parents=True, exist_ok=True)

        harness = LifecycleHarness()
        spec = NginxInstanceSpec(
            name="lc-audit-onlyifcached",
            template="nginx_lc_audit_onlyifcached.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_ROOT": str(data),
                "CACHE_ROOT": str(cache),
                "EXPORT_ROOT": str(export),
            },
            reason="audit §4.4 only-if-cached")
        try:
            endpoint = harness.start(spec)
        except Exception as exc:                                # noqa: BLE001
            harness.close()
            pytest.skip(f"only-if-cached instance did not start: {exc}")
        try:
            yield endpoint, data, cache
        finally:
            harness.close()

    def test_uncached_read_is_refused_not_filled(self, instance):
        """The miss must NOT be filled — that is the whole mode.

        The object is readable from the source, so an ordinary cache would fill
        and serve it. Refusing, AND leaving the cache store empty, is what
        proves the source was never pulled from.
        """
        endpoint, data, cache = instance
        (data / "never-cached.bin").write_bytes(b"o" * 4096)

        res = subprocess.run(
            [_XRDCP, "-f", "-s",
             f"root://{HOST}:{endpoint.port}//never-cached.bin",
             str(data.parent / "pulled-miss.bin")],
            capture_output=True, text=True, timeout=60)
        assert res.returncode != 0, (
            "only_if_cached served an object it had not cached")

        filled = [p for p in (cache / "oic").rglob("*") if p.is_file()]
        assert not filled, (
            f"the refused read still filled the cache: {[str(p) for p in filled]}")

    @staticmethod
    def _raw_open(port, path):
        """Anonymous login + kXR_open; return (status, kXR error code)."""
        sock = socket.create_connection((HOST, port), timeout=20)
        try:
            sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
            _recv_exact(sock, 16)

            def req(reqid, body=b"", payload=b""):
                hdr = b"\x00\x01" + struct.pack(">H", reqid)
                hdr += body.ljust(16, b"\x00")
                hdr += struct.pack(">I", len(payload))
                sock.sendall(hdr + payload)
                rsp = _recv_exact(sock, 8)
                status = struct.unpack(">H", rsp[2:4])[0]
                dlen = struct.unpack(">I", rsp[4:8])[0]
                data = _recv_exact(sock, dlen) if dlen else b""
                return status, data

            assert req(3006)[0] == kXR_ok, "protocol"
            assert req(3007, payload=b"anonymous\x00")[0] == kXR_ok, "login"

            body = struct.pack(">HH", 0o644, 0x0010) + b"\x00" * 12
            status, data = req(kXR_open, body=body,
                               payload=path.encode() + b"\x00")
            code = struct.unpack(">I", data[:4])[0] if (
                status == kXR_error and len(data) >= 4) else 0
            return status, code
        finally:
            sock.close()

    def test_refusal_is_not_found_so_clients_fail_over(self, instance):
        """The refusal must read as "not here", not as a server fault.

        A client that sees a transport/server error retries the same node; one
        that sees kXR_NotFound moves to another replica, which is the behaviour
        this mode exists to produce.

        The gate lives in the cache decorator's OPEN path (the audit scopes it
        to sd_cache_open_common), so this drives kXR_open directly. kXR_stat is
        deliberately NOT gated — metadata still answers truthfully.
        """
        endpoint, data, _cache = instance
        (data / "elsewhere.bin").write_bytes(b"e" * 2048)

        status, code = self._raw_open(endpoint.port, "/elsewhere.bin")
        assert status == kXR_error, (
            f"only_if_cached opened an uncached object (status={status})")
        assert code == kXR_NotFound, (
            f"refusal should be kXR_NotFound so a client fails over, got {code}")


# ===========================================================================
from split_continuation import load as _load_audit_fixes
_load_audit_fixes(globals(), __file__, "_test_audit_fixes_2026_08_09_part2.py")
