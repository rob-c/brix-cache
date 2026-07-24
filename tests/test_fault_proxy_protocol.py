"""
test_fault_proxy_protocol.py — tests for the protocol-surgery + oracle toolkit of
brix-fault-proxy (client/apps/diag/brix_fault_proxy.c):

  1. TLS record surgery   — set-type / fragment / set-version on the 5-byte record
                            header, walked record-by-record on the live stream.
  2. HTTP smuggling       — CL.TE / TE.CL desync, Transfer-Encoding obfuscation,
                            naked-LF line endings injected into a request.
  3. session record/replay— capture the byte timeline to a framed file, then act as
                            a synthetic peer replaying it with no live upstream.
  4. auto-bisection       — binary-search the smallest lever value at which an
                            operator probe (exit!=0) reproduces a bug.
  5. assert-recovery      — apply a fault, hold, clear, then poll a health probe
                            until it passes (or times out => STUCK).

Bisection + recovery spawn an operator-supplied probe, so they are DOUBLE-GATED on
--enable-exec exactly like the privileged netem levers: without the flag every
oracle verb refuses.

The 3-test ritual for this surface:

* SUCCESS  — each transform rewrites exactly the bytes it promises on the wire; a
             capture round-trips through replay with a dead upstream; bisect
             converges to a minimal value; recovery reports "recovered".
* ERROR    — malformed sub-verbs / arg counts are rejected with `err:` and leave
             the stream untouched (a passthrough byte-for-byte).
* SECURITY — the oracle verbs refuse without --enable-exec; the probe string is
             run via /bin/sh -c in its own process group (never inherits the
             proxy's sockets), and `clear` fully disarms the TLS/HTTP transforms.

Self-contained: builds the tool and drives it against a throwaway, crash-proof echo
server on ephemeral loopback ports. No root, no fleet server.
"""

import os
import socket
import subprocess
import threading
import time

import pytest

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")


@pytest.fixture(scope="module")
def bfp():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.02)
    return False


class _Echo:
    """Crash-proof streaming echo upstream. The accept loop swallows *every*
    transient error (a bare `except: break` here would masquerade as a proxy
    wedge), so it stays available for the whole test even under fork churn."""

    def __init__(self):
        self.port = _free_port()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(64)
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self._srv.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(3.0)
        try:
            while not self._stop:
                d = conn.recv(65536)
                if not d:
                    break
                conn.sendall(d)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _spawn(bfp, target_port, enable_exec=False):
    listen, ctl = _free_port(), _free_port()
    argv = [bfp, "--listen", str(listen), "--target", f"127.0.0.1:{target_port}",
            "--control", str(ctl), "--quiet"]
    if enable_exec:
        argv.append("--enable-exec")
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert _wait_port(ctl) and _wait_port(listen), "proxy never came up"
    return proc, listen, ctl


def _ctl(port, cmd):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(4096).decode()


def _roundtrip(listen, payload, wait=0.2):
    """Send `payload`, half-close, drain the reply. Tolerates a peer that closes
    first (replay mode answers then hangs up)."""
    out = b""
    with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
        s.settimeout(2.0)
        try:
            s.sendall(payload)
            time.sleep(wait)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
        except OSError:
            pass
    return out


def _poll_result(ctl, verb, deadline=30.0):
    end = time.time() + deadline
    last = ""
    while time.time() < end:
        last = _ctl(ctl, verb).strip()
        if last.startswith("done") or last.startswith("error"):
            return last
        time.sleep(0.2)
    return last


# A syntactically valid TLS application-data record: type 23, version 3.3, len 4.
_TLS_REC = bytes([23, 3, 3, 0, 4]) + b"PING"


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #
def test_tls_set_type_relabels_content_type(bfp):
    """`tls set-type` rewrites the record's content-type byte (23 -> 21 = alert)."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert _roundtrip(listen, _TLS_REC) == _TLS_REC          # passthrough first
        _ctl(ctl, "tls set-type 21 up")
        out = _roundtrip(listen, _TLS_REC)
        assert out and out[0] == 21, f"content-type not relabeled: {out!r}"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_tls_fragment_splits_one_record_into_many(bfp):
    """`tls fragment N` re-emits the payload as multiple <=N-byte records, each
    with its own valid 5-byte header."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "tls fragment 2 up")
        out = _roundtrip(listen, _TLS_REC)
        assert len(out) > len(_TLS_REC), f"not fragmented: {out!r}"
        # first fragment: header for a 2-byte record carrying the first 2 payload bytes
        assert out[:5] == bytes([23, 3, 3, 0, 2]) and out[5:7] == b"PI", repr(out[:7])
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_tls_set_version_downgrades_record(bfp):
    """`tls set-version` rewrites the record's protocol-version bytes (3.3 -> 3.1)."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "tls set-version 3 1 up")
        out = _roundtrip(listen, _TLS_REC)
        assert out and out[1] == 3 and out[2] == 1, f"version not downgraded: {out!r}"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_http_cl_te_injects_both_framing_headers(bfp):
    """`http cl-te` desync stamps BOTH a Content-Length and a chunked
    Transfer-Encoding onto the request so front/back end disagree on the boundary."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "http cl-te up")
        out = _roundtrip(listen, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"Content-Length" in out and b"Transfer-Encoding" in out, repr(out)
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_http_obfuscate_te_mangles_header_name(bfp):
    """`http obfuscate-te 1` rewrites a present Transfer-Encoding header name with a
    space before the colon — parsers that don't normalize it will skip the header."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "http obfuscate-te 1 up")
        req = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        out = _roundtrip(listen, req)
        assert b"Transfer-Encoding :" in out, repr(out[:90])
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_http_naked_lf_strips_carriage_returns(bfp):
    """`http naked-lf` re-terminates header lines with a bare LF (no CR)."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "http naked-lf up")
        out = _roundtrip(listen, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert out and b"\r" not in out and b"\n" in out, repr(out)
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_record_then_replay_reproduces_session_without_upstream(bfp, tmp_path):
    """A recorded byte timeline replays back to a fresh client with the upstream
    gone — the proxy becomes a synthetic peer."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    cap = str(tmp_path / "sess.bfpr")
    try:
        assert "ok" in _ctl(ctl, f"record {cap}")
        assert _roundtrip(listen, b"HELLO") == b"HELLO"          # live echo, captured
        _ctl(ctl, "record off")
        assert os.path.exists(cap) and os.path.getsize(cap) > 5, "empty capture"

        echo.close()                                             # kill the upstream
        _ctl(ctl, "replay dir down")
        assert "replaying" in _ctl(ctl, f"replay {cap}")
        out = _roundtrip(listen, b"anything-goes")
        assert b"HELLO" in out, f"replay did not reproduce recorded bytes: {out!r}"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_bisect_converges_to_minimal_reproducing_value(bfp, tmp_path):
    """auto-bisection finds the smallest `latency` at which a 120ms-timeout probe
    fails — proving monotonic binary search over a real lever."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port, enable_exec=True)
    probe = str(tmp_path / "probe.py")
    with open(probe, "w") as f:
        f.write("import socket,sys\n"
                "s=socket.socket(); s.settimeout(0.12)\n"
                "try:\n"
                f" s.connect(('127.0.0.1',{listen})); s.sendall(b'x'); s.recv(16); sys.exit(0)\n"
                "except Exception: sys.exit(1)\n")
    try:
        r = _ctl(ctl, f"bisect latency 0 400 600 python3 {probe}")
        assert "bisecting latency" in r, r
        res = _poll_result(ctl, "bisect-result", deadline=40)
        assert res.startswith("done: minimal latency="), res
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_recovery_asserts_service_comes_back(bfp, tmp_path):
    """assert-recovery: block the service, hold, auto-clear, then poll a health
    probe until it passes -> 'recovered'."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port, enable_exec=True)
    probe = str(tmp_path / "health.py")
    with open(probe, "w") as f:
        f.write("import socket,sys\n"
                f"s=socket.create_connection(('127.0.0.1',{listen}),1); s.sendall(b'ping')\n"
                "s.settimeout(1); r=s.recv(64); s.close(); sys.exit(0 if r==b'ping' else 1)\n")
    try:
        r = _ctl(ctl, f"recovery block | 200 | python3 {probe} | 5000")
        assert "recovery probe started" in r, r
        res = _poll_result(ctl, "recovery-result", deadline=20)
        assert res.startswith("done: recovered"), res
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #
def test_tls_unknown_subverb_rejected_stream_untouched(bfp):
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err:" in _ctl(ctl, "tls bogus 5 up")
        assert _roundtrip(listen, _TLS_REC) == _TLS_REC, "rejected verb still mutated stream"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_http_unknown_subverb_rejected(bfp):
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err:" in _ctl(ctl, "http not-a-mode up")
        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        assert _roundtrip(listen, req) == req, "rejected verb still mutated stream"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_replay_missing_capture_rejected(bfp, tmp_path):
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err:" in _ctl(ctl, f"replay {tmp_path / 'nope.bfpr'}")
        # replay never armed -> stream still proxies live
        assert _roundtrip(listen, b"LIVE") == b"LIVE"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_bisect_bad_arity_rejected(bfp):
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port, enable_exec=True)
    try:
        # missing the oracle command
        assert "err:" in _ctl(ctl, "bisect latency 0 10 500")
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# SECURITY                                                                     #
# --------------------------------------------------------------------------- #
def test_oracle_refused_without_enable_exec(bfp):
    """Both oracle verbs refuse to spawn anything unless --enable-exec was given."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)   # NO --enable-exec
    try:
        assert "needs --enable-exec" in _ctl(ctl, "bisect latency 0 10 500 /bin/true")
        assert "needs --enable-exec" in _ctl(ctl, "recovery block | 10 | /bin/true | 500")
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_clear_disarms_tls_and_http_transforms(bfp):
    """`clear` must fully reset the TLS/HTTP surgery back to byte-for-byte passthrough
    (a stuck transform would silently corrupt every later connection)."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "tls set-type 21 up")
        _ctl(ctl, "http naked-lf up")
        assert _roundtrip(listen, _TLS_REC)[0] == 21             # armed
        _ctl(ctl, "clear")
        assert _roundtrip(listen, _TLS_REC) == _TLS_REC, "TLS transform survived clear"
        out = _roundtrip(listen, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"\r\n" in out, "HTTP transform survived clear"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_oracle_probe_does_not_inherit_proxy_sockets(bfp, tmp_path):
    """The forked probe runs in its own process group with the proxy's descriptors
    closed: a probe that lists its open fds must not see the listen/control sockets,
    and the proxy keeps serving after the probe exits."""
    echo = _Echo()
    proc, listen, ctl = _spawn(bfp, echo.port, enable_exec=True)
    marker = str(tmp_path / "fds.txt")
    probe = str(tmp_path / "leak.py")
    with open(probe, "w") as f:
        # Fail (exit 1) so recovery keeps the fault cleared and just records; write
        # the count of inherited sockets above stdio for inspection.
        f.write("import os,sys\n"
                "fds=[fd for fd in os.listdir('/proc/self/fd') if int(fd)>2]\n"
                f"open({marker!r},'w').write(str(len(fds)))\n"
                "sys.exit(1)\n")
    try:
        _ctl(ctl, f"recovery latency 1 | 50 | python3 {probe} | 800")
        _poll_result(ctl, "recovery-result", deadline=10)
        assert os.path.exists(marker), "probe never ran"
        # /bin/sh + python open a couple of their own fds; the proxy's listen/control
        # relay sockets (many) must not be among them.
        assert int(open(marker).read()) <= 4, "probe inherited proxy descriptors"
        # proxy still serves after the probe churn
        assert _roundtrip(listen, b"STILL-UP") == b"STILL-UP"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()
