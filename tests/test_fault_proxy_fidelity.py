"""
test_fault_proxy_fidelity.py — behaviour tests for the brix-fault-proxy
feature-expansion levers (docs/refactor/brix-fault-proxy-feature-expansion.md,
Track U): per-direction toxicity (B1), slow-close (B2), connect-delay (B3),
refuse (B4), latency distribution shaping (B6), persistent control sessions
(A1) and the Prometheus metrics command (D1).

Each lever follows the house 3-test ritual:

* SUCCESS  — the lever changes observable relay behaviour (or the status/metrics
             snapshot) the way its grammar promises.
* ERROR    — a malformed argument (negative delay, unknown distribution, missing
             operand) is rejected with an `err` reply and does *not* mutate state.
* SECURITY / NEG — the boundary that keeps the lever safe: toxicity 0 must fully
             suppress an otherwise-armed fault, refuse must actually drop the
             connection (fail-closed), and an over-long control line must be
             refused rather than overrun the parser buffer.

Self-contained: reuses the echo upstreams + spawn/ctl helpers from
test_brix_fault_proxy on ephemeral ports. No fleet server, so no registry
declaration is required.
"""

import json
import socket
import subprocess
import time

import pytest

from settings import HOST
from test_brix_fault_proxy import (  # noqa: F401  (bfp is a re-exported fixture)
    _Echo,
    _StreamEcho,
    _ctl,
    _drain,
    _free_port,
    _spawn,
    bfp,
)

pytestmark = pytest.mark.timeout(120)


def _session(port, cmds):
    """Send several newline-delimited commands over ONE control connection and
    return the concatenated replies — exercises the A1 persistent session."""
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(("".join(c + "\n" for c in cmds)).encode())
        s.settimeout(1.0)
        out = b""
        end = time.time() + 2.0
        while time.time() < end:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        return out.decode(errors="replace")


# --------------------------------------------------------------------------- #
# B1 — per-connection toxicity gate                                            #
# --------------------------------------------------------------------------- #
class TestToxicity:
    def test_zero_toxicity_suppresses_armed_corruption(self, bfp):
        """SECURITY/NEG: corruption armed at 100% but toxicity 0 => byte-exact."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "corrupt 100 down")
            assert "ok" in _ctl(ctl, "toxicity 0 down")
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                assert _drain(s, len(b"echo:hello")) == b"echo:hello"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_full_toxicity_lets_corruption_through(self, bfp):
        """SUCCESS: default toxicity (100%) leaves an armed fault active."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "corrupt 100 down")
            assert "ok" in _ctl(ctl, "toxicity 100 down")
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                out = _drain(s, len(b"echo:hello"))
                assert out != b"echo:hello"  # every byte flipped
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_negative_toxicity_rejected(self, bfp):
        """ERROR: a negative percentage is refused and leaves the gate at 100%."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "toxicity -5 down")
            assert "tox=100.0000/100.0000%" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# B2 — slow-close (delayed FIN)                                               #
# --------------------------------------------------------------------------- #
class TestSlowClose:
    def test_slow_close_delays_eof(self, bfp):
        """SUCCESS: with slow-close armed, EOF arrives noticeably after the data."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "slow-close 400 both")
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                assert _drain(s, len(b"echo:hello")) == b"echo:hello"
                t0 = time.time()
                s.settimeout(3.0)
                assert s.recv(64) == b""       # blocks until the delayed close
                dt = time.time() - t0
            if dt >= 0:                        # WSL2 clock can step backwards
                assert dt >= 0.15
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_slow_close_shown_in_status(self, bfp):
        """SUCCESS: the lever is reflected in the per-direction status snapshot."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            _ctl(ctl, "slow-close 250 up")
            st = _ctl(ctl, "status")
            assert "sclose=250" in st.split("down[")[0]      # up side
            assert "sclose=0" in st.split("down[")[1]        # down untouched
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_negative_slow_close_rejected(self, bfp):
        """ERROR: a negative delay is refused and leaves the lever at 0."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "slow-close -1 both")
            assert "sclose=0" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# B3 — connect-delay (upstream dial latency)                                  #
# --------------------------------------------------------------------------- #
class TestConnectDelay:
    def test_connect_delay_defers_first_byte(self, bfp):
        """SUCCESS: the first echoed byte only arrives after the dial delay."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "connect-delay 400")
            t0 = time.time()
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                assert _drain(s, len(b"echo:hello")) == b"echo:hello"
            dt = time.time() - t0
            if dt >= 0:
                assert dt >= 0.15
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_connect_delay_shown_in_status(self, bfp):
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            _ctl(ctl, "connect-delay 123")
            assert "cdelay=123" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_negative_connect_delay_rejected(self, bfp):
        """ERROR: negative dial delay refused; state stays at 0."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "connect-delay -10")
            assert "cdelay=0" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# B4 — refuse (probabilistic accept drop)                                     #
# --------------------------------------------------------------------------- #
class TestRefuse:
    def test_full_refuse_drops_connection(self, bfp):
        """SECURITY/NEG: refuse 100% => the connection is accepted then dropped
        with no upstream echo, and the refused counter advances."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "refuse 100")
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                assert _drain(s, 16, deadline=1.0) == b""
            assert "refused=0 " not in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_zero_refuse_passes(self, bfp):
        """SUCCESS: the default (0%) forwards normally."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "refuse 0")
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                assert _drain(s, len(b"echo:hello")) == b"echo:hello"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_negative_refuse_rejected(self, bfp):
        """ERROR: a negative percentage is refused; state stays at 0%."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "refuse -1")
            assert "refuse=0.0000%" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# B6 — latency distribution shaping                                           #
# --------------------------------------------------------------------------- #
class TestLatencyDist:
    def test_normal_distribution_recorded(self, bfp):
        """SUCCESS: `latency-dist normal <mean> <sigma>` sets dist=1 and mean."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "latency-dist normal 80 20 both")
            st = _ctl(ctl, "status")
            assert "dist=1" in st and "jit=80" in st
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_uniform_distribution_recorded(self, bfp):
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "ok" in _ctl(ctl, "latency-dist uniform 40 both")
            st = _ctl(ctl, "status")
            assert "dist=0" in st and "jit=40" in st
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_bad_distribution_rejected(self, bfp):
        """ERROR: an unknown shape or a missing mean is refused (dist stays 0)."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "latency-dist bogus 10 both")
            assert "err" in _ctl(ctl, "latency-dist normal both")
            assert "dist=1" not in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# B5 — token-bucket rate + burst                                              #
# --------------------------------------------------------------------------- #
class TestRate:
    """B5: `rate <KB/s>` is now a monotonic-clock token bucket (not a bursty
    per-segment usleep); `burst <bytes>` sets the bucket depth so a short
    transfer can spend accumulated credit up front. Buckets are per-connection
    (relay_pump stack), so every fresh connection starts with a full bucket."""

    @staticmethod
    def _drive(listen, n):
        """Send `n` bytes up; the stream echo bounces them down (where the rate
        gate applies); return (bytes_drained, seconds) for the full round trip.
        Timed on time.monotonic() to match the gate's CLOCK_MONOTONIC."""
        payload = b"x" * n
        t0 = time.monotonic()
        with socket.create_connection((HOST, listen), timeout=5) as s:
            s.sendall(payload)
            s.settimeout(5.0)
            got = 0
            while got < n:
                d = s.recv(65536)
                if not d:
                    break
                got += len(d)
        return got, time.monotonic() - t0

    def test_rate_limits_throughput(self, bfp):
        """SUCCESS: `rate 256 down` paces a 128 KiB download to ~size/rate. A
        tight ±15%% band is unreliable on the WSL2 stepping clock
        ([[wsl2-clock-backwards-steps]]), so assert a firm lower bound only
        pacing can produce plus a broad order-of-magnitude rate band."""
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert _ctl(ctl, "rate 256 down").strip() == "ok"
            n = 128 * 1024
            got, dt = self._drive(listen, n)
            assert got == n
            # 128 KiB / 256 KiB/s = 0.5 s; the default 1500 B burst is
            # negligible, so pacing MUST cost real wall time.
            assert dt >= 0.25, f"transfer too fast ({dt:.3f}s) — not paced"
            kbps = n / 1024.0 / dt
            assert 96.0 <= kbps <= 640.0, f"measured {kbps:.0f} KB/s off 256"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_burst_credit_speeds_short_transfer(self, bfp):
        """SUCCESS: a burst >= the transfer size lets it complete from credit,
        materially faster than the same rate with the default MTU-sized bucket."""
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            n = 64 * 1024
            assert _ctl(ctl, "rate 128 down").strip() == "ok"
            _, slow = self._drive(listen, n)            # ~0.5 s throttled
            assert _ctl(ctl, f"burst {n} down").strip() == "ok"
            _, fast = self._drive(listen, n)            # covered by initial credit
            assert fast < slow, f"burst did not help (slow={slow:.3f} fast={fast:.3f})"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_negative_rate_and_burst_rejected(self, bfp):
        """ERROR: negative rate/burst are refused; the levers stay at 0."""
        echo = _StreamEcho()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "rate -1 down")
            assert "err" in _ctl(ctl, "burst -1 down")
            st = _ctl(ctl, "status")
            assert "rate=0" in st and "burst=0" in st
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_rate_gate_never_stalls(self, bfp):
        """SECURITY/NEG: the gate paces off CLOCK_MONOTONIC and clamps a
        backward step to zero credit (never a negative usleep), so a rated
        transfer always completes in bounded time and never wedges the relay.
        (Injecting a true clock step needs privilege / a fake clock; the
        monotonic clamp lives in fault_rate_gate — this asserts the observable
        bounded-completion safety property.)"""
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            assert _ctl(ctl, "rate 512 both").strip() == "ok"
            got, dt = self._drive(listen, 64 * 1024)
            assert got == 64 * 1024
            assert dt < 5.0, f"rated transfer stalled ({dt:.3f}s)"
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# A1 — persistent control sessions                                            #
# --------------------------------------------------------------------------- #
class TestPersistentSession:
    def test_many_commands_one_connection(self, bfp):
        """SUCCESS: several commands over a single socket each get a reply."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            out = _session(ctl, ["latency 15 up", "corrupt 25 down", "status"])
            assert out.count("ok") >= 2            # two setters acked
            assert "up[lat=15" in out              # status reply present
            assert "corrupt=25.0000%" in out.split("down[")[1]
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_quit_closes_session(self, bfp):
        """SUCCESS: `quit` ends the session; the socket then reads EOF."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            with socket.create_connection((HOST, ctl), timeout=3) as s:
                s.sendall(b"status\nquit\n")
                s.settimeout(2.0)
                seen = b""
                while True:
                    d = s.recv(4096)
                    if not d:
                        break              # server closed after quit
                    seen += d
                assert b"up[lat=" in seen
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_overlong_line_refused(self, bfp):
        """SECURITY/NEG: a line larger than the parser buffer is refused with a
        diagnostic rather than overrunning it."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            with socket.create_connection((HOST, ctl), timeout=3) as s:
                s.sendall(b"latency " + b"9" * 4096 + b"\n")
                s.settimeout(2.0)
                seen = b""
                try:
                    while len(seen) < 64:
                        d = s.recv(4096)
                        if not d:
                            break
                        seen += d
                except socket.timeout:
                    pass
                assert b"line too long" in seen
        finally:
            proc.terminate(); proc.wait(); echo.close()


# --------------------------------------------------------------------------- #
# D1 — Prometheus metrics command                                             #
# --------------------------------------------------------------------------- #
class TestJsonControl:
    """A2 JSON control I/O + A4 status-json machine oracle."""

    def test_json_set_and_status(self, bfp):
        """SUCCESS: a JSON lever request acks `{"ok":true}` and the JSON status
        snapshot reflects it as a typed field (no regex of the human string)."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            r = json.loads(_ctl(ctl, '{"cmd":"corrupt","pct":0.02,"dir":"down"}'))
            assert r == {"ok": True}
            st = json.loads(_ctl(ctl, '{"cmd":"status","format":"json"}'))
            assert st["down"]["corrupt_pct"] == 0.02
            assert st["up"]["corrupt_pct"] == 0.0      # other direction untouched
            assert st["flags"]["blocked"] is False     # typed booleans, not "0"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_json_large_bytecount_reprojects_as_integer(self, bfp):
        """SUCCESS/guard: a large byte count must reproject to the verb grammar as
        a plain integer, never `%g` scientific notation (which would defeat the
        verb-side atol). Verified through the human status `trunc=` field."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert json.loads(
                _ctl(ctl, '{"cmd":"truncate-at","at":5242880,"dir":"up"}'))["ok"]
            assert "trunc=5242880" in _ctl(ctl, "status").split("down[")[0]
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_malformed_json_does_not_wedge_grammar(self, bfp):
        """ERROR: a truncated object yields a parse error and the *next* newline
        command on a fresh connection still parses (parser not wedged)."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert json.loads(_ctl(ctl, '{"cmd":'))== {"ok": False, "error": "parse"}
            assert "ok" in _ctl(ctl, "latency 10 up")
            assert "up[lat=10" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_unknown_json_cmd_no_state_change(self, bfp):
        """SECURITY/NEG: an unknown JSON `cmd` is rejected `{"ok":false}` and
        mutates nothing (the status snapshot is byte-identical before/after)."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            # compare only the lever+flag prefix (before " | "); the counters
            # tail races with the spawn-probe connection's async accounting.
            before = _ctl(ctl, "status").split(" | ")[0]
            r = json.loads(_ctl(ctl, '{"cmd":"bogus","pct":99}'))
            assert r == {"ok": False, "error": "unknown command"}
            assert _ctl(ctl, "status").split(" | ")[0] == before
        finally:
            proc.terminate(); proc.wait(); echo.close()


class TestMetrics:
    def test_metrics_exposes_series(self, bfp):
        """SUCCESS: the `metrics` verb emits Prometheus text-exposition series."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            m = _ctl(ctl, "metrics")
            assert "brix_fault_proxy_conns_total" in m
            assert 'brix_fault_proxy_bytes_total{dir="up"}' in m
            assert 'brix_fault_proxy_bytes_total{dir="down"}' in m
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_metrics_counts_traffic(self, bfp):
        """SUCCESS: a completed relay bumps the conns_total counter."""
        echo = _Echo()
        proc, listen, ctl = _spawn(bfp, echo.port)
        try:
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                _drain(s, len(b"echo:hello"))
            time.sleep(0.2)
            total = 0
            for ln in _ctl(ctl, "metrics").splitlines():
                if ln.startswith("brix_fault_proxy_conns_total"):
                    total = int(ln.split()[1])
            assert total >= 1
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_unknown_verb_still_errors(self, bfp):
        """ERROR: metrics didn't broaden the grammar — junk verbs still err."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err: unknown command" in _ctl(ctl, "metricz")
        finally:
            proc.terminate(); proc.wait(); echo.close()


class TestCtlClient:
    """A3: first-party `ctl <host:port> <cmd>` client subcommand — replaces the
    external `nc` dependency with a scriptable exit-code contract."""

    @staticmethod
    def _ctl_cli(bfp, ctl_port, cmd, stdin=None):
        """Run `bfp ctl 127.0.0.1:<ctl_port> <cmd>`; return (rc, stdout)."""
        r = subprocess.run(
            [bfp, "ctl", f"{HOST}:{ctl_port}", cmd],
            input=stdin, capture_output=True, text=True, timeout=10)
        return r.returncode, r.stdout

    def test_status_roundtrip_exit0(self, bfp):
        """SUCCESS: `ctl ... status` prints the status line and exits 0."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            rc, out = self._ctl_cli(bfp, ctl, "status")
            assert rc == 0
            assert "up[lat=" in out and "epoch=" in out
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_set_command_takes_effect_via_cli(self, bfp):
        """SUCCESS: a `ctl` set is observed by an independent status query —
        the client really drives the live daemon, not a private copy."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            rc, out = self._ctl_cli(bfp, ctl, "latency 25 up")
            assert rc == 0 and out.strip() == "ok"
            assert "up[lat=25" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_json_roundtrip_and_error_exit3(self, bfp):
        """SUCCESS+ERROR: JSON requests round-trip; an err reply maps to exit 3
        (both a bad verb and a rejected JSON command)."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            rc, out = self._ctl_cli(bfp, ctl, '{"cmd":"status"}')
            assert rc == 0 and json.loads(out)["up"]["latency_ms"] == 0

            rc, out = self._ctl_cli(bfp, ctl, "bogus")
            assert rc == 3 and "err: unknown command" in out

            rc, out = self._ctl_cli(bfp, ctl, '{"cmd":"nope"}')
            assert rc == 3 and json.loads(out)["ok"] is False
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_stdin_batch_replays_every_command(self, bfp):
        """SUCCESS: `ctl ... -` streams stdin as a persistent session; each
        command's reply is returned in order (proves A1 session reuse)."""
        echo = _Echo()
        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            rc, out = self._ctl_cli(
                bfp, ctl, "-", stdin="corrupt 3 down\nstatus\n")
            assert rc == 0
            assert out.startswith("ok")
            assert "corrupt=3.0000%" in out
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_dead_port_fails_fast_exit4(self, bfp):
        """SECURITY/NEG: a `ctl` to an unbound port fails closed with exit 4 and
        must not hang — the connect timeout is enforced (well under the 10s cap
        via the 3s dial ceiling; assert on the exit code, not wall-clock)."""
        rc, _ = self._ctl_cli(bfp, _free_port(), "status")
        assert rc == 4

    def test_usage_error_exit2(self, bfp):
        """ERROR: `ctl` with no host/command prints usage and exits 2."""
        r = subprocess.run([bfp, "ctl"], capture_output=True, text=True,
                           timeout=10)
        assert r.returncode == 2
        assert "usage:" in r.stderr


class TestEventLog:
    """D2: `--event-log FILE` / live `event-log <path>` — one JSONL object per
    discrete fault event, with NO relayed payload bytes ever written."""

    _MARKER = b"TOPSECRETPAYLOAD-do-not-log-"

    def _drive_marker(self, listen, n):
        """Push `n` marker bytes up (the stream echo bounces them back down,
        where the down-direction levers apply); drain until the proxy closes."""
        payload = (self._MARKER * (n // len(self._MARKER) + 1))[:n]
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(payload)
            s.settimeout(2.0)
            try:
                while s.recv(65536):
                    pass
            except OSError:
                pass

    def test_truncate_event_logged(self, bfp, tmp_path):
        """SUCCESS: a `truncate-at` cut emits a `"event":"truncate"` JSONL line
        carrying the exact `at` byte offset."""
        log = tmp_path / "ev.jsonl"
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port,
                                   extra=["--event-log", str(log)])
        try:
            assert _ctl(ctl, "truncate-at 8192 down").strip() == "ok"
            self._drive_marker(listen, 20000)
            time.sleep(0.3)
            events = [json.loads(ln) for ln in
                      log.read_text().splitlines() if ln.strip()]
            trunc = [e for e in events if e.get("event") == "truncate"]
            assert trunc, f"no truncate event in {events}"
            assert trunc[0]["at"] == 8192
            assert trunc[0]["dir"] == "down"
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_bad_path_fails_closed(self, bfp, tmp_path):
        """ERROR: an unwritable `--event-log` aborts startup (exit 1, no crash);
        a live `event-log` to a bad dir returns `err:` and keeps serving."""
        listen, ctl_p, echo = _free_port(), _free_port(), _StreamEcho()
        r = subprocess.run(
            [bfp, "--listen", str(listen), "--target", f"{HOST}:{echo.port}",
             "--control", str(ctl_p), "--quiet",
             "--event-log", "/no/such/dir/x.jsonl"],
            capture_output=True, text=True, timeout=10)
        assert r.returncode == 1
        assert "event log" in r.stderr

        proc, _, ctl = _spawn(bfp, echo.port)
        try:
            assert "err" in _ctl(ctl, "event-log /no/such/dir/x.jsonl")
            # daemon still healthy after the rejected open
            assert "up[lat=" in _ctl(ctl, "status")
        finally:
            proc.terminate(); proc.wait(); echo.close()

    def test_log_holds_no_payload_bytes(self, bfp, tmp_path):
        """SECURITY/NEG: even with 100%% corruption armed, the event log records
        structural metadata only — a distinctive payload marker never leaks."""
        log = tmp_path / "ev.jsonl"
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port,
                                   extra=["--event-log", str(log)])
        try:
            _ctl(ctl, "corrupt 100 down")
            self._drive_marker(listen, 20000)
            time.sleep(0.3)
            blob = log.read_bytes()
            assert self._MARKER not in blob
            # a corrupt event WAS recorded (count only, no bytes)
            events = [json.loads(ln) for ln in
                      blob.decode(errors="replace").splitlines() if ln.strip()]
            corr = [e for e in events if e.get("event") == "corrupt"]
            assert corr and corr[0]["count"] > 0
            assert "dir" in corr[0] and "count" in corr[0]
        finally:
            proc.terminate(); proc.wait(); echo.close()
