from split_continuation import reexport as _reexport
_reexport(globals(), "_test_fault_proxy_fidelity_helpers")

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
