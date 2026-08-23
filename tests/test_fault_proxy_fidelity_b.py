from split_continuation import reexport as _reexport
def _check_test_truncate_event_logged_1(ctl):
    assert _ctl(ctl, "truncate-at 8192 down").strip() == "ok"

def _check_test_truncate_event_logged_2(trunc):
    assert trunc[0]["dir"] == "down"


_reexport(globals(), "_test_fault_proxy_fidelity_helpers")

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
            _check_test_truncate_event_logged_1(ctl)
            self._drive_marker(listen, 20000)
            time.sleep(0.3)
            events = [json.loads(ln) for ln in
                      log.read_text().splitlines() if ln.strip()]
            trunc = [e for e in events if e.get("event") == "truncate"]
            def _assert_test_truncate_event_logged_1():
                assert trunc, f"no truncate event in {events}"
                assert trunc[0]["at"] == 8192

            _assert_test_truncate_event_logged_1()
            _check_test_truncate_event_logged_2(trunc)
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
            def _assert_test_log_holds_no_payload_bytes_2():
                assert corr and corr[0]["count"] > 0
                assert "dir" in corr[0] and "count" in corr[0]

            _assert_test_log_holds_no_payload_bytes_2()
        finally:
            proc.terminate(); proc.wait(); echo.close()
