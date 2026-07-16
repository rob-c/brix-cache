"""
Phase-65 bad-actor guard — root:// stream relay (brix_guard_stream).

Self-contained: a real nginx-xrootd origin (anon auth) behind two transparent
relays — one with `brix_guard_stream on;`, one without — driven by the
clean-room xrdfs client.

Verifies: clean ops relayed byte-exact through the guarded relay, a junk-path
signature (kXR_stat /wp-login.php) drops the connection with one
signal=signature proto=root audit line, a kXR_NotFound response logs
signal=notfound, and the unguarded relay passes the same junk untouched
(guard defaults off).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_stream_guard.py -v -p no:xdist
"""

import os
import pathlib
import subprocess
import time

import pytest

from guard_http_lib import NGINX_BIN
from settings import BIND_HOST
from server_registry import NginxInstanceSpec

REPO = pathlib.Path(__file__).resolve().parents[1]
XRDFS = str(REPO / "client" / "bin" / "xrdfs")

pytestmark = [pytest.mark.timeout(180), pytest.mark.uses_lifecycle_harness]


def _xrdfs(port, *args, timeout=30):
    # XRDC_MAX_STALL_MS=0 = fail fast: a guard connection-drop must surface as
    # an error, not a 30s reconnect-retry stall.
    env = dict(os.environ, XRDC_MAX_STALL_MS="0")
    return subprocess.run(
        [XRDFS, f"root://{BIND_HOST}:{port}", *args],
        capture_output=True, text=True, timeout=timeout, env=env)


def _guard_lines(prefix):
    log = prefix / "error.log"
    if not log.exists():
        return []
    return [ln for ln in log.read_text().splitlines() if "signal=" in ln]


@pytest.fixture()
def relays(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not os.access(XRDFS, os.X_OK):
        pytest.skip(f"xrdfs not built: {XRDFS}")

    # brix_export is validated at config-parse time, so seed it before start().
    export = tmp_path / "export"
    export.mkdir()
    payload = os.urandom(300000)
    (export / "f.bin").write_bytes(payload)

    origin = lifecycle.start(NginxInstanceSpec(
        name="lc-stream-guard-origin",
        template="nginx_lc_stream_guard_origin.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "EXPORT_DIR": str(export)},
        reason="stream-guard origin (anon root:// export)"))
    guarded = lifecycle.start(NginxInstanceSpec(
        name="lc-stream-guard-guarded",
        template="nginx_lc_stream_guard_relay.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "ORIGIN_PORT": origin.port,
                         "GUARD_DIRECTIVE": "brix_guard_stream on;"},
        reason="stream-guard guarded transparent relay"))
    unguarded = lifecycle.start(NginxInstanceSpec(
        name="lc-stream-guard-unguarded",
        template="nginx_lc_stream_guard_relay.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "ORIGIN_PORT": origin.port,
                         "GUARD_DIRECTIVE": ""},
        reason="stream-guard unguarded relay (guard defaults off)"))

    # Guard audit lines land in each relay's own error.log (= {LOG_DIR}).
    return {"origin_port": origin.port, "guarded_port": guarded.port,
            "unguarded_port": unguarded.port,
            "guarded_prefix": pathlib.Path(guarded.prefix) / "logs",
            "unguarded_prefix": pathlib.Path(unguarded.prefix) / "logs",
            "payload": payload}


class TestStreamGuard:
    def test_valid_root_op_relayed(self, relays):
        """A clean cat through the guarded relay is byte-exact + unflagged."""
        before = len(_guard_lines(relays["guarded_prefix"]))
        result = subprocess.run(
            [XRDFS, f"root://{BIND_HOST}:{relays['guarded_port']}",
             "cat", "/f.bin"],
            capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == relays["payload"], "relay corrupted the bytes"
        time.sleep(0.3)
        assert len(_guard_lines(relays["guarded_prefix"])) == before, \
            "clean traffic was flagged"

    def test_junk_path_dropped(self, relays):
        """A scanner path inside a valid frame drops the connection."""
        result = _xrdfs(relays["guarded_port"], "stat", "/wp-login.php")
        assert result.returncode != 0, "junk path should not succeed"
        deadline = time.time() + 5
        while time.time() < deadline:
            lines = _guard_lines(relays["guarded_prefix"])
            if any("signal=signature" in ln for ln in lines):
                break
            time.sleep(0.1)
        lines = _guard_lines(relays["guarded_prefix"])
        sig = [ln for ln in lines if "signal=signature" in ln]
        assert sig, f"no signature audit line; got: {lines}"
        assert "proto=root" in sig[-1]
        assert "wp-login.php" in sig[-1]

    def test_notfound_logged(self, relays):
        """A kXR_NotFound response from the origin logs signal=notfound."""
        result = _xrdfs(relays["guarded_port"], "stat", "/does-not-exist")
        assert result.returncode != 0, "missing file should not stat"
        deadline = time.time() + 5
        while time.time() < deadline:
            if any("signal=notfound" in ln
                   for ln in _guard_lines(relays["guarded_prefix"])):
                break
            time.sleep(0.1)
        lines = _guard_lines(relays["guarded_prefix"])
        assert any("signal=notfound" in ln and "proto=root" in ln
                   for ln in lines), f"no notfound audit line; got: {lines}"

    def test_unguarded_relay_passes_junk(self, relays):
        """Without brix_guard_stream the same junk path is relayed."""
        result = _xrdfs(relays["unguarded_port"], "stat", "/wp-login.php")
        # The origin answers kXR_NotFound (a normal error) — the connection
        # survives and nothing is classified.
        assert "signal=" not in "\n".join(
            _guard_lines(relays["unguarded_prefix"])), \
            "unguarded relay must not classify"
        assert result.returncode != 0   # NotFound from the origin, not a drop
