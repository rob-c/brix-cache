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

from guard_http_lib import NGINX_BIN, free_port
from settings import BIND_HOST
from config_templates import render_config

REPO = pathlib.Path(__file__).resolve().parents[1]
XRDFS = str(REPO / "client" / "bin" / "xrdfs")

pytestmark = pytest.mark.timeout(180)


def _write_conf(prefix, body):
    conf = prefix / "nginx.conf"
    conf.write_text(render_config("nginx_stream_guard.conf",
                                  BASE_DIR=prefix,
                                  SERVER_BLOCKS=body))
    return conf


def _start_nginx(prefix, conf):
    rc = subprocess.run([NGINX_BIN, "-p", str(prefix), "-c", str(conf)],
                        capture_output=True, text=True)
    assert rc.returncode == 0, f"nginx start failed: {rc.stderr}"


def _stop_nginx(prefix, conf):
    subprocess.run([NGINX_BIN, "-p", str(prefix), "-c", str(conf), "-s",
                    "stop"], capture_output=True)


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


@pytest.fixture(scope="module")
def relays(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not os.access(XRDFS, os.X_OK):
        pytest.skip(f"xrdfs not built: {XRDFS}")

    root = tmp_path_factory.mktemp("streamguard")
    origin = root / "origin"
    guarded = root / "guarded"
    unguarded = root / "unguarded"
    for prefix in (origin, guarded, unguarded):
        (prefix / "logs").mkdir(parents=True)

    export = origin / "export"
    export.mkdir()
    payload = os.urandom(300000)
    (export / "f.bin").write_bytes(payload)

    origin_port = free_port()
    guarded_port = free_port()
    unguarded_port = free_port()

    origin_conf = _write_conf(origin, render_config(
        "nginx_stream_guard_origin_server.conf",
        BIND_HOST=BIND_HOST,
        PORT=origin_port,
        EXPORT_DIR=export))
    guarded_conf = _write_conf(guarded, render_config(
        "nginx_stream_guard_relay_server.conf",
        BIND_HOST=BIND_HOST,
        PORT=guarded_port,
        ORIGIN_PORT=origin_port,
        GUARD_DIRECTIVE="brix_guard_stream on;"))
    unguarded_conf = _write_conf(unguarded, render_config(
        "nginx_stream_guard_relay_server.conf",
        BIND_HOST=BIND_HOST,
        PORT=unguarded_port,
        ORIGIN_PORT=origin_port,
        GUARD_DIRECTIVE=""))

    _start_nginx(origin, origin_conf)
    _start_nginx(guarded, guarded_conf)
    _start_nginx(unguarded, unguarded_conf)
    time.sleep(0.5)

    yield {"origin_port": origin_port, "guarded_port": guarded_port,
           "unguarded_port": unguarded_port, "guarded_prefix": guarded,
           "unguarded_prefix": unguarded, "payload": payload}

    _stop_nginx(origin, origin_conf)
    _stop_nginx(guarded, guarded_conf)
    _stop_nginx(unguarded, unguarded_conf)


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
