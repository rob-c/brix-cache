"""
xrddiag probe-robustness (phase-37 §15.8): a gated adversarial auditor.

`xrddiag probe-robustness <url>` sends a battery of malformed / abusive frames
(path escape, unknown opcode, oversized dlen, OOB read on a bogus handle,
truncated header) and asserts the server REJECTS each cleanly and SURVIVES the
battery. It is a fuzzing-class tool, so it refuses any non-loopback resolved
address unless `--i-am-authorized` is given (resolve-once / connect-same-address,
to defeat DNS-rebind).

Self-contained: spins up its own anon nginx (NGINX_BIN) on a free loopback port,
so it never perturbs the shared fleet and is robust to fleet churn.

Run (serial):
    PYTHONPATH=tests pytest tests/test_xrddiag_probe.py -v -p no:xdist
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST
from config_templates import render_config

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def anon_server(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("probe")
    data = root / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hello\n")
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(render_config("nginx_stream_posix_anon.conf",
                                  BASE_DIR=root, BIND_HOST=BIND_HOST,
                                  PORT=port, DATA_DIR=data,
                                  WORKER_CONNECTIONS=256))
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        try:
            with socket.create_connection((HOST, port), timeout=1):
                break
        except OSError:
            time.sleep(0.1)
    yield port, conf
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _run(*args, timeout=40):
    return subprocess.run([XRDDIAG, *args], capture_output=True, text=True, timeout=timeout)


# --------------------------------------------------------------------------
# the battery: every probe rejected cleanly + server survives
# --------------------------------------------------------------------------

def test_probe_battery_all_rejected(anon_server):
    port, _ = anon_server
    p = _run("probe-robustness", f"root://{HOST}:{port}/")
    assert p.returncode == 0, f"a probe was served:\n{p.stdout}\n{p.stderr}"
    out = p.stdout
    for probe in ("path-escape", "bad-opcode", "oversized-dlen", "oob-read",
                  "partial-frame", "server-survives"):
        assert f"[PASS] {probe}" in out, f"{probe} not PASS:\n{out}"
    assert "ESCAPE SERVED" not in out
    assert "Result: 0 failure(s)" in out


def test_probe_server_survives(anon_server):
    """The battery must not crash the server — a fresh op works afterward."""
    port, _ = anon_server
    p = _run("probe-robustness", f"root://{HOST}:{port}/")
    assert "[PASS] server-survives" in p.stdout, p.stdout
    # and the server really is still up
    with socket.create_connection((HOST, port), timeout=2):
        pass


# --------------------------------------------------------------------------
# error path
# --------------------------------------------------------------------------

def test_probe_unreachable_clean_fail(anon_server):
    p = _run("probe-robustness", f"root://{HOST}:1/", timeout=20)
    assert p.returncode != 0, p.stdout


# --------------------------------------------------------------------------
# security-neg: the loopback safety gate
# --------------------------------------------------------------------------

def test_probe_refuses_non_loopback(anon_server):
    """A non-loopback resolved target is refused without --i-am-authorized."""
    p = _run("probe-robustness", "root://example.com:1094/", timeout=20)
    assert p.returncode == 3, f"gate should refuse (rc=3): {p.returncode}\n{p.stderr}"
    assert "refusing to fuzz non-loopback" in p.stderr, p.stderr


def test_probe_authorized_flag_accepted(anon_server):
    """--i-am-authorized is a recognized flag and does not perturb a clean run
    (against loopback the gate is a no-op, but the flag must parse + the battery
    still pass) — complements the non-loopback refusal test above."""
    port, _ = anon_server
    p = _run("probe-robustness", f"root://{HOST}:{port}/", "--i-am-authorized")
    assert "unknown option" not in p.stderr, p.stderr
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "Result: 0 failure(s)" in p.stdout, p.stdout
