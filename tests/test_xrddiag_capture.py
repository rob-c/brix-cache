"""
Session capture / replay (phase-37 §15.1): the .xrdcap bundle.

`xrdfs|xrdcp --capture <file.xrdcap>` records every wire frame + the negotiated
session metadata into a portable bundle. `xrddiag replay <file>` decodes it
OFFLINE (no server); `xrddiag replay <file> --playback <url>` re-issues the
captured request frames against a live server.

Self-contained: a throwaway anon nginx on a free loopback port.

Run (serial):
    PYTHONPATH=tests pytest tests/test_xrddiag_capture.py -v -p no:xdist
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def anon(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    root = tmp_path_factory.mktemp("xrdcap")
    data = root / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hello capture\n")
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        xrootd on;
        xrootd_root {data};
        xrootd_auth none;
    }}
}}
""")
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
    yield port, root
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _capture_stat(port, root):
    cap = root / "s.xrdcap"
    p = subprocess.run([XRDFS, "--capture", str(cap), f"root://{HOST}:{port}",
                        "stat", "/probe.txt"], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert cap.exists() and cap.stat().st_size > 0, "no capture written"
    return cap


# --------------------------------------------------------------------------
# success: capture + offline decode
# --------------------------------------------------------------------------

def test_capture_then_offline_replay(anon):
    port, root = anon
    cap = _capture_stat(port, root)
    p = subprocess.run([XRDDIAG, "replay", str(cap)], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    out = p.stdout
    assert "kXR_login" in out and "kXR_stat" in out, out      # decoded frames
    assert "endpoint" in out and "sessid" in out, out          # metadata
    assert "frame(s)" in out, out


def test_capture_verbose_hexdump(anon):
    port, root = anon
    cap = _capture_stat(port, root)
    p = subprocess.run([XRDDIAG, "replay", str(cap), "--wire-trace"],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    import re
    assert re.search(r"[0-9a-f]{2} [0-9a-f]{2} ", p.stdout), "no hexdump in verbose replay"


# --------------------------------------------------------------------------
# live playback: re-issue the captured request
# --------------------------------------------------------------------------

def test_playback_reissues_request(anon):
    port, root = anon
    cap = _capture_stat(port, root)
    p = subprocess.run([XRDDIAG, "replay", str(cap), "--playback",
                        f"root://{HOST}:{port}"], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    # the captured kXR_stat is re-issued and the server answers ok
    assert "re-issue kXR_stat" in p.stdout, p.stdout
    assert "-> ok" in p.stdout and "1 ok" in p.stdout, p.stdout


# --------------------------------------------------------------------------
# error: malformed bundle
# --------------------------------------------------------------------------

def test_replay_malformed_bundle(anon, tmp_path):
    bad = tmp_path / "bad.xrdcap"
    bad.write_bytes(b"not a capture file at all")
    p = subprocess.run([XRDDIAG, "replay", str(bad)], capture_output=True, text=True, timeout=20)
    assert p.returncode != 0, p.stdout
    assert "xrdcap" in (p.stdout + p.stderr).lower(), p.stderr
