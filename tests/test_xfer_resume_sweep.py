"""Phase 6 housekeeping — TTL sweep of abandoned upload-resume partials.

The worker-0 sweeper removes `*.xrdresume.part` files in the configured stage dir
once they are older than $BRIX_UPLOAD_RESUME_TTL, while preserving fresh ones
(an in-progress / recently-interrupted upload must never be disturbed) and
ignoring non-resume files.
"""
import os
import socket
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

PORT = int(os.environ.get("TEST_XFER_SWEEP_PORT") or free_port())


@pytest.fixture(scope="module")
def sweep_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")

    d = tmp_path_factory.mktemp("resumesweep")
    (d / "logs").mkdir()
    (d / "data").mkdir()
    stage = d / "stage"; stage.mkdir()

    # An abandoned partial (old mtime) → must be swept.
    old = stage / "deadbeef.xrdresume.part"
    old.write_bytes(b"abandoned")
    past = time.time() - 3600
    os.utime(old, (past, past))
    # A fresh partial (now) → must survive (TTL=600).
    fresh = stage / "cafef00d.xrdresume.part"
    fresh.write_bytes(b"in-progress")
    # A non-resume file (old) → must be ignored.
    keep = stage / "keepme.txt"
    keep.write_bytes(b"not a partial")
    os.utime(keep, (past, past))

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
env BRIX_UPLOAD_RESUME_TTL;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{PORT};
        xrootd on;
        brix_root {d}/data;
        brix_auth none;
        brix_allow_write on;
        brix_stage_dir {stage};
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    env = dict(os.environ, BRIX_UPLOAD_RESUME_TTL="600")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    deadline = time.time() + 10
    up = False
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, PORT), timeout=0.5).close()
            up = True
            break
        except OSError:
            time.sleep(0.1)
    if not up:
        err = proc.stderr.read().decode(errors="replace")
        proc.terminate()
        pytest.skip(f"sweep server did not start: {err}")

    class S:
        pass
    s = S()
    s.old, s.fresh, s.keep = str(old), str(fresh), str(keep)
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_ttl_sweep_removes_only_stale_partials(sweep_server):
    # Sweep fires ~5s after worker start; poll for the abandoned partial to go.
    deadline = time.time() + 15
    while time.time() < deadline and os.path.exists(sweep_server.old):
        time.sleep(0.3)

    assert not os.path.exists(sweep_server.old), \
        "abandoned (old) resume partial was not swept"
    assert os.path.exists(sweep_server.fresh), \
        "fresh resume partial (age < TTL) must be preserved"
    assert os.path.exists(sweep_server.keep), \
        "non-resume file must never be swept"
