"""
tests/test_frm_async.py

Phase 35 / Phase 3 — async stage completion (kXR_waitresp → kXR_attn asynresp).

With xrootd_frm_async_recall on, an open of a nearline file is acknowledged with
kXR_waitresp and satisfied IN PLACE via kXR_attn(asynresp) when the recall
finishes — no client poll/retry. The XRootD client handles the deferred response
transparently, so an xrdcp of a nearline file simply succeeds; we additionally
scrape /metrics to prove the async path (not the Phase-1 kXR_wait path) was used.

  S  xrdcp of a nearline file succeeds with the true tape bytes; the recall went
     through the async path (xrootd_frm_waitresp_total and asynresp_total both > 0).
  E  a nearline file whose recall fails returns an error, not a hang.

Self-contained; skips cleanly without nginx, xrdcp, or user-xattr support.
"""

import os
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

from settings import NGINX_BIN, free_ports, HOST, BIND_HOST

_P_DEFAULT, _M_DEFAULT = free_ports(2)
PORT = int(os.environ.get("TEST_FRM_ASYNC_PORT") or _P_DEFAULT)
METRICS_PORT = int(os.environ.get("TEST_FRM_ASYNC_METRICS") or _M_DEFAULT)

XRDCP = shutil.which("xrdcp")


from frm_helpers import xattr_ok as _xattr_ok


def _metric(name):
    try:
        with urllib.request.urlopen(
                "http://%s:%d/metrics" % (HOST, METRICS_PORT), timeout=5) as r:
            for line in r.read().decode(errors="replace").splitlines():
                if line.startswith(name + " "):
                    return float(line.split()[-1])
    except Exception:
        return None
    return None


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    d = tmp_path_factory.mktemp("frmasync")
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    tape = d / "tape"; tape.mkdir()
    queue = d / "frm.queue"
    audit = d / "audit.log"
    copycmd = str(d / "copycmd.sh")
    shutil.copy(os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"), copycmd)
    os.chmod(copycmd, 0o755)

    tape_content = b"ASYNC-TAPE-CONTENT-" + b"y" * 256 + b"\n"
    (tape / "near.dat").write_bytes(tape_content)
    (data / "near.dat").write_bytes(b"")
    os.setxattr(str(data / "near.dat"), "user.frm.residency", b"nearline")

    # nearline file with no tape source → recall fails
    (data / "failfile.dat").write_bytes(b"")
    os.setxattr(str(data / "failfile.dat"), "user.frm.residency", b"nearline")

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
env FRM_DATA_DIR;
env FRM_TAPE_DIR;
env FRM_LATENCY_MS;
env FRM_AUDIT_LOG;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{PORT};
        xrootd on;
        xrootd_root {data};
        xrootd_auth none;
        xrootd_frm on;
        xrootd_frm_queue_path {queue};
        xrootd_frm_copycmd {copycmd};
        xrootd_frm_copymax 4;
        xrootd_frm_async_recall on;
        xrootd_frm_stage_ttl 30s;
    }}
}}
http {{
    access_log off;
    server {{
        listen {BIND_HOST}:{METRICS_PORT};
        location = /metrics {{ xrootd_metrics on; }}
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    chk = subprocess.run([NGINX_BIN, "-t", "-p", str(d), "-c", str(cp)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip("nginx rejected config: %s" % chk.stderr.strip()[-300:])
    env = dict(os.environ)
    env.update(FRM_DATA_DIR=os.path.realpath(str(data)),
               FRM_TAPE_DIR=str(tape),
               FRM_LATENCY_MS="700",
               FRM_AUDIT_LOG=str(audit))
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
        pytest.skip("server did not start: %s" % err[-300:])

    class S:
        pass
    s = S()
    s.tape_content = tape_content
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _xrdcp(path, out, timeout=30):
    return subprocess.run(
        [XRDCP, "-f", "-s", f"root://{HOST}:{PORT}/{path}", out],
        capture_output=True, timeout=timeout)


def test_async_recall_satisfies_open_in_place(srv, tmp_path):
    out = str(tmp_path / "near.out")
    r = _xrdcp("/near.dat", out)
    assert r.returncode == 0, "xrdcp failed: %s" % r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == srv.tape_content, "recalled bytes mismatch"

    # prove the deferred (async) path carried it, not the Phase-1 kXR_wait poll.
    wr = _metric("xrootd_frm_waitresp_total")
    ar = _metric("xrootd_frm_asynresp_total")
    assert wr is not None and wr >= 1, "no kXR_waitresp recorded (got %r)" % wr
    assert ar is not None and ar >= 1, "no kXR_attn(asynresp) delivered (got %r)" % ar


def test_async_failed_recall_returns_error_not_hang(srv, tmp_path):
    r = _xrdcp("/failfile.dat", str(tmp_path / "f.out"), timeout=30)
    assert r.returncode != 0, "open of an unstageable file should fail, not hang"
