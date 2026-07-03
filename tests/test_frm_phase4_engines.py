"""
tests/test_frm_phase4_engines.py

Phase 35 / Phase 4 engines — F3 (residency-cmd oracle) + F5 (checksum-on-stage),
end-to-end through the stage agent.

F3: with brix_frm_residency_cmd set, the stage agent consults the oracle BEFORE
    copying. Oracle exit 0 = "already resident" → the copycmd is skipped and the
    open is served from disk (proven: the served bytes are the on-disk content and
    the fake-MSS audit log records no copy).

F5: with a per-file checksum on a Tape REST stage request, the agent verifies the
    recalled file after copy. A correct checksum → COMPLETED; a wrong one → FAILED
    and brix_frm_stage_fail_total{reason="verify"} increments.

Self-contained; skips cleanly without nginx / xrdcp / xattrs / requests.
"""

import os
import shutil
import socket
import subprocess
import time
import zlib
import json
import urllib.request

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST

XRDCP = shutil.which("xrdcp")


def _xattr_ok(tmp):
    try:
        p = os.path.join(tmp, ".xp"); open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1"); os.remove(p); return True
    except Exception:
        return False


def _wait_port(port, t=10):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection((HOST, port), timeout=0.5).close(); return True
        except OSError:
            time.sleep(0.1)
    return False


def _start(d, conf, env=None):
    cp = d / "nginx.conf"; cp.write_text(conf)
    chk = subprocess.run([NGINX_BIN, "-t", "-p", str(d), "-c", str(cp)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip("nginx rejected config: %s" % chk.stderr.strip()[-300:])
    return subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env or dict(os.environ))


# --------------------------------------------------------------------------- F3
@pytest.fixture(scope="module")
def f3(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built")
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    d = tmp_path_factory.mktemp("frmf3")
    if not _xattr_ok(str(d)):
        pytest.skip("no user xattrs")
    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    tape = d / "tape"; tape.mkdir()
    audit = d / "audit.log"
    port = 11257

    copycmd = str(d / "copy.sh")
    shutil.copy(os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"), copycmd)
    os.chmod(copycmd, 0o755)
    # residency oracle: always reports "online" (exit 0) → agent skips the copy.
    oracle = d / "oracle.sh"; oracle.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(str(oracle), 0o755)

    # nearline-marked file that ALREADY has its real bytes on disk; the tape copy
    # is DIFFERENT so we can tell whether the (skipped) copy ran.
    disk_bytes = b"DISK-RESIDENT-CONTENT\n"
    (tape / "f.dat").write_bytes(b"TAPE-WOULD-OVERWRITE\n")
    (data / "f.dat").write_bytes(disk_bytes)
    os.setxattr(str(data / "f.dat"), "user.frm.residency", b"nearline")

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
env FRM_DATA_DIR; env FRM_TAPE_DIR; env FRM_LATENCY_MS; env FRM_AUDIT_LOG;
events {{ worker_connections 64; }}
stream {{
  server {{
    listen {BIND_HOST}:{port};
    xrootd on; brix_storage_backend posix:{data}; brix_auth none;
    brix_frm on; brix_frm_queue_path {d}/frm.queue;
    brix_frm_copycmd {copycmd};
    brix_frm_residency_cmd {oracle};
    brix_frm_stage_wait 1;
  }}
}}
daemon off; master_process off;
"""
    env = dict(os.environ, FRM_DATA_DIR=os.path.realpath(str(data)),
               FRM_TAPE_DIR=str(tape), FRM_LATENCY_MS="100",
               FRM_AUDIT_LOG=str(audit))
    proc = _start(d, conf, env)
    if not _wait_port(port):
        proc.terminate(); pytest.skip("f3 server did not start")

    class S: pass
    s = S(); s.port = port; s.audit = str(audit); s.disk_bytes = disk_bytes
    yield s
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill()


def test_f3_oracle_online_skips_copy(f3, tmp_path):
    out = str(tmp_path / "f.out")
    r = subprocess.run([XRDCP, "-f", "-s",
                        f"root://{HOST}:{f3.port}//f.dat", out],
                       capture_output=True, timeout=30)
    assert r.returncode == 0, "xrdcp failed: %s" % r.stderr.decode(errors="replace")
    # served from disk (copy was skipped by the oracle) → disk bytes, not tape
    assert open(out, "rb").read() == f3.disk_bytes
    # the fake-MSS copycmd never ran
    n = 0
    if os.path.exists(f3.audit):
        n = sum(1 for ln in open(f3.audit) if ln.startswith("stage"))
    assert n == 0, "oracle said online but the copycmd still ran (%d times)" % n


# --------------------------------------------------------------------------- F5
@pytest.fixture(scope="module")
def f5(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built")
    d = tmp_path_factory.mktemp("frmf5")
    if not _xattr_ok(str(d)):
        pytest.skip("no user xattrs")
    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    tape = d / "tape"; tape.mkdir()
    port = 11258; mport = 11259

    copycmd = str(d / "copy.sh")
    shutil.copy(os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"), copycmd)
    os.chmod(copycmd, 0o755)

    content = b"CHECKSUMMED-TAPE-CONTENT-" + b"k" * 300 + b"\n"
    adler = "%08x" % (zlib.adler32(content) & 0xffffffff)
    for name in ("good.dat", "bad.dat"):
        (tape / name).write_bytes(content)
        (data / name).write_bytes(b"")
        os.setxattr(str(data / name), "user.frm.residency", b"nearline")

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
env FRM_DATA_DIR; env FRM_TAPE_DIR; env FRM_LATENCY_MS; env FRM_AUDIT_LOG;
events {{ worker_connections 64; }}
stream {{
  server {{
    listen {BIND_HOST}:{port};
    xrootd on; brix_storage_backend posix:{data}; brix_auth none;
    brix_frm on; brix_frm_queue_path {d}/frm.queue;
    brix_frm_copycmd {copycmd};
  }}
}}
http {{
  access_log off;
  server {{
    listen {BIND_HOST}:{mport};
    location = /metrics {{ brix_metrics on; }}
    location / {{
      brix_webdav on; brix_webdav_storage_backend posix:{data}; brix_webdav_auth none;
      brix_webdav_allow_write on; brix_webdav_tape_rest on;
    }}
  }}
}}
daemon off; master_process off;
"""
    env = dict(os.environ, FRM_DATA_DIR=os.path.realpath(str(data)),
               FRM_TAPE_DIR=str(tape), FRM_LATENCY_MS="100",
               FRM_AUDIT_LOG=str(d / "audit.log"))
    proc = _start(d, conf, env)
    if not _wait_port(mport):
        proc.terminate(); pytest.skip("f5 server did not start")

    class S: pass
    s = S(); s.port = port; s.mport = mport; s.adler = adler
    yield s
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill()


def _tape_stage(mport, path, checksum):
    body = json.dumps({"files": [{"path": path, "checksum": checksum,
                                  "checksumType": "adler32"}]}).encode()
    req = urllib.request.Request("http://%s:%d/api/v1/stage" % (HOST, mport),
                                 data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())["requestId"]


def _stage_state(mport, rid):
    with urllib.request.urlopen(
            "http://%s:%d/api/v1/stage/%s" % (HOST, mport, rid), timeout=5) as r:
        return json.loads(r.read())["files"][0]["state"]


def _metric(mport, name, label=None):
    with urllib.request.urlopen(
            "http://%s:%d/metrics" % (HOST, mport), timeout=5) as r:
        for ln in r.read().decode(errors="replace").splitlines():
            key = name + (("{" + label + "}") if label else " ")
            if ln.startswith(name) and (label is None or label in ln):
                try:
                    return float(ln.split()[-1])
                except ValueError:
                    pass
    return 0.0


def _poll_state(mport, rid, want, t=20):
    end = time.time() + t
    last = None
    while time.time() < end:
        last = _stage_state(mport, rid)
        if last in want:
            return last
        time.sleep(0.3)
    return last


def test_f5_correct_checksum_completes(f5):
    rid = _tape_stage(f5.mport, "/good.dat", f5.adler)
    st = _poll_state(f5.mport, rid, {"COMPLETED", "FAILED"})
    assert st == "COMPLETED", "correct checksum should complete, got %r" % st


def test_f5_wrong_checksum_fails_verify(f5):
    before = _metric(f5.mport, "brix_frm_stage_fail_total", 'reason="verify"')
    rid = _tape_stage(f5.mport, "/bad.dat", "deadbeef")
    st = _poll_state(f5.mport, rid, {"FAILED"})
    assert st == "FAILED", "wrong checksum should fail the recall, got %r" % st
    after = _metric(f5.mport, "brix_frm_stage_fail_total", 'reason="verify"')
    assert after > before, \
        "verify-fail metric did not increment (%r → %r)" % (before, after)
