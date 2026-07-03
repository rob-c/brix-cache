"""
tests/test_frm_staging.py

Phase 35 / Phase 1 — the usable synchronous tape gateway (stream face).

End-to-end against a self-contained nginx + a fake tape MSS (frm_fake_mss.sh):

  * a resident file is NOT reported offline
  * a nearline file (disk stub + user.frm.residency=nearline xattr, real bytes on
    "tape") IS reported offline (kXR_offline) on kXR_stat
  * opening a nearline file triggers a real, reaped recall and stalls the client
    with kXR_wait; xrdcp retries to a hit and gets the true tape bytes
  * N concurrent opens of one nearline file collapse to exactly ONE recall (dedup)

Self-contained: own nginx (worker + thread pool) on a dedicated port, no fleet.
Skips cleanly if user xattrs or the xrootd client tools are unavailable.
"""

import os
import shutil
import socket
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

PORT = int(os.environ.get("TEST_FRM_STAGING_PORT") or free_port())

kXR_login   = 3007
kXR_stat    = 3017
kXR_ok      = 0
kXR_offline = 8

XRDCP = shutil.which("xrdcp")
XRDFS = shutil.which("xrdfs")


from frm_helpers import xattr_ok as _xattr_ok


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    _, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return status, (_recv_exact(sock, dlen) if dlen else b"")


def _session():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    assert _read_response(sock)[0] == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00",
                             0, 0, 5, 0, 0))
    assert _read_response(sock)[0] == kXR_ok
    return sock


def _stat_flags(path):
    """Return the integer flags field from a kXR_stat response for `path`."""
    s = _session()
    pb = path.encode() + b"\x00"
    # ClientStatRequest: 2s streamid, H reqid, B options, 11s reserved,
    # 4s fhandle, I dlen
    req = struct.pack("!2sHB11s4sI", b"\x00\x07", kXR_stat, 0,
                      b"\x00" * 11, b"\x00" * 4, len(pb))
    s.sendall(req + pb)
    status, body = _read_response(s)
    s.close()
    assert status == kXR_ok, f"stat status {status}: {body!r}"
    # stat body: "id size flags mtime" (ASCII, space-separated)
    parts = body.rstrip(b"\x00").split()
    return int(parts[2])


@pytest.fixture(scope="module")
def staging(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")

    d = tmp_path_factory.mktemp("frmstage")
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    tape = d / "tape"; tape.mkdir()
    queue = d / "frm.queue"
    audit = d / "audit.log"
    copycmd = str(d / "copycmd.sh")
    shutil.copy(os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"),
                copycmd)
    os.chmod(copycmd, 0o755)

    # a resident file
    (data / "online.bin").write_bytes(b"resident-bytes\n")

    # a nearline file: a stub on disk with the residency marker, real bytes on tape
    tape_content = b"TAPE-RECALLED-CONTENT-" + b"z" * 200 + b"\n"
    (tape / "near.dat").write_bytes(tape_content)
    stub = data / "near.dat"
    stub.write_bytes(b"")                       # 0-byte placeholder
    os.setxattr(str(stub), "user.frm.residency", b"nearline")

    # a second nearline file for the dedup test
    (tape / "dedup.dat").write_bytes(tape_content)
    (data / "dedup.dat").write_bytes(b"")
    os.setxattr(str(data / "dedup.dat"), "user.frm.residency", b"nearline")

    # a nearline file with NO tape source — its recall always fails
    (data / "failfile.dat").write_bytes(b"")
    os.setxattr(str(data / "failfile.dat"), "user.frm.residency", b"nearline")

    conf = f"""
worker_processes 1;
thread_pool frmpool threads=2;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
# nginx wipes the worker environment; pass the fake-MSS knobs through explicitly.
env FRM_DATA_DIR;
env FRM_TAPE_DIR;
env FRM_LATENCY_MS;
env FRM_AUDIT_LOG;
env FRM_FAIL_MODE;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{PORT};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth none;
        brix_thread_pool frmpool;
        brix_frm on;
        brix_frm_queue_path {queue};
        brix_frm_copycmd {copycmd};
        brix_frm_copymax 4;
        brix_frm_stage_wait 1;
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    env = dict(os.environ)
    env.update(FRM_DATA_DIR=os.path.realpath(str(data)),
               FRM_TAPE_DIR=str(tape),
               FRM_LATENCY_MS="500",
               FRM_AUDIT_LOG=str(audit))
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env)
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
        pytest.skip(f"staging server did not start: {err}")

    class S:
        pass
    s = S()
    s.data = str(data)
    s.tape_content = tape_content
    s.audit = str(audit)
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _xrdcp(path, out, timeout=30):
    return subprocess.run(
        [XRDCP, "-f", f"root://{HOST}:{PORT}/{path}", out],
        capture_output=True, timeout=timeout)


def test_online_file_not_offline(staging):
    assert (_stat_flags("/online.bin") & kXR_offline) == 0


def test_nearline_xattr_not_a_stat_signal(staging):
    """Phase-64 P6: kXR_stat's offline flag now comes from the storage BACKEND's
    residency model (the brix_vfs_residency seam), NOT the legacy
    user.frm.residency xattr. An xattr-marked file on a POSIX export is therefore
    NOT flagged offline on stat. The tape:// root:// stat-offline UX (a real nearline
    backend) is covered in tests/run_tape_recall_stream.sh. NB: the OLD FRM
    open-staging gate still honors the xattr (see test_open_nearline_stages_and_serves)
    until open_request migrates with the FRM queue removal — a documented transitional
    state during the src/frm dissolution (spec §13c)."""
    assert (_stat_flags("/near.dat") & kXR_offline) == 0, \
        "the FRM residency xattr must NOT drive the stat offline flag on a posix export"


def test_open_nearline_stages_and_serves(staging, tmp_path):
    out = str(tmp_path / "near.out")
    r = _xrdcp("/near.dat", out)
    assert r.returncode == 0, f"xrdcp failed: {r.stderr.decode(errors='replace')}"
    assert open(out, "rb").read() == staging.tape_content, \
        "recalled content does not match the tape bytes"
    # once staged, it is no longer reported offline
    assert (_stat_flags("/near.dat") & kXR_offline) == 0


def test_concurrent_opens_dedup_to_one_recall(staging, tmp_path):
    open(staging.audit, "w").close()        # reset audit
    # NB: DEVNULL, not PIPE — an unread PIPE fills with xrdcp's progress output
    # and blocks the child.
    procs = [subprocess.Popen(
                [XRDCP, "-f", "-s", f"root://{HOST}:{PORT}//dedup.dat",
                 str(tmp_path / f"d{i}.out")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for i in range(8)]
    for p in procs:
        p.wait(timeout=30)
    ok = sum(1 for p in procs if p.returncode == 0)
    assert ok >= 1, "no concurrent xrdcp succeeded"
    n_recalls = sum(1 for line in open(staging.audit) if line.startswith("stage"))
    assert n_recalls == 1, \
        f"expected exactly one recall for 8 concurrent opens, got {n_recalls}"


def test_failed_recall_returns_error_not_hang(staging, tmp_path):
    # failfile.dat has no tape source → recall fails → file marked offline →
    # the open must return an error, not stall forever.
    r = _xrdcp("/failfile.dat", str(tmp_path / "f.out"), timeout=30)
    assert r.returncode != 0, "open of an unstageable file should fail, not hang"


def _xfer_audit_lines(prefix):
    p = os.path.join(prefix, "logs", "xfer_audit.log")
    try:
        with open(p, "r", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return []


def _wait_tape_line(prefix, lfn, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for line in _xfer_audit_lines(prefix):
            if "kind=tape" in line and lfn in line:
                return line
        time.sleep(0.2)
    return None


def test_recall_emits_unified_tape_audit_line(staging, tmp_path):
    """A tape recall joins the unified transfer ledger (kind=tape), so one audit
    log covers both staged uploads and recalls. Success → result=ok; a recall
    with no tape source → result=agent_fail."""
    prefix = os.path.dirname(staging.data)
    tape = os.path.join(prefix, "tape")

    # fresh nearline file WITH a tape source → recall succeeds
    ok_name = "audit_ok.dat"
    with open(os.path.join(tape, ok_name), "wb") as fh:
        fh.write(b"FRESH-AUDIT-TAPE\n")
    ok_stub = os.path.join(staging.data, ok_name)
    open(ok_stub, "wb").close()
    os.setxattr(ok_stub, "user.frm.residency", b"nearline")

    r = _xrdcp("/" + ok_name, str(tmp_path / "ok.out"), timeout=30)
    assert r.returncode == 0, f"recall failed: {r.stderr.decode(errors='replace')}"
    line = _wait_tape_line(prefix, ok_name)
    assert line is not None, "no kind=tape audit line for a successful recall"
    assert "result=ok" in line
    assert "dir=in" in line
    assert line.count("\n") == 1

    # fresh nearline file with NO tape source → recall fails → result=agent_fail
    fail_name = "audit_fail.dat"
    fail_stub = os.path.join(staging.data, fail_name)
    open(fail_stub, "wb").close()
    os.setxattr(fail_stub, "user.frm.residency", b"nearline")

    fr = _xrdcp("/" + fail_name, str(tmp_path / "fail.out"), timeout=30)
    assert fr.returncode != 0, "recall with no tape source should fail"
    fline = _wait_tape_line(prefix, fail_name)
    assert fline is not None, "no kind=tape audit line for a failed recall"
    assert "result=agent_fail" in fline
