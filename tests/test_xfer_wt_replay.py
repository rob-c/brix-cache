"""Phase 4b-2b-ii — write-through durable-flush REPLAY across a restart.

A WT async flush interrupted (here: a dead origin) leaves a journal record. On
restart the per-worker replay scheduler must re-drive it: requeue FAILED → claim
(which bumps `attempts`) → re-run the flush. With the origin still dead the record
returns to FAILED, but with a HIGHER attempt count — proving the recovery path
re-drove the transfer (against a recovered origin it would instead complete and
the record would be deleted).

Single self-contained instance, restarted in-test; no live origin needed. The
record is parsed straight from the journal (layout pinned by frm_format.h).
"""
import os
import socket
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST
from config_templates import render_config

PORT = int(os.environ.get("TEST_XFER_WTR_PORT") or free_port())
import shutil
XRDCP = shutil.which("xrdcp")

FRM_REC_SIZE = 4608
OFF_ATTEMPTS = 56      # uint32 LE
OFF_STATUS = 65
OFF_LFN = 108
LFN_LEN = 3072
OFF_XFER_KIND = 4300
FRM_ST_FAILED = 4
FRM_XFER_WT = 1


def _scan_wt(queue_path, name):
    """Return (status, attempts, lfn) for the first kind=wt record matching name."""
    try:
        data = open(queue_path, "rb").read()
    except OSError:
        return None
    off = FRM_REC_SIZE
    while off + FRM_REC_SIZE <= len(data):
        rec = data[off:off + FRM_REC_SIZE]
        if rec[OFF_XFER_KIND] == FRM_XFER_WT:
            lfn = rec[OFF_LFN:OFF_LFN + LFN_LEN].split(b"\x00", 1)[0]
            lfn = lfn.decode("utf-8", "replace")
            if name in lfn:
                attempts = struct.unpack_from("<I", rec, OFF_ATTEMPTS)[0]
                return rec[OFF_STATUS], attempts, lfn
        off += FRM_REC_SIZE
    return None


def _write_conf(d):
    data = d / "data"
    queue = d / "wt.queue"
    conf = render_config("nginx_xfer_wt_dead_origin.conf",
                         BASE_DIR=d,
                         BIND_HOST=BIND_HOST,
                         PORT=PORT,
                         DATA_DIR=data,
                         QUEUE_PATH=queue)
    cp = d / "nginx.conf"
    cp.write_text(conf)
    return cp, str(queue)


def _start(d, cp):
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, PORT), timeout=0.5).close()
            return proc
        except OSError:
            time.sleep(0.1)
    err = proc.stderr.read().decode(errors="replace")
    proc.terminate()
    pytest.skip(f"wt-replay server did not start: {err}")


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _poll_failed(queue, name, timeout=15):
    deadline = time.time() + timeout
    rec = None
    while time.time() < deadline:
        rec = _scan_wt(queue, name)
        if rec is not None and rec[0] == FRM_ST_FAILED:
            return rec
        time.sleep(0.3)
    return rec


def test_durable_flush_replayed_after_restart(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")

    d = tmp_path_factory.mktemp("wtreplay")
    (d / "logs").mkdir()
    (d / "data").mkdir()
    cp, queue = _write_conf(d)
    name = "wtr_recover.bin"
    src = d / "payload.bin"
    src.write_bytes(b"replay-me-" + b"r" * 400)

    # --- run 1: write, let the async flush fail against the dead origin ---
    proc = _start(d, cp)
    try:
        r = subprocess.run(
            [XRDCP, "-f", str(src), f"root://{HOST}:{PORT}//{name}"],
            capture_output=True, timeout=30)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        rec = _poll_failed(queue, name)
        assert rec is not None and rec[0] == FRM_ST_FAILED, \
            "expected a FAILED wt record after the dead-origin flush"
        attempts_before = rec[1]
    finally:
        _stop(proc)

    # --- run 2: restart; the replay scheduler must re-drive the record ---
    proc = _start(d, cp)
    try:
        deadline = time.time() + 20
        attempts_after = attempts_before
        while time.time() < deadline:
            rec = _scan_wt(queue, name)
            if rec is not None and rec[1] > attempts_before:
                attempts_after = rec[1]
                break
            time.sleep(0.3)
        assert attempts_after > attempts_before, (
            f"replay did not re-drive the record: attempts stayed "
            f"{attempts_before} (record={rec})")
    finally:
        _stop(proc)
