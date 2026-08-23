"""Phase 4b-2 — write-through async flush is recorded in the shared durable
journal (the FRM queue), so a flush interrupted by a crash leaves a recoverable
record instead of being silently lost.

Deterministic check: point a write-through-async server at a DEAD origin and write
a file. The local cache write + close succeed (async is fire-and-forget), the
background flush to the dead origin fails, and the producer must leave a
`kind=wt, status=FAILED` record in the journal. We parse the on-disk record
directly (the layout is pinned by frm_format.h's static asserts).

The replay that re-drives such a record on restart is Phase 4b-2b-ii.
"""
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

PORT = int(os.environ.get("TEST_XFER_WTJ_PORT") or free_port())
XRDCP = shutil.which("xrdcp")

# frm_record_t layout (frm_format.h) — byte offsets within a 4608-byte slot.
FRM_REC_SIZE = 4608
OFF_STATUS = 65
OFF_LFN = 108
LFN_LEN = 3072
OFF_XFER_KIND = 4300
FRM_ST_FAILED = 4
FRM_XFER_WT = 1


def _scan_wt_record(queue_path, name):
    """Return (status, lfn) for the first kind=wt record whose lfn contains
    `name`, or None. Slot 0 is the header; records follow."""
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
                return rec[OFF_STATUS], lfn
        off += FRM_REC_SIZE
    return None


def _wait_for_failed_record(queue_path, name):
    deadline = time.time() + 15
    while time.time() < deadline:
        record = _scan_wt_record(queue_path, name)
        if record is not None and record[0] == FRM_ST_FAILED:
            return record
        time.sleep(0.3)
    return None


def _require_wtj_dependencies():
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")


def _write_wtj_config(d, data, queue):
    (d / "logs").mkdir()
    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
thread_pool wtpool threads=2 max_queue=4096;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{PORT};
        brix_root on;
        brix_export {data};
        brix_auth none;
        brix_allow_write on;
        brix_thread_pool wtpool;
        brix_write_through on;
        brix_wt_mode async;
        brix_wt_origin 127.0.0.1:1;        # dead origin → flush always fails
        brix_frm on;
        brix_frm_queue_path {queue};
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    return cp


def _start_wtj_server(d, cp):
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
    pytest.skip(f"wt-journal server did not start: {err}")


def _stop_wtj_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def wtj_server(tmp_path_factory):
    _require_wtj_dependencies()
    d = tmp_path_factory.mktemp("wtjournal")
    data = d / "data"
    data.mkdir()
    queue = d / "wt.queue"
    cp = _write_wtj_config(d, data, queue)
    proc = _start_wtj_server(d, cp)

    class S:
        pass
    s = S()
    s.queue = str(queue)
    yield s
    _stop_wtj_server(proc)


def test_failed_async_flush_leaves_wt_journal_record(wtj_server, tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"durable-write-through-" + b"q" * 500)

    name = "wtj_durable.bin"
    r = subprocess.run(
        [XRDCP, "-f", str(src), f"root://{HOST}:{PORT}//{name}"],
        capture_output=True, timeout=30)
    assert r.returncode == 0, \
        f"cache write should succeed (async flush is deferred): " \
        f"{r.stderr.decode(errors='replace')}"

    # The background flush to the dead origin fails; the producer marks the
    # journal record FAILED. Poll for it.
    found = _wait_for_failed_record(wtj_server.queue, name)

    assert found is not None, "no kind=wt journal record for the async flush"
    status, lfn = found
    assert status == FRM_ST_FAILED, f"wt record status={status}, expected FAILED"
    assert name in lfn
