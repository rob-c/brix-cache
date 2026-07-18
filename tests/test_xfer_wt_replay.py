"""Write-back (tape) durable-flush REPLAY across a restart.

A write-back async flush interrupted (here: a dead origin) leaves a durable FAILED
record in the stage journal. On restart the per-worker reconcile (src/fs/xfer/
stage_engine_reconcile.c) must re-drive it: rebuild the stage tier from the record's
export anchor and re-flush. With the origin still dead the re-flush fails again, but
the record is re-persisted FAILED with a HIGHER `attempts` count — proving the
recovery path re-drove the transfer (against a recovered origin it would instead
complete and the record would be unlinked).

Single self-contained instance, restarted in-test; no live origin needed. The
record is parsed straight from the journal (brix_sreq_t layout, stage_engine.h).
This is confined to a write-back tier by the async flush mode.
"""
import os
import shutil
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure

pytestmark = [pytest.mark.uses_lifecycle_harness]

PORT = int(os.environ.get("TEST_XFER_WTR_PORT") or free_port())
XRDCP = shutil.which("xrdcp")

# brix_sreq_t on-disk layout (src/fs/xfer/stage_engine.h) — see test_xfer_wt_journal.
SREQ_FMT = "<40s i i 16s 1024s 16s 1024s 1024s H 6x Q Q q q q I i 128s 512s 1024s B"
F_KIND, F_STATE, F_SRC_KEY, F_DST_KEY = 1, 2, 4, 6
F_ATTEMPTS, F_LAST_ERRNO = 14, 15

BRIX_STAGE_FLUSH = 1
BRIX_SREQ_FAILED = 3


def _cstr(b):
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _scan_flush(journal_dir, name):
    """Return (state, attempts) for the first kind=FLUSH .req record matching name."""
    try:
        entries = os.listdir(journal_dir)
    except OSError:
        return None
    for fn in entries:
        if not fn.endswith(".req"):
            continue
        try:
            data = open(os.path.join(journal_dir, fn), "rb").read()
        except OSError:
            continue
        if len(data) < struct.calcsize(SREQ_FMT):
            continue
        rec = struct.unpack_from(SREQ_FMT, data, 0)
        if rec[F_KIND] != BRIX_STAGE_FLUSH:
            continue
        if name in _cstr(rec[F_DST_KEY]) or name in _cstr(rec[F_SRC_KEY]):
            return rec[F_STATE], rec[F_ATTEMPTS]
    return None


def _poll_failed(journal, name, timeout=15):
    deadline = time.time() + timeout
    rec = None
    while time.time() < deadline:
        rec = _scan_flush(journal, name)
        if rec is not None and rec[0] == BRIX_SREQ_FAILED:
            return rec
        time.sleep(0.3)
    return rec


def test_durable_flush_replayed_after_restart(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")

    data = tmp_path / "data"; data.mkdir()
    stage = tmp_path / "stage"; stage.mkdir()
    journal = tmp_path / "journal"; journal.mkdir()
    name = "wtr_recover.bin"
    src = tmp_path / "payload.bin"
    src.write_bytes(b"replay-me-" + b"r" * 400)

    spec = NginxInstanceSpec(
        name="lc-xfer-wt-replay",
        template="nginx_lc_xfer_wt_dead_origin.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST,
                         "DATA_DIR": str(data),
                         "STAGE_DIR": str(stage),
                         "JOURNAL_DIR": str(journal)},
        reason="write-back durable-flush replay across restart")
    try:
        ep = lifecycle.start(spec)
    except RegistryCommandFailure:
        pytest.skip("nginx build lacks the brix_stage tier directive surface")
    global PORT
    PORT = ep.port

    # --- run 1: write, let the async flush fail against the dead origin ---
    r = subprocess.run(
        [XRDCP, "-f", str(src), f"root://{HOST}:{ep.port}//{name}"],
        capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    rec = _poll_failed(journal, name)
    assert rec is not None and rec[0] == BRIX_SREQ_FAILED, \
        "expected a FAILED flush record after the dead-origin flush"
    attempts_before = rec[1]

    # --- run 2: restart; the reconcile must re-drive the record and bump attempts ---
    lifecycle.restart("lc-xfer-wt-replay")
    deadline = time.time() + 20
    attempts_after = attempts_before
    while time.time() < deadline:
        rec = _scan_flush(journal, name)
        if rec is not None and rec[1] > attempts_before:
            attempts_after = rec[1]
            break
        time.sleep(0.3)
    assert attempts_after > attempts_before, (
        f"replay did not re-drive the record: attempts stayed "
        f"{attempts_before} (record={rec})")
