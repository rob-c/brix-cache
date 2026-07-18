"""Write-back (tape) async flush is recorded in the durable stage journal, so a
flush interrupted by a dead origin leaves a recoverable FAILED record instead of
being silently lost.

Deterministic check: a root:// server composes a write-STAGE tier (brix_stage +
brix_stage_flush async) over a DEAD origin (root://127.0.0.1:1). A client write
lands on the local stage store and close returns immediately (async is
fire-and-forget); the background store->origin flush fails against the dead origin,
and the stage engine must leave a `kind=FLUSH, state=FAILED` record in the durable
journal ($BRIX_STAGE_JOURNAL_DIR). We parse the on-disk brix_sreq_t record
directly (layout pinned by stage_engine.h).

This behaviour is confined to a write-back tier by the async flush mode: a plain
export with no stage tier journals nothing. The restart replay that re-drives such
a record is exercised by test_xfer_wt_replay.py.
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

PORT = int(os.environ.get("TEST_XFER_WTJ_PORT") or free_port())
XRDCP = shutil.which("xrdcp")

# brix_sreq_t on-disk layout (src/fs/xfer/stage_engine.h).  Little-endian, natural
# alignment; the `6x` pads open_options (uint16) up to the 8-byte size_hint.  The C
# struct rounds its total size up to an 8-byte multiple (trailing pad); unpack_from
# reads only the fields below, so the trailing pad is harmless.
SREQ_FMT = "<40s i i 16s 1024s 16s 1024s 1024s H 6x Q Q q q q I i 128s 512s 1024s B"
# field indices in the unpacked tuple
F_KIND, F_STATE, F_SRC_KEY, F_DST_KEY = 1, 2, 4, 6
F_ATTEMPTS, F_LAST_ERRNO = 14, 15

BRIX_STAGE_FLUSH = 1
BRIX_SREQ_FAILED = 3


def _cstr(b):
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _scan_flush_record(journal_dir, name):
    """Return the unpacked brix_sreq_t tuple for the first kind=FLUSH .req record
    whose src/dst key contains `name`, or None."""
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
            return rec
    return None


@pytest.fixture
def wtj_server(lifecycle, tmp_path):
    global PORT
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")

    data = tmp_path / "data"; data.mkdir()
    stage = tmp_path / "stage"; stage.mkdir()
    journal = tmp_path / "journal"; journal.mkdir()

    spec = NginxInstanceSpec(
        name="lc-xfer-wt-journal",
        template="nginx_lc_xfer_wt_dead_origin.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "STAGE_DIR": str(stage), "JOURNAL_DIR": str(journal)},
        reason="write-back durable-flush journal record")
    try:
        ep = lifecycle.start(spec)
    except RegistryCommandFailure:
        pytest.skip("nginx build lacks the brix_stage tier directive surface")
    PORT = ep.port

    class S:
        pass
    s = S()
    s.journal = str(journal)
    yield s


def test_failed_async_flush_leaves_journal_record(wtj_server, tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"durable-write-through-" + b"q" * 500)

    name = "wtj_durable.bin"
    r = subprocess.run(
        [XRDCP, "-f", str(src), f"root://{HOST}:{PORT}//{name}"],
        capture_output=True, timeout=30)
    assert r.returncode == 0, \
        f"stage write should succeed (async flush is deferred): " \
        f"{r.stderr.decode(errors='replace')}"

    # The background flush to the dead origin fails; the engine marks the durable
    # record FAILED (state, not just left QUEUED). Poll for it.
    rec = None
    deadline = time.time() + 15
    while time.time() < deadline:
        rec = _scan_flush_record(wtj_server.journal, name)
        if rec is not None and rec[F_STATE] == BRIX_SREQ_FAILED:
            break
        time.sleep(0.3)

    assert rec is not None, "no kind=FLUSH journal record for the async flush"
    assert rec[F_STATE] == BRIX_SREQ_FAILED, \
        f"flush record state={rec[F_STATE]}, expected FAILED({BRIX_SREQ_FAILED})"
    # last_errno is stamped on the transient failure (dead origin -> connect error).
    assert rec[F_LAST_ERRNO] != 0, "FAILED record should carry a non-zero errno"
    assert name in _cstr(rec[F_DST_KEY]) or name in _cstr(rec[F_SRC_KEY])
