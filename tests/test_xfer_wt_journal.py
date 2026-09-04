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

The fixture explicitly disables cross-protocol lock enforcement because strict
mode must contact the authoritative origin to prove that no foreign lock exists.
Offline write acceptance and strict remote lock proof are mutually exclusive;
the dedicated Phase-107 suite covers the latter.

This behaviour is confined to a write-back tier by the async flush mode: a plain
export with no stage tier journals nothing. The restart replay that re-drives such
a record is exercised by test_xfer_wt_replay.py.
"""
import os
import struct
import time

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST
from official_interop_lib import worker_reachable
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure
from fleet_lifecycle_ports import lifecycle_ports_for
from _test_xfer_wt_wire import write_file

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xfer-wt-journal")]

# Placeholder until the fixture reassigns from ep.port; default to the ledger
# port (lc-xfer-wt-journal) so import-time URLs match the live bind.
PORT = int(os.environ.get("TEST_XFER_WTJ_PORT") or lifecycle_ports_for("lc-xfer-wt-journal")[0])
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


def _request_paths(journal_dir):
    try:
        entries = os.listdir(journal_dir)
    except OSError:
        return []
    return [os.path.join(journal_dir, name) for name in entries
            if name.endswith(".req")]


def _read_request(path):
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    if len(data) < struct.calcsize(SREQ_FMT):
        return None
    return struct.unpack_from(SREQ_FMT, data, 0)


def _is_named_flush(record, name):
    if record[F_KIND] != BRIX_STAGE_FLUSH:
        return False
    if name in _cstr(record[F_DST_KEY]):
        return True
    return name in _cstr(record[F_SRC_KEY])


def _scan_flush_record(journal_dir, name):
    """Return the unpacked brix_sreq_t tuple for the first kind=FLUSH .req record
    whose src/dst key contains `name`, or None."""
    for path in _request_paths(journal_dir):
        record = _read_request(path)
        if record is not None and _is_named_flush(record, name):
            return record
    return None


def _wait_for_failed_record(journal_dir, name):
    deadline = time.time() + 15
    while time.time() < deadline:
        record = _scan_flush_record(journal_dir, name)
        if record is not None and record[F_STATE] == BRIX_SREQ_FAILED:
            return record
        time.sleep(0.3)
    return None


@pytest.fixture
def wtj_server(lifecycle, tmp_path):
    global PORT
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    data = tmp_path / "data"; data.mkdir()
    stage = tmp_path / "stage"; stage.mkdir()
    journal = tmp_path / "journal"; journal.mkdir()
    # The de-escalated `nobody` worker must reach + own the export/stage/journal
    # trees (pytest tmp parents are root-0700 — untraversable otherwise).
    worker_reachable(data, stage, journal)

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
    name = "wtj_durable.bin"
    payload = b"durable-write-through-" + b"q" * 500
    write_file(HOST, PORT, f"/{name}", payload)

    # The background flush to the dead origin fails; the engine marks the durable
    # record FAILED (state, not just left QUEUED). Poll for it.
    rec = _wait_for_failed_record(wtj_server.journal, name)

    assert rec is not None, "no kind=FLUSH journal record for the async flush"
    assert rec[F_STATE] == BRIX_SREQ_FAILED, \
        f"flush record state={rec[F_STATE]}, expected FAILED({BRIX_SREQ_FAILED})"
    # last_errno is stamped on the transient failure (dead origin -> connect error).
    assert rec[F_LAST_ERRNO] != 0, "FAILED record should carry a non-zero errno"
    assert name in _cstr(rec[F_DST_KEY]) or name in _cstr(rec[F_SRC_KEY])
