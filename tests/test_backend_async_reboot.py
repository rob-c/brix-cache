"""test_backend_async_reboot.py — durability of the async backend-op queue.

The queue is only useful if a mutation the client was told to wait for cannot be
lost by a crash. Each enqueue fsyncs a fixed-size record to
``$BRIX_STAGE_JOURNAL_DIR/backend/<reqid>.req`` *before* the client parks; on
worker start, worker 0 replays any record left behind idempotently
(``brix_baq_reconcile``).

This test proves that path end-to-end:
  1. enqueue an rm with a long wait + large batch so it never flushes on its own,
  2. confirm the durable record hit the journal (and the file is still present),
  3. SIGKILL the worker mid-flight — the in-memory queue dies, the record does not,
  4. the respawned worker replays the record: the file is removed and the journal
     entry is consumed.

Self-provisioning; skips when the nginx binary is absent or lacks the queue.
"""

import glob
import os
import pathlib
import signal
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec
from _cache_partial_helpers import _session

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-backend-async-reboot")]

kXR_rm = 3014


def _have_nginx():
    if not os.path.exists(NGINX_BIN):
        return False
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        return "brix_baq_reconcile" in syms.stdout
    except Exception:
        return True


def _poll(predicate, timeout=15.0, interval=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_unflushed_mutation_replays_after_crash(lifecycle, tmp_path):
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the async queue")

    data = pathlib.Path(tmp_path) / "data"
    data.mkdir(parents=True, exist_ok=True)
    journal = pathlib.Path(tmp_path) / "journal"
    journal.mkdir(parents=True, exist_ok=True)   # baq mkdir()s only its backend/ child
    backend_journal = journal / "backend"

    target = data / "d" / "doomed.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"survive-the-crash\n")

    name = "lc-backend-async-reboot"
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_backend_async_stream.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "ALLOW_WRITE": "on",
            "ASYNC": "on",
            "BATCH": "64",         # far above one op — never flushes on size
            "WAIT": "30000ms",     # ...nor on time within the test window
            "JOURNAL_DIR": str(journal),
        },
        reason="durability of the async backend-op queue across a worker crash",
    ))

    # Enqueue the mutation; the reply never comes (it is parked behind the long
    # wait), so send it and move on — the durable record is what we verify.
    s = _session(ep.port)
    pb = b"/d/doomed.txt"
    s.sendall(struct.pack("!2sH16sI", b"\x00\x07", kXR_rm, b"\x00" * 16,
                          len(pb)) + pb)

    assert _poll(lambda: glob.glob(str(backend_journal / "*.req"))), \
        "mutation was never journalled"
    assert target.exists(), "op must not apply before the flush"
    s.close()

    # Crash the worker mid-flight: the in-memory queue is lost, the journal is not.
    lifecycle.kill_worker(name, signal.SIGKILL)

    # The respawned worker (slot 0) reconciles the journal: the file is removed and
    # its durable record is consumed.
    assert _poll(lambda: not target.exists()), \
        "crashed mutation was not replayed after restart"
    assert _poll(lambda: not glob.glob(str(backend_journal / "*.req"))), \
        "replayed journal record was not cleaned up"
