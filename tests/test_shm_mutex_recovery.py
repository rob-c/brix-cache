"""
tests/test_shm_mutex_recovery.py — regression wrapper for the SHM table-mutex
dead-holder recovery ("workers stuck after many reboots").

WHAT
    Compiles and runs the standalone C unit test tests/c/test_shm_mutex_recovery.c
    against the real build objects (shm_slots.o + nginx's ngx_shmtx.o). It proves
    that a module SHM-table mutex is recovered by nginx's per-zone force-unlock
    when the worker holding it dies.

WHY
    nginx's ngx_unlock_mutexes() (run on EVERY worker death) force-unlocks only
    &((ngx_slab_pool_t *)shm.addr)->mutex — the slab pool's own lock word. A
    table mutex bound to a SEPARATE embedded lock word is never recovered: a
    worker SIGKILLed mid-critical-section (e.g. at reload's
    worker_shutdown_timeout) while holding it strands the lock forever, and the
    spin+yield path has no timeout to escape. Across many reload/restart cycles
    that becomes a near-certainty and freezes every worker on the next kXR_open.
    The fix binds the table mutex to &sp->lock so nginx recovers it for free;
    this test is the durable guard that keeps it bound there.

    The runtime counterpart tests/test_shm_fork_safety.py proves the master
    survives the reap; this test proves the table mutex is actually unlocked.

RUN
    PYTHONPATH=tests pytest tests/test_shm_mutex_recovery.py -v
"""

import os
from pathlib import Path

import pytest

from cmdscripts.c_regression_units import shm_mutex_recovery

_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_NGX_SRC = os.path.dirname(_OBJS)


def test_dead_worker_table_mutex_is_recovered(tmp_path):
    shm_o = os.path.join(_OBJS, "addon", "compat", "shm_slots.o")
    shmtx_o = os.path.join(_OBJS, "src", "core", "ngx_shmtx.o")
    for obj in (shm_o, shmtx_o):
        if not os.path.exists(obj):
            pytest.skip(f"{obj} not built; build the module first (./configure && make)")

    ok, message = shm_mutex_recovery(tmp_path, Path(_NGX_SRC))
    if message.startswith("SKIP"):
        pytest.skip(message)
    assert ok, f"SHM mutex recovery test failed:\n{message}"
