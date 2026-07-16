"""
tests/test_cache_lock_reclaim.py — regression wrapper for cache-fill lock
dead-owner reclaim ("cache entry stuck after many reboots").

WHAT
    Compiles and runs tests/c/test_cache_lock_reclaim.c against the real compiled
    lock.o. Proves that an orphaned O_CREAT|O_EXCL cache-fill lock left by a dead
    worker is reclaimed instead of stranding the entry forever.

WHY
    The fill lock is a lock FILE (not an fcntl/flock the kernel releases on
    death), unlinked only at normal fill exits. A worker SIGKILLed mid-fill
    (e.g. at reload's worker_shutdown_timeout) leaves it behind; nothing else
    reclaims it (cache_reap skips *.lock), it survives reboots on disk, and every
    later request for that entry polls to cache_lock_timeout (default 300s) and
    fails kXR_FileLocked forever while pinning a thread-pool thread. Across many
    restart cycles these accumulate. The fix reclaims a provably-stale lock
    (owner pid dead) and retries; this test guards it (and guards against
    over-reclaiming a live owner's lock).

RUN
    PYTHONPATH=tests pytest tests/test_cache_lock_reclaim.py -v
"""

import os
from pathlib import Path

import pytest

from cmdscripts.c_regression_units import cache_lock_reclaim

_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_NGX_SRC = os.path.dirname(_OBJS)


def test_dead_owner_fill_lock_is_reclaimed(tmp_path):
    lock_o = os.path.join(_OBJS, "addon", "cache", "lock.o")
    if not os.path.exists(lock_o):
        pytest.skip(f"{lock_o} not built; build the module first (./configure && make)")

    ok, message = cache_lock_reclaim(tmp_path, Path(_NGX_SRC))
    if message.startswith("SKIP"):
        pytest.skip(message)
    assert ok, f"cache-lock reclaim test failed:\n{message}"
