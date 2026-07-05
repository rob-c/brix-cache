"""
tests/test_ratelimit_gauge_reset.py — regression wrapper for rate-limit in-use
gauge reset on reload ("throttle/concurrency wedges after many reboots").

WHAT
    Compiles and runs tests/c/test_ratelimit_gauge_reset.c against the real
    compiled ratelimit_zone.o. Proves the in-use gauges (in_flight, open_files)
    are cleared on reload adoption while the rate/bandwidth buckets survive.

WHY
    These gauges self-heal only via a matched decrement. A worker SIGKILLed
    mid-request (e.g. at reload's worker_shutdown_timeout) never releases, so the
    increment leaks; the node lives in the SHM zone that is adopted across reload
    ("live buckets survive"), so the leak persists and accumulates every restart
    cycle. LRU eviction only frees the tail under slab pressure, so a hot key (or
    a small-keyspace / global throttle) is never cleared and eventually the cap
    rejects that key — or the whole server — forever. Resetting the gauges at
    reload bounds any crash-leak to a single generation.

RUN
    PYTHONPATH=tests pytest tests/test_ratelimit_gauge_reset.py -v
"""

import os
import subprocess

import pytest

_HERE = os.path.dirname(__file__)
_RUNNER = os.path.join(_HERE, "c", "run_ratelimit_gauge_reset_tests.sh")
_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_NGX_SRC = os.path.dirname(_OBJS)


def test_reload_clears_leaked_inuse_gauges():
    zone_o = os.path.join(_OBJS, "addon", "ratelimit", "ratelimit_zone.o")
    if not os.path.exists(zone_o):
        pytest.skip(f"{zone_o} not built; build the module first (./configure && make)")

    proc = subprocess.run(
        [_RUNNER, _NGX_SRC],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
    )
    out = proc.stdout.decode(errors="replace")
    assert proc.returncode == 0, f"rate-limit gauge-reset test failed:\n{out}"
    assert "all rate-limit gauge-reset checks passed" in out, f"unexpected output:\n{out}"
