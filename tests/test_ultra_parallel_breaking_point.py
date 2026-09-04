"""
tests/test_ultra_parallel_breaking_point.py

Ultra-parallel BREAKING-POINT storms — FTS-shaped workloads at ladder
concurrency until the server degrades, asserting it degrades GRACEFULLY.

WHY: production FTS traffic looks like a DoS: thousands of independent
transfer jobs, each a fresh TCP connect + login + stat + open + read + close,
submitted with poor client-side backoff.  A server that handles overload
badly turns that load into hangs, mid-frame drops of established sessions and
worker crashes.  BriX's contract under an FTS storm is:

  1. every request on an established session is answered with a well-formed
     frame — served, or shed via kXR_wait (the protocol's backoff signal
     FTS/xrdcp honor);
  2. admission failures happen at CONNECT/handshake time (refused or reset
     before login), never as a mid-session drop of a logged-in stream;
  3. an established well-behaved session is never starved out by the storm
     (the partial-DoS / fairness property);
  4. immediately after the storm the server serves a byte-exact transfer.

The ladder storms N concurrent FTS jobs per rung (default 16..256, env
ULTRA_RUNGS for bigger manual ladders) and reports the breaking rung — the
first rung with DIRTY failures (mid-session drops / bad bytes / hangs).
Clean shedding (kXR_wait, connect-time refusal) never counts as breaking.
The comparison test runs the identical ladder against an official `xrootd`
daemon on the same data and asserts BriX breaks no earlier (skips cleanly
when `xrootd` is not installed).

The wire/job/rung machinery is shared with the 16k-wide MIXED storm suite
(test_ultra_parallel_mixed_storm.py) via _test_ultra_parallel_helpers.py.

Tunables (env): ULTRA_RUNGS="16,32,64,128,256", ULTRA_JOBS_PER_THREAD=3,
ULTRA_OP_TIMEOUT=20.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_ultra_parallel_breaking_point.py -v -s
"""

import os
import threading
import time

import pytest

import _test_ultra_parallel_helpers as U

pytestmark = [pytest.mark.slow, pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-ultra-parallel")]

RUNGS = [int(x) for x in
         os.environ.get("ULTRA_RUNGS", "16,32,64,128,256").split(",")]
JOBS = int(os.environ.get("ULTRA_JOBS_PER_THREAD", "3"))

stock_xrootd = U.stock_xrootd


# --------------------------------------------------------------------------- #
# Storm rungs                                                                  #
# --------------------------------------------------------------------------- #

def _storm_worker(port, path, ref, barrier, out, idx):
    res = U._empty_rung(0)
    try:
        barrier.wait(timeout=60)
    except threading.BrokenBarrierError:
        pass
    for _ in range(JOBS):
        kind, lat, detail = U._job_outcome(port, path, ref)
        res[kind] += 1
        if kind == "served":
            res["lat"].append(lat)
        elif kind == "errored" and len(res["err"]) < 3:
            res["err"].append(detail)
    out[idx] = res


def _spawn_and_join(port, n, path, ref, out):
    barrier = threading.Barrier(n)
    threads = [threading.Thread(target=_storm_worker, daemon=True,
                                args=(port, path, ref, barrier, out, i))
               for i in range(n)]
    for t in threads:
        t.start()
    deadline = time.perf_counter() + U.OP_TIMEOUT * (JOBS + 2) + 120
    for t in threads:
        t.join(timeout=max(1.0, deadline - time.perf_counter()))


def _collect_rung(n, out, wall):
    row = U._empty_rung(n)
    row["wall"] = wall
    for res in out:
        if res is None:                     # a hung worker IS a dirty failure
            row["errored"] += JOBS
            row["err"].append("worker hung past deadline")
        else:
            U._merge_rung(row, res)
    return row


def _run_rung(port, n, path="/storm.bin", ref=None):
    """N threads x JOBS back-to-back FTS jobs, released simultaneously."""
    ref = U._storm_blob() if ref is None else ref
    out = [None] * n
    started = time.perf_counter()
    _spawn_and_join(port, n, path, ref, out)
    return _collect_rung(n, out, time.perf_counter() - started)


def _ladder(label, port, rungs):
    rows = []
    for n in rungs:
        row = _run_rung(port, n)
        rows.append(row)
        if not U._server_alive(port):
            row["died"] = True
            break
    U._print_table(label, rows, JOBS)
    return rows


def _spawn_pressure(port, stop, n):
    """Background storm threads looping FTS jobs until `stop` is set."""
    def _pressure():
        while not stop.is_set():
            U._job_outcome(port, "/storm.bin", U._storm_blob())
    storm = [threading.Thread(target=_pressure, daemon=True)
             for _ in range(n)]
    for t in storm:
        t.start()
    return storm


# =========================================================================== #
# Tests                                                                        #
# =========================================================================== #

class TestUltraParallelBreakingPoint:

    def test_storm_ladder_sheds_cleanly_to_the_top_rung(self, lifecycle,
                                                        tmp_path):
        """Success: the full ladder produces NO dirty failures — every job is
        served or shed cleanly, the base rung is fully served, and the first
        transfer after the storm is byte-exact."""
        port = U._start(lifecycle, tmp_path)
        rows = _ladder("brix storm ladder", port, RUNGS)
        base = rows[0]
        assert base["served"] >= 0.99 * U._dispatched(base), \
            f"base rung n={base['n']} not served: {base}"
        for row in rows:
            assert not row.get("died"), f"server died at rung n={row['n']}"
            assert row["errored"] <= U._dirty_tol(row), \
                (f"rung n={row['n']}: {row['errored']} dirty failures "
                 f"(established sessions broken): {row['err'][:3]}")
        assert U._server_alive(port), "server unhealthy after the ladder"
        kind, _lat, detail = U._job_outcome(port, "/storm.bin",
                                            U._storm_blob())
        assert kind == "served", f"post-storm recovery transfer: {detail}"

    def test_concurrency_cap_sheds_with_kxr_wait_not_dirty_failures(
            self, lifecycle, tmp_path):
        """Error/backpressure: with brix_concurrency_limit far below the storm,
        the excess is shed via kXR_wait (the FTS backoff signal) — never by
        breaking established sessions — while some jobs still get served."""
        port = U._start(lifecycle, tmp_path,
                        rl_zone="brix_rate_limit_zone zone=rlc:4m;",
                        rl_rule="brix_concurrency_limit zone=rlc "
                                "key=ip limit=16;")
        row = _run_rung(port, 96)
        U._print_table("brix capped (limit=16, n=96)", [row], JOBS)
        assert row["throttled"] > 0, \
            "a 96-way storm over a 16-way cap must shed via kXR_wait"
        assert row["errored"] <= U._dirty_tol(row), \
            f"cap shed dirtily: {row['err'][:3]}"
        assert row["served"] > 0, "cap must shed the excess, not everything"
        assert U._server_alive(port), "server unhealthy after capped storm"

    def test_storm_cannot_starve_an_established_session(self, lifecycle,
                                                        tmp_path):
        """Security-negative (partial-DoS/fairness): a session established
        BEFORE the storm keeps completing timely byte-exact reads while a
        top-rung storm rages."""
        port = U._start(lifecycle, tmp_path)
        victim = U._login(port)
        fh = U._op_open_read(victim, "/victim.bin")
        stop, storm = threading.Event(), []
        try:
            storm = _spawn_pressure(port, stop, RUNGS[-1])
            U._victim_reads_stay_clean(victim, fh)
            U._op_close(victim, fh)
        finally:
            stop.set()
            victim.close()
            for t in storm:
                t.join(timeout=U.OP_TIMEOUT + 30)
        assert U._server_alive(port), "server unhealthy after fairness storm"

    def test_breaking_point_no_earlier_than_official_xrootd(
            self, lifecycle, tmp_path, stock_xrootd):
        """Comparison: the identical ladder against an official xrootd on the
        same payloads.  BriX must not break (dirty failures / death) at a rung
        the official server survives.  Ladders run sequentially — a
        breaking-rung comparison, not a throughput bench."""
        port = U._start(lifecycle, tmp_path)
        rows_brix = _ladder("brix", port, RUNGS)
        rows_stock = _ladder("official xrootd", stock_xrootd, RUNGS)
        bp_brix = U._breaking_rung(rows_brix)
        bp_stock = U._breaking_rung(rows_stock)
        print(f"\nbreaking rung: brix={bp_brix or 'none'} "
              f"official={bp_stock or 'none'} (ladder {RUNGS})")
        assert bp_brix is None or (bp_stock is not None
                                   and bp_brix >= bp_stock), \
            (f"brix broke at rung {bp_brix} while official xrootd "
             f"survived to {bp_stock or 'the top'}")
