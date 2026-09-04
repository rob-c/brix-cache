"""
tests/test_ultra_parallel_mixed_storm.py

16k-WIDE MIXED storms — read-only METADATA clients and TRANSFER clients
released SIMULTANEOUSLY, laddered to 16384 concurrent clients.

WHY: the single-shape ladder (test_ultra_parallel_breaking_point.py) proves
graceful shedding of homogeneous FTS transfer storms.  Real FTS overload is
WIDER and MIXED: a wall of cheap r/o metadata probes (stat polling) arrives
in the same instant as the transfer wave, and the two classes compete for
the same admission path, worker loops and fd budget.  The contract adds one
clause on top of the graceful-degradation contract the helpers encode:
NEITHER client class may be starved to zero while the other is served.

Every rung releases n clients through one barrier: 1 in 4 runs a full
FTS-shaped transfer (login+stat+open+read 64KiB+close, byte-verified), the
rest run r/o metadata loops (login + 2x ULTRA_MIX_META_OPS stats).  Client
threads use small stacks and spread their SOURCE address over 127.0.0.2-9 so
16k-wide rungs exhaust neither thread memory nor the local 4-tuple space;
the fd soft limit is raised per rung (a low hard limit clamps the ladder
rather than failing it).

The comparison test runs the identical mixed ladder against an official
`xrootd` daemon on the same payloads and asserts BriX breaks no earlier
(skips cleanly when `xrootd` is not installed).

Tunables (env): ULTRA_MIX_RUNGS="1024,4096,16384", ULTRA_MIX_JOBS=1,
ULTRA_MIX_META_OPS=3, ULTRA_MIX_PRESSURE=256, ULTRA_OP_TIMEOUT=20 (shared
with the single-shape suite).

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_ultra_parallel_mixed_storm.py -v -s
"""

import os
import threading
import time

import pytest

from settings import HOST

import _test_ultra_parallel_helpers as U

pytestmark = [pytest.mark.slow, pytest.mark.timeout(3000),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-ultra-parallel")]

MIX_RUNGS = [int(x) for x in
             os.environ.get("ULTRA_MIX_RUNGS", "1024,4096,16384").split(",")]
MIX_JOBS = int(os.environ.get("ULTRA_MIX_JOBS", "1"))
META_OPS = int(os.environ.get("ULTRA_MIX_META_OPS", "3"))
# Fairness pressure width.  NOT the ladder width: past ~256 threads the
# GIL-bound client starves its own VICTIM thread (a 256KiB read measured
# 26.5s at 1024 pressure threads purely from client-side scheduling), so a
# wider setting measures the client, not the server.  Width lives in the
# ladder tests; this one measures fairness.
PRESSURE = int(os.environ.get("ULTRA_MIX_PRESSURE", "256"))
TRANSFER_EVERY = 4          # 1 in 4 clients is a transfer; the rest metadata
STACK = 512 * 1024          # per-thread stack: 16k threads must stay cheap

stock_xrootd = U.stock_xrootd


# --------------------------------------------------------------------------- #
# Mixed jobs                                                                   #
# --------------------------------------------------------------------------- #

def _src_addr(idx):
    """Spread client SOURCE addresses over 127.0.0.2-9 (loopback only) so a
    16k-wide rung times 3 rungs times 2 servers never exhausts the ephemeral
    4-tuple space or the client-side TIME_WAIT budget."""
    if not HOST.startswith("127."):
        return None
    return f"127.0.0.{2 + idx % 8}"


def _meta_job(port, src):
    """One r/o metadata client: login + 2*META_OPS stats, clean disconnect."""
    s = U._login(port, src)
    try:
        for _ in range(META_OPS):
            U._op_stat(s, "/mix.bin")
            U._op_stat(s, "/")
    finally:
        s.close()


def _mix_outcome(port, idx, spread=True, heavy=False):
    """Classify one client's job; returns (class, (kind, latency, detail)).
    `spread=False` keeps every client on the default source address — the
    capped test needs that, or source spreading dilutes a key=ip cap 8x.
    `heavy=True` moves the 1MiB storm payload instead of the 64KiB mixed
    one — a 64KiB read drains in milliseconds, so only heavy transfers hold
    enough in-flight concurrency to engage a concurrency cap reliably."""
    src = _src_addr(idx) if spread else None
    if idx % TRANSFER_EVERY == 0:
        path, ref = (("/storm.bin", U._storm_blob()) if heavy
                     else ("/mix.bin", U._mix_blob()))
        return "xfer", U._outcome(
            lambda: U._fts_job(port, path, ref, src=src))
    return "meta", U._outcome(lambda: _meta_job(port, src))


# --------------------------------------------------------------------------- #
# Mixed rungs                                                                  #
# --------------------------------------------------------------------------- #

def _mix_worker(port, barrier, out, idx, spread, jobs, heavy):
    res = U._empty_rung(0)
    res["served_meta"] = res["served_xfer"] = 0
    try:
        barrier.wait(timeout=300)
    except threading.BrokenBarrierError:
        pass
    for _ in range(jobs):
        cls, (kind, lat, detail) = _mix_outcome(port, idx, spread, heavy)
        res[kind] += 1
        if kind == "served":
            res["lat"].append(lat)
            res["served_" + cls] += 1
        elif kind == "errored" and len(res["err"]) < 3:
            res["err"].append(detail)
    out[idx] = res


def _spawn_mix(port, n, out, spread, jobs, heavy):
    """Spawn n small-stack workers behind one barrier and join them.  A
    client-side thread-limit failure marks the REMAINING slots unspawned
    (not the server's fault) and aborts the barrier so started workers
    release immediately."""
    barrier = threading.Barrier(n)
    old = threading.stack_size(STACK)
    threads = []
    try:
        for i in range(n):
            t = threading.Thread(target=_mix_worker, daemon=True,
                                 args=(port, barrier, out, i, spread, jobs,
                                       heavy))
            try:
                t.start()
            except RuntimeError:
                for j in range(i, n):
                    out[j] = "unspawned"
                barrier.abort()
                break
            threads.append(t)
    finally:
        threading.stack_size(old)
    deadline = time.perf_counter() + U.OP_TIMEOUT * (jobs + 2) + 300
    for t in threads:
        t.join(timeout=max(1.0, deadline - time.perf_counter()))


def _collect_mix(n, out, wall, jobs):
    row = U._empty_rung(n)
    row["wall"] = wall
    row["served_meta"] = row["served_xfer"] = row["unspawned"] = 0
    for res in out:
        if res == "unspawned":
            row["unspawned"] += jobs
        elif res is None:                   # a hung worker IS a dirty failure
            row["errored"] += jobs
            if len(row["err"]) < 3:
                row["err"].append("worker hung past deadline")
        else:
            U._merge_rung(row, res)
            row["served_meta"] += res["served_meta"]
            row["served_xfer"] += res["served_xfer"]
    return row


def _run_mix_rung(port, n, spread=True, jobs=MIX_JOBS, heavy=False):
    budget = U._raise_nofile(n + 512)
    n_eff = min(n, budget)
    if n_eff < n:
        print(f"  [fd hard limit clamps rung {n} -> {n_eff}]", flush=True)
    out = [None] * n_eff
    started = time.perf_counter()
    _spawn_mix(port, n_eff, out, spread, jobs, heavy)
    return _collect_mix(n_eff, out, time.perf_counter() - started, jobs)


def _mix_ladder(label, port, rungs=None):
    rows = []
    for n in (MIX_RUNGS if rungs is None else rungs):
        row = _run_mix_rung(port, n)
        rows.append(row)
        if not U._server_alive(port):
            row["died"] = True
            break
    _print_mix(label, rows)
    return rows


def _print_mix(label, rows):
    U._print_table(label, rows, MIX_JOBS)
    for r in rows:
        note = f"  unspawned={r['unspawned']}" if r.get("unspawned") else ""
        print(f"      mix: meta served {r['served_meta']} / "
              f"xfer served {r['served_xfer']}{note}", flush=True)


def _assert_rung_clean(row):
    assert not row.get("died"), f"server died at rung n={row['n']}"
    assert row["errored"] <= U._dirty_tol(row), \
        (f"rung n={row['n']}: {row['errored']} dirty failures "
         f"(established sessions broken): {row['err'][:3]}")
    assert row["served_meta"] > 0 and row["served_xfer"] > 0, \
        (f"rung n={row['n']}: a client class was starved to zero "
         f"(meta {row['served_meta']} / xfer {row['served_xfer']})")


def _spawn_mix_pressure(port, stop, n):
    """Background mixed-storm threads looping jobs until `stop` is set."""
    def _pressure(idx):
        while not stop.is_set():
            _mix_outcome(port, idx)
    old = threading.stack_size(STACK)
    try:
        storm = [threading.Thread(target=_pressure, daemon=True, args=(i,))
                 for i in range(n)]
        for t in storm:
            t.start()
    finally:
        threading.stack_size(old)
    return storm


# =========================================================================== #
# Tests                                                                        #
# =========================================================================== #

class TestUltraParallelMixedStorm:

    def test_mixed_storm_ladder_sheds_cleanly_to_the_top_rung(
            self, lifecycle, tmp_path):
        """Success: metadata and transfer clients storm SIMULTANEOUSLY at
        every rung (top rung 16384 clients) with no dirty failures, BOTH
        client classes make progress at every rung, and the server serves a
        byte-exact transfer immediately afterwards."""
        port = U._start(lifecycle, tmp_path)
        rows = _mix_ladder("brix mixed storm", port)
        base = rows[0]
        assert base["served"] >= 0.99 * U._dispatched(base), \
            f"base rung n={base['n']} not served: {base}"
        for row in rows:
            _assert_rung_clean(row)
        assert U._server_alive(port), "server unhealthy after the ladder"
        kind, _lat, detail = U._job_outcome(port, "/mix.bin", U._mix_blob())
        assert kind == "served", f"post-storm recovery transfer: {detail}"

    def test_capped_mixed_storm_sheds_with_kxr_wait_not_dirty_failures(
            self, lifecycle, tmp_path):
        """Error/backpressure: a mixed storm far over brix_concurrency_limit
        is shed via kXR_wait — never by breaking established sessions —
        while some jobs of the storm still get served."""
        port = U._start(lifecycle, tmp_path,
                        rl_zone="brix_rate_limit_zone zone=rlc:4m;",
                        rl_rule="brix_concurrency_limit zone=rlc "
                                "key=ip limit=8;")
        # Single source (spreading would dilute the key=ip cap 8x), 3 jobs
        # per client, and HEAVY 1MiB transfers: light single-shot jobs drain
        # too fast to hold >16 in flight against a GIL-scheduled client.
        row = _run_mix_rung(port, 256, spread=False, jobs=3, heavy=True)
        _print_mix("brix mixed capped (limit=8, n=256)", [row])
        assert row["throttled"] > 0, \
            "a mixed storm over a 16-way cap must shed via kXR_wait"
        assert row["errored"] <= U._dirty_tol(row), \
            f"cap shed dirtily: {row['err'][:3]}"
        assert row["served"] > 0, "cap must shed the excess, not everything"
        assert U._server_alive(port), "server unhealthy after capped storm"

    def test_mixed_storm_cannot_starve_an_established_session(
            self, lifecycle, tmp_path):
        """Security-negative (partial-DoS/fairness): a transfer session
        established BEFORE the mixed storm keeps completing timely byte-exact
        reads while metadata AND transfer pressure rages."""
        port = U._start(lifecycle, tmp_path)
        U._raise_nofile(PRESSURE + 512)
        victim = U._login(port)
        fh = U._op_open_read(victim, "/victim.bin")
        stop, storm = threading.Event(), []
        try:
            storm = _spawn_mix_pressure(port, stop, PRESSURE)
            U._victim_reads_stay_clean(victim, fh)
            U._op_close(victim, fh)
        finally:
            stop.set()
            victim.close()
            for t in storm:
                t.join(timeout=U.OP_TIMEOUT + 30)
        assert U._server_alive(port), "server unhealthy after fairness storm"

    def test_mixed_breaking_point_no_earlier_than_official_xrootd(
            self, lifecycle, tmp_path, stock_xrootd):
        """Comparison: the identical mixed ladder against an official xrootd
        on the same payloads.  BriX must not break (dirty failures / death)
        at a rung the official server survives.  Ladders run sequentially —
        a breaking-rung comparison, not a throughput bench."""
        port = U._start(lifecycle, tmp_path)
        rows_brix = _mix_ladder("brix mixed", port)
        rows_stock = _mix_ladder("official xrootd mixed", stock_xrootd)
        bp_brix = U._breaking_rung(rows_brix)
        bp_stock = U._breaking_rung(rows_stock)
        print(f"\nmixed breaking rung: brix={bp_brix or 'none'} "
              f"official={bp_stock or 'none'} (ladder {MIX_RUNGS})")
        assert bp_brix is None or (bp_stock is not None
                                   and bp_brix >= bp_stock), \
            (f"brix broke at rung {bp_brix} while official xrootd "
             f"survived to {bp_stock or 'the top'}")
