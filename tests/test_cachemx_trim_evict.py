"""Watermark-reaper (trim) metric-accuracy conformance.

WHAT: A dedicated cache instance is booted with watermarks computed from the
      live filesystem occupancy so the reaper MUST fire, then the three
      watermark counters are asserted exactly: one purge cycle, every cached
      file reaped, and the byte counter equal to the byte-exact sum of the
      reaped files.

WHY:  The watermark family is one of three distinct eviction families
      (policy engine / watermark reaper / protocol-driven) — operators
      capacity-plan off these numbers, and the three families must not
      cross-contaminate: a reaper purge moves ONLY the watermark counters.
"""

import os
import time
from pathlib import Path

import pytest

import _cachemx as cx
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

SIZES = (5000, 7000, 9000)


def statvfs_used_pct(path: str) -> int:
    st = os.statvfs(path)
    used = st.f_blocks - st.f_bavail
    return int(100 * used / st.f_blocks)


class EvictRun:
    """One booted evict instance driven past its high watermark."""

    def __init__(self, ep, cache_dir, metrics_url, snap, misses, outputs):
        self.ep = ep
        self.cache_dir = cache_dir
        self.metrics = metrics_url
        self.snap = snap
        self.misses = misses
        self.outputs = outputs
        self.after = None

    def wait_for_purge(self, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            after = cx.mfetch(self.metrics)
            if self.snap.delta_or_absent("brix_cache_watermark_purges_total",
                                         after=after):
                self.after = after
                return after
            time.sleep(0.5)
        self.after = cx.mfetch(self.metrics)
        return self.after


@pytest.fixture(scope="module")
def ev(tmp_path_factory):
    """Boot the evict instance with the high watermark just below current
    filesystem occupancy so any cache fill trips the reaper, cold-read three
    known-size files, then wait for exactly one purge cycle."""
    work = tmp_path_factory.mktemp("cachemx-ev")
    cache_dir = work / "cache"
    cache_dir.mkdir()
    used = statvfs_used_pct(str(cache_dir))
    # Zero is rejected by the watermark parser. Keep a valid low < high pair;
    # normal test filesystems are already above 2%, so high remains below live
    # occupancy and the first fill deterministically triggers the reaper.
    high, low = max(2, used - 2), max(1, used - 5)
    if low >= high:
        low = high - 1

    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name="lc-cachemx-evict",
            template="nginx_lc_cachemx_evict.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST,
                             "CACHE_DIR": str(cache_dir),
                             "HIGH_WM": str(high), "LOW_WM": str(low),
                             "EVICT_THRESHOLD": "0.99"},
            reason="cachemx conformance: watermark reaper accounting"))
        metrics = f"http://{HOST}:{ep.extra_ports['METRICS_PORT']}/metrics"
        for i, size in enumerate(SIZES):
            (Path(ep.data_root) / f"ev{i}.bin").write_bytes(os.urandom(size))
        snap = cx.Snap(metrics)
        outputs = []
        for i in range(len(SIZES)):
            out = work / f"evo{i}.bin"
            r = cx.run_client(cx.XRDCP, "-f",
                              f"root://{HOST}:{ep.port}/ev{i}.bin",
                              str(out), env=cx.env_none(), timeout=30)
            assert r.returncode == 0, f"evict fill read {i}: {r.stderr}"
            outputs.append(out)
        cx.settle()
        misses = snap.delta_or_absent("brix_cache_misses_total",
                                      {"proto": "stream"})
        run = EvictRun(ep, cache_dir, metrics, snap, misses, outputs)
        run.wait_for_purge()
        yield run
    finally:
        harness.close()


def test_fills_are_cold_misses(ev):
    """The three priming reads were three stream misses (nothing cached)."""
    assert ev.misses == len(SIZES)


def test_reads_served_exact_payloads(ev):
    """Each fill read delivered the exact seeded byte count."""
    for out, size in zip(ev.outputs, SIZES):
        assert out.stat().st_size == size


def test_exactly_one_purge_cycle(ev):
    """The reaper fired exactly once for the whole overshoot — one purge
    cycle covering all files, not one purge per file."""
    assert ev.snap.delta("brix_cache_watermark_purges_total",
                         after=ev.after) == 1


def test_reaped_file_count_exact(ev):
    """Every cached file was reaped — the file counter equals the number of
    cached objects, exactly."""
    assert ev.snap.delta("brix_cache_watermark_evicted_files_total",
                         after=ev.after) == len(SIZES)


def test_reaped_bytes_exact(ev):
    """The byte counter equals the byte-exact sum of the reaped files."""
    assert ev.snap.delta("brix_cache_watermark_evicted_bytes_total",
                         after=ev.after) == sum(SIZES)


def test_cache_dir_emptied(ev):
    """The reap is real: no data files remain under the cache store."""
    leftovers = [p for p in ev.cache_dir.rglob("*") if p.is_file()]
    assert leftovers == []


def test_no_protocol_eviction_cross_contamination(ev):
    """A watermark purge must NOT move the protocol-driven eviction counter
    (that family is reserved for client-caused evictions: rm/DELETE/
    write-over-cached) nor the per-server policy-engine family."""
    assert ev.snap.delta_or_absent("brix_cache_bytes_evicted_total",
                                   {"proto": "stream"}, ev.after) == 0
    assert ev.snap.delta_or_absent("brix_cache_evictions_total",
                                   {"proto": "stream"}, ev.after) == 0


def test_usage_ratio_sample_renders(ev):
    """The occupancy gauge exports a bounded sample on an instance with an
    eviction-managed store."""
    text = ev.after or cx.mfetch(ev.metrics)
    rows = [l for l in text.splitlines()
            if l.startswith("brix_cache_usage_ratio")]
    assert len(rows) == 1
    val = float(rows[0].rsplit(" ", 1)[1])
    assert 0.0 <= val <= 1.0


def test_eviction_threshold_gauge_absent(ev):
    """brix_cache_eviction_threshold_ratio belongs to the per-server policy
    engine, not the watermark reaper: an instance configured with watermark
    trimming (and an on-fill threshold) still exports NO sample — calibrated
    live; a scraper must treat the gauge as policy-engine-only."""
    text = ev.after or cx.mfetch(ev.metrics)
    rows = [l for l in text.splitlines()
            if l.startswith("brix_cache_eviction_threshold_ratio ")]
    assert rows == []


def test_purge_counters_stable_after_settle(ev):
    """No second purge fires once occupancy is back under the low watermark —
    the counters are stable across a re-scrape."""
    a = cx.mfetch(ev.metrics)
    time.sleep(2)
    b = cx.mfetch(ev.metrics)
    for fam in ("brix_cache_watermark_purges_total",
                "brix_cache_watermark_evicted_files_total",
                "brix_cache_watermark_evicted_bytes_total"):
        va = [l for l in a.splitlines() if l.startswith(fam + " ")]
        vb = [l for l in b.splitlines() if l.startswith(fam + " ")]
        assert va == vb, f"{fam} moved with no cache activity"
