"""
Concurrent transfer tests for nginx-xrootd.

Runs N simultaneous 200 MB transfers from the same single-worker nginx
instance and measures per-connection throughput, aggregate throughput, and
data integrity.

Run:
    pytest tests/test_concurrent.py -v -s
"""

import hashlib
import multiprocessing as mp
import os
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags
from settings import (
    CA_DIR,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
)

# serial: these assert aggregate-throughput scaling ratios, which are only valid
# when the box isn't saturated — they must not run inside the parallel pool.
# timeout(180): each case spawns a ProcessPoolExecutor of GSI xrdcp workers; the
# 8-worker GSI cases can exceed the 30s default when the box is fatigued after a
# full-suite lane, causing spurious timeouts (they complete in seconds isolated).
pytestmark = [pytest.mark.serial, pytest.mark.timeout(180)]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANON_URL    = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
GSI_URL     = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"

PROXY_PEM = PROXY_STD

LARGE_FILE      = "large200.bin"
LARGE_FILE_SIZE = 200 * 1024 * 1024


def _resolve_large_file_md5() -> str:
    """Return the MD5 of large200.bin.

    Prefer the env var set by conftest._setup_session(); fall back to computing
    it from disk so that TEST_SKIP_SERVER_SETUP=1 runs still work.
    """
    import hashlib as _hashlib
    cached = os.environ.get("LARGE_FILE_MD5")
    if cached:
        return cached
    path = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "data", "large200.bin")
    if not os.path.exists(path):
        return ""
    h = _hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


LARGE_FILE_MD5 = _resolve_large_file_md5()

READ_CHUNK = 4 * 1024 * 1024   # 4 MiB — matches BRIX_READ_MAX in module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Per-worker transfer function (called from threads)
# ---------------------------------------------------------------------------

def _transfer_worker(worker_id: int, base_url: str) -> dict:
    """
    Open and read LARGE_FILE entirely in READ_CHUNK-sized requests.
    Returns a result dict with timing and integrity information.
    Called from a thread; each thread owns its own XRootD File object.
    """
    url = f"{base_url}//{LARGE_FILE}"
    result = {"id": worker_id, "url": base_url, "ok": False, "error": None}

    try:
        f = client.File()
        t_open = time.perf_counter()

        status, _ = f.open(url)
        if not status.ok:
            result["error"] = f"open failed: {status.message}"
            return result

        status, st = f.stat()
        if not status.ok:
            result["error"] = f"stat failed: {status.message}"
            return result
        total = st.size

        t_start = time.perf_counter()
        md5 = hashlib.md5()
        received = 0

        while received < total:
            want = min(READ_CHUNK, total - received)
            status, data = f.read(offset=received, size=want)
            if not status.ok:
                result["error"] = f"read at {received} failed: {status.message}"
                return result
            if len(data) != want:
                result["error"] = (
                    f"short read at {received}: got {len(data)}, want {want}"
                )
                return result
            md5.update(data)
            received += len(data)

        f.close()
        t_end = time.perf_counter()

        result.update(
            ok=True,
            bytes=received,
            md5=md5.hexdigest(),
            t_open=t_open,
            t_start=t_start,
            t_end=t_end,
            elapsed_total=t_end - t_open,
            elapsed_data=t_end - t_start,
            mib_s=(received / (1024**2)) / (t_end - t_start),
        )
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _worker_pool(max_workers: int):
    return ProcessPoolExecutor(
        max_workers=max_workers,
        mp_context=mp.get_context("spawn"),
    )


def _run_concurrent(n_workers: int, base_url: str) -> tuple[list[dict], float]:
    """
    Launch n_workers threads simultaneously, each transferring LARGE_FILE.
    Returns (results_list, wall_clock_elapsed).
    """
    t_wall_start = time.perf_counter()
    with _worker_pool(n_workers) as pool:
        futures = [
            pool.submit(_transfer_worker, i, base_url)
            for i in range(n_workers)
        ]
        results = [f.result() for f in as_completed(futures)]
    t_wall_end = time.perf_counter()
    return results, t_wall_end - t_wall_start


def _assert_and_report(results: list[dict], n: int, wall: float, label: str):
    total_bytes = 0
    for r in results:
        assert r["ok"], f"worker {r['id']} failed: {r['error']}"
        assert r["bytes"] == LARGE_FILE_SIZE, (
            f"worker {r['id']}: size {r['bytes']} != {LARGE_FILE_SIZE}"
        )
        assert r["md5"] == LARGE_FILE_MD5, (
            f"worker {r['id']}: md5 mismatch {r['md5']}"
        )
        total_bytes += r["bytes"]

    total_mib   = total_bytes / (1024**2)
    agg_mib_s   = total_mib / wall
    per_rates   = [r["mib_s"] for r in results]
    min_rate    = min(per_rates)
    max_rate    = max(per_rates)
    mean_rate   = sum(per_rates) / len(per_rates)

    # Time from first open to last close — measures true overlap
    t_first = min(r["t_open"]  for r in results)
    t_last  = max(r["t_end"]   for r in results)
    overlap = t_last - t_first

    print(
        f"\n  [{label}] {n} concurrent × 200 MiB = {total_mib:.0f} MiB total"
        f"\n    wall clock      : {wall:.2f}s"
        f"\n    open→close span : {overlap:.2f}s"
        f"\n    aggregate rate  : {agg_mib_s:.0f} MiB/s"
        f"\n    per-connection  : min={min_rate:.0f}  mean={mean_rate:.0f}"
        f"  max={max_rate:.0f} MiB/s"
    )
    return agg_mib_s, per_rates


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _pipe_pattern(size: int) -> bytes:
    """Position-derived payload: every 1 MiB window holds distinct bytes, so a
    mis-demultiplexed streamID returns the wrong slice and the assert fires."""
    period = bytes((i * 37 + 11) & 0xFF for i in range(256))
    return (period * (size // 256 + 1))[:size]


def _tls_read_slice(idx: int, offset: int, length: int, expect: bytes):
    """Open an independent File on the shared TLS connection, read one
    <=window slice, verify it byte-exact, close.  Returns (idx, ok, detail)."""
    f = client.File()
    try:
        st, _ = f.open(f"{GSI_TLS_URL}//{_PIPE_FILE}", OpenFlags.READ)
        if not st.ok:
            return idx, False, f"open: {st.message}"
        st, data = f.read(offset=offset, size=length)
        if not st.ok:
            return idx, False, f"read at {offset}: {st.message}"
        if bytes(data) != expect:
            return idx, False, f"slice mismatch at {offset} (len {len(data)})"
        return idx, True, ""
    finally:
        try:
            f.close()
        except Exception:
            pass
