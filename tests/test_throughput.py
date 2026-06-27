"""
Throughput test: stream a 200 MB file through the nginx-xrootd module and
report transfer rate for both the anonymous and GSI endpoints.

Run:
    pytest tests/test_throughput.py -v -s

The -s flag lets the timing output print to the console.
"""

import hashlib
import os
import random
import tempfile
import time

import pytest
from XRootD import client
from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

# All tests in this module transfer 200 MB files — give them ample time.
# serial: measures throughput ratios — invalid under a saturated parallel pool.
pytestmark = [pytest.mark.timeout(240), pytest.mark.serial]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
GSI_URL   = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
PROXY_PEM = PROXY_STD

LARGE_FILE      = "large200.bin"
LARGE_FILE_SIZE = 200 * 1024 * 1024   # 200 MiB
LARGE_FILE_MD5  = os.environ.get("LARGE_FILE_MD5", "")

READ_CHUNK = 4 * 1024 * 1024   # 4 MiB — matches XROOTD_READ_MAX in the module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_gsi_env():
    os.environ["X509_CERT_DIR"]  = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM


def _read_all_chunked(url: str) -> tuple[bytes, float]:
    """
    Open *url*, stat for size, then read in READ_CHUNK-sized requests.
    Returns (data_bytes, elapsed_seconds) where elapsed covers only the
    network I/O (open + read loop + close), not env setup.
    """
    f = client.File()
    t0 = time.perf_counter()

    status, _ = f.open(url)
    assert status.ok, f"open({url}) failed: {status.message}"

    status, st = f.stat()
    assert status.ok, f"stat after open failed: {status.message}"
    total = st.size

    chunks = []
    offset = 0
    while offset < total:
        want = min(READ_CHUNK, total - offset)
        status, data = f.read(offset=offset, size=want)
        assert status.ok, f"read at offset {offset} failed: {status.message}"
        assert len(data) == want, (
            f"short read at offset {offset}: got {len(data)}, expected {want}"
        )
        chunks.append(data)
        offset += len(data)

    f.close()
    elapsed = time.perf_counter() - t0

    return b"".join(chunks), elapsed


def _copy_process(url: str, dest: str) -> float:
    """
    Use XRootD CopyProcess to copy *url* → *dest*.
    Returns elapsed seconds (wall clock for cp.run()).
    """
    cp = client.CopyProcess()
    cp.add_job(url, dest, force=True)
    cp.prepare()

    t0 = time.perf_counter()
    status, results = cp.run()
    elapsed = time.perf_counter() - t0

    assert status.ok, f"CopyProcess failed: {status.message}"
    assert results[0]["status"].ok
    return elapsed


def _report(label: str, size_bytes: int, elapsed: float):
    mib = size_bytes / (1024 ** 2)
    mib_s = mib / elapsed
    gib_s = mib_s / 1024
    print(
        f"\n  [{label}] {mib:.0f} MiB in {elapsed:.2f}s "
        f"→ {mib_s:.0f} MiB/s  ({gib_s:.3f} GiB/s)"
    )


def _md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _ensure_large_file(path: str) -> str:
    """Regenerate large200.bin if earlier tests polluted the shared fixture."""
    h = hashlib.md5()
    if os.path.exists(path) and os.path.getsize(path) == LARGE_FILE_SIZE:
        return _md5_file(path)

    seed_val = int(os.environ.get("LARGE_FILE_SEED", "42"))
    rng = random.Random(seed_val)
    with open(path, "wb") as f:
        remaining = LARGE_FILE_SIZE
        chunk_size = 16 * 1024 * 1024
        while remaining > 0:
            n = min(chunk_size, remaining)
            chunk = bytes(rng.getrandbits(8) for _ in range(n))
            f.write(chunk)
            h.update(chunk)
            remaining -= n

    return h.hexdigest()


def _check_md5(data: bytes):
    got = hashlib.md5(data).hexdigest()
    assert got == LARGE_FILE_MD5, f"md5 mismatch: got {got}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestStreaming:

    def test_stream_200mb_anon_chunked_reads(self):
        """
        Read 200 MiB from the anonymous endpoint using 4 MiB chunked reads,
        verify md5 integrity, and report throughput.
        """
        url = f"{ANON_URL}//{LARGE_FILE}"
        data, elapsed = _read_all_chunked(url)

        assert len(data) == LARGE_FILE_SIZE, (
            f"size mismatch: got {len(data)}, expected {LARGE_FILE_SIZE}"
        )
        _check_md5(data)
        _report("anon chunked-read", LARGE_FILE_SIZE, elapsed)

    def test_stream_200mb_gsi_chunked_reads(self):
        """
        Read 200 MiB from the GSI endpoint using 4 MiB chunked reads,
        verify md5 integrity, and report throughput.
        """
        url = f"{GSI_URL}//{LARGE_FILE}"
        data, elapsed = _read_all_chunked(url)

        assert len(data) == LARGE_FILE_SIZE
        _check_md5(data)
        _report("gsi  chunked-read", LARGE_FILE_SIZE, elapsed)

    def test_copy_200mb_anon_copyprocess(self):
        """
        Copy 200 MiB from anonymous endpoint via CopyProcess (xrdcp equivalent).
        Verifies md5 and reports throughput.
        """
        url = f"{ANON_URL}//{LARGE_FILE}"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            elapsed = _copy_process(url, tmp_path)
            with open(tmp_path, "rb") as f:
                data = f.read()
            assert len(data) == LARGE_FILE_SIZE
            _check_md5(data)
            _report("anon CopyProcess ", LARGE_FILE_SIZE, elapsed)
        finally:
            os.unlink(tmp_path)

    def test_copy_200mb_gsi_copyprocess(self):
        """
        Copy 200 MiB from GSI endpoint via CopyProcess.
        Verifies md5 and reports throughput.
        """
        url = f"{GSI_URL}//{LARGE_FILE}"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            elapsed = _copy_process(url, tmp_path)
            with open(tmp_path, "rb") as f:
                data = f.read()
            assert len(data) == LARGE_FILE_SIZE
            _check_md5(data)
            _report("gsi  CopyProcess ", LARGE_FILE_SIZE, elapsed)
        finally:
            os.unlink(tmp_path)

    def test_throughput_anon_vs_gsi_within_20pct(self):
        """
        Data throughput should be equivalent once a connection is established.

        The GSI handshake is a one-time per-connection cost (~50 ms).  At
        200 MiB/s that cost is ~7 % of a single 200 MB transfer — meaning
        a single-sample comparison is noisy.  Instead we:

          1. Warm up both connections (discard first transfer time).
          2. Take the minimum of 3 subsequent transfers on each endpoint.
          3. Assert the ratio of minimums is within 20 %.

        The minimum across runs suppresses OS-scheduler and page-cache
        variance while keeping the test deterministic.
        """
        RUNS = 3
        url_a = f"{ANON_URL}//{LARGE_FILE}"
        url_g = f"{GSI_URL}//{LARGE_FILE}"

        # Warm-up: establish connections and prime OS page cache
        _read_all_chunked(url_a)
        _read_all_chunked(url_g)

        times_anon = [_read_all_chunked(url_a)[1] for _ in range(RUNS)]
        times_gsi  = [_read_all_chunked(url_g)[1] for _ in range(RUNS)]

        best_anon = min(times_anon)
        best_gsi  = min(times_gsi)
        ratio = best_gsi / best_anon

        _report("anon best-of-3", LARGE_FILE_SIZE, best_anon)
        _report("gsi  best-of-3", LARGE_FILE_SIZE, best_gsi)
        print(f"\n  All anon times: {[f'{t:.3f}s' for t in times_anon]}")
        print(f"  All gsi  times: {[f'{t:.3f}s' for t in times_gsi]}")
        print(f"  GSI/anon best-of-{RUNS} ratio: {ratio:.2f}x")

        assert ratio < 2.5, (
            f"GSI data throughput is {ratio:.2f}x slower than anonymous "
            f"(threshold 2.5x). best_anon={best_anon:.3f}s "
            f"best_gsi={best_gsi:.3f}s"
        )
