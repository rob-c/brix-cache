# _test_xrootd_performance_conformance_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_xrootd_performance_conformance.py.  `from _test_xrootd_performance_conformance_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""
Performance conformance checks against the official XRootD daemon.

These tests use the local reference xrootd server as the oracle for ambiguous
performance expectations.  They do not require nginx to beat the reference
implementation; they catch only large regressions after both servers have read
the same filesystem data through the same client API.

Tune thresholds when running on noisy hosts:
    TEST_PERF_CONFORMANCE_MIB=32
    TEST_PERF_READ_RATIO_LIMIT=4.0
    TEST_PERF_META_RATIO_LIMIT=5.0
    TEST_PERF_WRITE_RATIO_LIMIT=5.0
    TEST_PERF_COPY_RATIO_LIMIT=4.0
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import shutil
import socket
import struct
import time
from pathlib import Path

import pytest
from XRootD import client
from XRootD.client.flags import (
    AccessMode,
    DirListFlags,
    MkDirFlags,
    OpenFlags,
    QueryCode,
    StatInfoFlags,
)

from backend_matrix import root_endpoint_parts


pytestmark = pytest.mark.timeout(180)

PAYLOAD_MIB = int(os.environ.get("TEST_PERF_CONFORMANCE_MIB", "32"))
PAYLOAD_SIZE = PAYLOAD_MIB * 1024 * 1024
WRITE_MIB = int(os.environ.get("TEST_PERF_WRITE_MIB", str(min(PAYLOAD_MIB, 8))))
WRITE_SIZE = WRITE_MIB * 1024 * 1024
READ_CHUNK = int(os.environ.get("TEST_PERF_READ_CHUNK", str(4 * 1024 * 1024)))
READ_RUNS = int(os.environ.get("TEST_PERF_READ_RUNS", "3"))
META_RUNS = int(os.environ.get("TEST_PERF_META_RUNS", "3"))
META_ITERS = int(os.environ.get("TEST_PERF_META_ITERS", "50"))
SMALL_ITERS = int(os.environ.get("TEST_PERF_SMALL_ITERS", "100"))
RANDOM_READ_ITERS = int(os.environ.get("TEST_PERF_RANDOM_READ_ITERS", "200"))
HANDLE_STAT_ITERS = int(os.environ.get("TEST_PERF_HANDLE_STAT_ITERS", "200"))
FS_MUTATION_ITERS = int(os.environ.get("TEST_PERF_FS_MUTATION_ITERS", "25"))
CHMOD_ITERS = int(os.environ.get("TEST_PERF_CHMOD_ITERS", "25"))
MAKEPATH_ITERS = int(os.environ.get("TEST_PERF_MAKEPATH_ITERS", "25"))
TRUNCATE_ITERS = int(os.environ.get("TEST_PERF_TRUNCATE_ITERS", "20"))
SYNC_ITERS = int(os.environ.get("TEST_PERF_SYNC_ITERS", "12"))
READV_ITERS = int(os.environ.get("TEST_PERF_READV_ITERS", "30"))
MIXED_ITERS = int(os.environ.get("TEST_PERF_MIXED_ITERS", "25"))
LOCATE_ITERS = int(os.environ.get("TEST_PERF_LOCATE_ITERS", "50"))
RAW_ITERS = int(os.environ.get("TEST_PERF_RAW_ITERS", "100"))
SESSION_ITERS = int(os.environ.get("TEST_PERF_SESSION_ITERS", "40"))
CONCURRENT_WORKERS = int(os.environ.get("TEST_PERF_CONCURRENT_WORKERS", "4"))
READ_RATIO_LIMIT = float(os.environ.get("TEST_PERF_READ_RATIO_LIMIT", "4.0"))
META_RATIO_LIMIT = float(os.environ.get("TEST_PERF_META_RATIO_LIMIT", "5.0"))
WRITE_RATIO_LIMIT = float(os.environ.get("TEST_PERF_WRITE_RATIO_LIMIT", "5.0"))
COPY_RATIO_LIMIT = float(os.environ.get("TEST_PERF_COPY_RATIO_LIMIT", "4.0"))
CONCURRENT_RATIO_LIMIT = float(
    os.environ.get("TEST_PERF_CONCURRENT_RATIO_LIMIT", str(READ_RATIO_LIMIT))
)
# Grace defaults are intentionally generous so the ratio check (which catches
# actual regressions) isn't overwhelmed by transient OS-level noise during
# parallel test runs.  The env-var overrides are still available for dedicated
# performance-only runs where tighter bounds are meaningful.
READ_GRACE_SECONDS = float(os.environ.get("TEST_PERF_READ_GRACE_SECONDS", "1.0"))
META_GRACE_SECONDS = float(os.environ.get("TEST_PERF_META_GRACE_SECONDS", "1.0"))
WRITE_GRACE_SECONDS = float(os.environ.get("TEST_PERF_WRITE_GRACE_SECONDS", "1.0"))

# Worker-specific prefix prevents concurrent xdist workers from colliding on
# shared test files and from the module-teardown glob deleting another
# worker's in-use files.
_WORKER_ID = os.environ.get("PYTEST_XDIST_WORKER", "main")
PREFIX = f"_perf_conf_{_WORKER_ID}_"
SEED_BYTES = bytes((i * 17 + 29) & 0xFF for i in range(1024 * 1024))
RANDOM_READ_SIZE = 4096
RAW_READ_SIZE = 4096

kXR_OK = 0
kXR_CLOSE = 3003
kXR_LOGIN = 3007
kXR_OPEN = 3010
kXR_PING = 3011
kXR_READ = 3013
kXR_STAT = 3017
kXR_OPEN_READ = 0x0010


def _time_raw_read_loop(base_url: str, path: str) -> float:
    wire_path = path.encode("utf-8")
    digest = hashlib.md5()
    with _raw_session(base_url) as sock:
        fhandle = _raw_open(sock, wire_path, b"\x00\x02")
        try:
            start = time.perf_counter()
            for idx in range(RAW_ITERS):
                offset = (idx * 1048583) % (PAYLOAD_SIZE - RAW_READ_SIZE)
                data = _raw_read(
                    sock,
                    fhandle,
                    offset,
                    RAW_READ_SIZE,
                    struct.pack("!H", (idx + 3) & 0xFFFF),
                )
                assert data == _expected_deterministic_slice(offset, RAW_READ_SIZE)
                digest.update(data)
            elapsed = time.perf_counter() - start
        finally:
            _raw_close(sock, fhandle, b"\xff\xfe")
    assert digest.digest()
    return elapsed


def _time_raw_stat_loop(base_url: str, path: str) -> float:
    wire_path = path.encode("utf-8")
    with _raw_session(base_url) as sock:
        start = time.perf_counter()
        for idx in range(RAW_ITERS):
            streamid = struct.pack("!H", (idx + 2) & 0xFFFF)
            body = _raw_stat(sock, wire_path, streamid)
            assert body
        return time.perf_counter() - start


def _time_raw_session_ping_loop(base_url: str) -> float:
    start = time.perf_counter()
    for _ in range(SESSION_ITERS):
        with _raw_session(base_url) as sock:
            _raw_ping(sock, b"\x00\x02")
    return time.perf_counter() - start


def _time_dirlist_loop(base_url: str, path: str, expected_names: set[str]) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(META_ITERS):
        status, listing = fs.dirlist(path, DirListFlags.STAT)
        assert status.ok, f"dirlist({path}) failed: {status.message}"
        names = {entry.name for entry in listing}
        assert expected_names <= names
    return time.perf_counter() - start


def _time_readv_loop(base_url: str, remote: str) -> float:
    segments = [
        (0, 64 * 1024),
        (256 * 1024, 64 * 1024),
        (1024 * 1024, 128 * 1024),
        (2 * 1024 * 1024, 128 * 1024),
        (3 * 1024 * 1024, 256 * 1024),
        (4 * 1024 * 1024, 256 * 1024),
        (5 * 1024 * 1024, 512 * 1024),
        (6 * 1024 * 1024, 512 * 1024),
    ]
    f = client.File()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"readv open failed for {base_url}: {status.message}"

        start = time.perf_counter()
        for _ in range(READV_ITERS):
            status, result = f.vector_read(segments)
            assert status.ok, f"readv failed for {base_url}: {status.message}"
            chunks = list(result)
            assert len(chunks) == len(segments)
            for chunk, (_, length) in zip(chunks, segments):
                assert len(bytes(chunk.buffer)) == length
        return time.perf_counter() - start
    finally:
        f.close()


def _time_concurrent_reads(base_url: str, remote: str, expected_md5: str) -> float:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = [
            executor.submit(_read_chunked, base_url, remote, expected_md5)
            for _ in range(CONCURRENT_WORKERS)
        ]
        for future in futures:
            future.result()
    return time.perf_counter() - start


def _metadata_worker(
    base_url: str,
    meta_dir: str,
    paths: list[str],
    expected_names: set[str],
) -> None:
    fs = client.FileSystem(base_url)
    for idx in range(META_ITERS):
        status, info = fs.stat(paths[idx % len(paths)])
        assert status.ok, f"concurrent metadata stat failed: {status.message}"
        assert info.size > 0

        if idx % 5 == 0:
            status, listing = fs.dirlist(meta_dir)
            assert status.ok, f"concurrent metadata dirlist failed: {status.message}"
            assert expected_names <= {entry.name for entry in listing}


def _time_concurrent_metadata(
    base_url: str,
    meta_dir: str,
    paths: list[str],
    expected_names: set[str],
) -> float:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = [
            executor.submit(_metadata_worker, base_url, meta_dir, paths, expected_names)
            for _ in range(CONCURRENT_WORKERS)
        ]
        for future in futures:
            future.result()
    return time.perf_counter() - start


@pytest.fixture(scope="module")
def perf_env(test_env, ref_xrootd):
    data_dir = Path(test_env["data_dir"])
    payload = data_dir / f"{PREFIX}payload_{PAYLOAD_MIB}m.bin"
    expected_md5 = _write_deterministic(payload, PAYLOAD_SIZE)

    meta_dir = data_dir / f"{PREFIX}dir"
    meta_dir.mkdir(exist_ok=True)
    expected_names = set()
    stat_sweep_paths = []
    for idx in range(32):
        name = f"entry_{idx:02d}.dat"
        expected_names.add(name)
        (meta_dir / name).write_bytes(f"{name}\n".encode("ascii"))
        stat_sweep_paths.append(_remote(f"{meta_dir.name}/{name}"))

    small = data_dir / f"{PREFIX}small.dat"
    small_content = b"xrootd performance conformance small read\n" * 16
    small.write_bytes(small_content)

    empty = data_dir / f"{PREFIX}empty.dat"
    empty.write_bytes(b"")

    yield {
        "nginx_url": test_env["anon_url"],
        "ref_url": ref_xrootd["url"],
        "payload": _remote(payload.name),
        "payload_md5": expected_md5,
        "meta_dir": _remote(meta_dir.name),
        "meta_names": expected_names,
        "stat_sweep_paths": stat_sweep_paths,
        "small": _remote(small.name),
        "small_content": small_content,
        "empty": _remote(empty.name),
    }

    for path in data_dir.glob(f"{PREFIX}*"):
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)

__all__ = [n for n in dir() if not n.startswith('__')]
