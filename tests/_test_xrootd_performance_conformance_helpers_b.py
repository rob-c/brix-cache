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


def _time_random_read_loop(base_url: str, remote: str) -> float:
    if PAYLOAD_SIZE <= RANDOM_READ_SIZE:
        pytest.skip("random read conformance needs payload larger than read size")

    f = client.File()
    digest = hashlib.md5()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"random-read open failed for {base_url}: {status.message}"

        start = time.perf_counter()
        for idx in range(RANDOM_READ_ITERS):
            offset = (idx * 1048583) % (PAYLOAD_SIZE - RANDOM_READ_SIZE)
            status, data = f.read(offset=offset, size=RANDOM_READ_SIZE)
            assert status.ok, (
                f"random read failed for {base_url} at {offset}: {status.message}"
            )
            assert data == _expected_deterministic_slice(offset, RANDOM_READ_SIZE)
            digest.update(data)
        elapsed = time.perf_counter() - start
    finally:
        f.close()

    assert digest.digest()
    return elapsed


def _time_handle_stat_loop(base_url: str, remote: str) -> float:
    f = client.File()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"handle-stat open failed for {base_url}: {status.message}"

        start = time.perf_counter()
        for _ in range(HANDLE_STAT_ITERS):
            status, info = f.stat()
            assert status.ok, f"handle stat failed for {base_url}: {status.message}"
            assert info.size == PAYLOAD_SIZE
        return time.perf_counter() - start
    finally:
        f.close()


def _time_multifile_stat_sweep_loop(base_url: str, paths: list[str]) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(META_RUNS):
        for remote in paths:
            status, info = fs.stat(remote)
            assert status.ok, f"multifile stat failed for {base_url}: {status.message}"
            assert info.size > 0
    return time.perf_counter() - start


def _time_sync_write_loop(base_url: str, label: str) -> float:
    token = f"{label}_{os.getpid()}_{time.monotonic_ns()}"
    start = time.perf_counter()
    for idx in range(SYNC_ITERS):
        remote = _remote(f"{PREFIX}{token}_sync_{idx}.dat")
        f = client.File()
        try:
            status, _ = f.open(
                _url(base_url, remote),
                OpenFlags.DELETE | OpenFlags.NEW | OpenFlags.UPDATE,
                timeout=30,
            )
            assert status.ok, f"sync open failed for {base_url}: {status.message}"
            payload = f"sync-payload-{idx}\n".encode("ascii") * 64
            status, _ = f.write(payload, offset=0)
            assert status.ok, f"sync write failed for {base_url}: {status.message}"
            status, _ = f.sync()
            assert status.ok, f"sync failed for {base_url}: {status.message}"
        finally:
            f.close()
    return time.perf_counter() - start


def _time_chmod_loop(base_url: str, label: str) -> float:
    fs = client.FileSystem(base_url)
    token = f"{label}_{os.getpid()}_{time.monotonic_ns()}"
    start = time.perf_counter()
    for idx in range(CHMOD_ITERS):
        remote = _remote(f"{PREFIX}{token}_chmod_{idx}.dat")
        f = client.File()
        try:
            status, _ = f.open(
                _url(base_url, remote),
                OpenFlags.DELETE | OpenFlags.NEW | OpenFlags.UPDATE,
                timeout=30,
            )
            assert status.ok, f"chmod open failed for {base_url}: {status.message}"
            status, _ = f.write(b"chmod payload\n", offset=0)
            assert status.ok, f"chmod write failed for {base_url}: {status.message}"
        finally:
            f.close()

        status, _ = fs.chmod(
            remote,
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        assert status.ok, f"chmod readonly failed for {base_url}: {status.message}"
        status, _ = fs.chmod(
            remote,
            AccessMode.UR | AccessMode.UW | AccessMode.GR | AccessMode.OR,
        )
        assert status.ok, f"chmod writable failed for {base_url}: {status.message}"
        status, _ = fs.rm(remote)
        assert status.ok, f"chmod cleanup rm failed for {base_url}: {status.message}"
    return time.perf_counter() - start


def _time_mkdir_makepath_loop(base_url: str, label: str) -> float:
    fs = client.FileSystem(base_url)
    token = f"{label}_{os.getpid()}_{time.monotonic_ns()}"
    start = time.perf_counter()
    for idx in range(MAKEPATH_ITERS):
        root = _remote(f"{PREFIX}{token}_mkpath_{idx}")
        leaf = f"{root}/a/b/c"

        status, _ = fs.mkdir(leaf, MkDirFlags.MAKEPATH)
        assert status.ok, f"mkdir -p failed for {base_url}: {status.message}"
        status, info = fs.stat(leaf)
        assert status.ok, f"mkdir -p stat failed for {base_url}: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR, (
            "mkdir -p leaf is not reported as a directory"
        )

        for path in (leaf, f"{root}/a/b", f"{root}/a", root):
            status, _ = fs.rmdir(path)
            assert status.ok, (
                f"mkdir -p cleanup rmdir({path}) failed for {base_url}: "
                f"{status.message}"
            )
    return time.perf_counter() - start


def _time_handle_truncate_loop(base_url: str, label: str) -> float:
    fs = client.FileSystem(base_url)
    token = f"{label}_{os.getpid()}_{time.monotonic_ns()}"
    start = time.perf_counter()
    for idx in range(TRUNCATE_ITERS):
        remote = _remote(f"{PREFIX}{token}_truncate_{idx}.dat")
        f = client.File()
        try:
            status, _ = f.open(
                _url(base_url, remote),
                OpenFlags.DELETE | OpenFlags.NEW | OpenFlags.UPDATE,
                timeout=30,
            )
            assert status.ok, f"truncate open failed for {base_url}: {status.message}"
            status, _ = f.write(b"truncate payload\n", offset=0)
            assert status.ok, f"truncate write failed for {base_url}: {status.message}"
            status, _ = f.truncate(4096)
            assert status.ok, f"truncate extend failed for {base_url}: {status.message}"
            status, _ = f.truncate(8)
            assert status.ok, f"truncate shrink failed for {base_url}: {status.message}"
        finally:
            f.close()
        status, info = fs.stat(remote)
        assert status.ok and info.size == 8
        status, _ = fs.rm(remote)
        assert status.ok, f"truncate cleanup rm failed for {base_url}: {status.message}"
    return time.perf_counter() - start


def _time_fs_mutation_loop(base_url: str, label: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for idx in range(FS_MUTATION_ITERS):
        dirname = _remote(f"{PREFIX}{label}_ns_{os.getpid()}_{idx}")
        src = _remote(f"{dirname}/src.dat")
        dst = _remote(f"{dirname}/dst.dat")

        status, _ = fs.mkdir(dirname, MkDirFlags.NONE)
        assert status.ok, f"mkdir failed for {base_url}: {status.message}"

        f = client.File()
        try:
            status, _ = f.open(
                _url(base_url, src),
                OpenFlags.NEW | OpenFlags.UPDATE,
                timeout=30,
            )
            assert status.ok, f"namespace open failed for {base_url}: {status.message}"
            status, _ = f.write(b"namespace mutation payload\n", offset=0)
            assert status.ok, f"namespace write failed for {base_url}: {status.message}"
        finally:
            f.close()

        status, _ = fs.mv(src, dst)
        assert status.ok, f"mv failed for {base_url}: {status.message}"
        status, _ = fs.truncate(dst, 8)
        assert status.ok, f"truncate failed for {base_url}: {status.message}"
        status, info = fs.stat(dst)
        assert status.ok and info.size == 8
        status, _ = fs.rm(dst)
        assert status.ok, f"rm failed for {base_url}: {status.message}"
        status, _ = fs.rmdir(dirname)
        assert status.ok, f"rmdir failed for {base_url}: {status.message}"

    return time.perf_counter() - start


def _time_mixed_loop(
    *,
    base_url: str,
    payload_remote: str,
    payload_md5: str,
    meta_dir: str,
    expected_names: set[str],
    small_remote: str,
    small_content: bytes,
) -> float:
    fs = client.FileSystem(base_url)
    missing = _remote(f"{PREFIX}mixed_missing_{os.getpid()}.dat")
    digest = hashlib.md5()
    start = time.perf_counter()

    for idx in range(MIXED_ITERS):
        status, _ = fs.stat(small_remote)
        assert status.ok, f"mixed stat small failed for {base_url}: {status.message}"

        status, listing = fs.dirlist(meta_dir, DirListFlags.STAT)
        assert status.ok, f"mixed dirlist failed for {base_url}: {status.message}"
        assert expected_names <= {entry.name for entry in listing}

        status, _ = fs.stat(missing)
        assert not status.ok, f"mixed missing stat unexpectedly succeeded: {base_url}"

        f = client.File()
        try:
            status, _ = f.open(_url(base_url, small_remote), OpenFlags.READ, timeout=30)
            assert status.ok, f"mixed open small failed for {base_url}: {status.message}"
            status, data = f.read(offset=0, size=len(small_content))
            assert status.ok, f"mixed read small failed for {base_url}: {status.message}"
            assert data == small_content
        finally:
            f.close()

        pf = client.File()
        try:
            status, _ = pf.open(_url(base_url, payload_remote), OpenFlags.READ, timeout=30)
            assert status.ok, f"mixed open payload failed for {base_url}: {status.message}"
            max_offset = max(PAYLOAD_SIZE - 128 * 1024, 0)
            offset = ((idx * 256 * 1024) % max_offset) if max_offset else 0
            status, data = pf.read(offset=offset, size=128 * 1024)
            assert status.ok, f"mixed read payload failed for {base_url}: {status.message}"
            digest.update(data)
        finally:
            pf.close()

    elapsed = time.perf_counter() - start
    assert _remote_md5(base_url, payload_remote, PAYLOAD_SIZE) == payload_md5
    assert digest.digest()
    return elapsed


def _time_status_loop(base_url: str, path: str, iterations: int) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(iterations):
        status, _ = fs.stat(path)
        assert not status.ok, f"stat({path}) unexpectedly succeeded"
    return time.perf_counter() - start


def _time_api_ping_loop(base_url: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(META_ITERS):
        status, _ = fs.ping()
        assert status.ok, f"FileSystem.ping failed for {base_url}: {status.message}"
    return time.perf_counter() - start


def _time_locate_loop(base_url: str, path: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(LOCATE_ITERS):
        status, locations = fs.locate(path, OpenFlags.NONE)
        assert status.ok, f"locate failed for {base_url}: {status.message}"
        locs = list(locations)
        assert locs, "locate returned no locations"
    return time.perf_counter() - start


def _time_missing_locate_loop(base_url: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for idx in range(LOCATE_ITERS):
        missing = _remote(f"{PREFIX}missing_locate_{os.getpid()}_{idx}.dat")
        status, _ = fs.locate(missing, OpenFlags.NONE)
        assert not status.ok, f"missing locate unexpectedly succeeded: {base_url}"
    return time.perf_counter() - start


def _time_missing_rm_loop(base_url: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for idx in range(META_ITERS):
        missing = _remote(f"{PREFIX}missing_rm_{os.getpid()}_{idx}.dat")
        status, _ = fs.rm(missing)
        assert not status.ok, f"missing rm unexpectedly succeeded: {base_url}"
    return time.perf_counter() - start


def _time_nonempty_rmdir_loop(base_url: str, label: str) -> float:
    fs = client.FileSystem(base_url)
    token = f"{label}_{os.getpid()}_{time.monotonic_ns()}"
    dirname = _remote(f"{PREFIX}{token}_nonempty_rmdir")
    child = f"{dirname}/child.dat"

    status, _ = fs.mkdir(dirname, MkDirFlags.NONE)
    assert status.ok, f"nonempty rmdir setup mkdir failed: {status.message}"
    f = client.File()
    try:
        status, _ = f.open(
            _url(base_url, child),
            OpenFlags.DELETE | OpenFlags.NEW | OpenFlags.UPDATE,
            timeout=30,
        )
        assert status.ok, f"nonempty rmdir setup open failed: {status.message}"
        status, _ = f.write(b"still here\n", offset=0)
        assert status.ok, f"nonempty rmdir setup write failed: {status.message}"
    finally:
        f.close()

    start = time.perf_counter()
    for _ in range(META_ITERS):
        status, _ = fs.rmdir(dirname)
        assert not status.ok, f"nonempty rmdir unexpectedly succeeded: {base_url}"
    elapsed = time.perf_counter() - start

    status, _ = fs.rm(child)
    assert status.ok, f"nonempty rmdir cleanup rm failed: {status.message}"
    status, _ = fs.rmdir(dirname)
    assert status.ok, f"nonempty rmdir cleanup rmdir failed: {status.message}"
    return elapsed


def _time_query_space_loop(base_url: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(META_ITERS):
        status, resp = fs.query(QueryCode.SPACE, "/")
        assert status.ok, f"space query failed for {base_url}: {status.message}"
        assert b"oss.space=" in resp
    return time.perf_counter() - start


def _time_query_config_loop(base_url: str) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(META_ITERS):
        status, resp = fs.query(QueryCode.CONFIG, "readv")
        assert status.ok, f"CONFIG query failed for {base_url}: {status.message}"
        assert resp is not None
    return time.perf_counter() - start


def _time_plain_dirlist_loop(base_url: str, path: str, expected_names: set[str]) -> float:
    fs = client.FileSystem(base_url)
    start = time.perf_counter()
    for _ in range(META_ITERS):
        status, listing = fs.dirlist(path)
        assert status.ok, f"plain dirlist({path}) failed: {status.message}"
        assert expected_names <= {entry.name for entry in listing}
    return time.perf_counter() - start


def _time_raw_ping_loop(base_url: str) -> float:
    with _raw_session(base_url) as sock:
        start = time.perf_counter()
        for idx in range(RAW_ITERS):
            _raw_ping(sock, struct.pack("!H", (idx + 2) & 0xFFFF))
        return time.perf_counter() - start
