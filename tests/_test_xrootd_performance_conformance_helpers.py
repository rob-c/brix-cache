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


def _remote(name: str) -> str:
    return f"/{name.lstrip('/')}"


def _url(base_url: str, remote: str) -> str:
    return f"{base_url}//{remote.lstrip('/')}"


def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed early")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session(base_url: str) -> socket.socket:
    host, port = root_endpoint_parts(base_url)
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_OK
    assert len(body) == 8

    username = b"perf\x00\x00\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        b"\x00\x01", kXR_LOGIN,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, _ = _read_response(sock)
    assert status == kXR_OK
    return sock


def _raw_ping(sock: socket.socket, streamid: bytes) -> None:
    req = struct.pack("!2sH16sI", streamid, kXR_PING, b"\x00" * 16, 0)
    sock.sendall(req)
    status, _ = _read_response(sock)
    assert status == kXR_OK


def _raw_open(sock: socket.socket, path: bytes, streamid: bytes) -> bytes:
    req = struct.pack(
        "!2sHHH2s6s4sI",
        streamid, kXR_OPEN,
        0o644, kXR_OPEN_READ,
        b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
        len(path),
    )
    sock.sendall(req + path)
    status, body = _read_response(sock)
    assert status == kXR_OK
    assert len(body) >= 4
    return body[:4]


def _raw_read(
    sock: socket.socket,
    fhandle: bytes,
    offset: int,
    length: int,
    streamid: bytes,
) -> bytes:
    req = struct.pack("!2sH4sqiI", streamid, kXR_READ, fhandle, offset, length, 0)
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK
    assert len(body) == length
    return body


def _raw_close(sock: socket.socket, fhandle: bytes, streamid: bytes) -> None:
    req = struct.pack("!2sH4s12sI", streamid, kXR_CLOSE, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    status, _ = _read_response(sock)
    assert status == kXR_OK


def _raw_stat(sock: socket.socket, path: bytes, streamid: bytes) -> bytes:
    req = struct.pack(
        "!2sH1s7sI4sI",
        streamid, kXR_STAT,
        b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
        len(path),
    )
    sock.sendall(req + path)
    status, body = _read_response(sock)
    assert status == kXR_OK
    return body


def _write_deterministic(path: Path, size: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.md5()
    with path.open("wb") as fh:
        for chunk in _deterministic_chunks(size):
            fh.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def _file_md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _deterministic_chunks(size: int, chunk_size: int = 1024 * 1024):
    remaining = size
    seed = SEED_BYTES[:chunk_size]
    while remaining:
        chunk = seed[: min(len(seed), remaining)]
        yield chunk
        remaining -= len(chunk)


def _expected_deterministic_slice(offset: int, length: int) -> bytes:
    out = bytearray()
    pos = offset % len(SEED_BYTES)
    remaining = length
    while remaining:
        take = min(remaining, len(SEED_BYTES) - pos)
        out.extend(SEED_BYTES[pos:pos + take])
        remaining -= take
        pos = 0
    return bytes(out)


def _best(values: list[float]) -> float:
    return min(values)


def _assert_within_reference(
    *,
    label: str,
    nginx_seconds: float,
    ref_seconds: float,
    ratio_limit: float,
    grace_seconds: float,
) -> None:
    allowed = ref_seconds * ratio_limit + grace_seconds
    ratio = nginx_seconds / ref_seconds if ref_seconds > 0 else float("inf")
    assert nginx_seconds <= allowed, (
        f"{label}: nginx is {ratio:.2f}x reference "
        f"(nginx={nginx_seconds:.4f}s, ref={ref_seconds:.4f}s, "
        f"limit={ratio_limit:.2f}x + {grace_seconds:.3f}s)"
    )


def _read_chunked(base_url: str, remote: str, expected_md5: str) -> float:
    f = client.File()
    start = time.perf_counter()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"open failed for {base_url}: {status.message}"

        status, info = f.stat()
        assert status.ok, f"stat failed for {base_url}: {status.message}"

        digest = hashlib.md5()
        offset = 0
        while offset < info.size:
            want = min(READ_CHUNK, info.size - offset)
            status, data = f.read(offset=offset, size=want)
            assert status.ok, (
                f"read failed for {base_url} at {offset}: {status.message}"
            )
            assert len(data) == want, (
                f"short read for {base_url} at {offset}: got {len(data)}, "
                f"expected {want}"
            )
            digest.update(data)
            offset += len(data)
    finally:
        f.close()

    elapsed = time.perf_counter() - start
    assert offset == PAYLOAD_SIZE
    assert digest.hexdigest() == expected_md5
    return elapsed


def _write_chunked(base_url: str, remote: str, size: int) -> tuple[float, str]:
    f = client.File()
    digest = hashlib.md5()
    offset = 0
    start = time.perf_counter()
    try:
        status, _ = f.open(
            _url(base_url, remote),
            OpenFlags.DELETE | OpenFlags.NEW | OpenFlags.UPDATE,
            timeout=30,
        )
        assert status.ok, f"open for write failed for {base_url}: {status.message}"

        for chunk in _deterministic_chunks(size):
            status, _ = f.write(chunk, offset=offset)
            assert status.ok, (
                f"write failed for {base_url} at {offset}: {status.message}"
            )
            digest.update(chunk)
            offset += len(chunk)
    finally:
        f.close()

    elapsed = time.perf_counter() - start
    assert offset == size
    return elapsed, digest.hexdigest()


def _remote_md5(base_url: str, remote: str, expected_size: int) -> str:
    f = client.File()
    digest = hashlib.md5()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"open for md5 failed for {base_url}: {status.message}"
        offset = 0
        while offset < expected_size:
            want = min(READ_CHUNK, expected_size - offset)
            status, data = f.read(offset=offset, size=want)
            assert status.ok, (
                f"read for md5 failed for {base_url} at {offset}: {status.message}"
            )
            digest.update(data)
            offset += len(data)
    finally:
        f.close()
    return digest.hexdigest()


def _copy_process(base_url: str, remote: str, dest: Path, expected_md5: str) -> float:
    cp = client.CopyProcess()
    cp.add_job(_url(base_url, remote), str(dest), force=True)
    cp.prepare()

    start = time.perf_counter()
    status, results = cp.run()
    elapsed = time.perf_counter() - start

    assert status.ok, f"CopyProcess failed for {base_url}: {status.message}"
    assert results[0]["status"].ok, (
        f"CopyProcess job failed for {base_url}: {results[0]['status'].message}"
    )
    assert _file_md5(dest) == expected_md5
    return elapsed


def _copy_process_upload(
    base_url: str,
    source: Path,
    remote: str,
    expected_md5: str,
) -> float:
    cp = client.CopyProcess()
    cp.add_job(str(source), _url(base_url, remote), force=True)
    cp.prepare()

    start = time.perf_counter()
    status, results = cp.run()
    elapsed = time.perf_counter() - start

    assert status.ok, f"CopyProcess upload failed for {base_url}: {status.message}"
    assert results[0]["status"].ok, (
        f"CopyProcess upload job failed for {base_url}: "
        f"{results[0]['status'].message}"
    )
    assert _remote_md5(base_url, remote, source.stat().st_size) == expected_md5
    return elapsed


def _time_small_open_read_close_loop(
    base_url: str,
    remote: str,
    expected: bytes,
) -> float:
    start = time.perf_counter()
    for _ in range(SMALL_ITERS):
        f = client.File()
        try:
            status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
            assert status.ok, f"small open failed for {base_url}: {status.message}"
            status, data = f.read(offset=0, size=len(expected))
            assert status.ok, f"small read failed for {base_url}: {status.message}"
            assert data == expected
        finally:
            f.close()
    return time.perf_counter() - start


def _time_missing_open_loop(base_url: str) -> float:
    start = time.perf_counter()
    for idx in range(META_ITERS):
        remote = _remote(f"{PREFIX}missing_open_{os.getpid()}_{idx}.dat")
        f = client.File()
        try:
            status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
            assert not status.ok, f"missing open unexpectedly succeeded: {base_url}"
        finally:
            f.close()
    return time.perf_counter() - start


def _time_empty_file_loop(base_url: str, remote: str) -> float:
    start = time.perf_counter()
    for _ in range(META_ITERS):
        f = client.File()
        try:
            status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
            assert status.ok, f"empty open failed for {base_url}: {status.message}"
            status, info = f.stat()
            assert status.ok, f"empty stat failed for {base_url}: {status.message}"
            assert info.size == 0
            status, data = f.read(offset=0, size=4096)
            assert status.ok, f"empty read failed for {base_url}: {status.message}"
            assert data == b""
        finally:
            f.close()
    return time.perf_counter() - start


def _time_eof_short_read_loop(base_url: str, remote: str) -> float:
    f = client.File()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"EOF open failed for {base_url}: {status.message}"

        start = time.perf_counter()
        for _ in range(META_ITERS):
            status, data = f.read(offset=PAYLOAD_SIZE - 128, size=4096)
            assert status.ok, f"EOF short read failed for {base_url}: {status.message}"
            assert len(data) == 128
            assert data == _expected_deterministic_slice(PAYLOAD_SIZE - 128, 128)
        return time.perf_counter() - start
    finally:
        f.close()


def _time_exact_eof_read_loop(base_url: str, remote: str) -> float:
    f = client.File()
    try:
        status, _ = f.open(_url(base_url, remote), OpenFlags.READ, timeout=30)
        assert status.ok, f"exact EOF open failed for {base_url}: {status.message}"

        start = time.perf_counter()
        for _ in range(META_ITERS):
            status, data = f.read(offset=PAYLOAD_SIZE, size=4096)
            assert status.ok, f"exact EOF read failed for {base_url}: {status.message}"
            assert data == b""
        return time.perf_counter() - start
    finally:
        f.close()

# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrootd_performance_conformance_helpers_b")
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrootd_performance_conformance_helpers_c")
