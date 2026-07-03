# _test_brix_performance_conformance_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_brix_performance_conformance.py.  `from _test_brix_performance_conformance_helpers import *` re-exports EVERYTHING via
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
