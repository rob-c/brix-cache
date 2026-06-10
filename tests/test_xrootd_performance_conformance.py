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


def test_bulk_read_throughput_tracks_reference(perf_env):
    """Success path: nginx bulk-read throughput stays in the reference envelope."""
    # Warm the shared page cache and client paths before timing.
    _read_chunked(perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"])
    _read_chunked(perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"])

    nginx_times = []
    ref_times = []
    for run in range(READ_RUNS):
        if run % 2:
            ref_times.append(
                _read_chunked(
                    perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )
            nginx_times.append(
                _read_chunked(
                    perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )
        else:
            nginx_times.append(
                _read_chunked(
                    perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )
            ref_times.append(
                _read_chunked(
                    perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"]
                )
            )

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  bulk-read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={PAYLOAD_MIB}MiB"
    )
    _assert_within_reference(
        label="bulk read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=READ_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_copyprocess_download_throughput_tracks_reference(perf_env, tmp_path):
    """Client copy path: CopyProcess download throughput stays near reference."""
    # Warm file data and the XRootD client machinery before timing CopyProcess.
    _read_chunked(perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"])
    _read_chunked(perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"])

    nginx_times = []
    ref_times = []
    for run in range(READ_RUNS):
        nginx_dest = tmp_path / f"nginx-copy-{run}.bin"
        ref_dest = tmp_path / f"ref-copy-{run}.bin"
        if run % 2:
            ref_times.append(
                _copy_process(
                    perf_env["ref_url"], perf_env["payload"], ref_dest,
                    perf_env["payload_md5"],
                )
            )
            nginx_times.append(
                _copy_process(
                    perf_env["nginx_url"], perf_env["payload"], nginx_dest,
                    perf_env["payload_md5"],
                )
            )
        else:
            nginx_times.append(
                _copy_process(
                    perf_env["nginx_url"], perf_env["payload"], nginx_dest,
                    perf_env["payload_md5"],
                )
            )
            ref_times.append(
                _copy_process(
                    perf_env["ref_url"], perf_env["payload"], ref_dest,
                    perf_env["payload_md5"],
                )
            )

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  CopyProcess download best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={PAYLOAD_MIB}MiB"
    )
    _assert_within_reference(
        label="CopyProcess download",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=COPY_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_copyprocess_upload_throughput_tracks_reference(perf_env, tmp_path):
    """Client copy upload path stays near the official XRootD reference."""
    local = tmp_path / "copyprocess-upload.bin"
    expected_md5 = _write_deterministic(local, WRITE_SIZE)

    nginx_times = []
    ref_times = []
    for run in range(READ_RUNS):
        nginx_remote = _remote(f"{PREFIX}nginx_cp_upload_{os.getpid()}_{run}.bin")
        ref_remote = _remote(f"{PREFIX}ref_cp_upload_{os.getpid()}_{run}.bin")
        if run % 2:
            ref_times.append(
                _copy_process_upload(
                    perf_env["ref_url"], local, ref_remote, expected_md5
                )
            )
            nginx_times.append(
                _copy_process_upload(
                    perf_env["nginx_url"], local, nginx_remote, expected_md5
                )
            )
        else:
            nginx_times.append(
                _copy_process_upload(
                    perf_env["nginx_url"], local, nginx_remote, expected_md5
                )
            )
            ref_times.append(
                _copy_process_upload(
                    perf_env["ref_url"], local, ref_remote, expected_md5
                )
            )

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  CopyProcess upload best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={WRITE_MIB}MiB"
    )
    _assert_within_reference(
        label="CopyProcess upload",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=COPY_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_dirlist_stat_latency_tracks_reference(perf_env):
    """Metadata success path: STAT dirlist latency stays near reference."""
    nginx_times = [
        _time_dirlist_loop(
            perf_env["nginx_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_dirlist_loop(
            perf_env["ref_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  dirlist+stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="dirlist+stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_multifile_stat_sweep_latency_tracks_reference(perf_env):
    """Repeated stat sweep over many files stays near reference."""
    nginx_times = [
        _time_multifile_stat_sweep_loop(
            perf_env["nginx_url"], perf_env["stat_sweep_paths"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_multifile_stat_sweep_loop(
            perf_env["ref_url"], perf_env["stat_sweep_paths"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  multifile stat sweep best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"files={len(perf_env['stat_sweep_paths'])}"
    )
    _assert_within_reference(
        label="multifile stat sweep",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_concurrent_metadata_latency_tracks_reference(perf_env):
    """Concurrent stat+dirlist metadata fanout stays near reference."""
    if CONCURRENT_WORKERS < 2:
        pytest.skip("concurrent metadata conformance needs at least two workers")

    nginx_seconds = _time_concurrent_metadata(
        perf_env["nginx_url"],
        perf_env["meta_dir"],
        perf_env["stat_sweep_paths"],
        perf_env["meta_names"],
    )
    ref_seconds = _time_concurrent_metadata(
        perf_env["ref_url"],
        perf_env["meta_dir"],
        perf_env["stat_sweep_paths"],
        perf_env["meta_names"],
    )
    print(
        "\n  concurrent metadata: "
        f"nginx={nginx_seconds:.4f}s ref={ref_seconds:.4f}s "
        f"workers={CONCURRENT_WORKERS} iters={META_ITERS}"
    )
    _assert_within_reference(
        label="concurrent metadata",
        nginx_seconds=nginx_seconds,
        ref_seconds=ref_seconds,
        ratio_limit=CONCURRENT_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_plain_dirlist_latency_tracks_reference(perf_env):
    """Plain dirlist without stat payloads stays near reference."""
    nginx_times = [
        _time_plain_dirlist_loop(
            perf_env["nginx_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_plain_dirlist_loop(
            perf_env["ref_url"], perf_env["meta_dir"], perf_env["meta_names"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  plain dirlist best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="plain dirlist",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_api_ping_latency_tracks_reference(perf_env):
    """PyXRootD FileSystem.ping latency follows the official reference."""
    nginx_times = [
        _time_api_ping_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_api_ping_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  API ping best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="API ping",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_locate_latency_tracks_reference(perf_env):
    """kXR_locate success-path latency follows the official reference."""
    nginx_times = [
        _time_locate_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_locate_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  locate best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={LOCATE_ITERS}"
    )
    _assert_within_reference(
        label="locate",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_query_space_latency_tracks_reference(perf_env):
    """kXR_query SPACE latency follows the official XRootD reference."""
    nginx_times = [
        _time_query_space_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_query_space_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  query SPACE best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="query SPACE",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_query_config_latency_tracks_reference(perf_env):
    """kXR_query CONFIG latency follows the official XRootD reference."""
    nginx_times = [
        _time_query_config_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_query_config_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  query CONFIG best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="query CONFIG",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_ping_latency_tracks_reference(perf_env):
    """Persistent-session raw ping latency follows reference XRootD."""
    nginx_times = [
        _time_raw_ping_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_ping_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw ping best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RAW_ITERS}"
    )
    _assert_within_reference(
        label="raw ping",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_stat_latency_tracks_reference(perf_env):
    """Raw kXR_stat loop stays near reference without PyXRootD per-call overhead."""
    nginx_times = [
        _time_raw_stat_loop(perf_env["nginx_url"], perf_env["small"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_stat_loop(perf_env["ref_url"], perf_env["small"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RAW_ITERS}"
    )
    _assert_within_reference(
        label="raw stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_read_latency_tracks_reference(perf_env):
    """Raw kXR_open/read/close loop stays near reference on deterministic data."""
    if PAYLOAD_SIZE <= RAW_READ_SIZE:
        pytest.skip("raw read conformance needs payload larger than read size")

    nginx_times = [
        _time_raw_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RAW_ITERS}"
    )
    _assert_within_reference(
        label="raw read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_raw_session_login_ping_latency_tracks_reference(perf_env):
    """Connection setup + handshake/login/ping latency follows reference XRootD."""
    nginx_times = [
        _time_raw_session_ping_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_raw_session_ping_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  raw session+ping best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={SESSION_ITERS}"
    )
    _assert_within_reference(
        label="raw session login ping",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_mixed_workload_latency_tracks_reference(perf_env):
    """Mixed success/error workload stays in the official reference envelope."""
    nginx_times = [
        _time_mixed_loop(
            base_url=perf_env["nginx_url"],
            payload_remote=perf_env["payload"],
            payload_md5=perf_env["payload_md5"],
            meta_dir=perf_env["meta_dir"],
            expected_names=perf_env["meta_names"],
            small_remote=perf_env["small"],
            small_content=perf_env["small_content"],
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_mixed_loop(
            base_url=perf_env["ref_url"],
            payload_remote=perf_env["payload"],
            payload_md5=perf_env["payload_md5"],
            meta_dir=perf_env["meta_dir"],
            expected_names=perf_env["meta_names"],
            small_remote=perf_env["small"],
            small_content=perf_env["small_content"],
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  mixed workload best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={MIXED_ITERS}"
    )
    _assert_within_reference(
        label="mixed workload",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_eof_short_read_latency_tracks_reference(perf_env):
    """Read spanning EOF returns the same short-read behavior and latency envelope."""
    nginx_times = [
        _time_eof_short_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_eof_short_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  EOF short-read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="EOF short read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_exact_eof_read_latency_tracks_reference(perf_env):
    """Read starting exactly at EOF returns zero bytes within the reference envelope."""
    nginx_times = [
        _time_exact_eof_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_exact_eof_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  exact EOF read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="exact EOF read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_empty_file_open_stat_read_latency_tracks_reference(perf_env):
    """Zero-length file open/stat/read latency stays near reference."""
    nginx_times = [
        _time_empty_file_loop(perf_env["nginx_url"], perf_env["empty"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_empty_file_loop(perf_env["ref_url"], perf_env["empty"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  empty file open/stat/read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="empty file open/stat/read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_random_small_read_latency_tracks_reference(perf_env):
    """Random 4 KiB reads from one open handle stay near reference."""
    nginx_times = [
        _time_random_read_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_random_read_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  random small-read best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={RANDOM_READ_ITERS}"
    )
    _assert_within_reference(
        label="random small read",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_handle_stat_latency_tracks_reference(perf_env):
    """Handle-based File.stat() latency stays near the official reference."""
    nginx_times = [
        _time_handle_stat_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_handle_stat_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  handle stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={HANDLE_STAT_ITERS}"
    )
    _assert_within_reference(
        label="handle stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_sync_write_latency_tracks_reference(perf_env):
    """Write+sync latency stays in the reference envelope."""
    nginx_times = [
        _time_sync_write_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_sync_write_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  sync write best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={SYNC_ITERS}"
    )
    _assert_within_reference(
        label="sync write",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=WRITE_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_chmod_latency_tracks_reference(perf_env):
    """chmod metadata mutation latency stays near the official reference."""
    nginx_times = [
        _time_chmod_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_chmod_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  chmod best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={CHMOD_ITERS}"
    )
    _assert_within_reference(
        label="chmod",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_mkdir_makepath_latency_tracks_reference(perf_env):
    """Recursive mkdir creation/removal stays near the official reference."""
    nginx_times = [
        _time_mkdir_makepath_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_mkdir_makepath_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  mkdir -p best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={MAKEPATH_ITERS}"
    )
    _assert_within_reference(
        label="mkdir -p",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_handle_truncate_latency_tracks_reference(perf_env):
    """Handle-based truncate extend/shrink latency stays near reference."""
    nginx_times = [
        _time_handle_truncate_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_handle_truncate_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  handle truncate best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={TRUNCATE_ITERS}"
    )
    _assert_within_reference(
        label="handle truncate",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=WRITE_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_namespace_mutation_latency_tracks_reference(perf_env):
    """mkdir/create/mv/truncate/rm/rmdir loop stays near reference."""
    nginx_times = [
        _time_fs_mutation_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_fs_mutation_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  namespace mutation best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={FS_MUTATION_ITERS}"
    )
    _assert_within_reference(
        label="namespace mutation",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_small_open_read_close_latency_tracks_reference(perf_env):
    """Small-object success path: repeated open/read/close stays near reference."""
    nginx_times = [
        _time_small_open_read_close_loop(
            perf_env["nginx_url"], perf_env["small"], perf_env["small_content"]
        )
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_small_open_read_close_loop(
            perf_env["ref_url"], perf_env["small"], perf_env["small_content"]
        )
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  small open/read/close best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={SMALL_ITERS}"
    )
    _assert_within_reference(
        label="small open/read/close",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_readv_latency_tracks_reference(perf_env):
    """Vector-read success path: scatter/gather reads stay in reference envelope."""
    if PAYLOAD_SIZE < 7 * 1024 * 1024:
        pytest.skip("readv performance check needs at least a 7 MiB payload")

    nginx_times = [
        _time_readv_loop(perf_env["nginx_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_readv_loop(perf_env["ref_url"], perf_env["payload"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  readv best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={READV_ITERS}"
    )
    _assert_within_reference(
        label="readv",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=READ_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_write_throughput_tracks_reference(perf_env):
    """Write success path: client-visible write time stays near reference."""
    nginx_times = []
    ref_times = []
    expected_md5 = None
    for run in range(READ_RUNS):
        nginx_remote = _remote(f"{PREFIX}nginx_write_{os.getpid()}_{run}.bin")
        ref_remote = _remote(f"{PREFIX}ref_write_{os.getpid()}_{run}.bin")
        if run % 2:
            ref_elapsed, ref_md5 = _write_chunked(
                perf_env["ref_url"], ref_remote, WRITE_SIZE
            )
            nginx_elapsed, nginx_md5 = _write_chunked(
                perf_env["nginx_url"], nginx_remote, WRITE_SIZE
            )
        else:
            nginx_elapsed, nginx_md5 = _write_chunked(
                perf_env["nginx_url"], nginx_remote, WRITE_SIZE
            )
            ref_elapsed, ref_md5 = _write_chunked(
                perf_env["ref_url"], ref_remote, WRITE_SIZE
            )
        assert nginx_md5 == ref_md5
        expected_md5 = nginx_md5
        nginx_times.append(nginx_elapsed)
        ref_times.append(ref_elapsed)

        assert (
            _remote_md5(perf_env["nginx_url"], nginx_remote, WRITE_SIZE)
            == expected_md5
        )
        assert _remote_md5(perf_env["ref_url"], ref_remote, WRITE_SIZE) == expected_md5

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  write best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"size={WRITE_MIB}MiB"
    )
    _assert_within_reference(
        label="write",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=WRITE_RATIO_LIMIT,
        grace_seconds=WRITE_GRACE_SECONDS,
    )


def test_concurrent_bulk_read_throughput_tracks_reference(perf_env):
    """Concurrent success path: aggregate read behavior stays near reference."""
    if CONCURRENT_WORKERS < 2:
        pytest.skip("concurrent read conformance needs at least two workers")

    # Warm both backends before timing thread-pool fanout.
    _read_chunked(perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"])
    _read_chunked(perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"])

    nginx_seconds = _time_concurrent_reads(
        perf_env["nginx_url"], perf_env["payload"], perf_env["payload_md5"]
    )
    ref_seconds = _time_concurrent_reads(
        perf_env["ref_url"], perf_env["payload"], perf_env["payload_md5"]
    )
    print(
        "\n  concurrent bulk-read: "
        f"nginx={nginx_seconds:.4f}s ref={ref_seconds:.4f}s "
        f"workers={CONCURRENT_WORKERS} size={PAYLOAD_MIB}MiB"
    )
    _assert_within_reference(
        label="concurrent bulk read",
        nginx_seconds=nginx_seconds,
        ref_seconds=ref_seconds,
        ratio_limit=CONCURRENT_RATIO_LIMIT,
        grace_seconds=READ_GRACE_SECONDS,
    )


def test_missing_file_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file stats fail within the reference envelope."""
    missing = _remote(f"{PREFIX}missing_{os.getpid()}.dat")
    nginx_times = [
        _time_status_loop(perf_env["nginx_url"], missing, META_ITERS)
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_status_loop(perf_env["ref_url"], missing, META_ITERS)
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-stat best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="missing-file stat",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_missing_open_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file opens fail within the reference envelope."""
    nginx_times = [
        _time_missing_open_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_missing_open_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-open best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="missing-file open",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_missing_locate_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file locates fail within the reference envelope."""
    nginx_times = [
        _time_missing_locate_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_missing_locate_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-locate best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={LOCATE_ITERS}"
    )
    _assert_within_reference(
        label="missing-file locate",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_missing_rm_error_latency_tracks_reference(perf_env):
    """Error path: repeated missing-file rm calls fail within the reference envelope."""
    nginx_times = [
        _time_missing_rm_loop(perf_env["nginx_url"])
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_missing_rm_loop(perf_env["ref_url"])
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  missing-rm best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="missing-file rm",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


def test_nonempty_rmdir_error_latency_tracks_reference(perf_env):
    """Error path: non-empty directory rmdir fails within the reference envelope."""
    nginx_times = [
        _time_nonempty_rmdir_loop(perf_env["nginx_url"], "nginx")
        for _ in range(META_RUNS)
    ]
    ref_times = [
        _time_nonempty_rmdir_loop(perf_env["ref_url"], "ref")
        for _ in range(META_RUNS)
    ]

    best_nginx = _best(nginx_times)
    best_ref = _best(ref_times)
    print(
        "\n  nonempty-rmdir best: "
        f"nginx={best_nginx:.4f}s ref={best_ref:.4f}s "
        f"iters={META_ITERS}"
    )
    _assert_within_reference(
        label="nonempty rmdir",
        nginx_seconds=best_nginx,
        ref_seconds=best_ref,
        ratio_limit=META_RATIO_LIMIT,
        grace_seconds=META_GRACE_SECONDS,
    )


@pytest.mark.parametrize(
    "probe",
    [
        "/../etc/passwd",
        "/../../../../etc/shadow",
        "/%2e%2e/%2e%2e/etc/passwd",
    ],
)
def test_traversal_probe_is_not_a_fast_success_path(perf_env, probe):
    """Security negative: traversal-like probes must not become successful stats."""
    nginx_status, _ = client.FileSystem(perf_env["nginx_url"]).stat(probe)
    ref_status, _ = client.FileSystem(perf_env["ref_url"]).stat(probe)

    assert not nginx_status.ok, (
        f"nginx unexpectedly accepted traversal probe {probe!r}: "
        f"{nginx_status.message}"
    )
    assert not ref_status.ok, (
        "reference xrootd unexpectedly accepted the traversal probe; "
        "the localroot/path-confinement behavior is the reference contract "
        f"for this test fixture: {probe!r}"
    )
