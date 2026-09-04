"""
tests/test_readv_segment_size.py

Verifies the brix_readv_segment_size directive (the per-kXR_readv-element cap,
the official "maxReadv_ior") end-to-end against the OFFICIAL XRootD client:

  1. the server advertises the configured value via kXR_Qconfig "readv_ior_max"
     (and "readv_iov_max"), so official clients size their VectorReads to it; and
  2. an official VectorRead of an element up to that size returns the full,
     byte-exact data.

A dedicated anonymous nginx is started on a free port with the directive set to
16m, so a single 8 MiB readv element — larger than the stock 2 MiB default —
succeeds in one element. Single server per test so XrdCl's per-process connection
state stays simple (multiple servers in one process can wedge XrdCl).

Run:
    pytest tests/test_readv_segment_size.py -v
"""

import os
from pathlib import Path

import pytest
from XRootD import client
from XRootD.client.flags import QueryCode

from settings import HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-readv-seg16m")]

FILE_BYTES = 36 * 1024 * 1024
SEG_CAP = 16 * 1024 * 1024          # the configured brix_readv_segment_size
MAXSEGS = 1024                       # BRIX_READV_MAXSEGS


@pytest.fixture()
def server16m(lifecycle, tmp_path):
    """A dedicated anon nginx with brix_readv_segment_size 16m + a 20 MiB file."""
    data = tmp_path / "data"
    data.mkdir()
    payload = os.urandom(FILE_BYTES)
    (data / "big.bin").write_bytes(payload)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-readv-seg16m",
        template="nginx_lc_readv.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "READV_SEG": "16m"},
        reason="official VectorRead against a 16m brix_readv_segment_size cap"))
    return {"url": f"root://{HOST}:{ep.port}", "payload": payload,
            "pidfile": ep.pidfile}


def test_qconfig_advertises_configured_segment_size(server16m):
    """kXR_Qconfig readv_ior_max reports the configured cap; readv_iov_max the
    segment-count limit — so official clients size their VectorReads to match."""
    fs = client.FileSystem(server16m["url"])
    st, rsp = fs.query(QueryCode.CONFIG, "readv_ior_max")
    assert st.ok, f"Qconfig readv_ior_max failed: {st.message}"
    assert int(bytes(rsp).split()[0]) == SEG_CAP

    st, rsp = fs.query(QueryCode.CONFIG, "readv_iov_max")
    assert st.ok, f"Qconfig readv_iov_max failed: {st.message}"
    assert int(bytes(rsp).split()[0]) == MAXSEGS


def test_official_vectorread_large_element(server16m):
    """An official VectorRead of a single 8 MiB element (larger than the stock
    2 MiB default) returns the full element, byte-exact, because the cap is 16m."""
    req = 8 * 1024 * 1024
    f = client.File()
    st, _ = f.open(server16m["url"] + "//big.bin", 0)
    assert st.ok, f"open failed: {st.message}"
    try:
        st, vri = f.vector_read([(0, req)])
        assert st.ok, f"vector_read failed: {st.message}"
        got = b"".join(bytes(ch.buffer) for ch in vri.chunks)
        assert len(got) == req, f"expected {req} bytes, got {len(got)}"
        assert got == server16m["payload"][:req], "VectorRead bytes are not byte-exact"
    finally:
        f.close()


def _worker_rss_bytes(pidfile: str) -> int:
    master = int(Path(pidfile).read_text(encoding="ascii").strip())
    children = Path(f"/proc/{master}/task/{master}/children")
    pids = [int(value) for value in children.read_text().split()]
    assert pids, "test nginx has no worker process"
    total = 0
    for pid in pids:
        status = Path(f"/proc/{pid}/status").read_text()
        rss_line = next(line for line in status.splitlines()
                        if line.startswith("VmRSS:"))
        total += int(rss_line.split()[1]) * 1024
    return total


def _open_test_file(url: str):
    handle = client.File()
    status, _ = handle.open(url + "//big.bin", 0)
    assert status.ok, f"open failed: {status.message}"
    return handle


def _vector_bytes(handle, chunks) -> bytes:
    status, result = handle.vector_read(chunks)
    assert status.ok, f"vector_read failed: {status.message}"
    return b"".join(bytes(chunk.buffer) for chunk in result.chunks)


def _expected_bytes(payload: bytes, chunks) -> bytes:
    return b"".join(payload[offset:offset + length]
                    for offset, length in chunks)


def test_large_vectorread_server_residency_is_window_bounded(server16m):
    """A 32 MiB logical response must not create the old 32 MiB server buffer."""
    chunks = [(index * 8 * 1024 * 1024, 8 * 1024 * 1024)
              for index in range(4)]
    f = _open_test_file(server16m["url"])
    before = _worker_rss_bytes(server16m["pidfile"])
    try:
        got = _vector_bytes(f, chunks)
    finally:
        f.close()
    assert got == _expected_bytes(server16m["payload"], chunks)
    growth = max(0, _worker_rss_bytes(server16m["pidfile"]) - before)
    assert growth < 24 * 1024 * 1024, (
        f"worker RSS grew {growth} bytes for a 32 MiB readv; response was likely "
        "assembled instead of streamed through BRIX_READ_WINDOW")
