"""Paged I/O (kXR_pgread / kXR_pgwrite) and kXR_readv against the NON-posix
storage drivers.

Every existing pg-I/O and readv suite (test_conf_pgio*.py, test_readv.py,
test_aio.py) drives a plain posix export, so the two other drivers that carry
their own ``.preadv``/``.preadv2``/``.pwrite`` slots have never seen a paged or
vectored request:

  * ``pblock://`` — a block-mapped object store; a logical file is a chain of
    fixed-size blocks, so a page or a readv segment that crosses a block
    boundary is stitched by the driver, not by the kernel.
  * ``block:<device>`` — a fixed-extent device namespace; every read/write is
    windowed into the extent's byte range before it reaches posix, so the page
    offsets the server reports must be LOGICAL (extent-relative), not device
    offsets.

Both server-side engines route through the driver seam
(``src/protocols/root/read/pgread_encode.c`` calls ``driver->preadv2`` /
``brix_sd_obj_preadv``; ``readv_engine.c`` does the same), which is exactly the
code these servers exercise and the posix suites cannot reach.

INVARIANT 1 is the contract under test: pgread answers in the kXR_status (4007)
family with a per-page CRC32c, and the page split follows the absolute-file-
offset alignment rule regardless of how the driver stores the bytes.

The device for the block plane is a REGULAR FILE (sd_block_init falls back to
st_size when the target is not S_ISBLK), so the whole module runs unprivileged
with no loop device.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags

from _test_conf_pgio_helpers import (
    PG_PAGE,
    WR_NEW,
    _Handle,
    _open,
    _session,
    crc32c,
    kXR_delete,
    kXR_error,
    kXR_ok,
    kXR_open_read,
    kXR_open_updt,
    page_slices,
    pgread,
    pgread_bytes,
    pgwrite,
)
from cmdscripts.pblock_live import pblock_lab_start, pblock_worker_readable
from _xrdcl_proxy import real_bindings_available
from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-pgio-nonposix"),
              pytest.mark.skipif(
                  not real_bindings_available(),
                  reason="real libXrdCl bindings unavailable")]


PBLOCK_SPEC = "lc-pgio-pblock"
BLOCK_SPEC = "lc-pgio-block"

PB_BLOCK = 1024 * 1024                       # brix_pblock_block_size in the lab template
PB_SIZE = PB_BLOCK + 40_960 + 1234           # spans 2 pblock blocks, ends unaligned
DEV_SIZE = 64 * PG_PAGE + 1000               # 64 full pages + a short tail page
SRC_NAME = "/pgio_src.bin"


def _bytes(n: int, seed: int) -> bytes:
    """Deterministic non-repeating-per-page payload (a page-wise constant
    pattern would let a page-order bug pass unnoticed)."""
    return bytes(((i * 37) + (i >> 12) * 11 + seed) & 0xFF for i in range(n))


PB_DATA = _bytes(PB_SIZE, 7)
DEV_DATA = _bytes(DEV_SIZE, 71)


def _need_nginx() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")


def _upload(url: str, data: bytes) -> None:
    f = client.File()
    status, _ = f.open(url, OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    status, _ = f.write(data)
    assert status.ok, f"write failed: {status.message}"
    f.close()


def _download(url: str) -> bytes:
    f = client.File()
    status, _ = f.open(url, OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"
    try:
        status, data = f.read()
        assert status.ok, f"read failed: {status.message}"
        return bytes(data)
    finally:
        f.close()


def _readv(url: str, chunks: list, expect_ok: bool = True) -> list:
    """Issue kXR_readv; return [(offset, bytes)] in request order.

    ``expect_ok=False`` asserts the batch was REFUSED and returns []."""
    f = client.File()
    status, _ = f.open(url, OpenFlags.READ)
    assert status.ok, f"open for readv failed: {status.message}"
    try:
        status, result = f.vector_read(chunks)
        if not expect_ok:
            assert not status.ok, "readv batch was accepted, want refusal"
            return []
        assert status.ok, f"vector_read failed: {status.message}"
        return [(c.offset, bytes(c.buffer)) for c in result]
    finally:
        f.close()


def _assert_pages(pages, src: bytes, off: int, rlen: int, where: str) -> None:
    """The whole pgread contract in one place: page count, per-page logical
    offset, per-page bytes and the per-page CRC32c (INVARIANT 1)."""
    want = page_slices(src, off, rlen)
    assert len(pages) == len(want), (
        f"{where}: {len(pages)} pages, want {len(want)} "
        f"(off={off} len={rlen})")
    for i, (wo, wbytes) in enumerate(want):
        po, page, crc = pages[i]
        assert po == wo, f"{where}: page {i} offset {po} != {wo}"
        assert page == wbytes, f"{where}: page {i} bytes wrong"
        assert crc == crc32c(wbytes), (
            f"{where}: page {i} CRC32c wrong (len {len(wbytes)})")
    assert pgread_bytes(pages) == src[off:off + rlen], (
        f"{where}: reassembly wrong (off={off} len={rlen})")


# --------------------------------------------------------------------------- #
# Servers.                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pblock_srv():
    """A pblock:// export with one seeded multi-block file."""
    _need_nginx()
    harness = LifecycleHarness()
    try:
        ep = pblock_lab_start(harness, PBLOCK_SPEC, "")
        _upload(f"root://{HOST}:{ep.port}/{SRC_NAME}", PB_DATA)
        yield ep
    finally:
        harness.close()


@pytest.fixture(scope="module")
def block_srv(tmp_path_factory):
    """A block:<device> export over a regular-file device.

    The image must exist before the master starts: the backend is built while
    the config is parsed, and an absent device fails the whole load."""
    _need_nginx()
    devimg = tmp_path_factory.mktemp("pgio-block") / "dev.img"
    devimg.write_bytes(DEV_DATA)
    pblock_worker_readable(devimg)   # no-op unprivileged; root harness runs as nobody
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=BLOCK_SPEC,
            template="nginx_block_dev.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST, "DEVIMG": str(devimg)},
            reason="pg-I/O + readv against the fixed-extent block:<device> plane"))
        yield ep, devimg
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# pblock:// — success, error, security-negative.                               #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("off,rlen", [
    (0, PG_PAGE),                        # exactly one page
    (0, 3 * PG_PAGE),                    # multi-page, aligned
    (1024, 2 * PG_PAGE),                 # unaligned first page (short to 4096)
    (PB_BLOCK - 2048, 3 * PG_PAGE),      # straddles the 1 MiB pblock boundary
    (PB_SIZE - 1234, 1234),              # short final page at EOF
])
def test_pgread_pblock_pages_and_crc(pblock_srv, off, rlen):
    """(success) pgread over a block-mapped object store returns the same page
    split, bytes and per-page CRC32c a posix export would — including across a
    pblock block boundary, where the driver stitches two stored blocks into one
    logical page."""
    h = _Handle(HOST, pblock_srv.port, SRC_NAME, options=kXR_open_read)
    try:
        status, pages = pgread(h.sock, h.fh, off, rlen)
    finally:
        h.close()
    assert status == kXR_ok, f"pgread failed on pblock (off={off} len={rlen})"
    _assert_pages(pages, PB_DATA, off, rlen, "pblock pgread")


def test_readv_pblock_crosses_block_boundary(pblock_srv):
    """(success) kXR_readv segments are gathered through the driver's preadv
    slot; a segment that spans two pblock blocks, and a batch whose segments
    are non-contiguous, must both come back byte-exact and in request order."""
    segments = [
        (0, 4096),
        (PB_BLOCK - 1000, 4096),         # spans the block boundary
        (PB_BLOCK + 8192, 32768),
        (PB_SIZE - 500, 500),            # ends exactly at EOF
    ]
    got = _readv(f"root://{HOST}:{pblock_srv.port}/{SRC_NAME}", segments)
    assert len(got) == len(segments), f"readv returned {len(got)} segments"
    for (woff, wlen), (goff, gbuf) in zip(segments, got):
        assert goff == woff, f"readv segment offset {goff} != {woff}"
        assert gbuf == PB_DATA[woff:woff + wlen], (
            f"readv segment @{woff}+{wlen} bytes wrong")


def test_pgwrite_pblock_roundtrip(pblock_srv):
    """(success) pgwrite lands through the pblock write path at an unaligned
    offset spanning a block boundary, and the bytes read back — by pgread and
    by a plain read — are exactly what was sent."""
    url = f"root://{HOST}:{pblock_srv.port}//pgio_pgw.bin"
    base = _bytes(PB_BLOCK + 8192, 3)
    _upload(url, base)                    # allocate the blocks first
    off = PB_BLOCK - 1024                 # unaligned, straddles the boundary
    payload = _bytes(3 * PG_PAGE, 91)
    h = _Handle(HOST, pblock_srv.port, "/pgio_pgw.bin",
                options=kXR_open_updt)
    try:
        status, _info, cse = pgwrite(h.sock, h.fh, off, payload)
    finally:
        h.close()
    assert status == kXR_ok, "pgwrite refused on a pblock export"
    assert cse == b"", f"pgwrite reported bad pages on a clean write: {cse!r}"
    want = bytearray(base)
    want[off:off + len(payload)] = payload
    assert _download(url) == bytes(want), "pblock pgwrite bytes not durable"

    h = _Handle(HOST, pblock_srv.port, "/pgio_pgw.bin", options=kXR_open_read)
    try:
        status, pages = pgread(h.sock, h.fh, off, len(payload))
    finally:
        h.close()
    assert status == kXR_ok, "pgread after pgwrite failed"
    _assert_pages(pages, bytes(want), off, len(payload), "pblock pgwrite readback")


@pytest.mark.parametrize("bad", [0, 2])
def test_pgwrite_pblock_corrupt_page_rejected(pblock_srv, bad):
    """(error) A page whose CRC32c does not match its bytes must be flagged —
    by an error status or a non-empty CSE retransmit list — on the non-posix
    driver too.  Silent acceptance here would be silent data corruption in the
    object store."""
    rel = f"/pgio_bad_{bad}.bin"
    data = _bytes(4 * PG_PAGE, 17)
    # DELETE|NEW: the export prefix survives across runs, so a bare
    # kXR_new would fail "file exists" on the second invocation.
    h = _Handle(HOST, pblock_srv.port, rel, options=kXR_delete | WR_NEW)
    try:
        status, _info, cse = pgwrite(h.sock, h.fh, 0, data, corrupt_index=bad)
    finally:
        h.close()
    assert status == kXR_error or cse, (
        f"pblock ACCEPTED a corrupt pgwrite page (index {bad}) without "
        f"flagging it -- silent data corruption")


def test_pgwrite_pblock_read_only_handle_refused(pblock_srv):
    """(security-negative) A handle opened read-only must not become a write
    channel just because the export allows writes: pgwrite on it is refused and
    the stored object is untouched."""
    h = _Handle(HOST, pblock_srv.port, SRC_NAME, options=kXR_open_read)
    try:
        status, _info, _cse = pgwrite(h.sock, h.fh, 0, _bytes(PG_PAGE, 200))
    finally:
        h.close()
    assert status == kXR_error, (
        "pgwrite through a READ-ONLY handle was accepted on a pblock export")
    assert _download(f"root://{HOST}:{pblock_srv.port}/{SRC_NAME}") == PB_DATA, (
        "the refused pgwrite still mutated the object")


# --------------------------------------------------------------------------- #
# block:<device> — success, error, security-negative.                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("off,rlen", [
    (0, PG_PAGE),
    (0, 8 * PG_PAGE),
    (2000, 2 * PG_PAGE),                 # unaligned first page
    (DEV_SIZE - 1000, 1000),             # the short tail page at capacity
])
def test_pgread_block_extent_pages_and_crc(block_srv, off, rlen):
    """(success) The single whole-device extent "/0" answers pgread with
    EXTENT-RELATIVE page offsets and correct per-page CRC32c: the driver's
    windowing must not leak the device offset into the wire response."""
    ep, _devimg = block_srv
    h = _Handle(HOST, ep.port, "/0", options=kXR_open_read)
    try:
        status, pages = pgread(h.sock, h.fh, off, rlen)
    finally:
        h.close()
    assert status == kXR_ok, f"pgread failed on block: (off={off} len={rlen})"
    _assert_pages(pages, DEV_DATA, off, rlen, "block pgread")


def test_readv_block_extent(block_srv):
    """(success) Vectored reads through the extent window are byte-exact, and a
    segment that runs to the end of the device returns the short tail rather
    than reading into whatever follows it.  A segment that runs PAST the extent
    end is refused outright — the window must never satisfy a read from beyond
    the extent's own byte range."""
    ep, _devimg = block_srv
    url = f"root://{HOST}:{ep.port}//0"
    segments = [(0, 4096), (100_000, 8192), (DEV_SIZE - 300, 300)]
    got = _readv(url, segments)
    assert len(got) == len(segments)
    for (woff, wlen), (goff, gbuf) in zip(segments, got):
        assert goff == woff
        assert gbuf == DEV_DATA[woff:woff + wlen], (
            f"block readv segment @{woff}+{wlen} bytes wrong")
    _readv(url, [(0, 4096), (DEV_SIZE - 100, 4096)], expect_ok=False)


def test_pgwrite_block_extent_confinement(block_srv):
    """(error) A fixed extent cannot grow.  A pgwrite inside the extent lands
    and touches only its own range; a pgwrite that would cross the extent end
    is refused, and the device file neither grows nor gains a byte past its
    capacity."""
    ep, devimg = block_srv
    before = devimg.read_bytes()
    assert len(before) == DEV_SIZE

    off = 16 * PG_PAGE
    payload = _bytes(2 * PG_PAGE, 55)
    h = _Handle(HOST, ep.port, "/0", options=kXR_open_read | kXR_open_updt)
    try:
        status, _info, cse = pgwrite(h.sock, h.fh, off, payload)
    finally:
        h.close()
    assert status == kXR_ok and cse == b"", "in-extent pgwrite was refused"
    after = devimg.read_bytes()
    assert len(after) == DEV_SIZE, "an in-extent write grew the device"
    assert after[off:off + len(payload)] == payload, "in-extent write lost bytes"
    assert after[:off] == before[:off], "write scribbled before its offset"
    assert after[off + len(payload):] == before[off + len(payload):], (
        "write scribbled past its length")

    # Straddle the extent end: the request starts in range and runs past it.
    h = _Handle(HOST, ep.port, "/0", options=kXR_open_read | kXR_open_updt)
    try:
        status, _info, _cse = pgwrite(h.sock, h.fh, DEV_SIZE - 512,
                                      _bytes(2 * PG_PAGE, 99))
    finally:
        h.close()
    assert status == kXR_error, (
        "a pgwrite crossing the extent end was accepted -- a fixed extent must "
        "refuse to grow (ENOSPC), never spill into its neighbour")
    assert devimg.stat().st_size == DEV_SIZE, (
        "the refused boundary-crossing write still grew the device")


@pytest.mark.parametrize("name", [
    "/1",                                # out-of-range extent index
    "/etc",                              # non-numeric: not an extent name
    "/0/passwd",                         # an extent is not a directory
    "/../../etc/passwd",                 # escape attempt
])
def test_block_namespace_confinement(block_srv, name):
    """(security-negative) The device namespace exposes ONLY the fixed extent
    indices.  Anything else — an out-of-range index, a non-numeric component,
    an escape — must fail to open, so a device export can never be walked into
    an arbitrary host path."""
    ep, _devimg = block_srv
    sock = _session(HOST, ep.port)
    try:
        _sid, status, _body = _open(sock, name, kXR_open_read)
    finally:
        sock.close()
    assert status == kXR_error, (
        f"block:<device> export opened {name!r} (status {status}) -- the "
        f"namespace must expose only the fixed extent indices")
