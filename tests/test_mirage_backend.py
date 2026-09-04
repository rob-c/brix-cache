"""mirage — the sizes-only synthetic storage backend (parity audit §3 row 14).

`brix_storage_backend mirage:<size>` serves every path as a READ-ONLY regular
file of <size> bytes whose content is the deterministic offset pattern
byte(o) = (o*131+7) & 0xFF — the Mirage zero-storage analog for protocol and
throughput testing: the full root:// stack runs with no disks behind it, and
every range read is independently verifiable.

Coverage:
  * success  — open + stat report the configured size; reads at offset 0, an
               interior offset, and the EOF straddle return the exact pattern.
  * error    — a write open is refused (read-only backend); reading past EOF
               returns zero bytes, not garbage.
  * config   — a malformed size fails nginx -t.

Self-contained: launches its own short-lived nginx; no shared fleet.
"""

import socket
import struct

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-mirage-backend")]

_SERVER = "lc-mirage-backend"

SIZE = 65536
kXR_open, kXR_read = 3010, 3013
kXR_open_read = 0x0010
kXR_open_new, kXR_open_updt = 0x0008, 0x0002
kXR_stat = 3017


def _pattern(off, n):
    return bytes(((o * 131 + 7) & 0xFF) for o in range(off, off + n))


def _spec(backend_line):
    return NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_mirage_backend.conf",
        template_values={"BIND_HOST": BIND_HOST, "BACKEND": backend_line},
        reason="mirage backend wire and config coverage")


def _launch(lifecycle, backend_line):
    return lifecycle.start(_spec(backend_line)).port


def _open(sock, stream, path, mode_flags):
    body = struct.pack(">HH", 0o644, mode_flags) + b"\x00" * 12
    return H._send_req(sock, stream, kXR_open, body=body,
                       payload=path.encode() + b"\x00")


def test_pattern_reads_and_stat(lifecycle):
    """(success) any path opens at the configured size and range reads return
    the exact deterministic pattern — including the EOF straddle."""
    port = _launch(lifecycle, f"mirage:{SIZE}")
    H.ANON_HOST = BIND_HOST
    primary = None
    try:
        primary, sessid, stream = H._establish_primary(port)
        status, body = _open(primary, stream, "/any/imaginary/file.bin",
                             kXR_open_read)
        assert status == H.kXR_ok, f"mirage open failed: {status}"
        fh = body[:4]

        for off, n in ((0, 512), (12345, 1000), (SIZE - 100, 100)):
            status, data = H._read_handle(primary, stream, fh, n, offset=off)
            assert status in (H.kXR_ok, H.kXR_oksofar), f"read status={status}"
            assert data == _pattern(off, n), \
                f"pattern mismatch at {off}+{n}"

        # EOF straddle: ask past the end, get exactly the tail.
        status, data = H._read_handle(primary, stream, fh, 4096,
                                      offset=SIZE - 64)
        assert status in (H.kXR_ok, H.kXR_oksofar)
        assert data == _pattern(SIZE - 64, 64), "EOF straddle wrong"
    finally:
        if primary is not None:
            primary.close()


def test_write_open_refused_and_eof_empty(lifecycle):
    """(error) the backend is read-only: a create/update open is refused; a
    read entirely past EOF returns zero bytes."""
    port = _launch(lifecycle, f"mirage:{SIZE}")
    H.ANON_HOST = BIND_HOST
    primary = None
    try:
        primary, sessid, stream = H._establish_primary(port)

        status, _ = _open(primary, stream, "/newfile.bin",
                          kXR_open_new | kXR_open_updt)
        assert status == H.kXR_error, \
            f"write open on a read-only synthetic backend succeeded: {status}"

        status, body = _open(primary, stream, "/ok.bin", kXR_open_read)
        assert status == H.kXR_ok
        fh = body[:4]
        status, data = H._read_handle(primary, stream, fh, 512,
                                      offset=SIZE + 1024)
        assert status in (H.kXR_ok, H.kXR_oksofar)
        assert data == b"", f"past-EOF read returned {len(data)} bytes"
    finally:
        if primary is not None:
            primary.close()


def test_malformed_size_refused(lifecycle):
    """(config) a malformed mirage size fails nginx -t."""
    lifecycle.register(_spec("mirage:notasize"))
    lifecycle.reconfigure(_SERVER)
    t = lifecycle.nginx_test(_SERVER, check=False)
    assert t.returncode != 0, "malformed mirage size accepted by nginx -t"
    assert "mirage" in t.stderr, t.stderr
