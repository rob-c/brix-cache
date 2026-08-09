# _test_conf_pgio_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_pgio.py.  `from _test_conf_pgio_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""Differential PAGED-I/O (kXR_pgread / kXR_pgwrite) conformance.

kXR_pgread (3030) and kXR_pgwrite (3026) move file data in 4096-byte *pages*,
each page preceded (pgread) or prefixed (pgwrite) by a 4-byte CRC-32C
(Castagnoli, IETF RFC 7143) of that page's bytes. The response framing is the
kXR_status (4007) message family (ServerResponseBody_Status + an 8-byte file
offset + the interleaved [crc32c][page] data stream).

The reference for every assertion here is the STOCK XRootD server (launched on
an identical data tree next to our nginx-xrootd) and the stock client tools
(xrdcp). Wherever the high-level tools cannot exercise a wire corner, the
request is crafted as RAW WIRE over a plain TCP socket and replayed against BOTH
servers; the two answers, and the bytes/CRCs they carry, must agree. Any
divergence -- a wrong per-page CRC, a wrong page boundary / short-page split, a
botched reassembly, a corrupt page that is NOT rejected, or framing that
differs from stock -- is treated as a BUG IN OUR SERVER, and the assertion is
written to fail (no xfail/skip to paper over a real diff).

Wire references (consulted, not modified):
  /tmp/brix-src/src/XProtocol/XProtocol.hh
      ClientPgReadRequest / ClientPgWriteRequest
      ServerResponseBody_Status (kXR_status)  + ServerResponseBody_pgRead
      ServerResponseBody_pgWrite + ServerResponseBody_pgWrCSE
      kXR_pgPageSZ=4096  kXR_pgUnitSZ=4100  kXR_pgRetry=0x01
  /tmp/brix-src/src/XrdXrootd/XrdXrootdXeqPgrw.cc  do_PgRIO / do_PgWIO
  /tmp/brix-src/src/XrdXrootd/XrdXrootdResponse.cc srsComplete (status framing)

The status-response crc32c body field covers streamID..info (NOT the page
data); the per-page CRC32c values are what this suite verifies for data
integrity. Self-provisions on high ports; skips entirely without the stock
toolchain.
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Opcodes / status / error codes (XProtocol.hh).                              #
# --------------------------------------------------------------------------- #
kXR_login = 3007
kXR_open = 3010
kXR_close = 3003
kXR_read = 3013
kXR_pgwrite = 3026
kXR_pgread = 3030
kXR_1stRequest = 3000

kXR_ok = 0
kXR_oksofar = 4000
kXR_error = 4003
kXR_status = 4007

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new = 0x0008
kXR_delete = 0x0002
kXR_mkpath = 0x0100
kXR_open_wrto = 0x8000

# kXR_status RespType (XrdProto::RespType).
kXR_FinalResult = 0x00
kXR_PartialResult = 0x01

# Paged-I/O framing constants (XProtocol.hh XrdProto namespace).
PG_PAGE = 4096                 # kXR_pgPageSZ
PG_CRC = 4                     # sizeof(kXR_unt32)
PG_UNIT = PG_PAGE + PG_CRC     # kXR_pgUnitSZ = 4100
kXR_pgRetry = 0x01

# ServerResponseBody_Status length (crc32c[4]+streamID[2]+requestid[1]+
# resptype[1]+reserved[4]+dlen[4]); the kXR_status "info" for pg-I/O is the
# 8-byte file offset.
STATUS_BODY_LEN = 16
PG_INFO_LEN = 8

# Deterministic file sizes materialised by official_interop_lib.make_rich_tree.
SZ_FILES = {
    "sz_1.bin": 1,
    "sz_255.bin": 255,
    "sz_4095.bin": 4095,
    "sz_4096.bin": 4096,
    "sz_4097.bin": 4097,
    "sz_8192.bin": 8192,
    "sz_65536.bin": 65536,
}
DATA_BIN = "data.bin"      # 4096
DATA_SIZE = 4096
BIG_BIN = "big1m.bin"      # 1048576
BIG_SIZE = 1024 * 1024
CKSUM_BIN = "cksum.bin"    # 10000


# ===========================================================================
# Software CRC-32C (Castagnoli, poly 0x1EDC6F41 reflected = 0x82F63B78).
# Self-checked against the canonical vector "123456789" -> 0xe3069283.
# ===========================================================================
def _readback(host, port, name, size):
    h = _Handle(host, port, name, options=kXR_open_read)
    try:
        st, data = _read_drain(h.sock, h.fh, 0, size + 4096)
        assert st == kXR_ok
        return data
    finally:
        h.close()


WR_NEW = kXR_open_updt | kXR_new | kXR_mkpath


def _cse_offsets(cse):
    """Parse ServerResponseBody_pgWrCSE: cseCRC[4] dlFirst[2] dlLast[2] then a
    list of int64 page offsets."""
    if len(cse) < 8:
        return []
    body = cse[8:]
    n = len(body) // 8
    return list(struct.unpack("!" + "q" * n, body[:n * 8]))


def _cse_lengths(cse):
    """Return (dlFirst, dlLast) from a CSE trailer."""
    if len(cse) < 8:
        return (None, None)
    return struct.unpack("!hh", cse[4:8])


_kXR_ChkSumErr = 3019


def _retry_one_page(sock, fh, offset, data, index):
    """Resend page `index` (kXR_pgRetry) with a correct payload."""
    lens = page_lengths(offset, len(data))
    pgoff = offset + sum(lens[:index])
    rel = pgoff - offset
    return pgwrite(sock, fh, pgoff, data[rel:rel + lens[index]],
                   reqflags=kXR_pgRetry)


def _corrupt_pages(data, offset, indices):
    """Build a pgwrite payload corrupting the DATA of each listed page index."""
    payload = bytearray()
    lens = page_lengths(offset, len(data))
    rel = 0
    for i, ln in enumerate(lens):
        page = bytearray(data[rel:rel + ln])
        c = crc32c(bytes(page))
        if i in indices:
            page[0] ^= 0xFF       # data mismatches its CRC
        payload += struct.pack("!I", c)
        payload += bytes(page)
        rel += ln
    return bytes(payload)


def _send_raw_pgwrite(sock, fh, offset, payload, reqflags=0, streamid=b"\x00\x08"):
    """Send a prebuilt pgwrite payload; return (status, info_offset, cse)."""
    req = struct.pack("!2sH4sqBBHI", streamid, kXR_pgwrite, fh,
                      offset, 0, reqflags & 0xFF, 0, len(payload))
    sock.sendall(req + payload)
    resptype, info_off, cse = _read_status_message(sock)
    if resptype == "error":
        return kXR_error, None, cse
    return kXR_ok, info_off, cse

__all__ = [n for n in dir() if not n.startswith('__')]
