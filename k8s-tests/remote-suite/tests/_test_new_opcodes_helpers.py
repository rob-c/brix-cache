# _test_new_opcodes_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_new_opcodes.py.  `from _test_new_opcodes_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""
Functional tests for five newly-implemented XRootD protocol opcodes:

  kXR_pgread  (3030) — paged read with per-page CRC32c
  kXR_writev  (3031) — scatter-gather / vector write
  kXR_locate  (3027) — file replica location query
  kXR_sigver  (3029) — request signing (accepted without verification)
  kXR_statx   (3022) — multi-path stat

Run:
    pytest tests/test_new_opcodes.py -v -s
"""

import hashlib
import os
import struct
import socket
from pathlib import Path


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — shared by TestChkpointXeq and TestChkpointExtended
# ---------------------------------------------------------------------------

def _crc32c(data: bytes) -> int:
    """Pure-Python CRC32c using reversed Castagnoli polynomial 0x82F63B78."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


def _pgwrite_payload(data: bytes, offset: int, corrupt_page: int = -1) -> bytes:
    """Build a kXR_pgwrite payload: [4B CRC32c BE][page data] per 4096-byte page."""
    out = bytearray()
    pos, cur_off, page_idx = 0, offset, 0
    while pos < len(data):
        room = 4096 - (cur_off % 4096)
        chunk = data[pos: pos + room]
        crc = _crc32c(chunk)
        if page_idx == corrupt_page:
            crc = (crc ^ 0xDEADBEEF) & 0xFFFFFFFF
        out += struct.pack("!I", crc) + chunk
        pos += len(chunk);  cur_off += len(chunk);  page_idx += 1
    return bytes(out)

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, StatInfoFlags
from settings import (
    CA_DIR,
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
ANON_PORT = NGINX_ANON_PORT
GSI_URL   = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
PROXY_PEM = PROXY_STD

PATTERN   = bytes(i & 0xFF for i in range(65536))     # 64 KiB
LARGE     = bytes((i * 7 + 13) & 0xFF for i in range(512 * 1024))  # 512 KiB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def upload(url_base: str, remote: str, data: bytes) -> None:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    if data:
        status, _ = f.write(data)
        assert status.ok, f"write failed: {status.message}"
    f.close()


def open_rd(url_base: str, remote: str) -> client.File:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"
    return f


def open_wr(url_base: str, remote: str) -> client.File:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    return f


# ---------------------------------------------------------------------------
# kXR_pgread
# ---------------------------------------------------------------------------


__all__ = [n for n in dir() if not n.startswith('__')]
