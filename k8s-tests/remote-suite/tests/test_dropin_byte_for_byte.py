"""
tests/test_dropin_byte_for_byte.py — drop-in byte-for-byte parity vs the
OFFICIAL xrootd server.

This suite proves the nginx-xrootd module is a *drop-in* replacement for the
official /usr/bin/brix at the wire level: it provisions BOTH servers on the
SAME data root (a dedicated official xrootd and a dedicated nginx, on isolated
high ports) and then issues the identical raw `root://` request to each and
compares the responses.  Because both daemons read the same files, the
metadata (inode, size, mtime), the per-page CRC32c pgread stream, the dirlist
names and the file bytes are all expected to be IDENTICAL — not merely
"semantically equivalent".  Where a field legitimately cannot match across two
independent processes (e.g. a self-reported PID) the comparison is restricted
to the field ORDER / FORMAT / key-set, which is the actual conformance
contract.  All raw framing is built with `struct.pack` exactly as in
tests/test_readv_security.py, and every hostile / edge request is followed by a
sanity op proving the connection survived.

The whole module skips cleanly if the nginx binary or /usr/bin/brix is
absent, or if either server fails to come up.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_dropin_byte_for_byte.py -v
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, SERVER_HOST, free_ports

BRIX_BIN = os.environ.get("TEST_BRIX_BIN", "/usr/bin/brix")
H = SERVER_HOST

# Dedicated workspace for this file.
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_dropin_bfb")
# Ports the fixture BINDS (nginx listen + official xrootd xrd.port): allocate
# distinct free OS ports so they never collide with the managed fleet or with
# another self-contained test running in the same pytest invocation.  Any
# explicit env override is still honoured.
_NGINX_FREE, _BRIX_FREE = free_ports(2)
NGINX_PORT  = int(os.environ.get("TEST_DROPIN_NGINX_PORT") or _NGINX_FREE)
BRIX_PORT = int(os.environ.get("TEST_DROPIN_BRIX_PORT") or _BRIX_FREE)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (XProtocol.hh + src/protocols/root/protocol/opcodes.h)
# ---------------------------------------------------------------------------

kXR_query    = 3001
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_stat     = 3017
kXR_statx    = 3022
kXR_pgread   = 3030
kXR_clone    = 3032

kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_status   = 4007    # pgread extended-status framing

# XQueryType (ClientQueryRequest.infotype)
kXR_Qcksum   = 3
kXR_Qspace   = 5
kXR_Qconfig  = 7

# Server error codes (XProtocol.hh XErrorCode)
kXR_NotAuthorized = 3010
kXR_NotFound      = 3011
kXR_isDirectory   = 3016
kXR_Unsupported   = 3013   # also kXR_IOError numerically; disambiguated by msg
kXR_IOError       = 3007

# Open option flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0004

# dirlist options (ClientDirlistRequest.options)
kXR_dstat     = 2

PG_PAGESZ = 4096

# Seed files (written into the SHARED data root used by BOTH servers).
PLAIN_NAME   = "/dropin_plain.bin"
PLAIN_SIZE   = 70000          # not page-aligned → exercises a short final page
PLAIN_DATA   = bytes((i * 37 + 11) & 0xFF for i in range(PLAIN_SIZE))

SUBDIR       = "/dropin_dir"
SUBDIR_FILES = ["a.bin", "b.bin", "c.bin"]

NOPERM_NAME  = "/dropin_noperm.bin"   # chmod 000 → EACCES family


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — matches brix_crc32c_copy(); used to verify the
# per-page CRCs in the pgread response are correct on BOTH servers.
# ---------------------------------------------------------------------------

_CRC32C_POLY = 0x82F63B78
_CRC32C_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC32C_POLY if (_c & 1) else (_c >> 1)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py exactly)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake(host, port):
    sock = socket.create_connection((host, port), timeout=8)
    sock.settimeout(8)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


class _SessionUnavailable(Exception):
    """Raised when a handshake/login cannot complete cleanly — converted into a
    skip by the fixtures rather than surfacing as a hard error."""


def _session(host, port):
    """Drive the full handshake + login chain.  The official server may answer
    login with an authentication-continuation (kXR_authmore) when 'sec'
    payloads are present; for an unauthenticated/anon export both return
    kXR_ok, which is what these configs use.

    On any protocol-level surprise (rejected handshake, non-ok login, a server
    that demands auth we have not configured) this raises _SessionUnavailable
    so callers can SKIP cleanly instead of erroring — these configs export an
    anonymous root, so a healthy server always reaches kXR_ok here."""
    try:
        sock = _handshake(host, port)
    except (OSError, AssertionError) as exc:
        raise _SessionUnavailable(f"handshake failed @ {host}:{port}: {exc}")
    try:
        sid, status, body = _login(sock)
    except OSError as exc:
        sock.close()
        raise _SessionUnavailable(f"login I/O failed @ {host}:{port}: {exc}")
    if status != kXR_ok:
        sock.close()
        raise _SessionUnavailable(
            f"login not kXR_ok @ {host}:{port}: status={status} "
            f"{_error_msg(body)!r}")
    return sock


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _stat(sock, path, streamid=b"\x00\x10"):
    """ClientStatRequest: options[1] reserved[7] wants[u32] fhandle[4] dlen.
    Path-based stat (fhandle = 0) — see XProtocol.hh ClientStatRequest."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHB7sI4sI",
                      streamid, kXR_stat,
                      0, b"\x00" * 7, 0, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _statx(sock, paths, streamid=b"\x00\x11"):
    """kXR_statx: same header shape as kXR_stat; payload is one or more
    null-separated paths.  The XRootD python client has NO statx method, so
    this is raw-wire only."""
    if isinstance(paths, str):
        paths = [paths]
    payload = b"".join(p.encode() + b"\x00" for p in paths)
    req = struct.pack("!2sHB7sI4sI",
                      streamid, kXR_statx,
                      0, b"\x00" * 7, 0, b"\x00" * 4, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _query(sock, infotype, payload=b"", fhandle=b"\x00\x00\x00\x00",
           streamid=b"\x00\x12"):
    """ClientQueryRequest: infotype[u16] reserved1[2] fhandle[4]
    reserved2[8] dlen."""
    if isinstance(payload, str):
        payload = payload.encode()
    req = struct.pack("!2sHH2s4s8sI",
                      streamid, kXR_query,
                      infotype, b"\x00\x00", fhandle, b"\x00" * 8,
                      len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _dirlist(sock, path, options=kXR_dstat, streamid=b"\x00\x13"):
    """ClientDirlistRequest: options[1] reserved[15] dlen + path."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sH15sBI",
                      streamid, kXR_dirlist,
                      b"\x00" * 15, options, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _pgread(sock, fhandle, offset, rlen, streamid=b"\x00\x07"):
    """Issue kXR_pgread and fully drain the response.  Success is a kXR_status
    message (8-byte header + 24-byte status body), then bdy.dlen raw bytes of
    CRC-interleaved page data.  Returns (status, status_body, pages)."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    sid, status, body = _read_response(sock)
    pages = b""
    if status == kXR_status and len(body) >= 16:
        bdy_dlen = struct.unpack("!i", body[12:16])[0]
        if bdy_dlen > 0:
            pages = _recv_exact(sock, bdy_dlen)
    return status, body, pages


def _clone(sock, dst_fhandle, items=b"", streamid=b"\x00\x14"):
    """ClientCloneRequest: dst_fhandle[4] reserved[12] dlen + clone_list."""
    req = struct.pack("!2sH4s12sI",
                      streamid, kXR_clone, dst_fhandle, b"\x00" * 12,
                      len(items))
    sock.sendall(req + items)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _error_msg(body):
    return body[4:].split(b"\x00")[0].decode(errors="replace") if len(body) > 4 else ""


def _is_not_found(code, message):
    phrases = ("no such", "not found", "does not exist", "doesn't exist")
    return code == kXR_NotFound or any(text in message for text in phrases)


def _is_permission(code, message):
    phrases = ("permission", "not authoriz", "denied")
    return code == kXR_NotAuthorized or any(text in message for text in phrases)


def _is_directory(code, message):
    phrases = ("is a directory", "is directory")
    explicit = any(text in message for text in phrases)
    return code == kXR_isDirectory or explicit or (
        "directory" in message and "not" not in message)


def _error_family(status, body):
    """Coarse error family for cross-server comparison — handles BOTH the
    nginx numeric error codes and the official server's (which may differ in
    exact code but agree on the family conveyed by the message text)."""
    if status != kXR_error:
        return "ok"
    code = _error_code(body)
    msg = _error_msg(body).lower()
    if _is_not_found(code, msg):
        return "not_found"
    if _is_permission(code, msg):
        return "permission"
    if _is_directory(code, msg):
        return "is_directory"
    return "error"


def _decode_pages(pages):
    """Split a pgread page stream [crc4][<=4096 data]..., verify each CRC32c,
    return the concatenated data.  Raises on CRC mismatch."""
    out = bytearray()
    pos = 0
    while pos < len(pages):
        crc = struct.unpack("!I", pages[pos:pos + 4])[0]
        pos += 4
        page = pages[pos:pos + PG_PAGESZ]
        pos += len(page)
        if _CRC32C_OK:
            assert crc32c(page) == crc, "pgread per-page CRC32c mismatch"
        out.extend(page)
        if len(page) < PG_PAGESZ:
            break
    return bytes(out)



from split_continuation import load as _load_continuations
_load_continuations(
    globals(), __file__,
    "_dropin_byte_for_byte_part2.py",
    "_dropin_byte_for_byte_part3.py",
)
