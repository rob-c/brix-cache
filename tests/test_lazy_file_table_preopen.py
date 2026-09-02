"""
tests/test_lazy_file_table_preopen.py — the lazy handle table is NULL-safe.

WHAT: Raw-wire proof for the lazily allocated per-connection file-handle table
      (brix_ctx_t.files starts NULL; brix_files_ensure allocates it on the
      first kXR_open / bound-handle ensure — see
      src/protocols/root/connection/fd_table.c).

WHY:  Before this optimization the 16-slot brix_file_t table (~170 KB) was
      embedded in brix_ctx_t and zeroed on every connection, so metadata-only
      sessions paid ~150 KB of touched pages they never used.  Making it lazy
      shrinks an idle session ~6×, but every request path that indexes the
      table must now treat NULL as "no handle is open" — an unguarded deref is
      a remotely triggerable worker crash (segfault DoS: one frame with a
      handle before any open).

HOW:  Three properties against the shared anon fleet:
       1. success  — open/write/read/close round-trip works (the table
          allocates on first open and behaves as before).
       2. error    — after open+close, I/O on the freed handle is
          kXR_FileNotOpen (table present, slot free).
       3. security — every handle-bearing op sent BEFORE any open on a fresh
          session (table NULL) gets a clean error — kXR_FileNotOpen for the
          plain-validated ops — and the worker survives (the same connection
          or a fresh one still answers).

Run: TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_lazy_file_table_preopen.py -v
"""
import os
import socket
import struct

import pytest

from settings import NGINX_ANON_PORT, REMOTE_SERVER, SERVER_HOST

kXR_query = 3001
kXR_close = 3003
kXR_login = 3007
kXR_open = 3010
kXR_ping = 3011
kXR_read = 3013
kXR_sync = 3016
kXR_write = 3019
kXR_fattr = 3020
kXR_readv = 3025
kXR_pgwrite = 3026
kXR_truncate = 3028
kXR_pgread = 3030
kXR_writev = 3031
kXR_ok = 0
kXR_error = 4003
kXR_FileNotOpen = 3004            # XErrorCode (base 3000)
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_new = 0x0008
kXR_delete = 0x0004
kXR_mkpath = 0x0100

PROBE = "/lazy_ftab_probe.bin"
FH0 = b"\x00\x00\x00\x00"


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data.extend(chunk)
    return bytes(data)


def _resp(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return sid, status, (_recv_exact(sock, dlen) if dlen else b"")


def _session():
    s = socket.create_connection((SERVER_HOST, NGINX_ANON_PORT), timeout=8)
    s.settimeout(8)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    assert _resp(s)[1] == kXR_ok, "handshake rejected"
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0, 0))
    assert _resp(s)[1] == kXR_ok, "login rejected"
    return s


def _open(s, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00"
    req = struct.pack("!2sHHH2s6s4sI", streamid, kXR_open, 0o644, options,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4, len(p))
    s.sendall(req + p)
    return _resp(s)


def _read(s, fh, off, rlen, streamid=b"\x00\x08"):
    s.sendall(struct.pack("!2sH4sqiI", streamid, kXR_read, fh, off, rlen, 0))
    return _resp(s)


def _write(s, fh, off, payload, streamid=b"\x00\x09"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_write, fh, off, 0, len(payload))
    s.sendall(req + payload)
    return _resp(s)


def _close(s, fh, streamid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", streamid, kXR_close, fh, b"\x00" * 12, 0))
    return _resp(s)


def _ping(s, streamid=b"\x00\x0f"):
    s.sendall(struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0))
    return _resp(s)


def _err_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None


@pytest.fixture(autouse=True)
def _need_local_fleet():
    if REMOTE_SERVER:
        pytest.skip("needs the local anon fleet")
    try:
        s = _session()
    except OSError:
        pytest.skip(f"anon server {SERVER_HOST}:{NGINX_ANON_PORT} unreachable")
    s.close()


def test_lazy_table_open_io_close_roundtrip():
    """Success: the table allocates on first open; write+read round-trip."""
    s = _session()
    # kXR_delete (replace existing) rather than kXR_open_new (exclusive
    # create): the probe file may survive an earlier run of this module.
    sid, status, body = _open(s, PROBE,
                              kXR_open_updt | kXR_delete | kXR_mkpath)
    if status != kXR_ok:
        s.close()
        pytest.skip("could not create probe file (writes disabled?)")
    fh = body[:4]
    payload = b"lazy-file-table\n"
    assert _write(s, fh, 0, payload)[1] == kXR_ok
    sid, status, data = _read(s, fh, 0, 64, streamid=b"\x00\x0a")
    assert status == kXR_ok and data == payload, (
        f"read-back mismatch (status={status}, data={data!r})")
    assert _close(s, fh)[1] == kXR_ok
    s.close()


def test_closed_handle_is_file_not_open():
    """Error: after close the slot is free again — I/O on it is FileNotOpen."""
    s = _session()
    sid, status, body = _open(s, PROBE)
    if status != kXR_ok:
        s.close()
        pytest.skip("probe file missing (round-trip test skipped earlier?)")
    fh = body[:4]
    assert _close(s, fh)[1] == kXR_ok
    sid, status, body = _read(s, fh, 0, 16, streamid=b"\x00\x0b")
    s.close()
    assert status == kXR_error and _err_code(body) == kXR_FileNotOpen, (
        f"read on closed handle: status={status}, err={_err_code(body)}")


# Handle-bearing frames sent on a fresh session (ctx->files == NULL).
# strict=True → the plain handle validators run first: exactly kXR_FileNotOpen.
# strict=False → op-specific parsing may reject first: any clean error accepted.
_PREOPEN_OPS = {
    "read":     (True, struct.pack("!2sH4sqiI", b"\x00\x02", kXR_read,
                                   FH0, 0, 16, 0)),
    "write":    (True, struct.pack("!2sH4sqiI", b"\x00\x03", kXR_write,
                                   FH0, 0, 0, 4) + b"data"),
    "sync":     (True, struct.pack("!2sH4s12sI", b"\x00\x04", kXR_sync,
                                   FH0, b"\x00" * 12, 0)),
    "truncate": (True, struct.pack("!2sH4sq4sI", b"\x00\x05", kXR_truncate,
                                   FH0, 0, b"\x00" * 4, 0)),
    "close":    (True, struct.pack("!2sH4s12sI", b"\x00\x06", kXR_close,
                                   FH0, b"\x00" * 12, 0)),
    "pgread":   (True, struct.pack("!2sH4sqiI", b"\x00\x07", kXR_pgread,
                                   FH0, 0, 4096, 0)),
    "pgwrite":  (True, struct.pack("!2sH4sqiI", b"\x00\x08", kXR_pgwrite,
                                   FH0, 0, 0, 4) + b"data"),
    "readv":    (False, struct.pack("!2sH16sI", b"\x00\x09", kXR_readv,
                                    b"\x00" * 16, 16)
                        + struct.pack("!4siq", FH0, 16, 0)),
    "writev":   (False, struct.pack("!2sH16sI", b"\x00\x0a", kXR_writev,
                                    b"\x00" * 16, 20)
                        + struct.pack("!4siq", FH0, 4, 0) + b"data"),
    "fattr":    (False, struct.pack("!2sH4sBBB9sI", b"\x00\x0b", kXR_fattr,
                                    FH0, 2, 0, 0, b"\x00" * 9, 0)),
    "qcksum_fh": (False, struct.pack("!2sHH2s4s8sI", b"\x00\x0c", kXR_query,
                                     1, b"\x00" * 2, FH0, b"\x00" * 8, 0)),
}


def _assert_preopen_reply(op, strict, status, body):
    """A strict op must be kXR_FileNotOpen; a lax one any clean status."""
    if strict:
        assert status == kXR_error and _err_code(body) == kXR_FileNotOpen, (
            f"{op} pre-open: status={status}, err={_err_code(body)} "
            "(expected kXR_FileNotOpen)")
    else:
        assert status in (kXR_ok, kXR_error), (
            f"{op} pre-open: unexpected status={status}")


def _assert_link_state(op, strict, s):
    """Strict ops must leave the connection serviceable; a vector op with an
    invalid descriptor may legitimately answer and then drop the link
    (framing is unresynchronisable — see writev.c)."""
    if strict:
        assert _ping(s)[1] == kXR_ok, f"{op}: connection dead after pre-open op"
        return
    try:
        _ping(s)
    except (ConnectionError, OSError):
        pass


@pytest.mark.parametrize("op", sorted(_PREOPEN_OPS))
def test_preopen_handle_op_clean_error_no_crash(op):
    """Security-negative: a handle op before ANY open (NULL table) must be a
    clean error, never a worker crash."""
    strict, frame = _PREOPEN_OPS[op]
    s = _session()
    s.sendall(frame)
    sid, status, body = _resp(s)          # a crash shows up as ConnectionError
    _assert_preopen_reply(op, strict, status, body)
    _assert_link_state(op, strict, s)
    s.close()

    # A fresh session must still work (no worker was lost to a segfault).
    s2 = _session()
    assert _ping(s2)[1] == kXR_ok
    s2.close()
