"""XRootD wire-protocol CONFORMANCE tests — grounded in the C++ reference.

Motivation: the kXR_sigver-ack bug survived for a long time because our tests
checked our server against our OWN client — a consistent-but-non-standard pair.
These 20 tests instead assert what the XRootD C++ REFERENCE
(/tmp/brix-src/src) guarantees to ANY standard client, via a minimal raw-wire
client against a self-provisioned anon server. A failure here means this
implementation diverges from the protocol every other client/server speaks.

Each test cites the reference fact it pins (XProtocol.hh / XrdXrootdXeq.cc /
XrdXrootdResponse.cc / XrdXrootdProtocol.cc / XrdXrootdXeqPgrw.cc). Self-
provisioning — no shared fleet, no network.

Run:  PYTHONPATH=tests pytest tests/test_brix_conformance.py -v
"""

import os
import socket
import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST

BIND = BIND_HOST
PORT = None  # bound to the harness-assigned dynamic port by the `server` fixture

# opcodes
kXR_query, kXR_close, kXR_dirlist = 3001, 3003, 3004
kXR_protocol, kXR_login, kXR_open, kXR_ping, kXR_read = 3006, 3007, 3010, 3011, 3013
kXR_stat, kXR_statx, kXR_readv = 3017, 3022, 3025
kXR_pgread, kXR_sigver = 3030, 3029
# response status
kXR_ok, kXR_oksofar = 0, 4000
kXR_error, kXR_redirect, kXR_status = 4003, 4004, 4007
# error codes (XErrorCode)
kXR_ArgInvalid, kXR_InvalidRequest, kXR_NotFound = 3000, 3006, 3011
# flags / options
kXR_open_read = 0x0010
kXR_Qconfig = 7
kXR_isServer = 0x00000001
kXR_isDir, kXR_readable = 2, 16
kXR_SHA256_sig = 0x01

KNOWN = "/known.bin"
KNOWN_SIZE = 8192

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrootd-conformance")]


# --------------------------------------------------------------------------- #
# raw-wire client
# --------------------------------------------------------------------------- #
def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid, status, dlen = h[0:2], struct.unpack("!H", h[2:4])[0], struct.unpack("!I", h[4:8])[0]
    return sid, status, (_recv_exact(s, dlen) if dlen else b"")


def _connect():
    s = socket.create_connection((BIND, PORT), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    return s  # handshake reply read by the caller (test 8) or _login


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"conf\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session():
    s = _connect()
    _, st, _ = _resp(s)            # handshake reply
    assert st == kXR_ok
    _login(s)
    return s


def _ping(s, sid=b"\x00\x0f"):
    s.sendall(struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0))


def _stat(s, path, sid=b"\x00\x02"):
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_stat, b"\x00" * 16, len(p)) + p)


def _statx(s, paths, sid=b"\x00\x12"):
    p = "\n".join(paths).encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_statx, b"\x00" * 16, len(p)) + p)


def _query(s, infotype, arg, sid=b"\x00\x07"):
    a = arg.encode()
    s.sendall(struct.pack("!2sHH14sI", sid, kXR_query, infotype, b"\x00" * 14, len(a)) + a)


def _dirlist(s, path, sid=b"\x00\x04"):
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", sid, kXR_dirlist, b"\x00" * 16, len(p)) + p)


def _open(s, path, options=kXR_open_read, sid=b"\x00\x03"):
    p = path.encode()
    s.sendall(struct.pack("!2sHHH12sI", sid, kXR_open, 0, options, b"\x00" * 12, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _read(s, fhandle, offset, rlen, sid=b"\x00\x06"):
    s.sendall(struct.pack("!2sH4sqiI", sid, kXR_read, fhandle, offset, rlen, 0))


def _readv(s, segs, sid=b"\x00\x05"):
    payload = b"".join(struct.pack("!4siq", fh, rl, off) for fh, rl, off in segs)
    s.sendall(struct.pack("!2sH16sI", sid, kXR_readv, b"\x00" * 16, len(payload)) + payload)


def _pgread(s, fhandle, offset, rlen, sid=b"\x00\x08"):
    s.sendall(struct.pack("!2sH4sqiI", sid, kXR_pgread, fhandle, offset, rlen, 0))


def _close(s, fhandle, sid=b"\x00\x0e"):
    s.sendall(struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0))


def _sigver(s, expectrid, seqno=1, sid=b"\x00\x09"):
    s.sendall(struct.pack("!2sHHBBQB3sI", sid, kXR_sigver, expectrid, 0, 0,
                          seqno, kXR_SHA256_sig, b"\x00\x00\x00", 32) + b"\x00" * 32)


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


# --------------------------------------------------------------------------- #
# self-provisioned anon server
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="function")
def server(lifecycle, tmp_path_factory):
    global PORT
    base = tmp_path_factory.mktemp("conf")
    data = base / "data"
    (data / "sub").mkdir(parents=True)
    (data / "known.bin").write_bytes(bytes((i * 31 + 7) & 0xff for i in range(KNOWN_SIZE)))
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrootd-conformance",
        template="nginx_xrootd_conformance_self.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
    ))
    PORT = ep.port
    yield {"data": str(data)}


def _open_known(s):
    st, body = _open(s, KNOWN)
    assert st == kXR_ok, f"open {KNOWN} failed (status {st}, err {_err(body)})"
    return body[0:4]   # ServerResponseBody_Open.fhandle (4 bytes, XProtocol.hh:1090)


# =========================================================================== #
# THE 20 CONFORMANCE TESTS
# =========================================================================== #

# 1. streamid echoed verbatim, never byte-swapped (XrdXrootdResponse.cc:469-486).
def test_01_streamid_echoed_verbatim(server):
    s = _session()
    try:
        _ping(s, sid=b"\xab\xcd")
        sid, st, _ = _resp(s)
        assert sid == b"\xab\xcd", f"streamid not echoed verbatim: {sid!r}"
        assert st == kXR_ok
    finally:
        s.close()


# 2. kXR_ping -> empty kXR_ok (XrdXrootdXeq.cc:1815-1825).
def test_02_ping_empty_ok(server):
    s = _session()
    try:
        _ping(s)
        _, st, body = _resp(s)
        assert st == kXR_ok and body == b"", f"ping: status={st} body={body!r}"
    finally:
        s.close()


# 3. Unknown opcode -> kXR_error / kXR_InvalidRequest (XrdXrootdProtocol.cc:608).
def test_03_unknown_opcode_invalidrequest(server):
    s = _session()
    try:
        s.sendall(struct.pack("!2sH16sI", b"\x00\x21", 9999, b"\x00" * 16, 0))
        _, st, body = _resp(s)
        assert st == kXR_error, f"unknown opcode status={st}"
        assert _err(body) == kXR_InvalidRequest, f"errnum={_err(body)} (want 3006)"
    finally:
        s.close()


# 4. A data op before login is rejected (XrdXrootdProtocol.cc:470-478).
def test_04_prelogin_rejected(server):
    s = _connect()
    try:
        _, st, _ = _resp(s)   # handshake reply (no login yet)
        _stat(s, KNOWN, sid=b"\x00\x22")
        try:
            _, st, body = _resp(s)
        except EOFError:
            return  # dropping the link is also conformant
        assert st == kXR_error, f"pre-login stat not rejected (status={st})"
    finally:
        s.close()


# 5. Negative dlen -> kXR_ArgInvalid (XrdXrootdProtocol.cc:404-407).
def test_05_negative_dlen_arginvalid(server):
    s = _session()
    try:
        s.sendall(struct.pack("!2sH16si", b"\x00\x23", kXR_ping, b"\x00" * 16, -1))
        try:
            _, st, body = _resp(s)
        except EOFError:
            return  # link drop after the error is conformant
        assert st == kXR_error and _err(body) == kXR_ArgInvalid, \
            f"negative dlen: status={st} errnum={_err(body)}"
    finally:
        s.close()


# 6. Error body = [errnum:4 BE][msg][NUL]; ENOENT -> kXR_NotFound (XProtocol.hh:1072,
#    XrdXrootdResponse.cc:238-262, mapError ENOENT->kXR_NotFound).
def test_06_error_body_format(server):
    s = _session()
    try:
        _stat(s, "/does/not/exist", sid=b"\x00\x24")
        _, st, body = _resp(s)
        assert st == kXR_error, f"stat ENOENT status={st}"
        assert _err(body) == kXR_NotFound, f"errnum={_err(body)} (want 3011)"
        assert body.endswith(b"\x00"), "error message not NUL-terminated"
    finally:
        s.close()


# 7. kXR_sigver gets NO response on success (XrdXrootdProtocol.cc:650-651).
def test_07_sigver_no_response(server):
    s = _session()
    try:
        _sigver(s, expectrid=kXR_ping, sid=b"\x00\x09")
        _ping(s, sid=b"\x00\x0f")
        sid, st, body = _resp(s)
        assert sid == b"\x00\x0f" and st == kXR_ok and body == b"", \
            f"first response after sigver+ping is not the ping reply " \
            f"(sid={sid!r} status={st}) — server likely acked the sigver"
    finally:
        s.close()


# 8. Handshake reply: protover + server type DataServer (XrdXrootdProtocol.cc:297-330).
def test_08_handshake_reply(server):
    s = _connect()
    try:
        _, st, body = _resp(s)
        assert st == kXR_ok and len(body) == 8, f"handshake body len={len(body)}"
        protover, styp = struct.unpack("!II", body)
        assert protover == 0x00000520, f"protover=0x{protover:08x} (ref 0x00000520)"
        assert styp == 1, f"server type={styp} (want kXR_DataServer=1)"
    finally:
        s.close()


# 9. kXR_protocol reply: pval + flags with kXR_isServer set (XProtocol.hh:1233, Xeq:2050).
def test_09_protocol_flags(server):
    s = _connect()
    try:
        _resp(s)  # handshake
        s.sendall(struct.pack("!2sHiB B 10sI", b"\x00\x10", kXR_protocol,
                              0x00000520, 0, 0, b"\x00" * 10, 0))
        _, st, body = _resp(s)
        assert st == kXR_ok and len(body) >= 8, f"protocol resp len={len(body)}"
        pval, flags = struct.unpack("!iI", body[0:8])
        assert flags & kXR_isServer, f"kXR_isServer not set in flags 0x{flags:08x}"
    finally:
        s.close()


# 10. Anon login reply carries a 16-byte session id (XProtocol.hh:1081).
def test_10_login_sessid_16(server):
    s = _connect()
    try:
        _resp(s)
        s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                              os.getpid() & 0x7fffffff, b"conf\x00\x00\x00\x00",
                              0, 0, 0, 0, 0))
        _, st, body = _resp(s)
        assert st == kXR_ok and len(body) >= 16, f"login body len={len(body)} (<16)"
    finally:
        s.close()


# 11. kXR_stat -> "id size flags modtime" (>=4 int fields, size matches) (StatGen, Xeq:807).
def test_11_stat_format(server):
    s = _session()
    try:
        _stat(s, KNOWN, sid=b"\x00\x02")
        _, st, body = _resp(s)
        assert st == kXR_ok, f"stat status={st} err={_err(body)}"
        fields = body.rstrip(b"\x00").decode("ascii", "replace").split()
        assert len(fields) >= 4, f"statinfo has {len(fields)} fields (<4): {fields}"
        assert all(f.lstrip("-").isdigit() for f in fields[:4]), f"non-int fields: {fields[:4]}"
        assert int(fields[1]) == KNOWN_SIZE, f"size field={fields[1]} (want {KNOWN_SIZE})"
    finally:
        s.close()


# 12. stat of a directory sets kXR_isDir (XProtocol.hh:1260, StatGen flags).
def test_12_stat_dir_flag(server):
    s = _session()
    try:
        _stat(s, "/sub", sid=b"\x00\x02")
        _, st, body = _resp(s)
        assert st == kXR_ok, f"stat /sub status={st}"
        flags = int(body.rstrip(b"\x00").decode("ascii", "replace").split()[2])
        assert flags & kXR_isDir, f"kXR_isDir not set for a directory (flags={flags})"
    finally:
        s.close()


# 13. stat of a readable file sets kXR_readable (StatGen flags).
def test_13_stat_readable_flag(server):
    s = _session()
    try:
        _stat(s, KNOWN, sid=b"\x00\x02")
        _, st, body = _resp(s)
        flags = int(body.rstrip(b"\x00").decode("ascii", "replace").split()[2])
        assert flags & kXR_readable, f"kXR_readable not set (flags={flags})"
    finally:
        s.close()


# 14. kXR_statx -> one flag byte per path (XrdXrootdXeq.cc:3194-3203).
def test_14_statx_one_byte_per_path(server):
    s = _session()
    try:
        _statx(s, [KNOWN, "/sub"], sid=b"\x00\x12")
        _, st, body = _resp(s)
        assert st == kXR_ok, f"statx status={st} err={_err(body)}"
        assert len(body) == 2, f"statx returned {len(body)} bytes for 2 paths (want 2)"
        assert body[1] & kXR_isDir, "second path (/sub) should have kXR_isDir"
    finally:
        s.close()


# 15. kXR_query Qconfig "tpc" -> newline-terminated text, not an error (do_Qconf:2238).
def test_15_query_tpc_newline(server):
    s = _session()
    try:
        _query(s, kXR_Qconfig, "tpc", sid=b"\x00\x07")
        _, st, body = _resp(s)
        assert st == kXR_ok, f"query tpc status={st} err={_err(body)}"
        assert body.rstrip(b"\x00").endswith(b"\n"), f"query tpc not newline-terminated: {body!r}"
    finally:
        s.close()


# 16. kXR_query Qconfig "bind_max" -> integer + newline (do_Qconf:2168).
def test_16_query_bindmax_int(server):
    s = _session()
    try:
        _query(s, kXR_Qconfig, "bind_max", sid=b"\x00\x07")
        _, st, body = _resp(s)
        assert st == kXR_ok, f"query bind_max status={st} err={_err(body)}"
        txt = body.rstrip(b"\x00").decode("ascii", "replace").strip()
        assert txt.isdigit(), f"bind_max not an integer: {txt!r}"
    finally:
        s.close()


# 17. kXR_dirlist "/" -> newline-separated names, includes the known file (do_Dirlist:784).
def test_17_dirlist_names(server):
    s = _session()
    try:
        _dirlist(s, "/", sid=b"\x00\x04")
        chunks = b""
        while True:
            _, st, body = _resp(s)
            assert st in (kXR_ok, kXR_oksofar), f"dirlist status={st} err={_err(body)}"
            chunks += body
            if st == kXR_ok:
                break
        names = chunks.replace(b"\x00", b"\n").decode("ascii", "replace").split()
        assert "known.bin" in names, f"known.bin not in dirlist: {names}"
        assert "sub" in names, f"sub not in dirlist: {names}"
    finally:
        s.close()


# 18. kXR_open (read) -> 4-byte file handle, no extra bytes (ServerResponseBody_Open, Xeq:1501).
def test_18_open_returns_4byte_handle(server):
    s = _session()
    try:
        st, body = _open(s, KNOWN)
        assert st == kXR_ok, f"open status={st} err={_err(body)}"
        assert len(body) == 4, f"open response is {len(body)} bytes (want 4 = fhandle only)"
    finally:
        s.close()


# 19. kXR_read -> raw data bytes, kXR_ok, content matches (do_ReadAll:2683).
def test_19_read_raw_data(server):
    s = _session()
    try:
        fh = _open_known(s)
        _read(s, fh, 0, 1024)
        data = b""
        while True:
            _, st, body = _resp(s)
            assert st in (kXR_ok, kXR_oksofar), f"read status={st} err={_err(body)}"
            data += body
            if st == kXR_ok:
                break
        assert len(data) == 1024, f"read returned {len(data)} bytes (want 1024)"
        expect = bytes((i * 31 + 7) & 0xff for i in range(1024))
        assert data == expect, "read data does not match file content"
    finally:
        s.close()


# 20. kXR_readv -> each segment prefixed by a 16-byte readahead_list header
#     (fhandle/rlen/offset) then data (XProtocol.hh:694, do_ReadV:2880).
def test_20_readv_segment_framing(server):
    s = _session()
    try:
        fh = _open_known(s)
        segs = [(fh, 512, 0), (fh, 256, 4096)]
        _readv(s, segs)
        _, st, body = _resp(s)
        assert st in (kXR_ok, kXR_oksofar), f"readv status={st} err={_err(body)}"
        # Parse: [readahead_list(16)][data] repeated.
        off, seen = 0, []
        while off + 16 <= len(body):
            rfh = body[off:off + 4]
            rlen = struct.unpack("!i", body[off + 4:off + 8])[0]
            roff = struct.unpack("!q", body[off + 8:off + 16])[0]
            seen.append((rlen, roff))
            off += 16 + rlen
        assert (512, 0) in seen and (256, 4096) in seen, \
            f"readv segment headers wrong: {seen} (want rlen/offset 512/0 and 256/4096)"
    finally:
        s.close()
