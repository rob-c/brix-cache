# brix-remote-skip
"""
Raw-protocol tests for the kXR_pgwrite CSE (checksum-error) retransmit machine.

When a kXR_pgwrite page fails its CRC32c the server now follows the stock
"accept-then-correct" protocol instead of hard-failing:

  1. Every page is verified (not just up to the first bad one) and ALL pages —
     good and bad — are written to disk.
  2. The reply is a SUCCESS kXR_status frame whose status-body dlen advertises a
     ServerResponseBody_pgWrCSE trailer: cseCRC[4] dlFirst[2] dlLast[2] then a
     big-endian int64 vector of the corrupt pages' file offsets.
  3. The client resends each bad page with reqflags |= kXR_pgRetry (0x01).
  4. The server tracks uncorrected pages per open file (the "Fob"); a clean
     retry clears the page.
  5. kXR_close returns kXR_ChkSumErr while any page is still uncorrected — this
     close gate is what keeps a committed file from holding known-corrupt bytes.

These tests drive the shared anonymous fleet (root:// on 11094) over raw
sockets so the full machine — CSE reply shape, write-then-correct on disk, the
Fob retry path, and the close gate — can be exercised end to end.

Run:
    PYTHONPATH=tests pytest tests/test_pgwrite_cse.py -v
"""

import glob
import os
import struct
import socket

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_ANON_RESUME_OFF_PORT,
    SERVER_HOST,
)


# --------------------------------------------------------------------------- #
# Protocol constants
# --------------------------------------------------------------------------- #
kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_close     = 3003
kXR_pgwrite   = 3026

kXR_ok        = 0
kXR_error     = 4003
kXR_status    = 4007

kXR_ArgInvalid  = 3000
kXR_ChkSumErr   = 3019
kXR_TooManyErrs = 3033

kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0002

kXR_pgRetry   = 0x01
kXR_pgPageSZ  = 4096
kXR_pgMaxEpr  = 128     # max bad pages reportable per request (server cap)

_HOST = SERVER_HOST
_PORT = NGINX_ANON_PORT
# Stock direct-to-disk endpoint (brix_upload_resume off).  pgwrite
# accept-then-correct lands bytes on the FINAL object immediately here, so the
# tests that inspect on-disk state out-of-band MID-write must target this port;
# on the resume-ON _PORT those bytes are staged in a .xrdresume.*.part until
# close (see TestWriteThenCorrectResumeOn for the resume-ON commit coverage).
_RESUME_OFF_PORT = NGINX_ANON_RESUME_OFF_PORT


# --------------------------------------------------------------------------- #
# CRC32c (Castagnoli, reversed poly 0x82F63B78)
# --------------------------------------------------------------------------- #
def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# Wire helpers
# --------------------------------------------------------------------------- #
def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError(f"socket closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    """Read a plain response (hdr.dlen bytes). Use only for open/close."""
    hdr = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _handshake_login(host=_HOST, port=_PORT):
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"handshake failed: {status}"
    sock.sendall(struct.pack("!2sHI2s10xI",
                             b"\x00\x01", kXR_protocol, 0x00000520, b"\x02\x03", 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_protocol failed: {status}"
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", kXR_login, os.getpid() & 0xFFFFFFFF,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_login failed: {status}"
    return sock


def _open(sock, path: bytes, flags=kXR_open_updt | kXR_delete, mode=0o644):
    sock.sendall(struct.pack("!2sHHH2s6s4sI",
                             b"\x00\x02", kXR_open, mode, flags,
                             b"\x00\x00", b"\x00" * 6, b"\x00" * 4, len(path)) + path)
    status, body = _read_response(sock)
    assert status == kXR_ok, f"kXR_open({path}, {flags:#x}) failed: {status}"
    return body[:4]


def _close(sock, fhandle):
    """Send kXR_close, return (status, errcode|None)."""
    sock.sendall(struct.pack("!2sH4s12sI",
                             b"\x00\x09", kXR_close, fhandle, b"\x00" * 12, 0))
    status, body = _read_response(sock)
    errcode = struct.unpack("!I", body[:4])[0] if (status == kXR_error and len(body) >= 4) else None
    return status, errcode


# --------------------------------------------------------------------------- #
# Page-mode helpers
# --------------------------------------------------------------------------- #
def page_lengths(offset, total):
    """Per-page fragment lengths for `total` bytes placed at file `offset`."""
    lens = []
    cur, rem = offset, total
    while rem > 0:
        take = min(rem, kXR_pgPageSZ - (cur % kXR_pgPageSZ))
        lens.append(take)
        cur += take
        rem -= take
    return lens


def page_offset(offset, total, index):
    """Absolute file offset of page `index`."""
    return offset + sum(page_lengths(offset, total)[:index])


def build_payload(data, offset, corrupt_crc=(), corrupt_data=()):
    """Build a kXR_pgwrite payload.

    corrupt_crc:  page indices whose CRC field is flipped (data stays intact —
                  the data the server writes still equals the original).
    corrupt_data: page indices whose data is mutated while the CRC stays the
                  original's — the bytes the server writes are genuinely wrong
                  until corrected (models in-transit corruption).
    """
    corrupt_crc = set(corrupt_crc)
    corrupt_data = set(corrupt_data)
    out = bytearray()
    cur, pos, idx = offset, 0, 0
    while pos < len(data):
        room = kXR_pgPageSZ - (cur % kXR_pgPageSZ)
        chunk = bytearray(data[pos:pos + room])
        crc = _crc32c(bytes(chunk))
        if idx in corrupt_data:
            chunk[0] ^= 0xFF              # data now mismatches its CRC
        if idx in corrupt_crc:
            crc = (crc ^ 0xDEADBEEF) & 0xFFFFFFFF
        out += struct.pack("!I", crc)
        out += bytes(chunk)
        pos += len(chunk)
        cur += len(chunk)
        idx += 1
    return bytes(out)


def send_pgwrite(sock, fhandle, offset, payload, reqflags=0):
    """Send a raw kXR_pgwrite and read the kXR_status (+ CSE trailer) reply.

    Returns (status, info_offset, cse_bytes). For kXR_error, returns
    ('error', errcode, msg_bytes).
    """
    sock.sendall(struct.pack("!2sH4sqBBHi",
                             b"\x00\x03", kXR_pgwrite, fhandle, offset,
                             0, reqflags & 0xFF, 0, len(payload)) + payload)
    hdr = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", hdr)
    if status == kXR_error:
        body = _recv_exact(sock, dlen) if dlen else b""
        errcode = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
        return "error", errcode, body[4:]
    assert status == kXR_status, f"expected kXR_status, got {status}"
    body = _recv_exact(sock, dlen)
    assert len(body) >= 24, f"status body too short: {len(body)}"
    bdy_dlen, = struct.unpack("!i", body[12:16])
    info_off, = struct.unpack("!q", body[16:24])
    cse = _recv_exact(sock, bdy_dlen) if bdy_dlen > 0 else b""
    return kXR_status, info_off, cse


def parse_cse(cse):
    """Parse the CSE trailer -> (cse_crc, dlFirst, dlLast, [offsets], crc_ok)."""
    assert len(cse) >= 8, f"CSE trailer too short: {len(cse)}"
    cse_crc, dl_first, dl_last = struct.unpack("!Ihh", cse[:8])
    rest = cse[8:]
    n = len(rest) // 8
    offsets = list(struct.unpack("!" + "q" * n, rest[:n * 8]))
    crc_ok = (_crc32c(cse[4:]) == cse_crc)
    return cse_crc, dl_first, dl_last, offsets, crc_ok


def single_page_retry_payload(data, offset, total, index):
    """A correct single-page payload for page `index` of an original write."""
    pgoff = page_offset(offset, total, index)
    rel = pgoff - offset
    plen = page_lengths(offset, total)[index]
    return build_payload(data[rel:rel + plen], pgoff), pgoff


def disk_path(remote):
    return os.path.join(DATA_ROOT, remote.lstrip("/"))


# --------------------------------------------------------------------------- #
# 1) CSE reply shape
# --------------------------------------------------------------------------- #
class TestCSEReplyShape:
    def test_clean_write_has_empty_cse(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_clean.bin")
            st, _off, cse = send_pgwrite(sock, fh, 0, build_payload(b"x" * 500, 0))
            assert st == kXR_status
            assert cse == b"", "clean write must carry no CSE trailer"
            _close(sock, fh)
        finally:
            sock.close()

    def test_single_corrupt_page_lists_offset(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_single.bin")
            data = b"A" * 1000
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=[0]))
            assert st == kXR_status, f"want success+CSE, got {st}"
            crc, dl_first, dl_last, offs, crc_ok = parse_cse(cse)
            assert crc_ok, "cseCRC mismatch"
            assert offs == [0], offs
            assert dl_first == dl_last == 1000
        finally:
            sock.close()

    @pytest.mark.parametrize("bad", [0, 1, 2])
    def test_corrupt_position_in_three_pages(self, bad):
        sock = _handshake_login()
        try:
            fh = _open(sock, f"/_cse_3p_{bad}.bin".encode())
            data = os.urandom(kXR_pgPageSZ * 2 + 512)   # 3 pages (last short)
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=[bad]))
            assert st == kXR_status
            _crc, _f, _l, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [page_offset(0, len(data), bad)], offs
        finally:
            sock.close()

    def test_multiple_corrupt_pages_ordered(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_multi.bin")
            data = os.urandom(kXR_pgPageSZ * 4)         # 4 full pages
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=[0, 2, 3]))
            assert st == kXR_status
            _crc, dl_first, dl_last, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [page_offset(0, len(data), i) for i in (0, 2, 3)], offs
            assert dl_first == kXR_pgPageSZ and dl_last == kXR_pgPageSZ
        finally:
            sock.close()

    def test_all_pages_corrupt(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_all.bin")
            data = os.urandom(kXR_pgPageSZ * 3 + 10)
            npages = len(page_lengths(0, len(data)))
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=range(npages)))
            assert st == kXR_status
            _crc, _f, dl_last, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [page_offset(0, len(data), i) for i in range(npages)]
            assert dl_last == 10, "last page is a short final fragment"
        finally:
            sock.close()

    def test_unaligned_start_offset(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_unaligned.bin")
            data = os.urandom(300)
            st, _off, cse = send_pgwrite(sock, fh, 100,
                                         build_payload(data, 100, corrupt_crc=[0]))
            assert st == kXR_status
            _crc, dl_first, _l, offs, crc_ok = parse_cse(cse)
            assert crc_ok
            assert offs == [100], offs
            assert dl_first == 300
        finally:
            sock.close()

    def test_too_many_errors_per_request(self):
        """>128 corrupt pages in one request → kXR_TooManyErrs (no CSE list)."""
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_toomany.bin")
            npages = kXR_pgMaxEpr + 1
            data = os.urandom(kXR_pgPageSZ * npages)
            st, err, _msg = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_crc=range(npages)))
            assert st == "error", f"expected error, got {st}"
            assert err == kXR_TooManyErrs, f"expected kXR_TooManyErrs, got {err}"
        finally:
            sock.close()

    def test_malformed_payload_still_arginvalid(self):
        """A truncated payload (no room for a page after the CRC) → kXR_ArgInvalid."""
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_malformed.bin")
            st, err, _msg = send_pgwrite(sock, fh, 0, b"\x00\x00\x00\x00")  # 4B = CRC only
            assert st == "error"
            assert err == kXR_ArgInvalid, f"expected kXR_ArgInvalid, got {err}"
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# 2) Write-then-correct on disk
# --------------------------------------------------------------------------- #
class TestWriteThenCorrect:
    """Accept-then-correct ON DISK (stock direct-to-disk semantics).

    These inspect the final object out-of-band MID-write, so they run against
    the upload_resume=OFF endpoint where pgwrite lands bytes on the final file
    immediately.  The resume=ON commit path is covered by
    TestWriteThenCorrectResumeOn below.
    """

    def test_corrupt_bytes_land_on_disk_then_fixed(self):
        remote = "_cse_disk_fix.bin"
        sock = _handshake_login(port=_RESUME_OFF_PORT)
        try:
            fh = _open(sock, f"/{remote}".encode())
            good = os.urandom(2000)
            # Page 0 data arrives mutated (CRC of the original) → server writes
            # the wrong bytes and reports the page.
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(good, 0, corrupt_data=[0]))
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and offs == [0]

            # The corrupt bytes are on disk (accept-then-correct, not hold-back).
            on_disk = open(disk_path(remote), "rb").read()
            assert on_disk != good, "corrupt page should be on disk before retry"

            # Resend page 0 with correct data → clean status, Fob cleared.
            retry, pgoff = single_page_retry_payload(good, 0, len(good), 0)
            st, _off, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b"", "retry should verify clean"

            st, _err = _close(sock, fh)
            assert st == kXR_ok, "close should succeed once corrected"
        finally:
            sock.close()
        assert open(disk_path(remote), "rb").read() == good, "disk not fixed by retry"
        os.unlink(disk_path(remote))

    def test_good_pages_intact_alongside_bad(self):
        remote = "_cse_good_intact.bin"
        sock = _handshake_login(port=_RESUME_OFF_PORT)
        try:
            fh = _open(sock, f"/{remote}".encode())
            data = os.urandom(kXR_pgPageSZ * 3)
            # Corrupt only page 1's data; pages 0 and 2 must be correct on disk.
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(data, 0, corrupt_data=[1]))
            assert st == kXR_status
            on_disk = open(disk_path(remote), "rb").read()
            assert on_disk[0:kXR_pgPageSZ] == data[0:kXR_pgPageSZ]
            assert on_disk[2 * kXR_pgPageSZ:] == data[2 * kXR_pgPageSZ:]
            # correct page 1
            retry, pgoff = single_page_retry_payload(data, 0, len(data), 1)
            st, _o, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b""
            _close(sock, fh)
        finally:
            sock.close()
        assert open(disk_path(remote), "rb").read() == data
        os.unlink(disk_path(remote))


class TestWriteThenCorrectResumeOn:
    """Same accept-then-correct flow, but on the upload_resume=ON endpoint.

    With staging, the in-flight (and corrected) bytes live in a
    .xrdresume.*.part until close — they are NOT visible at the final path
    out-of-band mid-write — so the on-config contract is verified through the
    wire (the CSE status + close gate) and the FINAL committed object AFTER a
    clean close.  This proves pgwrite + upload_resume are compatible: the
    corrected bytes are what gets committed.
    """

    def test_corrupt_then_correct_commits_fixed_bytes(self):
        remote = "_cse_resume_on_fix.bin"
        sock = _handshake_login(port=_PORT)
        try:
            fh = _open(sock, f"/{remote}".encode())
            good = os.urandom(2000)
            # Page 0 arrives corrupt → reported via CSE.  Bytes are staged in the
            # .part (not the final path), so we do NOT inspect disk mid-write.
            st, _off, cse = send_pgwrite(sock, fh, 0,
                                         build_payload(good, 0, corrupt_data=[0]))
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and offs == [0]
            assert not os.path.exists(disk_path(remote)), \
                "resume=ON must stage writes, not touch the final path mid-write"

            # Correct page 0 → clean status, close gate opens.
            retry, pgoff = single_page_retry_payload(good, 0, len(good), 0)
            st, _off, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b"", "retry should verify clean"

            st, _err = _close(sock, fh)
            assert st == kXR_ok, "close should succeed once corrected"
        finally:
            sock.close()
        # The staged partial was synchronously committed onto the final path on
        # close, carrying the CORRECTED bytes (not the corrupt ones).
        assert open(disk_path(remote), "rb").read() == good, \
            "resume=ON commit must publish the corrected bytes"
        assert not glob.glob(disk_path(remote) + "*.xrdresume.*.part"), \
            "no resume partial should survive a clean close"
        os.unlink(disk_path(remote))


# --------------------------------------------------------------------------- #
# 3) Fob / retry state machine
# --------------------------------------------------------------------------- #
class TestFobRetry:
    def test_retry_clears_one_of_two(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_two_clear_one.bin")
            data = os.urandom(kXR_pgPageSZ * 2)
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_data=[0, 1]))
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and len(offs) == 2

            # Correct page 1 only; page 0 stays uncorrected → close still gated.
            retry, pgoff = single_page_retry_payload(data, 0, len(data), 1)
            st, _o, cse = send_pgwrite(sock, fh, pgoff, retry, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b""

            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr, \
                "one page still uncorrected → close must fail"

            # Now correct page 0 and close cleanly.
            retry0, pg0 = single_page_retry_payload(data, 0, len(data), 0)
            st, _o, cse = send_pgwrite(sock, fh, pg0, retry0, reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b""
            st, _err = _close(sock, fh)
            assert st == kXR_ok
        finally:
            sock.close()

    def test_retry_of_unregistered_offset_is_normal_write(self):
        """A pgRetry for a page that was never bad is treated as a normal write
        (succeeds, no error, Fob untouched) — a forged/stale retry can't poison
        the registry or the close gate."""
        remote = "_cse_stray_retry.bin"
        sock = _handshake_login()
        try:
            fh = _open(sock, f"/{remote}".encode())
            data = os.urandom(1000)
            # Stray retry on a clean handle (no prior CSE).
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0), reqflags=kXR_pgRetry)
            assert st == kXR_status and cse == b"", "stray retry should just write"
            st, _err = _close(sock, fh)
            assert st == kXR_ok, "stray retry must not register a Fob entry"
        finally:
            sock.close()
        assert open(disk_path(remote), "rb").read() == data
        os.unlink(disk_path(remote))

    def test_retry_spanning_two_pages_rejected(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_retry_2page.bin")
            data = os.urandom(kXR_pgPageSZ + 100)   # spans two pages
            st, err, _msg = send_pgwrite(sock, fh, 0, build_payload(data, 0),
                                         reqflags=kXR_pgRetry)
            assert st == "error", f"expected error, got {st}"
            assert err == kXR_ArgInvalid, f"expected kXR_ArgInvalid, got {err}"
        finally:
            sock.close()

    def test_retry_still_bad_keeps_offset(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_retry_stillbad.bin")
            data = os.urandom(900)
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_data=[0]))
            assert st == kXR_status
            # Retry but STILL corrupt → CSE again, same offset stays registered.
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_data=[0]),
                                       reqflags=kXR_pgRetry)
            assert st == kXR_status
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok and offs == [0]
            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# 4) Close gate (integrity core)
# --------------------------------------------------------------------------- #
class TestCloseGate:
    def test_close_blocked_with_uncorrected(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_close_block.bin")
            data = os.urandom(1000)
            st, _o, _cse = send_pgwrite(sock, fh, 0,
                                        build_payload(data, 0, corrupt_crc=[0]))
            assert st == kXR_status
            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr, (st, err)
        finally:
            sock.close()

    def test_close_message_reports_count(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_close_count.bin")
            data = os.urandom(kXR_pgPageSZ * 3)
            st, _o, _cse = send_pgwrite(sock, fh, 0,
                                        build_payload(data, 0, corrupt_crc=[0, 1, 2]))
            assert st == kXR_status
            # Inspect the close error message text for the count "3".
            sock.sendall(struct.pack("!2sH4s12sI",
                                     b"\x00\x09", kXR_close, fh, b"\x00" * 12, 0))
            status, body = _read_response(sock)
            assert status == kXR_error
            msg = body[4:].split(b"\x00", 1)[0]
            assert b"3" in msg, f"close message should report 3 errors: {msg!r}"
        finally:
            sock.close()

    def test_clean_write_closes_ok(self):
        sock = _handshake_login()
        try:
            fh = _open(sock, b"/_cse_clean_close.bin")
            st, _o, cse = send_pgwrite(sock, fh, 0, build_payload(b"z" * 4096, 0))
            assert st == kXR_status and cse == b""
            st, _err = _close(sock, fh)
            assert st == kXR_ok
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# 5) Proxy passthrough — the CSE frame and close gate must survive the proxy's
#    two-phase kXR_status expansion unchanged.
# --------------------------------------------------------------------------- #
class TestProxyPassthrough:
    def _proxy_port(self):
        try:
            from settings import PROXY_PURE_NGINX_PROXY_PORT
            return PROXY_PURE_NGINX_PROXY_PORT
        except Exception:
            return None

    def test_cse_and_close_gate_through_proxy(self):
        port = self._proxy_port()
        if port is None:
            pytest.skip("no pure-nginx proxy port configured")
        try:
            sock = _handshake_login(_HOST, port)
        except OSError:
            pytest.skip(f"proxy not listening on {port}")
        try:
            fh = _open(sock, b"/_cse_proxy.bin")
            data = os.urandom(kXR_pgPageSZ * 2)
            st, _o, cse = send_pgwrite(sock, fh, 0,
                                       build_payload(data, 0, corrupt_crc=[0, 1]))
            assert st == kXR_status, f"proxy must pass the CSE frame, got {st}"
            _c, _f, _l, offs, ok = parse_cse(cse)
            assert ok, "cseCRC must survive the proxy intact"
            assert offs == [0, kXR_pgPageSZ], offs
            # The close gate must propagate through the proxy.
            st, err = _close(sock, fh)
            assert st == kXR_error and err == kXR_ChkSumErr, (st, err)
        finally:
            sock.close()
