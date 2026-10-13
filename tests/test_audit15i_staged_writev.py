"""
test_audit15i_staged_writev.py — kXR_writev's handle-admission guard
(testsuite-combinatorial-coverage-audit 2026-08-15, §B2.13's staged-writer
arm, run at last).

§B2.13 (io_uring x tiers) was authored in tranche 5 and had never executed:
the default test binary is built without liburing, so all five of its tests
skipped and the row stayed open across three tranches.  Rebuilt with
BRIX_ENABLE_IO_URING=1 (liburing 2.12 is present on this host) the row runs —
four pass and the staged-writer arm fails.  This file is the isolation: the
SAME topology with no `brix_io_uring` anywhere reproduces the failure exactly,
so the ring is not the cause and the finding belongs to kXR_writev.

To run §B2.13 itself, point the harness at a liburing-enabled binary:

    BRIX_ENABLE_IO_URING=1 ./configure <the usual args> && make -j$(nproc)
    TEST_NGINX_BIN=<that objs/nginx> \\
        PYTHONPATH=tests pytest tests/test_audit15e_uring_tiers.py -v

What the guard promises (writev.c): "all-or-nothing handle admission
for the vector … INVARIANT — a bad handle in a later segment must never leave
earlier segments already written; admitting the whole vector up front makes
the write all-or-nothing."  Neither half holds.

DEFECT CANDIDATE #29 [RESOLVED] — kXR_writev used to reject the phase-70
whole-object staged writer because its handle has no local descriptor.  Handle
admission now uses the canonical write-handle validator, staged vectors append
through the staged writer, and close (or `kXR_wv_doSync`) commits one PUT.

DEFECT CANDIDATE #30 [RESOLVED — the pins below now assert the single answer] —
the refusal was not terminal: one kXR_writev was answered TWICE.
writev_validate_handles() reported its failure with
`return brix_send_error(...)`, and brix_send_error() returns
brix_queue_response()'s NGX_OK once the error frame is queued
(src/protocols/root/response/basic.c:65-96).  Its caller at writev.c tested
`rc != NGX_OK` to decide whether the vector was admitted, so a *successfully
sent* rejection read as "admitted" and the write proceeded anyway — into
`ctx->files[idx].fd`, which is exactly the descriptor the guard just rejected.
A second frame with the same streamid followed the first — a staged handle
(fd < 0) and a read-only handle both produced kXR_IOError "writev I/O error at
seg 0: Bad file descriptor" — and from then on every reply the client read
belonged to the previous request.  The fix makes writev_validate_handles()
return NGX_DONE on a refusal (writev.c) so the caller stops after the one error
frame; the pins below assert exactly that single answer.

The framing guard three lines earlier is the control that makes this a defect
rather than a house style: a descriptor block that is not a whole number of
16-byte descriptors is answered once, and the link is dropped.

DEFECT CANDIDATE #31 [RESOLVED with #30] — because #30's rejection was
discarded, an out-of-range file handle was used to index ctx->files[] anyway.
BRIX_MAX_FILES is 16 (src/core/types/tunables.h:197) but fhandle[0] is a byte,
so a client may name slot 255.  writev_validate_handles() catches
`idx >= BRIX_MAX_FILES` — but its rejection was thrown away exactly like the
others, after which writev_write_segment() read `ctx->files[255].fd` and
`.sd_obj`, up to 239 entries past the end of a 16-entry array, and handed that
descriptor to the VFS write.  The phase79 false-positive suppression right above
it (writev.c) states the assumption the fall-through broke: "idx (0..255 from
fhandle[0]) was already bounds-checked against BRIX_MAX_FILES by
writev_validate_handles before the sync path runs".  It was — and the answer was
ignored.  The NGX_DONE fix (#30) restores that assumption: the refusal is now
terminal, so the OOB read is unreachable and the wire behaviour after the
refusal is fully defined — no second frame at all.

Cases:
  * success       — plain kXR_write through the staged writer commits the
    whole object to the origin byte-exact and drains the spool;
  * regression    — plain write plus kXR_writev compose on one staged handle
    and commit byte-exact (#29);
  * regression    — consecutive staged vectors each receive exactly one
    success response and commit in order (#29/#30);
  * regression    — a bare posix export, a handle that was never opened, and the
    same single refusal: neither the ring nor staging is involved (#30);
  * regression    — an out-of-range handle is refused kXR_FileNotOpen, answered
    once, and the worker keeps serving — the write path never indexes past
    ctx->files[] (#31);
  * security-neg  — a read-only handle's vector is refused kXR_NotAuthorized
    before any byte: the guard now keeps its own "before any byte is written"
    promise rather than leaning on the kernel's EBADF, and the bytes are
    unchanged;
  * security-neg  — the framing guard IS terminal: a malformed descriptor
    block is answered exactly once and the link is dropped.

Run:
    PYTHONPATH=tests pytest tests/test_audit15i_staged_writev.py -v
"""

import os
import socket
import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

from _test_conf_pgio_helpers import (
    _session, _open, _close, _read_response,
    kXR_ok, kXR_error, kXR_open_read, kXR_open_updt, kXR_new, kXR_delete,
)
from test_io_uring_runtime import kXR_writev, kXR_wv_doSync, kXR_ArgInvalid

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("audit15i_staged_writev"),
              pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                 reason="nginx binary not built")]

NAME = "lc-audit15i-stagewv"

kXR_write         = 3019
kXR_FileNotOpen   = 3004
kXR_IOError       = 3007
kXR_NotAuthorized = 3010

WRITEV_SID = b"\x00\x05"          # the streamid every vector below carries


DEFECT30 = ("REGRESSION #30: a refused kXR_writev must be answered exactly once "
            "and send no second frame — writev_validate_handles() returns "
            "NGX_DONE and the caller stops instead of reading brix_send_error()'s "
            "NGX_OK as 'handles admitted' and writing the refused descriptor.")

DEFECT31 = ("REGRESSION #31: an out-of-range handle (slot 255 vs BRIX_MAX_FILES "
            "16) is refused kXR_FileNotOpen and goes no further — no OOB read of "
            "ctx->files[], no second frame, and the worker keeps serving.")

OOR_HANDLE = b"\xff\x00\x00\x00"   # slot 255; BRIX_MAX_FILES is 16
UNOPENED_HANDLE = b"\x07\x00\x00\x00"   # slot 7: in range, never opened


# ── wire helpers ──────────────────────────────────────────────────────────
# test_io_uring_runtime._writev builds this same frame but returns only
# (status, body); every test below turns on WHICH request a frame answers, so
# the streamid has to survive.  The frame layout is shared with it verbatim.

def _writev_frame(fhandle, segments, do_sync=False, streamid=WRITEV_SID):
    descs = b"".join(fhandle + struct.pack(">I", len(d))
                     + struct.pack(">q", off) for off, d in segments)
    options = kXR_wv_doSync if do_sync else 0
    hdr = (streamid + struct.pack(">H", kXR_writev) + bytes([options])
           + b"\x00" * 15 + struct.pack(">I", len(descs)))
    return hdr + descs + b"".join(d for _, d in segments)


def _writev(sock, fhandle, segments, do_sync=False):
    """One kXR_writev; returns the FIRST reply as (streamid, status, body)."""
    sock.sendall(_writev_frame(fhandle, segments, do_sync))
    return _read_response(sock)


def _write(sock, fhandle, offset, data, streamid=b"\x00\x06"):
    """One plain kXR_write; returns (streamid, status, body)."""
    sock.sendall(struct.pack("!2sH4sqB3sI", streamid, kXR_write, fhandle,
                             offset, 0, b"\0" * 3, len(data)) + data)
    return _read_response(sock)


def _next_frame(sock, timeout=3.0):
    """The frame after the one already read, or None if the server sent
    nothing more / closed the link."""
    sock.settimeout(timeout)
    try:
        return _read_response(sock)
    except (socket.timeout, ConnectionError, OSError):
        return None


def _errcode(body):
    """The kXR error number out of a kXR_error body ([errnum:4B BE][text])."""
    return struct.unpack(">I", body[:4])[0]


# ── fixture ───────────────────────────────────────────────────────────────

@pytest.fixture
def planes(lifecycle, tmp_path):
    """One nginx: the http origin, the ring-free staged writer over it, and a
    bare posix front.  Returns (endpoint, origin, posix, spool)."""
    origin = tmp_path / "origin"
    export = tmp_path / "export"
    spool = tmp_path / "spool"
    posix = tmp_path / "posix"
    for d in (origin, export, spool, posix):
        d.mkdir(parents=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15i_stagewritev.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(origin),
        template_values={"BIND_HOST": BIND_HOST,
                         "ORIGIN_ROOT": str(origin),
                         "EXPORT_ROOT": str(export),
                         "POSIX_ROOT": str(posix),
                         "SPOOL_DIR": str(spool)},
        reason="audit-15i staged-writer kXR_writev admission"))
    return ep, origin, posix, spool


def _open_staged(sock, path):
    """Open `path` fresh-for-write on the staged front; returns the handle."""
    _sid, status, body = _open(sock, path,
                               options=kXR_open_updt | kXR_new | kXR_delete,
                               streamid=b"\x00\x02")
    assert status == kXR_ok, f"staged open-for-write failed: {status} {body!r}"
    return body[:4]


# ── staged scalar and vector writes compose ───────────────────────────────

def test_a_plain_write_through_the_staged_writer_commits_whole(planes):
    """success: the phase-70 path itself is healthy — open, one kXR_write,
    close, and the whole object is at the origin byte-exact with nothing left
    in the spool.  Without this control, #29 could be read as "staging is
    broken" rather than "writev cannot see a staged handle"."""
    ep, origin, _posix, spool = planes
    payload = os.urandom(8192)

    sock = _session(HOST, ep.port)
    try:
        fh = _open_staged(sock, "/plain.bin")
        _sid, status, body = _write(sock, fh, 0, payload)
        assert status == kXR_ok, f"plain write on a staged handle: {body!r}"
        _sid, status, body = _close(sock, fh)
        assert status == kXR_ok, f"staged close: {body!r}"
    finally:
        sock.close()

    assert (origin / "plain.bin").read_bytes() == payload, \
        "the staged close did not commit the whole object to the origin"
    assert not [p for p in spool.rglob("*") if p.is_file()], \
        "the staged writer left its spool copy behind after the commit"


def test_writev_and_plain_write_commit_on_one_staged_handle(planes):
    """Regression #29: descriptor-less staged handles accept both opcodes."""
    ep, origin, _posix, spool = planes
    payload = os.urandom(4096)
    tail = os.urandom(3072)

    sock = _session(HOST, ep.port)
    try:
        fh = _open_staged(sock, "/both.bin")

        _sid, status, body = _write(sock, fh, 0, payload)
        assert status == kXR_ok, \
            f"the control write must succeed for the cross to mean anything: {body!r}"

        sid, status, body = _writev(sock, fh, [(len(payload), tail)])
        assert status == kXR_ok, f"vector write on staged handle: {body!r}"
        assert sid == WRITEV_SID, (sid, body)
        _sid, status, body = _close(sock, fh)
        assert status == kXR_ok, f"staged close failed: {body!r}"
    finally:
        sock.close()

    assert (origin / "both.bin").read_bytes() == payload + tail
    assert not [p for p in spool.rglob("*") if p.is_file()]


def test_consecutive_staged_vectors_are_answered_once_and_commit(planes):
    """Regression #29/#30: each valid vector gets one reply and the link stays usable."""
    ep, origin, _posix, _spool = planes
    first = os.urandom(1024)
    second = os.urandom(512)

    sock = _session(HOST, ep.port)
    try:
        fh = _open_staged(sock, "/twice.bin")
        sid, status, body = _writev(sock, fh, [(0, first)])
        assert status == kXR_ok, body
        assert sid == WRITEV_SID, (sid, status, body)
        assert _next_frame(sock) is None, DEFECT30

        sid, status, body = _writev(sock, fh, [(len(first), second)])
        assert status == kXR_ok, body
        assert _next_frame(sock) is None, DEFECT30
        _sid, status, body = _close(sock, fh)
        assert status == kXR_ok, body
    finally:
        sock.close()

    assert (origin / "twice.bin").read_bytes() == first + second


# ── the same fall-through on a bare posix export ──────────────────────────

def test_a_handle_never_opened_is_also_answered_once(planes):
    """DEFECT CANDIDATE #30, universality: a bare posix export (no backend, no
    staging, no ring) and an in-range handle that was simply never opened.
    Same single refusal, no second frame — so the fix is a property of the
    guard, not of the tier under it, and every root:// front carries it."""
    ep, _origin, posix, _spool = planes
    (posix / "hello.txt").write_bytes(b"hello\n")

    sock = _session(HOST, ep.extra_ports["POSIX_PORT"])
    try:
        sid, status, body = _writev(sock, UNOPENED_HANDLE, [(0, b"X" * 64)])
        assert status == kXR_error and _errcode(body) == kXR_FileNotOpen, body
        assert sid == WRITEV_SID, (sid, status, body)
        assert _next_frame(sock) is None, DEFECT30
    finally:
        sock.close()

    assert (posix / "hello.txt").read_bytes() == b"hello\n", \
        "the refused vector reached an unrelated file"


def test_an_out_of_range_handle_is_refused_and_the_worker_survives(planes):
    """DEFECT CANDIDATE #31, now closed: fhandle[0] is a byte and BRIX_MAX_FILES
    is 16, so slot 255 is nameable.  writev_validate_handles() refuses it
    kXR_FileNotOpen and — with #30 fixed — that refusal is terminal: no
    fall-through to writev_write_segment(), so ctx->files[255] is never read past
    the end of a 16-entry array.  What used to be an out-of-bounds read whose
    wire trace varied run to run is now fully defined: one refusal, no second
    frame, and the front stays up for every other client."""
    ep, _origin, posix, _spool = planes
    (posix / "victim.txt").write_bytes(b"victim\n")

    sock = _session(HOST, ep.extra_ports["POSIX_PORT"])
    try:
        sid, status, body = _writev(sock, OOR_HANDLE, [(0, b"X" * 64)])
        assert sid == WRITEV_SID, (DEFECT31, sid, status, body)
        assert status == kXR_error, (DEFECT31, status, body)
        assert _errcode(body) == kXR_FileNotOpen, (DEFECT31, body)
        assert _next_frame(sock) is None, DEFECT31
    finally:
        sock.close()

    # The worker must still be serving: an OOB read that has become fatal would
    # take the whole front down for every other client.
    probe = _session(HOST, ep.extra_ports["POSIX_PORT"])
    try:
        _sid, status, body = _open(probe, "/victim.txt",
                                   options=kXR_open_read, streamid=b"\x00\x02")
        assert status == kXR_ok, \
            f"the out-of-range handle took the front down with it: {body!r}"
        _close(probe, body[:4])
    finally:
        probe.close()

    assert (posix / "victim.txt").read_bytes() == b"victim\n"


def test_a_read_only_handle_is_refused_before_any_byte(planes):
    """security-negative: writev on a handle opened for READ is refused
    kXR_NotAuthorized and goes no further.  With #30 fixed the guard keeps its
    own documented "before any byte is written" invariant itself — it no longer
    falls through to the write syscall and leans on the kernel's EBADF.  One
    error frame, no second frame, and the file's bytes are untouched."""
    ep, _origin, posix, _spool = planes
    (posix / "ro.txt").write_bytes(b"readonly\n")

    sock = _session(HOST, ep.extra_ports["POSIX_PORT"])
    try:
        _sid, status, body = _open(sock, "/ro.txt", options=kXR_open_read,
                                   streamid=b"\x00\x02")
        assert status == kXR_ok, f"read open failed: {body!r}"
        fh = body[:4]

        sid, status, body = _writev(sock, fh, [(0, b"Z" * 32)])
        assert status == kXR_error and _errcode(body) == kXR_NotAuthorized, body
        assert sid == WRITEV_SID, (sid, status, body)
        assert _next_frame(sock) is None, DEFECT30
    finally:
        sock.close()

    assert (posix / "ro.txt").read_bytes() == b"readonly\n", \
        "a vector refused as NotAuthorized still overwrote the file"


def test_the_framing_guard_answers_once_and_drops_the_link(planes):
    """security-negative + the control that makes #30 a defect: the guard three
    lines above the handle check rejects a descriptor block that is not a whole
    number of 16-byte descriptors, answers exactly once, and drops the link.
    That is what a terminal rejection looks like on this path — the handle
    guard's second frame is a deviation from its own neighbour, not a
    convention."""
    ep, _origin, posix, _spool = planes
    (posix / "frame.txt").write_bytes(b"frame\n")

    sock = _session(HOST, ep.extra_ports["POSIX_PORT"])
    try:
        descs = b"\x00" * 20                    # 20 is not a multiple of 16
        sock.sendall(struct.pack("!2sH16sI", WRITEV_SID, kXR_writev,
                                 b"\0" * 16, len(descs)) + descs)
        sid, status, body = _read_response(sock)
        assert sid == WRITEV_SID, (sid, status, body)
        assert status == kXR_error, (status, body)
        assert _errcode(body) == kXR_ArgInvalid, body

        assert _next_frame(sock) is None, \
            "the framing rejection sent a second frame too"
    finally:
        sock.close()

    assert (posix / "frame.txt").read_bytes() == b"frame\n"
