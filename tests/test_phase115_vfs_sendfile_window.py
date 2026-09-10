"""Phase-115 §P4 — a ranged read must not fetch the whole object.

Found while proving §P3, and larger than it.

A storage backend with no kernel file descriptor carries
`BRIX_SD_CAP_MEMFILE`: gsiftp, http, xroot, s3, ceph, remote, ram, pblock.  The
serve path asked the VFS for a sendfile fd with `brix_vfs_file_sendfile_fd(fh)`
— a WHOLE-OBJECT question — and with no fd to hand back the VFS answered it by
MATERIALISING: preading the entire object through the driver into a memfd,
64 KiB at a time.  On a remote origin that is a network transfer of the whole
file, and it was paid on every ranged read.  Measured on this lab before the
fix: a 256-byte `Range` on a 384000-byte file produced SIX `ERET` commands over
six control connections, covering 0..384000.

Nothing was observably wrong — right bytes, right `Content-Range`, right status
— so the cost was invisible from the client, which is exactly why it survived
every byte-exactness test in test_phase115_gridftp_eret.py.  It also silently
cancelled the extension that suite exists to test: `ERET` was issued, correctly
formed, for the wrong window.

The fix is `brix_vfs_file_sendfile_fd_window(fh, off, len)`.  The backend probe
is unchanged — `sd_block`/`sd_pblock` acceptance does not widen — and only the
materialisation FALLBACK is gated on the window being the whole object.  A
strict sub-window declines the fd and the caller takes its memory-backed path,
which costs nothing: the memfd was already a full copy of an object the backend
cannot sendfile in the first place.  A HEAD reads nothing and says so with a
negative length.

This lives beside the ERET suite rather than inside it because it shares that
suite's lab and nothing else: the property is about the VFS seam, and it holds
for every CAP_MEMFILE backend, of which gsiftp is merely the one with a command
log that can prove it.  The shared `lab` fixture is module-scoped and both
modules carry the same `xdist_group`, so the two labs are never up at once.

Run: PYTHONPATH=tests python3 -m pytest tests/test_phase115_vfs_sendfile_window.py -v
"""

from __future__ import annotations

import http.client

import pytest

from settings import SERVER_HOST
from test_phase115_gridftp_eret import (PAYLOAD, WINDOW_END, WINDOW_START,
                                        _audit, _get, _ranged)
from test_phase115_gridftp_eret import lab  # noqa: F401  (shared fixture)


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-eret"),
]

def _requested_bytes(lines: list[str]) -> int:
    """How many bytes of payload the origin was asked to send, in total.

    ERET carries its own length; a RETR is unbounded and therefore costs the
    rest of the file from wherever the preceding REST left the cursor.
    """
    total, cursor = 0, 0
    for line in lines:
        parts = line.split(" ")
        if parts[0] == "REST":
            cursor = int(parts[1])
        elif parts[0] == "ERET":
            total += int(parts[3])
        elif parts[0] == "RETR":
            total += len(PAYLOAD) - cursor
    return total


def _head(port: int, path: str):
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=60)
    try:
        connection.request("HEAD", path)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_a_ranged_read_asks_the_origin_for_only_the_window(lab):
    """success: one bounded retrieve, sized to the Range and to nothing else.

    Counted in BYTES rather than in commands: an implementation that split the
    same whole-object fetch across more, smaller ERETs would satisfy a command
    count and still move the entire file.
    """
    before = len(_audit(lab.eret_audit))
    status, _, body, _ = _ranged(lab.eret_port, "/plain.bin")
    assert status == 206
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]

    asked = _audit(lab.eret_audit)[before:]
    wanted = WINDOW_END - WINDOW_START + 1
    assert _requested_bytes(asked) == wanted, (
        f"the origin was asked for {_requested_bytes(asked)} bytes to serve a "
        f"{wanted}-byte window: {asked}")


def test_a_whole_object_read_still_fetches_the_object_once(lab):
    """error side: the gate must not narrow the common path.

    Declining the memfd for a whole-object read would turn every ordinary GET
    into the memory-backed path, so this states the other half of the boundary
    — the window IS the object here, and one object's worth is what is moved.
    """
    before = len(_audit(lab.eret_audit))
    status, _, body, short = _get(lab.eret_port, "/plain.bin")
    assert (status, short, body) == (200, False, PAYLOAD)

    asked = _audit(lab.eret_audit)[before:]
    assert _requested_bytes(asked) == len(PAYLOAD), (
        f"a whole-object read moved {_requested_bytes(asked)} bytes: {asked}")


def test_a_head_never_fetches_the_body(lab):
    """security-negative: metadata must not pull the object.

    A HEAD reads nothing, so it passes a negative length and must never reach
    the materialisation fallback.  If it did, any unauthenticated client able
    to issue HEAD could make the gateway pull whole objects off the origin on
    demand, at no cost to itself and with no body to show for it — a bandwidth
    amplifier that no access log would explain.
    """
    before = len(_audit(lab.eret_audit))
    assert _head(lab.eret_port, "/plain.bin") == 200

    asked = _audit(lab.eret_audit)[before:]
    assert _requested_bytes(asked) == 0, \
        f"a HEAD moved {_requested_bytes(asked)} bytes of payload: {asked}"
