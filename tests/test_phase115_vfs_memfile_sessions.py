"""Phase-115 §P5 — what a materialisation COSTS, counted in origin sessions.

§P4 made a whole-object read the only thing that materialises a memfd.  This is
the question that becomes visible once that lands: how many times the driver is
asked for the object it is materialising.

`brix_vfs_memfile_fill()` used to read in fixed 64 KiB steps through a stack
buffer.  A driver whose `pread` slot is stateless pays a full round trip per
step, and gsiftp's is stateless by protocol — every `pread` opens a control
connection and runs USER/PASS/TYPE/REST/RETR.  Materialising the 384000-byte
subject therefore cost SIX retrieves where one would do.

The reason this survived §P4's census is that the six together move exactly one
object's worth of bytes.  A byte count cannot see it; only a count of RETRIEVES
can, which is why every assertion here is over the retrieve verbs in the
origin's own audit log rather than over bytes or over totals.

A retrieve is counted rather than a login because the two are not the same
cost and only one of them is the finding: a stat opens its own control session
to ask SIZE and MDTM, that session moves no data, and it is correct.  Counting
logins would have made the metadata probe indistinguishable from the fill it is
measuring.

The fix asks for the remainder (`size - off`) instead of a chunk, and fills the
memfd through one mmap of itself rather than through a stack buffer — it already
holds the whole object, so the mapping costs no memory the materialisation was
not paying anyway.

This module borrows the ERET lab exactly as test_phase115_vfs_sendfile_window.py
does: same module-scoped fixture, same xdist_group, so the three labs in that
group are never up at once and no lifecycle spec is added.

Run: PYTHONPATH=tests python3 -m pytest tests/test_phase115_vfs_memfile_sessions.py -v
"""

from __future__ import annotations

import http.client
from pathlib import Path

import pytest

from csource_scan import function_body
from settings import SERVER_HOST
from test_phase115_gridftp_eret import PAYLOAD, _audit, _get
from test_phase115_gridftp_eret import lab  # noqa: F401  (shared fixture)


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-eret"),
]

REPO_ROOT = Path(__file__).resolve().parents[1]
OPEN_HANDLE_C = REPO_ROOT / "src/fs/vfs/vfs_open_handle.c"


#: Every command that opens a data channel to move object bytes.
RETRIEVES = ("RETR", "ERET")


def _transfers(lines: list[str]) -> int:
    """How many times the origin was asked to send object bytes."""
    return sum(1 for line in lines if line.split(" ", 1)[0] in RETRIEVES)


def _verbs(lines: list[str]) -> list[str]:
    return [line.split(" ", 1)[0] for line in lines]


def _head(port: int, path: str) -> int:
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=60)
    try:
        connection.request("HEAD", path)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_a_whole_object_read_costs_one_origin_transfer(lab):
    """success: one GET, one retrieve.

    The bytes are asserted too, because "one retrieve" is trivially achievable
    by not fetching the object at all — and a materialisation that returned a
    short memfd would serve a short body with a 200.
    """
    before = len(_audit(lab.plain_audit))
    status, _, body, short = _get(lab.plain_port, "/plain.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD

    lines = _audit(lab.plain_audit)[before:]
    assert _transfers(lines) == 1, (
        f"serving one object cost {_transfers(lines)} retrieves; the fill loop "
        f"is asking for a fixed chunk again: {lines}")


def test_the_fill_loop_still_tolerates_a_short_answer(lab):
    """error side: asking for everything may not become assuming everything.

    The tempting way to write "ask for the remainder" is one `pread` and a
    length check, which breaks every driver that legitimately answers short.
    No origin in this harness answers short — a `REST`+`RETR` always yields the
    whole remainder — so the property is pinned on the loop's SHAPE: it must
    re-ask from a cursor it advances by what it actually received.
    """
    body = function_body(OPEN_HANDLE_C.read_text(encoding="utf-8"),
                         "brix_vfs_memfile_fill")
    assert "for (off = 0; off < size;" in body, body
    assert "off += n;" in body, body
    assert "(size_t) (size - off)" in body, (
        "the fill no longer asks for the whole remainder, which is the change "
        f"that took the object from six logins to one: {body}")


def test_a_head_moves_no_object_bytes(lab):
    """security negative: a HEAD must not materialise.

    A HEAD that materialised would let any client make this gateway pull whole
    objects off the origin on demand — no body to show for it, no bytes billed
    against the client, and an access log that records a metadata request.
    That is a bandwidth amplifier, and it is one HTTP verb away from the path
    above.

    The metadata probe is asserted POSITIVELY as well.  Without it the row
    passes just as well when the HEAD never reaches the origin at all — a
    cached answer, a wrong port, a lab that was not listening — and an
    amplifier test that cannot tell "did not transfer" from "did not ask" is
    not testing the amplifier.
    """
    before = len(_audit(lab.plain_audit))
    assert _head(lab.plain_port, "/plain.bin") == 200

    lines = _audit(lab.plain_audit)[before:]
    assert _transfers(lines) == 0, (
        f"a HEAD pulled object bytes off the origin {_transfers(lines)} "
        f"times: {lines}")
    assert "SIZE" in _verbs(lines), (
        f"the HEAD never reached this origin, so it proves nothing: {lines}")
