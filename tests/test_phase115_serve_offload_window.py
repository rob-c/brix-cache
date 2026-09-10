"""Phase-115 §P9 — the serve offload must fetch the window, not the object.

§P4 narrowed what a fd-less backend materialises to the window a request will
actually send.  §P6 then made every blocking-wire driver self-declare
`BRIX_SD_CAP_BLOCKING_WIRE`, which correctly routed gsiftp into
`brix_http_serve_offload_remote()` — a path that runs BEFORE `file_serve.c` and
copied the WHOLE object into a scratch temp file.  The layer above narrowed the
read and the layer below widened it straight back; nothing about the response
changed, so only the origin's own command log could see it, and it said
`ERET P 0 384000` to serve a 256-byte window.

The fix gives the offload the same window decision the serve already makes, and
writes the fetched window into the scratch fd AT ITS TRUE OFFSET over a hole of
the full object size.  `brix_http_serve_file_ranged()` then re-derives the same
window from the same header against the same size and reads exactly those bytes
— one computation run twice, so the fetch and the send cannot disagree.  The
hole costs no disk and is never read.

That last part is why the drain is ALL-OR-NOTHING for a bounded window: a `dst`
holding a hole inside the range the caller asked for is indistinguishable from
one holding the object's real zero bytes, so a window that ends early is EIO,
never a short copy.  Only an unbounded drain may stop at EOF.

This suite pins what §P4's cannot reach.  `test_phase115_vfs_sendfile_window.py`
counts bytes on `plain.bin`, which fits inside one 1 MiB drain chunk and is
therefore always one retrieve: it proves the window is narrowed, and would pass
identically against an implementation whose drain loop widened at the tail or
accepted a short answer.  Everything here needs the loop to run more than once,
or needs the origin to withhold what it promised.

Lab: the ERET lab, module-scoped and shared under the same `xdist_group`, so
the group's labs are never up at once and no lifecycle spec is added.

Run: PYTHONPATH=tests python3 -m pytest tests/test_phase115_serve_offload_window.py -v
"""

from __future__ import annotations

import pytest

from test_phase115_gridftp_eret import (BIG_PAYLOAD, PAYLOAD, WINDOW_END,
                                        WINDOW_START, _audit, _ranged)
from test_phase115_gridftp_eret import lab  # noqa: F401  (shared fixture)
from test_phase115_vfs_sendfile_window import _requested_bytes


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-eret"),
]

#: A window over `big.bin` that is deliberately not chunk-aligned at either end
#: and spans more than one 1 MiB drain chunk, so the loop must run twice and
#: neither iteration lands on a boundary that could hide an off-by-one.
BIG_START = 500000
BIG_END = 1999999

#: The status a materialisation failure owes the client.
NGX_BAD_GATEWAY = 502

#: What the pre-fix serve answered instead, and must never answer again.  The
#: whole-object drain stopped at the first empty read, produced a zero-length
#: scratch, and the range check then found the request unsatisfiable against
#: it.  416 tells the client its REQUEST was wrong — so it does not retry, and
#: an operator reading the log goes looking at the client — when what actually
#: happened is that the origin failed to deliver.
NGX_RANGE_NOT_SATISFIABLE = 416


def _erets(lines: list[str]) -> list[tuple[int, int]]:
    """Every `ERET P <off> <len>` in `lines`, as (offset, length) pairs."""
    return [(int(parts[2]), int(parts[3]))
            for parts in (line.split(" ") for line in lines)
            if parts[0] == "ERET"]


def test_a_window_spanning_several_chunks_asks_for_exactly_that_window(lab):
    """SUCCESS: the drain loop narrows every iteration, not just the first.

    1500000 bytes over a 1 MiB chunk is two retrieves: a full chunk and a
    451424-byte remainder.  Both assertions are needed and neither implies the
    other — the total says the loop never widened, and the count says a loop
    ran at all.  A single-iteration implementation that happened to fetch the
    whole window in one unbounded read would satisfy a byte-exactness check and
    fail both of these.

    The bytes are asserted against a position-revealing payload, which is what
    proves the sparse temp is written at the TRUE offset: a window copied to
    offset 0 of the scratch would be re-read from `BIG_START` and come back as
    the hole — 1500000 zero bytes with a perfectly correct `Content-Range`.
    """
    before = len(_audit(lab.eret_audit))
    status, headers, body, short = _ranged(lab.eret_port, "/big.bin",
                                           BIG_START, BIG_END)
    assert (status, short) == (206, False)
    assert body == BIG_PAYLOAD[BIG_START:BIG_END + 1]
    assert headers.get("Content-Range") == \
        f"bytes {BIG_START}-{BIG_END}/{len(BIG_PAYLOAD)}"

    asked = _audit(lab.eret_audit)[before:]
    wanted = BIG_END - BIG_START + 1
    assert _requested_bytes(asked) == wanted, (
        f"the origin was asked for {_requested_bytes(asked)} bytes to serve a "
        f"{wanted}-byte window: {asked}")
    assert len(_erets(asked)) > 1, (
        f"the window was fetched in one retrieve, so the drain loop's second "
        f"and later iterations are pinned by nothing: {asked}")


def test_the_chunks_of_one_window_tile_it_without_gap_or_overlap(lab):
    """SUCCESS, structural: WHERE each iteration asked, not just how much.

    A total is blind to placement.  A loop that advanced its cursor by the
    chunk size instead of by what it received, or that re-asked from the window
    start on a short answer, moves exactly the right number of bytes and puts
    them in the wrong places — and against an origin that always answers in
    full, the resulting body is still correct, because the misplaced bytes are
    overwritten by the next iteration.  It stops being correct the first time
    an origin answers short, which is the case below.
    """
    before = len(_audit(lab.eret_audit))
    _ranged(lab.eret_port, "/big.bin", BIG_START, BIG_END)
    windows = _erets(_audit(lab.eret_audit)[before:])

    cursor = BIG_START
    for offset, length in windows:
        assert offset == cursor, (
            f"iteration asked at {offset}, not at {cursor}: {windows}")
        cursor += length
    assert cursor == BIG_END + 1, \
        f"the iterations stopped at {cursor}, not at {BIG_END + 1}: {windows}"


def test_a_window_the_origin_withholds_is_an_error_not_a_short_body(lab):
    """ERROR: a bounded window that ends early must fail the whole read.

    The `hole` subject answers `ERET` with 226 and an empty data connection:
    the window is accepted, promised, and never sent.  There is no honest way
    to serve a partial answer to a bounded request — the caller named a range
    of a specific object, and anything less is not that range — so the read
    must fail rather than return what it has.

    The failure is asserted as a STATUS, not as an abort.  Materialising before
    composing the response is what makes that possible: nothing is on the wire
    when the drain gives up, so the refusal still has a status line to travel
    in, and a client cannot mistake it for a completed transfer.
    """
    status, headers, body, _ = _ranged(lab.eret_port,
                                       "/eret-hole-subject.bin")
    assert status != NGX_RANGE_NOT_SATISFIABLE, (
        "an origin failure was reported as an unsatisfiable range: the range "
        f"is satisfiable against this {len(PAYLOAD)}-byte object, and blaming "
        "the client for the origin's silence is both wrong and unactionable")
    assert status == NGX_BAD_GATEWAY, \
        f"a window the origin never sent answered {status}"
    assert headers.get("Content-Range") is None, \
        "a failed read still advertised a satisfied range"
    assert body != PAYLOAD[WINDOW_START:WINDOW_END + 1], \
        "the withheld window was served"


def test_an_unsent_window_never_arrives_as_zeroes(lab):
    """SECURITY-NEGATIVE: the hole must not reach the client as object bytes.

    This is the attack the all-or-nothing rule exists to stop, and it needs no
    forged bytes at all: the origin simply stays silent.  The scratch file is
    sparse, so every byte of an unsent window reads back as `\\0`, and a copy
    that reported success would serve those zeroes under a 206 with a correct
    `Content-Range`.  The client would then have 256 bytes it believes came
    from the object — and on any object whose real content at that offset is
    unknown to the caller, there is nothing to compare them against.  An origin
    that can stay silent could write zeroes into any window of any file.

    The control matters as much as the negative: the same door, the same
    request shape and the same lab must still serve a real window correctly,
    or "no zeroes arrived" is satisfied by a door that serves nothing at all.

    Unlike the three rows above, this one does NOT fail against the pre-§P9
    serve — it cannot, because the risk it names did not exist there: that
    scratch file was only ever as long as what had been read, so a window it
    failed to fetch had no zeroes to serve.  The hole is created by the sparse
    temp, which is the price of writing a narrowed window at its true offset.
    What this row pins is the line that pays it: drop the `errno = EIO` branch
    from `xvfs_drain_window()`'s short-read case and the request below comes
    back 206, with a correct `Content-Range` and a body of zeroes.
    """
    wanted = WINDOW_END - WINDOW_START + 1
    _, _, body, _ = _ranged(lab.eret_port, "/eret-hole-subject.bin")
    assert bytes(wanted) not in body, (
        f"{wanted} zero bytes reached the client for a window the origin "
        f"never sent — the sparse hole was served as object content")

    status, _, control, short = _ranged(lab.eret_port, "/plain.bin")
    assert (status, short) == (206, False)
    assert control == PAYLOAD[WINDOW_START:WINDOW_END + 1], \
        "the door serves nothing, so the refusal above proves nothing"
