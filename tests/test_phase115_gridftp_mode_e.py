"""Phase-115 W5.1 — the GridFTP MODE E data channel on the outbound FTP driver.

MODE E (GFD.020 §3.4) replaces RFC 959's "the bytes are the stream, and the
close is the end" with 17-byte extended-block headers that carry an ABSOLUTE
file offset.  That buys restart and striping, and it costs the receiver a
policing duty that stream mode never had: the sender now chooses where each
block lands, so a receiver that trusts the offsets will happily let an origin
rewrite bytes it has already committed, write outside the window the caller
asked for, or fall silent halfway through a header and have that read as EOF.

Every refusal here is therefore a security property, not a robustness nicety,
and each is driven by a real non-conforming block stream from the test origin
rather than by a unit-level stub — the framing is only interesting where it
meets the socket.

The lab is three WebDAV fronts that differ ONLY in their store line:

  ``mode_e``    `mode=e` over the extended-block-capable origin (the subject)
  ``stream``    no params over the SAME origin — MODE S (the control)
  ``refuse``    `mode=e` over an origin that answers `MODE E` 504

The MODE S control is what makes a byte-exactness assertion mean anything: with
one front you can only say "the bytes came back", with two you can say the mode
made no difference to them, which is the actual contract.
"""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import sys
import time

import pytest

from fleet_lifecycle_ports import lifecycle_ports_for
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-mode-e"),
]

# Deliberately larger than the driver's 64 KiB block: a single-block transfer
# would prove framing works only for the case where the header and the whole
# payload arrive together, which is the one case that cannot go wrong.
PAYLOAD = bytes(range(256)) * 1500          # 384000 bytes, position-revealing
SMALL = b"mode-e-fault-subject-payload" * 8


#: `status` for a request the server answered by closing the connection with
#: no status line at all — what `curl` prints as "Empty reply from server" and
#: scores as `%{http_code} 000`.
NO_REPLY = 0

#: The status a pre-header origin failure owes the client.
NGX_BAD_GATEWAY = 502


def _request(port: int, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None):
    """(status, headers, body, short) — every failure shape an OUTCOME.

    Two different failures have to stay distinguishable here, because the
    server is required to tell them apart:

    * a backend that fails AFTER the response headers are on the wire cannot
      change its status code; all it can do is stop early.  Collapsing that
      into an exception (or, worse, into the bytes that did arrive) would let a
      truncated transfer read as a successful one, so the short read comes back
      as ``short=True``.
    * a backend that fails BEFORE the headers go out still owes a status code.
      When it instead drops the connection, ``http.client`` raises
      ``RemoteDisconnected`` out of ``getresponse()`` — an ERROR with a
      traceback about the transport, which says nothing about the refusal that
      caused it and cannot be asserted on.  That is returned as ``NO_REPLY``
      so a row can state the difference between "answered 502" and "answered
      nothing", which is exactly the regression these tests guard.
    """
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=60)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        try:
            response = connection.getresponse()
        except (http.client.RemoteDisconnected, ConnectionResetError):
            return NO_REPLY, {}, b"", True
        try:
            payload, short = response.read(), False
        except http.client.IncompleteRead as partial:
            payload, short = partial.partial, True
        return response.status, dict(response.getheaders()), payload, short
    finally:
        connection.close()


def _await_log(path: Path, needle: str, timeout: float = 20.0) -> str:
    """Wait for `needle` in the error log and return the line carrying it."""
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if needle in line:
                return line
        time.sleep(0.2)
    raise AssertionError(f"{needle!r} never reached {path}\n--- tail ---\n"
                         + "\n".join(text.splitlines()[-40:]))


class _ModeELab:
    def __init__(self, harness: LifecycleHarness, root: Path, tmp: Path):
        capable_port, _ = lifecycle_ports_for("lc-p115-mode-e-origin")
        plain_port, _ = lifecycle_ports_for("lc-p115-mode-e-plain-origin")
        # Named so a test can assert WHICH retrieve command the driver chose.
        # Without that, every success row below passes identically whether the
        # surplus path ran or an ERET made it unreachable.
        self.capable_audit = tmp / "lc-p115-mode-e-origin.log"
        capable = harness.start(self._origin(
            "lc-p115-mode-e-origin", capable_port, root, tmp, mode_e=True))
        plain = harness.start(self._origin(
            "lc-p115-mode-e-plain-origin", plain_port, root, tmp, mode_e=False))
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-p115-mode-e",
            template="nginx_lc_gsiftp_mode_e.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_PORT": capable.port,
                "PLAIN_ORIGIN_PORT": plain.port,
                "ORIGIN_BASE": "/base",
                "E_EXPORT": str(tmp / "e-export"),
                "S_EXPORT": str(tmp / "s-export"),
                "REFUSE_EXPORT": str(tmp / "refuse-export"),
            },
            reason="WebDAV fronts over the MODE E and MODE S data channels",
        ))
        self.harness = harness
        self.root = root
        self.mode_e_port = endpoint.port
        self.stream_port = endpoint.extra_ports["STREAM_PORT"]
        self.refuse_port = endpoint.extra_ports["REFUSE_PORT"]
        self.error_log = Path(endpoint.prefix, "logs", "error.log")

    @staticmethod
    def _origin(name: str, port: int, root: Path, tmp: Path, *, mode_e: bool):
        argv = [sys.executable, "-m", "brix_suite.servers.ftp_origin_server",
                str(port), str(root), "--audit", str(tmp / f"{name}.log")]
        if not mode_e:
            argv.append("--no-mode-e")
        return NginxInstanceSpec(
            name=name,
            template="",
            kind="proc",
            protocol="ftp",
            readiness="tcp",
            data_root=str(root),
            template_values={"argv": argv},
            env={"PYTHONPATH": os.path.dirname(__file__)},
            reason="confined GridFTP origin, extended block mode "
                   + ("available" if mode_e else "refused"),
        )

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    tmp = tmp_path_factory.mktemp("p115-mode-e")
    root = tmp / "origin"
    (root / "base").mkdir(parents=True)
    for name in ("e-export", "s-export", "refuse-export"):
        (tmp / name).mkdir()
    (root / "base" / "plain.bin").write_bytes(PAYLOAD)
    # One seed per injectable fault.  The origin picks the fault from the NAME,
    # so every refusal costs a file rather than a whole second origin process.
    for fault in ("overlap", "out-of-window", "truncated-header", "short-eod"):
        (root / "base" / f"eb-{fault}-subject.bin").write_bytes(SMALL)
    # Deliberately PAYLOAD-sized, not SMALL: the late-overlap fault is defined
    # by firing on a window other than the first, which needs an object big
    # enough to have one.  Every other seed is smaller than a single window on
    # purpose, so its refusal lands before any header is sent.
    (root / "base" / "eb-late-overlap-subject.bin").write_bytes(PAYLOAD)
    harness = LifecycleHarness()
    lab = _ModeELab(harness, root, tmp)
    yield lab
    lab.close()


# ---- success: the bytes are the bytes ---------------------------------------

def test_mode_e_get_is_byte_exact(lab):
    status, _, body, short = _request(lab.mode_e_port, "GET", "/plain.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD


def test_mode_e_and_mode_s_return_identical_bytes(lab):
    """The contract is that the mode is invisible above the driver.

    Asserted against the OTHER front rather than against PAYLOAD alone, so the
    claim is about the two data channels agreeing and not about the fixture.
    """
    _, _, via_e, _ = _request(lab.mode_e_port, "GET", "/plain.bin")
    _, _, via_s, _ = _request(lab.stream_port, "GET", "/plain.bin")
    assert via_e == via_s == PAYLOAD


def test_mode_e_ranged_get_honours_the_absolute_offset(lab):
    """MODE E blocks are absolute-offset addressed and REST still applies.

    A receiver that quietly rebased a restarted transfer to zero would pass a
    whole-file GET and corrupt every ranged one, so the range is deliberately
    past the first 64 KiB block boundary.
    """
    start, end = 100000, 100255
    status, headers, body, short = _request(
        lab.mode_e_port, "GET", "/plain.bin",
        headers={"Range": f"bytes={start}-{end}"})
    assert (status, short) == (206, False)
    assert body == PAYLOAD[start:end + 1]
    assert headers.get("Content-Range") == \
        f"bytes {start}-{end}/{len(PAYLOAD)}"


def test_mode_e_put_lands_byte_exact_on_the_origin(lab):
    """The send half, read back through the MODE S front.

    Reading it back over the other data channel is the point: a send and a
    receive that shared a framing bug would agree with each other and with
    nothing else.
    """
    status, _, _, _ = _request(lab.mode_e_port, "PUT", "/uploaded.bin",
                               body=PAYLOAD)
    assert status in (201, 204)
    assert (lab.root / "base" / "uploaded.bin").read_bytes() == PAYLOAD
    assert _request(lab.stream_port, "GET", "/uploaded.bin")[2] == PAYLOAD


# ---- error: an origin that cannot do it -------------------------------------

def test_mode_e_get_fails_when_the_origin_refuses_the_mode(lab):
    """`mode=e` is a requirement, not a preference.

    The origin answers `MODE E` 504 and would serve the very same file happily
    in stream mode.  Silently taking that offer is the whole failure this test
    exists for: the operator asked for a restartable, offset-addressed channel
    and would have been given an un-restartable one with no way to tell.
    """
    status, _, body, _ = _request(lab.refuse_port, "GET", "/plain.bin")
    assert status >= 500, f"served {status} in the mode the operator refused"
    assert PAYLOAD[:64] not in body
    assert "refused MODE E" in _await_log(lab.error_log, "refused MODE E")


def test_mode_e_put_fails_when_the_origin_refuses_the_mode(lab):
    """The same refusal on the send half, which negotiates MODE separately."""
    status, _, _, _ = _request(lab.refuse_port, "PUT", "/never.bin",
                               body=b"should not land")
    assert status >= 500
    assert not (lab.root / "base" / "never.bin").exists()


# ---- security negatives: non-conforming block streams -----------------------

@pytest.mark.parametrize("fault,needle", [
    # A block covering bytes already committed.  Benign-looking — it is a
    # verbatim retransmit — but the receiver cannot distinguish it from an
    # origin rewriting data the caller may already have checksummed, so the
    # only safe answer is to refuse the transfer rather than pick a winner.
    ("overlap", "overlaps committed bytes"),
    # A block addressed far past the window the caller asked for.  Accepting it
    # would let the origin choose where in the caller's address space its bytes
    # land — a write primitive handed to the peer.
    ("out-of-window", "outside the requested window"),
    # Half a header, then a close.  A receiver that treated any close as EOF
    # would report a truncated transfer as a complete one.
    ("truncated-header", "closed mid-header"),
    # An EOF block promising two EODs when only one ever arrives.  Found while
    # building this lab: the receive loop polled only LIVE connections, so once
    # every connection had retired with the promise unmet it looped on an empty
    # poll set forever — one lie about an EOD count burned a worker thread at
    # 100% CPU with no timeout to end it.  The transfer must now END, and end
    # as a failure.
    ("short-eod", "promised EOD blocks"),
])
def test_non_conforming_block_stream_is_refused(lab, fault, needle):
    status, _, body, short = _request(
        lab.mode_e_port, "GET", f"/eb-{fault}-subject.bin")
    assert not (status == 200 and not short and body == SMALL), \
        f"the {fault} block stream was accepted as a complete transfer"
    _await_log(lab.error_log, needle)


def test_a_refused_transfer_leaves_no_partial_file_behind(lab):
    """A refusal is not a licence to keep what arrived before it.

    The overlap fault delivers a legitimate block first, so there ARE bytes in
    hand when the refusal fires; they must not reach the client as a short but
    otherwise ordinary 200.
    """
    status, headers, body, short = _request(
        lab.mode_e_port, "GET", "/eb-overlap-subject.bin")
    if status == 200:
        assert short or len(body) < len(SMALL), \
            "a refused MODE E transfer was served as a complete response"
        assert headers.get("Content-Length") != str(len(body))


# ---- success: an origin that answers with more than was asked for -----------

def _audit(path: Path) -> list[str]:
    """The origin's command log, oldest first, or [] before it has flushed."""
    if not path.exists():
        return []
    return [line for line in
            path.read_text(encoding="utf-8").splitlines() if line]


def _assert_window_was_not_declared(lines: list[str], start: int) -> None:
    """The origin was told WHERE to start and nothing else.

    Either half failing retires the surplus path while leaving the bytes
    correct: an ERET declares the window so nothing can over-run it, and a
    missing REST means the transfer began at zero, where a full-length answer
    is not surplus at all.
    """
    assert "ERET" not in [line.split(" ")[0] for line in lines], \
        "the window was declared, so this no longer exercises the surplus path"
    assert f"REST {start}" in lines, \
        f"the driver never positioned, so no surplus could arise: {lines}"


def _assert_retr_was_unbounded(lines: list[str]) -> None:
    """One retrieve, carrying no length — so the origin sent the whole tail."""
    retr = [line for line in lines if line.split(" ")[0] == "RETR"]
    assert len(retr) == 1, f"expected one RETR for one window, saw {retr}"
    assert not any(token.isdigit() for token in retr[0].split()), \
        f"RETR carried a length, so the origin did not over-run it: {retr[0]}"


def test_a_bare_retr_over_runs_the_window_and_the_transfer_still_succeeds(lab):
    """RFC 959 RETR names no length, so the origin sends the whole tail.

    A RANGED read is what makes that observable, and after §P9 it is the only
    thing that does.  This origin has no ERET, so the driver positions with
    `REST <start>` and issues a bare `RETR`; the origin then sends every byte
    from `start` to EOF — 284000 of them to satisfy a 256-byte window.  The
    surplus is the protocol working as specified, and MODE S has always
    abandoned it silently.  MODE E, which polices offsets, read the very first
    surplus block as an out-of-window attack and failed the transfer; a
    `mode=e` store over any door without ERET could not serve a ranged read.

    This was pinned on a WHOLE-object GET, where the driver's fixed 64 KiB fill
    made every window but the last a surplus.  §P5 (fill asks for the whole
    remainder) and §P9 (the offload fetches the requested window, drained a MiB
    at a time) each removed that independently: a 384000-byte object is now
    fetched by one read that asks for all of it, and nothing can be surplus to
    a request for everything.  The condition survives only where the window is
    genuinely narrower than what a length-less RETR delivers — a ranged read.

    The audit assertions are the part that has to be here.  Byte-exactness
    alone would pass just as well if someone later gave this origin ERET, at
    which point the window would be declared, no surplus would ever arrive, and
    the surplus path would again be pinned by nothing.
    """
    start, end = 100000, 100255
    lab.capable_audit.write_text("", encoding="utf-8")
    status, _, body, short = _request(
        lab.mode_e_port, "GET", "/plain.bin",
        headers={"Range": f"bytes={start}-{end}"})
    assert (status, short) == (206, False)
    assert body == PAYLOAD[start:end + 1]

    lines = _audit(lab.capable_audit)
    _assert_window_was_not_declared(lines, start)
    _assert_retr_was_unbounded(lines)


def test_the_surplus_that_is_kept_is_the_surplus_that_was_asked_for(lab):
    """Stopping at the edge must not become trusting anything past it.

    The relaxation is deliberately narrow — a block BEGINNING at or past an
    already-filled window ends the transfer, everything else is still policed —
    and the `overlap` fault above is what proves the narrowness: its object is
    smaller than one window, so the window fills exactly at EOF and the replayed
    block arrives after that point.  A wider rule ("the window is full, stop
    reading") would never see it, and a pinned refusal would have become a
    silent success with nobody the wiser.  Cross-checked against MODE S so the
    claim is that the two channels agree, not that the fixture is self-consistent.
    """
    _, _, via_e, _ = _request(lab.mode_e_port, "GET", "/plain.bin")
    _, _, via_s, _ = _request(lab.stream_port, "GET", "/plain.bin")
    assert via_e == via_s == PAYLOAD
    status, _, body, short = _request(
        lab.mode_e_port, "GET", "/eb-overlap-subject.bin")
    assert not (status == 200 and not short and body == SMALL), \
        "the overlap replay went undetected because the receiver stopped early"


# ---- error: a block that straddles the edge ---------------------------------

def test_a_block_straddling_the_window_end_is_truncated_not_refused(lab):
    """A short window inside one 64 KiB block: the commonest ranged read there is.

    The origin answers a 300-byte range with a whole 65536-byte block, so the
    block starts inside the window and runs past its end.  The bytes inside are
    exactly the ones asked for and are kept; the rest are never committed, and
    the connection is dropped rather than resynchronised, because the next 17
    bytes on it are payload and reading them as a header would let the file's
    own contents invent a block.

    The negative assertion carries the weight: a truncation at the edge is a
    COMPLETE window, so it must not be reported as the refusal a block genuinely
    outside the window earns.  An implementation that logged both the same way
    would pass every byte assertion here and leave an operator chasing a
    security event on every ordinary Range request.
    """
    before = lab.error_log.read_text(encoding="utf-8", errors="replace") \
        if lab.error_log.exists() else ""
    start, end = 200000, 200299
    status, headers, body, short = _request(
        lab.mode_e_port, "GET", "/plain.bin",
        headers={"Range": f"bytes={start}-{end}"})
    assert (status, short) == (206, False)
    assert body == PAYLOAD[start:end + 1]
    assert headers.get("Content-Range") == \
        f"bytes {start}-{end}/{len(PAYLOAD)}"
    after = lab.error_log.read_text(encoding="utf-8", errors="replace")
    assert "outside the requested window" not in after[len(before):], \
        "an ordinary straddling block was logged as an out-of-window refusal"


# ---- a backend failure BEFORE the header keeps its status code --------------
#
# Found while verifying the surplus fix above.  brix_serve_memory_backed()
# sent the response header and only then took the first driver pread.  Every
# backend served by that path (gsiftp, http, xroot, s3, pblock — anything with
# no single sendfile fd) first touches its origin on that pread, so an origin
# refusal arrived with a 200 already built and unflushed: the NGX_ERROR return
# closed the connection, nginx discarded the buffered header, and the client
# got a bare close.  `curl` scored it `000` with zero bytes; there was no
# status code anywhere for a client to branch on, and a proxy in front of it
# could not tell "origin refused" from "server crashed".  The first read now
# runs BEFORE the header, so a failure that has not yet reached the wire still
# has a status line to travel in.


def test_an_origin_refusal_before_any_byte_answers_a_status_not_a_bare_close(lab):
    """The refusal must arrive as 502, not as an empty reply.

    NO_REPLY is the assertion that matters and is spelled out separately from
    the code check: a regression here does not produce a WRONG status, it
    produces NO status, and a bare `assert status == 502` would report that as
    an unhandled RemoteDisconnected from inside the transport helper rather
    than as the defect it is.
    """
    status, headers, body, _ = _request(lab.refuse_port, "GET", "/plain.bin")
    assert status != NO_REPLY, \
        "the origin refusal was finalised by closing the connection"
    assert status == NGX_BAD_GATEWAY, f"origin refusal answered {status}"
    assert PAYLOAD[:64] not in body
    assert headers.get("Content-Length") != str(len(PAYLOAD)), \
        "the failed response still advertised the object's length"
    _await_log(lab.error_log, "refused MODE E")


def test_a_block_stream_refusal_before_any_byte_answers_502_as_well(lab):
    """The other pre-header failure shape, reached through a different door.

    The MODE E negotiation refusal above fails in the control channel before a
    data connection exists; these fail inside the block stream, with a data
    connection open and bytes already read into the driver's own buffer.  Both
    must reach the client the same way, because from the client's side they are
    the same event: the origin did not deliver the object.  Each subject is
    smaller than one 64 KiB window, so the refusal is provably pre-header.
    """
    for fault in ("overlap", "out-of-window", "short-eod"):
        status, _, body, _ = _request(
            lab.mode_e_port, "GET", f"/eb-{fault}-subject.bin")
        assert status != NO_REPLY, f"{fault} was finalised by a bare close"
        assert status == NGX_BAD_GATEWAY, f"{fault} answered {status}"
        assert body != SMALL


def test_a_refusal_on_a_later_window_is_still_policed_and_still_a_status(lab):
    """`late-overlap` fires only past the first window, and must still refuse.

    The fault is offset-addressed: the origin serves a transfer based at 0
    cleanly and replays a block on any transfer based past it, so it fires only
    where the receiver has ALREADY accepted bytes for this object.  That is the
    case a policing bug survives — an implementation that armed its overlap
    check on the first read of a request and disarmed it afterwards passes
    every other row in this file.

    §P9 changed the SHAPE of the report, not the refusal.  This was a
    post-header failure: the driver filled the first 64 KiB window, the 200 and
    its Content-Length went out, the replay on the second window left nothing
    to send but a stop, and the test pinned a short read on a declared length.
    A blocking-wire driver now materialises into a scratch file and responds
    from it, so nothing is on the wire when the refusal fires and the client
    gets a status carrying no object bytes at all.  That is strictly better —
    a truncated 200 can only be detected by comparing what arrived against
    Content-Length, a 502 cannot be missed — but it is a different shape, and
    pinning the old one now would pin a bug.

    The range spans three 64 KiB blocks on purpose.  A narrower one would fill
    inside the very first block, and the driver would truncate at the window
    edge and drop the connection before the replay was ever sent — the
    behaviour `test_a_block_straddling_the_window_end_is_truncated_not_refused`
    pins deliberately.  The replay has to be REACHED for its refusal to mean
    anything, so the window must outlast the first block.
    """
    start, end = 100000, 250000
    status, headers, body, _ = _request(
        lab.mode_e_port, "GET", "/eb-late-overlap-subject.bin",
        headers={"Range": f"bytes={start}-{end}"})
    assert status == NGX_BAD_GATEWAY, \
        f"a replayed block on a later window answered {status}"
    assert body != PAYLOAD[start:end + 1], "the refused window was served anyway"
    assert headers.get("Content-Range") is None, \
        "a refused transfer still advertised a satisfied range"
    _await_log(lab.error_log, "overlaps committed bytes")


def test_the_same_subject_read_from_the_first_window_is_byte_exact(lab):
    """The control for the row above: the fault really is offset-addressed.

    Without it, a `late-overlap` subject that failed for ANY other reason — a
    missing seed, a wedged origin, a driver that refused every read of that
    name — would satisfy the refusal assertion above and prove nothing about
    where the policing is armed.  A whole-object GET is based at 0, where this
    origin is conforming, so it must come back complete and byte-exact.
    """
    status, _, body, short = _request(
        lab.mode_e_port, "GET", "/eb-late-overlap-subject.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD


def test_the_502_promotion_does_not_swallow_404_or_403(lab):
    """Security negative: the promotion is for UNCLASSIFIED failures only.

    The pre-header status comes from the shared errno table, whose 500 default
    is promoted to 502 because this serve path is only ever reached for an
    origin-backed object.  The promotion must not reach the classes the table
    decides deliberately: a missing object is 404 and a refused one is 403, and
    turning either into "upstream is broken" would blur an existence or
    authorization answer into an availability one — the client retries, the
    operator hunts a network fault, and the real answer is never seen.
    """
    status, _, _, _ = _request(lab.mode_e_port, "GET", "/no-such-object.bin")
    assert status == 404, f"a missing object answered {status}, not 404"
    assert status != NGX_BAD_GATEWAY


def test_a_head_still_answers_without_touching_the_origin_for_bytes(lab):
    """Success: the pre-header read must not fire where there is no body.

    A HEAD (and a zero-length range) has nothing to prime, and priming anyway
    would turn every metadata request into an origin data transfer — a real
    cost on a tape or WAN backend, and one that would make HEAD fail wherever
    GET fails.  The refuse front is the proof: its origin cannot serve a single
    byte, and its HEAD must still succeed.
    """
    status, headers, body, short = _request(lab.mode_e_port, "HEAD", "/plain.bin")
    assert (status, short, body) == (200, False, b"")
    assert headers.get("Content-Length") == str(len(PAYLOAD))

    status, headers, body, _ = _request(lab.refuse_port, "HEAD", "/plain.bin")
    assert status == 200, \
        f"HEAD reached for bytes it never needed and answered {status}"
    assert (headers.get("Content-Length"), body) == (str(len(PAYLOAD)), b"")
