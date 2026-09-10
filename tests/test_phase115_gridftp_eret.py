"""Phase-115 W5.2 — ERET P, the partial-retrieve extension, on the FTP driver.

RFC 959 can only express "start here" (REST) and then streams to EOF.  For a
ranged read that is a bounded request answered with an unbounded transfer: the
driver takes the bytes it wanted and drops the connection, leaving the origin
pushing the rest of a file nobody is draining.  On a 256-byte range of a 10 GB
file the difference is not a micro-optimisation.

ERET P <offset> <length> <path> (GFD.020 §5.3) carries the WINDOW, so the origin
stops where the caller stopped.  It is not a store-line knob — it is discovered
from FEAT and used when present — which shapes every test here: the two fronts
carry an IDENTICAL configuration and the ORIGINS differ, so anything that comes
out different is attributable to the extension and to nothing an operator did.

Three properties are worth a test, and the third is the reason for the other
two:

  * a ranged read over an ERET origin is byte-exact, and byte-identical to the
    same read over an origin that has never heard of ERET;
  * an origin that advertises ERET and then refuses it is still served — real
    doors advertise more than they implement, and the fallback is the POSITIONED
    REST+RETR path, never a bare RETR that would start at zero;
  * an origin that answers ERET with the whole file from offset 0 is REFUSED.
    That is the one that matters.  Those bytes are a perfectly good file; they
    are simply the wrong part of it, and a driver that trusted the reply would
    hand the caller the head of a file as its middle with a 206 on top.  MODE E
    is what makes the lie detectable at all (its blocks carry absolute offsets),
    which is why the driver only ever sends ERET in MODE E.
"""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import sys
import time

import pytest

from brix_suite.servers.ftp_origin_server import (FEAT_DECOY,
                                                  ftp_origin_feat_bytes)
from fleet_lifecycle_ports import lifecycle_ports_for
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-eret"),
]

# Position-revealing: byte i of every 256-byte run equals i, so a body taken
# from the wrong offset is not merely unequal, it says WHICH offset it came
# from.  Larger than one 64 KiB block so a window can start mid-block.
PAYLOAD = bytes(range(256)) * 1500          # 384000 bytes
WINDOW_START, WINDOW_END = 100000, 100255   # deliberately not block-aligned

#: 3 MiB — three of the serve offload's 1 MiB drain chunks.  Position-revealing
#: like PAYLOAD, so a window read from the wrong offset is visible in the bytes
#: rather than only in a length.
BIG_PAYLOAD = bytes(range(256)) * 12288


def _get(port: int, path: str, headers: dict[str, str] | None = None):
    """(status, headers, body, short) — a short read reported, never hidden."""
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=60)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        try:
            body, short = response.read(), False
        except http.client.IncompleteRead as partial:
            body, short = partial.partial, True
        return response.status, dict(response.getheaders()), body, short
    finally:
        connection.close()


def _ranged(port: int, path: str, start: int = WINDOW_START,
            end: int = WINDOW_END):
    return _get(port, path, headers={"Range": f"bytes={start}-{end}"})


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


def _audit(path: Path) -> list[str]:
    """The origin's command log — the only place ERET is visible as a fact."""
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


class _EretLab:
    def __init__(self, harness: LifecycleHarness, root: Path, tmp: Path):
        ports = {name: lifecycle_ports_for(f"lc-p115-eret-{name}")[0]
                 for name in ("origin", "plain-origin", "decoy-origin")}
        self.eret_audit = tmp / "lc-p115-eret-origin.log"
        self.plain_audit = tmp / "lc-p115-eret-plain-origin.log"
        self.decoy_audit = tmp / "lc-p115-eret-decoy-origin.log"
        capable = harness.start(self._origin(
            "lc-p115-eret-origin", ports["origin"], root, tmp,
            flags=("--eret",)))
        plain = harness.start(self._origin(
            "lc-p115-eret-plain-origin", ports["plain-origin"], root, tmp,
            flags=()))
        decoy = harness.start(self._origin(
            "lc-p115-eret-decoy-origin", ports["decoy-origin"], root, tmp,
            flags=("--feat-decoy",)))
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-p115-eret",
            template="nginx_lc_gsiftp_eret.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_PORT": capable.port,
                "PLAIN_ORIGIN_PORT": plain.port,
                "DECOY_ORIGIN_PORT": decoy.port,
                "ORIGIN_BASE": "/base",
                "ERET_EXPORT": str(tmp / "eret-export"),
                "PLAIN_EXPORT": str(tmp / "plain-export"),
                "DECOY_EXPORT": str(tmp / "decoy-export"),
            },
            reason="three identical WebDAV fronts over an ERET origin, one "
                   "that advertises nothing and one that advertises look-alikes",
        ))
        self.harness = harness
        self.root = root
        self.eret_port = endpoint.port
        self.plain_port = endpoint.extra_ports["PLAIN_PORT"]
        self.decoy_port = endpoint.extra_ports["DECOY_PORT"]
        self.decoy_origin_port = decoy.port
        self.error_log = Path(endpoint.prefix, "logs", "error.log")

    @staticmethod
    def _origin(name: str, port: int, root: Path, tmp: Path, *,
                flags: tuple[str, ...]):
        """One confined origin process, distinguished only by `flags`.

        Passed as the raw argv tail rather than as a keyword per capability:
        the three origins here differ by exactly one switch each, and a bool
        parameter per switch would have to be threaded through this signature
        every time the register grows another FEAT row.
        """
        argv = [sys.executable, "-m", "brix_suite.servers.ftp_origin_server",
                str(port), str(root), "--audit", str(tmp / f"{name}.log")]
        argv += list(flags)
        return NginxInstanceSpec(
            name=name,
            template="",
            kind="proc",
            protocol="ftp",
            readiness="tcp",
            data_root=str(root),
            template_values={"argv": argv},
            env={"PYTHONPATH": os.path.dirname(__file__)},
            reason="confined GridFTP origin " + (" ".join(flags) or "(bare)"),
        )

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    tmp = tmp_path_factory.mktemp("p115-eret")
    root = tmp / "origin"
    (root / "base").mkdir(parents=True)
    for name in ("eret-export", "plain-export", "decoy-export"):
        (tmp / name).mkdir()
    (root / "base" / "plain.bin").write_bytes(PAYLOAD)
    # One seed per ERET misbehaviour; the origin picks it from the NAME, so a
    # second origin process is never needed to prove a second refusal.
    for fault in ("refuse", "liar", "overrun", "hole"):
        (root / "base" / f"eret-{fault}-subject.bin").write_bytes(PAYLOAD)
    # Bigger than one BRIX_SERVE_OFFLOAD_FILL_CHUNK, so a window over it costs
    # the offload's drain loop more than one iteration.  §P9's multi-iteration
    # properties are unreachable on `plain.bin`, which fits inside a single
    # chunk and is therefore always fetched by exactly one retrieve.
    (root / "base" / "big.bin").write_bytes(BIG_PAYLOAD)
    harness = LifecycleHarness()
    lab = _EretLab(harness, root, tmp)
    yield lab
    lab.close()


# ---- success: the window is the window --------------------------------------

def test_ranged_read_over_an_eret_origin_is_byte_exact(lab):
    status, headers, body, short = _ranged(lab.eret_port, "/plain.bin")
    assert (status, short) == (206, False)
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]
    assert headers.get("Content-Range") == \
        f"bytes {WINDOW_START}-{WINDOW_END}/{len(PAYLOAD)}"


def test_eret_and_rest_retr_return_identical_bytes(lab):
    """The extension must be invisible above the driver.

    Asserted against the OTHER front, not against PAYLOAD alone: the claim is
    that two different command sequences agree, which is the actual contract.
    A fixture-only assertion would pass just as happily if both fronts were
    quietly reading from offset zero.
    """
    _, _, via_eret, _ = _ranged(lab.eret_port, "/plain.bin")
    _, _, via_rest, _ = _ranged(lab.plain_port, "/plain.bin")
    assert via_eret == via_rest == PAYLOAD[WINDOW_START:WINDOW_END + 1]


def test_the_origin_really_was_asked_for_a_window(lab):
    """Byte-exactness alone cannot tell ERET from REST+RETR.

    Both produce the right bytes, so without the origin's own command log this
    whole suite would pass unchanged if `gftp_eret_wanted` always returned 0 —
    it would be testing the RFC 959 path twice and reporting it as ERET.
    """
    _ranged(lab.eret_port, "/plain.bin")
    _ranged(lab.plain_port, "/plain.bin")
    capable = _audit(lab.eret_audit)
    assert any(line.startswith("ERET ") for line in capable), \
        f"no ERET reached the advertising origin: {capable[-20:]}"
    assert any(f"ERET P {WINDOW_START} " in line for line in capable), \
        f"ERET carried the wrong offset: {capable[-20:]}"
    assert not any(line.startswith("ERET ") for line in _audit(lab.plain_audit)), \
        "ERET was sent to an origin that never advertised it"


def test_a_whole_file_read_still_works_over_an_eret_origin(lab):
    """The unranged case is the common one and must not regress.

    ERET is issued for it too — the window is simply the whole file — so this
    is not a trivial repeat of the ranged test: it is the path every ordinary
    GET against an ERET-capable origin now takes.
    """
    status, _, body, short = _get(lab.eret_port, "/plain.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD


# ---- error: advertised, then refused ----------------------------------------

def test_an_origin_that_refuses_its_own_advertisement_is_still_served(lab):
    """FEAT says ERET; the implementation answers 500.  Doors do this.

    The driver must fall back rather than fail a read of a file that is plainly
    there — but the fallback is the POSITIONED REST+RETR path.  The bytes prove
    which one it took: an unpositioned RETR would return the head of the file,
    and PAYLOAD is built so the head cannot be mistaken for the middle.
    """
    status, _, body, short = _ranged(lab.eret_port, "/eret-refuse-subject.bin")
    assert (status, short) == (206, False)
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]
    assert body != PAYLOAD[:len(body)], \
        "the fallback restarted at zero — an unpositioned RETR"


def test_the_refusal_is_visible_as_a_command_sequence(lab):
    """The fallback must be ONE ERET and then REST+RETR, on one session.

    Recorded because it is the compatibility layer's whole behaviour: a driver
    that retried ERET, or that reconnected, would still return the right bytes
    and would still pass the test above.
    """
    lab.eret_audit.write_text("", encoding="utf-8")
    _ranged(lab.eret_port, "/eret-refuse-subject.bin")
    lines = [line.split(" ")[0] for line in _audit(lab.eret_audit)]
    assert lines.count("ERET") == 1, f"ERET was retried: {lines}"
    assert "REST" in lines and "RETR" in lines, \
        f"the fallback was not the positioned RFC 959 path: {lines}"
    assert lines.index("REST") > lines.index("ERET"), \
        f"REST was sent before the ERET it falls back from: {lines}"


# ---- security negative: an origin that answers with the wrong bytes ---------

def test_an_eret_reply_outside_the_requested_window_is_refused(lab):
    """The origin ignores the window and answers with the whole file from 0.

    Nothing about that reply is malformed.  It is a real transfer of a real
    file, every byte genuine — it is simply more of the file than was asked
    for, starting in the wrong place.  In MODE S there would be no way to know:
    the driver would read the first 256 bytes off the socket and hand the HEAD
    of the file to a caller that believes it holds bytes 100000..100255, then
    answer 206 with a Content-Range that lies.  Silent corruption, dressed as a
    success, and produced by a door that merely does not implement ERET
    properly rather than by an attacker.

    MODE E blocks carry their absolute offset, so the receiver sees the
    mismatch and refuses.  That asymmetry is the entire reason `gftp_eret_wanted`
    returns 0 outside MODE E: the extension is only sent where its answer can be
    checked.  (An origin that also RELABELLED the blocks — head bytes carrying
    the requested offset — is indistinguishable from a corrupted file at this
    layer and belongs to the checksum layer, not to framing.)
    """
    status, _, body, short = _ranged(lab.eret_port, "/eret-liar-subject.bin")
    assert not (status == 206 and not short and len(body) == 256), \
        "an out-of-window ERET reply was served as a complete range"
    assert body[:32] != PAYLOAD[:32], \
        "the head of the file reached the client as the requested window"
    _await_log(lab.error_log, "outside the requested window")


def test_the_out_of_window_reply_is_refused_at_every_offset(lab):
    """Swept, because a single window could be refused by coincidence.

    Offset 0 is excluded deliberately: there "the whole file from 0" IS the
    requested window, the reply is correct, and asserting a refusal would be
    asserting that a conforming origin is rejected.
    """
    for start in (1, 65536, 200000):
        status, _, body, short = _ranged(lab.eret_port,
                                         "/eret-liar-subject.bin",
                                         start, start + 255)
        assert not (status == 206 and not short and len(body) == 256), \
            f"the out-of-window reply was accepted for the window at {start}"
        assert body[:32] != PAYLOAD[:32], \
            f"window at {start} was answered with the head of the file"


def test_a_refused_window_leaves_the_conforming_front_working(lab):
    """A refusal must not poison the lab, the worker or the next read.

    The refusal path tears down a data connection mid-transfer and marks the
    session failed; if any of that leaked — a wedged thread-pool task, a
    half-closed control socket reused from a cache — the damage would show up
    on the NEXT request rather than on the one that caused it.
    """
    _ranged(lab.eret_port, "/eret-liar-subject.bin")
    status, _, body, short = _ranged(lab.eret_port, "/plain.bin")
    assert (status, short) == (206, False)
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]


def test_an_eret_origin_that_over_runs_its_window_is_refused(lab):
    """ERET P declares the length, so bytes past it are the origin's fault.

    This is the counterweight to the surplus rule in the MODE E suite.  After a
    bare RETR the origin was never told where to stop, so blocks past the window
    end are the specification working and the receiver stops at the edge keeping
    what it asked for.  After ERET P the origin WAS told, in the same command
    that carried the offset, so the same blocks are a peer writing outside the
    address range it was given — and the answer must go back to a refusal.

    `liar` cannot pin this: it answers from offset 0, so it is refused on its
    offsets whatever the window rule says, and a driver that had dropped window
    policing altogether would still pass it.  `overrun` honours the offset and
    ignores the length, which is exactly and only the case the two rules
    disagree about.
    """
    status, _, body, short = _ranged(lab.eret_port, "/eret-overrun-subject.bin")
    assert not (status in (200, 206) and not short
                and body == PAYLOAD[WINDOW_START:WINDOW_END + 1]), \
        "an ERET reply that ran past its declared window was accepted"


def test_the_overrun_refusal_does_not_wedge_the_next_read(lab):
    """A refusal ends one transfer, not the driver.

    Pinned for the same reason the `liar` suite pins it: the refusal path tears
    down a data channel mid-block, and a session left holding a half-read block
    would poison the next caller instead of the one that misbehaved.
    """
    _ranged(lab.eret_port, "/eret-overrun-subject.bin")
    status, _, body, short = _ranged(lab.eret_port, "/plain.bin")
    assert (status, short) == (206, False)
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]


# ---- the FEAT terminator: how the whole extension was silently skipped ------
#
# Found 2026-09-07 while the MODE E surplus relaxation (W5.1) made it visible.
# `gftp_feat_line_is()` accepted a feature name followed by ' ', '\t' or NUL and
# by nothing else, so against a conforming door — where RFC 959 §4.2 makes every
# continuation line CRLF-terminated — it matched NOTHING.  ERET and SPAS were
# never once negotiated in production; the driver fell back to REST+RETR and to
# a single data connection, correctly, quietly, every time.
#
# That is the §H shape: the three tests above all read the right bytes whether
# the extension was used or skipped, and only `test_the_origin_really_was_asked_
# for_a_window` could tell — which is why the defect surfaced there and nowhere
# else.  These rows exist so it cannot go back to being invisible: one asserts
# the WIRE FORM the parser has to survive, one asserts the fallback is still the
# fallback, and one asserts the fix did not buy detection by loosening the match
# into a substring search.

def test_the_feat_reply_really_is_crlf_terminated(lab):
    """The census half: assert what the parser is actually handed.

    Every other test here would pass unchanged if this fixture wrote bare LF —
    and with bare LF the pre-fix parser worked, so a fixture that drifted would
    silently retire the coverage rather than fail.  Asserting the terminator on
    the WIRE is the cheapest thing that cannot drift: it is read from the origin
    over a socket, not from a constant in this file.
    """
    reply = ftp_origin_feat_bytes(SERVER_HOST, lab.decoy_origin_port)
    assert reply.startswith(b"211-"), reply[:80]
    assert b"\r\n" in reply, "the FEAT reply is not CRLF-terminated"
    assert b" REST STREAM\r\n" in reply, \
        f"a feature row is not CR-terminated: {reply!r}"
    assert b" REST STREAM\n\n" not in reply


def test_eret_is_detected_through_that_terminator(lab):
    """The success half, stated as detection rather than as bytes.

    Separate from `test_the_origin_really_was_asked_for_a_window` on purpose:
    that row asserts the OFFSET the command carried, and would keep failing for
    reasons that have nothing to do with FEAT.  This one asserts only that the
    capability was seen at all — the single bit whose loss cost the extension.
    """
    lab.eret_audit.write_text("", encoding="utf-8")
    _ranged(lab.eret_port, "/plain.bin")
    lines = _audit(lab.eret_audit)
    assert any(line.startswith("FEAT") for line in lines), \
        f"the driver never probed FEAT: {lines[-20:]}"
    assert any(line.startswith("ERET ") for line in lines), \
        ("FEAT advertised ERET over CRLF and the driver did not see it: "
         f"{lines[-20:]}")


def test_an_origin_that_advertises_nothing_still_gets_the_positioned_path(lab):
    """The error half: no capability, and the fallback is unchanged.

    The fix widened a terminator set, which is exactly the kind of change that
    can start matching where nothing was advertised at all.  The control origin
    answers a bare 211 list, so any ERET reaching it would be the parser reading
    a feature out of an empty advertisement.
    """
    lab.plain_audit.write_text("", encoding="utf-8")
    status, _, body, short = _ranged(lab.plain_port, "/plain.bin")
    assert (status, short) == (206, False)
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]
    verbs = [line.split(" ")[0] for line in _audit(lab.plain_audit)]
    assert "ERET" not in verbs, f"ERET was sent to an origin without it: {verbs}"
    assert "REST" in verbs and "RETR" in verbs, \
        f"the fallback was not the positioned RFC 959 path: {verbs}"
    assert verbs.index("REST") < verbs.index("RETR"), \
        f"RETR was sent before the REST that positions it: {verbs}"


# ---- security negative: a row that CONTAINS a feature is not the feature ----

def _assert_decoy_advertisement(reply: bytes) -> None:
    """The decoy rows are on the wire and the real ones are not.

    Split out of the test below only because the two halves are two different
    claims — what was offered, and what the driver did with it — and reading a
    failure is much easier when the message says which half broke.
    """
    for row in FEAT_DECOY:
        assert row.encode("ascii") + b"\r\n" in reply, \
            f"the decoy origin did not advertise {row!r}: {reply!r}"
    # Line-wise, not substring: " SITE ERET\r\n" ENDS with " ERET\r\n", and a
    # substring test would report the decoy origin as advertising the real
    # feature — the very confusion this whole row exists to rule out.
    rows = reply.split(b"\r\n")
    assert b" ERET" not in rows, "the decoy origin advertised real ERET"
    assert b" SPAS" not in rows, "the decoy origin advertised real SPAS"


def test_a_feat_row_that_merely_contains_eret_lights_no_bit(lab):
    """`ERETSTAT`, `SITE ERET`, `SPASV`, `X-ERET` — advertised, and inert.

    The cheap fix for the terminator bug is a substring search, and it would
    have made every test above green.  It would also make this origin's rows
    into capabilities: the driver would issue ERET and SPAS to a door that
    implements neither, take a 502 on each, and pay two round trips per read
    forever — and on a door where `SITE ERET` means something else entirely,
    it would be issuing a command it was never offered.

    The decoy rows are asserted to be on the wire first.  Without that this
    passes just as happily against an origin that advertised nothing at all,
    which is precisely the vacuous form of the test it is guarding against.
    """
    _assert_decoy_advertisement(
        ftp_origin_feat_bytes(SERVER_HOST, lab.decoy_origin_port))

    lab.decoy_audit.write_text("", encoding="utf-8")
    status, _, body, short = _ranged(lab.decoy_port, "/plain.bin")
    assert (status, short) == (206, False)
    assert body == PAYLOAD[WINDOW_START:WINDOW_END + 1]
    verbs = [line.split(" ")[0] for line in _audit(lab.decoy_audit)]
    assert "ERET" not in verbs, \
        f"a look-alike FEAT row was read as ERET: {verbs}"
    assert "SPAS" not in verbs, \
        f"a look-alike FEAT row was read as SPAS: {verbs}"


def test_the_look_alike_origin_serves_the_same_bytes_as_the_real_one(lab):
    """A refused capability must cost bytes, not correctness.

    Stated against the ERET front rather than against PAYLOAD alone for the
    same reason `test_eret_and_rest_retr_return_identical_bytes` is: the claim
    is that two command sequences agree, and a fixture-only assertion would
    hold just as well if both fronts were quietly reading from offset zero.
    """
    _, _, via_decoy, _ = _ranged(lab.decoy_port, "/plain.bin")
    _, _, via_eret, _ = _ranged(lab.eret_port, "/plain.bin")
    assert via_decoy == via_eret == PAYLOAD[WINDOW_START:WINDOW_END + 1]

