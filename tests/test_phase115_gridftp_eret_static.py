"""Static guard: phase-115 W5.2 — where ERET may be sent, and why ESTO is not.

W5.2 asked for the two GridFTP partial-transfer extensions.  Only ONE of them
was implemented, and the asymmetry is a design decision that has to be pinned
in the tree rather than remembered:

  * **ERET P** has a caller.  `sd_gsiftp_pread` issues a BOUNDED read on every
    read operation, and RFC 959 can only answer it with REST + a transfer that
    runs to EOF — so every ranged read leaves the origin pushing a tail nobody
    drains.  ERET carries the window and ends it.
  * **ESTO A** has none.  This driver has no partial-write path at all: writes
    go to a local scratch file and are published by ONE whole-file `STOR` plus
    a rename (`sd_gsiftp_staged.c`).  Implementing ESTO would ship a command
    nothing could ever emit — which is precisely the defect
    test_phase115_store_param_reachability.py exists to catch, and the same
    "deferred by design, with the boundary pinned" shape phase 114 used for the
    credential reaper.

So this file guards two things.  That ERET is only ever sent where its answer
can be VERIFIED (MODE E, whose blocks carry absolute offsets — in stream mode a
door that ignored the window would hand back the head of the file and nothing
could tell).  And that the ESTO deferral still holds: if a partial-write caller
ever appears on this driver, the reason for the deferral is gone and this test
must go red rather than let the register keep saying "by design".
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GSIFTP = REPO_ROOT / "src/fs/backend/gsiftp"

DATA_C = GSIFTP / "gftp_data.c"
FEAT_C = GSIFTP / "gftp_feat.c"
FEAT_H = GSIFTP / "gftp_feat.h"
CLIENT_H = GSIFTP / "gftp_client.h"
REPLY_C = GSIFTP / "gftp_reply.c"
CONTROL_C = GSIFTP / "gftp_control.c"
CONFIG = REPO_ROOT / "config"


def _body(path: Path, function: str) -> str:
    """The source of one top-level function, brace-matched."""
    text = path.read_text()
    match = re.search(rf"^{re.escape(function)}\(", text, re.M)
    assert match, f"{function} not found in {path.name} — it moved or was renamed"
    start = text.index("{", match.end())
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError(f"unbalanced braces in {function}")


# ---- ERET is only sent where the answer can be checked ----------------------

def test_eret_is_refused_outside_mode_e():
    """The MODE E guard is the security property, not a performance choice."""
    body = _body(DATA_C, "gftp_eret_wanted")
    assert "GFTP_DMODE_E" in body, \
        "gftp_eret_wanted no longer restricts ERET to MODE E"
    assert re.search(r"session->mode\s*!=\s*GFTP_DMODE_E", body), \
        "the MODE E guard is no longer a refusal on the wrong mode"


def test_eret_is_only_sent_when_the_origin_advertised_it():
    body = _body(DATA_C, "gftp_eret_wanted")
    assert "GFTP_FEAT_ERET" in body and "gftp_feat(" in body, \
        "ERET is no longer gated on the FEAT advertisement"


def test_the_feat_probe_is_lazy():
    """A session is one storage-driver call; an eager FEAT taxes every stat.

    `gftp_feat` must be reached from the retrieve decision and from nowhere
    else, or a listing pays a round trip for a capability it cannot use.
    """
    callers = {
        path.name
        for path in GSIFTP.glob("*.c")
        if path != FEAT_C and "gftp_feat(" in path.read_text()
    }
    # gftp_spas.c joined the set in W5.3 for the same reason gftp_data.c is in
    # it: the SPAS decision is part of ONE retrieve, taken after the driver
    # already knows a striped read is wanted.  Anything else appearing here is
    # a probe on a path that cannot spend the answer.
    assert callers == {"gftp_data.c", "gftp_spas.c"}, \
        f"gftp_feat() is now called from {sorted(callers)} — the probe is no " \
        "longer confined to the path that can use it"
    assert "feat_probed" in FEAT_C.read_text(), \
        "the probe no longer remembers that it ran"


def test_the_fallback_is_positioned_and_never_a_bare_retr():
    """An advertised-then-refused ERET must not restart the read at zero."""
    positioned = _body(DATA_C, "gftp_retrieve_positioned")
    assert "REST %lld" in positioned, \
        "the RFC 959 fallback no longer positions with REST"
    retr_sites = [
        function
        for function in ("gftp_retrieve_eret", "gftp_retrieve_positioned",
                         "gftp_retrieve")
        if '"RETR %s"' in _body(DATA_C, function)
    ]
    assert retr_sites == ["gftp_retrieve_positioned"], \
        f"RETR is emitted outside the positioned path: {retr_sites}"


def test_a_refused_eret_is_not_asked_again_on_the_same_session():
    body = _body(DATA_C, "gftp_retrieve_eret")
    assert re.search(r"session->feat\s*&=\s*~GFTP_FEAT_ERET", body), \
        "a refused ERET is no longer remembered — the next read re-asks"


def test_a_550_on_eret_is_the_file_failing_not_the_extension():
    """`550` says the PATH is unavailable; falling back would ask twice."""
    body = _body(DATA_C, "gftp_retrieve_eret")
    assert "550" in body and "ENOENT" in body, \
        "ERET no longer distinguishes a missing file from a missing extension"


# ---- the FEAT reply is only readable because of the continuation lines ------

def test_the_reply_scanner_keeps_the_continuation_lines():
    """A FEAT reply's final line is a bare "End": the payload is the middle.

    Before W5.2 the scanner stepped over the intermediate lines and kept only
    the terminator, so any capability probe built on `session->text` would have
    found nothing, always, and silently concluded the origin supports nothing.
    """
    assert "body_len" in REPLY_C.read_text(), \
        "gftp_reply_scan no longer reports the continuation lines"
    assert "cont" in _body(CONTROL_C, "gftp_store_reply"), \
        "the continuation lines are no longer kept on the session"
    assert "session->cont" in FEAT_C.read_text(), \
        "the FEAT probe reads the terminator line again — it will find nothing"


def test_the_continuation_buffer_truncates_rather_than_grows():
    """A capability list is short; an origin that floods it is not believed."""
    assert "GFTP_CONT_CAP" in CLIENT_H.read_text()
    assert "cont_truncated" in _body(CONTROL_C, "gftp_store_reply"), \
        "truncation of the continuation buffer is no longer recorded"


def test_feature_names_match_whole_tokens():
    """A feature name ends at a token boundary, and the SET of boundaries is
    what this asserts — not the spelling of any one comparison.

    The first version of this check grepped for the literal `line[len] ==
    \'\\0\'`.  That is the anti-pattern §H is about: the terminator set was
    \' \', \'\\t\' and NUL, so on a conforming door — where FEAT advertises each
    name on a CRLF-terminated continuation line — the matcher matched nothing,
    ERET and SPAS were never negotiated, and the pin was green throughout.  It
    then went red on the repair.  A set census reddens when a boundary is
    DROPPED and stays quiet when the same set is merely re-spelled.

    The behavioural proof — the matcher run over real reply bodies, plus a
    deliberate revert to the broken set — is test_phase115_gridftp_feat_tokens.
    """
    body = FEAT_C.read_text()
    assert "gftp_feat_line_is" in body, "the whole-token match was removed"
    boundaries = set(re.findall(r"after\s*==\s*\'(\\.|.)\'",
                                _body(FEAT_C, "gftp_feat_line_is")))
    assert boundaries == {"\\0", " ", "\\t", "\\r", "\\n"}, (
        f"the token-boundary set is {sorted(boundaries)}; dropping the line "
        "terminators makes every conforming advertisement invisible, and "
        "dropping the whitespace makes a parameterised line unreadable")


def test_the_new_source_is_registered_in_the_build():
    text = CONFIG.read_text()
    for name in ("gftp_feat.c", "gftp_feat.h"):
        assert name in text, f"{name} is not in the repo-root ./config"


# ---- ESTO: deferred by design, and the reason is checked, not remembered ----

# Every file that calls `gftp_store`, each one read for a windowed write:
#
#   sd_gsiftp_staged.c  — stages the whole request body to a scratch file and
#                         STOREs that file from byte 0.
#   sd_gsiftp_copy.c    — `sd_gsiftp_copy_publish` STOREs a scratch file to a
#                         temp name and RNFR/RNTOs it into place; its source
#                         callback preads sequentially from `written = 0`, so
#                         the object is written whole, never at an offset.
#
# gftp_data.c is excluded: it DEFINES gftp_store.
REVIEWED_STORE_CALLERS = {"sd_gsiftp_staged.c", "sd_gsiftp_copy.c"}


def _store_callers():
    """Every .c under src/ that CALLS gftp_store, less its definition site."""
    return {
        path.name
        for path in (REPO_ROOT / "src").rglob("*.c")
        if re.search(r"\bgftp_store\s*\(", path.read_text())
        and path.name != "gftp_data.c"
    }


def test_the_write_path_still_has_no_partial_caller():
    """The ESTO deferral rests on one fact: nothing writes at an offset.

    `gftp_store` takes a source callback and no offset, and its single caller
    hands it a whole scratch file.  If either changes, ESTO stops being
    unreachable and W5.2's deferral has to be revisited — so this fails loudly
    rather than leaving the register asserting something no longer true.
    """
    declaration = re.search(r"int gftp_store\((?P<args>[^;]*)\);",
                            CLIENT_H.read_text(), re.S)
    assert declaration, "gftp_store is no longer declared where W5.2 found it"
    args = declaration.group("args")
    assert "off_t" not in args and "offset" not in args, \
        "gftp_store now takes an offset — a partial write exists and ESTO is " \
        "no longer unreachable; revisit phase-115 W5.2"

    assert _store_callers() == REVIEWED_STORE_CALLERS, (
        "the gftp_store caller set changed (%s) — every caller must be read "
        "for a WINDOWED write before the ESTO deferral can still be trusted.  "
        "Review it, then add it to REVIEWED_STORE_CALLERS with the outcome."
        % sorted(_store_callers() ^ REVIEWED_STORE_CALLERS))


def test_no_store_caller_streams_from_a_nonzero_offset():
    """The PROPERTY the deferral actually needs, checked directly.

    Pinning the caller set alone was too weak in one direction and too strong
    in the other: it fired when `sd_gsiftp_copy.c` appeared (a whole-file temp
    publish, entirely benign) while never once looking at what a caller does.
    `gftp_source_fn` carries no offset argument, so a caller can only stream
    sequentially — which makes the one thing that could make ESTO reachable a
    ctx cursor that STARTS somewhere other than zero.  So read the cursor.
    """
    for name in sorted(REVIEWED_STORE_CALLERS):
        body = (GSIFTP / name).read_text()
        call = re.search(r"\bgftp_store\s*\(", body)
        assert call, f"{name} no longer calls gftp_store"
        # The ctx is initialised in the same function, above the call.
        preamble = body[:call.start()]
        func_start = preamble.rfind("\n{")
        init = preamble[func_start:]
        cursors = re.findall(r"\.?\b(?:written|offset|off|pos)\s*=\s*([^;,\n]+)",
                             init)
        assert cursors, (
            f"{name} calls gftp_store without initialising a source cursor "
            "anywhere in the calling function — read it by hand before "
            "trusting the ESTO deferral")
        for value in cursors:
            assert value.strip() in ("0", "0u", "(off_t) 0", "(size_t) 0"), (
                f"{name} starts its gftp_store source at {value.strip()!r}, "
                "not 0 — that is a WINDOWED write, ESTO is no longer "
                "unreachable, and phase-115 W5.2's deferral must be revisited")


def test_esto_is_absent_rather_than_half_present():
    """Half an extension is worse than none: it advertises what it cannot do."""
    emitted = {
        path.name
        for path in GSIFTP.glob("*.c")
        if re.search(r'"ESTO', path.read_text())
    }
    assert not emitted, \
        f"ESTO is emitted by {sorted(emitted)} but has no partial-write caller"
    assert "GFTP_FEAT_ESTO" not in FEAT_H.read_text(), \
        "ESTO is probed for but never sent — an unreachable capability"
