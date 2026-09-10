"""Static guard: phase-115 W5.3 — the SPAS address rule, and why SPOR is not.

W5.3 asked for the two GridFTP striped-passive extensions.  Only ONE of them
was implemented, and as in W5.2 the asymmetry is a design decision that has to
be pinned in the tree rather than remembered:

  * **SPAS** has a caller.  `gftp_retrieve` opens a data channel on every read,
    and a single TCP connection is a single congestion window — the reason a
    GridFTP door exists is links where that costs most of the bandwidth.
  * **SPOR** has none, and could not have one.  SPOR is the client handing the
    SERVER ports to dial, which requires this driver to LISTEN.  It is strictly
    a passive client: it never binds, and opening listeners from a blocking VFS
    worker thread inside nginx is a different lifetime problem from anything
    this driver solves today.  Same "deferred by design, boundary pinned" shape
    as W5.2's ESTO and phase 114's credential reaper.

The rest of this file guards THE security property.  `gftp_dc_open()` discards
PASV's address on purpose and dials the control channel's pinned numeric peer;
a SPAS reply is the one place in this protocol where the origin hands the client
a LIST of addresses.  Dialling them is the classic FTP bounce — the driver
becomes an origin-directed port scanner running inside the operator's network.
Every stripe must therefore equal the control peer, and the code that enforces
it must stay both PRESENT and REACHABLE: a check that stops being called is
worse than one that was never written, because the register still claims it.

The live proof is tests/test_phase115_gridftp_spas.py; this file is what fails
when the property is refactored away rather than exercised.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GSIFTP = REPO_ROOT / "src/fs/backend/gsiftp"

SPAS_C = GSIFTP / "gftp_spas.c"
SPAS_H = GSIFTP / "gftp_spas.h"
DATA_C = GSIFTP / "gftp_data.c"
DC_C = GSIFTP / "gftp_dc.c"
DC_H = GSIFTP / "gftp_dc.h"
CLIENT_H = GSIFTP / "gftp_client.h"
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


# ---- SECURITY: every stripe is checked against the pinned control peer -------

def test_every_stripe_is_compared_against_the_control_peer():
    """The address check exists and compares against `session->peer_ip`.

    `peer_ip` is the NUMERIC address the control channel actually connected to
    — not a name the origin supplied, and not a name re-resolved later — which
    is what makes the comparison meaningful rather than a formality.
    """
    body = _body(SPAS_C, "gftp_spas_same_peer")
    assert "session->peer_ip" in body, \
        "the stripe check no longer compares against the control channel's peer"
    assert "strcmp" in body, \
        "the stripe check is no longer an equality test on the address"


def test_the_address_check_is_reachable_from_the_stripe_parser():
    """A check nobody calls is worse than one nobody wrote.

    Pinned separately from its existence because the two fail independently:
    a refactor that kept `gftp_spas_same_peer` and stopped calling it would
    leave this suite's other rows green and the bounce wide open.
    """
    body = _body(SPAS_C, "gftp_spas_line")
    assert "gftp_spas_same_peer" in body, \
        "the per-stripe parser no longer checks the advertised address"


def test_a_foreign_stripe_abandons_the_whole_reply():
    """One bad stripe must not merely be SKIPPED.

    Dropping it and dialling the rest would leave the origin's remaining
    stripes holding blocks nobody reads — a hang — and would still have let
    the origin choose which of its addresses the driver connects to.  The
    parser therefore returns failure for the reply, not for the line.
    """
    body = _body(SPAS_C, "gftp_spas_line")
    assert "return -1" in body, \
        "a stripe that fails the address check no longer abandons the reply"
    parse = _body(SPAS_C, "gftp_spas_parse")
    assert "gftp_spas_line" in parse, \
        "the reply parser no longer runs the per-stripe check"


def test_a_truncated_stripe_list_refuses_the_reply():
    """Truncation must refuse the REPLY, not silently shorten it.

    The continuation buffer is finite.  For the FEAT probe, truncation can only
    LOSE a feature, so it fails safe.  Here it would silently DROP stripes —
    and the driver would then wait for EOD blocks on connections nobody opened.
    """
    body = _body(SPAS_C, "gftp_spas_parse")
    assert "cont_truncated" in body, \
        "a truncated continuation buffer no longer refuses the stripe list"


def test_the_dialler_is_given_an_address_rather_than_choosing_one():
    """`gftp_dc_open_at` dials what it is TOLD, so policy stays with the caller.

    The split is deliberate: the ordinary path keeps discarding PASV's address
    inside `gftp_dc_open`, and only the SPAS path — the one that can express an
    address policy — is allowed to name a peer.
    """
    assert "gftp_dc_open_at" in DC_H.read_text(), \
        "the address-taking dialler is gone"
    ordinary = _body(DC_C, "gftp_dc_open")
    assert "session->peer_ip" in ordinary, \
        "the ordinary data channel no longer pins itself to the control peer"


# ---- the ceiling is the operator's, not the origin's -------------------------

def test_an_over_budget_stripe_list_is_refused():
    body = _body(SPAS_C, "gftp_spas_request")
    assert "want_streams" in body, \
        "the stripe list is no longer checked against the operator's budget"


def test_the_refusal_is_remembered_for_the_session():
    """Ask-once, exactly as the ERET probe does — a refusal is not free."""
    body = _body(SPAS_C, "gftp_spas_request")
    assert re.search(r"session->feat\s*&=\s*~GFTP_FEAT_SPAS", body), \
        "a refused SPAS is re-asked on the next read"


def test_striping_is_confined_to_mode_e():
    """Blocks reassemble by absolute offset, and only MODE E carries one."""
    body = _body(SPAS_C, "gftp_spas_wanted")
    assert "GFTP_DMODE_E" in body, \
        "gftp_spas_wanted no longer restricts striping to MODE E"


def test_striping_is_only_attempted_when_the_origin_advertised_it():
    body = _body(SPAS_C, "gftp_spas_wanted")
    assert "GFTP_FEAT_SPAS" in body and "gftp_feat(" in body, \
        "SPAS is no longer gated on the FEAT advertisement"


def test_the_stripe_count_is_bounded_by_the_connection_array():
    """The parser may never write more ports than the group can hold."""
    body = _body(SPAS_C, "gftp_spas_line")
    assert "GFTP_STREAMS_MAX" in body, \
        "the stripe list is no longer bounded by the connection array"


# ---- every way of not striping still opens the one pinned connection ---------

def test_the_fallback_is_the_ordinary_pinned_connection():
    """One exit for all four refusals, so none can be added without a fallback.

    `gftp_dc_group_open` is written as a single short-circuit: everything that
    is not a successfully dialled stripe list falls through to `gftp_dc_open`.
    A future refusal added as its own early return would be a way to fail a
    transfer over a PERFORMANCE decision, which is the one thing `streams=`
    must never do.
    """
    body = _body(SPAS_C, "gftp_dc_group_open")
    assert "gftp_dc_open(session, &group->conns[0])" in body, \
        "the un-striped fallback no longer opens the ordinary data channel"
    assert body.count("return -1") == 1, \
        "gftp_dc_group_open grew a second failure exit; a striped attempt " \
        "that cannot be made must degrade, never fail the transfer"


def test_a_partial_dial_closes_what_it_opened():
    """Half a stripe group is a leak plus a hang; it must be torn down."""
    body = _body(SPAS_C, "gftp_spas_dial")
    assert "gftp_dc_group_close" in body, \
        "a failed stripe dial no longer closes the connections it opened"


# ---- SPOR is deferred, and the boundary is what says so ----------------------

def test_the_driver_never_listens():
    """SPOR would need a listening socket; this driver is a passive client.

    Pinned as an absence, because that is the whole claim.  A `listen()` or a
    `bind()` appearing anywhere in the gsiftp driver means the deferral's
    premise is gone and the register may no longer say "by design".
    """
    offenders = {}
    for path in sorted(GSIFTP.glob("*.c")):
        hits = [line.strip() for line in path.read_text().splitlines()
                if re.search(r"\b(listen|bind)\s*\(", line)]
        if hits:
            offenders[path.name] = hits
    assert not offenders, \
        f"the gsiftp driver now binds or listens: {offenders} — SPOR's " \
        "deferral rested on it never doing so"


def test_the_store_path_is_not_striped():
    """STOR stays single-connection: the striped counterpart is SPOR.

    `gftp_store` must keep using the single-channel open.  A group here would
    be a striped RETRIEVE channel used for a send — stripes the origin never
    agreed to and will not read.
    """
    body = _body(DATA_C, "gftp_store")
    assert "gftp_transfer_begin" in body, \
        "gftp_store no longer opens a single data channel"
    assert "gftp_dc_group_open" not in body, \
        "gftp_store now opens a stripe group; SPOR is not implemented and " \
        "an origin will not read stripes it never advertised"


def test_spor_is_not_implemented_anywhere():
    """The command must not appear on the wire at all."""
    offenders = [path.name for path in sorted(GSIFTP.glob("*.c"))
                 if '"SPOR' in path.read_text()]
    assert not offenders, \
        f"SPOR is now sent from {offenders} — it needs a listening driver, " \
        "and the W5.3 register entry says it is deferred"


# ---- the module is built, not merely written --------------------------------

def test_the_stripe_module_is_registered_in_the_build():
    """A source file nobody compiles is a test that cannot fail.

    Pinned after W5.3 shipped this file and the tree stopped linking: the
    callers landed in gftp_data.c before gftp_spas.c reached ./config.
    """
    config = CONFIG.read_text()
    assert "gsiftp/gftp_spas.c" in config, \
        "gftp_spas.c is not in the module source list"
    assert "gsiftp/gftp_spas.h" in config, \
        "gftp_spas.h is not in the module header list"
