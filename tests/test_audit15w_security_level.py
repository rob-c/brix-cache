"""brix_security_level at VALUE granularity — audit §Method, 15th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 36 ``ngx_conf_enum_t`` tables in
``src/`` turned 93 pairs into 48 written and 45 never written.
``brix_security_level`` contributes two of those 45, and they are the two that
switch enforcement OFF:

    standard    written — test_security_level.py reads its advertised byte,
                test_audit15f_sigver_crosses.py drives its opcode set
    intense     written — nginx_lc_audit_signing.conf, nginx_audit15f_sigver.conf
    pedantic    written — test_security_level.py reads its advertised byte
    none        NEVER written, on any plane
    compatible  NEVER written, on any plane

So the tokens an operator reaches for to relax a signing policy had no test at
all, and the two enforcing tokens were only ever measured one plane at a time.
The boundary between "this token enforces something" and "this token enforces
nothing" is what a reader of a config actually needs to know, and a boundary
cannot be established from either side alone.

WHAT THE VALUE SELECTS
----------------------
The token is stored as ``conf->security_level`` (0..4) and read in exactly two
places:

    protocol.c:143-151   the 6-byte kXR_protocol security trailer — seclvl is
                         the level itself, and secopt carries kXR_secOData iff
                         the level is >= 4 (pedantic), telling the client to
                         sign write payloads as well as headers.
    sigver.c:207-246     enforcement.  Level 0 returns before any opcode is
                         examined; otherwise brix_gsi_sigver_required(op, level)
                         (gsi_core.c:162-196) decides, and it answers 0 for
                         EVERY opcode when level <= 1.  So `compatible` is
                         advertised but, by construction, requires nothing.

WHAT THE TABLE ESTABLISHES
--------------------------
Six listeners on ONE instance, all ``brix_auth none`` (only GSI ever arms a
signing key, so an anonymous session is the unsignable case the policy is
written against) and all ``brix_signing_required on`` (which is what turns the
policy into a verdict instead of a log line).  Measured:

    plane                seclvl  secopt  kXR_stat   kXR_open   logs?
    none                 0       0       served     served     silent
    compatible           1       0       served     served     silent
    standard             2       0       served     REFUSED    warns
    intense              3       0       REFUSED    REFUSED    warns
    pedantic             4       1       REFUSED    REFUSED    warns
    (directive absent)   0       0       served     served     silent

Three separate things are visible in that table and nowhere else:

  * the enforcement boundary sits between ``compatible`` and ``standard``, not
    between ``none`` and ``compatible``, even though the wire advertisement
    changes at the other seam;
  * ``standard`` refusing kXR_open while serving kXR_stat is the opcode policy
    table, not a blanket deny — the same two opcodes on the next listener up
    (``intense``) are both refused;
  * off-GSI, ``pedantic`` adds nothing to ``intense`` except the advertised
    kXR_secOData bit.  Its extra rule (sigver.c:237 — a signature that skipped
    the payload) is unreachable without a signature to inspect.

The last row pins the merge default at 0/none
(server_conf_merge_security.c:244).

FINDING — DEFECT CANDIDATE #54
------------------------------
The unsignable-session WARN ends with a fixed remediation sentence, whatever
the flag it is advising about is set to (sigver.c:182-188):

    brix: brix_security_level=3 requires signed requests but this session's
    auth protocol established no signing key (only GSI does); requests are
    REFUSED. Set brix_signing_required on to refuse them.

The line states the requests ARE refused and then tells the operator to turn on
the switch that refused them.  Only the "requests are %s" clause is conditional;
the advice is unconditional.  ``test_the_remediation_advice_contradicts_the_
verdict`` pins today's text so a fix has to come past it.

FINDING — DEFECT CANDIDATE #55
------------------------------
``brix_security_level none`` (or ``compatible``) together with
``brix_signing_required on`` is a configuration that can never do anything: the
flag is read only on the path level 0/1 returns before reaching
(sigver.c:211-224).  ``nginx -t`` accepts it without a word, and no line is
logged at run time either — the once-per-session WARN lives inside the branch
that never executes.  An operator who set the fail-closed flag and left the
level at its default has no signing enforcement and no way to discover that
from the server.  §E and §F pin both halves (run-time silence, parse-time
silence).
"""

import os
import struct
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
# The trailer parser and the request framing both already exist: reuse them so
# this file measures the level and never the wire format.
from test_security_level import (_connect, _login, _protocol, _send_req,
                                 _security_requirements, kXR_ok, kXR_open,
                                 kXR_open_read, kXR_secOData)

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15w-seclevel")]

NAME = "lc-audit15w-seclevel"

kXR_stat = 3017
kXR_error = 4003
kXR_NotAuthorized = 3010

PROBE = b"audit15w-security-level-probe\n" * 4
PROBE_PATH = b"/probe.bin"

# The six listeners, by the template placeholder that carries each one.  PORT is
# the instance's own port; the rest arrive as extra_ports.
NONE, COMPATIBLE = "PORT", "CMP_PORT"
STANDARD, INTENSE, PEDANTIC = "STD_PORT", "INT_PORT", "PED_PORT"
DEFAULT = "DEF_PORT"
ALL_PLANES = (NONE, COMPATIBLE, STANDARD, INTENSE, PEDANTIC, DEFAULT)
RELAXING = (NONE, COMPATIBLE, DEFAULT)
ENFORCING = (STANDARD, INTENSE, PEDANTIC)

# What each plane's token is worth as a number, which is both the advertised
# seclvl byte and the level the WARN names.
LEVEL = {NONE: 0, COMPATIBLE: 1, STANDARD: 2, INTENSE: 3, PEDANTIC: 4,
         DEFAULT: 0}

WARN = "requires signed requests but this session's auth protocol"
ADVICE = "Set brix_signing_required on to refuse them."


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

@pytest.fixture
def seclevel(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / PROBE_PATH.decode().lstrip("/")).write_bytes(PROBE)

    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15w_seclevel.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        reason="audit-15w brix_security_level at value granularity"))


# --------------------------------------------------------------------------- #
# Client                                                                       #
# --------------------------------------------------------------------------- #

def _port(endpoint, plane):
    return endpoint.port if plane == NONE else endpoint.extra_ports[plane]


def _session(endpoint, plane, flags=0x01):
    """Handshake + kXR_protocol + anonymous kXR_login on one plane.

    All three are signing-exempt at every level (gsi_core.c:164-167), so this
    succeeds on the pedantic plane too — which is itself worth stating: a level
    that locked out the session state machine would be unusable rather than
    strict.  Returns (socket, the kXR_protocol response body)."""
    sock = _connect(_port(endpoint, plane), host=HOST)
    status, body = _protocol(sock, flags=flags)
    assert status == kXR_ok, f"kXR_protocol refused on {plane} (status={status})"
    _login(sock)
    return sock, body


def _verdict(res):
    """'served', or 'refused:<errno>' — the shape every case compares on."""
    status, data = res
    if status == kXR_ok:
        return "served"
    if status == kXR_error and len(data) >= 4:
        return f"refused:{struct.unpack('>I', data[:4])[0]}"
    return f"status:{status}"


def _stat(sock):
    return _verdict(_send_req(sock, b"\x00\x04", kXR_stat,
                              payload=PROBE_PATH + b"\x00"))


def _open(sock):
    body = struct.pack(">HHH", 0, kXR_open_read, 0) + b"\x00" * 10
    return _verdict(_send_req(sock, b"\x00\x03", kXR_open, body=body,
                              payload=PROBE_PATH + b"\x00"))


def _probe(endpoint, plane):
    """One session, one kXR_stat and one kXR_open; returns both verdicts."""
    sock, _body = _session(endpoint, plane)
    try:
        return {"stat": _stat(sock), "open": _open(sock)}
    finally:
        sock.close()


def _advert(endpoint, plane):
    sock, body = _session(endpoint, plane)
    try:
        return _security_requirements(body)
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# The log                                                                      #
# --------------------------------------------------------------------------- #

def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except OSError:
        return "(error log unavailable)"


def _await(endpoint, needle, timeout=15):
    """Wait for `needle` to reach the log; returns the whole log either way.

    The WARN is written by the worker after the refusal is already on the wire,
    so a read straight after the reply can lose the race.
    """
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        text = _errlog(endpoint)
        if needle in text:
            return text
        time.sleep(0.25)
    return text


def _level_lines(text, level):
    return [line for line in text.splitlines()
            if f"brix_security_level={level}" in line and WARN in line]


# --------------------------------------------------------------------------- #
# §A — the token is advertised on the wire                                     #
# --------------------------------------------------------------------------- #

class TestTheLevelIsAdvertisedOnTheWire:
    """kXR_protocol with kXR_secreqs is where a client learns what it must
    sign.  test_security_level.py pins two points of this curve (2 and 4);
    what was never measured is that the byte tracks the token across ALL of
    it — including the two values that mean "sign nothing"."""

    def test_every_token_advertises_its_own_seclvl_byte(self, seclevel):
        """success: one dict, six planes, no interpolation.

        seclvl is a raw number on the wire and the enum maps names to it
        positionally (module_enums.c:89-96); inserting a token in the middle of
        that table would renumber every level above it and silently reinterpret
        every deployed client's idea of what must be signed.  This is the test
        that would notice."""
        got = {plane: _advert(seclevel, plane)["seclvl"] for plane in ALL_PLANES}
        assert got == LEVEL, (
            "the advertised seclvl no longer matches the configured token; "
            f"expected {LEVEL}, measured {got}")

    def test_only_pedantic_asks_for_payload_signing(self, seclevel):
        """kXR_secOData tells the client to cover write payload bytes as well
        as the header (client/lib/auth/sigver.c:62).  It is a >= 4 test in the
        C, so it is the one bit that separates pedantic from intense on a plane
        where neither can actually verify anything."""
        got = {plane: _advert(seclevel, plane)["secopt"] for plane in ALL_PLANES}
        expected = {plane: (kXR_secOData if plane == PEDANTIC else 0)
                    for plane in ALL_PLANES}
        assert got == expected, (
            f"kXR_secOData is advertised on the wrong planes: {got}")

    def test_no_plane_advertises_a_security_vector(self, seclevel):
        """security-negative: secvsz stays 0 whatever the level.

        A non-zero secvsz means "N more bytes of per-request overrides follow",
        and the trailer is written as a fixed 6 bytes (protocol.c:150).  A level
        that set it would send a conformant client reading off the end of the
        response body."""
        got = {plane: _advert(seclevel, plane)["secvsz"] for plane in ALL_PLANES}
        assert set(got.values()) == {0}, (
            f"a security vector was advertised without one being sent: {got}")


# --------------------------------------------------------------------------- #
# §B — the relaxing tokens enforce nothing                                     #
# --------------------------------------------------------------------------- #

class TestTheRelaxingTokensEnforceNothing:
    """The two never-written values.  Both planes carry
    ``brix_signing_required on``, so they are configured as strictly as this
    directive pair allows, and both serve every request anyway."""

    def test_none_serves_a_covered_opcode_with_signing_required_on(
            self, seclevel):
        """success: `none` short-circuits before the opcode table is consulted
        (sigver.c:211), so the fail-closed flag beside it is dead code for this
        listener."""
        assert _probe(seclevel, NONE) == {"stat": "served", "open": "served"}, (
            "brix_security_level none refused a request; the level that means "
            "'no signing' must never gate an opcode")

    def test_compatible_serves_what_the_next_listener_up_refuses(self, seclevel):
        """The differential, and the reason `compatible` needed its own test.

        Same instance, same auth, same file, same opcode — the only thing that
        differs between these two listeners is the token, and it moves a
        request from refused to served."""
        compatible = _probe(seclevel, COMPATIBLE)
        standard = _probe(seclevel, STANDARD)
        assert compatible["open"] == "served", (
            "brix_security_level compatible refused kXR_open; "
            "brix_gsi_sigver_required answers 0 for every opcode at level 1")
        assert standard["open"].startswith("refused:"), (
            "the contrast plane stopped refusing, so this comparison no longer "
            f"measures the token: standard -> {standard['open']}")

    def test_the_refusal_carries_not_authorized(self, seclevel):
        """error: when a level does refuse, it refuses with the code the
        directive documents — not a server error, and not a storage errno."""
        assert _probe(seclevel, STANDARD)["open"] == \
            f"refused:{kXR_NotAuthorized}", (
                "a covered opcode on an unsignable session must fail with "
                "kXR_NotAuthorized")

    def test_compatible_advertises_a_level_it_does_not_enforce(self, seclevel):
        """security-negative: the advertisement and the enforcement disagree by
        design at level 1.

        A client that honours the trailer signs; a client that ignores it is
        served exactly the same.  An operator reading `compatible` as "signing
        where the client supports it" gets no server-side guarantee at all —
        the only thing that changed is what the server ASKED for."""
        sock, body = _session(seclevel, COMPATIBLE)
        try:
            assert _security_requirements(body)["seclvl"] == 1, \
                "compatible must still advertise level 1"
            assert _open(sock) == "served", (
                "an unsigned request was refused at compatible; if the level "
                "now enforces, this file's table and §E's silence both change")
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# §C — the level picks WHICH opcodes are covered                               #
# --------------------------------------------------------------------------- #

class TestTheLevelPicksTheCoveredOpcodes:
    """One matrix, measured in one pass, because the claim is about the shape
    of the gradient rather than about any single cell."""

    def test_the_covered_opcode_matrix(self, seclevel):
        """success + error in one measurement: six planes x two opcodes.

        kXR_open is in the level-2 set and kXR_stat is not (gsi_core.c:168-172),
        so `standard` splits them and `intense` does not.  That split is the
        whole content of "standard" — a reader who assumes it means "signing on"
        loses every read-side opcode."""
        expected = {
            (NONE, "stat"): "served", (NONE, "open"): "served",
            (COMPATIBLE, "stat"): "served", (COMPATIBLE, "open"): "served",
            (STANDARD, "stat"): "served",
            (STANDARD, "open"): f"refused:{kXR_NotAuthorized}",
            (INTENSE, "stat"): f"refused:{kXR_NotAuthorized}",
            (INTENSE, "open"): f"refused:{kXR_NotAuthorized}",
            (PEDANTIC, "stat"): f"refused:{kXR_NotAuthorized}",
            (PEDANTIC, "open"): f"refused:{kXR_NotAuthorized}",
            (DEFAULT, "stat"): "served", (DEFAULT, "open"): "served",
        }
        got = {(plane, op): verdict
               for plane in ALL_PLANES
               for op, verdict in _probe(seclevel, plane).items()}
        assert got == expected, (
            "the level -> covered-opcode gradient moved:\n"
            + "\n".join(f"  {plane:<9} {op:<5} {got[(plane, op)]:>16}"
                        f"  (expected {expected[(plane, op)]})"
                        for (plane, op) in expected
                        if got[(plane, op)] != expected[(plane, op)]))

    def test_pedantic_costs_nothing_beyond_intense_off_gsi(self, seclevel):
        """The honest limit of this plane: pedantic's extra rule needs a
        signature to inspect (sigver.c:237 checks a sigver nodata flag against a
        non-empty payload), and an unsignable session never produces one.  So
        the two levels are indistinguishable here except in the advertisement —
        which is exactly why §A measures that byte separately."""
        assert _probe(seclevel, PEDANTIC) == _probe(seclevel, INTENSE), (
            "pedantic and intense diverged on an unsignable session; the extra "
            "pedantic rule was believed unreachable without a signature")

    def test_the_handshake_opcodes_stay_exempt_at_every_level(self, seclevel):
        """security-negative in the other direction: strictness must not lock
        the door it is guarding.

        kXR_protocol and kXR_login are exempt at every level, so a session can
        still be established on the pedantic plane — _session() asserts both
        replies, so reaching the end of this loop is the assertion."""
        for plane in ALL_PLANES:
            sock, _body = _session(seclevel, plane)
            sock.close()


# --------------------------------------------------------------------------- #
# §D — the merge default                                                       #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """A listener with no brix_security_level at all.  Everything else on it is
    identical to the `none` listener, so any difference is the default."""

    def test_the_absent_directive_advertises_level_zero(self, seclevel):
        assert _advert(seclevel, DEFAULT)["seclvl"] == 0, (
            "the merge default moved off 0/none "
            "(server_conf_merge_security.c:244) — every deployment that omits "
            "the directive just started demanding signatures")

    def test_the_absent_directive_is_indistinguishable_from_none(self, seclevel):
        """success: same advertisement, same verdicts.

        Written out because "the default is none" is a claim about two
        different code paths — NGX_CONF_UNSET_UINT surviving the merge, and the
        enum happening to map `none` to the same 0 — and only comparing them
        tests both."""
        assert _advert(seclevel, DEFAULT) == _advert(seclevel, NONE)
        assert _probe(seclevel, DEFAULT) == _probe(seclevel, NONE)

    def test_the_default_plane_carries_the_flag_that_cannot_fire(self, seclevel):
        """security-negative, and the shape of defect candidate #55 as a
        deployment: this listener says `brix_signing_required on` and serves
        every unsigned request, because the level it was left at can require
        nothing."""
        assert _probe(seclevel, DEFAULT)["open"] == "served"


# --------------------------------------------------------------------------- #
# §E — what the operator is told                                               #
# --------------------------------------------------------------------------- #

class TestWhatTheOperatorIsTold:
    """The run-time half of #54 and #55.  Every line here is attributed by the
    ``brix_security_level=<n>`` field the WARN carries, so listeners can share
    one log without the assertions sharing evidence."""

    def test_each_enforcing_level_names_itself_in_the_log(self, seclevel):
        """success: the gap is visible.  One line per enforcing plane, naming
        the level that refused and stating the outcome."""
        for plane in ENFORCING:
            _probe(seclevel, plane)
        text = _await(seclevel, f"brix_security_level={LEVEL[PEDANTIC]}")
        for plane in ENFORCING:
            assert _level_lines(text, LEVEL[plane]), (
                f"no unsignable-session WARN for {plane} "
                f"(security_level={LEVEL[plane]})\n{text[-2000:]}")
            assert "requests are REFUSED" in text, (
                "the WARN must say what happened to the request")

    def test_the_relaxing_levels_say_nothing_at_all(self, seclevel):
        """DEFECT CANDIDATE #55, run-time half: levels 0 and 1 produce no line
        even with brix_signing_required on, because the branch that logs is
        inside the branch that never runs (sigver.c:211).

        The absence is synchronised, not raced: an enforcing plane is probed
        LAST and its line waited for, and the single worker writes the log in
        order — so once that line is present, any line the earlier probes were
        going to write is already there."""
        for plane in RELAXING:
            _probe(seclevel, plane)
        _probe(seclevel, INTENSE)
        text = _await(seclevel, f"brix_security_level={LEVEL[INTENSE]}")

        for plane in RELAXING:
            assert not _level_lines(text, LEVEL[plane]), (
                f"{plane} now logs something — if the silence was closed, this "
                "test should assert the new line rather than be deleted\n"
                + "\n".join(_level_lines(text, LEVEL[plane])))

    def test_one_line_per_session_not_per_request(self, seclevel):
        """The line is a property of the session's auth protocol, which cannot
        change mid-session, so a per-request line would be pure flood
        (sigver.c:180).  Measured as a delta so earlier cases' lines cannot be
        mistaken for this session's."""
        before = len(_level_lines(_await(seclevel, WARN, timeout=1),
                                  LEVEL[INTENSE]))
        sock, _body = _session(seclevel, INTENSE)
        try:
            assert _stat(sock).startswith("refused:")
            assert _open(sock).startswith("refused:")
            assert _stat(sock).startswith("refused:")
        finally:
            sock.close()

        deadline = time.time() + 15
        after = before
        while time.time() < deadline:
            after = len(_level_lines(_errlog(seclevel), LEVEL[INTENSE]))
            if after > before:
                break
            time.sleep(0.25)
        assert after == before + 1, (
            f"three covered requests on one session produced {after - before} "
            "WARN lines; the posture is logged once per session")

    def test_the_remediation_advice_contradicts_the_verdict(self, seclevel):
        """DEFECT CANDIDATE #54.

        The advice clause is unconditional (sigver.c:185-186) while the outcome
        clause is not, so on a plane that already sets the flag the one line
        says both "requests are REFUSED" and "Set brix_signing_required on to
        refuse them."  Pinned rather than tolerated: when the message is fixed
        this test fails, and the fix is to assert the new text."""
        _probe(seclevel, INTENSE)
        text = _await(seclevel, f"brix_security_level={LEVEL[INTENSE]}")
        lines = _level_lines(text, LEVEL[INTENSE])
        assert lines, f"no WARN to inspect\n{text[-2000:]}"
        assert all("requests are REFUSED" in line and ADVICE in line
                   for line in lines), (
            "the unsignable-session WARN no longer advises turning on the flag "
            "it just reported acting on — update this test to the new wording\n"
            + "\n".join(lines))


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"        {line}\n" for line in lines)


def _parse(tmp_path, knobs="", stream_extra=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15w_secparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """What the enum accepts and refuses.  Nothing here starts a server, and
    every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("token", ["none", "compatible", "standard",
                                       "intense", "pedantic"])
    def test_every_token_in_the_table_parses(self, tmp_path, token):
        """success: the enum table and the documentation agree on the spelling
        of all five, including the two this file had to add a listener for."""
        rc, out = _parse(tmp_path, _knobs(f"brix_security_level {token};"))
        assert rc == 0, f"brix_security_level {token} was rejected\n{out}"

    @pytest.mark.parametrize("token", ["PEDANTIC", "Compatible"])
    def test_the_token_is_case_insensitive(self, tmp_path, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the config
        language is case-insensitive here while the audit's own grep for
        written values is not.  Worth pinning: it is the reason a
        value-granularity sweep has to read the enum table rather than the
        configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"brix_security_level {token};"))
        assert rc == 0, f"the enum rejected {token!r}\n{out}"

    def test_an_unknown_token_is_refused(self, tmp_path):
        """error: a misspelt level must not silently leave the default in
        place — the failure mode would be a listener that enforces nothing."""
        rc, out = _parse(tmp_path, _knobs("brix_security_level paranoid;"))
        assert rc != 0 and 'invalid value "paranoid"' in out, out

    def test_the_wire_number_is_not_a_token(self, tmp_path):
        """error: the level travels the wire as a number and appears in the log
        as a number, so `2` is the obvious thing to write.  The enum takes names
        only, and says so."""
        rc, out = _parse(tmp_path, _knobs("brix_security_level 2;"))
        assert rc != 0 and 'invalid value "2"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become level 0."""
        rc, out = _parse(tmp_path, _knobs('brix_security_level "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", ["brix_security_level;",
                                      "brix_security_level none compatible;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_TAKE1 — neither omitting the level nor listing two
        of them may parse."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert 'invalid number of arguments in "brix_security_level"' in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two levels in one server block would leave which
        one wins to the parser's ordering.  nginx refuses instead."""
        rc, out = _parse(tmp_path, _knobs("brix_security_level none;",
                                          "brix_security_level intense;"))
        assert rc != 0 and '"brix_security_level" directive is duplicate' in out, out

    def test_the_directive_is_server_level_only(self, tmp_path):
        """security-negative: NGX_STREAM_SRV_CONF.  A level written at stream
        level would read like a site-wide floor and apply to nothing."""
        rc, out = _parse(tmp_path,
                         stream_extra="    brix_security_level intense;\n")
        assert rc != 0, f"a stream-level brix_security_level parsed\n{out}"
        assert '"brix_security_level" directive is not allowed here' in out, out

    @pytest.mark.parametrize("token", ["none", "compatible"])
    def test_the_inert_pair_parses_without_a_word(self, tmp_path, token):
        """DEFECT CANDIDATE #55, parse-time half.

        `brix_signing_required on` under a level that can require nothing is
        accepted in silence: no warning, no notice, nothing naming either
        directive.  Config parse is the last moment this is diagnosable — at
        run time the code that would say it is behind the branch that returns
        first (§E)."""
        rc, out = _parse(tmp_path, _knobs(f"brix_security_level {token};",
                                          "brix_signing_required on;"))
        assert rc == 0, f"the combination stopped parsing\n{out}"
        assert "signing" not in out.lower(), (
            "the inert combination is now diagnosed — pin the new diagnostic "
            f"here and close #55\n{out}")

    def test_the_flag_alone_parses(self, tmp_path):
        """The same configuration written the way an operator most likely
        arrives at it: the fail-closed flag turned on, the level never
        mentioned, so it merges to none and the flag is dead."""
        rc, out = _parse(tmp_path, _knobs("brix_signing_required on;"))
        assert rc == 0, f"brix_signing_required alone was rejected\n{out}"
        assert "signing" not in out.lower(), out
