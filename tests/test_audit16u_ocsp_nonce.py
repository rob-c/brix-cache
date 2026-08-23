"""brix_ocsp_require_nonce at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES: a directive scores
"covered" the moment any one of its tokens reaches a config the suite renders.
Re-run per (directive, VALUE) over the ``ngx_conf_set_flag_slot`` directives,
this flag is in the sharpest category the measurement has — BOTH arms unwritten,
and the branch behind them a security decision.

``brix_ocsp_require_nonce`` is the last of the OCSP family in that state.
``test_audit16a_ocsp_flags.py`` (file 1 of this tranche) entered
``brix_ocsp_enable`` and ``brix_ocsp_soft_fail`` for the first time and stood up
``tests/lib/ocsp_responder.py`` to do it; this one enters the third.  Before it,
no config in the corpus spelled either token.  The one place the directive
reached a config at all was ``test_ocsp_require_nonce.py``, which pushes it
through the ``{TLS_DIRECTIVES}`` placeholder of ``nginx_upstream_tls_verify.conf``
and then runs ``nginx -t`` — a PARSE gate.  Nothing ever started a server with
the flag set, so ``ocsp_request.c:224-230`` had never executed, and that file
says why in its own docstring: "Live OCSP negatives need a controllable
responder that this suite does not stand up".

WHAT THE VALUE SELECTS
----------------------
An OCSP request always carries a fresh nonce — ``ocsp_build_request()`` calls
``OCSP_request_add1_nonce(req, NULL, -1)`` unconditionally (ocsp_request.c:72),
whatever the flag says.  The flag governs only what a response that does NOT
echo it means.  ``OCSP_check_nonce()`` separates the two failures, and the C
treats them differently (ocsp_request.c:217-241)::

    nonce_rc < 0   response omitted it   -> deny ONLY under require_nonce,
                                            otherwise warn and continue
    nonce_rc == 0  response echoed a
                   DIFFERENT one         -> deny, unconditionally

So the flag's scope is exactly "missing", not "checked at all".  Missing is the
CWE-294 replay case: an on-path attacker who captured a still-valid, still
validly signed GOOD response can serve it back forever, and without a nonce to
bind it to this request there is nothing in the response that says when it was
minted for.  The default is off because most CA responders serve pre-signed,
nonce-less responses, so hard-fail has to be opt-in.

WHICH RESPONDER ANSWERS IS A PROPERTY OF THE CREDENTIAL
-------------------------------------------------------
``brix_ocsp_check_cert`` reads the URL out of the LEAF's authorityInfoAccess
extension (``X509_get1_ocsp(leaf)``, ocsp.c:143), so the config cannot choose
the responder — the certificate does.  A responder's nonce behaviour is fixed at
startup (``--omit-nonce`` is an argv switch), which is why this file runs THREE
of them and mints one credential per behaviour, each with an AIA naming its own
port.  Every credential then crosses all four planes: same certificate, same
worker, same trust store, same clock, so a difference in verdict can only be the
flag.

WHAT THE TABLE ESTABLISHES
--------------------------
Four listeners on one instance, four credentials crossing each::

    plane                        echoed  nonceless  mismatch  no-AIA
    require on,  soft_fail off   accept  REJECT     reject    reject
    require off, soft_fail off   accept  accept     reject    reject
    require absent, soft off     accept  accept     reject    reject   -> off
    require on,  soft_fail ON    accept  REJECT     reject    ACCEPT

Column 2 is the flag.  Column 3 is its boundary: a mismatched nonce denies in
every arm, so `off` is not "stop checking".  Column 4 is the control that keeps
row 4 honest — ``soft_fail on`` really is fail-open on that plane, it admits a
credential nobody vouched for, and it STILL does not admit the replay case.

WHAT ENTERING THE BRANCH ANSWERED — THE COMPOSITION
---------------------------------------------------
This tranche has twice found a fail-closed flag rendered inert by a performance
flag layered over it (#93), so the question row 4 asks was the reason for the
fourth plane: does ``brix_ocsp_soft_fail on`` swallow a deny the replay guard
raised?  It does not, and the reason is worth writing down because it is
incidental rather than designed: ``check_ocsp_response`` returns -1 for a nonce
deny, and ``ocsp_check_urls`` (ocsp.c:118-121) treats -1 as REVOKED — the one
verdict it documents as "never override".  The guard survives soft_fail by
sharing a return code with revocation, not by being exempted from the policy.
§F pins both halves so a refactor that gives the nonce deny its own code has to
decide deliberately which side of soft_fail it lands on.

THE FINDING — DEFECT CANDIDATE #98
----------------------------------
That shared return code is also visible to operators, and there it is a defect.
``check_ocsp_response`` returns -1 for SIX distinct outcomes — an unsuccessful
response status, an unparseable basic response, a failed signature check, a
missing nonce under this flag, a mismatched nonce, and a certificate the
response does not cover — and ``ocsp_check_urls`` logs every one of them as
``brix_ocsp: certificate is REVOKED``.  §G proves it from outside: on the armed
plane the nonce-less credential is refused with REVOKED in the error log while
the responder's own request log shows it answered GOOD.  A site alerting on
"REVOKED" gets a page about a certificate nobody revoked, and — worse — a site
reading the log to confirm a real revocation cannot tell it from a responder
that was merely misconfigured.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import x509forge
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN
from x509forge import make_ca, make_eec, make_proxy

# The OCSP client rig this tranche already built, reused whole: the responder
# control-plane wrapper, the AIA extension builder, the port probe, the GSI
# invocation and the error-log reader.  Reimplementing any of them would give
# this file a second opinion about what a login verdict is — and the whole
# reading below is that two files' verdicts differ only by a directive.
from test_audit16a_ocsp_flags import (
    CONNECT_HOST, SEED, SEED_PATH, _Mock, _accepted, _aia, _errlog, _holders,
    _listening, _port,
)
# The corpus measurement itself, from the file that wrote it yesterday.
from test_audit16t_compress_flag_arms import _corpus_writers, _source, _writes

def _expression_1():
    return (
        {tag: [] for tag in RESPONDERS}
    )

def _expression_2(responder):
    return (
        [] if responder is None
                       else [(_aia(RESPONDERS[responder]["port"]), False)]
    )

def _expression_3(ca, tag, ext):
    return (
        make_eec(ca, f"/O=XrdTest/CN=audit16u-{tag}", not_after_days=4000,
                               extra_ext=ext or None)
    )

def _expression_4(eec, spec, ext):
    return (
        make_proxy(eec, kind="rfc3820", not_after_days=4000,
                                   serial=spec["serial"], extra_ext=ext or None)
    )


def _phase_responders_1(proc):
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _check_responders_1(spec, tag, proc, log):
    assert _listening(spec["port"]), (
        f"the {tag} responder never listened on {spec['port']} "
        f"(exit={proc.poll()}, holders={_holders(spec['port'])})\n"
        f"{log.read_text(errors='replace')[-2000:]}")

def _check_test_the_lane_is_declared_where_the_ledger_says_2(nonce):
    assert nonce.port == LIFECYCLE_SHARED_PORTS[NAME]["port"]

def _check_test_the_lane_is_declared_where_the_ledger_says_4(slots):
    assert len(set(slots)) == len(slots), slots

def _check_test_the_lane_is_declared_where_the_ledger_says_3(plane, nonce):
    assert nonce.extra_ports[plane] == _EXTRA[plane]


pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16u-ocspnonce")]

NAME = "lc-audit16u-ocspnonce"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]

ROOT = Path(__file__).resolve().parents[1]
OCSP_REQ_C = ROOT / "src/auth/crypto/ocsp_request.c"
OCSP_C = ROOT / "src/auth/crypto/ocsp.c"
AUTH_CERT_C = ROOT / "src/auth/gsi/auth_cert.c"
CONF_STRUCTS_H = ROOT / "src/core/types/conf_structs.h"
CONFIGS = Path(__file__).resolve().parent / "configs"
TEMPLATE = CONFIGS / "nginx_audit16u_ocsp_nonce.conf"
RESPONDER = Path(__file__).resolve().parent / "lib" / "ocsp_responder.py"

DIRECTIVE = "brix_ocsp_require_nonce"

# The four listeners, by the template placeholder that carries each.  ARMED is
# the instance's own port; the rest arrive as extra_ports, which is also the
# convention _port() from file 1 already implements.
ARMED, DISARMED, ABSENT, SOFT = "PORT", "OFF_PORT", "ABSENT_PORT", "SOFT_PORT"
ALL_PLANES = (ARMED, DISARMED, ABSENT, SOFT)

# One responder per nonce behaviour.  Three processes rather than three control
# calls on one: the behaviour is chosen at startup and the responder a login
# reaches is minted into the certificate, so behaviour and credential have to be
# bound at PKI time or the table has an ordering dependency in it.
RESPONDERS = {
    "echo":      {"port": _EXTRA["RESP_PORT"],      "argv": []},
    "noncefree": {"port": _EXTRA["NONCELESS_PORT"], "argv": ["--omit-nonce"]},
    "badnonce":  {"port": _EXTRA["BADNONCE_PORT"],  "argv": ["--wrong-nonce"]},
}

# One credential per responder, plus the shape a real Globus proxy has.  Every
# verdict is `good`: the subject is what happens to a GOOD answer that arrives
# without a usable nonce, and any other verdict would give the deny a second
# cause.  Fixed serials — that is what the responder keys on and what its
# request log reports, so the attribution assertions can name a number.
CREDENTIALS = {
    "echoed":    {"serial": 210001, "responder": "echo"},
    "nonceless": {"serial": 210002, "responder": "noncefree"},
    "mismatch":  {"serial": 210003, "responder": "badnonce"},
    # No AIA at all — what xrdgsiproxy actually mints, and here the soft_fail
    # control: nobody is asked, so the plane's soft_fail token decides alone.
    "plain":     {"serial": 210004, "responder": None},
}

# The C's own words, quoted rather than paraphrased so a reworded log line
# fails this file instead of silently draining its evidence.
REPLAY_DENY = "denying (replay guard)"
NONCE_MISSING = "nonce missing in OCSP response"
NONCE_MISMATCH = "OCSP response nonce mismatch"
REVOKED_LINE = "certificate is REVOKED"


def _gate():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# PKI — one CA, one host certificate, one credential per responder             #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """The trust store every plane shares and the four credentials that cross it.

    Each credential is its own EEC plus a proxy off it, with the AIA on BOTH:
    the responder answers about the serial it is asked about, and a private
    issuer per credential means the answer is the same whichever certificate the
    server treats as the leaf.  Minted here rather than by xrdgsiproxy because
    the extension under test has to be ON the leaf and xrdgsiproxy cannot put it
    there — the same reason file 1 mints its own.

    ``not_after_days`` clears x509forge's fixed 2026-01-01 epoch, whose default
    one-day proxy is long expired.
    """
    base = tmp_path_factory.mktemp("a16unonce")
    ca_dir = base / "ca"
    ca_dir.mkdir()

    ca = make_ca("/O=XrdTest/CN=audit16u-nonce-CA")
    x509forge._place_ca_in_dir(ca_dir, ca, name="noncca")
    ca_dir.chmod(0o755)             # XrdCl refuses a group-writable CA dir

    host = make_eec(ca, f"/O=XrdTest/CN={CONNECT_HOST}", not_after_days=4000)

    def _write(cert, name):
        path = base / f"{name}.pem"
        path.write_bytes(cert.pem)
        return path

    # The responders sign with the CA's own key, so both halves have to exist as
    # files; _place_ca_in_dir only puts the hashed anchor into the store.
    ca_cert = _write(ca, "cacert")
    ca_key = base / "cakey.pem"
    ca_key.write_bytes(ca.key_pem)
    ca_key.chmod(0o600)

    host_cert = _write(host, "hostcert")
    host_key = base / "hostkey.pem"
    host_key.write_bytes(host.key_pem)
    host_key.chmod(0o600)

    creds = {}
    entries = _expression_1()
    for tag, spec in CREDENTIALS.items():
        responder = spec["responder"]
        ext = (_expression_2(responder))
        eec = _expression_3(ca, tag, ext)
        proxy = _expression_4(eec, spec, ext)
        # proxy, then the EEC it delegates from, then the proxy key — the
        # standard GSI proxy file, and the order the client puts on the wire,
        # which is why chain[0] is the proxy the OCSP query is about.
        path = base / f"{tag}cred.pem"
        path.write_bytes(proxy.pem + eec.pem + proxy.key_pem)
        path.chmod(0o600)
        creds[tag] = str(path)
        if responder is None:
            # `plain` registers with nobody.  If a query for its serial ever
            # turns up in a responder's log, the URL was found somewhere other
            # than the leaf and §E would be measuring the wrong thing.
            continue
        eec_pem = _write(eec, f"{tag}eec")
        proxy_pem = _write(proxy, f"{tag}proxy")
        entries[responder].append(f"{proxy_pem},{eec_pem},good")
        entries[responder].append(f"{eec_pem},{ca_cert},good")

    return {"base": base, "ca": str(ca_dir), "ca_cert": str(ca_cert),
            "ca_key": str(ca_key), "cert": str(host_cert), "key": str(host_key),
            "entries": entries, **creds}


# --------------------------------------------------------------------------- #
# The three responders                                                         #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def responders(pki):
    """One subprocess per nonce behaviour, each on its own ledger port.

    Their own output goes to a file per responder: a responder that dies before
    it listens takes the reason with it otherwise, and on a fixed port the
    reason is the whole diagnosis.
    """
    procs, mocks = [], {}
    try:
        for tag, spec in RESPONDERS.items():
            log = pki["base"] / f"responder-{tag}.log"
            handle = open(log, "wb")
            try:
                argv = [sys.executable, str(RESPONDER),
                        "--port", str(spec["port"]), "--bind", BIND_HOST,
                        "--signer-cert", pki["ca_cert"],
                        "--signer-key", pki["ca_key"]] + spec["argv"]
                for entry in pki["entries"][tag]:
                    argv += ["--entry", entry]
                proc = subprocess.Popen(argv, stdout=handle,
                                        stderr=subprocess.STDOUT)
            finally:
                handle.close()
            procs.append(proc)
            _check_responders_1(spec, tag, proc, log)
            mocks[tag] = _Mock(proc, spec["port"])
        yield mocks
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            _phase_responders_1(proc)


def _reset(responders):
    for mock in responders.values():
        mock.reset()


def _asked(responders, credential):
    """The log entries the credential's own responder recorded for its serial.

    Named rather than counted: every deny below has to be separated from a deny
    that happened without anyone being asked, and the serial is the only thing
    that says which of the three responders answered.
    """
    tag = CREDENTIALS[credential]["responder"]
    if tag is None:
        return []
    serial = CREDENTIALS[credential]["serial"]
    return [entry for entry in responders[tag].queries()
            if entry["serial"] == serial]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

@pytest.fixture
def nonce(lifecycle, tmp_path, pki, responders):
    _gate()
    data = tmp_path / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)
    _reset(responders)
    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16u_ocsp_nonce.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"]},
        reason="audit-16u brix_ocsp_require_nonce at value granularity"))


def _log_after(endpoint, mark):
    """The error log written since ``mark`` — the offset a caller took before
    the login it is about to attribute a line to."""
    return _errlog(endpoint)[mark:]


def _mark(endpoint):
    return len(_errlog(endpoint))


# --------------------------------------------------------------------------- #
# §A — the arms are written, literally                                         #
# --------------------------------------------------------------------------- #

class TestTheArmsAtConfigTime:
    """The audit's Method, applied to this file's own deliverable.  An arm counts
    as covered only when ``<directive> <value>;`` is spelled where a reader can
    grep it — a placeholder that renders to the token at runtime leaves the
    corpus still never saying so, which is exactly the state
    ``test_ocsp_require_nonce.py`` left this directive in."""

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_the_template_spells_the_arm(self, value):
        assert _writes(_source(TEMPLATE), DIRECTIVE, value), (
            f"{TEMPLATE.name} no longer writes `{DIRECTIVE} {value};` as a "
            "whole line — the arm this file exists to cover is gone")

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_this_template_is_the_corpus_writer(self, value):
        """Both arms, in exactly one file.  A second writer appearing is not a
        failure, but it changes what this file is: the audit entry says this
        directive reached NO config, and a reader who finds another one should
        be sent to it rather than believing this line."""
        writers = _corpus_writers(DIRECTIVE, value)
        assert writers == [TEMPLATE.name], (
            f"`{DIRECTIVE} {value};` is written by {writers}; this file's "
            f"premise is that only {TEMPLATE.name} does")

    def test_the_absent_plane_writes_neither_token(self):
        """The third plane measures the merge default, so it must not carry the
        directive in any form.  Written as a test because the obvious way to
        make §D green — copying the `off` server and forgetting to delete the
        line — turns the default plane into a second `off` plane."""
        block = _source(TEMPLATE).split("listen {ABSENT_PORT};")[1]
        block = block.split("}")[0]
        assert DIRECTIVE not in block, (
            f"the ABSENT_PORT server writes {DIRECTIVE}; it is the plane that "
            f"measures the default:\n{block}")

    def test_every_plane_enables_ocsp(self):
        """With `brix_ocsp_enable off` no request is built at all
        (auth_cert.c:293), so there is no response for a nonce to be missing
        from.  All four planes therefore have to enable it, or a plane would be
        measuring the absence of the mechanism rather than an arm of the flag."""
        text = _source(TEMPLATE)
        servers = [chunk for chunk in text.split("server {")[1:]]
        assert len(servers) == len(ALL_PLANES), servers
        for chunk in servers:
            assert _writes(chunk, "brix_ocsp_enable", "on"), chunk


# --------------------------------------------------------------------------- #
# §B — the guard, armed                                                        #
# --------------------------------------------------------------------------- #

class TestTheGuardArmed:
    """``require_nonce on``: a GOOD answer that omits the nonce is refused.

    This is the branch ocsp_request.c:224-230 has never executed under test.
    """

    def test_a_nonceless_good_answer_is_refused(self, nonce, pki, responders):
        """The security-positive.  The responder says GOOD about this exact
        serial and the login is still denied, because a GOOD answer with no
        nonce is a GOOD answer that could have been captured last month."""
        _reset(responders)
        ok, result = _accepted(nonce, ARMED, pki, "nonceless")
        assert not ok, (
            f"{DIRECTIVE} on accepted a nonce-less OCSP response — the replay "
            f"guard is not armed\n{result.stdout}\n{_errlog(nonce)[-2000:]}")

    def test_the_deny_happened_after_a_good_answer_arrived(self, nonce, pki,
                                                           responders):
        """Attribution, and the reason the row above is not enough on its own: a
        plane that refused every login — a broken chain, an unreadable CA
        directory — would satisfy it.  The responder's own log is the only thing
        that says the exchange completed and the verdict was GOOD."""
        _reset(responders)
        _accepted(nonce, ARMED, pki, "nonceless")
        assert _asked(responders, "nonceless") == [
            {"serial": CREDENTIALS["nonceless"]["serial"], "verdict": "good"}], (
            "the armed plane denied without the responder answering GOOD, so "
            "the deny is not the nonce: "
            f"{responders['noncefree'].queries()}")

    def test_the_deny_names_the_replay_guard(self, nonce, pki, responders):
        """The operator-facing half.  A deny with no explanation is
        indistinguishable from the certificate being bad, and this is the one
        line that tells a site which directive to look at."""
        _reset(responders)
        mark = _mark(nonce)
        _accepted(nonce, ARMED, pki, "nonceless")
        log = _log_after(nonce, mark)
        assert REPLAY_DENY in log, (
            f"the armed deny did not log {REPLAY_DENY!r}:\n{log[-3000:]}")
        assert DIRECTIVE in log, log[-3000:]

    def test_the_armed_plane_still_admits_an_echoed_nonce(self, nonce, pki,
                                                          responders):
        """The control for the class, and for the whole file.  ``require_nonce
        on`` refuses a MISSING nonce, not every login; without this row the
        cheapest way to make everything above green would read as the guard
        working."""
        _reset(responders)
        ok, result = _accepted(nonce, ARMED, pki, "echoed")
        assert ok, (
            f"{DIRECTIVE} on refused a credential whose responder echoed the "
            f"nonce\n{result.stderr}\n{_errlog(nonce)[-3000:]}")
        assert _asked(responders, "echoed"), responders["echo"].queries()


# --------------------------------------------------------------------------- #
# §C — the guard, disarmed                                                     #
# --------------------------------------------------------------------------- #

class TestTheGuardDisarmed:
    """``require_nonce off``: the same nonce-less answer is a warning, and the
    login continues.  This is what every deployment in the corpus runs today,
    and until this file nothing had written the token that says so."""

    def test_the_same_nonceless_answer_is_admitted(self, nonce, pki,
                                                   responders):
        _reset(responders)
        ok, result = _accepted(nonce, DISARMED, pki, "nonceless")
        assert ok, (
            f"{DIRECTIVE} off refused a nonce-less OCSP response; the arm is "
            "documented as warn-and-continue, and hard-failing it by default "
            "would break every pre-signed CA responder\n"
            f"{result.stderr}\n{_errlog(nonce)[-3000:]}")

    def test_the_admission_is_still_logged(self, nonce, pki, responders):
        """Disarmed is not silent.  ocsp_request.c:232-234 warns on the way
        past, which is the only trace a site running the default has that its
        responder is replayable at all."""
        _reset(responders)
        mark = _mark(nonce)
        _accepted(nonce, DISARMED, pki, "nonceless")
        log = _log_after(nonce, mark)
        assert NONCE_MISSING in log, (
            f"the disarmed plane admitted a nonce-less response without "
            f"warning:\n{log[-3000:]}")
        assert REPLAY_DENY not in log, (
            f"the disarmed plane logged the armed deny:\n{log[-3000:]}")

    def test_one_credential_two_planes_opposite_verdicts(self, nonce, pki,
                                                         responders):
        """The reading of the whole file, in one assertion: one certificate, one
        responder, one worker, one trust store, one clock — and the directive is
        the only difference.  Stated together so the pair cannot quietly become
        the same answer."""
        _reset(responders)
        assert _accepted(nonce, ARMED, pki, "nonceless")[0] is False
        assert _accepted(nonce, DISARMED, pki, "nonceless")[0] is True


# --------------------------------------------------------------------------- #
# §D — the merge default                                                       #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """conf_structs.h:533 merges the unset field to 0.  Off is therefore what
    every site that never heard of the flag runs, and until this class nothing
    asserted it from outside the C."""

    def test_the_absent_flag_admits_a_nonceless_answer(self, nonce, pki,
                                                       responders):
        _reset(responders)
        ok, result = _accepted(nonce, ABSENT, pki, "nonceless")
        assert ok, (
            f"with {DIRECTIVE} unwritten a nonce-less response denied the "
            "login — the default is not off, and every existing deployment "
            f"just changed behaviour\n{result.stderr}\n{_errlog(nonce)[-3000:]}")

    def test_the_default_is_not_a_licence_to_skip_the_check(self, nonce, pki,
                                                            responders):
        """The half that keeps the default from being vacuous.  Off tolerates a
        MISSING nonce; it does not stop the nonce being checked, so a response
        that echoes the wrong one still denies here."""
        _reset(responders)
        ok, result = _accepted(nonce, ABSENT, pki, "mismatch")
        assert not ok, (
            "the default plane accepted a response echoing a DIFFERENT nonce — "
            f"the check itself has stopped running\n{result.stdout}")

    def test_the_absent_plane_answers_exactly_as_the_off_plane(self, nonce, pki,
                                                               responders):
        """Both directions at once, over every credential, so a future change to
        the default has to break this test rather than drift past the two
        above."""
        _reset(responders)
        for credential in CREDENTIALS:
            assert (_accepted(nonce, ABSENT, pki, credential)[0]
                    == _accepted(nonce, DISARMED, pki, credential)[0]), (
                f"the default and the `off` token disagree on the "
                f"{credential} credential")


# --------------------------------------------------------------------------- #
# §E — the boundary: `off` is not "stop checking"                              #
# --------------------------------------------------------------------------- #

class TestTheScopeOfTheFlag:
    """``OCSP_check_nonce`` reports a missing nonce as <0 and a mismatched one
    as 0, and only the first is under the flag.  The distinction is the whole
    reason `off` is safe to default to: a replayed response that a MITM re-signs
    with its own nonce is still refused."""

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_a_mismatched_nonce_denies_on_every_plane(self, nonce, pki,
                                                      responders, plane):
        _reset(responders)
        ok, result = _accepted(nonce, plane, pki, "mismatch")
        assert not ok, (
            f"{plane}: a response echoing a DIFFERENT nonce was accepted — the "
            f"mismatch arm is meant to deny unconditionally\n{result.stdout}")

    def test_the_mismatch_deny_names_the_mismatch(self, nonce, pki,
                                                  responders):
        """Separated from the parametrised row above because a mismatch that
        denied for some OTHER reason — an unparseable response, a signature the
        rewrite broke — would satisfy it while proving nothing about nonces."""
        _reset(responders)
        mark = _mark(nonce)
        _accepted(nonce, DISARMED, pki, "mismatch")
        log = _log_after(nonce, mark)
        assert NONCE_MISMATCH in log, (
            f"the mismatch deny is not a nonce deny:\n{log[-3000:]}")
        assert _asked(responders, "mismatch"), responders["badnonce"].queries()

    def test_the_disarmed_plane_demonstrably_still_sends_a_nonce(
            self, nonce, pki, responders):
        """``ocsp_build_request`` adds a nonce unconditionally (§H pins that in
        the C); this is the observable half.  A mismatch can only be DETECTED if
        the request carried a nonce to mismatch against, so the `off` plane
        refusing the mismatch credential is proof that the flag governs the
        response side alone — it does not stop the client asking."""
        _reset(responders)
        assert _accepted(nonce, DISARMED, pki, "mismatch")[0] is False
        assert _asked(responders, "mismatch") == [
            {"serial": CREDENTIALS["mismatch"]["serial"], "verdict": "good"}], (
            "the disarmed plane refused the mismatch credential without the "
            "responder being asked, so the refusal proves nothing about the "
            f"request's nonce: {responders['badnonce'].queries()}")


# --------------------------------------------------------------------------- #
# §F — the composition with brix_ocsp_soft_fail                                #
# --------------------------------------------------------------------------- #

class TestTheCompositionWithSoftFail:
    """The question the fourth plane exists to ask.

    ``brix_ocsp_soft_fail on`` turns every non-answer into GOOD (ocsp.c:84,
    ``result = soft_fail ? 0 : -1``).  This tranche has already found a
    fail-closed flag rendered inert by a performance flag layered over it (#93),
    so the shape is worth checking rather than assuming.
    """

    def test_soft_fail_is_genuinely_on_upon_that_plane(self, nonce, pki,
                                                       responders):
        """The control, and it has to come first: the `plain` credential
        publishes no responder at all, so ocsp.c:147 returns the soft-fail
        default with nobody contacted.  Admitted here and refused on the three
        strict planes is what makes "soft_fail is on" a measurement rather than
        a reading of the template."""
        _reset(responders)
        ok, result = _accepted(nonce, SOFT, pki, "plain")
        assert ok, (
            "the SOFT plane refused a credential with no AIA — soft_fail is "
            f"not on there, so nothing below is about composition\n"
            f"{result.stderr}\n{_errlog(nonce)[-3000:]}")
        assert _accepted(nonce, ARMED, pki, "plain")[0] is False

    def test_soft_fail_does_not_swallow_the_replay_deny(self, nonce, pki,
                                                        responders):
        """The answer: it does not.  The same fail-open plane that admits a
        credential nobody vouched for still refuses the nonce-less GOOD."""
        _reset(responders)
        ok, result = _accepted(nonce, SOFT, pki, "nonceless")
        assert not ok, (
            f"{DIRECTIVE} on was inert under brix_ocsp_soft_fail on — the "
            "replay guard is switched off by a performance flag, which is the "
            f"shape defect candidate #93 describes\n{result.stdout}")
        assert REPLAY_DENY in _errlog(nonce), _errlog(nonce)[-3000:]

    def test_the_two_planes_differ_only_on_the_credential_nobody_answered_for(
            self, nonce, pki, responders):
        """The composition as a table.  ARMED and SOFT carry the same
        ``require_nonce on`` and opposite soft_fail tokens, so every cell where
        they agree is a cell soft_fail does not reach — and the only cell where
        they differ is the one where nobody was asked at all."""
        _reset(responders)
        verdicts = {credential: (_accepted(nonce, ARMED, pki, credential)[0],
                                 _accepted(nonce, SOFT, pki, credential)[0])
                    for credential in CREDENTIALS}
        assert verdicts == {"echoed": (True, True),
                            "nonceless": (False, False),
                            "mismatch": (False, False),
                            "plain": (False, True)}, verdicts

    def test_the_guard_survives_by_sharing_revocations_return_code(self):
        """WHY it survives, pinned in the C, because the reason is incidental
        rather than designed: ``check_ocsp_response`` returns -1 for a nonce
        deny, and ``ocsp_check_urls`` returns on -1 immediately as REVOKED —
        the one verdict it documents as never overridden.  A refactor that gives
        the nonce deny its own return code has to decide deliberately which side
        of soft_fail it lands on, and this test is where it finds that out."""
        loop = _fn(_source(OCSP_C), "ocsp_check_urls")
        assert "int result = soft_fail ? 0 : -1;" in loop, loop
        tail = loop[loop.index("if (status == -1)"):]
        assert tail.index("return -1;") < tail.index("soft_fail"), (
            "the -1 arm now consults soft_fail; a nonce deny is a -1, so the "
            f"replay guard has just become fail-open:\n{tail}")


# --------------------------------------------------------------------------- #
# §G — the finding (DEFECT CANDIDATE #98)                                      #
# --------------------------------------------------------------------------- #

class TestTheDenyIsReportedAsARevocation:
    """Six distinct outcomes share one return code and one log line."""

    def test_a_nonce_deny_is_logged_as_a_revocation(self, nonce, pki,
                                                    responders):
        """DEFECT CANDIDATE #98.  The responder answered GOOD — its own request
        log says so in the same assertion — and the error log says the
        certificate is REVOKED.  A site alerting on that string gets paged about
        a certificate nobody revoked; a site reading it to confirm a real
        revocation cannot tell the two apart.

        Pinning today's behaviour, not endorsing it: when the deny grows its own
        message (or ocsp_check_urls learns to distinguish a policy refusal from
        a verdict), this assertion should be inverted."""
        _reset(responders)
        mark = _mark(nonce)
        assert _accepted(nonce, ARMED, pki, "nonceless")[0] is False
        log = _log_after(nonce, mark)
        assert _asked(responders, "nonceless") == [
            {"serial": CREDENTIALS["nonceless"]["serial"], "verdict": "good"}], \
            responders["noncefree"].queries()
        assert REVOKED_LINE in log, (
            "defect candidate #98 is fixed — a nonce deny no longer reports as "
            f"a revocation; invert this test\n{log[-3000:]}")

    def test_a_mismatch_is_reported_the_same_way(self, nonce, pki, responders):
        """The second outcome, on a plane where the flag is off — so the
        conflation is not something ``require_nonce on`` opts into.  Every site
        running the default is exposed to it."""
        _reset(responders)
        mark = _mark(nonce)
        assert _accepted(nonce, DISARMED, pki, "mismatch")[0] is False
        assert REVOKED_LINE in _log_after(nonce, mark), _log_after(nonce, mark)

    def test_the_conflation_is_structural_not_incidental(self):
        """The scope of the defect, read off the C: every non-GOOD, non-UNKNOWN
        exit of ``check_ocsp_response`` is a bare ``return -1``, and the caller
        has only that one bit to report on.  Counted rather than described so
        the audit entry's "six outcomes" is a measurement."""
        body = _fn(_source(OCSP_REQ_C), "check_ocsp_response")
        # The status switch at the end maps a genuine REVOKED to rc, not to a
        # literal return, so every `return -1;` above it is a NON-revocation.
        head = body[:body.index("OCSP_resp_find_status")]
        assert head.count("return -1;") >= 5, head
        loop = _fn(_source(OCSP_C), "ocsp_check_urls")
        assert loop.count(REVOKED_LINE) == 1, loop
        assert "if (status == -1)" in loop, loop


# --------------------------------------------------------------------------- #
# §H — the mechanism is where this file says it is                             #
# --------------------------------------------------------------------------- #

def _fn(src, name):
    """The body of a C function, braces balanced.

    The same shape ``test_ocsp_require_nonce.py`` uses; kept local because that
    file's copy is a module-private helper of a source-pin suite and importing
    it would make this file's runtime evidence depend on a file that has
    none.
    """
    match = re.search(rf"\n{re.escape(name)}\(", src)
    assert match, f"function {name} not found"
    start = src.index("{", match.end())
    depth = 0
    for index in range(start, len(src)):
        if src[index] == "{":
            depth += 1
        elif src[index] == "}":
            depth -= 1
            if depth == 0:
                return src[start:index + 1]
    raise AssertionError(f"unbalanced braces in {name}")


class TestTheMechanismIsWhereThisFileSaysItIs:
    """Source pins for every claim the docstrings above make about the C.  A
    refactor that moves the gate must not leave this file passing while its
    explanation has become fiction — which is the failure mode a suite of pure
    behaviour assertions cannot detect."""

    def test_the_flag_reaches_the_check_from_the_server_conf(self):
        text = _source(AUTH_CERT_C)
        assert "conf->ocsp.require_nonce" in text, (
            "auth_cert.c no longer reads the flag out of the server conf; the "
            "directive is wired to nothing")
        call = text[text.index("brix_ocsp_check_cert("):]
        call = call[:call.index(";")]
        assert "conf->ocsp.soft_fail" in call and "require_nonce" in call, call

    def test_the_request_always_carries_a_nonce(self):
        """The flag governs the RESPONSE side only.  A future optimisation that
        skipped the nonce when the flag is off would make `off` mean "do not
        check", silently widening it from the missing case to the mismatch
        case — §E's boundary would go with it."""
        build = _fn(_source(OCSP_REQ_C), "ocsp_build_request")
        assert "OCSP_request_add1_nonce(req, NULL, -1);" in build, build
        assert "require_nonce" not in build, (
            "the request builder now consults the flag; the nonce is no longer "
            f"unconditional:\n{build}")

    def test_the_deny_precedes_the_warn_fallback_and_frees_the_response(self):
        body = _fn(_source(OCSP_REQ_C), "check_ocsp_response")
        missing = body[body.index("nonce_rc < 0"):]
        guard = missing[missing.index("if (require_nonce)"):]
        deny = guard[:guard.index("}") + 1]
        assert "OCSP_BASICRESP_free(bresp);" in deny, deny
        assert "return -1;" in deny, deny
        assert DIRECTIVE in deny, deny
        # The warn-and-continue fallback is reachable only when the flag is off.
        # Matched on the CLOSING quote: both messages open with the same words
        # and only the fallback's ends there, so the shorter pattern would find
        # the deny it is meant to be distinguished from.
        assert missing.index("if (require_nonce)") < missing.index(
            f'{NONCE_MISSING}");'), missing

    def test_the_nonce_check_precedes_the_status_lookup(self):
        """Order matters and is load-bearing: a GOOD verdict must not be read
        out of a response whose nonce already failed, or the deny would depend
        on what the responder said about revocation."""
        body = _fn(_source(OCSP_REQ_C), "check_ocsp_response")
        assert body.index("OCSP_check_nonce(") < body.index(
            "OCSP_resp_find_status("), body

    def test_the_mismatch_arm_is_not_under_the_flag(self):
        body = _fn(_source(OCSP_REQ_C), "check_ocsp_response")
        mismatch = body[body.index("nonce_rc == 0"):]
        mismatch = mismatch[:mismatch.index("OCSP_resp_find_status")]
        assert "require_nonce" not in mismatch, (
            "the mismatch deny is now gated on the flag — `off` has become "
            f"'stop checking', which §E asserts it is not:\n{mismatch}")

    def test_the_field_is_merged_off(self):
        text = _source(CONF_STRUCTS_H)
        assert re.search(r"ngx_flag_t\s+require_nonce;", text)
        assert ("ngx_conf_merge_value(c->require_nonce, p->require_nonce, 0)"
                in text), "the merge default moved off 0; §D is now wrong"

    def test_the_responder_url_comes_from_the_leaf(self):
        """Why the credential and not the config picks the responder — the fact
        the three-responder rig is built on."""
        body = _fn(_source(OCSP_C), "brix_ocsp_check_cert")
        assert "X509_get1_ocsp(leaf)" in body, body


# --------------------------------------------------------------------------- #
# §I — the worker survives the whole table                                     #
# --------------------------------------------------------------------------- #

class TestTheWorkerSurvivesTheTable:
    """File 1 of this tranche found a double free in this code path that killed
    the worker on every completed OCSP round trip (#64).  Every assertion above
    reads a single login's verdict, and a worker that dies AFTER answering still
    produces the right verdict for that login — so the crash hid behind exactly
    this kind of file until something asked whether the process was still
    there."""

    def test_no_plane_and_no_credential_crashes_the_worker(self, nonce, pki,
                                                           responders):
        for plane in ALL_PLANES:
            for credential in CREDENTIALS:
                _accepted(nonce, plane, pki, credential)
        log = _errlog(nonce)
        assert "exited on signal" not in log, log[-3000:]

    def test_a_second_login_survives_a_nonce_deny(self, nonce, pki,
                                                  responders):
        """The deny path frees the basic response and returns early, which is a
        different teardown from the accept path — and #64 was in a teardown."""
        assert _accepted(nonce, ARMED, pki, "nonceless")[0] is False
        assert _accepted(nonce, ARMED, pki, "echoed")[0] is True, (
            "the login after a nonce deny failed — the deny path is taking the "
            f"worker with it\n{_errlog(nonce)[-3000:]}")


# --------------------------------------------------------------------------- #
# §J — the responder rig answers what it was told to                           #
# --------------------------------------------------------------------------- #

class TestTheRigIsHonest:
    """The three responders are the instrument.  If two of them behaved the
    same, most of this file would be green for the wrong reason, so the
    instrument is calibrated here rather than assumed."""

    def test_the_three_responders_are_three_processes(self, responders):
        ports = {mock.port for mock in responders.values()}
        assert len(ports) == len(RESPONDERS), ports
        for tag, spec in RESPONDERS.items():
            assert responders[tag].port == spec["port"]

    def test_each_credential_reaches_only_its_own_responder(self, nonce, pki,
                                                            responders):
        """The AIA binding, measured.  A credential minted against the wrong
        port would make its verdict a property of another responder's
        behaviour, and every table above would still be internally
        consistent."""
        for credential, spec in CREDENTIALS.items():
            _reset(responders)
            _accepted(nonce, DISARMED, pki, credential)
            for tag, mock in responders.items():
                serials = [entry["serial"] for entry in mock.queries()]
                if tag == spec["responder"]:
                    assert spec["serial"] in serials, (
                        f"{credential} did not reach the {tag} responder: "
                        f"{mock.queries()}")
                else:
                    assert spec["serial"] not in serials, (
                        f"{credential} reached the {tag} responder as well: "
                        f"{mock.queries()}")

    def test_the_no_aia_credential_reaches_nobody(self, nonce, pki,
                                                  responders):
        """The soft_fail control has to be a NON-answer, not a quiet GOOD from
        some responder that happened to hold its serial."""
        _reset(responders)
        _accepted(nonce, SOFT, pki, "plain")
        for tag, mock in responders.items():
            assert CREDENTIALS["plain"]["serial"] not in [
                entry["serial"] for entry in mock.queries()], (
                f"the AIA-less credential reached the {tag} responder — the "
                f"URL is being found somewhere other than the leaf: "
                f"{mock.queries()}")

    def test_the_wrong_nonce_switch_changes_the_value_not_the_length(self):
        """``--wrong-nonce`` exists to hit ``OCSP_check_nonce() == 0``, which
        needs a nonce that is present and different.  A randomised value could
        collide with the one it must differ from, and this negative must not
        have a passing day — so the responder flips a bit instead, and this is
        the pin that keeps it deterministic."""
        text = _source(RESPONDER)
        assert "self.wrong_nonce" in text, text
        arm = text[text.index("if nonce is not None and self.wrong_nonce:"):]
        arm = arm[:arm.index("if nonce is not None:")]
        assert "^ 0xFF" in arm, (
            f"the mismatched nonce is no longer a deterministic bit flip:\n{arm}")
        assert "nonce.nonce[1:]" in arm, (
            f"the mismatched nonce no longer has the original's length:\n{arm}")


def test_the_lane_is_declared_where_the_ledger_says(nonce):
    """The four listeners are the four ledger slots, in one process.  Cheap, and
    it is the assertion that fails first if the ladder repack that made room for
    them drifted."""
    _check_test_the_lane_is_declared_where_the_ledger_says_2(nonce)
    for plane in (DISARMED, ABSENT, SOFT):
        _check_test_the_lane_is_declared_where_the_ledger_says_3(plane, nonce)
    # Seven distinct slots: four the worker listens on, three the test's own
    # responders bind.  A collision would make one plane answer for another.
    slots = [nonce.port] + [nonce.extra_ports[p] for p in (DISARMED, ABSENT,
                                                           SOFT)]
    slots += [spec["port"] for spec in RESPONDERS.values()]
    _check_test_the_lane_is_declared_where_the_ledger_says_4(slots)
