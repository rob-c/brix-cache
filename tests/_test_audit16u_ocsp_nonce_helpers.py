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
``brix_ocsp`` and ``brix_ocsp_soft_fail`` for the first time and stood up
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
# The launch spelling above is the §10.2 shim; the body the rig-honesty pins
# read moved to the brix_suite package (TS-5).
RESPONDER_SRC = (Path(__file__).resolve().parent / "brix_suite" / "servers"
                 / "ocsp_responder.py")

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

