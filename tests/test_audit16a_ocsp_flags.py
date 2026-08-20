"""brix_ocsp_enable / brix_ocsp_soft_fail at VALUE granularity — audit §Method,
16th tranche.

WHY THIS FILE EXISTS
--------------------
The coverage audit's Method (steps 1-2) counts directive NAMES: a directive
scores "covered" the moment any one of its tokens appears in a config the suite
renders.  Tranche 15 re-ran the measurement per (directive, VALUE) over the
``ngx_conf_enum_t`` tables; this tranche does the same for the 128 directives
whose setter is ``ngx_conf_set_flag_slot``.  A flag's name is answered by ONE of
its two tokens, and 106 of the 256 (flag, value) pairs are written nowhere in
the corpus in any form.

Three of them are the OCSP flags, and they are the sharpest entry in the list:
``brix_ocsp_enable``, ``brix_ocsp_soft_fail`` and ``brix_ocsp_stapling`` are the
only flags where BOTH arms are unwritten AND the branch is a security decision.
``src/auth/gsi/auth_cert.c:291`` — ``if (conf->ocsp.enable)``, the online
revocation check on every GSI login — had never been entered by any test.

The tree is not silent about the reason.  ``test_ocsp.py`` and
``test_ocsp_require_nonce.py`` pin the OCSP behaviour against the C source, and
the latter says why in its own docstring: "Live OCSP negatives need a
controllable responder that this suite does not stand up".  So this file stands
one up (``tests/lib/ocsp_responder.py``) and drives the flags for real.

WHAT THE VALUE SELECTS
----------------------
``brix_ocsp_enable`` gates the query itself: with it off, no OCSP request is
ever built, and a certificate the CA has revoked logs in.  ``brix_ocsp_soft_fail``
decides what a NON-answer means (ocsp.c:88, ``result = soft_fail ? 0 : -1``):

    soft_fail on   -> a network error, an UNKNOWN verdict, a stale response, or
                      a certificate with no responder URL at all are all treated
                      as GOOD.  REVOKED is never overridden.
    soft_fail off  -> every one of those denies the login.

The responder URL is not a directive.  ``brix_ocsp_check_cert`` reads it from
the LEAF certificate's authorityInfoAccess extension (``X509_get1_ocsp(leaf)``,
ocsp.c:143), and the leaf of a GSI login is ``chain[0]`` — the proxy the client
presented, with its EEC as ``chain[1]``, the issuer the OCSP CertID is built
over.  So "which responder, if any" is a property of the CREDENTIAL, which is
what makes the table below a table: five credentials, one trust store.

WHAT THE TABLE ESTABLISHES
--------------------------
Four listeners on ONE instance, five proxies crossing them.  Measured:

    plane                 good   revoked  unknown  dead   no-AIA
    enable off            accept ACCEPT   accept   accept accept
    on, soft_fail on      accept reject   accept   accept accept
    on, soft_fail off     accept reject   REJECT   REJECT REJECT
    on, soft_fail absent  accept reject   accept   accept accept  -> default on

Only the ``enable off`` row accepts a certificate the responder calls REVOKED,
and only the ``soft_fail off`` row distinguishes "the responder said GOOD" from
"nobody said anything".  Neither fact is reachable from a test that writes one
token, and until this file nothing wrote either.

WHAT ENTERING THE BRANCH FOUND — DEFECT CANDIDATE #64 (FIXED HERE)
------------------------------------------------------------------
The first run of this file segfaulted the worker on every login that reached a
responder.  ``ocsp_build_request()`` handed the caller's ``OCSP_CERTID`` to
``OCSP_request_add0_id()``, which takes ownership, while
``brix_ocsp_check_cert()`` went on to ``OCSP_CERTID_free(id)`` after the loop
(ocsp.c:175) — a double free on every completed round trip, and a
use-after-free on a second AIA URL.  Every error path in
``do_ocsp_request()`` frees the request too, so an unreachable responder
crashed the worker just as reliably as a live one::

    #0  ossl_asn1_primitive_free      () from libcrypto.so.3
    #7  brix_ocsp_check_cert (...) at src/auth/crypto/ocsp.c:175
    #8  gsi_auth_step_cert  (...) at src/auth/gsi/auth_cert.c:294

That is a pre-auth remote crash: the AIA URL lives in the CLIENT's own proxy
certificate, so any client that could reach the login could pick the responder
and take the worker down with it.  ``ocsp_build_request()`` now adds a
``OCSP_CERTID_dup()`` and leaves the caller's pointer alone;
``TestTheWorkerSurvivesTheQuery`` is the regression pin.

THE FINDING — DEFECT CANDIDATE #65
----------------------------------
``brix_ocsp_soft_fail off`` cannot be deployed on a GSI site, for a reason that
has nothing to do with responders being down: a Globus proxy carries no
authorityInfoAccess extension.  ``xrdgsiproxy`` does not copy one from the EEC
and RFC 3820 does not ask it to, so ``X509_get1_ocsp(leaf)`` returns nothing for
the ordinary credential every WLCG user holds, and ocsp.c:147 returns the
soft-fail default without ever contacting anyone.  With the strict token that
default is -1, so the login is denied — every login, from every user, whatever
the responder would have said.  ``test_the_strict_token_refuses_an_ordinary_
globus_proxy`` pins today's behaviour; the fix (walk the chain for an AIA, or
distinguish "no responder published" from "the responder did not answer") should
invert it, not delete it.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

import x509forge
from x509forge import make_ca, make_eec, make_proxy
from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from lib_py.util import pids_on_port
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16a-ocsp")]

NAME = "lc-audit16a-ocsp"
CONNECT_HOST = "localhost"  # net-literal-allow: GSI service identity

# The responder every credential's AIA points at, and the port that is reserved
# in the ledger precisely so nothing ever answers on it — the unreachable half
# of the table.
RESP_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["RESP_PORT"]
DEAD_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["DEAD_PORT"]
RESPONDER = Path(__file__).resolve().parent / "lib" / "ocsp_responder.py"

SEED = b"ocsp flag seed\n"
SEED_PATH = "/seed.txt"

SYS_XRDFS = shutil.which("xrdfs")

# The four listeners, by the template placeholder that carries each one.  PORT
# is the instance's own port; the rest arrive as extra_ports.
OFF, ON, HARD, DEFAULT = "PORT", "ON_PORT", "HARD_PORT", "DEF_PORT"
ALL_PLANES = (OFF, ON, HARD, DEFAULT)

# One credential per verdict.  Fixed serials: they are what the responder keys
# its answer on and what its request log reports back, so a readable number
# makes both the fixture and every log assertion legible.
CREDENTIALS = {
    "good":    {"serial": 160001, "verdict": "good",    "port": RESP_PORT},
    "revoked": {"serial": 160002, "verdict": "revoked", "port": RESP_PORT},
    "unknown": {"serial": 160003, "verdict": "unknown", "port": RESP_PORT},
    # An AIA nobody answers: nothing binds DEAD_PORT, so this is the
    # network-error arm — no verdict exists for it anywhere.
    "dead":    {"serial": 160004, "verdict": None,      "port": DEAD_PORT},
    # No AIA at all — the shape xrdgsiproxy actually mints.  See §E.
    "plain":   {"serial": 160005, "verdict": None,      "port": None},
}


# --------------------------------------------------------------------------- #
# PKI — one CA, one EEC + proxy per credential, an AIA on both                 #
# --------------------------------------------------------------------------- #

def _aia(port):
    """An authorityInfoAccess extension naming one OCSP responder."""
    return x509.AuthorityInformationAccess([
        x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(f"http://{HOST}:{port}/ocsp"))])


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """One hashed CA directory, one host certificate, five credentials.

    Each credential is its OWN EEC plus a proxy off it, and the AIA goes on
    BOTH: the responder is keyed on the serial it is asked about, and giving
    every credential a private issuer means the verdict is the same answer
    whichever certificate the server treats as the leaf.  The alternative —
    five proxies off one shared EEC — would make the EEC's own verdict
    ambiguous across five different expectations.

    Proxies are minted here rather than by xrdgsiproxy because the extension
    under test has to be ON the leaf and xrdgsiproxy has no way to put it
    there; test_pblock_group_multiuser.py mints its GSI credentials the same
    way.  ``not_after_days`` clears x509forge's fixed 2026-01-01 epoch, whose
    default 1-day proxy is long expired.
    """
    base = tmp_path_factory.mktemp("a16aocsp")
    ca_dir = base / "ca"
    ca_dir.mkdir()

    ca = make_ca("/O=XrdTest/CN=audit16a-ocsp-CA")
    x509forge._place_ca_in_dir(ca_dir, ca, name="ocspca")
    ca_dir.chmod(0o755)             # XrdCl refuses a group-writable CA dir

    host = make_eec(ca, f"/O=XrdTest/CN={CONNECT_HOST}", not_after_days=4000)

    def _write(cert, name):
        path = base / f"{name}.pem"
        path.write_bytes(cert.pem)
        return path

    # The responder signs with the CA's own key, so it needs both halves as
    # files; _place_ca_in_dir only puts the hashed anchor into the store.
    ca_cert = _write(ca, "cacert")
    ca_key = base / "cakey.pem"
    ca_key.write_bytes(ca.key_pem)
    ca_key.chmod(0o600)

    host_cert = _write(host, "hostcert")
    host_key = base / "hostkey.pem"
    host_key.write_bytes(host.key_pem)
    host_key.chmod(0o600)

    creds, entries = {}, []
    for tag, spec in CREDENTIALS.items():
        ext = [] if spec["port"] is None else [(_aia(spec["port"]), False)]
        eec = make_eec(ca, f"/O=XrdTest/CN=audit16a-{tag}", not_after_days=4000,
                       extra_ext=ext or None)
        proxy = make_proxy(eec, kind="rfc3820", not_after_days=4000,
                           serial=spec["serial"], extra_ext=ext or None)
        # The standard GSI proxy file: proxy, then the EEC it delegates from,
        # then the proxy key — the layout test_pblock_group_multiuser.py:162
        # feeds a live login.  It is also the order the client puts on the
        # wire, which is why chain[0] is the proxy (§D pins that).
        path = base / f"{tag}cred.pem"
        path.write_bytes(proxy.pem + eec.pem + proxy.key_pem)
        path.chmod(0o600)
        creds[tag] = str(path)
        if spec["verdict"] is None:
            # `plain` has no responder to register with; `dead` has one that
            # nothing runs.  Leaving both out of the table means a query that
            # somehow reached the live responder shows up in its log as an
            # UNAUTHORIZED for a serial this file can name.
            continue
        eec_pem = _write(eec, f"{tag}eec")
        proxy_pem = _write(proxy, f"{tag}proxy")
        entries.append(f"{proxy_pem},{eec_pem},{spec['verdict']}")
        entries.append(f"{eec_pem},{ca_cert},{spec['verdict']}")

    return {"base": base, "ca": str(ca_dir), "ca_cert": str(ca_cert),
            "ca_key": str(ca_key), "cert": str(host_cert), "key": str(host_key),
            "entries": entries, **creds}


# --------------------------------------------------------------------------- #
# The responder                                                                #
# --------------------------------------------------------------------------- #

class _Mock:
    """The responder plus the one question this file asks it: what was it asked
    about, and since when.

    Every verdict below is a login that either happened or did not, and the
    request log is the only thing that separates "denied because the responder
    said REVOKED" from "denied without anyone being asked" — which is exactly
    the difference between the two flags under test.
    """

    def __init__(self, proc, port):
        self.proc = proc
        self.port = port

    def _ctl(self, endpoint, method="GET"):
        request = urllib.request.Request(
            f"http://{HOST}:{self.port}/ctl/{endpoint}", method=method,
            data=b"" if method == "POST" else None)
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read()
        return json.loads(body) if body.startswith((b"[", b"{")) else body

    def queries(self):
        return self._ctl("log")

    def serials(self):
        return [entry["serial"] for entry in self.queries()]

    def reset(self):
        self._ctl("reset-log", method="POST")


def _listening(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def _holders(port):
    """Who is listening on a fixed ledger port, named rather than numbered: both
    port assertions below are about occupancy and neither is actionable without
    knowing who the occupant was."""
    named = []
    for pid in pids_on_port(port):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                argv = handle.read().replace(b"\0", b" ").decode(
                    "utf-8", "replace").strip()
        except OSError:
            argv = "(gone)"
        named.append(f"{pid} {argv[:120]}")
    return "; ".join(named) or "nobody"


@pytest.fixture(scope="module")
def responder(pki):
    """The controllable responder, on the ledger port every credential's AIA
    names.  Its own output goes to a file: a responder that exits before it
    listens takes the reason with it otherwise, and on a fixed port the reason
    is the whole diagnosis."""
    log = pki["base"] / "ocsp_responder.log"
    handle = open(log, "wb")
    try:
        argv = [sys.executable, str(RESPONDER), "--port", str(RESP_PORT),
                "--bind", BIND_HOST,
                "--signer-cert", pki["ca_cert"],
                "--signer-key", pki["ca_key"]]
        for entry in pki["entries"]:
            argv += ["--entry", entry]
        proc = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT)
    finally:
        handle.close()
    try:
        assert _listening(RESP_PORT), (
            f"OCSP responder never listened on {RESP_PORT} "
            f"(exit={proc.poll()}, holders={_holders(RESP_PORT)})\n"
            f"{log.read_text(errors='replace')[-2000:]}")
        assert not _listening(DEAD_PORT, 0.5), (
            f"DEAD_PORT {DEAD_PORT} is bound by something — it is reserved in "
            "the lifecycle ledger precisely so nothing answers on it: "
            f"{_holders(DEAD_PORT)}")
        yield _Mock(proc, RESP_PORT)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

@pytest.fixture
def ocsp(lifecycle, tmp_path, pki, responder):
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)

    responder.reset()
    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16a_ocsp.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"]},
        reason="audit-16a brix_ocsp_enable/soft_fail at value granularity"))


# --------------------------------------------------------------------------- #
# Client                                                                       #
# --------------------------------------------------------------------------- #

def _port(endpoint, plane):
    return endpoint.port if plane == OFF else endpoint.extra_ports[plane]


def _read(endpoint, plane, pki, credential):
    """Read the seed file over GSI with one credential on one plane.

    XrdSecPROTOCOL is pinned to gsi and KRB5CCNAME dropped so an ambient ticket
    can never satisfy a login this file believes a certificate authenticated.
    XrdSecGSISRVNAMES is the client's own check on the SERVER's name, which is
    not the subject here."""
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "gsi"
    env["X509_CERT_DIR"] = pki["ca"]
    env["X509_USER_PROXY"] = pki[credential]
    env["XrdSecGSISRVNAMES"] = "*"
    env.pop("KRB5CCNAME", None)
    return subprocess.run(
        [SYS_XRDFS, f"root://{CONNECT_HOST}:{_port(endpoint, plane)}",
         "cat", SEED_PATH],
        capture_output=True, text=True, timeout=90, env=env)


def _accepted(endpoint, plane, pki, credential):
    result = _read(endpoint, plane, pki, credential)
    return result.returncode == 0 and SEED.decode() in result.stdout, result


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except OSError:
        return "(error log unavailable)"


# --------------------------------------------------------------------------- #
# §A — brix_ocsp_enable: the flag that decides whether anyone is asked         #
# --------------------------------------------------------------------------- #

class TestTheEnableFlagDecidesWhetherRevocationIsChecked:

    def test_off_accepts_a_revoked_credential(self, ocsp, pki, responder):
        """The security-negative, and the reason the flag has to be tested by
        value.  The responder calls this certificate REVOKED — §A pins that
        from the other plane — and `off` never asks it, so the login succeeds.
        A site that writes `off` to work around a flaky responder is running
        with online revocation switched off, not degraded."""
        ok, result = _accepted(ocsp, OFF, pki, "revoked")
        assert ok, ("brix_ocsp_enable off refused a revoked credential; either "
                    "the flag no longer gates the check (update this test) or "
                    f"the chain is broken for an unrelated reason\n"
                    f"{result.stderr}\n{_errlog(ocsp)[-2000:]}")

    def test_off_sends_no_request_at_all(self, ocsp, pki, responder):
        """The flag gates the QUERY, not just the verdict.  Written separately
        from the row above because a `enable off` that still queried and then
        ignored the answer would pass that one — and would still leak every
        user's certificate serial to the CA on every login."""
        responder.reset()
        _accepted(ocsp, OFF, pki, "revoked")
        assert responder.queries() == [], \
            f"brix_ocsp_enable off queried the responder: {responder.queries()}"

    def test_on_rejects_a_revoked_credential(self, ocsp, pki, responder):
        """REVOKED is never overridden (ocsp.c:116), so this holds on the
        soft-fail plane as well as the strict one."""
        responder.reset()
        ok, result = _accepted(ocsp, ON, pki, "revoked")
        assert not ok, ("brix_ocsp_enable on accepted a credential the "
                        f"responder calls REVOKED\n{result.stdout}")
        assert {"serial": CREDENTIALS["revoked"]["serial"],
                "verdict": "revoked"} in responder.queries(), (
            "the login was refused without the responder being asked — the "
            f"deny is not a revocation verdict: {responder.queries()}")

    def test_the_same_credential_differs_only_by_the_flag(self, ocsp, pki,
                                                          responder):
        """Two listeners, one process, one trust store, one certificate, and
        opposite verdicts.  Stated as one assertion so the pair cannot quietly
        become the same answer."""
        assert _accepted(ocsp, OFF, pki, "revoked")[0] is True
        assert _accepted(ocsp, ON, pki, "revoked")[0] is False


# --------------------------------------------------------------------------- #
# §B — brix_ocsp_soft_fail: what a NON-answer means                            #
# --------------------------------------------------------------------------- #

class TestTheSoftFailFlagDecidesWhatSilenceMeans:
    """Every credential in this class is a perfectly good certificate that the
    responder does not vouch for: UNKNOWN, unreachable, or with no responder
    published at all.  The flag is the whole difference between them being
    admitted and being refused."""

    @pytest.mark.parametrize("credential", ["unknown", "dead", "plain"])
    def test_soft_fail_on_admits_what_nobody_vouched_for(self, ocsp, pki,
                                                         credential):
        ok, result = _accepted(ocsp, ON, pki, credential)
        assert ok, (f"brix_ocsp_soft_fail on refused the {credential} "
                    f"credential\n{result.stderr}\n{_errlog(ocsp)[-2000:]}")

    @pytest.mark.parametrize("credential", ["unknown", "dead", "plain"])
    def test_soft_fail_off_refuses_what_nobody_vouched_for(self, ocsp, pki,
                                                           credential):
        ok, result = _accepted(ocsp, HARD, pki, credential)
        assert not ok, (f"brix_ocsp_soft_fail off accepted the {credential} "
                        f"credential — the strict token is not strict\n"
                        f"{result.stdout}")

    def test_the_strict_token_still_admits_a_good_answer(self, ocsp, pki,
                                                         responder):
        """The attribution control for the class: `soft_fail off` refuses a
        non-answer, not every login.  Without this row a strict plane that
        denied unconditionally — the obvious way to get the three rows above
        green — would read as strictness working."""
        responder.reset()
        ok, result = _accepted(ocsp, HARD, pki, "good")
        assert ok, ("brix_ocsp_soft_fail off refused a credential the "
                    f"responder calls GOOD\n{result.stderr}\n"
                    f"{responder.queries()}\n{_errlog(ocsp)[-2000:]}")
        assert {"serial": CREDENTIALS["good"]["serial"], "verdict": "good"} \
            in responder.queries(), responder.queries()

    def test_a_dead_responder_is_reached_for_and_not_merely_skipped(
            self, ocsp, pki, responder):
        """The `dead` credential's AIA names DEAD_PORT, which nothing binds, so
        its refusal above must come from a failed connection — never from the
        live responder having answered something.  Pins the two unreachable
        cases apart from each other."""
        responder.reset()
        _accepted(ocsp, HARD, pki, "dead")
        assert responder.queries() == [], (
            "the dead credential's query reached the LIVE responder — its AIA "
            f"is pointing at the wrong port: {responder.queries()}")


# --------------------------------------------------------------------------- #
# §C — the merge default                                                       #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """conf_structs.h:532 merges the unset field to 1.  Soft-fail is therefore
    the token every deployment that writes only `brix_ocsp_enable on` runs, and
    until this class existed nothing asserted it from outside the C."""

    def test_the_absent_flag_tolerates_a_missing_answer(self, ocsp, pki):
        ok, result = _accepted(ocsp, DEFAULT, pki, "dead")
        assert ok, ("with brix_ocsp_soft_fail absent an unreachable responder "
                    f"denied the login — the default is not on\n"
                    f"{result.stderr}\n{_errlog(ocsp)[-2000:]}")

    def test_the_absent_flag_still_enforces_revocation(self, ocsp, pki):
        """The half that keeps the default from being vacuous: soft-fail is not
        no-fail, and REVOKED denies under it."""
        ok, result = _accepted(ocsp, DEFAULT, pki, "revoked")
        assert not ok, ("with brix_ocsp_soft_fail absent a revoked credential "
                        f"was accepted\n{result.stdout}")

    def test_the_absent_plane_answers_exactly_as_the_on_plane(self, ocsp, pki):
        """Both directions at once, over every credential, so a future change
        to the default has to break this test rather than drift past the two
        above."""
        for credential in CREDENTIALS:
            assert (_accepted(ocsp, DEFAULT, pki, credential)[0]
                    == _accepted(ocsp, ON, pki, credential)[0]), \
                f"default and `on` disagree on the {credential} credential"


# --------------------------------------------------------------------------- #
# §D — attribution: which certificate is asked about, and every plane agrees   #
# --------------------------------------------------------------------------- #

class TestWhatIsActuallyAskedAbout:

    def test_the_query_is_about_the_proxy_the_client_presented(
            self, ocsp, pki, responder):
        """``leaf = sk_X509_value(chain, 0)`` (auth_cert.c:280) and the client
        puts its proxy first, so the certificate whose revocation is checked is
        the short-lived proxy — not the EEC that identifies the user.  Both
        carry an AIA here, so the log says which one it was rather than which
        one happened to have a URL."""
        responder.reset()
        assert _accepted(ocsp, ON, pki, "good")[0]
        assert responder.serials() == [CREDENTIALS["good"]["serial"]], (
            "the OCSP query was not about the proxy the client presented: "
            f"{responder.queries()}")

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_every_plane_accepts_the_good_credential(self, ocsp, pki, plane):
        """The attribution control for the whole file: one credential the
        responder vouches for, accepted on all four listeners.  Without it a
        broken chain — a mis-hashed CA directory, an expired proxy — would read
        as revocation working."""
        ok, result = _accepted(ocsp, plane, pki, "good")
        assert ok, (f"{plane}: a GOOD credential was refused\n{result.stderr}"
                    f"\n{_errlog(ocsp)[-2000:]}")

    def test_four_listeners_over_one_store_still_disagree(self, ocsp, pki):
        """The four planes name an IDENTICAL brix_trusted_ca and differ only in
        two flags.  Were the per-server OCSP config merged from a shared parent
        — or were the store cache keyed on the CA path alone — this whole file
        would collapse to a single row."""
        verdicts = {plane: _accepted(ocsp, plane, pki, "unknown")[0]
                    for plane in ALL_PLANES}
        assert verdicts == {OFF: True, ON: True, HARD: False, DEFAULT: True}, \
            verdicts


# --------------------------------------------------------------------------- #
# §E — the finding (DEFECT CANDIDATE #55)                                      #
# --------------------------------------------------------------------------- #

class TestTheStrictTokenIsUndeployable:
    """`soft_fail off` is documented as "require a definitive answer".  On a GSI
    site it means "refuse everyone"."""

    def test_the_strict_token_refuses_an_ordinary_globus_proxy(self, ocsp, pki,
                                                               responder):
        """DEFECT CANDIDATE #65.  The `plain` credential is exactly what
        xrdgsiproxy mints: a valid RFC 3820 proxy off a valid EEC, with no AIA,
        because a proxy has no reason to carry one.  X509_get1_ocsp(leaf)
        returns nothing, ocsp.c:147 takes the soft-fail default, and under the
        strict token that default is a deny — with no responder involved at
        all, which the empty query log proves.

        Pinning the defect, not endorsing it: when the check learns to walk the
        chain for an AIA (the EEC has one, two certificates away), or to
        separate "no responder published" from "the responder did not answer",
        this assertion should be inverted."""
        responder.reset()
        ok, result = _accepted(ocsp, HARD, pki, "plain")
        assert not ok, ("brix_ocsp_soft_fail off now admits a proxy with no "
                        "AIA — defect candidate #65 is fixed; invert this "
                        f"test\n{result.stdout}")
        assert responder.queries() == [], (
            "a credential with no AIA reached the responder — the URL is being "
            f"found somewhere other than the leaf: {responder.queries()}")

    def test_the_same_proxy_is_admitted_by_every_other_plane(self, ocsp, pki):
        """The scale of the defect: the credential the strict plane refuses is
        the one every other configuration in the file accepts, and it is the
        only shape real users have."""
        verdicts = {plane: _accepted(ocsp, plane, pki, "plain")[0]
                    for plane in ALL_PLANES}
        assert verdicts == {OFF: True, ON: True, HARD: False, DEFAULT: True}, \
            verdicts


# --------------------------------------------------------------------------- #
# §G — the crash this file found (DEFECT CANDIDATE #64, fixed)                 #
# --------------------------------------------------------------------------- #

class TestTheWorkerSurvivesTheQuery:
    """The regression pin for the double free.

    Every other assertion in this file reads a single login's verdict, and a
    worker that dies AFTER answering still produces the right verdict for that
    login — which is exactly how the bug hid: the first run of this file was
    green on the `enable off` plane and timed out everywhere else.  These tests
    ask the different question of whether the process is still there.
    """

    def test_the_process_serves_a_second_login_after_a_query(self, ocsp, pki,
                                                             responder):
        """Two logins on one worker.  Before the fix the first one freed the
        OCSP_CERTID twice and the worker took SIGSEGV on the way out, so the
        second login met a freshly respawned process — or nothing at all."""
        assert _accepted(ocsp, ON, pki, "good")[0]
        assert _accepted(ocsp, ON, pki, "good")[0], (
            "the second login on the same worker failed — the OCSP query is "
            f"killing the process again\n{_errlog(ocsp)[-3000:]}")

    @pytest.mark.parametrize("credential", ["good", "revoked", "unknown",
                                            "dead"])
    def test_no_verdict_kills_the_worker(self, ocsp, pki, credential,
                                         responder):
        """Every outcome the responder can produce, plus the unreachable one.
        The crash was in the shared teardown, so it fired on GOOD, REVOKED,
        UNKNOWN and connect-failure alike — a security-negative in its own
        right, since the AIA URL comes from the client's certificate and any
        client could therefore choose to take the worker down."""
        _accepted(ocsp, HARD, pki, credential)
        log = _errlog(ocsp)
        assert "exited on signal" not in log, (
            f"the {credential} credential crashed the worker:\n{log[-3000:]}")

    def test_the_error_log_records_no_crash_across_the_whole_table(self, ocsp,
                                                                   pki,
                                                                   responder):
        """The whole matrix against one process.  Cheaper than it looks — the
        instance is already up — and it is the only test here that would catch
        a crash that needs two different verdicts in sequence to trigger."""
        for plane in ALL_PLANES:
            for credential in CREDENTIALS:
                _accepted(ocsp, plane, pki, credential)
        log = _errlog(ocsp)
        assert "exited on signal" not in log, log[-3000:]


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                          #
# --------------------------------------------------------------------------- #

FLAGS = ("brix_ocsp_enable", "brix_ocsp_soft_fail", "brix_ocsp_stapling",
         "brix_ocsp_require_nonce")


def _parse(tmp_path, knobs="", stream_extra=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16aparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """`on` and `off` are the only two tokens ngx_conf_set_flag_slot accepts,
    matched case-insensitively after a length test — so `On` parses and `1`,
    `true` and `yes` do not, for all four OCSP flags at once."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("token", ["on", "off"])
    def test_each_token_is_accepted(self, tmp_path, flag, token):
        rc, out = _parse(tmp_path, f"        brix_auth none;\n"
                                   f"        {flag} {token};\n")
        assert rc == 0, f"{flag} {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["ON", "Off", "oN"])
    def test_the_token_is_matched_case_insensitively(self, tmp_path, token):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp, so an
        operator's `On` parses.  Written down because a future hand-rolled
        setter using ngx_strcmp would silently reject it — and, worse, a
        hand-rolled one that defaulted instead of erroring would turn `ON` into
        `off` with no diagnostic."""
        rc, out = _parse(tmp_path, f"        brix_auth none;\n"
                                   f"        brix_ocsp_enable {token};\n")
        assert rc == 0, f"brix_ocsp_enable {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["1", "true", "yes", "soft"])
    def test_a_value_outside_the_pair_is_refused(self, tmp_path, token):
        """`1`, `true` and `yes` are the three words an operator reaches for
        that are not the pair, and none of them may parse into a silent
        default: `brix_ocsp_enable 1` quietly meaning `off` would be a
        revocation check that never runs."""
        rc, out = _parse(tmp_path, f"        brix_auth none;\n"
                                   f"        brix_ocsp_enable {token};\n")
        assert rc != 0, f"brix_ocsp_enable {token} parsed:\n{out}"
        assert "invalid value" in out, out

    @pytest.mark.parametrize("line", ["brix_ocsp_enable;",
                                      "brix_ocsp_enable on off;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse(tmp_path, f"        brix_auth none;\n        {line}\n")
        assert rc != 0, f"{line} parsed:\n{out}"
        assert "invalid number of arguments" in out, out

    def test_the_directive_is_refused_outside_a_server(self, tmp_path):
        """NGX_STREAM_SRV_CONF only (module.c:509).  A stream-level line is a
        parse error, not a default inherited by every server — which matters
        because an operator who wrote one stream-wide `brix_ocsp_enable on`
        must not believe every listener is checking revocation."""
        rc, out = _parse(tmp_path, "        brix_auth none;\n",
                         stream_extra="    brix_ocsp_enable on;\n")
        assert rc != 0, f"brix_ocsp_enable was accepted in stream {{}}:\n{out}"
        assert "directive is not allowed here" in out, out
