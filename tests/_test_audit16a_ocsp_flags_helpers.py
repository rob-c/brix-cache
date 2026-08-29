"""brix_ocsp / brix_ocsp_soft_fail at VALUE granularity — audit §Method,
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
``brix_ocsp``, ``brix_ocsp_soft_fail`` and ``brix_ocsp_stapling`` are the
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
``brix_ocsp`` gates the query itself: with it off, no OCSP request is
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

def _expression_1(spec):
    return (
        [] if spec["port"] is None else [(_aia(spec["port"]), False)]
    )

def _expression_2(ca, tag, ext):
    return (
        make_eec(ca, f"/O=XrdTest/CN=audit16a-{tag}", not_after_days=4000,
                               extra_ext=ext or None)
    )

def _expression_3(eec, spec, ext):
    return (
        make_proxy(eec, kind="rfc3820", not_after_days=4000,
                                   serial=spec["serial"], extra_ext=ext or None)
    )


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
        ext = _expression_1(spec)
        eec = _expression_2(ca, tag, ext)
        proxy = _expression_3(eec, spec, ext)
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
        reason="audit-16a brix_ocsp/soft_fail at value granularity"))


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
# §A — brix_ocsp: the flag that decides whether anyone is asked         #
# --------------------------------------------------------------------------- #

