"""brix_gsi_legacy_proxy at VALUE granularity — the (mode x plane x credential)
login table for pre-RFC 3820 (GT2) proxies.

WHAT THE VALUE SELECTS
----------------------
A legacy GT2 proxy is a certificate whose subject is its issuer's subject plus
exactly one CN of ``proxy`` (full), ``limited proxy`` (limited) or an all-digit
value (full), carrying NO proxyCertInfo extension
(store_policy_conformance.c::brix_gt2_proxy_kind).  The chain verifier reads
the mode off the trust store (gsi_verify.c::brix_gsi_verify_chain):

    off        -> nothing is marked for OpenSSL; a GT2 proxy's issuer is an
                  EEC, so the walk fails "unable to get local issuer
                  certificate".
    on         -> every GT2 proxy on the chain is flagged as a proxy before the
                  walk; full and limited alike log in, and a NOTICE
                  "legacy (pre-RFC 3820) proxy accepted" is written.
    full-only  -> as `on`, then brix_gsi_enforce_legacy_policy refuses a chain
                  holding a GT2 "limited proxy" with the WARN
                  "legacy limited proxy in the chain".

RFC 3820 proxies are not GT2 proxies and are accepted in every mode; the
absent directive merges to `on` (server_conf_merge_security.c:117 /
shared_conf_merge.h:256).  Both planes share one verifier — the stream GSI
login and the davs:// client-certificate path (webdav/auth_cert.c:540) both
call brix_gsi_verify_chain — so the table is measured on both.

WHAT THE TABLE ESTABLISHES
--------------------------
Eight listeners on ONE instance (four root://, four davs://) over ONE trust
anchor, crossed by four plain (non-VOMS) user proxies minted by
utils/voms_proxy_fake.py's proxy builder:

    credential     off      on       full-only   absent
    rfc            accept   accept   accept      accept
    gt2 full       REJECT   accept   accept      accept
    gt2 limited    REJECT   accept   REJECT      accept
    gt2 numeric    REJECT   accept   accept      accept

The `off` x GT2 cells are the security negatives (a site that wrote `off`
never admits a pre-RFC credential), `full-only` x limited is the only cell
that separates the two accepting tokens, and the numeric row pins that a
digit-only CN without proxyCertInfo is a FULL legacy proxy, not an EEC.

The VOMS half — a VOMS AC carried inside a GT2 proxy yields its VO under the
default mode — is test_voms_native_ac.py::test_legacy_gt2_proxy_is_admitted
on the registry's vo-acl member; this file is the plain-proxy table only.
"""

import http.client
import os
import shutil
import ssl
import subprocess
import sys

import pytest

import x509forge
from x509forge import make_ca, make_eec
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_UTILS = os.path.join(_REPO, "utils")
if _UTILS not in sys.path:
    sys.path.insert(0, _UTILS)
import voms_proxy_fake as minter  # noqa: E402  (the GT2 proxy builder)

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-gsi-legacy-proxy")]

NAME = "lc-gsi-legacy-proxy"
CONNECT_HOST = "localhost"  # net-literal-allow: GSI service identity

SEED = b"legacy proxy seed\n"
SEED_PATH = "/seed.txt"

SYS_XRDFS = shutil.which("xrdfs")

CA_DN = "/O=XrdTest/OU=gt2/CN=gsi-legacy-proxy-CA"
USER_DN = "/O=XrdTest/OU=gt2/CN=gsi-legacy-proxy-user"

# The four modes, by the template placeholder that carries each stream arm; the
# http arm of the same mode is HTTP_PORTS[mode].
OFF, ON, FULL, DEFAULT = "PORT", "ON_PORT", "FULL_PORT", "DEF_PORT"
MODES = (OFF, ON, FULL, DEFAULT)
HTTP_PORTS = {OFF: "HTTP_PORT", ON: "HTTP_ON_PORT", FULL: "HTTP_FULL_PORT",
              DEFAULT: "HTTP_DEF_PORT"}
ROOT, DAVS = "root", "davs"
PLANES = (ROOT, DAVS)

# The four credentials: the minter's proxy builder with legacy=False (RFC 3820,
# proxyCertInfo, numeric CN) or legacy=True with each GT2 CN kind.
RFC, GT2_FULL, GT2_LIMITED, GT2_NUMERIC = ("rfc", "gt2_full", "gt2_limited",
                                           "gt2_numeric")
CREDENTIALS = (RFC, GT2_FULL, GT2_LIMITED, GT2_NUMERIC)
_GT2_KIND = {GT2_FULL: "proxy", GT2_LIMITED: "limited", GT2_NUMERIC: "numeric"}

# The expected table, by credential then mode.
VERDICT = {
    RFC:         {OFF: True,  ON: True, FULL: True,  DEFAULT: True},
    GT2_FULL:    {OFF: False, ON: True, FULL: True,  DEFAULT: True},
    GT2_LIMITED: {OFF: False, ON: True, FULL: False, DEFAULT: True},
    GT2_NUMERIC: {OFF: False, ON: True, FULL: True,  DEFAULT: True},
}

ACCEPTED_NOTICE = "legacy (pre-RFC 3820) proxy accepted"
LIMITED_REFUSAL = "legacy limited proxy in the chain"
OFF_REFUSAL = "unable to get local issuer certificate"

CELLS = [pytest.param(mode, plane, id=f"{mode}-{plane}")
         for mode in MODES for plane in PLANES]


# --------------------------------------------------------------------------- #
# PKI — one anchor, one user, four proxies                                     #
# --------------------------------------------------------------------------- #

def _write_credential(base, tag, leaf_cert, leaf_key, eec):
    """One xrdgsiproxy-layout file (proxy cert, key, EEC) for X509_USER_PROXY,
    plus the cert-chain / key pair the davs:// client loads separately."""
    proxy = base / f"{tag}.pem"
    proxy.write_bytes(minter._pem(leaf_cert) + minter._key_pem(leaf_key)
                      + eec.pem)
    proxy.chmod(0o600)
    chain = base / f"{tag}_chain.pem"
    chain.write_bytes(minter._pem(leaf_cert) + eec.pem)
    key = base / f"{tag}_key.pem"
    key.write_bytes(minter._key_pem(leaf_key))
    key.chmod(0o600)
    return {"proxy": str(proxy), "chain": str(chain), "key": str(key)}


def _mint(base, tag, eec):
    """A plain proxy of `eec` in the shape `tag` names (no VOMS extension)."""
    kind = _GT2_KIND.get(tag)
    cert, key = minter._sign_proxy(eec.cert, eec.key, 1, None,
                                   legacy=kind is not None,
                                   legacy_kind=kind or "proxy")
    return _write_credential(base, tag, cert, key, eec)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """One hashed CA directory, the host credential, and the four proxies."""
    base = tmp_path_factory.mktemp("gt2pki")
    ca_dir = base / "ca"
    ca_dir.mkdir()
    ca = make_ca(CA_DN)
    x509forge.write_hashed_ca_dir(ca_dir, ca)
    ca_dir.chmod(0o755)             # XrdCl refuses a group-writable CA dir

    host = make_eec(ca, f"/O=XrdTest/OU=gt2/CN={CONNECT_HOST}")
    user = make_eec(ca, USER_DN)
    host_cert = base / "hostcert.pem"
    host_key = base / "hostkey.pem"
    host_cert.write_bytes(host.pem)
    host_key.write_bytes(host.key_pem)
    host_key.chmod(0o600)

    creds = {tag: _mint(base, tag, user) for tag in CREDENTIALS}
    return {"ca": str(ca_dir), "bundle": str(ca_dir / "ca.pem"),
            "cert": str(host_cert), "key": str(host_key), "creds": creds}


@pytest.fixture(scope="module")
def server(tmp_path_factory, pki):
    """The eight-listener instance, booted once for the module: every arm is
    idempotent (reads only), and the module is serialised by its xdist group,
    so one boot serves the whole table."""
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    base = tmp_path_factory.mktemp("gt2srv")
    data = base / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)
    tmp = base / "ngxtmp"
    tmp.mkdir()

    harness = LifecycleHarness()
    try:
        yield harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_gsi_legacy_proxy.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(data),
            template_values={"CERT": pki["cert"], "KEY": pki["key"],
                             "CA": pki["ca"], "BUNDLE": pki["bundle"],
                             "TMP_DIR": str(tmp)},
            reason="brix_gsi_legacy_proxy at value granularity, both planes"))
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# Clients                                                                      #
# --------------------------------------------------------------------------- #

def _port(endpoint, mode, plane):
    if plane == DAVS:
        return endpoint.extra_ports[HTTP_PORTS[mode]]
    return endpoint.port if mode == OFF else endpoint.extra_ports[mode]


def _read_root(endpoint, mode, pki, credential):
    """Read the seed over GSI with stock xrdfs.  XrdSecPROTOCOL is pinned to
    gsi and KRB5CCNAME dropped so an ambient ticket can never satisfy a login
    this file believes a certificate authenticated."""
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "gsi"
    env["X509_CERT_DIR"] = pki["ca"]
    env["X509_USER_PROXY"] = pki["creds"][credential]["proxy"]
    env["XrdSecGSISRVNAMES"] = "*"
    env.pop("KRB5CCNAME", None)
    result = subprocess.run(
        [SYS_XRDFS, f"root://{CONNECT_HOST}:{_port(endpoint, mode, ROOT)}",
         "cat", SEED_PATH],
        capture_output=True, text=True, timeout=90, env=env)
    ok = result.returncode == 0 and SEED.decode() in result.stdout
    return ok, f"rc={result.returncode} stdout={result.stdout!r} " \
               f"stderr={result.stderr!r}"


def _read_davs(endpoint, mode, pki, credential):
    """GET the seed over TLS with the proxy chain as the client certificate.
    Python's OpenSSL sends every certificate in the chain file, which is how
    the server sees the EEC behind the proxy; the server's own identity is not
    the subject here, so it is not verified."""
    cred = pki["creds"][credential]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cred["chain"], cred["key"])
    conn = http.client.HTTPSConnection(
        CONNECT_HOST, _port(endpoint, mode, DAVS), context=ctx, timeout=30)
    try:
        conn.request("GET", SEED_PATH)
        response = conn.getresponse()
        body = response.read()
    except (OSError, http.client.HTTPException) as exc:
        return False, f"davs request failed: {exc!r}"
    finally:
        conn.close()
    return response.status == 200 and body == SEED, \
        f"status={response.status} body={body!r}"


def _accepted(endpoint, mode, plane, pki, credential):
    read = _read_davs if plane == DAVS else _read_root
    return read(endpoint, mode, pki, credential)


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except OSError:
        return "(error log unavailable)"


def _log_delta(endpoint, do):
    """The error-log lines one action added.  The module runs serialised on one
    worker, so nothing else writes to this log between the two reads."""
    before = len(_errlog(endpoint))
    do()
    return _errlog(endpoint)[before:]


def _check(endpoint, mode, plane, pki, credential):
    ok, detail = _accepted(endpoint, mode, plane, pki, credential)
    want = VERDICT[credential][mode]
    verb = "refused" if want else "accepted"
    assert ok == want, (
        f"brix_gsi_legacy_proxy {mode} on {plane} {verb} the {credential} "
        f"credential\n{detail}\n{_errlog(endpoint)[-2500:]}")


# --------------------------------------------------------------------------- #
# §A — an RFC 3820 proxy is not a legacy proxy                                 #
# --------------------------------------------------------------------------- #

class TestRfcProxiesAreOutsideTheDirective:
    """The attribution control for the whole file: a proxyCertInfo-bearing
    proxy is accepted under every token on both planes.  Without this row an
    `off` that refused every login would read as strictness working."""

    @pytest.mark.parametrize("mode,plane", CELLS)
    def test_rfc3820_proxy_is_accepted(self, server, pki, mode, plane):
        _check(server, mode, plane, pki, RFC)


# --------------------------------------------------------------------------- #
# §B — the token decides whether a GT2 proxy may log in at all                 #
# --------------------------------------------------------------------------- #

class TestTheTokenDecidesGt2Acceptance:
    """A full GT2 proxy (CN=proxy) is accepted under `on` and `full-only` and
    refused under `off`; `off` x GT2 is the security negative."""

    @pytest.mark.parametrize("mode,plane", CELLS)
    def test_gt2_full_proxy(self, server, pki, mode, plane):
        _check(server, mode, plane, pki, GT2_FULL)

    @pytest.mark.parametrize("mode,plane", CELLS)
    def test_gt2_numeric_cn_proxy_behaves_like_the_full_one(
            self, server, pki, mode, plane):
        """A digit-only CN without proxyCertInfo is the other GT2 spelling of
        a FULL proxy (brix_gt2_proxy_kind): same row as CN=proxy."""
        _check(server, mode, plane, pki, GT2_NUMERIC)

    @pytest.mark.parametrize("plane", PLANES)
    def test_off_refuses_with_the_generic_chain_error(self, server, pki,
                                                       plane):
        """Under `off` nothing is marked for OpenSSL, so the refusal is the
        classic chain failure — the GT2 proxy's issuer is an EEC, which is
        no CA — and not a legacy-policy message.  On root:// the module's
        verifier reports it ("unable to get local issuer certificate"); on
        davs:// nginx's own handshake verification refuses first, with
        OpenSSL's error 32 ("key usage does not include certificate signing"),
        and the request never reaches the module."""
        delta = _log_delta(
            server, lambda: _accepted(server, OFF, plane, pki, GT2_FULL))
        refusals = (OFF_REFUSAL,) if plane == ROOT else (
            OFF_REFUSAL, "key usage does not include certificate signing")
        assert any(msg in delta for msg in refusals), \
            f"{plane}: `off` did not refuse via the chain walk\n{delta[-2500:]}"
        assert LIMITED_REFUSAL not in delta


# --------------------------------------------------------------------------- #
# §C — the only cell that separates `on` from `full-only`                      #
# --------------------------------------------------------------------------- #

class TestTheTokenDecidesWhatALimitedProxyMeans:
    """`on` and `full-only` agree on everything except a GT2 "limited proxy":
    accepted under `on`, refused under `full-only` after the walk."""

    @pytest.mark.parametrize("mode,plane", CELLS)
    def test_gt2_limited_proxy(self, server, pki, mode, plane):
        _check(server, mode, plane, pki, GT2_LIMITED)

    @pytest.mark.parametrize("plane", PLANES)
    def test_the_same_credential_is_refused_only_by_off_and_full_only(
            self, server, pki, plane):
        """Stated as one assertion so the cells cannot silently become the same
        answer: four listeners see one credential, exactly two refuse it."""
        verdicts = {mode: _accepted(server, mode, plane, pki, GT2_LIMITED)[0]
                    for mode in MODES}
        assert verdicts == {OFF: False, ON: True, FULL: False,
                            DEFAULT: True}, verdicts


# --------------------------------------------------------------------------- #
# §D — what the operator is told                                               #
# --------------------------------------------------------------------------- #

class TestTheLogTellsTheOperator:

    @pytest.mark.parametrize("plane", PLANES)
    def test_on_logs_the_acceptance_notice(self, server, pki, plane):
        """gsi_verify.c writes a NOTICE for every accepted GT2 leaf so a site
        can find the clients that still need to move to RFC 3820."""
        delta = _log_delta(
            server, lambda: _accepted(server, ON, plane, pki, GT2_FULL))
        assert ACCEPTED_NOTICE in delta, \
            f"{plane}: no acceptance NOTICE for a GT2 login\n{delta[-2500:]}"

    @pytest.mark.parametrize("plane", PLANES)
    def test_full_only_names_the_limited_proxy(self, server, pki, plane):
        """The refusal is the legacy policy talking, not a broken chain."""
        delta = _log_delta(
            server, lambda: _accepted(server, FULL, plane, pki, GT2_LIMITED))
        assert LIMITED_REFUSAL in delta, \
            f"{plane}: full-only refusal did not name the limited proxy\n" \
            f"{delta[-2500:]}"

    @pytest.mark.parametrize("plane", PLANES)
    def test_an_rfc_login_writes_no_legacy_notice(self, server, pki, plane):
        """Negative control on the log line: the NOTICE is per GT2 leaf, not
        per login, so an RFC 3820 proxy under `on` writes none."""
        delta = _log_delta(
            server, lambda: _accepted(server, ON, plane, pki, RFC))
        assert ACCEPTED_NOTICE not in delta, delta[-2500:]


# --------------------------------------------------------------------------- #
# §E — the token an unconfigured deployment runs                                #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """The absent directive merges to `on` on both planes; measured over all
    four credentials so a future change to the default has to break this test
    rather than drift past the parametrised cells above."""

    @pytest.mark.parametrize("plane", PLANES)
    def test_the_absent_directive_answers_exactly_as_on(self, server, pki,
                                                        plane):
        for credential in CREDENTIALS:
            absent = _accepted(server, DEFAULT, plane, pki, credential)[0]
            on = _accepted(server, ON, plane, pki, credential)[0]
            assert absent == on, \
                f"{plane}: default and on disagree on {credential}"
