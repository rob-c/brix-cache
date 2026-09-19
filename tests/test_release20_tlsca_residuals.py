"""2.0 F19 — the ``xrd.tlsca`` residuals: ``brix_crl_scope`` and
``brix_tls_verify_log``.

WHY THIS FILE EXISTS
--------------------
Stock XRootD's ``xrd.tlsca`` carries two knobs brix had no spelling for:
``crlcheck all|last`` (how far up the chain revocation is enforced) and
``verifylog off|failure|all`` (what the server says about a chain it just
verified).  The 2.0 register's F19 row ships them as ``brix_crl_scope`` and
``brix_tls_verify_log``, on BOTH planes — the stream (root://) server block and
the http (WebDAV) location — and this file is the row's evidence.

THE DISCOVERY THIS FILE EXISTS TO FREEZE
----------------------------------------
The obvious implementation of ``crlcheck last`` is OpenSSL's plain
``X509_V_FLAG_CRL_CHECK`` — check the leaf, skip the issuers — and it is
catastrophically wrong for a grid server.  OpenSSL's ``check_cert`` returns
early for any certificate carrying ``EXFLAG_PROXY``, so on a GSI login (proxy
at depth 0, the user's EEC at depth 1) plain ``CRL_CHECK`` checks NOTHING AT
ALL.  Measured on OpenSSL 3.0.18 with ``openssl verify -allow_proxy_certs``
against a CA that had revoked the EEC:

    -crl_check_all  -> error 23 at 1 depth lookup: certificate revoked
    -crl_check      -> OK

``brix_crl_scope last`` implemented on the flag would therefore have been
indistinguishable from ``brix_crl_mode off`` for every proxy login on the
planet: a revoked user need only wrap their credential in a proxy.  brix
instead arms ``CRL_CHECK|CRL_CHECK_ALL|USE_DELTAS`` under BOTH scope values and
narrows ``last`` inside the verify callback
(``brix_crl_out_of_scope``/``brix_chain_eec_depth``,
``src/auth/crypto/store_policy_store.c``), keyed on the depth of the shallowest
NON-proxy certificate rather than on depth 0.  The store-flag half of that
decision is pinned in C by ``SC-03/04/05`` in ``tests/c/x509_conformance_test.c``;
this file pins the behaviour it buys, end to end, over a real GSI handshake.

WHY THE LAB NEEDS AN INTERMEDIATE CA
------------------------------------
On a two-level hierarchy (root -> EEC) the end entity and the self-signed root
are covered by the SAME CRL — the root's — so no scope value can be told apart
from any other, whatever the implementation.  A third level is required:

    root -> intermediate -> EEC -> proxy

The EEC's CRL now comes from the intermediate and the intermediate's from the
root, so withholding ONLY the root's CRL produces a chain that ``all`` refuses
(``error 3 at 2 depth``, the intermediate) and ``last`` admits.  The lab
therefore builds two such hierarchies in one hashed CA directory: ``full``,
which publishes both CRLs, and ``gap``, which publishes only its
intermediate's.

WHAT THE TABLE ESTABLISHES
--------------------------
    credential   scope all   scope last   scope absent
    full         accept      accept       accept
    gap          REJECT      accept       REJECT       -> the default is `all`
    revoked      reject      REJECT       reject       -> the security pin

The ``revoked`` row is the invariant this knob is not allowed to break, and it
is the row that a flag-based ``last`` would have flipped to ``accept``.

THE SECOND FINDING — AN UNREADABLE CRL FAILED OPEN UNDER `try` (FIXED, F22)
---------------------------------------------------------------------------
This row found it and the next one fixed it, so it is documented here as the
reason §E looks the way it does.  ``pki_load_crls_from_dirent`` used to map a
per-entry ``fopen`` failure to 0, not to -1: a CRL inside a CRL DIRECTORY that
the worker could not read cost the directory that CRL and nothing else.  Under
``brix_crl_mode try`` the armed-flags predicate is ``crl_count > 0``
(``store_policy_store.c:414``), so a directory whose only CRL turned mode 000
disarmed revocation checking entirely, the server started, and it accepted
credentials the unread CRL revokes — a fail-open reachable by a chmod alone,
with no reload and no config edit.

The asymmetry that allowed it was in the config-time check: ``brix_crl`` naming
the FILE is ``access(R_OK)``-tested by ``brix_conf_check_path`` and refuses to
start, while naming its DIRECTORY passes, because ``access`` is asked about the
directory and never about what is in it.

Since F22 an unreadable entry is -1, ``pki_load_crls_from_dir`` propagates it,
and ``brix_gsi_build_trust_store`` turns it into an ``[emerg]`` naming both the
trusted_ca and the CRL path.  Both spellings now refuse to start, with
different messages, and neither ``try`` nor ``require`` can talk the loader out
of it — §E pins all of that, plus the control that an ordinary readable CRL
directory still loads under ``try``.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

import x509forge
from x509forge import make_ca, make_crl, make_eec
from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN
from _test_gsi_handshake_helpers import _mint_proxy

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-tlsca")]

NAME = "lc-r20-tlsca"
CONNECT_HOST = "localhost"  # net-literal-allow: GSI service identity

SEED = b"tlsca residual seed\n"
SEED_PATH = "/seed.txt"

SYS_XRDFS = shutil.which("xrdfs")

# §G reads the two planes' enum tables straight out of the sources: the only
# way to prove one spelling means one thing on both is to compare the tables.
SRC = Path(__file__).resolve().parent.parent / "src"

# The seven listeners, by the template placeholder that carries each one.
ALL, LAST, DEFAULT, VLOG, VFAIL, BADCRL, TRY = (
    "PORT", "LAST_PORT", "DEF_PORT", "VLOG_PORT", "VFAIL_PORT",
    "BADCRL_PORT", "TRY_PORT")

SCOPE_PLANES = (ALL, LAST, DEFAULT)

REJECTED = "brix: tls verify log: chain rejected at depth"
ACCEPTED = "brix: tls verify log: chain accepted, depth"

# Anything that would turn the error log into a credential store.  "BEGIN
# CERTIFICATE" is in the list because a full PEM chain in a world-readable log
# is the other half of what the F19 row forbids: it is not secret, but it is
# an attacker's shopping list of exactly which DNs this server trusts, in a
# form they can replay into their own store.
FORBIDDEN_IN_LOG = ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY",
                    "BEGIN EC PRIVATE KEY", "PRIVATE KEY",
                    "BEGIN CERTIFICATE")


# --------------------------------------------------------------------------- #
# PKI — two three-level hierarchies, one of them missing its root CRL          #
# --------------------------------------------------------------------------- #

def _hierarchy(ca_dir, tag):
    """One root + one intermediate, both placed in the hashed CA directory.

    The intermediate is placed as an anchor rather than shipped in the client's
    proxy file because that is what a grid deployment does: xrdgsiproxy writes
    proxy + EEC and nothing else, so an intermediate the server cannot look up
    is a chain it cannot build at all.
    """
    root = make_ca(f"/O=XrdTest/CN=f19-{tag}-root")
    inter = make_eec(root, f"/O=XrdTest/CN=f19-{tag}-int",
                     ca_true=True, keycert_sign=True)
    x509forge._place_ca_in_dir(ca_dir, root, name=f"{tag}root")
    x509forge._place_ca_in_dir(ca_dir, inter, name=f"{tag}int")
    return root, inter


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """The whole lab's PKI: one CA directory, three CRL directories, three
    proxies.

    xrdgsiproxy is a hard requirement and not a skip — every claim in this file
    is about what a PROXY chain does to a store, and a proxy minted any other
    way would not be that chain.
    """
    assert shutil.which("xrdgsiproxy"), \
        "xrdgsiproxy is required to mint the proxy chains this row is about"
    base = tmp_path_factory.mktemp("r20tlsca")

    ca_dir = base / "ca"
    ca_dir.mkdir()
    full_root, full_int = _hierarchy(ca_dir, "full")
    gap_root, gap_int = _hierarchy(ca_dir, "gap")

    host = make_eec(full_root, f"/O=XrdTest/CN={CONNECT_HOST}")
    good = make_eec(full_int, "/O=XrdTest/CN=f19-full-user")
    revoked = make_eec(full_int, "/O=XrdTest/CN=f19-revoked-user")
    gapped = make_eec(gap_int, "/O=XrdTest/CN=f19-gap-user")
    ca_dir.chmod(0o755)             # XrdCl refuses a group-writable CA dir

    # Three CRLs, and one deliberate hole: gap-root publishes nothing, so the
    # gap intermediate (depth 2 behind a proxy) has no CRL and only `all` cares.
    crl_dir = base / "crls"
    crl_dir.mkdir()
    (crl_dir / "fullroot.r0").write_bytes(make_crl(full_root))
    (crl_dir / "fullint.r0").write_bytes(make_crl(full_int, revoked=[revoked]))
    (crl_dir / "gapint.r0").write_bytes(make_crl(gap_int))

    # A directory whose only *.r0 is not a CRL at all: it matches the loader's
    # name predicate, so it is opened, and PEM_read_X509_CRL yields nothing.
    bad_dir = base / "badcrls"
    bad_dir.mkdir()
    (bad_dir / "fullroot.r0").write_bytes(b"-----BEGIN X509 CRL-----\nnot "
                                          b"base64 at all\n-----END X509 "
                                          b"CRL-----\n")

    # A directory holding one entry the loader's name predicate accepts and
    # that NOTHING can open.  Since 2.0 F22 a server pointed at it refuses to
    # start, so it is a parse-tier subject only — it is deliberately NOT wired
    # into the running instance, which could not start if it were.
    #
    # Unopenable is spelled as a symlink loop rather than mode 0o000: this
    # suite's lanes run as root, root bypasses DAC, and `nginx -t` does its
    # config-time `access(R_OK)` and its CRL fopen() as the INVOKING user (the
    # worker de-escalation happens later, and never for -t).  Every case here
    # therefore watched the loader open the "unreadable" CRL, load it fine and
    # start — reported as "F22 has reverted", which is the opposite of what
    # had happened.  ELOOP is refused for every uid, reaches the same
    # `access()`/`fopen()` failure arms, and leaves the file a real CRL for
    # the readable twin next to it.
    unread_dir = base / "unreadable"
    unread_dir.mkdir()
    # The loop's other half is deliberately named so the loader's predicate
    # (*.pem / *.r[0-9]) does NOT match it: two matching entries means readdir
    # order decides which path the refusal names, and the assertions below
    # name one.
    hidden = unread_dir / "fullint.r0"
    partner = unread_dir / "fullint.loop"
    hidden.symlink_to(partner)
    partner.symlink_to(hidden)

    def _write(cert, tag):
        pem = base / f"{tag}cert.pem"
        key = base / f"{tag}key.pem"
        pem.write_bytes(cert.pem)
        key.write_bytes(cert.key_pem)
        key.chmod(0o600)
        return str(pem), str(key)

    host_cert, host_key = _write(host, "host")

    def _proxy(cert, tag):
        pem, key = _write(cert, tag)
        out = str(base / f"{tag}proxy.pem")
        env = dict(os.environ, X509_CERT_DIR=str(ca_dir), X509_USER_PROXY=out)
        assert _mint_proxy(pem, key, out, str(ca_dir), env), \
            f"xrdgsiproxy could not mint the {tag} proxy"
        return out

    return {"ca": str(ca_dir), "crls": str(crl_dir), "bad": str(bad_dir),
            "unread": str(unread_dir), "unread_file": str(hidden),
            "cert": host_cert, "key": host_key,
            "full": _proxy(good, "full"),
            "revoked": _proxy(revoked, "revoked"),
            "gap": _proxy(gapped, "gap")}


@pytest.fixture
def tlsca(lifecycle, tmp_path, pki):
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)

    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_release20_tlsca.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"], "CRLDIR": pki["crls"],
                         "BADCRLDIR": pki["bad"]},
        reason="2.0 F19 xrd.tlsca residuals: crl scope + verification log."))


# --------------------------------------------------------------------------- #
# Client + log readers                                                         #
# --------------------------------------------------------------------------- #

def _port(endpoint, plane):
    return endpoint.port if plane == ALL else endpoint.extra_ports[plane]


def _read(endpoint, plane, pki, credential):
    """Read the seed file over GSI with one credential on one plane."""
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


def _logpath(endpoint):
    return os.path.join(endpoint.prefix, "logs", "error.log")


def _mark(endpoint):
    """Byte offset of the end of the error log, so a test reads only its own
    handshake.  Seven listeners share one log; without a mark a NOTICE from a
    neighbouring case would be attributed here."""
    try:
        return os.path.getsize(_logpath(endpoint))
    except OSError:
        return 0


def _since(endpoint, mark):
    try:
        with open(_logpath(endpoint), "rb") as fh:
            fh.seek(mark)
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _drive_and_log(endpoint, plane, pki, credential):
    mark = _mark(endpoint)
    ok, result = _accepted(endpoint, plane, pki, credential)
    return ok, result, _since(endpoint, mark)


# --------------------------------------------------------------------------- #
# §A — brix_crl_scope takes effect (success)                                   #
# --------------------------------------------------------------------------- #

class TestScopeTakesEffect:

    @pytest.mark.parametrize("plane", SCOPE_PLANES)
    def test_a_fully_covered_chain_is_accepted_under_every_scope(
            self, tlsca, pki, plane):
        """The attribution control for the whole file.  The `full` credential's
        every issuer publishes a CRL and none of them lists it, so a refusal
        here is a broken lab and not a scope decision — which matters, because
        `require` + CRL_CHECK_ALL over a three-level chain plus a proxy is
        precisely the configuration most likely to refuse everything."""
        ok, result = _accepted(tlsca, plane, pki, "full")
        assert ok, (f"{plane}: a fully CRL-covered chain was refused\n"
                    f"{result.stderr}\n{_since(tlsca, 0)[-2000:]}")

    def test_scope_all_refuses_a_chain_whose_root_publishes_no_crl(
            self, tlsca, pki):
        """`all` means every issuer.  The gap hierarchy's intermediate sits at
        depth 2 behind the proxy and its issuer (the gap root) publishes
        nothing, so under `require` the store reports UNABLE_TO_GET_CRL there
        and the login fails closed."""
        ok, result = _accepted(tlsca, ALL, pki, "gap")
        assert not ok, ("brix_crl_scope all accepted a chain with an "
                        f"uncovered issuer\n{result.stdout}")

    def test_scope_last_admits_the_same_chain(self, tlsca, pki):
        """The same credential, the same store, one token apart — and the only
        reason the token exists.  A site whose upstream CAs publish no CRL for
        their own issuers can enforce revocation on user credentials without
        being refused by its own trust anchors."""
        ok, result = _accepted(tlsca, LAST, pki, "gap")
        assert ok, ("brix_crl_scope last refused a chain whose only defect is "
                    f"an uncovered ISSUER\n{result.stderr}\n"
                    f"{_since(tlsca, 0)[-2000:]}")

    def test_the_two_scopes_disagree_on_exactly_one_credential(self, tlsca,
                                                               pki):
        """Stated as one assertion so the pair above cannot quietly become the
        same answer: three credentials, two planes, one disagreement."""
        table = {(plane, cred): _accepted(tlsca, plane, pki, cred)[0]
                 for plane in (ALL, LAST)
                 for cred in ("full", "gap", "revoked")}
        assert table == {(ALL, "full"): True, (LAST, "full"): True,
                         (ALL, "gap"): False, (LAST, "gap"): True,
                         (ALL, "revoked"): False,
                         (LAST, "revoked"): False}, table


class TestTheScopeMergeDefault:
    """``shared_conf_merge.h`` merges the unset field to BRIX_CRL_SCOPE_ALL.
    That is the value every deployment that never writes the directive runs,
    and it is the strict one — a new knob must not relax anything by existing.
    """

    def test_the_absent_directive_refuses_the_uncovered_chain(self, tlsca,
                                                             pki):
        ok, result = _accepted(tlsca, DEFAULT, pki, "gap")
        assert not ok, ("with brix_crl_scope absent an uncovered issuer was "
                        f"admitted — the default is not `all`\n{result.stdout}")

    def test_the_absent_plane_answers_exactly_as_the_all_plane(self, tlsca,
                                                              pki):
        for credential in ("full", "gap", "revoked"):
            assert (_accepted(tlsca, DEFAULT, pki, credential)[0]
                    == _accepted(tlsca, ALL, pki, credential)[0]), \
                f"default and `all` disagree on the {credential} credential"


# --------------------------------------------------------------------------- #
# §B — the security pin: `last` is not `off` (security negative)               #
# --------------------------------------------------------------------------- #

class TestARevokedCredentialIsRefusedUnderEveryScope:
    """THE row.  A ``last`` built on X509_V_FLAG_CRL_CHECK would accept every
    one of these, because OpenSSL skips the proxy at depth 0 and never reaches
    the EEC at depth 1.  See this module's docstring for the measurement.
    """

    @pytest.mark.parametrize("plane", SCOPE_PLANES)
    def test_a_revoked_end_entity_behind_a_proxy_is_refused(self, tlsca, pki,
                                                            plane):
        ok, result = _accepted(tlsca, plane, pki, "revoked")
        assert not ok, (
            f"{plane}: a proxy over a REVOKED end-entity certificate was "
            "accepted.  If brix_crl_scope last was reimplemented as plain "
            "X509_V_FLAG_CRL_CHECK, this is the bypass that creates: OpenSSL "
            f"skips proxy certificates in check_cert.\n{result.stdout}")

    def test_the_narrowed_scope_still_names_revocation_as_the_reason(
            self, tlsca, pki):
        """Attribution: `last` must refuse the revoked credential BECAUSE it is
        revoked, not because the narrowing broke chain building.  The verify
        log on the `all`-scoped logging plane names the verdict, and the same
        credential is accepted by nothing while `full` is accepted by
        everything."""
        ok, _, log = _drive_and_log(tlsca, VFAIL, pki, "revoked")
        assert not ok
        assert "certificate revoked" in log, \
            f"the refusal was not attributed to revocation\n{log}"


# --------------------------------------------------------------------------- #
# §C — brix_tls_verify_log takes effect (success)                              #
# --------------------------------------------------------------------------- #

class TestTheVerificationLog:

    def test_off_is_the_default_and_says_nothing_either_way(self, tlsca, pki):
        """The `all`-scoped plane writes no brix_tls_verify_log line, so it
        runs the merge default.  Neither an accepted nor a rejected chain may
        produce a verification-log line there — silence is brix's historical
        behaviour and the new knob must not change it for anyone who does not
        ask."""
        _, _, accepted_log = _drive_and_log(tlsca, ALL, pki, "full")
        _, _, rejected_log = _drive_and_log(tlsca, ALL, pki, "gap")
        assert ACCEPTED not in accepted_log, accepted_log
        assert REJECTED not in rejected_log, rejected_log

    def test_failure_logs_the_depth_and_subject_of_a_rejected_chain(
            self, tlsca, pki):
        ok, _, log = _drive_and_log(tlsca, VFAIL, pki, "gap")
        assert not ok
        assert REJECTED in log, f"verify_log failure logged nothing\n{log}"
        assert "f19-gap-int" in log, \
            f"the rejected line does not name the certificate that failed\n{log}"

    def test_failure_says_nothing_about_an_accepted_chain(self, tlsca, pki):
        """The half that separates `failure` from `all`."""
        ok, _, log = _drive_and_log(tlsca, VFAIL, pki, "full")
        assert ok
        assert ACCEPTED not in log, \
            f"verify_log failure logged an ACCEPTED chain\n{log}"

    def test_all_logs_every_certificate_in_an_accepted_chain(self, tlsca, pki):
        """One line per certificate, leaf upward.  The point of the value is
        answering "which CA did this login actually come through?", which no
        other line in the log does."""
        ok, _, log = _drive_and_log(tlsca, VLOG, pki, "full")
        assert ok, log
        assert log.count(ACCEPTED) >= 3, (
            "verify_log all logged fewer lines than the chain has "
            f"certificates (proxy, EEC, intermediate)\n{log}")
        for needle in ("f19-full-user", "f19-full-int"):
            assert needle in log, f"{needle} missing from the chain log\n{log}"

    def test_all_still_logs_a_rejection(self, tlsca, pki):
        """`all` is a superset of `failure`, not an alternative to it."""
        ok, _, log = _drive_and_log(tlsca, VLOG, pki, "gap")
        assert not ok
        assert REJECTED in log, f"verify_log all lost the failure half\n{log}"

    def test_the_three_values_are_three_different_behaviours(self, tlsca, pki):
        """Stated once, over both outcomes, so no two values can drift into
        each other without this failing."""
        seen = {}
        for plane in (ALL, VFAIL, VLOG):
            _, _, good = _drive_and_log(tlsca, plane, pki, "full")
            _, _, bad = _drive_and_log(tlsca, plane, pki, "gap")
            seen[plane] = (ACCEPTED in good, REJECTED in bad)
        assert seen == {ALL: (False, False), VFAIL: (False, True),
                        VLOG: (True, True)}, seen


# --------------------------------------------------------------------------- #
# §D — the log is not a credential store (security negative)                   #
# --------------------------------------------------------------------------- #

def _pem_body(path):
    """The base64 body of a PEM file, banners stripped and lines joined.

    A leak check has to look for the credential as it is on the wire, not as it
    is on disk: PEM wraps at 64 columns, so a run that spans a line break is
    invisible to a naive substring search of the file's own text.
    """
    lines = open(path, "rb").read().splitlines()
    return b"".join(ln for ln in lines if not ln.startswith(b"-----")).decode()


def _body_windows(body, width=48):
    """Non-overlapping ``width``-character windows of ``body``."""
    return {body[i:i + width]
            for i in range(0, max(len(body) - width, 1), width)}


class TestTheVerificationLogLeaksNothing:
    """The error log is world-readable by construction — nginx creates it 0644
    and an operator's log shipper reads it as nobody.  That is not the defect;
    printing certificate or key MATERIAL into it would be.  ``verify_log all``
    is the value with the largest blast radius, so it is the one measured.
    """

    def test_the_log_carries_distinguished_names_and_nothing_else(self, tlsca,
                                                                  pki):
        _, _, good = _drive_and_log(tlsca, VLOG, pki, "full")
        _, _, bad = _drive_and_log(tlsca, VLOG, pki, "gap")
        for needle in FORBIDDEN_IN_LOG:
            assert needle not in good, f"{needle!r} in an accepted-chain log"
            assert needle not in bad, f"{needle!r} in a rejected-chain log"

    def test_no_credential_body_reaches_the_log(self, tlsca, pki):
        """A stronger statement than the PEM banner check: no 48-byte run of
        the user's own certificate body may appear, banner or not."""
        _, _, log = _drive_and_log(tlsca, VLOG, pki, "full")
        windows = _body_windows(_pem_body(pki["full"]))
        leaked = sorted(w for w in windows if w and w in log)
        assert not leaked, f"credential body in the verification log: {leaked}"

    def test_the_log_is_world_readable_which_is_why_the_above_matters(
            self, tlsca, pki):
        """Not an assertion about a defect — an assertion about the threat
        model.  If nginx ever started creating error.log 0600 this test should
        be updated rather than deleted, because the two tests above would
        silently stop being interesting."""
        _drive_and_log(tlsca, VLOG, pki, "full")
        mode = os.stat(_logpath(tlsca)).st_mode
        assert mode & stat.S_IROTH, (
            "error.log is no longer world-readable; the leak tests above are "
            "still correct but no longer describe the risk they were written "
            f"for (mode {oct(stat.S_IMODE(mode))})")


# --------------------------------------------------------------------------- #
# §E-§G live in the continuation file (§10.2): this module is at its size cap. #
# --------------------------------------------------------------------------- #

from split_continuation import load as _load_continuations  # noqa: E402

_load_continuations(globals(), __file__,
                    "_test_release20_tlsca_residuals_part2.py")
