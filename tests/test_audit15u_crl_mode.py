"""brix_crl_mode at VALUE granularity — audit §Method, 15th tranche.

WHY THIS FILE EXISTS
--------------------
The coverage audit's Method (steps 1-2) counts directive NAMES: a directive
scores "covered" the moment any one of its tokens appears in a config the suite
renders.  Re-running the measurement per (directive, VALUE) over the 36
``ngx_conf_enum_t`` tables in ``src/`` turned 93 pairs into 48 written and 45
never written.  ``brix_crl_mode`` is the worst entry in that list: on the
ROOT/stream plane not ONE of its three tokens has ever been written.

The name looks covered because its WebDAV twin is.  ``brix_webdav_crl_mode`` is
exercised by ``test_wlcg_conformance_crl.py`` and by the ``crl`` clause family,
which drive davs:// with a bare End-Entity credential.  A GSI login on the
stream plane presents a PROXY chain instead, against a store built by a
different call site (``brix_rebuild_gsi_store``, auth/gsi/config.c:43) — the
same three tokens, a different plane, and no test on it.

WHAT THE VALUE SELECTS
----------------------
``brix_store_configure`` (auth/crypto/store_policy_store.c:205-247) turns the
token into store state, and the token is one of two inputs, not one:

    off      -> no CRL flags are ever set.  CRLs may be loaded; nothing reads
                them.
    try      -> ``X509_V_FLAG_CRL_CHECK | CRL_CHECK_ALL | USE_DELTAS`` are set
                ONLY IF ``crl_count > 0``, plus a verify callback that
                downgrades ``X509_V_ERR_UNABLE_TO_GET_CRL`` to success.
    require  -> the same flags, unconditionally, and NO downgrade: a chain
                whose issuer publishes no CRL is refused.

``crl_count`` is the number of CRLs that ``brix_crl`` actually loaded
(pki_build.c:229-237); a hashed CA directory alone contributes nothing to it.
So ``try`` has a second half that no name-level test could ever reach: with no
``brix_crl`` configured, ``try`` never arms the flags and is indistinguishable
from ``off``.

WHAT THE TABLE ESTABLISHES
--------------------------
Five listeners on ONE instance share ONE hashed CA directory holding TWO
anchors — one whose CRL is loaded, one that publishes none — and one CRL
directory.  Three credentials cross them: a good proxy, a revoked proxy, and a
proxy from the CA with no CRL.  Measured:

    plane                  good      revoked     no-CRL issuer
    off                    accept    ACCEPT      accept
    try                    accept    reject      accept
    require                accept    reject      REJECT
    (directive absent)     accept    reject      accept      -> default is try
    try, no brix_crl       accept    ACCEPT      accept      -> disarmed

Only the ``require`` x no-CRL cell separates ``try`` from ``require``, and only
the ``off`` and disarmed-``try`` cells accept a certificate the CA has revoked.
Neither fact is reachable from a test that writes one token.

THE FINDING — DEFECT CANDIDATE #52
----------------------------------
Two configurations accept revoked certificates, and the startup warning that
says so fires for exactly one of them.  ``postconfiguration.c:89-96`` emits

    NOTE: GSI auth is enabled but no CRL is configured — REVOKED certificates
    will be ACCEPTED (set brix_crl to a CRL file/dir, ...)

under ``xcf->crl.len == 0`` alone.  It never looks at ``crl_mode``.  A server
carrying ``brix_crl /etc/grid-security/certificates;`` and ``brix_crl_mode
off;`` loads every CRL on the host, enforces none of them, and starts in
silence — while the operator who simply forgot ``brix_crl`` is told.  The
warning is keyed on the presence of a CRL SOURCE, not on whether revocation is
enforced.  ``test_the_startup_warning_is_keyed_on_the_source_not_on_enforcement``
pins today's behaviour; when the condition learns about the mode, that test
should be inverted, not deleted.
"""

import os
import shutil
import subprocess

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
              pytest.mark.xdist_group("lc-audit15u-crlmode")]

NAME = "lc-audit15u-crlmode"
CONNECT_HOST = "localhost"  # net-literal-allow: GSI service identity

SEED = b"crl mode seed\n"
SEED_PATH = "/seed.txt"

SYS_XRDFS = shutil.which("xrdfs")

# The five listeners, by the template placeholder that carries each one.  PORT
# is the instance's own port; the rest arrive as extra_ports.
OFF, TRY, REQUIRE, DEFAULT, DISARMED = (
    "PORT", "TRY_PORT", "REQ_PORT", "DEF_PORT", "NOCRL_PORT")

# Every plane that has a CRL to consult accepts a credential the CRL does not
# name; the disarmed plane does too, for the different reason that it consults
# nothing.  Used as the attribution control under every rejection below.
ALL_PLANES = (OFF, TRY, REQUIRE, DEFAULT, DISARMED)

_WARNING = b"REVOKED certificates will be ACCEPTED"


# --------------------------------------------------------------------------- #
# PKI — two anchors, one CRL, three proxies                                    #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """One hashed CA directory holding two CAs, one CRL directory holding one
    CRL, and the three proxies that cross them.

    Two anchors, not one: ``try`` and ``require`` differ on exactly one input —
    a chain whose issuer publishes no CRL — so a single-CA store could not tell
    them apart at all.

    The CRL lives in its OWN directory rather than beside the CA.  ``brix_crl``
    counts what it loads and that count is half the ``try`` predicate
    (store_policy_store.c:221), so pointing it at a directory that also holds
    certificates would make the count an accident of directory contents.

    xrdgsiproxy is a hard requirement, not a skip: the row is about what a
    stock GSI client's PROXY chain does to a store, and a proxy minted any
    other way would not be that.
    """
    assert shutil.which("xrdgsiproxy"), \
        "xrdgsiproxy is required to mint the proxy chains this row is about"
    base = tmp_path_factory.mktemp("a15ucrlmode")

    ca_dir = base / "ca"
    crl_dir = base / "crls"
    ca_dir.mkdir()
    crl_dir.mkdir()

    crl_ca = make_ca("/O=XrdTest/CN=audit15u-crl-CA")
    bare_ca = make_ca("/O=XrdTest/CN=audit15u-nocrl-CA")
    host = make_eec(crl_ca, f"/O=XrdTest/CN={CONNECT_HOST}")
    good = make_eec(crl_ca, "/O=XrdTest/CN=audit15u-good")
    revoked = make_eec(crl_ca, "/O=XrdTest/CN=audit15u-revoked")
    bare = make_eec(bare_ca, "/O=XrdTest/CN=audit15u-nocrl")

    # _place_ca_in_dir, not write_hashed_ca_dir: the latter writes a fixed
    # ca.pem and two anchors would overwrite each other.  clauses/crl.py places
    # its CAs the same way.
    x509forge._place_ca_in_dir(ca_dir, crl_ca, name="crlca")
    x509forge._place_ca_in_dir(ca_dir, bare_ca, name="nocrlca")
    ca_dir.chmod(0o755)             # XrdCl refuses a group-writable CA dir
    (crl_dir / "crlca.r0").write_bytes(make_crl(crl_ca, revoked=[revoked]))

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

    return {"ca": str(ca_dir), "crls": str(crl_dir),
            "cert": host_cert, "key": host_key,
            "good": _proxy(good, "good"),
            "revoked": _proxy(revoked, "revoked"),
            "bare": _proxy(bare, "bare")}


@pytest.fixture
def crlmode(lifecycle, tmp_path, pki):
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)

    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15u_crlmode.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"], "CRLDIR": pki["crls"]},
        reason="audit-15u brix_crl_mode at value granularity"))


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
# §A — the three tokens, against the credential each one is about              #
# --------------------------------------------------------------------------- #

class TestTheTokenDecidesWhetherRevocationIsEnforced:

    def test_off_accepts_a_revoked_credential(self, crlmode, pki):
        """The security-negative, and the reason the token has to be tested by
        value.  The CRL naming this certificate is loaded — §D pins that from
        the log — and `off` sets no CRL flag at all, so the store never looks.
        A site that writes `off` to work around a stale CRL feed is running
        with revocation switched off, not degraded."""
        ok, result = _accepted(crlmode, OFF, pki, "revoked")
        assert ok, ("brix_crl_mode off refused a revoked credential; either "
                    "the token now enforces revocation (update this test) or "
                    "the chain is broken for an unrelated reason\n"
                    f"{result.stderr}")

    def test_try_rejects_a_revoked_credential(self, crlmode, pki):
        """crl_count is 1, so `try` arms CRL_CHECK|CRL_CHECK_ALL and the
        revoked serial is found.  The verify callback downgrades only
        UNABLE_TO_GET_CRL; CERT_REVOKED is not a tolerated verdict."""
        ok, result = _accepted(crlmode, TRY, pki, "revoked")
        assert not ok, \
            f"brix_crl_mode try accepted a revoked credential\n{result.stdout}"

    def test_require_rejects_a_revoked_credential(self, crlmode, pki):
        ok, result = _accepted(crlmode, REQUIRE, pki, "revoked")
        assert not ok, ("brix_crl_mode require accepted a revoked "
                        f"credential\n{result.stdout}")


class TestTheTokenDecidesWhatAMissingCrlMeans:
    """The one cell where `try` and `require` disagree.  Both credentials in
    this class are perfectly good certificates; the only thing wrong with the
    chain is that its CA publishes no CRL."""

    def test_try_accepts_an_issuer_that_publishes_no_crl(self, crlmode, pki):
        """`try` installs brix_crl_try_verify_cb, which turns
        X509_V_ERR_UNABLE_TO_GET_CRL into success.  This is what makes `try`
        deployable against a mixed IGTF distribution where not every anchor
        ships a CRL."""
        ok, result = _accepted(crlmode, TRY, pki, "bare")
        assert ok, ("brix_crl_mode try refused a good credential whose CA "
                    f"has no CRL\n{result.stderr}\n{_errlog(crlmode)[-2000:]}")

    def test_require_rejects_an_issuer_that_publishes_no_crl(self, crlmode,
                                                             pki):
        """The same credential, the same store, one token apart.  `require`
        sets no verify callback, so OpenSSL's UNABLE_TO_GET_CRL stands and the
        login fails closed — the WLCG/IGTF posture, and the entire difference
        between the two strict tokens."""
        ok, result = _accepted(crlmode, REQUIRE, pki, "bare")
        assert not ok, ("brix_crl_mode require accepted a credential whose "
                        f"issuer publishes no CRL\n{result.stdout}")

    def test_the_same_credential_is_refused_only_by_require(self, crlmode,
                                                            pki):
        """Stated as one assertion so the pair cannot silently become the same
        answer: three planes see one credential, and exactly one refuses it."""
        verdicts = {plane: _accepted(crlmode, plane, pki, "bare")[0]
                    for plane in (OFF, TRY, REQUIRE)}
        assert verdicts == {OFF: True, TRY: True, REQUIRE: False}, verdicts


class TestEveryRejectionIsAboutRevocation:

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_every_plane_accepts_the_unrevoked_credential(self, crlmode, pki,
                                                          plane):
        """The attribution control for the whole file.  The good proxy chains
        to the CA whose CRL IS loaded and is not named on it, so it must be
        accepted everywhere.  Without this row a `require` that refused every
        login — a plausible failure, since CRL_CHECK_ALL walks the whole chain
        including the proxy's own issuer — would read as strictness working."""
        ok, result = _accepted(crlmode, plane, pki, "good")
        assert ok, (f"{plane}: a good credential was refused\n{result.stderr}"
                    f"\n{_errlog(crlmode)[-2000:]}")


# --------------------------------------------------------------------------- #
# §B — the token an unconfigured deployment runs                               #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """server_conf_merge_security.c:126 merges the unset field to
    BRIX_CRL_MODE_TRY.  That is the token most deployments run, and until this
    class existed nothing asserted it from outside the C."""

    def test_the_absent_directive_enforces_revocation(self, crlmode, pki):
        ok, result = _accepted(crlmode, DEFAULT, pki, "revoked")
        assert not ok, ("with brix_crl_mode absent a revoked credential was "
                        f"accepted — the default is not try\n{result.stdout}")

    def test_the_absent_directive_tolerates_a_missing_crl(self, crlmode, pki):
        """The half that distinguishes the default from `require`: had the
        default been the strict token, this good credential would be refused."""
        ok, result = _accepted(crlmode, DEFAULT, pki, "bare")
        assert ok, ("with brix_crl_mode absent a credential whose CA has no "
                    f"CRL was refused — the default is require, not try\n"
                    f"{result.stderr}")

    def test_the_absent_plane_answers_exactly_as_the_try_plane(self, crlmode,
                                                               pki):
        """Both directions at once, over all three credentials, so a future
        change to the default has to break this test rather than drift past
        the two above."""
        for credential in ("good", "revoked", "bare"):
            assert (_accepted(crlmode, DEFAULT, pki, credential)[0]
                    == _accepted(crlmode, TRY, pki, credential)[0]), \
                f"default and try disagree on the {credential} credential"


# --------------------------------------------------------------------------- #
# §C — the half of `try` that is not the token                                 #
# --------------------------------------------------------------------------- #

class TestTryNeedsSomethingToTry:
    """`try` arms the store only when at least one CRL was loaded
    (store_policy_store.c:221).  The token is therefore not sufficient to
    describe the behaviour — a fact invisible to any test that reads the
    config for directive names."""

    def test_try_without_a_crl_source_accepts_a_revoked_credential(
            self, crlmode, pki):
        """Same token, same CA directory, no brix_crl: crl_count is 0, the
        flags are never set, and the plane behaves exactly like `off`.  This
        is the configuration a site reaches by removing a broken CRL feed and
        leaving the mode alone."""
        ok, result = _accepted(crlmode, DISARMED, pki, "revoked")
        assert ok, ("brix_crl_mode try enforced revocation with no brix_crl "
                    "configured — the crl_count predicate is gone (update "
                    f"this test)\n{result.stderr}")

    def test_the_same_token_on_the_same_credential_disagrees_with_itself(
            self, crlmode, pki):
        """Two listeners, one token, opposite verdicts.  The variable is
        brix_crl, so `brix_crl_mode try` on its own says nothing about whether
        revocation is enforced."""
        assert _accepted(crlmode, TRY, pki, "revoked")[0] is False
        assert _accepted(crlmode, DISARMED, pki, "revoked")[0] is True


# --------------------------------------------------------------------------- #
# §D — attribution: the store really is per-mode, and the CRL really loaded    #
# --------------------------------------------------------------------------- #

class TestTheStoreBehindTheTokens:

    def test_the_crl_was_loaded_at_startup(self, crlmode):
        """Without this line every rejection above could be a broken chain
        rather than a revocation check.  brix_rebuild_gsi_store logs the count
        it got from brix_crl (auth/gsi/config.c:47-51)."""
        log = _errlog(crlmode)
        assert 'brix: loaded 1 CRL(s) from' in log, \
            f"the CRL directory was not loaded\n{log[-3000:]}"

    def test_five_listeners_over_one_ca_and_one_crl_still_disagree(
            self, crlmode, pki):
        """The config-parse store cache (pki_build.c:262-283) memoises on a key
        that includes crl_mode.  Were it keyed on the paths alone — the obvious
        way to write it, and the four planes below name identical paths — all
        five listeners would share one store and this file's whole table would
        collapse to a single row."""
        verdicts = {plane: _accepted(crlmode, plane, pki, "revoked")[0]
                    for plane in ALL_PLANES}
        assert verdicts == {OFF: True, TRY: False, REQUIRE: False,
                            DEFAULT: False, DISARMED: True}, verdicts


# --------------------------------------------------------------------------- #
# §E — the startup warning (DEFECT CANDIDATE #52)                              #
# --------------------------------------------------------------------------- #

def _knobs(pki, *lines):
    """A minimal GSI server block plus whatever the case adds."""
    body = ["brix_auth gsi;",
            f"brix_certificate     {pki['cert']};",
            f"brix_certificate_key {pki['key']};",
            f"brix_trusted_ca      {pki['ca']};"]
    body.extend(lines)
    return "".join(f"        {line}\n" for line in body)


def _parse(tmp_path, knobs="", stream_extra=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15u_crlparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheStartupWarning:
    """Two configurations accept revoked certificates; one of them says so."""

    def test_the_warning_fires_when_no_crl_source_is_configured(self, tmp_path,
                                                                pki):
        """The positive control.  This is the mistake the warning was written
        for, and it still works."""
        rc, out = _parse(tmp_path, _knobs(pki))
        assert rc == 0, out
        assert _WARNING.decode() in out, \
            f"a gsi server with no brix_crl started silently\n{out}"

    def test_the_startup_warning_is_keyed_on_the_source_not_on_enforcement(
            self, tmp_path, pki):
        """DEFECT CANDIDATE #52.  This server loads every CRL it is given and
        then ignores all of them — the effect on a revoked certificate is
        identical to the case above, proven by
        test_off_accepts_a_revoked_credential — and it starts in silence,
        because postconfiguration.c:89 tests only ``xcf->crl.len == 0``.

        Pinning the defect, not endorsing it: when the condition learns about
        crl_mode this assertion should be inverted."""
        rc, out = _parse(tmp_path, _knobs(pki, f"brix_crl {pki['crls']};",
                                          "brix_crl_mode off;"))
        assert rc == 0, out
        assert _WARNING.decode() not in out, (
            "the no-CRL warning now fires for brix_crl_mode off — defect "
            f"candidate #52 is fixed; invert this test\n{out}")

    def test_an_enforcing_server_is_silent(self, tmp_path, pki):
        """The third corner: a CRL source and a token that reads it.  Silence
        here is correct, and it is what makes the silence in the case above
        indistinguishable to an operator."""
        rc, out = _parse(tmp_path, _knobs(pki, f"brix_crl {pki['crls']};",
                                          "brix_crl_mode require;"))
        assert rc == 0, out
        assert _WARNING.decode() not in out, out


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                          #
# --------------------------------------------------------------------------- #

class TestTheParseTier:
    """Every token in brix_crl_modes[] is accepted; nothing else is."""

    @pytest.mark.parametrize("token", ["off", "try", "require"])
    def test_each_token_in_the_table_is_accepted(self, tmp_path, token):
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n"
                         f"        brix_crl_mode {token};\n")
        assert rc == 0, f"brix_crl_mode {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["REQUIRE", "Off", "tRy"])
    def test_the_token_is_matched_case_insensitively(self, tmp_path, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the three
        tokens are three case-folded names and not three literals.  Written
        down because an operator's `Require` parses and a future hand-rolled
        setter that used ngx_strcmp would silently reject it."""
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n"
                         f"        brix_crl_mode {token};\n")
        assert rc == 0, f"brix_crl_mode {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["on", "1", "strict", "try,require"])
    def test_a_value_outside_the_table_is_refused(self, tmp_path, token):
        """`on` and `strict` are the two words an operator reaches for that
        are not in the table, and `1` is the raw value behind BRIX_CRL_MODE_TRY
        — none of them may parse into a silent default."""
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n"
                         f"        brix_crl_mode {token};\n")
        assert rc != 0, f"brix_crl_mode {token} parsed:\n{out}"
        assert "invalid value" in out, out

    @pytest.mark.parametrize("line", ["brix_crl_mode;",
                                      "brix_crl_mode try require;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n        {line}\n")
        assert rc != 0, f"{line} parsed:\n{out}"
        assert "invalid number of arguments" in out, out

    def test_the_directive_is_refused_outside_a_server(self, tmp_path):
        """NGX_STREAM_SRV_CONF only.  A stream-level line is a parse error, not
        a default inherited by every server — which matters because the merge
        default IS `try` and an operator who wrote a stream-wide `off` might
        otherwise believe it took."""
        rc, out = _parse(tmp_path, "        brix_auth none;\n",
                         stream_extra="    brix_crl_mode off;\n")
        assert rc != 0, f"brix_crl_mode was accepted in stream {{}}:\n{out}"
        assert "directive is not allowed here" in out, out
