"""brix_signing_policy at VALUE granularity — audit §Method, 15th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 36 ``ngx_conf_enum_t`` tables in
``src/`` turned 93 pairs into 48 written and 45 never written.
``brix_signing_policy`` contributes two of those 45: ``off`` and ``on`` appear
in no config the suite renders, on any plane.  ``require`` appears exactly once
— inside an ``nginx -t`` in test_audit15_zero_directive_parse.py — so the
directive has never decided a login.

The name looks covered because its WebDAV twin is.
``test_wlcg_conformance_signing_policy.py`` drives ``brix_webdav_signing_policy``
over davs:// with bare End-Entity credentials.  A GSI login on the ROOT/stream
plane presents a PROXY chain, and the enforcement walk skips every EXFLAG_PROXY
link (gsi_verify.c:85) — so the twin exercises the half of the rule that the
proxy exemption removes here, and neither plane substitutes for the other.

WHAT THE VALUE SELECTS
----------------------
The token reaches the store as ``sp_mode`` (auth/gsi/config.c:41) and is read
back on every login by ``brix_sp_table_check`` (store_policy.c:264-297):

    off      -> ``brix_gsi_enforce_signing_policy`` returns OK before it looks
                at anything (gsi_verify.c:71).  Policy files may be compiled;
                nothing consults them.
    on       -> for each non-proxy link, if a policy file exists for the issuer
                the subject DN must match its cond_subjects globs.  An issuer
                with NO policy file signs whatever it likes.
    require  -> the same, except that an issuer with no policy file may sign
                NOTHING (store_policy.c:284) — and a bundle-file trust anchor is
                refused outright at config time, because policy files are found
                by hash beside a CA directory.

So ``on`` and ``require`` differ on exactly one input — an issuer that publishes
no policy — and ``off`` and ``on`` differ on exactly one other: a subject
outside the namespace its CA declared.

WHAT THE TABLE ESTABLISHES
--------------------------
Four listeners on ONE instance share ONE hashed CA directory holding THREE
anchors, crossed by four proxies.  Measured:

    plane                in-namespace  out-of-namespace  CA w/o policy  exact-DN
    off                  accept        ACCEPT            accept         accept
    on                   accept        reject            accept         accept
    require              accept        reject            REJECT         accept
    (directive absent)   accept        reject            accept         accept

The last row pins the merge default at ``on``
(server_conf_merge_security.c:124).  The ``off`` x out-of-namespace cell is the
security negative: a CA that was told to sign only ``/O=.../OU=inside/*`` signs
an ``/OU=outside`` subject and the login succeeds.  The ``require`` x
no-policy-file cell is the only one that separates the two enforcing tokens.

THE PROXY EXEMPTION
-------------------
The ``exact-DN`` column exists to make the exemption observable rather than
assumed.  Its CA's policy names ONE literal subject with no trailing wildcard;
the credential presented is a proxy whose DN is that subject plus ``/CN=<serial>``
and therefore does NOT match the glob.  It is accepted under ``on`` AND under
``require``.  Had the walk not skipped proxy links, ``require`` would refuse
every proxy login on earth — the proxy's issuer is an EEC, which never has a
policy file of its own.

THE FINDING — DEFECT CANDIDATE #53
----------------------------------
``brix_signing_policy require`` with a bundle-FILE trust anchor is fatal
(store_policy_store.c:232) — correctly, since policy files are looked up beside
a hashed directory — but the refusal is reported at ``[warn]``:

    nginx: [warn] brix_pki: signing_policy: "require" needs a hashed CA
    directory, not a bundle file
    nginx: configuration file .../nginx.conf test failed

There is no ``[emerg]`` line and no ``file:line``, unlike every other brix
config refusal.  ``nginx -t`` therefore reports a failure whose only
explanation is a warning that reads like advice, and an operator grepping for
``emerg`` — the level nginx itself uses for fatal config errors — finds
nothing.  ``test_the_refusal_is_reported_without_an_emerg_line`` pins today's
shape; when the log level is raised that test should be updated, not deleted.
"""

import os
import shutil
import subprocess

import pytest

import x509forge
from x509forge import make_ca, make_eec
from x509forge_part2 import signing_policy_text
from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN
from _test_gsi_handshake_helpers import _mint_proxy

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15v-sigpolicy")]

NAME = "lc-audit15v-sigpolicy"
CONNECT_HOST = "localhost"  # net-literal-allow: GSI service identity

SEED = b"signing policy seed\n"
SEED_PATH = "/seed.txt"

SYS_XRDFS = shutil.which("xrdfs")

# The four listeners, by the template placeholder that carries each one.  PORT
# is the instance's own port; the rest arrive as extra_ports.
OFF, ON, REQUIRE, DEFAULT = "PORT", "ON_PORT", "REQ_PORT", "DEF_PORT"
ALL_PLANES = (OFF, ON, REQUIRE, DEFAULT)

# The three anchors.  Only the first two DNs are named in a policy file.
POLICY_CA_DN = "/O=XrdTest/OU=policy/CN=audit15v-policy-CA"
BARE_CA_DN = "/O=XrdTest/OU=nopolicy/CN=audit15v-bare-CA"
EXACT_CA_DN = "/O=XrdTest/OU=exact/CN=audit15v-exact-CA"

# The four subjects.  INSIDE_GLOB is what POLICY_CA_DN declared it would sign.
INSIDE_GLOB = "/O=XrdTest/OU=policy/OU=inside/*"
INSIDER_DN = "/O=XrdTest/OU=policy/OU=inside/CN=audit15v-insider"
OUTSIDER_DN = "/O=XrdTest/OU=policy/OU=outside/CN=audit15v-outsider"
STRANGER_DN = "/O=XrdTest/OU=nopolicy/CN=audit15v-stranger"
EXACT_DN = "/O=XrdTest/OU=exact/CN=audit15v-exact"

_REFUSAL = "may not sign subject"


# --------------------------------------------------------------------------- #
# PKI — three anchors, four proxies                                            #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """One hashed CA directory holding three CAs and the proxies that cross it.

    Three anchors, because the three tokens are only distinguishable across
    issuers that differ in what they PUBLISH: a CA with a wildcard policy (it
    separates `off` from `on`), a CA with no policy file at all (the only input
    that separates `on` from `require`), and a CA whose policy names one exact
    subject DN (which makes the proxy exemption observable).

    The host certificate hangs off the policy CA with an in-namespace DN so that
    nothing about the SERVER's own chain varies between the planes.

    xrdgsiproxy is a hard requirement, not a skip: the exemption this file
    measures is a property of a real RFC 3820 proxy, and a chain minted any
    other way would not be one.
    """
    assert shutil.which("xrdgsiproxy"), \
        "xrdgsiproxy is required to mint the proxy chains this row is about"
    base = tmp_path_factory.mktemp("a15vsigpol")

    ca_dir = base / "ca"
    ca_dir.mkdir()

    policy_ca = make_ca(POLICY_CA_DN)
    bare_ca = make_ca(BARE_CA_DN)
    exact_ca = make_ca(EXACT_CA_DN)

    host = make_eec(policy_ca, f"/O=XrdTest/OU=policy/OU=inside/CN={CONNECT_HOST}")
    insider = make_eec(policy_ca, INSIDER_DN)
    outsider = make_eec(policy_ca, OUTSIDER_DN)
    stranger = make_eec(bare_ca, STRANGER_DN)
    exact = make_eec(exact_ca, EXACT_DN)

    # _place_ca_in_dir, not write_hashed_ca_dir: the latter writes a fixed
    # ca.pem plus a fixed signing-policy, so three anchors would overwrite each
    # other.  clauses/crl.py places its CAs the same way.
    x509forge._place_ca_in_dir(
        ca_dir, policy_ca, name="polca",
        policy_text=signing_policy_text(POLICY_CA_DN, [INSIDE_GLOB]))
    x509forge._place_ca_in_dir(ca_dir, bare_ca, name="bareca")
    x509forge._place_ca_in_dir(
        ca_dir, exact_ca, name="exactca",
        policy_text=signing_policy_text(EXACT_CA_DN, [EXACT_DN]))
    ca_dir.chmod(0o755)             # XrdCl refuses a group-writable CA dir

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

    bundle = base / "ca-bundle.pem"
    bundle.write_bytes(policy_ca.pem)

    return {"ca": str(ca_dir), "bundle": str(bundle),
            "cert": host_cert, "key": host_key,
            "insider": _proxy(insider, "insider"),
            "outsider": _proxy(outsider, "outsider"),
            "stranger": _proxy(stranger, "stranger"),
            "exact": _proxy(exact, "exact")}


@pytest.fixture
def sigpolicy(lifecycle, tmp_path, pki):
    if SYS_XRDFS is None:
        pytest.skip("stock xrdfs not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / SEED_PATH.lstrip("/")).write_bytes(SEED)

    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15v_sigpolicy.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"]},
        reason="audit-15v brix_signing_policy at value granularity"))


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
# §A — the token decides whether the namespace rule applies at all             #
# --------------------------------------------------------------------------- #

class TestTheTokenDecidesWhetherTheNamespaceRuleApplies:
    """All three planes here are handed the same credential: a certificate the
    policy CA had no right to sign.  PKIX validation passes on all three — the
    signature is genuine and the anchor is trusted — so the only thing that can
    refuse it is the namespace rule."""

    def test_off_accepts_a_subject_outside_the_declared_namespace(
            self, sigpolicy, pki):
        """The security-negative, and the reason the token has to be tested by
        value.  The policy file IS compiled — §D pins that the same store
        enforces it one listener away — and `off` returns OK before reading it
        (gsi_verify.c:71).  A site that writes `off` to get past one awkward CA
        has switched the WLCG namespace rule off for every CA it trusts."""
        ok, result = _accepted(sigpolicy, OFF, pki, "outsider")
        assert ok, ("brix_signing_policy off refused an out-of-namespace "
                    "subject; either the token now enforces the rule (update "
                    f"this test) or the chain is broken for another reason\n"
                    f"{result.stderr}\n{_errlog(sigpolicy)[-2000:]}")

    def test_on_rejects_a_subject_outside_the_declared_namespace(
            self, sigpolicy, pki):
        """The CA declared ``cond_subjects "/O=XrdTest/OU=policy/OU=inside/*"``
        and signed an ``/OU=outside`` subject.  brix_sp_subject_allowed says no
        and the login fails."""
        ok, result = _accepted(sigpolicy, ON, pki, "outsider")
        assert not ok, ("brix_signing_policy on accepted a subject outside the "
                        f"namespace its CA declared\n{result.stdout}")

    def test_require_rejects_a_subject_outside_the_declared_namespace(
            self, sigpolicy, pki):
        """`require` is strictly stronger than `on`; it must refuse everything
        `on` refuses, which is what makes §B's single disagreeing cell the
        whole difference between them."""
        ok, result = _accepted(sigpolicy, REQUIRE, pki, "outsider")
        assert not ok, ("brix_signing_policy require accepted a subject "
                        f"outside the namespace its CA declared\n"
                        f"{result.stdout}")


# --------------------------------------------------------------------------- #
# §B — the token decides what a MISSING policy file means                      #
# --------------------------------------------------------------------------- #

class TestTheTokenDecidesWhatAMissingPolicyFileMeans:
    """The one cell where `on` and `require` disagree.  The credential is a
    perfectly good certificate from a trusted CA; the only thing wrong with the
    chain is that its issuer shipped no signing_policy file."""

    def test_on_accepts_a_ca_that_publishes_no_policy(self, sigpolicy, pki):
        """store_policy.c:284 returns "allowed" when no entry is found and the
        mode is not require.  This is what makes `on` deployable against a real
        IGTF distribution, where policy files are conventional but not
        universal."""
        ok, result = _accepted(sigpolicy, ON, pki, "stranger")
        assert ok, ("brix_signing_policy on refused a credential whose CA has "
                    f"no policy file\n{result.stderr}\n"
                    f"{_errlog(sigpolicy)[-2000:]}")

    def test_require_rejects_a_ca_that_publishes_no_policy(self, sigpolicy,
                                                           pki):
        """The same credential, the same store, one token apart.  `require`
        means every anchor must have positively declared a namespace before it
        may sign anything — the strict WLCG posture, and the entire difference
        between the two enforcing tokens."""
        ok, result = _accepted(sigpolicy, REQUIRE, pki, "stranger")
        assert not ok, ("brix_signing_policy require accepted a credential "
                        f"from a CA with no policy file\n{result.stdout}")

    def test_the_same_credential_is_refused_only_by_require(self, sigpolicy,
                                                             pki):
        """Stated as one assertion so the pair cannot silently become the same
        answer: three planes see one credential, and exactly one refuses it."""
        verdicts = {plane: _accepted(sigpolicy, plane, pki, "stranger")[0]
                    for plane in (OFF, ON, REQUIRE)}
        assert verdicts == {OFF: True, ON: True, REQUIRE: False}, verdicts


class TestEveryRejectionIsAboutTheNamespace:

    @pytest.mark.parametrize("plane", ALL_PLANES)
    def test_every_plane_accepts_the_in_namespace_credential(self, sigpolicy,
                                                              pki, plane):
        """The attribution control for the whole file.  The insider proxy chains
        to the policy CA and its EEC DN matches the declared glob, so it must be
        accepted everywhere.  Without this row a `require` that refused every
        login — the plausible failure, since a proxy's issuer is an EEC and no
        EEC has a policy file — would read as strictness working."""
        ok, result = _accepted(sigpolicy, plane, pki, "insider")
        assert ok, (f"{plane}: an in-namespace credential was refused\n"
                    f"{result.stderr}\n{_errlog(sigpolicy)[-2000:]}")


# --------------------------------------------------------------------------- #
# §C — the proxy links are exempt from the walk                                #
# --------------------------------------------------------------------------- #

class TestTheProxyLinkIsExempt:
    """gsi_verify.c:85 skips every EXFLAG_PROXY subject, so the rule is applied
    to the EEC<-CA link and to nothing else.  The exact-DN anchor makes that
    visible: its policy names one literal subject, and the credential presented
    is a proxy whose DN is that subject plus /CN=<serial>."""

    def test_on_accepts_a_proxy_whose_own_dn_is_outside_the_glob(
            self, sigpolicy, pki):
        """If the glob were matched against the LEAF, this login would fail:
        ``/O=XrdTest/OU=exact/CN=audit15v-exact/CN=<serial>`` is not
        ``/O=XrdTest/OU=exact/CN=audit15v-exact`` and the pattern has no
        trailing wildcard.  It is the EEC that is matched."""
        ok, result = _accepted(sigpolicy, ON, pki, "exact")
        assert ok, ("brix_signing_policy on refused a proxy whose EEC matches "
                    "an exact-DN policy — the walk is matching the proxy leaf "
                    f"instead of the EEC\n{result.stderr}\n"
                    f"{_errlog(sigpolicy)[-2000:]}")

    def test_require_accepts_the_same_proxy(self, sigpolicy, pki):
        """The sharper half.  Under `require` an issuer with no policy file may
        sign nothing — and a proxy's issuer is an EEC, which never has one.  A
        walk that did not skip proxy links would therefore refuse EVERY proxy
        login under `require`, i.e. the strict token would be unusable on the
        GSI plane."""
        ok, result = _accepted(sigpolicy, REQUIRE, pki, "exact")
        assert ok, ("brix_signing_policy require refused a proxy whose EEC has "
                    "a granting policy — the proxy link is no longer exempt\n"
                    f"{result.stderr}\n{_errlog(sigpolicy)[-2000:]}")

    def test_the_login_is_recorded_under_the_proxy_dn(self, sigpolicy, pki):
        """The exemption is not the identity being relaxed: the session is still
        the proxy's, and the DN the server logs is the proxy DN the policy would
        have rejected.  Written down because "the EEC is what was checked" and
        "the EEC is who you are" are different claims — the second is false."""
        ok, _result = _accepted(sigpolicy, REQUIRE, pki, "exact")
        assert ok
        log = _errlog(sigpolicy)
        assert f'GSI auth OK dn="{EXACT_DN}/CN=' in log, \
            f"the accepted DN is not the proxy DN\n{log[-3000:]}"


# --------------------------------------------------------------------------- #
# §D — the token an unconfigured deployment runs, and the store behind it      #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """server_conf_merge_security.c:124 merges the unset field to
    BRIX_SP_MODE_ON.  That is the token most deployments run, and until this
    class existed nothing asserted it from outside the C."""

    def test_the_absent_directive_enforces_the_namespace_rule(self, sigpolicy,
                                                               pki):
        ok, result = _accepted(sigpolicy, DEFAULT, pki, "outsider")
        assert not ok, ("with brix_signing_policy absent an out-of-namespace "
                        f"subject was accepted — the default is off\n"
                        f"{result.stdout}")

    def test_the_absent_directive_tolerates_a_ca_without_a_policy(
            self, sigpolicy, pki):
        """The half that distinguishes the default from `require`: had the
        default been the strict token, every CA in a stock IGTF distribution
        without a policy file would stop working on upgrade."""
        ok, result = _accepted(sigpolicy, DEFAULT, pki, "stranger")
        assert ok, ("with brix_signing_policy absent a credential from a CA "
                    "with no policy file was refused — the default is require, "
                    f"not on\n{result.stderr}")

    def test_the_absent_plane_answers_exactly_as_the_on_plane(self, sigpolicy,
                                                              pki):
        """Both directions at once, over all four credentials, so a future
        change to the default has to break this test rather than drift past the
        two above."""
        for credential in ("insider", "outsider", "stranger", "exact"):
            assert (_accepted(sigpolicy, DEFAULT, pki, credential)[0]
                    == _accepted(sigpolicy, ON, pki, credential)[0]), \
                f"default and on disagree on the {credential} credential"


class TestTheStoreBehindTheTokens:

    def test_four_listeners_over_one_ca_directory_still_disagree(
            self, sigpolicy, pki):
        """The config-parse store cache (pki_build.c) memoises on a key that
        includes sp_mode.  Were it keyed on the paths alone — the obvious way to
        write it, and all four planes name an identical brix_trusted_ca — every
        listener would share one store and this file's whole table would
        collapse to a single row."""
        verdicts = {plane: _accepted(sigpolicy, plane, pki, "stranger")[0]
                    for plane in ALL_PLANES}
        assert verdicts == {OFF: True, ON: True, REQUIRE: False,
                            DEFAULT: True}, verdicts

    def test_exactly_one_store_is_reused_across_the_four_listeners(
            self, sigpolicy):
        """The other direction, read off the startup log.  Four listeners, three
        distinct sp_modes (off, on, require, and the absent directive which
        merges to on), so exactly ONE of the four may hit the cache — and the
        one that does is the proof that the ABSENT directive and `on` produce
        the same key.  The no-CRL note is emitted once per gsi server, so it
        counts config-parse passes and makes the ratio independent of how many
        times the harness parsed the file."""
        log = _errlog(sigpolicy)
        reused = log.count("reusing the CA/CRL store already built")
        passes = log.count("no CRL is configured") // len(ALL_PLANES)
        assert passes >= 1, f"the config was never parsed?\n{log[-3000:]}"
        assert reused == passes, (
            f"{reused} store reuses over {passes} config-parse pass(es) of "
            f"{len(ALL_PLANES)} listeners — the store cache key no longer "
            f"separates the signing_policy modes\n{log[-3000:]}")

    def test_the_refusal_names_the_ca_and_the_subject(self, sigpolicy, pki):
        """Attribution for every rejection above: the refusals are the namespace
        rule talking, not a broken chain.  Both causes share one message, so an
        operator who set `require` and hit a CA with no policy file is told
        "namespace violation or missing policy" and has to guess which."""
        assert not _accepted(sigpolicy, REQUIRE, pki, "stranger")[0]
        log = _errlog(sigpolicy)
        assert f'CA "{BARE_CA_DN}" may not sign subject "{STRANGER_DN}"' in log, \
            f"the refusal did not come from the signing_policy walk\n{log[-3000:]}"
        assert _REFUSAL in log


# --------------------------------------------------------------------------- #
# §E — the parse tier, and the config-time refusal (DEFECT CANDIDATE #53)      #
# --------------------------------------------------------------------------- #

def _knobs(pki, ca, *lines):
    """A minimal GSI server block over one trust anchor, plus what a case adds."""
    body = ["brix_auth gsi;",
            f"brix_certificate     {pki['cert']};",
            f"brix_certificate_key {pki['key']};",
            f"brix_trusted_ca      {ca};"]
    body.extend(lines)
    return "".join(f"        {line}\n" for line in body)


def _parse(tmp_path, knobs="", stream_extra=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15v_sigparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestRequireNeedsAHashedDirectory:
    """`require` is the one token whose meaning depends on how the trust anchor
    was NAMED.  Policy files are found beside a hashed CA directory, so a
    bundle file can never satisfy it — and the code says so at config time
    rather than failing every login at run time."""

    def test_a_hashed_ca_directory_is_accepted(self, tmp_path, pki):
        """The positive control: same token, same certificates, anchor named as
        a directory."""
        rc, out = _parse(tmp_path,
                         _knobs(pki, pki["ca"], "brix_signing_policy require;"))
        assert rc == 0, out

    def test_a_bundle_file_is_refused(self, tmp_path, pki):
        """store_policy_store.c:232.  Without this the server would start and
        then refuse every login, because a store with no policy table under
        `require` allows nothing."""
        rc, out = _parse(tmp_path,
                         _knobs(pki, pki["bundle"],
                                "brix_signing_policy require;"))
        assert rc != 0, f"require accepted a bundle-file trust anchor:\n{out}"
        assert 'needs a hashed CA directory' in out, out

    @pytest.mark.parametrize("token", ["off", "on"])
    def test_the_same_bundle_file_is_fine_for_the_other_tokens(self, tmp_path,
                                                                pki, token):
        """The negative control that keeps the test above about `require`: the
        bundle file itself is a valid trust anchor, and only the strict token
        rejects it."""
        rc, out = _parse(tmp_path,
                         _knobs(pki, pki["bundle"],
                                f"brix_signing_policy {token};"))
        assert rc == 0, f"a bundle-file anchor was refused under {token}:\n{out}"

    def test_the_refusal_is_reported_without_an_emerg_line(self, tmp_path,
                                                            pki):
        """DEFECT CANDIDATE #53.  The condition is fatal — the config test fails
        — but it is logged at [warn] and carries no file:line, so `nginx -t`
        prints "test failed" with no [emerg] anywhere in its output.  Pinning
        the defect, not endorsing it: when the level is raised, this assertion
        is what tells you to update the expectation."""
        rc, out = _parse(tmp_path,
                         _knobs(pki, pki["bundle"],
                                "brix_signing_policy require;"))
        assert rc != 0, out
        assert "[warn]" in out, out
        assert "[emerg]" not in out, (
            "the bundle-file refusal now emits [emerg] — defect candidate #53 "
            f"is fixed; update this test\n{out}")

    def test_the_token_is_inert_without_gsi(self, tmp_path):
        """No brix_auth gsi, so no store is ever built and the strict token
        cannot refuse anything.  Written down because it is the shape of a real
        misconfiguration: `require` on a server that never verifies a
        certificate parses clean and enforces nothing."""
        rc, out = _parse(tmp_path, "        brix_auth none;\n"
                                   "        brix_signing_policy require;\n")
        assert rc == 0, out


class TestTheParseTier:
    """Every token in brix_signing_policy_modes[] is accepted; nothing else is."""

    @pytest.mark.parametrize("token", ["off", "on", "require"])
    def test_each_token_in_the_table_is_accepted(self, tmp_path, token):
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n"
                         f"        brix_signing_policy {token};\n")
        assert rc == 0, f"brix_signing_policy {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["OFF", "On", "ReQuIrE"])
    def test_the_token_is_matched_case_insensitively(self, tmp_path, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the three
        tokens are case-folded names and not literals.  Written down because an
        operator's `On` parses today and a hand-rolled setter using ngx_strcmp
        would silently reject it."""
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n"
                         f"        brix_signing_policy {token};\n")
        assert rc == 0, f"brix_signing_policy {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["yes", "1", "strict", "enforce"])
    def test_a_value_outside_the_table_is_refused(self, tmp_path, token):
        """`yes` and `enforce` are the words an operator reaches for that are
        not in the table, `strict` is the WebDAV vocabulary, and `1` is the raw
        value behind BRIX_SP_MODE_ON — none of them may parse into a silent
        default."""
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n"
                         f"        brix_signing_policy {token};\n")
        assert rc != 0, f"brix_signing_policy {token} parsed:\n{out}"
        assert "invalid value" in out, out

    @pytest.mark.parametrize("line", ["brix_signing_policy;",
                                      "brix_signing_policy on require;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse(tmp_path,
                         f"        brix_auth none;\n        {line}\n")
        assert rc != 0, f"{line} parsed:\n{out}"
        assert "invalid number of arguments" in out, out

    def test_the_directive_is_refused_outside_a_server(self, tmp_path):
        """NGX_STREAM_SRV_CONF only.  A stream-level line is a parse error, not
        a default inherited by every server — which matters because the merge
        default IS `on` and an operator who wrote a stream-wide `off` might
        otherwise believe it took."""
        rc, out = _parse(tmp_path, "        brix_auth none;\n",
                         stream_extra="    brix_signing_policy off;\n")
        assert rc != 0, f"brix_signing_policy was accepted in stream {{}}:\n{out}"
        assert "directive is not allowed here" in out, out
