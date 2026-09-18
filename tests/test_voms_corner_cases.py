"""
tests/test_voms_corner_cases.py

The corner-case matrix for the native VOMS attribute-certificate engine
(shared/voms/): every AC shape seen in WLCG/OSG — past and future — is either
verified correctly or refused with the right reason.  No server: each case
mints a proxy with utils/voms_proxy_fake.py's test knobs and runs the verdict
harness shared/voms/voms_ac_check.c, asserting its `status:` line and the
per-AC `verdict=` / `carrier=` / `fqan:` / `attr:` lines.

PKI, vomsdir and harness plumbing: tests/_test_voms_corner_helpers.py
(a temporary openssl PKI per module: test CA in certdir as <hash>.0 with its
CRL as <hash>.r0, RSA / EC P-256 / Ed25519 / expired / revoked / rogue VOMS
signers; vomsdir for cms, atlas, dteam and the legacy vo.example.org).

Client-diagnostic mode: with no --certdir the chain check is skipped (the
caller accepts an unverified signer); with no --vomsdir the LSC check is
skipped.  Both are covered so the diagnostic answer stays ok on a proxy the
server would refuse for trust reasons only.

    cd tests && TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=$PWD:$PWD/../brixtest/src \\
        ../.venv/bin/python -m pytest test_voms_corner_cases.py -q -p no:cacheprovider
"""

import base64
import os
import socket
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from split_continuation import reexport as _reexport

# make_pki, make_vomsdir, build_harness, run_check, mint, HARNESS_SRC, Pki, ...
_reexport(globals(), "_test_voms_corner_helpers")

FQAN_CMS = "/cms/Role=NULL/Capability=NULL"
OID_VOMS = x509.ObjectIdentifier("1.3.6.1.4.1.8005.100.100.5")
HOSTNAME = socket.gethostname()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("voms-corner-pki"))
    built = make_pki(root)
    make_vomsdir(built)
    return built


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    if not os.path.isfile(HARNESS_SRC):
        pytest.skip(f"{HARNESS_SRC} is not there yet (the verdict harness)")
    return build_harness(str(tmp_path_factory.mktemp("voms-corner-bin") / "voms_ac_check"))


@pytest.fixture
def out(tmp_path):
    return str(tmp_path / "proxy.pem")


# ---------------------------------------------------------------------------
# the case table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Case:
    """One corner case: how the proxy is minted, how the harness is run, and
    what it must print.  `verdict` defaults to `status` (the single AC's own
    verdict); None skips the per-AC check (decode-level failures print none)."""
    name: str
    status: str
    knobs: tuple = ()
    signer: str = "rsa"
    vo: str = "cms"
    fqan: str = FQAN_CMS
    certdir: bool = True
    vomsdir: bool = True
    skew: int | None = None
    verdict: str | None = "same"
    carrier: str = "0"
    digest: str | None = None
    fqans: tuple | None = None


CASES = [
    Case("baseline", "ok", fqans=(FQAN_CMS,)),
    Case("delegate", "ok", ("-delegate",), carrier="1"),
    Case("legacy_proxy", "ok", ("-legacy-proxy",)),
    Case("holder_utf8", "ok", ("-holder-utf8",)),
    Case("holder_entity_name", "holder", ("-holder-entity-name",)),
    Case("holder_serial_mismatch", "holder", ("-holder-serial", "424242")),
    Case("ac_expired", "expired", ("-ac-hours", "-1")),
    Case("not_before_600_default_skew", "notyet", ("-ac-not-before-offset", "600")),
    Case("not_before_600_skew_900", "ok", ("-ac-not-before-offset", "600"), skew=900),
    Case("sig_sha1", "ok", ("-sig-alg", "sha1"), digest="sha1"),
    Case("sig_sha384", "ok", ("-sig-alg", "sha384"), digest="sha384"),
    Case("sig_sha512", "ok", ("-sig-alg", "sha512"), digest="sha512"),
    Case("sig_pss", "ok", ("-sig-alg", "pss")),
    Case("sig_ecdsa", "ok", signer="ec", vo="atlas", fqan="/atlas/Role=NULL/Capability=NULL"),
    Case("sig_ed25519", "ok", signer="ed25519"),
    Case("sig_md5", "sigalg", ("-sig-alg", "md5")),
    Case("inner_alg_mismatch", "sigalg", ("-inner-alg-mismatch",)),
    Case("no_certs", "nosigner", ("-no-certs",)),
    Case("certs_order_reversed", "ok", ("-certs-order", "reversed")),
    Case("certs_chain_dteam_4line_lsc", "ok", ("-certs-chain",), vo="dteam",
         fqan="/dteam/Role=NULL/Capability=NULL"),
    Case("dteam_4line_lsc_signer_only", "lsc", vo="dteam",
         fqan="/dteam/Role=NULL/Capability=NULL"),
    Case("aki_mismatch", "issuer", ("-aki-mismatch",)),
    Case("rogue_signer", "lsc", signer="rogue"),
    Case("expired_signer", "untrusted", signer="expired"),
    Case("revoked_signer", "untrusted", signer="revoked"),
    Case("no_certdir_good_signer", "ok", certdir=False),
    Case("no_certdir_no_vomsdir_expired_signer", "ok", signer="expired",
         certdir=False, vomsdir=False),
    Case("critical_ext", "extension", ("-critical-ext", "1.2.3.4.5")),
    Case("noncritical_ext", "ok", ("-noncritical-ext", "1.2.3.4.5")),
    Case("no_policy_uri", "ok", ("-no-policy-uri",)),
    Case("uri_noport", "ok", ("-uri-noport",)),
    Case("utf8_fqan", "ok", ("-utf8-fqan",), fqans=(FQAN_CMS,)),
    Case("fqan_bad_dropped", "ok", ("-fqan-bad",), fqans=(FQAN_CMS,)),
    Case("empty_acseq", "decode", ("-empty-acseq",), verdict=None),
    Case("ac_count_40", "decode", ("-ac-count", "40"), verdict=None),
    Case("targets_this_host", "ok", ("-targets", f"other.example,{HOSTNAME}")),
    Case("targets_other_host", "target", ("-targets", "other.example")),
    Case("gen_attr", "ok", ("-gen-attr", "nickname=rob:cms")),
    Case("dotted_vo_hyphen_role_legacy_vomsdir", "ok", vo="vo.example.org",
         fqan="/vo.example.org/Role=data-manager/Capability=NULL",
         fqans=("/vo.example.org/Role=data-manager/Capability=NULL",)),
]


def _minted(pki, out, case: Case) -> str:
    return mint(pki, out, case.signer, case.vo, case.fqan, *case.knobs)


def _checked(harness, pki, proxy: str, case: Case):
    return run_check(harness, proxy, certdir=pki.certdir if case.certdir else None,
                     vomsdir=pki.vomsdir if case.vomsdir else None, skew=case.skew)


def _assert_ac(ac: dict, case: Case) -> None:
    expected = case.status if case.verdict == "same" else case.verdict
    assert ac["verdict"] == expected, ac
    assert ac["carrier"] == case.carrier, ac
    assert ac["vo"] == case.vo, ac
    _assert_ac_pins(ac, case)


def _assert_ac_pins(ac: dict, case: Case) -> None:
    """The optional digest= and fqan: pins of a case."""
    if case.digest is not None:
        assert ac["digest"].lower() == case.digest, ac
    if case.fqans is not None:
        assert tuple(ac["fqan"]) == case.fqans, ac


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_corner_case(pki, harness, out, case):
    """status: and the AC's verdict/carrier/vo (+digest/fqans when pinned)."""
    verdict = _checked(harness, pki, _minted(pki, out, case), case)
    assert verdict.status == case.status, verdict.stdout
    assert (verdict.returncode == 0) == (case.status == "ok"), verdict.stdout
    if case.verdict is None:
        assert verdict.acs == [], verdict.stdout
        return
    assert len(verdict.acs) == 1, verdict.stdout
    _assert_ac(verdict.acs[0], case)


# ---------------------------------------------------------------------------
# cases that need more than the table
# ---------------------------------------------------------------------------

def test_multi_vo_one_bad_lsc(pki, harness, out):
    """Two ACs (cms, atlas) signed by the RSA signer: cms verifies, atlas fails
    the LSC (its file names the EC signer); status is ok because one AC did."""
    mint(pki, out, "rsa", ["cms", "atlas"], [FQAN_CMS, "/atlas/Role=NULL/Capability=NULL"])
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok", verdict.stdout
    assert [(ac["vo"], ac["verdict"]) for ac in verdict.acs] == [("cms", "ok"), ("atlas", "lsc")]


def test_delegated_proxy_carries_parent_ac(pki, harness, out):
    """-delegate: leaf, VOMS proxy, user cert — the AC is on carrier 1 and the
    holder (the EEC, two hops up) still binds."""
    mint(pki, out, "rsa", "cms", FQAN_CMS, "-delegate")
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok", verdict.stdout
    assert verdict.acs[0]["carrier"] == "1", verdict.stdout
    assert verdict.acs[0]["fqan"] == [FQAN_CMS]


def test_no_policy_uri_takes_vo_from_fqan(pki, harness, out):
    mint(pki, out, "rsa", "cms", FQAN_CMS, "-no-policy-uri")
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok", verdict.stdout
    assert verdict.acs[0]["vo"] == "cms" and verdict.acs[0]["uri"] == "", verdict.stdout


def test_uri_noport_keeps_host(pki, harness, out):
    mint(pki, out, "rsa", "cms", FQAN_CMS, "-uri-noport")
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok", verdict.stdout
    assert verdict.acs[0]["uri"] == "voms-rsa.test.local", verdict.stdout


def test_fqan_bad_value_absent(pki, harness, out):
    """The malformed FQAN (a comma and a 0x01 byte) is dropped, never printed."""
    mint(pki, out, "rsa", "cms", FQAN_CMS, "-fqan-bad")
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok", verdict.stdout
    assert verdict.acs[0]["fqans"] == "1" and verdict.acs[0]["fqan"] == [FQAN_CMS]
    assert "," not in verdict.stdout and "\x01" not in verdict.stdout


def test_gen_attr_printed(pki, harness, out):
    mint(pki, out, "rsa", "cms", FQAN_CMS, "-gen-attr", "nickname=rob:cms",
         "-gen-attr", "site=CERN:")
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok", verdict.stdout
    assert verdict.acs[0]["attr"] == ["nickname=rob:cms", "site=CERN:"], verdict.stdout


def test_sig_alg_digests(pki, harness, out):
    """The digest= field names the scheme: PSS and Ed25519 carry no digest nid."""
    mint(pki, out, "ed25519", "cms", FQAN_CMS)
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok" and "25519" in verdict.acs[0]["digest"].lower(), verdict.stdout
    mint(pki, out, "rsa", "cms", FQAN_CMS, "-sig-alg", "pss")
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "ok" and "pss" in verdict.acs[0]["digest"].lower(), verdict.stdout


def _flip_last_ac_byte(proxy: str) -> None:
    """Rewrite the leaf with the last byte of its VOMS extension value (the
    tail of the AC signature) flipped — re-PEM of the patched DER, the proxy
    itself is NOT re-signed (the harness does not verify the proxy chain)."""
    with open(proxy, "rb") as fh:
        blob = fh.read()
    head, sep, tail = blob.partition(b"-----END CERTIFICATE-----\n")
    leaf = x509.load_pem_x509_certificate(head + sep)
    der = bytearray(leaf.public_bytes(serialization.Encoding.DER))
    value = leaf.extensions.get_extension_for_oid(OID_VOMS).value.public_bytes()
    pos = der.find(value) + len(value) - 1
    der[pos] ^= 0x01
    body = base64.encodebytes(bytes(der)).replace(b"\n", b"")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    pem = b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(lines) + b"\n" + sep
    os.chmod(proxy, 0o600)
    with open(proxy, "wb") as fh:
        fh.write(pem + tail)


def test_tampered_ac_signature(pki, harness, out):
    """Security-negative: one flipped bit in the AC signature → signature."""
    mint(pki, out, "rsa", "cms", FQAN_CMS)
    _flip_last_ac_byte(out)
    verdict = run_check(harness, out, certdir=pki.certdir, vomsdir=pki.vomsdir)
    assert verdict.status == "signature", verdict.stdout
    assert verdict.acs[0]["verdict"] == "signature", verdict.stdout


def test_ecdsa_sig_alg_needs_ec_key(pki, out):
    """The fake refuses a signature algorithm its host key cannot produce."""
    with pytest.raises(Exception):
        mint(pki, out, "rsa", "cms", FQAN_CMS, "-sig-alg", "ecdsa")
    with pytest.raises(Exception):
        mint(pki, out, "ec", "atlas", "/atlas/Role=NULL/Capability=NULL", "-sig-alg", "sha256")
