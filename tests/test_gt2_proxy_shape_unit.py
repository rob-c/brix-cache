"""utils/voms_proxy_fake.py — the GT2 (pre-RFC 3820) proxy SHAPES it mints.

A pure-Python check of the minter the GT2 server tests lean on
(test_gsi_legacy_proxy.py, test_voms_native_ac.py): the CLI is run end to end
against a throwaway CA / user / VOMS signer from x509forge and the first
certificate of the written file is parsed with ``cryptography``.

    -legacy-proxy                          CN=proxy           no proxyCertInfo
    -legacy-proxy -legacy-proxy-kind proxy    CN=proxy           no proxyCertInfo
    -legacy-proxy -legacy-proxy-kind limited  CN=limited proxy   no proxyCertInfo
    -legacy-proxy -legacy-proxy-kind numeric  CN=<digits>        no proxyCertInfo
    (default)                                 CN=<digits>        proxyCertInfo

Every kind keeps the proxy shape the server classifies on: subject = the
issuer's subject plus exactly ONE CN, issued by the user certificate.
"""

import os
import subprocess
import sys

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from x509forge import make_ca, make_eec

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE = os.path.join(_REPO, "utils", "voms_proxy_fake.py")

OID_PROXY_CERT_INFO = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.14")
OID_VOMS = x509.ObjectIdentifier("1.3.6.1.4.1.8005.100.100.5")

pytestmark = pytest.mark.skipif(not os.path.exists(FAKE),
                                reason="utils/voms_proxy_fake.py missing")


@pytest.fixture(scope="module")
def cast(tmp_path_factory):
    """CA, user EEC and a VOMS signing certificate, written as PEM files."""
    base = tmp_path_factory.mktemp("gt2shape")
    ca = make_ca("/O=XrdTest/OU=gt2shape/CN=CA")
    user = make_eec(ca, "/O=XrdTest/OU=gt2shape/CN=user")
    signer = make_eec(ca, "/O=XrdTest/OU=gt2shape/CN=voms.test.local")
    paths = {}
    for tag, cert in (("ca", ca), ("user", user), ("signer", signer)):
        pem = base / f"{tag}cert.pem"
        key = base / f"{tag}key.pem"
        pem.write_bytes(cert.pem)
        key.write_bytes(cert.key_pem)
        key.chmod(0o600)
        paths[tag] = (str(pem), str(key))
    paths["base"] = base
    paths["user_subject"] = user.cert.subject
    return paths


def _mint(cast, name, *extra):
    out = cast["base"] / f"{name}.pem"
    argv = [sys.executable, FAKE,
            "-cert", cast["user"][0], "-key", cast["user"][1],
            "-certdir", str(cast["base"]),
            "-hostcert", cast["signer"][0], "-hostkey", cast["signer"][1],
            "-voms", "cms", "-fqan", "/cms/Role=NULL/Capability=NULL",
            "-uri", "voms.test.local:15000", "-out", str(out), "-hours", "1",
            *extra]
    subprocess.run(argv, check=True, capture_output=True, timeout=120)
    return x509.load_pem_x509_certificate(out.read_bytes())


def _has(cert, oid):
    try:
        cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return False
    return True


def _trailing_cn(cert, cast):
    """The one CN the proxy adds to its issuer's subject, having checked the
    shape: issuer = the user, subject = issuer + exactly one RDN."""
    assert cert.issuer == cast["user_subject"]
    rdns = list(cert.subject.rdns)
    assert rdns[:-1] == list(cast["user_subject"].rdns), cert.subject
    attrs = list(rdns[-1])
    assert len(attrs) == 1 and attrs[0].oid == NameOID.COMMON_NAME, rdns[-1]
    return attrs[0].value


# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("extra,cn", [
    (("-legacy-proxy",), "proxy"),
    (("-legacy-proxy", "-legacy-proxy-kind", "proxy"), "proxy"),
    (("-legacy-proxy", "-legacy-proxy-kind", "limited"), "limited proxy"),
], ids=["default-kind", "proxy", "limited"])
def test_named_legacy_kinds_carry_the_gt2_cn_and_no_pci(cast, extra, cn):
    cert = _mint(cast, "-".join(extra).replace(" ", ""), *extra)
    assert _trailing_cn(cert, cast) == cn
    assert not _has(cert, OID_PROXY_CERT_INFO), \
        "a GT2 proxy must not carry proxyCertInfo"


def test_numeric_legacy_kind_is_all_digits_without_pci(cast):
    cert = _mint(cast, "numeric", "-legacy-proxy",
                 "-legacy-proxy-kind", "numeric")
    cn = _trailing_cn(cert, cast)
    assert cn.isdigit() and cn, cn
    assert not _has(cert, OID_PROXY_CERT_INFO)


def test_the_rfc_default_still_carries_pci(cast):
    """The historical proxy is unchanged: numeric CN with a critical
    proxyCertInfo, i.e. an RFC 3820 proxy and not a GT2 one."""
    cert = _mint(cast, "rfc")
    assert _trailing_cn(cert, cast).isdigit()
    ext = cert.extensions.get_extension_for_oid(OID_PROXY_CERT_INFO)
    assert ext.critical


def test_every_kind_keeps_the_voms_extension(cast):
    """The GT2 knobs change the proxy's shape only; the AC still travels."""
    for name, extra in (("v-rfc", ()), ("v-gt2", ("-legacy-proxy",)),
                        ("v-lim", ("-legacy-proxy", "-legacy-proxy-kind",
                                   "limited"))):
        assert _has(_mint(cast, name, *extra), OID_VOMS), name


def test_an_unknown_legacy_kind_is_refused():
    """argparse `choices`: a misspelt kind cannot silently mint a proxy."""
    result = subprocess.run(
        [sys.executable, FAKE, "-legacy-proxy", "-legacy-proxy-kind", "gt3",
         "-cert", "x", "-key", "x", "-hostcert", "x", "-hostkey", "x",
         "-voms", "cms", "-fqan", "/cms", "-out", "x"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert "invalid choice" in result.stderr

