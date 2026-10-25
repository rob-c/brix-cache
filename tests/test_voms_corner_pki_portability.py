"""The VOMS negative fixtures must work with every supported OpenSSL CLI."""

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import _test_voms_corner_helpers as helpers


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return helpers.make_pki(str(tmp_path_factory.mktemp("portable-voms-pki")))


def _cert(path):
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def test_expired_signer_has_matching_key_and_valid_ca_signature(pki):
    expired = _cert(pki.certs["expired"])
    ca = _cert(pki.ca_cert)
    key = serialization.load_pem_private_key(
        Path(pki.keys["expired"]).read_bytes(), password=None)
    expired.verify_directly_issued_by(ca)
    assert expired.public_key().public_numbers() == key.public_key().public_numbers()
    assert not expired.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert expired.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest


def test_expired_signer_is_actually_expired_not_merely_untrusted(pki):
    expired = _cert(pki.certs["expired"])
    now = datetime.datetime.now(datetime.timezone.utc)
    assert expired.not_valid_before_utc < expired.not_valid_after_utc < now
    assert _cert(pki.certs["rsa"]).not_valid_after_utc > now
    assert expired.issuer == _cert(pki.ca_cert).subject


def test_original_signer_algorithms_and_old_cli_compatibility(pki, monkeypatch, tmp_path):
    for name, kind in (("rsa", rsa.RSAPublicKey), ("ec", ec.EllipticCurvePublicKey),
                       ("ed25519", ed25519.Ed25519PublicKey)):
        assert isinstance(_cert(pki.certs[name]).public_key(), kind)

    def forbidden(*args):
        pytest.fail("expired fixture must not use OpenSSL's version-specific CLI")

    monkeypatch.setattr(helpers, "_openssl", forbidden)
    helpers._issue_expired(pki, str(tmp_path / "expired.key"),
                          str(tmp_path / "expired.pem"), "expired.test")
    assert _cert(tmp_path / "expired.pem").not_valid_after_utc < datetime.datetime.now(
        datetime.timezone.utc)
