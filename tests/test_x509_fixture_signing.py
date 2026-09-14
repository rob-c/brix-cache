"""Offline certificate generation retains algorithms and process policy scope."""

import json
import os
import subprocess
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import x509forge
from brix_suite.security.x509 import primitives
from clauses import ALL_CLAUSES


@pytest.fixture
def signing_policy(tmp_path, monkeypatch):
    parent = tmp_path / "parent-policy.cnf"
    parent.write_text("\n".join([
        "openssl_conf = test_init", "[test_init]", "alg_section = test_algorithms",
        "[test_algorithms]", "rh-allow-sha1-signatures = no", "",
    ]))
    monkeypatch.setenv("OPENSSL_CONF", str(parent))
    monkeypatch.setenv("BRIX_X509_POLICY_SENTINEL", "inherited")
    calls = []
    run = subprocess.run

    def observe(command, **options):
        calls.append((command, options.get("env")))
        return run(command, **options)

    monkeypatch.setattr(subprocess, "run", observe)
    return SimpleNamespace(parent=str(parent), calls=calls)


def _assert_child_policy(policy):
    assert os.environ["OPENSSL_CONF"] == policy.parent
    for command, environment in policy.calls:
        if "-sha1" not in command:
            assert environment is None, command
            continue
        assert command[1] in ("req", "x509")
        assert environment["OPENSSL_CONF"] != policy.parent
        assert environment["BRIX_X509_POLICY_SENTINEL"] == "inherited"


def _verify_signature(certificate, issuer, content):
    issuer.public_key().verify(
        certificate.signature, content, padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )


def _build_clause_chain(tmp_path, identifier, expected):
    clause = next(item for item in ALL_CLAUSES if item.id == identifier)
    root = x509forge.build_all(tmp_path / "corpus", [clause])
    errors = root / "build_errors.tsv"
    assert not errors.exists(), errors.read_text()
    manifest = json.loads((root / "manifest.json").read_text())
    assert len(manifest) == 1
    assert manifest[0]["id"] == identifier
    assert manifest[0]["expected"] == expected
    return x509.load_pem_x509_certificates(
        (root / "creds" / manifest[0]["cred"]).read_bytes()
    )


@pytest.mark.parametrize("identifier,index,digest,key_class,expected", [
    ("CHN-069", 0, "sha256", rsa.RSAPublicKey, "accept"),
    ("CHN-072", 0, "sha1", rsa.RSAPublicKey, "reject"),
    ("CHN-075", 1, "sha1", rsa.RSAPublicKey, "reject"),
    ("CHN-078", 1, "sha1", rsa.RSAPublicKey, "reject"),
    ("CHN-132", 0, "sha1", ec.EllipticCurvePublicKey, "reject"),
], ids=["normal", "sha1-leaf", "sha1-intermediate", "sha1-root", "sha1-ec-leaf"])
def test_clause_materializes_its_declared_certificate(
    tmp_path, signing_policy, identifier, index, digest, key_class, expected,
):
    certificates = _build_clause_chain(tmp_path, identifier, expected)
    certificate = certificates[index]
    assert certificate.signature_hash_algorithm.name == digest
    assert isinstance(certificate.public_key(), key_class)
    issuer = certificates[min(index + 1, len(certificates) - 1)]
    _verify_signature(certificate, issuer, certificate.tbs_certificate_bytes)
    _assert_child_policy(signing_policy)


@pytest.mark.parametrize("curve,key_size", [("P-256", 256), ("P-384", 384)])
def test_weak_digest_fallback_preserves_requested_ec_curve(
    signing_policy, curve, key_size,
):
    issuer = x509forge.make_ca("/CN=fixture issuer")
    leaf = x509forge.make_eec(
        issuer, "/CN=fixture leaf", key_type="ec", curve=curve, digest_name="sha1",
    )
    assert isinstance(leaf.key, ec.EllipticCurvePrivateKey)
    assert leaf.key.key_size == leaf.cert.public_key().key_size == key_size
    assert leaf.key.public_key().public_numbers() == leaf.cert.public_key().public_numbers()
    _verify_signature(leaf.cert, issuer.cert, leaf.cert.tbs_certificate_bytes)
    _assert_child_policy(signing_policy)


def test_signing_failure_remains_an_error_with_parent_policy_intact(signing_policy):
    issuer = x509forge.make_ca("/CN=fixture issuer")
    broken = SimpleNamespace(pem=issuer.pem, key_pem=b"not a private key")
    with pytest.raises(subprocess.CalledProcessError) as error:
        primitives._make_eec_openssl(
            broken, "/CN=fixture leaf", key_bits=2048, digest_name="sha1",
            not_after_days=1, not_before_days=-1,
        )
    assert error.value.returncode != 0
    assert error.value.stderr
    _assert_child_policy(signing_policy)


def test_generated_signature_rejects_modified_certificate_content(signing_policy):
    issuer = x509forge.make_ca("/CN=fixture issuer")
    leaf = x509forge.make_eec(issuer, "/CN=fixture leaf", digest_name="sha1")
    content = leaf.cert.tbs_certificate_bytes
    _verify_signature(leaf.cert, issuer.cert, content)
    changed = content[:-1] + bytes([content[-1] ^ 1])
    with pytest.raises(InvalidSignature):
        _verify_signature(leaf.cert, issuer.cert, changed)
    _assert_child_policy(signing_policy)
