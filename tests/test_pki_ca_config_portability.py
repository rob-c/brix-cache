"""Canonical fixture CAs must verify on real OpenSSL 1.1.1 as well as 3+."""
import os
import subprocess

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from brix_suite.security import pki
from cmdscripts.gsi_trust_live import _intermediate_ca_root_command


@pytest.fixture
def fixture_ca(tmp_path):
    key, certificate = tmp_path / "ca.key", tmp_path / "ca.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"],
                   check=True, capture_output=True)
    return key, certificate


def _generate(key, certificate):
    return subprocess.run(pki._ca_certificate_command(str(key), str(certificate)),
                          capture_output=True, text=True, timeout=30)


def test_canonical_ca_has_unique_extensions_and_verifies(fixture_ca):
    key, certificate = fixture_ca
    generated = _generate(key, certificate)
    assert generated.returncode == 0, generated.stderr
    parsed = x509.load_pem_x509_certificate(certificate.read_bytes())
    assert parsed.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    assert len(parsed.extensions) == 4
    verified = subprocess.run(["openssl", "verify", "-CAfile", str(certificate),
                               str(certificate)], capture_output=True, text=True)
    assert verified.returncode == 0, verified.stderr


def test_bad_private_key_still_fails_closed(fixture_ca):
    key, certificate = fixture_ca
    key.write_text("not a private key")
    assert _generate(key, certificate).returncode != 0


def test_distro_request_extensions_cannot_duplicate_fixture_ca(
        fixture_ca, tmp_path, monkeypatch):
    key, certificate = fixture_ca
    distro = tmp_path / "distro.cnf"
    distro.write_text("[req]\ndistinguished_name=dn\nx509_extensions=poison\n"
        "[dn]\n[poison]\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\n")
    monkeypatch.setenv("OPENSSL_CONF", str(distro))
    generated = _generate(key, certificate)
    assert generated.returncode == 0, generated.stderr
    parsed = x509.load_pem_x509_certificate(certificate.read_bytes())
    assert parsed.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    assert len(parsed.extensions) == 4
    assert os.environ["OPENSSL_CONF"] == str(distro)


def _demo_pki(directory, environment):
    script = pki.ROOT_DIR / "deploy/compose/common/pki-init.sh"
    return subprocess.run(["bash", str(script)], capture_output=True, text=True,
        timeout=30, env={**os.environ, **environment, "OUT": str(directory),
                        "HOSTS": "localhost", "DAYS": "1"})  # net-literal-allow: throwaway certificate SAN subject, not a dial target


@pytest.mark.parametrize("poisoned", [False, True])
def test_shipped_demo_ca_and_leaves_verify_independently_of_distro_defaults(
        tmp_path, poisoned):
    configuration = tmp_path / "request.cnf"
    configuration.write_text("[req]\ndistinguished_name=dn\nx509_extensions=poison\n"
        "[dn]\n[poison]\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\n")
    environment = {"OPENSSL_CONF": str(configuration)} if poisoned else {}
    directory = tmp_path / "demo"
    result = _demo_pki(directory, environment)
    assert result.returncode == 0, result.stdout + result.stderr
    ca = directory / "ca/ca.pem"
    parsed = x509.load_pem_x509_certificate(ca.read_bytes())
    assert parsed.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    assert len(parsed.extensions) == 4
    checked = subprocess.run(["openssl", "verify", "-CAfile", str(ca),
        str(ca), str(directory / "hostcert.pem"), str(directory / "usercert.pem")],
        capture_output=True, text=True, timeout=30)
    assert checked.returncode == 0, checked.stdout + checked.stderr


def test_shipped_demo_pki_refuses_an_invalid_output_directory(tmp_path):
    occupied = tmp_path / "occupied"
    occupied.write_text("not a directory")
    assert _demo_pki(occupied, {}).returncode != 0
    assert occupied.read_text() == "not a directory"


@pytest.mark.parametrize("poisoned", [False, True])
def test_gsi_intermediate_anchor_has_unique_extensions_and_verifies(
        tmp_path, monkeypatch, poisoned):
    configuration = tmp_path / "distro.cnf"
    configuration.write_text("[req]\ndistinguished_name=dn\nx509_extensions=poison\n"
        "[dn]\n[poison]\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\n")
    if poisoned:
        monkeypatch.setenv("OPENSSL_CONF", str(configuration))
    issued = subprocess.run(["openssl", *_intermediate_ca_root_command()],
        cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert issued.returncode == 0, issued.stderr
    certificate = tmp_path / "root.pem"
    parsed = x509.load_pem_x509_certificate(certificate.read_bytes())
    assert parsed.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    assert len(parsed.extensions) == 4
    verified = subprocess.run(["openssl", "verify", "-CAfile", str(certificate),
        str(certificate)], capture_output=True, text=True, timeout=30)
    assert verified.returncode == 0, verified.stderr


def test_gsi_intermediate_anchor_does_not_succeed_when_key_output_is_invalid(tmp_path):
    (tmp_path / "root.key").mkdir()
    issued = subprocess.run(["openssl", *_intermediate_ca_root_command()],
        cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert issued.returncode != 0
    assert not (tmp_path / "root.pem").exists()
