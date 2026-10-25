import os

import pytest

from cmdscripts.delegation_twostep import run_checks, sign_csr
from settings import NGINX_BIN

def _guard_test_delegation_twostep_flow_1():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

def _guard_test_delegation_twostep_flow_2(results):
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

def _check_test_delegation_twostep_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_delegation_twostep_flow_2(expected, messages):
    assert any(message.startswith(expected) for message in messages)


pytestmark = pytest.mark.xdist_group("cmd-delegation_twostep")


@pytest.fixture
def signing_fixture(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from brix_suite.security.x509.primitives import make_ca, proxy_cert_info_der

    issuer = make_ca('/CN=Fixture issuer')
    delegate = make_ca('/CN=Delegate key')
    oid = x509.ObjectIdentifier('1.3.6.1.5.5.7.1.14')
    extension = x509.UnrecognizedExtension(oid,
        proxy_cert_info_der('1.3.6.1.5.5.7.21.1'))
    request = (x509.CertificateSigningRequestBuilder().subject_name(delegate.cert.subject)
        .add_extension(extension, critical=True).sign(delegate.key, hashes.SHA256()))
    csr, cert, key, output = (tmp_path / name for name in
                              ('request.pem', 'issuer.pem', 'issuer.key', 'signed.pem'))
    csr.write_bytes(request.public_bytes(serialization.Encoding.PEM))
    cert.write_bytes(issuer.pem)
    key.write_bytes(issuer.key_pem)
    return csr, cert, key, output, issuer, request, extension


def test_fixture_csr_signing_preserves_requested_key_and_critical_extension(signing_fixture):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding

    csr, cert, key, output, issuer, request, extension = signing_fixture
    assert sign_csr(csr, cert, key, output)
    signed = x509.load_pem_x509_certificate(output.read_bytes())
    issuer.key.public_key().verify(signed.signature, signed.tbs_certificate_bytes,
                                   padding.PKCS1v15(), signed.signature_hash_algorithm)
    assert signed.public_key().public_numbers() == request.public_key().public_numbers()
    copied = signed.extensions.get_extension_for_oid(extension.oid)
    assert copied.critical and copied.value == extension


def test_malformed_fixture_csr_is_not_signed(signing_fixture):
    csr, cert, key, output, *_rest = signing_fixture
    csr.write_bytes(b'not a request')
    assert not sign_csr(csr, cert, key, output)
    assert not output.exists()


def test_wrong_fixture_signing_key_cannot_produce_a_certificate(signing_fixture):
    from brix_suite.security.x509.primitives import make_ca

    csr, cert, key, output, *_rest = signing_fixture
    key.write_bytes(make_ca('/CN=Wrong signer').key_pem)
    assert not sign_csr(csr, cert, key, output)
    assert not output.exists()


@pytest.mark.suite_job
def test_delegation_twostep_flow(tmp_path):
    _guard_test_delegation_twostep_flow_1()

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    _guard_test_delegation_twostep_flow_2(results)

    _check_test_delegation_twostep_flow_1(results)
    messages = [message for _, message in results]
    for expected in (
        "a1: getProxyReq accepted",
        "a2: X-Brix-Delegation-Id header present",
        "a3: response body is a PEM CSR",
        "b1: A signed its own CSR",
        "b2: putProxy accepted",
        "c1: B's putProxy to A's id rejected (403)",
        "d: unknown id rejected (404)",
        "e: garbage body rejected (400)",
        "f1: untrusted-EEC signed proxy rejected (403)",
        "g3: no credential file written while endpoint is off",
    ):
        _check_test_delegation_twostep_flow_2(expected, messages)
