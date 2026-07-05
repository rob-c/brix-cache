"""
Native xrdgsiproxy (phase-37 §14.3): RFC-3820 X.509 proxy create/info/destroy.

The one genuinely new crypto surface in the client. The gating proof is that a
proxy our tool builds authenticates GSI against the module's verifier (:11095
cleartext, :11096 in-protocol TLS) — i.e. our proxyCertInfo DER is correct — plus
a byte-for-byte match of that extension against the harness reference proxy
(utils/make_proxy.py).

Run (serial, manual fleet):
    TEST_SKIP_SERVER_SETUP=1 TEST_XRDFS_BIN=$PWD/client/bin/xrdfs \
    PYTHONPATH=tests pytest tests/test_xrdgsiproxy.py -v -p no:xdist
"""

import os
import shutil
import stat
import subprocess

import pytest

from settings import (
    CA_DIR,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
    USER_CERT,
    USER_KEY,
)

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDGSIPROXY = os.path.join(REPO, "client", "bin", "xrdgsiproxy")
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14"

_BASE_ENV = {k: v for k, v in os.environ.items()}
for _k in ("X509_USER_PROXY", "X509_CERT_DIR", "X509_USER_CERT", "X509_USER_KEY"):
    _BASE_ENV.pop(_k, None)


@pytest.fixture(scope="module")
def built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(["make", "-C", os.path.join(REPO, "client")],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDGSIPROXY):
        pytest.skip(f"build failed:\n{proc.stdout}\n{proc.stderr}")
    if not (os.path.exists(USER_CERT) and os.path.exists(USER_KEY)):
        pytest.skip("harness PKI (usercert/userkey) not present")
    return XRDGSIPROXY


def _init_env():
    env = dict(_BASE_ENV)
    env["X509_USER_CERT"] = USER_CERT
    env["X509_USER_KEY"] = USER_KEY
    return env


def _make_proxy(out, built):
    return subprocess.run([built, "init", "-out", out], capture_output=True,
                          text=True, env=_init_env(), timeout=30)


def test_init_creates_mode_0400(built, tmp_path):
    out = str(tmp_path / "p.pem")
    r = _make_proxy(out, built)
    assert r.returncode == 0, r.stderr
    assert os.path.exists(out)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o400, "proxy not mode 0400"
    # The chain holds proxy cert + user cert + proxy key.
    blob = open(out).read()
    assert blob.count("BEGIN CERTIFICATE") >= 2 and "PRIVATE KEY" in blob


def test_info_reports_validity(built, tmp_path):
    out = str(tmp_path / "p.pem")
    assert _make_proxy(out, built).returncode == 0
    r = subprocess.run([built, "info", "-file", out], capture_output=True,
                       text=True, env=_BASE_ENV, timeout=15)
    assert r.returncode == 0, r.stderr
    assert "subject" in r.stdout and "valid" in r.stdout


def test_destroy_removes(built, tmp_path):
    out = str(tmp_path / "p.pem")
    assert _make_proxy(out, built).returncode == 0
    r = subprocess.run([built, "destroy", "-file", out], capture_output=True,
                       text=True, env=_BASE_ENV, timeout=15)
    assert r.returncode == 0, r.stderr
    assert not os.path.exists(out)


def _gsi_ls(url, proxy, timeout=30):
    env = dict(_BASE_ENV)
    env["X509_USER_PROXY"] = proxy
    env["X509_CERT_DIR"] = CA_DIR
    return subprocess.run([NATIVE_XRDFS, url, "ls", "/"], capture_output=True,
                          text=True, env=env, timeout=timeout)


def test_proxy_authenticates_gsi_cleartext(built, tmp_path):
    """The gate: a proxy we built is accepted by the module's GSI verifier."""
    out = str(tmp_path / "p.pem")
    assert _make_proxy(out, built).returncode == 0
    r = _gsi_ls(f"root://{SERVER_HOST}:{NGINX_GSI_PORT}", out)
    assert r.returncode == 0, f"GSI auth with our proxy failed: {r.stderr}"


def test_proxy_authenticates_gsi_tls(built, tmp_path):
    out = str(tmp_path / "p.pem")
    assert _make_proxy(out, built).returncode == 0
    r = _gsi_ls(f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}", out)
    assert r.returncode == 0, f"GSI+TLS auth with our proxy failed: {r.stderr}"


@pytest.mark.skipif(not os.path.exists(PROXY_STD), reason="reference proxy absent")
def test_proxycertinfo_der_matches_reference(built, tmp_path):
    """The proxyCertInfo extension our tool emits is byte-identical to the
    harness reference proxy (utils/make_proxy.py) — the clean-room DER proof."""
    crypto = pytest.importorskip("cryptography")
    from cryptography import x509

    out = str(tmp_path / "p.pem")
    assert _make_proxy(out, built).returncode == 0

    def _pci(path):
        # The first PEM cert in the chain is the proxy.
        data = open(path, "rb").read()
        cert = x509.load_pem_x509_certificate(data)
        ext = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(PROXY_CERT_INFO_OID))
        return ext.value.value  # UnrecognizedExtension raw DER

    assert _pci(out) == _pci(PROXY_STD), "proxyCertInfo DER differs from reference"


def test_gsi_fails_after_destroy(built, tmp_path):
    out = str(tmp_path / "p.pem")
    assert _make_proxy(out, built).returncode == 0
    assert subprocess.run([built, "destroy", "-file", out],
                          env=_BASE_ENV, timeout=15).returncode == 0
    r = _gsi_ls(f"root://{SERVER_HOST}:{NGINX_GSI_PORT}", out)
    assert r.returncode != 0, "GSI unexpectedly succeeded with a destroyed proxy"
