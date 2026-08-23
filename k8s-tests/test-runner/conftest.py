import os
import socket
from pathlib import Path

import pytest


def _expression_1(namespace):
    return (
        namespace or os.environ.get("TEST_NAMESPACE", "k8s-tests-dev")
    )

def _expression_2(suffix):
    return (
        "root" if suffix == "xrootd" else "davs"
    )

def _expression_3(suffix):
    return (
        1094 if suffix == "xrootd" else 8443
    )


def _guard_get_server_urls_1(urls):
    if not urls:
        urls["xrootd"] = "root://localhost:1094"
        urls["webdav-https"] = "davs://localhost:8443"


def get_server_urls(namespace=None):
    ns = _expression_1(namespace)
    
    urls = {}
    for suffix in ("xrootd", "webdav-https"):
        svc = f"xrootd-servers-{suffix}"
        dns = f"{svc}.{ns}.svc.cluster.local"
        
        try:
            socket.gethostbyname(dns)
            scheme = _expression_2(suffix)
            port = _expression_3(suffix)
            urls[suffix] = f"{scheme}://{dns}:{port}"
        except socket.gaierror:
            pass
    
    for key, default_port in (("TEST_NGINX_URL", 1094), ("TEST_WEBDAV_URL", 8443)):
        url = os.environ.get(key)
        if url:
            urls["fallback"] = url
            break
    
    _guard_get_server_urls_1(urls)
    
    return urls


@pytest.fixture(scope="session")
def server_urls():
    return get_server_urls()


@pytest.fixture(scope="session")
def auth_mode():
    return os.environ.get("AUTH_MODE", "none")


@pytest.fixture(scope="session")
def pki_dir():
    return Path("/etc/grid-security")


@pytest.fixture(scope="session")
def ca_cert(pki_dir):
    cert_path = pki_dir / "certificates" / "ca.crt"
    if not cert_path.exists():
        pytest.skip("CA certificate not found — GSI tests require PKI setup")
    return str(cert_path)


@pytest.fixture(scope="session")
def test_namespace():
    return os.environ.get("TEST_NAMESPACE", "k8s-tests-dev")
