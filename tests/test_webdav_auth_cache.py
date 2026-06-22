"""
WebDAV x509 authentication cache tests.

These tests use a dedicated nginx instance so they can exercise two TLS
configurations without disturbing the main test server:

  - optional_no_ca: forces the module's cached CA/CRL store/manual verifier
  - optional + ssl_client_certificate: allows the nginx-verified fast path
"""

import os

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from settings import (
    CA_CERT,
    HOST,
    PROXY_STD,
    SERVER_CERT,
    SERVER_KEY,
    TEST_ROOT,
    WEBDAV_AUTH_CACHE_MANUAL_PORT,
    WEBDAV_AUTH_CACHE_NGINX_PORT,
    url_host,
)

PROXY_PEM = PROXY_STD
TEST_FILE = "auth_cache_probe.txt"


@pytest.fixture(scope="session", autouse=True)
def webdav_auth_cache_nginx():
    for path in (CA_CERT, PROXY_PEM, SERVER_CERT, SERVER_KEY):
        if not os.path.exists(path):
            pytest.skip(f"required PKI file not found: {path}")

    manual_port = WEBDAV_AUTH_CACHE_MANUAL_PORT
    nginx_port = WEBDAV_AUTH_CACHE_NGINX_PORT
    data_root = os.path.join(TEST_ROOT, "data-webdav-auth-cache")
    log_path = os.path.join(
        TEST_ROOT, "dedicated", "webdav-auth-cache", "logs", "error.log"
    )

    os.makedirs(data_root, exist_ok=True)
    with open(os.path.join(data_root, TEST_FILE), "wb") as fh:
        fh.write(b"webdav auth cache probe\n")

    yield {
        "manual_url": f"https://{url_host(HOST)}:{manual_port}/{TEST_FILE}",
        "nginx_url": f"https://{url_host(HOST)}:{nginx_port}/{TEST_FILE}",
        "log": log_path,
        "startup_log": log_path,
    }


def _read_log(path):
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_cached_ca_store_built_once_and_reused(webdav_auth_cache_nginx):
    info = webdav_auth_cache_nginx
    log_before = _read_log(info["startup_log"])
    built_before = log_before.count("xrootd_webdav: cached CA store built")
    assert built_before == 2, log_before

    for _ in range(3):
        resp = requests.get(info["manual_url"], cert=PROXY_PEM, verify=False)
        assert resp.status_code == 200

    startup_after = _read_log(info["startup_log"])
    runtime_after = _read_log(info["log"])
    assert startup_after.count("xrootd_webdav: cached CA store built") == built_before
    assert "GSI auth OK source=manual" in runtime_after


def test_keepalive_reuses_tls_connection_auth_cache(webdav_auth_cache_nginx):
    info = webdav_auth_cache_nginx

    with requests.Session() as session:
        session.cert = PROXY_PEM
        session.verify = False
        first = session.get(info["manual_url"])
        second = session.get(info["manual_url"])

    assert first.status_code == 200
    assert second.status_code == 200

    log = _read_log(info["log"])
    assert (
        "GSI auth reused from TLS connection cache" in log
        or "GSI auth reused from TLS session cache" in log
    ), log


def test_nginx_verified_client_cert_fast_path(webdav_auth_cache_nginx):
    info = webdav_auth_cache_nginx

    resp = requests.get(info["nginx_url"], cert=PROXY_PEM, verify=False)
    assert resp.status_code == 200

    log = _read_log(info["log"])
    assert "GSI auth OK source=nginx" in log, log
