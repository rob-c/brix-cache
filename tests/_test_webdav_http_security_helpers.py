"""
tests/test_webdav_http_security.py

HTTP/WebDAV security and protocol-conformance tests.

Covers:
  - RFC 7233 range requests (206 Partial Content correctness)
  - Conditional requests: If-Match, If-None-Match, If-Modified-Since,
    If-Unmodified-Since (ETag and Last-Modified caching headers)
  - HTTP error status codes for edge cases
  - PROPFIND Depth header variants (0, 1, absent)
  - PUT with Content-Range (partial/resumable upload)
  - Plain HTTP WebDAV port (8080) smoke tests

The HTTPS requests are run against both authenticated nginx WebDAV servers:
HTTPS+GSI/x509 on port 8444 and HTTPS+Token on port 8443.  Plain HTTP smoke
tests still use port 8080.  TLS verification is disabled because the test
server certificate is for a test CN, not 'localhost'.

Run:
    python3 -m pytest tests/test_webdav_http_security.py -v
"""

import os
import sys
import time
import xml.etree.ElementTree as ET

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from settings import (
    CA_CERT,
    DATA_ROOT as DEFAULT_DATA_ROOT,
    NGINX_HTTP_WEBDAV_PORT,
    PROXY_STD,
    TOKENS_DIR,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

# ---------------------------------------------------------------------------
# Module-level state (filled by the session fixture)
# ---------------------------------------------------------------------------

WEBDAV_BASE      = ""
HTTP_WEBDAV_BASE = ""
DATA_ROOT        = DEFAULT_DATA_ROOT
PROXY_PEM        = PROXY_STD
TOKEN_DIR        = TOKENS_DIR
AUTH_MODE        = "gsi"
TOKEN            = ""

_PFX_BASE = "wdavs_"  # unique prefix to avoid collisions with other test files
_PFX = _PFX_BASE


@pytest.fixture(scope="module", autouse=True, params=("gsi", "token"),
                ids=("gsi-8444", "token-8443"))
def _configure(request, test_env):
    global WEBDAV_BASE, HTTP_WEBDAV_BASE, DATA_ROOT, PROXY_PEM
    global TOKEN_DIR, AUTH_MODE, TOKEN, _PFX
    AUTH_MODE        = request.param
    _PFX             = f"{_PFX_BASE}{AUTH_MODE}_"
    WEBDAV_BASE      = (
        test_env["webdav_gsi_tls_url"]
        if AUTH_MODE == "gsi"
        else test_env["webdav_url"]
    )
    HTTP_WEBDAV_BASE = test_env["http_webdav_url"]
    DATA_ROOT        = test_env["data_dir"]
    PROXY_PEM        = test_env["proxy_pem"]
    TOKEN_DIR        = test_env.get("token_dir", TOKENS_DIR)
    TOKEN            = ""

    if AUTH_MODE == "token":
        issuer = TokenIssuer(TOKEN_DIR)
        if not os.path.exists(issuer.key_path):
            issuer.init_keys()
        TOKEN = issuer.generate(
            scope="storage.read:/ storage.write:/",
            lifetime=7200,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _url(path):
    return WEBDAV_BASE + path


def _http_url(path):
    return HTTP_WEBDAV_BASE + path


def _data_root():
    """Live DATA_ROOT (module-global mutated by the env fixture; split test
    shards must read it through this accessor, not a reexport-time copy)."""
    return DATA_ROOT


def _session():
    """requests.Session with the current HTTPS WebDAV auth mode."""
    s = requests.Session()
    if AUTH_MODE == "gsi":
        s.cert = (PROXY_PEM, PROXY_PEM)
    elif AUTH_MODE == "token":
        s.headers["Authorization"] = f"Bearer {TOKEN}"
    s.verify = False
    return s


def _put(path, data=b"", session=None):
    s = session or _session()
    r = s.put(_url(path), data=data)
    return r


def _get(path, **kwargs):
    s = _session()
    return s.get(_url(path), **kwargs)


def _make_file(rel, content=b"x"):
    """Write a file directly to the data root."""
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(content)


def _make_dir(rel):
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    os.makedirs(full, exist_ok=True)


def _remove(rel):
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    if os.path.isfile(full):
        os.unlink(full)
    elif os.path.isdir(full):
        import shutil
        shutil.rmtree(full)
    # Also clear any resumable-upload staged partials for this path.  With
    # brix_upload_resume on, an incomplete Content-Range PUT leaves a persistent,
    # identity-keyed "<dest>.xrdresume.<id>.part" sidecar that survives across
    # runs; unlinking only the destination leaves it behind, so a later "first
    # segment" PUT is (correctly) rejected 409 for not being contiguous with the
    # stale partial.  Removing the sidecars makes _remove a true state reset.
    import glob
    for part in glob.glob(f"{full}.xrdresume.*.part"):
        try:
            os.unlink(part)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# TestRangeRequests
# ---------------------------------------------------------------------------
