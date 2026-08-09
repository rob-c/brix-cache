"""
tests/test_https_webdav_token_status_codes.py

Comprehensive HTTPS status-code and RFC compliance tests for the TLS WebDAV
endpoint (port 8443, optional JWT/WLCG bearer-token auth).

Mirrors test_https_webdav_status_codes.py but authenticates via
Authorization: Bearer <JWT> instead of an x509 proxy certificate.  Targets
the HTTPS+Token server (port 8443, brix_webdav_auth optional) so that
HTTPS+Token and HTTPS+GSI have equal WebDAV-operation coverage.

Additional classes verify authentication behaviour:
  - optional-auth mode: unauthenticated requests still return data
  - bearer token present: full auth, all operations available
  - read-only token: write operations rejected (403)

Tests assert RFC-correct behaviour directly; regressions must fail normally.

RFC compliance: all tested behaviours are now compliant.

TLS verification is intentionally disabled for the server cert
(test CN ≠ "localhost").  Tokens are signed by the test JWKS authority
created during test environment initialisation.

Run:
    python3 -m pytest tests/test_https_webdav_token_status_codes.py -v
"""

import os
import sys
import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

from settings import NGINX_WEBDAV_PORT, SERVER_HOST, TOKENS_DIR

_PFX = "httst_"

BASE      = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
_ISSUER   = None
_RW_TOKEN = ""   # storage.read:/ storage.write:/ — populated by _init_token


@pytest.fixture(scope="module", autouse=True)
def _init_token():
    global _ISSUER, _RW_TOKEN
    _ISSUER = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(_ISSUER.key_path):
        _ISSUER.init_keys()
    # lifetime=7200 gives 2 h — enough for the whole test module run.
    _RW_TOKEN = _ISSUER.generate(
        scope="storage.read:/ storage.write:/", lifetime=7200
    )


def _url(path):
    return BASE + path


def _uid():
    return uuid.uuid4().hex[:12]


# Under a parallel (-n 12) run the single-worker nginx occasionally severs a
# brand-new TLS connection during the handshake (SSLEOFError before any HTTP
# bytes are exchanged).  urllib3 counts handshake SSLErrors against the
# "other"/"connect" buckets, so retrying there is method-independent and
# cannot replay a request.  read=0 keeps mid-request failures fail-fast:
# a PUT whose response was lost is never resent (a silent replay would turn
# a 201 into a 204 and break setup assertions).
_RETRY = urllib3.util.retry.Retry(
    total=2, connect=2, read=0, status=0, other=2, backoff_factor=0.2
)


def _mount_retry(s):
    """Mount the pre-request retry policy on both schemes of a Session."""
    adapter = requests.adapters.HTTPAdapter(max_retries=_RETRY)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _s():
    """requests.Session with read+write bearer token."""
    s = _mount_retry(requests.Session())
    s.headers["Authorization"] = f"Bearer {_RW_TOKEN}"
    s.verify = False
    return s


def _sa():
    """requests.Session WITHOUT any credentials (anonymous TLS)."""
    s = _mount_retry(requests.Session())
    s.verify = False
    return s


def _put(path, data=b"hello", session=None, **kw):
    sess = session or _s()
    return sess.put(_url(path), data=data, timeout=10, **kw)


def _get(path, session=None, **kw):
    sess = session or _s()
    return sess.get(_url(path), timeout=10, **kw)


def _head(path, session=None, **kw):
    sess = session or _s()
    return sess.head(_url(path), timeout=10, **kw)


def _delete(path, session=None, **kw):
    sess = session or _s()
    return sess.delete(_url(path), timeout=10, **kw)


def _mkcol(path, session=None, **kw):
    sess = session or _s()
    return sess.request("MKCOL", _url(path), timeout=10, **kw)


def _propfind(path, depth="1", session=None, **kw):
    body = (
        '<?xml version="1.0"?>'
        '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
    )
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    sess = session or _s()
    return sess.request(
        "PROPFIND", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _move(src, dst, overwrite="T", session=None, **kw):
    headers = {"Destination": BASE + dst, "Overwrite": overwrite}
    sess = session or _s()
    return sess.request("MOVE", _url(src), headers=headers, timeout=10, **kw)


def _copy(src, dst, overwrite="T", session=None, **kw):
    headers = {"Destination": BASE + dst, "Overwrite": overwrite}
    sess = session or _s()
    return sess.request("COPY", _url(src), headers=headers, timeout=10, **kw)


def _existing_file(session=None):
    """Create a file and return (path, content, etag)."""
    path = f"/{_PFX}{_uid()}.txt"
    content = f"https token test {_uid()}".encode()
    r = _put(path, content, session=session)
    assert r.status_code == 201, f"setup PUT failed: {r.status_code}"
    etag = r.headers.get("ETag", "")
    return path, content, etag


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
