"""
tests/test_https_webdav_status_codes.py

Comprehensive HTTPS status-code and RFC compliance tests for the TLS WebDAV
endpoint (port 8444, required x509 GSI proxy-cert auth).

Targets the dedicated HTTPS+GSI server (port 8444, brix_webdav_auth required).
All requests require a valid GSI proxy certificate; because the export also
accepts bearer tokens, unauthenticated requests return 401 Unauthorized with a
`WWW-Authenticate: Bearer` challenge rather than a bare 403.

Tests assert RFC-correct behaviour directly; regressions must fail normally.

RFC compliance: all tested behaviours are now compliant.

TLS verification is intentionally disabled for the server cert
(test CN ≠ "localhost").  Client auth uses proxy_std.pem which contains
both certificate and private key.

Run:
    python3 -m pytest tests/test_https_webdav_status_codes.py -v
"""

import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from settings import NGINX_WEBDAV_GSI_TLS_PORT, PROXY_STD, CA_CERT, SERVER_HOST

_PFX = "htss_"

BASE      = f"https://{SERVER_HOST}:{NGINX_WEBDAV_GSI_TLS_PORT}"
PROXY_PEM = PROXY_STD


def _url(path):
    return BASE + path


def _uid():
    return uuid.uuid4().hex[:12]


def _s():
    """requests.Session with client cert and TLS."""
    s = requests.Session()
    s.cert   = (PROXY_PEM, PROXY_PEM)
    s.verify = False
    return s


def _sa():
    """requests.Session WITHOUT client cert (anonymous TLS)."""
    s = requests.Session()
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
    content = f"https test {_uid()}".encode()
    r = _put(path, content, session=session)
    assert r.status_code == 201, f"setup PUT failed: {r.status_code}"
    etag = r.headers.get("ETag", "")
    return path, content, etag


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
