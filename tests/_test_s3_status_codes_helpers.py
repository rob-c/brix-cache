"""
tests/test_s3_status_codes.py

Comprehensive HTTP status-code and S3 API compliance tests for the S3-compatible
object storage endpoint (port 9001, anonymous access).

Tests assert S3-API-correct behaviour directly; regressions must fail normally.

S3 API compliance: all tested behaviours are now compliant.

Run:
    python3 -m pytest tests/test_s3_status_codes.py -v
"""

import os
import tempfile
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests
from settings import NGINX_S3_PORT, SERVER_HOST

BUCKET = "testbucket"
S3_NS  = "http://s3.amazonaws.com/doc/2006-03-01/"
_PFX   = "s3sc_"

BASE = f"http://{SERVER_HOST}:{NGINX_S3_PORT}"


def _uid():
    return uuid.uuid4().hex[:12]


def _obj_url(key):
    return f"{BASE}/{BUCKET}/{key}"


def _list_url(**params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{BASE}/{BUCKET}/?list-type=2"
    return f"{url}&{qs}" if qs else url


def _put(key, data=b"", **kw):
    return requests.put(_obj_url(key), data=data, timeout=10, **kw)


def _get(key, **kw):
    return requests.get(_obj_url(key), timeout=10, **kw)


def _head(key, **kw):
    return requests.head(_obj_url(key), timeout=10, **kw)


def _delete(key, **kw):
    return requests.delete(_obj_url(key), timeout=10, **kw)


def _list(**params):
    return requests.get(_list_url(**params), timeout=10)


def _existing_object():
    """Put an object and return (key, content, etag)."""
    key     = f"{_PFX}{_uid()}.bin"
    content = f"s3 status test {_uid()}".encode()
    r       = _put(key, content)
    assert r.status_code == 200, f"setup PUT failed: {r.status_code}"
    etag    = r.headers.get("ETag", "")
    return key, content, etag


def _s3_error_code(xml_text):
    """Parse the <Code> element from an S3 XML error body."""
    try:
        root = ET.fromstring(xml_text)
        code = root.findtext("Code") or root.findtext(f"{{{S3_NS}}}Code")
        return code or ""
    except ET.ParseError:
        return ""


# ---------------------------------------------------------------------------
# PutObject
# ---------------------------------------------------------------------------
