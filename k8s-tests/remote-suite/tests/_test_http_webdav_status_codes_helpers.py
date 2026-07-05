# _test_http_webdav_status_codes_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_http_webdav_status_codes.py.  `from _test_http_webdav_status_codes_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""
tests/test_http_webdav_status_codes.py

Comprehensive HTTP status-code and RFC compliance tests for the plain-HTTP
WebDAV endpoint (port 8080, anonymous access, no TLS).

Tests assert RFC-correct behaviour directly; regressions must fail normally.

RFC compliance: all tested behaviours are now compliant.

Run:
    python3 -m pytest tests/test_http_webdav_status_codes.py -v
"""

import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import requests

_PFX = "htsc_"


@pytest.fixture(scope="module", autouse=True)
def _base(test_env):
    global BASE, LOG_DIR
    BASE = test_env["http_webdav_url"]
    LOG_DIR = Path(test_env["log_dir"])


def _url(path):
    return BASE + path


def _uid():
    return uuid.uuid4().hex[:12]


def _put(path, data=b"hello", **kw):
    return requests.put(_url(path), data=data, timeout=10, **kw)


def _get(path, **kw):
    return requests.get(_url(path), timeout=10, **kw)


def _head(path, **kw):
    return requests.head(_url(path), timeout=10, **kw)


def _delete(path, **kw):
    return requests.delete(_url(path), timeout=10, **kw)


def _mkcol(path, **kw):
    return requests.request("MKCOL", _url(path), timeout=10, **kw)


def _propfind(path, depth="1", body=None, **kw):
    if body is None:
        body = (
            '<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
        )
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "PROPFIND", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _proppatch(path, body, **kw):
    headers = {"Content-Type": "application/xml"}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "PROPPATCH", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _search(path, body, **kw):
    headers = {"Content-Type": "application/xml"}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "SEARCH", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _move(src, dst, overwrite="T", **kw):
    headers = {
        "Destination": BASE + dst,
        "Overwrite": overwrite,
    }
    headers.update(kw.pop("headers", {}))
    return requests.request("MOVE", _url(src), headers=headers, timeout=10, **kw)


def _copy(src, dst, overwrite="T", depth=None, **kw):
    headers = {
        "Destination": BASE + dst,
        "Overwrite": overwrite,
    }
    if depth is not None:
        headers["Depth"] = depth
    headers.update(kw.pop("headers", {}))
    return requests.request("COPY", _url(src), headers=headers, timeout=10, **kw)


def _lock(path, timeout=None, **kw):
    headers = {}
    if timeout:
        headers["Timeout"] = f"Second-{timeout}"
    headers.update(kw.pop("headers", {}))
    # Default exclusive write lock body if not provided
    body = kw.pop("data",
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<D:lockinfo xmlns:D="DAV:">'
        '<D:lockscope><D:exclusive/></D:lockscope>'
        '<D:locktype><D:write/></D:locktype>'
        '</D:lockinfo>'
    )
    return requests.request("LOCK", _url(path), data=body, headers=headers, timeout=10, **kw)


def _unlock(path, token, **kw):
    if not token.startswith("<"):
        token = f"<{token}>"
    headers = {"Lock-Token": token}
    headers.update(kw.pop("headers", {}))
    return requests.request("UNLOCK", _url(path), headers=headers, timeout=10, **kw)


def _existing_file():
    """Create a file in the server root and return (path, content, etag)."""
    path = f"/{_PFX}{_uid()}.txt"
    content = f"test content {_uid()}".encode()
    r = _put(path, content)
    assert r.status_code == 201, f"setup PUT failed: {r.status_code}"
    etag = r.headers.get("ETag", "")
    return path, content, etag


def _error_log_size():
    path = LOG_DIR / "error.log"
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _assert_error_log_contains_since(offset, needle):
    path = LOG_DIR / "error.log"
    for _ in range(20):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                if needle in fh.read():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    pytest.fail(f"expected {needle!r} in {path} after offset {offset}")


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------


__all__ = [n for n in dir() if not n.startswith('__')]
