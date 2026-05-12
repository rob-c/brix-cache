"""
tests/test_http_webdav_lock.py

WebDAV LOCK and UNLOCK tests for the ngx_http_xrootd_webdav_module.
"""

import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

_PFX = "htlock_"


@pytest.fixture(scope="module", autouse=True)
def _base(test_env):
    global BASE
    BASE = test_env["http_webdav_url"]


def _url(path):
    return BASE + path


def _uid():
    return uuid.uuid4().hex[:12]


def _put(path, data=b"hello", **kw):
    return requests.put(_url(path), data=data, timeout=10, **kw)


def _get(path, **kw):
    return requests.get(_url(path), timeout=10, **kw)


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


class TestLock:
    def test_lock_new_file_201(self):
        path = f"/{_PFX}lock_{_uid()}.txt"
        r = _lock(path)
        assert r.status_code == 201
        assert "Lock-Token" in r.headers
        token = r.headers["Lock-Token"].strip("<>")
        assert "opaquelocktoken:" in token
        
        # Verify it shows up in PROPFIND
        r = _propfind(path)
        assert r.status_code == 207
        assert token in r.text
        assert "<D:lockdiscovery>" in r.text
        assert "<D:supportedlock>" in r.text

    def test_lock_refresh_200(self):
        path = f"/{_PFX}refresh_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]
        
        # Refresh using If header
        headers = {"If": f"({token})"}
        r = _lock(path, headers=headers, data="")
        assert r.status_code == 200

    def test_lock_enforcement_put_423(self):
        path = f"/{_PFX}locked_put_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        # PUT without lock token should fail
        r = _put(path, b"failed content")
        assert r.status_code == 423

        # PUT with lock token (in If header) should succeed
        headers = {"If": f"({token})"}
        r = _put(path, b"success content", headers=headers)
        assert r.status_code in (200, 201, 204)
        assert _get(path).content == b"success content"

    def test_lock_enforcement_delete_423(self):
        path = f"/{_PFX}locked_del_{_uid()}.txt"
        _put(path, b"content")
        r = _lock(path)
        token = r.headers["Lock-Token"]
        
        r = _delete(path)
        assert r.status_code == 423
        
        headers = {"If": f"({token})"}
        r = _delete(path, headers=headers)
        assert r.status_code == 204

    def test_unlock_204(self):
        path = f"/{_PFX}to_unlock_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]
        
        r = _unlock(path, token)
        assert r.status_code == 204
        
        # Verify PUT now succeeds without token
        r = _put(path, b"after unlock")
        assert r.status_code in (200, 201, 204)

    def test_lock_conflict_423(self):
        path = f"/{_PFX}conflict_{_uid()}.txt"
        _lock(path)
        
        # Second lock attempt from "someone else" (no If header)
        r = _lock(path)
        assert r.status_code == 423

    def test_lock_expiration(self):
        path = f"/{_PFX}expires_{_uid()}.txt"
        # 2 second timeout
        r = _lock(path, timeout=2)
        assert r.status_code == 201
        
        # Immediately should fail
        assert _put(path, b"too soon").status_code == 423
        
        # Wait for expiration
        time.sleep(3)
        
        # Should now succeed
        assert _put(path, b"expired").status_code in (200, 201, 204)
    def test_lock_depth_zero(self):
        """LOCK with Depth: 0 should only lock the directory, not its members."""
        dir_path = f"/{_PFX}depth0_{_uid()}"
        _mkcol(dir_path)
        
        # Lock the directory with Depth: 0
        r = _lock(dir_path, headers={"Depth": "0"})
        assert r.status_code == 201
        
        # Member should NOT be locked
        file_path = f"{dir_path}/member.txt"
        r = _put(file_path, b"member content")
        # Currently this will fail with 423 because all locks are infinity
        assert r.status_code == 201
        assert _get(file_path).content == b"member content"

    def test_lock_owner_from_body(self):
        """LOCK should extract owner from XML body if provided."""
        path = f"/{_PFX}owner_{_uid()}.txt"
        owner_href = "http://example.com/robot"
        body = (
            '<?xml version="1.0" encoding="utf-8" ?>'
            '<D:lockinfo xmlns:D="DAV:">'
            '<D:lockscope><D:exclusive/></D:lockscope>'
            '<D:locktype><D:write/></D:locktype>'
            f'<D:owner><D:href>{owner_href}</D:href></D:owner>'
            '</D:lockinfo>'
        )
        r = _lock(path, data=body)
        assert r.status_code == 201
        
        # Verify owner shows up in PROPFIND
        r = _propfind(path)
        assert r.status_code == 207
        assert owner_href in r.text
