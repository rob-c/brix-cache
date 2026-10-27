"""Resource-complete authorization regressions for WebDAV LOCK and UNLOCK.

LOCK mutates resource metadata and may create a lock-null object.  UNLOCK
removes that metadata and may reap the placeholder.  These tests pin the
security boundary under bearer scopes and XrdAcc: mutation authority is
required before the server probes or changes the target, while a fully
authorized owner can still acquire, refresh, and release a lock.
"""

import pathlib

import pytest
import requests

from test_backend_async_webdav import _Server, _bearer, _have_nginx


pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-backend-async-webdav")]

LOCK_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<D:lockinfo xmlns:D="DAV:">'
    '<D:lockscope><D:exclusive/></D:lockscope>'
    '<D:locktype><D:write/></D:locktype>'
    '<D:owner>authorization-regression</D:owner>'
    '</D:lockinfo>'
)


@pytest.fixture()
def make_lock_server(lifecycle, tmp_path):
    """Build isolated token or XrdAcc WebDAV lock fixtures."""
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without BriX WebDAV")

    def _factory(**kwargs):
        kwargs.setdefault("wait", "30000ms")
        kwargs.setdefault("authz_backstop", "enforce")
        return _Server(lifecycle, tmp_path, **kwargs).start()

    return _factory


def _lock(srv, path, headers=None):
    """Acquire a write lock and return the response."""
    request_headers = {
        "Content-Type": "application/xml",
        "Timeout": "Second-3600",
    }
    if headers:
        request_headers.update(headers)
    return requests.request(
        "LOCK", f"{srv.base}/{path}", data=LOCK_BODY,
        headers=request_headers, verify=False, timeout=15)


def _unlock(srv, path, token, headers=None):
    """Release a lock using its opaque token and optional authorization."""
    request_headers = {"Lock-Token": token}
    if headers:
        request_headers.update(headers)
    return requests.request(
        "UNLOCK", f"{srv.base}/{path}", headers=request_headers,
        verify=False, timeout=15)


def _token(response):
    """Return the RFC 4918 Lock-Token response header."""
    token = response.headers.get("Lock-Token")
    assert token, f"LOCK response omitted Lock-Token: {response.status_code}"
    return token


def test_token_write_scope_locks_and_unlocks_existing_resource(make_lock_server):
    """Success: in-scope mutation authority preserves normal LOCK/UNLOCK."""
    srv = make_lock_server(token_auth=True)
    target = pathlib.Path(srv.data) / "authorized.txt"
    target.write_bytes(b"unchanged\n")
    token = srv.issuer.generate(scope="storage.modify:/authorized.txt")
    headers = _bearer(token)

    locked = _lock(srv, "authorized.txt", headers)
    assert locked.status_code in (200, 201), locked.text
    released = _unlock(srv, "authorized.txt", _token(locked), headers)

    assert released.status_code == 204, released.text
    assert target.read_bytes() == b"unchanged\n"


def test_token_write_scope_creates_and_reaps_lock_null_resource(make_lock_server):
    """Success: modify-only authority reserves and releases a missing name."""
    srv = make_lock_server(token_auth=True)
    target = pathlib.Path(srv.data) / "new-null.txt"
    token = srv.issuer.generate(scope="storage.modify:/new-null.txt")
    headers = _bearer(token)

    locked = _lock(srv, "new-null.txt", headers)
    assert locked.status_code == 201, locked.text
    assert target.exists()

    released = _unlock(srv, "new-null.txt", _token(locked), headers)
    assert released.status_code == 204, released.text
    assert not target.exists()


def test_lock_null_creation_respects_infinity_ancestor_lock(make_lock_server):
    """SECURITY-NEG: an ancestor lock blocks reservation of a missing child."""
    srv = make_lock_server(token_auth=True)
    parent = pathlib.Path(srv.data) / "locked-tree"
    parent.mkdir()
    token = srv.issuer.generate(scope="storage.modify:/locked-tree")
    headers = _bearer(token)
    parent_lock = _lock(srv, "locked-tree", headers)
    assert parent_lock.status_code in (200, 201), parent_lock.text

    denied = _lock(srv, "locked-tree/missing.txt", headers)

    assert denied.status_code == 423, denied.text
    assert not (parent / "missing.txt").exists()
    assert _unlock(srv, "locked-tree", _token(parent_lock),
                   headers).status_code == 204


def test_token_read_scope_cannot_create_lock_null_resource(make_lock_server):
    """SECURITY-NEG: denied LOCK creates neither metadata nor a placeholder."""
    srv = make_lock_server(token_auth=True)
    token = srv.issuer.generate(scope="storage.read:/reserved.txt")
    target = pathlib.Path(srv.data) / "reserved.txt"

    response = _lock(srv, "reserved.txt", _bearer(token))

    assert response.status_code == 403, response.text
    assert not target.exists()


def test_token_read_scope_cannot_unlock_with_valid_lock_token(make_lock_server):
    """SECURITY-NEG: a leaked lock token is insufficient mutation authority."""
    srv = make_lock_server(token_auth=True)
    target = pathlib.Path(srv.data) / "held.txt"
    target.write_bytes(b"held\n")
    writer = srv.issuer.generate(scope="storage.modify:/held.txt")
    reader = srv.issuer.generate(scope="storage.read:/held.txt")
    locked = _lock(srv, "held.txt", _bearer(writer))
    assert locked.status_code in (200, 201), locked.text
    lock_token = _token(locked)

    denied = _unlock(srv, "held.txt", lock_token, _bearer(reader))
    still_locked = _lock(srv, "held.txt", _bearer(writer))

    assert denied.status_code == 403, denied.text
    assert still_locked.status_code == 423, still_locked.text
    assert _unlock(srv, "held.txt", lock_token,
                   _bearer(writer)).status_code == 204


def test_xrdacc_read_only_rule_cannot_lock_existing_resource(make_lock_server):
    """Error: XrdAcc READ does not imply metadata mutation authority."""
    srv = make_lock_server(xrdacc_rules="u * /readonly.txt r\n")
    target = pathlib.Path(srv.data) / "readonly.txt"
    target.write_bytes(b"readonly\n")

    response = _lock(srv, "readonly.txt")

    assert response.status_code == 403, response.text
    assert target.read_bytes() == b"readonly\n"


def test_xrdacc_update_rule_locks_and_unlocks_resource(make_lock_server):
    """Control: XrdAcc READ+WRITE retains normal lock lifecycle behavior."""
    srv = make_lock_server(xrdacc_rules="u * /mutable.txt rw\n")
    target = pathlib.Path(srv.data) / "mutable.txt"
    target.write_bytes(b"mutable\n")

    locked = _lock(srv, "mutable.txt")
    assert locked.status_code in (200, 201), locked.text
    released = _unlock(srv, "mutable.txt", _token(locked))

    assert released.status_code == 204, released.text
    assert target.read_bytes() == b"mutable\n"
