"""
tests/test_webdav_unlock_ownership.py

Coverage gap #7 (test-coverage-gap-audit): WebDAV UNLOCK ownership boundary.

Only the UNLOCK-success path was tested.  The security-load-bearing branches in
src/protocols/webdav/lock.c (the CRYPTO_memcmp lock-token comparison that stops one client
stealing another's lock) had no negative test:

  * UNLOCK with a wrong/forged Lock-Token        → 409, and the lock SURVIVES
  * UNLOCK with no Lock-Token header              → 400
  * UNLOCK of a never-locked resource             → 409
  * (control) UNLOCK with the correct token       → 204

Runs against the dedicated WebDAV HTTP server pre-started by
manage_test_servers.sh start-all (the "webdav-unlock-ownership" instance, auth
none + brix_allow_write on, serving WEBDAV_UNLOCK_OWNERSHIP_DATA_ROOT);
the lock_server fixture just connects to it.  Locks are stored in user xattrs,
so the data dir must support them (the fixture probes for this and skips if not).
"""

import os
import socket
import uuid

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import (
    HOST,
    WEBDAV_UNLOCK_OWNERSHIP_DATA_ROOT,
    WEBDAV_UNLOCK_OWNERSHIP_PORT,
)

PORT = WEBDAV_UNLOCK_OWNERSHIP_PORT

LOCK_BODY = ('<?xml version="1.0" encoding="utf-8" ?>'
             '<D:lockinfo xmlns:D="DAV:">'
             '<D:lockscope><D:exclusive/></D:lockscope>'
             '<D:locktype><D:write/></D:locktype>'
             '<D:owner>tester</D:owner></D:lockinfo>')


def _reachable(host, port, timeout=3.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def lock_server():
    """Connect to the dedicated WebDAV HTTP server pre-started by
    manage_test_servers.sh start-all (the "webdav-unlock-ownership" instance,
    auth none + brix_allow_write on, serving
    WEBDAV_UNLOCK_OWNERSHIP_DATA_ROOT).  Skips cleanly if that dedicated
    instance is not running.  The server and this test share the local
    filesystem; the tests drive LOCK/UNLOCK/PUT through the server, which stores
    locks as user xattrs under the data root — so the fixture probes that the
    data fs supports xattrs and skips otherwise."""
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    data = WEBDAV_UNLOCK_OWNERSHIP_DATA_ROOT
    os.makedirs(data, exist_ok=True)
    if not _reachable(HOST, PORT, 3):
        pytest.skip(
            f"dedicated webdav-unlock-ownership nginx not reachable on "
            f"{HOST}:{PORT} — run tests/manage_test_servers.sh start-all")

    # Verify the data fs supports user xattrs (locks live there).
    probe = os.path.join(data, ".xprobe")
    with open(probe, "w") as f:
        f.write("x")
    try:
        os.setxattr(probe, "user.test", b"1")
    except OSError:
        pytest.skip("data filesystem does not support user xattrs (needed for WebDAV locks)")
    finally:
        os.unlink(probe)


def _url(p):
    return f"http://{HOST}:{PORT}{p}"


def _lock(path):
    return requests.request("LOCK", _url(path), data=LOCK_BODY,
                            headers={"Timeout": "Second-3600"}, timeout=10)


def _unlock(path, token=None):
    headers = {}
    if token is not None:
        headers["Lock-Token"] = token if token.startswith("<") else f"<{token}>"
    return requests.request("UNLOCK", _url(path), headers=headers, timeout=10)


def _new_locked_file():
    path = f"/unlk_{uuid.uuid4().hex}.txt"
    r = _lock(path)
    assert r.status_code in (200, 201), f"LOCK setup failed: {r.status_code}"
    assert "Lock-Token" in r.headers, "LOCK did not return a Lock-Token"
    return path, r.headers["Lock-Token"].strip("<>")


FORGED = "opaquelocktoken:00000000-0000-0000-0000-000000000000"


def test_unlock_correct_token_succeeds(lock_server):
    path, token = _new_locked_file()
    assert _unlock(path, token).status_code == 204, \
        "UNLOCK with the correct token must succeed (204)"


def test_unlock_wrong_token_rejected_and_lock_survives(lock_server):
    path, token = _new_locked_file()
    # A forged/other token must NOT release someone else's lock.
    assert _unlock(path, FORGED).status_code == 409, \
        "UNLOCK with a forged token must be rejected (409)"
    # The lock must still be held — the correct token still releases it.
    assert _unlock(path, token).status_code == 204, \
        "the lock must survive a wrong-token UNLOCK attempt"


def test_unlock_garbage_token_rejected_and_lock_survives(lock_server):
    path, token = _new_locked_file()
    assert _unlock(path, "garbage-not-a-token").status_code in (400, 409), \
        "UNLOCK with a garbage token must be rejected"
    assert _unlock(path, token).status_code == 204, \
        "the lock must survive a garbage-token UNLOCK attempt"


def test_unlock_no_lock_token_header_400(lock_server):
    path, token = _new_locked_file()
    assert _unlock(path, token=None).status_code == 400, \
        "UNLOCK with no Lock-Token header must be 400"
    _unlock(path, token)  # cleanup


def test_unlock_never_locked_resource_409(lock_server):
    path = f"/never_locked_{uuid.uuid4().hex}.txt"
    requests.put(_url(path), data=b"x", timeout=10)
    assert _unlock(path, FORGED).status_code == 409, \
        "UNLOCK of a never-locked resource must be 409"
