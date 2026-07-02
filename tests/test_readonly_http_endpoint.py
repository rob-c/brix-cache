"""
tests/test_readonly_http_endpoint.py

Read-only ENDPOINT enforcement for the HTTP protocols (WebDAV + S3).

The native root:// read-only listener is covered by
test_privilege_escalation.py::TestReadOnlyServer (reads succeed AND every
mutating opcode is rejected).  The HTTP write-gate lives in
src/protocols/webdav/access.c (webdav_is_write_method && !allow_write -> 403) and
src/protocols/s3/handler.c (!allow_write -> 403 AccessDenied), but nothing exercised it
because every WebDAV/S3 server in the shared test config sets allow_write on.

This test stands up a dedicated nginx with WebDAV and S3 locations that OMIT
allow_write (so it defaults off = read-only) and asserts the full symmetric
contract on each protocol:

  * READ still works   — GET returns the seeded file content (200).
  * WRITE is disabled  — PUT / DELETE / MKCOL / MOVE / COPY -> 403.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_readonly_http_endpoint.py -v
"""

import http.client
import os
import socket
import uuid

import pytest

from settings import (
    READONLY_HTTP_DAV_PORT,
    READONLY_HTTP_DATA_ROOT,
    READONLY_HTTP_S3_PORT,
    SERVER_HOST,
)


def _reachable(host, port, timeout=1.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def readonly_http():
    """Connect to the dedicated READ-ONLY HTTP nginx pre-started by
    manage_test_servers.sh start-all (the "readonly-http" instance: a WebDAV
    server on READONLY_HTTP_DAV_PORT and an S3 server on READONLY_HTTP_S3_PORT,
    both with allow_write omitted so writes default off, serving
    READONLY_HTTP_DATA_ROOT).  Skips cleanly if that instance is not running.
    The server and this test share the local filesystem, so the seed/victim
    files written here are visible to the server and the test's assertions read
    the server's view of the same data root."""
    data = READONLY_HTTP_DATA_ROOT
    os.makedirs(data, exist_ok=True)
    # a seeded, readable file (and an existing victim for DELETE attempts)
    with open(os.path.join(data, "seed.txt"), "wb") as fh:
        fh.write(b"read-only-content")
    with open(os.path.join(data, "victim.txt"), "wb") as fh:
        fh.write(b"must-survive")

    if not (_reachable(SERVER_HOST, READONLY_HTTP_DAV_PORT, 3)
            and _reachable(SERVER_HOST, READONLY_HTTP_S3_PORT, 3)):
        pytest.skip(
            "dedicated read-only HTTP nginx not reachable on "
            f"{SERVER_HOST}:{READONLY_HTTP_DAV_PORT}/"
            f"{READONLY_HTTP_S3_PORT} — run "
            "tests/manage_test_servers.sh start-all")

    return {"data": data,
            "dav_port": READONLY_HTTP_DAV_PORT,
            "s3_port": READONLY_HTTP_S3_PORT}


def _req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(SERVER_HOST, port, timeout=8)
    try:
        conn.putrequest(method, path, skip_host=False, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# WebDAV read-only endpoint
# ---------------------------------------------------------------------------

class TestWebDavReadOnlyEndpoint:

    def test_get_still_works(self, readonly_http):
        st, body = _req(readonly_http["dav_port"], "GET", "/seed.txt")
        assert st == 200, f"read-only WebDAV GET should serve content, got {st}"
        assert body == b"read-only-content"

    def test_put_forbidden(self, readonly_http):
        st, _ = _req(readonly_http["dav_port"], "PUT",
                     f"/ro_put_{uuid.uuid4().hex}.txt", body=b"nope")
        assert st == 403, f"read-only WebDAV PUT must be 403, got {st}"

    def test_delete_forbidden_and_victim_survives(self, readonly_http):
        st, _ = _req(readonly_http["dav_port"], "DELETE", "/victim.txt")
        assert st == 403, f"read-only WebDAV DELETE must be 403, got {st}"
        assert os.path.exists(os.path.join(readonly_http["data"], "victim.txt"))

    def test_mkcol_forbidden(self, readonly_http):
        st, _ = _req(readonly_http["dav_port"], "MKCOL",
                     f"/ro_mkcol_{uuid.uuid4().hex}")
        assert st == 403, f"read-only WebDAV MKCOL must be 403, got {st}"

    def test_move_forbidden(self, readonly_http):
        st, _ = _req(readonly_http["dav_port"], "MOVE", "/seed.txt",
                     headers={"Destination": "/seed_moved.txt"})
        assert st == 403, f"read-only WebDAV MOVE must be 403, got {st}"

    def test_copy_forbidden(self, readonly_http):
        st, _ = _req(readonly_http["dav_port"], "COPY", "/seed.txt",
                     headers={"Destination": "/seed_copy.txt"})
        assert st == 403, f"read-only WebDAV COPY must be 403, got {st}"


# ---------------------------------------------------------------------------
# S3 read-only endpoint
# ---------------------------------------------------------------------------

class TestS3ReadOnlyEndpoint:

    BUCKET = "/testbucket"

    def test_get_still_works(self, readonly_http):
        st, body = _req(readonly_http["s3_port"], "GET", f"{self.BUCKET}/seed.txt")
        assert st == 200, f"read-only S3 GET should serve content, got {st}"
        assert body == b"read-only-content"

    def test_put_forbidden(self, readonly_http):
        st, _ = _req(readonly_http["s3_port"], "PUT",
                     f"{self.BUCKET}/ro_put_{uuid.uuid4().hex}.txt", body=b"nope")
        assert st == 403, f"read-only S3 PUT must be 403, got {st}"

    def test_delete_forbidden_and_victim_survives(self, readonly_http):
        st, _ = _req(readonly_http["s3_port"], "DELETE", f"{self.BUCKET}/victim.txt")
        assert st == 403, f"read-only S3 DELETE must be 403, got {st}"
        assert os.path.exists(os.path.join(readonly_http["data"], "victim.txt"))
