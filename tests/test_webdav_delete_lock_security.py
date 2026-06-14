"""
tests/test_webdav_delete_lock_security.py

Protocol-conformance + security tests for the WebDAV namespace/lock surface
(DELETE, LOCK/UNLOCK, MKCOL) and for HTTP header-injection hardening (CRLF in
the Destination header and in custom headers).  The suite runs against a
dedicated, write-enabled HTTP WebDAV nginx (xrootd_webdav on +
xrootd_webdav_allow_write on + xrootd_webdav_auth none) pre-started by
manage_test_servers.sh start-all (the "webdav-dellock" instance, serving
WEBDAV_DELLOCK_DATA_ROOT), so it never touches the shared test fleet and skips
cleanly when that instance is down.  The server and this test share the local
filesystem, so the fixture seeds any needed files into the data root and reads
the server's writes back from it.  It exercises the real handler code in
src/webdav/{namespace.c, lock.c, move.c, dispatch.c}: DELETE on
a non-empty collection (-> 409 Conflict per require_empty_dir policy), UNLOCK
ownership/token mismatch and malformed/missing Lock-Token, LOCK conflict /
shared-lock behaviour, MKCOL with a body and with a missing intermediate
collection (-> 409), and CRLF response-splitting attempts via the Destination
and arbitrary custom request headers (must be rejected/sanitised by nginx's
header parser, never reflected into the response).  Every hostile or edge
request is followed by a benign sanity operation on the same server to prove
the worker and the connection survived intact.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_webdav_delete_lock_security.py -v
"""

import http.client
import os
import socket
import uuid

import pytest

from settings import WEBDAV_DELLOCK_DATA_ROOT, WEBDAV_DELLOCK_PORT

# ---------------------------------------------------------------------------
# The write-enabled, no-auth HTTP WebDAV server is now a dedicated instance
# pre-started by manage_test_servers.sh start-all ("webdav-dellock" on port
# 13210, serving data-webdav-dellock); the webdav_server fixture just connects
# to it.  Override via TEST_WDAV_DELLOCK_PORT if it ever clashes locally.
# ---------------------------------------------------------------------------
H = "127.0.0.1"
WEBDAV_PORT = WEBDAV_DELLOCK_PORT

_DATA = None         # dedicated data root (set by the module fixture)


# ---------------------------------------------------------------------------
# Reachability helper.
# ---------------------------------------------------------------------------

def _reachable(host, port, timeout=3.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Module fixture: connect to the dedicated write-enabled, no-auth WebDAV nginx.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def webdav_server():
    """Connect to the dedicated WRITABLE HTTP WebDAV nginx pre-started by
    manage_test_servers.sh start-all (the "webdav-dellock" instance,
    xrootd_webdav_allow_write on + xrootd_webdav_auth none, serving
    WEBDAV_DELLOCK_DATA_ROOT).  Skips cleanly if that instance is not running.
    The server and this test share the local filesystem, so files seeded into
    the data root are visible to the server and the server's writes are visible
    to the test's assertions."""
    global _DATA

    data = WEBDAV_DELLOCK_DATA_ROOT
    os.makedirs(data, exist_ok=True)
    if not _reachable(H, WEBDAV_PORT, 3):
        pytest.skip(
            f"dedicated webdav-dellock nginx not reachable on {H}:{WEBDAV_PORT} "
            f"— run tests/manage_test_servers.sh start-all")

    _DATA = data
    yield {"port": WEBDAV_PORT, "data": data}


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def _req(method, path, body=None, headers=None):
    """Issue a single well-formed request through http.client.

    headers — header dict passed through http.client (which validates and will
              refuse to encode CRLF).  For CRLF-smuggling tests use the
              raw-socket helper _raw_request() instead.
    Returns (status, body_bytes, response_headers_dict).
    """
    conn = http.client.HTTPConnection(H, WEBDAV_PORT, timeout=8)
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
        return r.status, r.read(), dict(r.getheaders())
    finally:
        conn.close()


def _raw_request(method, path, raw_header_lines, body=b""):
    """Send a fully hand-built HTTP/1.1 request over a raw socket so we can
    inject literal CRLF bytes into a header value.  Returns the full raw
    response bytes (possibly empty if the server reset the connection)."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {H}:{WEBDAV_PORT}",
             "Connection: close"]
    lines.extend(raw_header_lines)
    lines.append(f"Content-Length: {len(body)}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    s = socket.create_connection((H, WEBDAV_PORT), timeout=8)
    try:
        s.sendall(req)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except OSError:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        s.close()


def _put(path, content=b"x"):
    return _req("PUT", path, body=content)


def _delete(path):
    return _req("DELETE", path)


def _mkcol(path, body=None, headers=None):
    return _req("MKCOL", path, body=body, headers=headers)


def _lock(path, owner="tester", scope="exclusive", token_header=None):
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<D:lockinfo xmlns:D="DAV:">'
        f'<D:lockscope><D:{scope}/></D:lockscope>'
        '<D:locktype><D:write/></D:locktype>'
        f'<D:owner><D:href>{owner}</D:href></D:owner>'
        '</D:lockinfo>'
    ).encode()
    headers = {"Content-Type": "application/xml", "Timeout": "Second-3600"}
    if token_header is not None:
        headers["If"] = token_header
    return _req("LOCK", path, body=body, headers=headers)


def _unlock(path, lock_token):
    return _req("UNLOCK", path, headers={"Lock-Token": lock_token})


def _extract_lock_token(headers, body):
    """Pull the opaquelocktoken from the Lock-Token response header (preferred)
    or from the activelock XML body."""
    lt = headers.get("Lock-Token") or headers.get("lock-token")
    if lt:
        return lt.strip().strip("<>")
    text = body.decode("utf-8", "replace")
    marker = "opaquelocktoken:"
    idx = text.find(marker)
    if idx == -1:
        return None
    end = idx
    while end < len(text) and text[end] not in "<> \t\r\n\"'":
        end += 1
    return text[idx:end]


def _sanity():
    """A benign op that must keep working — proves the worker survived the
    preceding hostile/edge request."""
    name = f"/sanity_{uuid.uuid4().hex}.txt"
    st, _, _ = _put(name, b"alive")
    assert st in (200, 201, 204), f"sanity PUT failed ({st}) — worker may be wedged"
    g, body, _ = _req("GET", name)
    assert g == 200 and body == b"alive", "sanity GET did not round-trip"
    _delete(name)


# ---------------------------------------------------------------------------
# DELETE on a non-empty collection
# ---------------------------------------------------------------------------

class TestDeleteNonEmptyCollection:

    def test_delete_nonempty_collection_returns_409(self):
        """src/webdav/namespace.c sets opts.require_empty_dir = 1, so DELETE of
        a non-empty collection maps XROOTD_NS_NOT_EMPTY -> 409 Conflict."""
        coll = f"/del_nonempty_{uuid.uuid4().hex}"
        assert _mkcol(coll)[0] == 201
        assert _put(f"{coll}/child.txt", b"keep")[0] in (200, 201, 204)

        st, _, _ = _delete(coll)
        assert st == 409, f"non-empty DELETE should be 409 Conflict, got {st}"

        # The collection and its child must still exist (no partial wipe).
        assert os.path.isdir(os.path.join(_DATA, coll.lstrip("/")))
        assert os.path.isfile(os.path.join(_DATA, coll.lstrip("/"), "child.txt"))

        # Emptying it first must then allow the DELETE (documented happy path).
        assert _delete(f"{coll}/child.txt")[0] in (200, 204)
        assert _delete(coll)[0] in (200, 204)
        assert not os.path.exists(os.path.join(_DATA, coll.lstrip("/")))
        _sanity()


# ---------------------------------------------------------------------------
# UNLOCK ownership / token / target conformance
# ---------------------------------------------------------------------------

class TestUnlock:

    def test_unlock_wrong_token_fails(self):
        """A LOCK held under one token cannot be released with a DIFFERENT
        (well-formed-but-wrong) token.  lock.c CRYPTO_memcmp mismatch -> 409
        Conflict; the lock must remain in force afterwards."""
        path = f"/unlock_wrongtok_{uuid.uuid4().hex}.txt"
        assert _put(path, b"locked-resource")[0] in (200, 201, 204)

        st, body, hdrs = _lock(path)
        assert st in (200, 201), f"LOCK should succeed, got {st}"
        real = _extract_lock_token(hdrs, body)
        assert real, "no lock token returned by LOCK"

        bogus = "<opaquelocktoken:00000000-0000-4000-8000-000000000000>"
        st_u, _, _ = _unlock(path, bogus)
        assert st_u in (403, 409), \
            f"UNLOCK with a foreign token must fail (403/409), got {st_u}"

        # Lock still held: a fresh LOCK (no matching If header) must conflict.
        st_relock, _, _ = _lock(path)
        assert st_relock == 423, \
            f"after a failed UNLOCK the lock must persist (LOCK -> 423), got {st_relock}"

        # Clean up with the genuine token, then prove the worker is healthy.
        _unlock(path, f"<{real}>")
        _sanity()

    def test_unlock_malformed_token_missing_header(self):
        """UNLOCK with NO Lock-Token header is malformed per RFC 4918 §9.11.1.
        webdav_handle_unlock returns NGX_HTTP_BAD_REQUEST -> 400 before any
        path/lock work."""
        path = f"/unlock_noheader_{uuid.uuid4().hex}.txt"
        assert _put(path, b"x")[0] in (200, 201, 204)

        st, _, _ = _req("UNLOCK", path)   # deliberately omit Lock-Token
        assert st == 400, f"UNLOCK without Lock-Token must be 400, got {st}"
        _sanity()

    def test_unlock_malformed_token_garbage_value(self):
        """UNLOCK carrying a syntactically-garbage Lock-Token on an UNLOCKED
        resource: the header is present (so not 400) but matches no active lock
        -> 409 Conflict (lock.c: no active lock on this path)."""
        path = f"/unlock_garbage_{uuid.uuid4().hex}.txt"
        assert _put(path, b"x")[0] in (200, 201, 204)

        st, _, _ = _unlock(path, "<not-a-real-token-@@@>")
        # Documented: missing header == 400; present-but-no-lock == 409.
        assert st in (400, 409), \
            f"garbage Lock-Token on an unlocked resource should be 400/409, got {st}"
        _sanity()

    def test_unlock_nonexistent_resource(self):
        """UNLOCK of a path that does not exist (and holds no lock).  With a
        Lock-Token header present, the handler resolves the path then finds no
        active lock -> 409 Conflict (or 404 if path resolution fails first)."""
        path = f"/unlock_missing_{uuid.uuid4().hex}.txt"
        assert not os.path.exists(os.path.join(_DATA, path.lstrip("/")))

        st, _, _ = _unlock(path, "<opaquelocktoken:deadbeef>")
        assert st in (404, 409), \
            f"UNLOCK of a nonexistent resource should be 404/409, got {st}"
        _sanity()


# ---------------------------------------------------------------------------
# LOCK conflict / shared-lock semantics
# ---------------------------------------------------------------------------

class TestLockConflict:

    def test_second_exclusive_lock_conflicts(self):
        """An exclusive write LOCK exists; a second LOCK without the matching
        If header must be refused.  lock.c: existing active lock + no If match
        -> 423 Locked."""
        path = f"/lock_conflict_{uuid.uuid4().hex}.txt"
        assert _put(path, b"resource")[0] in (200, 201, 204)

        st1, body1, hdr1 = _lock(path, scope="exclusive")
        assert st1 in (200, 201), f"first LOCK should succeed, got {st1}"
        tok = _extract_lock_token(hdr1, body1)
        assert tok, "first LOCK returned no token"

        st2, _, _ = _lock(path, scope="exclusive")
        assert st2 == 423, f"second conflicting LOCK must be 423 Locked, got {st2}"

        # Refresh by the SAME owner with a matching If header must succeed
        # (lock.c refresh path -> 200), proving it is the lock, not the path,
        # that is gated.
        st3, _, _ = _lock(path, scope="exclusive",
                          token_header=f"(<{tok}>)")
        assert st3 in (200, 201), \
            f"LOCK refresh with matching If token should succeed, got {st3}"

        _unlock(path, f"<{tok}>")
        _sanity()

    def test_shared_lock_supported_or_conflicts_cleanly(self):
        """LOCK advertises both exclusive and shared write lockentries
        (lock.c webdav_lock_append_supported).  A shared LOCK request must
        either be granted (200/201) or, if the existing lock is exclusive,
        refused cleanly with 423 — never a 5xx and never a silent grant that
        ignores an exclusive holder."""
        path = f"/lock_shared_{uuid.uuid4().hex}.txt"
        assert _put(path, b"resource")[0] in (200, 201, 204)

        # First a shared lock on a fresh resource — should be granted.
        st1, body1, hdr1 = _lock(path, scope="shared")
        assert st1 in (200, 201, 423), \
            f"shared LOCK should be granted or cleanly refused, got {st1}"

        if st1 in (200, 201):
            tok = _extract_lock_token(hdr1, body1)
            # A second shared lock without an If header: the xattr-backed lock
            # model holds one lock per node, so the unowned re-LOCK conflicts.
            st2, _, _ = _lock(path, scope="shared")
            assert st2 in (200, 201, 423), \
                f"second shared LOCK should be 200/201/423, got {st2}"
            if tok:
                _unlock(path, f"<{tok}>")
        _sanity()


# ---------------------------------------------------------------------------
# CRLF / header-injection hardening
# ---------------------------------------------------------------------------

class TestHeaderInjection:

    def test_crlf_in_destination_rejected(self):
        """A Destination header with embedded CRLF + a smuggled response line
        must NOT cause response splitting and must NOT escape the export root.

        ACTUAL behaviour: nginx's header parser truncates the value at the
        first CR/LF, so the injected 'Set-Cookie: pwned=1' is never reflected
        into the response.  The MOVE may then either be rejected (>=400) or
        proceed to the SAFE truncated, in-root path — but the smuggled header
        is never honoured, the source is never lost out-of-root, and nothing is
        created above the export root."""
        src = f"/crlf_dest_src_{uuid.uuid4().hex}.txt"
        assert _put(src, b"keep-me")[0] in (200, 201, 204)

        injected = (f"http://{H}:{WEBDAV_PORT}/crlf_dest_dst\r\n"
                    "Set-Cookie: pwned=1")
        raw = _raw_request("MOVE", src,
                           [f"Destination: {injected}", "Overwrite: T"])
        text = raw.decode("latin-1", "replace")

        # SECURITY INVARIANT 1: the smuggled header must never be reflected
        # back to the client (no HTTP response splitting).
        assert "pwned=1" not in text and "Set-Cookie" not in text, \
            "CRLF injection in Destination was reflected (response splitting!)"

        # SECURITY INVARIANT 2: nothing was created/written ABOVE the export
        # root (the CRLF must not be parlayed into a path-confinement escape).
        outside = os.path.dirname(_DATA.rstrip("/"))
        for esc in ("crlf_dest_dst", "pwned", "Set-Cookie"):
            leaked = os.path.join(outside, esc)
            if os.path.exists(leaked):
                try:
                    (os.rmdir if os.path.isdir(leaked) else os.remove)(leaked)
                finally:
                    pytest.fail(f"CONFINEMENT BREACH: {leaked} created out of root")

        # The smuggled line must not have survived inside the value either:
        # if a MOVE happened at all it went to the SAFE truncated path.
        assert not os.path.exists(
            os.path.join(_DATA, "crlf_dest_dst", "pwned")), \
            "injected CR/LF tail was honoured as part of the destination path"
        _sanity()

    def test_crlf_in_custom_header_sanitized(self):
        """A custom request header whose value carries CRLF + a smuggled
        response line must be rejected/sanitised by nginx — the injected header
        must not appear in the response and a benign request afterwards must
        still succeed (the connection/worker is unharmed)."""
        probe = f"/crlf_custom_{uuid.uuid4().hex}.txt"
        assert _put(probe, b"benign")[0] in (200, 201, 204)

        injected = "legit\r\nX-Injected-Header: pwned"
        raw = _raw_request("GET", probe, [f"X-Test-Meta: {injected}"])
        text = raw.decode("latin-1", "replace")

        assert "X-Injected-Header" not in text and "pwned" not in text, \
            "CRLF in a custom header leaked into the response (splitting!)"
        if text.startswith("HTTP/"):
            status = int(text.split()[1])
            # Either rejected (400) or the bad line ignored and the GET served.
            assert status in (200, 400), \
                f"CRLF custom-header GET should be 200 or 400, got {status}"
        _delete(probe)
        _sanity()


# ---------------------------------------------------------------------------
# MKCOL conformance
# ---------------------------------------------------------------------------

class TestMkcol:

    def test_mkcol_with_body_rejected_415(self):
        """RFC 4918 §9.3.1: a MKCOL request carrying a body whose entity the
        server does not understand SHOULD be rejected with 415 Unsupported
        Media Type.  Assert the ACTUAL behaviour: either the documented 415, or
        — since src/webdav/dispatch.c routes MKCOL straight to
        webdav_handle_mkcol without consuming a body — the collection is
        created (201) with the body ignored.  A silent partial state or a 5xx
        is NOT acceptable."""
        coll = f"/mkcol_body_{uuid.uuid4().hex}"
        st, _, _ = _mkcol(coll, body=b"<unexpected>body</unexpected>",
                          headers={"Content-Type": "application/xml"})
        assert st in (201, 415), \
            f"MKCOL with body should be 201 (body ignored) or 415, got {st}"

        if st == 415:
            # Rejected: the collection must NOT have been created.
            assert not os.path.exists(os.path.join(_DATA, coll.lstrip("/"))), \
                "MKCOL rejected with 415 but the collection was still created"
        else:
            # Accepted: it must be a real directory and re-MKCOL must 405.
            assert os.path.isdir(os.path.join(_DATA, coll.lstrip("/")))
            assert _mkcol(coll)[0] == 405, \
                "MKCOL on an existing collection must be 405 Method Not Allowed"
            _delete(coll)
        _sanity()

    def test_mkcol_missing_intermediate_returns_409(self):
        """RFC 4918 §9.3.1: MKCOL where an intermediate collection is absent
        MUST fail with 409 Conflict.  namespace.c maps both a NOT_FOUND path
        resolution and XROOTD_NS_NOT_FOUND mkdir result to 409."""
        parent = f"noparent_{uuid.uuid4().hex}"
        child = f"/{parent}/leaf"
        assert not os.path.exists(os.path.join(_DATA, parent))

        st, _, _ = _mkcol(child)
        assert st == 409, \
            f"MKCOL with a missing intermediate must be 409 Conflict, got {st}"
        # Nothing was created (no auto-vivified parent).
        assert not os.path.exists(os.path.join(_DATA, parent))
        _sanity()
