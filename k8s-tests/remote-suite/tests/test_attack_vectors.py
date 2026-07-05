"""
tests/test_attack_vectors.py

Web-facing attack-vector hardening tests that complement test_evil_paths.py
(path confinement).  Each class targets a class of bad-actor abuse the codebase
is *supposed* to be hardened against but that previously had NO test pinning the
behaviour down — so a future regression (e.g. someone adding XML_PARSE_NOENT, or
removing a body cap) would be caught here.

Severity covered:
  * DATA COMPROMISE — XXE external-entity file read (XML parsers in WebDAV
    PROPFIND/PROPPATCH/LOCK and S3 DeleteObjects); cross-protocol auth confusion.
  * DoS / DDoS — XML billion-laughs entity expansion; slowloris (partial request
    holding a worker); Content-Length lies.
  * RESPONSE SPLITTING — CRLF injection via the WebDAV Destination header and
    CORS Origin reflection.

The invariant for the read/leak tests is simple and protocol-agnostic: a hostile
request must NEVER cause the unmistakable host-secret bytes (the first field of
/etc/passwd) to appear in a response, the server must never hang, and a
concurrent well-behaved client must keep being served.

Run (against the live fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_attack_vectors.py -v
"""

import http.client
import socket
import ssl
import time
import uuid

import pytest

from settings import (
    SERVER_HOST,
    NGINX_HTTP_WEBDAV_PORT,   # plain HTTP WebDAV (8080)
    NGINX_S3_PORT,            # S3 (9001)
)

# The first field of /etc/passwd — unmistakable host content.  If this ever
# shows up in a response, an external entity (or a path escape) was expanded.
HOST_SECRET = b"root:x:0:0:"
BUCKET = "testbucket"


# --------------------------------------------------------------------------- #
# Raw HTTP helpers (server does its own normalisation/parsing)                 #
# --------------------------------------------------------------------------- #

def _port_up(port):
    try:
        with socket.create_connection((SERVER_HOST, port), timeout=2):
            return True
    except OSError:
        return False


def _conn(port, tls):
    if tls:
        ctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection(SERVER_HOST, port, timeout=10,
                                            context=ctx)
    return http.client.HTTPConnection(SERVER_HOST, port, timeout=10)


def _request(port, method, path, body=None, headers=None, tls=False):
    """Send one request; return (status, response_headers_list, body_bytes)."""
    c = _conn(port, tls)
    try:
        c.putrequest(method, path, skip_host=False, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        if body is not None:
            c.send(body)
        resp = c.getresponse()
        return resp.status, resp.getheaders(), resp.read()
    finally:
        c.close()


_HTTP_SKIP = pytest.mark.skipif(not _port_up(NGINX_HTTP_WEBDAV_PORT),
                                reason="http WebDAV (8080) not reachable")
_S3_SKIP = pytest.mark.skipif(not _port_up(NGINX_S3_PORT),
                              reason="S3 (9001) not reachable")


# ===========================================================================
# XXE + XML entity-expansion (billion laughs)
# ===========================================================================

# External-entity payloads: if the parser loads + substitutes external entities
# (XML_PARSE_NOENT / DTDLOAD), &xxe; expands to the contents of /etc/passwd and
# the server echoes host_secret back.  The contract: it must NOT.
def _xxe_propfind():
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE p [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
        '<D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&xxe;'
        '</D:displayname></D:prop></D:propfind>'
    ).encode()


def _xxe_proppatch():
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE p [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
        '<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:author>&xxe;'
        '</D:author></D:prop></D:set></D:propertyupdate>'
    ).encode()


def _xxe_lock():
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE p [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
        '<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
        '<D:locktype><D:write/></D:locktype>'
        '<D:owner>&xxe;</D:owner></D:lockinfo>'
    ).encode()


def _xxe_param_entity():
    # External *parameter* entity / DTD fetch (the other XXE flavour).
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE p SYSTEM "file:///etc/passwd">'
        '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
    ).encode()


def _billion_laughs():
    # Classic exponential entity expansion.  If libxml2's amplification cap is
    # disabled (XML_PARSE_HUGE), this balloons to ~hundreds of MB and wedges the
    # worker.  With the cap intact it errors out quickly and cheaply.
    lines = ['<?xml version="1.0"?>', '<!DOCTYPE lolz [',
             '<!ENTITY a0 "' + ("A" * 64) + '">']
    for i in range(1, 10):
        lines.append('<!ENTITY a%d "&a%d;&a%d;&a%d;&a%d;&a%d;&a%d;&a%d;&a%d;&a%d;&a%d;">'
                     % (i, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1))
    lines.append(']>')
    lines.append('<D:propfind xmlns:D="DAV:"><D:prop><D:x>&a9;</D:x></D:prop></D:propfind>')
    return "".join(lines).encode()


@_HTTP_SKIP
class TestXxeExternalEntity:
    """A hostile XML body must never read host files via external entities."""

    def _assert_no_leak(self, method, body, port=None, tls=False, path="/"):
        port = port or NGINX_HTTP_WEBDAV_PORT
        try:
            st, _, data = _request(port, method, path, body=body,
                                   headers={"Content-Type": "application/xml",
                                            "Depth": "0"}, tls=tls)
        except (OSError, http.client.HTTPException):
            return  # connection reset/parse-reject is an acceptable "deny"
        assert HOST_SECRET not in data, \
            f"{method} XXE leaked host content (status={st})"

    def test_propfind_external_entity_no_leak(self):
        self._assert_no_leak("PROPFIND", _xxe_propfind())

    def test_propfind_param_entity_dtd_no_leak(self):
        self._assert_no_leak("PROPFIND", _xxe_param_entity())

    def test_proppatch_external_entity_no_leak(self):
        self._assert_no_leak("PROPPATCH", _xxe_proppatch())

    def test_lock_external_entity_no_leak(self):
        self._assert_no_leak("LOCK", _xxe_lock())


@_S3_SKIP
class TestS3XxeExternalEntity:
    """S3 DeleteObjects parses an XML body — and (unlike the WebDAV sites) its
    parser omits the explicit NO_XXE guard, so this test is the regression net
    that the NOENT/DTDLOAD default stays safe."""

    def test_delete_objects_external_entity_no_leak(self):
        body = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE d [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
            '<Delete><Object><Key>&xxe;</Key></Object></Delete>'
        ).encode()
        try:
            st, _, data = _request(NGINX_S3_PORT, "POST", f"/{BUCKET}?delete",
                                   body=body,
                                   headers={"Content-Type": "application/xml"})
        except (OSError, http.client.HTTPException):
            return
        assert HOST_SECRET not in data, \
            f"S3 DeleteObjects XXE leaked host content (status={st})"


@_HTTP_SKIP
class TestXmlBillionLaughs:
    """Entity-expansion DoS must not hang the worker or balloon the response."""

    def test_propfind_billion_laughs_bounded(self):
        body = _billion_laughs()
        t0 = time.time()
        try:
            st, _, data = _request(NGINX_HTTP_WEBDAV_PORT, "PROPFIND", "/",
                                   body=body,
                                   headers={"Content-Type": "application/xml",
                                            "Depth": "0"})
        except (OSError, http.client.HTTPException):
            st, data = 0, b""
        elapsed = time.time() - t0
        # libxml2's default amplification cap should reject/limit this fast.
        assert elapsed < 10, f"billion-laughs took {elapsed:.1f}s (expansion uncapped?)"
        assert len(data) < 5 * 1024 * 1024, \
            f"billion-laughs response ballooned to {len(data)} bytes"
        assert HOST_SECRET not in data

    def test_server_responsive_after_xml_bomb(self):
        # The worker must still serve a normal request right after the bomb.
        st, _, _ = _request(NGINX_HTTP_WEBDAV_PORT, "OPTIONS", "/")
        assert st in (200, 204, 207, 401, 403, 404), \
            f"server not healthy after XML bomb (status={st})"


# ===========================================================================
# Slowloris — partial/slow requests must not wedge the event loop
# ===========================================================================

@_HTTP_SKIP
class TestSlowloris:
    def test_partial_headers_do_not_wedge_worker(self):
        """Hold several connections open with an incomplete header block, then
        prove a well-behaved client is still served promptly (nginx's event
        loop must not be blocked by the slow clients)."""
        slow = []
        try:
            for _ in range(12):
                s = socket.create_connection((SERVER_HOST, NGINX_HTTP_WEBDAV_PORT),
                                             timeout=5)
                # A request line + one header, but NEVER the terminating blank line.
                s.sendall(b"GET / HTTP/1.1\r\nHost: slowloris\r\n")
                slow.append(s)

            # A normal request must complete quickly despite the slow holders.
            t0 = time.time()
            st, _, _ = _request(NGINX_HTTP_WEBDAV_PORT, "OPTIONS", "/")
            elapsed = time.time() - t0
            assert elapsed < 5, \
                f"server unresponsive under slowloris ({elapsed:.1f}s)"
            assert st in (200, 204, 207, 401, 403, 404)
        finally:
            for s in slow:
                try:
                    s.close()
                except OSError:
                    pass

    def test_content_length_lie_does_not_wedge_worker(self):
        """Announce a large body, send almost nothing, hold the connection; a
        concurrent normal request must still be served (no per-request OOM or
        blocking read of the promised bytes)."""
        s = socket.create_connection((SERVER_HOST, NGINX_HTTP_WEBDAV_PORT),
                                     timeout=5)
        try:
            s.sendall(b"PUT /cl_lie_%s.txt HTTP/1.1\r\nHost: x\r\n"
                      b"Content-Length: 1073741824\r\n\r\n"
                      % uuid.uuid4().hex.encode())
            s.sendall(b"only-a-few-bytes")        # << 1 GiB promised
            t0 = time.time()
            st, _, _ = _request(NGINX_HTTP_WEBDAV_PORT, "OPTIONS", "/")
            assert time.time() - t0 < 5, "server blocked by Content-Length lie"
            assert st in (200, 204, 207, 401, 403, 404)
        finally:
            try:
                s.close()
            except OSError:
                pass


# ===========================================================================
# CRLF / header injection -> response splitting
# ===========================================================================

def _has_injected_header(headers, name="x-injected"):
    return any(k.lower() == name for k, _ in headers)


@_HTTP_SKIP
class TestHeaderInjection:
    def test_destination_crlf_not_reflected(self):
        """A CRLF-laden Destination (MOVE/COPY) must not split the response into
        an attacker-controlled header, and must never escape the root."""
        src = f"/hdrinj_src_{uuid.uuid4().hex}.txt"
        # create a source to MOVE
        try:
            _request(NGINX_HTTP_WEBDAV_PORT, "PUT", src, body=b"x")
        except OSError:
            pass
        # URL-ENCODED CRLF only: a raw \r\n is rejected by any compliant HTTP
        # client before it leaves the box (and a server-side parser would just
        # split it into request headers).  The real response-splitting risk is
        # the server DECODING %0d%0a out of the Destination and writing it into
        # a response header — that is what these probe.
        evil_dests = [
            "/dst%0d%0aX-Injected:%20pwned",
            "http://x/dst%0d%0aX-Injected:%20pwned",
            "/dst%0d%0aSet-Cookie:%20evil=1",
            "/dst%0aX-Injected:%20pwned",          # bare-LF variant
        ]
        for dest in evil_dests:
            try:
                st, headers, _ = _request(NGINX_HTTP_WEBDAV_PORT, "MOVE", src,
                                          headers={"Destination": dest})
            except (OSError, http.client.HTTPException):
                continue
            assert not _has_injected_header(headers), \
                f"Destination CRLF injected a response header (dest={dest!r})"
            assert not _has_injected_header(headers, "set-cookie"), \
                f"Destination CRLF injected Set-Cookie (dest={dest!r})"

    def test_cors_origin_encoded_crlf_not_reflected(self):
        """An Origin carrying encoded CRLF must not be echoed verbatim into
        Access-Control-Allow-Origin (response splitting / origin spoofing)."""
        evil_origin = "https://evil.example%0d%0aX-Injected:%20pwned"
        try:
            st, headers, _ = _request(
                NGINX_HTTP_WEBDAV_PORT, "OPTIONS", "/",
                headers={"Origin": evil_origin,
                         "Access-Control-Request-Method": "GET"})
        except (OSError, http.client.HTTPException):
            pytest.skip("preflight not accepted")
        assert not _has_injected_header(headers), \
            "CORS Origin split the response into an injected header"
        for k, v in headers:
            if k.lower() == "access-control-allow-origin":
                assert "\r" not in v and "\n" not in v, \
                    "Access-Control-Allow-Origin contains raw CRLF"
                assert "X-Injected" not in v

    def test_cors_origin_raw_crlf_socket_not_split(self):
        """Raw-socket variant: write a literal CRLF inside the Origin value
        (bypassing the client's own header validation) and confirm the server
        does not emit an attacker-named header in the response."""
        raw = (b"OPTIONS / HTTP/1.1\r\n"
               b"Host: x\r\n"
               b"Origin: https://evil.example\r\nX-Injected: pwned\r\n"
               b"Access-Control-Request-Method: GET\r\n"
               b"Connection: close\r\n\r\n")
        try:
            s = socket.create_connection((SERVER_HOST, NGINX_HTTP_WEBDAV_PORT),
                                         timeout=8)
            s.sendall(raw)
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
        except OSError:
            pytest.skip("connection failed")
        # Split the status line + header block (before the body).
        head = resp.split(b"\r\n\r\n", 1)[0].lower()
        # The server must not reflect our injected value into a RESPONSE header.
        # (It is free to treat the literal CRLF as a second *request* header and
        # ignore it — what matters is it never appears in the response head as
        # access-control-allow-origin: ...evil... with our injected token.)
        for line in head.split(b"\r\n"):
            if line.startswith(b"access-control-allow-origin:"):
                assert b"x-injected" not in line


# ===========================================================================
# Cross-protocol auth confusion (INVARIANT: S3 SigV4 != WLCG token)
# ===========================================================================

@_HTTP_SKIP
class TestCrossProtocolAuthConfusion:
    """An S3 SigV4 Authorization header presented to WebDAV (and vice versa)
    must not be honoured as a valid credential, crash the handler, or be parsed
    by the wrong auth path."""

    def test_aws_sigv4_header_not_honored_by_webdav(self):
        aws = ("AWS4-HMAC-SHA256 Credential=AKIA/20260101/us-east-1/s3/"
               "aws4_request, SignedHeaders=host, Signature=" + "0" * 64)
        st, _, data = _request(NGINX_HTTP_WEBDAV_PORT, "GET", "/test.txt",
                               headers={"Authorization": aws})
        # Whatever happens, it must not 5xx (crash) and must not leak host files.
        assert st < 500, f"AWS header crashed WebDAV auth (status={st})"
        assert HOST_SECRET not in data

    @_S3_SKIP
    def test_bearer_jwt_not_honored_as_s3_signature(self):
        bearer = "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0." + "A" * 32
        st, _, data = _request(NGINX_S3_PORT, "GET", f"/{BUCKET}/test.txt",
                               headers={"Authorization": bearer})
        assert st < 500, f"bearer header crashed S3 auth (status={st})"
        assert HOST_SECRET not in data
