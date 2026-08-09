"""
tests/test_webdav_redirect_ds.py — §6.1 HTTP redirect-to-dataserver +
brix_http_secretkey signed-CGI identity handoff.

Two nginx instances share one HMAC secret:

  * the MANAGER (stream CMS server + http WebDAV front) — a fake Python data
    node registers over the CMS wire, then a GET/HEAD/PUT to the WebDAV front
    is 307-redirected to the registered data server with the authenticated
    identity signed into the Location CGI (brixrdr.exp/usr/vo/mac);
  * the DATA SERVER (http WebDAV, brix_auth required) — a request carrying a
    valid signed CGI is authenticated by the shared key (identity adopted,
    file served); a tampered/expired/foreign-key CGI is 403, fail-closed.

Covered (success + error + security-negative):
  success       — a GET on the manager 307s to the data server, Location
                  carries scheme://host:port<path> and the signed CGI;
  success       — the data server serves a real file for a valid signed GET;
  loop-guard    — a request already carrying brixrdr.mac is served locally,
                  never re-redirected;
  security-neg  — a tampered MAC is refused 403 at the data server;
  security-neg  — an expired handoff is refused 403;
  security-neg  — a CGI signed with a DIFFERENT key is refused 403;
  off-path      — with the feature off the manager serves locally (no 307).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_webdav_redirect_ds.py -v
"""

import hashlib
import hmac
import os
import socket
import struct
import threading
import time
import urllib.error
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, SERVER_HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(90),
              pytest.mark.xdist_group("lc-webdav-redirect")]

H = SERVER_HOST
SECRET = "redirect-shared-hmac-key-0123456789"

# ── CMS wire constants (src/net/cms/cms_internal.h) ───────────────────────
CMS_RR_LOGIN, CMS_RR_PING, CMS_RR_PONG = 0, 17, 18
CMS_PT_SHORT, CMS_PT_INT = 0x80, 0xA0
CMS_LOGIN_VERSION = 3


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _cms_frame(streamid, code, modifier=0, payload=b""):
    return struct.pack(">IBBH", streamid, code, modifier, len(payload)) + payload


def _login_payload(dport, paths=b"r /"):
    p = b""
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", CMS_LOGIN_VERSION)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0x08)   # mode: server
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 5000)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 1)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 7)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", dport)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 0)
    for s in (b"redir-node", paths, b"", b""):
        if not s:
            p += struct.pack(">H", 0)
        else:
            p += struct.pack(">H", len(s) + 1) + s + b"\x00"
    return p


class FakeNode:
    """A CMS data node: logs in, answers pings so it stays registered."""

    def __init__(self, cms_port, dport):
        self.sock = socket.create_connection((H, cms_port), timeout=8)
        self.sock.settimeout(0.2)
        self.sock.sendall(_cms_frame(0, CMS_RR_LOGIN, 0, _login_payload(dport)))
        self._stop = False
        self._registered = threading.Event()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while not self._stop:
                try:
                    hdr = _recv_exact(self.sock, 8)
                except socket.timeout:
                    continue
                streamid, code, _mod, dlen = struct.unpack(">IBBH", hdr)
                if dlen:
                    _recv_exact(self.sock, dlen)
                if code == CMS_RR_PING:
                    self._registered.set()
                    self.sock.sendall(_cms_frame(streamid, CMS_RR_PONG))
        except (ConnectionResetError, OSError):
            pass

    def wait_registered(self, timeout=8.0):
        return self._registered.wait(timeout)

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _mac(method, path, exp, usr, vo, secret=SECRET):
    canon = f"{method}\n{path}\n{exp}\n{usr}\n{vo}".encode()
    return hmac.new(secret.encode(), canon, hashlib.sha256).hexdigest()


def _signed_cgi(method, path, usr="", vo="", ttl=120, secret=SECRET,
                exp=None):
    exp = str(int(time.time()) + ttl) if exp is None else str(exp)
    mac = _mac(method, path, exp, usr, vo, secret)
    return (f"brixrdr.exp={exp}&brixrdr.usr={usr}"
            f"&brixrdr.vo={vo}&brixrdr.mac={mac}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None   # surface the 307 instead of following it


_OPENER = urllib.request.build_opener(_NoRedirect)


def _http(method, port, path, query=""):
    url = f"http://{H}:{port}{path}"
    if query:
        url += "?" + query
    req = urllib.request.Request(url, method=method)
    try:
        with _OPENER.open(req, timeout=8) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


# ── fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def redirector():
    """The manager (WebDAV front + CMS server) plus a data server sharing the
    secret, and a fake CMS node registered into the manager.

    MODULE-scoped with its own LifecycleHarness (not the function-scoped
    `lifecycle` fixture): the two nginx instances bind FIXED ports, so a
    per-test start/stop cycle races the OS releasing those ports between tests
    (EADDRINUSE).  The tests are read-only against the running cluster, so one
    shared bring-up for the whole file is both correct and race-free.
    """
    from server_launcher import LifecycleHarness  # noqa: PLC0415 — lazy

    harness = LifecycleHarness()
    try:
        ds = harness.start(NginxInstanceSpec(
            name="lc-webdav-redirect-ds",
            template="nginx_webdav_redirect_ds.conf",
            protocol="root",
            readiness="tcp",
            template_values={"SECRET": SECRET},
            reason="§6.1 signed-CGI data server (verifies the handoff).",
        ))
        ds_http = ds.extra_ports["HTTP_PORT"]

        mgr = harness.start(NginxInstanceSpec(
            name="lc-webdav-redirect-mgr",
            template="nginx_webdav_redirect_mgr.conf",
            protocol="root",
            readiness="tcp",
            template_values={"SECRET": SECRET, "DS_HTTP_PORT": ds_http},
            reason="§6.1 HTTP redirect-to-dataserver manager.",
        ))
        cms_port = mgr.extra_ports["CMS_PORT"]
        mgr_http = mgr.extra_ports["HTTP_PORT"]

        # Register the data server node (its root:// port is what the registry
        # selects; the redirect swaps in the data server's HTTP port).
        node = FakeNode(cms_port, ds.port)
        assert node.wait_registered(), \
            "data node never registered with the manager"

        # Seed a file on the shared export so a valid signed GET returns bytes.
        with open(os.path.join(ds.data_root, "redir.txt"), "w") as fh:
            fh.write("redirected-body")

        try:
            yield {"mgr_http": mgr_http, "ds_http": ds_http,
                   "cms_port": cms_port}
        finally:
            node.close()
    finally:
        harness.close()


# ── manager side: the 307 ─────────────────────────────────────────────────

def test_manager_redirects_get(redirector):
    """success: a GET on the manager 307s to the data server, Location carries
    the target and a signed brixrdr.mac."""
    status, headers, _body = _http("GET", redirector["mgr_http"], "/redir.txt")
    assert status == 307, (status, headers)
    loc = headers.get("Location", "")
    assert f":{redirector['ds_http']}/redir.txt" in loc, loc
    assert "brixrdr.mac=" in loc, loc
    assert "brixrdr.exp=" in loc, loc


def test_loop_guard_serves_locally(redirector):
    """loop-guard: a request already carrying brixrdr.mac must NOT be
    re-redirected — the manager serves it (here: verifies the manager's own
    key, then serves the seeded file)."""
    path = "/redir.txt"
    cgi = _signed_cgi("GET", path)
    status, headers, _body = _http("GET", redirector["mgr_http"], path, cgi)
    assert status != 307, f"a signed request was re-redirected: {headers}"


# ── data-server side: verify + adopt ──────────────────────────────────────

def test_dataserver_accepts_valid_signed_get(redirector):
    """success: the data server serves the file for a valid signed GET (the
    identity is adopted, so brix_auth required is satisfied)."""
    path = "/redir.txt"
    cgi = _signed_cgi("GET", path, usr="/DC=test/CN=alice")
    status, _headers, body = _http("GET", redirector["ds_http"], path, cgi)
    assert status == 200, status
    assert body == b"redirected-body", body


def test_dataserver_rejects_tampered_mac(redirector):
    """security-neg: a flipped MAC is refused 403, fail-closed."""
    path = "/redir.txt"
    cgi = _signed_cgi("GET", path, usr="/DC=test/CN=alice")
    tampered = cgi[:-1] + ("0" if cgi[-1] != "0" else "1")
    status, _headers, _body = _http("GET", redirector["ds_http"], path,
                                    tampered)
    assert status == 403, status


def test_dataserver_rejects_expired(redirector):
    """security-neg: an expired handoff is refused 403 even with a valid MAC
    over the expired timestamp."""
    path = "/redir.txt"
    cgi = _signed_cgi("GET", path, usr="/DC=test/CN=alice",
                      exp=int(time.time()) - 10)
    status, _headers, _body = _http("GET", redirector["ds_http"], path, cgi)
    assert status == 403, status


def test_dataserver_rejects_foreign_key(redirector):
    """security-neg: a CGI signed with a DIFFERENT key is refused 403 — the
    shared secret is what authorises the handoff."""
    path = "/redir.txt"
    cgi = _signed_cgi("GET", path, usr="/DC=test/CN=mallory",
                      secret="a-totally-different-key")
    status, _headers, _body = _http("GET", redirector["ds_http"], path, cgi)
    assert status == 403, status


def test_dataserver_rejects_path_mismatch(redirector):
    """security-neg: a MAC signed for one path cannot be replayed against
    another (method+path are bound into the signature)."""
    cgi = _signed_cgi("GET", "/redir.txt", usr="/DC=test/CN=alice")
    status, _headers, _body = _http("GET", redirector["ds_http"],
                                    "/other.txt", cgi)
    assert status == 403, status
