"""
tests/test_ipv6_cms_redirect.py — phase-36 §7.2.2: CMS clustering + redirect to
IPv6 data servers, plus the dashboard / REST-admin IPv6 surface that feeds the
cluster registry.

WHAT THIS PROVES (the bracket-on-emit contract)
------------------------------------------------
The recurring phase-36 defect is that an IPv6 literal host gets re-emitted into a
"host:port" wire string / header WITHOUT brackets, so a client reading
"port + host" cannot tell where the address ends.  The fix brackets on emit.  Two
emission sites are exercised here:

  * dashboard/api_admin.c:admin_parse_server_uri — the admin REST URI carries the
    host segment bracketed ("[::1]"); the parser must strip the brackets before
    the host can match a registry entry.  Driven by HTTP over http://[::1]:HTTP.
  * response/control.c:brix_send_redirect (+ manager/registry.c via
    brix_format_host[_port]) — a manager-mode kXR_locate / kXR_open for a path
    served by an IPv6-registered data server returns a kXR_redirect whose host
    field is bracketed "[::1]", never bare "::1".  Driven over a RAW socket to
    ("::1", IPV6_MGR_PORT) because the PyXRootD client mishandles root://[::1].

HARNESS
-------
The "ipv6-mgr" dedicated instance (tests/configs/nginx_ipv6_mgr.conf) is
pre-started by manage_test_servers.sh start_all_dedicated:
  * stream [::1]:IPV6_MGR_PORT      — manager mode (kXR_locate/open -> redirect)
  * stream [::1]:11242              — CMS server face (fixed)
  * http   [::1]:IPV6_MGR_HTTP_PORT — dashboard + admin API + /metrics
The admin API is authorized by a "::1/128" CIDR allowlist, so every request from
::1 is admitted; the tests additionally send a fixed Bearer secret to mimic the
documented call shape.  Tests gate on requires_ipv6_loopback (no ::1 -> skip) and
a per-file reachable6(port) probe (instance down -> skip); neither ever reddens.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ipv6_cms_redirect.py -v
"""

import http.client
import json
import socket
import struct

import pytest

from settings import (
    IPV6_MGR_PORT,
    IPV6_MGR_HTTP_PORT,
    HOST6,
)

# The fixed admin-secret literal sent as a Bearer token.  Authorization actually
# succeeds via the ::1/128 CIDR allowlist in the config, but the documented admin
# call shape carries this token; >= 16 chars so it is a well-formed secret.
ADMIN_SECRET = "ipv6-phase36-admin-secret-token"

# IPv6 client host the tests connect to / register / expect echoed back.  Aliased
# to settings.HOST6 (default "::1"; env TEST_HOST6) so the client and a split
# (k8s) server resolve the same reachable IPv6 address; local runs stay identical.
IPV6_HOST = HOST6


# ---------------------------------------------------------------------------
# Skip discipline: requires_ipv6_loopback (session fixture from conftest) +
# a per-file reachable6() probe of each dedicated [::1] listener.
# ---------------------------------------------------------------------------

def reachable6(port, timeout=2.0):
    """True if [::1]:port accepts a TCP connection (AF_INET6 via ("::1", port))."""
    try:
        socket.create_connection((IPV6_HOST, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(autouse=True)
def _require_ipv6(requires_ipv6_loopback):
    """Compose the session-scoped IPv6-loopback gate onto every test in the file
    (requires_ipv6_loopback pytest.skips when ::1 cannot be bound)."""
    return


def _skip_if_stream_down():
    if not reachable6(IPV6_MGR_PORT):
        pytest.skip(f"ipv6-mgr stream [::1]:{IPV6_MGR_PORT} not reachable")


def _skip_if_http_down():
    if not reachable6(IPV6_MGR_HTTP_PORT):
        pytest.skip(f"ipv6-mgr http [::1]:{IPV6_MGR_HTTP_PORT} not reachable")


# ===========================================================================
# Raw-wire root:// helpers — connect to ("::1", port) (AF_INET6 automatically),
# drive handshake + login, then locate / open.  Frame layouts mirror
# tests/test_handshake_protocol_wire.py and tests/test_pgread_wire_conformance.py
# and are verified against /tmp/brix-src/src/XProtocol/XProtocol.hh.
# ===========================================================================

kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_locate   = 3027

kXR_ok       = 0
kXR_error    = 4003
kXR_redirect = 4004

kXR_open_read = 0x0010   # XOpenRequestOption: open for read

HANDSHAKE_FOURTH = 4
ROOTD_PQ         = 2012
SESSION_ID_LEN   = 16


def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """One ServerResponseHdr (streamid[2] status[2] dlen[4]) + its body."""
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _connect6(port, timeout=8):
    """Connect to the IPv6 loopback. socket.create_connection(("::1", port))
    yields an AF_INET6 socket; getaddrinfo(AF_INET6) keeps it unambiguous."""
    info = socket.getaddrinfo(IPV6_HOST, port, socket.AF_INET6,
                              socket.SOCK_STREAM)
    family, stype, proto, _, addr = info[0]
    sock = socket.socket(family, stype, proto)
    sock.settimeout(timeout)
    sock.connect(addr)
    return sock


def _handshake(sock):
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, HANDSHAKE_FOURTH, ROOTD_PQ))
    _, status, body = _read_response(sock)
    assert status == kXR_ok, "valid IPv6 handshake unexpectedly rejected"
    assert len(body) == 8, "handshake body must be 8 bytes"


def _login(sock, streamid=b"\x00\x01"):
    # ClientLoginRequest: streamid[2] requestid[2] pid[4] username[8]
    # ability2[1] ability[1] capver[1] reserved2[1] dlen[4].
    req = struct.pack("!2sHI8sBBBBI", streamid, kXR_login,
                      0x1234, b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    _, status, body = _read_response(sock)
    assert status == kXR_ok, f"anon login rejected: {_error_code(body)}"
    assert len(body) == SESSION_ID_LEN
    return sock


def _session6(port):
    """handshake + anonymous login -> an established IPv6 root:// session."""
    sock = _connect6(port)
    _handshake(sock)
    return _login(sock)


def _locate(sock, path, streamid=b"\x00\x02", options=0):
    # ClientLocateRequest: streamid[2] requestid[2] options[2] reserved[14] dlen[4]
    # followed by the path body.
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHH14sI", streamid, kXR_locate, options,
                      b"\x00" * 14, len(p)) + p
    sock.sendall(req)
    return _read_response(sock)


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x03"):
    # ClientOpenRequest: streamid[2] requestid[2] mode[2] options[2]
    # optiont[2] reserved[6] fhtemplt[4] dlen[4] + path body.
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI", streamid, kXR_open, 0, options,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4, len(p)) + p
    sock.sendall(req)
    return _read_response(sock)


def _parse_redirect(body):
    """kXR_redirect body is [port: 4 bytes BE][host string]. Return (port, host).
    host is decoded ASCII (it is a printable host[:opaque] literal)."""
    assert len(body) >= 4, "redirect body shorter than the 4-byte port field"
    port = struct.unpack("!I", body[:4])[0]
    host = body[4:].split(b"\x00", 1)[0].decode("ascii", "replace")
    return port, host


# ===========================================================================
# HTTP helpers — admin REST + read-only dashboard over http://[::1]:HTTP_PORT.
# ===========================================================================

def _http6_conn(timeout=8):
    return http.client.HTTPConnection(IPV6_HOST, IPV6_MGR_HTTP_PORT,
                                      timeout=timeout)


def _admin(method, uri, body=None, token=ADMIN_SECRET):
    """Issue an admin REST request; return (status, parsed-json-or-raw-text)."""
    conn = _http6_conn()
    try:
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
        conn.request(method, uri, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        try:
            return resp.status, json.loads(raw)
        except ValueError:
            return resp.status, raw
    finally:
        conn.close()


_ADMIN_BASE = "/brix/api/v1/admin"


def _dashboard_cookie():
    """Log into the read-only dashboard (password 'testpassword') and return the
    Set-Cookie session value, or None if login did not set a cookie."""
    conn = _http6_conn()
    try:
        conn.request("POST", "/brix/login", body="password=testpassword",
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        setc = resp.getheader("Set-Cookie")
        if not setc:
            return None
        return setc.split(";", 1)[0]
    finally:
        conn.close()


def _dashboard_get(path, cookie=None):
    conn = _http6_conn()
    try:
        headers = {"Cookie": cookie} if cookie else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        try:
            return resp.status, json.loads(raw)
        except ValueError:
            return resp.status, raw
    finally:
        conn.close()


def _register_ipv6_server(port, paths="/", host=IPV6_HOST):
    """Register an IPv6 data server in the cluster registry via the admin API
    (collection POST with a JSON body; admin_cluster_register path)."""
    return _admin("POST", f"{_ADMIN_BASE}/cluster/servers",
                  body={"host": host, "port": port, "paths": paths,
                        "free_mb": 100000, "util_pct": 5})


# A registered data-server port distinct from the manager/CMS/HTTP ports.
DS_PORT = 21194


# ===========================================================================
# 1. Admin REST — URI bracket-strip + bare-host JSON registration (GATING)
# ===========================================================================

class TestAdminBracketStrip:
    """dashboard/api_admin.c:admin_parse_server_uri must strip the "[...]" from
    an IPv6 host segment sent in the REST URI so it matches the registry's bare
    canonical host.  GATING: the bracketed URI must be accepted (200), not 400."""

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_register_ipv6_host_json_body(self):
        """REGRESSION/SMOKE: bare-literal host in the JSON body registers (the
        registry stores the address canonically bare)."""
        _skip_if_http_down()
        status, data = _register_ipv6_server(DS_PORT)
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "registered", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_drain_ipv6_host_uri_bracket_parse(self):
        """GATING: POST /cluster/servers/[::1]/PORT/drain — the bracketed host
        segment is split + stripped, so the drain targets the bare "::1" entry
        and returns 200 (bad/unstripped parse would 400 bad_uri)."""
        _skip_if_http_down()
        _register_ipv6_server(DS_PORT)
        status, data = _admin(
            "POST", f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}/drain",
            body={"duration_s": 30})
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "drained", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_undrain_ipv6_host_uri_bracket_parse(self):
        """GATING: POST /cluster/servers/[::1]/PORT/undrain after a drain — the
        bracket-stripped host matches the drained entry (200 undrained).  A
        404 not_found would mean the strip failed and the host never matched."""
        _skip_if_http_down()
        _register_ipv6_server(DS_PORT)
        _admin("POST",
               f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}/drain",
               body={"duration_s": 30})
        status, data = _admin(
            "POST",
            f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}/undrain")
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "undrained", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_remove_ipv6_host_uri_bracket_parse(self):
        """GATING: DELETE /cluster/servers/[::1]/PORT — canonical (bracket-
        stripped) host lookup removes the entry (200 removed)."""
        _skip_if_http_down()
        _register_ipv6_server(DS_PORT)
        status, data = _admin(
            "DELETE", f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}")
        assert status == 200, data
        assert isinstance(data, dict) and data.get("result") == "removed", data

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_register_full_lifecycle_ipv6_uris(self):
        """GATING: end-to-end register -> drain -> undrain -> remove using
        bracketed [::1] URIs throughout; every step round-trips a consistently
        bracket-stripped host."""
        _skip_if_http_down()
        assert _register_ipv6_server(DS_PORT)[0] == 200
        base = f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/{DS_PORT}"
        assert _admin("POST", f"{base}/drain", body={"duration_s": 30})[0] == 200
        assert _admin("POST", f"{base}/undrain")[0] == 200
        assert _admin("DELETE", base)[0] == 200

    @pytest.mark.registry_server("ipv6-mgr")
    def test_admin_malformed_ipv6_uri_rejected(self):
        """SECURITY-NEG: a non-numeric port segment -> 400 bad_uri; the parser
        rejects, never half-accepts a malformed bracketed URI."""
        _skip_if_http_down()
        status, data = _admin(
            "DELETE", f"{_ADMIN_BASE}/cluster/servers/[{IPV6_HOST}]/not-a-port")
        assert status == 400, data
        assert isinstance(data, dict) and data.get("error") in (
            "bad_uri", "invalid_field"), data


# ===========================================================================
# 2. Read-only dashboard JSON round-trips the IPv6 host (GATING-adjacent)
# ===========================================================================

class TestDashboardClusterRoundTrip:
    """GET /brix/api/v1/cluster (dashboard/api.c:dashboard_fill_cluster) must
    round-trip the registered IPv6 host in the "servers" array unmangled."""

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_json_contains_registered_ipv6_host(self):
        """GATING: register [::1]:DS, then the cluster JSON lists a server whose
        "host" is the bare canonical "::1" at the right port — proving the host
        survived store + JSON serialization without corruption."""
        _skip_if_http_down()
        assert _register_ipv6_server(DS_PORT)[0] == 200

        cookie = _dashboard_cookie()
        if cookie is None:
            pytest.skip("dashboard login did not set a session cookie")
        status, data = _dashboard_get("/brix/api/v1/cluster", cookie)
        assert status == 200, data
        assert isinstance(data, dict), data
        servers = data.get("servers", [])
        assert isinstance(servers, list), data
        match = [s for s in servers
                 if s.get("host") == IPV6_HOST and s.get("port") == DS_PORT]
        assert match, f"registered [::1]:{DS_PORT} not found in cluster JSON: {servers}"
        # The JSON host is stored bare (canonical); it must NOT be a bracketed
        # literal here — bracketing happens only at wire/redirect emit time.
        assert "[" not in match[0]["host"], match[0]

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_json_requires_auth(self):
        """REGRESSION: the read-only cluster endpoint is auth-gated (no cookie ->
        401), so the round-trip assertion above proves an authenticated read."""
        _skip_if_http_down()
        status, _ = _dashboard_get("/brix/api/v1/cluster")
        assert status == 401


# ===========================================================================
# 3. Manager-mode kXR_locate / kXR_open -> bracketed kXR_redirect (GATING)
# ===========================================================================

class TestManagerRedirectBracketing:
    """response/control.c:brix_send_redirect must bracket an IPv6 redirect host:
    the kXR_redirect body is [port:4B][host]; the host for an IPv6 data server is
    "[::1]", never bare "::1".  Manager-mode locate/open over a raw ::1 socket
    drives brix_srv_select -> brix_send_redirect after the DS is registered."""

    def _register_and_locate(self, opfn):
        """Register [::1]:DS for "/" then run opfn(sock, path); return the
        (status, body) response from the raw manager socket."""
        if _register_ipv6_server(DS_PORT)[0] != 200:
            pytest.skip("could not register IPv6 data server via admin API")
        sock = _session6(IPV6_MGR_PORT)
        try:
            return opfn(sock, "/store/ipv6/file.dat")
        finally:
            sock.close()

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_locate_returns_redirect(self):
        """GATING: manager-mode kXR_locate for a registered path returns
        kXR_redirect (4004) whose port == the registered DS port."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_locate)
        assert status == kXR_redirect, \
            f"expected kXR_redirect (4004), got {status} err={_error_code(body)}"
        port, host = _parse_redirect(body)
        assert port == DS_PORT, f"redirect port {port} != DS port {DS_PORT}"

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_locate_host_is_bracketed(self):
        """GATING: the redirect host field is the bracketed literal "[::1]", not
        the unparseable bare "::1" (response/control.c:71 bracket-on-emit)."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_locate)
        assert status == kXR_redirect, _error_code(body)
        _, host = _parse_redirect(body)
        # The host segment (before any "?opaque") must be exactly "[::1]".
        host_only = host.split("?", 1)[0]
        assert host_only == f"[{IPV6_HOST}]", \
            f"redirect host {host_only!r} must be bracketed [::1], not bare"
        assert not host_only.startswith(IPV6_HOST), \
            "bare ::1 (unbracketed) leaked into the redirect host field"

    @pytest.mark.registry_server("ipv6-mgr")
    def test_cluster_open_returns_bracketed_redirect(self):
        """GATING: manager-mode kXR_open(read) for a registered path also
        redirects to the DS with a bracketed [::1] host and the right port."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_open)
        assert status == kXR_redirect, \
            f"expected kXR_redirect (4004), got {status} err={_error_code(body)}"
        port, host = _parse_redirect(body)
        assert port == DS_PORT, f"redirect port {port} != DS port {DS_PORT}"
        assert host.split("?", 1)[0] == f"[{IPV6_HOST}]", \
            f"open redirect host {host!r} must be bracketed [::1]"

    @pytest.mark.registry_server("ipv6-mgr")
    def test_locate_and_open_redirect_to_same_target(self):
        """REGRESSION: locate and open select the same registered IPv6 target —
        both bracket the host identically, no per-opcode divergence."""
        _skip_if_http_down()
        _skip_if_stream_down()
        if _register_ipv6_server(DS_PORT)[0] != 200:
            pytest.skip("could not register IPv6 data server via admin API")
        sock = _session6(IPV6_MGR_PORT)
        try:
            _, ls, lb = _locate(sock, "/store/ipv6/file.dat")
            _, os_, ob = _open(sock, "/store/ipv6/file.dat")
        finally:
            sock.close()
        assert ls == kXR_redirect and os_ == kXR_redirect, (ls, os_)
        lport, lhost = _parse_redirect(lb)
        oport, ohost = _parse_redirect(ob)
        assert lport == oport == DS_PORT
        assert lhost.split("?", 1)[0] == ohost.split("?", 1)[0] == f"[{IPV6_HOST}]"

    @pytest.mark.registry_server("ipv6-mgr")
    def test_raw_redirect_body_never_contains_bare_ipv6(self):
        """GATING (negative): the raw redirect body, after the 4-byte port, never
        starts with a bare "::1" — the bracket must precede the literal so a
        client cannot mis-parse the colon-bearing address."""
        _skip_if_http_down()
        _skip_if_stream_down()
        _, status, body = self._register_and_locate(_locate)
        assert status == kXR_redirect, _error_code(body)
        host_bytes = body[4:]
        assert host_bytes.startswith(b"["), \
            f"redirect host must start with '[' (got {host_bytes[:8]!r})"
        assert not host_bytes.startswith(IPV6_HOST.encode()), \
            "bare ::1 must not be the first byte of the host field"


# ===========================================================================
# 4. Graceful-skip discipline (REGRESSION)
# ===========================================================================

class TestSkipDiscipline:
    """The suite must be a clean no-op when ::1 or the dedicated instance is
    absent — never a failure."""

    def test_reachable6_probe_is_boolean(self):
        """reachable6 returns a bool for a definitely-closed high port (no raise),
        so the per-file skip gate can never crash the collection."""
        # A port that is essentially never listening on ::1.
        assert reachable6(1, timeout=0.5) in (True, False)

    @pytest.mark.registry_server("ipv6-mgr")
    def test_instance_down_skips_not_fails(self):
        """If the ipv6-mgr HTTP face is down, the http-gated tests skip; this
        test documents that contract by skipping itself when it is down."""
        if not reachable6(IPV6_MGR_HTTP_PORT):
            pytest.skip("ipv6-mgr http face down — gated tests skip, never fail")
        # When up, a trivial reachability assertion holds.
        assert reachable6(IPV6_MGR_HTTP_PORT)
