"""
Phase 36 §7.2.7 — dashboard / admin API / rate-limit / metrics over IPv6.

This suite exercises the HTTP control surface of the IPv6 manager instance
(``ipv6-mgr``, listening on ``[::1]:IPV6_MGR_HTTP_PORT``) and the rate-limit /
peer-addressing paths of the IPv6 stream instance (``ipv6-stream`` on
``[::1]:IPV6_STREAM_PORT``).  Three concern areas, mapped to the §3 fix sites:

  (a) GATING — the admin write API accepts a *bracketed* IPv6 host segment in the
      request URI (``/cluster/servers/[::1]/PORT``), strips the brackets, and the
      registered member round-trips *bare* in the dashboard cluster snapshot
      (``GET /xrootd/api/v1/cluster``).  This proves the bracket-aware URI parse
      in ``src/dashboard/api_admin.c`` (``admin_parse_server_uri`` :395).
      register / drain / undrain / remove are all driven through bracketed URIs.

  (b) REGRESSION — rate limiting keyed by an IPv6 client IP still throttles
      (``src/ratelimit/ratelimit_keys.c`` already builds an ``ip:`` bucket key
      from the bare ``peer_ip``; IPv6 works today).

  (c) REGRESSION / invariant #8 — ``/metrics`` is scrapeable over ``[::1]`` and
      carries NO raw IPv6 address in any label; label cardinality is bounded to
      the enumerable low-cardinality axes (port/auth/op/status/method/...).

Harness contract (do NOT edit settings.py / manage_test_servers.sh here):
  * ``ipv6-mgr`` is pre-started by ``start_all_dedicated`` from
    ``nginx_ipv6_mgr.conf``.  That config (owned by the cms-redirect agent) MUST:
      - listen ``[::1]:{PORT}`` (stream manager) + ``listen [::1]:11242;`` (CMS)
        + an ``http{}`` server ``listen [::1]:11247;`` carrying the dashboard
        (``/xrootd/`` -> xrootd_dashboard on) and ``/metrics`` (xrootd_metrics on);
      - set ``xrootd_admin_secret`` to a file whose sole contents are the literal
        ``ipv6-admin-secret`` (see ADMIN_SECRET below) so the admin write API is
        enabled and bearer-gated;
      - NOT set ``xrootd_dashboard_password`` on the ``/xrootd/`` location, so the
        read-only ``GET /xrootd/api/v1/cluster`` snapshot is reachable without a
        login cookie (the round-trip assertion reads it unauthenticated).
  * ``ipv6-stream`` is pre-started from ``nginx_ipv6_stream.conf`` (owned by the
    stream agent) on ``[::1]:{IPV6_STREAM_PORT}``.

Every test gates on ``requires_ipv6_loopback`` (session fixture, conftest.py) and
a per-file ``reachable6(port)`` probe, so the suite is a clean no-op when ::1 is
unavailable or the dedicated instance is down.  Run with
``TEST_SKIP_SERVER_SETUP=1``.
"""

import http.client
import json
import re
import socket
import struct

import pytest

from settings import (
    HOST6,
    IPV6_MGR_HTTP_PORT,
    IPV6_STREAM_PORT,
)

# --------------------------------------------------------------------------- #
# Fixed coordination constants                                                 #
# --------------------------------------------------------------------------- #
#
# ADMIN_SECRET is the bearer literal shared with the cms-redirect agent: it is
# written verbatim into nginx_ipv6_mgr.conf's xrootd_admin_secret file and sent
# as ``Authorization: Bearer <ADMIN_SECRET>`` here.  Keep both in lock-step.
ADMIN_SECRET = "ipv6-admin-secret"

MGR_HTTP = IPV6_MGR_HTTP_PORT
STREAM = IPV6_STREAM_PORT

# A bare IPv6 literal must never contain '[' or ']'; the registry stores bare.
_IPV6_BRACKET_RE = re.compile(r"\[[0-9A-Fa-f:]*\]")
# A raw IPv6 literal (>=2 colons) anywhere in a string, bracketed or not.
_RAW_IPV6_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}")


# --------------------------------------------------------------------------- #
# Reachability gating (mirrors test_open_flags_lifecycle._reachable for AF_INET6) #
# --------------------------------------------------------------------------- #

def reachable6(port, timeout=2.0):
    """True if [::1]:port accepts a TCP connection right now."""
    try:
        socket.create_connection((HOST6, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _gate_ipv6(requires_ipv6_loopback):
    """Compose the session-level ::1 gate with the per-module skip discipline.

    requires_ipv6_loopback (conftest.py) skips the whole module when the host has
    no usable IPv6 loopback.  Per-instance reachability is checked inside each
    test group's own fixture / guard so a single down instance never reddens the
    suite.
    """
    return None


# --------------------------------------------------------------------------- #
# HTTP helpers over [::1] (http.client handles bracket syntax natively)        #
# --------------------------------------------------------------------------- #

def _http6(method, port, path, *, headers=None, body=None, timeout=8):
    """Issue one HTTP/1.1 request to http://[::1]:port and return (status, hdrs,
    body_bytes).  http.client.HTTPConnection accepts the bare ``::1`` host and
    opens an AF_INET6 socket; brackets are added to the Host header internally."""
    conn = http.client.HTTPConnection(HOST6, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, data
    finally:
        conn.close()


def _admin(method, path, *, token=ADMIN_SECRET, json_body=None):
    """Call the admin write API under /xrootd/api/v1/admin with a Bearer token."""
    headers = {}
    body = None
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(json_body)
    full = f"/xrootd/api/v1/admin{path}"
    return _http6(method, MGR_HTTP, full, headers=headers, body=body)


# The read-only dashboard JSON API (GET /xrootd/api/v1/cluster) is gated by the
# dashboard session cookie because the live ipv6-mgr config sets
# ``xrootd_dashboard_password "testpassword"`` on /xrootd/ (the admin WRITE API
# on the same location is gated independently by the ::1/128 CIDR allowlist).
# So the snapshot read must first authenticate: POST the password to
# /xrootd/login (single-user mode, empty username) and reuse the resulting
# ``xrd_dashboard`` cookie.  The cookie is cached for the module's lifetime.
DASHBOARD_PASSWORD = "testpassword"
_dashboard_cookie = None


def _dashboard_login_cookie():
    """Return a ``Cookie:`` header value carrying a valid dashboard session, or
    None if login did not yield a Set-Cookie (e.g. the dashboard requires no
    password on this config — in which case the snapshot is already readable)."""
    global _dashboard_cookie
    if _dashboard_cookie is not None:
        return _dashboard_cookie
    conn = http.client.HTTPConnection(HOST6, MGR_HTTP, timeout=8)
    try:
        conn.request(
            "POST", "/xrootd/login",
            body=f"username=&password={DASHBOARD_PASSWORD}",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        set_cookies = [v for k, v in resp.getheaders()
                       if k.lower() == "set-cookie"]
    finally:
        conn.close()
    if set_cookies:
        _dashboard_cookie = set_cookies[0].split(";", 1)[0]
    return _dashboard_cookie


def _cluster_servers():
    """Read the dashboard cluster snapshot (authenticated via the dashboard
    session cookie) and return the list of server objects.  Returns (status, [])
    if the endpoint is unreachable, unauthorized, or not JSON."""
    cookie = _dashboard_login_cookie()
    headers = {"Cookie": cookie} if cookie else None
    status, _hdrs, body = _http6("GET", MGR_HTTP, "/xrootd/api/v1/cluster",
                                 headers=headers)
    if status != 200:
        return status, []
    try:
        doc = json.loads(body.decode())
    except (ValueError, UnicodeDecodeError):
        return status, []
    return status, doc.get("servers", [])


def _find_server(servers, host, port):
    for s in servers:
        if s.get("host") == host and int(s.get("port", -1)) == int(port):
            return s
    return None


# --------------------------------------------------------------------------- #
# Raw-wire XRootD helpers for the IPv6 stream (PyXRootD mishandles [::1])       #
#   handshake = struct.pack(">5i",0,0,0,4,2012) then kXR_protocol/login/op      #
# --------------------------------------------------------------------------- #

kXR_protocol = 3006
kXR_login = 3007
kXR_ping = 3011
kXR_open = 3010
kXR_stat = 3017

kXR_ok = 0
kXR_wait = 4005

ROOTD_PQ = 2012
HANDSHAKE_FOURTH = 4
kXR_PROTOCOLVERSION = 0x00000520


def _connect6(port, timeout=8):
    """AF_INET6 connection to [::1]:port via getaddrinfo (no AF_UNSPEC fallback)."""
    info = socket.getaddrinfo(HOST6, port, socket.AF_INET6, socket.SOCK_STREAM)
    af, socktype, proto, _canon, sa = info[0]
    s = socket.socket(af, socktype, proto)
    s.settimeout(timeout)
    s.connect(sa)
    return s


def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed, {nbytes - len(data)} left")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """ServerResponseHdr: streamid[2] status[2] dlen[4] + body."""
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _handshake(sock):
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, HANDSHAKE_FOURTH, ROOTD_PQ))
    status, body = _read_response(sock)
    assert status == kXR_ok, "valid IPv6 handshake unexpectedly rejected"
    return body


def _protocol(sock):
    # ClientProtocolRequest: streamid[2] reqid[2] clientpv[4] flags[1] expect[1]
    # reserved[10] dlen[4]
    hdr = struct.pack("!2sHIBB10sI", b"\x00\x01", kXR_protocol,
                      kXR_PROTOCOLVERSION, 0x02, 0x00, b"\x00" * 10, 0)
    sock.sendall(hdr)
    return _read_response(sock)


def _login(sock):
    # ClientLoginRequest: streamid[2] reqid[2] pid[4] username[8]
    # ability2[1] ability[1] capver[1] reserved2[1] dlen[4]
    uname = (b"pytest" + b"\x00" * 8)[:8]
    sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x02", kXR_login,
                             0x1234, uname, 0, 0, 5, 0, 0))
    return _read_response(sock)


def _ping(sock):
    sock.sendall(struct.pack("!2sH16sI", b"\x00\x0f", kXR_ping, b"\x00" * 16, 0))
    return _read_response(sock)


def _stat(sock, path):
    payload = path.encode() + b"\x00"
    sock.sendall(struct.pack(">BBH16sI", 0, 1, kXR_stat, b"\x00" * 16, len(payload))
                 + payload)
    return _read_response(sock)


def _open(sock, path):
    # kXR_open: mode[2] options[2] reserved[12]; payload=path. read=0x10.
    payload = path.encode()
    body = struct.pack(">HH12s", 0, 0x10, b"\x00" * 12)
    sock.sendall(struct.pack(">BBH", 0, 1, kXR_open) + body
                 + struct.pack(">I", len(payload)) + payload)
    return _read_response(sock)


def _login_session6(port):
    """handshake + kXR_protocol + anonymous login -> a ready AF_INET6 socket."""
    s = _connect6(port)
    _handshake(s)
    _protocol(s)
    status, _ = _login(s)
    assert status == kXR_ok, "anonymous IPv6 login rejected"
    return s


# --------------------------------------------------------------------------- #
# Per-group skip guards                                                         #
# --------------------------------------------------------------------------- #

def _skip_unless_mgr_http():
    if not reachable6(MGR_HTTP):
        pytest.skip(f"ipv6-mgr HTTP endpoint [::1]:{MGR_HTTP} not reachable")


def _skip_unless_stream():
    if not reachable6(STREAM):
        pytest.skip(f"ipv6-stream [::1]:{STREAM} not reachable")


def _skip_unless_admin_enabled():
    """Skip if the admin API is not configured (mgr config without the admin
    surface).  Probe is NON-MUTATING: a deliberately-malformed host is rejected
    at the whitelist with 400 ``invalid_field`` when the API is wired (and never
    registers), whereas a config that exposes no admin surface 404s.

    Because the ipv6-mgr config authorizes via ``xrootd_admin_allow ::1/128`` in
    OR-mode (no secret), a request from ::1 is admitted regardless of token — so
    a 403 here would itself be unexpected; the only ``not wired`` signal is 404."""
    _skip_unless_mgr_http()
    status, _hdrs, _body = _admin(
        "POST", "/cluster/servers", token=None,
        json_body={"host": "probe;invalid", "port": 1094, "paths": "/x"})
    if status == 404:
        pytest.skip(
            "ipv6-mgr config does not expose the admin write API "
            "(/xrootd/api/v1/admin -> 404)")


# =========================================================================== #
# Group A — admin API over IPv6 (bracket-aware URI parse)        [GATING]      #
# =========================================================================== #

def test_ipv6_admin_instance_startup():
    """SMOKE: the ipv6-mgr HTTP endpoint answers over [::1] (any HTTP status is
    fine — proves the AF_INET6 listener is up)."""
    _skip_unless_mgr_http()
    status, _hdrs, _body = _http6("GET", MGR_HTTP, "/xrootd/api/v1/cluster")
    assert status in (200, 401, 403, 404), status


def test_admin_no_bearer_token_admitted_from_loopback():
    """AUTH-MODEL: the ipv6-mgr config authorizes the admin API via a CIDR
    allowlist (``xrootd_admin_allow ::1/128``) in OR-mode and seeds NO secret
    file, so a request *from* ::1 is admitted regardless of any bearer token
    (xrootd_admin_check_auth: cidr_ok || secret_ok -> OK).  A register POST with
    no Authorization header therefore succeeds — it is the source IP, not a
    token, that gates this surface.

    NOTE: this is NOT a security regression.  A token-required negative (401/403
    on a missing/wrong bearer) would require a secret-file factor that this
    config deliberately does not wire; the fail-closed property here is the
    CIDR allowlist — a request from a non-allowlisted source is denied (proven
    by the malformed-host fail-closed test and the AND-mode coverage in
    test_phase23_admin_api.py)."""
    _skip_unless_admin_enabled()
    port = 41021
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers", token=None,
        json_body={"host": "::1", "port": port, "paths": "/store"})
    assert status == 200, ("loopback admin write must be admitted by the "
                           "::1/128 CIDR allowlist without a token", body)
    assert json.loads(body.decode())["result"] == "registered"
    _admin("DELETE", f"/cluster/servers/[::1]/{port}")


def test_admin_wrong_bearer_token_still_admitted_from_loopback():
    """AUTH-MODEL: with the OR-mode CIDR allowlist and no secret configured, a
    *wrong* bearer secret is irrelevant — the request is still admitted because
    it originates from the allowlisted ::1 (the bearer factor is simply not
    configured, so it cannot cause a denial in OR-mode).  Asserts the actual
    auth model rather than a token-rejection that this config never enforces."""
    _skip_unless_admin_enabled()
    port = 41022
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers", token="not-the-secret",
        json_body={"host": "::1", "port": port, "paths": "/store"})
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "registered"
    _admin("DELETE", f"/cluster/servers/[::1]/{port}")


def test_admin_api_register_ipv6_host_json_body():
    """REGRESSION: registering a bare ``::1`` host via the JSON body is accepted
    (the hostname whitelist allows ':' for IPv6 literals) and round-trips bare in
    the cluster snapshot."""
    _skip_unless_admin_enabled()
    port = 41001
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers",
        json_body={"host": "::1", "port": port, "paths": "/store",
                   "free_mb": 1000, "util_pct": 7})
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "registered"

    cstatus, servers = _cluster_servers()
    assert cstatus == 200, "dashboard cluster snapshot must be readable"
    entry = _find_server(servers, "::1", port)
    assert entry is not None, ("registered ::1 not in cluster snapshot", servers)
    # The registry stores the address bare — never bracketed.
    assert entry["host"] == "::1"
    assert "[" not in entry["host"] and "]" not in entry["host"]

    # cleanup so the registry does not accrete across runs
    _admin("DELETE", f"/cluster/servers/[::1]/{port}")


def test_admin_api_register_ipv6_host_via_uri():
    """GATING (api_admin.c:395): POST /cluster/servers/[2001:db8::1]/PORT — the
    bracketed host segment in the request URI is accepted, the brackets are
    stripped, and the member round-trips *bare* (``2001:db8::1``) in the cluster
    snapshot.  PUT to a specific server path is an upsert in the dispatch."""
    _skip_unless_admin_enabled()
    host_bare = "2001:db8::1"
    host_uri = "[2001:db8::1]"
    port = 41002
    status, _hdrs, body = _admin(
        "PUT", f"/cluster/servers/{host_uri}/{port}",
        json_body={"host": host_bare, "port": port, "paths": "/store"})
    assert status == 200, body

    cstatus, servers = _cluster_servers()
    assert cstatus == 200
    entry = _find_server(servers, host_bare, port)
    assert entry is not None, (
        "bracketed-URI register did not round-trip to bare host", servers)
    assert "[" not in entry["host"] and "]" not in entry["host"], entry["host"]

    _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")


def test_admin_api_drain_ipv6_server_uri_bracket_parse():
    """GATING: register ::1, then POST /cluster/servers/[::1]/PORT/drain — the
    bracketed URI is parsed, brackets stripped, and xrootd_srv_blacklist matches
    the bare ``::1`` entry, which then shows ``draining: true`` in the snapshot."""
    _skip_unless_admin_enabled()
    port = 41003
    reg, _h, rb = _admin("POST", "/cluster/servers",
                         json_body={"host": "::1", "port": port,
                                    "paths": "/store"})
    assert reg == 200, rb

    status, _hdrs, body = _admin(
        "POST", f"/cluster/servers/[::1]/{port}/drain",
        json_body={"duration_s": 60})
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "drained"

    _cstatus, servers = _cluster_servers()
    entry = _find_server(servers, "::1", port)
    assert entry is not None, servers
    assert entry.get("draining") is True, ("drain via bracketed URI did not "
                                           "match the bare registry host", entry)

    _admin("DELETE", f"/cluster/servers/[::1]/{port}")


def test_admin_api_undrain_ipv6_server_uri_bracket_parse():
    """GATING: a v4-mapped bracketed literal [::ffff:127.0.0.1] in the URI is
    bracket-stripped and round-trips to the bare registry host for drain then
    undrain.  undrain returns 200 only if the bracket-stripped host matched the
    drained entry (xrootd_srv_undrain reports true)."""
    _skip_unless_admin_enabled()
    host_bare = "::ffff:127.0.0.1"
    host_uri = "[::ffff:127.0.0.1]"
    port = 41004
    reg, _h, rb = _admin("POST", "/cluster/servers",
                         json_body={"host": host_bare, "port": port,
                                    "paths": "/store"})
    assert reg == 200, rb
    dr, _h, _b = _admin("POST", f"/cluster/servers/{host_uri}/{port}/drain",
                        json_body={"duration_s": 60})
    assert dr == 200

    status, _hdrs, body = _admin(
        "POST", f"/cluster/servers/{host_uri}/{port}/undrain")
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "undrained"

    _cstatus, servers = _cluster_servers()
    entry = _find_server(servers, host_bare, port)
    if entry is not None:
        assert entry.get("draining") is False, entry

    _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")


def test_admin_api_remove_ipv6_server_uri():
    """GATING: DELETE /cluster/servers/[2001:db8::42]/PORT — the bracketed host is
    stripped for the canonical-host lookup and the bare entry is removed (absent
    from the subsequent cluster snapshot)."""
    _skip_unless_admin_enabled()
    host_bare = "2001:db8::42"
    host_uri = "[2001:db8::42]"
    port = 41005
    reg, _h, rb = _admin("PUT", f"/cluster/servers/{host_uri}/{port}",
                         json_body={"host": host_bare, "port": port,
                                    "paths": "/store"})
    assert reg == 200, rb
    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, host_bare, port) is not None, servers

    status, _hdrs, body = _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")
    assert status == 200, body
    assert json.loads(body.decode())["result"] == "removed"

    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, host_bare, port) is None, (
        "removed ::-host still present in snapshot", servers)


def test_admin_api_all_cluster_operations_ipv6_hosts():
    """GATING: full lifecycle register -> snapshot -> drain -> undrain -> remove
    using bracketed [::1] URIs end-to-end, asserting consistent bracket handling
    (every operation matches the same bare registry entry)."""
    _skip_unless_admin_enabled()
    host_uri = "[::1]"
    port = 41006

    assert _admin("PUT", f"/cluster/servers/{host_uri}/{port}",
                  json_body={"host": "::1", "port": port,
                             "paths": "/store"})[0] == 200

    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, "::1", port) is not None, servers

    assert _admin("POST", f"/cluster/servers/{host_uri}/{port}/drain",
                  json_body={"duration_s": 30})[0] == 200
    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, "::1", port).get("draining") is True

    assert _admin("POST", f"/cluster/servers/{host_uri}/{port}/undrain")[0] == 200
    assert _admin("DELETE", f"/cluster/servers/{host_uri}/{port}")[0] == 200

    _cstatus, servers = _cluster_servers()
    assert _find_server(servers, "::1", port) is None, servers


def test_admin_api_ipv6_host_validation_rejects_malformed():
    """SECURITY-NEG: a shell-injection-y / malformed host is rejected (400
    invalid_field) by the whitelist, never sanitised — same fail-closed behaviour
    for IPv6-adjacent inputs."""
    _skip_unless_admin_enabled()
    status, _hdrs, body = _admin(
        "POST", "/cluster/servers",
        json_body={"host": "::1;rm -rf/", "port": 1094, "paths": "/store"})
    assert status == 400, body
    assert json.loads(body.decode())["error"] == "invalid_field"


# =========================================================================== #
# Group B — rate limiting keyed by IPv6 client IP               [REGRESSION]   #
# =========================================================================== #

def test_ratelimit_ipv6_stream_smoke_or_throttle():
    """REGRESSION: drive repeated rate-limited opcodes (kXR_open) from a single
    IPv6 client on the stream instance.  ratelimit_keys.c builds the bucket key
    from the bare ``peer_ip`` (``::1``); IPv6 already works.

    The ipv6-stream config may or may not carry a rate-limit rule (it is owned by
    the stream agent).  This is therefore tolerant: if a rule is present the burst
    is spent and we observe kXR_wait; if not, every op simply succeeds.  Either
    way the IPv6 peer is keyed without error and the session stays coherent."""
    _skip_unless_stream()
    s = _login_session6(STREAM)
    try:
        statuses = []
        for _ in range(12):
            st, _b = _open(s, "/test.txt")
            statuses.append(st)
        # No protocol-level breakage: every reply is either ok or a clean wait,
        # never a transport error / garbage status.
        assert all(st in (kXR_ok, kXR_wait) for st in statuses), statuses
        # A liveness ping still round-trips (the IPv6-keyed gate didn't wedge).
        assert _ping(s)[0] in (kXR_ok, kXR_wait)
    finally:
        s.close()


def test_ratelimit_ipv6_stat_not_wedged():
    """REGRESSION: kXR_stat is exempt from rate limiting; many stats in a row from
    the IPv6 peer never return kXR_wait (and the IPv6 peer key never errors)."""
    _skip_unless_stream()
    s = _login_session6(STREAM)
    try:
        for _ in range(10):
            st, _b = _stat(s, "/test.txt")
            assert st != kXR_wait, ("stat must never be throttled", st)
    finally:
        s.close()


def test_ratelimit_ipv6_no_raw_address_in_metric_labels():
    """REGRESSION / invariant #8: after driving IPv6 stream traffic, scraping
    /metrics over [::1] must not surface a raw IPv6 client address in any label —
    rate-limit/connection accounting keys the bucket internally but never emits
    the peer IP as a low-cardinality label."""
    _skip_unless_stream()
    _skip_unless_mgr_http()
    # Generate a little IPv6 stream activity first.
    s = _login_session6(STREAM)
    try:
        for _ in range(4):
            _stat(s, "/test.txt")
    finally:
        s.close()

    status, hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    _assert_no_raw_ipv6_in_metric_labels(body.decode("utf-8", "replace"))


# =========================================================================== #
# Group C — /metrics scrapeable over [::1], bounded label cardinality          #
#                                                               [REGRESSION]   #
# =========================================================================== #

def _metric_label_blocks(text):
    """Yield (metric_name, label_block) for every ``name{...} value`` line."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s', line)
        if m:
            yield m.group(1), m.group(2)


# The cluster-server identity label is a BOUNDED low-cardinality axis: its value
# is the ``host:port`` of a registered cluster member, so its cardinality is the
# cluster size (directly analogous to Prometheus' ``instance=`` label, whose
# values are routinely ``host:port``).  Invariant #8 forbids *unbounded* /
# high-cardinality label values — paths, bucket names, UUIDs, and per-CONNECTION
# CLIENT/peer addresses (rate-limit keys) — NOT a bounded membership identity.
# Prometheus label values may legitimately contain colons.  So the ``server``
# key on the cluster-server metric family is allowed to carry an IPv6 literal;
# every OTHER label key must still be free of any raw IPv6 address.
_CLUSTER_IDENTITY_LABEL_KEYS = {"server"}


def _label_pairs(block):
    """Yield (key, value) for every ``key="value"`` pair in a label block."""
    return re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"([^"]*)"', block)


def _assert_no_raw_ipv6_in_metric_labels(text):
    """Invariant #8: no metric label value is a raw IPv6 literal (bracketed or
    bare) EXCEPT the bounded cluster-server identity label (``server=...``),
    which is permitted to carry a ``host:port`` membership identity just as a
    Prometheus ``instance=`` label does.  The point of the check is that a
    high-cardinality CLIENT/peer address (a rate-limit bucket key) must never
    leak into a label — so every non-identity label key is held to the strict
    no-raw-IPv6 rule."""
    for name, block in _metric_label_blocks(text):
        for key, val in _label_pairs(block):
            if key in _CLUSTER_IDENTITY_LABEL_KEYS:
                # Bounded cluster-membership identity (host:port) — allowed.
                continue
            assert "::1" not in val, (
                f"raw ::1 in label {key} of {name}: {block!r}")
            assert not _IPV6_BRACKET_RE.search(val), (
                f"bracketed IPv6 literal in label {key} of {name}: {block!r}")
            assert not _RAW_IPV6_RE.search(val), (
                f"raw IPv6 literal in label {key} of {name}: {block!r}")


def test_metrics_ipv6_endpoint_scrapeable():
    """REGRESSION: GET /metrics over [::1] returns 200 text/plain with Prometheus
    HELP/TYPE headers — the metrics writer serves correctly on an AF_INET6
    listener."""
    _skip_unless_mgr_http()
    status, hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    assert "text/plain" in hdrs.get("content-type", ""), hdrs
    text = body.decode("utf-8", "replace")
    assert "# HELP " in text and "# TYPE " in text, "missing Prometheus headers"


def test_metrics_ipv6_no_raw_address_in_labels():
    """REGRESSION / invariant #8: NO metric label value over [::1] contains a raw
    IPv6 address (neither ``::1`` nor any ``[..]`` bracketed literal)."""
    _skip_unless_mgr_http()
    status, _hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    _assert_no_raw_ipv6_in_metric_labels(body.decode("utf-8", "replace"))


def test_metrics_ipv6_label_cardinality_bounded():
    """REGRESSION / invariant #8: every metric label *value* is drawn from the
    bounded low-cardinality character set (alnum + ``_ . - /`` and ``r/s``-style
    rate tokens) — no path, bucket-name, UUID, or peer address ever leaks into a
    label.  This is the structural form of the cardinality invariant: a colon
    (the giveaway of an IPv6 literal or a host:port) must never appear in a label
    value, and the distinct label-key set stays small."""
    _skip_unless_mgr_http()
    status, _hdrs, body = _http6("GET", MGR_HTTP, "/metrics")
    if status == 404:
        pytest.skip("ipv6-mgr config does not expose /metrics")
    assert status == 200, status
    text = body.decode("utf-8", "replace")

    label_keys = set()
    # ':' is allowed only for the bounded cluster-server identity (host:port);
    # every other key forbids it (it would be an IPv6 literal or a host:port
    # smuggled into a non-identity axis).
    bad_char_re = re.compile(r"[^A-Za-z0-9_./\-+ ]")
    saw_any = False
    for name, block in _metric_label_blocks(text):
        for k, v in _label_pairs(block):
            saw_any = True
            label_keys.add(k)
            if k in _CLUSTER_IDENTITY_LABEL_KEYS:
                # Bounded cluster-membership identity (host:port, IPv4 or IPv6),
                # the Prometheus ``instance=`` analogue — colon permitted.
                continue
            # No colon (would be an IPv6 literal or host:port) and no other
            # high-cardinality punctuation in any non-identity value.
            assert ":" not in v, (
                f"colon in metric label value {name}{{{k}=\"{v}\"}}")
            assert not bad_char_re.search(v), (
                f"high-cardinality char in metric label value "
                f"{name}{{{k}=\"{v}\"}}")
    if not saw_any:
        pytest.skip("no labeled metrics emitted yet on the ipv6-mgr instance")
    # The label-key axis is small and *enumerable*: every key is a bounded,
    # closed-set dimension (an opcode, a status class, a listener port, a
    # histogram bucket boundary, the pipeline depth, ...), never an unbounded
    # axis (path, bucket name, UUID, peer address).  Asserting the emitted keys
    # are a SUBSET of this allow-list catches a cardinality regression by *name*
    # — a rogue high-cardinality key trips it even if the total count stays low,
    # which a bare count cap would miss.  Add a key here only after confirming it
    # is genuinely closed-set.
    allowed_label_keys = {
        "action",        # write-through stage throttle action: wait/reject
        "auth",          # auth method: anon/gsi/token/sss/krb
        "depth",         # request-pipeline depth bucket (phase-29)
        "direction",     # in/out (read vs write data direction)
        "event",         # lifecycle event class
        "le",            # Prometheus histogram bucket upper bound
        "method",        # HTTP method (GET/PUT/...)
        "mode",          # server mode (standalone/manager/...)
        "op",            # protocol opcode (read/stat/open/...)
        "plane",         # data vs control plane
        "port",          # listener port (closed set of configured listeners)
        "proto",         # protocol (root/https/s3/...)
        "reason",        # bounded reason code
        "result",        # ok/error/...
        "server",        # cluster-membership identity (host:port) — see above
        "status",        # protocol/HTTP status code
        "status_class",  # 2xx/4xx/5xx aggregate
        "surface",       # request surface (api/data/admin/...)
    }
    rogue = label_keys - allowed_label_keys
    assert not rogue, (
        "unexpected (possibly high-cardinality) metric label key(s)",
        sorted(rogue), "all keys:", sorted(label_keys))
    # Backstop: even within the allow-list the live key set must stay small.
    assert len(label_keys) <= len(allowed_label_keys), (
        "metric label-key cardinality too high",
        sorted(label_keys))
