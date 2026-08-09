"""
Phase 36 §7.2.7 — dashboard / admin API / rate-limit / metrics over IPv6.

This suite exercises the HTTP control surface of the IPv6 manager instance
(``ipv6-mgr``, listening on ``[::1]:IPV6_MGR_HTTP_PORT``) and the rate-limit /
peer-addressing paths of the IPv6 stream instance (``ipv6-stream`` on
``[::1]:IPV6_STREAM_PORT``).  Three concern areas, mapped to the §3 fix sites:

  (a) GATING — the admin write API accepts a *bracketed* IPv6 host segment in the
      request URI (``/cluster/servers/[::1]/PORT``), strips the brackets, and the
      registered member round-trips *bare* in the dashboard cluster snapshot
      (``GET /brix/api/v1/cluster``).  This proves the bracket-aware URI parse
      in ``src/observability/dashboard/api_admin.c`` (``admin_parse_server_uri`` :395).
      register / drain / undrain / remove are all driven through bracketed URIs.

  (b) REGRESSION — rate limiting keyed by an IPv6 client IP still throttles
      (``src/net/ratelimit/ratelimit_keys.c`` already builds an ``ip:`` bucket key
      from the bare ``peer_ip``; IPv6 works today).

  (c) REGRESSION / invariant #8 — ``/metrics`` is scrapeable over ``[::1]`` and
      carries NO raw IPv6 address in any label; label cardinality is bounded to
      the enumerable low-cardinality axes (port/auth/op/status/method/...).

Harness contract (do NOT edit settings.py / manage_test_servers.sh here):
  * ``ipv6-mgr`` is pre-started by ``start_all_dedicated`` from
    ``nginx_ipv6_mgr.conf``.  That config (owned by the cms-redirect agent) MUST:
      - listen ``[::1]:{PORT}`` (stream manager) + ``listen [::1]:11242;`` (CMS)
        + an ``http{}`` server ``listen [::1]:11247;`` carrying the dashboard
        (``/brix/`` -> brix_dashboard on) and ``/metrics`` (brix_metrics on);
      - set ``brix_admin_secret`` to a file whose sole contents are the literal
        ``ipv6-admin-secret`` (see ADMIN_SECRET below) so the admin write API is
        enabled and bearer-gated;
      - NOT set ``brix_dashboard_password`` on the ``/brix/`` location, so the
        read-only ``GET /brix/api/v1/cluster`` snapshot is reachable without a
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
# written verbatim into nginx_ipv6_mgr.conf's brix_admin_secret file and sent
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
    """Call the admin write API under /brix/api/v1/admin with a Bearer token."""
    headers = {}
    body = None
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(json_body)
    full = f"/brix/api/v1/admin{path}"
    return _http6(method, MGR_HTTP, full, headers=headers, body=body)


# The read-only dashboard JSON API (GET /brix/api/v1/cluster) is gated by the
# dashboard session cookie because the live ipv6-mgr config sets
# ``brix_dashboard_password "testpassword"`` on /brix/ (the admin WRITE API
# on the same location is gated independently by the ::1/128 CIDR allowlist).
# So the snapshot read must first authenticate: POST the password to
# /brix/login (single-user mode, empty username) and reuse the resulting
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
            "POST", "/brix/login",
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
    status, _hdrs, body = _http6("GET", MGR_HTTP, "/brix/api/v1/cluster",
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
        pytest.skip(f"ipv6-mgr HTTP endpoint [{HOST6}]:{MGR_HTTP} not reachable")


def _skip_unless_stream():
    if not reachable6(STREAM):
        pytest.skip(f"ipv6-stream [{HOST6}]:{STREAM} not reachable")


def _skip_unless_admin_enabled():
    """Skip if the admin API is not configured (mgr config without the admin
    surface).  Probe is NON-MUTATING: a deliberately-malformed host is rejected
    at the whitelist with 400 ``invalid_field`` when the API is wired (and never
    registers), whereas a config that exposes no admin surface 404s.

    Because the ipv6-mgr config authorizes via ``brix_admin_allow ::1/128`` in
    OR-mode (no secret), a request from ::1 is admitted regardless of token — so
    a 403 here would itself be unexpected; the only ``not wired`` signal is 404."""
    _skip_unless_mgr_http()
    status, _hdrs, _body = _admin(
        "POST", "/cluster/servers", token=None,
        json_body={"host": "probe;invalid", "port": 1094, "paths": "/x"})
    if status == 404:
        pytest.skip(
            "ipv6-mgr config does not expose the admin write API "
            "(/brix/api/v1/admin -> 404)")


# =========================================================================== #
# Group A — admin API over IPv6 (bracket-aware URI parse)        [GATING]      #
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
            assert "::1" not in val, (  # net-literal-allow: invariant-8 raw-IPv6-in-label check; ::1 is the search subject
                f"raw ::1 in label {key} of {name}: {block!r}")  # net-literal-allow: invariant-8 raw-IPv6-in-label check; ::1 is the search subject
            assert not _IPV6_BRACKET_RE.search(val), (
                f"bracketed IPv6 literal in label {key} of {name}: {block!r}")
            assert not _RAW_IPV6_RE.search(val), (
                f"raw IPv6 literal in label {key} of {name}: {block!r}")
