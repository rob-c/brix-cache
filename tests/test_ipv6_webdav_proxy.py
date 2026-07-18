"""
Phase 36 §7.2.4 — WebDAV proxy with an IPv6 backend (the GATING bracket-on-emit suite).

Topology:
    HTTP client ──► nginx WebDAV proxy ([::1]:IPV6_PROXY_PORT) ──► IPv6 upstream
                    (brix_webdav_proxy on)                       origin ([::1]:11245)

The proxy front (nginx_ipv6_proxy.conf) is configured with
    brix_webdav_proxy_upstream  http://[::1]:11245;
so the URL is parsed by src/protocols/webdav/proxy_config.c::webdav_proxy_add_url and the
per-request Host header is emitted by src/protocols/webdav/proxy_pool.c.  ngx_parse_url()
strips the brackets off "[::1]", so without the bracket-on-emit fix the proxy
would send the bare, RFC-ambiguous "Host: ::1:11245".  The fix re-brackets the
IPv6 literal, so the upstream must observe "Host: [::1]:11245".

These tests PROVE that fix end-to-end: every GATING case drives a real request
through the proxy and then reads the *upstream's* access log
(${TEST_ROOT}/dedicated/ipv6-upstream/logs/host_access.log, a custom
log_format that records $http_host) and asserts the recorded Host is the
bracketed form, never bare.

Skip discipline (never fails on instance-absent):
  * every test depends on the session fixture `requires_ipv6_loopback`
    (conftest.py) — clean skip on hosts without usable ::1;
  * a per-file reachable6(port) probe skips when the dedicated instance is down.

Run with TEST_SKIP_SERVER_SETUP=1 (the instances are pre-started by start-all).
"""

import http.client
import os
import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from settings import (
    HOST6,
    IPV6_PROXY_PORT,
    IPV6_UPSTREAM_DATA_ROOT,
    IPV6_UPSTREAM_PORT,
    TEST_ROOT,
)

# The WebDAV reverse-proxy directives (brix_webdav_proxy / _upstream) were
# retired in the legacy-proxy cleanup — only brix_webdav_proxy_certs (GSI
# client auth) survives, so this IPv6-proxy suite has no config surface to run
# against. Skip the whole module until/if the reverse proxy returns.
pytestmark = pytest.mark.skip(
    reason="WebDAV reverse-proxy (brix_webdav_proxy) retired in legacy-proxy "
           "cleanup; no config surface to exercise")

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

# The fixed upstream port hardcoded in nginx_ipv6_proxy.conf
# (brix_webdav_proxy_upstream http://[::1]:11245). Default upstream port is
# also 11245; if the harness ever moves the upstream port the proxy config must
# move with it — the gating assertions key off this exact literal.
UPSTREAM_HOST_BRACKETED = f"[::1]:{IPV6_UPSTREAM_PORT}"
UPSTREAM_HOST_BARE = f"::1:{IPV6_UPSTREAM_PORT}"

# Custom log_format ($http_host) on the upstream instance, written here by
# start_dedicated_nginx "ipv6-upstream":
UPSTREAM_HOST_LOG = (
    Path(TEST_ROOT) / "dedicated" / "ipv6-upstream" / "logs" / "host_access.log"
)


# --------------------------------------------------------------------------- #
# Skip helpers                                                                 #
# --------------------------------------------------------------------------- #

def reachable6(port, timeout=2.0):
    """True if [::1]:port accepts a TCP connection (mirrors the AF_INET6 probe
    pattern of test_open_flags_lifecycle._reachable)."""
    try:
        socket.create_connection((HOST6, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _require_ipv6_instances(requires_ipv6_loopback):
    """Gate the whole module: needs ::1 loopback AND both dedicated instances up.

    Depends on the session-scoped requires_ipv6_loopback fixture (skips when the
    host has no usable IPv6 loopback), then probes the proxy and upstream ports
    so an instance-down condition is a clean skip, never a failure.
    """
    if not reachable6(IPV6_PROXY_PORT):
        pytest.skip(f"IPv6 webdav proxy not up on [::1]:{IPV6_PROXY_PORT}")
    if not reachable6(IPV6_UPSTREAM_PORT):
        pytest.skip(f"IPv6 webdav upstream not up on [::1]:{IPV6_UPSTREAM_PORT}")


# --------------------------------------------------------------------------- #
# HTTP-over-IPv6 helpers (http.client handles bracketed literals natively)     #
# --------------------------------------------------------------------------- #

def _conn(timeout=15):
    """A plain HTTP connection to the proxy on the IPv6 loopback."""
    return http.client.HTTPConnection(HOST6, IPV6_PROXY_PORT, timeout=timeout)


def _request(method, path, body=None, headers=None, timeout=15):
    """Issue one request through the proxy → (status, resp_headers, body)."""
    conn = _conn(timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def _seed_upstream(name, content):
    """Write a file directly into the upstream's data root so a GET through the
    proxy can read it back. Returns the URL path."""
    root = Path(IPV6_UPSTREAM_DATA_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_bytes(content)
    return "/" + name


def _upstream_disk_path(name):
    return Path(IPV6_UPSTREAM_DATA_ROOT) / name


# --------------------------------------------------------------------------- #
# Upstream host-access-log helpers (the heart of the gating assertions)        #
# --------------------------------------------------------------------------- #

def _read_host_log_tail():
    """Return the upstream host_access.log as a list of lines (empty if absent).

    nginx buffers access-log writes; callers poll via _wait_for_host_log_line.
    """
    try:
        return UPSTREAM_HOST_LOG.read_text(errors="replace").splitlines()
    except FileNotFoundError:
        return []


def _wait_for_host_log_line(predicate, timeout=8.0):
    """Poll the upstream host log until a line matching `predicate` appears.

    Returns the matching line, or None if none appeared within `timeout`
    (access logs are flushed asynchronously, so a short poll is required).
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        for line in _read_host_log_tail():
            if predicate(line):
                return line
        last = _read_host_log_tail()
        time.sleep(0.1)
    return last and None


def _assert_proxy_sent_bracketed_host(marker_path):
    """Assert the upstream logged a bracketed Host for the request whose URI
    contains `marker_path`. This is the bracket-on-emit acceptance check.

    GATING: proves src/protocols/webdav/proxy_pool.c re-brackets the IPv6 literal.
    """
    def hit(line):
        return marker_path in line and "host=" in line

    line = _wait_for_host_log_line(hit)
    assert line is not None, (
        f"no upstream host_access.log line for {marker_path!r}; "
        f"log tail={_read_host_log_tail()[-5:]}"
    )
    host_field = line.split("host=", 1)[1].strip()
    assert host_field == UPSTREAM_HOST_BRACKETED, (
        f"proxy sent un-bracketed/wrong Host to IPv6 upstream: "
        f"got {host_field!r}, expected {UPSTREAM_HOST_BRACKETED!r} "
        f"(bare form {UPSTREAM_HOST_BARE!r} is the regression)"
    )
    # Defensive: the ambiguous bare literal must never appear.
    assert UPSTREAM_HOST_BARE not in host_field
    return host_field


# --------------------------------------------------------------------------- #
# GATING — Host-header bracket-on-emit through the proxy                        #
# --------------------------------------------------------------------------- #

class TestProxyHostHeaderBracketing:
    """Every request the proxy forwards must carry a bracketed IPv6 Host header.

    Gates 36: src/protocols/webdav/proxy_config.c (config-parse) + proxy_pool.c (per-req).
    """

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_get_small_file(self):
        """GATING: GET through the proxy → 200 byte-exact; upstream Host bracketed."""
        marker = f"ipv6gateget_{uuid.uuid4().hex[:8]}.txt"
        content = b"hello from nginx-xrootd\n"  # 24 bytes
        path = _seed_upstream(marker, content)

        status, _, body = _request("GET", path)
        assert status == 200, f"GET via proxy failed: {status}"
        assert body == content, "proxied GET body not byte-exact"

        self_host = _assert_proxy_sent_bracketed_host(marker)
        assert self_host == UPSTREAM_HOST_BRACKETED

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_put_small_file(self):
        """GATING: PUT through the proxy lands on the upstream; Host bracketed."""
        marker = f"ipv6gateput_{uuid.uuid4().hex[:8]}.txt"
        content = b"ipv6 proxy put payload\n"

        status, _, _ = _request(
            "PUT", "/" + marker, body=content,
            headers={"Content-Length": str(len(content))},
        )
        assert status in (200, 201, 204), f"PUT via proxy failed: {status}"

        # File must exist on the *upstream* origin's disk.
        disk = _upstream_disk_path(marker)
        assert disk.exists(), "PUT did not land on the IPv6 upstream origin"
        assert disk.read_bytes() == content

        _assert_proxy_sent_bracketed_host(marker)

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_get_large_file(self):
        """GATING: 256 KiB GET byte-exact; Host bracketed on the upstream req."""
        marker = f"ipv6gatebig_{uuid.uuid4().hex[:8]}.bin"
        content = bytes(i & 0xFF for i in range(256 * 1024))
        path = _seed_upstream(marker, content)

        status, _, body = _request("GET", path, timeout=30)
        assert status == 200, f"large GET via proxy failed: {status}"
        assert len(body) == len(content), f"short read: {len(body)}"
        assert body == content, "large proxied GET not byte-exact"

        _assert_proxy_sent_bracketed_host(marker)

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_host_header_is_never_bare(self):
        """GATING: across several requests, the upstream never sees the bare
        IPv6 literal '::1:11245' in any Host field."""
        markers = []
        for _ in range(3):
            m = f"ipv6gatebare_{uuid.uuid4().hex[:8]}.txt"
            _seed_upstream(m, b"x")
            status, _, _ = _request("GET", "/" + m)
            assert status == 200
            markers.append(m)

        # Wait for the last marker to ensure all three are flushed.
        _wait_for_host_log_line(lambda ln: markers[-1] in ln)

        for line in _read_host_log_tail():
            if "host=" not in line:
                continue
            host_field = line.split("host=", 1)[1].strip()
            assert host_field != UPSTREAM_HOST_BARE, (
                f"proxy emitted bare IPv6 Host: {line!r}"
            )

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_config_parse_brackets_first_request(self):
        """GATING: the static config URL http://[::1]:11245 loaded (proxy is up),
        and the very first proxied request carries the bracketed Host — proving
        webdav_proxy_add_url re-bracketed at config-parse time."""
        marker = f"ipv6gatecfg_{uuid.uuid4().hex[:8]}.txt"
        path = _seed_upstream(marker, b"cfg-parse-check\n")

        status, _, body = _request("GET", path)
        assert status == 200
        assert body == b"cfg-parse-check\n"

        host_field = _assert_proxy_sent_bracketed_host(marker)
        # The bracketed form embeds the IPv6 literal between '[' and ']'.
        assert host_field.startswith("[") and "]" in host_field
        assert "::1" in host_field


# --------------------------------------------------------------------------- #
# SMOKE / REGRESSION — functional proxy behaviour over IPv6                     #
# --------------------------------------------------------------------------- #

class TestProxyFunctionalIPv6:
    """Functional WebDAV operations through the IPv6 proxy (work today once the
    instance is up; exercise the already-clean socket/resolution layer)."""

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_client_connect_ipv6_listen_success(self):
        """SMOKE: a raw GET to the proxy's [::1] listener returns correct content."""
        marker = f"ipv6connect_{uuid.uuid4().hex[:8]}.txt"
        content = b"ipv6 listen ok\n"
        path = _seed_upstream(marker, content)

        status, _, body = _request("GET", path)
        assert status == 200
        assert body == content

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_head_content_length(self):
        """SMOKE: HEAD through the proxy returns the upstream Content-Length."""
        marker = f"ipv6head_{uuid.uuid4().hex[:8]}.bin"
        content = bytes(range(200))
        path = _seed_upstream(marker, content)

        status, headers, body = _request("HEAD", path)
        assert status == 200, f"HEAD failed: {status}"
        cl = headers.get("Content-Length") or headers.get("content-length")
        assert cl is not None and int(cl) == len(content)

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_delete_file(self):
        """SMOKE: DELETE through the proxy removes the file on the upstream."""
        marker = f"ipv6del_{uuid.uuid4().hex[:8]}.txt"
        _seed_upstream(marker, b"delete me\n")
        disk = _upstream_disk_path(marker)
        assert disk.exists()

        status, _, _ = _request("DELETE", "/" + marker)
        assert status in (200, 204), f"DELETE via proxy failed: {status}"
        assert not disk.exists(), "file still present on upstream after DELETE"

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_missing_file_returns_404(self):
        """SMOKE: a GET for a nonexistent path through the proxy is a clean 404."""
        status, _, _ = _request(
            "GET", f"/ipv6_absent_{uuid.uuid4().hex[:8]}.txt"
        )
        assert status == 404, f"expected 404, got {status}"

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_put_then_get_roundtrip(self):
        """SMOKE: PUT then GET the same object through the proxy; byte-exact."""
        marker = f"ipv6rt_{uuid.uuid4().hex[:8]}.txt"
        content = b"roundtrip-" + uuid.uuid4().hex.encode() + b"\n"

        status, _, _ = _request(
            "PUT", "/" + marker, body=content,
            headers={"Content-Length": str(len(content))},
        )
        assert status in (200, 201, 204), f"PUT failed: {status}"

        status, _, body = _request("GET", "/" + marker)
        assert status == 200, f"GET-back failed: {status}"
        assert body == content, "PUT/GET roundtrip not byte-exact through proxy"

    @pytest.mark.registry_servers("ipv6-proxy", "ipv6-upstream")
    def test_proxy_concurrent_clients(self):
        """REGRESSION: 3 concurrent IPv6 GETs return distinct content and the
        proxy emits a bracketed Host for each (no cross-talk / Host corruption)."""
        specs = []
        for i in range(3):
            m = f"ipv6conc_{i}_{uuid.uuid4().hex[:6]}.txt"
            c = f"concurrent client {i} payload\n".encode()
            _seed_upstream(m, c)
            specs.append((m, c))

        def fetch(spec):
            marker, content = spec
            status, _, body = _request("GET", "/" + marker)
            return marker, status, body, content

        with ThreadPoolExecutor(max_workers=3) as ex:
            results = list(ex.map(fetch, specs))

        for marker, status, body, content in results:
            assert status == 200, f"{marker}: status {status}"
            assert body == content, f"{marker}: content mismatch"

        # Every concurrent request must have been forwarded with a bracketed Host.
        for marker, _, _, _ in results:
            _assert_proxy_sent_bracketed_host(marker)
