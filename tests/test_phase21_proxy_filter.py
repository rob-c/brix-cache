"""
Phase 21 — multi-backend WebDAV proxy (Step D) and XrdHttp filters (Steps A/B).

Coverage:
  1. Source-marker checks for the multi-backend wiring + aux filter module.
  2. Config validation for the new proxy directives — retired (skip stubs kept
     to document the legacy-proxy cleanup).
  3. XrdHttp filter + OIDC introspection functional tests against throwaway
     registry instances (templates nginx_xrdhttp_filter.conf /
     nginx_webdav_introspect.conf via the `lifecycle` harness).
"""

import os
import socket
import time
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST, INTROSPECT_IDP_PORT

# The token-introspection IdP is a shared fixed-port fleet mock, declared below.
pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.registry_server("introspect-idp"),
    pytest.mark.xdist_group("lc-phase21-proxy-filter"),
]

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.skip(reason="WebDAV reverse-proxy transport (proxy.c/proxy_request.c/"
                  "proxy_response.c/proxy_internal.h) deleted in the A-2 surface "
                  "retirement; only proxy_pool.c (admin-API pool) survives")
def test_multi_backend_wiring_present():
    pass


@pytest.mark.skip(reason="WebDAV reverse-proxy transport (proxy_request.c) deleted "
                  "in the A-2 surface retirement")
def test_request_builder_uses_selected_backend():
    pass


# --------------------------------------------------------------------------- #
# 2. Config validation — retired directive surface                             #
# --------------------------------------------------------------------------- #

@pytest.mark.skip(reason="multi-backend WebDAV reverse-proxy directives "
                  "(brix_webdav_proxy/_upstream) retired in legacy-proxy cleanup")
def test_multi_url_proxy_directive_parses():
    pass


@pytest.mark.skip(reason="multi-backend WebDAV reverse-proxy directives "
                  "(brix_webdav_proxy/_upstream) retired in legacy-proxy cleanup")
def test_bad_scheme_rejected():
    pass


@pytest.mark.skip(reason="multi-backend WebDAV reverse-proxy "
                  "(brix_webdav_proxy) retired in legacy-proxy cleanup")
def test_round_robin_distributes():
    pass


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _headers(port, path, extra=""):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(
            (f"GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n")
            .encode())
        data = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    head = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    status = int(head.split("\r\n", 1)[0].split()[1])
    hdrs = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs


# --------------------------------------------------------------------------- #
# Steps A/B — XrdHttp output filter                                            #
# --------------------------------------------------------------------------- #

def test_aux_filter_module_registered():
    assert (ROOT / "src/protocols/webdav/xrdhttp_filter.c").exists()
    cfg = _read("config")
    assert "ngx_module_type=HTTP_AUX_FILTER" in cfg
    assert "ngx_http_brix_xrdhttp_filter_module" in cfg
    # The body filter / Want-Digest wiring is present.  phase-79 split: the
    # digest body filter moved into xrdhttp_filter.c; the Want-Digest request
    # parsing stays in xrdhttp.c.
    assert "xrdhttp_digest_body_filter" in _read("src/protocols/webdav/xrdhttp_filter.c")
    assert "Want-Digest" in _read("src/protocols/webdav/xrdhttp.c")


@pytest.fixture
def webdav_server(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hello world\n")
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-xrdhttp-filter",
        template="nginx_xrdhttp_filter.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST},
        reason="XrdHttp aux-filter functional coverage",
    ))
    yield endpoint.port


def test_xrdhttp_status_header_present(webdav_server):
    status, hdrs = _headers(webdav_server, "/hello.txt",
                            extra="X-Xrootd-Proto: 5.2\r\n")
    assert status == 200, (status, hdrs)
    assert "x-xrootd-status" in hdrs, hdrs


def test_xrdhttp_status_injected_on_404(webdav_server):
    # The filter covers error responses: a missing file still carries the
    # X-Xrootd-Status header for an XrdHttp client.
    status, hdrs = _headers(webdav_server, "/does_not_exist",
                            extra="X-Xrootd-Proto: 5.2\r\n")
    assert status == 404, (status, hdrs)
    assert "x-xrootd-status" in hdrs, hdrs


def test_no_xrdhttp_header_for_plain_client(webdav_server):
    status, hdrs = _headers(webdav_server, "/hello.txt")
    assert status == 200, (status, hdrs)
    assert not any(k.startswith("x-xrootd") for k in hdrs), hdrs


def test_want_digest_does_not_break_get(webdav_server):
    # Want-Digest enables the streaming digest filter; the GET must still
    # succeed and return the body.
    status, hdrs = _headers(webdav_server, "/hello.txt",
                            extra="X-Xrootd-Proto: 5.2\r\nWant-Digest: adler32\r\n")
    assert status == 200, (status, hdrs)


# --------------------------------------------------------------------------- #
# Step C — OIDC token introspection (revocation)                              #
# --------------------------------------------------------------------------- #

def test_introspect_wiring_present():
    intro = _read("src/protocols/webdav/introspect.c")
    assert "ngx_http_subrequest" in intro
    assert "webdav_introspect_access_handler" in intro
    # Registered as a second access-phase handler.
    pc = _read("src/protocols/webdav/postconfig.c")
    assert "webdav_introspect_access_handler" in pc


@pytest.fixture
def introspect_server(lifecycle, tmp_path):
    # The RFC 7662 IdP is the shared fixed-port introspect-idp mock (declared via
    # registry_server above); nothing here to start or stop.
    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hi\n")
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-introspect",
        template="nginx_webdav_introspect.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "IDP_PORT": INTROSPECT_IDP_PORT},
        reason="OIDC token-introspection functional coverage",
    ))
    yield endpoint.port


def test_active_token_allowed(introspect_server):
    status, _ = _headers(introspect_server, "/hello.txt",
                         extra="Authorization: Bearer good.jwt.token\r\n")
    assert status == 200, status


def test_revoked_token_forbidden(introspect_server):
    status, _ = _headers(introspect_server, "/hello.txt",
                         extra="Authorization: Bearer revoked.jwt.token\r\n")
    assert status == 403, status


def test_no_token_skips_introspection(introspect_server):
    # No bearer token -> introspection declines, request served normally.
    status, _ = _headers(introspect_server, "/hello.txt")
    assert status == 200, status
