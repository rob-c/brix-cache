"""
Phase-65 bad-actor guard — XrdHttp/WebDAV profile parity.

Same matrix as tests/test_arc_guard.py but under `brix_guard_profile
xrdhttp;`: the export namespace is root-open by default (operator narrows via
brix_guard_valid_prefix — exercised here with /store), signatures and the
op grammar still apply, and audit lines carry proto=xrdhttp.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_xrdhttp_guard.py -v -p no:xdist
"""

import os
import subprocess

import pytest

from guard_http_lib import (NGINX_BIN, AuditLog, GuardServer, StubBackend,
                            free_port)
from settings import HOST, BIND_HOST
from config_templates import render_config

pytestmark = pytest.mark.timeout(120)


@pytest.fixture(scope="module")
def stub_backend():
    backend = StubBackend()
    yield backend
    backend.stop()


@pytest.fixture(scope="module")
def _server(tmp_path_factory, stub_backend):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("xrdhttpguard")
    audit_path = root / "guard-audit.log"
    guard_port = free_port()
    conf = root / "nginx.conf"
    conf.write_text(render_config("nginx_guard_xrdhttp.conf",
                                  BASE_DIR=root,
                                  BIND_HOST=BIND_HOST,
                                  PORT=guard_port,
                                  AUDIT_LOG=audit_path,
                                  BACKEND_PORT=stub_backend.port))
    rc = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip(f"nginx -t failed: {rc.stderr}")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    server = GuardServer(HOST, guard_port)
    server.wait_ready("/store/ready")
    yield {"server": server, "audit": AuditLog(str(audit_path))}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "stop"],
                   capture_output=True)


@pytest.fixture()
def xrdhttp_guard_server(_server, stub_backend):
    stub_backend.reset()
    return _server["server"]


@pytest.fixture()
def audit_log(_server):
    return _server["audit"]


class TestXrdHttpGuard:
    def test_xrdhttp_signature_bounced(self, xrdhttp_guard_server,
                                       stub_backend):
        """A .git probe is bounced before the backend sees it."""
        r = xrdhttp_guard_server.get("/.git/config")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert stub_backend.hits == 0, "backend must never see junk"

    def test_xrdhttp_valid_get_proxied(self, xrdhttp_guard_server,
                                       stub_backend):
        """A clean export-namespace GET passes through to the backend."""
        r = xrdhttp_guard_server.get("/store/data/file.root")
        assert r.status == 200, f"clean request failed: {r.status}"
        assert stub_backend.hits == 1, "backend should see exactly one hit"

    def test_xrdhttp_off_prefix_bounced(self, xrdhttp_guard_server,
                                        stub_backend, audit_log):
        """Outside the configured /store prefix -> grammar bounce."""
        baseline = audit_log.line_count()
        r = xrdhttp_guard_server.get("/random/scan")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert stub_backend.hits == 0
        assert audit_log.wait_for_count(baseline + 1), "no audit line written"
        assert audit_log.last_line_has(signal="grammar", proto="xrdhttp")

    def test_xrdhttp_403_logged_authfail(self, xrdhttp_guard_server,
                                         stub_backend, audit_log):
        """A backend 403 logs signal=authfail with proto=xrdhttp."""
        baseline = audit_log.line_count()
        stub_backend.reply_status = 403
        r = xrdhttp_guard_server.get("/store/protected/file.root")
        assert r.status == 403
        assert audit_log.wait_for_count(baseline + 1), "no audit line written"
        assert audit_log.last_line_has(signal="authfail", proto="xrdhttp",
                                       status="403")
