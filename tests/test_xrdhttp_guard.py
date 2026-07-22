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

import pytest

from guard_http_lib import NGINX_BIN, AuditLog, GuardServer, StubBackend
from settings import HOST, BIND_HOST
from server_registry import NginxInstanceSpec

# The guard-stub mock holds a shared hit counter + reply status, so these tests
# must run sequentially (serial → one xdist worker); each resets the mock first.
pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.serial,
    pytest.mark.registry_server("guard-stub"),
    pytest.mark.xdist_group("lc-xrdhttp-guard"),
]


@pytest.fixture(scope="module")
def stub_backend():
    # The mock is a fixed-port registry singleton (declared above); this is just
    # the control client — no per-test server to start or stop.
    return StubBackend()


@pytest.fixture()
def _server(lifecycle, tmp_path, stub_backend):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    audit_path = tmp_path / "guard-audit.log"
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-xrdhttp-guard",
        template="nginx_guard_xrdhttp.conf",
        protocol="http",
        template_values={
            "BIND_HOST": BIND_HOST,
            "AUDIT_LOG": str(audit_path),
            "BACKEND_PORT": stub_backend.port,
        },
        reason="phase-65 XrdHttp guard-profile parity"))
    server = GuardServer(HOST, endpoint.port)
    server.wait_ready("/store/ready")
    return {"server": server, "audit": AuditLog(str(audit_path))}


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
