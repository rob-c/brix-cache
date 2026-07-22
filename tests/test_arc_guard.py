"""
Phase-65 bad-actor guard — ARC profile (ngx_http_brix_guard_module).

Self-contained: spins up a hit-counting stub backend plus an nginx with
`brix_guard on; brix_guard_profile arc;` in front of a stock proxy_pass,
and drives real HTTP through the guard.

Verifies: ACCESS-phase pre-backend bounce (signature + grammar, backend never
touched), clean ARC requests proxied untouched, LOG-phase audit lines for
backend 404 (notfound) / 401 (authfail), and that clean traffic is never
logged.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_arc_guard.py -v -p no:xdist
"""

import os
import time

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
    pytest.mark.xdist_group("lc-arc-guard"),
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
        name="lc-arc-guard",
        template="nginx_guard_arc_lc.conf",
        protocol="http",
        template_values={
            "BIND_HOST": BIND_HOST,
            "AUDIT_LOG": str(audit_path),
            "BACKEND_PORT": stub_backend.port,
        },
        reason="phase-65 ARC guard-profile matrix"))
    server = GuardServer(HOST, endpoint.port)
    server.wait_ready("/arex/ready")
    return {"server": server, "audit": AuditLog(str(audit_path))}


@pytest.fixture()
def guard_server(_server, stub_backend):
    stub_backend.reset()
    return _server["server"]


@pytest.fixture()
def audit_log(_server):
    return _server["audit"]


class TestArcGuardAccess:
    def test_signature_bounced_pre_backend(self, guard_server, stub_backend):
        """A scanner signature is bounced before the backend sees it."""
        r = guard_server.get("/wp-login.php")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert stub_backend.hits == 0, "backend must never see junk"

    def test_valid_arc_request_proxied(self, guard_server, stub_backend):
        """A clean ARC REST request passes through to the backend."""
        r = guard_server.get("/arex/rest/1.0/info")
        assert r.status == 200, f"clean request failed: {r.status}"
        assert stub_backend.hits == 1, "backend should see exactly one hit"

    def test_grammar_violation_bounced(self, guard_server, stub_backend):
        """A path outside the ARC namespace is bounced pre-backend."""
        r = guard_server.get("/random/scan")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert stub_backend.hits == 0, "backend must never see off-namespace"


class TestArcGuardAudit:
    def test_backend_404_logged_notfound(self, guard_server, stub_backend,
                                         audit_log):
        """A backend 404 produces one signal=notfound audit line."""
        baseline = audit_log.line_count()
        stub_backend.reply_status = 404
        r = guard_server.get("/arex/rest/1.0/jobs/does-not-exist")
        assert r.status == 404
        assert audit_log.wait_for_count(baseline + 1), "no audit line written"
        assert audit_log.last_line_has(signal="notfound", status="404",
                                       proto="arc")

    def test_missing_cred_401_logged_authfail(self, guard_server,
                                              stub_backend, audit_log):
        """A backend 401 (no cert, no bearer) logs signal=authfail."""
        baseline = audit_log.line_count()
        stub_backend.reply_status = 401
        r = guard_server.get("/arex/rest/1.0/jobs")
        assert r.status == 401
        assert audit_log.wait_for_count(baseline + 1), "no audit line written"
        assert audit_log.last_line_has(signal="authfail", status="401")

    def test_clean_request_not_logged(self, guard_server, stub_backend,
                                      audit_log):
        """A clean 200 round-trip adds no audit line."""
        baseline = audit_log.line_count()
        r = guard_server.get("/arex/rest/1.0/info")
        assert r.status == 200
        time.sleep(0.3)   # give the LOG phase a beat to (not) write
        assert audit_log.line_count() == baseline, "clean traffic was logged"

    def test_access_bounce_logged_once(self, guard_server, stub_backend,
                                       audit_log):
        """An ACCESS bounce writes exactly one line (no LOG-phase double)."""
        baseline = audit_log.line_count()
        guard_server.get("/wp-login.php")
        assert audit_log.wait_for_count(baseline + 1), "no audit line written"
        time.sleep(0.3)   # a double-log would land within this window
        assert audit_log.line_count() == baseline + 1, "bounce double-logged"
        assert audit_log.last_line_has(signal="signature")
