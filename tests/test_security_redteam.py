"""
tests/test_security_redteam.py

Phase 28 adversarial-hardening regression suite.

These tests validate the CONFIG-LEVEL contract of the Phase 28 hardening
directives — that the new security gates are wired in, parse correctly, and
fail closed where required.  They use `nginx -t` against crafted configs, so
they are self-contained and need no running backends.

The S3 unknown-key/bad-signature and WebDAV-TPC DNS-rebinding paths are covered
by the live adversarial suites. CMS has a live off-CIDR rejection below, while
vanilla cmsd SSS interoperability is exercised by test_cms_mesh_interop.py when
the mesh is configured with `sec.protocol sss`.

Run:
    NGINX_BIN=/tmp/nginx-1.28.3/objs/nginx \
        PYTHONPATH=tests pytest tests/test_security_redteam.py -v
"""

import itertools
import socket

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-security-redteam"),
]

_SEQ = itertools.count()

LONG_SECRET = b"a-sufficiently-long-admin-secret-0123456789"
KEYTAB = b"0 N:1 k:" + b"a" * 64 + b" u:cmsnode g:cms n:cluster\n"


class _RedTeam:
    """Config-test helper: create mode-sensitive credential files under a temp
    dir and run `nginx -t` against a committed template, returning
    (returncode, combined stdout+stderr) — the emerg messages ride stderr."""

    def __init__(self, harness, tmp_path):
        self._h = harness
        self._tmp = tmp_path

    def file(self, rel, content, mode):
        path = self._tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return str(path)

    def check(self, template, **values):
        name = f"lc-redteam-{next(_SEQ)}"
        self._h.register(NginxInstanceSpec(
            name=name, template=template, port=SHARED_PARSE_PLACEHOLDER_PORT,
            protocol="root", readiness="tcp", template_values=values))
        self._h.launcher.render_nginx(self._h.spec(name))
        r = self._h.nginx_test(name, check=False)
        return r.returncode, (r.stdout or "") + (r.stderr or "")


@pytest.fixture()
def redteam(tmp_path):
    harness = LifecycleHarness()
    try:
        yield _RedTeam(harness, tmp_path)
    finally:
        harness.close()


# ---------------------------------------------------------------------------
# W6 — admin secret hygiene + upstream allowlist
# ---------------------------------------------------------------------------

class TestAdminSecretHardening:

    def test_short_secret_rejected(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_admin.conf",
            SECRET=redteam.file("secret", b"short", 0o600), EXTRA="")
        assert rc != 0, "a <16 byte admin secret must be rejected at config load"
        assert "too short" in out, out

    def test_long_secret_accepted(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_admin.conf",
            SECRET=redteam.file("secret", LONG_SECRET, 0o600), EXTRA="")
        # A clean parse reaches "test is successful"; any directive error would
        # surface as an [emerg] about the directive itself.
        assert "too short" not in out, out
        assert "brix_admin" not in out or "successful" in out, out

    def test_proxy_allow_directive_parses(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_admin.conf",
            SECRET=redteam.file("secret", LONG_SECRET, 0o600),
            EXTRA="brix_admin_proxy_allow backend.example.org 10.1.2.3;")
        assert "brix_admin_proxy_allow" not in out or "successful" in out, out
        assert "unknown directive" not in out, out


# ---------------------------------------------------------------------------
# W1 — CMS registration auth directives + keytab permission enforcement
# ---------------------------------------------------------------------------

class TestCmsAuthConfig:

    def test_enabled_listener_requires_admission_policy(self, redteam):
        rc, out = redteam.check("nginx_redteam_cms.conf", EXTRA="")
        assert rc != 0, "a policy-free CMS registration listener must fail closed"
        assert "requires brix_cms_server_allow and/or" in out, out

    def test_allow_only_listener_remains_compatible(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_cms.conf",
            EXTRA="brix_cms_server_allow 127.0.0.1/32;")  # net-literal-allow: CMS ACL parser subject
        assert rc == 0, out

    def test_allow_and_keytab_parse(self, redteam):
        keytab = redteam.file("cms.keytab", KEYTAB, 0o600)
        rc, out = redteam.check(
            "nginx_redteam_cms.conf",
            EXTRA=("brix_cms_server_allow 127.0.0.0/8 10.0.0.0/8;\n"
                   f"    brix_cms_server_sss_keytab {keytab};"))
        # rc == 0 means the keytab parsed and loaded (a malformed keytab or bad
        # permission would emerg here); the "sss auth configured" NOTICE itself
        # goes to the error_log file, not nginx -t's stderr.
        assert rc == 0, out

    def test_keytab_only_listener_remains_supported(self, redteam):
        keytab = redteam.file("cms-only.keytab", KEYTAB, 0o600)
        rc, out = redteam.check(
            "nginx_redteam_cms.conf",
            EXTRA=f"brix_cms_server_sss_keytab {keytab};")
        assert rc == 0, out

    def test_world_readable_keytab_rejected(self, redteam):
        keytab = redteam.file("cms.keytab", KEYTAB, 0o644)   # world-readable
        rc, out = redteam.check(
            "nginx_redteam_cms.conf",
            EXTRA=f"brix_cms_server_sss_keytab {keytab};")
        assert rc != 0, "a world-readable cms sss keytab must be rejected"
        assert "unsafe permissions" in out, out

    def test_bad_cidr_rejected(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_cms.conf",
            EXTRA="brix_cms_server_allow not-a-cidr;")
        assert rc != 0, "an invalid CIDR must be rejected"
        assert "invalid CIDR" in out, out


def test_cms_peer_outside_allowlist_is_closed_before_login(lifecycle):
    """security-neg: the accept-time tripwire rejects an IPv4 loopback peer
    when the configured policy admits only the documentation-only TEST-NET-1.
    The connection closes before it can submit a LOGIN or touch the registry.
    """
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-redteam-cms-peer",
        template="nginx_redteam_cms.conf",
        protocol="root",
        readiness="tcp",
        template_values={"EXTRA":
                         "brix_cms_server_allow 192.0.2.0/24;"},
        reason="CMS off-CIDR accept-time refusal"))
    with socket.create_connection((endpoint.host, endpoint.port), timeout=5) as sock:
        sock.settimeout(5)
        assert sock.recv(1) == b""


# ---------------------------------------------------------------------------
# W7 — per-principal concurrency limit directive
# ---------------------------------------------------------------------------

class TestConcurrencyLimitConfig:

    def _ca(self, redteam):
        return redteam.file("ca", b"dummy", 0o600)

    def test_concurrency_directive_parses(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_concurrency.conf", CA=self._ca(redteam),
            EXTRA="brix_concurrency_limit zone=conc key=ip limit=4;")
        # cafile is a dummy so TLS init may complain, but the concurrency
        # directive itself must not be flagged unknown/invalid.
        assert "unknown parameter" not in out, out
        assert "unknown directive" not in out, out

    def test_concurrency_requires_limit(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_concurrency.conf", CA=self._ca(redteam),
            EXTRA="brix_concurrency_limit zone=conc key=ip;")
        assert rc != 0, "concurrency limit must require limit="
        assert "limit=" in out, out

    def test_concurrency_unknown_zone_rejected(self, redteam):
        rc, out = redteam.check(
            "nginx_redteam_concurrency.conf", CA=self._ca(redteam),
            EXTRA="brix_concurrency_limit zone=nope key=ip limit=4;")
        assert rc != 0, "concurrency limit with an undeclared zone must be rejected"
        assert "unknown zone" in out, out
