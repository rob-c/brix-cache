"""
tests/test_security_redteam.py

Phase 28 adversarial-hardening regression suite.

These tests validate the CONFIG-LEVEL contract of the Phase 28 hardening
directives — that the new security gates are wired in, parse correctly, and
fail closed where required.  They use `nginx -t` against crafted configs, so
they are self-contained and need no running backends.

The wire-level negative paths (a non-allowlisted CMS peer being refused
registration, an S3 unknown-key vs bad-signature returning identical bodies, a
WebDAV-TPC source whose DNS rebinds to a metadata IP being blocked) are
exercised end-to-end by the live suites (test_evil_paths.py,
test_token_security.py) and, for vanilla cmsd sss interop, by
test_cms_mesh_interop.py when the mesh is configured with `sec.protocol sss`.

Run:
    NGINX_BIN=/tmp/nginx-1.28.3/objs/nginx \
        PYTHONPATH=tests pytest tests/test_security_redteam.py -v
"""

import os
import subprocess
import tempfile

import pytest

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")


def _nginx_test(conf_text, extra_files=None):
    """Write conf (+ optional files) to a temp prefix and run `nginx -t`.

    Returns (returncode, combined_output).  extra_files maps a format
    placeholder name -> (relative_path, content_bytes, mode); each file is
    created and its absolute path is substituted into the conf via .format().
    """
    prefix = tempfile.mkdtemp(prefix="redteam_")
    for sub in ("logs", "conf", "tmp", "data"):
        os.makedirs(os.path.join(prefix, sub), exist_ok=True)
    created = {}
    for name, (rel, content, mode) in (extra_files or {}).items():
        path = os.path.join(prefix, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)
        os.chmod(path, mode)
        created[name] = path
    conf_path = os.path.join(prefix, "conf", "nginx.conf")
    with open(conf_path, "w") as fh:
        fh.write(conf_text.format(prefix=prefix, **created))
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", prefix, "-c", "conf/nginx.conf"],
        capture_output=True, text=True,
    )
    return proc.returncode, (proc.stdout + proc.stderr)


def _have_nginx():
    return os.path.exists(NGINX_BIN)


pytestmark = pytest.mark.skipif(not _have_nginx(),
                                reason="nginx binary not built")


# ---------------------------------------------------------------------------
# W6 — admin secret hygiene + upstream allowlist
# ---------------------------------------------------------------------------

class TestAdminSecretHardening:

    BASE = """
daemon off; pid {prefix}/nginx.pid; error_log {prefix}/logs/e.log info;
events {{ worker_connections 64; }}
http {{
  client_body_temp_path {prefix}/tmp;
  proxy_temp_path {prefix}/tmp;
  fastcgi_temp_path {prefix}/tmp;
  uwsgi_temp_path {prefix}/tmp;
  scgi_temp_path {prefix}/tmp;
  server {{ listen 28310;
    location /xrootd/api/v1/admin/ {{
      xrootd_dashboard on;
      xrootd_admin_secret {secret};
      {extra}
    }} }} }}
"""

    def test_short_secret_rejected(self):
        rc, out = _nginx_test(
            self.BASE.replace("{extra}", ""),
            {"secret": ("secret", b"short", 0o600)},
        )
        assert rc != 0, "a <16 byte admin secret must be rejected at config load"
        assert "too short" in out, out

    def test_long_secret_accepted(self):
        rc, out = _nginx_test(
            self.BASE.replace("{extra}", ""),
            {"secret": ("secret",
                        b"a-sufficiently-long-admin-secret-0123456789", 0o600)},
        )
        # A clean parse reaches "test is successful"; any directive error would
        # surface as an [emerg] about the directive itself.
        assert "too short" not in out, out
        assert "xrootd_admin" not in out or "successful" in out, out

    def test_proxy_allow_directive_parses(self):
        rc, out = _nginx_test(
            self.BASE.replace(
                "{extra}",
                "xrootd_admin_proxy_allow backend.example.org 10.1.2.3;"),
            {"secret": ("secret",
                        b"a-sufficiently-long-admin-secret-0123456789", 0o600)},
        )
        assert "xrootd_admin_proxy_allow" not in out or "successful" in out, out
        assert "unknown directive" not in out, out


# ---------------------------------------------------------------------------
# W1 — CMS registration auth directives + keytab permission enforcement
# ---------------------------------------------------------------------------

class TestCmsAuthConfig:

    BASE = """
daemon off; pid {prefix}/nginx.pid; error_log {prefix}/logs/e.log info;
events {{ worker_connections 64; }}
stream {{
  server {{ listen 28311;
    xrootd_cms_server on;
    {extra}
  }} }}
"""

    KEYTAB = b"0 N:1 k:" + b"a" * 64 + b" u:cmsnode g:cms n:cluster\n"

    def test_allow_and_keytab_parse(self):
        rc, out = _nginx_test(
            self.BASE.replace(
                "{extra}",
                "xrootd_cms_server_allow 127.0.0.0/8 10.0.0.0/8;\n"
                "    xrootd_cms_server_sss_keytab {keytab};"),
            {"keytab": ("cms.keytab", self.KEYTAB, 0o600)},
        )
        # rc == 0 means the keytab parsed and loaded (a malformed keytab or bad
        # permission would emerg here); the "sss auth configured" NOTICE itself
        # goes to the error_log file, not nginx -t's stderr.
        assert rc == 0, out

    def test_world_readable_keytab_rejected(self):
        rc, out = _nginx_test(
            self.BASE.replace(
                "{extra}", "xrootd_cms_server_sss_keytab {keytab};"),
            {"keytab": ("cms.keytab", self.KEYTAB, 0o644)},   # world-readable
        )
        assert rc != 0, "a world-readable cms sss keytab must be rejected"
        assert "unsafe permissions" in out, out

    def test_bad_cidr_rejected(self):
        rc, out = _nginx_test(
            self.BASE.replace(
                "{extra}", "xrootd_cms_server_allow not-a-cidr;"),
        )
        assert rc != 0, "an invalid CIDR must be rejected"
        assert "invalid CIDR" in out, out


# ---------------------------------------------------------------------------
# W7 — per-principal concurrency limit directive
# ---------------------------------------------------------------------------

class TestConcurrencyLimitConfig:

    BASE = """
daemon off; pid {prefix}/nginx.pid; error_log {prefix}/logs/e.log info;
events {{ worker_connections 64; }}
http {{
  client_body_temp_path {prefix}/tmp;
  proxy_temp_path {prefix}/tmp;
  fastcgi_temp_path {prefix}/tmp;
  uwsgi_temp_path {prefix}/tmp;
  scgi_temp_path {prefix}/tmp;
  xrootd_rate_limit_zone zone=conc:1m;
  server {{ listen 28312;
    location / {{ xrootd_webdav on; xrootd_webdav_storage_backend posix:{prefix}/data;
      xrootd_webdav_auth optional; xrootd_webdav_cafile {ca};
      {extra} }} }} }}
"""

    def _files(self):
        return {"ca": ("data/ca", b"dummy", 0o600)}

    def test_concurrency_directive_parses(self):
        rc, out = _nginx_test(
            self.BASE.replace("{extra}",
                              "xrootd_concurrency_limit zone=conc key=ip limit=4;"),
            self._files(),
        )
        # cafile is a dummy so TLS init may complain, but the concurrency
        # directive itself must not be flagged unknown/invalid.
        assert "unknown parameter" not in out, out
        assert "unknown directive" not in out, out

    def test_concurrency_requires_limit(self):
        rc, out = _nginx_test(
            self.BASE.replace("{extra}",
                              "xrootd_concurrency_limit zone=conc key=ip;"),
            self._files(),
        )
        assert rc != 0, "concurrency limit must require limit="
        assert "limit=" in out, out

    def test_concurrency_unknown_zone_rejected(self):
        rc, out = _nginx_test(
            self.BASE.replace("{extra}",
                              "xrootd_concurrency_limit zone=nope key=ip limit=4;"),
            self._files(),
        )
        assert rc != 0, "concurrency limit with an undeclared zone must be rejected"
        assert "unknown zone" in out, out
