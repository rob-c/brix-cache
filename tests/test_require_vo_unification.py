"""test_require_vo_unification.py — phase-101 W4: brix_webdav_require_vo →
brix_require_vo (per-path VOMS VO membership ACL).

The webdav-local vo_rules array moved into the shared preamble (common.vo_rules);
the bare brix_require_vo is now registered by the common module with a shared
grammar setter (src/core/config/policy.c → brix_http_conf_set_require_vo) and
adopted into every HTTP protocol conf.  The stream (root) plane already spelled
it bare.  It is honored on webdav/root where VOMS applies and parsed-but-inert on
s3 (SigV4 has no VO concept).

  * success (loc)  — bare brix_require_vo <path> <vo> parses inside a webdav
                     location; an s3 server may coexist (adopts it, inert).
  * success (main) — one http{}-scope brix_require_vo is adopted down into a
                     webdav location (proves the preamble+adopt path).
  * hard-rename    — the old brix_webdav_require_vo name is "unknown directive".
"""
import os
import subprocess
import tempfile

import pytest

from settings import NGINX_BIN

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN),
    reason="nginx binary (set NGINX_BIN) not available",
)


def _nginx_t(body):
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\nevents {{}}\n"
                + "http {\n"
                + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
                + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
                + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
                + "  brix_storage_backend posix:/tmp;\n"
                + body
                + "}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def test_bare_require_vo_parses_at_webdav_location():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28941;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_require_vo /data cms; brix_require_vo /data/sub atlas; } }\n")
    assert rc == 0, f"bare require_vo must parse at a webdav location:\n{out}"
    assert "successful" in out, out


def test_http_main_require_vo_adopts_into_webdav_and_coexists_with_s3():
    """One http{}-scope brix_require_vo is adopted down into a webdav location;
    an s3 server in the same http{} adopts it too (inert, but must not error)."""
    rc, out = _nginx_t(
        "  brix_require_vo /data cms;\n"
        "  server { listen 127.0.0.1:28942;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28943;\n"
        "    location / { brix_s3 on; brix_s3_bucket b; } }\n")
    assert rc == 0, f"http-main require_vo must adopt into webdav + s3:\n{out}"
    assert "successful" in out, out


def test_old_webdav_require_vo_name_unknown():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28944;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_webdav_require_vo /data cms; } }\n")
    assert rc != 0, out
    assert "unknown directive" in out and "brix_webdav_require_vo" in out, out
