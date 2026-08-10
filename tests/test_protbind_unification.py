"""test_protbind_unification.py — phase-101 W4: brix_webdav_protbind →
brix_protbind (per-host credential-source binding, XRootD sec.protbind).

The webdav-local protbind array moved into the shared preamble (common.protbind);
the bare brix_protbind is now registered by the common module with the same shared
grammar engine (src/auth/protbind/) that the stream plane already uses, via
brix_http_conf_set_protbind (src/core/config/policy.c), and adopted into every
HTTP protocol conf.  The rule array is inherited whole (never merged element-wise)
because rule ORDER decides which host template matches first.

  * success (loc)  — bare brix_protbind inside a webdav location parses; an s3
                     server may coexist (adopts it, inert).
  * success (main) — one http{}-scope brix_protbind is adopted down into a webdav
                     location (proves the preamble+adopt path).
  * hard-rename    — the old brix_webdav_protbind name is "unknown directive".
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


def test_bare_protbind_parses_at_webdav_location():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28951;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_protbind *.cern.ch only gsi;\n"
        "      brix_protbind grid.example.org token; } }\n")
    assert rc == 0, f"bare protbind must parse at a webdav location:\n{out}"
    assert "successful" in out, out


def test_http_main_protbind_adopts_into_webdav_and_coexists_with_s3():
    rc, out = _nginx_t(
        "  brix_protbind *.cern.ch only gsi;\n"
        "  server { listen 127.0.0.1:28952;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28953;\n"
        "    location / { brix_s3 on; brix_s3_bucket b; } }\n")
    assert rc == 0, f"http-main protbind must adopt into webdav + s3:\n{out}"
    assert "successful" in out, out


def test_old_webdav_protbind_name_unknown():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28954;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_webdav_protbind *.x only gsi; } }\n")
    assert rc != 0, out
    assert "unknown directive" in out and "brix_webdav_protbind" in out, out
