"""test_upload_unification.py — phase-101 W4: brix_webdav_upload_resume →
brix_upload_resume (resumable Content-Range PUT). De-prefixed to the bare name
the stream plane already used; the flag moved into the shared preamble and keeps
its default-ON semantics.

Deterministic `nginx -t` config-parse tests:
  * success     — bare brix_upload_resume off parses at a webdav location.
  * hard-rename — brix_webdav_upload_resume is now "unknown directive".
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
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def test_bare_upload_resume_parses():
    rc, out = _nginx_t(
        "  brix_upload_resume off;\n"          # http scope
        "  server { listen 127.0.0.1:28681;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_upload_resume on; } }\n")  # net-literal-allow: loopback literal is the subject under test
    assert rc == 0, f"bare brix_upload_resume must parse:\n{out}"
    assert "successful" in out, out


def test_old_webdav_upload_resume_is_unknown():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28682;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_webdav_upload_resume on; } }\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc != 0, out
    assert "unknown directive" in out and "brix_webdav_upload_resume" in out, out
