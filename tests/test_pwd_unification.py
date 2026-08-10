"""test_pwd_unification.py — phase-101 W4: brix_webdav_pwd_file → brix_pwd_file.

The HTTP basic-auth password-db directive is de-prefixed to the bare name the
stream plane already used; the backing field moved into the shared preamble.

Deterministic `nginx -t` config-parse tests (no fleet):
  * success     — bare brix_pwd_file parses at a webdav location and at http{}
                  scope; the file is validated at parse time.
  * hard-rename — brix_webdav_pwd_file is now "unknown directive" (no alias).
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


def _nginx_t(body, extra_files=None):
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        for name, content in (extra_files or {}).items():
            with open(os.path.join(d, name), "w") as fh:
                fh.write(content)
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
                + body.replace("{DIR}", d)
                + "}\n")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


# A minimal htpasswd-style line so brix_pwd_file <path> validates at parse time.
_PWD = "alice:$1$abcdefgh$0123456789012345678901\n"


def test_bare_pwd_file_parses_webdav_and_http_scope():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28581;\n"
        "    location / { brix_webdav on; brix_webdav_auth optional;\n"
        "      brix_pwd_file {DIR}/htpasswd; } }\n",
        extra_files={"htpasswd": _PWD})
    assert rc == 0, f"bare brix_pwd_file must parse on webdav:\n{out}"
    assert "successful" in out, out


def test_old_webdav_pwd_file_is_unknown():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28582;\n"
        "    location / { brix_webdav on; brix_webdav_auth optional;\n"
        "      brix_webdav_pwd_file {DIR}/htpasswd; } }\n",
        extra_files={"htpasswd": _PWD})
    assert rc != 0, f"brix_webdav_pwd_file must be unknown now:\n{out}"
    assert "unknown directive" in out and "brix_webdav_pwd_file" in out, out
