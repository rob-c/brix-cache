"""test_voms_unification.py — phase-101 W4: brix_webdav_vomsdir → brix_vomsdir and
brix_webdav_voms_cert_dir → brix_voms_cert_dir (VOMS AC trust directories). Both
str fields moved into the shared preamble; bare on the stream plane already.

  * success     — bare brix_vomsdir + brix_voms_cert_dir parse at a webdav loc.
  * hard-rename — the old brix_webdav_voms* names are now "unknown directive".
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
        for sub in ("logs", "tmp", "voms", "certs"):
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
                + body.replace("{DIR}", d)
                + "}\n")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def test_bare_voms_dirs_parse():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28921;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_vomsdir {DIR}/voms; brix_voms_cert_dir {DIR}/certs; } }\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc == 0, f"bare voms dirs must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("old", ["brix_webdav_vomsdir", "brix_webdav_voms_cert_dir"])
def test_old_webdav_voms_names_unknown(old):
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28922;\n"
        f"    location / {{ brix_webdav on; brix_webdav_auth none; {old} {{DIR}}/voms; }} }}\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out
