"""test_macaroon_unification.py — phase-101 W4: brix_webdav_macaroon_secret[_old]
→ brix_macaroon_secret[_old]. De-prefixed to the bare names the stream plane
already used; the two HMAC-secret fields moved into the shared preamble.

Deterministic `nginx -t` config-parse tests:
  * success     — bare brix_macaroon_secret + brix_macaroon_secret_old parse at a
                  webdav location (macaroon auth requires token support on).
  * hard-rename — the old brix_webdav_macaroon_secret[_old] are now unknown.
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

_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


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


def test_bare_macaroon_secret_parses():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28781;\n"
        "    location / { brix_webdav on; brix_webdav_auth optional;\n"
        f"      brix_macaroon_secret {_HEX};\n"
        f"      brix_macaroon_secret_old {_HEX}; }} }}\n")
    assert rc == 0, f"bare brix_macaroon_secret[_old] must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("old", ["brix_webdav_macaroon_secret",
                                 "brix_webdav_macaroon_secret_old"])
def test_old_webdav_macaroon_names_unknown(old):
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28782;\n"
        "    location / { brix_webdav on; brix_webdav_auth optional;\n"
        f"      {old} {_HEX}; }} }}\n")
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out
