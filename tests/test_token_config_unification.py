"""test_token_config_unification.py — phase-101 W4: brix_webdav_token_config →
brix_token_config (multi-issuer SciTokens registry file).

The webdav-local token_config str field moved into the shared preamble
(common.token_config); the bare brix_token_config is now registered by the common
module (str slot) and adopted into every HTTP protocol conf.  The stream (root)
plane already spelled it bare.  When set it overrides the single-issuer
jwks/issuer/audience fields; the built token_registry stays protocol-local.

A webdav location that ends up with token_config set (directly or adopted) builds
the registry at config time, so the success cases point it at a minimal valid
scitokens.cfg ([Issuer …] with issuer= + base_path=).

  * success (main) — one http{}-scope brix_token_config adopts into a webdav
                     location (registry built) and an s3 location (str adopted).
  * hard-rename    — the old brix_webdav_token_config name is "unknown directive".
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

SCITOKENS_CFG = "[Issuer test]\nissuer = https://issuer.example\nbase_path = /\n"


def _nginx_t(body):
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        cfg = os.path.join(d, "scitokens.cfg")
        with open(cfg, "w") as fh:
            fh.write(SCITOKENS_CFG)
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
                + body.replace("{CFG}", cfg)
                + "}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def test_bare_token_config_adopts_into_webdav_and_s3():
    rc, out = _nginx_t(
        "  brix_token_config {CFG};\n"
        "  server { listen 127.0.0.1:28971;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28972;\n"
        "    location / { brix_s3 on; brix_s3_bucket b; } }\n")
    assert rc == 0, f"bare token_config must adopt into webdav + s3:\n{out}"
    assert "successful" in out, out


def test_bare_token_config_builds_registry_at_webdav_location():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28973;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_token_config {CFG}; } }\n")
    assert rc == 0, f"bare token_config must build the registry at a webdav loc:\n{out}"
    assert "successful" in out, out


def test_old_webdav_token_config_name_unknown():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28974;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_webdav_token_config {CFG}; } }\n")
    assert rc != 0, out
    assert "unknown directive" in out and "brix_webdav_token_config" in out, out
