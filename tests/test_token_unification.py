"""test_token_unification.py — phase-101 W4: the WLCG token-trust quartet
de-prefixed and COLLAPSED across planes:
  brix_{webdav,s3}_token_jwks      → brix_token_jwks
  brix_{webdav,s3}_token_issuer    → brix_token_issuer
  brix_{webdav,s3}_token_audience  → brix_token_audience
  brix_{webdav,s3}_token_clock_skew→ brix_token_clock_skew

The four fields moved into the shared preamble (one field each, was a webdav/s3
pair). The unified clock_skew default is 30s (webdav's; stricter than s3's old
60s). The auth-mode SELECTORS brix_webdav_auth / brix_s3_token are deliberately
NOT unified. Per-worker JWKS key loads stay protocol-local.

Deterministic `nginx -t` (issuer/audience/clock_skew need no JWKS load). The
success case uses `brix_webdav_auth none` so no live verifier is demanded — the
point is that the bare token-trust directives PARSE at http{} scope and ADOPT
into both a webdav and an s3 conf without error, not that a token is verified:
  * success     — one http{}-scope brix_token_issuer/audience/clock_skew set
                  adopts into a webdav AND an s3 location.
  * hard-rename — the old brix_webdav_token_* / brix_s3_token_* names are unknown.
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


def test_bare_token_trust_covers_webdav_and_s3():
    """One http{}-scope token-trust set adopts into both HTTP protocols (was two
    byte-parallel prefixed sets)."""
    rc, out = _nginx_t(
        "  brix_token_issuer https://issuer.example;\n"
        "  brix_token_audience https://aud.example;\n"
        "  brix_token_clock_skew 45;\n"
        "  server { listen 127.0.0.1:28931;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28932;\n"
        "    location / { brix_s3 on; brix_s3_bucket b; } }\n")
    assert rc == 0, f"bare token trust must parse on webdav + s3:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("old", [
    "brix_webdav_token_jwks", "brix_webdav_token_issuer",
    "brix_webdav_token_audience", "brix_webdav_token_clock_skew",
    "brix_s3_token_jwks", "brix_s3_token_issuer",
    "brix_s3_token_audience", "brix_s3_token_clock_skew",
])
def test_old_prefixed_token_names_unknown(old):
    proto = "brix_s3 on; brix_s3_bucket b;" if old.startswith("brix_s3") \
        else "brix_webdav on; brix_webdav_auth optional;"
    val = "42" if old.endswith("clock_skew") else "x"
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28933;\n"
        f"    location / {{ {proto} {old} {val}; }} }}\n")
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out
