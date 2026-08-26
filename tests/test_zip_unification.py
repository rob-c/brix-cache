"""test_zip_unification.py — phase-101 W4: the ZIP member-access directives after
de-prefixing.

Before W4, brix_webdav_zip_access / brix_webdav_zip_cd_max_bytes and the byte-
parallel brix_s3_zip_* twins were separate registrations on the webdav and s3
modules (the stream plane already had bare brix_zip_*). W4 collapsed the HTTP
twins into ONE bare pair on the shared common module (fields promoted into the
preamble, adopted into every HTTP protocol incl. cvmfs).

Deterministic `nginx -t` config-parse tests (no fleet needed):

  * success       — one bare `brix_zip_access on;` at http{} scope covers webdav,
                    s3 AND cvmfs; brix_zip_cd_max_bytes takes a size.
  * hard-rename   — the retired names brix_webdav_zip_access / brix_s3_zip_access
                    are now "unknown directive" (W4 mandates NO alias code —
                    failing loudly is the correct behaviour).
  * error         — brix_zip_access maybe → stock flag-slot error.
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


def test_bare_zip_access_covers_all_http_protocols():
    """One http{}-scope brix_zip_access covers webdav + s3 + cvmfs (was three
    separate prefixed directives, and cvmfs had none)."""
    rc, out = _nginx_t(
        "  brix_zip_access on;\n"
        "  brix_zip_cd_max_bytes 8m;\n"
        "  server { listen 127.0.0.1:28481;\n"
        "    location /dav/ { brix_webdav on; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28482;\n"
        "    location /s3/ { brix_s3 on; brix_s3_bucket b; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28483;\n"
        "    location /cvmfs/ { brix_cvmfs on; } }\n")  # net-literal-allow: loopback literal is the subject under test
    assert rc == 0, f"bare brix_zip_access must parse on all HTTP planes:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("old", ["brix_webdav_zip_access", "brix_s3_zip_access",
                                 "brix_webdav_zip_cd_max_bytes",
                                 "brix_s3_zip_cd_max_bytes"])
def test_old_prefixed_names_are_unknown(old):
    """Hard-rename: the retired prefixed names must fail as unknown directives —
    NO alias, no 'renamed to' hint (phase-101 convention: fail loudly)."""
    val = "16m" if old.endswith("bytes") else "on"
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28484;\n"
        f"    location / {{ brix_webdav on; brix_webdav_auth none; {old} {val}; }} }}\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc != 0, f"{old} should be an unknown directive now:\n{out}"
    assert "unknown directive" in out and old in out, out


def test_zip_access_bad_flag_stock_error():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28485;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; brix_zip_access maybe; } }\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc != 0, out
    assert 'it must be "on" or "off"' in out, out
