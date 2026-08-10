"""test_tpc_unification.py — phase-101 W4: the HTTP-TPC SSRF + source-allowlist
policy de-prefixed onto the shared preamble.

Five byte-compatible webdav twins collapse to the bare stream spelling:
  brix_webdav_tpc_allow_local          → brix_tpc_allow_local
  brix_webdav_tpc_allow_private        → brix_tpc_allow_private
  brix_webdav_tpc_source_guard         → brix_tpc_source_guard
  brix_webdav_tpc_source_allow         → brix_tpc_source_allow
  brix_webdav_tpc_require_source_size  → brix_tpc_require_source_size

The five fields moved into common.tpc_*; brix_tpc_source_allow uses a custom
setter that appends EVERY argument (a SECURITY allowlist must not silently keep
only the first).  Honored by the webdav curl-COPY engine; the native root:// TPC
reads its own stream-conf copies.

The sixth TPC twin, brix_tpc_verify_checksum, was later unified too (flag on
stream vs <alg> on webdav) into one on|off|<alg> grammar — see
test_tpc_verify_checksum_unification.py.  Here we only pin that the old webdav
name is gone.

  * success (loc)  — the five bare brix_tpc_* parse inside a webdav location;
                     an s3 server may coexist (adopts them, inert).
  * success (main) — one http{}-scope bare knob adopts down into a webdav loc.
  * hard-rename    — each old brix_webdav_tpc_<twin> is "unknown directive".
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

TWINS = [
    "tpc_allow_local", "tpc_allow_private", "tpc_source_guard",
    "tpc_source_allow", "tpc_require_source_size",
]


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


def test_bare_tpc_knobs_parse_at_webdav_location():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28961;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_tpc_allow_local on; brix_tpc_allow_private on;\n"
        "      brix_tpc_source_guard on;\n"
        "      brix_tpc_source_allow a.cern.ch .example.org b.cern.ch;\n"
        "      brix_tpc_require_source_size on; } }\n")
    assert rc == 0, f"bare brix_tpc_* must parse at a webdav location:\n{out}"
    assert "successful" in out, out


def test_http_main_tpc_knob_adopts_into_webdav_and_coexists_with_s3():
    rc, out = _nginx_t(
        "  brix_tpc_allow_private on;\n"
        "  server { listen 127.0.0.1:28962;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; } }\n"
        "  server { listen 127.0.0.1:28963;\n"
        "    location / { brix_s3 on; brix_s3_bucket b; } }\n")
    assert rc == 0, f"http-main brix_tpc_* must adopt into webdav + s3:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("twin", TWINS)
def test_old_webdav_tpc_twin_unknown(twin):
    val = "a.b.c" if twin == "tpc_source_allow" else "on"
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28964;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        f"      brix_webdav_{twin} {val}; }} }}\n")
    assert rc != 0, out
    assert "unknown directive" in out and f"brix_webdav_{twin}" in out, out


def test_old_webdav_verify_checksum_name_unknown():
    """brix_webdav_tpc_verify_checksum was unified into the bare
    brix_tpc_verify_checksum (see test_tpc_verify_checksum_unification.py); the
    prefixed name must now be rejected."""
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28965;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_webdav_tpc_verify_checksum sha256; } }\n")
    assert rc != 0, out
    assert "unknown directive" in out and "brix_webdav_tpc_verify_checksum" in out, out
