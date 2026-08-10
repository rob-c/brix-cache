"""test_tpc_verify_checksum_unification.py — phase-101 W4: the sixth (and
semantically hardest) HTTP-TPC twin, brix_webdav_tpc_verify_checksum, unified with
the native brix_tpc_verify_checksum into ONE on|off|<alg> grammar.

Before: the stream (root) plane took a boolean (brix_tpc_verify_checksum on|off)
while webdav named an RFC-3230 algorithm (brix_webdav_tpc_verify_checksum <alg>) —
a genuine semantic divergence, not a mechanical de-prefix. Now a single bare
directive on every plane accepts on | off | <algorithm>:
  * the value is normalized at parse into common.tpc_verify_checksum — "" = off;
    "on" => "adler32" (the XRootD/WLCG default checksum); an algorithm name => its
    canonical spelling (validated by brix_checksum_parse);
  * the native TPC reads it as a boolean gate (kXR_Qcksum negotiates its own
    algorithm), so on/off/<alg> all just mean verify-or-not there;
  * the webdav curl-COPY uses the algorithm for Want-Digest + the post-copy
    recompute, so "on" gives it a concrete default (adler32).

Backward-compatible both ways: existing stream `on|off` configs keep working, and
existing webdav `<alg>` configs keep working under the bare name. The old prefixed
brix_webdav_tpc_verify_checksum is gone (hard-rename).

  * success  — on|off|<alg> parse on BOTH a stream server and a webdav location.
  * error    — a non-{on,off,algorithm} value is a clear EMERG listing the algs.
  * hard-rename — brix_webdav_tpc_verify_checksum is "unknown directive".
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


def _nginx_t(stream_body="", http_loc_body=""):
    """Render a config with BOTH a stream brix_root server and a webdav location so
    the directive can be exercised on each plane."""
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
                + "stream {\n"
                + "  server { listen 127.0.0.1:29001; brix_root on;\n"
                + f"    brix_export /tmp; {stream_body} }}\n"
                + "}\n"
                + "http {\n"
                + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
                + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
                + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
                + "  brix_storage_backend posix:/tmp;\n"
                + "  server { listen 127.0.0.1:29002;\n"
                + f"    location / {{ brix_webdav on; brix_webdav_auth none; {http_loc_body} }} }}\n"
                + "}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


@pytest.mark.parametrize("value", ["on", "off", "sha256", "adler32", "crc32c"])
def test_unified_grammar_parses_on_both_planes(value):
    rc, out = _nginx_t(f"brix_tpc_verify_checksum {value};",
                       f"brix_tpc_verify_checksum {value};")
    assert rc == 0, f"brix_tpc_verify_checksum {value} must parse on both planes:\n{out}"
    assert "successful" in out, out


def test_stream_alg_now_accepted_additively():
    """The stream plane historically took only on|off; naming an algorithm there is
    now additively accepted (the native path still verifies with its own alg)."""
    rc, out = _nginx_t("brix_tpc_verify_checksum sha256;", "")
    assert rc == 0, f"stream brix_tpc_verify_checksum <alg> must parse:\n{out}"
    assert "successful" in out, out


def test_webdav_on_maps_to_default_algorithm():
    """The webdav plane historically required an explicit algorithm; a generic
    'on' now resolves to the adler32 default and must parse."""
    rc, out = _nginx_t("", "brix_tpc_verify_checksum on;")
    assert rc == 0, f"webdav brix_tpc_verify_checksum on must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("plane", ["stream", "webdav"])
def test_invalid_value_is_clear_emerg(plane):
    if plane == "stream":
        rc, out = _nginx_t("brix_tpc_verify_checksum banana;", "")
    else:
        rc, out = _nginx_t("", "brix_tpc_verify_checksum banana;")
    assert rc != 0, out
    assert "brix_tpc_verify_checksum" in out and "expected on, off" in out, out
    # the error must enumerate the accepted algorithms
    assert "sha256" in out and "adler32" in out, out


def test_old_webdav_prefixed_name_unknown():
    rc, out = _nginx_t("", "brix_webdav_tpc_verify_checksum sha256;")
    assert rc != 0, out
    assert "unknown directive" in out and "brix_webdav_tpc_verify_checksum" in out, out
