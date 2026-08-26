"""test_cache_root_unification.py — phase-101 W8: brix_{webdav,s3}_cache_root →
bare brix_cache_root.

W8 was a MIGRATE-OR-KEEP decision. The behavior diff showed the legacy read-through
cache (cache_root → cache_storage_inst) is a DISTINCT, live mechanism that the
composable tier (brix_cache_store → sd_cache decorator) does not subsume (see
cache_storage.c: the reaper evicts through different instances depending on which
is set). So the honest outcome is option B — keep the mechanism, unify the two
byte-parallel prefixed twins into one bare name.

The cache_root (str) + cache_root_canon (char[PATH_MAX]) fields moved into the
shared preamble (common.*); brix_cache_root is registered once by the common
module and adopted into webdav and s3; each protocol still canonicalizes it (and
enforces the "outside every export root" guard) at merge. The stream plane's
fd-based cache (brix_cache_export) is a separate mechanism, left as-is.
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


def _load():
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    return "".join(f"load_module {m};\n" for m in modules)


def _nginx_t(http_main="", webdav_loc="", s3_loc=""):
    """One http{} with a webdav server + an s3 server; the export root is {d}/exp
    and a sibling {d}/cachedir sits OUTSIDE it. Placeholders {CACHE} (outside) and
    {UNDER} (inside the export) are substituted."""
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp", "exp", "cachedir"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        sub = lambda s: (s.replace("{CACHE}", d + "/cachedir")
                          .replace("{UNDER}", d + "/exp"))
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                _load()
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\nevents {{}}\n"
                + "http {\n"
                + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
                + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
                + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
                + f"  brix_storage_backend posix:{d}/exp;\n"
                + sub(http_main)
                + "  server { listen 127.0.0.1:29091;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + f"    location / {{ brix_webdav on; brix_webdav_auth none; {sub(webdav_loc)} }} }}\n"
                + "  server { listen 127.0.0.1:29092;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + f"    location / {{ brix_s3 on; brix_s3_bucket b; {sub(s3_loc)} }} }}\n"
                + "}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def test_bare_cache_root_adopts_into_webdav_and_s3():
    rc, out = _nginx_t(http_main="  brix_cache_root {CACHE};\n")
    assert rc == 0, f"bare brix_cache_root must adopt into webdav + s3:\n{out}"
    assert "successful" in out, out


def test_bare_cache_root_at_webdav_location():
    rc, out = _nginx_t(webdav_loc="brix_cache_root {CACHE};")
    assert rc == 0, f"bare brix_cache_root at a webdav loc must parse:\n{out}"
    assert "successful" in out, out


def test_cache_root_outside_export_guard_names_new_directive():
    # a cache_root at/beneath the export root is rejected — and the error must name
    # the NEW bare directive, proving the guard flows through the unified name.
    rc, out = _nginx_t(webdav_loc="brix_cache_root {UNDER};")
    assert rc != 0, out
    assert "brix_cache_root" in out and "brix_webdav" + "_cache_root" not in out, out


def test_old_webdav_cache_root_unknown():
    old = "brix_webdav" + "_cache_root"  # concatenated so a rename sweep won't touch it
    rc, out = _nginx_t(webdav_loc=old + " {CACHE};")
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out


def test_old_s3_cache_root_unknown():
    old = "brix_s3" + "_cache_root"  # concatenated so a rename sweep won't touch it
    rc, out = _nginx_t(s3_loc=old + " {CACHE};")
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out
