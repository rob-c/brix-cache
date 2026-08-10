"""test_w6_renames.py — phase-101 W6: naming-grammar outlier renames.

Per the codified grammar (docs/09-developer-guide/coding-standards.md):
  Rule 1: brix_<feature> is the feature toggle (no _enable).
  Rule 2: brix_<feature>_<param>, ONE prefix per feature.

Renames covered here (each a hard rename — the old name is gone):
  * brix_ocsp_enable        → brix_ocsp                    (Rule 1; siblings
        brix_ocsp_soft_fail / _require_nonce / _stapling already conform)
  * brix_scan_root          → brix_dashboard_scan_root     (Rule 2; disambiguates
        from the DIFFERENT brix_dashboard_browse_root confinement root)
  * brix_scan_max_files     → brix_dashboard_scan_max_files

(The larger impersonation-prefix unification to brix_idmap is deferred — its old
names span ~90 test/config files and need a dedicated coordinated sweep.)
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


def _nginx_t(text_builder):
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp", "data"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(text_builder(d))
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def _stream_conf(d, body):
    return (_load()
            + f"error_log {d}/logs/e.log;\npid {d}/logs/n.pid;\nevents {{}}\n"
            + "stream {\n"
            + "  server { listen 127.0.0.1:29011; brix_root on;\n"
            + f"    brix_export /tmp; {body} }}\n}}\n")


def _http_dash_conf(d, body):
    return (_load()
            + f"error_log {d}/logs/e.log;\npid {d}/logs/n.pid;\nevents {{}}\n"
            + "http {\n"
            + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
            + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
            + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
            + "  server { listen 127.0.0.1:29012;\n"
            + f"    location /dash {{ brix_dashboard on; {body.replace('{DATA}', d + '/data')} }} }}\n}}\n")


# --- brix_ocsp (Rule 1) ---

def test_brix_ocsp_new_name_parses():
    rc, out = _nginx_t(lambda d: _stream_conf(d, "brix_ocsp on;"))
    assert rc == 0, f"brix_ocsp must parse:\n{out}"
    assert "successful" in out, out


def test_brix_ocsp_enable_old_name_unknown():
    rc, out = _nginx_t(lambda d: _stream_conf(d, "brix_ocsp_enable on;"))
    assert rc != 0, out
    assert "unknown directive" in out and "brix_ocsp_enable" in out, out


# --- brix_dashboard_scan_* (Rule 2) ---

def test_dashboard_scan_new_names_parse():
    rc, out = _nginx_t(lambda d: _http_dash_conf(
        d, "brix_dashboard_scan_root {DATA}; brix_dashboard_scan_max_files 5000;"))
    assert rc == 0, f"brix_dashboard_scan_* must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("old", ["brix_scan_root", "brix_scan_max_files"])
def test_dashboard_scan_old_names_unknown(old):
    val = "5000" if old.endswith("max_files") else "{DATA}"
    rc, out = _nginx_t(lambda d: _http_dash_conf(d, f"{old} {val};"))
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out
