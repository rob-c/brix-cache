"""test_idmap_rename.py — phase-101 W6: the per-request UNIX identity directives
unified under ONE prefix, brix_idmap (Rule 2: one prefix per feature).

Four old prefixes (brix_impersonation, brix_impersonation_*, brix_gridmap, and the
already-conforming brix_idmap_*) collapse to a single brix_idmap family:
  brix_impersonation            → brix_idmap            (off|single|map toggle)
  brix_impersonation_user       → brix_idmap_user
  brix_impersonation_socket     → brix_idmap_socket
  brix_impersonation_export     → brix_idmap_export
  brix_impersonation_broker_user→ brix_idmap_broker_user
  brix_gridmap                  → brix_idmap_gridmap
  (brix_idmap_default_user / _min_uid / _cache_ttl / _forbidden_users /
   _forbidden_groups were already brix_idmap_* — unchanged.)

Name-only rename: the setters (brix_imp_conf_*) and the process-global settings
block (BRIX_IMP_F_* selectors) are untouched, so every mode/validation behaves
identically under the new spelling. These are hard renames — the old names are
gone.

Self-contained `nginx -t` (stream plane; brix_idmap is NGX_STREAM_{MAIN,SRV}_CONF).
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


def _nginx_t(server_body):
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "logs"), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\nevents {{}}\n"
                + "stream {\n"
                + "  server { listen 127.0.0.1:29031; brix_root on;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + f"    brix_export /tmp; {server_body.replace('{D}', d)} }}\n"
                + "}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


# --- new names accepted ---

def test_idmap_off_parses():
    rc, out = _nginx_t("brix_idmap off;")
    assert rc == 0, out
    assert "successful" in out


def test_idmap_single_with_user_parses():
    rc, out = _nginx_t("brix_idmap single; brix_idmap_user nobody;")
    assert rc == 0, out
    assert "successful" in out


def test_idmap_forbidden_lists_parse():
    """The identity deny-lists (security-critical) parse under the new prefix."""
    rc, out = _nginx_t(
        "brix_idmap single; brix_idmap_user nobody;\n"
        "    brix_idmap_forbidden_users root;\n"
        "    brix_idmap_forbidden_groups wheel;")
    assert rc == 0, out
    assert "successful" in out


# --- rename preserved the validation wiring (error names the NEW spelling) ---

def test_single_without_user_error_names_new_directive():
    rc, out = _nginx_t("brix_idmap single;")
    assert rc != 0, out
    # the rename must have flowed into the validation error string too
    assert "brix_idmap_user" in out, out
    assert "brix_impersonation" not in out, out


def test_invalid_mode_error_names_new_directive():
    rc, out = _nginx_t("brix_idmap bogus;")
    assert rc != 0, out
    assert "brix_idmap" in out and "brix_impersonation" not in out, out


# --- old names are gone (hard rename) ---

@pytest.mark.parametrize("old,val", [
    ("brix_impersonation", "off"),
    ("brix_impersonation_user", "nobody"),
    ("brix_impersonation_socket", "{D}/b.sock"),
    ("brix_impersonation_export", "/tmp"),
    ("brix_impersonation_broker_user", "nobody"),
    ("brix_gridmap", "{D}/gm"),
])
def test_old_identity_names_unknown(old, val):
    rc, out = _nginx_t(f"{old} {val};")
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out
