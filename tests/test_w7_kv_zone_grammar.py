"""test_w7_kv_zone_grammar.py — phase-101 W7 (Commit B): brix_kv_zone adopts the
nginx-conventional zone=name:size grammar.

Before: brix_kv_zone <name> <size> key=<bytes> val=<bytes>  (positional)
After:  brix_kv_zone zone=<name>:<size> key=<bytes> val=<bytes>

This unifies the shared-memory zone grammar with brix_rate_limit_zone (and
brix_token_cache), which already use zone=name:size. It is a HARD grammar change
(hard-rename discipline) — the old positional form is rejected with an EMERG that
names the new shape.
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


def _nginx_t(main_body):
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "logs"), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + f"error_log {d}/logs/e.log;\npid {d}/logs/n.pid;\nevents {{}}\n"
                + "stream {\n"
                + f"  {main_body}\n"
                + "  server { listen 127.0.0.1:29071; brix_root on; brix_export /tmp; }\n"
                + "}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def test_new_zone_grammar_parses():
    rc, out = _nginx_t("brix_kv_zone zone=tkn:16m key=32 val=5120;")
    assert rc == 0, f"brix_kv_zone zone=name:size must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("size", ["1m", "16m", "512k", "1048576"])
def test_zone_size_units(size):
    # kv_zone sizes use nginx's ngx_parse_size (k/m + bytes) — SHM zones don't
    # need a gibibyte suffix.
    rc, out = _nginx_t(f"brix_kv_zone zone=z:{size} key=32 val=16;")
    assert rc == 0, f"zone size {size} must parse:\n{out}"
    assert "successful" in out, out


def test_old_positional_form_rejected_with_new_shape_hint():
    rc, out = _nginx_t("brix_kv_zone tkn 16m key=32 val=5120;")
    assert rc != 0, out
    assert "brix_kv_zone" in out and "zone=name:size" in out, out


def test_zone_without_colon_rejected():
    rc, out = _nginx_t("brix_kv_zone zone=tkn key=32 val=5120;")
    assert rc != 0, out
    assert "expected zone=name:size" in out, out


def test_missing_val_rejected():
    # zone= + key= present, val= omitted (two args so it clears NGX_CONF_2MORE and
    # reaches the setter's key/val validation).
    rc, out = _nginx_t("brix_kv_zone zone=tkn:16m key=32;")
    assert rc != 0, out
    assert "key=" in out and "val=" in out, out
