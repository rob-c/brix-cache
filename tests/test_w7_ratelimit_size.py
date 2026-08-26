"""test_w7_ratelimit_size.py — phase-101 W7: ratelimit size-parser dedup.

The rate-limit code had two size parsers in ratelimit_keys_parse.c: a hand-rolled
k/m/g suffix parser (inside rl_parse_bw_rate) and rl_parse_size (which delegated to
nginx's ngx_parse_size). Contrary to the plan's premise, ngx_parse_size handles
ONLY k/m — NOT g — so the two were NOT a "superset": burst/zone sizes silently
rejected a gibibyte suffix while bandwidth RATES accepted it.

Both now route through one shared rl_parse_size_bytes(k|m|g) helper. This is a
strict SUPERSET (additive): every value that parsed before still parses, and a
`g` suffix on a burst or a zone size is now accepted too (matching the rate
grammar that already allowed `1g/s`). Bad values are still rejected.
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


def _nginx_t(zone_size, bw_rule=""):
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
                + f"  brix_rate_limit_zone zone=z:{zone_size};\n"
                + "  server { listen 127.0.0.1:29061; brix_root on;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + f"    brix_export /tmp; {bw_rule} }}\n}}\n")
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


@pytest.mark.parametrize("size", ["4m", "1024k", "1g", "2G", "512"])
def test_zone_size_accepts_kmg(size):
    """Zone sizes now accept g (they used to reject it via ngx_parse_size)."""
    rc, out = _nginx_t(size)
    assert rc == 0, f"brix_rate_limit_zone zone=z:{size} must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("burst", ["1g", "512m", "4096"])
def test_bandwidth_burst_accepts_kmg(burst):
    """Bandwidth burst now accepts g (via the shared parser)."""
    rc, out = _nginx_t("4m", f"brix_bandwidth_limit zone=z key=ip rate=1g/s burst={burst};")
    assert rc == 0, f"brix_bandwidth_limit burst={burst} must parse:\n{out}"
    assert "successful" in out, out


def test_bandwidth_rate_gigabit_still_parses():
    """The rate grammar already accepted g/s — must keep working after the dedup."""
    rc, out = _nginx_t("4m", "brix_bandwidth_limit zone=z key=ip rate=1g/s burst=64m;")
    assert rc == 0, out
    assert "successful" in out, out


def test_bad_zone_size_rejected():
    rc, out = _nginx_t("banana")
    assert rc != 0, out
    assert "bad size" in out or "brix_rate_limit_zone" in out, out


def test_bad_burst_rejected():
    rc, out = _nginx_t("4m", "brix_bandwidth_limit zone=z key=ip rate=1g/s burst=banana;")
    assert rc != 0, out
    assert "bad burst" in out or "brix_bandwidth_limit" in out, out
