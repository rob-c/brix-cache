"""Config-parse units for src/fs/cache/directives.c custom setters.

`nginx -t` only (no server start): every case renders a minimal stream server
and asserts accept (rc==0) or reject (rc!=0 + the exact [emerg] diagnostic the
setter emits). Covers the validation branches — value ranges, unit suffixes,
duplicate guards, regex compilation — that the fast fleet tier never drives via
a running config. Harness mirrors tests/test_frm_directive_pin.py:56.
"""

import subprocess

import pytest

from settings import BIND_HOST, NGINX_BIN


def _nginx_t(root, srv_directives):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    conf = root / "pin.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13298;
    brix_root on;
    brix_storage_backend posix:{root}/data;
    brix_auth none;
    {srv_directives}
}} }}
""")
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# (directive-line, expect_ok, needle-if-reject)
ACCEPT = [
    ("brix_cache_origin_family auto;", True, None),
    ("brix_cache_origin_family inet;", True, None),
    ("brix_cache_origin_family inet6;", True, None),
    ("brix_cache_eviction_threshold 0.95;", True, None),
    ("brix_cache_eviction_threshold 95%;", True, None),
    ("brix_cache_max_file_size 10m;", True, None),
    ("brix_cache_max_file_size 1048576;", True, None),
    ("brix_cache_high_watermark 0.9;", True, None),
    ("brix_cache_high_watermark 90%;", True, None),
    ("brix_cache_low_watermark 0.8;", True, None),
    ("brix_cache_include_regex \\.root$;", True, None),
]

REJECT = [
    ("brix_cache_origin_family ipv7;", "must be one of: auto, inet, inet6"),
    ("brix_cache_eviction_threshold banana;", "invalid value"),
    ("brix_cache_eviction_threshold 0;", "greater than 0 and less than 1.0"),
    ("brix_cache_eviction_threshold 150%;", "greater than 0 and less than 1.0"),
    ("brix_cache_max_file_size 10x;", "unknown suffix"),
    ("brix_cache_max_file_size 10mZ;", "trailing garbage"),
    ("brix_cache_high_watermark banana;", "invalid value"),
    ("brix_cache_high_watermark 100%;", "greater than 0 and less than 1.0"),
    ("brix_cache_low_watermark 0;", "greater than 0 and less than 1.0"),
    ("brix_cache_include_regex [unclosed;", "invalid pattern"),
]

DUP = [
    "brix_cache_eviction_threshold 0.9; brix_cache_eviction_threshold 0.8;",
    "brix_cache_max_file_size 1m; brix_cache_max_file_size 2m;",
    "brix_cache_high_watermark 0.9; brix_cache_high_watermark 0.8;",
    "brix_cache_include_regex a; brix_cache_include_regex b;",
]


@pytest.mark.parametrize("directive,_ok,_n", ACCEPT)
def test_directive_accepted(tmp_path, directive, _ok, _n):
    rc, out = _nginx_t(tmp_path, directive)
    assert rc == 0, f"expected accept for {directive!r}:\n{out}"


@pytest.mark.parametrize("directive,needle", REJECT)
def test_directive_rejected(tmp_path, directive, needle):
    rc, out = _nginx_t(tmp_path, directive)
    assert rc != 0, f"expected reject for {directive!r}"
    assert needle in out, f"expected {needle!r} for {directive!r}, got:\n{out}"


@pytest.mark.parametrize("directive", DUP)
def test_directive_duplicate_rejected(tmp_path, directive):
    rc, out = _nginx_t(tmp_path, directive)
    assert rc != 0, f"expected duplicate reject for {directive!r}"
    assert "is duplicate" in out, f"expected duplicate diag, got:\n{out}"
