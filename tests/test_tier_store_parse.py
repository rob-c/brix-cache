"""Config-parse units for the tier store-URL finaliser (src/fs/tier/tier_config.c
+ src/core/config/runtime_server_backend.c cross-directive checks).

`nginx -t` only. Store URLs parse at directive time but validate in the config
finaliser (brix_tier_parse_store), which emits [emerg] and so fails `nginx -t`.
brix_cache_store routes through that finaliser (the strings asserted here);
brix_storage_backend has its own setter with distinct wording. Each case
asserts the exact diagnostic. Harness lets the test own the full server body
and pre-creates the posix tier dirs (a posix store must be accessible).
"""

import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, HOST, NGINX_ANON_PORT, NGINX_BIN

REMOTE = f"brix_storage_backend root://{HOST}:{NGINX_ANON_PORT};"


def _nginx_t(root, body):
    for d in ("logs", "data", "cache", "cold"):
        (root / d).mkdir(exist_ok=True)
    conf = root / "tier.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13297;
    brix_root on;
    brix_auth none;
    {body}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# brix_cache_store bad URL → finaliser [emerg] (valid remote backend prepended).
STORE_URL_REJECT = [
    ("brix_cache_store nohost;", "has no scheme"),
    ("brix_cache_store bogus://h:1/;", 'unknown driver scheme "bogus"'),
    ("brix_cache_store root://[fe80::1/;", 'unbalanced "[" in store host'),
    ("brix_cache_store root://host:99999/;", "invalid store port"),
]


@pytest.mark.parametrize("store,needle", STORE_URL_REJECT)
def test_cache_store_url_rejected(tmp_path, store, needle):
    rc, out = _nginx_t(tmp_path, f"{REMOTE}\n    {store}")
    assert rc != 0, f"expected reject for {store!r}"
    assert needle in out, f"expected {needle!r} for {store!r}, got:\n{out}"


def test_storage_backend_missing_port_rejected(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_storage_backend root://host/;")
    assert rc != 0
    assert "remote origin needs host:port" in out, out


def test_posix_backend_accepted(tmp_path):
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend posix:{tmp_path}/data;")
    assert rc == 0, f"expected accept:\n{out}"


def test_remote_backend_with_cache_store_accepted(tmp_path):
    rc, out = _nginx_t(tmp_path, f"{REMOTE}\n    brix_cache_store posix:{tmp_path}/cache;")
    assert rc == 0, f"expected accept:\n{out}"


# Cross-directive tier rejects.
def test_cold_store_without_hot_rejected(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f"brix_storage_backend posix:{tmp_path}/data;\n"
        f"    brix_cache_cold_store posix:{tmp_path}/cold;",
    )
    assert rc != 0
    assert "requires brix_cache_store (the hot tier)" in out, out


def test_nearline_backend_requires_cache_store(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_storage_backend tape://host:1094/pool;")
    assert rc != 0
    assert "nearline and requires" in out, out


def test_slice_size_must_be_1m_multiple(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f"{REMOTE}\n    brix_cache_store posix:{tmp_path}/cache;\n"
        f"    brix_cache_slice_size 1500k;",
    )
    assert rc != 0
    assert "must be a positive multiple of 1m" in out, out


def test_slice_size_1m_accepted(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f"{REMOTE}\n    brix_cache_store posix:{tmp_path}/cache;\n"
        f"    brix_cache_slice_size 1m;",
    )
    assert rc == 0, f"expected accept:\n{out}"


# --- root+tape:// (a root:// origin declared to front an MSS) ---------------
# The scheme is what arms sd_xroot's nearline pair: residency from kXR_stat's
# kXR_offline flag, recall via kXR_prepare(kXR_stage). It is a CONTRACT, not a
# hint — an export that declares it must carry a cache tier to recall into, so
# the declaration is refused at config time when there is none.
def test_root_tape_backend_with_cache_store_accepted(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f"brix_storage_backend root+tape://{HOST}:{NGINX_ANON_PORT};\n"
        f"    brix_cache_store posix:{tmp_path}/cache;",
    )
    assert rc == 0, f"expected accept:\n{out}"


def test_root_tape_backend_without_cache_store_rejected(tmp_path):
    rc, out = _nginx_t(
        tmp_path, f"brix_storage_backend root+tape://{HOST}:{NGINX_ANON_PORT};")
    assert rc != 0
    assert "nearline and requires" in out, out


def test_roots_tape_backend_with_cache_store_accepted(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f"brix_storage_backend roots+tape://{HOST}:{NGINX_ANON_PORT};\n"
        f"    brix_cache_store posix:{tmp_path}/cache;",
    )
    assert rc == 0, f"expected accept:\n{out}"


# Confinement negative: a malformed nearline URL must be REJECTED, never fall
# through the remote-origin branch to be read as a local driver name (which
# would silently make the export a local store rooted wherever brix_export
# points, with none of the nearline contract enforced).
@pytest.mark.parametrize("url", [
    "root+tape://host",            # no port
    "root+tape://host:0",          # port out of range
    "root+tape://host:99999",
    "roots+tape://:1094",          # no host
])
def test_root_tape_malformed_rejected(tmp_path, url):
    rc, out = _nginx_t(
        tmp_path,
        f"brix_storage_backend {url};\n"
        f"    brix_cache_store posix:{tmp_path}/cache;",
    )
    assert rc != 0, f"expected reject for {url!r}:\n{out}"
    assert "remote origin" in out, f"for {url!r}, got:\n{out}"


# The `nearline` store param belongs to the BACKEND role only: a cache/stage
# tier IS the recall target, so accepting it there would leave the operator
# believing they had armed async recall when nothing reads the flag.
def test_nearline_param_rejected_on_cache_store(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f"{REMOTE}\n    brix_cache_store posix:{tmp_path}/cache nearline;",
    )
    assert rc != 0
    assert "belongs on brix_storage_backend" in out, out
