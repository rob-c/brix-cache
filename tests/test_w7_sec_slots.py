"""test_w7_sec_slots.py — phase-101 W7: value-syntax normalization (num→sec slot).

Seconds-valued directives that were `ngx_conf_set_num_slot` (bare integer only) are
converted to `ngx_conf_set_sec_slot`, which accepts nginx time units (`s`/`m`/`h`/
`d`/…) in addition to a bare integer. This is a strict SUPERSET — every existing
config keeps working (a bare integer is still parsed as seconds), and a suffixed
form becomes newly legal.

Covered here (the two unambiguously-clean `ngx_int_t` seconds fields; both keep
their post-parse clamps unchanged):
  * brix_s3_mpu_max_age        (s3 plane)         — e.g. `604800` == `7d`
  * brix_backend_s3_sts_ttl    (stream + http)    — e.g. `3600` == `1h`
                                                    (STS client still clamps
                                                     900..43200 AFTER parse)

(brix_token_clock_skew is deliberately NOT converted: it carries a [0,300]
security clamp on both planes, so `10m`=600 would be rejected — a unit-confusion
footgun that needs its own deliberate handling.)
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
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(text_builder(d))
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def _s3(d, body):
    return (_load()
            + f"error_log {d}/logs/e.log;\npid {d}/logs/n.pid;\nevents {{}}\n"
            + "http {\n"
            + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
            + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
            + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
            + "  brix_storage_backend posix:/tmp;\n"
            + "  server { listen 127.0.0.1:29041;\n"
            + f"    location / {{ brix_s3 on; brix_s3_bucket b; {body} }} }}\n}}\n")


def _stream(d, body):
    return (_load()
            + f"error_log {d}/logs/e.log;\npid {d}/logs/n.pid;\nevents {{}}\n"
            + "stream {\n"
            + "  server { listen 127.0.0.1:29042; brix_root on;\n"
            + f"    brix_export /tmp; {body} }}\n}}\n")


def _webdav(d, body):
    return (_load()
            + f"error_log {d}/logs/e.log;\npid {d}/logs/n.pid;\nevents {{}}\n"
            + "http {\n"
            + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
            + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
            + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
            + "  brix_storage_backend posix:/tmp;\n"
            + "  server { listen 127.0.0.1:29043;\n"
            + f"    location / {{ brix_webdav on; brix_webdav_auth none; {body} }} }}\n}}\n")


@pytest.mark.parametrize("value", ["604800", "7d", "3600", "1h", "0"])
def test_mpu_max_age_accepts_int_and_suffixed(value):
    rc, out = _nginx_t(lambda d: _s3(d, f"brix_s3_mpu_max_age {value};"))
    assert rc == 0, f"brix_s3_mpu_max_age {value} must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("value", ["3600", "1h", "1800"])
def test_sts_ttl_accepts_int_and_suffixed_http(value):
    rc, out = _nginx_t(lambda d: _s3(d, f"brix_backend_s3_sts_ttl {value};"))
    assert rc == 0, f"http brix_backend_s3_sts_ttl {value} must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("value", ["3600", "2h"])
def test_sts_ttl_accepts_int_and_suffixed_stream(value):
    rc, out = _nginx_t(lambda d: _stream(d, f"brix_backend_s3_sts_ttl {value};"))
    assert rc == 0, f"stream brix_backend_s3_sts_ttl {value} must parse:\n{out}"
    assert "successful" in out, out


# The two webdav ngx_uint_t seconds fields converted to time_t + sec_slot (W7).
@pytest.mark.parametrize("value", ["86400", "1h", "0"])
def test_cors_max_age_accepts_int_and_suffixed(value):
    rc, out = _nginx_t(lambda d: _webdav(d, f"brix_webdav_cors_max_age {value};"))
    assert rc == 0, f"brix_webdav_cors_max_age {value} must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("value", ["600", "5m", "1h"])
def test_lock_timeout_accepts_int_and_suffixed(value):
    rc, out = _nginx_t(lambda d: _webdav(d, f"brix_webdav_lock_timeout {value};"))
    assert rc == 0, f"brix_webdav_lock_timeout {value} must parse:\n{out}"
    assert "successful" in out, out


def test_lock_timeout_bad_value_rejected():
    rc, out = _nginx_t(lambda d: _webdav(d, "brix_webdav_lock_timeout banana;"))
    assert rc != 0, out


# brix_storage_credential_mint_ttl (preamble, both planes) — ngx_uint_t → time_t.
# Its readers thread through brix_vfs_ctx_bind_backend_mint(); the param + the vfs
# ctx field storage_cred_mint_ttl were changed to time_t in the same pass.
@pytest.mark.parametrize("value", ["3600", "2h", "0"])
def test_mint_ttl_accepts_int_and_suffixed_stream(value):
    rc, out = _nginx_t(lambda d: _stream(d, f"brix_storage_credential_mint_ttl {value};"))
    assert rc == 0, f"stream mint_ttl {value} must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("value", ["3600", "1h"])
def test_mint_ttl_accepts_int_and_suffixed_http(value):
    rc, out = _nginx_t(lambda d: _webdav(d, f"brix_storage_credential_mint_ttl {value};"))
    assert rc == 0, f"http mint_ttl {value} must parse:\n{out}"
    assert "successful" in out, out


def test_bad_time_value_is_rejected():
    rc, out = _nginx_t(lambda d: _s3(d, "brix_s3_mpu_max_age banana;"))
    assert rc != 0, out
    assert "brix_s3_mpu_max_age" in out or "invalid" in out, out
