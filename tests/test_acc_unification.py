"""test_acc_unification.py — phase-101 W2: the XrdAcc / kTLS config surface after
the dual-conf-poking setters were retired.

Before W2, brix_ktls, brix_cache_store_endpoint and the whole brix_authdb* /
brix_acc_* family were hand-rolled setters registered on the webdav module that
reached into BOTH the webdav and s3 loc-confs — hardwiring the protocol list and
silently EXCLUDING cvmfs (a cvmfs location could not enable kTLS or receive any
XrdAcc setting, with no diagnostic). W2 moved the whole family to the shared
common module on the standard generic slots, with the acc block promoted into the
shared preamble (common.acc) and adopted into every HTTP protocol.

These are deterministic `nginx -t` config-parse tests (no fleet / GSI needed):

  * success       — the acc + kTLS family parses on webdav, s3 AND cvmfs, and at
                    server{}/http{} scope — the registration reaches every plane.
  * new capability — brix_ktls + brix_acc_authdb at a CVMFS location parse (was
                    impossible pre-W2: cvmfs was excluded from the dual-poke).
                    (W5 2026-08-10: the XrdAcc entry is brix_acc_authdb; bare
                    brix_authdb is now the native u/g/p engine on webdav.)
  * error         — a bad enum (brix_acc_format bogus) and a bad flag
                    (brix_acc_pgo maybe) fail with the STOCK slot wording, proving
                    the move to generic slots (not the old hand-rolled text).

The behavioural pin (an XrdAcc deny denies the same DN on webdav/s3 identically)
stays in the existing test_acc.py / test_authdb.py suites, which W2 leaves green.
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


def _nginx_t(body):
    """Write a full config with the runner's load_module lines + `body` and run
    `nginx -t`. Returns (rc, combined_output)."""
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\n"
                + "events {}\n"
                + "http {\n"
                + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
                + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
                + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
                + "  brix_storage_backend posix:/tmp;\n"
                + body
                + "}\n")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


# authdb rules file so brix_acc_authdb <path> has a real target at parse time.
_AUTHDB = " ".join(["u", "*", "/", "rl"])


def test_acc_family_parses_on_webdav_s3_cvmfs():
    """The whole family, once per plane, reaches webdav, s3 AND cvmfs — plus the
    server/http scope the move unlocked."""
    with tempfile.TemporaryDirectory() as adb_dir:
        adb = os.path.join(adb_dir, "authdb")
        open(adb, "w").write(_AUTHDB + "\n")
        rc, out = _nginx_t(
            "  brix_ktls on;\n"                       # http scope
            "  brix_acc_resolve_hosts on;\n"          # http scope
            f"  brix_acc_authdb {adb};\n"
            "  brix_acc_format xrdacc;\n"
            "  brix_acc_audit deny;\n"
            "  brix_acc_refresh 60;\n"
            "  brix_acc_gidlifetime 3600;\n"
            "  brix_acc_pgo on;\n"
            "  brix_acc_nisdomain example.org;\n"
            "  brix_acc_spacechar _;\n"
            "  brix_acc_encoding on;\n"
            "  brix_acc_gidretran nobody;\n"
            "  server { listen 127.0.0.1:28381;\n"
            "    brix_cache_store_endpoint on;\n"      # server scope
            "    location /dav/ { brix_webdav on; brix_webdav_auth none; } }\n"
            "  server { listen 127.0.0.1:28382;\n"
            "    location /s3/ { brix_s3 on; brix_s3_bucket b; brix_webdav_auth none; } }\n"
            "  server { listen 127.0.0.1:28383;\n"
            "    location /cvmfs/ { brix_cvmfs on; } }\n")   # cvmfs — new under W2
    assert rc == 0, f"acc/kTLS family must parse on all three planes:\n{out}"
    assert "successful" in out, out


def test_ktls_and_authdb_reach_cvmfs_location():
    """New capability: kTLS + XrdAcc at a CVMFS location (impossible pre-W2, when
    the dual-poke hardwired webdav+s3 and left cvmfs out with no diagnostic)."""
    with tempfile.TemporaryDirectory() as adb_dir:
        adb = os.path.join(adb_dir, "authdb")
        open(adb, "w").write(_AUTHDB + "\n")
        rc, out = _nginx_t(
            "  server { listen 127.0.0.1:28384;\n"
            "    location /cvmfs/ {\n"
            "      brix_cvmfs on;\n"
            "      brix_ktls on;\n"
            f"      brix_acc_authdb {adb};\n"
            "      brix_acc_format xrdacc;\n"
            "    } }\n")
    assert rc == 0, f"kTLS + XrdAcc at a cvmfs location must parse under W2:\n{out}"


def test_authdb_format_bad_enum_stock_error():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28385;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_acc_format bogus; } }\n")
    assert rc != 0, f"bad enum should fail nginx -t:\n{out}"
    # stock ngx_conf_set_enum_slot wording, not the old hand-rolled "invalid value".
    assert "invalid value" in out and "bogus" in out, out


def test_acc_pgo_bad_flag_stock_error():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28386;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_acc_pgo maybe; } }\n")
    assert rc != 0, f"bad flag should fail nginx -t:\n{out}"
    assert 'it must be "on" or "off"' in out, out
