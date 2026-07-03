"""test_impersonate_config.py — config-time validation of the phase-40
`brix_impersonation` directives via `nginx -t`.

Unlike the end-to-end userns test, this needs NO root, NO user namespace, and NO
running broker — only the built nginx binary.  It drives `nginx -t` with each
operating mode and asserts the directive surface + mode validation:

  * `off` (and no directive)            -> config OK
  * `single` without a user             -> rejected, clear message
  * `single` with a user                -> config OK
  * `map` as a non-root master          -> rejected (broker needs root)
  * an invalid mode token               -> rejected, lists off|single|map

It lives in tests/userns/ so it shares that folder's standalone pytest root and
is never gated on the main server fleet.  Skips if the nginx binary is absent.
"""

import os
import subprocess
import textwrap

import pytest

NGINX = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
TMP = "/tmp/imp_conftest_pytest"


def _run_t(stream_body, port_suffix):
    os.makedirs(os.path.join(TMP, "logs"), exist_ok=True)
    os.makedirs(os.path.join(TMP, "export"), exist_ok=True)
    conf = os.path.join(TMP, "nginx.conf")
    with open(conf, "w") as fh:
        fh.write(textwrap.dedent(f"""\
            daemon off;
            master_process off;
            error_log {TMP}/logs/error.log info;
            pid {TMP}/nginx.pid;
            events {{ worker_connections 64; }}
            stream {{
              server {{
                listen 127.0.0.1:21{port_suffix};
                xrootd on;
                brix_storage_backend posix:{TMP}/export;
            {stream_body}
              }}
            }}
            """))
    r = subprocess.run([NGINX, "-t", "-c", conf],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


@pytest.fixture(autouse=True)
def _need_nginx():
    if not os.path.isfile(NGINX):
        pytest.skip(f"nginx binary not built at {NGINX} (set TEST_NGINX_BIN)")


def test_off_is_accepted():
    rc, out = _run_t("    brix_impersonation off;", "01")
    assert rc == 0, out
    assert "successful" in out


def test_no_directive_is_accepted():
    rc, out = _run_t("    # no impersonation directive", "02")
    assert rc == 0, out


def test_single_without_user_is_rejected():
    rc, out = _run_t("    brix_impersonation single;", "03")
    assert rc != 0
    assert "brix_impersonation_user" in out


def test_single_with_user_is_accepted():
    rc, out = _run_t(
        "    brix_impersonation single;\n"
        "    brix_impersonation_user nobody;", "04")
    assert rc == 0, out
    assert "successful" in out


def test_map_requires_root():
    if os.geteuid() == 0:
        pytest.skip("running as root: map would be accepted")
    rc, out = _run_t(
        "    brix_impersonation map;\n"
        "    brix_impersonation_socket /tmp/imp_conftest_pytest/b.sock;", "05")
    assert rc != 0
    assert "root" in out.lower()


def test_invalid_mode_is_rejected():
    rc, out = _run_t("    brix_impersonation bogus;", "06")
    assert rc != 0
    assert "off|single|map" in out
