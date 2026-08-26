"""test_gridftp_deprefix.py — phase-101 W3: the gridftp gateway shares the bare
stream directive names instead of its 11 brix_gridftp_* twins.

`ngx_stream_brix_common_module` (stream_common.c) owns the shared storage /
x509-trust / VO-ACL names on the stream plane; the root and gridftp modules adopt
them at merge.  A gridftp server therefore spells them exactly as a root://
server does, and the old prefixed twins are stock `unknown directive`s.

These are `nginx -t` config-parse assertions only (no server start, no fleet) —
the runtime RETR/STOR/GSI/VO behaviour is proven by the test_gridftp_* suite;
this pins the directive surface itself so a regression fails fast in CI.

Run:  PYTHONPATH=. python3 -m pytest test_gridftp_deprefix.py -p no:xdist -q
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


def _nginx_t_gridftp(body):
    """`nginx -t` a stream{} config with a brix_gridftp server carrying `body`.

    The export is a real dir (the gateway realpath()s it at config time), so a
    clean parse proves the bare names bound to the gridftp conf.
    """
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "export"), exist_ok=True)
        os.makedirs(os.path.join(d, "logs"), exist_ok=True)
        modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
        load = "".join(f"load_module {m};\n" for m in modules)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\n"
                + "events {}\n"
                + "stream {\n"
                + "  server { listen 127.0.0.1:28590;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + "    brix_gridftp on;\n"
                + f"    brix_export {d}/export;\n"
                + body
                + "  }\n"
                + "}\n")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


# --------------------------------------------------------------------------- #
# Success: the bare storage names parse on a gridftp server.                  #
# --------------------------------------------------------------------------- #

def test_bare_storage_names_parse_on_gridftp():
    rc, out = _nginx_t_gridftp(
        "    brix_allow_write on;\n"
        "    brix_verify_write off;\n"
        "    brix_storage_backend posix;\n")
    assert rc == 0, f"bare storage names must parse on a gridftp server:\n{out}"
    assert "successful" in out, out


# --------------------------------------------------------------------------- #
# Error: every de-prefixed twin is a stock `unknown directive`.               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("twin,arg", [
    ("brix_gridftp_export", "/tmp"),
    ("brix_gridftp_allow_write", "on"),
    ("brix_gridftp_verify_write", "on"),
    ("brix_gridftp_storage_backend", "posix"),
    ("brix_gridftp_storage_credential", "cred"),
    ("brix_gridftp_certificate", "/tmp/c.pem"),
    ("brix_gridftp_certificate_key", "/tmp/k.pem"),
    ("brix_gridftp_trusted_ca", "/tmp"),
    ("brix_gridftp_vomsdir", "/tmp"),
    ("brix_gridftp_voms_cert_dir", "/tmp"),
    ("brix_gridftp_require_vo", "/ atlas"),
])
def test_old_gridftp_twin_is_unknown_directive(twin, arg):
    rc, out = _nginx_t_gridftp(f"    {twin} {arg};\n")
    assert rc != 0, f"{twin} must be a stock unknown directive (W3):\n{out}"
    assert f'unknown directive "{twin}"' in out, out


# --------------------------------------------------------------------------- #
# The 4 genuinely gateway-specific directives are KEPT (still valid).         #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("directive", [
    "brix_gridftp_gsi off",
    "brix_gridftp_pasv_port_range 20000 20100",
    "brix_gridftp_require_allo_size on",
])
def test_gateway_specific_keepers_still_parse(directive):
    rc, out = _nginx_t_gridftp(f"    {directive};\n")
    assert rc == 0, f"gateway-specific keeper must still parse:\n{out}"
