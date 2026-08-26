"""test_crl_unification.py — phase-101 W4: the x509 CRL family de-prefixed:
brix_webdav_crl → brix_crl, brix_webdav_crl_mode → brix_crl_mode,
brix_webdav_signing_policy → brix_signing_policy. Fields moved into the shared
preamble; the two enum value-sets are mirrored verbatim on the common module.

  * success     — bare brix_crl_mode / brix_signing_policy parse at a webdav loc.
  * hard-rename — the old brix_webdav_* names are now "unknown directive".
  * error       — a bad enum value fails with the stock enum-slot wording.
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
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\nevents {{}}\n"
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


def test_bare_crl_family_parses():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28911;\n"
        "    location / { brix_webdav on; brix_webdav_auth none;\n"
        "      brix_crl_mode try; brix_signing_policy on; } }\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc == 0, f"bare crl family must parse:\n{out}"
    assert "successful" in out, out


@pytest.mark.parametrize("old", ["brix_webdav_crl", "brix_webdav_crl_mode",
                                 "brix_webdav_signing_policy"])
def test_old_webdav_crl_names_unknown(old):
    val = "/etc/grid-security/certificates" if old == "brix_webdav_crl" else "try"
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28912;\n"
        f"    location / {{ brix_webdav on; brix_webdav_auth none; {old} {val}; }} }}\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc != 0, out
    assert "unknown directive" in out and old in out, out


def test_crl_mode_bad_enum_stock_error():
    rc, out = _nginx_t(
        "  server { listen 127.0.0.1:28913;\n"
        "    location / { brix_webdav on; brix_webdav_auth none; brix_crl_mode bogus; } }\n")  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
    assert rc != 0, out
    assert "invalid value" in out and "bogus" in out, out
