"""
test_gsi_verify_depth.py — §5.10 (parity-fix wave 17): brix_verify_depth
directive plumbing.

The chain-depth ENFORCEMENT (X509_STORE_CTX_set_depth honoured by
brix_gsi_verify_chain) is proven behaviourally by the C-unit
`test_c_auth_units.py::test_c_auth_unit[gsi_verdepth]` — a deep forged chain is
accepted uncapped, rejected at depth 1, and accepted again at depth 20, against
the real verify function.

This file guards the CONFIG PATH that arms it: the root:// GSI login verify
passes `conf->gsi_verify_depth` (not the old hardcoded 0), and the directive is
registered and numeric-validated.

  * wiring        — the GSI login site forwards conf->gsi_verify_depth to
                    brix_gsi_verify_chain.
  * success       — nginx -t accepts `brix_verify_depth <n>`.
  * error         — a non-numeric argument is rejected at parse time.

Run:
    PYTHONPATH=tests pytest tests/test_gsi_verify_depth.py -v
"""

import os
import subprocess
import textwrap

import pytest

from settings import NGINX_BIN

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _nginx_t(tmp_path, depth_line):
    conf = tmp_path / "nginx.conf"
    conf.write_text(textwrap.dedent(f"""\
        daemon off;
        events {{ worker_connections 64; }}
        stream {{
            server {{
                listen 127.0.0.1:19733;
                brix_root on;
                brix_storage_backend posix:/tmp;
                brix_auth none;
                {depth_line}
            }}
        }}
    """))
    return subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True, timeout=30)


def test_gsi_login_forwards_conf_verify_depth():
    """(wiring) the root:// GSI cert-login verify passes conf->gsi_verify_depth
    to brix_gsi_verify_chain — not the pre-wave-17 hardcoded 0."""
    with open(os.path.join(_REPO, "src/auth/gsi/auth_cert.c")) as f:
        src = f.read()
    call = src[src.index("brix_gsi_verify_chain("):]
    call = call[:call.index(";") + 1]
    assert "conf->gsi_verify_depth" in call, \
        "root:// GSI verify no longer forwards conf->gsi_verify_depth"


def test_directive_accepts_a_number(tmp_path):
    """(success) brix_verify_depth <n> parses — the directive is registered
    and the value flows into the config."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    r = _nginx_t(tmp_path, "brix_verify_depth 3;")
    assert "syntax is ok" in (r.stdout + r.stderr), \
        f"valid brix_verify_depth rejected at parse:\n{r.stdout}\n{r.stderr}"


def test_directive_rejects_non_number(tmp_path):
    """(error) a non-numeric argument is refused by the num setter, and the
    config never reaches 'syntax is ok'."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    r = _nginx_t(tmp_path, "brix_verify_depth notanumber;")
    out = r.stdout + r.stderr
    assert "syntax is ok" not in out, \
        "a non-numeric brix_verify_depth was accepted"
    assert "invalid number" in out, \
        f"expected an 'invalid number' parse error, got:\n{out}"
