"""
test_tls_reuse.py — §5.10 (parity-fix wave 19): brix_tls_reuse directive
plumbing (the xrootd.tlsreuse analog for the root:// in-protocol TLS context).

The session-resumption BEHAVIOUR (cache + tickets disabled when off, inert when
on) is proven in isolation by the C-unit
`test_c_auth_units.py::test_c_auth_unit[tls_reuse]`, which drives the exact
header-inline helper brix_configure_tls runs, against a real SSL_CTX.

This file guards the CONFIG PATH that arms it: brix_configure_tls forwards
conf->tls_reuse to the helper, the directive is registered, and `off` actually
takes the disable branch at config init.

  * wiring        — brix_configure_tls calls brix_tls_apply_session_reuse with
                    xcf->tls_reuse.
  * success       — brix_tls_reuse off: config init runs the disable branch
                    (logs the resumption-disabled notice).
  * default/compat— no directive: resumption stays enabled (no notice) —
                    byte-identical to before the knob.

Run:
    PYTHONPATH=tests pytest tests/test_tls_reuse.py -v
"""

import os
import subprocess
import textwrap

import pytest

from settings import NGINX_BIN, SERVER_CERT, SERVER_KEY

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _nginx_t(tmp_path, reuse_line):
    conf = tmp_path / "nginx.conf"
    conf.write_text(textwrap.dedent(f"""\
        daemon off;
        error_log {tmp_path}/err.log info;
        pid {tmp_path}/nginx.pid;
        events {{ worker_connections 64; }}
        stream {{
            server {{
                listen 127.0.0.1:19745;
                brix_root on;
                brix_storage_backend posix:/tmp;
                brix_auth none;
                brix_tls on;
                brix_certificate {SERVER_CERT};
                brix_certificate_key {SERVER_KEY};
                {reuse_line}
            }}
        }}
    """))
    return subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True, timeout=30)


def _requirements():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
        pytest.skip("test host cert/key PKI not present")


_NOTICE = "TLS session resumption disabled"


def test_configure_tls_forwards_conf_tls_reuse():
    """(wiring) brix_configure_tls hands conf->tls_reuse to the resumption
    policy helper — not a hardcoded constant."""
    with open(os.path.join(_REPO,
              "src/protocols/root/session/tls_config.c")) as f:
        src = f.read()
    assert "brix_tls_apply_session_reuse(" in src, \
        "tls_config.c no longer applies the tlsreuse policy"
    call = src[src.index("brix_tls_apply_session_reuse("):]
    call = call[:call.index(";") + 1]
    assert "tls_reuse" in call, \
        "brix_configure_tls does not forward conf->tls_reuse to the helper"


def test_reuse_off_takes_the_disable_branch(tmp_path):
    """(success) brix_tls_reuse off: config init succeeds and logs that
    resumption was disabled — proving the off branch actually runs."""
    _requirements()
    r = _nginx_t(tmp_path, "brix_tls_reuse off;")
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"brix_tls_reuse off failed config test:\n{out}"
    assert _NOTICE in out, \
        f"the resumption-disabled branch did not run for off:\n{out}"


def test_default_keeps_resumption_enabled(tmp_path):
    """(default/compat) no directive: resumption stays on (no disable notice),
    byte-identical to a server without the knob."""
    _requirements()
    r = _nginx_t(tmp_path, "")
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"tls config without the knob failed:\n{out}"
    assert _NOTICE not in out, \
        "resumption was disabled even though brix_tls_reuse was not set"
