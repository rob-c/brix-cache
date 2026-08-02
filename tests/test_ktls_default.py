"""Phase-33 P5 — kTLS defaults OFF (opt-in, HW-offload-only).

kTLS was errantly defaulting ON on both TLS planes.  Software kTLS (engaged when
the kernel ``tls`` module is loaded) is a documented throughput regression on
AES-NI CPUs and is broken on WSL2, so P5 flips the default to OFF: kTLS now
only engages when an operator explicitly opts in with ``brix_ktls on`` AND the
negotiated cipher is hardware-offloadable.

These are pure ``nginx -t`` parse-time properties — no server boot.  When the
root:// TLS context is built, ``brix_ktls on`` sets ``SSL_OP_ENABLE_KTLS`` and
logs a NOTICE ("kernel-TLS (kTLS) requested ...").  The NOTICE is the single
observable proxy for "did brix ask OpenSSL for kTLS", so its presence/absence
across the directive states proves the default:

  success   — ``brix_ktls on``  → accepts and the NOTICE fires (opt-in works);
  default   — no directive       → accepts and the NOTICE is ABSENT (default OFF);
  off       — ``brix_ktls off``  → accepts and the NOTICE is ABSENT (explicit off);
  error/neg — ``brix_ktls maybe`` → ``nginx -t`` refuses the bogus flag value.

The default and off cases share the assertion that matters most — that the
NOTICE never fires unless an operator asks for it — which is exactly the P5
regression guard: a future merge that flips the default back ON turns the
default case red.
"""

import os

import pytest

from config_parse import nginx_t
from settings import NGINX_BIN, BIND_HOST, SERVER_CERT, SERVER_KEY
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT

# The config-parse NOTICE brix logs when it sets SSL_OP_ENABLE_KTLS on the
# root:// TLS context.  Emitted to stderr during `nginx -t` (config-parse
# NOTICEs use the init-cycle log, before error_log takes effect).
KTLS_NOTICE = "kernel-TLS (kTLS) requested"


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    for path in (SERVER_CERT, SERVER_KEY):
        if not os.path.exists(path):
            pytest.skip(f"TLS fixture missing: {path}")


def _tls_lines(ktls_line):
    """brix_tls block for nginx_min_sec.conf's {TLS_LINES} slot, with an
    optional trailing brix_ktls directive."""
    lines = (f"        brix_tls on;\n"
             f"        brix_certificate     {SERVER_CERT};\n"
             f"        brix_certificate_key {SERVER_KEY};\n")
    if ktls_line:
        lines += f"        {ktls_line}\n"
    return lines


def _parse(tmp_path, ktls_line):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    values = {
        "BIND_HOST": BIND_HOST,
        "PORT": PARSE_PLACEHOLDER_PORT,   # nginx -t never binds
        "DATA_ROOT": str(data),
        "LOG_DIR": str(tmp_path),
        "TMP_DIR": str(tmp_path),
        "TLS_LINES": _tls_lines(ktls_line),
        "AUTH": "none",
        "MIN_SEC": "compat",
    }
    result = nginx_t("nginx_min_sec.conf", tmp_path, **values)
    return result, (result.stdout or "") + (result.stderr or "")


# --------------------------------------------------------------------------- #
# success: opt-in works — brix_ktls on accepts and requests kTLS.
# --------------------------------------------------------------------------- #
def test_ktls_on_requests_offload(tmp_path):
    result, out = _parse(tmp_path, "brix_ktls on;")
    assert result.returncode == 0, out
    assert KTLS_NOTICE in out, ("brix_ktls on must request kTLS", out)


# --------------------------------------------------------------------------- #
# default: no directive → default OFF, no kTLS requested (the P5 guard).
# --------------------------------------------------------------------------- #
def test_ktls_default_is_off(tmp_path):
    result, out = _parse(tmp_path, None)
    assert result.returncode == 0, out
    assert KTLS_NOTICE not in out, (
        "kTLS must default OFF — no NOTICE without an explicit brix_ktls on", out)


# --------------------------------------------------------------------------- #
# off: explicit brix_ktls off also suppresses the request.
# --------------------------------------------------------------------------- #
def test_ktls_off_suppresses_offload(tmp_path):
    result, out = _parse(tmp_path, "brix_ktls off;")
    assert result.returncode == 0, out
    assert KTLS_NOTICE not in out, ("brix_ktls off must not request kTLS", out)


# --------------------------------------------------------------------------- #
# error/neg: a bogus flag value is refused at config parse.
# --------------------------------------------------------------------------- #
def test_ktls_bogus_value_refused(tmp_path):
    result, out = _parse(tmp_path, "brix_ktls maybe;")
    assert result.returncode != 0, out
    assert 'invalid value "maybe"' in out, out
