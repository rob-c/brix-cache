"""Load-time validation for ``brix_backend_krb5_forwardable`` (phase-70 §5.7).

The flag arms the krb5 origin leg: when a forwarded TGT has been captured
(src/auth/krb5/capture.c) the gateway may re-delegate it to a Kerberised origin
backend.  It is an ``ngx_conf_set_flag_slot`` directive that must exist on BOTH
request planes — the HTTP plane (src/core/config/http_common.c, ``BRIX_HTTP_ALL_CONF``)
and the STREAM plane (src/protocols/root/stream/module.c, ``NGX_STREAM_SRV_CONF``).

The stream-plane entry was the phase-70 §5.7 fix: the field/init/merge lived in
the shared conf (src/core/config/shared_conf.h) and the HTTP directive was
present, but the STREAM ``ngx_command_t`` table had no entry, so
``brix_backend_krb5_forwardable`` in a ``stream { server { … } }`` block was an
"unknown directive" at load.  This suite pins both planes so a future stream
command-table edit cannot silently drop it again.

3-test ritual (no server boot, ``nginx -t`` only):
  success      — ``on`` and ``off`` parse on the HTTP plane AND the STREAM plane;
  error        — a non-boolean value is rejected (flag slot enforces on/off);
  security-neg — the reject fires on the STREAM plane too (the fail-open a
                 dropped command entry would create — an armed directive silently
                 ignored — must instead be a hard load error).
"""

import subprocess

from settings import BIND_HOST, NGINX_BIN

DIRECTIVE = "brix_backend_krb5_forwardable"


def _preamble(root):
    (root / "logs").mkdir(exist_ok=True)
    return (
        f"daemon off; error_log {root}/logs/e.log info;\n"
        f"pid {root}/n.pid;\n"
        "events { worker_connections 64; }\n"
    )


def _nginx_t_http(root, value):
    conf = root / "krb5fwd_http.conf"
    conf.write_text(
        _preamble(root)
        + f"""http {{ server {{ listen {BIND_HOST}:13288;
    location / {{
        {DIRECTIVE} {value};
    }}
}} }}
"""
    )
    p = subprocess.run(
        [str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
        capture_output=True, text=True, timeout=30,
    )
    return p.returncode, p.stderr + p.stdout


def _nginx_t_stream(root, value):
    data = root / "data"
    data.mkdir(exist_ok=True)
    conf = root / "krb5fwd_stream.conf"
    conf.write_text(
        _preamble(root)
        + f"""stream {{ server {{ listen {BIND_HOST}:13289;
    brix_root on;
    brix_storage_backend posix:{data};
    {DIRECTIVE} {value};
}} }}
"""
    )
    p = subprocess.run(
        [str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
        capture_output=True, text=True, timeout=30,
    )
    return p.returncode, p.stderr + p.stdout


# --- success: both booleans parse on both planes ---------------------------

def test_http_on_parses(tmp_path):
    rc, out = _nginx_t_http(tmp_path, "on")
    assert rc == 0, f"HTTP-plane '{DIRECTIVE} on' rejected:\n{out}"


def test_http_off_parses(tmp_path):
    rc, out = _nginx_t_http(tmp_path, "off")
    assert rc == 0, f"HTTP-plane '{DIRECTIVE} off' rejected:\n{out}"


def test_stream_on_parses(tmp_path):
    # The stream command-table entry added in phase-70 §5.7 — the regression this
    # suite exists to catch.
    rc, out = _nginx_t_stream(tmp_path, "on")
    assert rc == 0, f"STREAM-plane '{DIRECTIVE} on' rejected:\n{out}"


def test_stream_off_parses(tmp_path):
    rc, out = _nginx_t_stream(tmp_path, "off")
    assert rc == 0, f"STREAM-plane '{DIRECTIVE} off' rejected:\n{out}"


# --- error / security-neg: a non-boolean must fail load, not fail open ------

def test_http_bogus_value_rejected(tmp_path):
    rc, out = _nginx_t_http(tmp_path, "maybe")
    assert rc != 0, "HTTP-plane non-boolean value unexpectedly accepted"
    assert DIRECTIVE in out, out


def test_stream_bogus_value_rejected(tmp_path):
    rc, out = _nginx_t_stream(tmp_path, "maybe")
    assert rc != 0, "STREAM-plane non-boolean value unexpectedly accepted"
    assert DIRECTIVE in out, out
