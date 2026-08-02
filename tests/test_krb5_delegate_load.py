"""``nginx -t`` load-time coverage for the ``brix_krb5_delegate`` directive
(phase-70 §5.7 inbound forwarded-TGT delegation-capture state machine).

The directive arms the two-round ``kXR_authmore``/``"fwdtgt"`` capture path; it is
stream-plane only (the krb5 handler is a root-protocol auth leg, not an HTTP one).
Ritual (no server boot, ``nginx -t`` only): ``on``/``off`` both parse (success),
and a non-boolean value is a HARD load error (security-negative — the failure a
silently-dropped command entry would create is an armed directive quietly ignored,
i.e. delegation fail-OPEN; it must instead refuse to load).
"""

import subprocess

from settings import BIND_HOST, NGINX_BIN

DIRECTIVE = "brix_krb5_delegate"


def _preamble(root):
    (root / "logs").mkdir(exist_ok=True)
    return (
        f"daemon off; error_log {root}/logs/e.log info;\n"
        f"pid {root}/n.pid;\n"
        "events { worker_connections 64; }\n"
    )


def _nginx_t_stream(root, value):
    data = root / "data"
    data.mkdir(exist_ok=True)
    conf = root / "krb5deleg_stream.conf"
    conf.write_text(
        _preamble(root)
        + f"""stream {{ server {{ listen {BIND_HOST}:13390;
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


# --- success: both booleans parse on the stream plane ----------------------

def test_stream_on_parses(tmp_path):
    rc, out = _nginx_t_stream(tmp_path, "on")
    assert rc == 0, f"STREAM-plane '{DIRECTIVE} on' rejected:\n{out}"


def test_stream_off_parses(tmp_path):
    rc, out = _nginx_t_stream(tmp_path, "off")
    assert rc == 0, f"STREAM-plane '{DIRECTIVE} off' rejected:\n{out}"


# --- error / security-neg: a non-boolean must fail load, not fail open ------

def test_stream_bogus_value_rejected(tmp_path):
    rc, out = _nginx_t_stream(tmp_path, "maybe")
    assert rc != 0, "STREAM-plane non-boolean value unexpectedly accepted"
    assert DIRECTIVE in out, out
