"""
Load-time trust validation for the token-exchange endpoint (P90-70.8, the
cheap first slice of phase-70 §6: "Trust config validated at load — not first
use").

The RFC-8693 exchange client (src/auth/token/exchange.c) pins libcurl to
HTTPS-only because a subject token and the client secret ride every request.
Before this slice, `brix_backend_token_exchange_endpoint http://…` parsed
fine and only surfaced as every EXCHANGE delegation fail-closing at first
use.  The directive's setter (src/core/config/http_common.c::
brix_conf_set_backend_tx_endpoint) now rejects it at ``nginx -t`` time.

3-test ritual (no server start, ``nginx -t`` only):
  success      — a well-formed https:// endpoint parses;
  error        — an http:// endpoint is rejected with the HTTPS-only
                 diagnostic;
  security-neg — a host-less https:/// URL and an embedded-whitespace URL
                 (the value is spliced into CURLOPT_URL verbatim) are
                 rejected.
"""

import subprocess

from settings import BIND_HOST, NGINX_BIN

DIAG = "brix_backend_token_exchange_endpoint"


def _nginx_t(root, endpoint_value):
    (root / "logs").mkdir(exist_ok=True)
    conf = root / "tx.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:13298;
    location / {{
        brix_backend_token_exchange_endpoint {endpoint_value};
    }}
}} }}
""")
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def test_https_endpoint_parses(tmp_path):
    rc, out = _nginx_t(tmp_path, "https://sts.example.org/token")
    assert rc == 0, f"valid https endpoint rejected:\n{out}"


def test_http_endpoint_rejected_at_load(tmp_path):
    rc, out = _nginx_t(tmp_path, "http://sts.example.org/token")
    assert rc != 0, "cleartext exchange endpoint unexpectedly accepted"
    assert DIAG in out and "https://" in out, out


def test_hostless_url_rejected(tmp_path):
    rc, out = _nginx_t(tmp_path, "https:///token")
    assert rc != 0, "host-less exchange endpoint unexpectedly accepted"
    assert DIAG in out, out


def test_embedded_whitespace_rejected(tmp_path):
    rc, out = _nginx_t(tmp_path, '"https://evil host/token"')
    assert rc != 0, "whitespace-bearing exchange endpoint unexpectedly accepted"
    assert "whitespace or control" in out, out
