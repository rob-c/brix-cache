"""
Load-time trust validation for the S3 STS endpoint (phase-70 §5.5 origin leg;
the §6 invariant "Trust config validated at load — not first use", the residual
the phase-88 audit flagged for the STS directive).

The STS client (src/auth/s3/sts_http.c) pins libcurl to http,https and hands the
SigV4-signed endpoint to CURLOPT_URL verbatim, while sts_host_from_url()
(src/auth/s3/sts.c) parses "scheme://host" for the "host" header. Before this
slice, `brix_backend_s3_sts_endpoint <garbage>` parsed fine and only surfaced as
every S3 STS exchange fail-closing at first use. The directive's setter
(src/core/config/http_common.c::brix_conf_set_backend_sts_endpoint) now rejects a
malformed endpoint at ``nginx -t`` time.

Unlike the token-exchange endpoint (HTTPS-only — a subject token + client secret
ride every request), STS is SigV4-signed and never transmits the secret, so an
http:// endpoint (a lab MinIO STS) is legitimate and MUST parse.

3-test ritual (no server start, ``nginx -t`` only):
  success      — well-formed https:// AND http:// endpoints both parse;
  error        — a scheme-less / non-http(s) endpoint is rejected;
  security-neg — a host-less URL and an embedded-whitespace URL (spliced into
                 CURLOPT_URL verbatim) are rejected.
"""

import subprocess

from settings import BIND_HOST, NGINX_BIN

DIAG = "brix_backend_s3_sts_endpoint"


def _nginx_t(root, endpoint_value):
    (root / "logs").mkdir(exist_ok=True)
    conf = root / "sts.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:13299;
    location / {{
        brix_backend_s3_sts_endpoint {endpoint_value};
    }}
}} }}
""")
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def test_https_endpoint_parses(tmp_path):
    rc, out = _nginx_t(tmp_path, "https://minio.example.org:9000")
    assert rc == 0, f"valid https STS endpoint rejected:\n{out}"


def test_http_endpoint_parses(tmp_path):
    # SigV4 never transmits the secret, so a lab MinIO STS over http is valid.
    rc, out = _nginx_t(tmp_path, "http://minio.lab:9000")
    assert rc == 0, f"valid http STS endpoint rejected:\n{out}"


def test_schemeless_endpoint_rejected_at_load(tmp_path):
    rc, out = _nginx_t(tmp_path, "minio.example.org:9000")
    assert rc != 0, "scheme-less STS endpoint unexpectedly accepted"
    assert DIAG in out and "http" in out, out


def test_hostless_url_rejected(tmp_path):
    rc, out = _nginx_t(tmp_path, "https:///assume")
    assert rc != 0, "host-less STS endpoint unexpectedly accepted"
    assert DIAG in out, out


def test_embedded_whitespace_rejected(tmp_path):
    rc, out = _nginx_t(tmp_path, '"https://evil host:9000"')
    assert rc != 0, "whitespace-bearing STS endpoint unexpectedly accepted"
    assert "whitespace or control" in out, out
