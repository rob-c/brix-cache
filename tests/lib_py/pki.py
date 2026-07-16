"""PKI/config helpers replacing tests/lib/pki.sh."""

from __future__ import annotations

from pathlib import Path
import os
import sys

from .util import render_cfg, run


REPO_ROOT = Path(__file__).resolve().parents[2]


DEFAULTS = {
    "NGINX_ANON_PORT": "11094",
    "NGINX_ANON_RESUME_OFF_PORT": "11118",
    "NGINX_GSI_PORT": "11095",
    "NGINX_GSI_TLS_PORT": "11096",
    "NGINX_TOKEN_PORT": "11097",
    "NGINX_METRICS_PORT": "9100",
    "NGINX_WEBDAV_PORT": "8443",
    "NGINX_WEBDAV_GSI_TLS_PORT": "8444",
    "NGINX_HTTP_WEBDAV_PORT": "8080",
    "NGINX_S3_PORT": "9001",
    "CRL_RELOAD_INTERVAL": "5",
    "HTTP_STUB_PORT": "11123",
    "UPSTREAM_PORT": "12120",
    "REFRESH_INTERVAL_MS": "100",
    "TOKEN_ISSUER": "https://test.example.com",
    "TOKEN_AUDIENCE": "nginx-xrootd",
    "WEBDAV_AUTH_CACHE_NGINX_PORT": "18445",
    "WEBDAV_TPC_SOURCE_REQUIRED_PORT": "18450",
    "WEBDAV_TPC_SOURCE_OPEN_PORT": "18451",
    "WEBDAV_TPC_DEST_CAFILE_PORT": "18452",
    "WEBDAV_TPC_DEST_CADIR_PORT": "18453",
    "WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT": "18454",
    "WEBDAV_TPC_DEST_DISABLED_PORT": "18455",
    "WEBDAV_TPC_DEST_READONLY_PORT": "18456",
    "BIND_HOST": "127.0.0.1",
    "BIND6_HOST": "[::1]",
    "CMS_PORT": "11161",
    "CMS_PATHS": "/",
    "METRICS_PORT": "9100",
    "META_CMS_PORT": "11186",
    "SELF_REGISTER_PORT": "11189",
    "KRB5_PRINCIPAL": "xrootd/localhost@NGINX.TEST",
}


def regenerate_pki(pki_dir: Path) -> None:
    pki_dir.mkdir(parents=True, exist_ok=True)
    env = {"PKI_DIR": str(pki_dir), "PYTHONPATH": "tests"}
    code = "from pki_helpers import blitz_test_pki; blitz_test_pki()"
    run([sys.executable, "-c", code], cwd=REPO_ROOT, env=env)
    run([sys.executable, str(REPO_ROOT / "utils/make_proxy.py"), str(pki_dir)], cwd=REPO_ROOT)


def substitute_config(src: Path, dest: Path, env: dict[str, str] | None = None) -> None:
    values = dict(DEFAULTS)
    values.update(os.environ)
    if env:
        values.update(env)
    test_root = Path(values.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(values.get("PKI_DIR", str(test_root / "pki")))
    data_dir = Path(values.get("DATA_DIR", str(test_root / "data")))
    log_dir = Path(values.get("LOG_DIR", str(test_root / "logs")))
    tmp_dir = Path(values.get("TMP_DIR", str(test_root / "tmp")))
    token_dir = Path(values.get("TOKEN_DIR", str(test_root / "tokens")))
    ref_dir = Path(values.get("REF_DIR", str(test_root / "ref")))
    computed = {
        "PORT": values.get("NGINX_PORT", values.get("NGINX_ANON_PORT", "11094")),
        "TOKEN_DIR": str(token_dir),
        "TOKEN_FILE": values.get("TOKEN_FILE", str(token_dir / "upstream.jwt")),
        "JWKS_FILE": values.get("JWKS_FILE", str(token_dir / "jwks.json")),
        "LOG_DIR": str(log_dir),
        "DATA_DIR": str(data_dir),
        "TMP_DIR": str(tmp_dir),
        "CA_CERT": str(pki_dir / "ca/ca.pem"),
        "CA_DIR": str(pki_dir / "ca"),
        "SERVER_CERT": str(pki_dir / "server/hostcert.pem"),
        "SERVER_KEY": str(pki_dir / "server/hostkey.pem"),
        "CA_PEM": str(pki_dir / "ca/ca.pem"),
        "CLIENT_CERT": str(pki_dir / "user/usercert.pem"),
        "CLIENT_KEY": str(pki_dir / "user/userkey.pem"),
        "CRL_PATH": values.get("CRL_PATH", str(pki_dir / "ca/test-user.crl.pem")),
        "VOMSDIR": str(pki_dir / "vomsdir"),
        "AUTHDB_PATH": values.get("AUTHDB_PATH", str(ref_dir / "authdb")),
        "CACHE_DIR": values.get("CACHE_DIR", str(data_dir / "cache")),
        "STAGE_CMD": values.get("STAGE_CMD", "/bin/true"),
        "KRB5_KEYTAB": values.get("KRB5_KEYTAB", str(test_root / "krb5/brix.keytab")),
    }
    values.update(computed)
    render_cfg(src, dest, **values)

