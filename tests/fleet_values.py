"""Session-wide template values for registry-native fleet rendering.

This is the pure-Python replacement for ``substitute_config`` in the retired
``tests/lib/pki.sh``: the dict of PKI paths, token locations, bind hosts, and
default ports that every committed ``tests/configs/*.conf`` template resolves
its ``{PLACEHOLDER}`` tokens against under strict rendering.

Faithfulness note: the bash renderer read the *per-instance subshell env*, so a
dedicated role that exported e.g. ``NGINX_S3_PORT`` or ``CMS_PORT`` saw that
override in its rendered config.  ``session_template_values`` therefore takes an
``env`` mapping (default ``os.environ``); ``RegistryLauncher`` passes
``os.environ`` merged with ``spec.env`` so the per-spec overrides feed rendering
exactly as they did under bash.

Keys are the template placeholder names (``ANON_PORT``, ``CA_CERT``, …), i.e.
the left-hand side of the old ``sed -e "s|{KEY}|...|g"`` rules — not the env var
names.  ``PORT``/``DATA_ROOT``/``LOG_DIR``/``TMP_DIR`` are intentionally omitted:
the launcher supplies those per-instance from the endpoint.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    try:
        return int(env.get(name, default))
    except (TypeError, ValueError):
        return default


def session_template_values(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the placeholder→value dict for one render, honouring ``env`` overrides.

    Mirrors the default-then-substitute logic of the old bash ``substitute_config``
    one-for-one; every ``: "${VAR:=default}"`` there becomes an ``env.get`` here,
    and every ``-e "s|{KEY}|$VAR|g"`` becomes a dict entry.
    """
    env = os.environ if env is None else env

    test_root = Path(env.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(env.get("PKI_DIR", str(test_root / "pki")))
    data_dir = Path(env.get("DATA_DIR", str(test_root / "data")))
    log_dir = Path(env.get("LOG_DIR", str(test_root / "logs")))
    tmp_dir = Path(env.get("TMP_DIR", str(test_root / "tmp")))
    token_dir = Path(env.get("TOKEN_DIR", str(test_root / "tokens")))
    ref_dir = Path(env.get("REF_DIR", str(test_root / "ref")))
    ref_port = _int(env, "REF_PORT", 11098)

    ca = pki_dir / "ca"
    server = pki_dir / "server"
    user = pki_dir / "user"

    values: dict[str, str] = {
        # --- default nginx ports (per-role env overrides win) -----------------
        "ANON_PORT": env.get("NGINX_ANON_PORT", "11094"),
        "ANON_RESUME_OFF_PORT": env.get("NGINX_ANON_RESUME_OFF_PORT", "11118"),
        "GSI_PORT": env.get("NGINX_GSI_PORT", "11095"),
        "GSI_TLS_PORT": env.get("NGINX_GSI_TLS_PORT", "11096"),
        "TOKEN_PORT": env.get("NGINX_TOKEN_PORT", "11097"),
        "METRICS_PORT": env.get("NGINX_METRICS_PORT", "9100"),
        "WEBDAV_PORT": env.get("NGINX_WEBDAV_PORT", "8443"),
        "WEBDAV_GSI_TLS_PORT": env.get("NGINX_WEBDAV_GSI_TLS_PORT", "8444"),
        "HTTP_WEBDAV_PORT": env.get("NGINX_HTTP_WEBDAV_PORT", "8080"),
        "S3_PORT": env.get("NGINX_S3_PORT", "9001"),
        "HTTP_STUB_PORT": env.get("HTTP_STUB_PORT", "11123"),
        "UPSTREAM_PORT": env.get("UPSTREAM_PORT", "12120"),
        "AUTH_PORT": env.get("WEBDAV_AUTH_CACHE_NGINX_PORT", "18445"),
        "SOURCE_REQUIRED_PORT": env.get("WEBDAV_TPC_SOURCE_REQUIRED_PORT", "18450"),
        "SOURCE_OPEN_PORT": env.get("WEBDAV_TPC_SOURCE_OPEN_PORT", "18451"),
        "DEST_CAFILE_PORT": env.get("WEBDAV_TPC_DEST_CAFILE_PORT", "18452"),
        "DEST_CADIR_PORT": env.get("WEBDAV_TPC_DEST_CADIR_PORT", "18453"),
        "DEST_NO_SERVICE_CERT_PORT": env.get("WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT", "18454"),
        "DEST_DISABLED_PORT": env.get("WEBDAV_TPC_DEST_DISABLED_PORT", "18455"),
        "DEST_READONLY_PORT": env.get("WEBDAV_TPC_DEST_READONLY_PORT", "18456"),
        # --- clustering / meshes ---------------------------------------------
        "CMS_PORT": env.get("CMS_PORT", "11161"),
        "CMS_PATHS": env.get("CMS_PATHS", "/"),
        "META_CMS_PORT": env.get("META_CMS_PORT", "11186"),
        "SELF_REGISTER_PORT": env.get("SELF_REGISTER_PORT", "11189"),
        # --- token / jwks -----------------------------------------------------
        "TOKEN_DIR": str(token_dir),
        "TOKEN_FILE": env.get("TOKEN_FILE", str(token_dir / "upstream.jwt")),
        "JWKS_FILE": env.get("JWKS_FILE", str(token_dir / "jwks.json")),
        "REFRESH_INTERVAL_MS": env.get("REFRESH_INTERVAL_MS", "100"),
        "TOKEN_ISSUER": env.get("TOKEN_ISSUER", "https://test.example.com"),
        "TOKEN_AUDIENCE": env.get("TOKEN_AUDIENCE", "nginx-xrootd"),
        # --- directories (DATA_DIR aliases DATA_ROOT for template drift) ------
        "TEST_ROOT": str(test_root),
        "LOG_DIR": str(log_dir),
        "DATA_DIR": str(data_dir),
        "DATA_ROOT": str(data_dir),
        "TMP_DIR": str(tmp_dir),
        "CACHE_DIR": env.get("CACHE_DIR", str(data_dir / "cache")),
        # --- PKI --------------------------------------------------------------
        "CA_CERT": str(ca / "ca.pem"),
        "CA_PEM": str(ca / "ca.pem"),
        "CA_DIR": str(ca),
        "SERVER_CERT": str(server / "hostcert.pem"),
        "SERVER_KEY": str(server / "hostkey.pem"),
        "CLIENT_CERT": str(user / "usercert.pem"),
        "CLIENT_KEY": str(user / "userkey.pem"),
        "CRL_PATH": env.get("CRL_PATH", str(ca / "test-user.crl.pem")),
        "CRL_RELOAD_INTERVAL": env.get("CRL_RELOAD_INTERVAL", "5"),
        "VOMSDIR": str(pki_dir / "vomsdir"),
        # --- WebDAV TPC per-role export roots ---------------------------------
        "SOURCE_REQUIRED_ROOT": env.get("SOURCE_REQUIRED_ROOT", str(data_dir / "source_required")),
        "SOURCE_OPEN_ROOT": env.get("SOURCE_OPEN_ROOT", str(data_dir / "source_open")),
        "DEST_CAFILE_ROOT": env.get("DEST_CAFILE_ROOT", str(data_dir / "dest_cafile")),
        "DEST_CADIR_ROOT": env.get("DEST_CADIR_ROOT", str(data_dir / "dest_cadir")),
        "DEST_NO_SERVICE_CERT_ROOT": env.get("DEST_NO_SERVICE_CERT_ROOT", str(data_dir / "dest_no_service_cert")),
        "DEST_DISABLED_ROOT": env.get("DEST_DISABLED_ROOT", str(data_dir / "dest_disabled")),
        "DEST_READONLY_ROOT": env.get("DEST_READONLY_ROOT", str(data_dir / "dest_readonly")),
        # --- haproxy failover map --------------------------------------------
        "MAP_A_HOST": env.get("MAP_A_HOST", "127.0.0.1"),
        "MAP_A_PORT": env.get("MAP_A_PORT", str(ref_port)),
        "MAP_B_HOST": env.get("MAP_B_HOST", "127.0.0.1"),
        "MAP_B_PORT": env.get("MAP_B_PORT", str(ref_port + 1)),
        # --- misc -------------------------------------------------------------
        "AUTHDB_PATH": env.get("AUTHDB_PATH", str(ref_dir / "authdb")),
        "BIND_HOST": env.get("BIND_HOST", "127.0.0.1"),
        "BIND6_HOST": env.get("BIND6_HOST", "[::1]"),
        "STAGE_CMD": env.get("STAGE_CMD", "/bin/true"),
        "KRB5_PRINCIPAL": env.get("KRB5_PRINCIPAL", "xrootd/localhost@NGINX.TEST"),
        "KRB5_KEYTAB": env.get("KRB5_KEYTAB", str(test_root / "krb5/xrootd.keytab")),
    }
    return values
