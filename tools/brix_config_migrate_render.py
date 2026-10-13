"""Deterministic, injection-safe nginx rendering for brix-config-migrate."""
from __future__ import annotations

import re
from typing import Any


def _nginx_arg(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@?=,+%*${}()\[\]-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _directive_lines(result: Any, indent: str) -> list[str]:
    order = (
        "listen", "brix_root", "brix_http_handoff",
        "brix_http_handoff_connect_timeout", "brix_http_handoff_idle_timeout",
        "brix_read_timeout", "brix_tcp_keepalive", "brix_export",
        "brix_storage_backend",
        "brix_cache",
        "brix_cache_store", "brix_cache_export", "brix_cache_slice_size",
        "brix_cache_prefetch", "brix_cache_prefetch_window",
        "brix_cache_low_watermark", "brix_cache_high_watermark",
        "brix_cache_reap_interval", "brix_cache_cold_max_age",
        "brix_cache_only_if_cached", "brix_cache_uvkeep",
        "brix_write_through", "brix_wt_origin", "brix_n2n_scheme",
        "brix_n2n_pool", "brix_n2n_prefix", "brix_allow_write", "brix_auth",
        "brix_protbind", "brix_tls", "brix_certificate",
        "brix_certificate_key", "brix_trusted_ca", "brix_verify_depth",
        "brix_crl", "brix_crl_mode", "brix_crl_scope",
        "brix_tls_verify_log", "brix_vomsdir",
        "brix_voms_cert_dir", "brix_idmap", "brix_idmap_gridmap",
        "brix_token_config", "brix_macaroon_secret",
        "brix_authdb_engine", "brix_authdb", "brix_acc_audit",
        "brix_acc_refresh", "brix_require_vo", "brix_tpc_streams",
        "brix_cms_manager",
    )
    return [f"{indent}{name} {' '.join(_nginx_arg(arg) for arg in args)};"
            for name in order for args in result.values.get(name, [])]


def _http_value(result: Any, name: str, fallback: str) -> tuple[str, ...]:
    explicit = result.http_values.get(name)
    if explicit:
        return explicit
    return result.values.get(fallback, [()])[0]


def _append_http_directive(lines: list[str], name: str,
                           args: tuple[str, ...], indent: str) -> None:
    if not args:
        return
    rendered = " ".join(_nginx_arg(arg) for arg in args)
    lines.append(f"{indent}{name} {rendered};")


def _http_head(result: Any) -> tuple[list[str], bool]:
    certificate = _http_value(result, "ssl_certificate", "brix_certificate")
    certificate_key = _http_value(
        result, "ssl_certificate_key", "brix_certificate_key")
    tls = bool(certificate and certificate_key)
    listen_suffix = " ssl" if tls else ""
    lines = ["", "# Basic XrdHttp alternative; review TLS/auth policy.",
             "http {", "    server {",
             f"        listen {_nginx_arg(result.http_port)}{listen_suffix};"]
    _append_http_directive(lines, "ssl_certificate", certificate, "        ")
    _append_http_directive(
        lines, "ssl_certificate_key", certificate_key, "        ")
    lines.extend(["        location / {", "            brix_webdav on;",
                  f"            brix_webdav_auth {'required' if tls else 'none'};"])
    return lines, tls


def _append_shared_http(lines: list[str], result: Any) -> None:
    shared = ("brix_export", "brix_storage_backend", "brix_allow_write",
              "brix_vomsdir", "brix_voms_cert_dir", "brix_require_vo",
              "brix_trusted_ca", "brix_crl", "brix_crl_mode",
              "brix_crl_scope", "brix_token_config",
              "brix_macaroon_secret")
    for name in shared:
        for args in result.values.get(name, []):
            _append_http_directive(lines, name, args, "            ")


def _append_http_values(lines: list[str], result: Any) -> None:
    for name in ("brix_trusted_ca_dir", "brix_webdav_proxy_certs",
                 "brix_idmap", "brix_idmap_gridmap"):
        _append_http_directive(
            lines, name, result.http_values.get(name, ()), "            ")


def _http_lines(result: Any) -> list[str]:
    if not result.http_port:
        return []
    lines, _tls = _http_head(result)
    _append_shared_http(lines, result)
    _append_http_values(lines, result)
    lines.extend(["        }", "    }", "}"])
    return lines


def render(result: Any, source: str) -> str:
    """Render deterministic nginx text with review items before active config."""
    reviews = [item for item in result.findings
               if item.severity in ("review", "unsupported")]
    lines = [f"# Suggested BriX-Cache config converted from {_nginx_arg(source)}.",
             "# Validate with nginx -t and review every item below before use."]
    lines.extend(f"# REVIEW line {item.line} {item.directive}: {item.message}"
                 for item in reviews)
    lines.extend(["", "worker_processes auto;", "error_log stderr info;", "",
                  "events { worker_connections 1024; }", "", "stream {",
                  "    server {"])
    lines.extend(_directive_lines(result, "        "))
    lines.extend(["    }", "}"])
    lines.extend(_http_lines(result))
    return "\n".join(lines) + "\n"
