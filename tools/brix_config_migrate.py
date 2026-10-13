#!/usr/bin/env python3
"""Suggest a fail-visible BriX-Cache nginx config from an XRootD config.

The converter is deliberately offline: it parses text, never loads an XRootD
plugin, executes an include, expands an environment variable, or contacts an
endpoint.  Exact mappings become active directives; ambiguous mappings are
called out as REVIEW items in both the generated file and the optional report.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from brix_config_migrate_core import (  # noqa: E402
    Conversion,
    ConvertOptions,
    Directive,
    Finding,
    PfcState,
    _auth_protocol,
    _first,
    _gsi_option,
    _named,
    _prefer,
    _size_bytes,
    convert_authdb,
    parse_config,
)
from brix_config_migrate_render import render  # noqa: E402
from brix_config_migrate_runtime import (  # noqa: E402
    convert_runtime as _convert_runtime,
    detect_http as _detect_http,
)
from logging_support import diagnostic  # noqa: E402


def _apply_gsi(directive: Directive, result: Conversion,
               options: ConvertOptions) -> None:
    values = {name: _gsi_option(directive.args, name)
              for name in ("cert", "key", "certdir", "crl", "crldir",
                           "gridmap", "vomsdir")}
    direct = {"brix_certificate": values["cert"],
              "brix_certificate_key": values["key"],
              "brix_trusted_ca": options.ca_bundle,
              "brix_vomsdir": _prefer(options.vomsdir, values["vomsdir"]),
              "brix_voms_cert_dir": _prefer(options.voms_cert_dir,
                                               values["certdir"])}
    for name, value in direct.items():
        if value:
            result.set(name, value)
    _apply_gridmap(values["gridmap"], result)
    if values["certdir"]:
        result.http_values["brix_trusted_ca_dir"] = (values["certdir"],)
    _apply_gsi_crl(values, directive, result)
    _review_gsi_identity(values, directive, result)


def _apply_gsi_crl(values: dict[str, str | None], directive: Directive,
                   result: Conversion) -> None:
    level = values["crl"]
    if level is None:
        return
    modes = {"0": "off", "1": "try", "2": "try", "3": "require"}
    mode = modes.get(level)
    if mode is None:
        result.note("review", directive, "unknown GSI CRL enforcement level")
        return
    result.set("brix_crl_mode", mode)
    if mode == "off":
        return
    crl_path = values["crldir"] or values["certdir"]
    if crl_path:
        result.set("brix_crl", crl_path)
        return
    result.note("review", directive,
                "GSI CRL checking needs -crldir or -certdir")


def _review_gsi_identity(values: dict[str, str | None], directive: Directive,
                         result: Conversion) -> None:
    if not values["cert"] or not values["key"]:
        result.note("review", directive,
                    "GSI listener needs an explicit certificate and key")


def _apply_gridmap(gridmap: str | None, result: Conversion) -> None:
    if gridmap and gridmap.lower() != "none":
        result.set("brix_idmap", "map")
        result.set("brix_idmap_gridmap", gridmap)


def _select_auth(protocols: list[str], directives: list[Directive],
                 result: Conversion) -> None:
    unique = list(dict.fromkeys(protocols))
    if set(unique) == {"gsi", "ztn"}:
        result.set("brix_auth", "both")
    elif len(unique) == 1:
        result.set("brix_auth", "token" if unique[0] == "ztn" else unique[0])
    elif unique:
        result.set("brix_auth", unique[0])
        first = _first(directives, "sec.protocol")
        if first:
            result.note("review", first,
                        "multiple auth methods need brix_protbind review")
    else:
        result.set("brix_auth", "none")


def _convert_auth_protocol(directive: Directive, result: Conversion,
                           options: ConvertOptions) -> str | None:
    protocol = _auth_protocol(directive)
    if protocol is None:
        result.note("review", directive, "cannot identify security protocol")
        return None
    protocol = protocol.lower()
    result.note("translated", directive, f"security protocol {protocol}")
    if protocol == "gsi":
        _apply_gsi(directive, result, options)
    _review_auth_companion(protocol, directive, result)
    return protocol


def _review_auth_companion(protocol: str, directive: Directive,
                           result: Conversion) -> None:
    messages = {
        "ztn": "token issuer, audience, JWKS and scope policy need site input",
        "sss": "SSS keytab and permitted identities need site input",
        "krb5": "Kerberos keytab and service principal need site input",
        "unix": "UNIX authentication policy needs site validation",
        "host": "host authentication policy needs site validation",
        "pwd": "password verifier policy needs site validation",
    }
    message = messages.get(protocol)
    if message:
        result.note("review", directive, message)


def _convert_auth(directives: list[Directive], result: Conversion,
                  options: ConvertOptions) -> None:
    protocols: list[str] = []
    for directive in _named(directives, "sec.protocol"):
        protocol = _convert_auth_protocol(directive, result, options)
        if protocol:
            protocols.append(protocol)
    _select_auth(protocols, directives, result)

    for directive in _named(directives, "sec.protbind"):
        _convert_protbind(directive, result)


def _convert_protbind(directive: Directive, result: Conversion) -> None:
    mapped = tuple("ztn" if arg == "token" else arg for arg in directive.args)
    if mapped:
        result.add("brix_protbind", *mapped)
        result.note("translated", directive, "per-host auth binding")


def _convert_tls(directives: list[Directive], result: Conversion,
                 options: ConvertOptions) -> None:
    tls = _first(directives, "xrd.tls")
    if tls and len(tls.args) >= 2:
        result.set("brix_certificate", tls.args[0])
        result.set("brix_certificate_key", tls.args[1])
        result.set("brix_tls", "on")
        result.note("translated", tls, "TLS certificate and key")
    for directive in _named(directives, "xrd.tlsca"):
        _convert_tlsca(directive, result, options)


def _convert_tlsca(directive: Directive, result: Conversion,
                    options: ConvertOptions) -> None:
    if len(directive.args) < 2:
        result.note("review", directive, "incomplete xrd.tlsca directive")
        return
    key, value = directive.args[0].lower(), directive.args[1]
    mapping = {"certdir": "brix_trusted_ca",
               "verdepth": "brix_verify_depth",
               "verifylog": "brix_tls_verify_log",
               "crlcheck": "brix_crl_scope"}
    target = mapping.get(key)
    if target is None:
        result.note("review", directive, "unmapped xrd.tlsca option")
        return
    if key == "certdir":
        _convert_ca_directory(directive, result, options, value)
        return
    result.set(target, value)
    result.note("translated", directive, f"TLS CA policy {key}")


def _convert_ca_directory(directive: Directive, result: Conversion,
                          options: ConvertOptions, value: str) -> None:
    result.http_values["brix_trusted_ca_dir"] = (value,)
    if options.ca_bundle:
        result.set("brix_trusted_ca", options.ca_bundle)
        result.note("translated", directive, "TLS CA directory and stream bundle")
        return
    result.note("review", directive,
                "CA directory maps to HTTP; supply --ca-bundle for root://")


def _storage_features(directives: list[Directive]) -> tuple[bool, bool, bool]:
    libraries = " ".join(" ".join(item.args).lower() for item in directives
                         if item.name in ("ofs.osslib", "xrootd.fslib"))
    pss = _either("xrdpss" in libraries, _first(directives, "pss.origin"))
    pfc = _either("xrdpfc" in libraries, _first_prefix(directives, "pfc."))
    ceph = _either("xrdceph" in libraries, _first_prefix(directives, "ceph."))
    return pss, pfc, ceph


def _first_prefix(directives: list[Directive], prefix: str) -> Directive | None:
    return next((item for item in directives if item.name.startswith(prefix)), None)


def _either(first: bool, second: object | None) -> bool:
    return first if first else second is not None


def _ceph_pool(directives: list[Directive], options: ConvertOptions) -> str:
    if options.ceph_pool:
        return options.ceph_pool
    names = ("ceph.pool", "ceph.defaultpool", "ceph.data_pool")
    directive = next((item for item in directives
                      if item.name in names and item.args), None)
    return directive.args[0] if directive else "REVIEW_POOL"


def _marked(value: str | None, marker: str) -> str:
    return f"{marker}{value}" if value else ""


def _set_ceph_backend(directives: list[Directive], result: Conversion,
                      options: ConvertOptions) -> None:
    pool = _ceph_pool(directives, options)
    conf = _marked(options.ceph_conf, "@")
    prefix = _marked(options.ceph_key_prefix, "?")
    result.set("brix_storage_backend", f"ceph:{pool}{conf}{prefix}")
    marker = _first(directives, "ofs.osslib") or directives[0]
    result.note("review" if pool == "REVIEW_POOL" else "translated",
                marker, "XrdCeph requires pool and site namelib validation")


def _set_non_ceph_backend(directives: list[Directive],
                          result: Conversion) -> None:
    localroot = _first(directives, "oss.localroot")
    origin = _first(directives, "pss.origin")
    if origin and origin.args:
        value = origin.args[0]
        if "://" not in value:
            value = f"root://{value}"
        result.set("brix_storage_backend", value)
        result.note("translated", origin, "PSS fixed origin")
        return
    elif localroot and localroot.args:
        result.set("brix_storage_backend", f"posix:{localroot.args[0]}")
        result.note("translated", localroot, "POSIX storage root")
        return
    export = _first(directives, "all.export")
    if export and export.args:
        result.set("brix_storage_backend", f"posix:{export.args[0]}")
        result.note("translated", export, "default POSIX export root")
        return
    marker = Directive("--storage-backend", (), 0)
    result.set("brix_storage_backend", "posix:REVIEW_DATA_ROOT")
    result.note("review", marker, "no storage root/backend was found")


def _set_primary_backend(directives: list[Directive], result: Conversion,
                         options: ConvertOptions, ceph: bool) -> None:
    if ceph:
        _set_ceph_backend(directives, result, options)
        return
    _set_non_ceph_backend(directives, result)


def _set_export(directives: list[Directive], result: Conversion) -> None:
    export = _first(directives, "all.export")
    if not export or not export.args:
        result.set("brix_export", "/")
        result.set("brix_allow_write", "off")
        return
    result.set("brix_export", export.args[0])
    writable = not any(arg.lower() in ("r/o", "ro") for arg in export.args[1:])
    result.set("brix_allow_write", "on" if writable else "off")
    result.note("translated", export, "export path and write policy")


def _set_n2n(directives: list[Directive], result: Conversion,
             options: ConvertOptions) -> None:
    values = (("brix_n2n_scheme", options.n2n_scheme),
              ("brix_n2n_pool", options.n2n_pool),
              ("brix_n2n_prefix", options.n2n_prefix))
    for name, value in values:
        if value:
            result.set(name, value)
    _note_namelib(directives, result)


def _note_namelib(directives: list[Directive], result: Conversion) -> None:
    namelib = next((item for item in directives
                    if item.name in ("ceph.namelib", "oss.namelib")), None)
    if namelib:
        result.note("review", namelib,
                    "loadable namelib cannot be translated; set --n2n-* explicitly")


def _convert_storage(directives: list[Directive], result: Conversion,
                     options: ConvertOptions) -> None:
    _pss, pfc, ceph = _storage_features(directives)
    localroot = _first(directives, "oss.localroot")
    origin = _first(directives, "pss.origin")
    _set_primary_backend(directives, result, options, ceph)
    _set_export(directives, result)

    if pfc:
        result.set("brix_cache", "on")
        if localroot and localroot.args:
            result.set("brix_cache_store", f"posix:{localroot.args[0]}")
            result.set("brix_cache_export", "/")
        _convert_pfc(directives, result)
        if origin and "brix_write_through" in result.values:
            result.set("brix_wt_origin",
                       re.sub(r"^roots?://", "", origin.args[0]))
    _set_n2n(directives, result, options)


def _pfc_ram(directive: Directive, result: Conversion, _state: PfcState) -> None:
    result.set("brix_cache_store", f"ram:{directive.args[0]}")


def _pfc_blocksize(directive: Directive, result: Conversion,
                   state: PfcState) -> None:
    result.set("brix_cache_slice_size", directive.args[0])
    state.blocksize = _size_bytes(directive.args[0])


def _pfc_prefetch(directive: Directive, result: Conversion,
                  state: PfcState) -> None:
    result.set("brix_cache_prefetch", directive.args[0])
    state.prefetch = int(directive.args[0]) if directive.args[0].isdigit() else None


def _pfc_diskusage(directive: Directive, result: Conversion,
                   _state: PfcState) -> None:
    result.set("brix_cache_low_watermark", directive.args[0])
    result.set("brix_cache_high_watermark", directive.args[1])
    _pfc_purge_interval(directive, result)


def _pfc_purge_interval(directive: Directive, result: Conversion) -> None:
    if "purgeinterval" not in directive.args:
        return
    index = directive.args.index("purgeinterval")
    if index + 1 < len(directive.args):
        result.set("brix_cache_reap_interval", directive.args[index + 1])


def _pfc_cold(directive: Directive, result: Conversion, _state: PfcState) -> None:
    result.set("brix_cache_cold_max_age", directive.args[0])


def _pfc_only_cached(directive: Directive, result: Conversion,
                     _state: PfcState) -> None:
    result.set("brix_cache_only_if_cached",
               directive.args[0] if directive.args else "on")


def _pfc_uvkeep(directive: Directive, result: Conversion, _state: PfcState) -> None:
    result.set("brix_cache_uvkeep", directive.args[0])


def _pfc_writethrough(directive: Directive, result: Conversion,
                      _state: PfcState) -> None:
    result.set("brix_write_through", directive.args[0] if directive.args else "on")


def _pfc_trace(_directive: Directive, _result: Conversion,
               _state: PfcState) -> None:
    return


def _pfc_handlers() -> dict[str, Callable[[Directive, Conversion, PfcState], None]]:
    return {"pfc.ram": _pfc_ram, "pfc.blocksize": _pfc_blocksize,
            "pfc.prefetch": _pfc_prefetch, "pfc.diskusage": _pfc_diskusage,
            "pfc.purgecoldfiles": _pfc_cold,
            "pfc.onlyifcached": _pfc_only_cached, "pfc.uvkeep": _pfc_uvkeep,
            "pfc.writethrough": _pfc_writethrough, "pfc.trace": _pfc_trace}


def _apply_pfc(directive: Directive, result: Conversion, state: PfcState) -> None:
    handler = _pfc_handlers().get(directive.name)
    if handler is None:
        result.note("review", directive, "PFC policy has no exact mapping")
        return
    requires = {"pfc.ram": 1, "pfc.blocksize": 1, "pfc.prefetch": 1,
                "pfc.diskusage": 2, "pfc.purgecoldfiles": 1, "pfc.uvkeep": 1}
    if len(directive.args) < requires.get(directive.name, 0):
        result.note("review", directive, "incomplete PFC directive")
        return
    handler(directive, result, state)
    result.note("translated", directive, "PFC cache policy")


def _convert_pfc(directives: list[Directive], result: Conversion) -> None:
    state = PfcState()
    for directive in directives:
        if directive.name.startswith("pfc."):
            _apply_pfc(directive, result, state)
    _set_prefetch_window(state, result)


def _set_prefetch_window(state: PfcState, result: Conversion) -> None:
    if state.blocksize and state.prefetch is not None and state.prefetch > 0:
        result.set("brix_cache_prefetch_window",
                   str(state.blocksize * state.prefetch))


def _service_port(directives: list[Directive]) -> Directive | None:
    port = _first(directives, "xrd.port")
    return port if port is not None else _first(directives, "xrootd.port")


def _convert_services(directives: list[Directive], result: Conversion,
                      options: ConvertOptions) -> None:
    port = _service_port(directives)
    result.set("listen", port.args[0] if port and port.args else "1094")
    result.set("brix_root", "on")
    if port:
        result.note("translated", port, "root:// listener")
        _note_port_aliases(directives, port, result)
    for directive in _named(directives, "all.manager"):
        _convert_manager(directive, result)
    _convert_tpc(_first(directives, "ofs.tpc"), result)
    _detect_http(directives, result, options)


def _note_port_aliases(directives: list[Directive], selected: Directive,
                       result: Conversion) -> None:
    for directive in directives:
        if directive is selected or directive.name not in ("xrd.port",
                                                            "xrootd.port"):
            continue
        same = directive.args == selected.args
        result.note("ignored" if same else "review", directive,
                    "duplicate listener alias" if same
                    else "conflicting root:// listener aliases")


def _convert_manager(directive: Directive, result: Conversion) -> None:
    if directive.args:
        result.add("brix_cms_manager", *directive.args)
        result.note("translated", directive, "CMS manager membership")


def _convert_tpc(tpc: Directive | None, result: Conversion) -> None:
    if tpc is None or "streams" not in tpc.args:
        return
    index = tpc.args.index("streams")
    if index + 1 < len(tpc.args):
        result.set("brix_tpc_streams", tpc.args[index + 1])
        result.note("translated", tpc, "TPC stream cap")


def _convert_http(directives: list[Directive], result: Conversion) -> None:
    mapping = {
        "http.cert": "ssl_certificate",
        "http.key": "ssl_certificate_key",
        "http.cadir": "brix_trusted_ca_dir",
        "http.gridmap": "brix_idmap_gridmap",
    }
    for directive in directives:
        if directive.name == "http.httpsmode":
            continue
        _convert_http_directive(directive, result, mapping)
    for directive in _named(directives, "http.httpsmode"):
        _convert_http_directive(directive, result, mapping)


def _convert_http_directive(directive: Directive, result: Conversion,
                            mapping: dict[str, str]) -> None:
    target = mapping.get(directive.name)
    if target and directive.args:
        result.http_values[target] = (directive.args[0],)
        _http_gridmap(directive, result)
        result.note("translated", directive, "XrdHttp listener policy")
        return
    if directive.name == "http.httpsmode":
        if _https_auto_supported(directive, result):
            result.note("translated", directive,
                        "automatic HTTPS policy follows the migrated certificate")
        else:
            result.note("review", directive,
                        "HTTPS mode needs an exact auto policy and certificate pair")
        return
    _http_voms_extractor(directive, result)


def _https_auto_supported(directive: Directive, result: Conversion) -> bool:
    http_pair = {"ssl_certificate", "ssl_certificate_key"}
    root_pair = {"brix_certificate", "brix_certificate_key"}
    has_certificate = (http_pair <= result.http_values.keys()
                       or root_pair <= result.values.keys())
    return (tuple(arg.lower() for arg in directive.args) == ("auto",)
            and has_certificate)


def _http_gridmap(directive: Directive, result: Conversion) -> None:
    if directive.name == "http.gridmap" and directive.args[0] != "/dev/null":
        result.http_values["brix_idmap"] = ("map",)


def _http_voms_extractor(directive: Directive, result: Conversion) -> None:
    if directive.name != "http.secxtractor" or not directive.args:
        return
    if "voms" in " ".join(directive.args).lower():
        result.http_values["brix_webdav_proxy_certs"] = ("on",)
        result.note("translated", directive,
                    "XrdHttp VOMS certificate extraction")


def _convert_authz(directives: list[Directive], result: Conversion,
                   options: ConvertOptions) -> None:
    authdb = _first(directives, "acc.authdb")
    if authdb and authdb.args:
        result.set("brix_authdb_engine", "xrdacc")
        result.set("brix_authdb", options.authdb_path or authdb.args[0])
        result.note("translated", authdb, "XrdAcc authorization database")
    _copy_first(directives, result, "acc.audit", "brix_acc_audit",
                "XrdAcc audit mode")
    _copy_first(directives, result, "acc.authrefresh", "brix_acc_refresh",
                "XrdAcc refresh interval")
    for rule in options.require_vo:
        _add_vo_rule(rule, result)
    _convert_auth_plugins(directives, result)


def _config_argument(directive: Directive) -> str | None:
    value = next((arg for arg in directive.args if arg.startswith("config=")), None)
    return value.split("=", 1)[1] if value else None


def _convert_auth_plugin(directive: Directive, result: Conversion) -> None:
    plugin = " ".join(directive.args).lower()
    if "scitokens" in plugin:
        config = _config_argument(directive)
        if config:
            result.set("brix_token_config", config)
            result.note("translated", directive, "SciTokens issuer registry")
            return
        result.note("review", directive, "SciTokens plugin has no config path")
        return
    if "macaroon" in plugin:
        result.note("translated", directive, "native macaroon support is built in")


def _convert_auth_plugins(directives: list[Directive], result: Conversion) -> None:
    for directive in _named(directives, "ofs.authlib"):
        _convert_auth_plugin(directive, result)
    secret = _first(directives, "macaroons.secretkey")
    if secret and secret.args:
        result.set("brix_macaroon_secret", secret.args[0])
        result.note("translated", secret, "macaroon root secret")


def _copy_first(directives: list[Directive], result: Conversion,
                source: str, target: str, message: str) -> None:
    directive = _first(directives, source)
    if directive and directive.args:
        result.set(target, directive.args[0])
        result.note("translated", directive, message)


def _add_vo_rule(rule: str, result: Conversion) -> None:
    if "=" not in rule:
        raise ValueError("--require-vo must be PATH=VO")
    path, vo = rule.split("=", 1)
    result.add("brix_require_vo", path, vo)
    supplied = Directive("--require-vo", (), 0)
    result.note("translated", supplied, "operator-supplied VOMS VO rule")


def convert(directives: list[Directive], options: ConvertOptions) -> Conversion:
    """Translate known surfaces and inventory every remaining directive."""
    if not directives:
        raise ValueError("input contains no directives")
    result = Conversion()
    _convert_services(directives, result, options)
    _convert_runtime(directives, result)
    _convert_storage(directives, result, options)
    _convert_auth(directives, result, options)
    _convert_tls(directives, result, options)
    _convert_http(directives, result)
    _convert_authz(directives, result, options)
    seen = {finding.line for finding in result.findings}
    ignored = ("all.adminpath", "all.pidpath", "xrd.allow",
               "xrd.sched", "xrd.trace", "pss.setopt", "ofs.authorize",
               "xrootd.seclib")
    for directive in directives:
        if directive.line in seen:
            continue
        severity = "ignored" if directive.name in ignored else "unsupported"
        message = ("nginx/process-level setting; no direct migration needed"
                   if severity == "ignored" else "no safe automatic mapping")
        result.note(severity, directive, message)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="brix-config-migrate",
        description="suggest BriX-Cache nginx configuration from XRootD config")
    parser.add_argument("input", type=Path, help="XRootD configuration file")
    parser.add_argument("-o", "--output", type=Path,
                        help="write nginx config (default: stdout)")
    parser.add_argument("--report", type=Path, help="write JSON decision report")
    parser.add_argument("--strict", action="store_true",
                        help="exit 3 if review/unsupported items remain")
    parser.add_argument("--ca-bundle")
    parser.add_argument("--authdb-input", type=Path,
                        help="explicit XrdAcc authdb companion to convert")
    parser.add_argument("--authdb-output", type=Path,
                        help="write a BriX-compatible XrdAcc authdb")
    parser.add_argument("--vomsdir")
    parser.add_argument("--voms-cert-dir")
    parser.add_argument("--require-vo", action="append", default=[], metavar="PATH=VO")
    parser.add_argument("--ceph-pool")
    parser.add_argument("--ceph-conf")
    parser.add_argument("--ceph-key-prefix")
    parser.add_argument("--n2n-scheme", choices=("identity", "ral", "cephfs_path"))
    parser.add_argument("--n2n-pool")
    parser.add_argument("--n2n-prefix")
    parser.add_argument("--http-port",
                        help="WebDAV port (private loopback target when shared with root)")
    parser.add_argument("--http-connect-timeout",
                        help="private WebDAV connect timeout (default: 5s)")
    parser.add_argument("--http-idle-timeout",
                        help="HTTP handoff idle timeout (default: 75s)")
    return parser


def _write(path: Path | None, content: str) -> None:
    if path is None:
        sys.stdout.write(content)
        return
    path.write_text(content, encoding="utf-8")


def _options(args: argparse.Namespace) -> ConvertOptions:
    return ConvertOptions(
        ca_bundle=args.ca_bundle, vomsdir=args.vomsdir,
        voms_cert_dir=args.voms_cert_dir, ceph_pool=args.ceph_pool,
        ceph_conf=args.ceph_conf, ceph_key_prefix=args.ceph_key_prefix,
        n2n_scheme=args.n2n_scheme, n2n_pool=args.n2n_pool,
        n2n_prefix=args.n2n_prefix, http_port=args.http_port,
        http_connect_timeout=args.http_connect_timeout,
        http_idle_timeout=args.http_idle_timeout,
        authdb_path=str(args.authdb_output) if args.authdb_output else None,
        require_vo=args.require_vo)


def _write_report(path: Path | None, input_path: Path,
                  result: Conversion) -> None:
    if path is None:
        return
    payload = {"input": str(input_path),
               "findings": [asdict(item) for item in result.findings]}
    _write(path, json.dumps(payload, indent=2) + "\n")


def _run(args: argparse.Namespace) -> Conversion:
    if (args.authdb_input is None) != (args.authdb_output is None):
        raise ValueError("--authdb-input and --authdb-output must be used together")
    directives = parse_config(args.input.read_text(encoding="utf-8"))
    result = convert(directives, _options(args))
    if args.authdb_input is not None:
        source = args.authdb_input.read_text(encoding="utf-8")
        _write(args.authdb_output, convert_authdb(source))
    _write(args.output, render(result, str(args.input)))
    _write_report(args.report, args.input, result)
    return result


def _status(result: Conversion, strict: bool) -> int:
    unresolved = _unresolved(result)
    if not unresolved:
        return 0
    diagnostic("WARN", "brix-config-migrate", "review_required",
               f"{len(unresolved)} item(s) require operator review")
    return 3 if strict else 0


def _unresolved(result: Conversion) -> list[Finding]:
    return [item for item in result.findings
            if item.severity in ("review", "unsupported")]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except (OSError, UnicodeError, ValueError) as exc:
        diagnostic("ERROR", "brix-config-migrate", "convert_failed", exc)
        return 2
    return _status(result, args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
