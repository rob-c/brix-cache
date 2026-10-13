"""Runtime and shared-port mappings for the XRootD migration tool."""
from __future__ import annotations

from brix_config_migrate_core import (
    Conversion,
    ConvertOptions,
    Directive,
    _named,
)


def _private_http_port(stream_port: str, requested: str | None) -> str:
    """Choose the loopback WebDAV port behind a shared public listener."""
    if requested:
        return requested
    numeric = int(stream_port)
    return str(numeric + 1 if numeric < 65535 else numeric - 1)


def _configure_http_listener(detected: str, stream_port: str,
                             options: ConvertOptions,
                             result: Conversion) -> bool:
    """Configure WebDAV and return whether a private handoff was selected."""
    if detected != stream_port or not detected.isdigit():
        result.http_port = options.http_port or detected
        return False
    private_port = _private_http_port(stream_port, options.http_port)
    target = f"127.0.0.1:{private_port}"
    result.http_port = target
    result.set("brix_http_handoff", target)
    result.set("brix_http_handoff_connect_timeout",
               options.http_connect_timeout or "5s")
    result.set("brix_http_handoff_idle_timeout",
               options.http_idle_timeout or "75s")
    return True


def detect_http(directives: list[Directive], result: Conversion,
                options: ConvertOptions) -> None:
    """Map a separate WebDAV listener or configure loopback handoff."""
    for directive in _named(directives, "xrd.protocol"):
        http = next((arg for arg in directive.args
                     if arg.lower().startswith(("xrdhttp:", "http:"))), None)
        if not http:
            continue
        detected = http.split(":", 1)[1]
        stream_port = result.values["listen"][0][0]
        handed_off = _configure_http_listener(
            detected, stream_port, options, result)
        if handed_off:
            result.note("translated", directive,
                        "shared root/HTTP port via a loopback WebDAV handoff")
        else:
            result.note("review", directive,
                        "XrdHttp detected; review the WebDAV listener policy")


def convert_runtime(directives: list[Directive], result: Conversion) -> None:
    """Map exact, semantics-preserving XRootD connection controls."""
    for directive in _named(directives, "xrd.timeout"):
        _convert_timeout(directive, result)
    for directive in _named(directives, "xrd.network"):
        _convert_network(directive, result)


def _convert_timeout(directive: Directive, result: Conversion) -> None:
    exact = (len(directive.args) == 2
             and directive.args[0].lower() == "read"
             and directive.args[1].isdigit())
    if not exact:
        result.note("review", directive,
                    "only an exact 'read SECONDS' timeout maps safely")
        return
    result.set("brix_read_timeout", f"{directive.args[1]}s")
    result.note("translated", directive, "client read timeout")


def _convert_network(directive: Directive, result: Conversion) -> None:
    policy = tuple(arg.lower() for arg in directive.args)
    if policy == ("keepalive",):
        result.set("brix_tcp_keepalive", "on")
        result.note("translated", directive, "TCP keepalive policy")
        return
    if policy == ("nodnr",):
        result.note("ignored", directive,
                    "DNS policy is supplied by BriX's resolver configuration")
        return
    result.note("review", directive,
                "network policy has no safe automatic mapping")
