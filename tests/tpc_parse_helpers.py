"""
tpc_parse_helpers.py — Python reimplementation of the native TPC opaque
parameter parser for testing.

Mirrors the C parser in src/tpc/parse.c so Python tests can verify the
opaque parameter parsing logic without starting an nginx server.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TpcOpaqueResult:
    """Parsed tpc.* opaque parameters (mirrors xrootd_tpc_params_t)."""
    src: str = ""
    src_host: str = ""
    src_port: int = 0
    src_path: str = ""
    dst: str = ""
    key: str = ""
    lfn: str = ""
    org: str = ""
    stage: str = ""
    token_mode: str = ""
    has_src: bool = False
    has_dst: bool = False
    has_key: bool = False
    has_lfn: bool = False
    has_org: bool = False
    has_stage: bool = False
    has_token_mode: bool = False


def _copy_value(dst_max: int, value: str) -> str:
    """Copy a value, truncating to dst_max."""
    if len(value) >= dst_max:
        return value[:dst_max - 1]
    return value


def parse_tpc_opaque(opaque: str) -> TpcOpaqueResult:
    """
    Parse tpc.* parameters from an opaque query string.

    Mirrors the C parser in src/tpc/parse.c.
    Returns a TpcOpaqueResult with populated fields.
    """
    out = TpcOpaqueResult()
    if not opaque:
        return out

    # Strip the path prefix (everything up to and including the first '?')
    # The C parser receives the raw opaque string which may start with /path?
    idx = opaque.find('?')
    if idx >= 0:
        opaque = opaque[idx + 1:]

    # Split on '&' to get tokens
    tokens = opaque.split('&')
    for token in tokens:
        if '=' not in token:
            continue

        key_part, _, value_part = token.partition('=')
        if not key_part.startswith('tpc.'):
            continue

        key = key_part[4:]  # strip 'tpc.' prefix
        value = value_part

        if key == 'src':
            out.src = _copy_value(512, value)
            out.has_src = True
        elif key == 'dst':
            out.dst = _copy_value(512, value)
            out.has_dst = True
        elif key == 'key':
            out.key = _copy_value(128, value)
            out.has_key = True
        elif key == 'lfn':
            out.lfn = _copy_value(4096, value)
            out.has_lfn = True
        elif key == 'org':
            out.org = _copy_value(256, value)
            out.has_org = True
        elif key == 'stage':
            out.stage = _copy_value(64, value)
            out.has_stage = True
        elif key == 'token_mode':
            out.token_mode = _copy_value(32, value)
            out.has_token_mode = True

    return out
