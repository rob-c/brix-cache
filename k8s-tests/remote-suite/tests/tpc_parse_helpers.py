"""
tpc_parse_helpers.py — Python reimplementation of the native TPC opaque
parameter parser for testing.

Mirrors the C parser in src/tpc/engine/parse.c so Python tests can verify the
opaque parameter parsing logic without starting an nginx server.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TpcOpaqueResult:
    """Parsed tpc.* opaque parameters (mirrors brix_tpc_params_t)."""
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

    Mirrors the C parser in src/tpc/engine/parse.c.
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
        pair = _tpc_pair(token)
        if pair is not None:
            _store_tpc_value(out, *pair)

    return out


def _tpc_pair(token):
    key_part, separator, value = token.partition('=')
    if not separator or not key_part.startswith('tpc.'):
        return None
    return key_part[4:], value


def _store_tpc_value(result, key, value):
    limits = {'src': 512, 'dst': 512, 'key': 128, 'lfn': 4096,
              'org': 256, 'stage': 64, 'token_mode': 32}
    limit = limits.get(key)
    if limit is None:
        return
    setattr(result, key, _copy_value(limit, value))
    setattr(result, 'has_' + key, True)
