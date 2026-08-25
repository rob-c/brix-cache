"""Vector generator + oracle for the non-UTF8 byte-input codec fast-lane suite.

Drives ``tests/c/nonutf8_codec_harness.c`` (which links the REAL production
kernels ``brix_http_urldecode`` / ``brix_http_urlencode`` from
``src/core/compat/uri.c`` and ``brix_opaque_illegal_byte`` from
``src/protocols/root/path/opaque_validate.c``). Every user-supplied byte on the
WebDAV/S3/XrdHttp percent-decode surface and the XRootD CGI-opaque gate flows
through these before auth or storage sees it, so this suite proves — for the
full 0x00-0xFF space and a battery of non-UTF8 multi-byte sequences (overlong,
surrogate, out-of-range, truncated, BOM, Latin-1) — that they are handled
byte-exactly.

The expected values come from independent Python oracles (a differential check,
not a copy of the C), except round-trip which asserts the model-free invariant
"every byte survives encode->decode". Pure Python + one tiny compiled harness;
no nginx runtime and no live server, so the whole thing rides the fast lane.

Consumed by ``tests/test_nonutf8_input.py`` (thin parametrized asserts).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess

from cmdscripts.compile_run import REPO_ROOT, run


# --- BRIX return codes / flags (mirror src/core/compat/uri.h) ---------------
DEC_OK = 0
DEC_OVERFLOW = 1
DEC_NUL_BYTE = 2
DEC_BADARG = 3
REJECT_NUL = 0x01
PLUS_TO_SPACE = 0x02

# --- opaque schema verdicts (mirror opaque_validate.h) ----------------------
SCHEMA_OK = 0
SCHEMA_BAD_TYPE = 1
SCHEMA_UNKNOWN_KEY = 2
# Recognized namespaces + bare keys (opaque_validate.c:130-137). Each namespace
# carries its dot so a bare "xrd" cannot masquerade as the "xrd." namespace.
SCHEMA_NAMESPACES = (b"oss.", b"tpc.", b"xrd.", b"xrdcl.", b"cms.", b"scitag.")
SCHEMA_BARE_KEYS = (b"authz",)
# keybuf the harness passes to brix_opaque_schema_check (do_schema, KEYBUF_CAP).
SCHEMA_KEYBUF_CAP = 256

# RFC 3986 unreserved set the encoder passes through (src/core/compat/uri.c:79).
UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

# The exact XRootD CGI-opaque permit set (src/protocols/root/path/opaque_validate.c:42).
OPAQUE_ALLOWED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    b".-_~"
    b"/:@[]"
    b"%+"
    b"=&,?;"
)


# --- independent oracles ----------------------------------------------------
def _hexval(c: int) -> int:
    if 0x30 <= c <= 0x39:
        return c - 0x30
    if 0x41 <= c <= 0x46:
        return c - 0x41 + 10
    if 0x61 <= c <= 0x66:
        return c - 0x61 + 10
    return -1


def _percent_byte(src: bytes, index: int) -> int | None:
    if src[index] != 0x25 or index + 2 >= len(src):
        return None
    high = _hexval(src[index + 1])
    low = _hexval(src[index + 2])
    if high < 0 or low < 0:
        return None
    return (high << 4) | low


def _decoded_token(src: bytes, index: int, flags: int) -> tuple[int, int, int]:
    decoded = _percent_byte(src, index)
    if decoded is not None:
        if decoded == 0 and flags & REJECT_NUL:
            return DEC_NUL_BYTE, 0, 0
        return DEC_OK, decoded, 3
    if src[index] == 0x2B and flags & PLUS_TO_SPACE:
        return DEC_OK, 0x20, 1
    return DEC_OK, src[index], 1


def _decode_bytes(src: bytes, dst_sz: int, flags: int) -> tuple[int, bytes]:
    output = bytearray()
    index = 0
    while index < len(src):
        if len(output) + 1 >= dst_sz:
            return DEC_OVERFLOW, b""
        status, value, consumed = _decoded_token(src, index, flags)
        if status != DEC_OK:
            return status, b""
        output.append(value)
        index += consumed
    return DEC_OK, bytes(output).split(b"\x00", 1)[0]


def dec_ref(src: bytes, dst_sz: int, flags: int) -> tuple[int, bytes]:
    """Reference percent-decoder matching brix_http_urldecode's contract.

    Returns (rc, view) where view is the C-string view of the decoded output
    (truncated at the first embedded NUL — exactly what strlen-based callers
    downstream observe, which is what the harness reports). On any non-OK rc the
    harness emits no bytes, so view is b"".
    """
    if dst_sz < 2:
        return DEC_BADARG, b""
    return _decode_bytes(src, dst_sz, flags)


def _encoded_token(value: int, safe: bytes) -> bytes:
    if value in UNRESERVED or value in safe:
        return bytes((value,))
    return b"%%%02X" % value


def _encode_bytes(src: bytes, dst_sz: int, safe: bytes) -> tuple[int, bytes]:
    output = bytearray()
    for value in src:
        token = _encoded_token(value, safe)
        if len(output) + len(token) >= dst_sz:
            return -1, b""
        output.extend(token)
    return len(output), bytes(output)


def enc_ref(src: bytes, dst_sz: int, safe: bytes) -> tuple[int, bytes]:
    """Reference RFC 3986 encoder mirroring brix_http_urlencode's contract."""
    if dst_sz < 1:
        return -1, b""
    return _encode_bytes(src, dst_sz, safe)


def opaque_ref(data: bytes) -> tuple[int, int]:
    """Reference for brix_opaque_illegal_byte (scan stops at the first NUL)."""
    for b in data:
        if b == 0:
            break
        if b not in OPAQUE_ALLOWED:
            return (1, b)
    return (0, -1)


def _schema_key_value(segment: bytes) -> tuple[bytes, bytes]:
    separator = segment.find(b"=")
    if separator < 0:
        return segment, b""
    return segment[:separator], segment[separator + 1:]


def _asize_verdict(value: bytes) -> tuple[int, bytes]:
    if value and all(0x30 <= byte <= 0x39 for byte in value):
        return SCHEMA_OK, b""
    return SCHEMA_BAD_TYPE, b"oss.asize"


def _known_schema_key(key: bytes) -> bool:
    for namespace in SCHEMA_NAMESPACES:
        if key.startswith(namespace):
            return True
    return key in SCHEMA_BARE_KEYS


def _schema_segment(seg: bytes) -> tuple[int, bytes]:
    """Verdict + offending-key for one '&'-delimited key=value segment
    (mirrors brix_opaque_check_segment)."""
    if not seg:
        return SCHEMA_OK, b""
    key, value = _schema_key_value(seg)
    if key == b"oss.asize":
        return _asize_verdict(value)
    if _known_schema_key(key):
        return SCHEMA_OK, b""
    return SCHEMA_UNKNOWN_KEY, key


def schema_ref(data: bytes) -> tuple[int, bytes]:
    """Reference for brix_opaque_schema_check: returns (verdict, offending-key
    C-string view). The gate is NUL-terminated (scan stops at the first NUL),
    tolerates a single leading '?', splits on top-level '&' only, and on a
    violation copies the offending key (truncated to KEYBUF_CAP-1) — which is
    exactly the byte sequence the harness echoes back for us to assert on."""
    s = data.split(b"\x00", 1)[0]              # NUL-terminated C string
    if s[:1] == b"?":
        s = s[1:]
    remaining = s
    while len(remaining) > 0:
        amp = remaining.find(b"&")
        seg = remaining if amp < 0 else remaining[:amp]
        verdict, key = _schema_segment(seg)
        if verdict != SCHEMA_OK:
            return (verdict, key[:SCHEMA_KEYBUF_CAP - 1])   # keybuf truncation
        if amp < 0:
            break
        remaining = remaining[amp + 1:]
    return (SCHEMA_OK, b"")


# Reserved basename suffixes/infixes (reserved_names.h:62-80). A basename that
# matches is service-internal -> hidden / NotFound.
INTERNAL_SUFFIXES = (b".cinfo", b".xrdcinfo", b".meta", b".xrdt", b".commit")
INTERNAL_INFIXES = (b".xrd-tmp.", b".xrdresume.")


def internal_name_ref(path: bytes) -> int:
    """Reference for brix_is_internal_name (pure lexical per-component test).
    The C API is NUL-terminated, so an embedded NUL truncates the name (a real
    change of verdict worth asserting). EVERY '/'-separated component is tested,
    not just the basename — a reserved DIRECTORY would otherwise vanish from
    listings while its subtree stayed reachable by name. Suffix/infix matching
    is byte-agnostic on the stem, so a non-UTF8 filename ending in a reserved
    suffix is still hidden."""
    for name in path.split(b"\x00", 1)[0].split(b"/"):
        if not name:
            continue
        if name.endswith(INTERNAL_SUFFIXES) \
                or any(infix in name for infix in INTERNAL_INFIXES):
            return 1
    return 0


# --- vector model -----------------------------------------------------------
@dataclass(frozen=True)
class Vec:
    vid: str
    line: str
    kind: str      # "codec" -> expect (rc, bytes); "opaque" -> expect (rc, int)
    expect: tuple


def _hx(data: bytes) -> str:
    return "." if not data else data.hex()


def _codec(vid: str, op: str, arg: str, dst_sz: int, data: bytes,
           expect: tuple) -> Vec:
    return Vec(vid, f"{op} {arg} {dst_sz} {_hx(data)}", "codec", expect)


def _opaque(vid: str, data: bytes) -> Vec:
    return Vec(vid, f"o {_hx(data)}", "opaque", opaque_ref(data))


def _schema(vid: str, data: bytes) -> Vec:
    # kind "schema" shares the codec 3-field wire format: (verdict, key-bytes).
    return Vec(vid, f"s {_hx(data)}", "schema", schema_ref(data))


def _name(vid: str, data: bytes) -> Vec:
    # kind "name" is a single-field verdict (int): 1 hidden, 0 visible.
    return Vec(vid, f"n {_hx(data)}", "name", internal_name_ref(data))


# Non-UTF8 multi-byte sequences: the heart of "handled correctly" — these must
# survive the percent-codec byte-for-byte even though none is valid UTF-8.
_NONUTF8_BLOBS: list[tuple[str, bytes]] = [
    ("lone-cont-80", b"\x80"),
    ("lone-cont-bf", b"\xbf"),
    ("lone-lead-c2", b"\xc2"),
    ("lone-lead-df", b"\xdf"),
    ("lone-lead-e0", b"\xe0"),
    ("lone-lead-f0", b"\xf0"),
    ("overlong-nul-c080", b"\xc0\x80"),
    ("overlong-slash-c0af", b"\xc0\xaf"),
    ("overlong-3byte-e08080", b"\xe0\x80\x80"),
    ("overlong-4byte-f0808080", b"\xf0\x80\x80\x80"),
    ("surrogate-lo-eda080", b"\xed\xa0\x80"),
    ("surrogate-hi-edbfbf", b"\xed\xbf\xbf"),
    ("surrogate-pair-eda080edb080", b"\xed\xa0\x80\xed\xb0\x80"),
    ("out-of-range-f4908080", b"\xf4\x90\x80\x80"),
    ("invalid-f5", b"\xf5\x80\x80\x80"),
    ("invalid-fe", b"\xfe"),
    ("invalid-ff", b"\xff"),
    ("truncated-2of3-e0a0", b"\xe0\xa0"),
    ("truncated-3of4-f09080", b"\xf0\x90\x80"),
    ("bom-utf16-be", b"\xfe\xff"),
    ("bom-utf16-le", b"\xff\xfe"),
    ("bom-utf8", b"\xef\xbb\xbf"),
    ("utf16le-A", b"A\x00"),
    ("utf16be-A", b"\x00A"),
    ("latin1-cafe", b"caf\xe9"),
    ("latin1-naive", b"na\xefve"),
    ("cp1252-smartquote", b"\x93hello\x94"),
    ("shift-jis-ish", b"\x82\xa0\x82\xa2"),
    ("gb18030-ish", b"\x81\x30\x81\x30"),
    ("all-high-nibble", bytes(range(0x80, 0x90))),
    ("mixed-valid-invalid", b"a\xc3\xa9b\xff\x80c"),
    ("high-run-32", bytes([0x80 + (i % 0x80) for i in range(32)])),
    ("high-run-64", bytes([0x80 + (i * 7 % 0x80) for i in range(64)])),
    ("full-highhalf", bytes(range(0x80, 0x100))),
    ("descending-high", bytes(range(0xFF, 0x7F, -1))),
    ("percent-lookalike-in-high", b"\x80%\x81%%\x82"),
    ("plus-in-high", b"\x80+\x81"),
    ("dotdot-in-high", b"\x80..\x81/passwd"),
    ("crlf-in-high", b"\x80\r\n\x81"),
    ("controls-run", bytes(range(0x01, 0x20))),
    ("del-and-high", b"\x7f\x80\xff"),
]
# Deterministic pseudo-random high-byte blobs of assorted lengths (LCG, no RNG
# dependency — reproducible ids).
_LCG = 0x1234_5678
for _n in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
           71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127):
    _buf = bytearray()
    for _ in range(_n):
        _LCG = (_LCG * 1_103_515_245 + 12_345) & 0x7FFF_FFFF
        _buf.append(0x80 | (_LCG >> 16 & 0x7F))   # force high bit: guaranteed non-UTF8-ascii
    _NONUTF8_BLOBS.append((f"prng-high-{_n}", bytes(_buf)))

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "nonutf8_codec_part2.py")
