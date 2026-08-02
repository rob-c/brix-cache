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


def dec_ref(src: bytes, dst_sz: int, flags: int) -> tuple[int, bytes]:
    """Reference percent-decoder mirroring brix_http_urldecode's contract.

    Returns (rc, view) where view is the C-string view of the decoded output
    (truncated at the first embedded NUL — exactly what strlen-based callers
    downstream observe, which is what the harness reports). On any non-OK rc the
    harness emits no bytes, so view is b"".
    """
    if dst_sz < 2:
        return (DEC_BADARG, b"")
    out = bytearray()
    di = 0
    si = 0
    n = len(src)
    while si < n:
        if di + 1 >= dst_sz:
            return (DEC_OVERFLOW, b"")
        c = src[si]
        if c == 0x25 and si + 2 < n:  # '%'
            hi = _hexval(src[si + 1])
            lo = _hexval(src[si + 2])
            if hi >= 0 and lo >= 0:
                dec = (hi << 4) | lo
                if dec == 0 and (flags & REJECT_NUL):
                    return (DEC_NUL_BYTE, b"")
                out.append(dec)
                di += 1
                si += 3
                continue
        if c == 0x2B and (flags & PLUS_TO_SPACE):  # '+'
            out.append(0x20)
            di += 1
            si += 1
            continue
        out.append(c)
        di += 1
        si += 1
    return (DEC_OK, bytes(out).split(b"\x00", 1)[0])


def enc_ref(src: bytes, dst_sz: int, safe: bytes) -> tuple[int, bytes]:
    """Reference RFC 3986 encoder mirroring brix_http_urlencode's contract."""
    if dst_sz < 1:
        return (-1, b"")
    out = bytearray()
    di = 0
    for c in src:
        if c in UNRESERVED or c in safe:
            if di + 1 >= dst_sz:
                return (-1, b"")
            out.append(c)
            di += 1
        else:
            if di + 3 >= dst_sz:
                return (-1, b"")
            out += b"%%%02X" % c
            di += 3
    return (di, bytes(out))


def opaque_ref(data: bytes) -> tuple[int, int]:
    """Reference for brix_opaque_illegal_byte (scan stops at the first NUL)."""
    for b in data:
        if b == 0:
            break
        if b not in OPAQUE_ALLOWED:
            return (1, b)
    return (0, -1)


def _schema_segment(seg: bytes) -> tuple[int, bytes]:
    """Verdict + offending-key for one '&'-delimited key=value segment
    (mirrors brix_opaque_check_segment)."""
    if not seg:
        return (SCHEMA_OK, b"")
    eq = seg.find(b"=")
    if eq < 0:
        key, val, has_val = seg, b"", False
    else:
        key, val, has_val = seg[:eq], seg[eq + 1:], True
    _ = has_val  # value presence is implicit in val/key split; kept for parity
    if key == b"oss.asize":
        if len(val) > 0 and all(0x30 <= c <= 0x39 for c in val):
            return (SCHEMA_OK, b"")
        return (SCHEMA_BAD_TYPE, key)
    for ns in SCHEMA_NAMESPACES:
        # has_prefix: key must begin with ns (and be at least as long).
        if len(key) >= len(ns) and key[:len(ns)] == ns:
            return (SCHEMA_OK, b"")
    if key in SCHEMA_BARE_KEYS:
        return (SCHEMA_OK, b"")
    return (SCHEMA_UNKNOWN_KEY, key)


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
    """Reference for brix_is_internal_name (pure lexical basename test). The C API
    is NUL-terminated, so an embedded NUL truncates the name (a real change of
    verdict worth asserting). Suffix/infix matching is byte-agnostic on the stem,
    so a non-UTF8 filename ending in a reserved suffix is still hidden."""
    s = path.split(b"\x00", 1)[0]              # NUL-terminated C string
    slash = s.rfind(b"/")
    name = s[slash + 1:] if slash >= 0 else s  # basename
    if len(name) == 0:
        return 0
    for suf in INTERNAL_SUFFIXES:
        if len(name) >= len(suf) and name[len(name) - len(suf):] == suf:
            return 1
    for infix in INTERNAL_INFIXES:
        if infix in name:
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


def build_vectors() -> list[Vec]:
    vecs: list[Vec] = []

    # 1. decode "%XX" -> byte, every non-NUL byte (byte-transparent decode).
    for b in range(0x01, 0x100):
        src = b"%%%02X" % b
        vecs.append(_codec(f"dec-pct-{b:02x}", "d", "0", 512, src,
                           dec_ref(src, 512, 0)))

    # 2. decode "%xx" lowercase-hex over the high half (case-insensitive nibble).
    for b in range(0x80, 0x100):
        src = b"%%%02x" % b
        vecs.append(_codec(f"dec-pctlc-{b:02x}", "d", "0", 512, src,
                           dec_ref(src, 512, 0)))

    # 3. literal high byte copied through untouched.
    for b in range(0x80, 0x100):
        src = bytes([b])
        vecs.append(_codec(f"dec-lit-{b:02x}", "d", "0", 512, src,
                           dec_ref(src, 512, 0)))

    # 4. REJECT_NUL must not disturb any non-NUL high byte's "%XX" decode.
    for b in range(0x80, 0x100):
        src = b"%%%02X" % b
        vecs.append(_codec(f"dec-rn-{b:02x}", "d", str(REJECT_NUL), 512, src,
                           dec_ref(src, 512, REJECT_NUL)))

    # 5. NUL handling + malformed-'%' preserved-verbatim (nginx-lenient).
    curated_dec = [
        ("nul-pct-plain", b"%00", 0),                 # -> embedded NUL, view empty
        ("nul-pct-reject", b"%00", REJECT_NUL),       # -> NUL_BYTE
        ("nul-literal-plain", b"\x00", 0),            # literal NUL, view empty
        ("nul-literal-reject", b"\x00", REJECT_NUL),  # literal NUL NOT gated by flag
        ("nul-embedded-prefix", b"A%00B", 0),         # view truncates to "A"
        ("nul-embedded-lit", b"A\x00B", 0),
        ("bad-pct-bare", b"%", 0),
        ("bad-pct-onenibble", b"%A", 0),
        ("bad-pct-nonhex-hi", b"%G0", 0),
        ("bad-pct-nonhex-lo", b"%0G", 0),
        ("bad-pct-nonhex-both", b"%ZZ", 0),
        ("bad-pct-space", b"%  ", 0),
        ("bad-pct-trailing", b"data%", 0),
        ("bad-pct-trailing2", b"data%4", 0),
        ("bad-pct-double", b"%%41", 0),               # -> "%A"
        ("bad-pct-tripled", b"%%%41", 0),
        ("pct-mixedcase", b"%aB%Cd", 0),
        ("pct-encoded-percent", b"%25", 0),           # -> literal '%'
        ("pct-encoded-nul-guard", b"%2500", 0),       # -> "%00" literal, not a NUL
        ("dotdot-encoded", b"%2e%2e%2fpasswd", 0),    # decodes to ../passwd (bytes only)
        ("high-pct-run", b"%80%81%FE%FF", 0),
        ("empty", b"", 0),
    ]
    for vid, src, fl in curated_dec:
        vecs.append(_codec(f"dec-{vid}", "d", str(fl), 512, src,
                           dec_ref(src, 512, fl)))

    # 6. overflow boundaries (exact-fit OK vs one-short OVERFLOW; %XX 3->1 shrink).
    overflow_dec = [
        ("fit-exact", b"AAAA", 5),     # 4 bytes + NUL -> OK
        ("fit-short", b"AAAA", 4),     # OVERFLOW
        ("fit-tiny", b"AAAA", 2),      # OVERFLOW after 0
        ("badarg-1", b"A", 1),         # BADARG (dst_sz < 2)
        ("badarg-0", b"A", 0),         # BADARG
        ("empty-badarg", b"", 1),      # BADARG regardless of content
        ("shrink-fit", b"%41%41", 3),  # 2 decoded bytes + NUL -> OK
        ("shrink-short", b"%41%41", 2),
        ("high-fit", b"%FF%FE", 3),
        ("high-short", b"%FF%FE", 2),
        ("bigblob-fit", b"\x80" * 40, 41),
        ("bigblob-short", b"\x80" * 40, 40),
    ]
    for vid, src, sz in overflow_dec:
        vecs.append(_codec(f"ovf-{vid}", "d", "0", sz, src,
                           dec_ref(src, sz, 0)))

    # 7. '+' handling with and without PLUS_TO_SPACE; %2B always literal '+'.
    plus_dec = [
        ("plain-noflag", b"a+b", 0),
        ("plain-flag", b"a+b", PLUS_TO_SPACE),
        ("run-flag", b"+++", PLUS_TO_SPACE),
        ("run-noflag", b"+++", 0),
        ("enc-plus-noflag", b"%2B", 0),
        ("enc-plus-flag", b"%2B", PLUS_TO_SPACE),
        ("high-plus-flag", b"\x80+\x81", PLUS_TO_SPACE),
        ("mixed", b"a+b%2Bc", PLUS_TO_SPACE),
    ]
    for vid, src, fl in plus_dec:
        vecs.append(_codec(f"plus-{vid}", "d", str(fl), 512, src,
                           dec_ref(src, 512, fl)))

    # 8. encode every byte 0x00-0xFF vs the RFC 3986 oracle (safe_extra = none).
    for b in range(0x00, 0x100):
        src = bytes([b])
        vecs.append(_codec(f"enc-byte-{b:02x}", "e", "-", 1024, src,
                           enc_ref(src, 1024, b"")))

    # 9. safe_extra passthrough, encode overflow, non-UTF8 blob encode.
    curated_enc = [
        ("safe-slash", "/", b"a/b/c", 64, b"/"),
        ("safe-none-slash", "-", b"a/b", 64, b""),
        ("safe-multi", "/:@", b"h:1/@x", 64, b"/:@"),
        ("safe-tilde-noop", "-", b"~-._", 64, b""),
        ("ovf-exact", "-", b"AAA", 4, b""),      # 3 pass-through + NUL -> ok
        ("ovf-short", "-", b"AAA", 3, b""),      # -1
        ("ovf-esc-exact", "-", b"\xff", 4, b""), # "%FF" + NUL -> ok
        ("ovf-esc-short", "-", b"\xff", 3, b""), # -1
        ("blob-highhalf", "-", bytes(range(0x80, 0x100)), 1024, b""),
        ("blob-controls", "-", bytes(range(0x00, 0x20)), 1024, b""),
    ]
    for vid, safe, src, sz, safe_b in curated_enc:
        vecs.append(_codec(f"enc-{vid}", "e", safe, sz, src,
                           enc_ref(src, sz, safe_b)))
    for name, blob in _NONUTF8_BLOBS:
        vecs.append(_codec(f"enc-blob-{name}", "e", "-", 4096, blob,
                           enc_ref(blob, 4096, b"")))

    # 10. round-trip: encode-then-decode is the identity for every non-NUL byte.
    for b in range(0x01, 0x100):
        src = bytes([b])
        vecs.append(_codec(f"rt-byte-{b:02x}", "r", "0", 4096, src,
                           (DEC_OK, src)))

    # 11. round-trip identity for every non-UTF8 multi-byte sequence.
    for name, blob in _NONUTF8_BLOBS:
        view = blob.split(b"\x00", 1)[0]   # C-string view (blobs here are NUL-free-prefixed)
        vecs.append(_codec(f"rt-blob-{name}", "r", "0", 8192, blob,
                           (DEC_OK, view)))

    # 12. opaque gate: exhaustive 0x01-0xFF verdict + offending byte.
    for b in range(0x01, 0x100):
        vecs.append(_opaque(f"opq-byte-{b:02x}", bytes([b])))

    # 13. opaque gate: empty, permitted strings, injection primitives, structure.
    curated_opq = [
        ("empty", b""),
        ("all-permitted", b"oss.asize=123&tpc.key=v,w;x?y=z"),
        ("ipv6-brackets", b"tpc.src=[::ffff:127.0.0.1]:1094"),
        ("unreserved", b"A.z-0_9~"),
        ("first-illegal-mid", b"oss.a=b c=d"),      # space -> illegal at the space
        ("high-byte-mid", b"oss.a=\xff"),
        ("control-lf", b"k=v\nSet-Cookie:x"),
        ("control-cr", b"k=v\rx"),
        ("control-tab", b"k=v\tx"),
        ("del", b"k=v\x7f"),
        ("shell-backtick", b"k=`id`"),
        ("shell-dollar", b"k=$x"),
        ("shell-pipe", b"k=a|b"),
        ("shell-lt", b"k=a<b"),
        ("shell-quote", b"k=a'b"),
        ("shell-dquote", b'k=a"b'),
        ("shell-star", b"k=a*b"),
        ("shell-paren", b"k=(a)"),
        ("shell-brace", b"k={a}"),
        ("backslash", b"k=a\\b"),
        ("nul-terminates", b"k=v\x00\xff"),         # scan stops at NUL, prefix clean
    ]
    for vid, data in curated_opq:
        vecs.append(_opaque(f"opq-{vid}", data))

    # 14. schema gate — offending-key echo byte-transparency: every non-NUL byte
    # as a lone (unrecognized) bare key must be reported verbatim in the copied
    # key, so a non-UTF8 key can be named in a rejection log without mojibake or
    # truncation. Distinct surface from the Tier-1 byte gate above.
    for b in range(0x01, 0x100):
        vecs.append(_schema(f"sch-key1-{b:02x}", bytes([b])))

    # 15. schema gate — typed-value enforcement: oss.asize is unsigned-int-typed,
    # so every non-digit value byte (all high bytes, controls, metachars) must be
    # rejected BAD_TYPE while the ten digits pass. Exhaustive over 0x01-0xFF.
    for b in range(0x01, 0x100):
        vecs.append(_schema(f"sch-val-{b:02x}", b"oss.asize=" + bytes([b])))

    # 16. schema gate — a recognized-namespace value is schema-orthogonal to byte
    # hygiene (Tier-1's job), so an arbitrary high byte in a tpc.src value is
    # accepted here. Confirms strict mode does not over-reject non-UTF8 values.
    for b in range(0x80, 0x100):
        vecs.append(_schema(f"sch-nsval-{b:02x}", b"tpc.src=" + bytes([b])))

    # 17. schema gate — structure, NUL truncation, nested-query scope, dot-guard,
    # keybuf truncation, and non-UTF8 keys among valid pairs.
    curated_sch = [
        ("empty", b""),
        ("q-only", b"?"),
        ("leading-q", b"?oss.asize=1"),
        ("amp-amp", b"oss.asize=1&&tpc.x=2"),          # empty middle seg is OK
        ("trailing-amp", b"authz=xyz&"),               # trailing empty seg unchecked
        ("bare-authz", b"authz=Bearer%20token"),
        ("unknown-bare", b"evil=1"),
        ("unknown-ns", b"foo.bar=1"),
        ("good-then-nul-key", b"oss.asize=5&hack\x00=1"),   # NUL truncates -> "...&hack"
        ("highkey-first", b"\xff\xfe=1&oss.asize=2"),       # high-byte key echoed verbatim
        ("high-in-mid-key", b"oss.asize=1&tp\xffc.x=2"),    # not the tpc. namespace
        ("asize-empty-val", b"oss.asize="),
        ("asize-noeq", b"oss.asize"),
        ("asize-leading-zeros", b"oss.asize=007"),
        ("asize-plus", b"oss.asize=+5"),
        ("asize-space", b"oss.asize= 5"),
        ("asize-highval", b"oss.asize=\xc3\xa9"),
        ("nested-query-scope", b"tpc.src=root://h//p?a=b&c=d"),  # nested '&c=d' seen as sibling
        ("scitag-ns", b"scitag.flow=1"),
        ("cms-ns", b"cms.foo=x"),
        ("xrdcl-ns", b"xrdcl.wantprot=unix"),
        ("xrd-bare-masq", b"xrd=1"),                    # "xrd" != "xrd." namespace
        ("long-key-trunc", b"x" * 300 + b"=1"),         # keybuf truncates at CAP-1
        ("high-run-key", bytes(range(0x80, 0x90)) + b"=1"),
        ("controls-key", bytes(range(0x01, 0x0b)) + b"=1"),
        ("del-key", b"\x7f=1"),
    ]
    for vid, data in curated_sch:
        vecs.append(_schema(f"sch-{vid}", data))

    # 18. internal-name gate — no lone byte (control/high/metachar) may be
    # misclassified as an internal sidecar/temp. Exhaustive negative over
    # 0x01-0xFF: a one-byte basename is never a reserved name.
    for b in range(0x01, 0x100):
        vecs.append(_name(f"nam-lone-{b:02x}", bytes([b])))

    # 19. internal-name gate — a reserved suffix with a non-UTF8 STEM must still
    # be hidden (the match is byte-agnostic on the stem; else a non-UTF8-named
    # sidecar would leak its existence/size/mtime to a client).
    for b in range(0x80, 0x100):
        vecs.append(_name(f"nam-stem-{b:02x}", bytes([b]) * 3 + b".cinfo"))

    # 20. internal-name gate — a reserved suffix POLLUTED by a trailing non-UTF8
    # byte no longer matches (suffix must be exactly at the end): a real file that
    # merely resembles ".cinfo" stays visible. Confirms no over-hiding.
    for b in range(0x80, 0x100):
        vecs.append(_name(f"nam-trail-{b:02x}", b"data.cinfo" + bytes([b])))

    # 21. internal-name gate — the upload-temp infix surrounded by non-UTF8 bytes
    # is still matched by strstr (byte-agnostic), so an in-flight upload with a
    # non-UTF8 name is hidden.
    for b in range(0x80, 0x100):
        vecs.append(_name(f"nam-infix-{b:02x}",
                          bytes([b]) + b".xrd-tmp." + bytes([b])))

    # 22. internal-name gate — structure, basename extraction, NUL truncation
    # (which can both hide AND reveal), near-misses, and non-UTF8 stems/infixes.
    curated_nam = [
        ("plain", b"file.txt", 0),
        ("cinfo", b"a.cinfo", 1),
        ("xrdcinfo", b"a.xrdcinfo", 1),
        ("meta", b"a.meta", 1),
        ("xrdt", b"a.xrdt", 1),
        ("commit", b"a.commit", 1),
        ("tmp-infix", b"a.xrd-tmp.4321.beef", 1),
        ("resume-infix", b"a.xrdresume.deadbeef.part", 1),
        ("path-hidden", b"/export/dir/a.cinfo", 1),
        ("path-visible-basename", b"/export/.cinfo/realfile", 0),  # basename "realfile"
        ("trailing-slash-empty", b"a.cinfo/", 0),                  # basename ""
        ("empty", b"", 0),
        ("just-slash", b"/", 0),
        ("dotfile-cinfo", b".cinfo", 1),
        ("suffix-not-at-end", b"a.cinfo.bak", 0),                  # ends ".bak"
        ("high-stem-cinfo", b"\xff\xfe.cinfo", 1),
        ("nul-truncate-hides", b"a.cinfo\x00.txt", 1),             # -> "a.cinfo"
        ("nul-truncate-reveals", b"a.txt\x00.cinfo", 0),           # -> "a.txt"
        ("high-around-infix", b"x\x80.xrd-tmp.\x81y", 1),
        ("near-miss-tmp-nodot", b"a.xrd-tmp", 0),                  # no trailing dot
        ("high-inside-infix-nomatch", b"a.xrd\xfftmp.x", 0),       # infix broken by high byte
        ("cr-in-stem", b"a\r.cinfo", 1),                           # byte-agnostic stem
        ("control-run-stem", bytes(range(0x01, 0x0b)) + b".meta", 1),
    ]
    for vid, data, _exp in curated_nam:
        v = _name(f"nam-{vid}", data)
        assert v.expect == _exp, f"{vid}: oracle {v.expect} != tabled {_exp}"
        vecs.append(v)

    return vecs


VECTORS: list[Vec] = build_vectors()


# --- harness build + run ----------------------------------------------------
_HARNESS_SRC = REPO_ROOT / "tests" / "c" / "nonutf8_codec_harness.c"
_KERNELS = [
    REPO_ROOT / "src" / "core" / "compat" / "uri.c",
    REPO_ROOT / "src" / "core" / "compat" / "hex.c",
    REPO_ROOT / "src" / "protocols" / "root" / "path" / "opaque_validate.c",
]

_cached_bin: Path | None = None


def build_harness(workdir: Path) -> Path:
    """Compile the harness against the real kernels once; cache the binary."""
    global _cached_bin
    if _cached_bin is not None and _cached_bin.exists():
        return _cached_bin
    import os

    binary = workdir / "nonutf8_codec_harness"
    argv = [
        os.environ.get("CC", "cc"),
        "-O", "-Wall", "-Wextra", "-Werror",
        "-I", str(REPO_ROOT / "src"),
        "-o", str(binary),
        str(_HARNESS_SRC),
        *[str(k) for k in _KERNELS],
    ]
    proc = run(argv, cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise RuntimeError(
            f"nonutf8 harness compile failed:\n{proc.stderr or proc.stdout}"
        )
    _cached_bin = binary
    return binary


def _parse(kind: str, out_line: str) -> tuple:
    parts = out_line.split()
    if not parts or parts[0] == "ERR":
        raise AssertionError(f"harness error line: {out_line!r}")
    if kind == "name":
        return int(parts[0])
    if kind == "opaque":
        return (int(parts[0]), int(parts[1]))
    rc = int(parts[0])
    hexout = parts[2] if len(parts) > 2 else "."
    data = b"" if hexout == "." else bytes.fromhex(hexout)
    # cross-check the length field the harness reports against the bytes it sent
    assert int(parts[1]) == len(data), f"len mismatch in {out_line!r}"
    return (rc, data)


def run_all(workdir: Path) -> dict[str, tuple]:
    """Run every vector through the harness in one pass; return {vid: actual}."""
    binary = build_harness(workdir)
    stdin = "\n".join(v.line for v in VECTORS) + "\n"
    proc = subprocess.run(
        [str(binary)], input=stdin, capture_output=True, text=True,
        cwd=REPO_ROOT, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"harness exited {proc.returncode}: {proc.stderr}")
    lines = [ln for ln in proc.stdout.splitlines() if ln != ""]
    if len(lines) != len(VECTORS):
        raise RuntimeError(
            f"harness produced {len(lines)} lines for {len(VECTORS)} vectors"
        )
    return {v.vid: _parse(v.kind, ln) for v, ln in zip(VECTORS, lines)}
