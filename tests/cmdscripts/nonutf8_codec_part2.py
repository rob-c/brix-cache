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
def build_vectors() -> list[Vec]:
    """Build every independent codec, schema, and internal-name vector."""
    vectors: list[Vec] = []
    for builder in _VECTOR_BUILDERS:
        vectors.extend(builder())
    return vectors


def _vectors_01_02() -> list[Vec]:
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

    return vecs


def _vectors_03_04() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_05_07() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_08_09() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_10_11() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_12_13() -> list[Vec]:
    vecs: list[Vec] = []
    # 12. opaque gate: exhaustive 0x01-0xFF verdict + offending byte.
    for b in range(0x01, 0x100):
        vecs.append(_opaque(f"opq-byte-{b:02x}", bytes([b])))

    # 13. opaque gate: empty, permitted strings, injection primitives, structure.
    curated_opq = [
        ("empty", b""),
        ("all-permitted", b"oss.asize=123&tpc.key=v,w;x?y=z"),
        ("ipv6-brackets", b"tpc.src=[::ffff:127.0.0.1]:1094"),  # net-literal-allow: opaque-parser input under test
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

    return vecs


def _vectors_14_15() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_16_17() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_18_19() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_20_21() -> list[Vec]:
    vecs: list[Vec] = []
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

    return vecs


def _vectors_22_22() -> list[Vec]:
    vecs: list[Vec] = []
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
        ("path-hidden-dir", b"/export/.cinfo/realfile", 1),        # reserved dir hides the subtree
        ("trailing-slash-dir", b"a.cinfo/", 1),                    # reserved dir, empty basename
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


_VECTOR_BUILDERS = (
    _vectors_01_02,
    _vectors_03_04,
    _vectors_05_07,
    _vectors_08_09,
    _vectors_10_11,
    _vectors_12_13,
    _vectors_14_15,
    _vectors_16_17,
    _vectors_18_19,
    _vectors_20_21,
    _vectors_22_22,
)


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
    parser = {"name": _parse_name, "opaque": _parse_opaque}.get(kind, _parse_codec)
    return parser(parts, out_line)


def _parse_name(parts: list[str], _out_line: str) -> int:
    return int(parts[0])


def _parse_opaque(parts: list[str], _out_line: str) -> tuple[int, int]:
    return int(parts[0]), int(parts[1])


def _parse_codec(parts: list[str], out_line: str) -> tuple[int, bytes]:
    rc = int(parts[0])
    hexout = parts[2] if len(parts) > 2 else "."
    data = b"" if hexout == "." else bytes.fromhex(hexout)
    assert int(parts[1]) == len(data), f"len mismatch in {out_line!r}"
    return rc, data


def run_all(workdir: Path) -> dict[str, tuple]:
    """Run every vector through the harness in one pass; return {vid: actual}."""
    binary = build_harness(workdir)
    stdin = "\n".join(v.line for v in VECTORS) + "\n"
    proc = _run_harness(binary, stdin)
    lines = _validated_output_lines(proc.stdout)
    return {v.vid: _parse(v.kind, line) for v, line in zip(VECTORS, lines)}


def _run_harness(binary: Path, stdin: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [str(binary)], input=stdin, capture_output=True, text=True,
        cwd=REPO_ROOT, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"harness exited {proc.returncode}: {proc.stderr}")
    return proc


def _validated_output_lines(stdout: str) -> list[str]:
    lines = [line for line in stdout.splitlines() if line]
    if len(lines) != len(VECTORS):
        raise RuntimeError(
            f"harness produced {len(lines)} lines for {len(VECTORS)} vectors"
        )
    return lines
