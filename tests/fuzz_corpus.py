"""tests/fuzz_corpus.py — deterministic malformed-packet corpora.

One source of truth for the protocol-conformance fuzz suites
(``test_fuzz_http_conformance.py`` and ``test_fuzz_binary_conformance.py``).

Every generator is a *pure* function evaluated at import time so the full case
set is enumerable by ``pytest --collect-only`` with no server running; the
suites then replay each case against the live fleet and assert the robust
liveness invariant (the server never crashes and never emits a malformed
framing) rather than any fragile per-case status.

Design mirrors the byte-exhaustive sweeps already proven in
``test_cms_hostile_conformance.py`` (full 0..255 modifier sweeps): most volume
comes from stepping a single wire field across its whole byte range while the
rest of the frame stays well-formed, which is where off-by-one length and
sign-extension parser bugs actually live.

Determinism: no ``random`` — a fixed LCG (``_lcg``) supplies the "binary
garbage" blobs so the collected node ids are stable across runs and xdist
workers.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# Deterministic pseudo-random bytes (stable ids; no random module)
# ---------------------------------------------------------------------------


def _lcg(seed: int, n: int) -> bytes:
    out = bytearray()
    x = seed & 0xFFFFFFFF
    for _ in range(n):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


# ===========================================================================
# HTTP-family corpus (nginx http core + WebDAV/S3 request handling)
# ===========================================================================

_HOST = b"Host: localhost\r\n"  # net-literal-allow: fuzz-payload Host header, not a dial target
CANON_GET = b"GET /fuzz_probe HTTP/1.1\r\n" + _HOST + b"\r\n"
CANON_PUT = (
    b"PUT /fuzz_probe.txt HTTP/1.1\r\n" + _HOST
    + b"Content-Length: 5\r\n\r\nhello"
)


def _http_method_sweep():
    """A byte in the method token — spaces/CR/LF here re-frame the request."""
    out = []
    for b in range(256):
        m = b"X" + bytes([b]) + b"Y"
        out.append((f"method-byte-{b:02x}", m + b" / HTTP/1.1\r\n" + _HOST + b"\r\n"))
    return out


def _http_version_sweep():
    out = []
    variants = [
        b"HTTP/1.1", b"HTTP/1.0", b"HTTP/0.9", b"HTTP/9.9", b"HTTP/1.",
        b"HTTP/", b"HTTP/1.11", b"HTTP/999999999.999999999", b"http/1.1",
        b"HTTP\\1.1", b"HTTP/1.1x", b"HTTP/-1.0", b"HTTP/ 1.1", b"HTTP/01.1",
        b"", b"HTTP/1.1 ", b"RTSP/1.0", b"HTTP/2.0", b"HTTP/1.1\t",
    ]
    for i, v in enumerate(variants):
        out.append((f"version-var-{i:02d}", b"GET / " + v + b"\r\n" + _HOST + b"\r\n"))
    for b in range(256):  # sweep the minor-version digit position
        out.append((f"version-digit-{b:02x}",
                    b"GET / HTTP/1." + bytes([b]) + b"\r\n" + _HOST + b"\r\n"))
    return out


def _http_request_line_struct():
    cases = [
        (b"\r\n", "empty-crlf"),
        (b"\n", "bare-lf"),
        (b" \r\n", "space-only"),
        (b"GET\r\n", "method-only"),
        (b"GET \r\n", "method-space"),
        (b"GET  /  HTTP/1.1\r\n" + _HOST + b"\r\n", "double-space"),
        (b"GET\t/\tHTTP/1.1\r\n" + _HOST + b"\r\n", "tab-delim"),
        (b" GET / HTTP/1.1\r\n" + _HOST + b"\r\n", "leading-space"),
        (b"GET / HTTP/1.1\rHost: x\r\n\r\n", "cr-no-lf"),
        (b"GET / HTTP/1.1\nHost: x\n\n", "lf-no-cr"),
        (b"GET / HTTP/1.1\r\n\r\n", "no-host"),
        (b"GET /\x00 HTTP/1.1\r\n" + _HOST + b"\r\n", "null-in-path"),
        (b"GET / HTTP/1.1 extra\r\n" + _HOST + b"\r\n", "trailing-token"),
        (b"\x00\x00\x00\x00\r\n", "null-request-line"),
        (b"GET / HTTP/1.1" + b" " * 8000 + b"\r\n\r\n", "trailing-spaces"),
    ]
    return [(f"reqline-{name}", raw) for raw, name in cases]


def _http_path_sweep():
    out = []
    for b in range(256):
        out.append((f"path-byte-{b:02x}",
                    b"GET /" + bytes([b]) + b"a HTTP/1.1\r\n" + _HOST + b"\r\n"))
    for b in range(256):  # percent-encoded octet
        out.append((f"path-pct-{b:02x}",
                    b"GET /%%%02X HTTP/1.1\r\n" % b + _HOST + b"\r\n"))
    curated = [
        (b"*", "asterisk"), (b"//", "double-slash"), (b"/%00", "pct-null"),
        (b"/%", "pct-truncated"), (b"/%zz", "pct-nonhex"), (b"/../../etc", "dotdot"),
        (b"/%2e%2e/%2e%2e/", "pct-dotdot"), (b"/." + b"/." * 4000, "deep-dot"),
        (b"/a" * 8000, "long-path"), (b"/?" + b"q" * 16000, "long-query"),
        (b"/#frag", "fragment"), (b"http://evil/x", "absolute-uri"),
        (b"/\\..\\..\\", "backslash"), (b"/%ff%fe", "pct-highbytes"),
    ]
    for raw, name in curated:
        out.append((f"path-{name}", b"GET " + raw + b" HTTP/1.1\r\n" + _HOST + b"\r\n"))
    return out


def _http_header_name_sweep():
    out = []
    for b in range(256):
        out.append((f"hname-byte-{b:02x}",
                    CANON_GET[:-2] + bytes([b]) + b"Name: v\r\n\r\n"))
    curated = [
        (b"NoColon value\r\n", "no-colon"),
        (b"Spaced Name: v\r\n", "space-in-name"),
        (b" LeadSpace: v\r\n", "leading-space-fold"),
        (b"\tTabFold: v\r\n", "tab-fold"),
        (b": emptyname\r\n", "empty-name"),
        (b"X" * 65000 + b": v\r\n", "huge-name"),
        (b"Name\x00: v\r\n", "null-in-name"),
        (b"Name : v\r\n", "space-before-colon"),
    ]
    for raw, name in curated:
        out.append((f"hname-{name}", CANON_GET[:-2] + raw + b"\r\n"))
    return out


def _http_header_value_sweep():
    out = []
    for b in range(256):
        out.append((f"hval-byte-{b:02x}",
                    CANON_GET[:-2] + b"X-Fuzz: " + bytes([b]) + b"\r\n\r\n"))
    curated = [
        (b"X-Fuzz: " + b"v" * 65000 + b"\r\n", "huge-value"),
        (b"X-Fuzz: a\r\n b\r\n", "obs-fold"),
        (b"X-Fuzz: a\r\n\tb\r\n", "obs-fold-tab"),
        (b"X-Fuzz:\r\n", "empty-value"),
        (b"X-Fuzz: v\x00\r\n", "embedded-null"),
        (b"X-Fuzz: v\rInjected: 1\r\n", "cr-injection"),
        (b"X-Fuzz: v\nInjected: 1\r\n", "lf-injection"),
    ]
    for raw, name in curated:
        out.append((f"hval-{name}", CANON_GET[:-2] + raw + b"\r\n"))
    return out


def _http_content_length():
    vals = [
        b"", b"-1", b"+5", b"0x10", b"5 5", b"99999999999999999999",
        b"4294967296", b"18446744073709551616", b"1e3", b" 5", b"5\t",
        b"5;", b"5 ", b"0", b"00005", b"5.0", b"nan", b"0b101", b"\x00",
    ]
    out = []
    for i, v in enumerate(vals):
        req = (b"PUT /fuzz HTTP/1.1\r\n" + _HOST + b"Content-Length: " + v
               + b"\r\n\r\nhello")
        out.append((f"clen-val-{i:02d}", req))
    conflicts = [
        (b"Content-Length: 5\r\nContent-Length: 6\r\n", "dup-conflict"),
        (b"Content-Length: 5\r\nContent-Length: 5\r\n", "dup-same"),
        (b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n", "cl-te-smuggle"),
    ]
    for raw, name in conflicts:
        out.append((f"clen-{name}",
                    b"PUT /fuzz HTTP/1.1\r\n" + _HOST + raw + b"\r\n0\r\n\r\n"))
    return out


def _http_transfer_encoding():
    tes = [
        b"chunked", b"Chunked", b"CHUNKED", b"chunked, chunked",
        b"gzip, chunked", b"identity", b"x", b"chunked ; ext",
        b" chunked", b"chunked\t", b"chunked, gzip", b"deflate",
    ]
    out = []
    for i, te in enumerate(tes):
        req = (b"POST /fuzz HTTP/1.1\r\n" + _HOST + b"Transfer-Encoding: " + te
               + b"\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        out.append((f"te-val-{i:02d}", req))
    return out


def _http_chunked_body():
    out = []
    for b in range(256):  # first byte of the chunk-size token
        req = (b"POST /fuzz HTTP/1.1\r\n" + _HOST
               + b"Transfer-Encoding: chunked\r\n\r\n"
               + bytes([b]) + b"\r\nAB\r\n0\r\n\r\n")
        out.append((f"chunk-sizebyte-{b:02x}", req))
    curated = [
        (b"-5\r\nAB\r\n", "neg-size"),
        (b"FFFFFFFFFFFFFFFF\r\n", "huge-size"),
        (b"7FFFFFFF\r\n", "int-max-size"),
        (b"0x5\r\nhello\r\n", "hex-prefix"),
        (b"5;ext=1\r\nhello\r\n0\r\n\r\n", "chunk-ext"),
        (b"5 \r\nhello\r\n0\r\n\r\n", "trailing-space-size"),
        (b"5\r\nAB\r\n", "short-chunk"),
        (b"5\r\nhello", "missing-terminator"),
        (b"G\r\n", "nonhex-size"),
        (b"\r\n", "empty-size"),
        (b"5\nhello\n0\n\n", "lf-only"),
    ]
    for raw, name in curated:
        out.append((f"chunk-{name}",
                    b"POST /fuzz HTTP/1.1\r\n" + _HOST
                    + b"Transfer-Encoding: chunked\r\n\r\n" + raw))
    return out


def _http_oversize():
    return [
        ("oversize-reqline", b"GET /" + b"a" * 65000 + b" HTTP/1.1\r\n\r\n"),
        ("oversize-header", b"GET / HTTP/1.1\r\n" + _HOST
         + b"X-Big: " + b"z" * 65000 + b"\r\n\r\n"),
        ("oversize-manyheaders", b"GET / HTTP/1.1\r\n" + _HOST
         + b"H: v\r\n" * 2000 + b"\r\n"),
        ("oversize-host", b"GET / HTTP/1.1\r\nHost: " + b"h" * 65000 + b"\r\n\r\n"),
    ]


def _http_truncation():
    out = []
    n = len(CANON_PUT)
    for off in range(1, n, 3):
        out.append((f"trunc-put-{off:03d}", CANON_PUT[:off]))
    return out


def _http_garbage():
    out = []
    for seed in (1, 7, 13, 99, 12345):
        for length in (1, 2, 4, 8, 16, 64, 256, 1024):
            out.append((f"garbage-{seed}-{length}", _lcg(seed, length)))
    return out


def http_generic_cases():
    """Full generic HTTP-family corpus (runs against every HTTP endpoint)."""
    cases = []
    for gen in (
        _http_method_sweep, _http_version_sweep, _http_request_line_struct,
        _http_path_sweep, _http_header_name_sweep, _http_header_value_sweep,
        _http_content_length, _http_transfer_encoding, _http_chunked_body,
        _http_oversize, _http_truncation, _http_garbage,
    ):
        cases.extend(gen())
    return cases


# --- S3-specific: SigV4 Authorization / x-amz header parsing ---------------


def s3_cases():
    out = []
    base = b"GET /bucket/key HTTP/1.1\r\n" + _HOST
    auths = [
        b"AWS4-HMAC-SHA256",
        b"AWS4-HMAC-SHA256 ",
        b"AWS4-HMAC-SHA256 Credential=",
        b"AWS4-HMAC-SHA256 Credential=/////",
        b"AWS4-HMAC-SHA256 Credential=k/20260101/us/s3/aws4_request",
        b"AWS4-HMAC-SHA256 Credential=k/20260101/us/s3/aws4_request, "
        b"SignedHeaders=host, Signature=",
        b"AWS4-HMAC-SHA256 Credential=k/x/x/x/x, SignedHeaders=, Signature=zz",
        b"AWS4-HMAC-SHA256 Credential=k/////////, SignedHeaders=host;x, "
        b"Signature=" + b"f" * 64,
        b"AWS4-HMAC-SHA256 Credential=k/20260101/us/s3/aws4_request,"
        b"SignedHeaders=host,Signature=g",
        b"AWS " + b"k" * 4000 + b":sig",
        b"AWS4-HMAC-SHA256 " + b"," * 5000,
        b"Bearer tokentokentoken",
        b"",
        b"AWS4-HMAC-SHA256 Credential=k/20260101/us/s3/aws4_request, "
        b"SignedHeaders=host, Signature=" + b"\x00" * 8,
    ]
    for i, a in enumerate(auths):
        out.append((f"s3-auth-{i:02d}",
                    base + b"Authorization: " + a + b"\r\n\r\n"))
    amz = [
        b"x-amz-date: 20260101T000000Z", b"x-amz-date: not-a-date",
        b"x-amz-content-sha256: " + b"f" * 64,
        b"x-amz-content-sha256: UNSIGNED-PAYLOAD",
        b"x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        b"x-amz-decoded-content-length: -1",
        b"x-amz-decoded-content-length: 99999999999999999999",
        b"x-amz-copy-source: /../../etc/passwd",
        b"x-amz-meta-\x00: v",
    ]
    for i, h in enumerate(amz):
        out.append((f"s3-amz-{i:02d}", base + h + b"\r\n\r\n"))
    queries = [
        b"/bucket/key?X-Amz-Signature=", b"/bucket/key?X-Amz-Expires=-1",
        b"/bucket/key?X-Amz-Expires=99999999999999999999",
        b"/bucket/key?uploadId=" + b"a" * 8000,
        b"/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=",
        b"/?list-type=2&continuation-token=%00%00",
    ]
    for i, q in enumerate(queries):
        out.append((f"s3-query-{i:02d}",
                    b"GET " + q + b" HTTP/1.1\r\n" + _HOST + b"\r\n"))
    return out


# --- WebDAV-specific: verbs, Destination/Depth/If, XML property bodies ------


def webdav_cases():
    out = []
    verbs = [
        b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE", b"LOCK",
        b"UNLOCK", b"OPTIONS", b"REPORT", b"ACL", b"propfind", b"PROPFIN",
        b"PROPFINDX", b"\x00PROPFIND",
    ]
    for i, v in enumerate(verbs):
        out.append((f"dav-verb-{i:02d}",
                    v + b" /fuzz HTTP/1.1\r\n" + _HOST + b"Depth: 0\r\n\r\n"))
    headers = [
        b"Depth: 0", b"Depth: 1", b"Depth: infinity", b"Depth: 2",
        b"Depth: -1", b"Depth: " + b"9" * 400, b"Depth: infinit",
        b"Destination: ", b"Destination: http://evil/../x",
        b"Destination: " + b"h" * 65000,
        b"Destination: /%00", b"Overwrite: X", b"Overwrite: ",
        b"If: (<locktoken>)", b"If: " + b"(" * 5000,
        b"Timeout: Second--1", b"Timeout: Infinite,Second-99999999999",
        b"Lock-Token: <>", b"Lock-Token: " + b"<" * 4000,
    ]
    for i, h in enumerate(headers):
        out.append((f"dav-hdr-{i:02d}",
                    b"PROPFIND /fuzz HTTP/1.1\r\n" + _HOST + h + b"\r\n\r\n"))
    bodies = [
        b"<?xml version='1.0'?><propfind/>",
        b"<?xml version='1.0'?><propfind xmlns:D='DAV:'><D:allprop/></propfind>",
        b"<?xml", b"<a>" * 20000, b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>",
        b"<propfind>" + b"\x00" * 100 + b"</propfind>",
        b"<propfind>" + b"\xff\xfe" * 500 + b"</propfind>",
        b"not xml at all", b"<propfind><prop>" + b"<x/>" * 20000 + b"</prop></propfind>",
    ]
    for i, body in enumerate(bodies):
        req = (b"PROPFIND /fuzz HTTP/1.1\r\n" + _HOST + b"Depth: 0\r\n"
               + b"Content-Length: %d\r\n\r\n" % len(body) + body)
        out.append((f"dav-xml-{i:02d}", req))
    return out


# ===========================================================================
# XRootD binary corpus (root:// stream parser) — frames sent post-handshake
# ===========================================================================

_KNOWN_OPCODES = list(range(3000, 3032))  # kXR_auth .. kXR_writev


def _frame(streamid: bytes, opcode: int, body16: bytes, dlen: int, payload=b""):
    return struct.pack("!2sH16sI", streamid, opcode, body16.ljust(16, b"\x00")[:16],
                       dlen) + payload


def _xrd_opcode_sweep():
    out = []
    for op in range(2990, 3051):  # dense around the valid band
        out.append((f"opcode-{op}", _frame(b"\x00\x01", op & 0xFFFF, b"", 0)))
    for op in range(0, 65536, 128):  # sparse full-u16 sweep
        out.append((f"opcode-wide-{op:05d}", _frame(b"\x00\x01", op, b"", 0)))
    return out


def _xrd_dlen_sweep():
    vals = [
        0, 1, 2, 4, 8, 255, 256, 4096, 4224, 4225, 65535, 65536,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x00020000, 0x0001FFFF,
    ]
    out = []
    for op, name in ((3017, "stat"), (3013, "read"), (3019, "write"), (3010, "open")):
        for v in vals:
            out.append((f"dlen-{name}-{v:08x}", _frame(b"\x00\x01", op, b"", v)))
    return out


def _xrd_handshake_variants():
    """Raw 20-byte handshake permutations (sent INSTEAD of the canonical one)."""
    out = []
    for b in range(256):  # first byte must be 0 for a valid handshake
        hs = bytes([b]) + b"\x00" * 15 + struct.pack("!II", 4, 2012)
        out.append((f"handshake-byte0-{b:02x}", ("raw", hs)))
    for n in range(0, 20):  # truncated handshakes
        out.append((f"handshake-trunc-{n:02d}",
                    ("raw", (b"\x00" * 12 + struct.pack("!II", 4, 2012))[:n])))
    return out


def _xrd_truncated_frame():
    out = []
    full = _frame(b"\x00\x01", 3017, b"", 8, b"/x\x00\x00\x00\x00\x00\x00")
    for n in range(0, 8):
        out.append((f"trunc-header-{n}", full[:n]))
    return out


def _xrd_dlen_payload_mismatch():
    out = []
    payload = b"/tmp/x\x00"
    for declared in (0, 1, len(payload) - 1, len(payload) + 1, len(payload) + 64,
                     0xFFFF, 0x7FFFFFFF):
        out.append((f"mismatch-stat-{declared:08x}",
                    _frame(b"\x00\x01", 3017, b"", declared, payload)))
    return out


def _xrd_streamid_sweep():
    out = []
    for b in range(256):
        sid = bytes([b, (b ^ 0xFF) & 0xFF])
        out.append((f"streamid-{b:02x}", _frame(sid, 3011, b"", 0)))  # ping
    return out


def _xrd_open_options_sweep():
    out = []
    path = b"/fuzz\x00"
    for opt in range(0, 65536, 512):
        body = struct.pack("!HH2s6s4s", 0o644, opt, b"\x00\x00", b"\x00" * 6, b"\x00" * 4)
        out.append((f"open-opt-{opt:05d}",
                    _frame(b"\x00\x02", 3010, body[:16], len(path), path)))
    return out


def _xrd_read_extents():
    out = []
    fh = b"\x00\x00\x00\x00"
    extremes = [
        (0, 0), (-1, 0), (0, -1), (0x7FFFFFFFFFFFFFFF, 0), (-1, -1),
        (0, 0x7FFFFFFF), (-0x8000000000000000, 1024),
    ]
    for i, (off, ln) in enumerate(extremes):
        # signed pack: q accepts the negative/extreme offsets, i the length
        body = struct.pack("!4sqi", fh, off, ln)
        out.append((f"read-extent-{i:02d}", _frame(b"\x00\x03", 3013, body[:16], 0)))
    return out


def xrootd_cases():
    """Each item: (label, spec) where spec is either raw frame bytes (sent
    after the canonical handshake) or ``("raw", bytes)`` to send verbatim in
    place of the handshake."""
    cases = []
    for gen in (
        _xrd_opcode_sweep, _xrd_dlen_sweep, _xrd_handshake_variants,
        _xrd_truncated_frame, _xrd_dlen_payload_mismatch, _xrd_streamid_sweep,
        _xrd_open_options_sweep, _xrd_read_extents,
    ):
        cases.extend(gen())
    return cases


# ===========================================================================
# TLS-record junk (roots:// / any TLS listener) — pre-handshake liveness
# ===========================================================================


def tls_junk_cases():
    out = []
    for b in range(256):  # first byte of a bogus TLS record (0x16 == handshake)
        out.append((f"tls-rectype-{b:02x}",
                    bytes([b]) + b"\x03\x01\x00\x10" + _lcg(b + 1, 16)))
    curated = [
        (b"\x16\x03\x01\xff\xff", "hs-huge-len"),
        (b"\x16\x03\x01\x00\x00", "hs-zero-len"),
        (b"\x16\xff\xff\x00\x04\x01\x00\x00\x00", "bad-version"),
        (b"\x16\x03\x01\x00\x04\x01\xff\xff\xff", "clienthello-huge"),
        (b"GET / HTTP/1.1\r\n\r\n", "cleartext-http-at-tls"),
        (b"\x00" * 64, "all-zero"),
        (b"\xff" * 64, "all-ones"),
        (b"\x16\x03\x03" + b"\x00\x05" + b"\x01\x00\x00\x01\xff", "trunc-hs"),
    ]
    for raw, name in curated:
        out.append((f"tls-{name}", raw))
    return out
