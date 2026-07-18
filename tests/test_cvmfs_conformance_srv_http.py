"""Phase-84 CVMFS conformance — srv_http: HTTP protocol semantics of the CAS serve.

Theme
-----
Protocol-poke a warmed cached CAS object (fill once, then every request is a
cache HIT through cvmfs_tier_open_respond -> brix_http_serve_file_ranged) and
spot-check the first-request fill path.  Corpus per RFC 9110 §14 (Range /
Content-Range / 416), §13.1.3 (If-Modified-Since / 304), §8.8.3 (ETag) and §9.3.2
(HEAD parity).  Official reference: a CVMFS Stratum-1 is Apache httpd serving
plain files — Apache honours multi-clause ranges with multipart/byteranges,
*ignores* syntactically invalid Range headers (200 full body), and stamps
`Content-Range: bytes */len` on 416s.

Engine under test: src/core/compat/range.c + range_vector.c (single-range,
max_ranges=1, suffix + open-ended allowed, end clamped to EOF) composed by
src/protocols/shared/file_serve.c; weak ETag = W/"mtime_hex-size_hex"
(src/core/http/etag.c); IMS via brix_http_check_if_modified_since (mtime <= ims
-> 304, run BEFORE range handling).

Genuine divergences from official/RFC behaviour are asserted RFC-side and pinned
with xfail + ``# DIVERGENCE:``.
"""

import os
import sys
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance

REPO = "test.cern.ch"
HOST = "127.0.0.1"
EPOCH = "Thu, 01 Jan 1970 00:00:01 GMT"
FUTURE = "Fri, 31 Dec 2100 23:59:59 GMT"

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")


# ---- module fixtures -------------------------------------------------------

@pytest.fixture(scope="module")
def srv():
    """One mock origin + one nginx for the whole module (port block srv_http:
    mock 13160, nginx 13170). manifest_ttl pinned high so the manifest body —
    which the mock regenerates with a fresh T timestamp per origin fetch — stays
    byte-stable in the site cache for every manifest test."""
    with srv_instance(PortBlock("srv_http"), objects=8, seed=84,
                      manifest_ttl=300) as s:
        yield s


class Corpus:
    """Deterministic object allocation: BIG (largest, warmed once in the fixture)
    is the shared protocol-poke target; two distinct-size objects for ETag
    comparison; the rest is a cold pool consumed one path per fill-path test."""

    def __init__(self, srv):
        paths = srv.objects()
        self.bodies = {p: urllib.request.urlopen(srv.mock_url + p).read()
                       for p in paths}
        by_size = sorted(paths, key=lambda p: len(self.bodies[p]), reverse=True)
        self.big = by_size[0]
        self.etag_pair = (by_size[1], by_size[2])
        assert len(self.bodies[by_size[1]]) != len(self.bodies[by_size[2]])
        self._cold = list(by_size[3:])

    def cold(self):
        return self._cold.pop()


@pytest.fixture(scope="module")
def corpus(srv):
    c = Corpus(srv)
    # Warm BIG + the ETag pair through nginx: byte-identical fill, then every
    # later request against them exercises the cached serve.
    for p in (c.big,) + c.etag_pair:
        st, _, body = GET(srv, p)
        assert st == 200 and body == c.bodies[p], f"warm fill of {p} broken"
    assert len(c.bodies[c.big]) > 8192          # range corpus needs headroom
    return c


@pytest.fixture(scope="module")
def big(corpus):
    """(path, reference bytes) of the warmed protocol-poke object."""
    return corpus.big, corpus.bodies[corpus.big]


# ---- local helpers ---------------------------------------------------------

def GET(srv, path, headers=None):
    return request(HOST, srv.nginx_port, "GET", path, headers)


def HEAD(srv, path, headers=None):
    return request(HOST, srv.nginx_port, "HEAD", path, headers)


def assert_206(ref, st, hdrs, body, start, end, *, head=False):
    """206 exactness: status, Content-Range, Content-Length, payload identity."""
    total = len(ref)
    assert st == 206
    assert hdrs.get("content-range") == f"bytes {start}-{end}/{total}"
    assert int(hdrs["content-length"]) == end - start + 1
    assert body == (b"" if head else ref[start:end + 1])


def assert_200_full(ref, st, hdrs, body, *, head=False):
    assert st == 200
    assert int(hdrs["content-length"]) == len(ref)
    assert body == (b"" if head else ref)


# ============================================================================
# Range corpus — satisfiable single ranges (RFC 9110 §14.1.2/§14.4) against the
# warmed cached object: 206 + exact Content-Range/Content-Length + payload
# byte-identity vs the full-body slice.
# ============================================================================

SINGLE_RANGES = [
    ("first_byte",       lambda L: ("bytes=0-0", 0, 0)),
    ("open_from_0",      lambda L: ("bytes=0-", 0, L - 1)),
    ("open_from_1",      lambda L: ("bytes=1-", 1, L - 1)),
    ("mid",              lambda L: ("bytes=100-199", 100, 199)),
    ("explicit_full",    lambda L: (f"bytes=0-{L - 1}", 0, L - 1)),
    ("penultimate_pair", lambda L: (f"bytes={L - 2}-{L - 1}", L - 2, L - 1)),
    ("exact_eof_byte",   lambda L: (f"bytes={L - 1}-{L - 1}", L - 1, L - 1)),
    ("open_at_last",     lambda L: (f"bytes={L - 1}-", L - 1, L - 1)),
    ("suffix_1",         lambda L: ("bytes=-1", L - 1, L - 1)),
    ("suffix_100",       lambda L: ("bytes=-100", L - 100, L - 1)),
    ("suffix_exact_len", lambda L: (f"bytes=-{L}", 0, L - 1)),
    ("suffix_overlong",  lambda L: (f"bytes=-{L + 5}", 0, L - 1)),   # clamp: whole file
    ("end_past_eof",     lambda L: (f"bytes=0-{L + 999}", 0, L - 1)),  # end clamped
    ("end_past_eof_mid", lambda L: (f"bytes={L - 10}-{2 * L}", L - 10, L - 1)),
    ("page_boundary",    lambda L: ("bytes=4095-4096", 4095, 4096)),
]


@pytest.mark.parametrize("spec", [s[1] for s in SINGLE_RANGES],
                         ids=[s[0] for s in SINGLE_RANGES])
def test_single_range(srv, big, spec):
    path, ref = big
    hdr, start, end = spec(len(ref))
    st, hdrs, body = GET(srv, path, {"Range": hdr})
    assert_206(ref, st, hdrs, body, start, end)


def test_range_payloads_are_slices_of_one_identity(srv, big):
    """Three disjoint ranges reassemble to exact slices of the same full body —
    the cached serve never mixes bytes across requests."""
    path, ref = big
    for start, end in ((0, 99), (1000, 1999), (len(ref) - 100, len(ref) - 1)):
        st, hdrs, body = GET(srv, path, {"Range": f"bytes={start}-{end}"})
        assert_206(ref, st, hdrs, body, start, end)


# ---- unsatisfiable → 416 (RFC 9110 §15.5.17) -------------------------------

UNSATISFIABLE = [
    ("start_eq_len_open",    lambda L: f"bytes={L}-"),
    ("start_eq_len_bounded", lambda L: f"bytes={L}-{L + 10}"),
    ("start_past_len",       lambda L: f"bytes={L + 1}-{L + 2}"),
    ("huge_start",           lambda L: "bytes=99999999999999-"),
    ("suffix_zero",          lambda L: "bytes=-0"),   # zero-length suffix: unsatisfiable
]


@pytest.mark.parametrize("spec", [s[1] for s in UNSATISFIABLE],
                         ids=[s[0] for s in UNSATISFIABLE])
def test_unsatisfiable_range_416(srv, big, spec):
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": spec(len(ref))})
    assert st == 416
    assert body == b""


def test_416_carries_content_range_star(srv, big):
    # RFC 9110 §15.5.17 — a 416 to a byte-range request SHOULD send
    # Content-Range: bytes */complete-length (Apache/official Stratum-1 does).
    # serve_range_unsatisfiable (src/protocols/shared/file_serve.c) now does
    # too; the bare-416 divergence was fixed 2026-07-18.
    path, ref = big
    st, hdrs, _ = GET(srv, path, {"Range": f"bytes={len(ref)}-"})
    assert st == 416
    assert hdrs.get("content-range") == f"bytes */{len(ref)}"


# ---- malformed Range headers -----------------------------------------------
# RFC 9110 §14.2: a server MAY ignore or reject an invalid ranges-specifier;
# official Stratum-1 (Apache) IGNORES and serves 200 full body.  brix ignores
# non-"bytes=" values but maps a "bytes="-prefixed value that fails the vector
# parser to 416 (range.c: parse failure -> present=1, satisfiable=0) — an
# interop divergence from Apache, pinned below.

MALFORMED_IGNORED = [                     # not "bytes=<spec>" at all → ignored, 200
    ("no_unit",        "0-499"),
    ("wrong_unit",     "octets=0-499"),
    ("bare_word",      "bytes"),
    ("space_before_eq", "bytes = 0-1"),
]

MALFORMED_REJECTED = [                    # "bytes="-prefixed garbage → brix 416s
    ("alpha_bounds",     "bytes=a-b"),
    ("reversed",         "bytes=5-2"),    # last-pos < first-pos: invalid per §14.1.2
    ("double_dash",      "bytes=--5"),
    ("triple_field",     "bytes=1-2-3"),
    ("spaces_in_spec",   "bytes=0 - 5"),
    ("no_digits",        "bytes=-"),
]


@pytest.mark.parametrize("hdr", [m[1] for m in MALFORMED_IGNORED],
                         ids=[m[0] for m in MALFORMED_IGNORED])
def test_malformed_range_ignored_200(srv, big, hdr):
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": hdr})
    assert_200_full(ref, st, hdrs, body)


@pytest.mark.parametrize("hdr", [m[1] for m in MALFORMED_REJECTED],
                         ids=[m[0] for m in MALFORMED_REJECTED])
@pytest.mark.xfail(strict=True,
                   reason="brix 416s malformed bytes= specs; Apache ignores (200)")
def test_malformed_bytes_spec_ignored_200(srv, big, hdr):
    # DIVERGENCE: official Stratum-1 (Apache) ignores a syntactically invalid
    # byte-ranges specifier and serves 200 full body; RFC 9110 §14.2 says MAY
    # ignore or reject, so 416 is RFC-tolerable but diverges from official
    # interop behaviour (clients sending sloppy ranges get errors, not bytes).
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": hdr})
    assert_200_full(ref, st, hdrs, body)


def test_empty_bytes_spec(srv, big):
    """'bytes=' with nothing after it: brix's own parser ignores it (header
    shorter than 7 chars), falls through as a plain 200 full-body serve —
    matching Apache. (nginx's core range filter never re-processes: brix serves
    the body itself.)"""
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": "bytes="})
    assert_200_full(ref, st, hdrs, body)


def test_range_unit_case_insensitive(srv, big):
    """RFC 9110 §14.1 range units are case-insensitive. brix's own parser
    (range.c memcmp "bytes=") is exact-case and passes 'Bytes=0-1' through as a
    200 — but nginx's core range header filter (case-insensitive match, active
    because the handler sets r->allow_ranges) then slices that 200 into a
    correct 206. Two-layer engine, conformant end result."""
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": "Bytes=0-1"})
    assert_206(ref, st, hdrs, body, 0, 1)


def test_leading_space_in_spec_tolerated(srv, big):
    """'bytes= 0-4': the vector parser skips leading spaces per component, so
    this lenient-accept yields a normal 206 (harmless superset of the ABNF)."""
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": "bytes= 0-4"})
    assert_206(ref, st, hdrs, body, 0, 4)


# ---- multi-clause ranges ---------------------------------------------------
# Official Stratum-1 (Apache) answers multi-clause ranges with a 206
# multipart/byteranges body. brix is a single-range engine (max_ranges=1): it
# serves the FIRST clause as a plain single-range 206 and never reads the rest.
# RFC 9110 §14.2 permits single-part handling; assert the actual contract.

@pytest.mark.parametrize("hdr,start,end", [
    ("bytes=0-1,3-4", 0, 1),          # disjoint → first clause
    ("bytes=0-10,5-15", 0, 10),       # overlapping → first clause
    ("bytes=0-0,-1", 0, 0),           # explicit + suffix → first clause
    ("bytes=0-0,junk", 0, 0),         # later garbage never parsed (max_ranges=1)
], ids=["disjoint", "overlapping", "explicit_plus_suffix", "trailing_garbage"])
def test_multi_clause_serves_first_range_single_part(srv, big, hdr, start, end):
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": hdr})
    assert_206(ref, st, hdrs, body, start, end)
    assert "multipart" not in hdrs.get("content-type", "")


# ============================================================================
# Conditional requests — If-Modified-Since / 304 (RFC 9110 §13.1.3, §15.4.5)
# ============================================================================

def _last_modified(srv, path):
    st, hdrs, _ = GET(srv, path)
    assert st == 200 and "last-modified" in hdrs
    return hdrs["last-modified"]


def test_ims_equal_date_304(srv, big):
    path, ref = big
    lm = _last_modified(srv, path)
    st, hdrs, body = GET(srv, path, {"If-Modified-Since": lm})
    assert st == 304
    assert body == b""


def test_ims_future_date_304(srv, big):
    path, _ = big
    st, _, body = GET(srv, path, {"If-Modified-Since": FUTURE})
    assert st == 304 and body == b""


def test_ims_old_date_200_full(srv, big):
    path, ref = big
    st, hdrs, body = GET(srv, path, {"If-Modified-Since": EPOCH})
    assert_200_full(ref, st, hdrs, body)


def test_ims_malformed_date_200(srv, big):
    """Unparseable IMS date is ignored (RFC 9110 §13.1.3: invalid date → not
    evaluated) — full 200."""
    path, ref = big
    st, hdrs, body = GET(srv, path, {"If-Modified-Since": "yesterday-ish"})
    assert_200_full(ref, st, hdrs, body)


def test_ims_head_304(srv, big):
    path, _ = big
    st, _, body = HEAD(srv, path, {"If-Modified-Since": FUTURE})
    assert st == 304 and body == b""


def test_ims_precedes_range_304(srv, big):
    """Range + fresh IMS: the conditional is evaluated before range handling —
    304, no partial body (RFC 9110 §13.2.2 evaluation order)."""
    path, _ = big
    st, _, body = GET(srv, path, {"Range": "bytes=0-0",
                                  "If-Modified-Since": FUTURE})
    assert st == 304 and body == b""


def test_ims_stale_plus_range_206(srv, big):
    path, ref = big
    st, hdrs, body = GET(srv, path, {"Range": "bytes=0-0",
                                     "If-Modified-Since": EPOCH})
    assert_206(ref, st, hdrs, body, 0, 0)


def test_304_carries_etag(srv, big):
    # RFC 9110 §15.4.5 — a 304 MUST generate the ETag (and other validators)
    # that would have been sent in the 200. The cvmfs 304 path (handler.c
    # cvmfs_tier_open_respond) now does; the bare-304 divergence was fixed
    # 2026-07-18.
    path, _ = big
    st, hdrs, _ = GET(srv, path, {"If-Modified-Since": FUTURE})
    assert st == 304
    assert "etag" in hdrs


# ---- If-None-Match (served by nginx's not-modified filter, registered by
#      brix_http_set_file_headers) ------------------------------------------

def test_if_none_match_matching_304(srv, big):
    path, _ = big
    st, hdrs, _ = GET(srv, path)
    assert st == 200
    etag = hdrs["etag"]
    st, _, body = GET(srv, path, {"If-None-Match": etag})
    assert st == 304 and body == b""


def test_if_none_match_mismatch_200(srv, big):
    path, ref = big
    st, hdrs, body = GET(srv, path, {"If-None-Match": 'W/"deadbeef-1"'})
    assert_200_full(ref, st, hdrs, body)


# ============================================================================
# ETag semantics (weak W/"mtime-size", src/core/http/etag.c)
# ============================================================================

def test_etag_present_and_weak(srv, big):
    path, _ = big
    st, hdrs, _ = GET(srv, path)
    assert st == 200
    etag = hdrs.get("etag")
    assert etag is not None
    assert etag.startswith('W/"') and etag.endswith('"')


def test_etag_stable_across_cache_hits(srv, big):
    path, _ = big
    tags = [GET(srv, path)[1]["etag"] for _ in range(3)]
    assert len(set(tags)) == 1


def test_etag_same_on_200_and_206(srv, big):
    path, _ = big
    full = GET(srv, path)[1]["etag"]
    ranged = GET(srv, path, {"Range": "bytes=0-9"})[1]["etag"]
    assert full == ranged


def test_etag_differs_between_objects(srv, corpus):
    a, b = corpus.etag_pair            # warmed, guaranteed distinct sizes
    ta = GET(srv, a)[1]["etag"]
    tb = GET(srv, b)[1]["etag"]
    assert ta != tb


def test_etag_get_head_identical(srv, big):
    path, _ = big
    assert GET(srv, path)[1]["etag"] == HEAD(srv, path)[1]["etag"]


# ============================================================================
# HEAD parity (RFC 9110 §9.3.2: same status + headers as GET, no body)
# ============================================================================

def test_head_200_parity(srv, big):
    path, ref = big
    gst, ghdrs, _ = GET(srv, path)
    hst, hhdrs, hbody = HEAD(srv, path)
    assert (hst, hbody) == (200, b"") and gst == 200
    assert hhdrs["content-length"] == ghdrs["content-length"] == str(len(ref))
    assert hhdrs["etag"] == ghdrs["etag"]


def test_head_range_206_parity(srv, big):
    path, ref = big
    st, hdrs, body = HEAD(srv, path, {"Range": "bytes=10-19"})
    assert_206(ref, st, hdrs, body, 10, 19, head=True)


def test_head_suffix_range_matches_get_headers(srv, big):
    path, ref = big
    gst, ghdrs, _ = GET(srv, path, {"Range": "bytes=-7"})
    hst, hhdrs, hbody = HEAD(srv, path, {"Range": "bytes=-7"})
    assert hst == gst == 206 and hbody == b""
    for k in ("content-range", "content-length"):
        assert hhdrs[k] == ghdrs[k]


def test_head_416_parity(srv, big):
    path, ref = big
    st, _, body = HEAD(srv, path, {"Range": f"bytes={len(ref)}-"})
    assert st == 416 and body == b""


def test_head_malformed_range_200(srv, big):
    path, ref = big
    st, hdrs, body = HEAD(srv, path, {"Range": "octets=0-1"})
    assert st == 200 and body == b""
    assert int(hdrs["content-length"]) == len(ref)


def test_head_404_parity(srv):
    bogus = f"/cvmfs/{REPO}/data/aa/" + "ab" * 19
    gst, _, _ = GET(srv, bogus)
    hst, _, hbody = HEAD(srv, bogus)
    assert gst == 404 and hst == 404 and hbody == b""


def test_head_range_on_404_object(srv):
    """Range on a missing object: the 404 wins — no 206/416 confusion."""
    bogus = f"/cvmfs/{REPO}/data/bb/" + "cd" * 19
    st, _, _ = GET(srv, bogus, {"Range": "bytes=0-0"})
    assert st == 404


# ============================================================================
# First-request (fill-path) serves — the protocol semantics must hold on the
# very first request, when the bytes arrive via a coalesced origin fill.
# ============================================================================

def test_cold_ranged_get_fills_whole_object_once(srv, corpus):
    path = corpus.cold()
    ref = corpus.bodies[path]
    srv.reset_log()
    st, hdrs, body = GET(srv, path, {"Range": "bytes=3-9"})
    assert_206(ref, st, hdrs, body, 3, 9)
    # the fill fetched the WHOLE object exactly once; the follow-up full GET is
    # a pure cache hit, byte-identical to origin.
    st, hdrs, body = GET(srv, path)
    assert_200_full(ref, st, hdrs, body)
    assert srv.count_log(path) == 1


def test_cold_head_fills_and_reports_exact_length(srv, corpus):
    path = corpus.cold()
    ref = corpus.bodies[path]
    st, hdrs, body = HEAD(srv, path)
    assert st == 200 and body == b""
    assert int(hdrs["content-length"]) == len(ref)
    st, _, body = GET(srv, path)
    assert st == 200 and body == ref


def test_cold_suffix_range_fill(srv, corpus):
    path = corpus.cold()
    ref = corpus.bodies[path]
    st, hdrs, body = GET(srv, path, {"Range": "bytes=-16"})
    assert_206(ref, st, hdrs, body, len(ref) - 16, len(ref) - 1)


def test_cold_ims_future_after_fill_304(srv, corpus):
    """IMS is evaluated against the just-filled object's mtime — a fresh fill
    with a future IMS still 304s (mtime <= IMS date)."""
    path = corpus.cold()
    st, _, body = GET(srv, path, {"If-Modified-Since": FUTURE})
    assert st == 304 and body == b""


# ============================================================================
# Range / conditional semantics on the manifest (TTL-cached metadata path)
# ============================================================================

@pytest.fixture(scope="module")
def manifest(srv):
    path = f"/cvmfs/{REPO}/.cvmfspublished"
    st, _, body = GET(srv, path)
    assert st == 200 and body.startswith(b"C")
    return path, body            # TTL=300s → byte-stable for the whole module


def test_manifest_range_prefix(srv, manifest):
    path, ref = manifest
    st, hdrs, body = GET(srv, path, {"Range": "bytes=0-9"})
    assert_206(ref, st, hdrs, body, 0, 9)


def test_manifest_suffix_range(srv, manifest):
    path, ref = manifest
    st, hdrs, body = GET(srv, path, {"Range": "bytes=-5"})
    assert_206(ref, st, hdrs, body, len(ref) - 5, len(ref) - 1)


def test_manifest_unsatisfiable_416(srv, manifest):
    path, ref = manifest
    st, _, body = GET(srv, path, {"Range": f"bytes={len(ref)}-"})
    assert st == 416 and body == b""


def test_manifest_head_parity(srv, manifest):
    path, ref = manifest
    st, hdrs, body = HEAD(srv, path)
    assert st == 200 and body == b""
    assert int(hdrs["content-length"]) == len(ref)


def test_manifest_ims_future_304(srv, manifest):
    path, _ = manifest
    st, _, body = GET(srv, path, {"If-Modified-Since": FUTURE})
    assert st == 304 and body == b""


# ============================================================================
# Content-Length exactness + misc surface
# ============================================================================

def test_cached_200_content_length_and_identity(srv, big):
    path, ref = big
    st, hdrs, body = GET(srv, path)
    assert_200_full(ref, st, hdrs, body)


def test_accept_ranges_advertised(srv, big):
    """Apache/official Stratum-1 advertises `Accept-Ranges: bytes`; brix sets
    r->allow_ranges so nginx's range header filter stamps it on plain 200s."""
    path, _ = big
    st, hdrs, _ = GET(srv, path)
    assert st == 200
    assert hdrs.get("accept-ranges") == "bytes"


def test_range_header_on_http10(srv, big):
    """HTTP/1.0 request with a Range header still gets a correct 206 (ranges
    are defined for 1.0 clients too; Apache serves them)."""
    path, ref = big
    st, hdrs, body = request(HOST, srv.nginx_port, "GET", path,
                             {"Range": "bytes=0-3"}, version="HTTP/1.0")
    assert_206(ref, st, hdrs, body, 0, 3)
