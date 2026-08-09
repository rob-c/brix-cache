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
from settings import HOST
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

def _last_modified(srv, path):
    st, hdrs, _ = GET(srv, path)
    assert st == 200 and "last-modified" in hdrs
    return hdrs["last-modified"]



@pytest.fixture(scope="module")
def manifest(srv):
    path = f"/cvmfs/{REPO}/.cvmfspublished"
    st, _, body = GET(srv, path)
    assert st == 200 and body.startswith(b"C")
    return path, body            # TTL=300s → byte-stable for the whole module
