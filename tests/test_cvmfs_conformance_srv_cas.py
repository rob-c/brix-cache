# tests/test_cvmfs_conformance_srv_cas.py — Phase-84 srv_cas conformance corpus.
#
# CAS-object serve correctness through the brix_cvmfs site cache: verify-on-fill
# (corrupt / truncated / wrong-length fills are never served as a corrupt 200;
# mismatches are quarantined and refetched), cache-hit byte identity with exactly
# one origin fetch, hash-length {40,64,96,128} and suffix variants through the
# verify path, compressed stored bytes served verbatim (the cache is a byte
# proxy — the CLIENT decompresses), and the negative-404 memo (absorption count,
# per-object isolation, negative_ttl expiry, object-appears-later servability).
#
# Port block: srv_cas = 13140 (mocks 13140-13149, nginx 13150-13159).
import hashlib
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import zlib
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import HOST

REPO = "test.cern.ch"
NEG_TTL = 2                       # seconds; keep expiry tests fast

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

# One shared allocator for this file's 20-port block (mocks +0.., nginx +10..).
BLOCK = PortBlock("srv_cas")


# ---- fixtures --------------------------------------------------------------

@pytest.fixture(scope="module")
def srv():
    """Synthetic-object instance: verify-on-fill + cache-hit + negative tests."""
    qdir = Path(tempfile.mkdtemp(prefix="cvmfs_cas_quarantine."))
    with srv_instance(BLOCK, objects=48, seed=84, negative_ttl=NEG_TTL,
                      client_hold=2, quarantine_dir=qdir) as s:
        s.qdir = qdir
        s._alloc = iter(s.objects())
        yield s
    shutil.rmtree(qdir, ignore_errors=True)


@pytest.fixture(scope="module")
def web():
    """Webroot instance: full control of stored bytes (hash-length/suffix/
    compressed corpora, object-appears-later negative tests)."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_cas_webroot."))
    (root / "cvmfs" / REPO / "data").mkdir(parents=True)
    qdir = Path(tempfile.mkdtemp(prefix="cvmfs_cas_webq."))
    with srv_instance(BLOCK, webroot=root, negative_ttl=NEG_TTL,
                      client_hold=2, quarantine_dir=qdir) as s:
        s.webroot = root
        s.qdir = qdir
        yield s
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(qdir, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path, method="GET"):
    return request(HOST, s.nginx_port, method, path)


def take(s):
    """A distinct, never-before-used synthetic object path (test isolation)."""
    return next(s._alloc)


def origin_bytes(s, path):
    """Reference bytes straight from the mock (fetch BEFORE arming faults)."""
    return urllib.request.urlopen(s.mock_url + path).read()


def arm(s, mode, count, path):
    s.set_fault(mode, count, path_re=re.escape(path))


def clear_fault(s):
    s.set_fault("none", 0)


def put_obj(w, body, suffix="", hexname=None):
    """Drop a CAS object into the webroot; returns its URL path. When hexname
    is None the object is named by sha1(stored bytes) — the verifiable case."""
    hx = hexname or hashlib.sha1(body).hexdigest()
    d = w.webroot / "cvmfs" / REPO / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / (hx[2:] + suffix)).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}{suffix}"


def count_heads(s, path):
    """Origin consultations for a MISSING object are HEAD size-probes (the fill
    probes before its data GET, and a 404 is definitive there) — /ctl/log only
    counts data GETs, so 404-absorption is measured on /ctl/heads."""
    return sum(1 for e in s.get_heads() if path in e["path"])


def missing_path(tag):
    """A valid-shape 40-hex CAS path guaranteed absent from both origins."""
    h = hashlib.sha1(f"srv_cas-missing:{tag}".encode()).hexdigest()
    return f"/cvmfs/{REPO}/data/{h[:2]}/{h[2:]}"


def body_for(tag, n=6000):
    """Deterministic per-test content (distinct objects per test)."""
    seed = hashlib.sha256(f"srv_cas:{tag}".encode()).digest()
    return (seed * (n // len(seed) + 1))[:n]


# ============================================================================
# 1. verify-on-fill: corrupt fills are never served, quarantined, refetched
# ============================================================================

@pytest.mark.parametrize("i", range(6))
def test_corrupt_fill_one_shot_served_clean(srv, i):
    # One corrupt origin transfer: the verifier discards it and the SAME
    # request refetches clean — the client never sees the corrupt bytes.
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    srv.reset_log()
    arm(srv, "corrupt", 1, obj)
    status, _, body = GET(srv, obj)
    assert status == 200
    assert body == clean, "corrupt fill leaked to the client"
    assert srv.count_log(obj) == 2, "expected corrupt attempt + clean refetch"


def test_corrupt_fill_quarantine_file_appears(srv):
    obj = take(srv)
    origin_bytes(srv, obj)
    before = set(os.listdir(srv.qdir))
    arm(srv, "corrupt", 1, obj)
    status, _, _ = GET(srv, obj)
    assert status == 200
    fresh = set(os.listdir(srv.qdir)) - before
    assert fresh, "mismatched fill was not quarantined into brix_cvmfs_quarantine_dir"


def test_corrupt_fill_quarantined_bytes_are_the_bad_bytes(srv):
    # Evidence integrity: the quarantined part is the corrupt transfer, i.e. it
    # does NOT hash to the object's CAS name.
    obj = take(srv)
    origin_bytes(srv, obj)
    before = set(os.listdir(srv.qdir))
    arm(srv, "corrupt", 1, obj)
    GET(srv, obj)
    fresh = set(os.listdir(srv.qdir)) - before
    assert len(fresh) == 1
    cas_hex = obj.rsplit("/", 2)[-2] + obj.rsplit("/", 1)[-1].rstrip("CHXMLP")
    quarantined = (srv.qdir / fresh.pop()).read_bytes()
    assert hashlib.sha1(quarantined).hexdigest() != cas_hex


def test_corrupt_recovery_next_get_is_cache_hit(srv):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    srv.reset_log()
    arm(srv, "corrupt", 1, obj)
    assert GET(srv, obj)[0] == 200
    n_fills = srv.count_log(obj)
    status, _, body = GET(srv, obj)
    assert status == 200 and body == clean
    assert srv.count_log(obj) == n_fills, "post-recovery GET went to origin again"


def test_persistent_corrupt_clean_error_never_corrupt_200(srv):
    # Every attempt corrupt: the mismatch retry budget (one per endpoint)
    # exhausts and the client gets a clean gateway error — never bad bytes.
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    try:
        arm(srv, "corrupt", 99, obj)
        status, _, body = GET(srv, obj)
        assert status >= 500, f"persistent corrupt fill answered {status}"
        assert body != clean and hashlib.sha1(body).hexdigest() not in obj
    finally:
        clear_fault(srv)
    # and the object recovers once the origin is healthy again
    status, _, body = GET(srv, obj)
    assert status == 200 and body == clean


def test_persistent_corrupt_quarantines_each_attempt(srv):
    obj = take(srv)
    origin_bytes(srv, obj)
    before = set(os.listdir(srv.qdir))
    try:
        arm(srv, "corrupt", 99, obj)
        assert GET(srv, obj)[0] >= 500
    finally:
        clear_fault(srv)
    fresh = set(os.listdir(srv.qdir)) - before
    assert len(fresh) >= 2, "each mismatched attempt should leave evidence"


def test_corrupt_targeted_leaves_other_object_clean(srv):
    # path_re-targeted fault on A must not perturb B's fill.
    obj_a, obj_b = take(srv), take(srv)
    clean_b = origin_bytes(srv, obj_b)
    srv.reset_log()
    arm(srv, "corrupt", 1, obj_a)
    status, _, body = GET(srv, obj_b)
    assert status == 200 and body == clean_b
    assert srv.count_log(obj_b) == 1
    clear_fault(srv)                      # fault for A was never consumed


# ---- truncated / wrong-length fills ----------------------------------------

@pytest.mark.parametrize("i", range(2))
def test_truncated_fill_one_shot_recovers_full_object(srv, i):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    arm(srv, "truncate", 1, obj)
    status, _, body = GET(srv, obj)
    assert status == 200
    assert body == clean, "truncated fill surfaced as a short/corrupt 200"


def test_persistent_truncate_clean_error_never_truncated_200(srv):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    try:
        arm(srv, "truncate", 99, obj)
        status, _, body = GET(srv, obj)
        if status == 200:
            assert body == clean, "truncated 200 served"
        else:
            assert status >= 500
    finally:
        clear_fault(srv)


@pytest.mark.parametrize("i", range(2))
def test_wrong_length_fill_one_shot_recovers_clean(srv, i):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    arm(srv, "wrong_length", 1, obj)
    status, _, body = GET(srv, obj)
    assert status == 200
    assert body == clean


def test_persistent_wrong_length_clean_error_never_corrupt_200(srv):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    try:
        arm(srv, "wrong_length", 99, obj)
        status, _, body = GET(srv, obj)
        if status == 200:
            assert body == clean
        else:
            assert status >= 500
    finally:
        clear_fault(srv)


@pytest.mark.parametrize("n", [1, 2])
def test_http500_fill_retried_to_clean_200(srv, n):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    arm(srv, "http500", n, obj)
    status, _, body = GET(srv, obj)
    assert status == 200 and body == clean


# ============================================================================
# 2. cache-hit correctness: byte identity, exactly one origin data fetch
# ============================================================================

@pytest.mark.parametrize("i", range(5))
def test_second_get_byte_identical_single_fetch(srv, i):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    srv.reset_log()
    first = GET(srv, obj)
    second = GET(srv, obj)
    assert first[0] == 200 and second[0] == 200
    assert first[2] == clean and second[2] == first[2]
    assert srv.count_log(obj) == 1, "cache hit still contacted the origin"


def test_ten_gets_single_origin_fetch(srv):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    srv.reset_log()
    for _ in range(10):
        status, _, body = GET(srv, obj)
        assert status == 200 and body == clean
    assert srv.count_log(obj) == 1


def test_head_after_get_no_extra_origin_traffic(srv):
    obj = take(srv)
    origin_bytes(srv, obj)
    assert GET(srv, obj)[0] == 200                     # filled + cached
    srv.reset_log()
    heads_before = len(srv.get_heads())
    status, headers, _ = GET(srv, obj, method="HEAD")
    assert status == 200
    assert srv.count_log(obj) == 0
    assert len(srv.get_heads()) == heads_before, "HEAD on a cached object probed origin"


def test_hit_survives_origin_mutation(web):
    # Once filled and verified, the cache is authoritative for the immutable
    # CAS object: mutating the origin's stored bytes must not change the serve.
    body = body_for("hit-mutate")
    path = put_obj(web, body)
    web.reset_log()
    assert GET(web, path)[2] == body
    disk = web.webroot / "cvmfs" / REPO / "data" / path.split("/")[-2] / path.split("/")[-1]
    disk.write_bytes(b"EVIL" + body)                   # origin goes bad afterwards
    status, _, got = GET(web, path)
    assert status == 200 and got == body
    assert web.count_log(path) == 1


def test_hit_served_while_origin_erroring(srv):
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    assert GET(srv, obj)[0] == 200                     # cached
    try:
        arm(srv, "http500", 99, obj)
        status, _, body = GET(srv, obj)
        assert status == 200 and body == clean, "cache hit depended on origin health"
    finally:
        clear_fault(srv)


# ============================================================================
# 3. hash-length {40,64,96,128} + suffix variants through the verify path
# ============================================================================

@pytest.mark.parametrize("suffix", ["", "C", "H", "X", "M", "L", "P"])
def test_sha1_named_object_each_suffix_served(web, suffix):
    body = body_for(f"sfx-{suffix or 'plain'}")
    path = put_obj(web, body, suffix=suffix)
    web.reset_log()
    status, _, got = GET(web, path)
    assert status == 200 and got == body
    assert web.count_log(path) == 1
    # verified fill is a cache hit afterwards
    assert GET(web, path)[2] == body
    assert web.count_log(path) == 1


@pytest.mark.parametrize("suffix", ["", "C", "H", "L"])
def test_misnamed_40hex_object_never_served(web, suffix):
    # Stored bytes do NOT hash to the CAS name: every fill fails verification,
    # is quarantined, and the client gets a clean error — official clients
    # would reject these bytes; a verifying cache must never publish them.
    body = body_for(f"misnamed-{suffix or 'plain'}")
    wrong = hashlib.sha1(f"not-the-content-{suffix}".encode()).hexdigest()
    path = put_obj(web, body, suffix=suffix, hexname=wrong)
    before = set(os.listdir(web.qdir))
    status, _, got = GET(web, path)
    assert status >= 500, f"misnamed CAS object served with {status}"
    assert got != body
    assert set(os.listdir(web.qdir)) - before, "no quarantine evidence for misnamed object"


@pytest.mark.parametrize("algo,hexlen", [("sha256", 64), ("sha384", 96), ("sha512", 128)])
def test_long_hash_names_served_verbatim(web, algo, hexlen):
    # Only the 40-hex sha1 convention is locally verifiable (verify.c); longer
    # hash names pass through UNVERIFIED and the cache behaves as the official
    # byte proxy: stored bytes served exactly, end-client verifies.
    body = body_for(f"long-{hexlen}")
    name = getattr(hashlib, algo)(body).hexdigest()
    assert len(name) == hexlen
    path = put_obj(web, body, hexname=name)
    web.reset_log()
    status, _, got = GET(web, path)
    assert status == 200 and got == body
    assert GET(web, path)[2] == body                    # hit, byte-identical
    assert web.count_log(path) == 1


@pytest.mark.parametrize("hexlen,suffix", [(64, "C"), (96, "H"), (128, "L")])
def test_long_hash_with_suffix_served_verbatim(web, hexlen, suffix):
    body = body_for(f"longsfx-{hexlen}{suffix}")
    name = hashlib.sha512(body).hexdigest()[:hexlen]
    path = put_obj(web, body, suffix=suffix, hexname=name)
    status, _, got = GET(web, path)
    assert status == 200 and got == body


def test_unverifiable_64hex_arbitrary_name_is_byte_proxied(web):
    # A 64-hex name unrelated to any digest of the bytes: unverifiable, so the
    # cache serves the stored bytes verbatim (matches official proxy behavior —
    # integrity is the CLIENT's job for non-sha1 conventions).
    body = body_for("arbitrary-64")
    path = put_obj(web, body, hexname="ab" * 32)
    status, _, got = GET(web, path)
    assert status == 200 and got == body


# ============================================================================
# 4. compressed stored bytes are served verbatim (cache is a byte proxy)
# ============================================================================

@pytest.mark.parametrize("level", [0, 1, 6, 9])
def test_compressed_object_served_verbatim(web, level):
    payload = body_for(f"zlib-{level}", n=50000)
    blob = zlib.compress(payload, level)
    path = put_obj(web, blob)                # CAS name = sha1(compressed bytes)
    web.reset_log()
    status, _, got = GET(web, path)
    assert status == 200
    assert got == blob, "cache did not serve the stored (compressed) bytes verbatim"
    assert zlib.decompress(got) == payload   # the CLIENT decompresses
    assert web.count_log(path) == 1


def test_compressed_object_cache_hit_verbatim(web):
    payload = body_for("zlib-hit", n=120000)
    blob = zlib.compress(payload, 6)
    path = put_obj(web, blob)
    web.reset_log()
    first = GET(web, path)[2]
    second = GET(web, path)[2]
    assert first == blob and second == blob
    assert web.count_log(path) == 1


# ============================================================================
# 5. negative-404 memo (T13): absorption, isolation, expiry, appear-later
# ============================================================================

def test_first_404_reaches_origin(srv):
    p = missing_path("first-404")
    srv.reset_log()
    status, _, _ = GET(srv, p)
    assert status == 404
    assert count_heads(srv, p) == 1


def test_absorbed_repeat_returns_404_without_origin(srv):
    p = missing_path("absorb-basic")
    srv.reset_log()
    assert GET(srv, p)[0] == 404
    assert GET(srv, p)[0] == 404
    assert count_heads(srv, p) == 1, "memoized 404 still went to origin"


@pytest.mark.parametrize("n", [10, 25, 50])
def test_404_storm_absorbed_to_single_origin_roundtrip(srv, n):
    p = missing_path(f"storm-{n}")
    srv.reset_log()
    statuses = {GET(srv, p)[0] for _ in range(n)}
    assert statuses == {404}
    assert count_heads(srv, p) == 1, f"{n}-request 404 storm not absorbed to one probe"


def test_negative_memo_per_object_isolation(srv):
    # Memoized 404 of A must not pre-404 a different missing object B.
    a, b = missing_path("iso-a"), missing_path("iso-b")
    srv.reset_log()
    assert GET(srv, a)[0] == 404
    assert GET(srv, a)[0] == 404          # A absorbed
    assert GET(srv, b)[0] == 404          # B's FIRST 404 must consult origin
    assert count_heads(srv, a) == 1
    assert count_heads(srv, b) == 1


def test_negative_memo_does_not_404_existing_object(srv):
    p = missing_path("iso-existing")
    obj = take(srv)
    clean = origin_bytes(srv, obj)
    assert GET(srv, p)[0] == 404          # memoize the miss
    status, _, body = GET(srv, obj)
    assert status == 200 and body == clean, "404 memo bled onto an existing object"


def test_negative_ttl_expiry_reconsults_origin(srv):
    p = missing_path("ttl-expiry")
    srv.reset_log()
    assert GET(srv, p)[0] == 404
    assert GET(srv, p)[0] == 404          # inside TTL: absorbed
    assert count_heads(srv, p) == 1
    time.sleep(NEG_TTL + 2)   # +2: ngx_time() is event-loop cached, 1s granular
    assert GET(srv, p)[0] == 404          # after TTL: origin consulted again
    assert count_heads(srv, p) == 2


def test_absorbed_404_has_no_origin_traffic_at_all(srv):
    # Neither a data GET nor a HEAD probe may leave the cache on a memo hit.
    p = missing_path("no-traffic")
    assert GET(srv, p)[0] == 404
    srv.reset_log()
    heads_before = len(srv.get_heads())
    assert GET(srv, p)[0] == 404
    assert GET(srv, p, method="HEAD")[0] == 404
    assert srv.count_log(p) == 0
    assert len(srv.get_heads()) == heads_before


def test_distinct_missing_uris_each_absorbed_independently(srv):
    paths = [missing_path(f"slots-{i}") for i in range(8)]
    srv.reset_log()
    for p in paths:                        # first pass: 8 origin 404s
        assert GET(srv, p)[0] == 404
    for p in paths:                        # second pass: all absorbed
        assert GET(srv, p)[0] == 404
    for p in paths:
        assert count_heads(srv, p) == 1


def test_object_appearing_within_ttl_still_absorbed(web):
    # The memo answers for the full negative_ttl even once the origin HAS the
    # object — bounded staleness is the contract that makes absorption safe.
    body = body_for("appear-early")
    hx = hashlib.sha1(body).hexdigest()
    path = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
    web.reset_log()
    assert GET(web, path)[0] == 404       # miss memoized at origin
    put_obj(web, body)                    # object appears immediately
    assert GET(web, path)[0] == 404, "memo bypassed inside negative_ttl"
    assert count_heads(web, path) == 1
    assert web.count_log(path) == 0       # no data GET ever left the cache


def test_object_appearing_after_ttl_expiry_becomes_servable(web):
    body = body_for("appear-late")
    hx = hashlib.sha1(body).hexdigest()
    path = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
    web.reset_log()
    assert GET(web, path)[0] == 404
    put_obj(web, body)
    time.sleep(NEG_TTL + 2)   # +2: ngx_time() is event-loop cached, 1s granular
    status, _, got = GET(web, path)
    assert status == 200 and got == body, "published object still 404 after memo expiry"
    assert GET(web, path)[2] == body      # and it caches normally
    assert web.count_log(path) == 1       # exactly one data fill
    assert count_heads(web, path) == 2    # the 404 probe + the fill's size probe
