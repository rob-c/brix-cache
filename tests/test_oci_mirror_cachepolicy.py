# tests/test_oci_mirror_cachepolicy.py — what the pull-through mirror keeps,
# for how long, and what it refuses to keep (phase-104 D2.7).
#
# The subject is the CACHE POLICY, not the grammar: every test here asks what
# the second request cost, what the client was told about the age of what it
# got, and — the part that matters most — which bytes were allowed to become
# cache-visible at all. A mirror that serves an image nobody verified is a
# supply-chain hole with a fast hit rate.
#
# Ports: oci_mirror block, mock at 14104, nginx front at 14112.
#
# The nginx front is a per-test lifecycle instance rather than a fleet member:
# each test needs its own cache store for "cold" to mean cold, and TTL legs
# need their own freshness window.
import hashlib
import json
import time
from pathlib import Path

import pytest

from oci.mirror_lane import (
    Mirror, cache_files, ctl_post, err_code, error_log, get, hits,
    manifest_layers, reset, spawn_mock, start_mirror, stop_mocks,
)

MOCK_PORT = 14104
NGINX_PORT = 14112

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-mirror-cachepolicy"),
]

#: Short enough that a test can outlive a freshness window without sleeping
#: its way into the 30 s pytest timeout, long enough that the "still fresh"
#: leg is not a race against the request it is making.
TTL_S = 3

MT_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MT_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
MT_DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"


@pytest.fixture(scope="module")
def upstream():
    proc, base = spawn_mock(MOCK_PORT)
    yield base
    stop_mocks(proc)


@pytest.fixture
def mirror(lifecycle, upstream, tmp_path):
    reset(upstream)
    return start_mirror(lifecycle, "lc-oci-cachepolicy", NGINX_PORT, MOCK_PORT,
                        tmp_path / "cache")


@pytest.fixture
def ttl_mirror(lifecycle, upstream, tmp_path):
    """The same front with a freshness window a test can outlive."""
    reset(upstream)
    return start_mirror(lifecycle, "lc-oci-cachepolicy-ttl", NGINX_PORT,
                        MOCK_PORT, tmp_path / "cache-ttl",
                        manifest_ttl="%ds" % TTL_S)


def digest_of(body, alg="sha256"):
    h = hashlib.sha512(body) if alg == "sha512" else hashlib.sha256(body)
    return "%s:%s" % (alg, h.hexdigest())


def data_hits(upstream_base):
    """Upstream requests on the DATA plane (the control plane is ours)."""
    return [h for h in hits(upstream_base) if h["path"].startswith("/v2/")]


def fetched(upstream_base):
    """The paths whose BYTES were pulled upstream.

    A tier fill probes the origin with HEAD before it GETs (the size the
    admission policy is deciding about), so counting every /v2/ request would
    count one fill twice. What a cache-policy assertion means by "it refetched
    the tag" is the GET.
    """
    return [h["path"] for h in data_hits(upstream_base) if h["method"] == "GET"]


def sidecar(mirror: Mirror, must_contain):
    """The one .ocimeta record whose body key contains `must_contain`."""
    for rel in cache_files(mirror.cache):
        if rel.endswith(".ocimeta") and must_contain in rel:
            return Path(mirror.cache, rel).read_text()
    raise AssertionError("no .ocimeta for %r in %s"
                         % (must_contain, cache_files(mirror.cache)))


# ---- success: what a warm mirror costs ----------------------------------- #

def test_cold_then_warm_pull_zero_upstream_data_hits(mirror: Mirror, upstream):
    """The whole point of the surface: the second pull does not leave the box."""
    status, _, cold = get(mirror.base + "/v2/lab/app/manifests/v1")
    assert status == 200
    layer = manifest_layers(cold)[0]["digest"]
    assert get("%s/v2/lab/app/blobs/%s" % (mirror.base, layer))[0] == 200

    reset(upstream)

    status, _, warm = get(mirror.base + "/v2/lab/app/manifests/v1")
    assert status == 200
    assert warm == cold
    status, _, blob = get("%s/v2/lab/app/blobs/%s" % (mirror.base, layer))
    assert status == 200
    assert digest_of(blob) == layer

    assert data_hits(upstream) == []


def test_sha512_image_cold_then_warm_and_verified_at_the_edge(mirror: Mirror,
                                                             upstream):
    """The second registered algorithm is not a parse case — it is a store key.

    Every digest in `lab/sha512app` is sha512, so this pull only succeeds if
    the classifier, the cache key, the store layout AND the verify-at-edge all
    read the algorithm out of the digest instead of assuming one — a fill that
    hashed these bytes with sha256 would evict them and serve nothing.

    The by-digest manifest leg is the load-bearing half: it is the one fetch
    whose key names the hash its bytes must have, so `verified=1` in its record
    is a claim only a sha512-aware verify can honestly make.
    """
    status, _, manifest = get(mirror.base + "/v2/lab/sha512app/manifests/v1")
    assert status == 200
    layer = manifest_layers(manifest)[0]["digest"]
    assert layer.startswith("sha512:")

    mdig = digest_of(manifest, "sha512")
    status, _, bydigest = get("%s/v2/lab/sha512app/manifests/%s"
                              % (mirror.base, mdig))
    assert status == 200
    assert bydigest == manifest
    assert "verified=1" in sidecar(mirror, mdig.split(":", 1)[1])

    status, _, blob = get("%s/v2/lab/sha512app/blobs/%s"
                          % (mirror.base, layer))
    assert status == 200
    assert digest_of(blob, "sha512") == layer

    reset(upstream)

    status, _, warm = get("%s/v2/lab/sha512app/blobs/%s"
                          % (mirror.base, layer))
    assert status == 200
    assert warm == blob
    assert data_hits(upstream) == []


@pytest.mark.parametrize("repo,ref,media_type", [
    ("lab/app", "v1", MT_OCI_MANIFEST),
    ("lab/multi", "latest", MT_OCI_INDEX),
    ("lab/dockerapp", "v1", MT_DOCKER_MANIFEST),
    ("lab/dockermulti", "latest", MT_DOCKER_LIST),
])
def test_media_type_roundtrip_all_four_manifest_kinds(mirror: Mirror, repo,
                                                      ref, media_type):
    """§0.7.3: an index and a manifest list are different objects.

    Podman branches on this header; getting it wrong sends the client down the
    wrong unpack path with bytes that are otherwise perfectly valid.
    """
    url = "%s/v2/%s/manifests/%s" % (mirror.base, repo, ref)

    status, headers, body = get(url)                       # cold: derived
    assert status == 200
    assert headers["Content-Type"] == media_type
    assert headers["Docker-Content-Digest"] == digest_of(body)

    status, headers, warm = get(url)                       # warm: memoized
    assert status == 200
    assert warm == body
    assert headers["Content-Type"] == media_type
    assert headers["Docker-Content-Digest"] == digest_of(body)


def test_if_none_match_304_local(mirror: Mirror, upstream):
    """A client holding the manifest gets 304 — and pays no upstream request."""
    status, headers, body = get(mirror.base + "/v2/lab/app/manifests/v1")
    assert status == 200
    etag = headers["ETag"]
    # The validator IS the digest: a mirror that answered with mtime+size
    # would invalidate every client's copy each time it refilled the same
    # bytes (App. B.1).
    assert etag.strip('"') == digest_of(body)

    reset(upstream)

    status, headers, empty = get(mirror.base + "/v2/lab/app/manifests/v1",
                                 headers={"If-None-Match": etag})

    assert status == 304
    assert empty == b""
    assert headers["Docker-Content-Digest"] == digest_of(body)
    assert data_hits(upstream) == []


def test_tag_fresh_serves_old_after_retag_until_ttl(ttl_mirror: Mirror,
                                                    upstream):
    """A tag is mutable, so it is cached for exactly as long as it was told."""
    _, _, moved_to = get("%s/v2/lab/app/manifests/v2" % ttl_mirror.base)
    new_digest = digest_of(moved_to)

    status, _, before = get("%s/v2/lab/app/manifests/v1" % ttl_mirror.base)
    assert status == 200
    old_digest = digest_of(before)
    assert old_digest != new_digest

    ctl_post(upstream, "retag", {"name": "lab/app", "tag": "v1",
                                 "digest": new_digest})
    reset(upstream)

    # Inside the window the mirror answers from what it holds — deliberately
    # the OLD image. That is the contract `brix_oci_manifest_ttl` states.
    status, headers, fresh = get("%s/v2/lab/app/manifests/v1"
                                 % ttl_mirror.base)
    assert status == 200
    assert headers["Docker-Content-Digest"] == old_digest
    assert data_hits(upstream) == []

    time.sleep(TTL_S + 1)

    status, headers, _ = get("%s/v2/lab/app/manifests/v1" % ttl_mirror.base,
                             method="HEAD")
    assert status == 200
    assert headers["Docker-Content-Digest"] == new_digest
    assert fetched(upstream) == ["/v2/lab/app/manifests/v1"]


def test_stale_revalidate_digest_equal_transfers_no_body(ttl_mirror: Mirror,
                                                         upstream):
    """Past the TTL, an unchanged tag costs an upstream fetch — not a body."""
    status, headers, body = get("%s/v2/lab/app/manifests/v1"
                                % ttl_mirror.base)
    assert status == 200
    etag = headers["ETag"]

    reset(upstream)
    time.sleep(TTL_S + 1)

    status, headers, empty = get("%s/v2/lab/app/manifests/v1"
                                 % ttl_mirror.base,
                                 headers={"If-None-Match": etag})

    assert status == 304
    assert empty == b""
    assert headers["Docker-Content-Digest"] == digest_of(body)
    # The revalidation DID happen — the mirror refetched the tag and found the
    # same object. What it did not do is send the client bytes it already had.
    assert fetched(upstream) == ["/v2/lab/app/manifests/v1"]


# ---- error: what a broken upstream costs --------------------------------- #

def test_upstream_down_fresh_serves__stale_marks__cold_retry_later(
        ttl_mirror: Mirror, upstream):
    """Three legs of one policy: an unreachable registry is not an outage."""
    assert get("%s/v2/lab/app/manifests/v1" % ttl_mirror.base)[0] == 200
    ctl_post(upstream, "fault", {"kind": "http500", "persist": True})

    # Leg 1 — inside the window nothing is even attempted upstream.
    status, headers, _ = get("%s/v2/lab/app/manifests/v1" % ttl_mirror.base)
    assert status == 200
    assert "Warning" not in headers

    # Leg 2 — past it, the copy is served anyway and SAYS it is stale, so a CI
    # pipeline can tell "the mirror is degraded" from "the tag still points
    # here" (RFC 9111 §5.5.1).
    time.sleep(TTL_S + 1)
    status, headers, _ = get("%s/v2/lab/app/manifests/v1" % ttl_mirror.base)
    assert status == 200
    assert headers.get("Warning", "").startswith("110 ")

    # Leg 3 — an object never held has nothing to fall back to. The answer is
    # the fill tier's never-drop one: a KEEP-ALIVE 504 carrying our own
    # Retry-After, not a 502 envelope (DRIFT vs J.4, which pins 502 for an
    # upstream 5xx). A transient origin failure is deliberately NOT routed
    # through the OCI failure interceptor — http_cache_fill.h states it, and
    # the reason is that "the origin is unwell right now" is the one verdict a
    # client should retry rather than treat as an answer about the image. The
    # definitive failures (404, an unanswerable challenge, corrupt bytes) do
    # get the registry envelope, which the other two lanes assert.
    status, headers, _ = get("%s/v2/lab/multi/manifests/latest"
                             % ttl_mirror.base)
    assert status == 504
    assert headers["Retry-After"] == "2"


# ---- security-negative --------------------------------------------------- #

def test_corrupt_fill_refused_guarded_then_recovers(mirror: Mirror, upstream):
    """Bytes that do not hash to their own key never become cache-visible."""
    _, _, manifest = get(mirror.base + "/v2/lab/app/manifests/v1")
    layer = manifest_layers(manifest)[0]["digest"]

    # Persistent: one fill is a HEAD and then a GET, and a one-shot fault
    # would be spent on the probe and never reach the bytes.
    ctl_post(upstream, "fault", {"kind": "corrupt", "path_re": "/blobs/",
                                 "persist": True})

    status, _, body = get("%s/v2/lab/app/blobs/%s" % (mirror.base, layer))

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert not any(layer.split(":")[1] in rel for rel in cache_files(mirror.cache))
    assert "signal=oci_tamper" in error_log(mirror.endpoint)

    # The refusal is about the bytes, not about the object: once the upstream
    # stops lying, the same pull succeeds.
    ctl_post(upstream, "fault", {"kind": "none"})
    status, _, good = get("%s/v2/lab/app/blobs/%s" % (mirror.base, layer))
    assert status == 200
    assert digest_of(good) == layer


def test_corrupt_sha512_fill_refused_not_hashed_with_the_wrong_function(
        mirror: Mirror, upstream):
    """A sha512 blob must be checked WITH sha512, in both directions.

    Two opposite bugs both fail this test. Verifying sha512 bytes with sha256
    rejects every honest fill, so the clean leg at the end would 502; skipping
    the verify because the algorithm was unrecognized serves the corrupted
    bytes, so the first leg would 200. Only hashing under the digest's own
    algorithm passes both.
    """
    _, _, manifest = get(mirror.base + "/v2/lab/sha512app/manifests/v1")
    layer = manifest_layers(manifest)[0]["digest"]
    assert layer.startswith("sha512:")

    ctl_post(upstream, "fault", {"kind": "corrupt", "path_re": "/blobs/",
                                 "persist": True})

    status, _, body = get("%s/v2/lab/sha512app/blobs/%s"
                          % (mirror.base, layer))

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert not any(layer.split(":")[1] in rel
                   for rel in cache_files(mirror.cache))
    assert "signal=oci_tamper" in error_log(mirror.endpoint)

    ctl_post(upstream, "fault", {"kind": "none"})
    status, _, good = get("%s/v2/lab/sha512app/blobs/%s"
                          % (mirror.base, layer))
    assert status == 200
    assert digest_of(good, "sha512") == layer


def test_wrong_digest_header_marks_unverified_sidecar(mirror: Mirror,
                                                      upstream):
    """The upstream's word about its own bytes is not a verification."""
    ctl_post(upstream, "fault", {"kind": "wrong_digest_header",
                                 "path_re": "/manifests/", "persist": True})

    status, headers, body = get(mirror.base + "/v2/lab/app/manifests/v1")

    assert status == 200
    # What we advertise is what we hashed, never what we were told.
    assert headers["Docker-Content-Digest"] == digest_of(body)
    assert "0" * 64 not in headers["Docker-Content-Digest"]
    assert "verified=0" in sidecar(mirror, "manifests")

    # And the digest the upstream invented names nothing: it was never allowed
    # to become a cache-visible object under that name.
    status, _, refused = get("%s/v2/lab/app/manifests/sha256:%s"
                             % (mirror.base, "0" * 64))
    assert status in (404, 502)
    assert err_code(refused) in ("MANIFEST_UNKNOWN", "UNAVAILABLE")
