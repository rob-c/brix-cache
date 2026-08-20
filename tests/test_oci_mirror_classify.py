# tests/test_oci_mirror_classify.py — the /v2/ classifier, method gate and
# route plumbing of the pull-through mirror (phase-104 D0.4).
#
# The subject is the GRAMMAR, not the cache: every test here asks what the
# mirror decided a URL *is* — which class, which upstream route, which refusal
# — and reads the mock's request log to prove what did (or did not) leave the
# box. Ports: oci_mirror block, mock at 14100, nginx front at 14110.
#
# The nginx front is a per-test lifecycle instance rather than a fleet member:
# the mirror needs its own cache store per test to keep "cold" meaning cold,
# and the surface is off by default everywhere else in the fleet.
import hashlib
import json

import pytest

from oci.mirror_lane import (
    Mirror, cache_files, err_code, error_log, get, hits, reset, spawn_mock,
    start_mirror, stop_mocks,
)

MOCK_PORT = 14100
NGINX_PORT = 14110

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-mirror-classify"),
]


@pytest.fixture(scope="module")
def upstream():
    proc, base = spawn_mock(MOCK_PORT)
    yield base
    stop_mocks(proc)


@pytest.fixture
def mirror(lifecycle, upstream, tmp_path):
    reset(upstream)
    return start_mirror(lifecycle, "lc-oci-classify", NGINX_PORT, MOCK_PORT,
                        tmp_path / "cache")


def test_api_root_answers_locally(mirror: Mirror, upstream):
    """`/v2/` is the version handshake: our answer, not a proxied one."""
    status, headers, body = get(mirror.base + "/v2/")

    assert status == 200
    assert json.loads(body) == {}
    assert headers["Docker-Distribution-API-Version"] == "registry/2.0"
    # The handshake must not cost an upstream round trip — podman performs it
    # before every single pull.
    assert hits(upstream) == []


@pytest.mark.parametrize("route", [
    "/v2/lab/app/manifests/v1",
    "/v2/lab/multi/manifests/latest",
    "/v2/lab/app/tags/list",
    "/v2/lab/app/referrers/sha256:" + "ab" * 32,
])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_matrix_get_head_every_class_routes(mirror: Mirror, upstream, route,
                                            method):
    """Every §0.7.1 mirror row reaches the upstream route it names."""
    status, _, _ = get(mirror.base + route, method=method)

    assert status == 200
    assert route in [h["path"] for h in hits(upstream)]


def test_blob_class_routes_by_digest(mirror: Mirror, upstream):
    """A blob is addressed by digest, and the bytes we hand back hash to it."""
    _, _, manifest = get(mirror.base + "/v2/lab/app/manifests/v1")
    digest = json.loads(manifest)["layers"][0]["digest"]

    status, _, body = get(mirror.base + "/v2/lab/app/blobs/" + digest)

    assert status == 200
    assert "sha256:" + hashlib.sha256(body).hexdigest() == digest
    assert any(h["path"].endswith("/blobs/" + digest) for h in hits(upstream))


def test_percent_encoded_slash_shares_one_cache_key(mirror: Mirror, upstream):
    """`lab%2fapp` and `lab/app` are one repository, so one cache entry.

    Two entries for one object would be a cache-poisoning seam: whoever picks
    the spelling picks which entry a later, differently-spelled pull reads.
    """
    status_plain, _, plain = get(mirror.base + "/v2/lab/app/manifests/v1")
    warm = (len(hits(upstream)), cache_files(mirror.cache))

    status_enc, _, encoded = get(mirror.base + "/v2/lab%2fapp/manifests/v1")

    assert (status_plain, status_enc) == (200, 200)
    assert encoded == plain
    assert (len(hits(upstream)), cache_files(mirror.cache)) == warm


def test_shorthand_name_expands_to_one_namespaced_cache_key(lifecycle,
                                                            upstream,
                                                            tmp_path):
    """`alpine` and `library/alpine` are one repository upstream, so one entry.

    Every client resolves a single-component name against an implicit
    namespace before it reaches the wire — that is what makes `podman pull
    alpine` work — so a mirror that treated the two spellings as different
    repositories would fill, store and verify the same image twice, and a
    later pull would read whichever copy the spelling picked. The expansion is
    therefore applied where the key is built, once, ahead of every consumer.
    `lab` stands in for DockerHub's `library` here because the namespace is
    the operator's to name; the mechanism is the same one.
    """
    reset(upstream)
    mirror = start_mirror(lifecycle, "lc-oci-classify-ns", NGINX_PORT + 3,
                          MOCK_PORT, tmp_path / "nscache",
                          extra_lines="brix_oci_upstream_namespace lab;")

    status_short, _, short = get(mirror.base + "/v2/app/manifests/v1")
    filled = (len(hits(upstream)), cache_files(mirror.cache))

    status_full, _, full = get(mirror.base + "/v2/lab/app/manifests/v1")

    assert (status_short, status_full) == (200, 200)
    assert full == short
    # The shorthand left as the fully-qualified name; the qualified spelling
    # then read the entry the shorthand filled.
    assert [h["path"] for h in hits(upstream, method="GET")] == [
        "/v2/lab/app/manifests/v1"]
    assert (len(hits(upstream)), cache_files(mirror.cache)) == filled


def test_tags_list_forwards_uncached_with_pagination(mirror: Mirror, upstream):
    """Tag lists are unboundedly mutable: forwarded verbatim, never cached."""
    status_a, _, first = get(mirror.base + "/v2/lab/app/tags/list?n=1")
    status_b, _, second = get(mirror.base + "/v2/lab/app/tags/list?n=1")

    assert (status_a, status_b) == (200, 200)
    assert json.loads(first)["tags"] == ["v1"]      # ?n= reached the upstream
    assert second == first
    # Two client requests, two upstream GETs — a cached tag list would show one.
    forwarded = hits(upstream, method="GET",
                     path_prefix="/v2/lab/app/tags/list")
    assert len(forwarded) == 2
    assert all(h["path"].endswith("?n=1") for h in forwarded)
    assert cache_files(mirror.cache) == []


def test_referrers_forwards_uncached_with_its_filter(mirror: Mirror,
                                                     upstream):
    """The referrers graph is a listing, and a stale one is a missed signature.

    A cached answer here would hide the very artifact the client came to
    verify — the signature pushed a minute ago — so the route is forwarded
    verbatim, filter and all, and nothing is stored.
    """
    subject = "sha256:" + "ab" * 32
    route = "/v2/lab/app/referrers/" + subject

    status_a, _, first = get(mirror.base + route)
    status_b, headers, filtered = get(
        mirror.base + route + "?artifactType=application/vnd.example.sbom")

    assert (status_a, status_b) == (200, 200)
    assert len(json.loads(first)["manifests"]) == 2
    # The filter reached the upstream: it answered with the selection AND the
    # header that says a selection happened.
    assert len(json.loads(filtered)["manifests"]) == 1
    assert headers["OCI-Filters-Applied"] == "artifactType"

    forwarded = hits(upstream, method="GET", path_prefix=route)
    assert len(forwarded) == 2
    assert cache_files(mirror.cache) == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_write_methods_405_allow_header_and_ocipush_guard(mirror: Mirror,
                                                          upstream, method):
    """A write aimed at a mirror is refused AND recorded as a push attempt."""
    status, headers, body = get(mirror.base + "/v2/lab/app/blobs/uploads/",
                                method=method)

    assert status == 405
    assert headers["Allow"] == "GET, HEAD"
    assert err_code(body) == "UNSUPPORTED"
    assert hits(upstream) == []                     # refused before any egress
    assert "signal=ocipush" in error_log(mirror.endpoint)


@pytest.mark.parametrize("name", [
    "n" * 256,                                      # over the 255-B name cap
    "Lab/App",                                      # uppercase is not in the grammar
    "lab/app___tool",                               # ___ is not a legal separator
    "lab/-app",                                     # component may not start with '-'
    "lab/app-",                                     # …nor end with one
    "lab/.wh.app",                                  # …nor with '.'
])
def test_bad_name_shapes_400_name_invalid(mirror: Mirror, upstream, name):
    """Grammar refusals, before any egress.

    An empty component ("lab//app") is deliberately absent: nginx's
    `merge_slashes on` default collapses it in the core URI parser, so no
    client can put that shape in front of the classifier.
    """
    status, _, body = get(mirror.base + "/v2/%s/manifests/v1" % name)

    assert status == 400
    assert err_code(body) == "NAME_INVALID"
    assert hits(upstream) == []


@pytest.mark.parametrize("digest", [
    "sha256:" + "z" * 64,                           # non-hex
    "sha256:" + "a" * 63,                           # one short
    "sha256:" + "a" * 65,                           # one long
    "sha512:" + "a" * 64,                           # sha256's width, sha512's name
    "sha256:" + "a" * 128,                          # sha512's width, sha256's name
    "sha384:" + "a" * 96,                           # a real algorithm, unregistered
    "a" * 64,                                       # no algorithm prefix
])
def test_bad_digest_400_digest_invalid(mirror: Mirror, upstream, digest):
    status, _, body = get(mirror.base + "/v2/lab/app/blobs/" + digest)

    assert status == 400
    assert err_code(body) == "DIGEST_INVALID"
    assert hits(upstream) == []


@pytest.mark.parametrize("route", [
    "/v2/lab/app/manifests/" + "t" * 129,           # tag cap is 128
    "/v2/lab/app/frobs/v1",                         # not a terminal we serve
    "/v2/lab/app/manifests/",                       # empty reference
    "/v2/manifests/v1",                             # no repository name
])
def test_unknown_and_malformed_routes_refused(mirror: Mirror, upstream, route):
    status, _, body = get(mirror.base + route)

    assert status in (400, 404)
    assert err_code(body) in ("NAME_INVALID", "NAME_UNKNOWN", "TAG_INVALID",
                             "MANIFEST_UNKNOWN", "UNSUPPORTED")
    assert hits(upstream) == []


@pytest.mark.parametrize("route", [
    "/v2/lab/../../etc/passwd",
    "/v2/lab/%2e%2e/%2e%2e/etc/passwd",
    "/v2/lab/app/manifests/..%2f..%2fetc%2fpasswd",
    "/v2/lab/app/blobs/sha256:../../../etc/passwd",
    "/v2/lab/app/manifests/v1/../../../../etc/passwd",
])
def test_traversal_corpus_never_escapes_the_v2_prefix(mirror: Mirror, upstream,
                                                      route):
    """No spelling of `..` may address anything outside the mirror's namespace.

    nginx normalizes `..` out of the URI before our handler ever runs, so the
    assertion that carries weight is the pair: the client is refused, and
    nothing that left for the upstream — nor anything that landed in the cache
    store — is outside `/v2/`.
    """
    status, _, _ = get(mirror.base + route)

    assert status in (400, 404)
    for row in hits(upstream):
        assert row["path"].startswith("/v2/")
        assert ".." not in row["path"]
    for path in cache_files(mirror.cache):
        assert path.startswith("v2/")
