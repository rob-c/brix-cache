# tests/test_oci_registry_push.py — the local registry's push surface
# (phase-104 D4: upload sessions, manifest PUT, authorization, DELETE).
#
# The subject is the WRITE path. Every test here asks what the registry did
# with bytes a client handed it — where they landed, what it refused to
# accept, and what a later pull gets back — because a registry that reports
# success without storing a verifiable object is worse than one that fails:
# the operator believes the image is published and nothing holds it.
#
# Ports: the oci_registry block, nginx front at 14150 (mocks would take
# 14140–14149; this surface has no upstream and therefore no mock).
#
# The nginx front is a per-test lifecycle instance rather than a fleet member:
# each test needs its own empty store for "already present" to mean something,
# and the surface is off by default everywhere else in the fleet.
import json
import functools
import os
import threading
import time
import urllib.parse

import pytest

from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from oci.registry_lane import (
    Registry, digest_of, err_code, image_manifest, push_blob, push_manifest,
    registry_spec, req, start_registry,
)

def _check_test_retag_between_two_manifests_is_never_seen_half_done_2(_put):
    assert _put(b'{"a":"one"}')[0] == 201

def _check_test_retag_between_two_manifests_is_never_seen_half_done_3(seen):
    assert len(set(seen)) == 2, "the hammer never crossed a swap: %r" % set(seen)

def _check_test_retag_between_two_manifests_is_never_seen_half_done_1(status):
    assert status == 201


try:
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                    # noqa: BLE001 — cryptography is optional
    _HAVE_TOKENFORGE = False

NGINX_PORT = 14150

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-registry-push"),
]

#: What a push token has to carry. `storage.modify` is the WLCG scope the
#: write gate reads (brix_token_check_write); `storage.read` alone is the
#: read-only credential the same gate must refuse.
PUSH_SCOPE = "storage.read:/ storage.create:/ storage.modify:/"
PULL_SCOPE = "storage.read:/"

LAYER = b"a plausible layer, gzipped in spirit only\n" * 64
CONFIG = b'{"architecture":"amd64","os":"linux"}'


@pytest.fixture
def registry(lifecycle, tmp_path) -> Registry:
    return start_registry(lifecycle, "lc-oci-registry", NGINX_PORT,
                          tmp_path / "store")


@pytest.fixture
def authenticated(lifecycle, tmp_path):
    """A registry that authenticates: a named issuer, no anonymous leg.

    Returns (Registry, TokenForge). This is the deployment D4.5 is written
    for — the un-authenticated variant of it does not exist as a running
    server, because oci_merge.c refuses to start one (asserted separately by
    test_registry_without_an_auth_plane_is_refused_at_parse_time).
    """
    if not _HAVE_TOKENFORGE:
        pytest.skip("tokenforge (cryptography) unavailable")

    mint = tmp_path / "mint"
    forge = TokenForge(str(mint))
    forge.init_keys()
    cfg = mint / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "oci-registry", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])

    reg = start_registry(lifecycle, "lc-oci-registry-auth", NGINX_PORT + 1,
                         tmp_path / "authstore", anonymous=False,
                         issuers=str(cfg))
    return reg, forge


def _bearer(forge, scope):
    return {"Authorization": "Bearer " + forge.generate(sub="alice",
                                                        scope=scope)}


# ---- success: the whole podman-push shape -------------------------------- #

def test_api_root_answers_before_any_credential(registry: Registry):
    """`/v2/` is the version handshake, and it precedes authorization."""
    status, headers, body = req(registry.base + "/v2/")

    assert status == 200
    assert json.loads(body) == {}
    assert headers["Docker-Distribution-API-Version"] == "registry/2.0"


def test_session_start_reports_a_resumable_zero_length_upload(
        registry: Registry):
    """A fresh session is OPEN: it exists, and it holds nothing yet."""
    status, headers, _ = req(registry.base + "/v2/lab/app/blobs/uploads/",
                             method="POST")

    assert status == 202
    assert headers["Location"].startswith("/v2/lab/app/blobs/uploads/")
    assert headers["Range"] == "0-0"
    assert headers["Docker-Upload-UUID"]

    # ...and asking about it agrees, which is what makes a resume possible.
    status, headers, _ = req(registry.base + headers["Location"])
    assert status == 204
    assert headers["Range"] == "0-0"


@pytest.mark.parametrize("chunks", [1, 4])
def test_blob_round_trips_through_the_session_machine(registry: Registry,
                                                      chunks):
    """POST → PATCH×n → PUT stores bytes a pull hands back unchanged."""
    digest = push_blob(registry, "lab/app", LAYER, chunks=chunks)

    status, headers, body = req(
        "%s/v2/lab/app/blobs/%s" % (registry.base, digest))

    assert status == 200
    assert body == LAYER
    assert headers["Docker-Content-Digest"] == digest


def test_monolithic_post_stores_the_blob_in_one_request(registry: Registry):
    """`POST ?digest=` is the one-shot shortcut podman uses for small blobs."""
    digest = digest_of(CONFIG)

    status, headers, _ = req(
        "%s/v2/lab/app/blobs/uploads/?digest=%s"
        % (registry.base, urllib.parse.quote(digest, safe="")),
        method="POST", data=CONFIG)

    assert status == 201
    assert headers["Docker-Content-Digest"] == digest
    assert req("%s/v2/lab/app/blobs/%s" % (registry.base, digest))[2] == CONFIG


def test_manifest_put_publishes_a_tag_a_pull_resolves(registry: Registry):
    """The published tag resolves to the manifest, byte for byte."""
    config = push_blob(registry, "lab/app", CONFIG)
    layer = push_blob(registry, "lab/app", LAYER)
    manifest = image_manifest(config, [layer])

    status, headers, _ = push_manifest(registry, "lab/app", "v1", manifest)
    assert status == 201
    digest = headers["Docker-Content-Digest"]

    status, headers, body = req(registry.base + "/v2/lab/app/manifests/v1")
    assert status == 200
    assert json.loads(body) == manifest
    assert headers["Docker-Content-Digest"] == digest
    assert headers["Content-Type"] == manifest["mediaType"]

    # The same object is reachable by digest — that is what makes the digest
    # a stable pin while the tag stays free to move.
    assert req("%s/v2/lab/app/manifests/%s" % (registry.base, digest))[0] == 200


def test_sha512_image_pushes_and_resolves_under_its_own_algorithm(
        registry: Registry):
    """The second registered algorithm has to survive the whole write path.

    The seal checks the digest the client named, the store files the object
    under the algorithm that digest names, and the read side has to find it
    there again. None of that is a parse case: each of those steps used to
    spell "sha256" literally, and each would fail differently here.
    """
    config = push_blob(registry, "lab/s512", CONFIG, alg="sha512")
    layer = push_blob(registry, "lab/s512", LAYER, alg="sha512")
    assert config.startswith("sha512:")

    manifest = image_manifest(config, [layer])
    digest = digest_of(json.dumps(manifest).encode(), "sha512")

    status, headers, _ = push_manifest(registry, "lab/s512", digest, manifest)
    assert status == 201
    assert headers["Docker-Content-Digest"] == digest

    status, headers, body = req("%s/v2/lab/s512/manifests/%s"
                                % (registry.base, digest))
    assert status == 200
    assert json.loads(body) == manifest
    assert headers["Docker-Content-Digest"] == digest
    assert req("%s/v2/lab/s512/blobs/%s" % (registry.base, layer))[2] == LAYER


def _put_tag(url, marker):
    manifest = image_manifest(digest_of(marker), [digest_of(LAYER)])
    return req(
        url, method="PUT", data=json.dumps(manifest).encode(),
        headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})


def _swap_tags(stop, put):
    index = 0
    while not stop.is_set():
        put(b'{"a":"one"}' if index % 2 else b'{"a":"two"}')
        index += 1


def _publish_swap_manifests(registry):
    digests = []
    for marker in (b'{"a":"one"}', b'{"a":"two"}'):
        config = digest_of(marker)
        push_blob(registry, "lab/app", marker)
        push_blob(registry, "lab/app", LAYER)
        manifest = image_manifest(config, [digest_of(LAYER)])
        status, headers, _ = push_manifest(
            registry, "lab/app", "v" + str(len(digests)), manifest)
        _check_test_retag_between_two_manifests_is_never_seen_half_done_1(status)
        digests.append(headers["Docker-Content-Digest"])
    return digests


def _read_during_swaps(url, stop, writer):
    seen, failures = [], []
    writer.start()
    try:
        for _ in range(200):
            status, headers, body = req(url)
            if status != 200:
                failures.append("read saw %d" % status)
                break
            seen.append(headers["Docker-Content-Digest"])
            if digest_of(body) != headers["Docker-Content-Digest"]:
                failures.append("body does not hash to its own digest header")
                break
    finally:
        stop.set()
        writer.join(timeout=10)
    return seen, failures


def test_retag_between_two_manifests_is_never_seen_half_done(
        registry: Registry):
    """A tag is one file holding one line, and a reader sees one or the other.

    Retagging is how a site promotes a build to `prod`, and it happens while
    the farm is pulling that exact tag. If the swap were a truncate-then-write
    a puller would occasionally resolve `prod` to an empty or half-written
    digest and fail its deployment for reasons no log explains — so the store
    writes a temporary and renames it. This hammers the window: every read
    taken across a thousand swaps must resolve to a manifest that was, at some
    instant, actually published.
    """
    digests = _publish_swap_manifests(registry)

    url = registry.base + "/v2/lab/app/manifests/prod"

    put = functools.partial(_put_tag, url)

    # `prod` exists BEFORE the hammer starts: a 404 from a tag that was never
    # published is a race in the test, not a torn read in the store, and it
    # would mask the one this is looking for.
    _check_test_retag_between_two_manifests_is_never_seen_half_done_2(put)

    stop = threading.Event()
    writer = threading.Thread(target=_swap_tags, args=(stop, put), daemon=True)
    seen, failures = _read_during_swaps(url, stop, writer)

    assert not failures, failures
    assert set(seen) <= set(digests), "a read resolved to an unpublished digest"
    _check_test_retag_between_two_manifests_is_never_seen_half_done_3(seen)


def test_tags_list_answers_from_the_local_store(registry: Registry):
    """A registry knows its own tags; nothing is forwarded anywhere."""
    config = push_blob(registry, "lab/app", CONFIG)
    manifest = image_manifest(config, [])
    for tag in ("v1", "v2"):
        assert push_manifest(registry, "lab/app", tag, manifest)[0] == 201

    status, _, body = req(registry.base + "/v2/lab/app/tags/list")

    assert status == 200
    listing = json.loads(body)
    assert listing["name"] == "lab/app"
    assert sorted(listing["tags"]) == ["v1", "v2"]


def test_cross_repo_mount_publishes_without_moving_bytes(registry: Registry):
    """A blob already in the CAS is mounted, not re-uploaded."""
    digest = push_blob(registry, "lab/app", LAYER)

    status, headers, _ = req(
        "%s/v2/lab/other/blobs/uploads/?mount=%s&from=lab/app"
        % (registry.base, urllib.parse.quote(digest, safe="")),
        method="POST")

    assert status == 201
    assert headers["Docker-Content-Digest"] == digest
    assert req("%s/v2/lab/other/blobs/%s" % (registry.base, digest))[0] == 200


def test_delete_by_digest_drops_the_manifest(registry: Registry):
    """DELETE removes the object; a later pull of it is an honest 404."""
    config = push_blob(registry, "lab/app", CONFIG)
    _, headers, _ = push_manifest(registry, "lab/app", "v1",
                                  image_manifest(config, []))
    digest = headers["Docker-Content-Digest"]

    status, _, _ = req("%s/v2/lab/app/manifests/%s" % (registry.base, digest),
                       method="DELETE")
    assert status == 202
    assert req("%s/v2/lab/app/manifests/%s" % (registry.base, digest))[0] == 404


# ---- error: what the surface refuses, and how it says so ----------------- #

def test_seal_with_the_wrong_digest_is_refused_and_the_session_survives(
        registry: Registry):
    """A mis-stated digest must not become a stored object — or a lost one."""
    status, headers, _ = req(registry.base + "/v2/lab/app/blobs/uploads/",
                             method="POST")
    location = headers["Location"]
    _, headers, _ = req(registry.base + location, method="PATCH", data=LAYER)
    location = headers["Location"]

    wrong = digest_of(b"not what was sent")
    status, _, body = req(
        "%s%s?digest=%s" % (registry.base, location,
                            urllib.parse.quote(wrong, safe="")),
        method="PUT")

    assert status == 400
    assert err_code(body) == "DIGEST_INVALID"
    assert req("%s/v2/lab/app/blobs/%s" % (registry.base, wrong))[0] == 404

    # J.7: the session stays ACTIVE, holding every byte it already accepted,
    # so the client can seal it correctly instead of re-uploading.
    status, headers, _ = req(registry.base + location)
    assert status == 204
    assert headers["Range"] == "0-%d" % (len(LAYER) - 1)


def test_a_sha512_seal_is_verified_and_not_waved_through(
        registry: Registry):
    """An algorithm the seal cannot check is an unchecked write.

    The dangerous shape is not a refused push — it is a push whose digest the
    server did not know how to verify and stored anyway, leaving a name that
    lies about its own bytes to every puller that trusts it. So state a
    well-formed sha512 digest of some OTHER payload: it must be refused
    exactly as sha256's is, and the honest seal of the same session must
    still land.
    """
    status, headers, _ = req(registry.base + "/v2/lab/s512/blobs/uploads/",
                             method="POST")
    assert status == 202
    location = headers["Location"]
    _, headers, _ = req(registry.base + location, method="PATCH", data=LAYER)
    location = headers["Location"]

    wrong = digest_of(b"not what was sent", "sha512")
    status, _, body = req(
        "%s%s?digest=%s" % (registry.base, location,
                            urllib.parse.quote(wrong, safe="")),
        method="PUT")

    assert status == 400
    assert err_code(body) == "DIGEST_INVALID"
    assert req("%s/v2/lab/s512/blobs/%s" % (registry.base, wrong))[0] == 404

    right = digest_of(LAYER, "sha512")
    status, _, _ = req(
        "%s%s?digest=%s" % (registry.base, location,
                            urllib.parse.quote(right, safe="")),
        method="PUT")
    assert status == 201
    assert req("%s/v2/lab/s512/blobs/%s" % (registry.base, right))[2] == LAYER


def test_manifest_naming_an_unpushed_blob_is_refused(registry: Registry):
    """The invariant that makes "the tag resolves" mean "the image is here"."""
    ghost = digest_of(b"a layer nobody ever uploaded")

    status, _, body = push_manifest(registry, "lab/app", "v1",
                                    image_manifest(ghost, []))

    assert status == 400
    assert err_code(body) == "MANIFEST_BLOB_UNKNOWN"
    assert ghost in body.decode()          # the detail names WHICH blob
    assert req(registry.base + "/v2/lab/app/manifests/v1")[0] == 404


def test_patch_at_the_wrong_offset_reports_where_to_resume(registry: Registry):
    """A resume that guesses wrong is corrected, not silently accepted."""
    _, headers, _ = req(registry.base + "/v2/lab/app/blobs/uploads/",
                        method="POST")
    location = headers["Location"]
    _, headers, _ = req(registry.base + location, method="PATCH", data=LAYER)
    location = headers["Location"]

    status, headers, body = req(
        registry.base + location, method="PATCH", data=b"tail",
        headers={"Content-Range": "%d-%d" % (0, 3)})

    assert status == 416
    assert err_code(body) == "BLOB_UPLOAD_INVALID"
    assert headers["Range"] == "0-%d" % (len(LAYER) - 1)


def test_unknown_session_is_not_resurrected_by_a_patch(registry: Registry):
    """SEALED / ABORTED / REAPED are one answer to a client: it is finished."""
    _, headers, _ = req(registry.base + "/v2/lab/app/blobs/uploads/",
                        method="POST")
    location = headers["Location"]
    assert req(registry.base + location, method="DELETE")[0] == 204

    status, _, body = req(registry.base + location, method="PATCH", data=LAYER)

    assert status == 404
    assert err_code(body) == "BLOB_UPLOAD_UNKNOWN"


def test_blob_over_the_cap_is_refused_by_measured_bytes(lifecycle, tmp_path):
    """The cap is enforced against what arrived, not against a header.

    Real layer PATCHes arrive chunked with no Content-Length at all (App. Y-2),
    so a header-based cap would be no cap.
    """
    reg = start_registry(lifecycle, "lc-oci-registry-cap", NGINX_PORT + 2,
                         tmp_path / "capped",
                         extra_lines="brix_oci_max_blob_size 1k;")

    _, headers, _ = req(reg.base + "/v2/lab/app/blobs/uploads/", method="POST")

    status, _, body = req(reg.base + headers["Location"], method="PATCH",
                          data=b"x" * 4096)

    assert status == 413
    assert err_code(body) == "SIZE_INVALID"


def test_manifest_over_the_document_cap_is_refused_before_it_is_parsed(
        registry: Registry):
    """4 MiB is not a manifest, and brix will not allocate to find out.

    The cap is checked against the declared length on the way in and again
    against what actually arrived, because a client can lie in a header but
    not about how many bytes it sent. Refusing on the declared length is what
    keeps a lie cheap: nothing is parsed, nothing is buffered whole.
    """
    oversize = b'{"schemaVersion":2,"pad":"' + b"p" * (4 << 20) + b'"}'

    status, _, body = req(registry.base + "/v2/lab/app/manifests/fat",
                          method="PUT", data=oversize,
                          headers={"Content-Type":
                                   "application/vnd.oci.image.manifest.v1+json"})

    assert status == 413
    assert err_code(body) == "SIZE_INVALID"
    assert not (registry.store / "repos" / "lab" / "app" / "tags").exists()


def test_an_idle_session_is_reaped_and_its_bytes_go_with_it(lifecycle,
                                                            tmp_path):
    """An abandoned push must not hold disk forever.

    Clients die mid-layer — a cancelled CI job, a laptop lid. The staged
    part-file's mtime is the last time that client sent anything, which is
    exactly the idleness `brix_oci_upload_grace` is about, and the sweep runs
    on the way into a session-creating request: an idle registry has nothing
    to reap and does no work. Backdating the part-file is the honest way to
    age a session without sleeping for the grace window.
    """
    reg = start_registry(lifecycle, "lc-oci-registry-reap", NGINX_PORT + 4,
                         tmp_path / "reaped",
                         extra_lines="brix_oci_upload_grace 30s;")

    _, headers, _ = req(reg.base + "/v2/lab/app/blobs/uploads/", method="POST")
    location = headers["Location"]
    assert req(reg.base + location, method="PATCH", data=LAYER)[0] == 202

    sessions = list((reg.store / "_uploads").iterdir())
    assert len(sessions) == 1, sessions
    part = sessions[0] / "part"
    assert part.stat().st_size == len(LAYER)

    aged = time.time() - 3600
    os.utime(part, (aged, aged))

    # ...and the next client to start a push is what sweeps it.
    req(reg.base + "/v2/lab/other/blobs/uploads/", method="POST")

    assert not sessions[0].exists(), "the idle session survived the sweep"
    status, _, body = req(reg.base + location)
    assert status == 404
    assert err_code(body) == "BLOB_UPLOAD_UNKNOWN"


def test_pull_of_an_unpushed_object_is_a_miss_not_a_fill(registry: Registry):
    """This surface IS the source of truth: a miss has nowhere to come from."""
    status, _, body = req(
        "%s/v2/lab/app/blobs/%s" % (registry.base, digest_of(b"absent")))

    assert status == 404
    assert err_code(body) == "BLOB_UNKNOWN"


# ---- security-negative --------------------------------------------------- #

def test_anonymous_push_is_challenged_on_an_authenticating_registry(
        authenticated):
    """An unauthenticated push is a supply-chain hole. Refuse it — followably.

    `podman login` only works against a registry whose refusal names a realm,
    so the challenge shape is part of the contract, not decoration.
    """
    reg, _ = authenticated

    status, headers, body = req(reg.base + "/v2/lab/app/blobs/uploads/",
                                method="POST")

    assert status == 401
    assert err_code(body) == "UNAUTHORIZED"
    challenge = headers.get("WWW-Authenticate", "")
    assert challenge.startswith("Bearer ")
    assert 'realm="' in challenge


def test_a_scoped_token_is_admitted_to_the_write_path(authenticated):
    """The other half of the refusal: the right credential does get through."""
    reg, forge = authenticated

    status, headers, body = req(reg.base + "/v2/lab/app/blobs/uploads/",
                                method="POST",
                                headers=_bearer(forge, PUSH_SCOPE))

    assert status == 202, (status, body)
    assert headers["Location"].startswith("/v2/lab/app/blobs/uploads/")


def test_a_read_only_token_may_pull_but_never_push(authenticated):
    """A valid token without `storage.modify` is a 403, not a 401.

    The distinction is load-bearing: a 401 sends a client back to the token
    endpoint for a credential it already holds, looping forever against a
    scope problem no re-login can fix.
    """
    reg, forge = authenticated
    creds = _bearer(forge, PULL_SCOPE)

    status, _, body = req(reg.base + "/v2/lab/app/blobs/uploads/",
                          method="POST", headers=creds)
    assert status == 403
    assert err_code(body) == "DENIED"

    # ...and the same credential still reads: the refusal is scoped to writes,
    # not to the identity.
    status, _, body = req(
        "%s/v2/lab/app/blobs/%s" % (reg.base, digest_of(b"absent")),
        headers=creds)
    assert status == 404
    assert err_code(body) == "BLOB_UNKNOWN"


def test_registry_without_an_auth_plane_is_refused_at_parse_time(
        lifecycle, tmp_path):
    """Fail-closed at the earliest possible moment: config parse.

    `brix_oci_registry on` with no issuer, no client certificate and no typed
    anonymous opt-in is an open push surface. It is not a server that answers
    401 — it is a server that never starts.
    """
    reg = lifecycle.register(registry_spec(
        "lc-oci-registry-noauth", SHARED_PARSE_PLACEHOLDER_PORT,
        tmp_path / "noauth", anonymous=False))
    lifecycle.launcher.render_nginx(reg)
    res = lifecycle.launcher.nginx_test(reg, check=False)

    output = res.stdout + res.stderr
    assert res.returncode != 0, output
    assert "brix_oci_registry on without an authenticated context" in output
    assert "brix_oci_token_issuers" in output


def test_a_read_only_location_refuses_every_write(lifecycle, tmp_path):
    """INVARIANT #3: no credential promotes a read-only location."""
    reg = start_registry(lifecycle, "lc-oci-registry-ro", NGINX_PORT + 3,
                         tmp_path / "ro", writable=False)

    status, _, body = req(reg.base + "/v2/lab/app/blobs/uploads/",
                          method="POST")

    assert status == 403
    assert err_code(body) == "DENIED"


def test_another_repos_layer_is_not_readable_by_digest(registry: Registry):
    """The CAS is global; a repository serves only what it was told it holds.

    Without the reference mark, one tenant reads another tenant's private
    layer by guessing nothing more than its digest — which a leaked manifest
    hands over for free.
    """
    digest = push_blob(registry, "lab/private", LAYER)

    assert req("%s/v2/lab/private/blobs/%s" % (registry.base, digest))[0] == 200

    status, _, body = req(
        "%s/v2/lab/public/blobs/%s" % (registry.base, digest))

    assert status == 404
    assert err_code(body) == "BLOB_UNKNOWN"


@pytest.mark.parametrize("evil", [
    "/v2/lab/app/blobs/sha256:../../../../etc/passwd",
    "/v2/lab/app/manifests/..%2f..%2fetc%2fpasswd",
    "/v2/lab/app/blobs/uploads/../../../../etc/passwd",
])
def test_traversal_shaped_references_never_classify(registry: Registry, evil):
    """The grammar IS the traversal defense: what cannot classify cannot open."""
    status, _, _ = req(registry.base + evil)

    assert status in (400, 404)
