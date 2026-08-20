# tests/test_oci_registry_referrers.py — the referrers graph on the local
# registry (phase-104 D15.1).
#
# The subject is DISCOVERABILITY. A signature, an SBOM or a provenance
# attestation is an ordinary manifest that names another manifest as its
# `subject`; the registry's whole contribution is to make the reverse
# direction answerable, so every test here asks what a client holding only an
# image digest can find out — and what it is refused when it asks with
# something that is not a digest at all.
#
# Ports: the oci_registry block, nginx front at 14154 (14150–14153 are the
# push lane's four fronts).
import json

import pytest

from oci.registry_lane import (
    Registry, digest_of, err_code, image_manifest, push_blob, push_manifest,
    req, start_registry,
)

NGINX_PORT = 14154

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-registry-referrers"),
]

INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
SBOM_TYPE = "application/vnd.example.sbom.v1+json"
SIG_TYPE = "application/vnd.example.signature.v1+json"

CONFIG = b'{"architecture":"amd64","os":"linux"}'
LAYER = b"a plausible layer, gzipped in spirit only\n" * 16


@pytest.fixture
def registry(lifecycle, tmp_path) -> Registry:
    return start_registry(lifecycle, "lc-oci-referrers", NGINX_PORT,
                          tmp_path / "store")


def _push_subject(reg: Registry, repo="lab/app", reference="v1") -> str:
    """Push a complete image and return the digest others will refer to."""
    config = push_blob(reg, repo, CONFIG)
    layer = push_blob(reg, repo, LAYER)
    manifest = image_manifest(config, [layer])
    status, headers, body = push_manifest(reg, repo, reference, manifest)
    assert status == 201, "subject push refused: %d %s" % (status, body)
    return headers["Docker-Content-Digest"]


def _push_referrer(reg: Registry, subject: str, artifact_type=None,
                   repo="lab/app", payload=b"{}", annotations=None):
    """Push a manifest that names `subject`, as cosign/syft do.

    Returns (status, headers, digest-of-the-document). The artifact carries a
    real blob so the push clears the same blob-existence proof every other
    manifest does — the subject descriptor is the one reference that is
    deliberately NOT required to exist.
    """
    config = push_blob(reg, repo, payload)
    manifest = image_manifest(config, [])
    manifest["subject"] = {"mediaType": MANIFEST_TYPE, "digest": subject,
                           "size": 0}
    if artifact_type is not None:
        manifest["artifactType"] = artifact_type
    if annotations is not None:
        manifest["annotations"] = annotations

    status, headers, _ = push_manifest(reg, repo, digest_of(
        json.dumps(manifest).encode()), manifest)
    return status, headers, digest_of(json.dumps(manifest).encode())


def _referrers(reg: Registry, subject: str, repo="lab/app", query=""):
    status, headers, body = req("%s/v2/%s/referrers/%s%s"
                                % (reg.base, repo, subject, query))
    return status, headers, json.loads(body) if body else None


# ---- success: the graph answers ------------------------------------------ #

def test_a_pushed_referrer_appears_in_its_subjects_listing(
        registry: Registry):
    """The edge a push declares is the edge a later listing reports."""
    subject = _push_subject(registry)
    status, _, referrer = _push_referrer(registry, subject,
                                         artifact_type=SBOM_TYPE)
    assert status == 201

    status, headers, index = _referrers(registry, subject)

    assert status == 200
    assert headers["Content-Type"] == INDEX_TYPE
    assert index["schemaVersion"] == 2 and index["mediaType"] == INDEX_TYPE
    assert [d["digest"] for d in index["manifests"]] == [referrer]
    assert index["manifests"][0]["artifactType"] == SBOM_TYPE
    assert index["manifests"][0]["mediaType"] == MANIFEST_TYPE
    assert index["manifests"][0]["size"] > 0


def test_push_of_a_referrer_reports_the_subject_it_understood(
        registry: Registry):
    """OCI-Subject is how a signing tool learns the API is live here.

    Without the header the client falls back to the tag-schema workaround —
    so its absence is not cosmetic, it changes what cosign writes.
    """
    subject = _push_subject(registry)

    status, headers, _ = _push_referrer(registry, subject,
                                        artifact_type=SBOM_TYPE)

    assert status == 201
    assert headers["OCI-Subject"] == subject


def test_a_manifest_without_a_subject_claims_none(registry: Registry):
    """An ordinary image push is not an edge, and must not announce one."""
    config = push_blob(registry, "lab/app", CONFIG)
    status, headers, _ = push_manifest(registry, "lab/app", "plain",
                                       image_manifest(config, []))

    assert status == 201
    assert "OCI-Subject" not in headers


def test_artifact_type_falls_back_to_the_config_media_type(
        registry: Registry):
    """A manifest that sets no artifactType is described by its config type.

    This is the image spec's own fallback, and it is what makes a cosign
    signature — which sets only the config media type — filterable at all.
    """
    subject = _push_subject(registry)
    _push_referrer(registry, subject)              # no artifactType field

    _, _, index = _referrers(registry, subject)

    assert index["manifests"][0]["artifactType"] == (
        "application/vnd.oci.image.config.v1+json")


def test_annotations_ride_into_the_listing(registry: Registry):
    """The descriptor carries what the tooling attached to the artifact."""
    subject = _push_subject(registry)
    _push_referrer(registry, subject, artifact_type=SBOM_TYPE,
                   annotations={"org.example.tool": "syft"})

    _, _, index = _referrers(registry, subject)

    assert index["manifests"][0]["annotations"] == {
        "org.example.tool": "syft"}


def test_a_subject_collects_every_referrer_pushed_at_it(registry: Registry):
    """Two artifacts about one image are two entries, not a replacement."""
    subject = _push_subject(registry)
    _, _, sbom = _push_referrer(registry, subject, artifact_type=SBOM_TYPE,
                                payload=b'{"sbom":1}')
    _, _, sig = _push_referrer(registry, subject, artifact_type=SIG_TYPE,
                               payload=b'{"sig":1}')

    _, _, index = _referrers(registry, subject)

    assert sorted(d["digest"] for d in index["manifests"]) == sorted(
        [sbom, sig])


# ---- the filter ----------------------------------------------------------- #

def test_artifact_type_filter_selects_and_declares_itself(
        registry: Registry):
    """A filtered answer MUST say it was filtered.

    Without OCI-Filters-Applied a client cannot distinguish "no signatures of
    this type" from "this registry ignored your filter", and would read the
    second as the first — which is a verification silently skipped.
    """
    subject = _push_subject(registry)
    _, _, sbom = _push_referrer(registry, subject, artifact_type=SBOM_TYPE,
                                payload=b'{"sbom":1}')
    _push_referrer(registry, subject, artifact_type=SIG_TYPE,
                   payload=b'{"sig":1}')

    status, headers, index = _referrers(registry, subject,
                                        query="?artifactType=" + SBOM_TYPE)

    assert status == 200
    assert headers["OCI-Filters-Applied"] == "artifactType"
    assert [d["digest"] for d in index["manifests"]] == [sbom]


def test_an_unknown_filter_value_is_declared_and_selects_nothing(
        registry: Registry):
    """Selecting on a type nothing carries is an empty, honest answer."""
    subject = _push_subject(registry)
    _push_referrer(registry, subject, artifact_type=SBOM_TYPE)

    status, headers, index = _referrers(
        registry, subject, query="?artifactType=application/vnd.nobody")

    assert status == 200
    assert headers["OCI-Filters-Applied"] == "artifactType"
    assert index["manifests"] == []


def test_an_unfiltered_answer_does_not_claim_a_filter(registry: Registry):
    """The header is a statement about THIS response, not about support."""
    subject = _push_subject(registry)
    _push_referrer(registry, subject, artifact_type=SBOM_TYPE)

    _, headers, _ = _referrers(registry, subject)

    assert "OCI-Filters-Applied" not in headers


# ---- absence and deletion ------------------------------------------------- #

def test_an_unknown_subject_is_an_empty_graph_not_a_404(registry: Registry):
    """"Nothing refers to it" is a complete answer to the question asked.

    404 would be a different claim — that the repository or the route is
    unknown — and would make a verifier retry rather than conclude.
    """
    _push_subject(registry)
    absent = "sha256:" + "ab" * 32

    status, _, index = _referrers(registry, absent)

    assert status == 200
    assert index["manifests"] == []


def test_deleting_a_referrer_cuts_the_edge(registry: Registry):
    """The listing describes what is here, so a deleted artifact leaves it."""
    subject = _push_subject(registry)
    _, _, referrer = _push_referrer(registry, subject,
                                    artifact_type=SBOM_TYPE)

    status, _, _ = req("%s/v2/lab/app/manifests/%s" % (registry.base,
                                                       referrer),
                       method="DELETE")
    assert status == 202

    _, _, index = _referrers(registry, subject)
    assert index["manifests"] == []


def test_deleting_the_subject_leaves_its_referrers_intact(
        registry: Registry):
    """The artifacts still exist and still say what they said.

    A signature over an image this registry no longer holds is still a valid
    signature; dropping it because the subject went away would destroy
    evidence the pusher owns, not clean up after them.
    """
    subject = _push_subject(registry)
    _, _, referrer = _push_referrer(registry, subject,
                                    artifact_type=SBOM_TYPE)

    status, _, _ = req("%s/v2/lab/app/manifests/%s" % (registry.base,
                                                       subject),
                       method="DELETE")
    assert status == 202

    _, _, index = _referrers(registry, subject)
    assert [d["digest"] for d in index["manifests"]] == [referrer]


def test_the_graph_is_per_repository(registry: Registry):
    """A referrer in one repository is not evidence about another.

    Cross-repository leakage here would let anyone who can push to a scratch
    repository fabricate the appearance of a signature over somebody else's
    image, since the subject is a bare digest with no owner attached.
    """
    subject = _push_subject(registry)
    _push_referrer(registry, subject, artifact_type=SBOM_TYPE,
                   repo="evil/scratch")

    _, _, mine = _referrers(registry, subject, repo="lab/app")
    _, _, theirs = _referrers(registry, subject, repo="evil/scratch")

    assert mine["manifests"] == []
    assert len(theirs["manifests"]) == 1


# ---- refusals ------------------------------------------------------------- #

def test_a_tag_cannot_name_the_subject(registry: Registry):
    """Only a digest may name a subject.

    A tag would make the answer depend on where that tag pointed when each
    referrer was pushed — exactly the mutability the referrers graph exists
    to escape.
    """
    _push_subject(registry)

    status, _, body = req(registry.base + "/v2/lab/app/referrers/v1")

    assert status == 400
    assert err_code(body) == "DIGEST_INVALID"


@pytest.mark.parametrize("subject", [
    "sha256:" + "ab" * 31,                       # too short
    "sha256:" + "ab" * 33,                       # too long
    "sha256:" + "AB" * 32,                       # uppercase is not the grammar
    "sha512:" + "ab" * 32,                       # an algorithm we do not store
    "ab" * 32,                                   # bare hex, no algorithm
])
def test_a_malformed_subject_is_refused_by_the_grammar(registry: Registry,
                                                       subject):
    """The subject names a DIRECTORY, so the grammar is the traversal defense.

    Every one of these is refused by the classifier before any path is built
    — which is why the store code below it may treat the hex as safe.
    """
    status, _, body = req("%s/v2/lab/app/referrers/%s"
                          % (registry.base, subject))

    assert status == 400
    assert err_code(body) == "DIGEST_INVALID"


@pytest.mark.parametrize("subject", [
    "sha256:..%2f..%2f..%2fetc%2fpasswd",
    "sha256:" + "ab" * 32 + "%2f..%2f..%2fblobs",
    "..%2f..%2f..%2fetc%2fpasswd",
])
def test_a_traversal_spelling_of_the_subject_reaches_nothing(
        registry: Registry, tmp_path, subject):
    """No spelling of the subject may name a path outside the graph.

    Some of these never reach the classifier at all — nginx resolves `../`
    while parsing, which turns them into a different, equally unrouteable
    request — so the assertion is on the OUTCOME (a refusal, and a store
    that grew nothing), not on which layer did the refusing.
    """
    before = sorted(p.name for p in registry.store.rglob("*"))

    status, _, body = req("%s/v2/lab/app/referrers/%s"
                          % (registry.base, subject))

    assert status in (400, 404)
    assert err_code(body) in ("DIGEST_INVALID", "NAME_INVALID",
                              "NAME_UNKNOWN")
    assert sorted(p.name for p in registry.store.rglob("*")) == before


@pytest.mark.parametrize("subject", [
    "not a descriptor",                          # subject is not an object
    {"mediaType": MANIFEST_TYPE, "size": 0},     # no digest at all
    {"digest": "sha256:nothex", "size": 0},      # a digest we cannot store
    {"digest": "sha512:" + "ab" * 32, "size": 0},
])
def test_a_subject_we_cannot_read_is_refused_not_stored(registry: Registry,
                                                        subject):
    """An unreadable subject is a 400, never a quiet accept.

    Storing it would publish an artifact whose edge nothing can follow — and
    to the pusher that is indistinguishable from a signature that WAS
    recorded, which is the worst of the available outcomes.
    """
    config = push_blob(registry, "lab/app", CONFIG)
    manifest = image_manifest(config, [])
    manifest["subject"] = subject

    status, headers, body = push_manifest(registry, "lab/app", "bad",
                                          manifest)

    assert status == 400
    assert err_code(body) == "MANIFEST_INVALID"
    assert "OCI-Subject" not in headers


@pytest.mark.parametrize("method", ["PUT", "POST", "PATCH", "DELETE"])
def test_the_referrers_route_is_read_only(registry: Registry, method):
    """The graph is written by manifest pushes, never by this endpoint.

    A writable referrers route would be a way to assert an edge without
    owning either end of it.
    """
    subject = "sha256:" + "cd" * 32

    status, _, body = req("%s/v2/lab/app/referrers/%s"
                          % (registry.base, subject), method=method,
                          data=b"{}" if method != "DELETE" else None)

    assert status == 405
    assert err_code(body) == "UNSUPPORTED"


def test_a_referrer_still_has_to_prove_its_own_blobs(registry: Registry):
    """`subject` is exempt from the existence walk; `layers` is not.

    Otherwise a referrer would be the hole through which an incomplete image
    enters a store whose whole invariant is that a resolvable name resolves
    to a complete object.
    """
    subject = _push_subject(registry)
    manifest = image_manifest(digest_of(CONFIG),
                              [digest_of(b"a layer nobody uploaded")])
    manifest["subject"] = {"mediaType": MANIFEST_TYPE, "digest": subject,
                           "size": 0}

    status, _, body = push_manifest(registry, "lab/app", "orphan", manifest)

    assert status == 400
    assert err_code(body) == "MANIFEST_BLOB_UNKNOWN"
