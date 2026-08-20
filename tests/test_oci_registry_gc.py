# tests/test_oci_registry_gc.py — `brixoci gc` over a real store (D15.3).
#
# The subject is RECLAMATION, and the reason it is a tool rather than a
# handler: a manifest DELETE deliberately leaves the CAS alone, because one
# repository's delete cannot see the other repositories holding the same
# layer. Every test here therefore pushes through the registry itself, asks
# the tool to answer that whole-store question, and then checks BOTH
# directions — that the orphan went, and that everything still referenced is
# still servable afterwards.
#
# Ports: the oci_registry block, nginx front at 14155 (14150–14154 are the
# push and referrers lanes).
import json
import os
import subprocess

import pytest

from oci.registry_lane import (
    Registry, digest_of, image_manifest, push_blob, push_manifest, req,
    start_registry,
)

NGINX_PORT = 14155

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIXOCI = os.path.join(REPO_ROOT, "client", "bin", "brixoci")

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-registry-gc"),
    pytest.mark.skipif(not os.path.exists(BRIXOCI),
                       reason="client/bin/brixoci not built"),
]

CONFIG = b'{"architecture":"amd64","os":"linux"}'
SHARED = b"a layer two images legitimately share\n" * 8
HEX = "c" * 64


@pytest.fixture
def registry(lifecycle, tmp_path) -> Registry:
    return start_registry(lifecycle, "lc-oci-gc", NGINX_PORT,
                          tmp_path / "store")


def gc(store, *args, expect=0):
    """Run the tool over `store`; returns its parsed --json report."""
    proc = subprocess.run([BRIXOCI, "gc", str(store), "--json", *args],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == expect, "gc rc=%d: %s%s" % (
        proc.returncode, proc.stdout, proc.stderr)
    return json.loads(proc.stdout) if proc.returncode == 0 else proc.stderr


def push_image(reg: Registry, repo, reference, config_bytes, layer_bytes,
               alg="sha256"):
    """Push one complete image; returns (manifest digest, blob digests)."""
    config = push_blob(reg, repo, config_bytes, alg=alg)
    layer = push_blob(reg, repo, layer_bytes, alg=alg)
    status, headers, body = push_manifest(reg, repo, reference,
                                          image_manifest(config, [layer]))
    assert status == 201, "push refused: %d %s" % (status, body)
    return headers["Docker-Content-Digest"], (config, layer)


def blob_path(reg: Registry, digest):
    """Where the store files that digest — the CAS is keyed by ALGORITHM."""
    alg, hexpart = digest.split(":", 1)
    return reg.store / "blobs" / alg / hexpart[:2] / hexpart


def manifest_path(reg: Registry, repo, digest):
    alg, hexpart = digest.split(":", 1)
    return reg.store / "repos" / repo / "manifests" / alg / hexpart


def delete_manifest(reg: Registry, repo, digest):
    status, _, body = req("%s/v2/%s/manifests/%s" % (reg.base, repo, digest),
                          method="DELETE")
    assert status == 202, "delete refused: %d %s" % (status, body)


# ---- success: the orphan goes, the shared layer stays -------------------- #

def test_gc_reclaims_only_what_the_delete_orphaned(registry: Registry):
    """The delete's own config blob is reclaimed; the shared layer is not.

    Two repositories hold the same layer by content, which is the exact case
    a request handler cannot decide — it sees one repository at a time.
    """
    gone, (gone_config, shared) = push_image(registry, "lab/app", "v1",
                                             b'{"id":"gone"}', SHARED)
    kept, (kept_config, _) = push_image(registry, "lab/other", "v1",
                                        b'{"id":"kept"}', SHARED)
    delete_manifest(registry, "lab/app", gone)

    report = gc(registry.store, "--grace", "0")

    assert report["blobs_swept"] == 1
    assert not blob_path(registry, gone_config).exists()
    assert blob_path(registry, shared).exists()
    assert blob_path(registry, kept_config).exists()
    assert manifest_path(registry, "lab/other", kept).exists()


def test_sha512_objects_are_marked_and_swept_under_their_own_algorithm(
        registry: Registry):
    """The store is keyed by algorithm, so BOTH walks have to visit sha512.

    A mark walk that only opened `manifests/sha256` would find the live
    image's blobs unreferenced and delete them; a sweep that only scanned
    `blobs/sha256` would leave the orphan behind forever. A repository
    holding nothing but sha512 objects separates the two failures, because
    each one shows up on a different side of the same report.

    The manifests go in BY DIGEST: a push by tag has no client-supplied
    digest to be checked against and is therefore filed under the algorithm
    the registry itself produces.
    """
    live_config = push_blob(registry, "lab/s512", b'{"id":"live"}',
                            alg="sha512")
    shared = push_blob(registry, "lab/s512", SHARED, alg="sha512")
    gone_config = push_blob(registry, "lab/s512", b'{"id":"gone"}',
                            alg="sha512")

    live = image_manifest(live_config, [shared])
    gone = image_manifest(gone_config, [shared])
    live_digest = digest_of(json.dumps(live).encode(), "sha512")
    gone_digest = digest_of(json.dumps(gone).encode(), "sha512")
    for manifest, digest in ((live, live_digest), (gone, gone_digest)):
        status, headers, body = push_manifest(registry, "lab/s512", digest,
                                              manifest)
        assert status == 201, "push refused: %d %s" % (status, body)
        assert headers["Docker-Content-Digest"] == digest

    delete_manifest(registry, "lab/s512", gone_digest)

    report = gc(registry.store, "--grace", "0")

    assert report["blobs_swept"] == 1
    assert not blob_path(registry, gone_config).exists()
    assert blob_path(registry, live_config).exists()
    assert blob_path(registry, shared).exists()
    assert manifest_path(registry, "lab/s512", live_digest).exists()


def test_the_surviving_image_is_still_servable_after_a_sweep(
        registry: Registry):
    """Reclaiming space must not cost the registry an image it still holds.

    A GC that leaves the store technically tidy but the pull path broken has
    done the one thing it was never allowed to do.
    """
    digest, (config, layer) = push_image(registry, "lab/app", "v1", CONFIG,
                                         SHARED)
    push_blob(registry, "lab/app", b"an upload nobody ever named\n")

    gc(registry.store, "--grace", "0")

    assert req("%s/v2/lab/app/manifests/v1" % registry.base)[0] == 200
    assert req("%s/v2/lab/app/manifests/%s" % (registry.base, digest))[0] == 200
    for blob in (config, layer):
        assert req("%s/v2/lab/app/blobs/%s" % (registry.base, blob))[0] == 200


def test_stale_layer_marks_are_dropped(registry: Registry):
    """A DELETE leaves the per-repo reference marks standing; GC clears them."""
    digest, (config, layer) = push_image(registry, "lab/app", "v1", CONFIG,
                                         SHARED)
    marks = registry.store / "repos" / "lab" / "app" / "layers"
    assert {p.name for p in marks.iterdir()} == {config.split(":")[1],
                                                 layer.split(":")[1]}
    delete_manifest(registry, "lab/app", digest)

    report = gc(registry.store, "--grace", "0")

    assert report["layer_marks_dropped"] == 2
    assert list(marks.iterdir()) == []


def test_untagged_manifests_and_tags_are_never_swept(registry: Registry):
    """An untagged manifest is not garbage — every referrer is one.

    Sweeping by reachability-from-tags is what a signing store cannot
    survive, so the pass removes no manifest at all: that stays an explicit
    DELETE, and the tool only cleans up after one.
    """
    config = push_blob(registry, "lab/app", CONFIG)
    body = image_manifest(config, [])
    digest = digest_of(json.dumps(body).encode())
    assert push_manifest(registry, "lab/app", digest, body)[0] == 201

    report = gc(registry.store, "--grace", "0")

    assert report["manifests"] == 1
    assert manifest_path(registry, "lab/app", digest).exists()
    assert blob_path(registry, config).exists()
    assert req("%s/v2/lab/app/manifests/%s" % (registry.base, digest))[0] == 200


def test_a_dangling_referrer_descriptor_is_dropped(registry: Registry):
    """A descriptor whose referrer is gone describes an edge nothing follows.

    The manifest file is removed underneath the registry on purpose: that is
    the state a crash between the two unlinks of a DELETE leaves, and the
    hole this sweep exists to close.
    """
    subject, _ = push_image(registry, "lab/app", "v1", CONFIG, SHARED)
    config = push_blob(registry, "lab/app", b'{"sbom":true}')
    artifact = image_manifest(config, [])
    artifact["subject"] = {"mediaType": artifact["mediaType"],
                           "digest": subject, "size": 0}
    referrer = digest_of(json.dumps(artifact).encode())
    assert push_manifest(registry, "lab/app", referrer, artifact)[0] == 201
    manifest_path(registry, "lab/app", referrer).unlink()

    report = gc(registry.store, "--grace", "0")

    assert report["referrers_dropped"] == 1
    descriptors = (registry.store / "repos" / "lab" / "app" / "referrers"
                   / "sha256" / subject.split(":")[1])
    assert not descriptors.exists()


# ---- the grace window and --dry-run -------------------------------------- #

def test_grace_protects_a_blob_whose_manifest_has_not_landed(
        registry: Registry):
    """Between a blob sealing and its manifest arriving it looks like garbage.

    Every push spends time in that state, so the default window — not the
    operator's attention — is what keeps a concurrent push from being
    sabotaged by a cron entry.
    """
    inflight = push_blob(registry, "lab/app", b"the first layer of a push\n")

    report = gc(registry.store)

    assert report["blobs_swept"] == 0 and report["blobs_within_grace"] == 1
    assert blob_path(registry, inflight).exists()

    report = gc(registry.store, "--grace", "0")

    assert report["blobs_swept"] == 1
    assert not blob_path(registry, inflight).exists()


def test_dry_run_reports_exactly_what_a_real_pass_would_remove(
        registry: Registry):
    """The rehearsal has to be worth trusting, or nobody rehearses."""
    orphan = push_blob(registry, "lab/app", b"an upload nobody ever named\n")

    dry = gc(registry.store, "--grace", "0", "--dry-run")

    assert dry["dry_run"] is True and dry["blobs_swept"] == 1
    assert blob_path(registry, orphan).exists()

    real = gc(registry.store, "--grace", "0")

    assert real["dry_run"] is False
    assert (real["blobs_swept"], real["bytes_reclaimed"]) == (
        dry["blobs_swept"], dry["bytes_reclaimed"])
    assert not blob_path(registry, orphan).exists()


# ---- error ---------------------------------------------------------------- #

def test_a_directory_that_is_not_a_store_is_refused(registry: Registry,
                                                    tmp_path):
    """`brixoci gc /` is a plausible typo, and it must not be a destructive one."""
    decoy = tmp_path / "home"
    (decoy / "docs").mkdir(parents=True)
    (decoy / "docs" / ("%s" % HEX)).write_text("not a blob\n")

    stderr = gc(decoy, expect=2)

    assert "not an OCI registry store" in stderr
    assert (decoy / "docs" / HEX).exists()


def test_the_store_parent_is_not_a_store(registry: Registry):
    """One level up holds the store — and is not one, which is the point."""
    _, (config, _) = push_image(registry, "lab/app", "v1", CONFIG, SHARED)

    stderr = gc(registry.store.parent, expect=2)

    assert "not an OCI registry store" in stderr
    assert blob_path(registry, config).exists()


def test_gc_takes_exactly_one_store(registry: Registry):
    proc = subprocess.run([BRIXOCI, "gc"], capture_output=True, text=True,
                          timeout=60)

    assert proc.returncode == 2
    assert "exactly one store directory" in proc.stderr


# ---- security negatives --------------------------------------------------- #

def test_a_symlinked_fanout_cannot_walk_the_sweep_out_of_the_store(
        registry: Registry, tmp_path):
    """A link planted in the store must not turn GC into a delete anywhere.

    The fan-out directory name is not content-addressed, so it is the one
    component an attacker with write access to the store could replace — the
    walk refuses to follow it because it stats with lstat, not stat.
    """
    push_image(registry, "lab/app", "v1", CONFIG, SHARED)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / HEX
    victim.write_text("somebody else's file\n")
    os.symlink(outside, registry.store / "blobs" / "sha256" / "zz")

    gc(registry.store, "--grace", "0")

    assert victim.exists()


def test_a_symlinked_repository_cannot_widen_the_mark_walk(
        registry: Registry, tmp_path):
    """The same refusal on the repos/ side, where the walk recurses.

    Following a link here would be worse than a stray delete: it would mark
    from manifests outside the store, and a mark set that answers for the
    wrong store is how live blobs get swept.
    """
    _, (config, layer) = push_image(registry, "lab/app", "v1", CONFIG, SHARED)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "manifests" / "sha256").mkdir(parents=True)
    (elsewhere / "manifests" / "sha256" / HEX).write_text("{}")
    os.symlink(elsewhere, registry.store / "repos" / "linked")

    report = gc(registry.store, "--grace", "0")

    assert report["repositories"] == 1                 # lab/app, and only it
    assert (elsewhere / "manifests" / "sha256" / HEX).exists()
    assert blob_path(registry, config).exists()
    assert blob_path(registry, layer).exists()


def test_names_that_are_not_digests_are_left_alone(registry: Registry):
    """The tool unlinks only names it has re-parsed as a sha256 digest.

    Anything else in the store — a sidecar, an operator's note, a partial
    file from something else entirely — is not this pass's to judge.
    """
    digest, (config, _) = push_image(registry, "lab/app", "v1", CONFIG, SHARED)
    fanout = blob_path(registry, config).parent
    (fanout / "README").write_text("operator note\n")
    (fanout / (config.split(":")[1] + ".partial")).write_text("half a blob\n")
    sidecar = manifest_path(registry, "lab/app", digest).with_suffix(".meta")
    delete_manifest(registry, "lab/app", digest)

    report = gc(registry.store, "--grace", "0")

    assert report["blobs_swept"] == 2                  # config + layer only
    assert (fanout / "README").exists()
    assert (fanout / (config.split(":")[1] + ".partial")).exists()
    assert not sidecar.exists()                        # the DELETE took it
