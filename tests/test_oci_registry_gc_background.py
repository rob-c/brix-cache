# tests/test_oci_registry_gc_background.py — the in-proxy sweep (D15.5).
#
# The D15.3 lane next door proves the mark-and-sweep KERNEL is right. This
# one proves the only thing the server adds on top of it: that the pass runs
# without anybody asking. So every assertion here is about the timer —
# something must be reclaimed with no tool invoked anywhere in the test, the
# grace window must still hold when the caller is a background thread rather
# than an operator at a shell, and the two configurations that would make the
# timer dangerous must not start a server at all.
#
# Ports: the oci_registry block, nginx front at 14156 (14150–14155 are the
# push, referrers and `brixoci gc` lanes).
import json
import os
import time
from pathlib import Path

import pytest

from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from oci.mirror_lane import mirror_spec
from oci.registry_lane import (
    Registry, digest_of, image_manifest, push_blob, push_manifest, req,
    registry_spec, start_registry,
)

NGINX_PORT = 14156

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-registry-gc-background"),
]

CONFIG = b'{"architecture":"amd64","os":"linux"}'
SHARED = b"a layer two images legitimately share\n" * 8

#: How long a sweep on a 1 s timer is allowed to take before the lane calls
#: it a failure. The pass itself walks a handful of files; the slack is for a
#: loaded host and for the thread pool picking the task up.
SWEEP_TIMEOUT = 30.0


def wait_for(predicate, *, timeout=SWEEP_TIMEOUT, what="condition"):
    """Poll until `predicate` holds; returns how long that took."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("%s did not hold within %.0fs" % (what, timeout))


def blob_path(reg: Registry, digest) -> Path:
    alg, hexpart = digest.split(":", 1)
    return reg.store / "blobs" / alg / hexpart[:2] / hexpart


def error_log(reg: Registry) -> str:
    path = Path(reg.endpoint.prefix, "logs", "error.log")
    return path.read_text(encoding="utf-8", errors="replace") \
        if path.exists() else ""


def push_image(reg: Registry, repo, reference, config_bytes, layer_bytes):
    """Push one complete image; returns (manifest digest, blob digests)."""
    config = push_blob(reg, repo, config_bytes)
    layer = push_blob(reg, repo, layer_bytes)
    status, headers, body = push_manifest(reg, repo, reference,
                                          image_manifest(config, [layer]))
    assert status == 201, "push refused: %d %s" % (status, body)
    return headers["Docker-Content-Digest"], (config, layer)


def delete_manifest(reg: Registry, repo, digest):
    status, _, body = req("%s/v2/%s/manifests/%s" % (reg.base, repo, digest),
                          method="DELETE")
    assert status == 202, "delete refused: %d %s" % (status, body)


@pytest.fixture
def swept(lifecycle, tmp_path) -> Registry:
    """A registry that sweeps every second and keeps nothing on grace."""
    return start_registry(
        lifecycle, "lc-oci-gc-bg", NGINX_PORT, tmp_path / "store",
        extra_lines="brix_oci_gc_interval 1s; brix_oci_gc_grace 0;")


# ---- success: the timer reclaims, with no tool in the picture ------------ #

def test_the_timer_reclaims_what_a_delete_orphaned(swept: Registry):
    """A DELETE, then nothing but waiting: the orphan goes on its own.

    The shared layer is what says the background caller runs the same
    whole-store kernel and not some per-repository shortcut — no request
    handler can see that a second repository still holds it.
    """
    gone, (gone_config, shared) = push_image(swept, "lab/app", "v1",
                                             b'{"id":"gone"}', SHARED)
    kept, (kept_config, _) = push_image(swept, "lab/other", "v1",
                                        b'{"id":"kept"}', SHARED)
    delete_manifest(swept, "lab/app", gone)

    wait_for(lambda: not blob_path(swept, gone_config).exists(),
             what="the orphaned config blob")

    assert blob_path(swept, shared).exists()
    assert blob_path(swept, kept_config).exists()
    assert "registry gc over" in error_log(swept)


def test_the_surviving_image_is_still_servable_after_a_background_sweep(
        swept: Registry):
    """Reclaiming behind the server's back must not cost it a live image.

    The pass runs on a thread while the same worker keeps answering, so this
    is the leg where an over-eager sweep would show up as a 404 on a pull
    rather than as a missing file somebody notices later.
    """
    digest, (config, layer) = push_image(swept, "lab/app", "v1", CONFIG,
                                         SHARED)
    orphan = push_blob(swept, "lab/app", b"an upload nobody ever named\n")

    wait_for(lambda: not blob_path(swept, orphan).exists(),
             what="the unreferenced blob")

    assert req("%s/v2/lab/app/manifests/v1" % swept.base)[0] == 200
    assert req("%s/v2/lab/app/manifests/%s" % (swept.base, digest))[0] == 200
    for blob in (config, layer):
        assert req("%s/v2/lab/app/blobs/%s" % (swept.base, blob))[0] == 200


def test_a_sweep_leaves_the_manifests_alone(swept: Registry):
    """Untagged is not garbage — and the timer gets no say the tool lacks."""
    config = push_blob(swept, "lab/app", CONFIG)
    body = image_manifest(config, [])
    digest = digest_of(json.dumps(body).encode())
    assert push_manifest(swept, "lab/app", digest, body)[0] == 201
    orphan = push_blob(swept, "lab/app", b"reclaim me\n")

    wait_for(lambda: not blob_path(swept, orphan).exists(),
             what="the unreferenced blob")

    assert req("%s/v2/lab/app/manifests/%s" % (swept.base, digest))[0] == 200
    assert blob_path(swept, config).exists()


# ---- security-negative: the window that makes an unattended sweep safe --- #

def test_the_grace_window_protects_a_push_still_in_flight(lifecycle, tmp_path):
    """A blob sealed but not yet named by a manifest survives every pass.

    This is the whole safety argument for running unattended: between a
    client's last PUT and its manifest PUT the blob IS unreferenced, and a
    sweeper that took that literally would corrupt concurrent pushes on a
    busy registry. Both blobs here are unreferenced and the only difference
    between them is age, so the lane cannot pass by the pass never running:
    the backdated one has to go before the young one is checked.
    """
    reg = start_registry(lifecycle, "lc-oci-gc-bg-grace", NGINX_PORT + 1,
                         tmp_path / "store",
                         extra_lines="brix_oci_gc_interval 1s;")

    in_flight = push_blob(reg, "lab/app", b"the layer whose manifest is late\n")
    settled = push_blob(reg, "lab/app", b"a blob from an hour ago\n")
    old = time.time() - 2 * 3600
    os.utime(blob_path(reg, settled), (old, old))

    wait_for(lambda: not blob_path(reg, settled).exists(),
             what="the blob outside the default grace window")

    assert blob_path(reg, in_flight).exists(), \
        "the sweep took a blob whose manifest had not landed yet"


def test_a_mirror_location_may_not_arm_a_store_sweep(lifecycle, tmp_path):
    """A mirror's objects belong to the cache tier, not to a store sweep.

    Unlinking them behind the tier's back would leave it serving index
    entries for files that are gone, so the config never starts.
    """
    spec = mirror_spec("lc-oci-gc-bg-mirror", SHARED_PARSE_PLACEHOLDER_PORT,
                       SHARED_PARSE_PLACEHOLDER_PORT, tmp_path / "cache",
                       extra_lines="brix_oci_gc_interval 5s;")
    lifecycle.register(spec)
    lifecycle.launcher.render_nginx(spec)
    res = lifecycle.launcher.nginx_test(spec, check=False)

    output = res.stdout + res.stderr
    assert res.returncode != 0, output
    assert "brix_oci_gc_interval" in output
    assert "pull-through mirror" in output


# ---- error: a cadence that is not maintenance --------------------------- #

def test_a_sub_second_interval_is_refused_at_parse_time(lifecycle, tmp_path):
    """Below a second the passes overlap into a busy walk of the disk."""
    spec = registry_spec("lc-oci-gc-bg-busy", SHARED_PARSE_PLACEHOLDER_PORT,
                         tmp_path / "store",
                         extra_lines="brix_oci_gc_interval 500ms;")
    lifecycle.register(spec)
    lifecycle.launcher.render_nginx(spec)
    res = lifecycle.launcher.nginx_test(spec, check=False)

    output = res.stdout + res.stderr
    assert res.returncode != 0, output
    assert "brix_oci_gc_interval" in output
    assert "busy loop" in output
