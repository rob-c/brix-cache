# tests/test_oci_mirror_podman_pull.py — the pull-through mirror judged by a
# REAL registry client instead of by urllib (phase-104 D3.3).
#
# Every other mirror lane asserts against requests this repository wrote. That
# proves the mirror does what we believe the spec says; it does not prove the
# mirror is usable. This one hands the surface to podman — which negotiates its
# own Accept set, walks the manifest to the config blob and every layer, checks
# each digest itself, and unpacks the tars — and asks a question no hand-rolled
# request can: does an image come out the other side, and is it the SAME image
# the upstream holds?
#
# Ports: 14120 mock registry, 14121 the nginx front (one at a time — every
# mirror fixture here is function-scoped so "cold" means cold).
#
# Three legs, per the standing rule:
#   success  — cold pull matches the upstream's manifest digest, then the warm
#              pull succeeds with the upstream's kill switch thrown;
#   error    — upstream unreachable and nothing held: podman gets our status
#              and stops, in seconds, rather than hanging on a stalled fill;
#   security — podman push at a read-only mirror is refused and audited.
#
# Plus a weekly-tier variant against real DockerHub, opt-in via
# $BRIX_OCI_LIVE_DOCKERHUB (SKIP, never FAIL, on a box with no internet).
import hashlib
import os
import subprocess
import time
from pathlib import Path

import pytest

from brix_suite.registry import NginxInstanceSpec
from cmdscripts.container_runtime import container_runtime
from oci.mirror_lane import (
    Mirror, ctl_post, error_log, get, hits, reset, spawn_mock, start_mirror,
    stop_mocks,
)
from settings import HOST

MOCK_PORT = 14120
NGINX_PORT = 14121

#: Accept set wide enough that the mock answers with the image manifest itself
#: rather than an index — the digest podman reports for a single-arch pull.
ACCEPT = ("application/vnd.oci.image.manifest.v1+json, "
          "application/vnd.docker.distribution.manifest.v2+json")

#: A pull of three mock blobs over loopback is a sub-second operation; the
#: budget exists to separate "failed" from "hung", so it is generous.
PULL_BUDGET_S = 60

#: podman, or nothing. The lane pulls through a CLEARTEXT registry, which
#: podman is told to trust per invocation (--tls-verify=false); docker only
#: takes that as daemon configuration, and a test does not get to rewrite
#: /etc/docker/daemon.json. Narrowing the probe is what keeps the lane running
#: on a host that has both engines installed.
RUNTIME = container_runtime(("podman",))

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-mirror-podman"),
    pytest.mark.timeout(300),
    pytest.mark.skipif(RUNTIME is None,
                       reason="no usable podman on this host"),
]


@pytest.fixture(scope="module")
def upstream():
    proc, base = spawn_mock(MOCK_PORT)
    yield base
    stop_mocks(proc)


@pytest.fixture
def mirror(lifecycle, upstream, tmp_path) -> Mirror:
    """A cold mirror whose tag manifests stay fresh for the whole test.

    The TTL is long on purpose: a warm-path assertion that counts upstream
    requests must not be racing a revalidation window.
    """
    reset(upstream)
    return start_mirror(lifecycle, "lc-oci-podman", NGINX_PORT, MOCK_PORT,
                        tmp_path / "cache", manifest_ttl="600s")


@pytest.fixture
def images():
    """Image references to remove when the test ends.

    A pull leaves bytes in the caller's own container storage, and a lane that
    leaves them there poisons the next run's "cold" leg (and quietly grows a
    developer's disk). Removal is unconditional and its failure is not: an
    image the test never managed to pull is exactly the case where the cleanup
    has nothing to do.
    """
    refs = []
    yield refs
    for ref in refs:
        run_runtime("rmi", "-f", ref, check=False)


def run_runtime(*argv, check=True, timeout=PULL_BUDGET_S):
    """One container-runtime command, captured."""
    proc = subprocess.run([RUNTIME, *argv], capture_output=True, text=True,
                          timeout=timeout)
    if check and proc.returncode != 0:
        raise AssertionError("%s %s failed (%d)\n%s%s"
                             % (RUNTIME, " ".join(argv), proc.returncode,
                                proc.stdout, proc.stderr))
    return proc


def pull(ref, *extra, check=True):
    return run_runtime("pull", "--tls-verify=false", *extra, ref, check=check)


def ref_for(mirror: Mirror, repo_tag):
    """`host:port/repo:tag` — what a registry client is handed."""
    return "%s/%s" % (mirror.base.split("://", 1)[1], repo_tag)


def upstream_digest(upstream_base, repo, tag):
    """The manifest digest as the ORIGIN computes it.

    Deriving the expectation from the mirror would only prove the mirror
    agrees with itself; the whole point of an oracle lane is a second source.
    """
    _, _, body = get("%s/v2/%s/manifests/%s" % (upstream_base, repo, tag),
                     headers={"Accept": ACCEPT})
    return "sha256:" + hashlib.sha256(body).hexdigest()


def test_cold_pull_matches_origin_digest__warm_pull_needs_no_upstream(
        mirror: Mirror, upstream, images):
    """The image podman assembles is the origin's, and the second one is free."""
    want = upstream_digest(upstream, "lab/app", "v1")
    reset(upstream)                       # the digest probe is not the subject
    ref = ref_for(mirror, "lab/app:v1")
    images.append(ref)

    pull(ref)

    got = run_runtime("image", "inspect", ref, "--format", "{{.Digest}}")
    assert got.stdout.strip() == want
    assert [h["path"] for h in hits(upstream, method="GET")] != []

    # Kill switch: every upstream answer from here on is a 500. A warm pull
    # that touches the origin at all now FAILS rather than quietly costing a
    # round trip, which is the only way to prove the cache carried it.
    reset(upstream)
    ctl_post(upstream, "fault", {"kind": "http500", "persist": True})
    run_runtime("rmi", "-f", ref)
    pull(ref)

    assert hits(upstream) == []
    assert run_runtime("image", "inspect", ref,
                       "--format", "{{.Digest}}").stdout.strip() == want


def test_cold_pull_with_upstream_down_fails_promptly(mirror: Mirror, upstream,
                                                     images):
    """Nothing held, origin refusing: podman is told, quickly.

    DRIFT vs §D3.3, which pins "our 502 envelope is what podman saw": an
    upstream 5xx is not a definitive answer about the object, so the fill
    plane's never-drop policy answers a cold miss with a keep-alive 504 +
    Retry-After instead (see §D2.7). What the leg is really about survives the
    difference — podman gets a STATUS and exits, instead of hanging on a fill
    that will never complete.
    """
    ctl_post(upstream, "fault", {"kind": "http500", "persist": True})
    ref = ref_for(mirror, "lab/app:v2")
    images.append(ref)

    started = time.monotonic()
    # podman < 5 has no `pull --retry`; the flag only tightens the budget, so
    # probe once and drop it where unsupported (the 504 verdict is the same).
    proc = pull(ref, "--retry", "0", check=False)
    if proc.returncode == 125 and "unknown flag: --retry" in proc.stderr:
        started = time.monotonic()
        proc = pull(ref, check=False)
    elapsed = time.monotonic() - started

    assert proc.returncode != 0
    assert "504" in proc.stderr
    assert elapsed < PULL_BUDGET_S


def test_push_at_the_mirror_is_refused_and_audited(mirror: Mirror, upstream,
                                                   images):
    """A real client's push walks into the same 405 a hand-made POST does.

    Worth its own leg because podman does not start with the POST: it HEADs
    each blob first, and a mirror that answered those from cache and only then
    refused would leak which layers a site holds before saying no.
    """
    src = ref_for(mirror, "lab/app:v1")
    dst = ref_for(mirror, "lab/pushed:v1")
    images.append(src)
    pull(src)

    proc = run_runtime("push", "--tls-verify=false", src,
                       "docker://" + dst, check=False)

    assert proc.returncode != 0
    assert "unsupported" in proc.stderr.lower()
    assert "signal=ocipush" in error_log(mirror.endpoint)


# --- weekly tier: the same flow against a registry we do not control --------
#
# Everything above runs against a mock, so it proves the mirror is consistent
# with our reading of the spec. Only a real registry proves the reading. This
# is opt-in rather than internet-detected: a lab firewall that black-holes
# outbound 443 turns "detect and run" into a five-minute timeout.

LIVE_UPSTREAM = "https://registry-1.docker.io"
LIVE_IMAGE = "library/alpine:latest"


@pytest.fixture
def live_mirror(lifecycle, tmp_path) -> Mirror:
    """A mirror pointed at real DockerHub: TLS upstream, real token dance."""
    cache = tmp_path / "cache-live"
    cache.mkdir(parents=True, exist_ok=True)   # the merge stats it, and refuses
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-oci-podman-live",
        template="oci_mirror_live.conf",
        port=NGINX_PORT,
        protocol="http",
        readiness="tcp",
        template_values={
            "BIND_HOST": HOST,
            "UPSTREAM": LIVE_UPSTREAM,
            "CACHE_DIR": str(cache),
            "MANIFEST_TTL": "600s",
        },
        reason="phase-104 D3.3 live DockerHub oracle",
    ))
    return Mirror("http://%s:%d" % (endpoint.host, endpoint.port), endpoint,
                  cache)


@pytest.mark.slow
@pytest.mark.skipif(os.environ.get("BRIX_OCI_LIVE_DOCKERHUB") != "1",
                    reason="set BRIX_OCI_LIVE_DOCKERHUB=1 to pull from "
                           "real DockerHub through the mirror")
def test_live_dockerhub_alpine_pull(live_mirror: Mirror, images):
    """alpine:latest, through us, from the registry everyone actually uses."""
    ref = ref_for(live_mirror, LIVE_IMAGE)
    images.append(ref)

    pull(ref, check=True)

    digest = run_runtime("image", "inspect", ref,
                         "--format", "{{.Digest}}").stdout.strip()
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
