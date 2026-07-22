"""No-root verification of upload staging temp-file modes (stage-private / publish-intended).

A staged upload is written to a temp file that is later atomically renamed onto the namespace
object. Because rename preserves the temp's mode, the temp mode IS the final served mode — so a
naive "make the temp 0600" would ship every object 0600 and break VO-shared impersonated reads.
The fix keeps the temp PRIVATE (0600) during the write (a peer mapped uid cannot read an
in-progress upload) and restores the client-intended mode (0644) at commit.

This test drives a real WebDAV write server (impersonation off) over GSI and stats the on-disk
artifacts:
  * a completed PUT commits at 0644 (publish-intended — NOT over-tightened to 0600);
  * an in-flight resumable-PUT partial is 0600 (stage-private) while incomplete, then the
    completed object is 0644.

Run: PYTHONPATH=tests pytest tests/test_mu_stage_modes.py -v   (no root needed)
"""
import os
import stat

import pytest
import requests

from mu_authz_lib import creds, ports, principals
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-mu-stage-modes")]


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _spec():
    """A single GSI WebDAV write node, driven by the registry lifecycle harness.

    Its export is the shared MU data root so the on-disk mode assertions inspect
    the same tree the server writes; the PKI paths are the cast built by the
    ``cast`` fixture (deterministic locations, populated before the server boots).
    """
    return NginxInstanceSpec(
        name="lc-mu-stage-webdav",
        template="nginx_mu_stage_modes_webdav.conf",
        protocol="https",
        readiness="webdav",
        data_root=ports.MU.DATA_ROOT,
        template_values={
            "CERT": os.path.join(ports.MU.PKI_DIR, "server", "hostcert.pem"),
            "KEY": os.path.join(ports.MU.PKI_DIR, "server", "hostkey.pem"),
            "CA": os.path.join(ports.MU.CA_DIR, "ca.pem"),
        },
        reason="MU WebDAV write node: staging temp-file mode verification.",
    )


@pytest.fixture(scope="module")
def cast():
    """Build the MU PKI/principal cast once for the module (idempotent)."""
    principals.build_cast()


@pytest.fixture
def stage_env(lifecycle, cast):
    os.makedirs(os.path.join(ports.MU.DATA_ROOT, "stage"), exist_ok=True)
    return lifecycle.start(_spec())


@pytest.fixture(scope="module")
def alice_proxy(cast):
    cert = os.path.join(ports.MU.PKI_DIR, "user", "alice_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", "alice_userkey.pem")
    return creds.gen_gsi_proxy(cert, key, "stage_alice")


def test_completed_put_commits_at_client_mode(stage_env, alice_proxy):
    """A completed PUT publishes the object at its client-intended 0644 — the temp's private
    0600 must NOT leak onto the committed namespace file (that would break VO-shared reads)."""
    url = stage_env.url
    dest = os.path.join(stage_env.data_root, "stage", "committed.bin")
    if os.path.exists(dest):
        os.remove(dest)
    r = requests.put(url + "/stage/committed.bin", data=b"C" * 4096,
                     cert=alice_proxy, verify=False, timeout=30)
    assert r.status_code in (200, 201, 204), f"PUT failed: {r.status_code} {r.text[:200]}"
    assert os.path.exists(dest), "committed object missing on disk"
    assert _mode(dest) == 0o644, (
        f"committed object mode {oct(_mode(dest))} != 0o644 — the private staging mode leaked "
        f"onto the served file (would break impersonated cross-user reads)")


def test_inflight_resume_partial_is_private_then_publishes(stage_env, alice_proxy):
    """An in-flight resumable-PUT partial is 0600 (a peer mapped uid cannot read the in-progress
    upload); once completed the object is published at 0644."""
    url = stage_env.url
    stage_dir = os.path.join(stage_env.data_root, "stage")
    final = os.path.join(stage_dir, "resumable.bin")
    if os.path.exists(final):
        os.remove(final)
    # Clear any leftover resume partial from a prior interrupted run (identity-keyed
    # name); otherwise a stale offset yields a 409 resume conflict.
    for fn in os.listdir(stage_dir):
        if ".xrdresume." in fn:
            os.remove(os.path.join(stage_dir, fn))
    payload = b"R" * 4096

    # First chunk: bytes 0-2047/4096 — incomplete, so the server holds a persistent partial.
    r1 = requests.put(url + "/stage/resumable.bin", data=payload[:2048],
                      headers={"Content-Range": "bytes 0-2047/4096"},
                      cert=alice_proxy, verify=False, timeout=30)
    assert r1.status_code in (200, 201, 202, 204, 308), \
        f"partial PUT failed: {r1.status_code} {r1.text[:200]}"
    assert not os.path.exists(final), "object committed before the upload completed"

    # The partial lives in the stage dir (the export, no separate stage dir configured),
    # identity-keyed with a ".xrdresume." name. Scope to the stage dir + match by name so a
    # same-sized sibling elsewhere in the export cannot be mistaken for it.
    inflight = [os.path.join(stage_dir, fn) for fn in os.listdir(stage_dir)
                if ".xrdresume." in fn]
    assert inflight, f"could not locate the in-flight resume partial in {stage_dir}"
    for p in inflight:
        assert _mode(p) == 0o600, (
            f"in-flight resume partial {p} mode {oct(_mode(p))} != 0o600 — a peer mapped uid "
            f"could read the in-progress upload")

    # Second chunk completes the upload → atomic commit at the client-intended mode.
    r2 = requests.put(url + "/stage/resumable.bin", data=payload[2048:],
                      headers={"Content-Range": "bytes 2048-4095/4096"},
                      cert=alice_proxy, verify=False, timeout=30)
    assert r2.status_code in (200, 201, 204), \
        f"completing PUT failed: {r2.status_code} {r2.text[:200]}"
    assert os.path.exists(final), "object not committed after completion"
    assert _mode(final) == 0o644, (
        f"completed resumable object mode {oct(_mode(final))} != 0o644 (publish-intended failed)")
