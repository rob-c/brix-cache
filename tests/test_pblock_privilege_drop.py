"""pblock storage-backend privilege-drop e2e (host-root).

pblock writes each object's blob block-files and the SQLite catalog.db as the
nginx *worker* uid — it has no impersonation broker and never chowns (per-principal
ownership is synthetic, recorded only in the catalog). So a worker that runs as
root would create every blob/dir/catalog.db owned by root: a privilege-escape
foothold letting a client's uploaded bytes land as root on disk.

The pblock driver defends against this by permanently dropping a root worker to an
unprivileged account (the `user <acct>;` account when non-root, else "nobody")
BEFORE it creates any on-disk state. These tests launch the real nginx binary as
root with an explicit `user root;` worker (so the drop path is actually taken) and
assert:

  * a WebDAV PUT over a pblock:// backend lands blobs + catalog.db owned by the
    dropped unprivileged account, never root (the security guarantee);
  * a large object stripes into multiple block files, all unprivileged;
  * if the dropped worker cannot write the export, the request fails closed and NO
    file is created — never a silent fallback that writes as root.

This can ONLY be exercised as real root (a root master forking a root worker that
the driver then drops). Off a root host every test skips cleanly.

Run privileged:  sudo -E env PYTHONPATH=tests pytest tests/test_pblock_privilege_drop.py -v
"""
from __future__ import annotations

import os
import pwd
import shutil

import pytest
import requests

import settings
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

import impersonation_gridmap_helpers as H

pytestmark = [
    pytest.mark.privileged,
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="pblock root-worker privilege-drop needs a real root "
                              "master + worker"),
]

BIND = "127.0.0.1"
BASE = os.path.join(settings.TEST_ROOT, "pbdrop")
NOBODY_UID = pwd.getpwnam("nobody").pw_uid


@pytest.fixture(scope="module")
def harness():
    os.makedirs(BASE, exist_ok=True)
    os.chmod(BASE, 0o755)
    H.make_world_traversable(BASE)
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()
        shutil.rmtree(BASE, ignore_errors=True)


def _mkexport(name: str, mode: int, owner_uid: int | None = None) -> str:
    """Create <BASE>/<name>/export with the given mode (and optional owner) plus a
    throwaway harness data_root, and return the export path."""
    root = os.path.join(BASE, name)
    export = os.path.join(root, "export")
    os.makedirs(export, exist_ok=True)
    os.makedirs(os.path.join(root, "harness_data"), exist_ok=True)
    if owner_uid is not None:
        os.chown(export, owner_uid, owner_uid)
    os.chmod(export, mode)
    H.make_world_traversable(export)
    return export


def _start(harness, name: str, export: str, block_size: str = "64m"):
    """Launch a `user root;` pblock/webdav instance; return (base_url, prefix).

    data_root is a throwaway dir so the harness's root-mode 0777 chmod lands there,
    not on our export (whose permissions each test controls)."""
    ep = harness.start(NginxInstanceSpec(
        name=name,
        template="nginx_pblock_privdrop_webdav.conf",
        protocol="http",
        data_root=os.path.join(BASE, name, "harness_data"),
        readiness="tcp",
        template_values={"EXPORT": export, "BLOCK_SIZE": block_size},
    ))
    # The worker drops to nobody, so its client-body temp dir (created root-owned
    # by the master) must be writable by that account for spooled (large) bodies —
    # the operational analogue of making the export writable. A production deploy
    # sets `user <acct>;` so nginx owns these dirs to the worker from the start.
    os.chmod(os.path.join(ep.prefix, "tmp"), 0o777)
    return f"http://{BIND}:{ep.port}", ep.prefix


def _block_files(export: str):
    """Every pblock block file (numeric basename under <export>/data/.../<blobid>/)
    with its stat, i.e. the striped object data on disk."""
    out = []
    for dirpath, _dirs, files in os.walk(os.path.join(export, "data")):
        for f in files:
            if f.isdigit():
                p = os.path.join(dirpath, f)
                out.append((p, os.stat(p)))
    return out


def _catalog_files(export: str):
    return [os.path.join(export, n) for n in os.listdir(export)
            if n.startswith("catalog.db")]


def _assert_unprivileged(st: os.stat_result, where: str):
    assert st.st_uid != 0, f"{where} must never be owned by root (uid 0)"
    assert st.st_gid != 0, f"{where} must never be group-owned by root (gid 0)"
    assert st.st_uid == NOBODY_UID, (
        f"{where} should be owned by the dropped account nobody "
        f"(uid {NOBODY_UID}), got uid {st.st_uid}")


def test_pblock_blobs_and_db_never_root_owned(harness):
    """A WebDAV PUT over pblock from a `user root;` worker lands the blob AND the
    SQLite catalog owned by the dropped account (nobody), never root."""
    export = _mkexport("owned", 0o777)
    url, prefix = _start(harness, "pb-owned", export)

    r = requests.put(f"{url}/object.dat", data=b"pblock-body-xyz", timeout=30)
    assert r.status_code in (200, 201, 204), r.text

    blocks = _block_files(export)
    cats = _catalog_files(export)
    assert blocks, "the object must have produced at least one block file on disk"
    assert cats, "the pblock catalog.db must exist on disk"
    for path, st in blocks:
        _assert_unprivileged(st, f"blob {path}")
    for c in cats:
        _assert_unprivileged(os.stat(c), f"catalog {c}")

    # The drop actually happened (a root worker would not have logged this).
    log = os.path.join(prefix, "logs", "error.log")
    if os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as fh:
            assert "dropped to \"nobody\"" in fh.read(), \
                "expected the pblock root->nobody drop warning in the error log"


def test_pblock_large_object_stripes_into_multiple_unprivileged_blocks(harness):
    """A >block_size object stripes into multiple block files, every one owned by
    the dropped unprivileged account — striping is on by default and never root."""
    export = _mkexport("stripe", 0o777)
    url, _ = _start(harness, "pb-stripe", export, block_size="1m")

    body = b"S" * (3 * 1024 * 1024 + 4096)  # > 3 * 1 MiB blocks
    r = requests.put(f"{url}/big.bin", data=body, timeout=60)
    assert r.status_code in (200, 201, 204), r.text

    blocks = _block_files(export)
    assert len(blocks) >= 3, (
        f"a {len(body)}-byte object with a 1 MiB block size should stripe into "
        f">=3 block files, found {len(blocks)}")
    for path, st in blocks:
        _assert_unprivileged(st, f"stripe {path}")


def test_pblock_fails_closed_when_dropped_worker_cannot_write(harness):
    """If the export is not writable by the dropped account, the write fails closed
    and creates NO file — never a fallback that writes as root. (A worker that did
    NOT drop would still be root and would have written root-owned files here.)"""
    export = _mkexport("failclosed", 0o755, owner_uid=0)  # root:root 0755
    url, _ = _start(harness, "pb-failclosed", export)

    try:
        r = requests.put(f"{url}/nope.dat", data=b"x", timeout=30)
        status = r.status_code
    except requests.RequestException:
        status = 599  # connection dropped is also an acceptable fail-closed
    assert status >= 400, f"write into a non-writable pblock export must fail, got {status}"

    leaked = [os.path.join(dp, f)
              for dp, _d, fs in os.walk(export) for f in fs]
    assert not leaked, f"fail-closed must create no files, found: {leaked}"
