"""
Cache coherence on in-band delete: deleting a file through a read-through cache
node removes it from BOTH the origin backend and the local cache store.

A brix cache node is a read-through decorator (brix_sd_cache_driver) whose source
is the origin backend. A client delete lands in brix_vfs_unlink ->
brix_vfs_delete_via_driver (src/fs/vfs/vfs_unlink.c): the unlink is dispatched on
the unwrapped leaf (so it reaches the origin over the same channel a fill uses),
and on success the local cached copy is dropped via brix_sd_cache_evict
(vfs_unlink.c:169). This suite proves that contract end to end, without any
client-forced revalidation — the second read simply finds the object gone.

Harness: the partial-fill lifecycle harness (_cache_partial_helpers) boots a
root:// origin plus a cache node in front of it. seed_origin writes into the
origin's backing store; read_range warms the cache; residency inspects the cache
store via xrdcinfo; a raw kXR_rm issues the in-band delete through the cache node.

Run: PYTHONPATH=tests pytest tests/test_cache_origin_delete_eviction.py -v
"""
import os
import struct

import pytest

from _cache_partial_helpers import (
    make_cache_node, seed_origin, read_range, residency,
    _session, _read_frame, make_open_req,
)

# serial + registry lifecycle: each test boots its own cache+origin pair, and the
# slice read path is flagged crash-prone under concurrency (see
# test_cache_partial_fill.py); mirror its markers.
pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness]

kXR_rm = 3014
BLK = 1024 * 1024


def _origin_file(node, path):
    """The origin's on-disk path for `path` — inverse of seed_origin's write
    target (node.backend_data is the origin root, _cache_partial_helpers.py)."""
    return os.path.join(node.backend_data, path.lstrip("/"))


def rm_path(port, path):
    """Issue an in-band kXR_rm for `path` over a fresh logged-in session and
    return the response status (0 == kXR_ok). Wire format matches the ClientRequest
    header used across the suite: 2-byte streamid, 2-byte request id, 16 reserved
    bytes, 4-byte dlen, then the path body."""
    session = _session(port)
    try:
        path_bytes = path.encode()
        req = struct.pack("!2sH16sI", b"\x00\x02", kXR_rm,
                          b"\x00" * 16, len(path_bytes)) + path_bytes
        session.sendall(req)
        status, _body = _read_frame(session)
        return status
    finally:
        session.close()


def open_status(port, path):
    """Open `path` and return the response status without asserting — used to
    prove a deleted object now opens with an error (ENOENT -> non-zero)."""
    session = _session(port)
    try:
        session.sendall(make_open_req(path.encode()))
        status, _body = _read_frame(session)
        return status
    finally:
        session.close()


class TestCacheOriginDeleteEviction:
    """In-band delete propagates to the origin and evicts the local cache copy."""

    def test_delete_removes_from_origin_and_cache(self, lifecycle, tmp_path):
        """A warm, complete cached object deleted via the cache node is gone from
        the origin backing store AND the cache store, and re-opening it fails —
        with no revalidation trigger."""
        with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path,
                             lifecycle=lifecycle, allow_write=True) as node:
            data = seed_origin(node, "/f.bin", 4 * BLK)
            warmed = read_range(node.cache_port, "/f.bin", 0, 4 * BLK)
            assert warmed == data, "warm read did not return the seeded bytes"
            assert residency(node.store_dir, "f.bin").get("complete") is True, \
                "cache did not become complete after a full warm read"
            assert os.path.exists(_origin_file(node, "/f.bin")), \
                "origin file missing before delete"

            status = rm_path(node.cache_port, "/f.bin")
            assert status == 0, f"in-band delete failed, status={status}"

            assert not os.path.exists(_origin_file(node, "/f.bin")), \
                "delete did not propagate to the origin backend"
            assert residency(node.store_dir, "f.bin").get("absent"), \
                "cached copy was not evicted on delete"
            assert open_status(node.cache_port, "/f.bin") != 0, \
                "deleted object still opens on the cache node"

    def test_delete_missing_path_errors_and_leaves_cache_intact(self, lifecycle,
                                                                 tmp_path):
        """Deleting a nonexistent path returns an error and does not disturb an
        unrelated warm cached object."""
        with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path,
                             lifecycle=lifecycle, allow_write=True) as node:
            seed_origin(node, "/keep.bin", 2 * BLK)
            read_range(node.cache_port, "/keep.bin", 0, 2 * BLK)
            assert residency(node.store_dir, "keep.bin").get("complete") is True

            status = rm_path(node.cache_port, "/nope.bin")
            assert status != 0, "delete of a missing path unexpectedly succeeded"

            assert os.path.exists(_origin_file(node, "/keep.bin")), \
                "unrelated origin file removed by a failed delete"
            assert residency(node.store_dir, "keep.bin").get("complete") is True, \
                "unrelated cached object evicted by a failed delete"

    def test_delete_denied_when_write_disabled(self, lifecycle, tmp_path):
        """With writes disabled the cache node rejects the delete before touching
        the backend: the origin file and the cached copy both survive."""
        with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path,
                             lifecycle=lifecycle, allow_write=False) as node:
            seed_origin(node, "/f.bin", 2 * BLK)
            read_range(node.cache_port, "/f.bin", 0, 2 * BLK)
            assert residency(node.store_dir, "f.bin").get("complete") is True

            status = rm_path(node.cache_port, "/f.bin")
            assert status != 0, "delete succeeded on a read-only cache node"

            assert os.path.exists(_origin_file(node, "/f.bin")), \
                "origin file removed despite writes being disabled"
            assert residency(node.store_dir, "f.bin").get("complete") is True, \
                "cached copy evicted despite writes being disabled"
