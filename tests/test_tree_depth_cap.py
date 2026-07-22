"""D-6/T2 — recursion-depth cap on the confined tree ops.

Three server functions delete or copy a directory tree by recursing on the C
stack, INDEPENDENTLY of the ``max_depth``-capped generic walker
(``vfs_walk_dir``):

  * ``brix_fs_remove_tree_confined`` (src/core/compat/fs_walk_remove.c) — the
    WebDAV/XRootD recursive DELETE and the S3 AbortMultipartUpload cleanup.
  * ``brix_vfs_copytree``           (src/fs/vfs/vfs_walk.c)             — the
    confined recursive COPY.
  * ``brix_vfs_driver_rmtree``      (src/fs/vfs/vfs_unlink.c)           — the
    recursive DELETE through a non-POSIX (object/S3) storage driver.

Left unbounded, an attacker-nested tree (deep MKCOL/PUT nesting) drives the
worker into a C-stack overflow — a crash-class denial of service.  The fix caps
every one of these recursions at ``BRIX_FS_TREE_MAX_DEPTH`` and aborts with
``ELOOP`` past it.

These are file-static functions that require a confined-canon filesystem + the
impersonation/beneath machinery to drive, so — matching the source-invariant
guardrails already used for the OCSP transport in this suite — the properties are
asserted against the source.  The security-negative case pins the ONE subtle
correctness property the cap depends on: each recursion must re-enter the
depth-CARRYING core, never the public entry point (which resets depth to 0 and
would silently defeat the cap).
"""

from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src"

REMOVE_TREE = _SRC / "core" / "compat" / "fs_walk_remove.c"
COPYTREE = _SRC / "fs" / "vfs" / "vfs_walk_copy.c"
DRIVER_RMTREE = _SRC / "fs" / "vfs" / "vfs_unlink.c"
FS_WALK_H = _SRC / "core" / "compat" / "fs_walk.h"


class TestTreeDepthCap:
    """The independently-recursive confined tree ops must share one explicit
    depth ceiling so a hostile deep tree errors instead of faulting."""

    @pytest.fixture(scope="class")
    def header(self):
        return FS_WALK_H.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def remove_tree(self):
        return REMOVE_TREE.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def copytree(self):
        return COPYTREE.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def driver_rmtree(self):
        return DRIVER_RMTREE.read_text(encoding="utf-8")

    # -- success: the shared cap exists and every recursion site enforces it -- #
    def test_cap_constant_is_defined_once(self, header):
        assert "#define BRIX_FS_TREE_MAX_DEPTH  512" in header

    def test_all_three_ops_enforce_the_cap(self, remove_tree, copytree,
                                           driver_rmtree):
        for src in (remove_tree, copytree, driver_rmtree):
            assert "depth > BRIX_FS_TREE_MAX_DEPTH" in src

    # -- error: exceeding the cap aborts with ELOOP, not a fault ------------- #
    def test_over_cap_returns_eloop_not_crash(self, remove_tree, copytree,
                                              driver_rmtree):
        for src in (remove_tree, copytree, driver_rmtree):
            assert "errno = ELOOP" in src
            assert "return NGX_ERROR" in src

    # -- security-negative: recursion must NOT reset depth via the public entry #
    def test_remove_tree_recurses_through_depth_carrying_core(self, remove_tree):
        # The per-entry helper must recurse into the depth-carrying core
        # (`_at(..., depth + 1)`), never back through the public wrapper which
        # would reset depth to 0 and defeat the cap.
        assert "brix_fs_remove_tree_at(log, root_canon, child, depth + 1)" \
            in remove_tree
        # The public entry is a thin depth-0 wrapper only.
        assert "return brix_fs_remove_tree_at(log, root_canon, path, 0);" \
            in remove_tree

    def test_copytree_recurses_through_depth_carrying_core(self, copytree):
        assert "vfs_copytree_run(ctx, src_child, dst_child, depth + 1)" \
            in copytree
        assert "return vfs_copytree_run(&ctx, src, dst, 0);" in copytree
        # The old contract-frozen public function must NOT be the recursion edge.
        assert "return brix_vfs_copytree(ctx->log" not in copytree

    def test_driver_rmtree_threads_depth(self, driver_rmtree):
        assert "brix_vfs_driver_rmtree(leaf, drv, child, cred, depth + 1)" \
            in driver_rmtree
        assert "brix_vfs_driver_rmtree(leaf, drv, logical,\n" \
            "                                    use_cred ? &cred : NULL, 0)" \
            in driver_rmtree
