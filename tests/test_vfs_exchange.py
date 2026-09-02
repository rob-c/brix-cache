"""test_vfs_exchange.py — phase-107 C6: the atomic two-name exchange contract.

Behavior coverage lives in the C object unit (tests/c/test_vfs_exchange.c —
real renameat2(RENAME_EXCHANGE) through the real confined rootfd: inode-swap
atomicity, both-must-exist ENOENT, EXDEV confinement including the
prefix-boundary trap).  No protocol verb reaches brix_vfs_exchange yet (the
OCI tag flip is phase-108), so what this file pins is the SOURCE contract the
verb must keep while it waits for its first caller:

  - the typed policy gate runs FIRST — before the cross-export comparison —
    so a read-only export answers EROFS without leaking whether either name
    exists (the same existence-probe rule the conditional-publish rows carry);
  - cross-export exchange is EXDEV at the VFS layer (the driver arm's
    export-relative keying would otherwise pass a foreign path through);
  - a backend without the primitive refuses ENOTSUP and is NEVER emulated
    with two renames (§3.5) — in the dispatch helper AND in both engine arms;
  - the C3 durable-publish barrier and the cache eviction cover BOTH names
    (both directory entries changed);
  - both decorators relay the slot pair (the R-wave parity lesson: a slot the
    cache does not relay turns a working leaf primitive into ENOTSUP).

Reference: docs/refactor/phase-107-vfs-mutation-surface-completion.md §3.5/C6.

Run:
  PYTHONPATH=tests pytest tests/test_vfs_exchange.py -v
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _fn(text: str, name: str) -> str:
    """The body of a top-level C function: from its definition line to the
    first closing brace at column 0."""
    m = re.search(rf"^{re.escape(name)}\(.*?^\}}", text, re.S | re.M)
    assert m, f"function {name} not found — re-anchor this pin"
    return m.group(0)


# --------------------------------------------------------------------------
# The VFS verb: gate order, EXDEV, no emulation
# --------------------------------------------------------------------------

def test_policy_gate_runs_before_any_name_comparison():
    """EROFS before EXDEV/EINVAL: a read-only export must refuse the mutation
    without evaluating either name, or the refusal ordering becomes an
    existence/confinement probe.  The gate lives in the shared entry helper
    (brix_vfs_two_name_entry); the pin follows it there AND pins the helper
    call above the EXDEV check in brix_vfs_exchange itself."""
    text = _src("src/fs/vfs/vfs_rename.c")
    entry = _fn(text, "brix_vfs_two_name_entry")
    assert "brix_vfs_require_confined_mutation" in entry, (
        "the typed policy gate left the shared entry helper")
    assert "BRIX_VFS_MUTATE_RENAME" in entry, (
        "exchange is write-gated as a rename-class mutation")
    body = _fn(text, "brix_vfs_exchange")
    gate = body.index("brix_vfs_two_name_entry(")
    xdev = body.index("brix_beneath_strip_root")
    assert gate < xdev, "the entry gate moved below the EXDEV check"


def test_cross_export_exchange_is_exdev_before_driver_dispatch():
    body = _fn(_src("src/fs/vfs/vfs_rename.c"), "brix_vfs_exchange")
    m = re.search(r"brix_beneath_strip_root\(.*?errno = EXDEV;", body, re.S)
    assert m, "the cross-export EXDEV refusal left brix_vfs_exchange"
    assert body.index("errno = EXDEV") < body.index(
        "brix_vfs_exchange_driver(ctx"), (
        "EXDEV must be decided before the driver arm sees a foreign key")


def test_exchange_is_never_emulated_with_two_renames():
    """§3.5: a caller that asked for an atomic swap would rather have ENOTSUP
    than a window in which neither name resolves.  Neither engine arm may
    fall back to rename."""
    ns = _fn(_src("src/core/compat/namespace_ops.c"), "brix_ns_exchange")
    assert "brix_exchange_beneath" in ns
    assert "brix_rename_beneath" not in ns, (
        "the POSIX arm grew a rename fallback — §3.5 forbids emulation")

    dispatch = _src("src/fs/backend/sd_cred_forward.h")
    m = re.search(
        r"if \(inst->driver->exchange == NULL\) \{.*?errno = ENOTSUP;",
        dispatch, re.S)
    assert m, "the NULL-slot ENOTSUP refusal left brix_sd_exchange_maybe_cred"

    drv = _fn(_src("src/fs/vfs/vfs_rename.c"), "brix_vfs_exchange_driver")
    assert "brix_sd_exchange_maybe_cred" in drv
    assert "->rename(" not in drv and "brix_sd_rename" not in drv, (
        "the driver arm grew a rename fallback — §3.5 forbids emulation")


# --------------------------------------------------------------------------
# Both names: barrier + eviction
# --------------------------------------------------------------------------

def test_c3_barrier_covers_both_names_in_both_arms():
    text = _src("src/fs/vfs/vfs_rename.c")
    posix_arm = _fn(text, "brix_vfs_exchange")
    assert len(re.findall(r"brix_publish_dirsync\(", posix_arm)) == 2, (
        "the POSIX arm must flush BOTH parents — both entries changed")
    driver_arm = _fn(text, "brix_vfs_exchange_driver")
    assert len(re.findall(r"sync_publish\(leaf, [ab]_key\)", driver_arm)) == 2, (
        "the driver arm must barrier BOTH keys")


def test_driver_arm_evicts_both_keys():
    driver_arm = _fn(_src("src/fs/vfs/vfs_rename.c"),
                     "brix_vfs_exchange_driver")
    assert re.search(
        r"brix_sd_cache_evict\(ctx->sd, a_key\)\s*\+"
        r"\s*brix_sd_cache_evict\(ctx->sd, b_key\)", driver_arm), (
        "both keys map to new content — both cache entries must go")


# --------------------------------------------------------------------------
# Decorator parity (the R-wave lesson)
# --------------------------------------------------------------------------

def test_both_decorators_relay_the_exchange_slot_pair():
    for rel in ("src/fs/backend/cache/sd_cache.c",
                "src/fs/backend/stage/sd_stage.c"):
        text = _src(rel)
        assert re.search(r"\.exchange\s*=", text), f"{rel}: .exchange relay gone"
        assert re.search(r"\.exchange_cred\s*=", text), (
            f"{rel}: .exchange_cred relay gone — the cred twin is the "
            f"security-relevant half")


def test_posix_leaf_implements_the_primitive():
    text = _src("src/fs/backend/posix/sd_posix.c")
    assert re.search(r"\.exchange\s*=\s*sd_posix_exchange", text)
