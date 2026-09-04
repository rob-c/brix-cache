"""test_vfs_mutation_baseline.py — phase-107 W0: freeze the contract.

Pins the eight behaviours phase-107 exists to change, so that every wave's
inversion is a deliberate edit to THIS file rather than an accident nobody
noticed.  Each pin names the wave that inverts it; when that wave lands, the
pinned assertion is rewritten to assert the NEW behaviour (and the wave's own
success/error/security tests carry the real coverage).  A pin that fails
before its wave landed means the tree moved under the plan — stop and re-read
phase-107 §8 before proceeding.

The pins are deliberately cheap: source-contract assertions over the exact
lines the plan anchors to, plus one pure-behaviour probe (the O_PATH fsync)
that needs no build at all.  They run in the --pr tier with no fleet.

Reference: docs/refactor/phase-107-vfs-mutation-surface-completion.md §8/W0.

Run:
  PYTHONPATH=tests pytest tests/test_vfs_mutation_baseline.py -v
"""

import errno
import os
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# B1 — out-of-order writes on staged-only backends spill (INVERTED by W2)
# --------------------------------------------------------------------------

def test_b1_vfs_writer_spills_out_of_order_staged_writes():
    """W2 (phase-107 C1) replaced the staged out-of-order EINVAL refusal with
    the one-way SEQUENTIAL → SPILL transition: off != staged_cursor now enters
    spill mode instead of failing, and the writer dispatches on `mode`."""
    text = _src("src/fs/vfs/vfs_writer.c")
    assert not re.search(
        r"if \(off != w->staged_cursor\) \{\s*\n\s*errno = EINVAL;", text), (
        "the pre-W2 EINVAL refusal came back — the spill transition regressed")
    m = re.search(
        r"if \(off != w->staged_cursor\) \{\s*\n\s*"
        r"if \(brix_vfs_writer_spill_enter\(w, off, len\) != NGX_OK\)", text)
    assert m, "the SEQUENTIAL → SPILL transition (spill_enter on reorder) moved"
    assert "brix_vfs_writer_spill_put" in text, (
        "spill-mode writes must route through brix_vfs_writer_spill_put")


def test_b1_sd_http_staged_write_is_sequential_only():
    """sd_http_staged_write refuses a non-append offset with ESPIPE (W2)."""
    text = _src("src/fs/backend/http/sd_http_write.c")
    assert re.search(
        r"if \(\(size_t\) off != ss->len\) \{\s*\n\s*errno = ESPIPE;", text), (
        "the sd_http ESPIPE sequential guard moved — re-anchor W2")


def test_b1_sd_http_staged_buffer_is_capped():
    """W2 capped the doubling staged buffer: growth past SD_HTTP_STAGED_MAX is
    refused ENOSPC (never a truncated object), and the doubled allocation is
    clamped so it cannot overshoot the cap."""
    text = _src("src/fs/backend/http/sd_http_write.c")
    assert "SD_HTTP_STAGED_MAX" in text, (
        "the W2 staged-buffer cap disappeared from sd_http_write.c")
    assert re.search(
        r"if \(ss->len \+ len > SD_HTTP_STAGED_MAX\) \{\s*\n\s*"
        r"errno = ENOSPC;", text), (
        "the over-cap append must refuse ENOSPC before any allocation")
    assert "ncap = ss->cap ? ss->cap * 2 : (1u << 20)" in text, (
        "the doubling growth itself should remain (only the cap was added)")


# --------------------------------------------------------------------------
# B2 — prepare's cancel/evict arms are noops (inverted: W6)
# --------------------------------------------------------------------------

def test_b2_prepare_evict_reaches_the_vfs():
    """W6 (phase-107 C2) replaced the logged-noop evict arm and the
    fork/exec-only stage arm with the VFS verbs: prepare_recall.c owns the
    per-path lifecycle (record-before-driver-call, brix_vfs_recall,
    delete-on-synchronous-failure; owner-checked brix_vfs_evict), and
    prepare.c routes every resolved path through it instead of
    short-circuiting evict before the scan."""
    recall = _src("src/protocols/root/query/prepare_recall.c")
    assert "brix_vfs_recall(" in recall, (
        "the W6 stage arm no longer reaches brix_vfs_recall")
    assert "brix_vfs_evict(" in recall, (
        "the W6 evict arm no longer reaches brix_vfs_evict")
    assert "brix_stage_request_owner_check" in recall, (
        "the FRM-1 ownership check left the evict arm")
    text = _src("src/protocols/root/query/prepare.c")
    assert "kXR_evict" in text
    assert "brix_prepare_evict_one" in text and "brix_prepare_recall_one" in text, (
        "prepare.c no longer dispatches the per-path W6 arms")
    assert not re.search(r"evict[^\n]*noop|noop[^\n]*evict", text,
                         re.IGNORECASE), (
        "the pre-W6 evict-noop comment came back — the arm regressed")


# --------------------------------------------------------------------------
# B3 — no publish flushes a parent directory; the one attempt is inert
#      (inverted: W3)
# --------------------------------------------------------------------------

def test_b3_fsync_on_an_o_path_fd_fails_ebadf():
    """The kernel-level fact that makes staged_file.c:319 inert.

    Pure behaviour, no repo code: fsync(2) on an O_PATH descriptor fails
    EBADF, so `(void) fsync(rootfd)` on brix_beneath_open_root()'s O_PATH fd
    can never have flushed anything.  This pin is permanent — it documents the
    trap and never inverts.
    """
    fd = os.open("/tmp", os.O_PATH | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError) as exc:
            os.fsync(fd)
        assert exc.value.errno == errno.EBADF
    finally:
        os.close(fd)


def test_b3_staged_file_publish_flushes_parent_directory():
    """W3 (phase-107 C3) replaced the inert `(void) fsync(rootfd)` — fsync on
    an O_PATH fd is EBADF, discarded — with the durable-publish barrier: the
    PARENT of the published path is flushed through brix_publish_dirsync, a
    failed barrier FAILS the commit, and the per-export brix_vfs_backend_durable
    gate (absent/unregistered = on) decides whether it runs."""
    text = _src("src/core/compat/staged_file.c")
    assert "(void) fsync(rootfd);" not in text, (
        "the pre-W3 inert directory fsync came back — the barrier regressed")
    assert re.search(r"brix_vfs_backend_durable\(root_canon\)\s*\n?\s*"
                     r"&& brix_publish_dirsync\(", text), (
        "the gated brix_publish_dirsync barrier moved — re-anchor W3")
    beneath = _src("src/fs/path/beneath.c")
    assert re.search(r"brix_beneath_open_root[\s\S]{0,400}O_PATH\s*\|\s*"
                     r"O_DIRECTORY", beneath), (
        "brix_beneath_open_root no longer opens O_PATH|O_DIRECTORY — the EBADF "
        "trap pin above loses its anchor")


def test_b3_sync_publish_slot_exists():
    """W3's slot: sd.h carries sync_publish and posix implements it."""
    sd_h = _src("src/fs/backend/sd.h")
    assert re.search(r"\(\*sync_publish\)", sd_h), (
        "the W3 sync_publish slot disappeared from sd.h")
    assert "sd_posix_sync_publish" in _src(
        "src/fs/backend/posix/sd_posix.c"), (
        "posix no longer publishes the sync_publish slot")


# --------------------------------------------------------------------------
# B4 — DeleteObjects is a per-key loop; no batch verb exists (inverted: W5)
# --------------------------------------------------------------------------

def test_b4_s3_delete_objects_batches():
    """W5 (phase-107 C4) replaced the per-key brix_vfs_unlink loop with the
    collect-then-execute batch: every key is confined FIRST, then ONE
    brix_vfs_delete_many() call disposes the batch under one write gate and
    one metric observation."""
    text = _src("src/protocols/s3/delete_objects.c")
    assert "brix_vfs_unlink(" not in text, (
        "the pre-W5 per-key unlink loop came back to delete_objects.c")
    batch = _src("src/protocols/s3/delete_objects_batch.c")
    assert "brix_vfs_delete_many(" in batch, (
        "the ONE-batch VFS call left delete_objects_batch.c — re-anchor W5")
    sd_h = _src("src/fs/backend/sd.h")
    assert re.search(r"\(\*unlink_many\)", sd_h), (
        "the W5 unlink_many slot disappeared from sd.h")
    assert re.search(r"\(\*unlink_many_cred\)", sd_h), (
        "the W5 unlink_many_cred twin disappeared from sd.h")
    assert "BRIX_SD_CAP_BULK_DELETE" in sd_h, (
        "the W5 CAP_BULK_DELETE capability bit disappeared from sd.h")
    # the rmtree walker only batches when the leaf advertises the bit —
    # the per-LEVEL rule from §4/C4 lives in vfs_unlink_many.c
    many = _src("src/fs/vfs/vfs_unlink_many.c")
    assert "BRIX_SD_CAP_BULK_DELETE" in many
    assert "brix_vfs_rmtree_dispatch" in _src("src/fs/vfs/vfs_unlink.c"), (
        "brix_vfs_driver_rmtree lost its W5 bulk dispatch")


# --------------------------------------------------------------------------
# B5 — oss.asize is parsed and discarded; no reserve slot (inverted: W4)
# --------------------------------------------------------------------------

def test_b5_oss_asize_reaches_the_driver():
    """W4 (phase-107 C5): the declaration flows in on all three edges
    (oss.asize / Content-Length / ALLO) and reaches storage through BOTH halves
    of the contract — the object-keyed reserve slot and staged_open's
    declared_size parameter."""
    text = _src("src/protocols/root/path/opaque_validate.c")
    assert "brix_opaque_asize" in text, (
        "the typed oss.asize reader vanished — re-anchor W4")
    sd_h = _src("src/fs/backend/sd.h")
    assert re.search(r"\(\*reserve\)\(brix_sd_obj_t \*obj, off_t size\)",
                     sd_h), "the W4 reserve slot disappeared from sd.h"
    assert re.search(r"\(\*staged_open\)\([^;]*off_t declared_size",
                     sd_h), "staged_open lost its declared_size parameter"
    vfs_open = _src("src/fs/vfs/vfs_open.c")
    assert "brix_vfs_open_reserve" in vfs_open, (
        "the object-plane reserve hook left vfs_open.c")
    assert "brix_vfs_fd_reserve" in vfs_open, (
        "the fd-keyed reserve half left vfs_open.c")
    # remote actually consumes it: the part size derives from the declaration
    assert "sd_remote_part_size(declared_size)" in _src(
        "src/fs/backend/remote/sd_remote_write.c"), (
        "sd_remote no longer derives the multipart part size from the "
        "declaration — the 160 GB ceiling is back")


# --------------------------------------------------------------------------
# B6 — sd_remote publish preconditions are decided by the ORIGIN (was: a
#      HEAD-then-PUT race; inverted by W7)
# --------------------------------------------------------------------------

def test_b6_sd_remote_precondition_is_decided_at_the_origin():
    """Inverted by W7: staged_commit carries a typed brix_sd_precond_t and
    sd_remote arms If-None-Match: * / If-Match on the publish request itself —
    the origin decides atomically, so the pre-W7 HEAD-before-PUT existence
    check (and its documented race) is gone from the commit path."""
    text = _src("src/fs/backend/remote/sd_remote_write.c")
    sig = re.search(r"sd_remote_staged_commit\(brix_sd_staged_t \*h, "
                    r"brix_sd_precond_t \*pre\)", text)
    assert sig, "staged_commit lost its typed precondition parameter — W7"
    assert "brix_sd_precond_absent" in text, (
        "the ABSENT arm left sd_remote's commit — the conditional publish "
        "no longer reaches the origin")
    sd_h = _src("src/fs/backend/sd.h")
    assert "brix_sd_precond_t" in sd_h, (
        "the typed precondition vanished from the slot contract")


# --------------------------------------------------------------------------
# B7 — a WebDAV lock stops nothing outside WebDAV (inverted: W8)
# --------------------------------------------------------------------------

def test_b7_lock_gate_is_wired_into_every_path_mutator():
    """Inverted by W8: brix_vfs_require_unlocked (the xattr-backed body in
    vfs_lock_gate.c) runs after the policy gate at every path mutator, so a
    live foreign WebDAV lock refuses root://, GridFTP, S3 and OCI mutations —
    not just WebDAV's own.  The per-unit shape is deliberate, not uniform:
    rename AND exchange gate BOTH names through the shared two_name_entry;
    copy gates only the DESTINATION (the source is read, not replaced);
    truncate_path gates only its path-native branch (the open+ftruncate
    fallback reaches brix_vfs_open's own gate — gating both would double-book
    the advisory metric); delete_many gates every key before any arm and
    refuses the batch atomically; and vfs_writer.c carries NO direct call
    because every writer route enters through the already-gated
    brix_vfs_open / brix_vfs_staged_open."""
    assert (REPO / "src/fs/vfs/vfs_lock_gate.c").exists(), (
        "vfs_lock_gate.c disappeared — the W8 body was reverted")
    gated = {
        "vfs_open.c":        1,   # open-for-write
        "vfs_unlink.c":      1,   # single-key remove (ancestor coverage)
        "vfs_rename.c":      2,   # two_name_entry: both names (rename+exchange)
        "vfs_mkdir.c":       1,   # a locked ancestor covers the new name
        "vfs_copy.c":        1,   # destination only
        "vfs_xattr.c":       1,   # dead-prop / tag writes
        "vfs_staged.c":      1,   # gated at open — ownership provable there
        "vfs_sync.c":        1,   # truncate_path, path-native branch only
        "vfs_unlink_many.c": 1,   # per-key, before any arm; atomic refusal
    }
    for unit, want in gated.items():
        hits = _src(f"src/fs/vfs/{unit}").count("brix_vfs_require_unlocked")
        assert hits >= want, (
            f"{unit} lost its W8 lock gate ({hits} < {want} call sites)")
    assert "require_unlocked" not in _src("src/fs/vfs/vfs_writer.c"), (
        "vfs_writer.c gained a direct lock gate — its routes gate at open, "
        "so a second call would double-book the advisory refusal metric")


def test_b7_http_status_table_maps_ebusy_to_423():
    """Inverted by W8: the EBUSY -> 423 Locked row (RFC 4918 §11.3) landed
    beside W7's ECANCELED -> 412 row — a lock-gate refusal is a client-visible
    lock conflict on every HTTP plane, never a 500."""
    text = _src("src/core/compat/error_mapping.c")
    assert re.search(r"\{\s*EBUSY,\s*423\s*\}", text), (
        "the W8 EBUSY -> 423 row left the table")
    assert re.search(r"\{\s*ECANCELED,\s*412\s*\}", text), (
        "the W7 ECANCELED -> 412 row left the table")


# --------------------------------------------------------------------------
# B8 — the dedup plane publishes with no gate (inverted: W1)
# --------------------------------------------------------------------------

def test_b8_gcas_dedup_is_gated_on_the_service_domain():
    """Inverted by W1: both dedup slots now pass brix_vfs_service_mutation
    (C8) before the driver runs, so an export-pointed store refuses instead of
    publishing.  tests/c/test_vfs_service_domain.c carries the behaviour
    coverage; this pin keeps the gate from silently vanishing."""
    text = _src("src/fs/cache/gcas.c")
    assert "dedup_publish(cs->store" in text
    assert text.count(
        "brix_vfs_service_mutation(cs->store, BRIX_VFS_MUTATE_DEDUP)") == 2, (
        "one of gcas' two dedup slots lost the W1 service-domain gate")
    assert "(void) cs->store->driver->dedup_gc(cs->store, rel);" in text, (
        "dedup_gc's discarded result changed — re-anchor W1")


# --------------------------------------------------------------------------
# Vocabulary width — W1 took the metric mirror 11 -> 15 (phase-108 -> 16)
# --------------------------------------------------------------------------

def test_vocabulary_is_sixteen_members():
    """Inverted by W1.  The four phase-107 members exist, the metric mirror
    moved with them, and the label tables carry exactly the new strings — the
    _Static_assert at vfs_policy.c:33 enforces the count equality at compile
    time; this pin catches a string-table drift the assert cannot see."""
    unified = _src("src/observability/metrics/unified.h")
    assert "#define BRIX_VFS_MUTATE_OP_METRIC_COUNT  16" in unified, (
        "the metric mirror is not 16 — the credential operation landed only in part")
    policy = _src("src/fs/vfs/vfs_policy.h")
    for member in ("BRIX_VFS_MUTATE_STAGE", "BRIX_VFS_MUTATE_EVICT",
                   "BRIX_VFS_MUTATE_LOCK", "BRIX_VFS_MUTATE_DEDUP"):
        assert member in policy, f"{member} missing from the W1 vocabulary"
    for table in ("src/fs/vfs/vfs_policy.c",
                  "src/observability/metrics/unified.c"):
        text = _src(table)
        for label in ('"stage"', '"evict"', '"lock"', '"dedup"'):
            assert label in text, f"{table} lacks the {label} label"
