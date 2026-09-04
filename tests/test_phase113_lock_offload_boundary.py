"""Phase-113 closure: the WebDAV LOCK offload boundary the phase *keeps*, pinned
as assertions.

Phase 113 is CLOSED / TRIGGER NOT OBSERVED. Phase 109 offloaded the PROPFIND and
SEARCH metadata builds onto the thread pool but correctly **excluded LOCK**:
LOCK's descendant conflict walk is not read-only — it reaps expired lock-null
resources and mutates the lock table inline — so moving only its blocking read
onto a worker would split one mutation across the event loop and a thread, a
time-of-check/time-of-use window. No workload demonstrates a LOCK-driven stall,
so no offload code is warranted; the bounded inline path is the accepted
outcome.

There is therefore nothing to *implement*. What the phase decided is a boundary,
and the deferral is only sound while the boundary's load-bearing facts stay true
in the tree — every one of them true by construction and, apart from the
not-offloaded structural guard, guarded by nothing. This file pins them so a
later change cannot quietly turn the deferral into the TOCTOU bug it declined:

  * security / correctness — LOCK has no offload front door and no LOCK-path file
                    wires an offload seam (the headline decision: LOCK stays on
                    the event loop). The structural twin of this — that the seam
                    is absent *while the walk still mutates inline* — is held by
                    ``test_metadata_offload_guard.py``; this file pins the
                    complementary fact that no ``webdav_lock_offload`` symbol
                    exists at all, so a front door cannot be added unnoticed;
  * security     — the inline expired-lock cleanup refuses on a read-only export
                    *before* it mutates (the mutation-policy gate is the first
                    thing it does), so a read-only export never reaps — phase-105
                    Appendix H.2, and phase-113's "a read-only export still
                    returns EROFS before an authorization or lock conflict";
  * security     — the lock-null reap removes only an empty regular file it
                    verified with a no-follow probe, through the VFS seam, so a
                    planted symlink or a non-empty squat cannot redirect the
                    unlink;
  * feature      — the descendant conflict walk is entry-bounded because it is
                    cycle-safe: it opens confined, and it recurses only on a
                    kind it established without following a symlink. That is the
                    "current walk is entry-bounded and time-bounded" premise the
                    whole deferral rests on.

Run:
    PYTHONPATH=tests pytest tests/test_phase113_lock_offload_boundary.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("phase113-lock-boundary")]

WEBDAV = Path(__file__).resolve().parent.parent / "src" / "protocols" / "webdav"

# The offload front doors that DO exist (the adopted metadata methods) — named
# so the absence of a LOCK front door below is a meaningful negative.
ADOPTED_FRONT_DOORS = ("webdav_propfind_offload", "webdav_search_offload")
# The symbol that must never come into existence while LOCK stays inline.
LOCK_FRONT_DOOR = "webdav_lock_offload"
# Every offload seam a LOCK-path file could dispatch through.
OFFLOAD_SEAMS = ("webdav_walk_offload", "webdav_propfind_offload",
                 "webdav_search_offload", LOCK_FRONT_DOOR)
LOCK_PATH_FILES = ("lock.c", "lock_check.c", "lock_discovery.c")


def _strip(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _text(fname: str) -> str:
    return _strip((WEBDAV / fname).read_text())


def _all_webdav_c():
    return sorted(WEBDAV.glob("*.c"))


# --- the headline decision: LOCK is not offloaded ---------------------------

def test_no_lock_offload_front_door_exists_while_the_adopted_ones_do():
    """(security) The whole phase reduces to: LOCK stays on the event loop.

    The two adopted methods have thread-offload front doors; LOCK has none, and
    the symbol must not exist anywhere in the module — a `webdav_lock_offload`
    appearing is precisely the deferred, boundary-gated work sneaking in without
    the phase-113 design being reopened. The presence of the two adopted doors
    is asserted alongside so this is a real absence, not an empty tree.
    """
    joined = "".join(_strip(p.read_text()) for p in _all_webdav_c())
    joined += _strip((WEBDAV / "walk_offload.h").read_text())
    for door in ADOPTED_FRONT_DOORS:
        assert door in joined, (
            f"{door} is gone — the offload surface changed shape; re-derive the "
            "LOCK-exclusion boundary before trusting this guard")
    assert LOCK_FRONT_DOOR not in joined, (
        f"{LOCK_FRONT_DOOR} now exists — LOCK acquired a thread-offload path "
        "while phase-113 keeps it inline; reopen the phase-113 design and "
        "satisfy its whole boundary before adding this")


@pytest.mark.parametrize("fname", LOCK_PATH_FILES)
def test_no_lock_path_file_dispatches_through_an_offload_seam(fname):
    """(security) Complements the offload guard's lock.c/lock_check.c check by
    covering every LOCK-path file, lock_discovery.c included: none may call an
    offload seam while the conflict walk mutates inline."""
    p = WEBDAV / fname
    if not p.exists():
        pytest.skip(f"{fname} not present")
    body = _text(fname)
    wired = [seam for seam in OFFLOAD_SEAMS if f"{seam}(" in body]
    assert not wired, (
        f"{fname} dispatches through {wired} — a LOCK-path build was pushed to "
        "a worker; its inline lock-null reap and lock-table mutation would then "
        "run off the event loop (phase-113 TOCTOU boundary)")


# --- the inline reap is mutation-gated, gate first --------------------------

def test_expired_lock_cleanup_checks_the_mutation_policy_before_it_mutates():
    """(security) phase-113 boundary: "a read-only export still returns EROFS
    before an authorization or lock conflict." The inline expired-lock cleanup
    is a WRITE (phase-105 Appendix H.2); its very first act must be the
    mutation-policy check, and it must return on anything but ALLOWED — before
    it deletes the lock xattr or reaps the lock-null resource. A syscall ordered
    ahead of the gate would mutate a read-only export.
    """
    body = _text("lock.c")
    fn = re.search(r"webdav_lock_expired_cleanup\s*\([^)]*\)\s*\{(.*?)\n\}",
                   body, re.S)
    assert fn, "webdav_lock_expired_cleanup not found in lock.c"
    inner = fn.group(1)
    gate = inner.find("brix_vfs_policy_from_write_enable")
    ret = inner.find("return", gate)
    delete = inner.find("webdav_lock_xattr_delete")
    reap = inner.find("webdav_lock_reap_null")
    assert gate != -1, (
        "the expired-lock cleanup no longer consults the VFS mutation policy — "
        "a read-only export would reap an expired lock (phase-105 Appendix H.2)")
    assert "BRIX_VFS_MUTATION_ALLOWED" in inner, (
        "the cleanup gate no longer tests for the ALLOWED verdict")
    assert -1 < ret < delete and ret < reap, (
        "the mutation-policy gate does not short-circuit before the delete/reap "
        "— removal can run before the read-only export is refused")


# --- the lock-null reap cannot be redirected --------------------------------

def test_the_lock_null_reap_unlinks_only_a_verified_empty_regular_file():
    """(security-negative) The reap removes a name a LOCK reserved. It must fire
    only for a lock-null record, and only after a no-follow probe confirms a
    regular, zero-length file — and it must unlink through the VFS seam, never a
    bare syscall. Without the no-follow probe and the size/type checks, a client
    who replaced the reserved name with a symlink or a non-empty file could aim
    the unlink elsewhere.
    """
    body = _text("lock.c")
    fn = re.search(r"webdav_lock_reap_null\s*\([^)]*\)\s*\{(.*?)\n\}", body, re.S)
    assert fn, "webdav_lock_reap_null not found in lock.c"
    inner = fn.group(1)
    for guard in ("is_null", "brix_vfs_probe", "is_regular", "size == 0",
                  "brix_vfs_unlink"):
        assert guard in inner, (
            f"webdav_lock_reap_null lost its `{guard}` guard — the reserved-name "
            "unlink is no longer confined to a verified empty regular file")
    assert re.search(r"brix_vfs_probe\s*\([^,]+,\s*1\b", inner), (
        "the reap's stat is not a no-follow probe — a symlink left at the "
        "reserved name would be followed")
    assert not re.search(r"(?<![\w.>])unlink\s*\(", inner), (
        "webdav_lock_reap_null calls a bare unlink() instead of brix_vfs_unlink "
        "— the removal escapes the confined VFS seam")


# --- the inline walk is entry-bounded because it is cycle-safe --------------

def test_the_descendant_lock_walk_is_confined_and_never_recurses_through_a_symlink():
    """(feature) phase-113's stated reason the inline path is acceptable: "the
    current walk is entry-bounded and its backend calls are time-bounded." A
    subtree walk is entry-bounded only if it cannot cycle, and it cannot cycle
    only if it never follows a symlink into recursion. This pins that
    check_locks_descendants opens confined-quiet, and every stat feeding its
    recursion decision is a no-follow probe — the two facts that make "bounded"
    true.
    """
    body = _text("lock_check.c")
    fn = re.search(r"check_locks_descendants\s*\([^)]*\)\s*\{(.*?)\n\}\n",
                   body, re.S)
    assert fn, "check_locks_descendants not found in lock_check.c"
    inner = fn.group(1)
    assert "brix_vfs_opendir_quiet" in inner, (
        "the recursive lock scan no longer opens through the confined quiet "
        "opendir — a planted in-export symlink could redirect it out of root")
    probes = re.findall(r"brix_vfs_probe\s*\(\s*&\w+\s*,\s*(\d)", inner)
    assert probes, "no VFS probe drives the recursion kind decision"
    assert all(arg == "1" for arg in probes), (
        f"a follow probe ({probes}) decides recursion — the walk could descend "
        "through a symlink and cycle, breaking the entry-bounded premise")
    # A directory verdict must come from d_type or the no-follow probe, never a
    # follow-stat: the recursion guard is is_dir, set from those two only.
    assert "BRIX_VFS_DT_DIR" in inner and "BRIX_VFS_DT_UNKNOWN" in inner, (
        "the recursion no longer keys on d_type with a no-follow fallback")


def test_probe_arg_detector_is_not_vacuous():
    """(error) The no-follow assertion must actually reject a follow probe."""
    follow = re.findall(r"brix_vfs_probe\s*\(\s*&\w+\s*,\s*(\d)",
                        "brix_vfs_probe(&c, 0 /* follow */, &s)")
    assert follow == ["0"] and not all(a == "1" for a in follow), (
        "detector logic broken: a follow probe (arg 0) would pass the no-follow "
        "assertion")
