"""
test_vfs_read_only_static.py — the phase-105 source contract for the VFS
read-only mutation gate (docs/refactor/phase-105-vfs-read-only-mutation-gate.md,
Appendix K.2).

WHAT: A source-level audit of the mutation-policy kernel and of every VFS entry
      point that must consult it: the enum fails closed, each mutator names the
      kernel with the operation from the closed vocabulary, the gate is the
      FIRST thing in its function body (before leaf resolution, cache
      invalidation, credential selection or a namespace call), the raw ctx-less
      export helpers each carry a wrapper that gates, the objects that outlive a
      request carry the policy by value, and neither policy TU can answer EACCES.

WHY:  The wire suites can prove a refusal happened; they cannot prove a backend
      call did NOT occur, nor that the refusal preceded the work.  Appendix I.5
      makes read-only precede the credential refusal unconditionally, and §0.2
      records that several mutators dispatch past the cache decorator to the
      leaf, so the gate cannot live on the decorator and must be re-proved at
      each entry point.  A gate that drifts below a side effect, or a new
      mutator added without one, is exactly the regression this file catches.

HOW:  Read the sources, cut each named function's body at column-0 braces, and
      assert on offsets within it.  No build, no fleet, no network.

Cases
  success        — the inventoried gates exist, name the expected op, and
                   precede every side-effect marker in their own body.
  error          — the enums, the op-name table and the metric mirror agree, so
                   an out-of-range op cannot index past the table.
  security-neg   — no EACCES in the policy TUs, no raw export mutator without a
                   gating wrapper, no un-normalised policy in the ctx
                   constructor, and the handle gate answers kXR_fsReadOnly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

POLICY_H = "src/fs/vfs/vfs_policy.h"
POLICY_C = "src/fs/vfs/vfs_policy.c"
POLICY_EXPORT_C = "src/fs/vfs/vfs_policy_export.c"
UNIFIED_H = "src/observability/metrics/unified.h"
FD_TABLE_C = "src/protocols/root/connection/fd_table.c"
ADOPT_C = "src/fs/vfs/vfs_open_adopt.c"

# The closed operation vocabulary, in declaration order (vfs_policy.h).
OPS = ("OPEN", "WRITE", "TRUNCATE", "SYNC", "MKDIR", "REMOVE",
       "RENAME", "COPY", "SETATTR", "XATTR", "PUBLISH")

OP_LABELS = ("open", "write", "truncate", "sync", "mkdir", "remove",
             "rename", "copy", "setattr", "xattr", "publish")

# Every VFS/protocol entry point that must consult the kernel, with the
# operation it is required to name.  Sourced from the phase-105 inventory; a new
# mutator belongs here the day it is written.
GATES = (
    ("src/fs/vfs/vfs_open.c", "brix_vfs_open_precheck", "OPEN"),
    ("src/fs/vfs/vfs_copy.c", "brix_vfs_copy", "COPY"),
    ("src/fs/vfs/vfs_sync.c", "brix_vfs_truncate", "TRUNCATE"),
    ("src/fs/vfs/vfs_sync.c", "brix_vfs_truncate_path", "TRUNCATE"),
    ("src/fs/vfs/vfs_sync.c", "brix_vfs_sync", "SYNC"),
    ("src/fs/vfs/vfs_writer.c", "brix_vfs_writer_write", "WRITE"),
    ("src/fs/vfs/vfs_writer.c", "brix_vfs_writer_write_fd", "WRITE"),
    ("src/fs/vfs/vfs_writer.c", "brix_vfs_writer_commit_ex", "PUBLISH"),
    ("src/fs/vfs/vfs_xattr.c", "brix_vfs_xattr_mutate", "XATTR"),
    ("src/fs/vfs/vfs_xattr.c", "brix_vfs_fsetxattr_carried", "XATTR"),
    ("src/fs/vfs/vfs_xattr.c", "brix_vfs_fremovexattr_carried", "XATTR"),
    ("src/fs/vfs/vfs_staged.c", "staged_alloc_handle", "OPEN"),
    ("src/fs/vfs/vfs_staged.c", "brix_vfs_staged_write", "WRITE"),
    ("src/fs/vfs/vfs_staged.c", "brix_vfs_staged_commit", "PUBLISH"),
    ("src/fs/vfs/vfs_rename.c", "brix_vfs_rename", "RENAME"),
    ("src/fs/vfs/vfs_mkdir.c", "brix_vfs_mkdir", "MKDIR"),
    ("src/fs/vfs/vfs_mkdir.c", "brix_vfs_chmod", "SETATTR"),
    ("src/fs/vfs/vfs_mkdir.c", "brix_vfs_setattr", "SETATTR"),
    ("src/fs/vfs/vfs_unlink.c", "brix_vfs_delete", "REMOVE"),
    (FD_TABLE_C, "brix_validate_write_handle", "WRITE"),
    ("src/protocols/root/write/mv.c", "mv_make_dst_parents", "MKDIR"),
)

# The ctx-less raw export helpers and the operation each must name.
EXPORT_WRAPPERS = (
    ("brix_vfs_export_open_fd", "OPEN"),
    ("brix_vfs_export_open_fd_at", "OPEN"),
    ("brix_vfs_export_unlink", "REMOVE"),
    ("brix_vfs_export_unlink_at", "REMOVE"),
    ("brix_vfs_export_rmdir", "REMOVE"),
    ("brix_vfs_export_mkdir", "MKDIR"),
    ("brix_vfs_export_mkpath", "MKDIR"),
    ("brix_vfs_export_rename", "RENAME"),
    ("brix_vfs_export_copyfile", "COPY"),
    ("brix_vfs_export_copytree", "COPY"),
)

# The kernel forms.  Any of them satisfies a gate.  confined_mutation_checked
# (phase-109) is the NULL-checked inline over require_confined_mutation —
# added so the gcc-13 analyzer can see the ctx != NULL contract locally; it
# routes into the same kernel, so it IS a gate.
KERNEL_CALL = re.compile(
    r"brix_vfs_(?:require_(?:mutation_policy|mutation|confined_mutation"
    r"|carried_mutation)|export_require_mutation"
    r"|confined_mutation_checked)\s*\(")

# Any project call in a gated body.  Everything not allowlisted below is work,
# and work must not happen before the refusal: §0.2 records that several
# mutators dispatch past the cache decorator to the leaf and compensate with a
# hand-rolled brix_sd_cache_evict(), so a gate that drifts below either one lets
# a read-only export resolve a backend, spend a credential, or invalidate a
# cache entry it was never allowed to touch.
PROJECT_CALL = re.compile(r"\b((?:brix|ngx|xvfs)_[a-z0-9_]+)\s*\(")

# The only work permitted ahead of the gate, each for a stated reason.
PRE_GATE_ALLOWED = frozenset((
    # confinement is EINVAL and precedes the policy by design (§4.1)
    "brix_vfs_require_confined",
    # pure accessors: a resolved-path pointer and a monotonic clock read
    "brix_vfs_ctx_path", "brix_vfs_now_ns",
    # the refusal's own observation sink, reached only on the failing branch
    "brix_vfs_xattr_observe_mut",
    # building the policy value that the very next line gates on
    "brix_vfs_export_op_ctx_init", "brix_vfs_policy_from_write_enable",
    # handle bookkeeping ahead of a handle-keyed gate: both refuse an unopened
    # or unpublished handle, and the reopen can only re-attach a handle whose
    # original open already passed the OPEN gate (fd_table.c:298)
    "brix_validate_file_handle", "brix_ensure_write_handle",
))

_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(errors="ignore")


def _strip(text: str) -> str:
    """Blank out comments and string literals, preserving offsets, so an
    ordering assertion reads code and not prose."""
    text = _COMMENT.sub(lambda m: " " * len(m.group(0)), text)
    return _STRING.sub(lambda m: " " * len(m.group(0)), text)


def _body(rel: str, func: str) -> str:
    """The text of `func` in `rel`, from its column-0 definition line to the
    column-0 closing brace.  The tree's coding standard puts the return type on
    its own line and both braces at column 0, so this is exact."""
    src = _read(rel)
    start = re.search(rf"^{re.escape(func)}\s*\(", src, re.M)
    assert start is not None, f"{rel}: no definition of {func}()"
    end = re.search(r"^\}", src[start.start():], re.M)
    assert end is not None, f"{rel}: unterminated body for {func}()"
    return src[start.start():start.start() + end.end()]


def _gate_offset(body: str, op: str) -> int:
    """Offset of the kernel call that names BRIX_VFS_MUTATE_<op>, or -1.  The
    call may wrap across lines, so anchor on the operation token and look back
    for a kernel name in the same statement."""
    for token in re.finditer(rf"\bBRIX_VFS_MUTATE_{op}\b", body):
        head = body[max(0, token.start() - 240):token.start()]
        call = KERNEL_CALL.search(head)
        if call is not None and ";" not in head[call.end():]:
            return max(0, token.start() - 240) + call.start()
    return -1


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel,func,op", GATES,
                         ids=[f"{f}-{o}" for _, f, o in GATES])
def test_mutator_names_the_kernel(rel: str, func: str, op: str) -> None:
    """Every inventoried mutation entry point consults the kernel and names the
    operation the vocabulary reserves for it."""
    assert _gate_offset(_body(rel, func), op) >= 0, (
        f"{rel}:{func}() does not gate on BRIX_VFS_MUTATE_{op}")


@pytest.mark.parametrize("rel,func,op", GATES,
                         ids=[f"{f}-{o}" for _, f, o in GATES])
def test_gate_precedes_every_side_effect(rel: str, func: str, op: str) -> None:
    """Appendix I.5 / §0.2: nothing but the allowlisted preliminaries may run
    ahead of the refusal — no leaf resolution, no cache invalidation, no
    namespace call, no confined syscall, no credential selection.  Otherwise a
    read-only export still does the work, and still leaks which of the later
    gates would also have refused."""
    body = _strip(_body(rel, func))
    gate = _gate_offset(body, op)
    assert gate >= 0, f"{rel}:{func}() lost its BRIX_VFS_MUTATE_{op} gate"
    early = {c for c in PROJECT_CALL.findall(body[:gate])
             if c != func and c not in PRE_GATE_ALLOWED
             and not c.startswith("brix_vfs_require_mutation")}
    assert not early, (
        f"{rel}:{func}() runs {sorted(early)} before its read-only gate")


@pytest.mark.parametrize("func,op", EXPORT_WRAPPERS)
def test_export_wrapper_gates(func: str, op: str) -> None:
    """The ctx-less raw helpers reach storage without a brix_vfs_ctx_t, so each
    carries a wrapper that gates on the policy the caller passed by value."""
    assert _gate_offset(_body(POLICY_EXPORT_C, func), op) >= 0, (
        f"{func}() does not gate on BRIX_VFS_MUTATE_{op}")


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_policy_enum_fails_closed() -> None:
    """READ_ONLY must be the zero value: a zeroed or partially-built object is
    then read-only by construction, never accidentally writable."""
    header = _read(POLICY_H)
    assert re.search(r"BRIX_VFS_MUTATION_READ_ONLY\s*=\s*0\b", header)
    assert re.search(r"BRIX_VFS_MUTATION_ALLOWED\s*=\s*1\b", header)


def test_operation_vocabulary_is_closed() -> None:
    """One vocabulary, one label table, one metric mirror — an op cannot index
    past the names table and cannot mint an unbounded metric label (#8)."""
    header = _read(POLICY_H)
    declared = re.findall(r"\bBRIX_VFS_MUTATE_([A-Z]+)\b", header)
    assert [o for o in declared if o != "OP_COUNT"][:len(OPS)] == list(OPS)
    table = _body(POLICY_C, "brix_vfs_mutation_op_name")
    assert re.findall(r'"([a-z]+)"', table)[:len(OP_LABELS)] == list(OP_LABELS)
    assert '"unknown"' in table
    mirror = re.search(r"BRIX_VFS_MUTATE_OP_METRIC_COUNT\s+(\d+)",
                       _read(UNIFIED_H))
    assert mirror is not None and int(mirror.group(1)) == len(OPS)


def test_metric_mirror_is_compile_time_checked() -> None:
    """The mirror in unified.h keeps the metrics layer free of an fs dependency;
    only a _Static_assert stops the two from drifting."""
    src = _read(POLICY_C)
    assert "_Static_assert" in src
    assert "BRIX_VFS_MUTATE_OP_METRIC_COUNT" in src


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel", (POLICY_C, POLICY_EXPORT_C))
def test_policy_never_answers_eacces(rel: str) -> None:
    """A read-only refusal is a statement about the SERVER.  Laundering it into
    EACCES would make it indistinguishable from an authorization failure and
    would invert the Appendix I.5 precedence."""
    code = [ln for ln in _read(rel).splitlines()
            if not ln.lstrip().startswith(("*", "//", "/*"))]
    assert not [ln for ln in code if "EACCES" in ln], f"{rel} can answer EACCES"


def test_ctx_constructor_normalises_a_stray_policy() -> None:
    """brix_vfs_ctx_init() takes the policy from its caller; anything that is
    not exactly ALLOWED must collapse to READ_ONLY rather than being stored."""
    body = _body(ADOPT_C, "brix_vfs_ctx_init")
    assert re.search(
        r"mutation_policy\s*=\s*\(\s*mutation_policy\s*=="
        r"\s*BRIX_VFS_MUTATION_ALLOWED\s*\)", body), (
        "brix_vfs_ctx_init() stores its policy argument unnormalised")
    assert "BRIX_VFS_MUTATION_READ_ONLY" in body


def test_handle_carries_the_policy_by_value() -> None:
    """A handle outlives the ctx that opened it (Appendix D.5), so it copies the
    policy; a reload that turns the export read-only under an open write handle
    is answered on the next op."""
    assert re.search(r"brix_vfs_mutation_policy_t\s+mutation_policy;",
                     _read("src/fs/vfs/vfs.h"))
    body = _strip(_body(FD_TABLE_C, "brix_validate_write_handle"))
    gate = body.index("brix_vfs_require_carried_mutation")
    assert "kXR_fsReadOnly" in body[gate:], (
        "the handle gate does not answer kXR_fsReadOnly")
    assert "kXR_NotAuthorized" not in body[gate:], (
        "the handle gate can still answer an authorization code")


# ---------------------------------------------------------------------------
# backend independence (W5) — the refusal cannot depend on which driver, or on
# how the decorators are composed, because it is decided before either is known
# ---------------------------------------------------------------------------

DRIVER_LIST_H = "src/core/types/fs_list.h"

#: The three DECORATOR rows of BRIX_FS_DRIVER_LIST.  §0.2 of the plan is that
#: several mutators dispatch past the decorator onto the leaf, so "which
#: decorator, in which order" is a real variable everywhere BELOW the gate —
#: and must be no variable at all above it.
DECORATORS = ("cache", "stage", "remote")


def _driver_rows() -> tuple[str, ...]:
    """Every driver name BRIX_FS_DRIVER_LIST registers, conditional rows
    included — the registry is the enumeration, so a driver added tomorrow
    joins these assertions without anyone remembering to add it."""
    src = _read(DRIVER_LIST_H)
    rows = re.findall(r'^\s*X\(\s*[A-Z0-9_]+,\s*([a-z0-9_]+),', src, re.M)
    assert len(rows) >= 12, rows      # 9 core + 2 ceph + pblock
    return tuple(rows)


def test_the_driver_registry_is_the_enumeration() -> None:
    """Success: the twelve rows the plan names are all really registered, so
    the two assertions below are quantified over the whole registry and not
    over a list transcribed into this file."""
    rows = _driver_rows()
    assert set(rows) >= {"posix", "block", "http", "xroot", "cache", "stage",
                         "remote", "frm", "mirage", "ceph", "cephfs_ro",
                         "pblock"}, rows


def test_the_policy_kernel_names_no_driver() -> None:
    """Security-negative, and the whole of W5's backend-independence claim.

    Running the spy against each of the twelve drivers in turn would repeat one
    assertion twelve times; it would still not rule out a thirteenth driver
    behaving differently.  This does: the kernel and its export wrappers are the
    entire decision path, and if the name of no driver and no decorator appears
    anywhere in them, the refusal provably cannot vary with either — nor with
    the order the decorators are composed in, which is a fact about a chain the
    kernel never sees.  `tests/c/test_vfs_read_only_spy.c` then shows the same
    thing dynamically for one driver carrying every capability bit.
    """
    forbidden = set(_driver_rows()) | set(DECORATORS)
    for rel in (POLICY_H, POLICY_C, POLICY_EXPORT_C):
        words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", _strip(_read(rel))))
        assert not (words & forbidden), (rel, sorted(words & forbidden))


@pytest.mark.parametrize("rel,func,op", GATES, ids=[f"{g[1]}" for g in GATES])
def test_no_mutator_resolves_a_leaf_before_its_gate(rel: str, func: str,
                                                    op: str) -> None:
    """§0.2: `brix_vfs_ns_leaf()` reaches past the decorator, and the four
    sites that lost the decorator's cache invalidation by doing so are the
    reason this phase gates the ENTRY POINT rather than the chain.  A leaf
    resolved before the gate would make the refusal depend on the composition
    the leaf was picked out of — and would leak, to a caller with no write
    right, which driver actually backs the path."""
    body = _strip(_body(rel, func))
    gate = _gate_offset(body, op)
    assert gate >= 0, f"{rel}:{func} has no {op} gate"
    for marker in ("brix_vfs_ns_leaf", "brix_sd_cache_evict",
                   "brix_vfs_backend_resolve"):
        found = body.find(marker)
        assert found < 0 or found > gate, (
            f"{rel}:{func} reaches {marker}() before its mutation gate")
