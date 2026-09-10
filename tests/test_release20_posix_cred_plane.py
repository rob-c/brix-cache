"""test_release20_posix_cred_plane.py — 2.0 F21: the posix per-user identity plane.

F21 was registered as "the 18 `id` cells on `posix` become implemented", on the
premise that a per-user op on a local filesystem "is refused with EACCES in deny
mode and runs as the **export identity** in allow mode".  Auditing the source to
implement it disproved the premise, and this module exists so that the four
findings below can never quietly revert into that misunderstanding again.

  A. **The posix per-user story is not in the `_cred` plane at all.**  `sd_posix`
     has zero `_cred` slots and needs none: the identity is not a credential
     threaded through the SD vtable, it is the calling thread's own
     `setfsuid`/`setfsgid`, installed by the privileged broker one layer BELOW
     the driver at the `beneath` / `confined_canon` seam.  Under `brix_idmap map`
     every namespace syscall `sd_posix` issues is already performed as the mapped
     user, on that user's own DAC.

  B. **`exchange` was the one confined mutation that was NOT brokered.**
     `brix_exchange_beneath()` answered `ENOTSUP` whenever impersonation was
     active, because the broker had no `RENAME_EXCHANGE` verb -- so an export ran
     its whole namespace as the mapped user except this single op, and a tier
     that swapped two names silently lost the capability the moment `brix_idmap
     map` was switched on.  F21 added `IMP_OP_RENAME_EXCHANGE`.

  C. **A `_cred` cell whose base op the driver does not implement cannot be
     `id`.**  The refusal `id` describes lives in `sd_cred_forward.h`'s deny
     branch, which is gated on `driver-><op> != NULL`; where the base slot is
     absent NEITHER branch can run, so there is no per-user gap to claim.

  D. **`sd_posix_dedup.c` deliberately stays the export identity.**  The GCAS
     hardlink farm is server-owned storage shared by every publisher of the same
     bytes; there is no single caller to scope it to.

Every test here is hermetic: source-contract assertions plus a real
`renameat2(RENAME_EXCHANGE)` exercised through `ctypes` on this host, which is
the same syscall (and the same flag) the broker primitive issues.  Nothing needs
root, a fleet, or a built binary.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

BROKER_OPS = REPO / "src/auth/impersonate/broker_ops.c"
BROKER_OPS_NS = REPO / "src/auth/impersonate/broker_ops_ns.c"
BROKER_INTERNAL = REPO / "src/auth/impersonate/broker_internal.h"
IMP_PROTO = REPO / "src/auth/impersonate/impersonate_proto.h"
IMP_HEADER = REPO / "src/auth/impersonate/impersonate.h"
CLIENT_OPS = REPO / "src/auth/impersonate/client_ops.c"
BENEATH = REPO / "src/fs/path/beneath.c"
CONFINED = REPO / "src/fs/path/resolve_confined_ops.c"
SD_POSIX = REPO / "src/fs/backend/posix/sd_posix.c"
SD_POSIX_NS = REPO / "src/fs/backend/posix/sd_posix_ns.c"
SD_POSIX_DEDUP = REPO / "src/fs/backend/posix/sd_posix_dedup.c"
CRED_FORWARD = REPO / "src/fs/backend/sd_cred_forward.h"
MATRIX = REPO / "docs/09-developer-guide/storage-driver-slot-matrix.md"
IMP_DOC = REPO / "docs/06-authentication/impersonation.md"

RENAME_EXCHANGE = 1 << 1


def _body(path: Path, signature: str, close: str = "\n}\n") -> str:
    """The text of one C construct, from its opening line to the closing brace in
    column 0 (`close` is "\\n};\\n" for a struct initialiser).  Deliberately
    literal: these tests are about what the shipped source says, so a refactor
    that silently moves the logic elsewhere should fail here rather than pass
    against a body that is no longer the one that runs."""
    text = path.read_text()
    start = text.index(signature)
    return text[start:text.index(close, start)]


def _code(path: Path) -> str:
    """`path` with every C comment removed.  Needed wherever a test asserts that
    a construct is ABSENT: these files document their own decisions in prose, so
    a naive substring search finds the explanation and calls it a call site."""
    text = re.sub(r"/\*[\s\S]*?\*/", " ", path.read_text())
    return re.sub(r"//[^\n]*", " ", text)


# --------------------------------------------------------------------------
# B. the broker's RENAME_EXCHANGE verb
# --------------------------------------------------------------------------

def test_broker_declares_the_exchange_opcode():
    """The wire op exists and was APPENDED (20), so IMP_PROTO_VERSION stays 1:
    an older worker never sends it and a newer one only reaches a broker built
    from the same tree."""
    proto = IMP_PROTO.read_text()
    assert re.search(r"IMP_OP_RENAME_EXCHANGE\s*=\s*20\b", proto)
    assert re.search(r"#define\s+IMP_PROTO_VERSION\s+1\b", proto)


def test_broker_exchange_uses_renameat2_with_the_exchange_flag():
    body = _body(BROKER_OPS, "imp_do_exchange(int sfd")
    assert "SYS_renameat2" in body
    assert "RENAME_EXCHANGE" in body


def test_broker_exchange_defines_the_flag_when_libc_does_not():
    """RENAME_EXCHANGE is not in every libc's <stdio.h>; the broker carries its
    own definition so the verb cannot silently compile to flag 0 (a plain
    rename) on an older toolchain."""
    header = BROKER_INTERNAL.read_text()
    assert re.search(
        r"#ifndef RENAME_EXCHANGE\s*\n#define RENAME_EXCHANGE \(1u << 1\)", header)


def test_broker_exchange_reports_a_missing_flag_as_enotsup():
    body = _body(BROKER_OPS, "imp_do_exchange(int sfd")
    assert "ENOSYS" in body and "EINVAL" in body and "ENOTSUP" in body


def test_broker_exchange_is_never_emulated_with_two_renames():
    """SECURITY-NEGATIVE, and the whole reason the verb is separate from
    imp_do_rename: the only emulation of an atomic swap is two renames, and that
    window -- an instant in which one of the two names does not resolve -- is
    exactly what a caller asking for `exchange` asked to avoid.  A future
    "compatibility" fallback would look like correctness and would be a silent
    loss of the contract, so the body must contain ONE syscall and no rename."""
    body = _body(BROKER_OPS, "imp_do_exchange(int sfd")
    assert body.count("syscall(") == 1
    assert "renameat(" not in body


def test_noreplace_still_degrades_while_exchange_does_not():
    """The two flags have OPPOSITE degradation policies and the asymmetry is the
    point: NOREPLACE under-claiming exclusivity is survivable, EXCHANGE losing
    atomicity is not.  If a later cleanup folds them into one primitive this
    fails."""
    exchange = _body(BROKER_OPS, "imp_do_exchange(int sfd")
    rename = _body(BROKER_OPS, "imp_do_rename(int sfd")
    assert rename.count("renameat(") == 2       # direct arm + ENOSYS/EINVAL fallback
    assert "renameat(" not in exchange


def test_broker_dispatches_the_exchange_op_through_the_two_path_handler():
    ops = BROKER_OPS.read_text()
    assert re.search(r"\{\s*IMP_OP_RENAME_EXCHANGE,\s*imp_op_rename_link\s*\}", ops)
    handler = _body(BROKER_OPS_NS, "imp_op_rename_link(const imp_op_ctx_t")
    assert "IMP_OP_RENAME_EXCHANGE" in handler
    assert "imp_do_exchange" in handler


def test_client_verb_and_declaration_exist():
    assert "brix_imp_rename_exchange" in IMP_HEADER.read_text()
    body = _body(CLIENT_OPS, "brix_imp_rename_exchange(const char *src")
    assert "IMP_OP_RENAME_EXCHANGE" in body


def test_beneath_exchange_delegates_to_the_broker():
    """Finding B, at the seam: the arm that used to `errno = ENOTSUP; return -1`
    now routes to the broker like its three siblings."""
    body = _body(BENEATH, "beneath_two_path(beneath_two_path_op_t op")
    assert "case BENEATH_2P_EXCHANGE: return brix_imp_rename_exchange(src, dst);" in body


def test_no_beneath_helper_refuses_for_lack_of_a_broker_verb():
    """SECURITY-NEGATIVE / census: every confined helper must now have a broker
    route.  A helper that answers ENOTSUP inside a brix_imp_client_active()
    branch is a capability that disappears the moment impersonation is enabled
    -- which is exactly the F21 defect."""
    text = BENEATH.read_text()
    for match in re.finditer(r"if \(brix_imp_client_active\(\)\) \{", text):
        arm = text[match.start():text.index("\n    }\n", match.start())]
        assert "ENOTSUP" not in arm, arm


# --------------------------------------------------------------------------
# B, executed: the syscall the broker actually issues
# --------------------------------------------------------------------------

def _renameat2(old: str, new: str, flags: int) -> int:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    ctypes.set_errno(0)
    rc = libc.syscall(
        ctypes.c_long(316),                       # SYS_renameat2 on x86_64
        ctypes.c_int(-100),                       # AT_FDCWD
        ctypes.c_char_p(old.encode()),
        ctypes.c_int(-100),
        ctypes.c_char_p(new.encode()),
        ctypes.c_uint(flags))
    return rc if rc == 0 else -ctypes.get_errno()


@pytest.mark.skipif(os.uname().machine != "x86_64",
                    reason="SYS_renameat2 number is hard-coded for x86_64")
def test_renameat2_exchange_swaps_both_names(tmp_path):
    """SUCCESS: the swap the broker performs.  Asserted on the CONTENT behind
    each name, not on a return code -- an exchange that left both names
    resolving to their original inodes would still return 0."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("alpha")
    b.write_text("beta")
    rc = _renameat2(str(a), str(b), RENAME_EXCHANGE)
    if rc == -errno.ENOSYS or rc == -errno.EINVAL:
        pytest.skip("kernel/filesystem here has no RENAME_EXCHANGE")
    assert rc == 0
    assert a.read_text() == "beta"
    assert b.read_text() == "alpha"


@pytest.mark.skipif(os.uname().machine != "x86_64",
                    reason="SYS_renameat2 number is hard-coded for x86_64")
def test_renameat2_exchange_refuses_a_missing_destination(tmp_path):
    """ERROR + SECURITY-NEGATIVE: an exchange needs BOTH names to exist.  A
    plain rename would have succeeded here by MOVING the source, so the source
    surviving in place is the observable proof that no rename fallback ran --
    the same property the source-level pin above asserts, checked against the
    kernel instead of against the text."""
    a, b = tmp_path / "a", tmp_path / "gone"
    a.write_text("alpha")
    rc = _renameat2(str(a), str(b), RENAME_EXCHANGE)
    if rc == -errno.ENOSYS:
        pytest.skip("kernel/filesystem here has no RENAME_EXCHANGE")
    assert rc == -errno.ENOENT
    assert a.read_text() == "alpha"
    assert not b.exists()


# --------------------------------------------------------------------------
# A. the posix per-user identity lives at the seam, not in the `_cred` plane
# --------------------------------------------------------------------------

def test_sd_posix_declares_no_cred_slots():
    """Finding A, stated negatively.  The absence is deliberate, so a future
    reader who adds `.open_cred` to close an `id` cell should have to delete
    this test -- and read the docstring while doing it."""
    table = _body(SD_POSIX, "const brix_sd_driver_t brix_sd_posix_driver = {",
                  close="\n};\n")
    assert "_cred" not in table
    assert ".cred_accept" not in table


def test_sd_posix_namespace_ops_route_through_the_identity_seam():
    """Finding A, stated positively: the namespace ops call the confined
    helpers, which are the layer that delegates to the broker.  Invariant 12's
    guard covers raw DATA syscalls; nothing else pins the IDENTITY seam."""
    text = SD_POSIX_NS.read_text()
    for helper in ("brix_lstat_beneath", "brix_open_beneath",
                   "brix_exchange_beneath", "brix_setattr_confined_canon",
                   "brix_chmod_confined_canon", "brix_getxattr_confined_canon",
                   "brix_setxattr_confined_canon"):
        assert helper in text, helper


def test_every_confined_mutation_has_an_impersonation_branch():
    """The seam's contract in one assertion: each of these helpers dispatches on
    brix_imp_client_active() somewhere in beneath.c."""
    text = BENEATH.read_text()
    assert text.count("brix_imp_client_active()") >= 6
    for verb in ("brix_imp_open", "brix_imp_stat", "brix_imp_unlink",
                 "brix_imp_mkdir", "brix_imp_rename",
                 "brix_imp_rename_noreplace", "brix_imp_rename_exchange",
                 "brix_imp_link"):
        assert verb + "(" in text, verb


def test_directory_open_is_brokered_as_an_open_not_a_new_verb():
    """The register asked for "an opendir verb for opendir_cred".  There isn't
    one and there should not be: brix_opendir_confined_canon_at() asks the
    broker for an O_DIRECTORY fd and fdopendir()s it, so the mapped user's DAC
    has already decided by the time the fd comes back."""
    body = _body(CONFINED, "brix_opendir_confined_canon_at(ngx_log_t *log")
    assert "brix_imp_client_active()" in body
    assert "brix_imp_open(rel, O_RDONLY | O_DIRECTORY, 0)" in body
    assert "fdopendir" in body
    assert "IMP_OP_OPENDIR" not in IMP_PROTO.read_text()


def test_opendir_beneath_is_the_off_impersonation_arm_only():
    """brix_opendir_beneath() is the one beneath helper with no impersonation
    branch, which is safe ONLY because it has exactly one caller and that caller
    checks first.  A second caller would reintroduce the F21 defect silently, so
    the count is the assertion."""
    callers = [p for p in (REPO / "src").rglob("*.c")
               if p != BENEATH and "brix_opendir_beneath" in p.read_text()]
    assert callers == [CONFINED], callers
    assert "IMPERSONATION:" in _body(BENEATH, "brix_opendir_beneath(int rootfd")


# --------------------------------------------------------------------------
# C. `id` is only meaningful where the plain twin exists
# --------------------------------------------------------------------------

def _matrix_lines() -> list:
    """The generated table only, between its fences -- never the surrounding
    prose, which also contains pipe characters."""
    body = MATRIX.read_text().split("<!-- sd-slot-matrix:begin -->")[1]
    body = body.split("<!-- sd-slot-matrix:end -->")[0]
    return [[c.strip() for c in l.strip("|").split("|")]
            for l in body.splitlines() if l.startswith("|")]


def _matrix_rows() -> dict:
    """{op: {driver: verdict}} for every slot row (the bold counts row, which is
    not a slot, is dropped by the backtick test)."""
    lines = _matrix_lines()
    drivers = lines[0][1:]
    return {cells[0].strip("`"): dict(zip(drivers, cells[1:]))
            for cells in lines[2:] if cells[0].startswith("`")}


def test_no_cred_cell_claims_id_without_an_implemented_base_op():
    """Finding C.  sd_cred_forward.h's deny branch is gated on
    `driver-><op> != NULL`; where the base slot is absent neither branch can
    run, so `id` would describe a refusal that cannot happen."""
    rows = _matrix_rows()
    offenders = [
        (op, drv)
        for op, cells in rows.items() if op.endswith("_cred")
        for drv, verdict in cells.items()
        if verdict == "id" and rows.get(op[: -len("_cred")], {}).get(drv) != "✅"
    ]
    assert offenders == [], offenders


def _cred_forward_deny_gates() -> dict:
    """{op: True if that op's EACCES refusal can only be reached when the driver
    implements the plain slot}.  Three spellings are in use and all three count:
    the same-line `&& inst->driver-><op> != NULL` (16 forwarders), and -- where
    an earlier guard already returned on the absent slot -- ENOSYS (`mkdir`) or
    a no-op NGX_OK (`setattr`).  What matters is that the refusal is downstream
    of a `inst->driver-><op> == NULL` decision, not how that decision answers."""
    gates = {}
    for fwd in re.split(r"static ngx_inline", _code(CRED_FORWARD))[1:]:
        head, _, tail = fwd.partition("cred->fallback_deny")
        if not tail:
            continue
        op = re.match(r"\s*&&\s*inst->driver->(\w+)_cred == NULL", tail).group(1)
        gates[op] = (f"inst->driver->{op} != NULL" in tail[:200]
                     or f"inst->driver->{op} == NULL" in head)
    return gates


def test_cred_forward_deny_branch_is_gated_on_the_plain_slot():
    """The source half of finding C: the EACCES refusal that `id` describes can
    only be reached when the driver actually implements the plain slot -- which
    is why stamping `id` on a cell whose base op is absent describes a refusal
    that cannot happen."""
    gates = _cred_forward_deny_gates()
    assert len(gates) == 18, sorted(gates)
    assert [op for op, gated in gates.items() if not gated] == []


def test_posix_keeps_id_only_where_it_has_the_base_op():
    """The four cells this rule moved (recall/evict/unlink_many/truncate_path)
    stay off `id`, and the ones with a real base op stay on it."""
    rows = _matrix_rows()
    for op in ("recall_cred", "evict_cred", "unlink_many_cred",
               "truncate_path_cred"):
        assert rows[op]["posix"] != "id", op
    for op in ("open_cred", "stat_cred", "rename_cred", "exchange_cred"):
        assert rows[op]["posix"] == "id", op


# --------------------------------------------------------------------------
# D. the GCAS farm is deliberately the export identity
# --------------------------------------------------------------------------

def test_gcas_dedup_stays_the_export_identity_on_purpose():
    """Finding D.  These raw link/rename/unlink calls are the ONE posix
    namespace site that is not routed through the identity seam, and that is a
    decision, not an oversight: the farm's names are content-derived, no client
    can address them, and one inode is shared by every publisher of those bytes,
    so st_nlink -- the refcount -- would become unmaintainable if each publish
    ran as a different user.  The comment is asserted because without it the
    next auditor "fixes" this."""
    prose = SD_POSIX_DEDUP.read_text()
    assert "IDENTITY:" in prose
    assert "SERVER-OWNED" in prose
    code = _code(SD_POSIX_DEDUP)
    assert "brix_imp_" not in code
    assert "_confined_canon(" not in code
    assert "_beneath(" not in code


# --------------------------------------------------------------------------
# the docs say what the code does
# --------------------------------------------------------------------------

def test_slot_matrix_documents_the_two_corrections():
    text = MATRIX.read_text()
    assert "`id` is only stamped where the plain twin exists (2.0 F21)" in text
    assert 'On `posix`, `id` does NOT mean "runs as the export" (2.0 F21)' in text
    assert "IMP_OP_RENAME_EXCHANGE" in text


def test_the_operator_guide_names_the_brokered_exchange():
    """The user-facing half of F21.  `docs/06-authentication/impersonation.md` is
    where an operator decides whether turning impersonation on costs them
    anything; until 2.0 it cost them the atomic two-name swap, silently.  The
    page must now list `exchange` among the brokered mutations AND say which way
    it fails, because "brokered" alone would leave a reader assuming the same
    kernel fallback the exclusive-rename arm has."""
    text = IMP_DOC.read_text()
    assert "renameat2(RENAME_EXCHANGE)" in text
    assert "never emulated with two renames" in text.lower()
    assert "ENOTSUP" in text


def test_the_operator_guide_does_not_promise_an_exchange_fallback():
    """SECURITY-NEGATIVE for the doc: the failure this pins is a future editor
    "harmonising" the exchange bullet with the NOREPLACE one, which DOES degrade.
    An operator who read that would build a publish path on an atomicity
    guarantee the server never makes -- the exact window `RENAME_EXCHANGE`
    exists to close.  The two contracts differ on purpose and the page must keep
    saying so."""
    text = IMP_DOC.read_text()
    swap = text[text.index("renameat2(RENAME_EXCHANGE)"):]
    swap = swap[:swap.index("- **S3 runs every op")]
    assert "fall back to a plain rename" in swap, \
        "the page must still contrast exchange with the NOREPLACE arm"
    assert "exclusive-rename" in swap
    for promise in ("falls back to two renames", "degrades to two renames",
                    "emulated with two renames instead"):
        assert promise not in swap, promise
