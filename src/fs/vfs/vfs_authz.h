/*
 * vfs_authz.h — the VFS authorization backstop (phase-108 C12), internal API.
 *
 * WHAT: Declares position 1.5 of the §3.4 mutation ordering — the check that
 *       runs after the phase-105 mutation-policy kernel (position 1, EROFS) and
 *       before the lock check (position 2, EBUSY): does THIS identity have the
 *       privilege the operation needs on the resolved path? It is a BACKSTOP,
 *       not a relocation — the protocol edge still refuses first, composes the
 *       wire-correct denial, and owns the SHM verdict cache. The VFS kernel is
 *       the checkpoint that cannot be forgotten when a new handler reaches
 *       storage without asking (§C12.4).
 *
 * WHY:  Authorization is decided today at 28 protocol-edge sites in several
 *       vocabularies, held together by comments ("deliberately auth-free so
 *       this gate cannot be bypassed"). A comment is a convention the next
 *       author must be told about; a backstop is what replaces a convention.
 *       The backstop re-derives the verdict from the IDENTITY — never from the
 *       edge's cache — so a disagreement means a real bypass, not a stale memo.
 *
 * HOW:  Reuses the exact three-tier evaluator the edge runs (auth_gate.c), in
 *       its identity-only forms: native authdb via brix_check_authdb_identity,
 *       VO ACL via brix_check_vo_acl_identity, token scope via
 *       brix_identity_check_token_scope; the xrdacc arm memoizes its
 *       brix_acc_entity_t on the identity (identity.h acc_entity) so position
 *       1.5 stays allocation-free. Fail-closed: an unbound ctx, an identity it
 *       cannot interpret, or an operation with no privilege mapping is a
 *       refusal — a counter+WARN under OBSERVE, EACCES under ENFORCE.
 *
 * The two GATE wrappers below are what the VFS mutators actually call: they
 * fuse position 1 and position 1.5 into one line so the backstop is inherited,
 * not remembered. The raw brix_vfs_require_confined_mutation / _require_mutation
 * kernel forms are banned at mutator call sites by
 * tools/ci/check_authz_backstop.py; only these wrappers (and the phase-105
 * kernel itself, and the carried-policy delayed-work forms) may reach them.
 */
#ifndef BRIX_VFS_AUTHZ_H
#define BRIX_VFS_AUTHZ_H

#include "vfs.h"
#include "vfs_policy.h"

/* The backstop's per-evaluation outcome, mirrored as a bounded metric label by
 * BRIX_AUTHZ_BACKSTOP_RESULT_COUNT (observability/metrics/unified.h); vfs_authz.c
 * carries the compile-time equality check. AGREE = the backstop reached the same
 * verdict the edge did (the normal case); EDGE_MISSING = the backstop would have
 * refused but the edge already allowed the request (the bypass class this item
 * exists to catch); NO_RULES = a bound export with no rules (allow-all today);
 * UNBOUND = a ctx that reached a mutation without binding a rule set. The last
 * two are honest facts, not errors — but UNBOUND fails closed under ENFORCE. */
typedef enum {
    BRIX_AUTHZ_BACKSTOP_AGREE = 0,
    BRIX_AUTHZ_BACKSTOP_EDGE_MISSING,
    BRIX_AUTHZ_BACKSTOP_NO_RULES,
    BRIX_AUTHZ_BACKSTOP_UNBOUND,
    BRIX_AUTHZ_BACKSTOP_RESULT_N   /* never a real result — the array bound */
} brix_authz_backstop_result_t;

/* Map a bounded mutation operation onto the BRIX_AUTH_* privilege the edge
 * already passes by hand for it (§C12.3). Returns the primary needed-privilege
 * mask; *also_delete is set to 1 for RENAME/COPY, which the tree already treats
 * as UPDATE on the destination AND DELETE on the source (mv.c precedent). An
 * operation with no export-storage mapping (DEDUP, CREDENTIAL — governed by the
 * typed domain assert, not a rule) returns 0, which the kernel reads as
 * "undecidable" ⇒ fail-closed. Pure. */
uint32_t brix_vfs_authz_level_for_op(brix_vfs_mutation_op_t op,
    int *also_delete);

/* Position 1.5 for a mutation: re-derive the authorization verdict for `op` on
 * ctx->resolved from ctx->identity + ctx->authz. NGX_OK when the backstop
 * agrees (or is OFF, or the export is allow-all); NGX_ERROR with errno EACCES
 * under ENFORCE when it would refuse. Under OBSERVE a refusal is recorded
 * (counter + WARN) and NGX_OK is returned — the edge stays authoritative for
 * one release. Never consults the SHM verdict cache. */
ngx_int_t brix_vfs_require_authorized(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);

/* Destination half of RENAME/COPY: UPDATE on the already-confined target.
 * The ordinary form checks DELETE on the source. */
ngx_int_t brix_vfs_require_authorized_target(const brix_vfs_ctx_t *ctx,
    const char *path, brix_vfs_mutation_op_t op);

/* Read-side twins. Data access asks for BRIX_AUTH_READ/BRIX_AOP_READ; namespace
 * metadata and enumeration ask for BRIX_AUTH_LOOKUP/BRIX_AOP_STAT. Keeping the
 * privileges distinct matches the edge and avoids silently requiring both. */
ngx_int_t brix_vfs_require_authorized_read(const brix_vfs_ctx_t *ctx);
ngx_int_t brix_vfs_require_authorized_lookup(const brix_vfs_ctx_t *ctx);

/* GATE wrapper — confined path mutators. Runs position 1 (confinement + the
 * phase-105 mutation-policy kernel, EROFS/EINVAL, NULL-safe) then position 1.5
 * (the authorization backstop, EACCES). Returns NGX_OK only when both pass.
 * The EROFS non-disclosure property survives because position 1 answers first:
 * a read-only endpoint returns EROFS and the backstop never speaks. */
ngx_int_t brix_vfs_gate_confined(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);

/* GATE wrapper — handle/ctx mutators that gate on the ctx policy without a
 * fresh confinement check (the handle was confined at open). Runs position 1
 * (brix_vfs_require_mutation) then position 1.5. */
ngx_int_t brix_vfs_gate_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);

/* Late handle form of the same fused gate. A file handle can outlive the
 * stack-owned ctx used to open it, so adoption snapshots the bounded authz
 * bundle, identity and root. This helper reconstructs a transient ctx and
 * preserves policy-before-authz ordering without dereferencing fh->ctx. */
ngx_int_t brix_vfs_gate_file_mutation(const brix_vfs_file_t *fh,
    brix_vfs_mutation_op_t op);

#endif /* BRIX_VFS_AUTHZ_H */
