/*
 * broker_ops_internal.h — private split contract between broker_ops.c and
 * broker_ops_ns.c after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the parent-relative namespace-mutation op handlers that
 *       live in broker_ops_ns.c and are referenced by the opcode dispatch table
 *       (imp_op_table) which stays in broker_ops.c.
 * WHY:  broker_ops.c was 693 lines — over the 500-line file-size cap. The
 *       parent-confined namespace ops (mkdir/unlink/rmdir/chmod/chown/rename/
 *       link/setattr/symlink/readlink) plus their private imp_with_parent /
 *       imp_step_* machinery form one cohesive concern and move to
 *       broker_ops_ns.c; the primitives, fd/xattr ops, and the dispatch entry
 *       (imp_do_op + imp_op_table) stay in broker_ops.c. Only the eight op
 *       handlers cross the boundary (the table references them), so exactly
 *       those become non-static and are declared here.
 * HOW:  Both translation units include this header; none of these symbols is
 *       exported beyond src/auth/impersonate/. Requires imp_op_ctx_t from
 *       broker_internal.h before inclusion.
 */
#ifndef BRIX_BROKER_OPS_INTERNAL_H
#define BRIX_BROKER_OPS_INTERNAL_H

#include "broker_internal.h"   /* imp_op_ctx_t */

/* broker_ops_ns.c — parent-relative namespace-mutation op handlers.  Each takes
 * the bundled op context and returns 0 or -errno; all are dispatched by
 * imp_op_table in broker_ops.c. */
int imp_op_mkdir(const imp_op_ctx_t *c);
int imp_op_unlink(const imp_op_ctx_t *c);       /* UNLINK + RMDIR */
int imp_op_chmod(const imp_op_ctx_t *c);
int imp_op_chown(const imp_op_ctx_t *c);
int imp_op_rename_link(const imp_op_ctx_t *c);  /* RENAME + RENAME_NOREPLACE + LINK */
int imp_op_setattr(const imp_op_ctx_t *c);
int imp_op_symlink(const imp_op_ctx_t *c);
int imp_op_readlink(const imp_op_ctx_t *c);

#endif /* BRIX_BROKER_OPS_INTERNAL_H */
