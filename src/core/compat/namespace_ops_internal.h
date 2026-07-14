#ifndef BRIX_NAMESPACE_OPS_INTERNAL_H
#define BRIX_NAMESPACE_OPS_INTERNAL_H

/*
 * namespace_ops_internal.h — declarations shared between the two halves of the
 * namespace-mutation service after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the two confinement/result helpers that the local-copy
 *       path (namespace_ops_copy.c) reuses from the mutation core
 *       (namespace_ops.c): ns_rel() (open the RESOLVE_BENEATH rootfd + return the
 *       within-root tail) and ns_set_err() (record errno + mapped BRIX_NS_*).
 * WHY:  namespace_ops.c (delete/mkdir/rename core + confinement primitives) and
 *       namespace_ops_copy.c (single-file local copy path) were one 611-line
 *       file; splitting keeps each focused and under the 500-line cap. The copy
 *       path must open its rootfd and map errno exactly as the core does — so
 *       those two helpers, and only those two, become non-static and are shared
 *       through this header rather than duplicated. errno_to_ns_status() stays
 *       static in namespace_ops.c (used there directly by mkdir/rename and,
 *       transitively, by ns_set_err()).
 * HOW:  Both translation units include this header; neither symbol is exported
 *       beyond the namespace-ops module. It layers on namespace_ops.h for the
 *       brix_ns_result_t definition.
 */

#include "namespace_ops.h"   /* brix_ns_result_t */

/*
 * ns_rel — open a confinement rootfd on root_canon and return the within-root
 * relative tail of abspath.  *rootfd_out receives the fd (caller closes it);
 * returns NULL with *rootfd_out=-1 and errno set when the rootfd cannot be
 * opened or abspath escapes root_canon.  Defined in namespace_ops.c.
 */
const char *ns_rel(const char *root_canon, const char *abspath,
    int *rootfd_out);

/*
 * ns_set_err — record a failed syscall's errno on the result: stores err in
 * res->sys_errno and the mapped BRIX_NS_* code in res->status.  Defined in
 * namespace_ops.c.
 */
void ns_set_err(brix_ns_result_t *res, int err);

#endif /* BRIX_NAMESPACE_OPS_INTERNAL_H */
