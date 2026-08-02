#ifndef NGX_BRIX_CMS_CNS_EMIT_H
#define NGX_BRIX_CMS_CNS_EMIT_H

/*
 * cns_emit.h — data-server CNS event emission (§6 wire wrappers). See cns_emit.c.
 *
 * WHAT: brix_cns_emit() is the single, shared "report a namespace mutation to the
 *       manager" seam used by every data-server mutation call site (file
 *       close-after-write → ADD, rm → DEL, rmdir → RMDIR, mkdir → MKDIR).
 * WHY:  the receive/apply side (brix_cns_apply) has always handled all four ops;
 *       only ADD was ever emitted. This closes the remaining emit wrappers so a
 *       delete/mkdir/rmdir on a data server converges into the manager inventory.
 * HOW:  no-op unless `brix_cns emit` is set AND the worker's manager CMS link is
 *       connected + logged in; strips the export root_canon prefix to the
 *       client-facing logical path; encodes + fire-and-forget sends a CMS_RR_CNS
 *       frame. Best-effort by design (INVARIANT: never blocks the data path).
 */

#include "core/ngx_brix_module.h"   /* ngx_stream_brix_srv_conf_t, ngx types */
#include <stdint.h>

/* LOOP-ONLY. `op` is one of BRIX_CNS_ADD/DEL/MKDIR/RMDIR (cns.h). `resolved` is
 * the canonical (root_canon-prefixed) on-disk path of the mutated object; the
 * logical path reported to the manager is derived from it. size/mtime are 0 for
 * DEL/RMDIR (apply ignores them). Silent no-op when CNS is off or the manager
 * link is down. */
void brix_cns_emit(ngx_stream_brix_srv_conf_t *conf, uint8_t op,
                   const char *resolved, uint64_t size, uint64_t mtime);

#endif /* NGX_BRIX_CMS_CNS_EMIT_H */
