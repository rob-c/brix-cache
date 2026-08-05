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

/* LOOP-ONLY. Report a completed rename as one two-path BRIX_CNS_MV event, so the
 * manager moves the entry AND the recorded subtree under it in a single locked
 * step. `size`/`mtime`/`is_dir` describe the destination as observed after the
 * rename. Same best-effort gating as brix_cns_emit. */
void brix_cns_emit_rename(ngx_stream_brix_srv_conf_t *conf,
                          const char *src_resolved, const char *dst_resolved,
                          uint64_t size, uint64_t mtime, int is_dir);

/*
 * HTTP-plane seam (WebDAV / S3 / gridftp).
 *
 * WHY a second entry point: the manager link hangs off a stream{} server conf,
 * which an http{} handler has no path to. These resolve the emitting server
 * block from the cycle instead, so a plane that never sees a stream conf can
 * still report — closing the "manager only tracks root:// mutations" gap.
 *
 * `root_canon` is the CALLER's export root: it is the prefix stripped to form
 * the logical path, and an http location's root need not be the stream one.
 * size/mtime must come from the caller's own VFS probe (its identity, backend
 * credential and delegation bind there, not here); they are 0 for DEL/RMDIR.
 *
 * Same best-effort contract as the stream entry points: silent no-op when CNS
 * is off or the manager link is down, and never blocks the data path.
 */

/* Cheap gate — is any server block in EMIT mode with a live link? Lets a caller
 * skip an observation syscall it would only need in order to report. */
ngx_flag_t brix_cns_emit_active(void);

void brix_cns_emit_at(const char *root_canon, uint8_t op, const char *resolved,
                      uint64_t size, uint64_t mtime);

void brix_cns_emit_rename_at(const char *root_canon, const char *src_resolved,
                             const char *dst_resolved, uint64_t size,
                             uint64_t mtime, int is_dir);

#endif /* NGX_BRIX_CMS_CNS_EMIT_H */
