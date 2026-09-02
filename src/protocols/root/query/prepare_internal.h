#ifndef BRIX_PREPARE_INTERNAL_H
#define BRIX_PREPARE_INTERNAL_H

/*
 * prepare_internal.h — helpers shared across the kXR_prepare / kXR_QPrep
 * translation units (prepare.c, prepare_qprep.c).  These were file-static in
 * prepare.c until the QPrep handler was split into prepare_qprep.c to keep each
 * file focused (and under the size cap); only the genuinely shared entry points
 * are promoted here — everything else stays static in its owning .c.
 */

#include "core/ngx_brix_module.h"

/*
 * Log a PREPARE/QPREP access event and send the wire error in one step.
 * Returns brix_send_error()'s result verbatim (NGX_OK on a queued response).
 * `path` may be NULL (rendered as "-").
 */
ngx_int_t brix_prepare_send_fail(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg);

/*
 * Validate + authorize ONE newline-separated prepare path (length/extract/
 * forbidden-component pre-checks, confined stat, three authorization tiers).
 * Lives in prepare_check.c; the prepare.c scan pipeline is the sole caller.
 * `out_resolved` is a PATH_MAX buffer filled with the absolute path on auth-pass
 * paths ('\0' if unresolvable); pass NULL when staging collection is not needed.
 * Returns NGX_OK on pass, NGX_DONE when a response was already sent, or an error.
 */
ngx_int_t brix_prepare_check_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const u_char *line, size_t line_len,
    ngx_flag_t noerrs, ngx_uint_t *missing, char *out_resolved);

/* Owner-key storage: "anon-session:" + 32 hex chars + NUL fits with room. */
#define BRIX_PREPARE_OWNER_KEY_MAX  64

/*
 * Shared state for the kXR_prepare path-scan pipeline (alloc → scan → emit),
 * promoted here when the W6 recall/evict arms moved to prepare_recall.c.
 * Passed by pointer so the phases read/accumulate the same counters and
 * staging buffers without a long positional argument list.  group_reqid points
 * at a caller-owned BRIX_STAGE_REQID_LEN buffer.
 */
typedef struct {
    ngx_stream_brix_srv_conf_t *conf;
    uint16_t     options;          /* req.options snapshot */
    ngx_flag_t   need_resolved;    /* fill out_resolved (any arm below is on)  */
    ngx_flag_t   do_stage;         /* kXR_stage: drive brix_vfs_recall (W6)    */
    ngx_flag_t   do_evict;         /* kXR_evict: drive brix_vfs_evict (W6)     */
    ngx_flag_t   do_enqueue;       /* record into the durable FRM queue        */
    ngx_flag_t   collect_stage;    /* prepare_command configured (the fallback)*/
    const char **stage_paths;      /* pool array, stage_max entries            */
    char        *stage_bufs;       /* pool array, stage_max * PATH_MAX         */
    ngx_uint_t   stage_max;
    ngx_uint_t   stage_count;      /* accumulated resolved paths (buffer slots)*/
    ngx_uint_t   cmd_count;        /* stage_paths entries for prepare_command  */
    ngx_uint_t   paths;            /* non-empty lines seen                     */
    ngx_uint_t   missing;          /* absent-but-authorized paths (noerrs)     */
    char        *group_reqid;      /* first durable reqid = client handle      */
} prepare_scan_t;

/*
 * The stable owner string for FRM stage records and the FRM-1 ownership checks
 * (cancel/evict): the identity DN when authenticated, else "anon-session:" +
 * hex(sessid) rendered into the caller's anon_key buffer.  Lives in prepare.c.
 */
const char *brix_prepare_owner_key(brix_ctx_t *ctx, char *anon_key,
    size_t anon_key_sz);

/*
 * The op_vfs_ctx pattern (op_table.c) for the prepare plane: bind identity,
 * write policy, backend-credential policy and the phase-70 delegation to a
 * stream VFS ctx for `resolved`.  Lives in prepare_recall.c; shared with
 * kXR_QPrep so the residency probe sees the same credential policy the
 * recall/evict arms see.
 */
void brix_prepare_vfs_ctx(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *resolved,
    brix_vfs_ctx_t *vctx);

/*
 * W6 per-path arms (prepare_recall.c).  Both return NGX_OK to continue the
 * scan, or NGX_DONE after sending a terminal wire response themselves.
 *
 * recall_one: the record-before-driver-call lifecycle around brix_vfs_recall —
 * join an existing registry record (same reqid, one record), else record FIRST,
 * then drive the driver; a synchronous driver failure deletes the record so no
 * orphan reqid is pollable; ENOTSUP falls back to prepare_command collection /
 * the durable FRM engine, or kXR_Unsupported on a nearline export with neither.
 *
 * evict_one: FRM-1 ownership (a path bound to a live stage record may only be
 * evicted by that record's creator) then brix_vfs_evict; a retired record is
 * deleted so kXR_QPrep answers from residency truth, not a stale DONE.
 */
ngx_int_t brix_prepare_recall_one(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, char *out_resolved);
ngx_int_t brix_prepare_evict_one(brix_ctx_t *ctx, ngx_connection_t *c,
    prepare_scan_t *sc, char *out_resolved);

#endif /* BRIX_PREPARE_INTERNAL_H */
