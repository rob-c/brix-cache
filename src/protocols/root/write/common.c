
/*
 * common.c — shared helpers for write-side opcode handlers.
 *
 * Provides brix_try_post_write_aio() — AIO task setup and thread-pool
 * dispatch for kXR_write / kXR_pgwrite syscalls — and the two §6 CNS emit
 * wrappers whose only difference from the bare brix_cns_emit seam is that they
 * must first observe the mutated object (size / mtime / dir-ness) through the
 * VFS.  They live here rather than in net/cms because the observation needs a
 * request-identity VFS context, which is root-plane knowledge.
 *
 * Note: path-based write opcodes (mkdir, mv, rmdir, truncate) perform auth via
 * brix_auth_gate() directly; chmod/rm dispatch through the op-descriptor
 * table in op_table.c.  The former shared resolver
 * (brix_write_resolve_existing_path) was retired once those callers migrated
 * and has been removed.
 */
#include "core/ngx_brix_module.h"
#include "fs/vfs/vfs.h"                    /* brix_vfs_probe for size/mtime     */
#include "protocols/root/path/op_path.h"   /* brix_root_vfs_bind_session          */
#include "net/cms/cns.h"                   /* BRIX_CNS_ADD / BRIX_CNS_MKDIR     */
#include "net/cms/cns_emit.h"              /* brix_cns_emit{,_rename}           */

/*
 * root_cns_probe — stat one mutated object with the requesting user's identity.
 *
 * WHAT: Fills *st for `path` through the VFS seam, bound exactly as every other
 *       namespace op in this plane binds (identity + backend credential +
 *       delegation), so a remote-backed export is probed as the CLIENT.
 * WHY:  A CNS event carries size/mtime, and for a rename also the destination's
 *       dir-ness.  Reading them with a raw stat() would both bypass the VFS seam
 *       (INVARIANT 12) and read the wrong thing on a non-POSIX backend.
 * HOW:  ctx_init + bind_backend_cred + bind_deleg + brix_vfs_probe, no-follow so
 *       a symlink is reported as itself.  Returns NGX_OK on a hit.
 */
static ngx_int_t
root_cns_probe(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *path, brix_vfs_stat_t *st)
{
    brix_vfs_ctx_t vctx;

    brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls */, ctx->identity, path);
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_root_vfs_bind_session(ctx, conf, &vctx);

    return brix_vfs_probe(&vctx, 1 /* no-follow */, st);
}

void
brix_root_cns_emit_moved(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *src_resolved,
    const char *dst_resolved)
{
    brix_vfs_stat_t st;

    /* Gate BEFORE the probe: the probe is a real syscall, and CNS is off on
     * every node that is not a federation data server. */
    if (conf->cns_mode != BRIX_CNS_EMIT) {
        return;
    }
    if (root_cns_probe(ctx, c, conf, dst_resolved, &st) != NGX_OK) {
        /* The rename succeeded but the destination cannot be observed (a racing
         * unlink, a backend that lost it).  Emitting a rename whose metadata we
         * had to invent would seed the manager with a wrong size, so drop the
         * source entry instead and let the next ADD re-establish the truth. */
        brix_cns_emit(conf, BRIX_CNS_DEL, src_resolved, 0, 0);
        return;
    }
    brix_cns_emit_rename(conf, src_resolved, dst_resolved,
                           (uint64_t) st.size, (uint64_t) st.mtime,
                           st.is_directory);
}

void
brix_root_cns_emit_resized(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *resolved)
{
    brix_vfs_stat_t st;

    if (conf->cns_mode != BRIX_CNS_EMIT) {
        return;
    }
    if (root_cns_probe(ctx, c, conf, resolved, &st) != NGX_OK) {
        return;                            /* unobservable → leave the entry be */
    }
    brix_cns_emit(conf, st.is_directory ? BRIX_CNS_MKDIR : BRIX_CNS_ADD,
                    resolved, (uint64_t) st.size, (uint64_t) st.mtime);
}

ngx_int_t
brix_try_post_write_aio(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    off_t offset, const u_char *data, size_t len, int64_t req_offset,
    ngx_uint_t is_pgwrite, u_char *payload_to_free,
    const xrdp_pg_bad_t *bad, size_t bad_count, const char *fallback_log,
    ngx_flag_t *posted)
{
    ngx_stream_brix_srv_conf_t *conf;
    ngx_thread_task_t            *task;
    brix_write_aio_t           *t;

    *posted = 0;

    conf = ngx_stream_get_module_srv_conf((ngx_stream_session_t *) (c->data),
                                          ngx_stream_brix_module);
    if (conf->common.thread_pool == NULL) {
        return NGX_OK;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(brix_write_aio_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->c               = c;
    t->ctx             = ctx;
    t->conf            = conf;
    t->fd              = ctx->files[idx].fd;
    t->handle_idx      = idx;
    t->offset          = offset;
    t->data            = data;
    t->len             = len;
    t->req_offset      = req_offset;
    t->is_pgwrite      = is_pgwrite;
    t->nwritten        = -1;
    t->io_errno        = 0;
    t->csi             = ctx->files[idx].csi;  /* phase-59 W2: tag update */
    t->obj             = ctx->files[idx].sd_obj; /* Layer 3: driver obj or zeroed */
    t->payload_to_free = payload_to_free;
    t->bad_page_count  = (bad != NULL && bad_count > kXR_pgMaxEpr)
                         ? kXR_pgMaxEpr : bad_count;
    if (bad != NULL && t->bad_page_count > 0) {
        ngx_memcpy(t->bad_pages, bad,
                   t->bad_page_count * sizeof(xrdp_pg_bad_t));
    }
    t->streamid[0]     = ctx->recv.cur_streamid[0];
    t->streamid[1]     = ctx->recv.cur_streamid[1];
    ngx_cpystrn((u_char *) t->path,
                (u_char *) (ctx->files[idx].path != NULL
                             ? ctx->files[idx].path : "-"),
                sizeof(t->path));
    t->start_ns = brix_phase_now_ns();  /* phase-56 D-2 */

    brix_task_bind(task, brix_write_aio_thread, brix_write_aio_done);

    return brix_aio_post_task(ctx, c, conf->common.thread_pool, task, fallback_log,
                                posted);
}
/* WHY: Provides uniform thread-pool dispatch for write syscalls, enabling parallel disk I/O without blocking the main event loop during large file transfers. Detaches payload from ctx->recv.payload_buf so the main thread can safely read next request headers while write happens in worker threads. The posted flag enables callers to distinguish between dispatched and fallback cases — dispatched=1 means completion callback handles response; dispatched=0 means caller must perform synchronous pwrite. */
/* HOW: Sets *posted=0 initially; retrieves conf via ngx_stream_get_module_srv_conf(); returns NGX_OK if thread_pool==NULL (no AIO configured). Allocates task struct with ngx_thread_task_alloc() — if OOM returns NGX_ERROR. Populates t=brix_write_aio_t context: c, ctx, conf, fd from files[idx], handle_idx, offset, data, len, req_offset, is_pgwrite, nwritten=-1, io_errno=0, payload_to_free, streamid copy, path copy via ngx_cpystrn(). Binds the worker + done callbacks via brix_task_bind(task, brix_write_aio_thread, brix_write_aio_done). Calls brix_aio_post_task() which sets posted=1 on success or 0 if queue full. Returns result from post_task call. */
