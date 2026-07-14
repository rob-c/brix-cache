/*
 * fd_table_teardown.c — handle-slot teardown machinery for the root:// per-
 * connection file-handle table.
 *
 * Split verbatim from fd_table.c (mechanical file-size split, zero behaviour
 * change): the full free/reset path for one slot — staging-temp unlink through
 * the VFS seam, descriptor + CSI release, staging-file rollback, and the field
 * reset that returns a slot to its unused state — plus brix_free_fhandle and
 * brix_close_all_files that drive it. The public entry points remain declared
 * in fd_table.h; the fhandle_* helpers here are file-local statics used only by
 * this teardown path.
 */

#include "fd_table.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_open_fd_at (handle-table confined open) */
#include "protocols/root/session/registry.h"
#include "fs/cache/writethrough_metrics.h"
#include "protocols/root/write/pgw_fob.h"
#include "fs/backend/csi_tagstore.h"
#include "protocols/root/zip/zip_member.h"   /* brix_zip_handle_cleanup (frees inflate stream) */
#include "protocols/ssi/ssi.h"          /* brix_ssi_handle_cleanup (timers + registry) */

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* fhandle_unlink_staging — remove a handle-owned staging temp (checkpoint journal
 * or POSC partial) through the VFS seam. `abs_path` is the absolute staging path;
 * strip `root_canon` to the export-relative key and confined-unlink it (the
 * teardown context has no request ctx, but the srv conf still gives root_canon +
 * rootfd). Falls back to a raw unlink only when the path is not under the export
 * root (no confinement is possible then). */
static void
fhandle_unlink_staging(const char *abs_path, const char *root_canon,
    ngx_log_t *log)
{
    size_t root_len = (root_canon != NULL) ? ngx_strlen(root_canon) : 0;

    if (root_len > 0
        && ngx_strncmp((u_char *) abs_path, (u_char *) root_canon, root_len) == 0
        && abs_path[root_len] == '/')
    {
        (void) brix_vfs_unlink_path(log, root_canon, abs_path + root_len);
        return;
    }
    (void) unlink(abs_path);  /* vfs-seam-allow: handle-owned staging temp not under the export root */
}

/* fhandle_release_descriptors — close the handle's byte-I/O descriptor(s) and the
 * CSI engine. WHY: three mutually-exclusive descriptor owners must be torn down in
 * one place so exactly one close runs: a phase-70 staged-write handle (abort — drop
 * the temp unless already committed), a driver-backed object handle (its own close
 * commits metadata and owns file->fd, so we must NOT also raw-close it), or a plain
 * POSIX fd. HOW: staged first (independent of the fd owner), then the fd owner in
 * strict driver-vs-raw priority, then the CSI flush+free. Fields are nulled as each
 * resource is released so a later reset cannot double-free. */
static void
fhandle_release_descriptors(brix_file_t *file)
{
    /* Whole-object staged write adapter (phase-70): release the staged handle.
     * If it was never committed (kXR_sync/close did not run — a disconnect or an
     * aborted upload) drop the staged temp so no partial object is published. A
     * committed handle already consumed its staged state; abort is then a no-op. */
    if (file->staged != NULL) {
        brix_vfs_staged_abort(file->staged, file->staged_committed ? 0 : 1);
        file->staged              = NULL;
        file->staged_expected_off = 0;
        file->staged_committed    = 0;
    }

    if (file->sd_obj.driver != NULL) {
        /* Layer 3: a driver-backed handle owns its descriptor(s) and commits any
         * pending metadata (e.g. catalog size/mtime) in its own close(); do NOT
         * also raw-close file->fd, which is the driver's block-0 descriptor. */
        (void) file->sd_obj.driver->close(&file->sd_obj);
        file->sd_obj.driver = NULL;
        file->sd_obj.inst   = NULL;
        file->sd_obj.state  = NULL;
        file->sd_obj.fd     = -1;
    } else if (file->fd >= 0) {
        close(file->fd);
    }

    /* xmeta P3: flush + free the CSI engine (merges folded block CRCs
     * into the file's metadata record). */
    if (file->csi != NULL) {
        brix_csi_close((brix_csi_t *) file->csi);
        ngx_free(file->csi);
        file->csi = NULL;
    }
}

/* fhandle_release_staging_files — unlink + free the handle-owned staging temps and
 * the heap path copy, and drop the TPC registry entry. WHY: checkpoint and POSC temps
 * are rollback state owned by the handle; if still set at teardown the session ended
 * without a clean kXR_close, so the partials must not be left on disk (except the
 * deterministic identity-keyed resume partial, which is preserved for reconnect). HOW:
 * confined-unlink each temp through the VFS seam, free every heap allocation, then
 * remove any TPC transfer keyed on this handle. */
static void
fhandle_release_staging_files(brix_file_t *file, const char *root_canon,
    ngx_log_t *tlog)
{
    /*
     * Checkpoint files are temporary rollback state owned by the handle.
     * Normal close/free removes any abandoned checkpoint path.
     */
    if (file->ckp_path != NULL) {
        fhandle_unlink_staging(file->ckp_path, root_canon, tlog);
        ngx_free(file->ckp_path);
    }

    /*
     * POSC cleanup: if posc_final_path is still set here the session ended
     * without a clean kXR_close (disconnect, error, or abandon).  Unlink the
     * temp staging file so partial writes are not left on disk.
     *
     * EXCEPTION — upload resume (is_resume): the partial is deterministic and
     * identity-keyed, so it is PRESERVED on a non-clean close.  That is the
     * whole mechanism: the same client reconnecting re-opens it in place (no
     * truncate) and resumes from its offset.  Abandoned partials are reclaimed
     * by an operator glob-clean ("*.xrdresume.*.part") rather than here.
     */
    if (file->posc_final_path != NULL) {
        if (file->path != NULL && !file->is_resume) {
            fhandle_unlink_staging(file->path, root_canon, tlog);
        }
        ngx_free(file->posc_final_path);
    }

    if (file->path != NULL) {
        ngx_free(file->path);
    }

    if (file->tpc_transfer_id != 0) {
        (void) brix_tpc_registry_remove(file->tpc_transfer_id, NULL);
    }
}

/* fhandle_reset_slot — zero every field of a freed slot back to its unused state,
 * releasing the ZIP inflate stream and SSI timers/registration along the way. WHY:
 * a slot is reused for the next kXR_open, so no stale pointer, capability bit, or
 * TPC/write-tracking counter may survive — a reused slot must be indistinguishable
 * from a never-used one. HOW: run the two pool-owned sub-cleanups (zip, ssi) that
 * must precede their pointer being dropped, then set every scalar/pointer field to
 * its zero/null/sentinel value; must run AFTER descriptor + staging release so their
 * niling is not clobbered. */
static void
fhandle_reset_slot(brix_file_t *file)
{
    /* ZIP member handle: release the deflate inflate stream (if any) and clear
     * the zip_* state so a reused slot cannot be mistaken for a zip handle. */
    brix_zip_handle_cleanup(file);
    file->zip_mode        = 0;
    file->zip_method      = 0;
    file->zip_data_off    = 0;
    file->zip_comp_size   = 0;
    file->zip_uncomp_size = 0;
    file->zip_crc32       = 0;
    file->zip_logical_pos = 0;
    file->zip_comp_pos    = 0;

    file->fd             = -1;
    ngx_memzero(&file->sd_obj, sizeof(file->sd_obj));  /* Layer 3: clear driver obj */
    file->shared_handle_slot_hint = -1;  /* Phase 33 C2: drop the cached SHM slot */
    file->readable       = 0;
    file->writable       = 0;
    file->from_cache     = 0;
    file->bytes_read     = 0;
    file->bytes_written  = 0;
    file->open_time      = 0;
    file->path           = NULL;
    /* §7: cancel SSI async-deferral timers + unregister the session before the
     * .ssi pointer is dropped (runs on close + disconnect; NULL-safe). */
    brix_ssi_handle_cleanup(file->ssi);
    file->ssi            = NULL;   /* §7: SSI state is connection-pool owned */
    file->is_regular     = 0;
    file->device         = 0;
    file->inode          = 0;
    file->cached_size    = 0;
    file->read_last_end  = -1;
    file->read_ahead_end = 0;
    file->ckp_path       = NULL;
    file->ckp_size       = 0;
    file->posc_final_path = NULL;
    file->is_resume       = 0;
    file->tpc_destination = 0;
    file->tpc_armed       = 0;
    file->tpc_started     = 0;
    file->tpc_done        = 0;
    file->tpc_key[0]      = '\0';
    file->tpc_org[0]      = '\0';
    file->tpc_src_host[0] = '\0';
    file->tpc_src_port    = 0;
    file->tpc_src_path[0] = '\0';
    file->tpc_token_mode[0] = '\0';
    file->tpc_transfer_id = 0;
    file->wt_enabled      = 0;
    file->wt_policy       = 0;
    file->wt_mode_bits    = 0;
    file->wt_dirty_offset = -1;
    file->wt_bytes_written = 0;
    file->wt_flush_task    = NULL;
    file->wt_flush_pending = 0;
    file->wrts_enabled     = 0;
    file->wrts_head        = 0;
    file->wrts_count       = 0;
    file->wrts_gen         = 0;
    brix_pgw_fob_reset(file);
}

/* brix_free_fhandle — full teardown of one slot: close the fd, unpublish from
 * shared memory (unbound only), unlink checkpoint/POSC staging files, free the heap
 * path, and reset every field to its zero/null state. Called on session end, error
 * recovery, and kXR_close completion. */

void
brix_free_fhandle(brix_ctx_t *ctx, int handle_index)
{
    brix_file_t                *file;
    ngx_stream_brix_srv_conf_t *conf;
    const char                   *root_canon;
    ngx_log_t                    *tlog;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES) {
        return;
    }

    file = &ctx->files[handle_index];

    /* The teardown has no request ctx, but the srv conf still yields the export
     * root_canon so handle-owned staging temps can be confined-unlinked. */
    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);
    root_canon = (conf != NULL) ? conf->common.root_canon : NULL;
    tlog = (ctx->session != NULL && ctx->session->connection != NULL)
           ? ctx->session->connection->log : NULL;

    if (!ctx->is_bound && file->fd >= 0) {
        brix_session_handle_unpublish(ctx->login.sessid, handle_index);
    }

    fhandle_release_descriptors(file);
    fhandle_release_staging_files(file, root_canon, tlog);
    brix_wt_mark_clean(ctx, handle_index);
    fhandle_reset_slot(file);
}

/* brix_close_all_files — brix_free_fhandle every slot; used at session
 * termination or error recovery when all handles must be released at once. */

void
brix_close_all_files(brix_ctx_t *ctx)
{
    int handle_index;

    for (handle_index = 0; handle_index < BRIX_MAX_FILES; handle_index++) {
        brix_free_fhandle(ctx, handle_index);
    }
}
