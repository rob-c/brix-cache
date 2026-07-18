/*
 * put_internal.h - shared declarations for the WebDAV PUT split.
 *
 * The PUT path is split across three translation units by concern:
 *   put.c        - orchestrator + finalize (body_inner / handle_put_body / commit)
 *   put_setup.c  - precondition/setup (precheck / open_target / start_dashboard /
 *                  resumable Content-Range branch)
 *   put_body.c   - body-write concern (thread offload / codec / sync write / async
 *                  done + checksum-on-ingest)
 *
 * Symbols DEFINED in one of those units and REFERENCED from another are declared
 * here.  Single-file symbols stay `static` in their own .c.  Types come from the
 * include block each .c copies (webdav.h + fs/vfs/vfs.h) ahead of this header.
 */
#ifndef BRIX_WEBDAV_PUT_INTERNAL_H
#define BRIX_WEBDAV_PUT_INTERNAL_H

/*
 * Outcome of a per-phase PUT helper, telling the orchestrator how to proceed.
 * The helpers own their own error responses (metrics/status already sent), so
 * the orchestrator only branches on whether to continue, stop, or (for the
 * resumable branch) treat the request as fully handled.
 */
typedef enum {
    WEBDAV_PUT_CONTINUE = 0,   /* phase succeeded — proceed to the next phase   */
    WEBDAV_PUT_DONE            /* request fully handled/responded — stop, return */
} webdav_put_step_t;

void webdav_put_persist_checksums(ngx_http_request_t *r, const char *path);

webdav_put_step_t webdav_put_precheck(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, char *path, int *created);

webdav_put_step_t webdav_put_open_target(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx, brix_vfs_writer_t **out_writer);

void webdav_put_start_dashboard(ngx_http_request_t *r, const char *path,
    int64_t bytes);

webdav_put_step_t webdav_put_stream_body(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_writer_t *writer, int created);

#endif /* BRIX_WEBDAV_PUT_INTERNAL_H */
