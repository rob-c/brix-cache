#include "query_internal.h"
#include "checksum_qcksum_internal.h"
#include "core/compat/checksum.h"
#include "core/compat/integrity_info.h"
#include "protocols/root/response/response.h"
#include "core/aio/aio.h"
#include "fs/vfs/vfs.h"   /* confined read-open via the VFS seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */
#include "net/manager/registry.h"
#include "net/manager/pending.h"
#include "net/cms/cms_internal.h"

#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

/*
 * WHAT: kXR_Qcksum — compute single-file checksum (adler32/crc32c/md5/sha1/sha256) by path or open file handle.
 *       Dispatches to path-based handler (full security chain + confined open) or handle-based handler (already-open fd).
 *       Supports async execution via thread pool when configured; falls back to synchronous event-loop computation otherwise.
 *
 * WHY:  Qcksum is the most common XRootD query opcode — clients need file integrity verification before transfer, after staging,
 *       and for checksum-based deduplication. Multiple algorithm support (adler32/crc32c/md5/sha1/sha256) covers legacy HEP tools
 *       (xrdcp uses adler32) alongside modern requirements (SHA256 for cloud storage). Async execution prevents blocking on large files.
 *
 * HOW:  brix_query_cksum() routes by payload prefix byte: non-zero → path-based handler (cksum_path); zero or empty → handle-based
 *       handler (cksum_handle). cksum_path parses algo:path from wire, resolves path, checks authdb/VO/token scope, opens confined fd,
 *       then either posts thread task or computes sync. cksum_handle validates fhandle index, optionally extracts algo prefix, delegates to
 *       build_checksum which dispatches via checksum_parse to specialized helper functions per algorithm. Both paths log access + increment metric.
 */

/* defined in checksum_qcksum_async.c */
extern void brix_cksum_aio_thread(void *data, ngx_log_t *log);
extern void brix_cksum_aio_done(ngx_event_t *ev);

/* brix_qcksum_req_t, BRIX_QCKSUM_DEFAULT_ALGO/_ALGO_SZ, and the shared
 * brix_query_parse_algorithm/_build_checksum prototypes live in
 * checksum_qcksum_internal.h (shared with checksum_qcksum_path.c). */

ngx_flag_t
brix_query_parse_algorithm(const u_char *src, size_t len, char *algo,
    size_t algo_sz)
{
    brix_checksum_alg_t alg;

    return brix_checksum_parse((const char *) src, len, &alg, algo,
                                 algo_sz) == NGX_OK;
}

/* WHAT: Wraps brix_send_error() and returns NGX_DONE if the error was successfully sent (NGX_OK), otherwise
 *      propagates the original return value. This ensures callers receive consistent result semantics.
 * WHY: kXR_Qcksum must distinguish between "error sent to client" vs "send failed internally"; NGX_DONE signals
 *      that the error response reached the wire while NGX_ERROR indicates a transport failure. Callers use this
 *      distinction for different retry/failure handling strategies.
 * HOW: Single wrapper — call brix_send_error(), return NGX_DONE if result was NGX_OK, else propagate original value. */

static ngx_int_t
brix_query_cksum_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = brix_send_error(ctx, c, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}

/* WHAT: Computes a file checksum using one of six supported algorithms: adler32, crc32, crc32c, md5, sha1, or sha256.
 *      All algorithms dispatch through brix_integrity_get_fd() → brix_checksum_hex_fd().
 * WHY: kXR_Qcksum supports multiple hash algorithms for client flexibility and cross-platform compatibility.
 *      HEP clients historically use adler32/crc32c; modern tools prefer SHA1/SHA256. MD5 is retained for legacy support.
 * HOW: Sequential strcmp checks against supported algo strings, dispatching to specialized helper functions per algorithm. */

ngx_int_t
brix_query_build_checksum(brix_ctx_t *ctx, ngx_connection_t *c,
    int fd, brix_sd_obj_t *obj, const char *resolved, const char *algo,
    char *resp, size_t resp_sz)
{
    brix_integrity_info_t  info;
    brix_integrity_opts_t  iopts;
    char                     token[256];

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache  = 1;
    iopts.update_xattr_cache = 1;

    if (brix_integrity_get_fd(c->log, fd, obj, resolved, algo, &iopts, &info)
        != NGX_OK)
    {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        return brix_query_cksum_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
    }

    /* kXR_Qcksum wire format: "algo hexvalue" (space-separated) */
    snprintf(token, sizeof(token), "%s %s", info.alg_name, info.hex);
    ngx_cpystrn((u_char *) resp, (u_char *) token, resp_sz);
    return NGX_OK;
}

/*
 * WHAT: Extract the optional algorithm carried on a handle-based Qcksum payload (prefix byte 0,
 *      followed by a NUL-bounded algorithm name) into *algo. A missing/empty/unknown name leaves
 *      *algo at its default.
 * WHY:  Clients may pin the algorithm for a handle checksum by prefixing the fhandle payload with
 *      a zero byte + "<algo>". Unlike the path variant, an unknown name here is silently ignored
 *      (the original handler discarded the parse result) — the default algorithm still applies.
 * HOW:  Guard on payload[0]==0 with at least one following byte, strnlen the algorithm run, and
 *      forward it to brix_query_parse_algorithm (whose failure is intentionally ignored).
 */
static void
brix_qcksum_handle_extract_algo(brix_ctx_t *ctx, char *algo, size_t algo_sz)
{
    const u_char *ap;
    size_t        alen;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen <= 1
        || ctx->recv.payload[0] != 0)
    {
        return;
    }

    ap   = ctx->recv.payload + 1;
    alen = strnlen((const char *) ap, (size_t) (ctx->recv.cur_dlen - 1));
    if (alen > 0) {
        (void) brix_query_parse_algorithm(ap, alen, algo, algo_sz);
    }
}

/*
 * WHAT: Try to offload a whole-object checksum on an already-open fhandle fd to the thread pool.
 *      Returns NGX_OK with *handled=1 when posted, *handled=0 for the fall-through-to-sync case,
 *      or a terminal rc with *handled=1 on task-alloc/post failure.
 * WHY:  The handle variant computes on an fd it does NOT own (close_fd=0, no VFS handle to
 *      release) — so, unlike the path variant, its failure exits never close anything. Keeping
 *      the two async posters separate avoids a conditional-ownership branch that would re-inflate
 *      the complexity both splits are removing.
 * HOW:  Alloc the task, populate brix_cksum_aio_t from the files[] slot (fd + snapshotted sd_obj),
 *      bind the callbacks, and brix_aio_post_task; a full queue leaves *handled=0 for sync.
 */
static ngx_int_t
brix_qcksum_handle_try_async(brix_qcksum_req_t *rq, int idx,
    const char *resolved, ngx_flag_t *handled)
{
    brix_ctx_t                 *ctx  = rq->ctx;
    ngx_connection_t           *c    = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    brix_cksum_aio_t  *t;
    ngx_thread_task_t *task;
    ngx_flag_t         posted = 0;

    *handled = 0;

    if (conf->common.thread_pool == NULL) {
        return NGX_OK;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(brix_cksum_aio_t));
    if (task == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        *handled = 1;
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    t = task->ctx;
    t->ctx      = ctx;
    t->c        = c;
    t->conf     = conf;
    t->fd       = ctx->files[idx].fd;
    t->close_fd = 0;
    t->obj      = ctx->files[idx].sd_obj; /* Layer 3: whole-object checksum */
    ngx_memcpy(t->streamid, ctx->recv.cur_streamid, 2);
    ngx_cpystrn((u_char *) t->algo, (u_char *) rq->algo, sizeof(t->algo));
    ngx_cpystrn((u_char *) t->resolved, (u_char *) resolved,
                sizeof(t->resolved));
    t->error_code = 0;

    brix_task_bind(task, brix_cksum_aio_thread, brix_cksum_aio_done);
    task->ctx = t;

    if (brix_aio_post_task(ctx, c, conf->common.thread_pool, task,
                             "cksum thread pool queue full, using sync",
                             &posted) != NGX_OK)
    {
        *handled = 1;
        return NGX_ERROR;
    }

    if (posted) {
        *handled = 1;
        return NGX_OK;
    }
    return NGX_OK;
}

/* WHAT: Computes checksum on an already-open file using its stored fhandle index. Extracts optional algo from payload (prefix byte=0),
 *      validates the handle index, and delegates to brix_query_build_checksum(). Returns hex-formatted result.
 * WHY: kXR_Qcksum can query either open-file handles or arbitrary paths; this handler implements the handle-based variant where
 *      the file is already opened (lower overhead than re-opening). Clients use handles for repeated checksum queries on same file.
 * HOW: extract optional algo → validate fhandle index range + fd → try async offload, else build checksum synchronously + reply. */

static ngx_int_t
brix_query_cksum_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const xrdw_query_req_t *req)
{
    brix_qcksum_req_t rq;
    char       resolved[PATH_MAX];
    char       resp[256];
    int        idx;
    ngx_int_t  rc;
    ngx_flag_t handled = 0;

    ngx_memzero(&rq, sizeof(rq));
    rq.ctx  = ctx;
    rq.c    = c;
    rq.conf = conf;
    ngx_cpystrn((u_char *) rq.algo, (u_char *) BRIX_QCKSUM_DEFAULT_ALGO,
                sizeof(rq.algo));
    brix_qcksum_handle_extract_algo(ctx, rq.algo, sizeof(rq.algo));

    idx = (int) (unsigned char) req->fhandle[0];
    if (idx < 0 || idx >= BRIX_MAX_FILES || ctx->files[idx].fd < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        return brix_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_cpystrn((u_char *) resolved,
                (u_char *) (ctx->files[idx].path != NULL
                            ? ctx->files[idx].path : "-"),
                sizeof(resolved));

    rc = brix_qcksum_handle_try_async(&rq, idx, resolved, &handled);
    if (handled) {
        return rc;
    }

    rc = brix_query_build_checksum(ctx, c, ctx->files[idx].fd,
                                     &ctx->files[idx].sd_obj, resolved,
                                     rq.algo, resp, sizeof(resp));
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSUM);
    brix_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
    return brix_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}

/* public API: brix_query_cksum() — kXR_Qcksum dispatch entry point * WHAT: Main dispatcher for Qcksum requests. Routes by payload prefix byte: non-zero → path-based handler (cksum_path with full security chain); zero or empty → handle-based handler (cksum_handle with already-open fd). Default algo is adler32. Both paths support async thread pool execution and synchronous fallback. */

ngx_int_t
brix_query_cksum(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const xrdw_query_req_t *req)
{
    /*
     * Wire-format routing on the payload's first byte:
     *   non-zero first byte → payload is a printable "[algo:]path" string, so
     *     take the path-based variant (full auth chain + confined open).
     *   zero or empty payload → no path on the wire; use the fhandle index from
     *     the request header (handle-based variant on an already-open fd).
     * The default algorithm is adler32 (xrdcp's default) in either variant; a
     * leading "algo:" prefix in the path payload overrides it downstream (each
     * variant seeds its own algo buffer from BRIX_QCKSUM_DEFAULT_ALGO).
     */
    if (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL && ctx->recv.payload[0] != 0) {
        return brix_query_cksum_path(ctx, c, conf);
    }

    return brix_query_cksum_handle(ctx, c, conf, req);
}
