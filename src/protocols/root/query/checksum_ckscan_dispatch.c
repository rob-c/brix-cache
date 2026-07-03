#include "query_internal.h"
#include "protocols/root/response/response.h"
#include "core/aio/aio.h"
#include "core/compat/checksum.h"
#include "fs/path/beneath.h"

#include <dirent.h>
#include <sys/stat.h>

/*
 * WHAT: kXR_Qckscan dispatch — parse wire payload (algo:path or bare path), resolve path, check auth/VO/token scope,
 *       then execute ckscan via async thread pool (if configured) or synchronous fallback. Returns checksum results as one
 *       "algo hex logical_path" line per file to the client.
 *
 * WHY:  Qckscan requests arrive with a wire payload that may optionally prefix the path with an algorithm specifier
 *       ("crc32c:/data/atlas/..."). This dispatch layer extracts and validates the algo, resolves the path against the export root,
 *       checks authdb read permission + VO ACL + token scope, then routes to async (ngx_thread_pool_run) or sync execution.
 *       The async path allocates a thread task with all scan parameters; the done callback delivers results back on the client connection.
 *       Sync fallback runs when no thread pool is configured or the queue is full.
 *
 * HOW:  brix_query_ckscan() validates payload presence, calls ckscan_select_payload() to extract algo + path from wire data (defaulting
 *       to adler32), extracts and resolves path, checks authdb/VO/token scope, then either posts a thread task or runs ckscan_sync().
 *       ckscan_select_payload() scans for ':' or ' ' before the first '/' to detect algo prefix; validates via checksum_parse + algorithm_supported.
 *       ckscan_sync() mirrors the async thread logic on the event loop: stat → open → checksum for files, walk tree for directories.
 */

/* AIO function declarations — defined in checksum_ckscan_async.c */
extern void brix_ckscan_aio_thread(void *data, ngx_log_t *log);
extern void brix_ckscan_aio_done(ngx_event_t *ev);

/* ckscan_algorithm_supported — true only for adler32 or crc32c (xrdadler32
 * compatibility), via brix_checksum_parse; gates the extracted algo prefix. */

static ngx_flag_t
brix_ckscan_algorithm_supported(const char *algo)
{
    brix_checksum_alg_t alg;

    if (brix_checksum_parse(algo, strlen(algo), &alg, NULL, 0) != NGX_OK) {
        return 0;
    }

    return alg == BRIX_CHECKSUM_ADLER32
           || alg == BRIX_CHECKSUM_CRC32C
           || alg == BRIX_CHECKSUM_CRC64
           || alg == BRIX_CHECKSUM_CRC64NVME;
}

/* ckscan_send_error — wrap brix_send_error, returning NGX_DONE on success
 * (request complete) else NGX_ERROR; used on an invalid/unsupported algo prefix. */

static ngx_int_t
brix_ckscan_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = brix_send_error(ctx, c, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}

/* ckscan_select_payload — parse the request payload into algo + scan path: bytes
 * before the first '/' are checked for a ':'/' ' delimiter ("algo:path"), default
 * adler32, validated by checksum_parse + algorithm_supported. NGX_DONE on an
 * invalid/unsupported algo, else NGX_OK with path/algo filled. */

static ngx_int_t
brix_ckscan_select_payload(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char **path_payload, size_t *path_payload_len,
    char *algo, size_t algo_sz)
{
    const u_char *payload = ctx->payload;
    size_t        payload_len = (size_t) ctx->cur_dlen;
    size_t        wire_len;
    size_t        i;

    ngx_cpystrn((u_char *) algo, (u_char *) "adler32", algo_sz);
    *path_payload = payload;
    *path_payload_len = payload_len;

    wire_len = strnlen((const char *) payload, payload_len);
    for (i = 0; i < wire_len && payload[i] != '/'; i++) {
        if (payload[i] == ':' || payload[i] == ' ') {
            brix_checksum_alg_t alg;

            if (i == 0 || i >= algo_sz || i + 1 >= payload_len) {
                return brix_ckscan_send_error(ctx, c, kXR_ArgInvalid,
                                                "invalid checksum algorithm");
            }

            if (brix_checksum_parse((const char *) payload, i, &alg, algo,
                                      algo_sz) != NGX_OK
                || !brix_ckscan_algorithm_supported(algo))
            {
                return brix_ckscan_send_error(ctx, c, kXR_ArgInvalid,
                                                "unknown checksum algorithm");
            }

            *path_payload = payload + i + 1;
            *path_payload_len = payload_len - (i + 1);
            return NGX_OK;
        }
    }

    return NGX_OK;
}

/* Synchronous fallback (used when thread pool is not configured). */

/* ckscan_sync — the event-loop fallback (no thread pool, or queue full) mirroring
 * the async worker: stat the target, checksum a regular file via a confined fd or
 * walk a directory (ckscan_walk, depth/file limits) into a growable buffer, then
 * send ok+checksum or error. */

static ngx_int_t
brix_ckscan_sync(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int rootfd,
    const char *logical, const char *algo)
{
    u_char      *buf;
    size_t       cap  = BRIX_CKSCAN_INIT_CAP;
    size_t       used = 0;
    uint16_t     err_code = 0;
    char         err_msg[128] = "";
    ngx_int_t    rc;

    buf = ngx_alloc(cap, c->log);
    if (buf == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSCAN);
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    /* The whole stat/open/checksum/walk now lives in the confined VFS walk
     * (brix_ckscan_run → brix_vfs_walk); this layer only frames the result. */
    if (brix_ckscan_run(c->log, rootfd, logical, algo, &buf, &cap, &used,
                          conf->ckscan_max_depth, conf->ckscan_max_files,
                          &err_code, err_msg, sizeof(err_msg)) != NGX_OK)
    {
        ngx_free(buf);
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSCAN);
        return brix_send_error(ctx, c, err_code, err_msg);
    }

    buf[used] = '\0';
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSCAN);
    brix_log_access(ctx, c, "QUERY", logical, "ckscan", 1, 0, NULL, 0);
    rc = brix_send_ok(ctx, c, buf, (uint32_t) (used + 1));
    ngx_free(buf);
    return rc;
}

/* brix_query_ckscan — kXR_Qckscan entry point: parse algo+path (select_payload),
 * resolve against the export root, check authdb read + VO ACL + token scope, then
 * route to the async thread pool (NGX_OK posted) or the sync fallback
 * (NGX_DONE/NGX_ERROR). */

ngx_int_t
brix_query_ckscan(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char         full_path[PATH_MAX];
    char         pathbuf[BRIX_MAX_PATH + 1];
    char         algo[32];
    const u_char *path_payload;
    size_t        path_payload_len;
    ngx_int_t     rc;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_CKSCAN, "QUERY",
                          "-", "ckscan", kXR_ArgMissing, "no path given");
    }

    rc = brix_ckscan_select_payload(ctx, c, &path_payload, &path_payload_len,
                                      algo, sizeof(algo));
    if (rc == NGX_DONE) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSCAN);
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSCAN);
        return rc;
    }

    if (!brix_extract_path(c->log, path_payload, path_payload_len,
                             pathbuf, sizeof(pathbuf), 1)) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_CKSCAN, "QUERY",
                          "-", "ckscan", kXR_ArgInvalid, "invalid path payload");
    }

    brix_beneath_full_path(conf->common.root_canon, pathbuf,
                             full_path, sizeof(full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_QUERY_CKSCAN, "QUERY",
                         pathbuf, full_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    if (conf->common.thread_pool != NULL) {
        brix_ckscan_aio_t *t;
        ngx_thread_task_t   *task;
        ngx_flag_t           posted;

        task = ngx_thread_task_alloc(c->pool, sizeof(brix_ckscan_aio_t));
        if (task == NULL) {
            BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSCAN);
            return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
        }

        t = task->ctx;

        t->ctx    = ctx;
        t->c      = c;
        t->conf   = conf;
        t->rootfd = conf->rootfd;
        ngx_memcpy(t->streamid, ctx->cur_streamid, 2);
        ngx_cpystrn((u_char *) t->algo, (u_char *) algo, sizeof(t->algo));
        ngx_cpystrn((u_char *) t->scan_logical, (u_char *) pathbuf,
                    sizeof(t->scan_logical));
        t->max_depth = conf->ckscan_max_depth;
        t->max_files = conf->ckscan_max_files;
        t->resp      = NULL;
        t->resp_len  = 0;
        t->error_code = 0;

        brix_task_bind(task, brix_ckscan_aio_thread, brix_ckscan_aio_done);
        task->ctx           = t;

        if (brix_aio_post_task(ctx, c, conf->common.thread_pool, task,
                                 "ckscan thread pool queue full, using sync",
                                 &posted) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (posted) {
            return NGX_OK;
        }
    }

    return brix_ckscan_sync(ctx, c, conf, conf->rootfd, pathbuf, algo);
}
