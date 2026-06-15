#include "query_internal.h"
#include "../response/response.h"
#include "../aio/aio.h"
#include "../compat/checksum.h"
#include "../path/beneath.h"

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
 * HOW:  xrootd_query_ckscan() validates payload presence, calls ckscan_select_payload() to extract algo + path from wire data (defaulting
 *       to adler32), extracts and resolves path, checks authdb/VO/token scope, then either posts a thread task or runs ckscan_sync().
 *       ckscan_select_payload() scans for ':' or ' ' before the first '/' to detect algo prefix; validates via checksum_parse + algorithm_supported.
 *       ckscan_sync() mirrors the async thread logic on the event loop: stat → open → checksum for files, walk tree for directories.
 */

/* AIO function declarations — defined in checksum_ckscan_async.c */
extern void xrootd_ckscan_aio_thread(void *data, ngx_log_t *log);
extern void xrootd_ckscan_aio_done(ngx_event_t *ev);

/* ---- static helper: ckscan_algorithm_supported() — validates algo against supported set ----
 * WHAT: Parses algo string via xrootd_checksum_parse, returns true only for adler32 or crc32c (xrdadler32 compatibility). Used by select_payload to validate extracted algo prefix. */

static ngx_flag_t
xrootd_ckscan_algorithm_supported(const char *algo)
{
    xrootd_checksum_alg_t alg;

    if (xrootd_checksum_parse(algo, strlen(algo), &alg, NULL, 0) != NGX_OK) {
        return 0;
    }

    return alg == XROOTD_CHECKSUM_ADLER32
           || alg == XROOTD_CHECKSUM_CRC32C
           || alg == XROOTD_CHECKSUM_CRC64
           || alg == XROOTD_CHECKSUM_CRC64NVME;
}

/* ---- static helper: ckscan_send_error() — error response wrapper ----
 * WHAT: Wraps xrootd_send_error returning NGX_DONE on success (request complete), NGX_ERROR otherwise. Used by select_payload when algo prefix is invalid or unsupported. */

static ngx_int_t
xrootd_ckscan_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = xrootd_send_error(ctx, c, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}

/* ---- static helper: ckscan_select_payload() — parse wire payload for algo + path ----
 * WHAT: Extracts algorithm specifier and scan path from the request payload. Default algo is adler32. Scans payload bytes before first '/' for ':' or ' ' delimiter to detect "algo:path" prefix format. Validates via checksum_parse + algorithm_supported (only adler32/crc32c). Returns NGX_DONE on invalid/unsupported algo, NGX_OK otherwise with extracted path and algo populated. */

static ngx_int_t
xrootd_ckscan_select_payload(xrootd_ctx_t *ctx, ngx_connection_t *c,
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
            xrootd_checksum_alg_t alg;

            if (i == 0 || i >= algo_sz || i + 1 >= payload_len) {
                return xrootd_ckscan_send_error(ctx, c, kXR_ArgInvalid,
                                                "invalid checksum algorithm");
            }

            if (xrootd_checksum_parse((const char *) payload, i, &alg, algo,
                                      algo_sz) != NGX_OK
                || !xrootd_ckscan_algorithm_supported(algo))
            {
                return xrootd_ckscan_send_error(ctx, c, kXR_ArgInvalid,
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

/* ---- static helper: ckscan_sync() — synchronous event-loop ckscan execution ----
 * WHAT: Mirrors the async thread worker logic on the event loop. Stat's target, opens confined fd for regular files computing single checksum; walks directories recursively with depth/file limits via ckscan_walk. Allocates response buffer with dynamic growth. Sends ok+checksum data or error to client. Used when no thread pool configured or queue is full. */

static ngx_int_t
xrootd_ckscan_sync(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int rootfd,
    const char *logical, const char *algo)
{
    struct stat  st;
    u_char      *buf;
    size_t       cap  = XROOTD_CKSCAN_INIT_CAP;
    size_t       used = 0;
    ngx_uint_t   nfiles = 0;
    ngx_int_t    rc;

    buf = ngx_alloc(cap, c->log);
    if (buf == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    if (xrootd_stat_beneath(rootfd, logical, &st) != 0) {
        ngx_free(buf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
        return xrootd_send_error(ctx, c, kXR_NotFound, strerror(errno));
    }

    if (S_ISREG(st.st_mode)) {
        int  fd;
        int  append_rc;
        /* Hex result: 8 chars (adler32/crc32c), 16 (crc64/crc64nvme), or up to
         * EVP_MAX_MD_SIZE*2 for a digest — 129 covers every case. */
        char hex[129];

        fd = xrootd_open_beneath(rootfd, logical, O_RDONLY, 0);
        if (fd < 0) {
            ngx_free(buf);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }

        if (xrootd_checksum_hex_name_fd(algo, fd, logical, c->log,
                                        hex, sizeof(hex), NULL, 0) != NGX_OK)
        {
            close(fd);
            ngx_free(buf);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "checksum computation failed");
        }
        close(fd);

        append_rc = xrootd_ckscan_append(&buf, &cap, &used,
                                         algo, hex, logical);
        if (append_rc <= 0) {
            ngx_free(buf);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
            return xrootd_send_error(ctx, c,
                                     append_rc == 0 ? kXR_ArgTooLong
                                                    : kXR_NoMemory,
                                     append_rc == 0 ? "path too long"
                                                    : "out of memory");
        }

    } else if (S_ISDIR(st.st_mode)) {
        char errmsg[128] = "";

        if (xrootd_ckscan_walk(c->log, rootfd, logical, algo,
                               &buf, &cap, &used, 0, conf->ckscan_max_depth,
                               conf->ckscan_max_files, &nfiles, errmsg,
                               sizeof(errmsg)) < 0)
        {
            ngx_free(buf);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
            return xrootd_send_error(ctx, c, kXR_IOError, errmsg);
        }
    } else {
        ngx_free(buf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "not a file or directory");
    }

    buf[used] = '\0';
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSCAN);
    xrootd_log_access(ctx, c, "QUERY", logical, "ckscan", 1, 0, NULL, 0);
    rc = xrootd_send_ok(ctx, c, buf, (uint32_t) (used + 1));
    ngx_free(buf);
    return rc;
}

/* ---- public API: xrootd_query_ckscan() — kXR_Qckscan dispatch entry point ----
 * WHAT: Main dispatch handler for Qckscan requests. Validates payload presence, extracts algo+path via select_payload, resolves path against export root, checks authdb read permission + VO ACL + token scope, then routes to async thread pool (if configured) or synchronous fallback execution. Returns NGX_OK when task posted to thread pool, NGX_DONE/NGX_ERROR for sync completion. */

ngx_int_t
xrootd_query_ckscan(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char         full_path[PATH_MAX];
    char         pathbuf[XROOTD_MAX_PATH + 1];
    char         algo[32];
    const u_char *path_payload;
    size_t        path_payload_len;
    ngx_int_t     rc;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                          "-", "ckscan", kXR_ArgMissing, "no path given");
    }

    rc = xrootd_ckscan_select_payload(ctx, c, &path_payload, &path_payload_len,
                                      algo, sizeof(algo));
    if (rc == NGX_DONE) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
        return rc;
    }

    if (!xrootd_extract_path(c->log, path_payload, path_payload_len,
                             pathbuf, sizeof(pathbuf), 1)) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                          "-", "ckscan", kXR_ArgInvalid, "invalid path payload");
    }

    xrootd_beneath_full_path(conf->common.root_canon, pathbuf,
                             full_path, sizeof(full_path));

    if (xrootd_auth_gate(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                         pathbuf, full_path, conf,
                         XROOTD_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    if (conf->common.thread_pool != NULL) {
        xrootd_ckscan_aio_t *t;
        ngx_thread_task_t   *task;
        ngx_flag_t           posted;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_ckscan_aio_t));
        if (task == NULL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
            return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
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

        xrootd_task_bind(task, xrootd_ckscan_aio_thread, xrootd_ckscan_aio_done);
        task->ctx           = t;

        if (xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task,
                                 "ckscan thread pool queue full, using sync",
                                 &posted) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (posted) {
            return NGX_OK;
        }
    }

    return xrootd_ckscan_sync(ctx, c, conf, conf->rootfd, pathbuf, algo);
}
