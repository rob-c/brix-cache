#include "query_internal.h"
#include "../compat/checksum.h"
#include "../compat/integrity_info.h"
#include "../response/response.h"
#include "../aio/aio.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../cms/cms_internal.h"

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
 * HOW:  xrootd_query_cksum() routes by payload prefix byte: non-zero → path-based handler (cksum_path); zero or empty → handle-based
 *       handler (cksum_handle). cksum_path parses algo:path from wire, resolves path, checks authdb/VO/token scope, opens confined fd,
 *       then either posts thread task or computes sync. cksum_handle validates fhandle index, optionally extracts algo prefix, delegates to
 *       build_checksum which dispatches via checksum_parse to specialized helper functions per algorithm. Both paths log access + increment metric.
 */

/* defined in checksum_qcksum_async.c */
extern void xrootd_cksum_aio_thread(void *data, ngx_log_t *log);
extern void xrootd_cksum_aio_done(ngx_event_t *ev);

static ngx_flag_t
xrootd_query_parse_algorithm(const u_char *src, size_t len, char *algo,
    size_t algo_sz)
{
    xrootd_checksum_alg_t alg;

    return xrootd_checksum_parse((const char *) src, len, &alg, algo,
                                 algo_sz) == NGX_OK;
}

/* ---- Function: xrootd_query_cksum_send_error() — error response wrapper with NGX_DONE handling ---- */
/* WHAT: Wraps xrootd_send_error() and returns NGX_DONE if the error was successfully sent (NGX_OK), otherwise
 *      propagates the original return value. This ensures callers receive consistent result semantics.
 * WHY: kXR_Qcksum must distinguish between "error sent to client" vs "send failed internally"; NGX_DONE signals
 *      that the error response reached the wire while NGX_ERROR indicates a transport failure. Callers use this
 *      distinction for different retry/failure handling strategies.
 * HOW: Single wrapper — call xrootd_send_error(), return NGX_DONE if result was NGX_OK, else propagate original value. */

static ngx_int_t
xrootd_query_cksum_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = xrootd_send_error(ctx, c, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}

/* ---- Function: xrootd_query_build_checksum() — multi-algorithm checksum computation ---- */
/* WHAT: Computes a file checksum using one of six supported algorithms: adler32, crc32, crc32c, md5, sha1, or sha256.
 *      All algorithms dispatch through xrootd_integrity_get_fd() → xrootd_checksum_hex_fd().
 * WHY: kXR_Qcksum supports multiple hash algorithms for client flexibility and cross-platform compatibility.
 *      HEP clients historically use adler32/crc32c; modern tools prefer SHA1/SHA256. MD5 is retained for legacy support.
 * HOW: Sequential strcmp checks against supported algo strings, dispatching to specialized helper functions per algorithm. */

static ngx_int_t
xrootd_query_build_checksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int fd, const char *resolved, const char *algo, char *resp, size_t resp_sz)
{
    xrootd_integrity_info_t  info;
    xrootd_integrity_opts_t  iopts;
    char                     token[256];

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache  = 1;
    iopts.update_xattr_cache = 1;

    if (xrootd_integrity_get_fd(c->log, fd, resolved, algo, &iopts, &info) != NGX_OK)
    {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_query_cksum_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
    }

    /* kXR_Qcksum wire format: "algo hexvalue" (space-separated) */
    snprintf(token, sizeof(token), "%s %s", info.alg_name, info.hex);
    ngx_cpystrn((u_char *) resp, (u_char *) token, resp_sz);
    return NGX_OK;
}

/* ---- Function: xrootd_query_cksum_path() — path-based kXR_Qcksum handler ---- */
/* WHAT: Parses a payload containing "algo:path", resolves the path through security checks (authdb, VO ACL, token scope),
 *      opens the file confined, and delegates checksum computation to xrootd_query_build_checksum(). Returns hex-formatted result.
 * WHY: kXR_Qcksum can query either open-file handles or arbitrary paths; this handler implements the path-based variant with
 *      full security chain verification before accessing any filesystem resource.
 * HOW: 1) Parse payload for algo:path separator (':' or ' '). 2) Extract and resolve path via xrootd_extract_path + resolve_path. 3) Verify authdb/VO ACL/token scope. 4) Open confined fd. 5) Build checksum + send result. */

static ngx_int_t
xrootd_query_cksum_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, char *algo, size_t algo_sz)
{
    char          full_path[PATH_MAX];
    char          pathbuf[XROOTD_MAX_PATH + 1];
    char          resp[256];
    int           fd;
    const u_char *payload = ctx->payload;
    size_t        payload_len = (size_t) ctx->cur_dlen;
    size_t        wire_len;
    const u_char *sep = NULL;
    size_t        alg_len = 0;
    const u_char *path_payload = payload;
    size_t        path_payload_len = payload_len;
    ngx_int_t     rc;

    wire_len = strnlen((const char *) payload, payload_len);

    for (size_t i = 0; i < wire_len; i++) {
        if (payload[i] == ':' || payload[i] == ' ') {
            sep = payload + i;
            alg_len = i;
            break;
        }
    }

    if (sep != NULL && alg_len > 0 && alg_len + 1 < payload_len) {
        if (!xrootd_query_parse_algorithm(payload, alg_len, algo, algo_sz)) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "unknown checksum algorithm");
        }
        path_payload = sep + 1;
        path_payload_len = payload_len - (alg_len + 1);
    }

    /*
     * Standard XRootD also requests the algorithm as a "?cks.type=<algo>" CGI on
     * the path (what stock clients and EOS send; xrootd_extract_path strips the
     * ?cgi suffix below). Honor it — overriding any legacy "algo path" prefix — so
     * `xrdfs ... cksum -a <algo>` selects the algorithm here too, not just via the
     * non-standard prefix form.
     */
    {
        const u_char *qmark = memchr(path_payload, '?', path_payload_len);
        if (qmark != NULL) {
            static const char key[] = "cks.type=";
            const u_char     *p   = qmark + 1;
            const u_char     *end = path_payload + path_payload_len;
            while (p < end) {
                const u_char *amp  = memchr(p, '&', (size_t) (end - p));
                size_t        flen = amp ? (size_t) (amp - p) : (size_t) (end - p);
                /* The raw query payload still carries the wire NUL terminator;
                 * when "cks.type=<algo>" is the LAST CGI field (no trailing '&')
                 * that NUL (and any stray CR/LF) lands inside flen and corrupts
                 * the algorithm value ("adler32\0" -> unknown algorithm), which
                 * broke every explicit algo + `xrdcp --cksum` (XrdCl appends
                 * exactly "?cks.type=<algo>"). Trim trailing NUL/CR/LF so the
                 * last-field form parses identically to "...&cks.type=algo&". */
                while (flen > 0 && (p[flen - 1] == '\0'
                                    || p[flen - 1] == '\r'
                                    || p[flen - 1] == '\n')) {
                    flen--;
                }
                if (flen > sizeof(key) - 1
                    && ngx_strncmp(p, key, sizeof(key) - 1) == 0) {
                    if (!xrootd_query_parse_algorithm(p + sizeof(key) - 1,
                            flen - (sizeof(key) - 1), algo, algo_sz)) {
                        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                                 "unknown checksum algorithm");
                    }
                    break;
                }
                if (amp == NULL) {
                    break;
                }
                p = amp + 1;
            }
        }
    }

    if (!xrootd_extract_path(c->log, path_payload, path_payload_len,
                             pathbuf, sizeof(pathbuf), 1)) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    /*
     * Manager / redirector mode: a kXR_Qcksum is metadata about one specific
     * file, and a pure redirector keeps no local copy.  Bounce the query to the
     * data server that authoritatively holds the path — exactly as kXR_stat and
     * kXR_open do — so a client behind the redirector still gets a checksum.
     */
    if (conf->manager_mode) {
        char     redir_host[256];
        uint16_t redir_port;

        /* tried/triedrc: converge to not-found once the client has visited
         * every server holding this path (avoids the redirect-limit loop). */
        if (xrootd_manager_tried_exhausted(ctx->payload, ctx->cur_dlen,
                                           pathbuf)) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY", pathbuf,
                              "cksum", kXR_NotFound,
                              "file not found on any data server");
        }

        if (xrootd_srv_select(pathbuf, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                                pathbuf, "registry", redir_host, redir_port);
        }

        /* Registry miss — ask the CMS parent via kYR_locate (async). */
        if (conf->cms_ctx != NULL) {
            uint32_t streamid;

            streamid = ngx_xrootd_cms_next_streamid(conf->cms_ctx);
            if (xrootd_pending_insert(streamid, ngx_pid, c->fd, c->number,
                                      ctx->cur_streamid,
                                      conf->cms_locate_timeout) == NGX_OK)
            {
                ctx->cms_wait_streamid = streamid;
                ctx->state = XRD_ST_WAITING_CMS;
                ngx_add_timer(c->read, conf->cms_locate_timeout);
                if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
                                               pathbuf) == NGX_OK)
                {
                    return NGX_AGAIN;
                }
                ngx_del_timer(c->read);
                ctx->state = XRD_ST_REQ_HEADER;
                xrootd_pending_remove(streamid, ngx_pid);
            }
        }
        /* Registry + CMS miss: fall through to the local resolve (404). */
    }

    xrootd_beneath_full_path(conf->common.root_canon, pathbuf,
                              full_path, sizeof(full_path));

    if (xrootd_auth_gate(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                         pathbuf, full_path, conf,
                         XROOTD_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    fd = xrootd_open_beneath(conf->rootfd, pathbuf, O_RDONLY, 0);
    if (fd < 0) {
        /*
         * Read-through cache miss: the file has not been pulled from the origin
         * yet (a cached hit is computed locally above).  The origin holds the
         * authoritative bytes — identical to anything we would later cache — so
         * redirect the metadata query there rather than returning "not found".
         */
        if (errno == ENOENT && conf->cache_origin_host.len > 0) {
            char   origin_host[256];
            size_t hlen = conf->cache_origin_host.len < sizeof(origin_host)
                          ? conf->cache_origin_host.len : sizeof(origin_host) - 1;

            ngx_memcpy(origin_host, conf->cache_origin_host.data, hlen);
            origin_host[hlen] = '\0';
            XROOTD_RETURN_REDIR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                                pathbuf, "cache-origin", origin_host,
                                conf->cache_origin_port);
        }
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                          full_path, "cksum", xrootd_kxr_from_errno(errno),
                          strerror(errno));
    }

    if (conf->common.thread_pool != NULL) {
        xrootd_cksum_aio_t *t;
        ngx_thread_task_t  *task;
        ngx_flag_t          posted;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_cksum_aio_t));
        if (task == NULL) {
            close(fd);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
            return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
        }

        t = task->ctx;
        t->ctx      = ctx;
        t->c        = c;
        t->conf     = conf;
        t->fd       = fd;
        t->close_fd = 1;
        ngx_memcpy(t->streamid, ctx->cur_streamid, 2);
        ngx_cpystrn((u_char *) t->algo, (u_char *) algo, sizeof(t->algo));
        ngx_cpystrn((u_char *) t->resolved, (u_char *) full_path,
                    sizeof(t->resolved));
        t->error_code = 0;

        xrootd_task_bind(task, xrootd_cksum_aio_thread, xrootd_cksum_aio_done);
        task->ctx           = t;

        if (xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task,
                                 "cksum thread pool queue full, using sync",
                                 &posted) != NGX_OK)
        {
            close(fd);
            return NGX_ERROR;
        }

        if (posted) {
            return NGX_OK;
        }
    }

    rc = xrootd_query_build_checksum(ctx, c, fd, full_path, algo, resp,
                                     sizeof(resp));
    close(fd);
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    xrootd_log_access(ctx, c, "QUERY", full_path, "cksum", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}

/* ---- Function: xrootd_query_cksum_handle() — handle-based kXR_Qcksum handler ---- */
/* WHAT: Computes checksum on an already-open file using its stored fhandle index. Extracts optional algo from payload (prefix byte=0),
 *      validates the handle index, and delegates to xrootd_query_build_checksum(). Returns hex-formatted result.
 * WHY: kXR_Qcksum can query either open-file handles or arbitrary paths; this handler implements the handle-based variant where
 *      the file is already opened (lower overhead than re-opening). Clients use handles for repeated checksum queries on same file.
 * HOW: 1) Extract optional algo from payload if prefix byte = 0. 2) Validate fhandle index range and fd validity. 3) Build checksum + send result. */

static ngx_int_t
xrootd_query_cksum_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ClientQueryRequest *req,
    char *algo, size_t algo_sz)
{
    char      resolved[PATH_MAX];
    char      resp[256];
    int       idx;
    ngx_int_t rc;

    if (ctx->payload != NULL && ctx->cur_dlen > 1 && ctx->payload[0] == 0) {
        const u_char *ap = ctx->payload + 1;
        size_t        alen;

        alen = strnlen((const char *) ap, (size_t) (ctx->cur_dlen - 1));
        if (alen > 0) {
            (void) xrootd_query_parse_algorithm(ap, alen, algo, algo_sz);
        }
    }

    idx = (int) (unsigned char) req->fhandle[0];
    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_cpystrn((u_char *) resolved,
                (u_char *) (ctx->files[idx].path != NULL
                            ? ctx->files[idx].path : "-"),
                sizeof(resolved));

    if (conf->common.thread_pool != NULL) {
        xrootd_cksum_aio_t *t;
        ngx_thread_task_t  *task;
        ngx_flag_t          posted;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_cksum_aio_t));
        if (task == NULL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
            return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
        }

        t = task->ctx;
        t->ctx      = ctx;
        t->c        = c;
        t->conf     = conf;
        t->fd       = ctx->files[idx].fd;
        t->close_fd = 0;
        ngx_memcpy(t->streamid, ctx->cur_streamid, 2);
        ngx_cpystrn((u_char *) t->algo, (u_char *) algo, sizeof(t->algo));
        ngx_cpystrn((u_char *) t->resolved, (u_char *) resolved,
                    sizeof(t->resolved));
        t->error_code = 0;

        xrootd_task_bind(task, xrootd_cksum_aio_thread, xrootd_cksum_aio_done);
        task->ctx           = t;

        if (xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task,
                                 "cksum thread pool queue full, using sync",
                                 &posted) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (posted) {
            return NGX_OK;
        }
    }

    rc = xrootd_query_build_checksum(ctx, c, ctx->files[idx].fd, resolved,
                                     algo, resp, sizeof(resp));
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
    xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}

/* ---- public API: xrootd_query_cksum() — kXR_Qcksum dispatch entry point ----
 * WHAT: Main dispatcher for Qcksum requests. Routes by payload prefix byte: non-zero → path-based handler (cksum_path with full security chain); zero or empty → handle-based handler (cksum_handle with already-open fd). Default algo is adler32. Both paths support async thread pool execution and synchronous fallback. */

ngx_int_t
xrootd_query_cksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ClientQueryRequest *req)
{
    char algo[32];

    ngx_cpystrn((u_char *) algo, (u_char *) "adler32", sizeof(algo));

    /*
     * Wire-format routing on the payload's first byte:
     *   non-zero first byte → payload is a printable "[algo:]path" string, so
     *     take the path-based variant (full auth chain + confined open).
     *   zero or empty payload → no path on the wire; use the fhandle index from
     *     the request header (handle-based variant on an already-open fd).
     * The default algorithm is adler32 (xrdcp's default) in either variant; a
     * leading "algo:" prefix in the path payload overrides it downstream.
     */
    if (ctx->cur_dlen > 0 && ctx->payload != NULL && ctx->payload[0] != 0) {
        return xrootd_query_cksum_path(ctx, c, conf, algo, sizeof(algo));
    }

    return xrootd_query_cksum_handle(ctx, c, conf, req, algo, sizeof(algo));
}
