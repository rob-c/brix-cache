/*
 * tpc_curl.c - (kept) routing + shared helpers
 * Phase-38 split of tpc_curl.c; behavior-identical.
 */
#include "tpc_curl_internal.h"
#include "fs/vfs/vfs.h"   /* confined open/unlink via the VFS seam */


/*
 * webdav_tpc_curl_ctx_t — file-local working bundle for a single-stream TPC
 * transfer.
 *
 * WHAT: carries the immutable request parameters (log/conf/headers/direction/
 *       paths/id, snapshotted from the caller's webdav_tpc_req_t) plus the
 *       mutable libcurl resources (curl handle, header and resolve slists, the
 *       local FILE*) that the setup helpers below acquire and thread among
 *       themselves.
 * WHY:  webdav_tpc_run_curl_core's body decomposes into setup/perform/finish
 *       steps that must share the same growing resource set — a struct passes
 *       that state explicitly (no globals) instead of a long helper arg list.
 *       It stays file-local because it owns live curl resources, not a public
 *       request contract (that is webdav_tpc_req_t in webdav_tpc.h).
 * HOW:  the core builds one on the stack, hands its address to each helper, and
 *       always tears the resources down through webdav_tpc_curl_finish().
 */
typedef struct {
    ngx_log_t                        *log;
    ngx_http_brix_webdav_loc_conf_t  *conf;
    ngx_array_t                      *transfer_headers;
    int                               is_push;
    const char                       *file_path;
    const char                       *url;
    const char                       *log_tag;
    uint64_t                          transfer_id;
    const char                       *user_cert;  /* per-user pull-leg cert (or NULL) */
    const char                       *user_key;   /* per-user pull-leg key  (or NULL) */

    CURL                             *curl;
    struct curl_slist                *hdrs;
    struct curl_slist                *resolve;
    FILE                             *fp;
} webdav_tpc_curl_ctx_t;


/*
 * tpc_core_apply_tls_creds — set the client cert/key and CA options on the easy
 * handle, preferring the requesting user's delegated proxy over the static
 * service cert.
 *
 * WHAT: emits CURLOPT_SSLCERT/SSLKEY from ctx->user_cert/_key when present (a
 *       per-user delegated proxy the resolver supplied), else from conf->tpc_cert/
 *       _key (the service identity); CA options always come from conf.
 * WHY:  a TPC PULL must present the END USER's x509 to the source, not the
 *       destination's service cert.  When no per-user proxy was resolved
 *       (non-delegated setups), behaviour is byte-identical to before.  The
 *       bearer path is untouched (it is an Authorization header).
 * HOW:  user_cert/_key win their respective slots and each falls back
 *       independently to the matching conf field only when NULL; the two CA
 *       setopts are emitted only when their conf field is non-empty, as before.
 */
static void
tpc_core_apply_tls_creds(webdav_tpc_curl_ctx_t *ctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf = ctx->conf;

    if (ctx->user_cert != NULL) {
        curl_easy_setopt(ctx->curl, CURLOPT_SSLCERT, ctx->user_cert);
    } else if (conf->tpc_cert.len > 0) {
        curl_easy_setopt(ctx->curl, CURLOPT_SSLCERT,
                         (const char *) conf->tpc_cert.data);
    }
    if (ctx->user_key != NULL) {
        curl_easy_setopt(ctx->curl, CURLOPT_SSLKEY, ctx->user_key);
    } else if (conf->tpc_key.len > 0) {
        curl_easy_setopt(ctx->curl, CURLOPT_SSLKEY,
                         (const char *) conf->tpc_key.data);
    }
    if (conf->tpc_cafile.len > 0) {
        curl_easy_setopt(ctx->curl, CURLOPT_CAINFO,
                         (const char *) conf->tpc_cafile.data);
    }
    if (conf->tpc_cadir.len > 0) {
        curl_easy_setopt(ctx->curl, CURLOPT_CAPATH,
                         (const char *) conf->tpc_cadir.data);
    }
}


/*
 * tpc_core_append_headers — build the CURLOPT_HTTPHEADER slist from the
 * transfer_headers array.
 *
 * WHAT: appends each header string (Source/Credential and friends) to
 *       ctx->hdrs, then installs the list on the handle.
 * WHY:  the append loop carries an OOM early-exit; keeping it in its own helper
 *       lets the core return through finish() without a nested loop+branch.
 * HOW:  NGX_OK when the list is installed (or there are no headers to add);
 *       NGX_ERROR on curl_slist_append() OOM (ctx->hdrs holds the partial list
 *       for the caller to free via finish()).
 */
static ngx_int_t
tpc_core_append_headers(webdav_tpc_curl_ctx_t *ctx)
{
    ngx_str_t   *headers;
    ngx_uint_t   i;

    if (ctx->transfer_headers == NULL || ctx->transfer_headers->nelts == 0) {
        return NGX_OK;
    }

    headers = ctx->transfer_headers->elts;
    for (i = 0; i < ctx->transfer_headers->nelts; i++) {
        struct curl_slist *next;
        next = curl_slist_append(ctx->hdrs, (const char *) headers[i].data);
        if (next == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "brix_webdav: curl_slist_append() OOM for TPC %s",
                          ctx->log_tag);
            return NGX_ERROR;
        }
        ctx->hdrs = next;
    }
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, ctx->hdrs);
    return NGX_OK;
}


/*
 * tpc_core_open_local — open the local file endpoint through the confined VFS
 * resolver and wire it to the handle.
 *
 * WHAT: push → read-only open of the export path + UPLOAD/READDATA (and
 *       INFILESIZE from fstat); pull → create/truncate the staged temp +
 *       WRITEDATA.
 * WHY:  the two directions share the confined-open + fdopen + null-check shape;
 *       the confinement (openat2 RESOLVE_BENEATH + O_NOFOLLOW) is the symlink-
 *       escape guard and must stay in one reviewable place.
 * HOW:  NGX_OK with ctx->fp set on success; NGX_ERROR (ctx->fp left NULL) when
 *       the confined open or fdopen fails.  Behavior is byte-identical to the
 *       former inline branches.
 */
static ngx_int_t
tpc_core_open_local(webdav_tpc_curl_ctx_t *ctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf = ctx->conf;
    int  fd;

    if (ctx->is_push) {
        struct stat st;

        fd = brix_vfs_open_fd(ctx->log, conf->common.root_canon, ctx->file_path,
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
        if (fd >= 0) {
            ctx->fp = fdopen(fd, "rb");
            if (ctx->fp == NULL) {
                (void) close(fd);
            }
        }
        if (ctx->fp == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
                          "brix_webdav: TPC push open(\"%s\") failed",
                          ctx->file_path);
            return NGX_ERROR;
        }
        if (fstat(fileno(ctx->fp), &st) == 0) {
            curl_easy_setopt(ctx->curl, CURLOPT_INFILESIZE_LARGE,
                             (curl_off_t) st.st_size);
        }
        curl_easy_setopt(ctx->curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(ctx->curl, CURLOPT_READDATA, ctx->fp);
        return NGX_OK;
    }

    fd = brix_vfs_open_fd(ctx->log, conf->common.root_canon, ctx->file_path,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (fd >= 0) {
        ctx->fp = fdopen(fd, "wb");
        if (ctx->fp == NULL) {
            (void) close(fd);
        }
    }
    if (ctx->fp == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
                      "brix_webdav: TPC pull open(\"%s\") failed",
                      ctx->file_path);
        return NGX_ERROR;
    }
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, ctx->fp);
    return NGX_OK;
}


/*
 * tpc_core_setup — initialise the easy handle and apply every transfer option
 * up to (but not including) curl_easy_perform().
 *
 * WHAT: curl_easy_init + fixed options + errbuf + optional progress cb +
 *       HTTPS-only pin + URL + TLS/rebind pin (tpc_curl_secure) + timeout/stall
 *       bounds + client creds + request headers + local-file open.
 * WHY:  concentrates the whole configure phase so the core reads as
 *       setup → perform → finish; each early failure returns a distinct rc that
 *       the core forwards through finish().
 * HOW:  errbuf and progress are owned by the caller (they must outlive
 *       curl_easy_perform), so they are passed in.  Returns NGX_OK on a fully
 *       configured handle, or the mapped HTTP error status on failure.
 */
static ngx_int_t
tpc_core_setup(webdav_tpc_curl_ctx_t *ctx, char *errbuf
#ifdef CURLOPT_XFERINFOFUNCTION
               , webdav_tpc_curl_progress_t *progress
#endif
               )
{
    ctx->curl = curl_easy_init();
    if (ctx->curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "brix_webdav: curl_easy_init() failed for TPC %s",
                      ctx->log_tag);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    errbuf[0] = '\0';
    curl_easy_setopt(ctx->curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(ctx->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ctx->curl, CURLOPT_FAILONERROR, 1L);

#ifdef CURLOPT_XFERINFOFUNCTION
    if (ctx->transfer_id != 0) {
        ngx_memzero(progress, sizeof(*progress));
        progress->transfer_id = ctx->transfer_id;
        progress->log = ctx->log;
        progress->is_push = ctx->is_push;
        curl_easy_setopt(ctx->curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_XFERINFOFUNCTION,
                         webdav_tpc_curl_progress);
        curl_easy_setopt(ctx->curl, CURLOPT_XFERINFODATA, progress);
    }
#endif

    /* Restrict to HTTPS only — equivalent to curl --proto =https */
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(ctx->curl, CURLOPT_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(ctx->curl, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS);
#endif

    curl_easy_setopt(ctx->curl, CURLOPT_URL, ctx->url);

    /* TLS verification + DNS-rebind pin (W2).  A prohibited/rebind target or
     * resolve failure aborts the transfer with 403 rather than connecting. */
    if (tpc_curl_secure(ctx->curl, ctx->conf, ctx->url, ctx->log,
                        &ctx->resolve) < 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (ctx->conf->tpc_timeout > 0) {
        curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT,
                         (long) ctx->conf->tpc_timeout);
    }
    tpc_curl_apply_stall_bounds(ctx->curl, ctx->conf);   /* Phase 39 (WS4) */

    tpc_core_apply_tls_creds(ctx);

    if (tpc_core_append_headers(ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Open the local endpoint through the confined resolver (openat2
     * RESOLVE_BENEATH + O_NOFOLLOW): the push side reads an export path supplied
     * by the client, so a raw fopen() would follow a planted in-export symlink
     * out of the export root.  The pull side targets the staged temp; confining
     * it too costs nothing and removes the absolute-path re-open TOCTOU. */
    if (tpc_core_open_local(ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


/*
 * tpc_core_perform — run curl_easy_perform and map its result to an rc.
 *
 * WHAT: executes the configured transfer and returns NGX_OK on CURLE_OK,
 *       NGX_HTTP_BAD_GATEWAY otherwise (logging errbuf/strerror).
 * WHY:  keeps the perform + result-mapping out of the orchestrator body.
 * HOW:  errbuf is the same buffer installed in setup; unchanged behavior.
 */
static ngx_int_t
tpc_core_perform(webdav_tpc_curl_ctx_t *ctx, const char *errbuf)
{
    CURLcode res = curl_easy_perform(ctx->curl);

    if (res == CURLE_OK) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                  "brix_webdav: HTTP-TPC %s failed: %s",
                  ctx->log_tag, errbuf[0] ? errbuf : curl_easy_strerror(res));
    return NGX_HTTP_BAD_GATEWAY;
}


/*
 * webdav_tpc_run_curl_core — perform a single HTTP transfer using libcurl.
 *
 * @is_push:   0 = pull (GET remote → write to file_path)
 *             1 = push (read from file_path → PUT to url)
 * @file_path: local file to write (pull) or read (push)
 * @url:       remote HTTPS URL to fetch from (pull) or PUT to (push)
 * @log_tag:   short label for log messages, e.g. "pull" or "push"
 *
 * Reads as setup → perform → finish: tpc_core_setup() configures the handle
 * (returning the mapped HTTP error on any failure), tpc_core_perform() runs the
 * transfer, and webdav_tpc_curl_finish() tears down every resource on all exits.
 * The 8-param signature is frozen by tpc_curl_internal.h; state is threaded
 * through a file-local webdav_tpc_curl_ctx_t instead.
 */
ngx_int_t
webdav_tpc_run_curl_core(ngx_log_t *log,
                         ngx_http_brix_webdav_loc_conf_t *conf,
                         ngx_array_t *transfer_headers,
                         int is_push,
                         const char *file_path,
                         const char *url,
                         const char *log_tag,
                         uint64_t transfer_id,
                         const char *user_cert,
                         const char *user_key)
{
    webdav_tpc_curl_ctx_t ctx;
    char                  errbuf[CURL_ERROR_SIZE];
    ngx_int_t             rc;
#ifdef CURLOPT_XFERINFOFUNCTION
    webdav_tpc_curl_progress_t progress;
#endif
#ifdef WEBDAV_TPC_PMARK_SOCKCB
    webdav_tpc_pmark_rec_t pmrec;   /* outlives curl_easy_perform() below */
#endif

    ngx_memzero(&ctx, sizeof(ctx));
    ctx.log              = log;
    ctx.conf             = conf;
    ctx.transfer_headers = transfer_headers;
    ctx.is_push          = is_push;
    ctx.file_path        = file_path;
    ctx.url              = url;
    ctx.log_tag          = log_tag;
    ctx.transfer_id      = transfer_id;
    ctx.user_cert        = user_cert;
    ctx.user_key         = user_key;

    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_STARTED]);

    rc = tpc_core_setup(&ctx, errbuf
#ifdef CURLOPT_XFERINFOFUNCTION
                        , &progress
#endif
                        );
    if (rc != NGX_OK) {
        return webdav_tpc_curl_finish(rc, ctx.curl, ctx.hdrs, ctx.resolve,
                                      ctx.fp);
    }

#ifdef WEBDAV_TPC_PMARK_SOCKCB
    /* SciTags: mark the outbound data socket (flow label at open, firefly at
     * close).  pmrec lives until curl_easy_perform() returns. */
    webdav_tpc_pmark_attach(ctx.curl, &pmrec, conf, is_push, file_path, log);
#endif

    rc = tpc_core_perform(&ctx, errbuf);

    return webdav_tpc_curl_finish(rc, ctx.curl, ctx.hdrs, ctx.resolve, ctx.fp);
}


ngx_int_t
webdav_tpc_run_curl_pull(ngx_log_t *log,
                         ngx_http_brix_webdav_loc_conf_t *conf,
                         const char *source_url, const char *tmp_path,
                         ngx_array_t *transfer_headers,
                         uint64_t transfer_id,
                         const char *user_cert, const char *user_key)
{
    return webdav_tpc_run_curl_core(log, conf, transfer_headers,
                                    0, tmp_path, source_url, "pull",
                                    transfer_id, user_cert, user_key);
}


ngx_int_t
webdav_tpc_run_curl_push(ngx_log_t *log,
                         ngx_http_brix_webdav_loc_conf_t *conf,
                         const char *dest_url, const char *local_path,
                         ngx_array_t *transfer_headers,
                         uint64_t transfer_id)
{
    /* Push presents the service credential (or a bearer header) to the
     * destination — the per-user client-cert override is a pull-leg concern. */
    return webdav_tpc_run_curl_core(log, conf, transfer_headers,
                                    1, local_path, dest_url, "push",
                                    transfer_id, NULL, NULL);
}
