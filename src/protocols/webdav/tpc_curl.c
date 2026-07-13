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


/*
 * webdav_tpc_run_curl_multi_finish — tear down a curl_multi run and record the
 * success/error metric, returning rc unchanged.
 *
 * Called at every exit of webdav_tpc_run_curl_pull_multi (success and each early
 * failure). The easy[], hdrs[] and resolve[] arrays start zeroed, so iterating
 * all n_streams slots frees exactly the handles that were set up before the exit
 * — letting the driver exit with a plain `return` instead of a shared
 * goto/label. cm is created before the first failure site, so it is always live.
 */
ngx_int_t
webdav_tpc_run_curl_multi_finish(ngx_int_t rc, CURLM *cm, CURL **easy,
    struct curl_slist **hdrs, struct curl_slist **resolve,
    ngx_uint_t n_streams, int fd)
{
    ngx_uint_t i;

    for (i = 0; i < n_streams; i++) {
        if (easy[i] != NULL) {
            curl_multi_remove_handle(cm, easy[i]);
            curl_easy_cleanup(easy[i]);
        }
        if (hdrs[i] != NULL) {
            curl_slist_free_all(hdrs[i]);
        }
        if (resolve[i] != NULL) {
            curl_slist_free_all(resolve[i]);
        }
    }
    curl_multi_cleanup(cm);
    close(fd);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_SUCCESS]);
    } else {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_ERROR]);
    }
    return rc;
}


/*
 * tpc_ms_prepare_output — create and pre-size the multi-stream assembly temp.
 *
 * WHAT: opens tmp_path O_CREAT|O_TRUNC and ftruncates it to total_size so every
 *       stream can pwrite its disjoint range in place.
 * WHY:  factors the fd lifecycle (open + failure-close on ftruncate) out of the
 *       driver so the driver never owns a half-set-up fd.
 * HOW:  returns the ready fd (>= 0) on success; -1 on open or ftruncate
 *       failure (any opened fd is closed before returning).
 */
static int
tpc_ms_prepare_output(ngx_log_t *log, const char *tmp_path, off_t total_size)
{
    int           fd;
    brix_sd_obj_t obj;

    /* Pre-create the output file at full size so all streams can pwrite. */
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);  /* vfs-seam-allow: TPC multi-stream assembly temp (committed via rename) */
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_webdav: multi-stream: open(\"%s\") failed",
                      tmp_path);
        return -1;
    }

    brix_sd_posix_wrap(&obj, fd);
    if (brix_sd_posix_driver.ftruncate(&obj, total_size) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_webdav: multi-stream: ftruncate failed");
        close(fd);
        return -1;
    }
    return fd;
}


/* webdav_tpc_ms_ctx_t is declared in tpc_curl_internal.h (shared with the pmark
 * callback). */


/*
 * tpc_ms_setup_stream — configure one range-covering easy handle and add it to
 * the multi handle.
 *
 * WHAT: computes stream i's byte range, initialises its write context, creates
 *       and configures the easy handle (conf/egress + Range + write cb + pmark),
 *       and registers it with ctx->cm.
 * WHY:  isolates the per-stream construction (with its two distinct early-fail
 *       codes) so the driver loop stays flat.
 * HOW:  writes the handle/slists into ctx->easy[i]/hdrs[i]/resolve[i] and the
 *       write context into ctx->write_ctx[i].  Returns NGX_OK, or the mapped
 *       HTTP status (INTERNAL on curl_easy_init OOM, FORBIDDEN on egress/OOM) —
 *       the caller tears down all slots via webdav_tpc_run_curl_multi_finish().
 */
static ngx_int_t
tpc_ms_setup_stream(webdav_tpc_ms_ctx_t *ctx, ngx_uint_t i)
{
    off_t chunk = ctx->total_size / (off_t) ctx->n_streams;
    off_t start = (off_t) i * chunk;
    off_t end   = (i == ctx->n_streams - 1)
                      ? ctx->total_size - 1 : start + chunk - 1;
    char  range_buf[64];

    ctx->write_ctx[i].fd         = ctx->fd;
    ctx->write_ctx[i].cur_offset = start;
    ctx->write_ctx[i].stream_idx = i;
    ctx->write_ctx[i].progress   = ctx->progress;

    ctx->easy[i] = curl_easy_init();
    if (ctx->easy[i] == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tpc_curl_apply_conf(ctx->easy[i], ctx->conf, ctx->source_url,
                            ctx->transfer_headers, ctx->log,
                            ctx->user_cert, ctx->user_key,
                            &ctx->hdrs[i], &ctx->resolve[i]) < 0) {
        /* Egress check failed (prohibited/rebind) or OOM — abort. */
        return NGX_HTTP_FORBIDDEN;
    }

    snprintf(range_buf, sizeof(range_buf), "%lld-%lld",
             (long long) start, (long long) end);
    curl_easy_setopt(ctx->easy[i], CURLOPT_RANGE, range_buf);
    curl_easy_setopt(ctx->easy[i], CURLOPT_WRITEFUNCTION, ms_write_cb);
    curl_easy_setopt(ctx->easy[i], CURLOPT_WRITEDATA, &ctx->write_ctx[i]);

#ifdef WEBDAV_TPC_PMARK_SOCKCB
    /* SciTags: mark each parallel pull stream's outbound socket. pmrec[]
     * lives until the curl_multi loop + cleanup below. */
    webdav_tpc_pmark_attach(ctx->easy[i], &ctx->pmrec[i], ctx->conf, 0 /*pull*/,
                            ctx->tmp_path, ctx->log);
#endif

    curl_multi_add_handle(ctx->cm, ctx->easy[i]);
    return NGX_OK;
}


/*
 * tpc_ms_drive — pump all handles on cm to completion.
 *
 * WHAT: runs the curl_multi_perform / curl_multi_wait loop until no handle is
 *       still running.
 * WHY:  separates the event pump (with its wait-error early exit) from result
 *       harvesting.
 * HOW:  NGX_OK when the loop drains normally; NGX_HTTP_BAD_GATEWAY on a
 *       curl_multi_wait error.
 */
static ngx_int_t
tpc_ms_drive(ngx_log_t *log, CURLM *cm)
{
    int still_running;

    curl_multi_perform(cm, &still_running);
    while (still_running) {
        int       numfds;
        CURLMcode mc = curl_multi_wait(cm, NULL, 0, 1000, &numfds);
        if (mc != CURLM_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "brix_webdav: curl_multi_wait error: %s",
                          curl_multi_strerror(mc));
            return NGX_HTTP_BAD_GATEWAY;
        }
        curl_multi_perform(cm, &still_running);
    }
    return NGX_OK;
}


/*
 * tpc_ms_harvest — drain completion messages; any stream error fails the run.
 *
 * WHAT: reads CURLMSG_DONE messages and maps the first per-stream failure to
 *       NGX_HTTP_BAD_GATEWAY (all messages are still drained/logged).
 * WHY:  keeps result inspection out of the driver body.
 * HOW:  NGX_OK when every stream reported CURLE_OK; NGX_HTTP_BAD_GATEWAY
 *       otherwise.
 */
static ngx_int_t
tpc_ms_harvest(ngx_log_t *log, CURLM *cm)
{
    CURLMsg  *msg;
    int       msgs_left;
    ngx_int_t rc = NGX_OK;

    while ((msg = curl_multi_info_read(cm, &msgs_left)) != NULL) {
        if (msg->msg == CURLMSG_DONE && msg->data.result != CURLE_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_webdav: HTTP-TPC multi-stream failed: %s",
                          curl_easy_strerror(msg->data.result));
            rc = NGX_HTTP_BAD_GATEWAY;
        }
    }
    return rc;
}


/*
 * webdav_tpc_run_curl_pull_multi — parallel Range-based GET using curl_multi.
 *
 * Issues a HEAD request to learn Content-Length.  On success, divides the file
 * into n_streams equal-sized byte ranges and runs them concurrently via
 * curl_multi_perform.  Each stream writes to the output file via pwrite at its
 * own offset so the file is assembled in-place without post-merge overhead.
 *
 * Falls back to single-stream when Content-Length is unknown (chunked source or
 * HEAD failure) or when n_streams <= 1.
 *
 * progress may be NULL when called from the non-marker thread path.  When
 * non-NULL, each stream's write callback increments bytes_per_stream[i]
 * atomically so the event-loop poll timer can report per-stream progress.
 *
 * Body reads as: fall back → prepare output → set up N streams → drive →
 * harvest → finish.  Every exit past cm-init routes through
 * webdav_tpc_run_curl_multi_finish() so exactly the set-up handles are freed.
 * The 8-param signature is frozen (out-of-file callers in tpc_marker.c /
 * tpc_thread.c) and reported as a residual.
 */
ngx_int_t
webdav_tpc_run_curl_pull_multi(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const char *source_url, const char *tmp_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams,
    uint64_t transfer_id, tpc_ms_progress_t *progress,
    const char *user_cert, const char *user_key)
{
    off_t              total_size;
    CURLM             *cm = NULL;
    CURL              *easy[BRIX_TPC_MAX_STREAMS];
    struct curl_slist *hdrs[BRIX_TPC_MAX_STREAMS];
    struct curl_slist *resolve[BRIX_TPC_MAX_STREAMS];
    ms_stream_ctx_t    write_ctx[BRIX_TPC_MAX_STREAMS];
#ifdef WEBDAV_TPC_PMARK_SOCKCB
    webdav_tpc_pmark_rec_t pmrec[BRIX_TPC_MAX_STREAMS];
#endif
    webdav_tpc_ms_ctx_t msctx;
    int                fd = -1;
    ngx_uint_t         i;
    ngx_int_t          rc = NGX_OK;

    if (n_streams <= 1) {
        return webdav_tpc_run_curl_pull(log, conf, source_url, tmp_path,
                                        transfer_headers, transfer_id,
                                        user_cert, user_key);
    }
    if (n_streams > BRIX_TPC_MAX_STREAMS) {
        n_streams = BRIX_TPC_MAX_STREAMS;
    }

    /* HEAD to learn file size so we can split into ranges. */
    total_size = tpc_curl_head_size(log, conf, source_url, transfer_headers,
                                    user_cert, user_key);
    if (total_size <= 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "brix_webdav: multi-stream: unknown Content-Length,"
                      " falling back to single stream");
        return webdav_tpc_run_curl_pull(log, conf, source_url, tmp_path,
                                        transfer_headers, transfer_id,
                                        user_cert, user_key);
    }

    if (progress != NULL) {
        progress->total_size = total_size;
    }

    fd = tpc_ms_prepare_output(log, tmp_path, total_size);
    if (fd < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cm = curl_multi_init();
    if (cm == NULL) {
        close(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(easy, sizeof(easy));
    ngx_memzero(hdrs, sizeof(hdrs));
    ngx_memzero(resolve, sizeof(resolve));

    ngx_memzero(&msctx, sizeof(msctx));
    msctx.log              = log;
    msctx.conf             = conf;
    msctx.source_url       = source_url;
    msctx.tmp_path         = tmp_path;
    msctx.transfer_headers = transfer_headers;
    msctx.user_cert        = user_cert;
    msctx.user_key         = user_key;
    msctx.n_streams        = n_streams;
    msctx.total_size       = total_size;
    msctx.fd               = fd;
    msctx.cm               = cm;
    msctx.easy             = easy;
    msctx.hdrs             = hdrs;
    msctx.resolve          = resolve;
    msctx.write_ctx        = write_ctx;
    msctx.progress         = progress;
#ifdef WEBDAV_TPC_PMARK_SOCKCB
    msctx.pmrec            = pmrec;
#endif

    /* Set up N easy handles, each covering a disjoint byte range. */
    for (i = 0; i < n_streams; i++) {
        rc = tpc_ms_setup_stream(&msctx, i);
        if (rc != NGX_OK) {
            return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs,
                                                    resolve, n_streams, fd);
        }
    }

    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_STARTED]);

    rc = tpc_ms_drive(log, cm);
    if (rc != NGX_OK) {
        return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs,
                                                resolve, n_streams, fd);
    }

    rc = tpc_ms_harvest(log, cm);

    return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs, resolve,
                                            n_streams, fd);
}
