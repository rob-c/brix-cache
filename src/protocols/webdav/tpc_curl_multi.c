/*
 * tpc_curl_multi.c - parallel Range-based multi-stream pull (curl_multi driver).
 * Phase-38 split of tpc_curl.c; behavior-identical.
 */
#include "tpc_curl_internal.h"


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
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);  /* vfs-seam-allow: TPC multi-stream assembly temp (committed via rename); O_NOFOLLOW matches the sibling staging opens */
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
