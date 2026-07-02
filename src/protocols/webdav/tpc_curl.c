/*
 * tpc_curl.c - (kept) routing + shared helpers
 * Phase-38 split of tpc_curl.c; behavior-identical.
 */
#include "tpc_curl_internal.h"
#include "fs/vfs.h"   /* confined open/unlink via the VFS seam */


/*
 * webdav_tpc_run_curl_core — perform a single HTTP transfer using libcurl.
 *
 * @is_push:   0 = pull (GET remote → write to file_path)
 *             1 = push (read from file_path → PUT to url)
 * @file_path: local file to write (pull) or read (push)
 * @url:       remote HTTPS URL to fetch from (pull) or PUT to (push)
 * @log_tag:   short label for log messages, e.g. "pull" or "push"
 */
ngx_int_t
webdav_tpc_run_curl_core(ngx_log_t *log,
                         ngx_http_xrootd_webdav_loc_conf_t *conf,
                         ngx_array_t *transfer_headers,
                         int is_push,
                         const char *file_path,
                         const char *url,
                         const char *log_tag,
                         uint64_t transfer_id)
{
    CURL              *curl = NULL;
    struct curl_slist *hdrs = NULL;
    struct curl_slist *resolve = NULL;
    CURLcode           res;
    FILE              *fp = NULL;
    char               errbuf[CURL_ERROR_SIZE];
    ngx_int_t          rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_uint_t         i;
    ngx_str_t         *headers;
#ifdef CURLOPT_XFERINFOFUNCTION
    webdav_tpc_curl_progress_t progress;
#endif
#ifdef WEBDAV_TPC_PMARK_SOCKCB
    webdav_tpc_pmark_rec_t pmrec;   /* outlives curl_easy_perform() below */
#endif

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_STARTED]);

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_webdav: curl_easy_init() failed for TPC %s",
                      log_tag);
        return webdav_tpc_curl_finish(rc, curl, hdrs, resolve, fp);
    }

    errbuf[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

#ifdef CURLOPT_XFERINFOFUNCTION
    if (transfer_id != 0) {
        ngx_memzero(&progress, sizeof(progress));
        progress.transfer_id = transfer_id;
        progress.log = log;
        progress.is_push = is_push;
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,
                         webdav_tpc_curl_progress);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress);
    }
#endif

    /* Restrict to HTTPS only — equivalent to curl --proto =https */
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS);
#endif

    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* TLS verification + DNS-rebind pin (W2).  A prohibited/rebind target or
     * resolve failure aborts the transfer with 403 rather than connecting. */
    if (tpc_curl_secure(curl, conf, url, log, &resolve) < 0) {
        rc = NGX_HTTP_FORBIDDEN;
        return webdav_tpc_curl_finish(rc, curl, hdrs, resolve, fp);
    }

    if (conf->tpc_timeout > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) conf->tpc_timeout);
    }
    tpc_curl_apply_stall_bounds(curl, conf);   /* Phase 39 (WS4) */

    if (conf->tpc_cert.len > 0) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT,
                         (const char *) conf->tpc_cert.data);
    }
    if (conf->tpc_key.len > 0) {
        curl_easy_setopt(curl, CURLOPT_SSLKEY,
                         (const char *) conf->tpc_key.data);
    }
    if (conf->tpc_cafile.len > 0) {
        curl_easy_setopt(curl, CURLOPT_CAINFO,
                         (const char *) conf->tpc_cafile.data);
    }
    if (conf->tpc_cadir.len > 0) {
        curl_easy_setopt(curl, CURLOPT_CAPATH,
                         (const char *) conf->tpc_cadir.data);
    }

    if (transfer_headers != NULL && transfer_headers->nelts > 0) {
        headers = transfer_headers->elts;
        for (i = 0; i < transfer_headers->nelts; i++) {
            struct curl_slist *next;
            next = curl_slist_append(hdrs, (const char *) headers[i].data);
            if (next == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "xrootd_webdav: curl_slist_append() OOM for TPC %s",
                              log_tag);
                return webdav_tpc_curl_finish(rc, curl, hdrs, resolve, fp);
            }
            hdrs = next;
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }

    /* Open the local endpoint through the confined resolver (openat2
     * RESOLVE_BENEATH + O_NOFOLLOW): the push side reads an export path supplied
     * by the client, so a raw fopen() would follow a planted in-export symlink
     * out of the export root.  The pull side targets the staged temp; confining
     * it too costs nothing and removes the absolute-path re-open TOCTOU. */
    if (is_push) {
        struct stat  st;
        int          fd;

        fd = xrootd_vfs_open_fd(log, conf->common.root_canon, file_path,
                                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
        if (fd >= 0) {
            fp = fdopen(fd, "rb");
            if (fp == NULL) {
                (void) close(fd);
            }
        }
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: TPC push open(\"%s\") failed",
                          file_path);
            return webdav_tpc_curl_finish(rc, curl, hdrs, resolve, fp);
        }
        if (fstat(fileno(fp), &st) == 0) {
            curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                             (curl_off_t) st.st_size);
        }
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    } else {
        int fd;

        fd = xrootd_vfs_open_fd(log, conf->common.root_canon, file_path,
                                        O_WRONLY | O_CREAT | O_TRUNC
                                            | O_CLOEXEC | O_NOFOLLOW,
                                        0600);
        if (fd >= 0) {
            fp = fdopen(fd, "wb");
            if (fp == NULL) {
                (void) close(fd);
            }
        }
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: TPC pull open(\"%s\") failed",
                          file_path);
            return webdav_tpc_curl_finish(rc, curl, hdrs, resolve, fp);
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    }

#ifdef WEBDAV_TPC_PMARK_SOCKCB
    /* SciTags: mark the outbound data socket (flow label at open, firefly at
     * close).  pmrec lives until curl_easy_perform() returns. */
    webdav_tpc_pmark_attach(curl, &pmrec, conf, is_push, file_path, log);
#endif

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: HTTP-TPC %s failed: %s",
                      log_tag, errbuf[0] ? errbuf : curl_easy_strerror(res));
        rc = NGX_HTTP_BAD_GATEWAY;
    }

    return webdav_tpc_curl_finish(rc, curl, hdrs, resolve, fp);
}


ngx_int_t
webdav_tpc_run_curl_pull(ngx_log_t *log,
                         ngx_http_xrootd_webdav_loc_conf_t *conf,
                         const char *source_url, const char *tmp_path,
                         ngx_array_t *transfer_headers,
                         uint64_t transfer_id)
{
    return webdav_tpc_run_curl_core(log, conf, transfer_headers,
                                    0, tmp_path, source_url, "pull",
                                    transfer_id);
}


ngx_int_t
webdav_tpc_run_curl_push(ngx_log_t *log,
                         ngx_http_xrootd_webdav_loc_conf_t *conf,
                         const char *dest_url, const char *local_path,
                         ngx_array_t *transfer_headers,
                         uint64_t transfer_id)
{
    return webdav_tpc_run_curl_core(log, conf, transfer_headers,
                                    1, local_path, dest_url, "push",
                                    transfer_id);
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
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_SUCCESS]);
    } else {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
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
 */
ngx_int_t
webdav_tpc_run_curl_pull_multi(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *source_url, const char *tmp_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams,
    uint64_t transfer_id, tpc_ms_progress_t *progress)
{
    off_t              total_size;
    CURLM             *cm = NULL;
    CURL              *easy[XROOTD_TPC_MAX_STREAMS];
    struct curl_slist *hdrs[XROOTD_TPC_MAX_STREAMS];
    struct curl_slist *resolve[XROOTD_TPC_MAX_STREAMS];
    ms_stream_ctx_t    write_ctx[XROOTD_TPC_MAX_STREAMS];
#ifdef WEBDAV_TPC_PMARK_SOCKCB
    webdav_tpc_pmark_rec_t pmrec[XROOTD_TPC_MAX_STREAMS];
#endif
    int                fd = -1;
    ngx_uint_t         i;
    int                still_running;
    ngx_int_t          rc = NGX_OK;

    if (n_streams <= 1) {
        return webdav_tpc_run_curl_pull(log, conf, source_url, tmp_path,
                                        transfer_headers, transfer_id);
    }
    if (n_streams > XROOTD_TPC_MAX_STREAMS) {
        n_streams = XROOTD_TPC_MAX_STREAMS;
    }

    /* HEAD to learn file size so we can split into ranges. */
    total_size = tpc_curl_head_size(log, conf, source_url, transfer_headers);
    if (total_size <= 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "xrootd_webdav: multi-stream: unknown Content-Length,"
                      " falling back to single stream");
        return webdav_tpc_run_curl_pull(log, conf, source_url, tmp_path,
                                        transfer_headers, transfer_id);
    }

    if (progress != NULL) {
        progress->total_size = total_size;
    }

    /* Pre-create the output file at full size so all streams can pwrite. */
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);  /* vfs-seam-allow: TPC multi-stream assembly temp (committed via rename) */
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_webdav: multi-stream: open(\"%s\") failed",
                      tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    {
        xrootd_sd_obj_t obj;
        xrootd_sd_posix_wrap(&obj, fd);
        if (xrootd_sd_posix_driver.ftruncate(&obj, total_size) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: multi-stream: ftruncate failed");
            close(fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    cm = curl_multi_init();
    if (cm == NULL) {
        close(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(easy, sizeof(easy));
    ngx_memzero(hdrs, sizeof(hdrs));
    ngx_memzero(resolve, sizeof(resolve));

    /* Set up N easy handles, each covering a disjoint byte range. */
    for (i = 0; i < n_streams; i++) {
        off_t chunk = total_size / (off_t) n_streams;
        off_t start = (off_t) i * chunk;
        off_t end   = (i == n_streams - 1) ? total_size - 1 : start + chunk - 1;
        char  range_buf[64];

        write_ctx[i].fd         = fd;
        write_ctx[i].cur_offset = start;
        write_ctx[i].stream_idx = i;
        write_ctx[i].progress   = progress;

        easy[i] = curl_easy_init();
        if (easy[i] == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs,
                                                    resolve, n_streams, fd);
        }

        if (tpc_curl_apply_conf(easy[i], conf, source_url, transfer_headers,
                                log, &hdrs[i], &resolve[i]) < 0) {
            /* Egress check failed (prohibited/rebind) or OOM — abort. */
            rc = NGX_HTTP_FORBIDDEN;
            return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs,
                                                    resolve, n_streams, fd);
        }

        snprintf(range_buf, sizeof(range_buf), "%lld-%lld",
                 (long long) start, (long long) end);
        curl_easy_setopt(easy[i], CURLOPT_RANGE, range_buf);
        curl_easy_setopt(easy[i], CURLOPT_WRITEFUNCTION, ms_write_cb);
        curl_easy_setopt(easy[i], CURLOPT_WRITEDATA, &write_ctx[i]);

#ifdef WEBDAV_TPC_PMARK_SOCKCB
        /* SciTags: mark each parallel pull stream's outbound socket. pmrec[]
         * lives until the curl_multi loop + cleanup below. */
        webdav_tpc_pmark_attach(easy[i], &pmrec[i], conf, 0 /*pull*/,
                                tmp_path, log);
#endif

        curl_multi_add_handle(cm, easy[i]);
    }

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_STARTED]);

    /* Drive all handles to completion. */
    curl_multi_perform(cm, &still_running);
    while (still_running) {
        int       numfds;
        CURLMcode mc = curl_multi_wait(cm, NULL, 0, 1000, &numfds);
        if (mc != CURLM_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_webdav: curl_multi_wait error: %s",
                          curl_multi_strerror(mc));
            rc = NGX_HTTP_BAD_GATEWAY;
            return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs,
                                                    resolve, n_streams, fd);
        }
        curl_multi_perform(cm, &still_running);
    }

    /* Harvest results — any per-stream failure fails the whole transfer. */
    {
        CURLMsg *msg;
        int      msgs_left;
        while ((msg = curl_multi_info_read(cm, &msgs_left)) != NULL) {
            if (msg->msg == CURLMSG_DONE
                && msg->data.result != CURLE_OK)
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "xrootd_webdav: HTTP-TPC multi-stream failed: %s",
                              curl_easy_strerror(msg->data.result));
                rc = NGX_HTTP_BAD_GATEWAY;
            }
        }
    }

    return webdav_tpc_run_curl_multi_finish(rc, cm, easy, hdrs, resolve,
                                            n_streams, fd);
}
