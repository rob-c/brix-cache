/*
 * tpc_curl.c - HTTP-TPC transfer using libcurl for WebDAV COPY operations.
 *
 * Both pull (remote → local via GET) and push (local → remote via PUT) share
 * the same curl setup: HTTPS-only protocol restriction, TLS credentials,
 * timeout, and forwarded transfer headers. Only the direction-specific options
 * differ.
 *
 * curl_global_init() is called once per worker process in the module's
 * init_process hook (module.c) before any thread pool threads start.
 * CURLOPT_NOSIGNAL=1 is required for all handles in multi-threaded nginx.
 */

#include "webdav.h"
#include "../tpc/common/registry.h"

#include <curl/curl.h>
#include <sys/stat.h>

typedef struct {
    uint64_t   transfer_id;
    ngx_log_t *log;
    int        is_push;
    off_t      last_done;
} webdav_tpc_curl_progress_t;

#ifdef CURLOPT_XFERINFOFUNCTION
static int
webdav_tpc_curl_progress(void *clientp, curl_off_t dltotal,
                         curl_off_t dlnow, curl_off_t ultotal,
                         curl_off_t ulnow)
{
    webdav_tpc_curl_progress_t *progress = clientp;
    off_t                       done;
    off_t                       total;

    if (progress == NULL || progress->transfer_id == 0) {
        return 0;
    }

    done = progress->is_push ? (off_t) ulnow : (off_t) dlnow;
    total = progress->is_push ? (off_t) ultotal : (off_t) dltotal;

    if (done != progress->last_done) {
        progress->last_done = done;
        (void) xrootd_tpc_progress_emit(progress->transfer_id, done, total,
                                        XROOTD_TPC_STATE_ACTIVE,
                                        progress->log);
    }

    return 0;
}
#endif

/*
 * webdav_tpc_run_curl_core — perform a single HTTP transfer using libcurl.
 *
 * @is_push:   0 = pull (GET remote → write to file_path)
 *             1 = push (read from file_path → PUT to url)
 * @file_path: local file to write (pull) or read (push)
 * @url:       remote HTTPS URL to fetch from (pull) or PUT to (push)
 * @log_tag:   short label for log messages, e.g. "pull" or "push"
 */
static ngx_int_t
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
    CURLcode           res;
    FILE              *fp = NULL;
    char               errbuf[CURL_ERROR_SIZE];
    ngx_int_t          rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_uint_t         i;
    ngx_str_t         *headers;
#ifdef CURLOPT_XFERINFOFUNCTION
    webdav_tpc_curl_progress_t progress;
#endif

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_STARTED]);

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_webdav: curl_easy_init() failed for TPC %s",
                      log_tag);
        goto cleanup;
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

    if (conf->tpc_timeout > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) conf->tpc_timeout);
    }

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
                goto cleanup;
            }
            hdrs = next;
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }

    if (is_push) {
        struct stat  st;

        fp = fopen(file_path, "rb");
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: TPC push fopen(\"%s\") failed",
                          file_path);
            goto cleanup;
        }
        if (fstat(fileno(fp), &st) == 0) {
            curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                             (curl_off_t) st.st_size);
        }
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    } else {
        fp = fopen(file_path, "wb");
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: TPC pull fopen(\"%s\") failed",
                          file_path);
            goto cleanup;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    }

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: HTTP-TPC %s failed: %s",
                      log_tag, errbuf[0] ? errbuf : curl_easy_strerror(res));
        rc = NGX_HTTP_BAD_GATEWAY;
    }

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    if (hdrs != NULL) {
        curl_slist_free_all(hdrs);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }

    if (rc == NGX_OK) {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_SUCCESS]);
    } else {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
    }
    return rc;
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
