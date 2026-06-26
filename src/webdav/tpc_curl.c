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
#include "../fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "../tpc/common/registry.h"
#include "../compat/net_target.h"
#include "../compat/host_format.h"  /* xrootd_format_host — IPv6 bracketing */

#include <curl/curl.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * SciTags packet marking for the OUTBOUND TPC leg (phase-34).
 *
 * libcurl owns the gateway→remote connection, so we hook its socket lifecycle:
 *  - CURLOPT_OPENSOCKETFUNCTION creates the data socket and, while it is still
 *    UNconnected, leases the IPv6 flow label toward the destination address curl
 *    is about to connect to (the kernel then stamps every egress packet).
 *  - CURLOPT_CLOSESOCKETFUNCTION emits a firefly (start+end with TCP_INFO) for
 *    the connected socket just before closing it.
 * Codes are resolved once at handle setup from the WebDAV pmark config (path /
 * default mapping; the per-request identity is not threaded into the TPC worker).
 * Everything is fail-open.  Requires curl >= 7.21.7 for the close callback.
 */
typedef struct {
    xrootd_pmark_conf_t *pm;
    ngx_uint_t           exp;
    ngx_uint_t           act;
    int                  peer_is_src;   /* pull: remote supplies the data */
    int                  fd;            /* the data socket we marked, or -1 */
    char                 app[32];
    ngx_log_t           *log;
    unsigned             active:1;
} webdav_tpc_pmark_rec_t;

#if defined(CURLOPT_OPENSOCKETFUNCTION) && defined(CURLOPT_CLOSESOCKETFUNCTION)
#define WEBDAV_TPC_PMARK_SOCKCB 1

static curl_socket_t
webdav_tpc_pmark_opensocket(void *clientp, curlsocktype purpose,
    struct curl_sockaddr *address)
{
    webdav_tpc_pmark_rec_t *rec = clientp;
    curl_socket_t           fd;

    fd = socket(address->family, address->socktype, address->protocol);
    if (fd == CURL_SOCKET_BAD) {
        return CURL_SOCKET_BAD;
    }
    /* Only the actual data connection; skip any proxy/other socket types. */
    if (rec != NULL && rec->active && purpose == CURLSOCKTYPE_IPCXN) {
        (void) xrootd_pmark_flowlabel_apply_addr((int) fd,
            (struct sockaddr *) &address->addr, (socklen_t) address->addrlen,
            rec->exp, rec->act, rec->log);
        rec->fd = (int) fd;
    }
    return fd;
}

static int
webdav_tpc_pmark_closesocket(void *clientp, curl_socket_t item)
{
    webdav_tpc_pmark_rec_t *rec = clientp;

    if (rec != NULL && rec->active && rec->fd == (int) item) {
        /* Socket is still connected here — emit the firefly (reads TCP_INFO)
         * before the close below. */
        xrootd_pmark_firefly_oneshot(rec->pm, (int) item, rec->exp, rec->act,
            rec->peer_is_src, rec->app, rec->log);
        rec->fd = -1;
    }
    return close((int) item);
}

/* Resolve codes + attach the socket callbacks to `curl`.  `rec` is caller-owned
 * (stack) and must outlive curl_easy_perform().  No-op when pmark is off or the
 * transfer does not map to an (experiment, activity). */
static void
webdav_tpc_pmark_attach(CURL *curl, webdav_tpc_pmark_rec_t *rec,
    ngx_http_xrootd_webdav_loc_conf_t *conf, int is_push,
    const char *file_path, ngx_log_t *log)
{
    xrootd_pmark_conf_t *pm = &conf->common.pmark;
    ngx_uint_t           e, a;
    size_t               n;

    ngx_memzero(rec, sizeof(*rec));
    rec->fd = -1;

    if (!pm->enable
        || xrootd_pmark_runtime_ensure(pm, ngx_cycle->pool, log) != NGX_OK
        || xrootd_pmark_map_codes(pm, "", "", file_path, NULL, &e, &a) != NGX_OK)
    {
        return;
    }

    rec->pm  = pm;
    rec->exp = e;
    rec->act = a;
    rec->peer_is_src = is_push ? 0 : 1;   /* pull (GET) → remote is source */
    rec->log = log;
    n = pm->appname.len < sizeof(rec->app) - 1
      ? pm->appname.len : sizeof(rec->app) - 1;
    if (n) { ngx_memcpy(rec->app, pm->appname.data, n); }
    rec->app[n] = '\0';
    rec->active = 1;

    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION,
                     webdav_tpc_pmark_opensocket);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, rec);
    curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION,
                     webdav_tpc_pmark_closesocket);
    curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, rec);
}
#endif /* socket callbacks available */

/*
 * tpc_curl_secure — enforce TLS verification and pin the SSRF-validated IP.
 *
 * Two defenses applied to every outbound curl handle (Phase 28 W2):
 *  (1) Explicit CURLOPT_SSL_VERIFYPEER/VERIFYHOST — never rely on curl's
 *      compile-time defaults, which a non-standard build could weaken.
 *  (2) Resolve the URL host once here (under SSRF policy) and pin the result
 *      via CURLOPT_RESOLVE.  curl then connects only to that exact address
 *      rather than performing its own independent DNS lookup, closing the
 *      DNS-rebind TOCTOU window between the policy check and the connect.
 *      TLS SNI/cert validation still uses the original hostname, so pinning
 *      does not weaken certificate checking.
 *
 * Runs in the TPC thread pool, so the blocking getaddrinfo() inside
 * check_dns_pin is safe here.  Returns 0 with *resolve_out set (caller frees
 * the slist after the transfer) on success; -1 when the host is prohibited or
 * unresolvable — the transfer MUST abort.
 */
static int
tpc_curl_secure(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *url, ngx_log_t *log, struct curl_slist **resolve_out)
{
    xrootd_net_target_t        tgt;
    xrootd_net_target_policy_t pol;
    ngx_str_t                  url_str;
    char                       pin_ip[128];
    char                       err[256];
    char                       entry[512];   /* "[host]:port:addr" — room for a
                                              * bracketed IPv6/long host + addr */
    uint16_t                   port;
    struct curl_slist         *rs;

    *resolve_out = NULL;

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    url_str.data = (u_char *) url;
    url_str.len  = ngx_strlen(url);

    ngx_memzero(&pol, sizeof(pol));
    pol.require_https      = 1;
    pol.allow_local        = conf->tpc_allow_local;
    pol.allow_private      = conf->tpc_allow_private;
    pol.default_https_port = 443;

    if (xrootd_net_target_parse(NULL, &url_str, &tgt, err, sizeof(err)) != NGX_OK
        || xrootd_net_target_check_dns_pin(&tgt, &pol, pin_ip, sizeof(pin_ip),
                                           err, sizeof(err)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: TPC egress check blocked \"%s\": %s",
                      url, err);
        return -1;
    }

    port = tgt.has_port ? tgt.port : 443;
    {
        /* curl's CURLOPT_RESOLVE host field must bracket an IPv6 literal
         * ("[::1]:443:addr") to match the bracketed host in an IPv6 URL;
         * tgt.host arrives bare from net_target.  The resolved address (pin_ip)
         * stays bare — curl accepts a bare IPv6 in the address position. */
        char   hostz[256], hostb[288];
        size_t hl = ngx_min(tgt.host.len, sizeof(hostz) - 1);
        ngx_memcpy(hostz, tgt.host.data, hl);
        hostz[hl] = '\0';
        xrootd_format_host(hostz, hostb, sizeof(hostb));
        snprintf(entry, sizeof(entry), "%s:%u:%s",
                 hostb, (unsigned) port, pin_ip);
    }

    rs = curl_slist_append(NULL, entry);
    if (rs == NULL) {
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_RESOLVE, rs);
    *resolve_out = rs;
    return 0;
}

typedef struct {
    uint64_t   transfer_id;
    ngx_log_t *log;
    int        is_push;
    off_t      last_done;
} webdav_tpc_curl_progress_t;

/* Per-stream write state for multi-stream pull. */
typedef struct {
    int                fd;
    off_t              cur_offset;   /* increments with each write */
    ngx_uint_t         stream_idx;
    tpc_ms_progress_t *progress;     /* NULL if progress tracking disabled */
} ms_stream_ctx_t;

/*
 * Apply URL, TLS credentials, timeout, and forwarded headers to a curl handle.
 * The caller must free *hdrs_out via curl_slist_free_all() after cleanup.
 * Returns 0 on success, -1 on slist OOM.
 */
/*
 * Phase 39 (WS4): bound a stalled / black-holed TPC remote.  Always cap connect
 * time (a connect to a black hole otherwise hangs the thread-pool worker forever)
 * and enable TCP keepalive; optionally abort a transfer that stays below a
 * bytes/sec floor (idle / low-speed) WITHOUT killing a slow-but-progressing one.
 * Pure additive curl configuration — no data-copy cost; the low-speed bound is
 * off unless the operator sets both knobs.
 */
#ifndef XROOTD_TPC_CONNECT_TIMEOUT_SECS
#define XROOTD_TPC_CONNECT_TIMEOUT_SECS  30L
#endif
static void
tpc_curl_apply_stall_bounds(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
                     XROOTD_TPC_CONNECT_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    if (conf->tpc_low_speed_bytes > 0 && conf->tpc_low_speed_secs > 0) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                         (long) conf->tpc_low_speed_bytes);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,
                         (long) conf->tpc_low_speed_secs);
    }
}

static int
tpc_curl_apply_conf(CURL *curl,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *url, ngx_array_t *transfer_headers, ngx_log_t *log,
    struct curl_slist **hdrs_out, struct curl_slist **resolve_out)
{
    ngx_uint_t         i;
    ngx_str_t         *headers;
    struct curl_slist *hdrs = NULL;

    *resolve_out = NULL;

    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,    1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);

#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS);
#endif

    /* TLS verification + DNS-rebind pin (W2). */
    if (tpc_curl_secure(curl, conf, url, log, resolve_out) < 0) {
        return -1;
    }

    if (conf->tpc_timeout > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) conf->tpc_timeout);
    tpc_curl_apply_stall_bounds(curl, conf);   /* Phase 39 (WS4) */
    if (conf->tpc_cert.len > 0)
        curl_easy_setopt(curl, CURLOPT_SSLCERT,
                         (const char *) conf->tpc_cert.data);
    if (conf->tpc_key.len > 0)
        curl_easy_setopt(curl, CURLOPT_SSLKEY,
                         (const char *) conf->tpc_key.data);
    if (conf->tpc_cafile.len > 0)
        curl_easy_setopt(curl, CURLOPT_CAINFO,
                         (const char *) conf->tpc_cafile.data);
    if (conf->tpc_cadir.len > 0)
        curl_easy_setopt(curl, CURLOPT_CAPATH,
                         (const char *) conf->tpc_cadir.data);

    if (transfer_headers != NULL && transfer_headers->nelts > 0) {
        headers = transfer_headers->elts;
        for (i = 0; i < transfer_headers->nelts; i++) {
            struct curl_slist *next = curl_slist_append(
                hdrs, (const char *) headers[i].data);
            if (next == NULL) {
                if (hdrs) curl_slist_free_all(hdrs);
                *hdrs_out = NULL;
                return -1;
            }
            hdrs = next;
        }
    }

    *hdrs_out = hdrs;
    if (hdrs != NULL) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }
    return 0;
}

/*
 * Issue a HEAD request to retrieve Content-Length.
 * Returns the size in bytes, or -1 if unknown / request failed.
 */
static off_t
tpc_curl_head_size(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *url, ngx_array_t *transfer_headers)
{
    CURL              *curl;
    struct curl_slist *hdrs = NULL;
    struct curl_slist *resolve = NULL;
    CURLcode           res;
    off_t              content_length = -1;

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: curl_easy_init() failed for HEAD");
        return -1;
    }

    if (tpc_curl_apply_conf(curl, conf, url, transfer_headers, log,
                            &hdrs, &resolve) < 0) {
        if (resolve) curl_slist_free_all(resolve);
        curl_easy_cleanup(curl);
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
#ifdef CURLINFO_CONTENT_LENGTH_DOWNLOAD_T
        curl_off_t cl;
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
        content_length = (cl >= 0) ? (off_t) cl : -1;
#else
        double cl;
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &cl);
        content_length = (cl >= 1.0) ? (off_t) cl : -1;
#endif
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: HEAD for multi-stream size failed: %s",
                      curl_easy_strerror(res));
    }

    if (hdrs) curl_slist_free_all(hdrs);
    if (resolve) curl_slist_free_all(resolve);
    curl_easy_cleanup(curl);
    return content_length;
}

/* Write callback for multi-stream range downloads. */
static size_t
ms_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    ms_stream_ctx_t *ctx   = userdata;
    size_t           total = size * nmemb;
    size_t           done  = 0;

    xrootd_sd_obj_t obj;

    xrootd_sd_posix_wrap(&obj, ctx->fd);   /* phase-55: SD seam */
    while (done < total) {
        ssize_t n = xrootd_sd_posix_driver.pwrite(&obj, ptr + done, total - done,
                                                  ctx->cur_offset + (off_t) done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;  /* signal error to curl */
        }
        done += (size_t) n;
    }

    ctx->cur_offset += (off_t) total;

    if (ctx->progress != NULL) {
        ngx_atomic_fetch_add(
            &ctx->progress->bytes_per_stream[ctx->stream_idx],
            (ngx_atomic_int_t) total);
    }

    return total;
}

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

    /*
     * Phase 39 (WS5): abort promptly if the client that requested this transfer
     * disconnected (registry_request_cancel set the flag).  Lock-free best-effort
     * read via registry_find; a missed read just falls back to the WS4
     * low-speed/transfer-timeout bounds.  A non-zero return is
     * CURLE_ABORTED_BY_CALLBACK.
     */
    {
        const xrootd_tpc_transfer_t *t =
            xrootd_tpc_registry_find(progress->transfer_id);
        if (t != NULL && t->cancelled) {
            return 1;
        }
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
 * webdav_tpc_curl_finish — release a single-transfer's libcurl resources and
 * record the success/error metric, returning rc unchanged.
 *
 * Called at every exit of webdav_tpc_run_curl_core (success and each early
 * failure). All handles are NULL-tolerant and start NULL, so invoking this at
 * any point frees exactly what had been built so far — which lets the core
 * function exit with a plain `return` instead of a shared goto/label.
 */
static ngx_int_t
webdav_tpc_curl_finish(ngx_int_t rc, CURL *curl, struct curl_slist *hdrs,
    struct curl_slist *resolve, FILE *fp)
{
    if (fp != NULL) {
        fclose(fp);
    }
    if (hdrs != NULL) {
        curl_slist_free_all(hdrs);
    }
    if (resolve != NULL) {
        curl_slist_free_all(resolve);
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

        fd = xrootd_open_confined_canon(log, conf->common.root_canon, file_path,
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

        fd = xrootd_open_confined_canon(log, conf->common.root_canon, file_path,
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
static ngx_int_t
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
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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
