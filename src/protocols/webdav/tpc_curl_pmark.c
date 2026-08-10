/*
 * tpc_curl_pmark.c - extracted concern
 * Phase-38 split of tpc_curl.c; behavior-identical.
 */
#include "tpc_curl_internal.h"

curl_socket_t
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
        (void) brix_pmark_flowlabel_apply_addr((int) fd,
            (struct sockaddr *) &address->addr, (socklen_t) address->addrlen,
            rec->exp, rec->act, rec->log);
        rec->fd = (int) fd;
    }
    return fd;
}


int
webdav_tpc_pmark_closesocket(void *clientp, curl_socket_t item)
{
    webdav_tpc_pmark_rec_t *rec = clientp;

    if (rec != NULL && rec->active && rec->fd == (int) item) {
        /* Socket is still connected here — emit the firefly (reads TCP_INFO)
         * before the close below. */
        brix_pmark_firefly_oneshot(rec->pm, (int) item, rec->exp, rec->act,
            rec->peer_is_src, rec->app, rec->log);
        rec->fd = -1;
    }
    return close((int) item);
}


/* Resolve codes + attach the socket callbacks to `curl`.  `rec` is caller-owned
 * (stack) and must outlive curl_easy_perform().  No-op when pmark is off or the
 * transfer does not map to an (experiment, activity). */
void
webdav_tpc_pmark_attach(CURL *curl, webdav_tpc_pmark_rec_t *rec,
    ngx_http_brix_webdav_loc_conf_t *conf, int is_push,
    const char *file_path, ngx_log_t *log)
{
    brix_pmark_conf_t *pm = &conf->common.pmark;
    ngx_uint_t           e, a;
    size_t               n;

    brix_pmark_flow_id_t flow_id = {
        .vo_csv = "", .user = "", .path = file_path, .cgi = NULL,
    };

    ngx_memzero(rec, sizeof(*rec));
    rec->fd = -1;

    if (!pm->enable
        || brix_pmark_runtime_ensure(pm, ngx_cycle->pool, log) != NGX_OK
        || brix_pmark_map_codes(pm, &flow_id, &e, &a) != NGX_OK)
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


/* ---- Record a stream's connected remote endpoint for perf markers ----
 *
 * WHAT: Formats the easy handle's CONNECTED peer (CURLINFO_PRIMARY_IP/PORT)
 *       as "tcp:<ip>:<port>" (IPv6 bracketed: "tcp:[<ip>]:<port>") into
 *       progress->remote[idx], exactly once per stream.
 *
 * WHY:  §6.10 WLCG perf-marker parity — the optional "RemoteConnections:"
 *       line names where the stripe's data actually comes from. It must be
 *       the connected endpoint curl reports, never text from the client's
 *       Source URL (a hostile URL string must not be reflected into the
 *       marker stream).
 *
 * HOW:  1. No-op unless progress and easy exist and the slot is uncaptured.
 *       2. getinfo PRIMARY_IP/PORT — available once the transfer is past
 *          connect, which the first write callback guarantees.
 *       3. Format (':' in the ip ⇒ IPv6 ⇒ brackets), write-release with a
 *          memory barrier BEFORE flipping remote_ready so the event-loop
 *          marker reader never sees a torn string.
 */
void
webdav_tpc_capture_remote(CURL *easy, tpc_ms_progress_t *progress,
                          ngx_uint_t idx)
{
    char *primary_ip = NULL;
    long  primary_port = 0;
    int   written;

    if (progress == NULL || easy == NULL
        || idx >= BRIX_TPC_MAX_STREAMS || progress->remote_ready[idx]) {
        return;
    }
    if (curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &primary_ip) != CURLE_OK
        || curl_easy_getinfo(easy, CURLINFO_PRIMARY_PORT,
                             &primary_port) != CURLE_OK
        || primary_ip == NULL || primary_ip[0] == '\0') {
        return;
    }

    written = snprintf(progress->remote[idx], sizeof(progress->remote[idx]),
                       strchr(primary_ip, ':') != NULL
                           ? "tcp:[%s]:%ld" : "tcp:%s:%ld",
                       primary_ip, primary_port);
    if (written <= 0 || (size_t) written >= sizeof(progress->remote[idx])) {
        progress->remote[idx][0] = '\0';
        return;
    }

    ngx_memory_barrier();
    progress->remote_ready[idx] = 1;
}

/* Write callback for multi-stream range downloads. */
size_t
ms_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    ms_stream_ctx_t *ctx   = userdata;
    size_t           total = size * nmemb;
    size_t           done  = 0;

    webdav_tpc_capture_remote(ctx->easy, ctx->progress, ctx->stream_idx);

    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, ctx->fd);   /* phase-55: SD seam */
    while (done < total) {
        /* backend-agnostic vtable form (not the concrete brix_sd_posix_driver)
         * so a non-POSIX backend serves this path unchanged. */
        ssize_t n = obj.driver->pwrite(&obj, ptr + done, total - done,
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


int
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
        const brix_tpc_transfer_t *t =
            brix_tpc_registry_find(progress->transfer_id);
        if (t != NULL && t->cancelled) {
            return 1;
        }
    }

    done = progress->is_push ? (off_t) ulnow : (off_t) dlnow;
    total = progress->is_push ? (off_t) ultotal : (off_t) dltotal;

    if (done != progress->last_done) {
        progress->last_done = done;
        (void) brix_tpc_progress_emit(progress->transfer_id, done, total,
                                        BRIX_TPC_STATE_ACTIVE,
                                        progress->log);
    }

    return 0;
}


/*
 * webdav_tpc_curl_finish — release a single-transfer's libcurl resources and
 * record the success/error metric, returning rc unchanged.
 *
 * Called at every exit of webdav_tpc_run_curl_core (success and each early
 * failure). All handles are NULL-tolerant and start NULL, so invoking this at
 * any point frees exactly what had been built so far — which lets the core
 * function exit with a plain `return` instead of a shared goto/label.
 */
ngx_int_t
webdav_tpc_curl_finish(ngx_int_t rc, CURL *curl, struct curl_slist *hdrs,
    struct curl_slist *resolve, FILE *fp)
{
    if (fp != NULL) {
        /* Cleanup-only close: rc already encodes the transfer outcome and the
         * stream's data (if any) was consumed by libcurl; nothing actionable
         * remains on a close error. */
        (void) fclose(fp);
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
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_SUCCESS]);
    } else {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_CURL_ERROR]);
    }
    return rc;
}
