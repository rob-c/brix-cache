#include "cms_internal.h"
#include "../manager/pending.h"
#include "../manager/registry.h"
#include "../path/beneath.h"
#include "../path/path.h"           /* xrootd_sanitize_log_string (WS6) */
#include "../compat/net_target.h"   /* xrootd_net_host_chars_valid (WS6) */
#include "../metrics/metrics_macros.h"   /* Phase 51 (A1): resilience counters */

static ngx_connection_t *cms_find_client_connection(int fd);

/* ---- cms_wake_pending_session — redirect waiting XRootD client to CMS-managed server ----
 *
 * WHAT: Parses the first host:port entry from a kYR_select or kYR_try payload and wakes the suspended XRootD client session that is waiting for a locate response. The CMS manager has resolved which server should serve this path, and we redirect the client there. WHY: Per-worker design — the CMS connection and the waiting XRootD connection are in the same nginx worker process, so resolving the saved client fd within this worker is sufficient. HOW: 1) Lookup pending locate entry by streamid + pid → 2) Remove from pending table → 3) Resolve fd to live ngx_connection_t → 4) Update client state to XRD_ST_REQ_HEADER → 5) Call xrootd_send_redirect with host/port → 6) Resume reading on client connection. */

static ngx_int_t
cms_wake_pending_session(ngx_xrootd_cms_ctx_t *cms_ctx, uint32_t streamid,
    const char *host, uint16_t port)
{
    xrootd_pending_locate_t  *pending;
    ngx_connection_t         *client_conn;
    ngx_stream_session_t     *session;
    xrootd_ctx_t             *xrd_ctx;
    int                       conn_fd;
    ngx_atomic_uint_t         conn_number;
    u_char                    client_streamid[2];

    pending = xrootd_pending_lookup(streamid, ngx_pid);
    if (pending == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cms_ctx->cycle->log, 0,
                       "xrootd: CMS wake: streamid=%uD not found in pending table",
                       streamid);
        return NGX_OK;  /* session timed out and was already removed */
    }

    conn_fd = pending->conn_fd;
    conn_number = pending->conn_number;
    client_streamid[0] = pending->client_streamid[0];
    client_streamid[1] = pending->client_streamid[1];
    xrootd_pending_unlock();

    xrootd_pending_remove(streamid, ngx_pid);

    client_conn = cms_find_client_connection(conn_fd);
    if (client_conn == NULL || client_conn->number != conn_number) {
        return NGX_OK;  /* fd was recycled after the client disconnected */
    }

    session = client_conn->data;
    if (session == NULL) {
        return NGX_OK;
    }

    xrd_ctx = ngx_stream_get_module_ctx(session, ngx_stream_xrootd_module);
    if (xrd_ctx == NULL || xrd_ctx->state != XRD_ST_WAITING_CMS) {
        return NGX_OK;
    }

    /*
     * WS6: the redirect host comes straight from the manager's kYR_select /
     * kYR_try payload and is copied verbatim into the "Shost:port" redirect the
     * client parses.  A compromised/hostile manager could inject control bytes or
     * an alternate scheme here, so validate it with the same character allowlist
     * the registry uses as its store choke point (xrootd_net_host_chars_valid).
     * On reject, drop the redirect and leave the client in XRD_ST_WAITING_CMS to
     * hit its own cms_locate_timeout — we never emit a poisoned host.
     */
    if (host == NULL
        || !xrootd_net_host_chars_valid(host, ngx_strlen(host)))
    {
        char  safe[256];
        xrootd_sanitize_log_string(host, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_WARN, cms_ctx->cycle->log, 0,
                      "xrootd: CMS select: rejected redirect to invalid host "
                      "\"%s\" for fd=%d", safe, conn_fd);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, cms_ctx->cycle->log, 0,
                  "xrootd: CMS select: redirecting client fd=%d to %s:%u",
                  conn_fd, host, (unsigned) port);

    ngx_del_timer(client_conn->read);
    xrd_ctx->state = XRD_ST_REQ_HEADER;
    xrd_ctx->cur_streamid[0] = client_streamid[0];
    xrd_ctx->cur_streamid[1] = client_streamid[1];
    if (xrootd_send_redirect(xrd_ctx, client_conn, host, port) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cms_ctx->cycle->log, 0,
                      "xrootd: CMS select: failed to queue redirect for fd=%d",
                      conn_fd);
        return NGX_ERROR;
    }
    xrootd_schedule_read_resume(client_conn);
    return NGX_OK;
}

static ngx_connection_t *
cms_find_client_connection(int fd)
{
    ngx_uint_t        i;
    ngx_connection_t *c;

    if (fd < 0) {
        return NULL;
    }

    if (ngx_cycle->files != NULL && (ngx_uint_t) fd < ngx_cycle->files_n) {
        c = ngx_cycle->files[fd];
        if (c != NULL && c->fd == fd) {
            return c;
        }
        return NULL;
    }

    for (i = 0; i < ngx_cycle->connection_n; i++) {
        c = &ngx_cycle->connections[i];
        if (c->fd == fd) {
            return c;
        }
    }

    return NULL;
}

/* ---- ngx_xrootd_cms_process_frame — CMS opcode dispatch from received frame ----
 *
 * WHAT: Decodes the first 4 bytes of a complete CMS frame (streamid + rrCode) and dispatches to handler based on opcode. Handles PING→PONG, SPACE→AVAIL, STATUS=suspend/resume control, SELECT/TRY=client redirect. WHY: Centralized dispatch keeps recv.c self-contained — each opcode handler is inline rather than delegating to separate files. HOW: 1) Extract streamid via ngx_xrootd_cms_get32() → 2) Read rrCode at offset 4 → 3) Switch on code → 4) Call appropriate send function or update conf flags. Unknown opcodes are silently ignored (debug log). */

static ngx_int_t
ngx_xrootd_cms_process_frame(ngx_xrootd_cms_ctx_t *ctx)
{
    uint32_t  streamid;
    u_char    code;

    streamid = ngx_xrootd_cms_get32(ctx->inbuf);
    code = ctx->inbuf[4];

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "xrootd: CMS process frame code=%ui streamid=%uD",
                   (ngx_uint_t) code, streamid);

    switch (code) {
    case CMS_RR_PING:
        return ngx_xrootd_cms_send_pong(ctx, streamid);

    case CMS_RR_SPACE:
        return ngx_xrootd_cms_send_avail(ctx, streamid);

    case CMS_RR_STATUS: {
        u_char mod = ctx->inbuf[5];
        if (mod & CMS_ST_SUSPEND) {
            ctx->conf->cms_suspended = 1;
            ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                          "xrootd: CMS suspend received — new logins paused");
        } else if (mod & CMS_ST_RESUME) {
            ctx->conf->cms_suspended = 0;
            ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                          "xrootd: CMS resume received — accepting logins");
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "xrootd: CMS status modifier=0x%02xi (no action)",
                           (ngx_uint_t) mod);
        }
        return NGX_OK;
    }

    case CMS_RR_SELECT: {
        /*
         * kYR_select payload: NUL-terminated hostname + 2-byte big-endian port.
         * The manager has resolved the kYR_locate and named a specific server.
         */
        const u_char  *payload = ctx->inbuf + NGX_XROOTD_CMS_HDR_LEN;
        size_t         payload_len = ctx->in_need - NGX_XROOTD_CMS_HDR_LEN;
        char           host[256];
        size_t         host_len;
        uint16_t       port;

        if (payload_len < 3) {
            /* need at least one host byte, a NUL, and two port bytes */
            return NGX_OK;
        }

        ngx_cpystrn((u_char *) host, (u_char *) payload, sizeof(host));
        host_len = ngx_strlen(host);

        if (host_len + 3 > payload_len) {
            /* port bytes would fall outside the received payload */
            return NGX_OK;
        }

        port = ngx_xrootd_cms_get16(payload + host_len + 1);
        return cms_wake_pending_session(ctx, streamid, host, port);
    }

    case CMS_RR_TRY: {
        /*
         * kYR_try: the manager offers an ordered list of alternatives.
         * Each entry is a NUL-terminated hostname followed by a 2-byte
         * big-endian port.  Use only the first entry; the client will
         * retry remaining entries if it cannot reach this one.
         */
        const u_char  *payload = ctx->inbuf + NGX_XROOTD_CMS_HDR_LEN;
        size_t         payload_len = ctx->in_need - NGX_XROOTD_CMS_HDR_LEN;
        char           host[256];
        size_t         host_len;
        uint16_t       port;

        if (payload_len < 3) {
            return NGX_OK;
        }

        ngx_cpystrn((u_char *) host, (u_char *) payload, sizeof(host));
        host_len = ngx_strlen(host);

        if (host_len + 3 > payload_len) {
            return NGX_OK;
        }

        port = ngx_xrootd_cms_get16(payload + host_len + 1);
        return cms_wake_pending_session(ctx, streamid, host, port);
    }

    case CMS_RR_STATE: {
        /*
         * kYR_state (raw): the manager asks "do you hold <path>?" as part of
         * on-demand selection.  The payload is the raw NUL-terminated namespace
         * path (no Pup framing).  We answer kYR_have (echoing streamid = path
         * hash) if we can serve the path, else stay silent so the manager won't
         * select us — matching real cmsd.
         *
         * Two ways to "have" a path:
         *   - manager_mode (a sub-manager registered UP to a meta-manager):
         *     forward the query to our own server registry — if any registered
         *     leaf data node exports a prefix covering the path, we have it (the
         *     client will be redirected to us and we then redirect down to the
         *     leaf).  This is what makes a multi-tier meta->nginx->leaf mesh
         *     resolve.
         *   - data node: the file exists on our local export filesystem.
         */
        const u_char  *payload = ctx->inbuf + NGX_XROOTD_CMS_HDR_LEN;
        size_t         plen = ctx->in_need - NGX_XROOTD_CMS_HDR_LEN;
        char           pathz[1024];
        size_t         pl;

        /* bounded length of the NUL-terminated path */
        for (pl = 0; pl < plen && payload[pl] != '\0'; pl++) { /* void */ }
        if (pl == 0 || payload[0] != '/' || pl >= sizeof(pathz)) {
            return NGX_OK;
        }

        /* reject path traversal before touching the registry/filesystem */
        {
            size_t k;
            for (k = 0; k + 1 < pl; k++) {
                if (payload[k] == '.' && payload[k + 1] == '.') {
                    return NGX_OK;
                }
            }
        }

        ngx_memcpy(pathz, payload, pl);
        pathz[pl] = '\0';

        if (ctx->conf->manager_mode) {
            char      host[256];
            uint16_t  dport;
            if (xrootd_srv_select(pathz, 0, host, sizeof(host), &dport)) {
                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                               "xrootd: CMS state(mgr): registry serves "
                               "\"%*s\", replying kYR_have", pl, payload);
                return ngx_xrootd_cms_send_have(ctx, streamid, pathz, pl);
            }
            return NGX_OK;
        }

        {
            struct stat  st;

            /*
             * Kernel-confined existence probe.  A malicious manager can ask
             * "do you hold <path>?" for ANY path; the raw stat() this replaced
             * followed symlinks, so a symlink planted under the export root
             * (e.g. /link -> /etc) would make us answer kYR_have for a file
             * OUTSIDE the root — a cross-root information leak and a
             * cluster-poisoning vector.  xrootd_stat_beneath() resolves the
             * path under the persistent export rootfd with openat2
             * RESOLVE_BENEATH, so any symlink or ".." that escapes the root is
             * rejected by the kernel and we correctly stay silent.  (The ".."
             * pre-check above remains as cheap defence-in-depth.)  A node with
             * no local export root (rootfd < 0) never holds files locally.
             */
            if (ctx->conf->rootfd >= 0
                && xrootd_stat_beneath(ctx->conf->rootfd, pathz, &st) == 0)
            {
                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                               "xrootd: CMS state: have \"%*s\", "
                               "replying kYR_have", pl, payload);
                return ngx_xrootd_cms_send_have(ctx, streamid, pathz, pl);
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "xrootd: CMS state: do not have \"%*s\"",
                       pl, payload);
        return NGX_OK;
    }

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "xrootd: ignoring CMS rrCode=%ui", (ngx_uint_t) code);
        return NGX_OK;
    }
}

/* ---- ngx_xrootd_cms_read_handler — CMS incoming frame read loop and dispatch ----
 *
 * WHAT: Event handler for reading incoming CMS frames from the manager connection. Accumulates bytes until a complete header is received, then reads payload based on dlen. Dispatches each opcode (PING→PONG, SPACE→AVAIL, STATUS=suspend/resume, SELECT/TRY=redirect) via ngx_xrootd_cms_process_frame(). Disconnects and retries on timeout or error. */

void
ngx_xrootd_cms_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_xrootd_cms_ctx_t  *ctx;
    ssize_t                n;
    uint16_t               dlen;
    ngx_uint_t             processed = 0;

    c = ev->data;
    ctx = c->data;

    if (ctx == NULL || ctx->connection != c) {
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "xrootd: CMS read handler timedout=%d in_pos=%uz in_need=%uz",
                   (int) ev->timedout, ctx->in_pos, ctx->in_need);

    if (ev->timedout) {
        /*
         * WS1: the manager went silent past cms_read_timeout (black-holed /
         * half-open).  Tear down and reconnect with backoff so we fail over
         * instead of heartbeating into a dead socket forever.
         */
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: CMS manager silent past read timeout — "
                      "reconnecting");
        XROOTD_RESIL_METRIC_INC(cms_read_timeouts_total);
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    for ( ;; ) {
        n = c->recv(c, ctx->inbuf + ctx->in_pos,
                    ctx->in_need - ctx->in_pos);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "xrootd: CMS recv EOF/error, disconnecting");
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->in_pos += (size_t) n;

        if (ctx->in_pos < ctx->in_need) {
            continue;
        }

        if (ctx->in_need == NGX_XROOTD_CMS_HDR_LEN) {
            dlen = ngx_xrootd_cms_get16(ctx->inbuf + 6);

            if ((size_t) dlen + NGX_XROOTD_CMS_HDR_LEN
                > NGX_XROOTD_CMS_MAX_FRAME)
            {
                ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                              "xrootd: CMS frame too large: %ui",
                              (ngx_uint_t) dlen);
                ngx_xrootd_cms_disconnect(ctx);
                ngx_xrootd_cms_schedule_retry(ctx);
                return;
            }

            ctx->in_need = NGX_XROOTD_CMS_HDR_LEN + dlen;
            if (ctx->in_pos < ctx->in_need) {
                continue;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "xrootd: CMS process_frame code=%ui",
                       (ngx_uint_t) ctx->inbuf[4]);

        if (ngx_xrootd_cms_process_frame(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->in_pos = 0;
        ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

        /* WS1: a frame from the manager proves it is alive — reset the silence
         * deadline so a responsive manager is never reconnected. */
        ngx_xrootd_cms_arm_read_deadline(ctx);

        /* A2: fairness — after a bounded number of frames, yield the worker to
         * other connections and resume via a posted read event, so a flooding
         * manager cannot monopolise the event loop. */
        if (++processed >= NGX_XROOTD_CMS_MAX_FRAMES_PER_WAKEUP) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_xrootd_cms_disconnect(ctx);
                ngx_xrootd_cms_schedule_retry(ctx);
                return;
            }
            XROOTD_RESIL_METRIC_INC(cms_frame_yields_total);
            ngx_post_event(c->read, &ngx_posted_events);
            return;
        }
    }

    if (ctx->connection != NULL
        && ngx_handle_read_event(c->read, 0) != NGX_OK)
    {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
    }
}
