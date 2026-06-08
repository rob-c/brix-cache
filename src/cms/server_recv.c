#include "server.h"

/* ---- xrootd_cms_srv_close — tear down CMS server-side connection and unregister data server ----
 * WHAT: Closes the TCP connection to a CMS data-server client, removes ping timer, and unregisters from the server registry if logged_in. WHY: When a data server disconnects, it must be removed from the CMS manager's registry so locate queries don't route clients to dead servers. HOW: 1) If ping_timer set → remove timer → 2) If logged_in → unregister host/port from registry → 3) Set ctx->c = NULL → 4) Close TCP connection. */

void
xrootd_cms_srv_close(xrootd_cms_srv_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->c;
    if (c == NULL) {
        return;
    }

    if (ctx->ping_timer.timer_set) {
        ngx_del_timer(&ctx->ping_timer);
    }

    if (ctx->logged_in) {
        /* Blacklist for 30 s so in-flight locate responses don't route to a
         * server that just went away.  xrootd_srv_register() clears the flag
         * the moment the server successfully reconnects and re-heartbeats. */
        xrootd_srv_blacklist(ctx->host, ctx->port, 30000);
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "xrootd: CMS server: data server %s:%d disconnected "
                      "(blacklisted 30 s)",
                      ctx->host, (int) ctx->port);
    }

    ctx->c = NULL;
    ngx_close_connection(c);
}

/* --- TLV walk helpers ---------------------------------------------------- */

/*
 * The LOGIN/LOAD/AVAIL payloads use a simple type-tagged encoding:
 *   CMS_PT_SHORT (0x80) + big-endian uint16
 *   CMS_PT_INT   (0xa0) + big-endian uint32
 *
 * Walk *p forward by one tagged value, returning the decoded uint32.
 * Advances *p past the tag+value bytes.  Returns 0 and sets *p=end on error.
 */
static uint32_t
tlv_read_next(const u_char **p, const u_char *end)
{
    if (*p >= end) {
        *p = end;
        return 0;
    }

    if (**p == CMS_PT_SHORT) {
        if (end - *p < 3) { *p = end; return 0; }
        uint32_t v = ngx_xrootd_cms_get16(*p + 1);
        *p += 3;
        return v;
    }

    if (**p == CMS_PT_INT) {
        if (end - *p < 5) { *p = end; return 0; }
        uint32_t v = ngx_xrootd_cms_get32(*p + 1);
        *p += 5;
        return v;
    }

    /* Unknown tag — treat as end of parseable data. */
    *p = end;
    return 0;
}

/* --- LOGIN payload parser ------------------------------------------------- */

/*
 * Parse the CMS LOGIN frame payload.  The format (from cms/send.c) is:
 *
 *   PT_SHORT  version       (3 bytes)
 *   PT_INT    mode          (5 bytes)
 *   PT_INT    pid           (5 bytes)
 *   PT_INT    total_gb      (5 bytes)
 *   PT_INT    free_mb       (5 bytes)  ← extracted
 *   PT_INT    min_free_mb   (5 bytes)
 *   PT_SHORT  num_cpus      (3 bytes)
 *   PT_SHORT  util_pct      (3 bytes)  ← extracted
 *   PT_SHORT  port          (3 bytes)  ← extracted
 *   PT_SHORT  (flags1)      (3 bytes)
 *   PT_SHORT  (flags2)      (3 bytes)
 *   PT_SHORT  path_len      (3 bytes)  ← extracted
 *   <raw path bytes>        (path_len bytes)
 *   PT_SHORT  0             (3 bytes)
 *   PT_SHORT  0             (3 bytes)
 */
static int
cms_srv_parse_login(xrootd_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;
    uint32_t       path_len;

    /* version */  (void) tlv_read_next(&p, end);
    /* mode    */  (void) tlv_read_next(&p, end);
    /* pid     */  (void) tlv_read_next(&p, end);
    /* total_gb */ (void) tlv_read_next(&p, end);
    ctx->free_mb   = tlv_read_next(&p, end);
    /* min_free */ (void) tlv_read_next(&p, end);
    /* num_cpus */ (void) tlv_read_next(&p, end);
    ctx->util_pct  = tlv_read_next(&p, end);
    ctx->port      = (uint16_t) tlv_read_next(&p, end);
    /* flags1  */ (void) tlv_read_next(&p, end);
    /* flags2  */ (void) tlv_read_next(&p, end);
    path_len       = tlv_read_next(&p, end);

    if (p == end && payload_len > 0 && ctx->port == 0) {
        /* Truncated or malformed payload. */
        return 0;
    }

    if (path_len > 0) {
        if ((size_t)(end - p) < path_len) {
            return 0;
        }
        size_t copy = path_len < sizeof(ctx->paths) - 1
                      ? path_len
                      : sizeof(ctx->paths) - 1;
        ngx_memcpy(ctx->paths, p, copy);
        ctx->paths[copy] = '\0';
    } else {
        ctx->paths[0] = '\0';
    }

    /* Default XRootD port if the data server didn't advertise one. */
    if (ctx->port == 0) {
        ctx->port = XROOTD_DEFAULT_PORT;
    }

    return 1;
}

/* --- LOAD/AVAIL payload parsers ------------------------------------------ */

/*
 * LOAD payload (from cms/send.c):
 *   PT_SHORT  count=6      (3 bytes)
 *   <6 raw bytes>          (cpu load values, ignored)
 *   PT_INT    free_mb      (5 bytes)  ← extracted
 */
static uint32_t
cms_srv_parse_load_free_mb(const u_char *payload, size_t payload_len)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;

    /* count field */
    (void) tlv_read_next(&p, end);

    /* skip 6 raw CPU bytes */
    if (end - p >= 6) {
        p += 6;
    } else {
        return 0;
    }

    return tlv_read_next(&p, end);
}

/*
 * AVAIL payload (from cms/send.c):
 *   PT_INT    free_mb      (5 bytes)  ← extracted
 *   PT_INT    util_pct     (5 bytes)  ← extracted
 *
 * Used for both CMS_RR_AVAIL and CMS_RR_SPACE.
 */
static void
cms_srv_parse_avail(const u_char *payload, size_t payload_len,
    uint32_t *free_mb, uint32_t *util_pct)
{
    const u_char  *p   = payload;
    const u_char  *end = payload + payload_len;

    *free_mb  = tlv_read_next(&p, end);
    *util_pct = tlv_read_next(&p, end);
}

/* --- Ping timer ----------------------------------------------------------- */

static void
xrootd_cms_srv_ping_timer(ngx_event_t *ev)
{
    xrootd_cms_srv_ctx_t  *ctx = ev->data;

    if (xrootd_cms_srv_send_ping(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: CMS server: ping to %s failed, closing",
                      ctx->host);
        xrootd_cms_srv_close(ctx);
        return;
    }

    ngx_add_timer(&ctx->ping_timer, ctx->interval_ms);
}

/* --- Frame dispatcher ----------------------------------------------------- */

static void
cms_srv_process_frame(xrootd_cms_srv_ctx_t *ctx, u_char code,
    const u_char *payload, size_t payload_len)
{
    uint32_t  free_mb, util_pct;

    switch (code) {

    case CMS_RR_LOGIN:
        if (!cms_srv_parse_login(ctx, payload, payload_len)) {
            ngx_log_error(NGX_LOG_WARN, ctx->c->log, 0,
                          "xrootd: CMS server: malformed LOGIN from %s",
                          ctx->host);
            xrootd_cms_srv_close(ctx);
            return;
        }

        xrootd_srv_register(ctx->host, ctx->port, ctx->paths,
                             ctx->free_mb, ctx->util_pct);
        ctx->logged_in = 1;

        /* Arm the periodic ping now that the data server is logged in. */
        ctx->ping_timer.handler = xrootd_cms_srv_ping_timer;
        ngx_add_timer(&ctx->ping_timer, ctx->interval_ms);

        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "xrootd: CMS server: registered %s:%d paths=[%s] "
                      "free_mb=%uD util_pct=%uD",
                      ctx->host, (int) ctx->port, ctx->paths,
                      ctx->free_mb, ctx->util_pct);
        break;

    case CMS_RR_LOAD:
        if (!ctx->logged_in) { break; }
        free_mb = cms_srv_parse_load_free_mb(payload, payload_len);
        xrootd_srv_update_load(ctx->host, ctx->port, free_mb, ctx->util_pct);
        ctx->free_mb = free_mb;
        break;

    case CMS_RR_AVAIL:
    case CMS_RR_SPACE:
        if (!ctx->logged_in) { break; }
        cms_srv_parse_avail(payload, payload_len, &free_mb, &util_pct);
        xrootd_srv_update_load(ctx->host, ctx->port, free_mb, util_pct);
        ctx->free_mb  = free_mb;
        ctx->util_pct = util_pct;
        break;

    case CMS_RR_PONG:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                       "xrootd: CMS server: pong from %s", ctx->host);
        break;

    case CMS_RR_GONE:
        if (!ctx->logged_in) { break; }
        if (payload_len > 0) {
            /*
             * A data server signals that it no longer holds a specific path.
             * Remove that path token from its registry entry without touching
             * the rest of the registration (the server still holds other paths).
             */
            char   path[XROOTD_SRV_MAX_PATHS];
            size_t copy = payload_len < sizeof(path) - 1
                          ? payload_len : sizeof(path) - 1;
            ngx_memcpy(path, payload, copy);
            path[copy] = '\0';
            xrootd_srv_unregister_path(ctx->host, ctx->port, path);
            ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                           "xrootd: CMS server: kYR_gone path=%s from %s:%d",
                           path, ctx->host, (int) ctx->port);
        }
        break;

    default:
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->c->log, 0,
                       "xrootd: CMS server: unknown rrCode=%ui from %s",
                       (ngx_uint_t) code, ctx->host);
        break;
    }
}

/* --- Read handler --------------------------------------------------------- */

/* ---- xrootd_cms_srv_write — CMS server write event handler (sync-only) ----
 * WHAT: Write handler for incoming CMS data-server connections. Since all writes are synchronous via send_ping(), this handler only processes timeout events and closes the connection if timed out. WHY: The ping timer fires and calls send_ping() synchronously; no async write buffering needed — write handler is essentially a timeout guard. HOW: On timeout → close connection via xrootd_cms_srv_close(). */

void
xrootd_cms_srv_write(ngx_event_t *ev)
{
    /* We send synchronously via send_ping; nothing to flush here. */
    ngx_connection_t      *c   = ev->data;
    xrootd_cms_srv_ctx_t  *ctx = c->data;

    if (ev->timedout) {
        xrootd_cms_srv_close(ctx);
    }
}

/* ---- xrootd_cms_srv_read — CMS server-side frame read loop and dispatch ----
 * WHAT: Event handler for reading incoming frames from connected CMS data-server clients. Accumulates bytes until header complete, then reads payload based on dlen. Dispatches each opcode (LOGIN→register, LOAD/AVAIL→update load, PONG→debug log, GONE→unregister path) via cms_srv_process_frame(). WHY: Server-side counterpart to recv.c — accepts incoming connections from data servers and manages their registration lifecycle with the CMS manager. HOW: 1) Loop recv() until in_pos >= in_need → 2) If header size → extend to full frame → 3) On complete frame → decode code at offset 4 → 4) Call cms_srv_process_frame(). Disconnect on timeout, error, or frame too large (>NGX_XROOTD_CMS_MAX_FRAME). */

void
xrootd_cms_srv_read(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    xrootd_cms_srv_ctx_t  *ctx;
    ssize_t                n;
    uint16_t               dlen;
    u_char                 code;

    c   = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        xrootd_cms_srv_close(ctx);
        return;
    }

    for ( ;; ) {
        n = c->recv(c, ctx->inbuf + ctx->in_pos,
                    ctx->in_need - ctx->in_pos);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            xrootd_cms_srv_close(ctx);
            return;
        }

        ctx->in_pos += (size_t) n;

        if (ctx->in_pos < ctx->in_need) {
            continue;
        }

        /* Completed reading the header — extend to full frame if needed. */
        if (ctx->in_need == NGX_XROOTD_CMS_HDR_LEN) {
            dlen = ngx_xrootd_cms_get16(ctx->inbuf + 6);

            if ((size_t) dlen + NGX_XROOTD_CMS_HDR_LEN
                > NGX_XROOTD_CMS_MAX_FRAME)
            {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: CMS server: frame too large (%ui) "
                              "from %s", (ngx_uint_t) dlen, ctx->host);
                xrootd_cms_srv_close(ctx);
                return;
            }

            ctx->in_need = NGX_XROOTD_CMS_HDR_LEN + dlen;
            if (ctx->in_pos < ctx->in_need) {
                continue;
            }
        }

        /* Full frame received — dispatch. */
        code = ctx->inbuf[4];
        dlen = ngx_xrootd_cms_get16(ctx->inbuf + 6);
        cms_srv_process_frame(ctx, code,
                              ctx->inbuf + NGX_XROOTD_CMS_HDR_LEN, dlen);

        /* ctx->c may be NULL if the frame handler closed the connection. */
        if (ctx->c == NULL) {
            return;
        }

        ctx->in_pos  = 0;
        ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        xrootd_cms_srv_close(ctx);
    }
}
