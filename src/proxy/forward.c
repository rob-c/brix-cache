/*
 * forward.c — request forwarding, file-handle translation, response relay.
 */

#include "proxy_internal.h"
#include "../session/registry.h"

/* ---- audit log helper ------------------------------------------------------ */

void
proxy_write_audit(xrootd_proxy_ctx_t *proxy, int local_fh)
{
    ngx_stream_xrootd_srv_conf_t *conf = proxy->conf;
    xrootd_proxy_fh_entry_t      *entry;
    u_char                        buf[1024];
    u_char                       *p;
    ngx_msec_int_t                duration_ms;

    if (conf == NULL || conf->proxy_audit_log_fd == NGX_INVALID_FILE) {
        return;
    }
    if (local_fh < 0 || local_fh >= XROOTD_MAX_FILES) {
        return;
    }
    entry = &proxy->fh_map[local_fh];

    duration_ms = (ngx_msec_int_t)(ngx_current_msec - entry->open_msec);

    p = ngx_snprintf(buf, sizeof(buf) - 2,
        "{\"path\":\"%s\","
        "\"bytes_read\":%uL,"
        "\"bytes_written\":%uL,"
        "\"duration_ms\":%M}\n",
        entry->path,
        (uint64_t) entry->bytes_read,
        (uint64_t) entry->bytes_written,
        duration_ms);

    ngx_write_fd(conf->proxy_audit_log_fd, buf, (size_t)(p - buf));
}

/* ---- path-op audit (rm, mkdir, rmdir, mv, chmod, truncate) --------------- */

static void
proxy_write_path_audit(xrootd_proxy_ctx_t *proxy, uint16_t status)
{
    ngx_stream_xrootd_srv_conf_t *conf = proxy->conf;
    const char  *op_str;
    const char  *status_str = (status == kXR_ok) ? "ok" : "error";
    const char  *user = "";
    u_char       buf[256 + XROOTD_PROXY_PATH_MAX * 2];
    u_char      *p;

    if (conf == NULL || conf->proxy_audit_log_fd == NGX_INVALID_FILE) {
        return;
    }

    switch (proxy->fwd_reqid) {
    case kXR_rm:       op_str = "rm";       break;
    case kXR_mkdir:    op_str = "mkdir";    break;
    case kXR_rmdir:    op_str = "rmdir";    break;
    case kXR_mv:       op_str = "mv";       break;
    case kXR_chmod:    op_str = "chmod";    break;
    case kXR_truncate: op_str = "truncate"; break;
    default: return;
    }

    if (proxy->client_ctx != NULL && proxy->client_ctx->login_user[0] != '\0') {
        user = proxy->client_ctx->login_user;
    }

    if (proxy->fwd_reqid == kXR_mv && proxy->fwd_path2[0] != '\0') {
        p = ngx_snprintf(buf, sizeof(buf) - 2,
            "{\"type\":\"path\",\"op\":\"%s\","
            "\"path\":\"%s\",\"dest\":\"%s\","
            "\"status\":\"%s\",\"user\":\"%s\"}\n",
            op_str, proxy->fwd_path, proxy->fwd_path2,
            status_str, user);
    } else {
        p = ngx_snprintf(buf, sizeof(buf) - 2,
            "{\"type\":\"path\",\"op\":\"%s\","
            "\"path\":\"%s\","
            "\"status\":\"%s\",\"user\":\"%s\"}\n",
            op_str, proxy->fwd_path, status_str, user);
    }

    ngx_write_fd(conf->proxy_audit_log_fd, buf, (size_t)(p - buf));
}

/* ---- kXR_wait timer callback: re-issue saved kXR_open -------------------- */

void
xrootd_proxy_wait_handler(ngx_event_t *ev)
{
    xrootd_proxy_ctx_t *proxy = ev->data;
    xrootd_ctx_t       *ctx;
    u_char             *req;
    size_t              len;
    ngx_int_t           rc;

    if (proxy == NULL) {
        return;
    }
    ctx = proxy->client_ctx;
    if (ctx == NULL || ctx->destroyed) {
        xrootd_proxy_cleanup(proxy);
        return;
    }

    req = proxy->wait_retry_req;
    len = proxy->wait_retry_req_len;
    if (req == NULL || proxy->conn == NULL) {
        return;
    }

    proxy->wait_retry_req     = NULL;
    proxy->wait_retry_req_len = 0;

    /* Re-issue the kXR_open */
    proxy->fwd_reqid       = kXR_open;
    proxy->fwd_streamid[0] = req[0];
    proxy->fwd_streamid[1] = req[1];
    proxy->fwd_local_fh    = proxy->wait_retry_local_fh;
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = len > XRD_REQUEST_HDR_LEN
                             ? len - XRD_REQUEST_HDR_LEN : 0;

    proxy->wbuf     = req;
    proxy->wbuf_len = len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    rc = xrootd_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        ngx_free(req);
        proxy->wbuf = NULL;
        xrootd_proxy_abort(proxy, "proxy: wait retry open send failed");
        return;
    }
    if (proxy->wbuf_pos == proxy->wbuf_len) {
        ngx_free(req);
        proxy->wbuf = NULL;
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy, "proxy: read arm failed after wait retry");
        }
    }
    /* else: write handler will complete the send */
}

/* ---- file handle allocation ---------------------------------------------- */

int
xrootd_proxy_alloc_local_fh(xrootd_proxy_ctx_t *proxy)
{
    int i;

    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (proxy->fh_map[i].upstream_fh == XROOTD_PROXY_FH_FREE) {
            return i;
        }
    }
    return -1;
}

/* ---- lazy open for bound secondary connections --------------------------- */

/*
 * xrootd_proxy_lazy_open — issue a synthetic kXR_open on the upstream for a
 * handle that was opened by the primary session.
 *
 * Used when a bound secondary connection (ctx->is_bound) sends kXR_read for a
 * handle that has no upstream mapping yet in this connection's fh_map.  The
 * function looks up the canonical path from the shared session handle registry
 * (where the primary published it), builds an anonymous kXR_open, and queues it.
 * read_req (the original kXR_read) is saved as proxy->saved_req; it will be
 * dispatched by relay_to_client once the open response arrives.
 *
 * Ownership of read_req transfers to this function on NGX_OK; caller must not
 * free it.  On error the function frees read_req itself.
 */
static ngx_int_t
xrootd_proxy_lazy_open(xrootd_proxy_ctx_t *proxy,
    xrootd_ctx_t *ctx, ngx_connection_t *c,
    int local_fh, u_char *read_req, size_t read_req_len)
{
    xrootd_shared_handle_entry_t  he;
    size_t                         pathlen, frame_len;
    u_char                        *frame;
    ClientOpenRequest             *oreq;
    ngx_int_t                      rc;

    if (!xrootd_session_handle_lookup(ctx->bound_sessid, local_fh, &he)) {
        ngx_free(read_req);
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "proxy: bound handle not published by primary");
    }

    pathlen   = ngx_strlen(he.path);
    frame_len = sizeof(ClientOpenRequest) + pathlen;

    frame = ngx_alloc(frame_len, c->log);
    if (frame == NULL) {
        ngx_free(read_req);
        return xrootd_send_error(ctx, c, kXR_IOError,
                                 "proxy: OOM for lazy open");
    }

    oreq = (ClientOpenRequest *)(void *) frame;
    ngx_memzero(oreq, sizeof(*oreq));
    oreq->streamid[0] = 0;
    oreq->streamid[1] = 0xfe;          /* synthetic — not echoed to client */
    oreq->requestid   = htons(kXR_open);
    oreq->options     = htons(kXR_open_read);
    oreq->dlen        = htonl((kXR_int32) pathlen);
    ngx_memcpy(frame + sizeof(*oreq), he.path, pathlen);

    /* Mark the slot pending while we wait for the open response */
    proxy->fh_map[local_fh].upstream_fh = 255;

    /* Save the kXR_read so relay_to_client can dispatch it after open */
    proxy->saved_req        = read_req;
    proxy->saved_req_len    = read_req_len;
    proxy->saved_local_fh   = local_fh;

    proxy->fwd_is_lazy_open = 1;
    proxy->fwd_local_fh     = local_fh;
    proxy->fwd_reqid        = kXR_open;
    proxy->fwd_streaming    = 0;
    proxy->fwd_payload_len  = 0;

    proxy->wbuf     = frame;
    proxy->wbuf_len = frame_len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    ctx->state = XRD_ST_PROXY;

    rc = xrootd_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        ngx_free(frame);
        proxy->wbuf = NULL;
        xrootd_proxy_abort(proxy, "proxy: lazy open send failed");
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos == proxy->wbuf_len) {
        ngx_free(frame);
        proxy->wbuf = NULL;
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy, "proxy: read arm failed after lazy open");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* ---- path prefix rewriting ----------------------------------------------- */

/*
 * proxy_rewrite_path — apply xrootd_proxy_path_rewrite to a path payload.
 *
 * Returns a pointer to the (possibly reallocated) buffer containing the full
 * request with the rewritten path.  When the path starts with strip_prefix,
 * the strip prefix is removed and add_prefix is prepended; if the result is
 * the same length, the rewrite is done in-place.  When the result is longer,
 * a new buffer is allocated (caller must free on success; original is freed
 * if non-NULL and different).
 *
 * On OOM or a path that does not match the strip prefix, *req is returned
 * unchanged and *total_out reflects the original length.
 *
 * path_off is the byte offset of the path within *req.
 * path_len is the current path length in bytes (not NUL-terminated).
 */
static u_char *
proxy_rewrite_path(ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf,
                   u_char *req, size_t total,
                   size_t path_off, size_t path_len,
                   size_t *total_out)
{
    const u_char *strip = conf->proxy_path_strip.data;
    size_t        slen  = conf->proxy_path_strip.len;
    const u_char *add   = conf->proxy_path_add.data;
    size_t        alen  = conf->proxy_path_add.len;
    size_t        new_path_len, new_total;
    u_char       *new_req;

    if (slen == 0 || path_len < slen
        || ngx_strncmp(req + path_off, strip, slen) != 0)
    {
        *total_out = total;
        return req; /* no match — pass through unchanged */
    }

    new_path_len = alen + (path_len - slen);
    new_total    = total - path_len + new_path_len;

    if (new_path_len == path_len) {
        /* Same length: rewrite in-place */
        ngx_memcpy(req + path_off, add, alen);
        *total_out = total;
        return req;
    }

    new_req = ngx_alloc(new_total, c->log);
    if (new_req == NULL) {
        *total_out = total;
        return req; /* OOM: pass original unchanged */
    }

    /* Copy header portion before path, then new path, then anything after */
    ngx_memcpy(new_req, req, path_off);
    ngx_memcpy(new_req + path_off, add, alen);
    ngx_memcpy(new_req + path_off + alen,
               req + path_off + slen,
               total - path_off - slen);

    /* Update the 4-byte dlen field in the request header (bytes 20-23) */
    {
        uint32_t new_dlen = htonl((uint32_t) (new_total - XRD_REQUEST_HDR_LEN));
        ngx_memcpy(new_req + 20, &new_dlen, 4);
    }

    *total_out = new_total;
    return new_req;
}

/*
 * proxy_rewrite_prepare_payload — apply path rewriting to a kXR_prepare payload.
 * The payload is a newline-separated list of paths.
 */
static u_char *
proxy_rewrite_prepare_payload(ngx_connection_t *c,
                              ngx_stream_xrootd_srv_conf_t *conf,
                              u_char *req, size_t total,
                              size_t *total_out)
{
    const u_char *strip = conf->proxy_path_strip.data;
    size_t        slen  = conf->proxy_path_strip.len;
    const u_char *add   = conf->proxy_path_add.data;
    size_t        alen  = conf->proxy_path_add.len;
    u_char       *payload, *p, *line_start, *new_req, *dst;
    size_t        plen, new_total, line_len;
    ngx_uint_t    needs_rewrite = 0;

    if (slen == 0 || total <= XRD_REQUEST_HDR_LEN) {
        *total_out = total;
        return req;
    }

    payload = req + XRD_REQUEST_HDR_LEN;
    plen    = total - XRD_REQUEST_HDR_LEN;

    /* First pass: calculate new total length and check if we need to do anything */
    new_total = XRD_REQUEST_HDR_LEN;
    p = payload;
    line_start = payload;
    while (p < payload + plen) {
        if (*p == '\n' || p == payload + plen - 1) {
            line_len = (p == payload + plen - 1 && *p != '\n')
                       ? (size_t)(p - line_start + 1)
                       : (size_t)(p - line_start);

            if (line_len >= slen && ngx_strncmp(line_start, strip, slen) == 0) {
                new_total += alen + (line_len - slen);
                needs_rewrite = 1;
            } else {
                new_total += line_len;
            }
            if (*p == '\n') {
                new_total++;
            }
            line_start = p + 1;
        }
        p++;
    }

    if (!needs_rewrite) {
        *total_out = total;
        return req;
    }

    new_req = ngx_alloc(new_total, c->log);
    if (new_req == NULL) {
        *total_out = total;
        return req;
    }

    ngx_memcpy(new_req, req, XRD_REQUEST_HDR_LEN);
    dst = new_req + XRD_REQUEST_HDR_LEN;
    p = payload;
    line_start = payload;

    while (p < payload + plen) {
        if (*p == '\n' || p == payload + plen - 1) {
            line_len = (p == payload + plen - 1 && *p != '\n')
                       ? (size_t)(p - line_start + 1)
                       : (size_t)(p - line_start);

            if (line_len >= slen && ngx_strncmp(line_start, strip, slen) == 0) {
                ngx_memcpy(dst, add, alen);
                dst += alen;
                ngx_memcpy(dst, line_start + slen, line_len - slen);
                dst += (line_len - slen);
            } else {
                ngx_memcpy(dst, line_start, line_len);
                dst += line_len;
            }
            if (*p == '\n') {
                *dst++ = '\n';
            }
            line_start = p + 1;
        }
        p++;
    }

    /* Update dlen in header */
    {
        uint32_t dlen_be = htonl((uint32_t)(new_total - XRD_REQUEST_HDR_LEN));
        ngx_memcpy(new_req + 20, &dlen_be, 4);
    }

    ngx_free(req);
    *total_out = new_total;
    return new_req;
}

/* ---- fhandle translation helpers ----------------------------------------- */

/*
 * Translate a 1-byte local file handle in buf[offset] to the upstream handle.
 * Returns 0 on success, -1 if the local handle is invalid.
 */
static int
proxy_translate_fh(xrootd_proxy_ctx_t *proxy, u_char *buf, size_t offset)
{
    int local_fh = (int)(unsigned char) buf[offset];

    if (local_fh < 0 || local_fh >= XROOTD_MAX_FILES
        || proxy->fh_map[local_fh].upstream_fh == XROOTD_PROXY_FH_FREE)
    {
        return -1;
    }
    buf[offset] = (u_char)(unsigned int) proxy->fh_map[local_fh].upstream_fh;
    return 0;
}

/* ---- build and send the forwarded request --------------------------------- */

ngx_int_t
xrootd_proxy_forward_request(xrootd_proxy_ctx_t *proxy,
                              xrootd_ctx_t       *ctx,
                              ngx_connection_t   *c)
{
    uint16_t  reqid = ctx->cur_reqid;
    size_t    total = XRD_REQUEST_HDR_LEN + ctx->cur_dlen;
    u_char   *req;

    /* Allocate forwarded request buffer — freed by cleanup or after send */
    req = ngx_alloc(total, c->log);
    if (req == NULL) {
        return xrootd_send_error(ctx, c, kXR_IOError,
                                 "proxy: out of memory building request");
    }

    /* Copy full request header then payload */
    ngx_memcpy(req, ctx->hdr_buf, XRD_REQUEST_HDR_LEN);
    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        ngx_memcpy(req + XRD_REQUEST_HDR_LEN, ctx->payload, ctx->cur_dlen);
    }

    /* Pre-set forwarding metadata */
    proxy->fwd_reqid       = reqid;
    proxy->fwd_streamid[0] = ctx->cur_streamid[0];
    proxy->fwd_streamid[1] = ctx->cur_streamid[1];
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = ctx->cur_dlen;

    /* ---- file handle translation ---- */

    switch (reqid) {

    case kXR_open: {
        /* Pre-allocate a local file handle for when the response arrives */
        int local_fh = xrootd_proxy_alloc_local_fh(proxy);
        if (local_fh < 0) {
            ngx_free(req);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: no free file handles");
        }
        /* Mark slot as pending (non-free but no upstream handle yet) */
        proxy->fh_map[local_fh].upstream_fh = 255; /* sentinel: awaiting open response */
        proxy->fwd_local_fh = local_fh;

        /* Apply path rewriting before capturing path for audit */
        if (proxy->conf != NULL && proxy->conf->proxy_path_strip.len > 0
            && ctx->cur_dlen > 0)
        {
            req = proxy_rewrite_path(c, proxy->conf, req, total,
                                     XRD_REQUEST_HDR_LEN, ctx->cur_dlen,
                                     &total);
            /* Recalculate cur_dlen for audit capture below */
        }

        /* Capture path from payload for audit log */
        if (proxy->conf != NULL
            && proxy->conf->proxy_audit_log_fd != NGX_INVALID_FILE)
        {
            const u_char *path_start = req + XRD_REQUEST_HDR_LEN;
            size_t        path_len   = total > XRD_REQUEST_HDR_LEN
                                       ? total - XRD_REQUEST_HDR_LEN : 0;
            size_t        plen       = path_len < XROOTD_PROXY_PATH_MAX - 1
                                       ? path_len : XROOTD_PROXY_PATH_MAX - 1;
            ngx_memcpy(proxy->fh_map[local_fh].path, path_start, plen);
            proxy->fh_map[local_fh].path[plen] = '\0';
        }
        break;
    }

    case kXR_read:
    case kXR_pgread:
    case kXR_write:
    case kXR_pgwrite:
    case kXR_close:
    case kXR_sync:
    case kXR_chkpoint: {
        /* fhandle is at body[0] in the 24-byte request header */
        int local_fh = (int)(unsigned char) req[4]; /* save before translation */

        /* Bound secondary: lazy-open the file on first read for this handle */
        if (ctx->is_bound
            && (reqid == kXR_read || reqid == kXR_pgread)
            && local_fh >= 0 && local_fh < XROOTD_MAX_FILES
            && proxy->fh_map[local_fh].upstream_fh == XROOTD_PROXY_FH_FREE)
        {
            /* req ownership transfers to xrootd_proxy_lazy_open */
            return xrootd_proxy_lazy_open(proxy, ctx, c, local_fh, req, total);
        }

        if (proxy_translate_fh(proxy, req + 4, 0) != 0) {
            ngx_free(req);
            return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                     "proxy: invalid file handle");
        }
        proxy->fwd_local_fh = local_fh;
        break;
    }

    case kXR_stat:
    case kXR_truncate:
    case kXR_fattr:
        /* fhandle at body[0]; only translate if nonzero (path-based if 0) */
        if (req[4] != 0) {
            if (proxy_translate_fh(proxy, req + 4, 0) != 0) {
                ngx_free(req);
                return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                         "proxy: invalid file handle");
            }
        } else if (reqid == kXR_truncate
                   && proxy->conf != NULL
                   && proxy->conf->proxy_audit_log_fd != NGX_INVALID_FILE
                   && ctx->cur_dlen > 0)
        {
            size_t plen = ctx->cur_dlen < XROOTD_PROXY_PATH_MAX
                          ? ctx->cur_dlen : XROOTD_PROXY_PATH_MAX - 1;
            ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, plen);
            proxy->fwd_path[plen]  = '\0';
            proxy->fwd_path2[0]    = '\0';
            proxy->fwd_path_audit  = 1;
        }
        proxy->fwd_local_fh = -1;
        break;

    case kXR_readv: {
        /*
         * Payload is an array of readahead_list: { fhandle[4], rlen[4], offset[8] }
         * Translate fhandle[0] in each entry.
         *
         * Bound secondary: collect ALL unique unresolved fhandles across all
         * segments and open them sequentially before dispatching.  xrdcp parallel
         * streams may reference several handles in a single readv.
         */
        u_char *payload = req + XRD_REQUEST_HDR_LEN;

        if (ctx->is_bound && ctx->cur_dlen >= 4) {
            /* First pass: collect unique unresolved fhs */
            int   pending[XROOTD_MAX_FILES];
            int   n_pending = 0;
            size_t pos;
            int   seen[XROOTD_MAX_FILES];
            int   i;

            for (i = 0; i < XROOTD_MAX_FILES; i++) { seen[i] = 0; }

            pos = 0;
            while (pos + 16 <= ctx->cur_dlen) {
                int fh = (int)(unsigned char) payload[pos];
                if (fh >= 0 && fh < XROOTD_MAX_FILES
                    && proxy->fh_map[fh].upstream_fh == XROOTD_PROXY_FH_FREE
                    && !seen[fh])
                {
                    seen[fh] = 1;
                    pending[n_pending++] = fh;
                }
                pos += 16;
            }

            if (n_pending > 0) {
                /* Store the queue; lazy_open will consume entries one by one */
                int first_fh = pending[0];
                for (i = 1; i < n_pending; i++) {
                    proxy->lazy_open_pending_fhs[i - 1] = pending[i];
                }
                proxy->lazy_open_pending_count = n_pending - 1;
                return xrootd_proxy_lazy_open(proxy, ctx, c, first_fh, req, total);
            }
        }

        {
            size_t pos = 0;
            while (pos + 16 <= ctx->cur_dlen) {
                if (proxy_translate_fh(proxy, payload + pos, 0) != 0) {
                    ngx_free(req);
                    return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                             "proxy: invalid fhandle in readv");
                }
                pos += 16;
            }
        }
        proxy->fwd_local_fh = -1;
        break;
    }

    case kXR_writev: {
        /* Payload: write_list { fhandle[4], wlen[4], offset[8] } */
        u_char *payload = req + XRD_REQUEST_HDR_LEN;
        size_t  pos     = 0;
        while (pos + 16 <= ctx->cur_dlen) {
            if (proxy_translate_fh(proxy, payload + pos, 0) != 0) {
                ngx_free(req);
                return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                         "proxy: invalid fhandle in writev");
            }
            pos += 16;
        }
        proxy->fwd_local_fh = -1;
        break;
    }

    case kXR_clone: {
        /* src_fhandle at body[0], dst_fhandle at body[4] */
        if (proxy_translate_fh(proxy, req + 4, 0) != 0
            || proxy_translate_fh(proxy, req + 4, 4) != 0)
        {
            ngx_free(req);
            return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                     "proxy: invalid fhandle in clone");
        }
        proxy->fwd_local_fh = -1;
        break;
    }

    case kXR_prepare:
        proxy->fwd_local_fh   = -1;
        proxy->fwd_path_audit = 0;
        if (proxy->conf != NULL && proxy->conf->proxy_path_strip.len > 0
            && ctx->cur_dlen > 0)
        {
            req = proxy_rewrite_prepare_payload(c, proxy->conf, req, total, &total);
        }
        break;

    default: {
        /* Path-based ops: rewrite the path payload if configured */
        proxy->fwd_local_fh   = -1;
        proxy->fwd_path_audit = 0;
        if (proxy->conf != NULL && proxy->conf->proxy_path_strip.len > 0
            && ctx->cur_dlen > 0)
        {
            req = proxy_rewrite_path(c, proxy->conf, req, total,
                                     XRD_REQUEST_HDR_LEN, ctx->cur_dlen,
                                     &total);
        }
        /* Capture path/dest for mutation-op audit log */
        if (proxy->conf != NULL
            && proxy->conf->proxy_audit_log_fd != NGX_INVALID_FILE
            && ctx->cur_dlen > 0)
        {
            switch (reqid) {
            case kXR_rm:
            case kXR_rmdir:
            case kXR_mkdir:
            case kXR_chmod: {
                size_t plen = (total - XRD_REQUEST_HDR_LEN) < XROOTD_PROXY_PATH_MAX
                              ? total - XRD_REQUEST_HDR_LEN
                              : XROOTD_PROXY_PATH_MAX - 1;
                ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, plen);
                proxy->fwd_path[plen] = '\0';
                proxy->fwd_path2[0]   = '\0';
                proxy->fwd_path_audit = 1;
                break;
            }
            case kXR_mv: {
                /* payload: src[arg1len] + ' ' + dst */
                uint16_t arg1len_be;
                size_t   src_len, dst_off, dst_len;
                ngx_memcpy(&arg1len_be, req + 18, 2);
                src_len = (size_t) ntohs(arg1len_be);
                if (src_len >= XROOTD_PROXY_PATH_MAX) {
                    src_len = XROOTD_PROXY_PATH_MAX - 1;
                }
                ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, src_len);
                proxy->fwd_path[src_len] = '\0';
                dst_off = XRD_REQUEST_HDR_LEN + src_len + 1; /* skip space */
                if (dst_off < total) {
                    dst_len = total - dst_off;
                    if (dst_len >= XROOTD_PROXY_PATH_MAX) {
                        dst_len = XROOTD_PROXY_PATH_MAX - 1;
                    }
                    ngx_memcpy(proxy->fwd_path2, req + dst_off, dst_len);
                    proxy->fwd_path2[dst_len] = '\0';
                } else {
                    proxy->fwd_path2[0] = '\0';
                }
                proxy->fwd_path_audit = 1;
                break;
            }
            default:
                break;
            }
        }
        break;
    }
    }

    /* fwd_payload_len may have changed if path was rewritten (total updated) */
    proxy->fwd_payload_len = total > XRD_REQUEST_HDR_LEN
                             ? total - XRD_REQUEST_HDR_LEN : 0;

    /* Save a copy for transparent kXR_wait retry (if payload is not huge) */
    if (total < 128 * 1024) {
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
        }
        proxy->wait_retry_req = ngx_alloc(total, c->log);
        if (proxy->wait_retry_req != NULL) {
            ngx_memcpy(proxy->wait_retry_req, req, total);
            proxy->wait_retry_req_len  = total;
        } else {
            proxy->wait_retry_req_len  = 0;
        }
        proxy->wait_retry_local_fh = proxy->fwd_local_fh;
        proxy->wait_retry_count    = 0;
    }

    /* Queue the request to the upstream write buffer */
    proxy->wbuf     = req;
    proxy->wbuf_len = total;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    /* Reset response accumulator */
    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    /* Suspend client read loop while we wait for the upstream response */
    ctx->state = XRD_ST_PROXY;

    ngx_int_t rc = xrootd_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        ngx_free(req);
        proxy->wbuf = NULL;
        xrootd_proxy_abort(proxy, "proxy: upstream write error");
        return NGX_ERROR;
    }

    if (proxy->wbuf_pos == proxy->wbuf_len) {
        /* Fully sent immediately — free the request buffer and arm upstream read */
        ngx_free(req);
        proxy->wbuf = NULL;
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy, "proxy: read arm failed");
            return NGX_ERROR;
        }
    }
    /* else: write handler will complete the send and arm the read */

    return NGX_OK;
}

/* ---- relay upstream response to client ------------------------------------ */

void
xrootd_proxy_relay_to_client(xrootd_proxy_ctx_t *proxy)
{
    xrootd_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    uint16_t          status = proxy->resp_status;
    uint32_t          dlen   = proxy->resp_dlen;
    u_char           *body   = proxy->resp_body;
    size_t            total;
    u_char           *buf;

    /* ---- lazy open (bound secondary): handle synthetic kXR_open response ---- */
    if (proxy->fwd_is_lazy_open) {
        int local_fh = proxy->fwd_local_fh;

        proxy->fwd_is_lazy_open = 0;

        if (status == kXR_ok) {
            /* Extract upstream fhandle from open response body[0] */
            int upstream_fh = (body != NULL && dlen >= 1)
                              ? (int)(unsigned char) body[0] : 0;
            if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
                proxy->fh_map[local_fh].upstream_fh = upstream_fh;
                proxy->fh_map[local_fh].open_msec   = ngx_current_msec;
            }
        } else {
            /* Open failed — report error to client and drop saved read */
            if (proxy->saved_req != NULL) {
                ngx_free(proxy->saved_req);
                proxy->saved_req = NULL;
            }
            if (proxy->resp_body != NULL) {
                ngx_free(proxy->resp_body);
                proxy->resp_body = NULL;
            }
            if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
                proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
            }
            proxy->state = XRD_PX_IDLE;
            ctx->state   = XRD_ST_REQ_HEADER;
            xrootd_send_error(ctx, c, kXR_IOError,
                              "proxy: lazy open for bound secondary failed");
            xrootd_schedule_read_resume(c);
            return;
        }

        /* Discard the open response body; don't relay it to the client */
        if (proxy->resp_body != NULL) {
            ngx_free(proxy->resp_body);
            proxy->resp_body = NULL;
        }

        /* If more fhs still need lazy-open (multi-handle readv), do next one */
        if (proxy->lazy_open_pending_count > 0) {
            int next_fh;

            proxy->lazy_open_pending_count--;
            next_fh = proxy->lazy_open_pending_fhs[proxy->lazy_open_pending_count];

            /* saved_req and saved_req_len are still set from the first lazy_open call */
            {
                u_char *rreq = proxy->saved_req;
                size_t  rlen = proxy->saved_req_len;

                /* Pass ownership to lazy_open */
                proxy->saved_req = NULL;
                if (xrootd_proxy_lazy_open(proxy, ctx, c, next_fh, rreq, rlen)
                    != NGX_OK)
                {
                    /* Error already handled / reported */
                }
            }
            return;
        }

        /* Dispatch the saved kXR_read / kXR_pgread / kXR_readv */
        if (proxy->saved_req != NULL) {
            u_char   *rreq     = proxy->saved_req;
            size_t    rlen     = proxy->saved_req_len;
            int       lfh      = proxy->saved_local_fh;
            uint16_t  saved_rid;

            /* Translate the client-side fhandle(s) to upstream handles */
            saved_rid = ntohs(((ClientRequestHdr *)(void *) rreq)->requestid);
            if (saved_rid == kXR_read || saved_rid == kXR_pgread) {
                int ufh = (lfh >= 0 && lfh < XROOTD_MAX_FILES)
                          ? proxy->fh_map[lfh].upstream_fh : -1;
                if (ufh >= 0) rreq[4] = (u_char)(unsigned int) ufh;
            } else if (saved_rid == kXR_readv) {
                /* Translate every segment's fhandle using the full fh_map */
                u_char *pl    = rreq + XRD_REQUEST_HDR_LEN;
                size_t  pos   = 0;
                size_t  pdlen = rlen > XRD_REQUEST_HDR_LEN
                                ? rlen - XRD_REQUEST_HDR_LEN : 0;
                while (pos + 16 <= pdlen) {
                    int cfh = (int)(unsigned char) pl[pos];
                    if (cfh >= 0 && cfh < XROOTD_MAX_FILES
                        && proxy->fh_map[cfh].upstream_fh >= 0)
                    {
                        pl[pos] = (u_char)(unsigned int) proxy->fh_map[cfh].upstream_fh;
                    }
                    pos += 16;
                }
                lfh = -1; /* readv fwd_local_fh stays -1 */
            }

            {
                ClientRequestHdr *hdr = (ClientRequestHdr *)(void *) rreq;
                proxy->fwd_reqid       = ntohs(hdr->requestid);
                proxy->fwd_streamid[0] = hdr->streamid[0];
                proxy->fwd_streamid[1] = hdr->streamid[1];
            }
            proxy->fwd_local_fh    = lfh;
            proxy->fwd_streaming   = 0;
            proxy->fwd_payload_len = rlen > XRD_REQUEST_HDR_LEN
                                     ? rlen - XRD_REQUEST_HDR_LEN : 0;
            proxy->saved_req       = NULL;

            /* ---- kXR_waitresp / kXR_attn: transparent async response support ---- */
            /*
             * Note: We don't need a specific opcode case here.  By default we forward
             * everything and await a response.  If we get kXR_waitresp (async ack),
             * we will transition back to IDLE in relay_to_client but stay ready to
             * receive unsolicited kXR_attn frames in events.c.
             */

            /* Save a copy for transparent kXR_wait retry (if payload is not huge) */
            if (rlen < 128 * 1024) {
                if (proxy->wait_retry_req != NULL) {
                    ngx_free(proxy->wait_retry_req);
                }
                proxy->wait_retry_req = ngx_alloc(rlen, c->log);
                if (proxy->wait_retry_req != NULL) {
                    ngx_memcpy(proxy->wait_retry_req, rreq, rlen);
                    proxy->wait_retry_req_len  = rlen;
                } else {
                    proxy->wait_retry_req_len  = 0;
                }
                proxy->wait_retry_local_fh = proxy->fwd_local_fh;
                proxy->wait_retry_count    = 0;
            }

            proxy->wbuf     = rreq;

            proxy->wbuf_len = rlen;
            proxy->wbuf_pos = 0;
            proxy->state    = XRD_PX_FORWARDING;

            proxy->rhdr_pos      = 0;
            proxy->resp_dlen     = 0;
            proxy->resp_body     = NULL;
            proxy->resp_body_pos = 0;

            if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
                xrootd_proxy_abort(proxy,
                    "proxy: send deferred read after lazy open failed");
                return;
            }
            if (proxy->wbuf_pos < proxy->wbuf_len) {
                return; /* write handler completes the send */
            }
            if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
                xrootd_proxy_abort(proxy,
                    "proxy: read arm failed after lazy open read");
            }
        } else {
            proxy->state = XRD_PX_IDLE;
            ctx->state   = XRD_ST_REQ_HEADER;
            xrootd_schedule_read_resume(c);
        }
        return;
    }

    /* ---- kXR_wait: absorb upstream "busy, try later" ---- */
    if (status == kXR_wait
        && proxy->wait_retry_req != NULL
        && proxy->wait_retry_count < XROOTD_PROXY_MAX_WAIT_RETRIES)
    {
        uint32_t wait_be = 0;
        uint32_t wait_secs;

        if (body != NULL && dlen >= 4) {
            ngx_memcpy(&wait_be, body, 4);
        }
        wait_secs = ntohl(wait_be);
        if (wait_secs < 1)                         { wait_secs = 1; }
        if (wait_secs > XROOTD_PROXY_MAX_WAIT_SECS) { wait_secs = XROOTD_PROXY_MAX_WAIT_SECS; }

        proxy->wait_retry_count++;
        XROOTD_PROXY_METRIC_INC(ctx, wait_responses_total);
        XROOTD_PROXY_UP_INC(proxy, wait_responses_total);

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd proxy: kXR_wait for reqid=%d, retry %d in %us",
                       (int) proxy->fwd_reqid, proxy->wait_retry_count, wait_secs);

        if (proxy->resp_body != NULL) {
            ngx_free(proxy->resp_body);
            proxy->resp_body = NULL;
        }
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body_pos = 0;
        proxy->state         = XRD_PX_IDLE;

        ngx_memzero(&proxy->wait_ev, sizeof(proxy->wait_ev));
        proxy->wait_ev.handler = xrootd_proxy_wait_handler;
        proxy->wait_ev.data    = proxy;
        proxy->wait_ev.log     = proxy->conn->log;
        ngx_add_timer(&proxy->wait_ev, wait_secs * 1000);
        return;
    }

    /* kXR_wait exhausted retries — free retry buffer and relay the wait to client */
    if (status == kXR_wait) {
        int local_fh = proxy->fwd_local_fh;
        if (proxy->fwd_reqid == kXR_open && local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
            proxy->wait_retry_req = NULL;
        }
    }

    /* ---- kXR_redirect: follow-through (transparently reconnect) ---- */
    if (status == kXR_redirect && body != NULL && dlen > 0
        && proxy->redirect_count < 3)
    {
        /* Payload is "host:port\0" */
        char *target = (char *) body;
        char *colon  = ngx_strchr(target, ':');

        if (colon != NULL) {
            *colon = '\0';
            if (proxy->redirect_host.data != NULL) {
                ngx_free(proxy->redirect_host.data);
            }
            proxy->redirect_host.len  = (size_t)(colon - target);
            proxy->redirect_host.data = ngx_alloc(proxy->redirect_host.len + 1,
                                                 c->log);
            if (proxy->redirect_host.data != NULL) {
                ngx_memcpy(proxy->redirect_host.data, target,
                           proxy->redirect_host.len);
                proxy->redirect_host.data[proxy->redirect_host.len] = '\0';
                proxy->redirect_port = (uint16_t) atoi(colon + 1);

                proxy->redirect_count++;
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "xrootd proxy: following redirect %d to %s:%d",
                              proxy->redirect_count,
                              proxy->redirect_host.data,
                              (int) proxy->redirect_port);

                /* Close current upstream and reconnect to redirected target */
                if (proxy->conn != NULL) {
                    ngx_close_connection(proxy->conn);
                    proxy->conn = NULL;
                }
                if (proxy->resp_body != NULL) {
                    ngx_free(proxy->resp_body);
                    proxy->resp_body = NULL;
                }
                /* Use the copy saved for wait-retry to re-issue the request */
                proxy->saved_req     = proxy->wait_retry_req;
                proxy->saved_req_len = proxy->wait_retry_req_len;
                proxy->saved_local_fh = proxy->wait_retry_local_fh;
                proxy->wait_retry_req     = NULL;
                proxy->wait_retry_req_len = 0;

                proxy->state         = XRD_PX_CONNECTING;
                proxy->bs_phase      = XRD_PX_BS_HANDSHAKE;
                proxy->rhdr_pos      = 0;
                proxy->resp_dlen     = 0;
                proxy->resp_body_pos = 0;

                if (xrootd_proxy_connect(proxy, c, proxy->conf) == NGX_OK) {
                    return; /* reconnect in progress; will dispatch saved_req */
                }
                /* reconnect failed — fall through to relay redirect to client */
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "xrootd proxy: redirect follow failed, relaying");
            }
        }
    }

    /* ---- path-op audit: rm, mkdir, rmdir, mv, chmod, truncate ---- */
    if (proxy->fwd_path_audit
        && (status == kXR_ok || status == kXR_error))
    {
        if (status == kXR_ok) {
            XROOTD_PROXY_METRIC_INC(ctx, path_ops_total);
            XROOTD_PROXY_UP_INC(proxy, path_ops_total);
        } else {
            XROOTD_PROXY_METRIC_INC(ctx, path_op_errors_total);
            XROOTD_PROXY_UP_INC(proxy, path_op_errors_total);
        }
        proxy_write_path_audit(proxy, status);
        proxy->fwd_path_audit = 0;
    }

    /* ---- kXR_open: translate upstream fhandle to local fhandle ---- */
    if (proxy->fwd_reqid == kXR_open && status == kXR_ok) {
        int local_fh    = proxy->fwd_local_fh;
        int upstream_fh = (body != NULL && dlen >= 1)
                          ? (int)(unsigned char) body[0]
                          : 0;

        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = upstream_fh;
            proxy->fh_map[local_fh].open_msec   = ngx_current_msec;
            if (body != NULL) {
                body[0] = (u_char)(unsigned int) local_fh;
                /* Zero out bytes 1-3 of the fhandle field (match local convention) */
                body[1] = 0;
                body[2] = 0;
                body[3] = 0;
            }
        }
        /* Open is final — release the retry copy */
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
            proxy->wait_retry_req = NULL;
        }
        XROOTD_PROXY_METRIC_INC(ctx, opens_total);
        XROOTD_PROXY_UP_INC(proxy, opens_total);
    }

    if (status == kXR_error && proxy->fwd_reqid == kXR_open) {
        int local_fh = proxy->fwd_local_fh;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
            proxy->wait_retry_req = NULL;
        }
        XROOTD_PROXY_METRIC_INC(ctx, open_errors);
        XROOTD_PROXY_UP_INC(proxy, open_errors);
    }

    /* ---- read/readv/pgread: track bytes returned to client ---- */
    if (status == kXR_ok || status == kXR_oksofar) {
        int local_fh = proxy->fwd_local_fh;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            switch (proxy->fwd_reqid) {
            case kXR_read:
            case kXR_pgread:
            case kXR_readv:
                proxy->fh_map[local_fh].bytes_read += dlen;
                XROOTD_PROXY_METRIC_INC(ctx, reads_total);
                XROOTD_PROXY_METRIC_ADD(ctx, read_bytes_total, dlen);
                XROOTD_PROXY_UP_INC(proxy, reads_total);
                XROOTD_PROXY_UP_ADD(proxy, read_bytes_total, dlen);
                break;
            case kXR_write:
            case kXR_pgwrite:
            case kXR_writev:
                proxy->fh_map[local_fh].bytes_written += proxy->fwd_payload_len;
                XROOTD_PROXY_METRIC_INC(ctx, writes_total);
                XROOTD_PROXY_METRIC_ADD(ctx, write_bytes_total,
                                        proxy->fwd_payload_len);
                XROOTD_PROXY_UP_INC(proxy, writes_total);
                XROOTD_PROXY_UP_ADD(proxy, write_bytes_total, proxy->fwd_payload_len);
                break;
            default:
                break;
            }
        }
    }

    /* ---- kXR_close: emit audit record, free the handle slot on success ---- */
    if (proxy->fwd_reqid == kXR_close && status == kXR_ok) {
        int local_fh = proxy->fwd_local_fh;
        if (local_fh >= 0 && local_fh < XROOTD_MAX_FILES) {
            proxy_write_audit(proxy, local_fh);
            proxy->fh_map[local_fh].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        XROOTD_PROXY_METRIC_INC(ctx, closes_total);
        XROOTD_PROXY_UP_INC(proxy, closes_total);
    }

    /* ---- build and send relay buffer ---- */
    total = XRD_RESPONSE_HDR_LEN + dlen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        xrootd_proxy_abort(proxy, "proxy: pool alloc failed in relay");
        return;
    }

    xrootd_build_resp_hdr(proxy->fwd_streamid, status, dlen,
                          (ServerResponseHdr *)(void *) buf);
    if (dlen > 0 && body != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);
    }

    /* Free the heap-allocated body now that we've copied it */
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd proxy: relay reqid=%d status=%d dlen=%uz",
                   (int) proxy->fwd_reqid, (int) status, (size_t) dlen);

    if (status == kXR_oksofar) {
        /* More chunks to come — relay this frame but stay in FORWARDING */
        proxy->fwd_streaming = 1;
        proxy->rhdr_pos      = 0;
        proxy->resp_dlen     = 0;
        proxy->resp_body     = NULL;
        proxy->resp_body_pos = 0;
        xrootd_queue_response(ctx, c, buf, total);
        /* State stays XRD_ST_PROXY; read handler loops */
        return;
    }

    /* Final response — transition back to client loop */
    proxy->state = XRD_PX_IDLE;
    ctx->state   = XRD_ST_REQ_HEADER;
    xrootd_queue_response(ctx, c, buf, total);
    xrootd_schedule_read_resume(c);
}

/* ---- deferred request dispatch (called after bootstrap completes) --------- */

/*
 * xrootd_proxy_dispatch_pending — dispatch proxy->saved_req to upstream.
 *
 * Called from events.c when bootstrap completes.  Handles the bound-secondary
 * lazy-open case: if the saved request is a kXR_read / kXR_readv for a handle
 * with no upstream mapping, a synthetic kXR_open is issued first.
 */
ngx_int_t
xrootd_proxy_dispatch_pending(xrootd_proxy_ctx_t *proxy)
{
    xrootd_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    u_char           *req = proxy->saved_req;
    size_t            len = proxy->saved_req_len;
    int               saved_lfh = proxy->saved_local_fh;
    uint16_t          reqid;
    ClientRequestHdr *hdr;

    if (req == NULL) {
        return NGX_OK;
    }

    hdr   = (ClientRequestHdr *)(void *) req;
    reqid = ntohs(hdr->requestid);

    /* Bound secondary lazy-open check: kXR_read / kXR_pgread / kXR_readv */
    if (ctx->is_bound) {
        int check_fh = -1;
        if ((reqid == kXR_read || reqid == kXR_pgread) && len >= 5) {
            check_fh = (int)(unsigned char) req[4];
        } else if (reqid == kXR_readv && len > XRD_REQUEST_HDR_LEN + 4) {
            check_fh = (int)(unsigned char) req[XRD_REQUEST_HDR_LEN];
        }
        if (check_fh >= 0 && check_fh < XROOTD_MAX_FILES
            && proxy->fh_map[check_fh].upstream_fh == XROOTD_PROXY_FH_FREE)
        {
            proxy->saved_req = NULL; /* ownership to lazy_open */
            return xrootd_proxy_lazy_open(proxy, ctx, c, check_fh, req, len);
        }
    }

    /* Normal deferred dispatch (e.g. kXR_open queued during bootstrap) */
    proxy->fwd_reqid       = reqid;
    proxy->fwd_streamid[0] = hdr->streamid[0];
    proxy->fwd_streamid[1] = hdr->streamid[1];
    proxy->fwd_local_fh    = saved_lfh;
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = len > XRD_REQUEST_HDR_LEN
                             ? len - XRD_REQUEST_HDR_LEN : 0;
    proxy->saved_req       = NULL;  /* ownership transferred to wbuf */

    proxy->wbuf     = req;
    proxy->wbuf_len = len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
        xrootd_proxy_abort(proxy, "proxy: send deferred request failed");
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len) {
        return NGX_OK; /* write handler will complete the send */
    }
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        xrootd_proxy_abort(proxy, "proxy: read arm failed after deferred send");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- main dispatch entry point ------------------------------------------- */

ngx_int_t
xrootd_proxy_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_proxy_ctx_t *proxy;
    int                 i;

    /* --- lazy initialisation: connect to upstream on first dispatch --- */
    if (ctx->proxy == NULL) {
        proxy = ngx_pcalloc(c->pool, sizeof(xrootd_proxy_ctx_t));
        if (proxy == NULL) {
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: out of memory");
        }
        for (i = 0; i < XROOTD_MAX_FILES; i++) {
            proxy->fh_map[i].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        proxy->client_ctx     = ctx;
        proxy->client_conn    = c;
        proxy->conf           = conf;
        proxy->fwd_local_fh   = -1;
        proxy->saved_local_fh = -1;
        proxy->reconnect_left = (int) conf->proxy_reconnect_attempts;
        ctx->proxy            = proxy;

        if (xrootd_proxy_connect(proxy, c, conf) != NGX_OK) {
            ctx->proxy = NULL;
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: upstream connect failed");
        }
    }

    proxy = ctx->proxy;

    /* --- if bootstrap is still in progress, save this request --- */
    if (proxy->state != XRD_PX_IDLE) {
        size_t total = XRD_REQUEST_HDR_LEN + ctx->cur_dlen;
        u_char *saved;

        saved = ngx_alloc(total, c->log);
        if (saved == NULL) {
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: out of memory saving request");
        }
        ngx_memcpy(saved, ctx->hdr_buf, XRD_REQUEST_HDR_LEN);
        if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
            ngx_memcpy(saved + XRD_REQUEST_HDR_LEN, ctx->payload, ctx->cur_dlen);
        }

        proxy->saved_req     = saved;
        proxy->saved_req_len = total;

        /* Pre-allocate a local fh for a deferred open */
        if (ctx->cur_reqid == kXR_open) {
            int local_fh = xrootd_proxy_alloc_local_fh(proxy);
            if (local_fh < 0) {
                ngx_free(saved);
                proxy->saved_req = NULL;
                return xrootd_send_error(ctx, c, kXR_IOError,
                                         "proxy: no free file handles");
            }
            proxy->fh_map[local_fh].upstream_fh = 255;  /* pending */
            proxy->saved_local_fh                = local_fh;
        } else {
            proxy->saved_local_fh = -1;
        }

        /* Suspend client read loop until bootstrap + deferred dispatch complete */
        ctx->state = XRD_ST_PROXY;
        return NGX_OK;
    }

    /* --- upstream is ready: forward the request now --- */
    return xrootd_proxy_forward_request(proxy, ctx, c);
}
