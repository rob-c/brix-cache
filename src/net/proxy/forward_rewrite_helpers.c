#include "proxy_internal.h"
#include "protocols/root/session/registry.h"

/*
 * WHAT: Path prefix rewriting and file handle translation helpers for the transparent XRootD proxy.
 * WHY: The proxy translates paths between client-facing namespace and upstream filesystem namespace (e.g., /data → /mnt/storage).
 *      kXR_prepare payloads contain newline-separated path lists that need per-line rewriting. File handles are local to the client
 *      session but must be translated to upstream handle IDs before forwarding. INVARIANT: all rewrote buffers allocated via ngx_alloc;
 *      original request freed on success when reallocation occurred (caller responsibility tracked via total_out).
 * HOW: proxy_rewrite_path uses three strategies — no-match pass-through, same-length in-place rewrite, longer-path reallocation with dlen update.
 *      proxy_rewrite_prepare_payload does two-pass approach (calculate length + check needs_rewrite first, then copy/rewrite). proxy_translate_fh
 *      looks up local handle in fh_map and replaces byte at offset; returns -1 for invalid/unmapped handles.
 */

/* path prefix rewriting */

/* proxy_rewrite_path — apply the strip/add prefix transform to a request payload
 * carrying one filesystem path (transparent proxy: client /data → upstream
 * /mnt/storage); same-length rewrites are in-place, longer results reallocate and
 * update the dlen header. */
u_char *
proxy_rewrite_path(ngx_connection_t *c,
                    ngx_stream_brix_srv_conf_t *conf,
                    u_char *req, size_t total,
                    size_t path_off, size_t path_len,
                    size_t *total_out)
{
    const u_char *strip = conf->proxy.path_strip.data;
    size_t        slen  = conf->proxy.path_strip.len;
    const u_char *add   = conf->proxy.path_add.data;
    size_t        alen  = conf->proxy.path_add.len;
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
u_char *
proxy_rewrite_prepare_payload(ngx_connection_t *c,
                              ngx_stream_brix_srv_conf_t *conf,
                              u_char *req, size_t total,
                              size_t *total_out)
{
    const u_char *strip = conf->proxy.path_strip.data;
    size_t        slen  = conf->proxy.path_strip.len;
    const u_char *add   = conf->proxy.path_add.data;
    size_t        alen  = conf->proxy.path_add.len;
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

/* fhandle translation helpers */

/*
 * Translate a 1-byte local file handle in buf[offset] to the upstream handle.
 * Returns 0 on success, -1 if the local handle is invalid.
 */
int
proxy_translate_fh(brix_proxy_ctx_t *proxy, u_char *buf, size_t offset)
{
    int local_fh = (int)(unsigned char) buf[offset];

    if (local_fh < 0 || local_fh >= BRIX_MAX_FILES
        || proxy->fh_map[local_fh].upstream_fh == BRIX_PROXY_FH_FREE)
    {
        return -1;
    }
    buf[offset] = (u_char)(unsigned int) proxy->fh_map[local_fh].upstream_fh;
    return 0;
}

