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
 * WHAT: File-local view of the strip/add prefix transform plus the payload
 *       slice a kXR_prepare rewrite operates over.
 * WHY: proxy_rewrite_prepare_payload's two passes (measure, then copy) share the
 *      same conf-derived prefixes and payload bounds. Bundling them into one
 *      frozen, file-local struct lets the extracted pass helpers stay under the
 *      5-parameter cap without threading six loose scalars through each call.
 * HOW: Populated once by proxy_rewrite_prepare_payload from conf + req/total,
 *      then passed by const pointer to the pass helpers. Never mutated after
 *      construction; carries no ownership.
 */
typedef struct {
    const u_char *strip;   /* prefix to strip from each matching line */
    size_t        slen;    /* length of strip */
    const u_char *add;     /* prefix to prepend in place of strip */
    size_t        alen;    /* length of add */
    const u_char *payload; /* first byte after the request header */
    size_t        plen;    /* payload length in bytes */
} proxy_prepare_rewrite_t;

/*
 * WHAT: Compute the length of the line that ends at cursor p, given its start.
 * WHY: Both prepare passes must treat a final line without a trailing newline as
 *      inclusive of p, but a '\n'-terminated line as exclusive of p. Centralizing
 *      the off-by-one keeps the two passes byte-identical.
 * HOW: p is a boundary (either '\n' or the payload's last byte). If p is the last
 *      byte and is not itself '\n', the line includes p (+1); otherwise it ends
 *      just before p.
 */
static size_t
proxy_prepare_line_len(const u_char *line_start, const u_char *p,
                       const u_char *last)
{
    if (p == last && *p != '\n') {
        return (size_t)(p - line_start + 1);
    }
    return (size_t)(p - line_start);
}

/*
 * WHAT: Report whether a payload line begins with the strip prefix.
 * WHY: The match test (long-enough line AND prefix equality) gates every
 *      rewrite decision in both passes; a single helper keeps them consistent.
 * HOW: True when line_len covers slen and the leading slen bytes equal strip.
 */
static ngx_uint_t
proxy_prepare_line_matches(const proxy_prepare_rewrite_t *rw,
                           const u_char *line_start, size_t line_len)
{
    return (line_len >= rw->slen
            && ngx_strncmp(line_start, rw->strip, rw->slen) == 0);
}

/*
 * WHAT: First pass — compute the rewritten payload's total request size and
 *       whether any line actually needs rewriting.
 * WHY: The copy pass must allocate the exact output size up front, and the whole
 *      operation is skipped (original buffer returned) when no line matches.
 * HOW: Walk the payload line by line; matching lines contribute alen +
 *      (line_len - slen), others contribute line_len; a terminating '\n' adds
 *      one byte. Accumulates onto the header length and sets *needs_rewrite.
 */
static size_t
proxy_prepare_measure(const proxy_prepare_rewrite_t *rw,
                      ngx_uint_t *needs_rewrite)
{
    const u_char *p          = rw->payload;
    const u_char *line_start = rw->payload;
    const u_char *last       = rw->payload + rw->plen - 1;
    size_t        new_total  = XRD_REQUEST_HDR_LEN;

    *needs_rewrite = 0;

    while (p < rw->payload + rw->plen) {
        if (*p == '\n' || p == last) {
            size_t line_len = proxy_prepare_line_len(line_start, p, last);

            if (proxy_prepare_line_matches(rw, line_start, line_len)) {
                new_total += rw->alen + (line_len - rw->slen);
                *needs_rewrite = 1;
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
    return new_total;
}

/*
 * WHAT: Second pass — emit the rewritten payload into dst.
 * WHY: Once the size is known and a rewrite is required, each line is copied
 *      verbatim or with its strip prefix replaced by add, preserving line order
 *      and newline placement byte-for-byte.
 * HOW: Walk the payload identically to the measure pass; for matching lines write
 *      add then the post-strip remainder, otherwise copy the line as-is; re-emit
 *      a trailing '\n' when the boundary byte was one.
 */
static void
proxy_prepare_emit(const proxy_prepare_rewrite_t *rw, u_char *dst)
{
    const u_char *p          = rw->payload;
    const u_char *line_start = rw->payload;
    const u_char *last       = rw->payload + rw->plen - 1;

    while (p < rw->payload + rw->plen) {
        if (*p == '\n' || p == last) {
            size_t line_len = proxy_prepare_line_len(line_start, p, last);

            if (proxy_prepare_line_matches(rw, line_start, line_len)) {
                ngx_memcpy(dst, rw->add, rw->alen);
                dst += rw->alen;
                ngx_memcpy(dst, line_start + rw->slen, line_len - rw->slen);
                dst += (line_len - rw->slen);
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
    proxy_prepare_rewrite_t rw;
    u_char                 *new_req;
    size_t                  new_total;
    ngx_uint_t              needs_rewrite = 0;

    if (conf->proxy.path_strip.len == 0 || total <= XRD_REQUEST_HDR_LEN) {
        *total_out = total;
        return req;
    }

    rw.strip   = conf->proxy.path_strip.data;
    rw.slen    = conf->proxy.path_strip.len;
    rw.add     = conf->proxy.path_add.data;
    rw.alen    = conf->proxy.path_add.len;
    rw.payload = req + XRD_REQUEST_HDR_LEN;
    rw.plen    = total - XRD_REQUEST_HDR_LEN;

    new_total = proxy_prepare_measure(&rw, &needs_rewrite);
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
    proxy_prepare_emit(&rw, new_req + XRD_REQUEST_HDR_LEN);

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
 * proxy_reject_request — free the forwarded-request buffer and queue a
 * kXR_error to the client.
 *
 * WHY: brix_send_error() returns NGX_OK once the error frame is queued, so a
 * translate handler that did `ngx_free(req); return brix_send_error(...)`
 * handed NGX_OK back to brix_proxy_forward_request(), which read that as
 * "continue forwarding" and went on to copy (save_wait_retry), tap and queue
 * the freed buffer as an owned wbuf — a use-after-free and a later double
 * free. Mapping the queued-error case to NGX_ABORT gives the forwarding
 * pipeline an unambiguous "stop, req is gone, session continues" signal.
 */
ngx_int_t
proxy_reject_request(brix_ctx_t *ctx, ngx_connection_t *c,
                     u_char *req, uint16_t errcode, const char *msg)
{
    ngx_int_t rc;

    ngx_free(req);
    rc = brix_send_error(ctx, c, errcode, msg);
    return (rc == NGX_OK) ? NGX_ABORT : rc;
}

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

