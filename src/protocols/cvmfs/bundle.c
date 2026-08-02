/* bundle.c — the phase-87 G2 chunk-bundle batch-fetch endpoint.
 *
 * WHAT: POST /cvmfs/<repo>/.cvmfs-bundle (gated brix_cvmfs_bundle, default
 *       off): the body is a newline-separated want-list of repo-relative CAS
 *       paths ("data/<2hex>/<hex>[sfx]"); the response streams every
 *       CACHE-RESIDENT member back in one framed reply (shared/cvmfs/bundle/
 *       wire format), with a miss marker for everything else.
 * WHY:  CVMFS has no batch fetch — a cold client start is thousands of
 *       serialized RTTs. One POST turns the cache-warm part of that into a
 *       single round-trip; misses fall back to ordinary single GETs, which
 *       fill the cache for the next requester. Serving only resident bytes
 *       keeps the endpoint synchronous and bounded — it never triggers an
 *       origin fill, so it can never stall behind a dead Stratum-1.
 * HOW:  every want line is validated by rebuilding "/cvmfs/<repo>/<line>"
 *       through the pure classifier — only a canonical CAS shape passes, so
 *       traversal cannot be expressed. Members are read through the VFS seam
 *       (INVARIANT 12) into pool buffers under the shared per-object/total
 *       caps; integrity stays per-object (the client CAS-verifies each member
 *       against its path-derived hash — the frame carries no trust).
 */
#include "cvmfs.h"
#include "cvmfs_module_internal.h"

#include "cvmfs/bundle/bundle.h"
#include "fs/backend/cache/sd_cache.h"     /* brix_sd_cache_fill_needs_offload */
#include "fs/vfs/vfs.h"

#include <limits.h>

/* One parsed + policed want-list entry, resolved to served bytes or a miss. */
typedef struct {
    const char  *rel;              /* repo-relative path (into body buffer)  */
    size_t       rel_len;
    u_char      *data;             /* pool copy of the member bytes          */
    size_t       data_len;
    unsigned     miss:1;
} cvmfs_bundle_want_t;

/* Read the (memory- or temp-file-backed) request body into one contiguous
 * pool buffer. Returns the buffer, or NULL with *status set. The accumulation
 * cap re-enforces CVMFS_BUNDLE_MAX_WANT for chunked bodies whose length the
 * preflight check could not see. */
static u_char *
cvmfs_bundle_read_body(ngx_http_request_t *r, size_t *len_out,
    ngx_uint_t *status)
{
    ngx_chain_t *cl;
    u_char      *body;
    size_t       total = 0;

    if (r->request_body == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }

    body = ngx_pnalloc(r->pool, CVMFS_BUNDLE_MAX_WANT);
    if (body == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        size_t     n;

        if (b->in_file) {
            n = (size_t) (b->file_last - b->file_pos);
            if (total + n > CVMFS_BUNDLE_MAX_WANT) {
                *status = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                return NULL;
            }
            if (ngx_read_file(b->file, body + total, n, b->file_pos)
                != (ssize_t) n)
            {
                *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NULL;
            }
        } else {
            n = (size_t) (b->last - b->pos);
            if (total + n > CVMFS_BUNDLE_MAX_WANT) {
                *status = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                return NULL;
            }
            ngx_memcpy(body + total, b->pos, n);
        }
        total += n;
    }

    *len_out = total;
    return body;
}

/* Parse + police the want-list: each non-empty line must classify as a CAS
 * object under THIS request's repo ("/cvmfs/<repo>/<line>" through the pure
 * classifier — the only path grammar the endpoint speaks). Fills `want[]`
 * (rel pointers alias `body`); returns the entry count, or -1 with *status
 * set on any malformed/oversize/traversal line. */
static ngx_int_t
cvmfs_bundle_parse_want(ngx_http_request_t *r, u_char *body, size_t body_len,
    cvmfs_bundle_want_t *want, ngx_uint_t *status)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    size_t      pos = 0;
    ngx_uint_t  n = 0;
    char        probe[CVMFS_BUNDLE_MAX_PATH + 128];

    while (pos < body_len) {
        size_t start = pos, len;

        while (pos < body_len && body[pos] != '\n') {
            pos++;
        }
        len = pos - start;
        if (pos < body_len) {
            pos++;                              /* consume '\n'            */
        }
        if (len > 0 && body[start + len - 1] == '\r') {
            len--;                              /* tolerate CRLF senders   */
        }
        if (len == 0) {
            continue;                           /* skip blank lines        */
        }
        if (len > CVMFS_BUNDLE_MAX_PATH || n >= CVMFS_BUNDLE_MAX_ITEMS) {
            *status = NGX_HTTP_BAD_REQUEST;
            return -1;
        }

        {
            cvmfs_url_info_t info;
            int              plen;

            plen = ngx_snprintf((u_char *) probe, sizeof(probe),
                                "/cvmfs/%*s/%*s",
                                ctx->url.repo_len, ctx->url.repo,
                                len, body + start)
                   - (u_char *) probe;
            cvmfs_classify_url(probe, (size_t) plen, &info);
            if (info.cls != CVMFS_URL_CAS) {
                *status = NGX_HTTP_BAD_REQUEST;   /* traversal / non-CAS  */
                return -1;
            }
        }

        want[n].rel      = (const char *) (body + start);
        want[n].rel_len  = len;
        want[n].data     = NULL;
        want[n].data_len = 0;
        want[n].miss     = 1;
        n++;
    }
    return (ngx_int_t) n;
}

/* fs path = export root + "/cvmfs/<repo>/<rel>" (the same join the
 * single-GET path builds from r->uri; "/" is the pure-cache anchor).
 * -1 = doesn't fit — the entry stays a miss. */
static int
cvmfs_bundle_fs_path(ngx_http_brix_cvmfs_ctx_t *ctx, const char *root,
    const cvmfs_bundle_want_t *w, char *path, size_t cap)
{
    size_t rn = (root[0] == '/' && root[1] == '\0') ? 0 : ngx_strlen(root);
    size_t need = rn + sizeof("/cvmfs/") - 1 + ctx->url.repo_len + 1
                + w->rel_len + 1;

    if (need > cap) {
        return -1;
    }
    ngx_snprintf((u_char *) path, cap, "%*s/cvmfs/%*s/%*s%Z",
                 rn, root, ctx->url.repo_len, ctx->url.repo,
                 w->rel_len, w->rel);
    return 0;
}

/* Copy the open, within-budget object into a pool buffer and mark the
 * entry a hit. -1 = leave it a miss (oversize, over budget, unreadable). */
static int
cvmfs_bundle_read_obj(ngx_http_request_t *r, brix_vfs_file_t *fh,
    cvmfs_bundle_want_t *w, size_t *budget)
{
    brix_vfs_stat_t vst;
    size_t          off;

    if (brix_vfs_file_stat(fh, &vst) != NGX_OK
        || vst.is_directory
        || (size_t) vst.size > CVMFS_BUNDLE_MAX_OBJ
        || (size_t) vst.size > *budget)
    {
        return -1;
    }

    w->data = ngx_pnalloc(r->pool, vst.size > 0 ? (size_t) vst.size : 1);
    if (w->data == NULL) {
        return -1;
    }
    for (off = 0; off < (size_t) vst.size; ) {
        ssize_t rd = brix_vfs_file_pread(fh, w->data + off,
                                          (size_t) vst.size - off, (off_t) off);
        if (rd <= 0) {
            return -1;                          /* short/failed read → miss */
        }
        off += (size_t) rd;
    }

    w->data_len = (size_t) vst.size;
    w->miss     = 0;
    *budget    -= w->data_len;
    return 0;
}

/* Resolve ONE want entry against the local tier: a cache-resident,
 * within-budget object is copied into a pool buffer; everything else
 * (remote, absent, oversize, over the response budget, unreadable) stays a
 * miss — the client fetches it singly. `*budget` is the remaining
 * whole-response data allowance. */
static void
cvmfs_bundle_fill_one(ngx_http_request_t *r, const char *root,
    brix_sd_instance_t *sd, cvmfs_bundle_want_t *w, size_t *budget)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    char              path[PATH_MAX];
    brix_vfs_ctx_t  vctx;
    brix_vfs_file_t *fh;
    int               vfs_err = 0;
    int               is_tls = 0;
    const char       *key;

    if (cvmfs_bundle_fs_path(ctx, root, w, path, sizeof(path)) != 0) {
        return;                                              /* stays a miss */
    }

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log,
        BRIX_PROTO_CVMFS, root, "", /* allow_write */ 0, is_tls, NULL,
        path);
    vctx.sd = sd;
    key = brix_vfs_export_relative(&vctx, path);

    /* resident-only contract: a remote miss is NEVER filled from here */
    if (brix_sd_cache_fill_needs_offload(sd, key)) {
        return;
    }

    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        return;
    }
    (void) cvmfs_bundle_read_obj(r, fh, w, budget);
    brix_vfs_close(fh, r->connection->log);
}

/* Frame the resolved want-list into an output chain and send it. The whole
 * response is resident pool memory (caps guarantee bounded size), so the
 * length is exact and the send is one pass. */
static ngx_int_t
cvmfs_bundle_respond(ngx_http_request_t *r, cvmfs_bundle_want_t *want,
    ngx_uint_t n_want)
{
    ngx_chain_t  *out = NULL, **link = &out;
    ngx_buf_t    *b, *tail = NULL;
    off_t         content_len = 0;
    ngx_uint_t    i;
    ngx_int_t     rc;

    b = ngx_create_temp_buf(r->pool, CVMFS_BUNDLE_HDR_LEN);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cvmfs_bundle_hdr_encode(b->pos, (uint32_t) n_want);
    b->last = b->pos + CVMFS_BUNDLE_HDR_LEN;
    content_len += CVMFS_BUNDLE_HDR_LEN;

    *link = ngx_alloc_chain_link(r->pool);
    if (*link == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    (*link)->buf = b;
    link = &(*link)->next;
    tail = b;

    for (i = 0; i < n_want; i++) {
        cvmfs_bundle_want_t *w = &want[i];
        size_t               hdr_cap = 4 + w->rel_len + 8;
        int                  hn;

        b = ngx_create_temp_buf(r->pool, hdr_cap);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        hn = cvmfs_bundle_item_encode(b->pos, hdr_cap, w->rel, w->rel_len,
                                      w->miss ? CVMFS_BUNDLE_MISS
                                              : (uint64_t) w->data_len);
        if (hn < 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;   /* cannot happen: policed */
        }
        b->last = b->pos + hn;
        content_len += hn;

        *link = ngx_alloc_chain_link(r->pool);
        if (*link == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        (*link)->buf = b;
        link = &(*link)->next;
        tail = b;

        if (!w->miss && w->data_len > 0) {
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            b->memory = 1;
            b->pos    = w->data;
            b->last   = w->data + w->data_len;
            b->start  = w->data;
            b->end    = b->last;
            content_len += (off_t) w->data_len;

            *link = ngx_alloc_chain_link(r->pool);
            if (*link == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            (*link)->buf = b;
            link = &(*link)->next;
            tail = b;
        }
    }

    *link = NULL;
    tail->last_buf      = 1;      /* never NULL: the header link is always
                                     appended before the loop */
    tail->last_in_chain = 1;

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_len;
    ngx_str_set(&r->headers_out.content_type, "application/x-cvmfs-bundle");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, out);
}

/* Body-ready continuation: parse, resolve, respond, finalize. */
static void
cvmfs_bundle_body_ready(ngx_http_request_t *r)
{
    ngx_http_brix_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_cvmfs_module);
    ngx_http_brix_cvmfs_ctx_t      *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    cvmfs_bundle_want_t              *want;
    brix_sd_instance_t             *sd;
    const char                       *root;
    u_char                           *body;
    size_t                            body_len = 0;
    size_t                            budget = CVMFS_BUNDLE_MAX_TOTAL;
    ngx_uint_t                        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_uint_t                        hits = 0, i;
    ngx_int_t                         n;

    body = cvmfs_bundle_read_body(r, &body_len, &status);
    if (body == NULL) {
        ngx_http_finalize_request(r, (ngx_int_t) status);
        return;
    }

    want = ngx_pcalloc(r->pool,
                       CVMFS_BUNDLE_MAX_ITEMS * sizeof(cvmfs_bundle_want_t));
    if (want == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    n = cvmfs_bundle_parse_want(r, body, body_len, want, &status);
    if (n < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "cvmfs-bundle: reject client=%V cause=\"malformed want-list "
            "(non-CAS line, oversize line, or more than %ui items)\"",
            &r->connection->addr_text, (ngx_uint_t) CVMFS_BUNDLE_MAX_ITEMS);
        ngx_http_finalize_request(r, (ngx_int_t) status);
        return;
    }

    root = (ctx != NULL && ctx->up_root != NULL) ? ctx->up_root
                                                 : lcf->common.root_canon;
    sd = cvmfs_resolve_sd(r, lcf);
    if (sd == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "cvmfs: no storage backend registered for \"%s\" - check "
            "brix_storage_backend", root);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    for (i = 0; i < (ngx_uint_t) n; i++) {
        cvmfs_bundle_fill_one(r, root, sd, &want[i], &budget);
        hits += want[i].miss ? 0 : 1;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "cvmfs-bundle: served client=%V items=%ui hits=%ui misses=%ui "
        "bytes=%uz",
        &r->connection->addr_text, (ngx_uint_t) n, hits,
        (ngx_uint_t) n - hits, CVMFS_BUNDLE_MAX_TOTAL - budget);

    ngx_http_finalize_request(r, cvmfs_bundle_respond(r, want, (ngx_uint_t) n));
}

ngx_int_t
brix_cvmfs_bundle_handle(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_int_t  rc;

    (void) lcf;

    /* preflight: a declared body over the want cap never gets buffered
     * (chunked senders are caught by the accumulation cap instead) */
    if (r->headers_in.content_length_n > (off_t) CVMFS_BUNDLE_MAX_WANT) {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    rc = ngx_http_read_client_request_body(r, cvmfs_bundle_body_ready);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}
