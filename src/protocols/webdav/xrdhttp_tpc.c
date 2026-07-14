/*
 * xrdhttp_tpc.c — XrdHttp TPC / checksum / digest support for the nginx-xrootd
 * WebDAV module.
 *
 * WHAT: Split verbatim from xrdhttp.c:
 *   - TPC shim: synthesise Source:/Destination: headers from ?tpc.src= /
 *     ?tpc.dst=, and inject an Authorization: Bearer from X-Xrootd-Tpc-Token.
 *   - Checksum: Digest: response header computed on-demand from the open fd for
 *     xrd.want.cksum / Want-Digest requests.
 *   - Streaming Digest body filter: fold the response body through adler32 and
 *     emit a Digest trailer for XrdHttp clients.
 *
 * WHY: Groups the TPC-header + checksum/digest concern in one focused file so
 * xrdhttp.c stays under the file-size cap.  See xrdhttp.c for request parsing,
 * xrdhttp_response.c for the status/redirect dialect, and xrdhttp.h for the API.
 *
 * HOW: Behaviour is identical to the original combined file — functions were
 * moved verbatim.
 */

#include "xrdhttp.h"
#include "webdav.h"
#include "protocols/root/protocol/opcodes.h"
#include "core/compat/integrity_info.h"
#include "core/compat/net_target.h"
#include "core/compat/checksum.h"
#include "core/http/http_headers.h"
#include "core/http/http_query.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>   /* adler32() for the streaming Digest body filter */
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"

/* Our nginx module context tag for the XrdHttp per-request context. */
extern ngx_module_t ngx_http_brix_webdav_module;

/* TPC header injection */
ngx_int_t
xrdhttp_inject_tpc_headers(ngx_http_request_t *r)
{
    xrdhttp_req_ctx_t *ctx;
    ngx_table_elt_t   *h;

    ctx = (xrdhttp_req_ctx_t *)
          ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    /*
     * ?tpc.src= → inject Source: header (if not already present).
     * This allows XrdHttp clients to signal TPC pull via URL instead of header.
     */
    if (ctx->tpc_src[0]
        && webdav_tpc_find_header(r, "Source", sizeof("Source") - 1) == NULL)
    {
        brix_net_target_t target;
        ngx_str_t           url;
        char                err[256];

        url.data = (u_char *) ctx->tpc_src;
        url.len  = ngx_strlen(ctx->tpc_src);

        if (brix_net_target_parse(NULL, &url, &target, err, sizeof(err))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrdhttp: invalid tpc.src URL: %s; ignored", err);
        } else if (ngx_strncasecmp(url.data, (u_char *) "https://", 8) != 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrdhttp: tpc.src must be https://; ignored");
        } else {
            if (brix_http_request_header_add(r, "Source", ctx->tpc_src,
                                               NULL) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /*
     * ?tpc.dst= → inject Destination: header (if not already present).
     */
    if (ctx->tpc_dst[0]
        && webdav_tpc_find_header(r, "Destination",
                                  sizeof("Destination") - 1) == NULL)
    {
        brix_net_target_t target;
        ngx_str_t           url;
        char                err[256];

        url.data = (u_char *) ctx->tpc_dst;
        url.len  = ngx_strlen(ctx->tpc_dst);

        if (brix_net_target_parse(NULL, &url, &target, err, sizeof(err))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrdhttp: invalid tpc.dst URL: %s; ignored", err);
        } else if (ngx_strncasecmp(url.data, (u_char *) "https://", 8) != 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrdhttp: tpc.dst must be https://; ignored");
        } else {
            if (brix_http_request_header_add(r, "Destination",
                                               ctx->tpc_dst,
                                               NULL) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /*
     * X-Xrootd-Tpc-Token → if Authorization: Bearer is absent, inject from
     * the captured TPC token.  This allows TPC delegation via this header.
     */
    if (ctx->tpc_token[0]
        && r->headers_in.authorization == NULL)
    {
        char bearer_buf[sizeof("Bearer ") + XRDHTTP_TPC_KEY_MAX];
        snprintf(bearer_buf, sizeof(bearer_buf), "Bearer %s", ctx->tpc_token);

        if (brix_http_request_header_add(r, "Authorization", bearer_buf,
                                           &h) != NGX_OK)
        {
            return NGX_ERROR;
        }
        /* Point nginx's fast-path field at this new entry. */
        r->headers_in.authorization = h;
    }

    return NGX_OK;
}

/* checksum header injection */
ngx_int_t
xrdhttp_add_checksum_header(ngx_http_request_t *r,
                             ngx_fd_t fd,
                             const struct stat *sb)
{
    xrdhttp_req_ctx_t *ctx;
    /* algo (32) + '=' + sha256 hex (64) + NUL = 98; round up generously */
    char               hdr_value[256];
    char               algo[32];
    brix_checksum_alg_t alg;

    ctx = (xrdhttp_req_ctx_t *)
          ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL || !ctx->want_cksum[0] || fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (sb->st_size > (off_t) 2 * 1024 * 1024 * 1024LL) {
        /* Skip checksum computation for files > 2 GiB to bound latency. */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrdhttp: skipping checksum for large file (> 2 GiB)");
        return NGX_OK;
    }

    if (brix_checksum_parse(ctx->want_cksum, strlen(ctx->want_cksum),
                              &alg, algo, sizeof(algo)) == NGX_OK)
    {
        brix_integrity_info_t  info;
        brix_integrity_opts_t  iopts;

        ngx_memzero(&iopts, sizeof(iopts));
        iopts.allow_xattr_cache  = 1;
        iopts.update_xattr_cache = 1;

        if (brix_integrity_get_fd(r->connection->log, fd, NULL, "<xrdhttp>",
                                    algo, &iopts, &info) != NGX_OK
            || brix_integrity_format_http_digest(&info, hdr_value,
                                                   sizeof(hdr_value)) != NGX_OK)
        {
            return NGX_OK;
        }
    } else {
        char safe_alg[sizeof(ctx->want_cksum) * 4];
        brix_sanitize_log_string(ctx->want_cksum,
                                   safe_alg, sizeof(safe_alg));
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrdhttp: unsupported checksum algorithm \"%s\"",
                       safe_alg);
        return NGX_OK;
    }

    return brix_http_set_header(r, "Digest", hdr_value, NULL);
}

/* streaming Digest body filter (Phase 21 Step B) */
ngx_int_t
xrdhttp_digest_body_filter(ngx_http_request_t *r, ngx_chain_t *in,
    ngx_http_output_body_filter_pt next)
{
    xrdhttp_req_ctx_t *ctx;
    ngx_chain_t       *cl;
    ngx_uint_t         saw_last = 0;

    ctx = (xrdhttp_req_ctx_t *)
          ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    if (ctx == NULL || !ctx->is_xrdhttp || !ctx->compute_digest) {
        return next(r, in);          /* pass-through */
    }

    if (ctx->adler == 0) {
        ctx->adler = (uint32_t) adler32(0L, Z_NULL, 0);   /* seed = 1 */
    }

    for (cl = in; cl != NULL; cl = cl->next) {
        ngx_buf_t *b = cl->buf;

        if (ngx_buf_in_memory(b) && b->last > b->pos) {
            ctx->adler = (uint32_t) adler32((uLong) ctx->adler, b->pos,
                                            (uInt) (b->last - b->pos));
        }
        if (b->last_buf || b->last_in_chain) {
            saw_last = 1;
        }
    }

    /* On the final buffer, queue the Digest as a response trailer.  nginx only
     * transmits trailers on chunked HTTP/1.1 and HTTP/2/3 responses; for a
     * fixed Content-Length GET the fd-based xrdhttp_add_checksum_header() path
     * supplies the Digest header instead, so this is purely additive. */
    if (saw_last && !ctx->digest_emitted) {
        ngx_table_elt_t *h = ngx_list_push(&r->headers_out.trailers);
        if (h != NULL) {
            u_char *v = ngx_pnalloc(r->pool, sizeof("adler32=") - 1 + 8 + 1);
            if (v != NULL) {
                size_t n = ngx_sprintf(v, "adler32=%08xD", ctx->adler) - v;
                h->hash = 1;
                ngx_str_set(&h->key, "Digest");
                h->value.data = v;
                h->value.len  = n;
            }
        }
        ctx->digest_emitted = 1;
    }

    return next(r, in);
}
