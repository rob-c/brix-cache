/*
 * xrdhttp_response.c — XrdHttp response-side dialect for the nginx-xrootd WebDAV module.
 *
 * WHAT: The response half of the XrdHttp compatibility layer, split verbatim
 *   from xrdhttp.c:
 *   - HTTP→kXR status mapping table + lookup (X-Xrootd-Status).
 *   - Response header injection: X-Xrootd-Requuid echo, X-Xrootd-Status,
 *     X-Xrootd-Wait / X-Xrootd-Retry back-pressure headers.
 *   - Redirect dialect: X-Xrootd-Redir-Host/Port + tpc.key / xrd.opaque passthrough.
 *   - ?xrd.stats and multi-range request detection.
 *
 * WHY: Groups the status-mapping + response-emission concern in one focused file
 * so xrdhttp.c stays under the file-size cap.  See xrdhttp.c for the request-side
 * parsing half and xrdhttp.h for the public API contract.
 *
 * HOW: Behaviour is identical to the original combined file — functions were
 * moved verbatim.  The static ?xrd.stats query helper (xrdhttp_args_has_key)
 * lives here alongside its sole caller.
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

/* HTTP -> kXR status mapping */

/*
 * WHAT: One row of the HTTP-status to kXR-error mapping table.
 * WHY:  A data table replaces a long switch ladder, keeping the lookup
 *       function trivially simple and the mapping auditable at a glance.
 * HOW:  http_status is the numeric HTTP code (nginx macro value); xrd_code
 *       is the corresponding kXR_* error constant.
 */
typedef struct {
    ngx_int_t http_status;
    int       xrd_code;
} xrdhttp_status_map_row_t;

/* Exact HTTP -> kXR mappings.  Codes not listed fall through to the
 * class-based default (4xx -> kXR_ArgInvalid, 5xx -> kXR_ServerError). */
static const xrdhttp_status_map_row_t xrdhttp_status_map[] = {
    { NGX_HTTP_BAD_REQUEST,             kXR_ArgInvalid    },
    { NGX_HTTP_UNAUTHORIZED,            kXR_NotAuthorized },
    { NGX_HTTP_FORBIDDEN,               kXR_NotAuthorized },
    { NGX_HTTP_NOT_FOUND,               kXR_NotFound      },
    { NGX_HTTP_NOT_ALLOWED,            kXR_Unsupported   },
    { NGX_HTTP_CONFLICT,               kXR_FSError       },
    { NGX_HTTP_LENGTH_REQUIRED,        kXR_ArgMissing    },
    { 423 /* Locked */,                kXR_FileLocked    },
    { NGX_HTTP_REQUEST_URI_TOO_LARGE,  kXR_ArgTooLong    },
    { NGX_HTTP_RANGE_NOT_SATISFIABLE,  kXR_ArgInvalid    },
    { NGX_HTTP_INTERNAL_SERVER_ERROR,  kXR_ServerError   },
    { NGX_HTTP_NOT_IMPLEMENTED,        kXR_Unsupported   },
    { NGX_HTTP_BAD_GATEWAY,            kXR_FSError       },
    { NGX_HTTP_SERVICE_UNAVAILABLE,    kXR_TooManyErrs   },
    { NGX_HTTP_INSUFFICIENT_STORAGE,   kXR_NoSpace       },
};

/*
 * WHAT: Map any non-2xx HTTP status to a kXR_* error code by class.
 * WHY:  HTTP codes without an exact table entry still need a sensible kXR
 *       error so clients never see kXR_ok on a failure.
 * HOW:  4xx -> kXR_ArgInvalid, 5xx (and above) -> kXR_ServerError, and any
 *       remaining code (1xx/3xx) -> kXR_ok, matching the original ladder.
 */
static int
xrdhttp_status_class_default(ngx_int_t http_status)
{
    if (http_status >= 400 && http_status < 500) {
        return kXR_ArgInvalid;
    }
    if (http_status >= 500) {
        return kXR_ServerError;
    }
    return kXR_ok;
}

int
xrdhttp_http_to_xrd_status(ngx_int_t http_status)
{
    size_t i;

    if (http_status >= 200 && http_status < 300) {
        return kXR_ok;
    }

    for (i = 0; i < sizeof(xrdhttp_status_map) / sizeof(xrdhttp_status_map[0]);
         i++)
    {
        if (xrdhttp_status_map[i].http_status == http_status) {
            return xrdhttp_status_map[i].xrd_code;
        }
    }

    return xrdhttp_status_class_default(http_status);
}

ngx_int_t
xrdhttp_add_response_headers(ngx_http_request_t *r, ngx_int_t http_status)
{
    xrdhttp_req_ctx_t *ctx;
    int                xrd_code;

    ctx = (xrdhttp_req_ctx_t *)
          ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL || !ctx->is_xrdhttp) {
        return NGX_OK;
    }

    /* Guard against double-injection: filter + direct call in get.c. */
    if (ctx->headers_injected) {
        return NGX_OK;
    }
    ctx->headers_injected = 1;

    /* X-Xrootd-Requuid — echo the request UUID back to the client. */
    if (ctx->requuid[0]) {
        if (brix_http_set_header(r, "X-Xrootd-Requuid", ctx->requuid,
                                   NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* X-Xrootd-Status — always emit per XrdHttp spec: 0 = success, non-zero = error. */
    xrd_code = xrdhttp_http_to_xrd_status(http_status);
    if (brix_http_set_header_num(r, "X-Xrootd-Status",
                                   (long) xrd_code) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* X-Xrootd-Wait — back-pressure for async/tape-recall scenarios. */
    if (ctx->wait_seconds > 0) {
        if (brix_http_set_header_num(r, "X-Xrootd-Wait",
                                       (long) ctx->wait_seconds) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* X-Xrootd-Retry — hint for client retry interval. */
    if (ctx->retry_seconds > 0) {
        if (brix_http_set_header_num(r, "X-Xrootd-Retry",
                                       (long) ctx->retry_seconds) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* redirect dialect */

/*
 * WHAT: Produce the redirect Location URL, appending tpc.key / xrd.opaque
 *       query params from ctx when present.
 * WHY:  XrdHttp redirects must carry the TPC key and opaque data forward to
 *       the target node; this is the only place that formatting lives.
 * HOW:  Returns location_url unchanged when there is nothing to append or ctx
 *       is absent; otherwise formats into loc_buf and returns it.  On overflow
 *       it warns and falls back to the plain (truncated) URL — identical to the
 *       original inline behaviour.
 */
static const char *
xrdhttp_build_redirect_location(ngx_http_request_t *r,
                                const xrdhttp_req_ctx_t *ctx,
                                const char *location_url,
                                char *loc_buf, size_t loc_bufsz)
{
    const char *sep;
    int         loc_len;

    if (ctx == NULL || !(ctx->tpc_key[0] || ctx->opaque[0])) {
        return location_url;
    }

    sep = (ngx_strchr(location_url, '?') != NULL) ? "&" : "?";

    if (ctx->tpc_key[0] && ctx->opaque[0]) {
        loc_len = snprintf(loc_buf, loc_bufsz,
                           "%s%stpc.key=%s&xrd.opaque=%s",
                           location_url, sep, ctx->tpc_key, ctx->opaque);
    } else if (ctx->tpc_key[0]) {
        loc_len = snprintf(loc_buf, loc_bufsz,
                           "%s%stpc.key=%s",
                           location_url, sep, ctx->tpc_key);
    } else {
        loc_len = snprintf(loc_buf, loc_bufsz,
                           "%s%sxrd.opaque=%s",
                           location_url, sep, ctx->opaque);
    }

    if (loc_len < 0 || (size_t) loc_len >= loc_bufsz) {
        /* Overflow: use the plain URL without appended params. */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrdhttp: redirect URL overflow, opaque dropped");
        ngx_cpystrn((u_char *) loc_buf, (u_char *) location_url, loc_bufsz);
    }

    return loc_buf;
}

/*
 * WHAT: Add the Location header for a redirect to location_url.
 * WHY:  Separating list-push + string-dup keeps the redirect entry point flat.
 * HOW:  Returns NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR on allocation
 *       failure (same sentinels the caller returns directly).
 */
static ngx_int_t
xrdhttp_set_location_header(ngx_http_request_t *r, const char *location_url)
{
    ngx_table_elt_t *location_hdr = ngx_list_push(&r->headers_out.headers);

    if (location_hdr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    location_hdr->hash = 1;
    ngx_str_set(&location_hdr->key, "Location");
    location_hdr->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){
        ngx_strlen(location_url), (u_char *) location_url
    });
    if (location_hdr->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    location_hdr->value.len = ngx_strlen(location_url);

    return NGX_OK;
}

/*
 * WHAT: Emit the X-Xrootd-Redir-Host / X-Xrootd-Redir-Port headers.
 * WHY:  Hierarchical cluster topologies advertise the concrete target node
 *       alongside the Location URL.
 * HOW:  Each header is only added when its value is meaningful; returns
 *       NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR on header-set failure.
 */
static ngx_int_t
xrdhttp_set_redir_target_headers(ngx_http_request_t *r,
                                 const char *redir_host, int redir_port)
{
    if (redir_host != NULL && redir_host[0]) {
        if (brix_http_set_header(r, "X-Xrootd-Redir-Host", redir_host,
                                   NULL) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    if (redir_port > 0) {
        if (brix_http_set_header_num(r, "X-Xrootd-Redir-Port",
                                       (long) redir_port) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
xrdhttp_send_redirect(ngx_http_request_t *r,
                       const char *location_url,
                       const char *redir_host,
                       int         redir_port)
{
    xrdhttp_req_ctx_t *ctx;
    char               loc_buf[XRDHTTP_TPC_URL_MAX + XRDHTTP_OPAQUE_MAX + 64];
    ngx_int_t          rc;

    ctx = (xrdhttp_req_ctx_t *)
          ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    location_url = xrdhttp_build_redirect_location(r, ctx, location_url,
                                                   loc_buf, sizeof(loc_buf));

    rc = xrdhttp_set_location_header(r, location_url);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = xrdhttp_set_redir_target_headers(r, redir_host, redir_port);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Echo XrdHttp response headers (Requuid, Status=kXR_ok for redirect). */
    if (xrdhttp_add_response_headers(r, NGX_HTTP_TEMPORARY_REDIRECT)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_TEMPORARY_REDIRECT;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * Check if query string contains a bare key (no '=' required, or key=anything).
 * Used for ?xrd.stats detection.
 */
static int
xrdhttp_args_has_key(const ngx_str_t *args, const char *key, size_t key_len)
{
    (void) key_len;

    return brix_http_query_has(*args, key,
                                 BRIX_HTTP_QUERY_CASE_INSENSITIVE
                                 | BRIX_HTTP_QUERY_HAS_VALUE_OK);
}

/* ?xrd.stats detection */
int
xrdhttp_request_is_stats_query(ngx_http_request_t *r)
{
    if (r->args.len == 0) {
        return 0;
    }
    return xrdhttp_args_has_key(&r->args, "xrd.stats",
                                sizeof("xrd.stats") - 1);
}

/* multirange detection */
int
xrdhttp_request_is_multirange(ngx_http_request_t *r)
{
    ngx_table_elt_t *range;

    range = r->headers_in.range;
    if (range == NULL) {
        return 0;
    }

    /* A multi-range header has at least two comma-separated ranges. */
    return (ngx_strlchr(range->value.data,
                        range->value.data + range->value.len,
                        ',') != NULL);
}
