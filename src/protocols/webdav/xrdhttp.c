/*
 * xrdhttp.c — XrdHttp protocol extension support for the nginx-xrootd WebDAV module.
 *
 * WHAT: Implements XrdHttp parity features on top of the existing WebDAV handler:
 *   - Request parsing: X-Xrootd-Proto detection, ?xrd.* / ?tpc.* query params,
 *     X-Xrootd-Requuid / X-Xrootd-Tpc-Token header capture.
 *   - Response injection: X-Xrootd-Requuid echo, X-Xrootd-Status kXR error codes,
 *     X-Xrootd-Wait / X-Xrootd-Retry back-pressure headers.
 *   - Redirect dialect: X-Xrootd-Redir-Host/Port + tpc.key / xrd.opaque passthrough.
 *   - TPC shim: synthesise Source:/Destination: headers from ?tpc.src= / ?tpc.dst=.
 *   - Checksum: Digest: header computed on-demand for xrd.want.cksum requests.
 *   - HTTP→kXR status mapping for X-Xrootd-Status.
 *
 * WHY: XRootD-aware clients (xrdcp --prefer-xrdhttp, ROOT TFile, davix-get with XRD
 * hints) negotiate the protocol version via X-Xrootd-Proto and rely on X-Xrootd-Status
 * to distinguish between "file not found", "not authorised", "server busy" etc. without
 * parsing HTTP status codes.  Without this layer clients fall back to slow error-path
 * retries or misinterpret error conditions.
 *
 * HOW: A single per-request context struct (xrdhttp_req_ctx_t) is allocated from r->pool
 * by xrdhttp_get_ctx() the first time any XrdHttp function is called.  Parsing functions
 * walk r->headers_in and the raw r->args query string; they write NUL-terminated results
 * into fixed-size fields (no dynamic allocation) and silently truncate over-length values
 * so that untrusted client data cannot cause unbounded memory use.  All values written to
 * logs pass through brix_sanitize_log_string().
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

/* context management */
xrdhttp_req_ctx_t *
xrdhttp_get_ctx(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *webdav_ctx;

    webdav_ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (webdav_ctx != NULL) {
        /* xrdhttp is the first member — cast is well-defined by C11 §6.7.2.1p15. */
        return &webdav_ctx->xrdhttp;
    }

    /* Allocate the full webdav context (xrdhttp fields zero-initialised by pcalloc).
     * This path is hit on unauthenticated requests where auth_cert.c / auth_token.c
     * never allocated the context themselves. */
    BRIX_PCALLOC_OR_RETURN(webdav_ctx, r->pool, sizeof(ngx_http_brix_webdav_req_ctx_t), NULL);
    ngx_http_set_ctx(r, webdav_ctx, ngx_http_brix_webdav_module);
    return &webdav_ctx->xrdhttp;
}

/* query string helpers */
/*
 * Copy the value of query parameter <key> from the raw nginx args string into
 * <dst> (max <dstsz> bytes including NUL terminator).  Performs URL-decoding
 * of %HH sequences in the value.  Silently truncates if the decoded value
 * would overflow dst.  Returns 1 on match, 0 if key not found.
 */
static int
xrdhttp_args_get(const ngx_str_t *args, const char *key, size_t key_len,
                 char *dst, size_t dstsz)
{
    (void) key_len;

    return brix_http_query_get(*args, key, dst, dstsz,
                                 BRIX_HTTP_QUERY_CASE_INSENSITIVE
                                 | BRIX_HTTP_QUERY_DECODE_VALUE
                                 | BRIX_HTTP_QUERY_PLUS_TO_SPACE
                                 | BRIX_HTTP_QUERY_REJECT_NUL
                                 | BRIX_HTTP_QUERY_ALLOW_EMPTY
                                 | BRIX_HTTP_QUERY_TRUNCATE) > 0;
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

/*
 * Normalize an RFC 3230 algorithm token to the internal name used by
 * brix_checksum_parse().  Extracts the first token from a comma-separated
 * list (ignoring q-value suffixes), lowercases it, and strips hyphens so that
 * "SHA-256" → "sha256", "SHA-1" → "sha1", "CRC32c" → "crc32c".  The bare
 * RFC 3230 name "SHA" (meaning SHA-1) is mapped to "sha1" as a special case.
 */
static void
xrdhttp_normalize_rfc3230_algo(const u_char *value, size_t vlen,
                                char *dst, size_t dstsz)
{
    const u_char *p = value;
    const u_char *end;
    size_t        out = 0;
    size_t        i;

    /* First token only (up to ',' or ';'). */
    for (end = p; (size_t)(end - p) < vlen && *end != ',' && *end != ';'; end++)
        ;
    vlen = (size_t)(end - p);

    /* Trim leading/trailing whitespace. */
    while (vlen > 0 && (*p == ' ' || *p == '\t')) { p++; vlen--; }
    while (vlen > 0 && (p[vlen - 1] == ' ' || p[vlen - 1] == '\t')) { vlen--; }

    /* Lowercase, strip hyphens: "sha-256" → "sha256". */
    for (i = 0; i < vlen && out < dstsz - 1; i++) {
        if (p[i] != '-') {
            dst[out++] = (char) tolower((unsigned char) p[i]);
        }
    }
    dst[out] = '\0';

    /* RFC 3230 bare "sha" means SHA-1. */
    if (strcmp(dst, "sha") == 0 && dstsz >= 5) {
        ngx_memcpy(dst, "sha1", 5);
    }
}

/* request parsing */

/*
 * WHAT: Copy a header value into a fixed-size ctx field, NUL-terminated and
 *       silently truncated to cap-1 bytes.
 * WHY:  Requuid / Tpc-Token capture shares identical bounded-copy logic;
 *       centralising it removes duplicated ngx_min/memcpy boilerplate.
 * HOW:  No-op when the header is absent or empty; otherwise copies at most
 *       cap-1 bytes and writes the terminator.
 */
static void
xrdhttp_capture_header(ngx_http_request_t *r, const char *name,
                       size_t name_len, char *dst, size_t cap)
{
    ngx_table_elt_t *h = webdav_tpc_find_header(r, name, name_len);

    if (h != NULL && h->value.len > 0) {
        size_t copy = ngx_min(h->value.len, cap - 1);
        ngx_memcpy(dst, h->value.data, copy);
        dst[copy] = '\0';
    }
}

/*
 * WHAT: Detect the XrdHttp dialect and its digest/version hints from headers.
 * WHY:  X-Xrootd-Proto flags an XrdHttp client and gates the adler32 streaming
 *       digest (Want-Digest), which is only meaningful for such clients.
 * HOW:  Sets ctx->is_xrdhttp + proto_version from X-Xrootd-Proto, then arms
 *       ctx->compute_digest when an XrdHttp client asks for adler32.
 */
static void
xrdhttp_parse_proto_headers(ngx_http_request_t *r, xrdhttp_req_ctx_t *ctx)
{
    ngx_table_elt_t *h;

    h = webdav_tpc_find_header(r, "X-Xrootd-Proto",
                               sizeof("X-Xrootd-Proto") - 1);
    if (h != NULL) {
        ctx->is_xrdhttp = 1;
        ngx_cpystrn((u_char *) ctx->proto_version,
                    h->value.data,
                    ngx_min(h->value.len + 1,
                            (size_t) sizeof(ctx->proto_version)));

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrdhttp: X-Xrootd-Proto=\"%s\"",
                       ctx->proto_version);
    }

    /* Want-Digest: adler32 (RFC 3230) enables the streaming body digest.
     * Only meaningful for XrdHttp clients; the body filter folds the response
     * through adler32 and emits a Digest trailer. Only adler32 streams here.
     * Other algorithms (crc32c, crc64, crc64nvme, md5, sha) are computed from
     * the fd via xrdhttp_add_checksum_header() because they are not folded
     * incrementally over the response body in this filter. */
    h = webdav_tpc_find_header(r, "Want-Digest", sizeof("Want-Digest") - 1);
    if (ctx->is_xrdhttp && h != NULL && h->value.len > 0
        && ngx_strcasestrn(h->value.data, "adler32",
                           sizeof("adler32") - 2) != NULL)
    {
        ctx->compute_digest = 1;
    }
}

/*
 * WHAT: Copy the ?xrd.* / ?tpc.* query parameters into their ctx fields.
 * WHY:  XrdHttp clients can signal client identity, checksum wants, opaque
 *       data and TPC endpoints via the query string.
 * HOW:  No-op when there is no query string; otherwise decodes each known key
 *       into its bounded ctx buffer (truncating over-length values).
 */
static void
xrdhttp_parse_query_params(ngx_http_request_t *r, xrdhttp_req_ctx_t *ctx)
{
    if (r->args.len == 0) {
        return;
    }

    xrdhttp_args_get(&r->args, "xrd.clnt.uuid",
                     sizeof("xrd.clnt.uuid") - 1,
                     ctx->clnt_uuid, sizeof(ctx->clnt_uuid));

    xrdhttp_args_get(&r->args, "xrd.clnt.app",
                     sizeof("xrd.clnt.app") - 1,
                     ctx->clnt_app, sizeof(ctx->clnt_app));

    xrdhttp_args_get(&r->args, "xrd.want.cksum",
                     sizeof("xrd.want.cksum") - 1,
                     ctx->want_cksum, sizeof(ctx->want_cksum));

    xrdhttp_args_get(&r->args, "xrd.opaque",
                     sizeof("xrd.opaque") - 1,
                     ctx->opaque, sizeof(ctx->opaque));

    xrdhttp_args_get(&r->args, "tpc.src",
                     sizeof("tpc.src") - 1,
                     ctx->tpc_src, sizeof(ctx->tpc_src));

    xrdhttp_args_get(&r->args, "tpc.dst",
                     sizeof("tpc.dst") - 1,
                     ctx->tpc_dst, sizeof(ctx->tpc_dst));

    xrdhttp_args_get(&r->args, "tpc.key",
                     sizeof("tpc.key") - 1,
                     ctx->tpc_key, sizeof(ctx->tpc_key));
}

/*
 * WHAT: Emit sanitised debug lines for the parsed client identity + checksum.
 * WHY:  Untrusted client values must be escaped before logging; keeping the
 *       (debug-only) formatting out of the main path keeps it simple.
 * HOW:  Sanitises app/uuid and the requested checksum algorithm via
 *       brix_sanitize_log_string() before logging at debug level.
 */
static void
xrdhttp_log_client_identity(ngx_http_request_t *r, xrdhttp_req_ctx_t *ctx)
{
    if (ctx->clnt_app[0] || ctx->clnt_uuid[0]) {
        char safe_app[sizeof(ctx->clnt_app) * 4];
        char safe_uuid[sizeof(ctx->clnt_uuid) * 4];
        brix_sanitize_log_string(ctx->clnt_app,
                                   safe_app, sizeof(safe_app));
        brix_sanitize_log_string(ctx->clnt_uuid,
                                   safe_uuid, sizeof(safe_uuid));
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrdhttp: client app=\"%s\" uuid=\"%s\"",
                       safe_app, safe_uuid);
    }

    if (ctx->want_cksum[0]) {
        char safe_alg[sizeof(ctx->want_cksum) * 4];
        brix_sanitize_log_string(ctx->want_cksum,
                                   safe_alg, sizeof(safe_alg));
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrdhttp: client requests checksum alg=\"%s\"",
                       safe_alg);
    }
}

void
xrdhttp_parse_request(ngx_http_request_t *r)
{
    xrdhttp_req_ctx_t *ctx;
    ngx_table_elt_t   *h;

    ctx = xrdhttp_get_ctx(r);
    if (ctx == NULL) {
        return;
    }

    xrdhttp_parse_proto_headers(r, ctx);

    /* Capture X-Xrootd-Requuid (echo in every response). */
    xrdhttp_capture_header(r, "X-Xrootd-Requuid",
                           sizeof("X-Xrootd-Requuid") - 1,
                           ctx->requuid, XRDHTTP_UUID_MAX);

    /* Capture X-Xrootd-Tpc-Token. */
    xrdhttp_capture_header(r, "X-Xrootd-Tpc-Token",
                           sizeof("X-Xrootd-Tpc-Token") - 1,
                           ctx->tpc_token, XRDHTTP_TPC_KEY_MAX);

    xrdhttp_parse_query_params(r, ctx);

    /* Want-Digest (RFC 3230): XrdClHttp sends this on HEAD to request
     * checksums.  Only consulted when ?xrd.want.cksum= was not supplied
     * (the query param takes priority). */
    if (!ctx->want_cksum[0]) {
        h = webdav_tpc_find_header(r, "Want-Digest", sizeof("Want-Digest") - 1);
        if (h != NULL && h->value.len > 0) {
            xrdhttp_normalize_rfc3230_algo(h->value.data, h->value.len,
                                           ctx->want_cksum,
                                           sizeof(ctx->want_cksum));
        }
    }

    xrdhttp_log_client_identity(r, ctx);
}

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
