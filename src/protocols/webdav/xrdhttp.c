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
