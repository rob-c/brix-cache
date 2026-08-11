/*
 * xrdhttp.c — XrdHttp protocol extension support for the nginx-xrootd WebDAV module.
 *
 * WHAT: Implements XrdHttp parity features on top of the existing WebDAV handler:
 *   - Request parsing: X-Xrootd-Proto detection, ?xrd.* / ?tpc.* query params,
 *     X-Xrootd-Requuid / X-Xrootd-Tpc-Token header capture.
 *   - Response injection: X-Xrootd-Requuid echo, X-Xrootd-Status kXR error codes,
 *     X-Xrootd-Wait / X-Xrootd-Retry back-pressure headers.
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
 * Normalize ONE RFC 3230 algorithm token (no list handling) to the internal
 * name used by brix_checksum_parse(): trims surrounding whitespace,
 * lowercases, and strips hyphens so that "SHA-256" → "sha256", "SHA-1" →
 * "sha1", "CRC32c" → "crc32c".  The bare RFC 3230 name "SHA" (meaning SHA-1)
 * is mapped to "sha1" as a special case.
 */
static void
xrdhttp_normalize_one_rfc3230_token(const u_char *token, size_t token_len,
                                     char *dst, size_t dstsz)
{
    const u_char *cursor = token;
    size_t        out = 0;
    size_t        i;

    /* Trim leading/trailing whitespace. */
    while (token_len > 0 && (*cursor == ' ' || *cursor == '\t')) {
        cursor++;
        token_len--;
    }
    while (token_len > 0 && (cursor[token_len - 1] == ' '
                             || cursor[token_len - 1] == '\t')) {
        token_len--;
    }

    /* Lowercase, strip hyphens: "sha-256" → "sha256". */
    for (i = 0; i < token_len && out < dstsz - 1; i++) {
        if (cursor[i] != '-') {
            dst[out++] = (char) tolower((unsigned char) cursor[i]);
        }
    }
    dst[out] = '\0';

    /* RFC 3230 bare "sha" means SHA-1. */
    if (strcmp(dst, "sha") == 0 && dstsz >= 5) {
        ngx_memcpy(dst, "sha1", 5);
    }
}

/*
 * Normalize an RFC 3230 algorithm list by its FIRST token only (q-values and
 * later alternatives ignored) — the historical behavior, kept as the fallback
 * when q-negotiation finds no supported candidate so the downstream
 * "unsupported algorithm" refusal path is byte-identical to before.
 */
static void
xrdhttp_normalize_rfc3230_algo(const u_char *value, size_t vlen,
                                char *dst, size_t dstsz)
{
    const u_char *end;

    for (end = value;
         (size_t)(end - value) < vlen && *end != ',' && *end != ';';
         end++)
        ;
    xrdhttp_normalize_one_rfc3230_token(value, (size_t)(end - value),
                                         dst, dstsz);
}

/* Parse a bare qvalue (leading '0' or '1', optional up to three decimals) that
 * runs from `cursor` to `entry_end`, into thousandths (0..1000).  Malformed →
 * permissive 1000. */
static int
q_value_millis(const u_char *cursor, const u_char *entry_end)
{
    int q_millis;

    if (cursor >= entry_end || (*cursor != '0' && *cursor != '1')) {
        return 1000;                      /* malformed — keep permissive */
    }
    q_millis = (*cursor == '1') ? 1000 : 0;
    cursor++;
    if (cursor < entry_end && *cursor == '.') {
        int scale = 100;

        cursor++;
        for (int digits = 0;
             cursor < entry_end && digits < 3 && *cursor >= '0' && *cursor <= '9';
             digits++, cursor++)
        {
            q_millis += (*cursor - '0') * scale;
            scale /= 10;
        }
    }
    return q_millis > 1000 ? 1000 : q_millis;
}

/*
 * Parse the ";q=..." parameter of one Want-Digest entry into thousandths
 * (RFC 7231 qvalue: 0..1 with up to three decimals → 0..1000).  `params`
 * points at the first ';' (or == entry_end when the entry has no parameters).
 * Absent or unparseable q defaults to 1000; an explicit q=0 (in any spelling)
 * returns 0, which disqualifies the entry.
 */
static int
xrdhttp_rfc3230_q_millis(const u_char *params, const u_char *entry_end)
{
    const u_char *cursor = params;

    while (cursor < entry_end) {
        if (*cursor != ';') {
            cursor++;
            continue;
        }
        cursor++;
        while (cursor < entry_end && (*cursor == ' ' || *cursor == '\t')) {
            cursor++;
        }
        if (entry_end - cursor < 2
            || (cursor[0] != 'q' && cursor[0] != 'Q') || cursor[1] != '=')
        {
            continue;
        }
        cursor += 2;
        return q_value_millis(cursor, entry_end);
    }

    return 1000;                          /* no q parameter — default 1.0 */
}

/* ---- Pick the best supported algorithm from an RFC 3230 Want-Digest list ----
 *
 * WHAT: Walks the full comma-separated Want-Digest value — each entry an
 *       algorithm token with an optional ";q=" quality — and writes into dst
 *       the highest-q entry this server can actually compute.  When no entry
 *       is both supported and acceptable (q>0): an ACCEPTABLE-but-unsupported
 *       list falls back to the historical first-token normalization so the
 *       downstream refusal path is unchanged, while a list whose every entry
 *       carries q=0 yields the empty string — the client explicitly refused
 *       every algorithm, so no digest may be computed on its behalf.
 *
 * WHY:  §6.4 parity: RFC 3230 lets a client rank alternatives
 *       ("md5;q=0.4, sha-256;q=0.9").  Honoring only the first token made the
 *       server compute an unwanted digest — or refuse outright — whenever a
 *       client led with an algorithm this build lacks; and RFC 7231 q=0 means
 *       "not acceptable", which a first-token reader silently ignored.
 *
 * HOW:  1. Split on ','; within an entry the token runs to the first ';'.
 *       2. q = xrdhttp_rfc3230_q_millis (absent → 1000; q=0 disqualifies).
 *       3. Normalize each q>0 token and probe brix_checksum_parse — NGX_OK
 *          means this build computes it.
 *       4. Keep the supported entry with the strictly highest q (ties keep
 *          the earlier entry, preserving the client's list order).
 *       5. Nothing kept: any q>0 entry seen → xrdhttp_normalize_rfc3230_algo
 *          fallback; all entries q=0 → dst = "".
 */
static void
xrdhttp_select_rfc3230_algo(const u_char *value, size_t vlen,
                             char *dst, size_t dstsz)
{
    const u_char *cursor = value;
    const u_char *end = value + vlen;
    int           best_q_millis = -1;
    int           any_acceptable = 0;

    dst[0] = '\0';

    while (cursor < end) {
        const u_char *entry_end = cursor;
        const u_char *token_end;
        char          candidate[64];
        int           q_millis;

        while (entry_end < end && *entry_end != ',') {
            entry_end++;
        }
        token_end = cursor;
        while (token_end < entry_end && *token_end != ';') {
            token_end++;
        }

        q_millis = xrdhttp_rfc3230_q_millis(token_end, entry_end);
        xrdhttp_normalize_one_rfc3230_token(cursor,
                                             (size_t)(token_end - cursor),
                                             candidate, sizeof(candidate));

        if (candidate[0] != '\0' && q_millis > 0) {
            any_acceptable = 1;

            if (q_millis > best_q_millis) {
                brix_checksum_alg_t alg;
                char                canonical[32];

                if (brix_checksum_parse(candidate, strlen(candidate), &alg,
                                          canonical,
                                          sizeof(canonical)) == NGX_OK)
                {
                    best_q_millis = q_millis;
                    ngx_cpystrn((u_char *) dst, (u_char *) candidate, dstsz);
                }
            }
        }

        cursor = entry_end + 1;           /* step past the ',' */
    }

    if (best_q_millis < 0 && any_acceptable) {
        xrdhttp_normalize_rfc3230_algo(value, vlen, dst, dstsz);
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

/*
 * §6.5 http.header2cgi: for each configured (header, cgikey) pair, append the
 * incoming header's value to the xrd opaque blob as "&<cgikey>=<value>" (or
 * "<cgikey>=<value>" when the opaque was empty). Downstream authz (token/scope,
 * xrd.* opaque) and the backend both read ctx->opaque, so a site can bridge an
 * arbitrary request header into the request's CGI exactly as XrdHttp does.
 * Bounded to XRDHTTP_OPAQUE_MAX; a value that would overflow stops the loop.
 */
static void
xrdhttp_apply_header2cgi(ngx_http_request_t *r, xrdhttp_req_ctx_t *ctx)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf;
    ngx_keyval_t                    *kv;
    ngx_uint_t                       i;
    size_t                           len;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (wlcf == NULL || wlcf->header2cgi == NULL) {
        return;
    }
    kv  = wlcf->header2cgi->elts;
    len = ngx_strlen(ctx->opaque);

    for (i = 0; i < wlcf->header2cgi->nelts; i++) {
        char     val[256];
        u_char  *end;

        val[0] = '\0';
        xrdhttp_capture_header(r, (const char *) kv[i].key.data, kv[i].key.len,
                               val, sizeof(val));
        if (val[0] == '\0' || len + 2 >= XRDHTTP_OPAQUE_MAX) {
            continue;
        }
        end = ngx_snprintf((u_char *) ctx->opaque + len,
                           XRDHTTP_OPAQUE_MAX - len, "%s%V=%s",
                           len ? "&" : "", &kv[i].value, val);
        len = (size_t) (end - (u_char *) ctx->opaque);
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
    xrdhttp_apply_header2cgi(r, ctx);

    /* Want-Digest (RFC 3230): XrdClHttp sends this on HEAD to request
     * checksums.  Only consulted when ?xrd.want.cksum= was not supplied
     * (the query param takes priority).  Full q-value negotiation (§6.4):
     * the highest-q algorithm this build supports wins, not the first token. */
    if (!ctx->want_cksum[0]) {
        h = webdav_tpc_find_header(r, "Want-Digest", sizeof("Want-Digest") - 1);
        if (h != NULL && h->value.len > 0) {
            xrdhttp_select_rfc3230_algo(h->value.data, h->value.len,
                                        ctx->want_cksum,
                                        sizeof(ctx->want_cksum));
        }
    }

    xrdhttp_log_client_identity(r, ctx);
}
