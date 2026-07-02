/*
 * conditional.c — S3 conditional requests + response-header overrides (phase-43 W3).
 *
 * WHAT: Two GET/HEAD request modifiers that AWS S3 clients rely on:
 *   1. Conditional preconditions — If-Match / If-None-Match / If-Modified-Since
 *      / If-Unmodified-Since, evaluated with S3 semantics (304 Not Modified,
 *      412 PreconditionFailed).
 *   2. response-* query overrides — response-content-type / -content-disposition
 *      / -content-encoding / -content-language / -cache-control / -expires, which
 *      let a (pre)signed GET dictate the response headers (browser "save-as"
 *      download flows).
 *
 * WHY: nginx's core not-modified filter already covers If-None-Match, If-Match
 *   and If-Unmodified-Since, but its If-Modified-Since uses `exact` semantics
 *   (304 only when the date equals mtime), whereas S3 requires `before`
 *   semantics (304 when the object has NOT been modified since the date).  A
 *   single explicit evaluator here owns the full S3 contract and emits proper
 *   S3 XML for 412 (the core filter sends a bodyless 412).  It front-runs the
 *   core filter — it never disagrees with it, it only adds the future-date 304
 *   case and the XML body.
 *
 * HOW: Precondition evaluation delegates to the shared RFC 9110 §13.2.2
 *   evaluator xrootd_http_eval_preconditions() (core/http/http_conditionals.c)
 *   — GET/HEAD in READ|TIME mode (If-None-Match match ⇒ 304, S3 `before`
 *   If-Modified-Since semantics), conditional PUT in ETag-only write mode
 *   (match ⇒ 412).  This file owns only the S3 protocol edge: the XML 412
 *   body, the bare 304, the pre-body PUT existence probe, and the response-*
 *   overrides.  Overrides are applied from the serve pre-header hook so they
 *   win over the headers set_file_headers computed; every override value is
 *   rejected if it carries a control byte (defeats response-splitting), so
 *   they are safe to honor on any request without an open header-injection
 *   risk.
 */

#include "s3.h"
#include "core/http/etag.h"
#include "core/http/http_conditionals.h"
#include "core/http/http_headers.h"
#include "core/http/http_query.h"
#include "fs/vfs/vfs.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* response-* override values: decode, + → space, reject NUL, allow empty. */
#define S3_OVERRIDE_QUERY_FLAGS \
    (XROOTD_HTTP_QUERY_DECODE_VALUE | XROOTD_HTTP_QUERY_PLUS_TO_SPACE \
     | XROOTD_HTTP_QUERY_REJECT_NUL | XROOTD_HTTP_QUERY_ALLOW_EMPTY)

/*
 * Sending the conditional outcomes
 * */

ngx_int_t
s3_send_not_modified(ngx_http_request_t *r, const char *etag, time_t mtime)
{
    (void) s3_set_header(r, "ETag", etag);
    r->headers_out.last_modified_time = mtime;

    r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
    r->headers_out.content_length_n = 0;
    /* A bare 304 carries no body; the not-modified filter must not re-touch it. */
    r->disable_not_modified = 1;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

ngx_int_t
s3_send_precondition_failed(ngx_http_request_t *r)
{
    return s3_send_xml_error(r, NGX_HTTP_PRECONDITION_FAILED,
        "PreconditionFailed",
        "At least one of the preconditions you specified did not hold.");
}

/*
 * s3_handle_conditional — evaluate preconditions and, when they short-circuit,
 * send the 304/412 response.  Returns:
 *   NGX_DECLINED — caller should proceed to serve the object (no precondition,
 *                  or all preconditions passed);
 *   an HTTP rc   — a 304/412 response was sent; caller returns it.
 */
ngx_int_t
s3_handle_conditional(ngx_http_request_t *r, time_t mtime, off_t size)
{
    char      etag[48];
    ngx_int_t verdict;

    if (r->headers_in.if_match == NULL
        && r->headers_in.if_none_match == NULL
        && r->headers_in.if_modified_since == NULL
        && r->headers_in.if_unmodified_since == NULL)
    {
        return NGX_DECLINED;   /* no conditional headers — common fast path */
    }

    xrootd_http_etag_str(etag, sizeof(etag), mtime, size, 0);
    verdict = xrootd_http_eval_preconditions(r, 1 /* exists */, mtime, size,
        0, XROOTD_HTTP_COND_READ | XROOTD_HTTP_COND_TIME
           | XROOTD_HTTP_COND_WEAK_EQUIV);

    if (verdict == NGX_HTTP_NOT_MODIFIED) {
        return s3_send_not_modified(r, etag, mtime);
    }
    if (verdict == NGX_HTTP_PRECONDITION_FAILED) {
        return s3_send_precondition_failed(r);
    }
    return NGX_DECLINED;
}

/*
 * Conditional PUT (create-if-absent / overwrite-if-match)
 * */

/*
 * s3_put_precondition — evaluate If-None-Match / If-Match on a PutObject before
 * the body is read.
 *
 * WHAT: Implements S3 conditional writes:
 *   - If-None-Match: *           → 412 if the object already exists (atomic-ish
 *                                  create-if-absent; the canonical concurrency-
 *                                  safe write).
 *   - If-None-Match: "<etag>"    → 412 if the existing object carries that etag.
 *   - If-Match: * / "<etag>"     → 412 unless the object exists (and matches).
 * WHY: Lets clients implement compare-and-swap / create-once semantics without a
 *   separate HEAD round-trip; checked here (pre-body) so a doomed write never
 *   consumes the upload bandwidth.
 * HOW: A single confined stat of the destination yields existence + mtime/size;
 *   the verdict comes from the shared evaluator in ETag-only write mode (the
 *   same engine as the GET path, minus READ|TIME: a match ⇒ 412, never 304,
 *   and the date headers are not part of the S3 conditional-write contract).
 *
 * NOTE (atomicity): the existence test and the later staged-rename commit are
 *   not a single atomic step, so two racing If-None-Match:* creates of the same
 *   key can both pass here (last-writer-wins).  The window is the staged write
 *   duration; closing it fully needs renameat2(RENAME_NOREPLACE) plumbed through
 *   the confinement + impersonation rename path — a deliberate follow-up.
 *
 * Returns NGX_DECLINED to proceed with the write, or a 412 rc already sent.
 */
ngx_int_t
s3_put_precondition(ngx_http_request_t *r, const char *root_canon,
    const char *fs_path)
{
    ngx_table_elt_t  *if_none = r->headers_in.if_none_match;
    ngx_table_elt_t  *if_match = r->headers_in.if_match;
    int               exists = 0;
    xrootd_vfs_ctx_t  vctx;
    xrootd_vfs_stat_t vst;
    ngx_http_s3_req_ctx_t *s3ctx;
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    int               is_tls = 0;

    if (if_none == NULL && if_match == NULL) {
        return NGX_DECLINED;          /* unconditional PUT — fast path */
    }

    /*
     * Existence + synthetic-etag probe via the VFS metadata surface (OP_STAT,
     * metered + access-logged), delegating to the same confined no-follow
     * lstat underneath.  An object is only "exists" when it is a regular file;
     * a symlink at the key reports as non-regular and is treated as absent,
     * matching the S3 object model (the lister never emits symlinks).
     */
    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log, XROOTD_PROTO_S3,
        root_canon, cf->cache_root_canon, cf->common.allow_write, is_tls,
        (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);

    if (xrootd_vfs_stat(&vctx, &vst) == NGX_OK && vst.is_regular) {
        exists = 1;
    }

    if (xrootd_http_eval_preconditions(r, exists,
            exists ? vst.mtime : 0, exists ? vst.size : 0,
            0, XROOTD_HTTP_COND_WEAK_EQUIV) != NGX_OK)
    {
        return s3_send_precondition_failed(r);
    }

    return NGX_DECLINED;
}

/*
 * s3_put_is_exclusive_create — true when a PutObject carries `If-None-Match: *`,
 * i.e. the client asked for atomic create-if-absent.  W6b uses this to commit
 * with renameat2(RENAME_NOREPLACE) so two racing creates can't both win (the
 * stat-based precondition above only narrows, it cannot make it atomic).
 */
int
s3_put_is_exclusive_create(ngx_http_request_t *r)
{
    ngx_table_elt_t *if_none = r->headers_in.if_none_match;

    return if_none != NULL
           && if_none->value.len == 1
           && if_none->value.data[0] == '*';
}

/*
 * response-* header overrides (GET)
 * */

/* Copy a response-* override into a simple response header, rejecting control
 * bytes (response-splitting guard).  No-op when the param is absent. */
static void
s3_override_header(ngx_http_request_t *r, const char *param, const char *header)
{
    char   val[1024];
    size_t len;

    /* query_get returns 1 on success and NUL-terminates val; the decoded
     * length is strlen(val), NOT the return value. */
    if (xrootd_http_query_get(r->args, param, val, sizeof(val),
                              S3_OVERRIDE_QUERY_FLAGS) <= 0)
    {
        return;
    }
    len = ngx_strlen(val);
    if (len == 0 || xrootd_http_str_has_ctl((u_char *) val, len)) {
        return;
    }
    (void) xrootd_http_set_header(r, header, val, NULL);
}

void
s3_apply_response_overrides(ngx_http_request_t *r)
{
    char   ct[256];
    size_t len;

    if (r->args.len == 0) {
        return;
    }

    /* response-content-type overrides the computed Content-Type in-place. */
    if (xrootd_http_query_get(r->args, "response-content-type", ct, sizeof(ct),
                              S3_OVERRIDE_QUERY_FLAGS) > 0
        && (len = ngx_strlen(ct)) > 0
        && !xrootd_http_str_has_ctl((u_char *) ct, len))
    {
        u_char *p = ngx_pnalloc(r->pool, len);
        if (p != NULL) {
            ngx_memcpy(p, ct, len);
            r->headers_out.content_type.data    = p;
            r->headers_out.content_type.len     = len;
            r->headers_out.content_type_len     = len;
            r->headers_out.content_type_lowcase = NULL;
        }
    }

    s3_override_header(r, "response-content-disposition", "Content-Disposition");
    s3_override_header(r, "response-content-encoding",    "Content-Encoding");
    s3_override_header(r, "response-content-language",    "Content-Language");
    s3_override_header(r, "response-cache-control",       "Cache-Control");
    s3_override_header(r, "response-expires",             "Expires");
}

/*
 * s3_get_pre_header — serve-pipeline pre-header hook (xrootd_http_pre_header_fn).
 * Applies any response-* overrides after set_file_headers but before the
 * response headers are sent.
 */
void
s3_get_pre_header(ngx_http_request_t *r, ngx_fd_t fd, off_t file_size,
    void *userdata)
{
    (void) fd;
    (void) file_size;
    (void) userdata;
    s3_apply_response_overrides(r);
}
