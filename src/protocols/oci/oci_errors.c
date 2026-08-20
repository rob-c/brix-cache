/*
 * oci_errors.c — the §0.7.6 error envelope, the J.5 errno map, the guard line.
 *
 * WHAT: every way this plane says "no". One JSON envelope emitter, one
 *       errno → HTTP table for the read surface, one guard-core audit line,
 *       and the two response primitives (API-version header, complete-body
 *       send) the gate and the mirror handler share.
 * WHY:  a container client parses the envelope, not the status line: podman
 *       prints `code`/`message` straight to the operator, and `docker pull`
 *       distinguishes "repository does not exist" from "you are not allowed"
 *       purely by the code. Emitting the envelope in exactly one place is
 *       what keeps that contract from drifting per call site — and it is the
 *       same reason the errno map lives here rather than inline in the
 *       handler: the mapping is a POLICY (a full disk on a read is the
 *       ORIGIN's problem, hence 502, not the client's 500), and a policy
 *       spread over five call sites is a policy nobody can audit.
 * HOW:  two parallel tables indexed by brix_oci_err_t (no switch to fall out
 *       of sync with the enum), a bounded snprintf into a stack buffer, and
 *       the standard nginx send_header + one-buf output_filter tail. The
 *       envelope is emitted here, so callers return this function's rc, not
 *       the status — returning the status would have the core paint its own
 *       HTML error page over the JSON.
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/compat/error_mapping.h"
#include "core/http/http_headers.h"
#include "fs/scan/scan_record.h"           /* brix_scan_json_escape    */
#include "protocols/shared/guard_audit_http.h" /* the one audit-line emitter */

#include <errno.h>
#include <stdio.h>

/* Indexed by brix_oci_err_t. Index 0 (…_ERR_NONE) is the spec's catch-all:
 * an emitter that was handed no classifier verdict still owes the client a
 * well-formed envelope. */
static const char *const  oci_err_code_tab[] = {
    "UNKNOWN",
    "NAME_INVALID",
    "NAME_UNKNOWN",
    "MANIFEST_UNKNOWN",
    "MANIFEST_INVALID",
    "MANIFEST_BLOB_UNKNOWN",
    "BLOB_UNKNOWN",
    "BLOB_UPLOAD_UNKNOWN",
    "BLOB_UPLOAD_INVALID",
    "DIGEST_INVALID",
    "SIZE_INVALID",
    "UNAUTHORIZED",
    "DENIED",
    "UNSUPPORTED",
    "TOOMANYREQUESTS",
    "UNAVAILABLE"
};

/* The spec's recommended human message for each code, same order. These are
 * operator- and user-facing: podman prints them verbatim. */
static const char *const  oci_err_msg_tab[] = {
    "unknown error",
    "invalid repository name",
    "repository name not known to registry",
    "manifest unknown",
    "manifest invalid",
    "blob unknown to registry",
    "blob unknown to registry",
    "blob upload unknown to registry",
    "blob upload invalid",
    "provided digest did not match uploaded content",
    "provided length did not match content length",
    "authentication required",
    "requested access to the resource is denied",
    "the operation is unsupported",
    "too many requests",
    "service unavailable"
};

const char *
brix_oci_err_code(brix_oci_err_t err)
{
    if ((size_t) err >= sizeof(oci_err_code_tab) / sizeof(oci_err_code_tab[0])) {
        return oci_err_code_tab[0];
    }
    return oci_err_code_tab[err];
}

static const char *
oci_err_message(brix_oci_err_t err)
{
    if ((size_t) err >= sizeof(oci_err_msg_tab) / sizeof(oci_err_msg_tab[0])) {
        return oci_err_msg_tab[0];
    }
    return oci_err_msg_tab[err];
}

ngx_int_t
brix_oci_api_version_header(ngx_http_request_t *r)
{
    return brix_http_set_header(r, "Docker-Distribution-API-Version",
                                "registry/2.0", NULL);
}

ngx_int_t
brix_oci_send_body(ngx_http_request_t *r, ngx_uint_t status,
    const char *ctype, const u_char *body, size_t len)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    ngx_int_t    rc;

    r->headers_out.status           = status;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type.len  = ngx_strlen(ctype);
    r->headers_out.content_type.data = (u_char *) ctype;
    r->headers_out.content_type_len  = r->headers_out.content_type.len;

    if (brix_oci_api_version_header(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* A bodiless answer (the 201s this surface returns carry their whole
     * meaning in Location + Docker-Content-Digest) must go out as headers
     * only: a zero-length in-memory buf is not a "special" buf, so the write
     * filter logs "zero size buf in writer" and fails the request after the
     * header has already left. */
    if (len == 0) {
        r->header_only = 1;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    /* An in-memory body, never a file range: b->memory (invariant #2 — the
     * cleartext file-backed/sendfile path is for cached objects only). */
    b->pos            = (u_char *) body;
    b->last           = (u_char *) body + len;
    b->memory         = 1;
    b->last_buf       = (r == r->main) ? 1 : 0;
    b->last_in_chain  = 1;

    out.buf  = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

ngx_int_t
brix_oci_error(ngx_http_request_t *r, ngx_uint_t status,
    brix_oci_err_t err, const char *detail)
{
    char     esc[256];
    char     buf[640];
    u_char  *body;
    int      n;

    /* `detail` is operator- or upstream-supplied and lands inside a JSON
     * string: escape it, and drop it entirely rather than truncate mid-escape
     * if it will not fit (a half-escaped tail is a broken envelope). */
    if (detail != NULL
        && brix_scan_json_escape(detail, ngx_strlen(detail), esc, sizeof(esc))
           < 0)
    {
        detail = NULL;
    }

    n = snprintf(buf, sizeof(buf),
                 "{\"errors\":[{\"code\":\"%s\",\"message\":\"%s\"%s%s%s}]}\n",
                 brix_oci_err_code(err), oci_err_message(err),
                 (detail != NULL) ? ",\"detail\":\"" : "",
                 (detail != NULL) ? esc : "",
                 (detail != NULL) ? "\"" : "");
    if (n < 0 || (size_t) n >= sizeof(buf)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    body = ngx_pnalloc(r->pool, (size_t) n);
    if (body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(body, buf, (size_t) n);

    return brix_oci_send_body(r, status, "application/json", body,
                              (size_t) n);
}

void
brix_oci_guard_emit(ngx_http_request_t *r, guard_reason_t reason,
    guard_op_class_t op, ngx_uint_t status)
{
    brix_http_guard_audit(r, "oci", reason, op, status);
}

ngx_int_t
brix_oci_refuse(ngx_http_request_t *r, ngx_uint_t status, brix_oci_err_t err,
    const char *detail)
{
    ngx_int_t  rc = brix_oci_error(r, status, err, detail);

    /* brix_oci_error() answers NGX_OK when the envelope went out — the same
     * value every seam in this module uses for "carry on". A refusal that
     * travels back through such a seam therefore has to arrive as something
     * else, or the request proceeds past its own denial and answers twice.
     * NGX_DONE is that value; each caller translates it at its own boundary
     * (never returning it from an nginx content handler, which would leave
     * the request suspended). */
    return (rc == NGX_OK) ? NGX_DONE : rc;
}


ngx_uint_t
brix_oci_errno_status(ngx_http_request_t *r, int err)
{
    if (err == ENOENT || err == ENOTDIR || err == ENAMETOOLONG) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* The confinement cascade refused the open. On a plane whose every path
     * component came out of a validating classifier this cannot be a client
     * spelling — it is a store whose permissions or symlinks have drifted,
     * or a genuine escape attempt. Say so once, loudly, with the signal the
     * fail2ban filter keys on. */
    if (err == EACCES || err == EPERM || err == ELOOP || err == EXDEV) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, err,
            "oci: store open refused signal=oci_path_escape uri=\"%V\" "
            "client=%V", &r->uri, &r->connection->addr_text);
        return NGX_HTTP_FORBIDDEN;
    }

    /* Read surface: a bad or full store is the CACHE's failure, and from the
     * client's seat the mirror is a gateway — 502, never a 500 that would
     * have podman blame its own request. */
    if (err == EIO || err == ENOSPC || err == EDQUOT) {
        return NGX_HTTP_BAD_GATEWAY;
    }

    return brix_http_errno_to_status(err);
}
