#ifndef BRIX_CACHE_ORIGIN_S3_TRANSPORT_INTERNAL_H
#define BRIX_CACHE_ORIGIN_S3_TRANSPORT_INTERNAL_H

/*
 * s3_transport_internal.h — shared internals of the libcurl origin transport,
 * split across two translation units with NO behavior change:
 *   s3_transport.c        — response capture buffers + callbacks, the request
 *                           execution body, the vtable entry points/accessors.
 *   s3_transport_setup.c  — operator policy (globals + public setters), the
 *                           per-thread curl handle lifecycle, per-request curl
 *                           option configuration, and the upstream trace line.
 * Not a public interface; see s3_transport.h for the exported transport vtable.
 */

#include <curl/curl.h>
#include <stddef.h>

/* Transport-private response: the captured body + raw response header block. */
typedef struct {
    char   *body;
    size_t  body_len;
    size_t  body_cap;
    char   *hdrs;          /* raw "Name: value\r\n" lines as received */
    size_t  hdrs_len;
    size_t  hdrs_cap;
} s3o_resp_t;

/* s3o_request_t — one origin request's inputs, shared by the plain and
 * cred-scoped transport slots.
 *
 * WHAT: The immutable inputs of a single synchronous libcurl request: the
 *       target (host/port/tls), the HTTP call (method/path/headers/body), the
 *       caller timeout, the OPTIONAL mutual-TLS client cert, and the operator CA
 *       context (`tctx`).
 * WHY:  Both vtable entry points (s3o_request / s3o_request_cred) pass the same
 *       dozen-plus arguments straight through to one shared body; collapsing
 *       them into a file-local descriptor keeps the shared body and its extracted
 *       helpers at one argument instead of fourteen, with no behavior change.
 * HOW:  `tctx` is the transport's OPTIONAL context — a NUL-terminated CA
 *       file-or-dir PATH (the operator's trusted CA for origin TLS), or NULL for
 *       libcurl's system bundle; applied via s3o_apply_ca(). `client_cert_pem`
 *       is NULL for the plain slot; on a `tls` request a non-empty path is
 *       presented as the mutual-TLS client cert (cert chain + key in one PEM). */
typedef struct {
    void        *tctx;             /* operator CA path (via s3o_apply_ca), or NULL */
    const char  *host;
    int          port;
    int          tls;
    const char  *method;
    const char  *path_and_query;
    const char  *headers;
    const void  *body;
    size_t       body_len;
    int          timeout_ms;
    const char  *client_cert_pem;  /* mutual-TLS client PEM, or NULL (plain slot) */
} s3o_request_t;

/* s3o_trace_t — the fields of one upstream-request trace line.
 *
 * WHAT: Bundles the request-identity (method/host/port/path) plus the outcome
 *       (status/bytes/duration/error) that s3o_trace() formats into a single
 *       line.
 * WHY:  The trace inputs were passed as 8 loose params; a small file-local
 *       descriptor keeps the emit signature at one argument and lets the two
 *       call sites (transport failure vs HTTP outcome) fill a stack struct in
 *       place with no behavior change.
 * HOW:  `status` < 0 marks a transport-level failure (curl error text in
 *       `err`); otherwise it is the HTTP status and `err` is NULL. `path` is
 *       wire-derived and gets sanitized by s3o_trace(). */
typedef struct {
    const char *method;
    const char *host;
    int         port;
    const char *path;              /* path_and_query, wire-derived → sanitized */
    int         status;            /* < 0 = transport failure, else HTTP status */
    size_t      bytes;
    long        dur_ms;
    const char *err;               /* curl error text when status < 0, else NULL */
    const char *proto;             /* negotiated HTTP version token, or NULL     */
} s3o_trace_t;

/* Response-capture callbacks — defined in s3_transport.c, wired into a curl
 * handle by s3o_configure() in s3_transport_setup.c. */
size_t s3o_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t s3o_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata);

/* Per-thread warm curl handle, reset and ready for a new request; NULL only on
 * alloc failure. Defined in s3_transport_setup.c. */
CURL *s3o_curl_acquire(void);

/* Build the curl_slist for one request (defined in s3_transport_setup.c). */
struct curl_slist *s3o_build_headers(const s3o_request_t *req);

/* Set every per-request curl option for `req` on `curl` (defined in
 * s3_transport_setup.c). `r` binds the response-capture callbacks; `slist` is
 * the caller-owned header list. */
void s3o_configure(CURL *curl, const s3o_request_t *req, s3o_resp_t *r,
                   struct curl_slist *slist);

/* Emit one upstream-request trace line (defined in s3_transport_setup.c). */
void s3o_trace(const s3o_trace_t *t);

/* The HTTP version the origin actually negotiated, as a short token ("1.1",
 * "2", …), or NULL when libcurl cannot say (defined in s3_transport_setup.c). */
const char *s3o_negotiated_proto(CURL *curl);

#endif /* BRIX_CACHE_ORIGIN_S3_TRANSPORT_INTERNAL_H */
