/*
 * sd_s3_transport.h — pluggable HTTP transport for the shared S3 storage driver.
 *
 * WHAT: The narrow HTTP request/response interface the S3 driver (sd_s3.c) needs,
 *       so the S3 *protocol* logic (request building, SigV4, range GET, multipart
 *       upload, XML) can live once in src/fs/backend/ while the actual HTTP
 *       transport is injected per consumer.
 * WHY:  The S3 backend was client-only because it was welded to the client's
 *       hand-rolled HTTP/1.1 stack (xrdc_http_*). src/ cannot depend on
 *       client/lib, and the server has no HTTP-client substrate. Injecting the
 *       transport breaks that coupling: the userland client fills it with
 *       xrdc_http; a future server consumer (e.g. an S3 cache origin) fills it
 *       with its own. The driver code is shared either way.
 * HOW:  Pure C, ngx-free. One synchronous request op + response accessors. The
 *       response carries a transport-private `opaque` handle (the consumer's real
 *       response object); the driver only ever reaches it through these accessors
 *       and frees it via resp_free.
 */
#ifndef BRIX_SD_S3_TRANSPORT_H
#define BRIX_SD_S3_TRANSPORT_H

#include <stddef.h>
#include <sys/types.h>   /* ssize_t */

/* A transport-agnostic response handle. status is the HTTP status code; opaque
 * is the transport's own response object, reached only via the accessors below. */
typedef struct {
    int   status;
    void *opaque;
} brix_s3_resp_t;

typedef struct brix_s3_transport_s {
    /* Perform one HTTP request. `path_and_query` is the already-encoded
     * "/key?canon-query" (or "/key"); `headers` is the pre-built header block
     * (the SigV4 Authorization + x-amz-* lines). On success fills *resp and
     * returns 0; on a transport-level failure returns -1 and writes a message
     * into errbuf[errcap]. A non-2xx HTTP status is NOT a failure here — it is
     * reported via resp->status for the driver to map. */
    int (*request)(void *tctx,
                   const char *host, int port, int tls,
                   const char *method, const char *path_and_query,
                   const char *headers, const void *body, size_t body_len,
                   int timeout_ms, brix_s3_resp_t *resp,
                   char *errbuf, size_t errcap);

    /* OPTIONAL — like `request`, plus a per-request TLS client certificate
     * (mutual-TLS) so a caller can authenticate the upstream leg AS the end
     * user (phase-70 §5.1 x509 pass-through/select over an https backend leg).
     *
     * `client_cert_pem` is a filesystem PATH to a PEM file holding the user's
     * proxy — certificate chain AND private key in one file (the same on-disk
     * form the GSI origin presenter consumes, see origin_auth.c). When non-NULL
     * on a `tls` request the transport presents it as the client cert on the
     * handshake; NULL means "no client cert" (identical to `request`).
     *
     * A transport that cannot present a client cert leaves this slot NULL; the
     * sd_http driver treats a NULL slot as "GSI-over-https unsupported" and
     * (in deny mode) refuses rather than silently falling back to anonymous. */
    int (*request_cred)(void *tctx,
                        const char *host, int port, int tls,
                        const char *method, const char *path_and_query,
                        const char *headers, const void *body, size_t body_len,
                        int timeout_ms, const char *client_cert_pem,
                        brix_s3_resp_t *resp, char *errbuf, size_t errcap);

    /* Copy response header `name` into out[outcap] (NUL-terminated). 0 if found,
     * -1 if absent. */
    int (*resp_header)(const brix_s3_resp_t *resp, const char *name,
                       char *out, size_t outcap);

    /* OPTIONAL — the raw response header block ("Name: value" lines separated
     * by CRLF/LF, NUL-terminated; valid until resp_free). Lets the driver
     * ENUMERATE headers (generic x-amz-meta-* listxattr), which the by-name
     * resp_header lookup cannot. A transport that does not retain the raw
     * block leaves this NULL; the driver must then report enumeration as
     * unsupported (ENOTSUP), never guess names. */
    const char *(*resp_headers_raw)(const brix_s3_resp_t *resp);

    /* The response body bytes + length (valid until resp_free). */
    const void *(*resp_body)(const brix_s3_resp_t *resp, size_t *len);

    /* Release the transport-private response. */
    void (*resp_free)(brix_s3_resp_t *resp);
} brix_s3_transport_t;

#endif /* BRIX_SD_S3_TRANSPORT_H */
