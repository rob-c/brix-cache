/*
 * sts_internal.h — cross-file contract for the S3 STS exchange (phase-79 split).
 *
 * WHAT: the shared structs, constants and entry points that the three STS
 *       translation units (`sts.c` orchestrator, `sts_sign.c` SigV4 request
 *       builder, `sts_http.c` transport + XML parser) exchange across their
 *       file boundaries. Nothing here is part of the public API — callers use
 *       only `sts.h`.
 * WHY:  the STS client was one 815-line file; splitting it by concern (build,
 *       transport, orchestrate) keeps each file under the 500-line focus limit,
 *       but the three pieces still share the request/response state structs and
 *       a handful of pure entry points. Declaring those once here — instead of
 *       duplicating the typedefs — is what keeps the split behaviour-identical:
 *       every file sees the exact same struct layout and function signature.
 * HOW:  include after "sts.h" (for brix_s3_sts_conf_t / brix_identity_t). It
 *       declares sts_req_t / sts_resp_t / sts_creds_buf_t, the response size
 *       cap, and the four non-static seam functions the orchestrator calls into.
 *
 * Requires: sts.h (brix_s3_sts_conf_t, brix_identity_t) before inclusion.
 */
#ifndef BRIX_AUTH_S3_STS_INTERNAL_H
#define BRIX_AUTH_S3_STS_INTERNAL_H

#include "sts.h"

/* Bound on a captured STS response body — a hostile/huge reply cannot exhaust
 * memory. Shared by the transport buffer (sts_http.c) and its allocator (sts.c). */
#define BRIX_STS_RESP_MAX  (64 * 1024)


/*
 * sts_req_t — request-construction state for one STS exchange.
 *
 * WHAT: bundles the immutable inputs (config, timestamps, derived identity) and
 *       the derived host/credential strings that the query-building and signing
 *       helpers all read, so those helpers take one struct pointer instead of a
 *       loose 5-7 argument tail.
 * WHY:  sts_build_action_qs() and sts_sign_query() previously each carried the
 *       same {cf, host, amzdate, datestamp, ...} argument cluster; promoting it
 *       removes the parameter bloat with zero behaviour change (identical values,
 *       identical evaluation order — the caller fills the struct once). It is
 *       shared across files so the orchestrator (sts.c) can fill it and the
 *       builder (sts_sign.c) can read it.
 * HOW:  brix_s3_sts_assume() zero-initialises one on its stack, populates it in
 *       the prepare phase, and threads a const pointer through the pure builders.
 *
 *   cf         — validated STS target config (borrowed, not owned)
 *   id         — inbound identity mapped to RoleSessionName (may be NULL)
 *   host       — NUL-terminated authority for the SigV4 "host" header
 *   amzdate    — "YYYYMMDDTHHMMSSZ"
 *   datestamp  — "YYYYMMDD" (amzdate prefix)
 *   rsn        — sanitised RoleSessionName
 *   credential — pre-encoded X-Amz-Credential value ("AKID%2F...%2Faws4_request")
 *   ttl        — clamped DurationSeconds
 */
typedef struct {
    const brix_s3_sts_conf_t *cf;
    const brix_identity_t    *id;
    const char               *host;
    char                      amzdate[17];
    char                      datestamp[9];
    char                      rsn[65];
    char                      credential[512];
    int                       ttl;
} sts_req_t;


/*
 * sts_resp_t — growable capture buffer for the STS HTTP response body.
 *
 * WHAT: a pool-backed buffer plus its current length and capacity, filled by the
 *       libcurl write callback and consumed by the XML parser.
 * WHY:  shared because the orchestrator (sts.c) allocates and sizes it before
 *       the transfer while the transport (sts_http.c) grows it during the fetch.
 * HOW:  sts_perform pre-sizes buf to BRIX_STS_RESP_MAX; sts_write_cb appends
 *       bounded by cap; sts_parse_response reads [buf, buf+len).
 */
typedef struct {
    u_char *buf;
    size_t  len;
    size_t  cap;
} sts_resp_t;


/*
 * sts_creds_buf_t — the three fixed output buffers sts_parse_response fills.
 *
 * WHAT: bundles each destination buffer with its capacity — AccessKeyId,
 *       SecretAccessKey and (optional) SessionToken — so the parser takes one
 *       struct pointer instead of three loose (char *, size_t) argument pairs.
 * WHY:  keeps sts_parse_response within the ≤5-argument budget with zero
 *       behaviour change; the buffers are the caller's stack storage (borrowed,
 *       written NUL-terminated by the parser). Shared so the orchestrator's
 *       finish phase (sts.c) can hand its stack buffers to the parser (sts_http.c).
 * HOW:  sts_finish declares r_ak/r_sk/r_session, points each field+size at them,
 *       and reads the extracted credentials back after NGX_OK.
 *
 *   ak / aksz            — AccessKeyId buffer and its capacity
 *   sk / sksz            — SecretAccessKey buffer and its capacity
 *   session / sesssz     — SessionToken buffer and its capacity (may stay empty)
 */
typedef struct {
    char   *ak;
    size_t  aksz;
    char   *sk;
    size_t  sksz;
    char   *session;
    size_t  sesssz;
} sts_creds_buf_t;


/* ---- Request builder (sts_sign.c) ---------------------------------------- */

/*
 * sts_build_action_qs — build the canonical (sorted, encoded) STS query string,
 * WITHOUT the trailing X-Amz-Signature. Returns NGX_OK / NGX_ERROR (overflow).
 */
ngx_int_t sts_build_action_qs(const sts_req_t *req, char *out, size_t outsz);

/*
 * sts_sign_query — build and SigV4-sign the STS request query string, appending
 * "&X-Amz-Signature=<hex>" to the canonical action query. NGX_OK / NGX_ERROR.
 */
ngx_int_t sts_sign_query(const sts_req_t *req, const char *action_qs,
    char *out, size_t outsz);


/* ---- Transport + response parsing (sts_http.c) --------------------------- */

/*
 * sts_http_get — GET the signed STS URL and capture the response body into
 * `resp`, returning the HTTP status in *http_status. NGX_OK / NGX_ERROR.
 */
ngx_int_t sts_http_get(const char *url, sts_resp_t *resp, long *http_status,
    ngx_log_t *log);

/*
 * sts_parse_response — extract AccessKeyId / SecretAccessKey / SessionToken from
 * the STS XML body into the caller's fixed buffers. NGX_OK when at least the
 * AccessKeyId and SecretAccessKey are present; NGX_ERROR otherwise.
 */
ngx_int_t sts_parse_response(const u_char *body, size_t len,
    const sts_creds_buf_t *creds, ngx_log_t *log);


#endif /* BRIX_AUTH_S3_STS_INTERNAL_H */
