/*
 * s3_auth_internal.h — declarations for SigV4 helper functions shared across
 * the auth_sigv4_*.c fragments (canonical.c → headers.c / verify.c).
 *
 * Include after "s3.h".
 */
/*
 * ============================================================
 * WHAT: SigV4 credential components and parser declarations.
 * ============================================================
 *
 * This header defines the parsed representation of AWS Signature V4
 * credentials (access key, date, region, signed headers, signature)
 * and declares the two parsers that populate it:
 *   - parse_authorization() — parses the Authorization header
 *     from a signed request.
 *   - parse_presigned_authorization() — parses X-Amz-* query params
 *     from a presigned URL.
 *
 * The sigv4_components_t struct is shared across auth_sigv4_parse.c,
 * auth_sigv4_canonical.c, and auth_sigv4_verify.c so the canonical
 * string builder and signature verifier operate on identical parsed data.
 * ============================================================
 */
#pragma once

/* -------------------------------------------------------------------------
 * SigV4 Authorization header parser — defined in auth_sigv4_parse.c.
 * ---------------------------------------------------------------------- */

typedef struct {
    char akid[128];         /* Access key identifier */
    char date[16];          /* YYYYMMDD, e.g. "20260512" */
    char region[64];        /* AWS region, e.g. "us-east-1" */
    char amz_date[32];      /* Full request timestamp: YYYYMMDDTHHMMSSZ */
    char signed_hdrs[256];  /* Comma-separated signed headers */
    char signature[128];    /* Hex-encoded HMAC-SHA256 signature (64 bytes) */
    ngx_uint_t presigned;   /* 1 when auth came from X-Amz-* query params */
    ngx_uint_t amz_expires; /* X-Amz-Expires seconds for presigned URLs */
} sigv4_components_t;

/* Derive the SigV4 signing key, caching the last result per worker.
 * Returns 1 on success, 0 on failure. */
int s3_sigv4_derive_signing_key_cached(const ngx_str_t *secret_key,
                                        const char *date,   /* YYYYMMDD */
                                        const char *region,
                                        u_char out[32]);

/* Parse the AWS4-HMAC-SHA256 Authorization header into components.
 * Returns NGX_OK on success, NGX_ERROR on parse failure. */
int parse_authorization(const ngx_str_t *auth, sigv4_components_t *out);

/*
 * Parse SigV4 presigned URL query parameters.
 * Returns NGX_OK when X-Amz-Signature is present and valid, NGX_DECLINED when
 * the request is not presigned, or NGX_ERROR when the presigned form is
 * present but malformed.
 */
int parse_presigned_authorization(ngx_http_request_t *r,
    sigv4_components_t *out);
