#pragma once

#include <ngx_config.h>
#include <ngx_core.h>

#define BRIX_HTTP_QUERY_CASE_INSENSITIVE  0x0001u
#define BRIX_HTTP_QUERY_DECODE_VALUE      0x0002u
#define BRIX_HTTP_QUERY_PLUS_TO_SPACE     0x0004u
#define BRIX_HTTP_QUERY_REJECT_NUL        0x0008u
#define BRIX_HTTP_QUERY_ALLOW_EMPTY       0x0010u
#define BRIX_HTTP_QUERY_TRUNCATE          0x0020u
#define BRIX_HTTP_QUERY_HAS_VALUE_OK      0x0040u
#define BRIX_HTTP_QUERY_HAS_EMPTY_OK      0x0080u

/* A request query is copied into the request pool and split exactly once.  The
 * immutable parameter slices below are then shared by authentication and
 * operation routing, so neither side can silently see a different query. */
#define BRIX_HTTP_QUERY_MAX_PARAMS  128u
#define BRIX_HTTP_QUERY_MAX_BYTES   16384u
#define BRIX_HTTP_QUERY_MAX_NAME    255u

#define BRIX_HTTP_QUERY_DUPLICATE  -2

typedef struct {
    ngx_str_t  raw_name;   /* encoded spelling within the immutable raw copy */
    ngx_str_t  name;       /* decoded once; never aliases nginx's mutable URI */
    ngx_str_t  value;      /* decoded once with the same policy as the name   */
    unsigned   has_value:1;
} brix_http_query_param_t;

typedef struct {
    ngx_str_t                 raw;
    brix_http_query_param_t  *params;
    ngx_uint_t                count;
    unsigned                  parsed:1;
} brix_http_query_t;

/* Strict request-boundary parser.  Empty queries are valid.  Non-empty
 * segments, names, percent escapes, parameter count, and total bytes are
 * validated before the representation is published. */
int brix_http_query_parse(ngx_pool_t *pool, ngx_str_t args,
    brix_http_query_t *query);

/* Read a singleton parameter from an already parsed query.  A duplicate is a
 * distinct failure so security-sensitive callers can reject ambiguity. */
int brix_http_query_parsed_get(const brix_http_query_t *query,
    const char *key, char *out, size_t outsz, unsigned flags);
int brix_http_query_parsed_value(const brix_http_query_t *query,
    const char *key, ngx_str_t *out, unsigned flags);

int brix_http_query_parsed_has(const brix_http_query_t *query,
    const char *key, unsigned flags);

/* Require a single unambiguous value for every decoded name. */
int brix_http_query_unique(const brix_http_query_t *query, unsigned flags);

/*
 * brix_http_query_get - parse a query string and extract value for key into buffer.
 *
 * WHAT: Searches args (e.g. r->args) for key=, extracts the value substring, optionally
 *       URL-decodes it (+ → space), rejects null bytes, truncates to outsz. Returns
 *       NGX_OK on success or NGX_ERROR/NGX_DECLINED on failure.
 *
 * WHY: WebDAV and S3 handlers extract URL parameters (e.g. ?versionId=XXX,
 *      ?partNumber=N). This function handles decoding, validation, and truncation
 *      in one call for both modules.
 *
 * HOW: Walks args byte-by-byte looking for key followed by '='. Extracts value substring,
 *      applies flags (case-insensitive match, URL decode, +→space, reject NUL,
 *      allow empty). Copies into out[0..outsz-1] with truncation if needed.
 */

int brix_http_query_get(ngx_str_t args, const char *key, char *out,
    size_t outsz, unsigned flags);

/*
 * brix_http_query_has - check whether a query string contains a named key.
 *
 * WHAT: Searches args for the presence of key= (value may be empty). Returns NGX_OK
 *       if found, NGX_DECLINED if absent. Flags control case sensitivity and
 *       whether an empty value counts as "present".
 *
 * WHY: S3 operations check ?versionId presence to distinguish versioned vs unversioned
 *      requests. WebDAV checks for optional parameters without needing their values.
 *
 * HOW: Walks args looking for key followed by '='. Returns NGX_OK on match with
 *      flags (case-insensitive, value-ok), NGX_DECLINED on absence.
 */

int brix_http_query_has(ngx_str_t args, const char *key, unsigned flags);

/* Allocation-free decoded-name probe for policy gates that must run before
 * the request-owned parsed representation is allocated.  Returns true on an
 * undecodable/invalid name so security classification fails closed. */
int brix_http_query_has_decoded_name(ngx_str_t args, const char *key,
    unsigned flags);
