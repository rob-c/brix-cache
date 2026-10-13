/*
 * query.c — S3 request-query boundary and field limits.
 *
 * WHAT: Builds the immutable shared query representation and applies the
 *       strict singleton and consumer-buffer policies for S3 requests.
 * WHY: SigV4 and operation routing must reject, not truncate or omit, any
 *      parameter that cannot be represented identically by both sides.
 * HOW: Parse into r->pool, reject duplicate decoded names, then validate every
 *      value against its narrowest known consumer buffer.
 */

#include "s3.h"
#include "core/compat/uri.h"

static int
s3_query_limits_ok(const brix_http_query_t *query)
{
    typedef struct {
        const char *name;
        size_t      buffer_size;
        size_t      exact_len;
    } s3_query_limit_t;
    const s3_query_limit_t limits[] = {
        { "uploadId", 25, 24 },
        { "partNumber", 8, 0 },
        { "list-type", 8, 0 },
        { "encoding-type", 8, 0 },
        { "fetch-owner", 8, 0 },
        { "max-keys", 32, 0 },
        { "max-uploads", 16, 0 },
        { "max-parts", 16, 0 },
        { "part-number-marker", 16, 0 },
        { "key-marker", 256, 0 },
        { "X-Amz-Algorithm", 64, 0 },
        { "X-Amz-Credential", BRIX_S3_CREDENTIAL_BUF_SIZE, 0 },
        { "X-Amz-Date", BRIX_S3_ISO8601_BUF_SIZE, 0 },
        { "X-Amz-Expires", 32, 0 },
        { "X-Amz-SignedHeaders", BRIX_S3_SIGNED_HEADERS_BUF_SIZE, 0 },
        { "X-Amz-Signature", 128, 0 },
        { "response-cache-control", BRIX_S3_CONDITIONAL_VAL_BUF, 0 },
        { "response-content-disposition", BRIX_S3_CONDITIONAL_VAL_BUF, 0 },
        { "response-content-encoding", BRIX_S3_CONDITIONAL_VAL_BUF, 0 },
        { "response-content-language", BRIX_S3_CONDITIONAL_VAL_BUF, 0 },
        { "response-content-type", 256, 0 },
        { "response-expires", BRIX_S3_CONDITIONAL_VAL_BUF, 0 },
    };
    ngx_uint_t i;
    size_t     j;
    size_t     canonical_len = 0;
    u_char     encoded[BRIX_S3_QUERY_ENCODE_BUF_SIZE];

    if (query->count > 64) {
        return 0;
    }

    for (i = 0; i < query->count; i++) {
        size_t buffer_size = BRIX_S3_HEADER_VALUE_BUF_SIZE;
        size_t exact_len = 0;

        for (j = 0; j < sizeof(limits) / sizeof(limits[0]); j++) {
            if (query->params[i].name.len == ngx_strlen(limits[j].name)
                && ngx_strncmp(query->params[i].name.data, limits[j].name,
                               query->params[i].name.len) == 0)
            {
                buffer_size = limits[j].buffer_size;
                exact_len = limits[j].exact_len;
                break;
            }
        }
        if (query->params[i].value.len >= buffer_size
            || (exact_len > 0 && query->params[i].value.len != exact_len))
        {
            return 0;
        }
        {
            ssize_t name_len = brix_http_urlencode(query->params[i].name.data,
                query->params[i].name.len, (char *) encoded, sizeof(encoded), "");
            ssize_t value_len = brix_http_urlencode(query->params[i].value.data,
                query->params[i].value.len, (char *) encoded, sizeof(encoded), "");

            if (name_len < 0 || value_len < 0) {
                return 0;
            }
            canonical_len += (i > 0) + (size_t) name_len + 1
                             + (size_t) value_len;
            if (canonical_len >= BRIX_S3_CANONICAL_QUERY_BUF_SIZE) {
                return 0;
            }
        }
    }
    return 1;
}

int
s3_query_prepare(ngx_http_request_t *r, ngx_http_s3_req_ctx_t *ctx)
{
    if (r == NULL || ctx == NULL
        || brix_http_query_parse(r->pool, r->args, &ctx->query) < 0
        || brix_http_query_unique(&ctx->query, 0) < 0
        || !s3_query_limits_ok(&ctx->query))
    {
        return -1;
    }
    return 1;
}
