/*
 * http_query_parsed.c — immutable request-owned HTTP query representation.
 *
 * WHAT: Strictly parses one nginx args string into pool-owned decoded names and
 *       values, then provides singleton lookup and duplicate validation.
 * WHY: Authentication and operation routing must consume identical parameters;
 *      reparsing with different limits permits signed/handled query divergence.
 * HOW: Copy once into the request pool, reject malformed escapes/NUL/empty
 *      segments and configured bounds, and publish length-delimited slices.
 */

#include "http_query.h"
#include "core/compat/uri.h"

static int
brix_http_query_hex(u_char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
           || (c >= 'A' && c <= 'F');
}

static int
brix_http_query_raw_valid(const u_char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (data[i] == '\0') {
            return 0;
        }
        if (data[i] != '%') {
            continue;
        }
        if (i + 2 >= len || !brix_http_query_hex(data[i + 1])
            || !brix_http_query_hex(data[i + 2])
            || (data[i + 1] == '0' && data[i + 2] == '0'))
        {
            return 0;
        }
        i += 2;
    }
    return 1;
}

static int
brix_http_query_count(ngx_str_t args, ngx_uint_t *count)
{
    size_t     start;
    size_t     i;
    ngx_uint_t total;

    if (args.len == 0) {
        *count = 0;
        return 1;
    }
    if (args.data == NULL || args.len > BRIX_HTTP_QUERY_MAX_BYTES) {
        return -1;
    }

    start = 0;
    total = 1;
    for (i = 0; i < args.len; i++) {
        if (args.data[i] != '&') {
            continue;
        }
        if (i == start || total >= BRIX_HTTP_QUERY_MAX_PARAMS) {
            return -1;
        }
        start = i + 1;
        total++;
    }
    if (start == args.len) {
        return -1;
    }
    *count = total;
    return 1;
}

static int
brix_http_query_decode(ngx_pool_t *pool, const u_char *raw, size_t raw_len,
    int require_name, ngx_str_t *decoded_out)
{
    char   *decoded;
    size_t  decoded_size;

    if ((require_name && (raw_len == 0 || raw_len > BRIX_HTTP_QUERY_MAX_NAME))
        || !brix_http_query_raw_valid(raw, raw_len))
    {
        return -1;
    }
    decoded_size = raw_len > 0 ? raw_len + 1 : 2;
    decoded = ngx_pnalloc(pool, decoded_size);
    if (decoded == NULL
        || brix_http_urldecode(raw, raw_len, decoded, decoded_size,
               BRIX_URLDECODE_PLUS_TO_SPACE |
               BRIX_URLDECODE_REJECT_NUL) != BRIX_URLDECODE_OK
        || (require_name && decoded[0] == '\0'))
    {
        return -1;
    }
    decoded_out->data = (u_char *) decoded;
    decoded_out->len = ngx_strlen(decoded);
    return 1;
}

static int
brix_http_query_store(ngx_pool_t *pool, brix_http_query_t *query)
{
    u_char    *cursor;
    u_char    *end;
    ngx_uint_t index;

    cursor = query->raw.data;
    end = cursor + query->raw.len;
    index = 0;
    while (cursor < end) {
        u_char *segment_end = ngx_strlchr(cursor, end, '&');
        u_char *equals;

        if (segment_end == NULL) {
            segment_end = end;
        }
        equals = ngx_strlchr(cursor, segment_end, '=');
        query->params[index].raw_name.data = cursor;
        query->params[index].raw_name.len =
            (size_t) ((equals ? equals : segment_end) - cursor);
        if (brix_http_query_decode(pool, cursor,
                (size_t) ((equals ? equals : segment_end) - cursor), 1,
                &query->params[index].name) < 0
            || brix_http_query_decode(pool,
                equals ? equals + 1 : segment_end,
                equals ? (size_t) (segment_end - equals - 1) : 0, 0,
                &query->params[index].value) < 0)
        {
            return -1;
        }
        query->params[index].has_value = (equals != NULL);
        index++;
        cursor = segment_end < end ? segment_end + 1 : end;
    }
    return 1;
}

int
brix_http_query_parse(ngx_pool_t *pool, ngx_str_t args,
    brix_http_query_t *query)
{
    ngx_uint_t count;

    if (pool == NULL || query == NULL) {
        return -1;
    }
    if (query->parsed) {
        return 1;
    }
    if (brix_http_query_count(args, &count) < 0) {
        return -1;
    }
    if (args.len > 0) {
        query->raw.data = ngx_pnalloc(pool, args.len + 1);
        if (query->raw.data == NULL) {
            return -1;
        }
        ngx_memcpy(query->raw.data, args.data, args.len);
        query->raw.data[args.len] = '\0';
        query->raw.len = args.len;
    }
    if (count > 0) {
        query->params = ngx_pcalloc(pool, count * sizeof(*query->params));
        if (query->params == NULL) {
            return -1;
        }
    }
    query->count = count;
    if (count > 0 && brix_http_query_store(pool, query) < 0) {
        return -1;
    }
    query->parsed = 1;
    return 1;
}

static int
brix_http_query_name_eq(const ngx_str_t *name, const char *key,
    size_t key_len, unsigned flags)
{
    if (name->len != key_len) {
        return 0;
    }
    if (flags & BRIX_HTTP_QUERY_CASE_INSENSITIVE) {
        return ngx_strncasecmp(name->data, (u_char *) key, key_len) == 0;
    }
    return ngx_strncmp(name->data, key, key_len) == 0;
}

/* ---- Find one unambiguous decoded query name ----
 * WHAT: Return zero with a nullable match, or BRIX_HTTP_QUERY_DUPLICATE.
 * WHY: Value lookup and presence routing must reject the same ambiguity.
 * HOW: 1. Scan the validated immutable query. 2. Reject a second matching name.
 *      Callers validate query/key and retain their distinct empty-value rules.
 */
static int
brix_http_query_find_singleton(const brix_http_query_t *query,
    const char *key, unsigned flags, const brix_http_query_param_t **match)
{
    size_t key_len = ngx_strlen(key);
    ngx_uint_t i;

    *match = NULL;
    for (i = 0; i < query->count; i++) {
        if (!brix_http_query_name_eq(&query->params[i].name, key,
                                     key_len, flags))
        {
            continue;
        }
        if (*match != NULL) {
            return BRIX_HTTP_QUERY_DUPLICATE;
        }
        *match = &query->params[i];
    }
    return 0;
}

int
brix_http_query_parsed_value(const brix_http_query_t *query,
    const char *key, ngx_str_t *out, unsigned flags)
{
    const brix_http_query_param_t *match;

    if (query == NULL || !query->parsed || key == NULL || out == NULL) {
        return -1;
    }
    out->data = NULL;
    out->len = 0;
    if (brix_http_query_find_singleton(query, key, flags, &match)
        == BRIX_HTTP_QUERY_DUPLICATE)
    {
        return BRIX_HTTP_QUERY_DUPLICATE;
    }
    if (match == NULL || !match->has_value
        || (match->value.len == 0 && !(flags & BRIX_HTTP_QUERY_ALLOW_EMPTY)))
    {
        return 0;
    }
    *out = match->value;
    return 1;
}

int
brix_http_query_parsed_get(const brix_http_query_t *query,
    const char *key, char *out, size_t outsz, unsigned flags)
{
    ngx_str_t value;
    size_t    copy;
    int       rc;

    if (out == NULL || outsz == 0) {
        return -1;
    }
    rc = brix_http_query_parsed_value(query, key, &value, flags);
    if (rc != 1) {
        return rc;
    }
    if (value.len >= outsz && !(flags & BRIX_HTTP_QUERY_TRUNCATE)) {
        return -1;
    }
    copy = value.len < outsz - 1 ? value.len : outsz - 1;
    ngx_memcpy(out, value.data, copy);
    out[copy] = '\0';
    return 1;
}

int
brix_http_query_parsed_has(const brix_http_query_t *query,
    const char *key, unsigned flags)
{
    const brix_http_query_param_t *match;

    if (query == NULL || !query->parsed || key == NULL) {
        return -1;
    }
    if (brix_http_query_find_singleton(query, key, flags, &match)
        == BRIX_HTTP_QUERY_DUPLICATE)
    {
        return BRIX_HTTP_QUERY_DUPLICATE;
    }
    if (match == NULL) {
        return 0;
    }
    if (!match->has_value) {
        return 1;
    }
    if (match->value.len == 0 && (flags & BRIX_HTTP_QUERY_HAS_EMPTY_OK)) {
        return 1;
    }
    return !!(flags & BRIX_HTTP_QUERY_HAS_VALUE_OK);
}

int
brix_http_query_unique(const brix_http_query_t *query, unsigned flags)
{
    ngx_uint_t i;
    ngx_uint_t j;

    if (query == NULL || !query->parsed) {
        return -1;
    }
    for (i = 0; i < query->count; i++) {
        for (j = i + 1; j < query->count; j++) {
            if (brix_http_query_name_eq(&query->params[i].name,
                    (const char *) query->params[j].name.data,
                    query->params[j].name.len, flags))
            {
                return BRIX_HTTP_QUERY_DUPLICATE;
            }
        }
    }
    return 1;
}
