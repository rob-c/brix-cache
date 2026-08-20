/* json_iter.c — raw-span getter + array iterator beside json_min (see
 * json_iter.h for the contract). */
#include "core/compat/json_iter.h"

#include <string.h>

/* Advance *i past whitespace. */
static void
ws_skip(const char *s, size_t n, size_t *i)
{
    while (*i < n && (s[*i] == ' ' || s[*i] == '\t' || s[*i] == '\n' ||
                      s[*i] == '\r')) {
        (*i)++;
    }
}

/* Advance *i past one string token (opening quote at s[*i]). 0 / -1. */
static int
str_skip(const char *s, size_t n, size_t *i)
{
    (*i)++;                                   /* opening quote */
    while (*i < n) {
        if (s[*i] == '\\') {
            *i += 2;                          /* escape pair (incl. \") */
            continue;
        }
        if (s[*i] == '"') {
            (*i)++;
            return 0;
        }
        (*i)++;
    }
    return -1;
}

/* Consume an unquoted scalar, stopping before its enclosing delimiter. */
static void
scalar_skip(const char *s, size_t n, size_t *i)
{
    while (*i < n && s[*i] != ',' && s[*i] != '}' && s[*i] != ']' &&
           s[*i] != ' ' && s[*i] != '\t' && s[*i] != '\n' &&
           s[*i] != '\r') {
        (*i)++;
    }
}

/* Consume one value byte or nested JSON token. 1 means a scalar completed. */
static int
value_step(const char *s, size_t n, size_t *i, int *depth)
{
    char c = s[*i];

    if (c == '"') {
        return str_skip(s, n, i);
    }
    if (c == '{' || c == '[') {
        if (++*depth > BRIX_JSON_DEPTH_MAX) {
            return -1;
        }
        (*i)++;
        return 0;
    }
    if (c == '}' || c == ']') {
        if (--*depth < 0) {
            return -1;
        }
        (*i)++;
        return 0;
    }
    if (*depth == 0) {
        scalar_skip(s, n, i);
        return 1;
    }
    (*i)++;
    return 0;
}

/* Advance *i past exactly one JSON value (leading ws consumed here). The
 * container walk is iterative — depth is a counter, not a stack — so the
 * depth cap bounds work without bounding recursion. 0 / -1. */
static int
value_skip(const char *s, size_t n, size_t *i)
{
    int depth = 0;

    ws_skip(s, n, i);
    if (*i >= n) {
        return -1;
    }
    do {
        int scalar = value_step(s, n, i, &depth);

        if (scalar < 0) {
            return -1;
        }
        if (scalar || depth == 0) {
            return 0;
        }
    } while (*i < n);
    return -1;
}

/* Read one member after an object opening delimiter. 1 field / 0 end / -1. */
static int
object_field(const char *json, size_t len, size_t *i, const char **k,
             size_t *klen, const char **value, size_t *vlen)
{
    size_t start;

    ws_skip(json, len, i);
    if (*i < len && json[*i] == '}') {
        return 0;
    }
    if (*i >= len || json[*i] != '"') {
        return -1;
    }
    start = ++*i;
    if (str_skip(json, len, i) != 0) {
        return -1;
    }
    *k = json + start;
    *klen = *i - start - 1;
    ws_skip(json, len, i);
    if (*i >= len || json[*i] != ':') {
        return -1;
    }
    (*i)++;
    ws_skip(json, len, i);
    start = *i;
    if (value_skip(json, len, i) != 0) {
        return -1;
    }
    *value = json + start;
    *vlen = *i - start;
    return 1;
}

/* Advance after an object field. 1 next field / 0 clean end / -1 malformed. */
static int
object_field_delim(const char *json, size_t len, size_t *i)
{
    ws_skip(json, len, i);
    if (*i < len && json[*i] == ',') {
        (*i)++;
        return 1;
    }
    return *i < len && json[*i] == '}' ? 0 : -1;
}

int
brix_json_get_raw(const char *json, size_t len, const char *key,
                  const char **out, size_t *outlen)
{
    size_t i = 0, klen = strlen(key);

    ws_skip(json, len, &i);
    if (i >= len || json[i] != '{') {
        return -1;
    }
    i++;
    for (;;) {
        const char *field, *value;
        size_t      flen, vlen;
        int         rc;

        rc = object_field(json, len, &i, &field, &flen, &value, &vlen);
        if (rc < 0) {
            return -1;
        }
        if (rc == 0) {
            return 0;
        }
        if (flen == klen && memcmp(field, key, klen) == 0) {
            *out = value;
            *outlen = vlen;
            return 1;
        }
        rc = object_field_delim(json, len, &i);
        if (rc < 0) {
            return -1;
        }
        if (rc == 0) {
            return 0;
        }
    }
}

int
brix_json_arr_next(const char *arr, size_t arrlen, size_t *cursor,
                   const char **elem, size_t *elemlen)
{
    size_t i = *cursor;
    size_t vstart;

    if (i == 0) {
        ws_skip(arr, arrlen, &i);
        if (i >= arrlen || arr[i] != '[') {
            return -1;
        }
        i++;
    } else {
        ws_skip(arr, arrlen, &i);
        if (i < arrlen && arr[i] == ',') {
            i++;
        } else if (i < arrlen && arr[i] == ']') {
            return 0;
        } else {
            return -1;
        }
    }
    ws_skip(arr, arrlen, &i);
    if (i < arrlen && arr[i] == ']') {
        return *cursor == 0 ? 0 : -1;         /* [] ok; trailing comma not */
    }
    vstart = i;
    if (value_skip(arr, arrlen, &i) != 0) {
        return -1;
    }
    *elem    = arr + vstart;
    *elemlen = i - vstart;
    *cursor  = i;
    return 1;
}
