/*
 * json_min.c — minimal, dependency-free JSON value extractor (libxrdproto).
 *
 * See json_min.h.  A string-aware, depth-tracking scanner that finds a top-level
 * object member by key and copies its value (strings unescaped to UTF-8, scalars
 * raw).  libc only; no allocation; never recurses unboundedly (object/array skip
 * uses an explicit byte cursor, not recursion).
 */
#include "json_min.h"

#include <string.h>
#include <stdint.h>

/* Append one byte to a bounded output cursor (NUL-termination done by caller). */
static void
jm_put(char *out, size_t outsz, size_t *pos, char c)
{
    if (*pos + 1 < outsz) {            /* keep one byte for the trailing NUL */
        out[*pos] = c;
    }
    (*pos)++;
}

/* Encode a Unicode code point as UTF-8 into the bounded output. */
static void
jm_put_utf8(char *out, size_t outsz, size_t *pos, uint32_t cp)
{
    if (cp < 0x80) {
        jm_put(out, outsz, pos, (char) cp);
    } else if (cp < 0x800) {
        jm_put(out, outsz, pos, (char) (0xC0 | (cp >> 6)));
        jm_put(out, outsz, pos, (char) (0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        jm_put(out, outsz, pos, (char) (0xE0 | (cp >> 12)));
        jm_put(out, outsz, pos, (char) (0x80 | ((cp >> 6) & 0x3F)));
        jm_put(out, outsz, pos, (char) (0x80 | (cp & 0x3F)));
    } else {
        jm_put(out, outsz, pos, (char) (0xF0 | (cp >> 18)));
        jm_put(out, outsz, pos, (char) (0x80 | ((cp >> 12) & 0x3F)));
        jm_put(out, outsz, pos, (char) (0x80 | ((cp >> 6) & 0x3F)));
        jm_put(out, outsz, pos, (char) (0x80 | (cp & 0x3F)));
    }
}

/* Parse one hex nibble; -1 if not a hex digit. */
static int
jm_hex(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* Read 4 hex digits at p (p<end-3 guaranteed by caller); -1 on a bad digit. */
static int
jm_u16(const char *p)
{
    int a = jm_hex(p[0]), b = jm_hex(p[1]), c = jm_hex(p[2]), d = jm_hex(p[3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) {
        return -1;
    }
    return (a << 12) | (b << 8) | (c << 4) | d;
}

static const char *
jm_skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
        p++;
    }
    return p;
}

/*
 * Parse a JSON string starting at the opening quote `p` (*p == '"').  If `out`
 * is non-NULL, the decoded (unescaped) content is written to out[outsz]; if NULL,
 * the string is only skipped.  Returns the position just past the closing quote,
 * or NULL on a malformed/unterminated string.
 */
static const char *
jm_string(const char *p, const char *end, char *out, size_t outsz, size_t *outlen)
{
    size_t pos = 0;

    p++;                                       /* skip opening quote */
    while (p < end) {
        char c = *p;

        if (c == '"') {
            if (out != NULL && outsz > 0) {
                out[pos < outsz ? pos : outsz - 1] = '\0';
            }
            if (outlen != NULL) {
                *outlen = pos;
            }
            return p + 1;
        }
        if (c == '\\') {
            p++;
            if (p >= end) {
                return NULL;
            }
            switch (*p) {
            case '"':  if (out) { jm_put(out, outsz, &pos, '"'); }  break;
            case '\\': if (out) { jm_put(out, outsz, &pos, '\\'); } break;
            case '/':  if (out) { jm_put(out, outsz, &pos, '/'); }  break;
            case 'b':  if (out) { jm_put(out, outsz, &pos, '\b'); } break;
            case 'f':  if (out) { jm_put(out, outsz, &pos, '\f'); } break;
            case 'n':  if (out) { jm_put(out, outsz, &pos, '\n'); } break;
            case 'r':  if (out) { jm_put(out, outsz, &pos, '\r'); } break;
            case 't':  if (out) { jm_put(out, outsz, &pos, '\t'); } break;
            case 'u': {
                int hi;
                if (p + 4 >= end || (hi = jm_u16(p + 1)) < 0) {
                    return NULL;
                }
                p += 4;
                if (hi >= 0xD800 && hi <= 0xDBFF) {
                    /* high surrogate — must be followed by \uDC00..\uDFFF */
                    int lo;
                    if (p + 6 < end && p[1] == '\\' && p[2] == 'u'
                        && (lo = jm_u16(p + 3)) >= 0xDC00 && lo <= 0xDFFF)
                    {
                        uint32_t cp = 0x10000u
                                    + (((uint32_t) hi - 0xD800u) << 10)
                                    + ((uint32_t) lo - 0xDC00u);
                        if (out) { jm_put_utf8(out, outsz, &pos, cp); }
                        p += 6;
                    } else if (out) {
                        jm_put_utf8(out, outsz, &pos, 0xFFFD);  /* lone surrogate */
                    }
                } else if (out) {
                    jm_put_utf8(out, outsz, &pos, (uint32_t) hi);
                }
                break;
            }
            default:
                return NULL;                   /* invalid escape */
            }
            p++;
        } else {
            if (out) { jm_put(out, outsz, &pos, c); }
            p++;
        }
    }
    return NULL;                               /* unterminated */
}

/*
 * Skip any JSON value at p (already ws-skipped), returning the position just past
 * it, or NULL on malformed input.  Objects/arrays are skipped with a string-aware
 * depth counter so braces/brackets inside strings don't confuse nesting.
 */
static const char *
jm_skip_value(const char *p, const char *end)
{
    if (p >= end) {
        return NULL;
    }
    if (*p == '"') {
        return jm_string(p, end, NULL, 0, NULL);
    }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (p < end) {
            char c = *p;
            if (c == '"') {
                p = jm_string(p, end, NULL, 0, NULL);
                if (p == NULL) {
                    return NULL;
                }
                continue;
            }
            if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth == 0) {
                    return p + 1;
                }
            }
            p++;
        }
        return NULL;                           /* unbalanced */
    }
    /* scalar: number / true / false / null — to the next delimiter */
    while (p < end && *p != ',' && *p != '}' && *p != ']'
           && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
    {
        p++;
    }
    return p;
}

int
xrootd_json_get_str(const char *json, size_t len, const char *key, char *out,
    size_t outsz)
{
    const char *p = json;
    const char *end = json + len;
    size_t      keylen;

    if (json == NULL || key == NULL || out == NULL || outsz == 0) {
        return 0;
    }
    keylen = strlen(key);

    p = jm_skip_ws(p, end);
    if (p >= end || *p != '{') {
        return 0;
    }
    p++;                                       /* enter the top-level object */

    for (;;) {
        const char  *kstart;
        char         kbuf[128];
        size_t       klen = 0;

        p = jm_skip_ws(p, end);
        if (p >= end || *p == '}') {
            return 0;                          /* end of object, key not found */
        }
        if (*p != '"') {
            return 0;                          /* not a member key — malformed */
        }
        kstart = p;
        /* Read the member key into kbuf (decoded) for an exact compare. */
        p = jm_string(kstart, end, kbuf, sizeof(kbuf), &klen);
        if (p == NULL) {
            return 0;
        }
        p = jm_skip_ws(p, end);
        if (p >= end || *p != ':') {
            return 0;
        }
        p++;                                   /* past ':' */
        p = jm_skip_ws(p, end);
        if (p >= end) {
            return 0;
        }

        if (klen == keylen && memcmp(kbuf, key, keylen) == 0) {
            /* Found it.  String → decode; scalar → raw token; object/array → 0. */
            if (*p == '"') {
                return jm_string(p, end, out, outsz, NULL) != NULL ? 1 : 0;
            }
            if (*p == '{' || *p == '[') {
                return 0;                      /* no flat-string form */
            }
            {
                const char *vend = jm_skip_value(p, end);
                size_t      n;
                if (vend == NULL) {
                    return 0;
                }
                n = (size_t) (vend - p);
                if (n >= outsz) {
                    n = outsz - 1;
                }
                memcpy(out, p, n);
                out[n] = '\0';
                return 1;
            }
        }

        /* Not our key — skip the value and continue to the next member. */
        p = jm_skip_value(p, end);
        if (p == NULL) {
            return 0;
        }
        p = jm_skip_ws(p, end);
        if (p < end && *p == ',') {
            p++;
        }
    }
}
