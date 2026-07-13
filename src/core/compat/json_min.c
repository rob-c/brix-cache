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

/* ---- Combine a UTF-16 surrogate pair into a Unicode code point ----
 *
 * WHAT: Returns the code point encoded by high surrogate `hi` (0xD800..0xDBFF)
 * and low surrogate `lo` (0xDC00..0xDFFF).  Pure arithmetic; no validation.
 *
 * WHY: Keeps the RFC 8259 surrogate-pair math in one named place instead of
 * inlined in the escape decoder.
 *
 * HOW: 1. Shift the high surrogate's 10 payload bits up.
 *      2. Add the low surrogate's 10 payload bits and the 0x10000 plane base.
 */
static uint32_t
jm_utf16_pair(int hi, int lo)
{
    return 0x10000u + (((uint32_t) hi - 0xD800u) << 10)
                    + ((uint32_t) lo - 0xDC00u);
}

/* ---- Decode a \uXXXX escape (with surrogate-pair handling) ----
 *
 * WHAT: Decodes the \uXXXX escape whose 'u' is at **pp, emitting UTF-8 into
 * the bounded output (if `out` is non-NULL).  Advances *pp to the LAST hex
 * digit consumed (the caller steps past it).  Returns 0 on success, -1 on a
 * truncated/non-hex escape.
 *
 * WHY: Splits the surrogate-pair state machine out of jm_string so the scan
 * loop stays a flat character dispatch.
 *
 * HOW: 1. Require 4 hex digits after the 'u'; parse them (else -1).
 *      2. High surrogate followed by a valid \uDC00..\uDFFF low surrogate →
 *         emit the combined code point and consume the second escape too.
 *      3. Lone high surrogate → emit U+FFFD without consuming further input.
 *      4. Anything else → emit the code unit as-is.
 */
static int
jm_unescape_u(const char **pp, const char *end, char *out, size_t outsz,
    size_t *pos)
{
    const char *p = *pp;
    int         hi;

    if (p + 4 >= end || (hi = jm_u16(p + 1)) < 0) {
        return -1;
    }
    p += 4;
    if (hi >= 0xD800 && hi <= 0xDBFF) {
        /* high surrogate — must be followed by \uDC00..\uDFFF */
        int lo;
        if (p + 6 < end && p[1] == '\\' && p[2] == 'u'
            && (lo = jm_u16(p + 3)) >= 0xDC00 && lo <= 0xDFFF)
        {
            if (out) { jm_put_utf8(out, outsz, pos, jm_utf16_pair(hi, lo)); }
            p += 6;
        } else if (out) {
            jm_put_utf8(out, outsz, pos, 0xFFFD);  /* lone surrogate */
        }
    } else if (out) {
        jm_put_utf8(out, outsz, pos, (uint32_t) hi);
    }
    *pp = p;
    return 0;
}

/* ---- Decode one escape sequence after a backslash ----
 *
 * WHAT: Decodes the escape whose introducer character is at **pp (the byte
 * after the backslash), emitting into the bounded output when `out` is
 * non-NULL.  Advances *pp to the LAST character consumed.  Returns 0 on
 * success, -1 on a dangling backslash or invalid/truncated escape.
 *
 * WHY: Pulls the per-escape dispatch out of jm_string so the string scanner
 * only walks bytes and delegates decoding.
 *
 * HOW: 1. Fail if the backslash was the last input byte.
 *      2. Map the two-character escapes to their single-byte expansions.
 *      3. Delegate \uXXXX to jm_unescape_u.
 *      4. Reject any other escape character.
 */
static int
jm_unescape_char(const char **pp, const char *end, char *out, size_t outsz,
    size_t *pos)
{
    const char *p = *pp;
    char        d;

    if (p >= end) {
        return -1;
    }
    switch (*p) {
    case '"':  d = '"';  break;
    case '\\': d = '\\'; break;
    case '/':  d = '/';  break;
    case 'b':  d = '\b'; break;
    case 'f':  d = '\f'; break;
    case 'n':  d = '\n'; break;
    case 'r':  d = '\r'; break;
    case 't':  d = '\t'; break;
    case 'u':
        if (jm_unescape_u(&p, end, out, outsz, pos) != 0) {
            return -1;
        }
        *pp = p;
        return 0;
    default:
        return -1;                             /* invalid escape */
    }
    if (out) { jm_put(out, outsz, pos, d); }
    *pp = p;
    return 0;
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
            if (jm_unescape_char(&p, end, out, outsz, &pos) != 0) {
                return NULL;
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
/* ---- Skip an object/array with a string-aware depth counter ----
 *
 * WHAT: Skips the container starting at `p` (*p == '{' or '['), returning the
 * position just past its closing brace/bracket, or NULL on an unbalanced or
 * malformed (bad embedded string) container.
 *
 * WHY: Keeps the non-recursive depth-counting skip (the file's "never recurses
 * unboundedly" guarantee) in one place, out of the value dispatcher.
 *
 * HOW: 1. Walk bytes, letting jm_string consume whole strings so braces and
 *         brackets inside strings never touch the depth counter.
 *      2. Increment depth on '{'/'[', decrement on '}'/']'.
 *      3. Depth back to zero → done; input exhausted first → NULL.
 */
static const char *
jm_skip_container(const char *p, const char *end)
{
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
    return NULL;                               /* unbalanced */
}

/* ---- Skip a scalar token to the next delimiter ----
 *
 * WHAT: Advances past a number/true/false/null token starting at `p` and
 * returns the position of the first delimiter (',', '}', ']', whitespace) or
 * `end`.  Never fails.
 *
 * WHY: Separates the trivial scalar scan from the container skip so
 * jm_skip_value is a plain three-way dispatch.
 *
 * HOW: 1. Advance while the byte is not a value delimiter and input remains.
 */
static const char *
jm_skip_scalar(const char *p, const char *end)
{
    while (p < end && *p != ',' && *p != '}' && *p != ']'
           && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
    {
        p++;
    }
    return p;
}

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
        return jm_skip_container(p, end);
    }
    /* scalar: number / true / false / null — to the next delimiter */
    return jm_skip_scalar(p, end);
}

/* ---- Parse one object member key and position on its value ----
 *
 * WHAT: At the start of an object member, decodes the member key into
 * kbuf[kbufsz] (length in *klen), consumes the ':' separator, and leaves *pp
 * at the first byte of the value (ws-skipped).  Returns 0 on success, -1 on
 * end-of-object, missing/unterminated key, missing ':', or truncated input.
 *
 * WHY: Isolates the member-header grammar (ws key ws ':' ws) so the lookup
 * loop reads as key-compare + value-handling only.
 *
 * HOW: 1. Skip whitespace; '}' or end of input → no more members (-1).
 *      2. Require and decode a quoted key via jm_string.
 *      3. Skip whitespace; require ':'; skip whitespace.
 *      4. Fail if the value itself is missing (input exhausted).
 */
static int
jm_member_key(const char **pp, const char *end, char *kbuf, size_t kbufsz,
    size_t *klen)
{
    const char *p = jm_skip_ws(*pp, end);

    if (p >= end || *p == '}') {
        return -1;                             /* end of object, key not found */
    }
    if (*p != '"') {
        return -1;                             /* not a member key — malformed */
    }
    /* Read the member key into kbuf (decoded) for an exact compare. */
    p = jm_string(p, end, kbuf, kbufsz, klen);
    if (p == NULL) {
        return -1;
    }
    p = jm_skip_ws(p, end);
    if (p >= end || *p != ':') {
        return -1;
    }
    p++;                                       /* past ':' */
    p = jm_skip_ws(p, end);
    if (p >= end) {
        return -1;
    }
    *pp = p;
    return 0;
}

/* ---- Copy the matched member's value into the caller's buffer ----
 *
 * WHAT: Emits the value at `p` as a flat NUL-terminated string in out[outsz]:
 * strings are unescaped, scalars copied raw (truncated to fit), objects and
 * arrays have no flat form.  Returns 1 on success, 0 on container values or
 * malformed input.
 *
 * WHY: Separates the found-key output formatting from the member-scan loop in
 * brix_json_get_str.
 *
 * HOW: 1. String value → decode through jm_string.
 *      2. Object/array → 0 (no flat-string form).
 *      3. Scalar → bound the raw token with jm_skip_value and copy it,
 *         clamped to outsz - 1, then NUL-terminate.
 */
static int
jm_emit_value(const char *p, const char *end, char *out, size_t outsz)
{
    const char *vend;
    size_t      n;

    /* Found it.  String → decode; scalar → raw token; object/array → 0. */
    if (*p == '"') {
        return jm_string(p, end, out, outsz, NULL) != NULL ? 1 : 0;
    }
    if (*p == '{' || *p == '[') {
        return 0;                              /* no flat-string form */
    }
    vend = jm_skip_value(p, end);
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

int
brix_json_get_str(const char *json, size_t len, const char *key, char *out,
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
        char         kbuf[128];
        size_t       klen = 0;

        if (jm_member_key(&p, end, kbuf, sizeof(kbuf), &klen) != 0) {
            return 0;
        }

        if (klen == keylen && memcmp(kbuf, key, keylen) == 0) {
            return jm_emit_value(p, end, out, outsz);
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
