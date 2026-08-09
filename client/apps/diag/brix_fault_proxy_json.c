/*
 * brix_fault_proxy_json.c — optional JSON control-input front-end (A2).
 *
 * WHAT: lets a control-plane client send one command as a flat JSON object,
 *       e.g. {"cmd":"latency","args":"down 25"} or {"cmd":"status","args":"json"},
 *       instead of the bare "verb args" line grammar.  The core recognises a
 *       leading '{' and hands the line here; this module reprojects it onto the
 *       exact same verb line and the core runs it through the ONE command parser.
 *
 * WHY:  automation (and the A4 `status json` reply) is easier to drive from a
 *       JSON tool-chain when the request side is JSON too — without teaching the
 *       command grammar a second dialect.  By translating to a verb line rather
 *       than duplicating any lever logic, every command stays defined in exactly
 *       one place (apply_command) and JSON input can never drift from it.
 *
 * HOW:  a small dependency-free scanner extracts the string value of the object
 *       keys "cmd" (required) and "args" (optional), decoding standard JSON
 *       string escapes, and emits "<cmd>" or "<cmd> <args>".  It parses only what
 *       it needs (two string fields of a flat object); anything malformed or a
 *       missing "cmd" returns -1 so the caller answers a structured parse error.
 *       No lever state is touched here — this is a pure string transform.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "brix_fault_proxy_mods.h"

/* Skip JSON insignificant whitespace. */
static const char *
json_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    return p;
}

/* Decode a single hex nibble, or -1 if not a hex digit. */
static int
hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* The two-character JSON escapes, as a table rather than a switch ladder
 * (coding-standards §8.6). \u is handled separately — it is not two characters. */
static const struct { char esc; char dec; } JSON_ESCAPES[] = {
    { '"', '"' }, { '\\', '\\' }, { '/', '/' }, { 'b', '\b' },
    { 'f', '\f' }, { 'n', '\n' }, { 'r', '\r' }, { 't', '\t' },
};

/* Decode a two-character escape; 1 = known (result in *dec), 0 = unknown. */
static int
json_escape_decode(char e, char *dec)
{
    for (size_t i = 0; i < sizeof(JSON_ESCAPES) / sizeof(JSON_ESCAPES[0]); i++) {
        if (JSON_ESCAPES[i].esc == e) {
            *dec = JSON_ESCAPES[i].dec;
            return 1;
        }
    }
    return 0;
}

/* Read exactly four hex digits as a code point, or -1 if any is not hex. A NUL
 * is not a hex digit, so this cannot run off the end of the string. */
static int
json_parse_u4(const char *p)
{
    int cp = 0;
    for (int i = 0; i < 4; i++) {
        int h = hex_nibble(p[i]);
        if (h < 0) {
            return -1;
        }
        cp = (cp << 4) | h;
    }
    return cp;
}

/* Append `cp` to out[*o] as UTF-8. 0 = written, -1 = would overflow. */
static int
json_emit_utf8(unsigned cp, char *out, size_t *o, size_t outsz)
{
    if (cp < 0x80) {
        if (*o + 1 >= outsz) return -1;
        out[(*o)++] = (char) cp;
    } else if (cp < 0x800) {
        if (*o + 2 >= outsz) return -1;
        out[(*o)++] = (char) (0xC0 | (cp >> 6));
        out[(*o)++] = (char) (0x80 | (cp & 0x3F));
    } else {
        if (*o + 3 >= outsz) return -1;
        out[(*o)++] = (char) (0xE0 | (cp >> 12));
        out[(*o)++] = (char) (0x80 | ((cp >> 6) & 0x3F));
        out[(*o)++] = (char) (0x80 | (cp & 0x3F));
    }
    return 0;
}

/* Decode the escape whose body starts at `*pp` (i.e. just past the backslash),
 * appending to out[*o] and advancing `*pp` past it. 0 = ok, -1 = rejected.
 * \uXXXX is emitted as UTF-8 (BMP only, which is all control-plane text needs). */
static int
json_parse_escape(const char **pp, char *out, size_t *o, size_t outsz)
{
    const char *p = *pp;
    char        dec;

    if (*p == 'u') {
        int cp = json_parse_u4(p + 1);
        if (cp < 0) {
            return -1;
        }
        *pp = p + 5;                        /* 'u' + four hex digits */
        return json_emit_utf8((unsigned) cp, out, o, outsz);
    }
    if (!json_escape_decode(*p, &dec)) {
        return -1;                          /* invalid escape */
    }
    if (*o + 1 >= outsz) {
        return -1;
    }
    out[(*o)++] = dec;
    *pp = p + 1;
    return 0;
}

/*
 * Parse a JSON string starting at `*pp` (which must point at the opening quote),
 * decoding escapes into `out` (NUL-terminated, bounded by `outsz`).  Advances
 * `*pp` past the closing quote.  Returns 0 on success, -1 on malformed input or
 * overflow.
 */
static int
json_parse_string(const char **pp, char *out, size_t outsz)
{
    const char *p = *pp;
    size_t      o = 0;

    if (*p != '"') {
        return -1;
    }
    p++;
    for (;;) {
        unsigned char c = (unsigned char) *p;
        if (c == '\0') {
            return -1;                      /* unterminated string */
        }
        if (c == '"') {
            p++;
            break;                          /* closing quote */
        }
        if (c == '\\') {
            p++;
            if (json_parse_escape(&p, out, &o, outsz) != 0) {
                return -1;
            }
            continue;
        }
        if (o + 1 >= outsz) {
            return -1;                      /* value would overflow */
        }
        out[o++] = (char) c;
        p++;
    }
    out[o] = '\0';
    *pp = p;
    return 0;
}

/*
 * Find the string value of top-level object key `key` in `json`.  Returns 1 and
 * fills `out` on success, 0 if the key is absent, -1 if present but malformed.
 * Scans object members ("key" : value , ...) so a value string containing the
 * key text cannot be mistaken for the key itself.
 */
/* Consume `"name" :` at `*pp`, leaving `*pp` on the value. 0 = ok, -1 = malformed. */
static int
json_member_key(const char **pp, char *kbuf, size_t ksz)
{
    const char *p = json_skip_ws(*pp);
    if (json_parse_string(&p, kbuf, ksz) != 0) {
        return -1;
    }
    p = json_skip_ws(p);
    if (*p != ':') {
        return -1;
    }
    *pp = json_skip_ws(p + 1);
    return 0;
}

/* Consume the value at `*pp` — a string, or a bare token up to ',' or '}'. */
static int
json_skip_value(const char **pp)
{
    if (**pp != '"') {
        while (**pp != '\0' && **pp != ',' && **pp != '}') {
            (*pp)++;
        }
        return 0;
    }
    char skip[512];
    return json_parse_string(pp, skip, sizeof skip);
}

static int
json_object_get(const char *json, const char *key, char *out, size_t outsz)
{
    const char *p = json_skip_ws(json);
    if (*p != '{') {
        return -1;
    }
    p = json_skip_ws(p + 1);
    if (*p == '}') {
        return 0;                           /* empty object */
    }
    for (;;) {
        char kbuf[64];
        if (json_member_key(&p, kbuf, sizeof kbuf) != 0) {
            return -1;
        }
        if (strcmp(kbuf, key) == 0) {
            if (*p != '"') {
                return -1;                  /* we only accept string values */
            }
            return json_parse_string(&p, out, outsz) == 0 ? 1 : -1;
        }
        if (json_skip_value(&p) != 0) {
            return -1;
        }
        p = json_skip_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == '}') {
            return 0;                       /* key not found */
        }
        return -1;
    }
}

/*
 * Like json_object_get, but also accepts a NON-string value (number/bool/null):
 * a string value is decoded, a bare token is copied verbatim (so 5242880 stays
 * an integer and 0.02 stays 0.02 — never reprojected through %g).  Returns 1 and
 * fills `out` on success, 0 if the key is absent, -1 if the object is malformed.
 */
int
fp_json_get(const char *json, const char *key, char *out, size_t outsz)
{
    const char *p = json_skip_ws(json);
    if (*p != '{') {
        return -1;
    }
    p = json_skip_ws(p + 1);
    if (*p == '}') {
        return 0;
    }
    for (;;) {
        char kbuf[64];
        if (json_member_key(&p, kbuf, sizeof kbuf) != 0) {
            return -1;
        }
        int match = (strcmp(kbuf, key) == 0);
        if (match && *p == '"') {
            return json_parse_string(&p, out, outsz) == 0 ? 1 : -1;
        }
        if (match) {
            /* bare token: copy up to ',' or '}' (trimming trailing space). */
            size_t o = 0;
            while (*p != '\0' && *p != ',' && *p != '}') {
                if (o + 1 < outsz) { out[o++] = *p; }
                p++;
            }
            while (o > 0 && (out[o - 1] == ' ' || out[o - 1] == '\t')) { o--; }
            out[o] = '\0';
            return o > 0 ? 1 : -1;
        }
        if (json_skip_value(&p) != 0) {
            return -1;
        }
        p = json_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') { return 0; }
        return -1;
    }
}

/*
 * Reproject a flat JSON command object onto a verb line for apply_command().
 * Emits "<cmd>" (no args) or "<cmd> <args>".  Returns 0 on success, -1 on a
 * malformed object or a missing "cmd".
 */
int
fp_json_to_verb(const char *json, char *out, size_t outsz)
{
    char cmd[64]  = "";
    char args[1900] = "";

    if (json_object_get(json, "cmd", cmd, sizeof cmd) != 1 || cmd[0] == '\0') {
        return -1;                          /* "cmd" is required */
    }
    if (json_object_get(json, "args", args, sizeof args) < 0) {
        return -1;                          /* present but malformed */
    }

    int n;
    if (args[0] != '\0') {
        n = snprintf(out, outsz, "%s %s", cmd, args);
    } else {
        n = snprintf(out, outsz, "%s", cmd);
    }
    if (n < 0 || (size_t) n >= outsz) {
        return -1;
    }
    return 0;
}
