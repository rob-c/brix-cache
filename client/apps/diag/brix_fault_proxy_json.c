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

/*
 * Parse a JSON string starting at `*pp` (which must point at the opening quote),
 * decoding escapes into `out` (NUL-terminated, bounded by `outsz`).  Advances
 * `*pp` past the closing quote.  Returns 0 on success, -1 on malformed input or
 * overflow.  \uXXXX is emitted as UTF-8 (BMP only, control-plane text).
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
            char e = *p;
            char dec;
            switch (e) {
            case '"':  dec = '"';  break;
            case '\\': dec = '\\'; break;
            case '/':  dec = '/';  break;
            case 'b':  dec = '\b'; break;
            case 'f':  dec = '\f'; break;
            case 'n':  dec = '\n'; break;
            case 'r':  dec = '\r'; break;
            case 't':  dec = '\t'; break;
            case 'u': {
                int h0 = hex_nibble(p[1]), h1 = hex_nibble(p[2]);
                int h2 = hex_nibble(p[3]), h3 = hex_nibble(p[4]);
                if (h0 < 0 || h1 < 0 || h2 < 0 || h3 < 0) {
                    return -1;
                }
                unsigned cp = (unsigned) ((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                p += 4;
                if (cp < 0x80) {
                    if (o + 1 >= outsz) return -1;
                    out[o++] = (char) cp;
                } else if (cp < 0x800) {
                    if (o + 2 >= outsz) return -1;
                    out[o++] = (char) (0xC0 | (cp >> 6));
                    out[o++] = (char) (0x80 | (cp & 0x3F));
                } else {
                    if (o + 3 >= outsz) return -1;
                    out[o++] = (char) (0xE0 | (cp >> 12));
                    out[o++] = (char) (0x80 | ((cp >> 6) & 0x3F));
                    out[o++] = (char) (0x80 | (cp & 0x3F));
                }
                p++;
                continue;
            }
            default:
                return -1;                  /* invalid escape */
            }
            if (o + 1 >= outsz) return -1;
            out[o++] = dec;
            p++;
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
static int
json_object_get(const char *json, const char *key, char *out, size_t outsz)
{
    const char *p = json_skip_ws(json);
    if (*p != '{') {
        return -1;
    }
    p++;
    p = json_skip_ws(p);
    if (*p == '}') {
        return 0;                           /* empty object */
    }
    for (;;) {
        char kbuf[64];
        p = json_skip_ws(p);
        if (json_parse_string(&p, kbuf, sizeof kbuf) != 0) {
            return -1;
        }
        p = json_skip_ws(p);
        if (*p != ':') {
            return -1;
        }
        p++;
        p = json_skip_ws(p);
        if (strcmp(kbuf, key) == 0) {
            if (*p != '"') {
                return -1;                  /* we only accept string values */
            }
            return json_parse_string(&p, out, outsz) == 0 ? 1 : -1;
        }
        /* Not our key: skip this value (string, or a bare token up to , or }). */
        if (*p == '"') {
            char skip[512];
            if (json_parse_string(&p, skip, sizeof skip) != 0) {
                return -1;
            }
        } else {
            while (*p != '\0' && *p != ',' && *p != '}') {
                p++;
            }
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
