/* jsonout.c — shared JSON string/kv emitters (see jsonout.h). */
#include "cli/jsonout.h"

/*
 * brix_json_escape — write the ESCAPED body of a JSON string (no quotes).
 *
 * WHAT: emits `s` to `out` with the JSON string escapes applied; a NULL `s`
 *       emits nothing.
 * WHY:  these strings routinely carry untrusted, server-supplied wire text
 *       (paths, status messages, directory-entry names), so control bytes,
 *       quotes and backslashes MUST be escaped or a hostile value could break
 *       out of the string and forge JSON structure — a security requirement.
 * HOW:  per-byte switch for the short escapes (" \\ \n \r \t); any other
 *       control byte (<0x20) or non-ASCII byte (>=0x80) becomes a \uXXXX escape;
 *       printable ASCII passes through verbatim.
 */
void
brix_json_escape(FILE *out, const char *s)
{
    const unsigned char *p;
    if (s == NULL) { return; }   /* NULL input: emit nothing; brix_json_fputs's surrounding quotes yield "" */
    p = (const unsigned char *) s;
    for (; *p != '\0'; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out);  break;
        case '\r': fputs("\\r", out);  break;
        case '\t': fputs("\\t", out);  break;
        default:
            if (*p < 0x20 || *p >= 0x80) {
                fprintf(out, "\\u%04x", (unsigned) *p);
            } else {
                fputc(*p, out);
            }
        }
    }
}

/*
 * brix_json_fputs — write a complete, quoted, escaped JSON string.
 *
 * WHAT: emits `"<escaped s>"` to `out` (a NULL `s` yields an empty string "").
 * WHY:  the single choke-point for emitting any JSON string value or key, so
 *       every string in the output is quoted AND escaped the same safe way.
 * HOW:  writes the opening quote, delegates the body to brix_json_escape, then
 *       writes the closing quote.
 */
void
brix_json_fputs(FILE *out, const char *s)
{
    fputc('"', out);
    brix_json_escape(out, s);
    fputc('"', out);
}

/*
 * brix_json_kv_str — write a "key":"value" pair, optionally comma-terminated.
 *
 * WHAT: emits `"<k>":"<v>"` (both escaped) plus a trailing ',' when `comma`.
 * WHY:  object fields carrying string values are the common case; folding the
 *       colon and optional separator here keeps every call site uniform.
 * HOW:  brix_json_fputs for the key, a ':', brix_json_fputs for the value, then
 *       a ',' iff `comma` is nonzero.
 */
void
brix_json_kv_str(FILE *out, const char *k, const char *v, int comma)
{
    brix_json_fputs(out, k);
    fputc(':', out);
    brix_json_fputs(out, v);
    if (comma) { fputc(',', out); }
}

/*
 * brix_json_kv_ll — write a "key":<number> pair, optionally comma-terminated.
 *
 * WHAT: emits `"<k>":<v>` with `v` as a decimal long long, plus a trailing ','
 *       when `comma`.
 * WHY:  numeric fields (sizes, mtimes, counts) must appear unquoted so JSON
 *       consumers read them as numbers, not strings.
 * HOW:  brix_json_fputs for the (escaped) key, then a printf of ":%lld" and the
 *       optional separator.
 */
void
brix_json_kv_ll(FILE *out, const char *k, long long v, int comma)
{
    brix_json_fputs(out, k);
    fprintf(out, ":%lld%s", v, comma ? "," : "");
}

/*
 * brix_json_kv_bool — write a "key":true|false pair, optionally comma-terminated.
 *
 * WHAT: emits `"<k>":true` or `"<k>":false` (nonzero `v` = true), plus a
 *       trailing ',' when `comma`.
 * WHY:  boolean fields must be the JSON literals true/false, never quoted or 0/1.
 * HOW:  brix_json_fputs for the (escaped) key, then a printf of the literal and
 *       the optional separator.
 */
void
brix_json_kv_bool(FILE *out, const char *k, int v, int comma)
{
    brix_json_fputs(out, k);
    fprintf(out, ":%s%s", v ? "true" : "false", comma ? "," : "");
}
