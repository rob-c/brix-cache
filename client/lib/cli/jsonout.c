/* jsonout.c — shared JSON string/kv emitters (see jsonout.h). */
#include "cli/jsonout.h"

void
brix_json_escape(FILE *out, const char *s)
{
    const unsigned char *p;
    if (s == NULL) { return; }   /* NULL → empty string via brix_json_fputs */
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

void
brix_json_fputs(FILE *out, const char *s)
{
    fputc('"', out);
    brix_json_escape(out, s);
    fputc('"', out);
}

void
brix_json_kv_str(FILE *out, const char *k, const char *v, int comma)
{
    brix_json_fputs(out, k);
    fputc(':', out);
    brix_json_fputs(out, v);
    if (comma) { fputc(',', out); }
}

void
brix_json_kv_ll(FILE *out, const char *k, long long v, int comma)
{
    brix_json_fputs(out, k);
    fprintf(out, ":%lld%s", v, comma ? "," : "");
}

void
brix_json_kv_bool(FILE *out, const char *k, int v, int comma)
{
    brix_json_fputs(out, k);
    fprintf(out, ":%s%s", v ? "true" : "false", comma ? "," : "");
}
