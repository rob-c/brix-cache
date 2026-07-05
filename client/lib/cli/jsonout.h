#ifndef BRIX_CLI_JSONOUT_H
#define BRIX_CLI_JSONOUT_H
#include <stdio.h>

/* WHAT: minimal shared JSON emit helpers for the CLI tools' --json modes.
 * WHY:  one escaping implementation across xrdfs/xrddiag — divergent
 *       hand-rolled escapers are a classic output-injection bug.
 * HOW:  RFC 8259 string escaping; bytes <0x20 and >=0x80 emit \u00XX so the
 *       output is pure ASCII regardless of on-wire filename bytes. */
void brix_json_escape(FILE *out, const char *s);   /* escaped, no quotes  */
void brix_json_fputs(FILE *out, const char *s);    /* "escaped"           */
void brix_json_kv_str(FILE *out, const char *k, const char *v, int comma);
void brix_json_kv_ll(FILE *out, const char *k, long long v, int comma);
void brix_json_kv_bool(FILE *out, const char *k, int v, int comma);

#endif
