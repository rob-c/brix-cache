/*
 * scan_engine_internal.h — symbols shared between the scan_engine.c
 * translation units (the POSIX-walk core and the catalog-enumeration split).
 *
 * Not a public API: only scan_engine.c and its scan_engine_<concern>.c siblings
 * include this. Everything here is defined in exactly one .c and referenced from
 * another; single-file symbols stay static in their own file.
 */
#ifndef BRIX_SCAN_ENGINE_INTERNAL_H
#define BRIX_SCAN_ENGINE_INTERNAL_H

#include <ngx_core.h>

/* One NDJSON line = JSON record (≤ SCAN record sizing) + '\n'. */
#define SCAN_LINE_MAX 3072

/* Append a ready NDJSON line (llen bytes) plus a newline to the growing heap
 * buffer. Returns 0 ok, -1 OOM (caller owns *buf on failure). Mirrors
 * brix_ckscan_append's exponential growth. Defined in scan_engine.c. */
int scan_append(u_char **buf, size_t *cap, size_t *used, const char *line,
    size_t llen);

#endif /* BRIX_SCAN_ENGINE_INTERNAL_H */
