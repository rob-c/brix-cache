/*
 * unit_check.h — shared scaffold for the standalone (plain-gcc, nginx-free)
 * unit tests under shared/: the CHECK counter pair, best-effort recursive
 * fixture removal, and an opt-in zlib compression helper.
 *
 * Usage: #include "testkit/unit_check.h" (needs -I shared). Define
 * BRIX_UNIT_WANT_ZLIB before including — and link -lz — to get zlib_of().
 */
#ifndef BRIX_TESTKIT_UNIT_CHECK_H
#define BRIX_TESTKIT_UNIT_CHECK_H

#include <stdio.h>
#include <stdlib.h>

static int g_checks, g_failed;

#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/* Best-effort removal of a test fixture tree. */
static inline void rm_rf(const char *p) {
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    if (system(cmd) != 0) { /* best effort */ }
}

#ifdef BRIX_UNIT_WANT_ZLIB
#include <zlib.h>

/* zlib-compress src into a malloc'd buffer; caller frees. */
static inline unsigned char *zlib_of(const unsigned char *src, size_t n,
                                     size_t *outn) {
    uLongf cap = compressBound(n);
    unsigned char *buf = malloc(cap);
    compress(buf, &cap, src, n);
    *outn = cap;
    return buf;
}
#endif

#endif /* BRIX_TESTKIT_UNIT_CHECK_H */
