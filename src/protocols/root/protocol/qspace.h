/*
 * qspace.h — kXR_Qspace "oss.*" space-report grammar (single source of truth).
 *
 * WHAT: the kXR_Qspace (3015) response body is an "&"-joined key/value report:
 *         oss.cgroup=default&oss.space=<total>&oss.free=<free>&oss.maxf=<maxf>
 *         &oss.used=<used>&oss.quota=-1
 *       This header co-locates both halves of that grammar:
 *         - brix_qspace_format: bytes  -> the oss.* report (server emit)
 *         - brix_qspace_parse:  report -> total/free bytes (client decode)
 * WHY:  the server formatted the report (src/query/space.c) and the native client
 *       picked the oss.space=/oss.free= tokens back out (client/lib/posix_map.c)
 *       with the token spellings AND their byte offsets hand-written on each side
 *       (the parser even hard-coded `p + 10` / `p + 9` for the key lengths). One
 *       definition keeps the emit and the decode on the same token vocabulary.
 * HOW:  header-only static inlines over libc (snprintf/strstr/strtoull) — no ngx,
 *       no allocation — so the same code compiles into the nginx module and the
 *       ngx-free client. The key offsets are derived from the token macros, never
 *       re-spelled as integer literals.
 *
 * Clean-room: token grammar from the reference xrootd Qspace response (oss.* keys).
 */
#ifndef BRIX_PROTOCOL_QSPACE_H
#define BRIX_PROTOCOL_QSPACE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The two tokens both trees agree on (the server emits all keys; the client only
 * needs these two). Keep the trailing '=' so the parser's offset is sizeof()-1. */
#define BRIX_QSPACE_TOK_TOTAL  "oss.space="
#define BRIX_QSPACE_TOK_FREE   "oss.free="

/*
 * Format the full oss.* capacity report (server). `maxf` is the max single-file
 * allocation (the reference server reports it equal to free when no quota is
 * enforced); quota is fixed at -1 (unlimited). Returns snprintf's value.
 */
static inline int
brix_qspace_format(char *out, size_t outsz, unsigned long long total,
                     unsigned long long freeb, unsigned long long maxf,
                     unsigned long long used)
{
    return snprintf(out, outsz,
                    "oss.cgroup=default"
                    "&" BRIX_QSPACE_TOK_TOTAL "%llu"
                    "&" BRIX_QSPACE_TOK_FREE  "%llu"
                    "&oss.maxf=%llu"
                    "&oss.used=%llu"
                    "&oss.quota=-1",
                    total, freeb, maxf, used);
}

/*
 * Extract total and free bytes from an oss.* report (client). Either out-pointer
 * may be NULL; both default to 0 (also the value when a token is absent). Matches
 * the token anywhere in the string (the keys are order-independent on the wire).
 */
static inline void
brix_qspace_parse(const char *text, unsigned long long *total,
                    unsigned long long *freeb)
{
    const char *p;

    if (total != NULL) { *total = 0; }
    if (freeb != NULL) { *freeb = 0; }
    if (text == NULL) {
        return;
    }

    p = strstr(text, BRIX_QSPACE_TOK_TOTAL);
    if (p != NULL && total != NULL) {
        *total = strtoull(p + (sizeof(BRIX_QSPACE_TOK_TOTAL) - 1), NULL, 10);
    }
    p = strstr(text, BRIX_QSPACE_TOK_FREE);
    if (p != NULL && freeb != NULL) {
        *freeb = strtoull(p + (sizeof(BRIX_QSPACE_TOK_FREE) - 1), NULL, 10);
    }
}

#endif /* BRIX_PROTOCOL_QSPACE_H */
