/*
 * guard_classify.c — bad-actor request classification.
 *
 * WHAT: the classifier half of the guard core: signature-blocklist matching,
 *   namespace-grammar checks, and the pre-backend / post-response verdicts
 *   built on them.
 * WHY:  every adapter (ARC HTTP, XrdHttp/WebDAV, root:// relay) needs the same
 *   junk-vs-legitimate decision; keeping it pure C makes the decision
 *   testable without a server.
 * HOW:  pure functions over a caller-built guard_ruleset_t and a normalized
 *   guard_request_t — no allocation, no I/O, no globals.
 */
#include "guard.h"
#include <string.h>

/* ---- Test one signature pattern against a path ----
 *
 * WHAT: returns 1 if `path[0..len)` matches signature `s` (case-sensitive
 *   suffix, prefix, or substring per s->kind), else 0.
 *
 * WHY: the three pattern kinds cover the junk-scanner corpus (extension
 *   probes, well-known directory probes, embedded traversal/artifact tokens)
 *   without regex machinery in a pure-C core.
 *
 * HOW: 1. Reject empty or over-long patterns (can never match).
 *      2. SUFFIX: memcmp against the path tail.
 *      3. PREFIX: memcmp against the path head.
 *      4. SUBSTR: sliding-window memcmp across the path.
 */
static int
sig_hit(const guard_sig_t *s, const char *path, size_t len)
{
    if (s->pat_len == 0 || s->pat_len > len) {
        return 0;
    }
    switch (s->kind) {
    case GUARD_SIG_SUFFIX:
        return memcmp(path + len - s->pat_len, s->pat, s->pat_len) == 0;
    case GUARD_SIG_PREFIX:
        return memcmp(path, s->pat, s->pat_len) == 0;
    case GUARD_SIG_SUBSTR:
    default: {
        size_t window_start;
        for (window_start = 0; window_start + s->pat_len <= len;
             window_start++)
        {
            if (memcmp(path + window_start, s->pat, s->pat_len) == 0) {
                return 1;
            }
        }
        return 0;
    }
    }
}

/* ---- Match a path against the ruleset's signature blocklist ----
 *
 * WHAT: returns 1 if `path[0..len)` matches any configured signature, else 0.
 *
 * WHY: signatures are the highest-confidence bad-actor tell — a single hit on
 *   a grid data path (".php", "/wp-", "/.env") identifies a scanner, so this
 *   is the first check every adapter runs.
 *
 * HOW: 1. Linearly test each configured signature via sig_hit().
 *      2. First hit wins; order is irrelevant to the verdict.
 */
int
guard_signature_match(const guard_ruleset_t *rs, const char *path, size_t len)
{
    int sig_index;

    for (sig_index = 0; sig_index < rs->n_sigs; sig_index++) {
        if (sig_hit(&rs->sigs[sig_index], path, len)) {
            return 1;
        }
    }
    return 0;
}
