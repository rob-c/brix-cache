/*
 * suggest.c — Damerau-Levenshtein closest-match helper (spec WS-7).
 *
 * WHAT: brix_suggest(arg, candidates) finds the first candidate within
 *       Damerau-Levenshtein edit distance ≤ 2 from arg (first-in-table tiebreak).
 * WHY:  powers "did you mean?" hints at every unknown-subcommand/type error so
 *       users see actionable feedback instead of a bare "unknown command" line.
 * HOW:  classic Damerau-Levenshtein DP with adjacent transpositions using a
 *       fixed-size stack matrix (max 65 × 65 cells); arg is capped at 64 bytes
 *       before comparison; function iterates the NULL-terminated candidates
 *       table and returns the first hit at distance ≤ 2, or NULL.
 */
#include "cli/suggest.h"

#include <stddef.h>
#include <string.h>

/* Maximum bytes of arg to consider (spec WS-7: "caps… at 64 bytes"). */
#define SUGGEST_ARG_MAX 64

/* Maximum candidate length this function handles; equal to SUGGEST_ARG_MAX so
 * the fixed-size DP table d[SUGGEST_ARG_MAX+1][SUGGEST_ARG_MAX+1] can hold
 * both dimensions without overflow.  A 65-char candidate CAN be DL-distance 1
 * from a 64-char arg (a single insertion), but since dl_distance rejects any
 * blen > SUGGEST_ARG_MAX via its own overflow guard, those calls would just
 * return the sentinel — so we skip them early here instead.  Equal caps give
 * the tightest early-exit bound consistent with the DP table size. */
#define SUGGEST_CAND_MAX SUGGEST_ARG_MAX

/*
 * WHAT: compute the Damerau-Levenshtein distance between two strings.
 * WHY:  handles single-keystroke transpositions (e.g. "satt"→"stat") that
 *       plain Levenshtein does not count as one edit.
 * HOW:  classic O(n·m) DP table (restricted DL, adjacent transpositions only).
 *       Strings are passed as length-bounded slices to avoid re-strlen.
 *       Returns the exact DL distance, or SUGGEST_ARG_MAX+1 on overflow.
 */
static unsigned int
dl_distance(const char *a, size_t alen,
            const char *b, size_t blen)
{
    /* Stack-allocate a (alen+1) × (blen+1) table.
     * Both dimensions are ≤ SUGGEST_ARG_MAX+1 = 65. */
    unsigned int d[SUGGEST_ARG_MAX + 1][SUGGEST_ARG_MAX + 1];
    size_t       i, j;

    /* Guard: if either string exceeds our cap, they can't be within distance 2
     * of each other — return a large sentinel. */
    if (alen > SUGGEST_ARG_MAX || blen > SUGGEST_ARG_MAX) {
        return SUGGEST_ARG_MAX + 1;
    }

    for (i = 0; i <= alen; i++) { d[i][0] = (unsigned int) i; }
    for (j = 0; j <= blen; j++) { d[0][j] = (unsigned int) j; }

    for (i = 1; i <= alen; i++) {
        for (j = 1; j <= blen; j++) {
            unsigned int cost = (a[i - 1] == b[j - 1]) ? 0u : 1u;
            unsigned int del  = d[i - 1][j] + 1;
            unsigned int ins  = d[i][j - 1] + 1;
            unsigned int sub  = d[i - 1][j - 1] + cost;
            unsigned int best = del < ins ? del : ins;
            best = best < sub ? best : sub;
            /* Adjacent transposition (Damerau extension). */
            if (i > 1 && j > 1
                    && a[i - 1] == b[j - 2]
                    && a[i - 2] == b[j - 1]) {
                unsigned int trans = d[i - 2][j - 2] + cost;
                if (trans < best) { best = trans; }
            }
            d[i][j] = best;
        }
    }
    return d[alen][blen];
}

const char *
brix_suggest(const char *arg, const char *const *candidates)
{
    /*
     * WHAT: iterate the NULL-terminated candidate table and return the first
     *       entry within DL distance ≤ 2 from arg (capped at 64 bytes).
     * WHY:  first-in-table tiebreak ensures deterministic output; callers build
     *       their table with the most-likely candidates at the front.
     * HOW:  cap alen to SUGGEST_ARG_MAX; skip candidates longer than
     *       SUGGEST_CAND_MAX (they are unreachably far away from a short arg);
     *       return on the first distance ≤ 2 match, else NULL.
     */
    size_t       alen;
    size_t       i;

    if (arg == NULL || candidates == NULL) {
        return NULL;
    }

    alen = strlen(arg);
    if (alen > SUGGEST_ARG_MAX) {
        alen = SUGGEST_ARG_MAX;
    }

    for (i = 0; candidates[i] != NULL; i++) {
        size_t       clen = strlen(candidates[i]);
        unsigned int dist;

        if (clen > SUGGEST_CAND_MAX) {
            continue;   /* candidate too long to match any short arg */
        }
        dist = dl_distance(arg, alen, candidates[i], clen);
        if (dist <= 2) {
            return candidates[i];
        }
    }
    return NULL;
}
