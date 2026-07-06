/*
 * suggest.h — Damerau-Levenshtein closest-match helper (spec WS-7).
 *
 * WHAT: brix_suggest() finds the closest candidate from a NULL-terminated table
 *       using Damerau-Levenshtein distance, returning the first entry within
 *       distance ≤ 2.
 * WHY:  powers did-you-mean hints at every unknown-subcommand/type error site
 *       so users get actionable feedback instead of bare "unknown command" lines.
 * HOW:  declared here, implemented in suggest.c; callers include suggest.h and
 *       link against libbrix.
 */
#ifndef BRIX_SUGGEST_H
#define BRIX_SUGGEST_H

/*
 * Return the first candidate with Damerau-Levenshtein distance ≤ 2 from `arg`,
 * or NULL when no candidate is close enough.
 *
 * WHAT: closest-match lookup over a NULL-terminated string table.
 * WHY:  drives "did you mean?" hints; distance ≤ 2 covers single-key typos and
 *       common transpositions without producing spurious suggestions for clearly
 *       wrong input.
 * HOW:  arg is truncated to 64 bytes before comparison; ties broken by
 *       first-in-table order; NULL arg or NULL candidates returns NULL.
 */
const char *brix_suggest(const char *arg, const char *const *candidates);

#endif /* BRIX_SUGGEST_H */
