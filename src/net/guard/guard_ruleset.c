/*
 * guard_ruleset.c — guard ruleset construction.
 *
 * WHAT: builders that populate a guard_ruleset_t: zero-init, the built-in
 *   junk-scanner signature set, operator-supplied signatures/prefixes, and
 *   per-profile grammar defaults ("arc" | "xrdhttp" | "root").
 * WHY:  adapters (nginx http module, stream relay) assemble rulesets at config
 *   time from directives; the assembly logic itself is protocol-agnostic and
 *   lives here, next to the classifier that consumes it.
 * HOW:  pure C, no allocation — patterns are borrowed pointers that must
 *   outlive the ruleset (string literals or nginx conf-pool strings).
 */
#include "guard.h"
#include <string.h>

/* ---- Zero a ruleset ----
 *
 * WHAT: resets every field of *rs to zero (no signatures, no prefixes, no ops
 *   allowed, grammar not enforced, outcome flags off).
 *
 * WHY: gives adapters one canonical empty state to build on, so a
 *   half-initialized ruleset can never classify.
 *
 * HOW: 1. memset the whole struct.
 */
void
guard_ruleset_init(guard_ruleset_t *rs)
{
    memset(rs, 0, sizeof(*rs));
}

/* ---- Add one signature to the blocklist ----
 *
 * WHAT: appends (kind, pat, pat_len) to rs->sigs. Returns 1 on success, 0 if
 *   the fixed table is full.
 *
 * WHY: operator directives and the built-in defaults share one append path,
 *   with a hard cap instead of allocation (pure-C core rule).
 *
 * HOW: 1. Refuse when n_sigs is at GUARD_MAX_SIGS.
 *      2. Store the borrowed pattern pointer + length and bump the count.
 */
int
guard_ruleset_add_signature(guard_ruleset_t *rs, guard_sig_kind_t kind,
    const char *pat, size_t pat_len)
{
    if (rs->n_sigs >= GUARD_MAX_SIGS) {
        return 0;
    }
    rs->sigs[rs->n_sigs].kind    = kind;
    rs->sigs[rs->n_sigs].pat     = pat;
    rs->sigs[rs->n_sigs].pat_len = pat_len;
    rs->n_sigs++;
    return 1;
}

/* ---- Append the built-in junk-scanner signature set ----
 *
 * WHAT: adds the default web-scanner corpus (php/asp/cgi extension probes,
 *   wordpress/cgi-bin/vendor/.git prefixes, .env//../ /phpMyAdmin/.aws
 *   substrings) to rs.
 *
 * WHY: these patterns never appear in legitimate grid traffic (ARC REST,
 *   WebDAV data paths, root:// namespaces) but dominate internet scanner
 *   noise — a curated default beats making every operator assemble one.
 *
 * HOW: 1. Walk a static descriptor table (string literals — they outlive any
 *         ruleset by definition).
 *      2. Append each via guard_ruleset_add_signature().
 */
void
guard_ruleset_add_default_signatures(guard_ruleset_t *rs)
{
    static const struct { guard_sig_kind_t kind; const char *pat; } defaults[] = {
        { GUARD_SIG_SUFFIX, ".php" },   { GUARD_SIG_SUFFIX, ".asp" },
        { GUARD_SIG_SUFFIX, ".aspx" },  { GUARD_SIG_SUFFIX, ".cgi" },
        { GUARD_SIG_PREFIX, "/wp-" },   { GUARD_SIG_PREFIX, "/cgi-bin" },
        { GUARD_SIG_PREFIX, "/vendor" },{ GUARD_SIG_PREFIX, "/.git" },
        { GUARD_SIG_SUBSTR, "/.env" },  { GUARD_SIG_SUBSTR, "phpMyAdmin" },
        { GUARD_SIG_SUBSTR, "/../" },   { GUARD_SIG_SUBSTR, "/.aws" },
        { GUARD_SIG_SUBSTR, "/wp-config" },
    };
    size_t default_index;

    for (default_index = 0;
         default_index < sizeof(defaults) / sizeof(defaults[0]);
         default_index++)
    {
        guard_ruleset_add_signature(rs, defaults[default_index].kind,
            defaults[default_index].pat, strlen(defaults[default_index].pat));
    }
}
