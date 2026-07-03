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

/* ---- Add one valid namespace prefix ----
 *
 * WHAT: appends `pfx[0..len)` to the grammar prefix table. Returns 1 on
 *   success, 0 if the fixed table is full.
 *
 * WHY: operators narrow the guarded namespace per location (an ARC endpoint
 *   root, a WebDAV export root) beyond the profile defaults.
 *
 * HOW: 1. Refuse when n_prefixes is at GUARD_MAX_PREFIXES.
 *      2. Store the borrowed pointer + length and bump the count.
 */
int
guard_ruleset_add_prefix(guard_ruleset_t *rs, const char *pfx, size_t len)
{
    if (rs->n_prefixes >= GUARD_MAX_PREFIXES) {
        return 0;
    }
    rs->prefixes[rs->n_prefixes]   = pfx;
    rs->prefix_len[rs->n_prefixes] = len;
    rs->n_prefixes++;
    return 1;
}

/* ---- Permit a fixed list of op-classes ----
 *
 * WHAT: sets op_allowed[op] = 1 for each entry of ops[0..count).
 *
 * WHY: profile grammars are op-lists; a tiny shared setter keeps each
 *   profile branch declarative.
 *
 * HOW: 1. Walk the list, flip each slot on.
 */
static void
allow_ops(guard_ruleset_t *rs, const guard_op_class_t *ops, int count)
{
    int op_index;

    for (op_index = 0; op_index < count; op_index++) {
        rs->op_allowed[ops[op_index]] = 1;
    }
}

/* ---- Load built-in grammar defaults for a service profile ----
 *
 * WHAT: configures rs for "arc" (ARC REST namespaces + job ops), "xrdhttp"
 *   (root-open export, data ops only), or "root" (root:// op-classes incl.
 *   handshake). Unknown profiles get permissive grammar (signatures still
 *   apply). Always enables grammar enforcement + both outcome flags except
 *   in the unknown-profile case, where grammar drops to advisory.
 *
 * WHY: sensible per-service defaults mean a bare `profile arc;` directive is
 *   already useful; operators refine with explicit prefix/method directives.
 *
 * HOW: 1. Turn on enforcement + notfound/authfail flagging.
 *      2. Per profile: add namespace prefixes (arc only — xrdhttp/root serve
 *         the export root) and allow that service's op-classes.
 *      3. Unknown profile: allow every op, drop to advisory grammar.
 */
void
guard_ruleset_load_profile(guard_ruleset_t *rs, const char *profile)
{
    rs->enforce_grammar = 1;
    rs->flag_notfound   = 1;
    rs->flag_authfail   = 1;

    if (strcmp(profile, "arc") == 0) {
        static const guard_op_class_t arc_ops[] = {
            GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
            GUARD_OP_JOBCTL, GUARD_OP_STAGE, GUARD_OP_INFO, GUARD_OP_DELEG };
        guard_ruleset_add_prefix(rs, "/arex", 5);
        guard_ruleset_add_prefix(rs, "/rest", 5);
        guard_ruleset_add_prefix(rs, "/datadelivery", 13);
        allow_ops(rs, arc_ops, (int) (sizeof(arc_ops) / sizeof(arc_ops[0])));
    } else if (strcmp(profile, "xrdhttp") == 0) {
        static const guard_op_class_t dav_ops[] = {
            GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
            GUARD_OP_INFO };
        /* XrdHttp/WebDAV serves the export root; operator narrows via
         * brix_guard_valid_prefix. Default: root-open but grammar on ops. */
        allow_ops(rs, dav_ops, (int) (sizeof(dav_ops) / sizeof(dav_ops[0])));
    } else if (strcmp(profile, "root") == 0) {
        static const guard_op_class_t root_ops[] = {
            GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
            GUARD_OP_INFO, GUARD_OP_STAGE, GUARD_OP_HANDSHAKE };
        allow_ops(rs, root_ops,
            (int) (sizeof(root_ops) / sizeof(root_ops[0])));
    } else {
        /* unknown profile: permissive grammar, signatures still apply */
        int op_index;
        for (op_index = 0; op_index <= GUARD_OP_UNKNOWN; op_index++) {
            rs->op_allowed[op_index] = 1;
        }
        rs->enforce_grammar = 0;
    }
}
