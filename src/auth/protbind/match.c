/*
 * match.c — protbind name/id mapping and host-template matching.
 *
 * WHAT: Owns the two pure lookups the protbind engine is built from: the
 *       protocol-token ↔ BRIX_AUTH_* id table, and the single-wildcard host
 *       template matcher.
 *
 * WHY:  Both are total, side-effect-free functions over their inputs, so they
 *       are kept apart from policy.c (which composes them into a verdict) and
 *       config.c (which only needs the name table).  That split is what makes
 *       the template semantics unit-testable on their own.
 *
 * HOW:  A static descriptor table drives the name mapping in both directions;
 *       the matcher splits a template at its first `*` into a prefix and a
 *       suffix and compares both ends case-insensitively, which is exactly
 *       XrdOucNList's behaviour (the class stock XrdSecServer matches
 *       sec.protbind templates with).
 */

#include "core/ngx_brix_module.h"
#include "protbind.h"

/*
 * One row of the protocol-token table.
 *
 * `name` is the canonical wire/directive token and `alias` an accepted second
 * spelling (BriX has always called the ztn scheme "token" in `brix_auth`, so
 * both spellings must parse); NULL alias means there is only one spelling.
 */
typedef struct {
    const char  *name;
    const char  *alias;
    ngx_uint_t   proto;
} brix_protbind_name_t;

/* Declaration order is documentation only; lookups are by name or by id. */
static const brix_protbind_name_t  brix_protbind_names[] = {
    { "gsi",  NULL,    BRIX_AUTH_GSI   },
    { "ztn",  "token", BRIX_AUTH_TOKEN },
    { "sss",  NULL,    BRIX_AUTH_SSS   },
    { "unix", NULL,    BRIX_AUTH_UNIX  },
    { "krb5", NULL,    BRIX_AUTH_KRB5  },
    { "host", NULL,    BRIX_AUTH_HOST  },
    { "pwd",  NULL,    BRIX_AUTH_PWD   },
};

#define BRIX_PROTBIND_NAME_COUNT \
    (sizeof(brix_protbind_names) / sizeof(brix_protbind_names[0]))

/*
 * brix_protbind_token_is — does an ngx_str_t token equal a NUL-terminated name?
 *
 * WHAT: Returns 1 on an exact, length-checked, case-sensitive match.
 *
 * WHY:  Directive tokens are ngx_str_t (not NUL-terminated), so the comparison
 *       must be length-bounded; protocol names are lower-case by definition in
 *       both XRootD's grammar and BriX's, so no case folding is wanted here —
 *       an upper-case "GSI" should be rejected as a typo, not silently bound.
 *
 * HOW:  Compare lengths first, then the bytes.
 */
static ngx_flag_t
brix_protbind_token_is(const ngx_str_t *token, const char *name)
{
    size_t  name_len = ngx_strlen(name);

    return token->len == name_len
           && ngx_strncmp(token->data, name, name_len) == 0;
}

/* ---- Map a directive token to its BRIX_AUTH_* id ----
 *
 * WHAT: On a known token writes its id through `out` and returns NGX_OK;
 *       returns NGX_DECLINED (leaving *out untouched) for anything else.
 *
 * WHY:  The config parser must reject unknown protocol names loudly rather
 *       than binding a host template to a scheme the server cannot run.
 *
 * HOW:  1. Walk the descriptor table.
 *       2. Accept either the canonical name or the row's alias.
 *       3. Publish the id and return NGX_OK; fall through to NGX_DECLINED.
 */
ngx_int_t
brix_protbind_proto_id(const ngx_str_t *name, ngx_uint_t *out)
{
    ngx_uint_t  row;

    for (row = 0; row < BRIX_PROTBIND_NAME_COUNT; row++) {
        const brix_protbind_name_t *entry = &brix_protbind_names[row];

        if (brix_protbind_token_is(name, entry->name)
            || (entry->alias != NULL
                && brix_protbind_token_is(name, entry->alias)))
        {
            *out = entry->proto;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

/* ---- Match a peer hostname against one host template ----
 *
 * WHAT: Returns 1 when `host` satisfies `tpl`, 0 otherwise.  A bare "*"
 *       matches unconditionally — including a NULL or empty host, so a
 *       wildcard-only ruleset never forces a reverse-DNS lookup.
 *
 * WHY:  Stock XRootD matches sec.protbind templates with XrdOucNList, whose
 *       contract is "at most one `*`, splitting the template into a prefix and
 *       a suffix that must both be present, in order, in the name".  Matching
 *       that behaviour byte-for-byte is what makes an existing site's
 *       sec.protbind stanza mean the same thing here.  Comparison is
 *       case-insensitive because DNS names are.
 *
 * HOW:  1. Reject an empty template; accept a bare "*" immediately.
 *       2. With no `*`, require an exact case-insensitive equality.
 *       3. Otherwise split at the FIRST `*` into prefix/suffix, require the
 *          host to be at least as long as their sum (so the two never overlap),
 *          and compare each end.  Any later `*` stays a literal byte of the
 *          suffix, matching XrdOucNList.
 */
ngx_flag_t
brix_protbind_host_match(const ngx_str_t *tpl, const char *host)
{
    u_char  *star;
    size_t   host_len, prefix_len, suffix_len;

    if (tpl->len == 0) {
        return 0;
    }

    if (tpl->len == 1 && tpl->data[0] == '*') {
        return 1;
    }

    if (host == NULL || host[0] == '\0') {
        return 0;
    }

    host_len = ngx_strlen(host);
    star = ngx_strlchr(tpl->data, tpl->data + tpl->len, '*');

    if (star == NULL) {
        return host_len == tpl->len
               && ngx_strncasecmp((u_char *) host, tpl->data, tpl->len) == 0;
    }

    prefix_len = (size_t) (star - tpl->data);
    suffix_len = tpl->len - prefix_len - 1;

    if (host_len < prefix_len + suffix_len) {
        return 0;
    }

    if (prefix_len > 0
        && ngx_strncasecmp((u_char *) host, tpl->data, prefix_len) != 0)
    {
        return 0;
    }

    if (suffix_len > 0
        && ngx_strncasecmp((u_char *) host + host_len - suffix_len,
                           star + 1, suffix_len) != 0)
    {
        return 0;
    }

    return 1;
}

/* ---- Does this ruleset ever need a resolved peer hostname? ----
 *
 * WHAT: Returns 1 when at least one rule carries a template other than a bare
 *       "*", i.e. when matching cannot be decided from the wildcard alone.
 *
 * WHY:  Reverse DNS is a blocking network round-trip on the event loop's
 *       critical path.  The dominant configuration is a single
 *       `brix_protbind * <protos>` line, which is decidable without any lookup;
 *       asking this question first keeps that case free.
 *
 * HOW:  Scan the rule array for any template that is not exactly "*".
 */
ngx_flag_t
brix_protbind_needs_hostname(ngx_array_t *rules)
{
    brix_protbind_rule_t  *rule;
    ngx_uint_t             index;

    if (rules == NULL) {
        return 0;
    }

    rule = rules->elts;
    for (index = 0; index < rules->nelts; index++) {
        if (rule[index].host_tpl.len != 1
            || rule[index].host_tpl.data[0] != '*')
        {
            return 1;
        }
    }

    return 0;
}

/* ---- Can any rule select this protocol? ----
 *
 * WHAT: Returns 1 when at least one rule lists `proto` (a BRIX_AUTH_* id).
 *
 * WHY:  The per-scheme startup loaders (GSI trust store, token issuers, krb5
 *       keytab, SSS keytab) each run only when `brix_auth` selects their
 *       scheme.  A protbind rule can select a scheme the mode did not, so the
 *       loaders must ask this too — otherwise a rule naming `gsi` would
 *       advertise a protocol whose certificate was never loaded, which fails
 *       at the first handshake instead of at config time.
 *
 * HOW:  Scan every rule's protocol list.  BRIX_PROTBIND_NONE rules carry no
 *       protocols, so they never match.
 */
ngx_flag_t
brix_protbind_any_names(ngx_array_t *rules, ngx_uint_t proto)
{
    brix_protbind_rule_t  *rule;
    ngx_uint_t             index, slot;

    if (rules == NULL) {
        return 0;
    }

    rule = rules->elts;
    for (index = 0; index < rules->nelts; index++) {
        for (slot = 0; slot < rule[index].count; slot++) {
            if (rule[index].protos[slot] == proto) {
                return 1;
            }
        }
    }

    return 0;
}
