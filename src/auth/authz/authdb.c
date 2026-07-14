#include "core/ngx_brix_module.h"

#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "fs/path/path_internal.h"

/* Return 1 if `path` is at or beneath `prefix` (component-aligned prefix match). */
static ngx_flag_t
brix_path_prefix_match(const char *prefix, const char *path)
{
    size_t prefix_len;

    if (prefix == NULL || path == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(prefix, path, prefix_len) != 0) {
        return 0;
    }

    /* Require the match to fall on a path-component boundary so that prefix
     * "/foo" matches "/foo" (exact) and "/foo/bar" (child) but NOT "/foobar".
     * The char immediately after the prefix in path must therefore be either
     * end-of-string or a '/' separator. */
    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}
/* Compare the first `bits` of two packed addresses — the CIDR prefix-match core. */
static ngx_flag_t
brix_authdb_addr_prefix_match(const u_char *a, const u_char *b,
                                ngx_uint_t bits)
{
    ngx_uint_t full;
    ngx_uint_t rem;

    /* Compare two raw addresses (4 bytes IPv4 / 16 bytes IPv6) under a /bits
     * CIDR mask. Split the prefix length into whole bytes plus leftover bits:
     * the first `full` bytes must match exactly, and the next byte must match
     * only on its top `rem` bits. */
    full = bits / 8;
    rem = bits % 8;

    if (full > 0 && ngx_memcmp(a, b, full) != 0) {
        return 0;
    }

    if (rem != 0) {
        /* Top `rem` bits set: e.g. rem=3 -> 0xff << 5 -> 0b11100000. Mask both
         * addresses' partial byte and compare only the significant high bits. */
        u_char mask = (u_char) (0xffu << (8 - rem));
        if ((a[full] & mask) != (b[full] & mask)) {
            return 0;
        }
    }

    return 1;
}
/* Match a peer IP against a rule's host CIDR (rule_id is host/addr[/bits]). */
static ngx_flag_t
brix_authdb_host_cidr_match(const char *rule_id, const char *peer_ip)
{
    char        cidr[128];
    char       *slash;
    char       *end;
    long        bits;
    u_char      rule_addr[16];
    u_char      peer_addr[16];
    int         family;
    ngx_uint_t  max_bits;

    if (rule_id == NULL || peer_ip == NULL || peer_ip[0] == '\0') {
        return 0;
    }

    /* Reject anything that would not fit (with NUL) in the local cidr buffer;
     * this bounds the copy below and prevents reading a truncated CIDR. */
    if (strlen(rule_id) >= sizeof(cidr)) {
        return 0;
    }

    /* Work on a private mutable copy so we can split "addr/bits" in place. */
    ngx_cpystrn((u_char *) cidr, (u_char *) rule_id, sizeof(cidr));
    slash = strchr(cidr, '/');
    if (slash == NULL) {
        /* No '/': rule_id is a bare address -> require an exact string match
         * against the peer IP (no masking). */
        return strcmp(rule_id, peer_ip) == 0;
    }

    /* Split at '/': cidr now holds the address, slash holds the bit count. */
    *slash++ = '\0';
    /* Infer family from the address half; a ':' can only appear in IPv6. */
    if (strchr(cidr, ':') != NULL) {
        family = AF_INET6;
        max_bits = 128;
    } else {
        family = AF_INET;
        max_bits = 32;
    }

    /* Parse and validate the prefix length: must be a complete integer
     * (end consumed entirely, slash actually had digits) within [0, max_bits].
     * Any junk or out-of-range value rejects the rule rather than matching. */
    bits = strtol(slash, &end, 10);
    if (end == slash || *end != '\0' || bits < 0
        || (ngx_uint_t) bits > max_bits)
    {
        return 0;
    }

    if (inet_pton(family, cidr, rule_addr) != 1
        || inet_pton(family, peer_ip, peer_addr) != 1)
    {
        return 0;
    }

    return brix_authdb_addr_prefix_match(rule_addr, peer_addr,
                                           (ngx_uint_t) bits);
}
/* Match a peer IP against an authdb rule's host id (exact, hostname, or CIDR). */
static ngx_flag_t
brix_authdb_host_match(const ngx_str_t *rule_id, const char *peer_ip)
{
    if (rule_id == NULL || peer_ip == NULL || peer_ip[0] == '\0') {
        return 0;
    }

    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }

    return brix_authdb_host_cidr_match((const char *) rule_id->data,
                                         peer_ip);
}
/* WHAT: 1 if a user-type rule's id matches this identity's DN (wildcard or exact).
 * WHY:  isolates the USER matcher (exact/'*' split) from the dispatch switch.
 * HOW:  a bare '*' id matches any DN; otherwise require an exact string compare
 *       of the rule id against dn. dn may be an empty string (no match). */
static ngx_flag_t
adb_user_matches(const ngx_str_t *rule_id, const char *dn)
{
    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }
    return ngx_strcmp(rule_id->data, dn) == 0;
}

/* WHAT: 1 if a group-type rule's id matches this identity's VO list (wildcard or
 *       membership).
 * WHY:  isolates the GROUP matcher ('*'/VO-membership split) from the switch.
 * HOW:  a bare '*' id matches any VO list; otherwise the rule id (a VO name) must
 *       appear in the comma-separated vo_list. */
static ngx_flag_t
adb_group_matches(const ngx_str_t *rule_id, const char *vo_list)
{
    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }
    return brix_vo_list_contains(vo_list, (const char *) rule_id->data);
}

/* WHAT: 1 if `rule` applies to this identity by its matcher type; else 0.
 * WHY:  table-flat dispatch over the four rule kinds (all/user/group/host),
 *       keeping the caller's loop body linear. Pure — no I/O, no mutation.
 * HOW:  branch on rule->type: ALL matches unconditionally; USER splits to
 *       adb_user_matches(dn); GROUP to adb_group_matches(vo_list); HOST to
 *       brix_authdb_host_match(peer_ip). Any unknown type does not match
 *       (default-deny). Semantics are frozen against the multi-user conformance
 *       suite; do not alter the per-type rules. */
static ngx_flag_t
adb_identity_matches(const brix_authdb_rule_t *rule, const char *dn,
                     const char *vo_list, const char *peer_ip)
{
    switch (rule->type) {
    case BRIX_AUTH_ALL:
        return 1;
    case BRIX_AUTH_USER:
        return adb_user_matches(&rule->id, dn);
    case BRIX_AUTH_GROUP:
        return adb_group_matches(&rule->id, vo_list);
    case BRIX_AUTHDB_HOST:
        return brix_authdb_host_match(&rule->id, peer_ip);
    default:
        return 0;
    }
}

/* Find the authdb rule granting `needed_privs` on resolved_path for `identity`;
 * returns the matching rule or NULL. */
const brix_authdb_rule_t *
brix_find_authdb_rule_identity(const char *resolved_path, ngx_array_t *rules,
                        const brix_identity_t *identity,
                        const char *peer_ip, uint32_t needed_privs)
{
    const brix_authdb_rule_t *best = NULL;
    brix_authdb_rule_t       *rule;
    size_t                      best_len = 0;
    ngx_uint_t                  i;
    const char                 *dn;
    const char                 *vo_list;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    dn = brix_identity_dn_cstr(identity);
    vo_list = brix_identity_vo_csv_cstr(identity);

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!brix_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        if (!adb_identity_matches(&rule[i], dn, vo_list, peer_ip)) {
            continue;
        }

        /* Path + identity match: now require the rule to grant ALL needed bits
         * ((privs & needed) == needed). Only sufficient rules compete; among
         * them the longest prefix wins, with >= letting a later equal-length
         * rule override an earlier one (config last-wins on ties). This is the
         * XRootD longest-prefix semantics — frozen against the conformance suite. */
        if ((rule[i].privs & needed_privs) == needed_privs) {
            if (rule_len >= best_len) {
                best = &rule[i];
                best_len = rule_len;
            }
        }
    }

    return best;
}

/* Find the authdb rule granting needed_privs on resolved_path for ctx's identity
 * (wraps the _identity form). */
const brix_authdb_rule_t *
brix_find_authdb_rule(const char *resolved_path, ngx_array_t *rules,
                        brix_ctx_t *ctx, uint32_t needed_privs)
{
    brix_identity_t fallback;

    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->identity != NULL) {
        return brix_find_authdb_rule_identity(resolved_path, rules,
                                                ctx->identity, ctx->login.peer_ip,
                                                needed_privs);
    }

    /* Legacy path: wrap the raw dn/vo_list strings in a transient identity.
     * Fields alias ctx storage (no ownership); safe for this synchronous call. */
    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->login.dn;
    fallback.dn.len = strlen(ctx->login.dn);
    fallback.vo_csv.data = (u_char *) ctx->login.vo_list;
    fallback.vo_csv.len = strlen(ctx->login.vo_list);

    return brix_find_authdb_rule_identity(resolved_path, rules,
                                            &fallback, ctx->login.peer_ip,
                                            needed_privs);
}
/* Authorize `query->identity` for query->needed_privs on query->resolved_path
 * against query->rules. Returns NGX_OK (granted) or NGX_ERROR (denied). */
ngx_int_t
brix_check_authdb_identity(ngx_log_t *log, const brix_authdb_query_t *query)
{
    const brix_authdb_rule_t   *rule;
    char                          safe_path[512];
    const char                   *dn;
    const char                   *vo_list;

    /* No rules loaded == no authdb policy == unrestricted (allow-all). */
    if (query->rules == NULL || query->rules->nelts == 0) {
        return NGX_OK;
    }

    rule = brix_find_authdb_rule_identity(query->resolved_path, query->rules,
                                            query->identity, query->peer_ip,
                                            query->needed_privs);
    if (rule != NULL) {
        return NGX_OK;
    }

    dn = brix_identity_dn_cstr(query->identity);
    vo_list = brix_identity_vo_csv_cstr(query->identity);
    brix_sanitize_log_string(query->resolved_path, safe_path, sizeof(safe_path));

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: authdb denied path=\"%s\" privs=0x%02xd "
                  "dn=\"%s\" vos=\"%s\" peer=\"%s\"",
                  safe_path, query->needed_privs, dn,
                  vo_list[0] ? vo_list : "-",
                  (query->peer_ip != NULL && query->peer_ip[0])
                      ? query->peer_ip : "-");

    return NGX_ERROR;
}

/* Authorize ctx for needed_privs on resolved_path via the authdb (wraps the
 * _identity form). */
ngx_int_t
brix_check_authdb(brix_ctx_t *ctx, const char *resolved_path,
                    uint32_t needed_privs)
{
    ngx_stream_brix_srv_conf_t *conf;
    brix_identity_t            fallback;

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);

    if (ctx->identity != NULL) {
        brix_authdb_query_t query = {
            .rules         = conf->authdb_rules,
            .identity      = ctx->identity,
            .peer_ip       = ctx->login.peer_ip,
            .resolved_path = resolved_path,
            .needed_privs  = needed_privs,
        };
        return brix_check_authdb_identity(ctx->session->connection->log,
                                            &query);
    }

    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->login.dn;
    fallback.dn.len = strlen(ctx->login.dn);
    fallback.vo_csv.data = (u_char *) ctx->login.vo_list;
    fallback.vo_csv.len = strlen(ctx->login.vo_list);

    brix_authdb_query_t query = {
        .rules         = conf->authdb_rules,
        .identity      = &fallback,
        .peer_ip       = ctx->login.peer_ip,
        .resolved_path = resolved_path,
        .needed_privs  = needed_privs,
    };
    return brix_check_authdb_identity(ctx->session->connection->log, &query);
}
