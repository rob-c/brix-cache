/* ------------------------------------------------------------------ */
/* VO ACL Enforcement — Virtual Organization Access Control              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements three functions for Virtual Organization Membership Service (VOMS) access control. xrootd_finalize_vo_rules() canonicalizes all VO ACL rule paths using xrootd_finalize_path_rules wrapper with sizeof(xrootd_vo_rule_t), offsetof(path), offsetof(resolved) parameters preparing rules for runtime enforcement; xrootd_vo_list_contains() searches comma-separated client VO list string for a required VO name returning 1 when found or when both strings are empty/null (allow-all fallback); returns 0 when required VO not present in client list; xrootd_check_vo_acl() performs ACL lookup via xrootd_find_vo_rule(), compares required VO against client VO list using xrootd_vo_list_contains(), logs warn-level denial entry with sanitized path/VO strings on failure.
 *
 * WHY: VO ACL enforcement is critical for multi-tenant XRootD deployments where different virtual organizations require different access levels — without this check, clients from unauthorized VOs could access restricted filesystem paths. Comma-separated VO list format enables single-string representation of multiple organizational memberships; allow-all fallback (empty/null required_vo returns 1) ensures no restrictions when VO requirement is unspecified rather than accidental denial. */

/* ------------------------------------------------------------------ */
/* Section: VO Rule Finalization                                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_finalize_vo_rules() wraps xrootd_finalize_path_rules with VO-specific struct parameters — sizeof(xrootd_vo_rule_t), offsetof(xrootd_vo_rule_t, path), offsetof(xrootd_vo_rule_t, resolved), sizeof(resolved field) — canonicalizing all VO ACL rule paths against the configured root directory using realpath(2). Returns NGX_OK when all paths resolved; returns NGX_ERROR on any resolution failure.
 *
 * WHY: VO rule finalization ensures runtime ACL enforcement uses consistent canonical path representations — without this step, rules referencing different path forms could fail comparison during access control checks causing either over-permissive or under-permissive behavior depending on mismatch direction. Canonicalization prevents policy bypass attempts through different path representations of the same filesystem location. */

/* ------------------------------------------------------------------ */
/* Section: VO List Search                                               */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_vo_list_contains() searches comma-separated client VO list string for a required VO name using strchr(2) to locate each comma delimiter, comparing substring length and content via ngx_strncmp(). Returns 1 when required VO found OR when both strings are empty/null (allow-all fallback); returns 0 when required VO not present in client list.
 *
 * WHY: Comma-separated format enables single-string representation of multiple organizational memberships without requiring array structures for runtime comparison; allow-all fallback ensures no restrictions when VO requirement is unspecified rather than accidental denial — empty required_vo means "any VO allowed" while empty vo_list means "no VOs registered (deny)". */

/* ------------------------------------------------------------------ */
/* Section: ACL Enforcement                                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_check_vo_acl() performs three-step ACL enforcement: lookup rule for resolved_path via xrootd_find_vo_rule(), compare required VO against client VO list using xrootd_vo_list_contains(), log warn-level denial entry with sanitized path/VO strings on failure. Returns NGX_OK when access granted (rule found + client has required VO); returns NGX_ERROR when denied (rule found + client lacks required VO). NULL/empty vo_rules array returns NGX_OK immediately — no ACL rules means unrestricted access.
 *
 * WHY: Three-step enforcement ensures consistent policy application across all filesystem operations requiring VOMS authorization — rule lookup determines which path requires which VO, list comparison verifies client membership, sanitization prevents log corruption from wire protocol binary data. Allow-all behavior when vo_rules is NULL prevents accidental denial in deployments without VOMS configuration while maintaining strict enforcement when rules exist. */

/* ---- Function: xrootd_finalize_vo_rules() ----
 *
 * WHAT: Wraps xrootd_finalize_path_rules with VO-specific struct parameters — sizeof(xrootd_vo_rule_t), offsetof(xrootd_vo_rule_t, path), offsetof(xrootd_vo_rule_t, resolved), sizeof(resolved field) — canonicalizing all VO ACL rule paths against the configured root directory using realpath(2). Returns NGX_OK when all paths resolved; returns NGX_ERROR on any resolution failure.
 *
 * WHY: VO rule finalization ensures runtime ACL enforcement uses consistent canonical path representations — without this step, rules referencing different path forms could fail comparison during access control checks causing either over-permissive or under-permissive behavior depending on mismatch direction. Canonicalization prevents policy bypass attempts through different path representations of the same filesystem location. */

/* ---- Function: xrootd_vo_list_contains() ----
 *
 * WHAT: Searches comma-separated client VO list string for a required VO name using strchr(2) to locate each comma delimiter, comparing substring length and content via ngx_strncmp(). Returns 1 when required VO found OR when both strings are empty/null (allow-all fallback); returns 0 when required VO not present in client list.
 *
 * WHY: Comma-separated format enables single-string representation of multiple organizational memberships without requiring array structures for runtime comparison; allow-all fallback ensures no restrictions when VO requirement is unspecified rather than accidental denial — empty required_vo means "any VO allowed" while empty vo_list means "no VOs registered (deny)". */

/* ---- Function: xrootd_check_vo_acl() ----
 *
 * WHAT: Performs three-step ACL enforcement: lookup rule for resolved_path via xrootd_find_vo_rule(), compare required VO against client VO list using xrootd_vo_list_contains(), log warn-level denial entry with sanitized path/VO strings on failure. Returns NGX_OK when access granted (rule found + client has required VO); returns NGX_ERROR when denied (rule found + client lacks required VO). NULL/empty vo_rules array returns NGX_OK immediately — no ACL rules means unrestricted access.
 *
 * WHY: Three-step enforcement ensures consistent policy application across all filesystem operations requiring VOMS authorization — rule lookup determines which path requires which VO, list comparison verifies client membership, sanitization prevents log corruption from wire protocol binary data. Allow-all behavior when vo_rules is NULL prevents accidental denial in deployments without VOMS configuration while maintaining strict enforcement when rules exist. */

#include "../ngx_xrootd_module.h"

#include <stddef.h>
#include <string.h>

#include "path_internal.h"

ngx_int_t
xrootd_finalize_vo_rules(ngx_log_t *log, const ngx_str_t *root,
                         ngx_array_t *rules)
{
    return xrootd_finalize_path_rules(log, root, rules,
                                      sizeof(xrootd_vo_rule_t),
                                      offsetof(xrootd_vo_rule_t, path),
                                      offsetof(xrootd_vo_rule_t, resolved),
                                      sizeof(((xrootd_vo_rule_t *) 0)->resolved));
}
/* ---- HOW: Calls xrootd_finalize_path_rules(log, root, rules, sizeof(xrootd_vo_rule_t), offsetof(xrootd_vo_rule_t, path), offsetof(xrootd_vo_rule_t, resolved), sizeof(resolved)) — passes VO rule struct size and field offsets so the generic finalizer canonicalizes each rule's path via realpath(2) into resolved. Returns xrootd_finalize_path_rules() result directly (NGX_OK or NGX_ERROR). Simple wrapper with no additional logic. */

ngx_flag_t
xrootd_vo_list_contains(const char *vo_list, const char *required_vo)
{
    const char *start;
    const char *end;
    size_t required_len;

    if (required_vo == NULL || required_vo[0] == '\0') {
        return 1;
    }

    if (vo_list == NULL || vo_list[0] == '\0') {
        return 0;
    }

    required_len = strlen(required_vo);
    start = vo_list;

    while (*start != '\0') {
        end = strchr(start, ',');

        if (end == NULL) {
            end = start + strlen(start);
        }

        if ((size_t) (end - start) == required_len
            && ngx_strncmp(start, required_vo, required_len) == 0)
        {
            return 1;
        }

        start = (*end == '\0') ? end : end + 1;
    }

    return 0;
}
/* ---- HOW: Checks required_vo==NULL || required_vo[0]=='\0' → returns 1 (allow-all). Checks vo_list==NULL || vo_list[0]=='\0' → returns 0 (no VOs registered, deny). Computes strlen(required_vo) into required_len. Scans vo_list: start=vo_list; while *start!='\0', end=strchr(start,',') — if NULL end=start+strlen(start). If (end-start)==required_len && ngx_strncmp(start,required_vo,required_len)==0 → returns 1 (match found). Updates start=(*end=='\0')?end:end+1 to skip past comma. Returns 0 after full scan with no match. */

ngx_int_t
xrootd_check_vo_acl(ngx_log_t *log, const char *resolved_path,
                    ngx_array_t *vo_rules, const char *vo_list)
{
    const xrootd_vo_rule_t *rule;
    char                    safe_path[512];
    char                    safe_vo[128];

    if (vo_rules == NULL || vo_rules->nelts == 0) {
        return NGX_OK;
    }

    rule = xrootd_find_vo_rule(resolved_path, vo_rules);
    if (rule == NULL) {
        return NGX_OK;
    }

    if (xrootd_vo_list_contains(vo_list, (const char *) rule->vo.data)) {
        return NGX_OK;
    }

    xrootd_sanitize_log_string(resolved_path, safe_path, sizeof(safe_path));
    xrootd_sanitize_log_string((const char *) rule->vo.data, safe_vo,
                               sizeof(safe_vo));

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd: VO ACL denied path=\"%s\" required_vo=\"%s\" "
                  "client_vos=\"%s\"",
                  safe_path, safe_vo, (vo_list && vo_list[0]) ? vo_list : "-");

    return NGX_ERROR;
}
/* ---- HOW: Checks vo_rules==NULL || vo_rules->nelts==0 → returns NGX_OK (no rules = unrestricted). Calls xrootd_find_vo_rule(resolved_path, vo_rules) — if rule==NULL returns NGX_OK (no matching rule = unrestricted). If rule found checks xrootd_vo_list_contains(vo_list, rule->vo.data) — if returns 1 (client has required VO) returns NGX_OK. Otherwise: sanitizes resolved_path into safe_path[512], rule->vo.data into safe_vo[128] via xrootd_sanitize_log_string(); logs warn-level error with "VO ACL denied path=... required_vo=... client_vos=..." format; returns NGX_ERROR. */
