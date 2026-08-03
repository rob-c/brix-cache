/*
 * egress_guard.c — TPC source-host egress allowlist implementation.
 *
 * See egress_guard.h for the rationale. The pure predicate below carries no
 * nginx dependency and is exercised by egress_guard_unittest.c; the ngx
 * wrappers (behind XRDPROTO_NO_NGX) walk the configured pattern array and
 * render the refusal text used at the native root:// and WebDAV TPC gates.
 */
#include "egress_guard.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strncasecmp — pure, ngx-free */

/* ---- Pure host/pattern predicate ----
 *
 * WHAT: case-insensitive match of a source hostname against one allowlist
 *   pattern — leading '.' = domain suffix, otherwise exact host.
 *
 * WHY: the match rule is the security contract; keeping it a pure function lets
 *   the offline unit prove every branch (exact / suffix / boundary / empty)
 *   with no server, and keeps its spelling identical to brix_host_pattern_match.
 *
 * HOW: 1. Reject NULL / empty pattern (an empty rule never matches).
 *      2. '.'-led pattern: host must be strictly longer and share the suffix.
 *      3. Else exact length + case-insensitive compare.
 */
int
brix_tpc_host_pattern_match(const char *pattern, const char *host)
{
    size_t plen;
    size_t hlen;

    if (pattern == NULL || host == NULL || pattern[0] == '\0') {
        return 0;
    }

    plen = strlen(pattern);
    hlen = strlen(host);

    if (pattern[0] == '.') {
        if (hlen <= plen) {
            return 0;
        }
        return strncasecmp(host + (hlen - plen), pattern, plen) == 0 ? 1 : 0;
    }

    return (hlen == plen && strncasecmp(host, pattern, plen) == 0) ? 1 : 0;
}

#ifndef XRDPROTO_NO_NGX

/* ---- Allowlist membership ----
 *
 * WHAT: 1 if `host` matches any configured pattern, else 0.
 *
 * WHY: an empty / unset list must deny everything when the guard is on, so the
 *   no-list case returns 0 (not "allow") — fail-closed.
 *
 * HOW: conf tokens are NUL-terminated (ngx_conf_set_str_array_slot), so each
 *   pattern is passed straight to the pure predicate as a C string.
 */
int
brix_tpc_source_allow_match(ngx_array_t *allow, const char *host)
{
    ngx_str_t  *pats;
    ngx_uint_t  i;

    if (allow == NULL || allow->nelts == 0) {
        return 0;
    }

    pats = allow->elts;
    for (i = 0; i < allow->nelts; i++) {
        if (brix_tpc_host_pattern_match((const char *) pats[i].data, host)) {
            return 1;
        }
    }
    return 0;
}

/* ---- Origination gate decision ----
 *
 * WHAT: the allow/refuse verdict the native + WebDAV TPC start paths consult
 *   before dialling the source; on refusal it fills a stable message.
 *
 * WHY: centralising the verdict keeps the two call sites byte-identical and
 *   guarantees the refusal phrase (grepped by fail2ban and matched by the
 *   client self-test) never drifts between planes.
 *
 * HOW: 1. Guard off → allow (legacy no-op).
 *      2. Non-empty host on the allowlist → allow.
 *      3. Else format "TPC source host not permitted: <host>" and refuse.
 */
int
brix_tpc_source_guard_check(ngx_flag_t guard_on, ngx_array_t *allow,
    const char *host, char *err, size_t errsz)
{
    if (!guard_on) {
        return 0;
    }

    if (host != NULL && host[0] != '\0'
        && brix_tpc_source_allow_match(allow, host))
    {
        return 0;
    }

    snprintf(err, errsz, "TPC source host not permitted: %s",
             (host != NULL && host[0] != '\0') ? host : "(none)");
    return -1;
}

#endif /* !XRDPROTO_NO_NGX */
