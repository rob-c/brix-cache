/*
 * vo_token.h — VO-name safety predicate (ngx-free, header-only).
 *
 * WHAT: brix_vo_token_is_safe() — 1 if a VO/FQAN token is safe to place into
 *       the module's comma-separated VO list and later into metric labels /
 *       access-log fields, 0 otherwise.
 * WHY:  VO names arrive from a VOMS Attribute Certificate (attacker-influenced
 *       for a forged/self-signed AC).  A comma would break the list encoding, a
 *       slash/backslash could confuse downstream path/label consumers, and
 *       control or non-ASCII bytes could inject into logs.  Rejecting them at
 *       the edge keeps every consumer safe.
 * HOW:  Reject empty, any byte <= ' ' (control/space), any byte >= 0x7f
 *       (non-ASCII / DEL), and the ',', '/', '\\' separators.  Header-only so
 *       the exact predicate is shared by collect.c and its unit test.
 */
#ifndef BRIX_AUTH_VOMS_VO_TOKEN_H
#define BRIX_AUTH_VOMS_VO_TOKEN_H

#include <stddef.h>

static inline int
brix_vo_token_is_safe(const char *vo, size_t vo_len)
{
    size_t i;

    if (vo == NULL || vo_len == 0) {
        return 0;
    }
    for (i = 0; i < vo_len; i++) {
        unsigned char ch = (unsigned char) vo[i];

        if (ch <= ' ' || ch >= 0x7f || ch == ',' || ch == '/' || ch == '\\') {
            return 0;
        }
    }
    return 1;
}

/*
 * WHAT: brix_fqan_token_is_safe() — 1 if a RAW VOMS FQAN
 *       ("/cms/Role=production/Capability=NULL") is safe to place into the
 *       identity's private FQAN CSV, 0 otherwise.
 * WHY:  2.0 F20 — the `v` (vorg) and `l` (role) authdb selectors, and the
 *       XrdAcc engine's own `vorg`/`role`/`group` templates, are all derived
 *       from the FQAN by brix_identity_derive_attrs.  The VO-name predicate
 *       above rejects '/' on purpose (a VO name reaches metric labels and log
 *       fields), so an FQAN can never travel in the VO list — it needs its own
 *       channel and its own, deliberately narrower, predicate.
 * HOW:  Reject empty, any byte <= ' ' (control/space), any byte >= 0x7f, the
 *       ',' that separates the CSV, and '\\'.  '/' and '=' are the FQAN's own
 *       grammar and are allowed.  This CSV is consumed ONLY by
 *       brix_identity_derive_attrs; it must never be logged or used as a metric
 *       label value (INVARIANT 8) — the VO list stays the value for those.
 */
static inline int
brix_fqan_token_is_safe(const char *fqan, size_t fqan_len)
{
    size_t i;

    if (fqan == NULL || fqan_len == 0) {
        return 0;
    }
    for (i = 0; i < fqan_len; i++) {
        unsigned char ch = (unsigned char) fqan[i];

        if (ch <= ' ' || ch >= 0x7f || ch == ',' || ch == '\\') {
            return 0;
        }
    }
    return 1;
}

#endif /* BRIX_AUTH_VOMS_VO_TOKEN_H */
