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

#endif /* BRIX_AUTH_VOMS_VO_TOKEN_H */
