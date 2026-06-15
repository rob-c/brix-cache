/*
 * capability.c — path/template capability matching (XrdAccCapability).
 *
 * WHAT: xrootd_acc_cap_privs() walks one identity's capability list and, on the
 *   FIRST path whose prefix matches the request path, OR-s that capability's
 *   positive and negative privileges into the accumulator and returns 1.
 *   Template (`@=`) capabilities substitute a runtime value (the user name) into
 *   the path before matching; template-indirection capabilities recurse into a
 *   named template's own list.
 *
 * WHY: faithful port of XrdAccCapability::Privs()/Subcomp().  Two fidelity
 *   points vs the `native` engine: (1) matching is a RAW prefix (strncmp), so
 *   `/foo` matches `/foobar` — XrdAcc does not enforce component boundaries; and
 *   (2) within one identity's list the FIRST match wins, not the longest, so
 *   authdb authors order specific paths before general ones.
 *
 * HOW: for each node — if it is a template indirection, recurse; else if the
 *   request is at least as long as the prefix and matches (plain strncmp, or
 *   Subcomp when a substitution value is supplied), accumulate and stop.
 */

#include "acc.h"

/*
 * Subcomp — match a `@=` template path against (path, pathsub).
 * Ports XrdAccCapability::Subcomp(): the fixed prefix before `@=` must match,
 * the substitution value must appear at that point in the request path, and the
 * fixed tail after `@=` must match what follows.  Returns 1 on match.
 */
static int
xrootd_acc_cap_subcomp(const xrootd_acc_cap_t *cap, const char *path, int plen,
                       const char *pathsub, int sublen)
{
    int ncmp;

    /* Prefix before "@=" must match. */
    if (ngx_strncmp(path, cap->path, cap->pins) != 0) {
        return 0;
    }

    /* The substitution value must appear at the insertion point. */
    if (ngx_strncmp(path + cap->pins, pathsub, sublen) != 0) {
        return 0;
    }

    /* Enough room for the fixed tail? */
    ncmp = cap->pins + sublen;
    if ((plen - ncmp) < cap->prem) {
        return 0;
    }

    /* Match the fixed tail after "@=" (cap->path[pins+2 ..]). */
    if (cap->prem) {
        return ngx_strncmp(cap->path + cap->pins + 2, path + ncmp,
                           (size_t) cap->prem) == 0;
    }
    return 1;
}

int
xrootd_acc_cap_privs(xrootd_acc_cap_t *cap, xrootd_acc_priv_caps_t *out,
                     const char *path, int plen, const char *pathsub)
{
    int  psl = (pathsub != NULL) ? (int) ngx_strlen(pathsub) : 0;

    for (; cap != NULL; cap = cap->next) {

        /* Template indirection: search the referenced template's list. */
        if (cap->tmpl != NULL) {
            if (xrootd_acc_cap_privs(cap->tmpl, out, path, plen, pathsub)) {
                return 1;
            }
            continue;
        }

        if (plen < cap->plen) {
            continue;
        }

        if ((pathsub == NULL && ngx_strncmp(path, cap->path, cap->plen) == 0)
            || (pathsub != NULL
                && xrootd_acc_cap_subcomp(cap, path, plen, pathsub, psl)))
        {
            out->pprivs |= cap->caps.pprivs;
            out->nprivs |= cap->caps.nprivs;
            return 1;
        }
    }

    return 0;
}
