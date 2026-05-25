#include "../ngx_xrootd_module.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "path_internal.h"

/* ---- Function: xrootd_mkdir_recursive() ----
 *
 * WHAT: Creates directories recursively from root to target path using unconstrained mkdir syscall. Thin wrapper that delegates to xrootd_mkdir_recursive_policy() with NULL log and rules (no group policy enforcement).
 *
 * WHY: Provides a simple API for callers who only need directory creation without policy checks — used by write/mv.c rename operations when creating intermediate directories during move.
 *
 * HOW: Copies path argument into tmp buffer, delegates to xrootd_mkdir_recursive_policy(path, mode, NULL, NULL). Returns 0 on success (all levels created or existed), -1 on failure. */

int
xrootd_mkdir_recursive(const char *path, mode_t mode)
{
    return xrootd_mkdir_recursive_policy(path, mode, NULL, NULL);
}

/* ---- Function: xrootd_mkdir_recursive_policy() ----
 *
 * WHAT: Creates directories recursively from root to target path, applying parent group policy at each newly-created intermediate level when log and rules are provided. Uses local stack buffer (tmp[PATH_MAX]) to progressively truncate the path at each '/' separator, mkdir() each prefix, then restore the '/' before advancing.
 *
 * WHY: XRootD MKCOL requests may create multi-level directory trees in a single call. Creating each level individually ensures intermediate directories inherit the correct parent group policy from their newly-created parent, preventing misconfigured permissions on nested paths. The policy application happens only when mkdir succeeds (not when EEXIST is returned) — existing parents retain their original policy.
 *
 * HOW: 1) Copy path into tmp[PATH_MAX], strip trailing '/' if present; 2) Iterate forward through tmp advancing p at each '/', temporarily null-terminate at '/' to get the prefix path, call mkdir(prefix, mode); 3) On successful mkdir (not EEXIST), call xrootd_apply_parent_group_policy_path() with log and rules; 4) Restore '/' at p position and continue iterating until all levels created. Returns 0 on success, -1 on first failure. Thread safety: uses local stack buffers only — safe for concurrent use. */

int
xrootd_mkdir_recursive_policy(const char *path, mode_t mode,
                              ngx_log_t *log, ngx_array_t *rules)
{
    char  tmp[PATH_MAX];
    char *p;
    int   n;

    n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (n > 0 && tmp[n - 1] == '/') {
        tmp[n - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';

            if (mkdir(tmp, mode) != 0) {
                if (errno != EEXIST) {
                    return -1;
                }
            } else if (log != NULL && rules != NULL) {
                if (xrootd_apply_parent_group_policy_path(log, tmp, rules)
                    == NGX_ERROR)
                {
                    return -1;
                }
            }

            *p = '/';
        }
    }

    if (mkdir(tmp, mode) != 0) {
        if (errno != EEXIST) {
            return -1;
        }
    } else if (log != NULL && rules != NULL) {
        if (xrootd_apply_parent_group_policy_path(log, tmp, rules)
            == NGX_ERROR)
        {
            return -1;
        }
    }

    return 0;
}

/* ---- Function: xrootd_mkdir_recursive_confined_canon() ----
 *
 * WHAT: Creates directories recursively from root to target path using confined mkdirat syscall under parent directory confinement. Takes pre-canonicalized root_canon and resolved path, validates that resolved is within root_canon before proceeding. Applies optional group policy at each newly-created intermediate level.
 *
 * WHY: The confined variant uses xrootd_mkdir_confined_canon() (mkdirat under confinement) instead of plain mkdir(), preventing directory creation outside the export root even if symlinks were introduced between path resolution and creation. This is the security-critical variant used by WebDAV MKCOL and native XRootD mkdir opcodes.
 *
 * HOW: 1) Copy resolved into tmp[PATH_MAX], strip trailing '/' if present; 2) Validate resolved starts with root_canon (EXDEV on mismatch, EEXIST if resolved equals root); 3) Compute p = pointer to relative portion after root_canon; 4) Iterate forward through tmp advancing p at each '/', null-terminate prefix, call xrootd_mkdir_confined_canon(log, root_canon, tmp, mode); 5) On success (not EEXIST), apply group policy if rules != NULL; 6) Restore '/' and continue. Returns 0 on success, -1 on first failure. Thread safety: uses local stack buffers only — safe for concurrent use. */

int
xrootd_mkdir_recursive_confined_canon(ngx_log_t *log, const char *root_canon,
                                      const char *resolved, mode_t mode,
                                      ngx_array_t *rules)
{
    char   tmp[PATH_MAX];
    char  *p;
    size_t root_len;
    int    n;

    n = snprintf(tmp, sizeof(tmp), "%s", resolved);
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (n > 0 && tmp[n - 1] == '/') {
        tmp[n - 1] = '\0';
    }

    root_len = strlen(root_canon);
    if (root_len == 1 && root_canon[0] == '/') {
        p = tmp + 1;
    } else {
        if (strncmp(tmp, root_canon, root_len) != 0
            || (tmp[root_len] != '\0' && tmp[root_len] != '/'))
        {
            errno = EXDEV;
            return -1;
        }
        if (tmp[root_len] == '\0') {
            errno = EEXIST;
            return -1;
        }
        p = tmp + root_len + 1;
    }

    for (; *p; p++) {
        if (*p == '/') {
            *p = '\0';

            if (xrootd_mkdir_confined_canon(log, root_canon, tmp, mode) != 0
                && errno != EEXIST)
            {
                *p = '/';
                return -1;
            }
            if (rules != NULL) {
                (void) xrootd_apply_parent_group_policy_path(log, tmp, rules);
            }

            *p = '/';
        }
    }

    if (xrootd_mkdir_confined_canon(log, root_canon, tmp, mode) != 0
        && errno != EEXIST)
    {
        return -1;
    }
    if (rules != NULL) {
        (void) xrootd_apply_parent_group_policy_path(log, tmp, rules);
    }

    return 0;
}

/* ---- Function: xrootd_mkdir_recursive_confined() ----
 *
 * WHAT: Thin wrapper that converts ngx_str_t root argument to canonical form via xrootd_get_canonical_root(), then delegates to xrootd_mkdir_recursive_confined_canon(). Provides the non-canonical API variant for callers holding ngx_str_t root configuration.
 *
 * WHY: Many callers (WebDAV dispatch, native XRootD handler) hold root as ngx_str_t from location config. This wrapper bridges between the nginx string type and the canonical char* form required by xrootd_mkdir_recursive_confined_canon(). Sets errno = EACCES on canonical_root failure.
 *
 * HOW: 1) Call xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon)); 2) On success, delegate to xrootd_mkdir_recursive_confined_canon(log, root_canon, resolved, mode, rules); 3) Return delegated result. Returns 0 on success, -1 on failure. Thread safety: uses local stack buffer — safe for concurrent use. */

int
xrootd_mkdir_recursive_confined(ngx_log_t *log, const ngx_str_t *root,
                                const char *resolved, mode_t mode,
                                ngx_array_t *rules)
{
    char   root_canon[PATH_MAX];

    if (!xrootd_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

    return xrootd_mkdir_recursive_confined_canon(log, root_canon, resolved,
                                                 mode, rules);
}

/* ---- Recursive directory creation with optional group policy enforcement ----
 *
 * WHAT: Creates directories recursively from the root down to the target path, applying parent group policy at each newly-created intermediate level when log and rules are provided. Four variants: unconstrained recursive mkdir (xrootd_mkdir_recursive), policy-aware variant (xrootd_mkdir_recursive_policy), confined canonical variant (xrootd_mkdir_recursive_confined_canon), and confined wrapper that converts ngx_str_t root to canonical form (xrootd_mkdir_recursive_confined).
 *
 * WHY: XRootD clients often create multi-level directory trees in a single MKCOL request. Creating each level individually with mkdir ensures intermediate directories inherit the correct group policy from their parent, preventing misconfigured permissions on nested paths. The confined variants use mkdirat under confinement to prevent creating directories outside the export root even if symlinks were introduced between path resolution and creation. Thread safety: uses local stack buffers only — safe for concurrent use. */
