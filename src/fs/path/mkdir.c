#include "core/ngx_brix_module.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "path_internal.h"

/*
 * WHAT: Per-level make-directory result codes shared by the recursive-mkdir
 *       driver. A level is either freshly created, already present (EEXIST),
 *       or a hard error.
 *
 * WHY:  The three public variants (plain / confined-canon / beneath) differ
 *       only in HOW one level is created and in whether policy runs on EEXIST.
 *       Normalising the syscall outcome to these three states lets one shared
 *       walk drive all of them while each variant keeps identical semantics.
 *
 * HOW:  Backend hooks return BRIX_MKDIR_CREATED on a fresh mkdir,
 *       BRIX_MKDIR_EXISTED when the syscall failed with EEXIST, and
 *       BRIX_MKDIR_ERROR for any other failure (errno preserved).
 */
#define BRIX_MKDIR_ERROR    (-1)
#define BRIX_MKDIR_CREATED   (0)
#define BRIX_MKDIR_EXISTED   (1)

/*
 * WHAT: File-local descriptor bundling everything the recursive-mkdir walk
 *       needs: the level-creation backend, its bound arguments, the group
 *       policy rules, and whether a policy failure is fatal.
 *
 * WHY:  Passing this single context keeps every helper at or below the
 *       five-parameter limit and makes the per-variant behaviour explicit and
 *       data-driven rather than duplicated across three near-identical loops.
 *
 * HOW:  make_level() is invoked for each prefix in tmp and returns a
 *       BRIX_MKDIR_* code. root_len is the length of root_canon and is used by
 *       the beneath backend to derive the export-relative path. policy_on_exist
 *       selects the two behavioural regimes: the plain variant applies policy
 *       only on fresh create and treats failure as fatal (policy_on_exist=0);
 *       the confined variants apply policy best-effort on every level whenever
 *       rules are set and ignore the result (policy_on_exist=1).
 */
typedef struct brix_mkdir_walk_s brix_mkdir_walk_t;
struct brix_mkdir_walk_s {
    ngx_log_t   *log;
    const char  *root_canon;
    size_t       root_len;
    int          rootfd;
    mode_t       mode;
    ngx_array_t *rules;
    int          policy_on_exist;
    int        (*make_level)(const brix_mkdir_walk_t *w, const char *dir);
};

/*
 * WHAT: Copy <src> into a caller-owned tmp[PATH_MAX] buffer, stripping a single
 *       trailing '/', and reject over-long paths.
 *
 * WHY:  All three variants begin with byte-identical normalisation; sharing it
 *       removes duplication and guarantees the length/ENAMETOOLONG guard stays
 *       consistent (a divergence here could silently truncate a confined path).
 *
 * HOW:  snprintf into tmp; on overflow set errno=ENAMETOOLONG and return -1.
 *       Store the resulting length via *out_len and drop a lone trailing slash.
 *       Returns 0 on success.
 */
static int
brix_mkdir_copy_tmp(char *tmp, const char *src, int *out_len)
{
    int n;

    n = snprintf(tmp, PATH_MAX, "%s", src);
    if (n < 0 || (size_t) n >= (size_t) PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (n > 0 && tmp[n - 1] == '/') {
        tmp[n - 1] = '\0';
        n--;
    }

    *out_len = n;
    return 0;
}

/*
 * WHAT: Validate that the normalised <tmp> lies under <root_canon> and return a
 *       pointer to the first character after the root prefix (the start of the
 *       relative portion to walk).
 *
 * WHY:  This is the security-critical confinement gate shared by the confined
 *       and beneath variants: a resolved path that is not a sub-path of the
 *       export root must be rejected (EXDEV) so recursive creation can never
 *       escape the export even if a symlink was swapped in after resolution.
 *
 * HOW:  For a root of "/" the whole path (after the leading slash) is relative.
 *       Otherwise require a byte-exact root prefix followed by end-of-string or
 *       '/'; a mismatch yields EXDEV, an exact match (path == root) yields
 *       EEXIST. Returns the walk-start pointer, or NULL with errno set.
 */
static char *
brix_mkdir_confined_start(char *tmp, const char *root_canon, size_t root_len)
{
    if (root_len == 1 && root_canon[0] == '/') {
        return tmp + 1;
    }

    if (strncmp(tmp, root_canon, root_len) != 0
        || (tmp[root_len] != '\0' && tmp[root_len] != '/'))
    {
        errno = EXDEV;
        return NULL;
    }

    if (tmp[root_len] == '\0') {
        errno = EEXIST;
        return NULL;
    }

    return tmp + root_len + 1;
}

/*
 * WHAT: Apply parent-group policy to a just-processed directory level per the
 *       walk's behavioural regime.
 *
 * WHY:  The plain variant enforces policy only on freshly-created levels and
 *       fails the whole operation if policy application errors; the confined
 *       variants apply policy best-effort on every level and ignore the result.
 *       Centralising the branch keeps those two contracts byte-identical to the
 *       original inline code.
 *
 * HOW:  No-op when rules are unset. When policy_on_exist is false, run only if
 *       the level was freshly created and propagate NGX_ERROR as a fatal -1.
 *       When policy_on_exist is true, run unconditionally and discard the
 *       result. Returns 0 to continue, -1 to abort.
 */
static int
brix_mkdir_apply_policy(const brix_mkdir_walk_t *w, const char *dir, int made)
{
    if (w->rules == NULL) {
        return 0;
    }

    if (!w->policy_on_exist) {
        if (made != BRIX_MKDIR_CREATED) {
            return 0;
        }
        if (brix_apply_parent_group_policy_path(w->log, dir, w->rules)
            == NGX_ERROR)
        {
            return -1;
        }
        return 0;
    }

    (void) brix_apply_parent_group_policy_path(w->log, dir, w->rules);
    return 0;
}

/*
 * WHAT: Create one directory level <dir> and apply policy for it.
 *
 * WHY:  Every prefix and the final target go through the same create-then-policy
 *       sequence; factoring it into one helper removes the four inline copies
 *       and keeps the EEXIST-is-success rule in a single place.
 *
 * HOW:  Invoke the backend make_level hook. A BRIX_MKDIR_ERROR aborts with the
 *       backend's errno preserved. Otherwise defer to brix_mkdir_apply_policy()
 *       with the create/existed outcome. Returns 0 to continue, -1 to abort.
 */
static int
brix_mkdir_one_level(const brix_mkdir_walk_t *w, const char *dir)
{
    int made;

    made = w->make_level(w, dir);
    if (made == BRIX_MKDIR_ERROR) {
        return -1;
    }

    return brix_mkdir_apply_policy(w, dir, made);
}

/*
 * WHAT: Walk <tmp> from the relative-portion start pointer <p> to the target,
 *       creating every intermediate directory and then the target itself.
 *
 * WHY:  This is the single shared component walk behind all three public
 *       variants — the only place the '/'-by-'/' truncation logic lives, so a
 *       fix or audit touches one code path.
 *
 * HOW:  Advance p; at each '/', temporarily terminate to expose the prefix,
 *       create that level, then restore the '/' before continuing (restoring
 *       even on the error path so the buffer stays well-formed). After the loop
 *       create the full path once more for the final level. Returns 0 / -1.
 */
static int
brix_mkdir_walk(const brix_mkdir_walk_t *w, char *tmp, char *p)
{
    for (; *p; p++) {
        if (*p != '/') {
            continue;
        }

        *p = '\0';
        if (brix_mkdir_one_level(w, tmp) != 0) {
            *p = '/';
            return -1;
        }
        *p = '/';
    }

    return brix_mkdir_one_level(w, tmp);
}

/*
 * WHAT: make_level backend for the unconstrained variant — a plain mkdir(2).
 *
 * WHY:  Used where the caller only needs directory creation without export
 *       confinement (e.g. rename intermediate directories).
 *
 * HOW:  mkdir(dir, mode); map success to CREATED, EEXIST to EXISTED, any other
 *       failure to ERROR with errno intact.
 */
static int
brix_mkdir_level_plain(const brix_mkdir_walk_t *w, const char *dir)
{
    if (mkdir(dir, w->mode) == 0) {
        return BRIX_MKDIR_CREATED;
    }
    return (errno == EEXIST) ? BRIX_MKDIR_EXISTED : BRIX_MKDIR_ERROR;
}

/*
 * WHAT: make_level backend for the confined-canonical variant.
 *
 * WHY:  Creates each level via the confined mkdirat so a symlink introduced
 *       between resolution and creation cannot redirect the mkdir outside the
 *       export root.
 *
 * HOW:  brix_mkdir_confined_canon(log, root_canon, dir, mode); classify the
 *       result as CREATED / EXISTED / ERROR.
 */
static int
brix_mkdir_level_confined(const brix_mkdir_walk_t *w, const char *dir)
{
    if (brix_mkdir_confined_canon(w->log, w->root_canon, dir, w->mode) == 0) {
        return BRIX_MKDIR_CREATED;
    }
    return (errno == EEXIST) ? BRIX_MKDIR_EXISTED : BRIX_MKDIR_ERROR;
}

/*
 * WHAT: make_level backend for the beneath variant.
 *
 * WHY:  Creates each level via openat2(RESOLVE_BENEATH) under a pre-opened
 *       export-root dirfd, giving the same escape-proof confinement as the
 *       canonical variant without re-opening parents per level.
 *
 * HOW:  brix_mkdir_beneath(rootfd, dir + root_len, mode) — the export-relative
 *       path is dir past the root prefix; classify CREATED / EXISTED / ERROR.
 */
static int
brix_mkdir_level_beneath(const brix_mkdir_walk_t *w, const char *dir)
{
    if (brix_mkdir_beneath(w->rootfd, dir + w->root_len, w->mode) == 0) {
        return BRIX_MKDIR_CREATED;
    }
    return (errno == EEXIST) ? BRIX_MKDIR_EXISTED : BRIX_MKDIR_ERROR;
}

/*
 *
 * WHAT: Creates directories recursively from root to target path using unconstrained mkdir syscall. Thin wrapper that delegates to brix_mkdir_recursive_policy() with NULL log and rules (no group policy enforcement).
 *
 * WHY: Provides a simple API for callers who only need directory creation without policy checks — used by write/mv.c rename operations when creating intermediate directories during move.
 *
 * HOW: Copies path argument into tmp buffer, delegates to brix_mkdir_recursive_policy(path, mode, NULL, NULL). Returns 0 on success (all levels created or existed), -1 on failure. */

int
brix_mkdir_recursive(const char *path, mode_t mode)
{
    return brix_mkdir_recursive_policy(path, mode, NULL, NULL);
}

/*
 *
 * WHAT: Creates directories recursively from root to target path, applying parent group policy at each newly-created intermediate level when log and rules are provided. Uses local stack buffer (tmp[PATH_MAX]) to progressively truncate the path at each '/' separator, mkdir() each prefix, then restore the '/' before advancing.
 *
 * WHY: XRootD MKCOL requests may create multi-level directory trees in a single call. Creating each level individually ensures intermediate directories inherit the correct parent group policy from their newly-created parent, preventing misconfigured permissions on nested paths. The policy application happens only when mkdir succeeds (not when EEXIST is returned) — existing parents retain their original policy.
 *
 * HOW: Normalise path into tmp[PATH_MAX] (strip trailing '/'), then drive the shared component walk from tmp+1 with the plain-mkdir backend and fatal-on-create policy (policy_on_exist=0). Returns 0 on success, -1 on first failure. Thread safety: uses local stack buffers only — safe for concurrent use. */

int
brix_mkdir_recursive_policy(const char *path, mode_t mode,
                              ngx_log_t *log, ngx_array_t *rules)
{
    char              tmp[PATH_MAX];
    int               n = 0;
    brix_mkdir_walk_t w;

    if (brix_mkdir_copy_tmp(tmp, path, &n) != 0) {
        return -1;
    }

    ngx_memzero(&w, sizeof(w));
    w.log             = log;
    w.mode            = mode;
    w.rules           = rules;
    w.policy_on_exist = 0;
    w.make_level      = brix_mkdir_level_plain;

    return brix_mkdir_walk(&w, tmp, tmp + 1);
}

/*
 *
 * WHAT: Creates directories recursively from root to target path using confined mkdirat syscall under parent directory confinement. Takes pre-canonicalized root_canon and resolved path, validates that resolved is within root_canon before proceeding. Applies optional group policy at each newly-created intermediate level.
 *
 * WHY: The confined variant uses brix_mkdir_confined_canon() (mkdirat under confinement) instead of plain mkdir(), preventing directory creation outside the export root even if symlinks were introduced between path resolution and creation. This is the security-critical variant used by WebDAV MKCOL and native XRootD mkdir opcodes.
 *
 * HOW: Normalise resolved into tmp[PATH_MAX], confinement-gate it against root_canon (EXDEV on mismatch, EEXIST if equal) to obtain the relative-walk start pointer, then drive the shared walk with the confined-canon backend and best-effort policy (policy_on_exist=1). Returns 0 on success, -1 on first failure. Thread safety: uses local stack buffers only — safe for concurrent use. */

int
brix_mkdir_recursive_confined_canon(ngx_log_t *log, const char *root_canon,
                                      const char *resolved, mode_t mode,
                                      ngx_array_t *rules)
{
    char              tmp[PATH_MAX];
    char             *p;
    int               n = 0;
    brix_mkdir_walk_t w;

    if (brix_mkdir_copy_tmp(tmp, resolved, &n) != 0) {
        return -1;
    }

    ngx_memzero(&w, sizeof(w));
    w.log             = log;
    w.root_canon      = root_canon;
    w.root_len        = strlen(root_canon);
    w.mode            = mode;
    w.rules           = rules;
    w.policy_on_exist = 1;
    w.make_level      = brix_mkdir_level_confined;

    p = brix_mkdir_confined_start(tmp, root_canon, w.root_len);
    if (p == NULL) {
        return -1;
    }

    return brix_mkdir_walk(&w, tmp, p);
}

/*
 *
 * WHAT: Creates directories recursively from root to target path, creating each level via openat2(RESOLVE_BENEATH) under a pre-opened export-root dirfd. Validates that resolved is within root_canon before proceeding. Applies optional group policy at each newly-created intermediate level.
 *
 * WHY: As the confined-canon variant, but reuses an already-open rootfd (O_PATH dirfd of the export root) instead of re-opening parents per level — the same symlink-escape-proof confinement with less per-call syscall overhead. Used on the hot WebDAV/native mkdir paths.
 *
 * HOW: Normalise resolved into tmp[PATH_MAX], confinement-gate it against root_canon (EXDEV on mismatch, EEXIST if equal) to obtain the relative-walk start pointer, then drive the shared walk with the beneath backend (which passes the export-relative path tmp+root_len to brix_mkdir_beneath) and best-effort policy (policy_on_exist=1). Returns 0 on success, -1 on first failure. Thread safety: uses local stack buffers only — safe for concurrent use. */

int
brix_mkdir_recursive_beneath(ngx_log_t *log, int rootfd,
                                const char *root_canon, const char *resolved,
                                mode_t mode, ngx_array_t *rules)
{
    char              tmp[PATH_MAX];
    char             *p;
    int               n = 0;
    brix_mkdir_walk_t w;

    if (brix_mkdir_copy_tmp(tmp, resolved, &n) != 0) {
        return -1;
    }

    ngx_memzero(&w, sizeof(w));
    w.log             = log;
    w.rootfd          = rootfd;
    w.root_canon      = root_canon;
    w.root_len        = strlen(root_canon);
    w.mode            = mode;
    w.rules           = rules;
    w.policy_on_exist = 1;
    w.make_level      = brix_mkdir_level_beneath;

    p = brix_mkdir_confined_start(tmp, root_canon, w.root_len);
    if (p == NULL) {
        return -1;
    }

    return brix_mkdir_walk(&w, tmp, p);
}

/* Recursive directory creation with optional group policy enforcement
 * WHAT: Creates directories recursively from the root down to the target path, applying parent group policy at each newly-created intermediate level when log and rules are provided. Four public variants: unconstrained recursive mkdir (brix_mkdir_recursive), policy-aware variant (brix_mkdir_recursive_policy), confined canonical variant (brix_mkdir_recursive_confined_canon), and beneath variant (brix_mkdir_recursive_beneath). All share one component walk (brix_mkdir_walk) driven by a per-variant make_level backend.
 *
 * WHY: XRootD clients often create multi-level directory trees in a single MKCOL request. Creating each level individually with mkdir ensures intermediate directories inherit the correct group policy from their parent, preventing misconfigured permissions on nested paths. The confined variants use mkdirat under confinement to prevent creating directories outside the export root even if symlinks were introduced between path resolution and creation. Thread safety: uses local stack buffers only — safe for concurrent use. */
