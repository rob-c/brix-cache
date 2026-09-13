/*
 * WHAT: Parent directory group policy inheritance for XRootD mkdir operations.
 *
 *   - brix_finalize_group_rules(): canonicalizes paths via brix_finalize_path_rules
 *   - brix_parent_group_mode_bits(): computes group permission bits from parent st_mode
 *     - Directories: S_IRWXG (all 3 group bits)
 *     - Files: S_IRGRP|S_IWGRP + inherited S_IXGRP (if child has it)
 *   - brix_apply_parent_group_policy_impl(): full policy enforcement
 *     - Finds matching group rule (longest-prefix match)
 *     - Extracts parent directory path via strrchr
 *     - Stats parent and child (stat/fstat)
 *     - Computes desired_mode (child mode sans group bits | parent-derived bits)
 *     - Applies S_ISGID from parent if child is directory
 *     - chown/fchown child to parent's gid if different
 *     - chmod/fchmod child to desired_mode if differs
 *   - Public wrappers:
 *     - brix_apply_parent_group_policy_fd() (fd-based)
 *     - brix_apply_parent_group_policy_path() (path-based)
 *
 * WHY: Group policy inheritance for shared HEP datasets.
 *
 *   - New files/dirs inherit parent's group ownership and permission bits
 *   - Critical for multi-user Unix groups needing consistent access
 *   - S_ISGID propagation: subdirectories inherit group
 *   - File execute bit: inherited only if child already has it (prevents over-permission)
 */

#include "core/ngx_brix_module.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fs/path/path_internal.h"

ngx_int_t
brix_finalize_group_rules(ngx_log_t *log, const ngx_str_t *root,
                            ngx_array_t *rules)
{
    return brix_finalize_path_rules(log, root, rules,
                                      sizeof(brix_group_rule_t),
                                      offsetof(brix_group_rule_t, path),
                                      offsetof(brix_group_rule_t, resolved),
                                      sizeof(((brix_group_rule_t *) 0)->resolved));
}
/* HOW: Canonicalizes group rule paths.
 *
 *   - Calls brix_finalize_path_rules() with:
 *     - sizeof(brix_group_rule_t)
 *     - offsetof(brix_group_rule_t, path)
 *     - offsetof(brix_group_rule_t, resolved)
 *     - sizeof(resolved)
 *   - Generic finalizer canonicalizes each rule's path via realpath(2)
 *   - Returns result directly (NGX_OK or NGX_ERROR)
 */

static mode_t
brix_parent_group_mode_bits(const struct stat *parent,
                              const struct stat *child)
{
    mode_t group_bits;

    if (S_ISDIR(child->st_mode)) {
        group_bits = parent->st_mode & S_IRWXG;
    } else {
        group_bits = parent->st_mode & (S_IRGRP | S_IWGRP);
        if (child->st_mode & S_IXGRP) {
            group_bits |= S_IXGRP;
        }
    }

    return group_bits;
}
/* HOW: Computes group permission bits from parent st_mode.
 *
 *   - If S_ISDIR(child->st_mode): group_bits = parent->st_mode & S_IRWXG
 *   - Else (file): group_bits = parent->st_mode & (S_IRGRP | S_IWGRP)
 *   - If child->st_mode & S_IXGRP → group_bits |= S_IXGRP (inherits execute)
 *   - Returns computed group_bits
 */

/*
 * WHAT: brix_derive_parent_dir() copies path into the caller's parent buffer,
 * then truncates it in place at the final '/' so it names the parent directory.
 * Returns NGX_OK with parent populated, NGX_DECLINED when the path has no usable
 * parent (relative/malformed, or a top-level entry whose parent is the FS root),
 * or NGX_ERROR (with errno=ENAMETOOLONG) when path does not fit the buffer.
 *
 * WHY: Isolating the parent-derivation branches (overflow check plus the two
 * strrchr sentinels) out of the policy driver keeps each unit simple while
 * preserving the exact decline/error semantics the policy depends on: a
 * top-level entry must be declined so policy never reattributes the filesystem
 * root's gid/mode to a child.
 *
 * HOW: snprintf(parent,parent_size,"%s",path); rc<0 or rc>=parent_size →
 * errno=ENAMETOOLONG + NGX_ERROR. strrchr(parent,'/') — if NULL (no slash) or
 * ==parent (only slash at index 0, e.g. "/foo") → NGX_DECLINED. Otherwise
 * *slash='\0' truncates ("/data/atlas/file" → "/data/atlas") and returns NGX_OK.
 */
static ngx_int_t
brix_derive_parent_dir(const char *path, char *parent, size_t parent_size)
{
    char *slash;
    int   rc;

    rc = snprintf(parent, parent_size, "%s", path);
    if (rc < 0 || (size_t) rc >= parent_size) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return NGX_DECLINED;
    }

    *slash = '\0';
    return NGX_OK;
}

/*
 * WHAT: brix_stat_child() fills child_st with the child object's metadata,
 * using fstat(fd) when fd>=0 and stat(path) otherwise.
 *
 * WHY: The fd-vs-path selection is a mechanical detail; hoisting it out of the
 * policy driver removes one nested branch pair there while keeping the identical
 * "fd wins if present" contract shared by the two public wrappers.
 *
 * HOW: fd>=0 → fstat(fd,child_st); else → stat(path,child_st). Either syscall
 * returning non-zero → NGX_ERROR (errno left as set by the syscall). Else NGX_OK.
 */
static ngx_int_t
brix_stat_child(int fd, const char *path, struct stat *child_st)
{
    if (fd >= 0) {
        if (fstat(fd, child_st) != 0) {
            return NGX_ERROR;
        }
    } else {
        if (stat(path, child_st) != 0) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: brix_apply_child_gid() sets the child's group to gid (uid untouched via
 * (uid_t)-1), using fchown(fd) when fd>=0 and chown(path) otherwise.
 *
 * WHY: The gid is taken from the parent dir, never from the request, so the
 * caller cannot choose an arbitrary group. Factoring the fd/path split keeps the
 * driver's ownership step to a single decision while preserving that guarantee.
 *
 * HOW: fd>=0 → fchown(fd,(uid_t)-1,gid); else → chown(path,(uid_t)-1,gid). Either
 * returning non-zero → NGX_ERROR (errno from the syscall). Else NGX_OK.
 */
static ngx_int_t
brix_apply_child_gid(int fd, const char *path, gid_t gid)
{
    if (fd >= 0) {
        if (fchown(fd, (uid_t) -1, gid) != 0) {
            return NGX_ERROR;
        }
    } else {
        if (chown(path, (uid_t) -1, gid) != 0) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: brix_apply_child_mode() sets the child's low 12 permission/special bits
 * to mode&BRIX_PERM_MASK, using fchmod(fd) when fd>=0 and chmod(path) otherwise.
 *
 * WHY: A chown can silently clear setuid/setgid on some kernels, so mode is
 * re-asserted after ownership; keeping the fd/path split here mirrors the gid
 * helper and leaves the driver a single mode-application decision.
 *
 * HOW: fd>=0 → fchmod(fd,mode&BRIX_PERM_MASK); else → chmod(path,mode&BRIX_PERM_MASK).
 * Either returning non-zero → NGX_ERROR (errno from the syscall). Else NGX_OK.
 */
static ngx_int_t
brix_apply_child_mode(int fd, const char *path, mode_t mode)
{
    if (fd >= 0) {
        if (fchmod(fd, mode & BRIX_PERM_MASK) != 0) {
            return NGX_ERROR;
        }
    } else {
        if (chmod(path, mode & BRIX_PERM_MASK) != 0) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: brix_desired_child_mode() computes the child's target mode from its
 * current mode and the parent's mode: clears the child's group bits and any
 * stale setgid, ORs in the parent-derived group bits, and re-adds S_ISGID only
 * for a subdirectory of a setgid parent.
 *
 * WHY: Clear-then-set makes the parent-derived bits authoritative rather than
 * merged with whatever umask/create-mode left behind, while owner/other bits are
 * preserved untouched; setgid propagates only to subdirectories of a setgid
 * parent, mirroring the kernel's directory-inheritance semantics so deeper mkdir
 * keeps the group and plain files never inherit setgid.
 *
 * HOW: desired = (child->st_mode & ~(S_IRWXG|S_ISGID)) |
 * brix_parent_group_mode_bits(parent,child). If S_ISDIR(child->st_mode) and
 * (parent->st_mode & S_ISGID) → desired |= S_ISGID. Returns desired.
 * Uses BRIX_PERM_MASK for permission bit extraction.
 */
static mode_t
brix_desired_child_mode(const struct stat *parent, const struct stat *child)
{
    mode_t desired_mode;

    desired_mode = (child->st_mode & ~(S_IRWXG | S_ISGID))
                 | brix_parent_group_mode_bits(parent, child);

    if (S_ISDIR(child->st_mode) && (parent->st_mode & S_ISGID)) {
        desired_mode |= S_ISGID;
    }

    return desired_mode;
}

/*
 * WHAT: brix_apply_parent_group_policy_impl() enforces parent-directory group
 * policy on the child named by path (statted via fd when fd>=0): it finds the
 * matching group rule, derives and stats the parent directory, stats the child,
 * computes the desired mode, then chowns the child's gid to the parent's and
 * chmods it to the desired mode when either differs.
 *
 * WHY: This is the single policy driver behind both public wrappers. Ordering is
 * load-bearing: gid is applied before mode so the mode re-assert restores any
 * S_ISGID a chown may have cleared, and non-matching / rootless paths are
 * declined so policy never touches objects it does not own.
 *
 * HOW: rule=brix_find_group_rule(path,rules) — NULL → NGX_DECLINED.
 * brix_derive_parent_dir(path,parent,sizeof) — non-OK returned as-is
 * (NGX_DECLINED for rootless/malformed, NGX_ERROR+ENAMETOOLONG for overflow).
 * stat(parent,&parent_st)!=0 → NGX_ERROR. brix_stat_child(fd,path,&child_st)
 * propagated. desired_mode=brix_desired_child_mode(&parent_st,&child_st). If
 * child_st.st_gid!=parent_st.st_gid → brix_apply_child_gid(fd,path,
 * parent_st.st_gid), propagate non-OK. If (child_st.st_mode & BRIX_PERM_MASK) !=
 * (desired_mode & BRIX_PERM_MASK) → brix_apply_child_mode(fd,path,desired_mode),
 * propagate non-OK. Returns NGX_OK on success.
 */
static ngx_int_t
brix_apply_parent_group_policy_impl(ngx_log_t *log, int fd,
                                      const char *path, ngx_array_t *rules)
{
    const brix_group_rule_t *rule;
    struct stat                parent_st;
    struct stat                child_st;
    char                       parent[PATH_MAX];
    mode_t                     desired_mode;
    ngx_int_t                  rc;

    (void) log;

    rule = brix_find_group_rule(path, rules);
    if (rule == NULL) {
        return NGX_DECLINED;
    }

    rc = brix_derive_parent_dir(path, parent, sizeof(parent));
    if (rc != NGX_OK) {
        return rc;
    }

    if (stat(parent, &parent_st) != 0) {
        return NGX_ERROR;
    }

    rc = brix_stat_child(fd, path, &child_st);
    if (rc != NGX_OK) {
        return rc;
    }

    desired_mode = brix_desired_child_mode(&parent_st, &child_st);

    /* Apply gid first (uid kept via (uid_t)-1), THEN mode below. The gid is
     * taken from the parent dir, never from the request, so the caller cannot
     * choose an arbitrary group. */
    if (child_st.st_gid != parent_st.st_gid) {
        rc = brix_apply_child_gid(fd, path, parent_st.st_gid);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* Compare and apply only the low 12 permission/special bits (07777 =
     * setuid|setgid|sticky + rwxrwxrwx); the file-type bits in st_mode are
     * masked off so chmod is skipped entirely when nothing in those bits moved. */
    if ((child_st.st_mode & BRIX_PERM_MASK) != (desired_mode & BRIX_PERM_MASK)) {
        rc = brix_apply_child_mode(fd, path, desired_mode);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

ngx_int_t
brix_apply_parent_group_policy_fd(ngx_log_t *log, int fd, const char *path,
                                    ngx_array_t *rules)
{
    return brix_apply_parent_group_policy_impl(log, fd, path, rules);
}
/* HOW: Direct wrapper.
 *
 *   - Calls brix_apply_parent_group_policy_impl(log, fd, path, rules)
 *   - Returns impl result directly (NGX_OK/NGX_ERROR/NGX_DECLINED)
 */

ngx_int_t
brix_apply_parent_group_policy_path(ngx_log_t *log, const char *path,
                                      ngx_array_t *rules)
{
    return brix_apply_parent_group_policy_impl(log, -1, path, rules);
}
/* HOW: Direct wrapper.
 *
 *   - Calls brix_apply_parent_group_policy_impl(log, -1, path, rules)
 *   - fd=-1 indicates path-based stat/fstat
 *   - Returns impl result directly
 */
