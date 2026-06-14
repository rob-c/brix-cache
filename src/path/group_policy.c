/* ------------------------------------------------------------------ */
/* Parent Group Policy — Inherit GID and group permissions from parent    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements parent directory group policy inheritance for XRootD mkdir operations. xrootd_finalize_group_rules() canonicalizes all group rule paths using xrootd_finalize_path_rules with sizeof(xrootd_group_rule_t) parameters; xrootd_parent_group_mode_bits() computes desired group permission bits from parent's st_mode (S_IRWXG for directories, S_IRGRP|S_IWGRP for files + inherited file execute bit); xrootd_apply_parent_group_policy_impl() performs full policy enforcement: finds matching group rule via longest-prefix match, extracts parent directory path via strrchr, stat(parent) and stat/fstat(child), computes desired_mode (child mode masked without group bits then ORed with parent-derived bits), applies S_ISGID from parent if child is a directory, chown/fchown child to parent's gid if different, chmod/fchmod child to desired_mode if differs. Public wrappers: xrootd_apply_parent_group_policy_fd() (fd-based), xrootd_apply_parent_group_policy_path() (path-based).
 *
 * WHY: Group policy inheritance ensures new files/directories created under a parent directory inherit the parent's group ownership and appropriate group permission bits — critical for shared HEP datasets where multiple users in the same Unix group need consistent access. S_ISGID propagation on directories ensures subdirectories also inherit the group; file execute bit inherited only if child already has it prevents over-permissive mode assignment on regular files. */

/* ------------------------------------------------------------------ */
/* Section: Rule Finalization                                            */
/* ------------------------------------------------------------------ */
#include "../ngx_xrootd_module.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "path_internal.h"

ngx_int_t
xrootd_finalize_group_rules(ngx_log_t *log, const ngx_str_t *root,
                            ngx_array_t *rules)
{
    return xrootd_finalize_path_rules(log, root, rules,
                                      sizeof(xrootd_group_rule_t),
                                      offsetof(xrootd_group_rule_t, path),
                                      offsetof(xrootd_group_rule_t, resolved),
                                      sizeof(((xrootd_group_rule_t *) 0)->resolved));
}
/* ---- HOW: Calls xrootd_finalize_path_rules(log, root, rules, sizeof(xrootd_group_rule_t), offsetof(xrootd_group_rule_t, path), offsetof(xrootd_group_rule_t, resolved), sizeof(resolved)) — passes group rule struct size and field offsets so the generic finalizer canonicalizes each rule's path via realpath(2) into resolved. Returns xrootd_finalize_path_rules() result directly (NGX_OK or NGX_ERROR). */

static mode_t
xrootd_parent_group_mode_bits(const struct stat *parent,
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
/* ---- HOW: If S_ISDIR(child->st_mode): group_bits=parent->st_mode & S_IRWXG (all 3 group bits). Else: group_bits=parent->st_mode & (S_IRGRP | S_IWGRP) (read+write only for files). If child->st_mode & S_IXGRP → group_bits |= S_IXGRP (inherits file execute bit if child already has it). Returns computed group_bits. */

static ngx_int_t
xrootd_apply_parent_group_policy_impl(ngx_log_t *log, int fd,
                                      const char *path, ngx_array_t *rules)
{
    const xrootd_group_rule_t *rule;
    struct stat                parent_st;
    struct stat                child_st;
    char                       parent[PATH_MAX];
    char                      *slash;
    mode_t                     desired_mode;
    int                        rc;

    (void) log;

    rule = xrootd_find_group_rule(path, rules);
    if (rule == NULL) {
        return NGX_DECLINED;
    }

    rc = snprintf(parent, sizeof(parent), "%s", path);
    if (rc < 0 || (size_t) rc >= sizeof(parent)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    /* Derive the parent directory by truncating at the final '/'. slash==parent
     * means the only slash is at index 0 (a top-level entry like "/foo"), whose
     * parent is "/" — declined here so policy never reattributes the filesystem
     * root's gid/mode to a child. slash==NULL means a relative/malformed path. */
    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return NGX_DECLINED;
    }

    /* In-place truncate: turns "/data/atlas/file" into "/data/atlas". */
    *slash = '\0';
    if (stat(parent, &parent_st) != 0) {
        return NGX_ERROR;
    }

    if (fd >= 0) {
        if (fstat(fd, &child_st) != 0) {
            return NGX_ERROR;
        }
    } else {
        if (stat(path, &child_st) != 0) {
            return NGX_ERROR;
        }
    }

    /* Clear-then-set: strip the child's existing group bits and any stale setgid
     * (~(S_IRWXG | S_ISGID)) so the parent-derived bits are authoritative rather
     * than merged with whatever umask/create-mode left behind. Owner and other
     * bits are preserved untouched. setgid is re-added below only when warranted,
     * so it is never inherited onto plain files. */
    desired_mode = (child_st.st_mode & ~(S_IRWXG | S_ISGID))
                 | xrootd_parent_group_mode_bits(&parent_st, &child_st);

    /* Propagate setgid only to subdirectories of a setgid parent, mirroring the
     * kernel's directory-inheritance semantics so deeper mkdir keeps the group. */
    if (S_ISDIR(child_st.st_mode) && (parent_st.st_mode & S_ISGID)) {
        desired_mode |= S_ISGID;
    }

    /* Apply gid first (uid kept via (uid_t)-1), THEN mode below. A chown can
     * silently clear setuid/setgid on some kernels, so re-asserting desired_mode
     * afterwards restores any S_ISGID this policy intends to keep. The gid is
     * taken from the parent dir, never from the request, so the caller cannot
     * choose an arbitrary group. */
    if (child_st.st_gid != parent_st.st_gid) {
        if (fd >= 0) {
            if (fchown(fd, (uid_t) -1, parent_st.st_gid) != 0) {
                return NGX_ERROR;
            }
        } else {
            if (chown(path, (uid_t) -1, parent_st.st_gid) != 0) {
                return NGX_ERROR;
            }
        }
    }

    /* Compare and apply only the low 12 permission/special bits (07777 =
     * setuid|setgid|sticky + rwxrwxrwx); the file-type bits in st_mode are
     * masked off so chmod is skipped entirely when nothing in those bits moved. */
    if ((child_st.st_mode & 07777) != (desired_mode & 07777)) {
        if (fd >= 0) {
            if (fchmod(fd, desired_mode & 07777) != 0) {
                return NGX_ERROR;
            }
        } else {
            if (chmod(path, desired_mode & 07777) != 0) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}
/* ---- HOW: Finds rule=xrootd_find_group_rule(path, rules) — if NULL returns NGX_DECLINED (no matching rule). snprintf(parent,sizeof,parent,"%s",path) into parent buffer; rc<0 or rc>=sizeof → errno=ENAMETOOLONG+NGX_ERROR. strrchr(parent,'/') — if NULL || ==parent (root path) returns NGX_DECLINED. *slash='\0' truncates to parent dir path. stat(parent,&parent_st) — if !=0 returns NGX_ERROR. fd>=0: fstat(fd,&child_st); else: stat(path,&child_st) — both if !=0 return NGX_ERROR. desired_mode=(child_st.st_mode & ~(S_IRWXG|S_ISGID)) | xrootd_parent_group_mode_bits(&parent_st, &child_st). If S_ISDIR(child)&&parent has S_ISGID → desired_mode |= S_ISGID (propagate setgid to subdirs). If child_st.gid != parent_st.gid: fd>=0→fchown(fd,-1,parent_st.gid); else→chown(path,-1,parent_st.gid) — both if !=0 return NGX_ERROR. If (child&07777)!=(desired&07777): fd>=0→fchmod(fd,desired&07777); else→chmod(path,...) — both if !=0 return NGX_ERROR. Returns NGX_OK on success. */

ngx_int_t
xrootd_apply_parent_group_policy_fd(ngx_log_t *log, int fd, const char *path,
                                    ngx_array_t *rules)
{
    return xrootd_apply_parent_group_policy_impl(log, fd, path, rules);
}
/* ---- HOW: Direct wrapper — calls xrootd_apply_parent_group_policy_impl(log, fd, path, rules) with the provided file descriptor. Returns impl result directly (NGX_OK/NGX_ERROR/NGX_DECLINED). */

ngx_int_t
xrootd_apply_parent_group_policy_path(ngx_log_t *log, const char *path,
                                      ngx_array_t *rules)
{
    return xrootd_apply_parent_group_policy_impl(log, -1, path, rules);
}
/* ---- HOW: Direct wrapper — calls xrootd_apply_parent_group_policy_impl(log, -1, path, rules) with fd=-1 (path-based stat/fstat). Returns impl result directly. */
