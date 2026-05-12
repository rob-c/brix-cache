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

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return NGX_DECLINED;
    }

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

    desired_mode = (child_st.st_mode & ~(S_IRWXG | S_ISGID))
                 | xrootd_parent_group_mode_bits(&parent_st, &child_st);

    if (S_ISDIR(child_st.st_mode) && (parent_st.st_mode & S_ISGID)) {
        desired_mode |= S_ISGID;
    }

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

ngx_int_t
xrootd_apply_parent_group_policy_fd(ngx_log_t *log, int fd, const char *path,
                                    ngx_array_t *rules)
{
    return xrootd_apply_parent_group_policy_impl(log, fd, path, rules);
}

ngx_int_t
xrootd_apply_parent_group_policy_path(ngx_log_t *log, const char *path,
                                      ngx_array_t *rules)
{
    return xrootd_apply_parent_group_policy_impl(log, -1, path, rules);
}
