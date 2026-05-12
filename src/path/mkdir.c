#include "../ngx_xrootd_module.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "path_internal.h"

int
xrootd_mkdir_recursive(const char *path, mode_t mode)
{
    return xrootd_mkdir_recursive_policy(path, mode, NULL, NULL);
}

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

int
xrootd_mkdir_recursive_confined(ngx_log_t *log, const ngx_str_t *root,
                                const char *resolved, mode_t mode,
                                ngx_array_t *rules)
{
    char   root_canon[PATH_MAX];
    char   tmp[PATH_MAX];
    char  *p;
    size_t root_len;
    int    n;

    if (!xrootd_get_canonical_root(log, root, root_canon,
                                   sizeof(root_canon))) {
        errno = EACCES;
        return -1;
    }

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
