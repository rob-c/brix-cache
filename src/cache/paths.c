#include "cache_internal.h"

#if (NGX_THREADS)

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int
xrootd_cache_append_suffix(char *dst, size_t dstsz, const char *path,
    const char *suffix)
{
    int n;

    n = snprintf(dst, dstsz, "%s%s", path, suffix);
    return (n >= 0 && (size_t) n < dstsz) ? 0 : -1;
}

int
xrootd_cache_ensure_parent(const char *path)
{
    char  parent[PATH_MAX];
    char *slash;
    int   n;

    n = snprintf(parent, sizeof(parent), "%s", path);
    if (n < 0 || (size_t) n >= sizeof(parent)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return 0;
    }

    *slash = '\0';
    return xrootd_mkdir_recursive(parent, 0755);
}

int
xrootd_cache_file_ready(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return (errno == ENOENT) ? 0 : -1;
    }

    if (!S_ISREG(st.st_mode)) {
        errno = S_ISDIR(st.st_mode) ? EISDIR : EINVAL;
        return -1;
    }

    return 1;
}

#endif /* NGX_THREADS */
