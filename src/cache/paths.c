#include "cache_internal.h"
#include "meta.h"


#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* ---- Cache Path Utilities Section ----
 *
 * WHAT: Three helper functions for cache file path management — suffix appending, parent directory creation, and ready-file validation.
 * WHY: Cache operations require deterministic filename construction (base + suffix), guaranteed parent directory existence, and precise file-state detection to support the open-or-fill admission decision logic.
 * HOW: Each function handles a single path operation with bounds checking and errno translation for consistent error reporting across cache subsystem.
 */

/* ---- xrootd_cache_append_suffix — append a suffix string to a cache path ----
 *
 * WHAT: Creates the full filename by concatenating base path + suffix. Used for constructing cache file names (e.g., "data" → "data.cache"). Returns NGX_OK on success, -1 on truncation or snprintf failure.
 * WHY: Cache naming convention uses deterministic suffix appending so that atomic rename operations can safely swap .part → final filename without collision risk from concurrent workers.
 * HOW: Single-pass snprintf concatenation with bounds validation — returns 0 (NGX_OK) when result fits within dstsz, -1 when snprintf truncates or produces negative output. */

int
xrootd_cache_append_suffix(char *dst, size_t dstsz, const char *path,
    const char *suffix)
{
    int n;

    n = snprintf(dst, dstsz, "%s%s", path, suffix);
    return (n >= 0 && (size_t) n < dstsz) ? 0 : -1;
}

int
xrootd_cache_meta_path(char *dst, size_t dstsz, const char *cache_path)
{
    return xrootd_cache_append_suffix(dst, dstsz, cache_path, ".meta");
}

/* ---- xrootd_cache_ensure_parent — create parent directories for a cache file ----
 *
 * WHAT: Extracts the directory portion of path and creates it recursively via mkdir. Returns NGX_OK if parent exists or was created, -1 on ENAMETOOLONG failure. The caller must ensure path fits in PATH_MAX.
 * WHY: Cache fill workers may attempt to write to paths where parent directories don't yet exist (e.g., newly discovered origin files). Preventing ENOENT failures ensures the fetch pipeline can proceed without manual directory setup.
 * HOW: Two-phase approach — first snprintf into PATH_MAX buffer with bounds check, then strrchr to locate last '/' separator and null-terminate to extract dirname, finally xrootd_mkdir_recursive with 0755 permissions for safe creation. */

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

/* ---- xrootd_cache_file_ready — check whether cache file exists and is a regular file ----
 *
 * WHAT: Validates that the path refers to an existing regular file (not directory, symlink, etc.). Returns 1 for ready file, 0 if file doesn't exist yet (ENOENT), -1 on stat failure or non-regular type. Used in cache open-or-fill decision logic.
 * WHY: The open-or-fill admission filter needs precise three-state detection — return value 1 means "cache hit, use existing" vs 0 means "cache miss, schedule fill" vs -1 means "error, abort". Misclassifying a directory as a ready file would cause corruption.
 * HOW: stat() call with ENOENT special-cased to return 0 (not -1) for cache-miss detection; S_ISREG check rejects directories and symlinks with errno translation (EISDIR vs EINVAL); only regular files pass the readiness gate. */

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
