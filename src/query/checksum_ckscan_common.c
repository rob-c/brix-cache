/*
 * checksum_ckscan_common.c — shared helpers for kXR_Qckscan directory/file checksum scans.
 *
 * WHAT: Provides three functions used by checksum_ckscan_async.c and checksum_ckscan_dispatch.c to walk filesystem trees and compute per-file checksums. ckscan_append() grows a response buffer with "algo hex logical_path" lines; xrootd_ckscan_join_logical() constructs canonical logical paths from parent+child components; xrootd_ckscan_walk() recursively scans directories up to max_depth/max_files limits, computing checksums for regular files.
 *
 * WHY: kXR_Qckscan walks a directory tree off the event loop (async via thread pool) and returns one checksum line per file. These shared helpers eliminate code duplication between async and dispatch implementations while providing consistent path construction, buffer growth logic, and recursive walk semantics with depth/capacity limits.
 */

#include "query_internal.h"
#include "../response/response.h"
#include "../aio/aio.h"
#include "../compat/checksum.h"
#include "../compat/fs_walk.h"

#include <dirent.h>
#include <sys/stat.h>

/* ---- kXR_Qckscan — directory / file checksum scan ---- */

/* Append one "algo hex  logical_path\n" line, growing the buffer if needed. */
int
xrootd_ckscan_append(u_char **buf, size_t *cap, size_t *used,
    const char *algo, uint32_t cksum, const char *logical)
{
    char    line[XROOTD_MAX_PATH + 64];
    size_t  llen;
    u_char *nb;

    llen = (size_t) snprintf(line, sizeof(line), "%s %08x  %s\n",
                             algo, (unsigned int) cksum, logical);
    if (llen >= sizeof(line)) {
        return 0;  /* path too long: skip */
    }

    if (*used + llen + 2 > *cap) {
        size_t new_cap = *cap * 2 + llen + 2;
        nb = ngx_alloc(new_cap, ngx_cycle->log);
        if (nb == NULL) {
            return -1;
        }
        if (*buf) {
            ngx_memcpy(nb, *buf, *used);
            ngx_free(*buf);
        }
        *buf = nb;
        *cap = new_cap;
    }

    ngx_memcpy(*buf + *used, line, llen);
    *used += llen;
    return 1;
}
/* ---- WHY: Qckscan responses are newline-delimited "algo hex logical_path" lines growing into a dynamically-sized buffer. The client expects all checksum results in one response, so the buffer must handle arbitrary tree sizes via exponential growth. Returns 1 on success (line appended), 0 if output line would overflow local snprintf buffer (path too long → skip silently), -1 if OOM during buffer reallocation. ---- */

/* ---- HOW: snprintf(line) formats "%s %08x  %s\n" with algo, cksum as hex, logical path — returns llen. If llen >= sizeof(line) returns 0 (skip). Checks *used+llen+2 <= *cap — if insufficient allocates new_cap=*cap*2+llen+2 via ngx_alloc(), copies existing *buf content, frees old buffer, updates *buf and *cap. memcpy line into *buf at offset *used; increments *used by llen. Returns 1. */

static ngx_flag_t
xrootd_ckscan_join_logical(const char *parent, const char *name,
    char *out, size_t outsz)
{
    int n;

    if (strcmp(parent, "/") == 0) {
        n = snprintf(out, outsz, "/%s", name);
        return (n >= 0 && (size_t) n < outsz);
    }

    n = snprintf(out, outsz, "%s/%s", parent, name);
    return (n >= 0 && (size_t) n < outsz);
}
/* ---- WHY: Qckscan responses use logical paths (relative to export root) rather than resolved filesystem paths. This function constructs canonical logical paths from parent directory + child name, handling the special case where parent is "/" (root export) which produces "/<name>" instead of "//<name>". Used by ckscan_walk() for every child entry and by dispatchers to construct per-file response lines. ---- */

/* ---- HOW: If strcmp(parent, "/") == 0, snprintf out as "/%s" (root case). Otherwise snprintf as "%s/%s" (normal join). Returns ngx_flag_t true if n >= 0 && (size_t) n < outsz (fits in buffer), false on truncation. Static helper used exclusively by ckscan_walk(). */

/* Recursive directory scanner; returns 0 on success, -1 on hard error. */
int
xrootd_ckscan_walk(ngx_log_t *log, const char *root_resolved,
    const char *resolved_dir, const char *logical_dir, const char *algo,
    u_char **buf, size_t *cap, size_t *used, ngx_uint_t depth,
    ngx_uint_t max_depth, ngx_uint_t max_files, ngx_uint_t *nfiles,
    char *errmsg, size_t errsz)
{
    DIR           *dh;
    struct dirent *de;
    struct stat    st;
    char           child_resolved[PATH_MAX];
    char           child_logical[XROOTD_MAX_PATH + 1];
    int            dfd;

    if (depth > max_depth) {
        return 0;
    }

    dfd = xrootd_open_confined_canon(log, root_resolved, resolved_dir,
                                     O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) {
        snprintf(errmsg, errsz, "opendir failed: %s", strerror(errno));
        return -1;
    }

    dh = fdopendir(dfd);
    if (dh == NULL) {
        close(dfd);
        snprintf(errmsg, errsz, "opendir failed: %s", strerror(errno));
        return -1;
    }

    while ((de = readdir(dh)) != NULL) {
        if (xrootd_fs_is_dot_entry(de->d_name)) {
            continue;
        }

        if (xrootd_fs_join_path(resolved_dir, de->d_name,
                                child_resolved, sizeof(child_resolved))
            != NGX_OK)
        {
            continue;
        }

        if (!xrootd_ckscan_join_logical(logical_dir, de->d_name,
                                        child_logical, sizeof(child_logical))) {
            continue;
        }

        if (fstatat(dirfd(dh), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (xrootd_ckscan_walk(log, root_resolved, child_resolved,
                                   child_logical, algo, buf, cap, used,
                                   depth + 1, max_depth, max_files, nfiles,
                                   errmsg, errsz) < 0)
            {
                closedir(dh);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            int      fd;
            uint32_t cksum;
            xrootd_checksum_alg_t alg;

            if (*nfiles >= max_files) {
                continue;
            }
            (*nfiles)++;

            fd = xrootd_open_confined_canon(log, root_resolved,
                                            child_resolved, O_RDONLY, 0);
            if (fd < 0) {
                continue;
            }

            if (xrootd_checksum_parse(algo, strlen(algo), &alg, NULL, 0)
                    != NGX_OK
                || xrootd_checksum_u32_fd(alg, fd, child_resolved, log,
                                          &cksum) != NGX_OK)
            {
                cksum = (uint32_t) -1;
            }
            close(fd);

            if (cksum == (uint32_t) -1) {
                continue;  /* skip unreadable files */
            }

            if (xrootd_ckscan_append(buf, cap, used,
                                     algo, cksum, child_logical) < 0) {
                snprintf(errmsg, errsz, "out of memory");
                closedir(dh);
                return -1;
            }
        }
    }

    closedir(dh);
    return 0;
}
/* ---- WHY: kXR_Qckscan walks directory trees off the event loop via thread pool to compute per-file checksums. Supports recursive traversal up to max_depth with max_files cap, skipping unreadable files and dot entries. Returns one "algo hex logical_path" line per regular file in the response buffer. Depth/capacity limits prevent runaway scans on large filesystems. ---- */

/* ---- HOW: Checks depth > max_depth → returns 0 (cap reached). Opens resolved_dir via xrootd_open_confined_canon() + fdopendir() — if both fail logs errno to errmsg, returns -1. readdir loop over entries: skips dot entries via xrootd_fs_is_dot_entry(), joins child resolved path via xrootd_fs_join_path(), joins child logical path via xrootd_ckscan_join_logical(). fstatat AT_SYMLINK_NOFOLLOW → if S_ISDIR recurses ckscan_walk(depth+1); if S_ISREG checks *nfiles < max_files, opens file via confined canon, parses algo to alg, computes checksum via xrootd_checksum_u32_fd() — on failure sets cksum=-1. If cksum valid calls ckscan_append() for response line; if OOM returns -1. closedir at end, returns 0 success or -1 error. */
