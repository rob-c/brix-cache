/*
 * vfs_scratch.c — capability-gated "materialize to local POSIX scratch" helper.
 * See vfs_scratch.h for the contract and rationale.
 */
#include "vfs_scratch.h"
#include "../compat/staged_file.h"   /* xrootd_commit_staged (storage<->scratch move) */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* the capability gate*/
ngx_uint_t
xrootd_vfs_scratch_needed(const xrootd_sd_instance_t *storage, unsigned force)
{
    if (force) {
        return 1;
    }
    /* NULL storage == the default POSIX backend, which always has a kernel fd.
     * A bound instance is checked: no CAP_FD -> it cannot be operated on with a
     * real fd, so a local scratch copy is required. */
    if (storage == NULL) {
        return 0;
    }
    return (xrootd_sd_caps(storage) & XROOTD_SD_CAP_FD) ? 0 : 1;
}

/* Build "<stage_dir>/<key>.scratch" (deterministic).  0 / -1 (errno set). */
static ngx_int_t
scratch_path_for(const char *stage_dir, const char *key, char *out, size_t outsz)
{
    int n;

    if (stage_dir == NULL || stage_dir[0] == '\0' || key == NULL || key[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }
    n = snprintf(out, outsz, "%s/%s.scratch", stage_dir, key);
    if (n < 0 || (size_t) n >= outsz) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* PRODUCE*/
ngx_int_t
xrootd_vfs_scratch_produce_target(const xrootd_sd_instance_t *storage,
    const char *logical_path, const char *stage_dir, const char *key,
    unsigned force, char *out, size_t outsz, ngx_uint_t *materialized,
    ngx_log_t *log)
{
    int n;

    (void) log;
    if (logical_path == NULL || out == NULL || materialized == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (!xrootd_vfs_scratch_needed(storage, force)) {
        /* Operate in place: the producer writes straight to the export object. */
        n = snprintf(out, outsz, "%s", logical_path);
        if (n < 0 || (size_t) n >= outsz) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }
        *materialized = 0;
        return NGX_OK;
    }

    if (scratch_path_for(stage_dir, key, out, outsz) != NGX_OK) {
        return NGX_ERROR;
    }
    *materialized = 1;
    return NGX_OK;
}

ngx_int_t
xrootd_vfs_scratch_produce_commit(const char *logical_path, const char *stage_dir,
    const char *key, ngx_uint_t materialized, ngx_log_t *log)
{
    char scratch[PATH_MAX];

    if (!materialized) {
        return NGX_OK;                       /* produced in place — nothing to move */
    }
    if (logical_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (scratch_path_for(stage_dir, key, scratch, sizeof(scratch)) != NGX_OK) {
        return NGX_ERROR;
    }
    /* Publish: same-FS rename, or a cross-device VFS<->VFS copy (the producer
     * already wrote + closed the file, so no staged fd to fsync — pass -1). */
    return xrootd_commit_staged(NGX_INVALID_FILE, scratch, logical_path, log);
}

/* CONSUME*/
/* Copy the whole of src_fd into dst_fd through the SD driver (positional; bytes
 * stay on the backend). 0 / -1 (errno set). */
static ngx_int_t
scratch_copy_in(int src_fd, int dst_fd)
{
    static const size_t CHUNK = 256 * 1024;
    char           *buf = malloc(CHUNK);
    off_t           off = 0;
    xrootd_sd_obj_t s, d;

    if (buf == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    xrootd_sd_posix_wrap(&s, src_fd);
    xrootd_sd_posix_wrap(&d, dst_fd);
    for ( ;; ) {
        ssize_t r = s.driver->pread(&s, buf, CHUNK, off);
        if (r < 0) { if (errno == EINTR) { continue; } free(buf); return NGX_ERROR; }
        if (r == 0) { break; }
        ssize_t w_done = 0;
        while (w_done < r) {
            ssize_t w = d.driver->pwrite(&d, buf + w_done, (size_t) (r - w_done),
                                         off + w_done);
            if (w < 0) { if (errno == EINTR) { continue; } free(buf); return NGX_ERROR; }
            w_done += w;
        }
        off += r;
    }
    free(buf);
    return NGX_OK;
}

ngx_fd_t
xrootd_vfs_scratch_stage_fd(ngx_fd_t src_fd, const char *stage_dir, ngx_log_t *log)
{
    char tmpl[PATH_MAX];
    int  dst_fd, rd_fd, e, n;

    (void) log;
    if (stage_dir == NULL || stage_dir[0] == '\0') {
        errno = EINVAL;
        return NGX_INVALID_FILE;
    }
    n = snprintf(tmpl, sizeof(tmpl), "%s/.vfsstage.XXXXXX", stage_dir);
    if (n < 0 || (size_t) n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        return NGX_INVALID_FILE;
    }
    dst_fd = mkstemp(tmpl);
    if (dst_fd < 0) {
        return NGX_INVALID_FILE;
    }
    /* Anonymous from here: the bytes live only behind the open fd(s). */
    (void) unlink(tmpl);
    if (scratch_copy_in(src_fd, dst_fd) != NGX_OK) {
        e = errno; close(dst_fd); errno = e; return NGX_INVALID_FILE;
    }
    /* Reopen the now-unlinked inode read-only via /proc so the consumer gets a
     * clean O_RDONLY fd at offset 0 (the write fd is positional, but a fresh
     * read fd keeps the consumer's pread semantics simple). */
    {
        char proc[64];
        (void) snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dst_fd);
        rd_fd = open(proc, O_RDONLY | O_CLOEXEC);
    }
    e = errno;
    close(dst_fd);
    if (rd_fd < 0) {
        errno = e;
        return NGX_INVALID_FILE;
    }
    return rd_fd;
}
