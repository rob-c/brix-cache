/*
 * fs_usage.c - filesystem usage arithmetic from statvfs(2).
 *
 * WHAT: Converts struct statvfs fields (f_blocks, f_bfree, f_bavail) into computed
 *       total/free/available/used bytes and occupancy ratio in ppm. Provides both a
 *       raw statvfs converter and a path-based convenience wrapper.
 *
 * WHY: Prometheus metrics report disk occupancy. WebDAV PROPFIND may include filesystem
 *      usage properties. Query responses need available-space information for clients.
 *      Single shared implementation avoids duplication across modules.
 *
 * HOW: Uses f_frsize (preferred) or f_bsize as block size multiplier. Computes total,
 *      free, available, used, and occupancy bytes. Occupancy ppm = occupancy_bytes /
 *      total_bytes × 1000000 using long double for precision.
 */

#include "fs_usage.h"

/*
 * xrootd_fs_usage_from_statvfs - convert struct statvfs fields into computed usage bytes.
 *
 * WHAT: Takes a populated struct statvfs and computes total_bytes, free_bytes,
 *       available_bytes, used_bytes, occupancy_bytes, and occupancy_ppm into out.
 *
 * WHY: statvfs returns raw block counts; callers need byte-level values for metrics
 *      reporting and client responses. This function handles the arithmetic uniformly.
 *
 * HOW: Uses f_frsize (preferred) or f_bsize as block size. Computes:
 *      total = f_blocks × block_size, free = f_bfree × block_size,
 *      available = f_bavail × block_size, used = total - free,
 *      occupancy = total - available, occupancy_ppm = occupancy/total × 10^6.
 */

ngx_int_t
xrootd_fs_usage_from_statvfs(const struct statvfs *vfs, xrootd_fs_usage_t *out)
{
    uint64_t block_size;

    if (vfs == NULL || out == NULL || vfs->f_blocks == 0) {
        return NGX_ERROR;
    }

    block_size = vfs->f_frsize ? (uint64_t) vfs->f_frsize
                               : (uint64_t) vfs->f_bsize;

    out->total_bytes = (uint64_t) vfs->f_blocks * block_size;
    out->free_bytes = (uint64_t) vfs->f_bfree * block_size;
    out->available_bytes = (uint64_t) vfs->f_bavail * block_size;
    out->used_bytes = out->total_bytes - out->free_bytes;
    out->occupancy_bytes = out->total_bytes - out->available_bytes;
    out->occupancy_ppm = (ngx_uint_t)
        (((long double) out->occupancy_bytes * 1000000.0L)
         / (long double) out->total_bytes);

    return NGX_OK;
}

/*
 * xrootd_fs_usage_stat - statvfs a path and convert to usage bytes.
 *
 * WHAT: Calls statvfs(path) on the given filesystem path, then delegates to
 *       xrootd_fs_usage_from_statvfs() to compute usage values into out.
 *
 * WHY: Convenience wrapper for callers that have a path string but not a populated
 *      struct statvfs. Used by metrics exporters and WebDAV property handlers.
 *
 * HOW: Validates path non-empty, calls statvfs(path, &vfs), then delegates to
 *      xrootd_fs_usage_from_statvfs(&vfs, out). Returns NGX_OK or NGX_ERROR.
 */

ngx_int_t
xrootd_fs_usage_stat(const char *path, xrootd_fs_usage_t *out)
{
    struct statvfs vfs;

    if (path == NULL || path[0] == '\0') {
        return NGX_ERROR;
    }

    if (statvfs(path, &vfs) != 0) {
        return NGX_ERROR;
    }

    return xrootd_fs_usage_from_statvfs(&vfs, out);
}
