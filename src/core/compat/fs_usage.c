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
#include "../types/tunables.h"  /* BRIX_CORE_FS_USAGE_PPM */

/* ---- Multiply a block count without allowing capacity wraparound ----
 *
 * WHAT: Stores count * block_size and returns NGX_OK, or NGX_ERROR when the
 *       product exceeds uint64_t.
 *
 * WHY: Filesystem counters can come from FUSE and other untrusted filesystem
 *      implementations; wrapped capacity becomes a believable but false policy
 *      and monitoring input.
 *
 * HOW: Reject a non-zero multiplier whose count exceeds the exact quotient,
 *      otherwise perform the product.
 */
static ngx_int_t
brix_fs_usage_product(uint64_t count, uint64_t block_size, uint64_t *out)
{
    if (block_size != 0 && count > UINT64_MAX / block_size) {
        return NGX_ERROR;
    }
    *out = count * block_size;
    return NGX_OK;
}

/*
 * brix_fs_usage_from_statvfs - convert struct statvfs fields into computed usage bytes.
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
brix_fs_usage_from_statvfs(const struct statvfs *vfs, brix_fs_usage_t *out)
{
    uint64_t block_size;
    uint64_t total_bytes;
    uint64_t free_bytes;
    uint64_t available_bytes;

    if (vfs == NULL || out == NULL || vfs->f_blocks == 0) {
        return NGX_ERROR;
    }

    block_size = vfs->f_frsize ? (uint64_t) vfs->f_frsize
                               : (uint64_t) vfs->f_bsize;
    if (block_size == 0 || vfs->f_bfree > vfs->f_blocks
        || vfs->f_bavail > vfs->f_blocks
        || brix_fs_usage_product((uint64_t) vfs->f_blocks, block_size,
                                 &total_bytes) != NGX_OK
        || brix_fs_usage_product((uint64_t) vfs->f_bfree, block_size,
                                 &free_bytes) != NGX_OK
        || brix_fs_usage_product((uint64_t) vfs->f_bavail, block_size,
                                 &available_bytes) != NGX_OK)
    {
        return NGX_ERROR;
    }

    out->total_bytes = total_bytes;
    out->free_bytes = free_bytes;
    out->available_bytes = available_bytes;
    out->used_bytes = out->total_bytes - out->free_bytes;
    out->occupancy_bytes = out->total_bytes - out->available_bytes;
    out->occupancy_ppm = (ngx_uint_t)
        (((long double) out->occupancy_bytes * BRIX_CORE_FS_USAGE_PPM)
         / (long double) out->total_bytes);

    return NGX_OK;
}

/*
 * brix_fs_usage_stat - statvfs a path and convert to usage bytes.
 *
 * WHAT: Calls statvfs(path) on the given filesystem path, then delegates to
 *       brix_fs_usage_from_statvfs() to compute usage values into out.
 *
 * WHY: Convenience wrapper for callers that have a path string but not a populated
 *      struct statvfs. Used by metrics exporters and WebDAV property handlers.
 *
 * HOW: Validates path non-empty, calls statvfs(path, &vfs), then delegates to
 *      brix_fs_usage_from_statvfs(&vfs, out). Returns NGX_OK or NGX_ERROR.
 */

ngx_int_t
brix_fs_usage_stat(const char *path, brix_fs_usage_t *out)
{
    struct statvfs vfs;

    if (path == NULL || path[0] == '\0') {
        return NGX_ERROR;
    }

    if (statvfs(path, &vfs) != 0) {
        return NGX_ERROR;
    }

    return brix_fs_usage_from_statvfs(&vfs, out);
}
