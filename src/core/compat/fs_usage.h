#ifndef BRIX_COMPAT_FS_USAGE_H
#define BRIX_COMPAT_FS_USAGE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <sys/statvfs.h>

/*
 * brix_fs_usage_t — filesystem usage computed from statvfs(2).
 *
 * WHAT: Struct holding total/free/available/used bytes and occupancy ratio (ppm) derived
 *      from struct statvfs fields. WHY: Prometheus metrics, WebDAV PROPFIND properties,
 *      query responses need byte-level disk usage values rather than raw block counts. */

typedef struct {
    uint64_t   total_bytes;       /* f_blocks * block_size */
    uint64_t   free_bytes;        /* f_bfree  * block_size */
    uint64_t   available_bytes;   /* f_bavail * block_size */
    uint64_t   used_bytes;        /* total - free */
    uint64_t   occupancy_bytes;   /* total - available */
    ngx_uint_t occupancy_ppm;     /* occupancy_bytes / total, parts per million */
} brix_fs_usage_t;

/*
 * brix_fs_usage_from_statvfs — convert statvfs fields to computed usage bytes.
 *
 * WHAT: Takes populated struct statvfs and computes total/free/available/used bytes +
 *      occupancy ppm into out. WHY: statvfs returns raw block counts; callers need byte values.
 * HOW: f_frsize or f_bsize as multiplier → arithmetic for each field. Returns NGX_OK/NGX_ERROR. */

ngx_int_t brix_fs_usage_from_statvfs(const struct statvfs *vfs,
    brix_fs_usage_t *out);

/*
 * brix_fs_usage_stat — convenience wrapper: statvfs(path) + convert to usage bytes.
 *
 * WHAT: Calls statvfs on path then delegates to brix_fs_usage_from_statvfs(). WHY: Callers
 *      with a path string but no populated struct statvfs need a single-call entry point.
 * HOW: Validate path non-empty → statvfs(path, &vfs) → delegate to from_statvfs(&vfs, out). */

ngx_int_t brix_fs_usage_stat(const char *path, brix_fs_usage_t *out);

#endif /* BRIX_COMPAT_FS_USAGE_H */
