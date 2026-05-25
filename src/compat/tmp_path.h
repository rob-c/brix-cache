/*
 * tmp_path.h — Uniform temporary-file path construction for atomic writes.
 *
 * Single function: xrootd_make_tmp_path() generates unique temp paths in the format
 * <base>.xrd-tmp.<pid>.<random> used by S3 PUT, WebDAV COPY, and WebDAV TPC pull. The .xrd-tmp.
 * prefix enables operators to glob-clean orphaned temp files across all subsystems with one
 * pattern: find /export -name "*.xrd-tmp.*" -mtime +1 -delete.
 */

#ifndef XROOTD_COMPAT_TMP_PATH_H
#define XROOTD_COMPAT_TMP_PATH_H

#include <ngx_core.h>
#include <stddef.h>

/*
 * xrootd_make_tmp_path — build a unique temporary path adjacent to base_path.
 *
 * Writes "<base_path>.xrd-tmp.<pid>.<random>" into out[out_sz].
 * Using a uniform suffix across all protocols means stale temp files from
 * any subsystem (WebDAV COPY, WebDAV TPC pull, S3 PUT) are recognisable
 * and can be cleaned by a single glob pattern ("*.xrd-tmp.*").
 *
 * Returns NGX_OK on success, NGX_ERROR if out_sz is too small.
 */
ngx_int_t xrootd_make_tmp_path(const char *base_path, char *out, size_t out_sz);

#endif /* XROOTD_COMPAT_TMP_PATH_H */
