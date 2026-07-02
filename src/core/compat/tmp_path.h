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

/*
 * xrootd_make_resume_path — build the DETERMINISTIC upload-resume staging path.
 *
 * With stage_dir empty/NULL: writes
 *   "<base_path>.xrdresume.<hex16(SHA-256(principal "\0" base_path))>.part"
 * (adjacent to the destination → atomic rename commit).  With stage_dir set:
 *   "<stage_dir>/<hex16(...)>.xrdresume.part"
 * (the partial lives on a fast cache device; commit moves it to storage).
 * Either way the name is a pure function of (principal, base_path), so a
 * reconnecting client's re-open of the same final path by the same identity
 * lands on the same staging file and resumes from its offset.  principal ""/NULL
 * => "anonymous".  Stale partials glob-clean with "*.xrdresume*.part".
 *
 * Returns NGX_OK, or NGX_ERROR on hash failure / truncation.
 */
ngx_int_t xrootd_make_resume_path(const char *base_path, const char *principal,
                                  const char *stage_dir, char *out,
                                  size_t out_sz);

/* Register an export root to scan for orphaned atomic-write temps (phase-64 SP4).
 * Called by each protocol's config finaliser; deduped. */
void xrootd_tmp_reap_register(const char *export_root);

/* Reap orphaned "<final>.xrd-tmp.<pid>.<rand>" temps (interrupted NON-staged direct
 * writes) under every registered export root: a temp whose owner pid is dead is
 * removed; one whose owner is still alive (a draining worker during reload) is kept.
 * Returns the count removed. Call once at worker-0 startup. */
ngx_uint_t xrootd_tmp_reap_all(ngx_log_t *log);

#endif /* XROOTD_COMPAT_TMP_PATH_H */
