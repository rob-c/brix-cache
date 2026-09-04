/*
 * tmp_path.h — Uniform temporary-file path construction for atomic writes.
 *
 * Single function: brix_make_tmp_path() generates unique temp paths in the format
 * <base>.xrd-tmp.<pid>.<random> used by S3 PUT, WebDAV COPY, and WebDAV TPC pull. The .xrd-tmp.
 * prefix enables operators to glob-clean orphaned temp files across all subsystems with one
 * pattern: find /export -name "*.xrd-tmp.*" -mtime +1 -delete.
 */

#ifndef BRIX_COMPAT_TMP_PATH_H
#define BRIX_COMPAT_TMP_PATH_H

#include <ngx_core.h>
#include <stddef.h>
#include <time.h>

/*
 * brix_make_tmp_path — build a unique temporary path adjacent to base_path.
 *
 * Writes "<base_path>.xrd-tmp.<pid>.<random>" into out[out_sz].
 * Using a uniform suffix across all protocols means stale temp files from
 * any subsystem (WebDAV COPY, WebDAV TPC pull, S3 PUT) are recognisable
 * and can be cleaned by a single glob pattern ("*.xrd-tmp.*").
 *
 * Returns NGX_OK on success, NGX_ERROR if out_sz is too small.
 */
ngx_int_t brix_make_tmp_path(const char *base_path, char *out, size_t out_sz);

/*
 * brix_tmp_is_temp_name — nonzero if `name` (a bare directory-entry name)
 * is a staged atomic-write temp, i.e. carries the ".xrd-tmp." infix. Store
 * enumerators use it to skip a crash-orphaned temp so it is never listed as
 * an object before the startup reaper removes it.
 */
int brix_tmp_is_temp_name(const char *name);

/*
 * brix_make_resume_path — build the DETERMINISTIC upload-resume staging path.
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
ngx_int_t brix_make_resume_path(const char *base_path, const char *principal,
                                  const char *stage_dir, char *out,
                                  size_t out_sz);

/* POSC-orphan reaping policy (ofs.persist analog, parity audit §1.9). Governs
 * what brix_tmp_reap_all() does with a crash-orphaned "<final>.xrd-tmp.*" temp
 * whose owner pid is dead. AUTO removes it (the historical default); MANUAL and
 * OFF both KEEP it for an operator to inspect/recover. Node-global: the reaper
 * runs once at worker-0 startup, so the policy is a property of the node, set by
 * the last server block that carries a brix_posc_persist directive. */
#define BRIX_POSC_PERSIST_AUTO    0   /* reap dead-owner orphans (default)      */
#define BRIX_POSC_PERSIST_MANUAL  1   /* keep orphans for manual recovery       */
#define BRIX_POSC_PERSIST_OFF     2   /* keep orphans; no automatic recovery    */

/* Set the node-global reaping policy. mode is a BRIX_POSC_PERSIST_* value;
 * hold_sec is a grace period (seconds) — under AUTO an orphan is reaped only
 * once it has been idle at least hold_sec (mtime age), so a temp from a transfer
 * that is about to reconnect-and-resume is not nuked out from under it. 0 = no
 * grace (reap immediately). Called at config time; AUTO/0 = historical behaviour. */
void brix_tmp_reap_set_policy(int mode, time_t hold_sec);

/* Register an export root to scan for orphaned atomic-write temps (phase-64 SP4).
 * Called by each protocol's config finaliser; deduped. */
void brix_tmp_reap_register(const char *export_root);

/* Reap orphaned "<final>.xrd-tmp.<pid>.<rand>" temps (interrupted NON-staged direct
 * writes) under every registered export root: a temp whose owner pid is dead is
 * removed; one whose owner is still alive (a draining worker during reload) is kept.
 * Returns the count removed. Call once at worker-0 startup. */
ngx_uint_t brix_tmp_reap_all(ngx_log_t *log);

#endif /* BRIX_COMPAT_TMP_PATH_H */
