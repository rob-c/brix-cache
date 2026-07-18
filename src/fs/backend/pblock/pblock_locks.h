/*
 * pblock_locks.h — Phase-83 F15 byte-range locks / mandatory lease
 * enforcement for pblock.
 *
 * WHAT: A driver-owned `locks(path, off, len, mode, owner, expires_at)`
 *       catalog table plus MANDATORY enforcement: a live foreign lease
 *       refuses conflicting opens at open time (whole-file leases —
 *       `len = 0` means the whole file), denies overlapping pwrites through
 *       an open-time snapshot (range leases, `len > 0`), and blocks the
 *       bypass routes — unlink, rename and staged publish of a leased path.
 *       Modes: 'W' excludes other writers, 'X' excludes everyone else.
 *       Refusals are errno EBUSY, which the protocol edge maps to
 *       kXR_FileLocked / HTTP 423.
 *
 * WHY:  Real concurrent-writer exclusion (two STORs to one path), the
 *       "single-writer" guarantee TPC destinations want, and a mandatory
 *       backing model for WebDAV LOCK semantics — enforced by the storage
 *       driver, not advisory.
 *
 * HOW:  Leases are rows (owner = synthetic catalog uid; `expires_at` is a
 *       unix-seconds deadline so a crashed client can never wedge the
 *       export — expired rows are ignored everywhere). Tests plant and
 *       release rows via sqlite3, the standard ctl channel. Enforcement DB
 *       reads happen only at metadata boundaries (open/unlink/rename/
 *       commit); the pwrite check is a pure scan of the per-handle snapshot
 *       taken at open — per the phase design, a conflicting later open is
 *       refused at *its* open, which is what makes per-I/O DB hits
 *       unnecessary. A later-acquired lease does not affect already-open
 *       handles (the documented snapshot model). Gated by its own
 *       `locks=1` static opt; ngx-free (libc + sqlite3),
 *       BRIX_HAVE_SQLITE-gated.
 *
 * Requires: pblock_store.h, sd_pblock_internal.h and fs/backend/sd.h before
 * inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_LOCKS_H
#define BRIX_FS_BACKEND_PBLOCK_LOCKS_H

/* One snapshotted foreign range lease (os->lock_rng array element). Named
 * struct so sd_pblock_internal.h can hold the pointer without including us. */
typedef struct pblock_lock_rng_s {
    int64_t off;
    int64_t len;          /* > 0: range; 0 rows are refused at open instead */
    int64_t expires_at;   /* unix seconds; ignored once in the past */
} pblock_lock_rng_t;

/* Create the `locks` table (idempotent). Returns 0 on success. */
int pblock_locks_init(pblock_state_t *st);

/* Open-time gate: refuse (errno EBUSY, -1) when a live foreign 'X' lease
 * exists, or `want_write` and a live foreign whole-file 'W' lease exists. */
int pblock_locks_open_check(const pblock_state_t *st, const char *path,
    int want_write, uint32_t uid);

/* Namespace gate for unlink/rename/staged-publish: refuse (errno EBUSY,
 * -1) when ANY live foreign lease exists — a lock you cannot release must
 * not be dissolvable by deleting or renaming the file under it. */
int pblock_locks_ns_check(const pblock_state_t *st, const char *path,
    uint32_t uid);

/* Snapshot the live foreign range leases into os->lock_rng/lock_n
 * (malloc'd; freed at close). Best-effort: on any failure the handle
 * carries no snapshot. */
void pblock_locks_snapshot(const pblock_state_t *st, pblock_obj_t *os,
    uint32_t uid);

/* Pure hot-path check over the open-time snapshot: 1 when [off, off+len)
 * overlaps a still-live snapshotted range lease. No DB, no locks. */
int pblock_locks_range_denied(const pblock_obj_t *os, off_t off, size_t len);

/* Namespace row maintenance — best-effort. */
void pblock_locks_rename(const pblock_state_t *st, const char *src,
    const char *dst);
void pblock_locks_drop(const pblock_state_t *st, const char *path);

#endif /* BRIX_FS_BACKEND_PBLOCK_LOCKS_H */
