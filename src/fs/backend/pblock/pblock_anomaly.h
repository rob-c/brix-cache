/*
 * pblock_anomaly.h — Phase-83 F9 eventual-consistency anomaly emulation.
 *
 * WHAT: Deterministic S3-style read-after-write anomalies for lab exports:
 *         ctl `anomaly.visibility_ms=N`  — a freshly created path answers
 *                                          ENOENT to *other* opens/stats for
 *                                          N ms after creation
 *         ctl `anomaly.stale_stat_ms=N`  — for N ms after an update, stat
 *                                          serves the pre-update size/mtime
 *         ctl `anomaly.list_lag_ms=N`    — readdir omits rows created within
 *                                          the last N ms
 *       State is a driver-owned `recent` table keyed by path with two
 *       independent event timestamps (created_ms / updated_ms) plus the
 *       pre-update row snapshot — independent columns, because a PUT's own
 *       close-touch records an update and must not erase the create event
 *       that drives visibility lag.
 *
 * WHY:  The cache tier, remote-origin drivers and TPC flows claim to tolerate
 *       S3 eventual consistency but are tested against nothing. This makes
 *       pblock a deterministic consistency simulator under the full stack.
 *
 * HOW:  All catalog-side, at metadata boundaries only — the byte path is
 *       untouched. Gated on the F1 lab master gate (`lab=1` in the ?tail):
 *       callers guard on `st->lab != NULL`, so a production-shaped export
 *       never reaches this module. Events are recorded only while the
 *       matching ctl rule is armed; consultation is a pure read (rows expire
 *       logically, never deleted in the read path). The anomaly never applies
 *       to the handle that wrote: a writer reads through its own open
 *       snapshot (os->meta) and write-intent opens are exempted at the call
 *       site — the S3 session monotonic-read guarantee, structurally.
 *       ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-gated.
 *
 * Requires: pblock_store.h and fs/backend/sd.h before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_ANOMALY_H
#define BRIX_FS_BACKEND_PBLOCK_ANOMALY_H

/* Create the `recent` table (idempotent). Called once at init when the lab
 * gate is armed. Returns 0 on success. */
int pblock_anomaly_init(pblock_state_t *st);

/* Event recording — best-effort, no-ops unless the matching rule is armed. */
void pblock_anomaly_created(pblock_state_t *st, const char *path);
void pblock_anomaly_updated(pblock_state_t *st, const char *path,
    int64_t old_size, int64_t old_mtime);

/* Consultation — pure reads. */
int pblock_anomaly_hidden(pblock_state_t *st, const char *path);
int pblock_anomaly_stale(pblock_state_t *st, const char *path,
    int64_t *size_io, int64_t *mtime_io);
int pblock_anomaly_list_hidden(pblock_state_t *st, const char *dir,
    const char *name);

/* Namespace row maintenance — best-effort. */
void pblock_anomaly_rename(pblock_state_t *st, const char *src,
    const char *dst);
void pblock_anomaly_drop(pblock_state_t *st, const char *path);

#endif /* BRIX_FS_BACKEND_PBLOCK_ANOMALY_H */
