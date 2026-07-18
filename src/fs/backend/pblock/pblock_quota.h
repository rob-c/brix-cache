/*
 * pblock_quota.h — Phase-83 F5 quotas + space accounting for the pblock driver.
 *
 * WHAT: A `usage(scope, id, bytes, inodes)` rollup table maintained by SQLite
 *       triggers on `objects` — transactional by construction (every catalog
 *       insert/update/delete adjusts the rollup inside the same statement
 *       window), so no driver call site can forget it. Scopes: 'total' (id 0),
 *       'uid', 'gid'. On top of it: admission checks (EDQUOT before bytes are
 *       accepted) at the catalog boundaries — open-create, staged open/commit,
 *       mkdir, server_copy, and the close/fsync size write-back.
 *
 * WHY:  Deterministic ENOSPC/EDQUOT/507/kXR_NoSpace tests without filling a
 *       disk, per-uid quota tests for the P80 multiuser model, and honest
 *       numbers for the `space` seam slot (kXR_statvfs / SRR).
 *
 * HOW:  All work happens at metadata boundaries (the hot byte path is
 *       untouched). Static limits ride the `?tail` opts (`quota=`,
 *       `quota_inodes=`); per-uid limits are runtime `ctl` rows
 *       (`quota.uid.<n>` = bytes, size suffixes allowed). Enabled only when a
 *       quota opt is present — otherwise no table, no triggers, byte-for-byte
 *       production catalog writes. ngx-free; BRIX_HAVE_SQLITE-gated like the
 *       rest of the backend.
 *
 * Requires: pblock_store.h (pblock_state_t) before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_QUOTA_H
#define BRIX_FS_BACKEND_PBLOCK_QUOTA_H

#include <stdint.h>

/* Create the usage table + maintenance triggers and rebuild the rollup from
 * the current objects rows (covers enabling quota on an existing export).
 * 0 on success, -1 on a sqlite failure (quota stays off — fail-safe). */
int pblock_quota_init(pblock_state_t *st);

/* Admission: would adding (add_bytes, add_inodes) attributed to `uid` exceed
 * the export quota (static opts) or the uid's `quota.uid.<n>` ctl limit?
 * 0 = admitted; -1 with errno=EDQUOT when a limit would be exceeded. Negative
 * deltas (shrink/replace) are always admitted. */
int pblock_quota_admit(const pblock_state_t *st, uint32_t uid,
                       int64_t add_bytes, int64_t add_inodes);

/* Largest size a handle opened on a `cur_size`-byte file owned by `uid` may
 * grow it to — the export byte quota and the uid's ctl limit, whichever leaves
 * less room. INT64_MAX when no byte limit applies. Snapshotted into the handle
 * at open so the write hot path enforces quota without touching the DB. */
int64_t pblock_quota_max_size(const pblock_state_t *st, uint32_t uid,
                              int64_t cur_size);

/* Admission for the close/fsync size write-back on `path`: computes the growth
 * vs the currently-stored row size and admits it. 0 or -1/errno=EDQUOT. */
int pblock_quota_touch_admit(const pblock_state_t *st, const char *path,
                             uint32_t uid, int64_t newsize);

/* Read one rollup row (scope 'total'/'uid'/'gid'); absent row reads as zeros.
 * 0 on success, -1 on a sqlite failure. */
int pblock_quota_usage(const pblock_state_t *st, const char *scope, int64_t id,
                       int64_t *bytes, int64_t *inodes);

#endif /* BRIX_FS_BACKEND_PBLOCK_QUOTA_H */
