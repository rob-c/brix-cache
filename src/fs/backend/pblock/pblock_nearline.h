/*
 * pblock_nearline.h — Phase-83 F4 nearline/tape simulation for the pblock driver.
 *
 * WHAT: A driver-owned `nearline(path, res)` catalog table modelling tape
 *       residency (the brix_sd_residency_t states) plus a bounded synchronous
 *       recall — the same contract sd_frm implements over a real MSS adapter,
 *       here as pure simulation: recall latency and failure are runtime `ctl`
 *       rules, no MSS process anywhere.
 *
 * WHY:  Exercises the dormant nearline lane natively — the `residency`/`recall`
 *       vtable slots, `BRIX_SD_CAP_NEARLINE`, the cache tier's recall-at-fill,
 *       kXR offline/stall classification — with deterministic timing tests
 *       (today only reachable with a scripted frm://exec MSS).
 *
 * HOW:  Absent row ⇒ ONLINE (the default for everything ever written); tests
 *       demote files by inserting rows via the sqlite3 CLI (the standard ctl
 *       channel). `ctl` knobs: `nearline.recall_ms` (simulated recall latency,
 *       capped) and `nearline.fail.<path>` (that path's recall lands LOST).
 *       Recall is synchronous like sd_frm's (nothing consumes NGX_AGAIN parking
 *       yet — the stage-engine RECALL integration is the deferred async half):
 *       sleep the latency, then flip the row ONLINE (delete) or LOST. Armed by
 *       `nearline=1` in the `?tail` static opts; off ⇒ no table consulted,
 *       byte-for-byte production driver. ngx-free; BRIX_HAVE_SQLITE-gated.
 *
 * Requires: pblock_store.h (pblock_state_t) + fs/backend/sd.h
 * (brix_sd_residency_t) before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_NEARLINE_H
#define BRIX_FS_BACKEND_PBLOCK_NEARLINE_H

/* Create the nearline residency table (idempotent). 0 on success, -1 on a
 * sqlite failure (the feature stays off — fail-safe). */
int pblock_nearline_init(pblock_state_t *st);

/* Pure residency read for `path` — never initiates or advances a recall.
 * Absent row ⇒ BRIX_SD_RES_ONLINE. 0 on success (out set), -1/errno. */
int pblock_nearline_res(const pblock_state_t *st, const char *path,
                        brix_sd_residency_t *out);

/* Bounded synchronous recall of `path`: ONLINE ⇒ 0 immediately; LOST ⇒
 * -1/errno=ENOENT; NEARLINE/OFFLINE ⇒ sleep the simulated latency
 * (`ctl:nearline.recall_ms`, capped at 30s), then either flip the row ONLINE
 * and return 0, or — when `ctl:nearline.fail.<path>` is set — mark it LOST and
 * return -1/errno=EIO (the recall failed; the object is gone). */
int pblock_nearline_recall(const pblock_state_t *st, const char *path);

/* Row maintenance at namespace boundaries: residency follows the logical path
 * (a rename moves it; an unlink/overwrite discards it — new content is ONLINE
 * by absence). Best-effort: errors are swallowed (simulation bookkeeping must
 * never fail the namespace op). */
void pblock_nearline_rename(const pblock_state_t *st, const char *src,
                            const char *dst);
void pblock_nearline_drop(const pblock_state_t *st, const char *path);

#endif /* BRIX_FS_BACKEND_PBLOCK_NEARLINE_H */
