/*
 * pblock_fault.h — Phase-83 fault injection (F1) + I/O shaping (F8) for pblock.
 *
 * WHAT: The instance-level lab rule cache and the per-open snapshot the hot byte
 *       path evaluates. Rules live as rows in the catalog ctl table
 *       (pblock_ctl.h); this module resolves them into a plain-struct snapshot at
 *       open (a metadata boundary) and evaluates that snapshot — a pure function
 *       over counters, no SQLite, no locks — on every pread/pwrite.
 *
 *       Wave-A rule grammar (ctl value strings):
 *         fault.pread  / fault.pwrite = "errno=EIO [after_bytes=N] | short=N"
 *         shape.read_bps / shape.write_bps = <bytes/sec>   (nanosleep paced)
 *         shape.open_ms                    = <ms>          (delay at open)
 *
 * WHY:  The doc's hard bar is hot-path purity: with lab OFF the driver stores a
 *       NULL lab pointer and the byte path never calls in here. With lab ON, a
 *       set fault only affects handles opened AFTER it was set — the snapshot is
 *       taken once at open, so already-open handles are unaffected (documented
 *       consequence of the epoch model).
 *
 * HOW:  ngx-free (libc + sqlite3 via pblock_ctl). The instance cache re-reads
 *       ctl only when MAX(epoch) advances; the per-open snapshot is a malloc'd
 *       value copy. Gated by BRIX_HAVE_SQLITE.
 *
 * Requires: sd_pblock_catalog.h (pblock_catalog) before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_FAULT_H
#define BRIX_FS_BACKEND_PBLOCK_FAULT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "sd_pblock_catalog.h"

/* One resolved read-or-write rule. All-zero/-1 fields ⇒ inert. */
typedef struct {
    int      inj_errno;    /* errno to inject, or 0 for none                    */
    int64_t  after_bytes;  /* -1: inject immediately; else once cumulative >=   */
    int      short_to;     /* -1: none; else clamp the op to this many bytes    */
    int64_t  rate_bps;     /* 0: unlimited; else nanosleep-pace to bytes/sec    */
} pblock_rule_t;

typedef struct pblock_lab_state pblock_lab_state_t;   /* instance-level cache   */

/* Per-open snapshot: resolved rules + running counters. NULL ⇒ nothing to do. */
typedef struct {
    pblock_rule_t r;         /* read rule  */
    pblock_rule_t w;         /* write rule */
    int64_t       rbytes;    /* cumulative bytes read through this handle       */
    int64_t       wbytes;    /* cumulative bytes written through this handle    */
} pblock_lab_obj_t;

/* Build the instance lab cache. Returns NULL on OOM (caller treats as lab-off). */
pblock_lab_state_t *pblock_lab_state_create(pblock_catalog *cat);
void                pblock_lab_state_destroy(pblock_lab_state_t *ls);

/* Take a per-open snapshot. Re-reads ctl iff the control epoch advanced. Applies
 * the F8 open delay (shape.open_ms) inline. Returns a malloc'd snapshot, or NULL
 * when no rule currently applies (hot path stays NULL-gated) or on OOM. */
pblock_lab_obj_t *pblock_lab_snapshot(pblock_lab_state_t *ls, const char *path);
void              pblock_lab_obj_free(pblock_lab_obj_t *lo);

/* Hot-path gate. is_write selects the rule; *len (requested length) may be
 * reduced (short op). Applies F8 pacing, then evaluates F1. Returns 0 to
 * proceed, or a positive errno to fail the op with. */
int pblock_lab_io_gate(pblock_lab_obj_t *lo, int is_write, size_t *len, off_t off);

/* F7 crash points. If ls is non-NULL (lab on) and the ctl `crash.at` value
 * equals `point`, the worker dies immediately with _exit(PBLOCK_CRASH_EXIT) to
 * simulate a mid-operation power loss (nginx master respawns it). No-op when ls
 * is NULL (gate off) or no crash point is armed. Compiled-in points are the
 * named durability boundaries: after_block_write, before_catalog_update,
 * after_catalog_update, mid_staged_commit, before_unlink_row. */
#define PBLOCK_CRASH_EXIT 86
void pblock_lab_crash(pblock_lab_state_t *ls, const char *point);

#endif /* BRIX_FS_BACKEND_PBLOCK_FAULT_H */
