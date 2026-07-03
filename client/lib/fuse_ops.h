/*
 * fuse_ops.h — pooled metadata-op runner + op thunks shared by the FUSE drivers.
 *
 * WHAT: A small library of "run one metadata op on a connection from the pool"
 *       primitives.  brix_fuse_run() checks a conn out of the pool, invokes an
 *       op thunk, checks it back in (marking the slot healthy/unhealthy from the
 *       fault class), and maps the result to a FUSE-style negative errno.  The
 *       op thunks (brix_fuse_op_*) each wrap one brix_* metadata call with a
 *       typed ctx struct so they share the one runner.
 * WHY:  Both FUSE drivers — xrootdfs.c (resilient/async) and xrootdfs_legacy.c
 *       (simple/synchronous) — performed the identical checkout → op → checkin →
 *       errno-map dance for every metadata op, differing only in whether they
 *       retried transient faults.  Folding that into one parameterised runner
 *       (max_retries==0 == the legacy single-shot path, >0 == the async retry+
 *       backoff path) removes the duplication without changing either driver's
 *       behaviour, and gives both the same canonical op thunks.
 * HOW:  No fuse3 dependency — this operates purely on brix_conn/brix_pool, so it
 *       lives in the general client lib.  A driver builds a typed ctx, then calls
 *       brix_fuse_run(pool, retries, brix_fuse_op_X, &ctx, &st); on non-zero it
 *       gets a ready-to-return negative errno.
 */
#ifndef XRDC_FUSE_OPS_H
#define XRDC_FUSE_OPS_H

#include "brix.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* An op thunk runs one metadata operation against a checked-out connection. */
typedef int (*brix_fuse_op_fn)(brix_conn *c, void *ctx, brix_status *st);

/* Map an brix_status to a negative errno (FUSE convention). Never returns 0:
 * an unmapped fault becomes -EIO. */
int brix_fuse_errno(const brix_status *st);

/* A connection is reusable after a fault unless the fault was at the socket or
 * protocol layer (those tell the pool to drop + reconnect the slot). */
int brix_fuse_conn_healthy(const brix_status *st);

/*
 * Run `op` on a connection borrowed from `pool`.
 * Retry budget (mirrors the data-plane mfile path so metadata is as resilient
 * as read/write on a lossy link):
 *   max_stall_ms > 0 → DEADLINE-bounded: retry TRANSIENT faults (socket/protocol)
 *                      with exponential backoff + jitter, reconnecting the dropped
 *                      slot, until the op succeeds or the patience window elapses
 *                      (NOT a fixed count — a flapping link is ridden out as long
 *                      as progress is possible). max_retries is ignored.
 *   max_stall_ms == 0 → legacy COUNT bound: max_retries == 0 is a single attempt
 *                      (the simple driver), max_retries > 0 retries that many times.
 *
 * benign_errno (idempotency normalization for re-issued MUTATIONS): when > 0 and
 * a RETRY (not the first attempt) fails with this POSIX errno, treat it as
 * success — the first attempt's change was already applied and its reply was lost
 * to the sever (EEXIST for mkdir/symlink/link, ENOENT for rm/rmdir/mv). Pass 0
 * for read-only / naturally-idempotent ops (chmod/truncate/setattr).
 *
 * Fatal faults (NotFound, NotAuthorized, …) return immediately.  Returns 0 on
 * success or a negative errno ready to hand back to FUSE.
 */
int brix_fuse_run(brix_pool *pool, int max_retries, int max_stall_ms,
                  int benign_errno, brix_fuse_op_fn op, void *ctx,
                  brix_status *st);

/* ---- typed ctx structs for the standard metadata ops -------------------- */
struct brix_fuse_ctx_stat  { const char *path; brix_statinfo *si; };
struct brix_fuse_ctx_dir   { const char *path; brix_dirent **ents; size_t *n; };
struct brix_fuse_ctx_mkdir { const char *path; int mode; };
struct brix_fuse_ctx_mv    { const char *from; const char *to; };
struct brix_fuse_ctx_chmod { const char *path; int mode; };
struct brix_fuse_ctx_trunc { const char *path; int64_t size; };
struct brix_fuse_ctx_setattr {
    const char     *path;
    int             set_times;
    struct timespec times[2];
    int             set_owner;
    uint32_t        uid, gid;
};
struct brix_fuse_ctx_link2 { const char *a; const char *b; };

/* ---- op thunks (ctx type noted) ----------------------------------------- */
int brix_fuse_op_stat(brix_conn *c, void *ctx, brix_status *st);     /* ctx_stat: follow-stat */
int brix_fuse_op_lstat(brix_conn *c, void *ctx, brix_status *st);    /* ctx_stat: no-follow */
int brix_fuse_op_dirlist(brix_conn *c, void *ctx, brix_status *st);  /* ctx_dir */
int brix_fuse_op_mkdir(brix_conn *c, void *ctx, brix_status *st);    /* ctx_mkdir */
int brix_fuse_op_rm(brix_conn *c, void *ctx, brix_status *st);       /* ctx = const char * path */
int brix_fuse_op_rmdir(brix_conn *c, void *ctx, brix_status *st);    /* ctx = const char * path */
int brix_fuse_op_mv(brix_conn *c, void *ctx, brix_status *st);       /* ctx_mv */
int brix_fuse_op_chmod(brix_conn *c, void *ctx, brix_status *st);    /* ctx_chmod */
int brix_fuse_op_trunc(brix_conn *c, void *ctx, brix_status *st);    /* ctx_trunc */
int brix_fuse_op_setattr(brix_conn *c, void *ctx, brix_status *st);  /* ctx_setattr */
int brix_fuse_op_symlink(brix_conn *c, void *ctx, brix_status *st);  /* ctx_link2: a=target b=link */
int brix_fuse_op_link(brix_conn *c, void *ctx, brix_status *st);     /* ctx_link2: a=old b=new */

#endif /* XRDC_FUSE_OPS_H */
