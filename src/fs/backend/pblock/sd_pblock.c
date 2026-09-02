/*
 * sd_pblock.c — the pblock ("pseudo-block") Storage Driver: a full-capability,
 * block-based drop-in for POSIX.
 *
 * WHAT: Implements brix_sd_pblock_driver, a complete backend that stores each
 *       object's bytes striped across fixed-size POSIX "block" files and the
 *       entire logical namespace + metadata in a SQLite catalog
 *       (sd_pblock_catalog.c). It advertises the same capabilities as the POSIX
 *       driver and implements every vtable slot. This file owns the instance and
 *       object lifecycle (init/cleanup, open/close and their helpers) and the
 *       driver descriptor; the byte I/O (sd_pblock_io.c), namespace/directory/
 *       xattr ops (sd_pblock_namespace.c) and staged atomic publish
 *       (sd_pblock_staged.c) live in siblings reached through
 *       sd_pblock_internal.h.
 *
 * WHY:  Striping bulk content into fixed-size blocks (default 64 MiB, set per
 *       file at creation and configurable per export) is the defining property
 *       of a block backend, and splitting that content from the namespace/
 *       metadata keeps the hot byte path free of any database work. SQLite is
 *       touched only at metadata boundaries. Split from a single 1111-line file
 *       (phase-79) to hold every pblock file under the ~500-line, one-concept cap.
 *
 * HOW:  An object's bytes live at <data>/<aa>/<bb>/<blob_id>/<block_index>;
 *       block 0 is opened persistently as obj->fd (so small files keep a real
 *       fd for zero-copy sendfile), and higher blocks are opened transiently per
 *       I/O. Reads/writes map [off,off+len) across blocks (holes read as zeros);
 *       writes update the cached size/mtime in memory and flush to the catalog
 *       on fsync/close. The whole file is ngx-free (libc + sqlite, malloc-owned
 *       state) so it is identical in the module and the standalone unit test.
 *       Compiled only when the build found libsqlite3 (BRIX_HAVE_SQLITE).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* preadv2(2) (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "sd_pblock_internal.h"  /* shared obj state + split-out vtable slots */
#include "pblock_ctl.h"          /* Phase-83 lab control plane (opts + ctl table) */
#include "pblock_fault.h"        /* Phase-83 fault injection + I/O shaping */
#include "pblock_csi.h"          /* Phase-83 F3 per-block CRC32c integrity */
#include "pblock_quota.h"        /* Phase-83 F5 quotas + space accounting */
#include "pblock_nearline.h"     /* Phase-83 F4 nearline/tape simulation */
#include "pblock_anomaly.h"      /* Phase-83 F9 consistency anomalies */
#include "pblock_locks.h"        /* Phase-83 F15 mandatory lease enforcement */
#include "pblock_refs.h"         /* Phase-83 F10 refcounted blobs + dedup */
#include "pblock_snap.h"         /* Phase-83 F6 snapshots / fixture reset */
#include "pblock_hist.h"         /* Phase-83 F11 versioning + trash/undelete */
#include "core/compat/wverify.h" /* F10 whole-object CRC accumulator */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

/* The per-open object state (pblock_obj_t), the directory/staged state structs
 * and the split-out vtable-slot prototypes live in sd_pblock_internal.h. The
 * instance init/cleanup lifecycle and its arm helpers live in
 * sd_pblock_lifecycle.c; the object open/close lifecycle lives in
 * sd_pblock_open.c. This file keeps the catalog enumeration, space/nearline
 * slots and the driver descriptor that binds every slot together. */

/* ---- catalog enumeration (F14) -------------------------------------------- */

/* Adapter from the catalog's flat row callback to the driver's enumerate cb. */
typedef struct {
    brix_sd_catalog_cb cb;
    void              *ctx;
    int                want_stat;
} pblock_enum_ctx_t;

static int
pblock_enum_thunk(void *vctx, const char *path, int is_dir, int64_t size,
    int64_t mtime)
{
    pblock_enum_ctx_t     *ec = vctx;
    brix_sd_catalog_ent_t  ent;

    if (is_dir) {
        return 0;   /* enumerate reports stored objects, not directories */
    }
    memset(&ent, 0, sizeof(ent));
    ent.key       = path;    /* the catalog IS the namespace: key == logical path */
    ent.path      = path;
    ent.have_stat = ec->want_stat;
    ent.size      = (off_t) size;
    ent.mtime     = (time_t) mtime;
    return ec->cb(ec->ctx, &ent);
}

/* driver->enumerate — flat scan of every stored object (NGX_OK, or NGX_ERROR
 * with errno on a catalog error). Advertised via BRIX_SD_CAP_CATALOG. */
static ngx_int_t
sd_pblock_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    pblock_state_t    *st = inst->state;
    pblock_enum_ctx_t  ec;

    if (st == NULL || cb == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    ec.cb = cb;
    ec.ctx = ctx;
    ec.want_stat = want_stat;
    if (pblock_catalog_enumerate(st->cat, pblock_enum_thunk, &ec) != 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- space accounting (F5) ------------------------------------------------ */

/* driver->space — quota-aware capacity numbers for kXR_statvfs/SRR. Answers
 * only when a byte quota is armed (then total = the quota, used = the usage
 * rollup); otherwise NGX_ERROR/ENOTSUP so callers fall back to statvfs(2) on
 * the backing filesystem — byte-for-byte the pre-F5 behaviour. */
static ngx_int_t
sd_pblock_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    pblock_state_t *st = inst->state;
    int64_t         bytes, inodes;

    if (st == NULL || !st->quota || st->quota_bytes <= 0) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (pblock_quota_usage(st, "total", 0, &bytes, &inodes) != 0) {
        return NGX_ERROR;
    }
    out->total_bytes = (uint64_t) st->quota_bytes;
    out->used_bytes  = bytes > 0 ? (uint64_t) bytes : 0;
    out->free_bytes  = bytes < st->quota_bytes
                           ? (uint64_t) (st->quota_bytes - bytes) : 0;
    return NGX_OK;
}

/* ---- nearline simulation (F4) --------------------------------------------- */

/* driver->residency — pure read of the simulated tape-residency model. Only
 * reached when CAP_NEARLINE is advertised (nearline=1 armed); never initiates
 * or advances a recall — protocol handlers (kXR stat's offline flag, the tape
 * REST API, S3 storage-class) classify without staging side effects. */
static ngx_int_t
sd_pblock_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out)
{
    pblock_state_t *st = inst->state;
    int             rc;

    if (st == NULL || !st->nearline) {
        *out = BRIX_SD_RES_ONLINE;
        return NGX_OK;
    }
    rc = pblock_catalog_lookup(st->cat, key, NULL);
    if (rc != 0) {
        errno = rc == 1 ? ENOENT : errno;
        return NGX_ERROR;
    }
    return pblock_nearline_res(st, key, out) == 0 ? NGX_OK : NGX_ERROR;
}

/* driver->recall — the cache tier's recall-at-fill entry (phase-64 §9.3).
 * Synchronous like sd_frm's (no parking handle to mint): by return the object
 * is either ONLINE (NGX_OK — a normal fill follows) or the recall failed
 * (NGX_ERROR, errno set). The simulated latency/outcome are ctl-driven
 * (pblock_nearline.h). */
ngx_int_t
sd_pblock_recall(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40])
{
    pblock_state_t *st = inst->state;
    int             rc;

    reqid_out[0] = '\0';
    if (st == NULL || !st->nearline) {
        return NGX_OK;
    }
    rc = pblock_catalog_lookup(st->cat, key, NULL);
    if (rc != 0) {
        errno = rc == 1 ? ENOENT : errno;
        return NGX_ERROR;
    }
    return pblock_nearline_recall(st, key) == 0 ? NGX_OK : NGX_ERROR;
}

/* driver->evict (phase-107 C2) — release the simulated online copy: demote the
 * residency row to NEARLINE (the simulated tape copy survives; a later recall
 * restages it — the exact inverse of sd_pblock_recall). ENOTSUP when the
 * export is not armed nearline: without a tape model the block store's copy is
 * the ONLY copy and evicting it would be a delete wearing a different verb
 * (the sd.h contract). Reports the object's catalog size as the bytes
 * released — the logical online footprint the simulation just gave up (no
 * physical block moves; this is bookkeeping, exactly like the recall's sleep).
 * The *_cred twin gates W_OK against catalog ownership and delegates here
 * (sd_pblock_cred.c) — pblock is its own multi-user authority, unlike frm's
 * service-only MSS adapter. */
ngx_int_t
sd_pblock_evict(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;
    int             rc;

    if (bytes_out != NULL) {
        *bytes_out = 0;
    }
    if (st == NULL || !st->nearline) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc != 0) {
        errno = rc == 1 ? ENOENT : errno;
        return NGX_ERROR;
    }
    if (meta.is_dir) {
        errno = EISDIR;
        return NGX_ERROR;
    }
    if (pblock_nearline_evict(st, path) != 0) {
        return NGX_ERROR;               /* errno set (ENOENT lost / EIO) */
    }
    if (bytes_out != NULL && meta.size > 0) {
        *bytes_out = (uint64_t) meta.size;
    }
    return NGX_OK;
}

/* ---- commit-time dedup (phase-88 W1) -------------------------------------- */

/* sd_pblock_dedup_publish — driver->dedup_publish for pblock.
 *
 * WHAT: Collapse the (content-verified) object at `path` onto a byte-identical
 *       existing blob via the F10 refs machinery. The canonical alias `canon`
 *       is ignored: pblock's blobs table already carries content identity, so
 *       no extra namespace entry is needed and eviction is refcount-driven
 *       (driver->dedup_gc is NULL). NGX_OK on fold/keep, NGX_ERROR with
 *       ENOTSUP when the export has no refs gate (opts dedup=1), else the
 *       fold's errno.
 *
 * WHY:  Serving brix_cache_global_cas from a pblock cache store — the posix
 *       hardlink farm has no meaning here, but refcounted-blob dedup gives the
 *       same one-copy-per-content guarantee with byte-verified folds.
 *
 * HOW:  1. Gate on st->refs.  2. pblock_refs_dedup_existing re-nominates the
 *       committed blob by its recorded content hash and folds when a candidate
 *       byte-verifies.
 */
static ngx_int_t
sd_pblock_dedup_publish(brix_sd_instance_t *inst, const char *path,
    const char *canon)
{
    pblock_state_t *st = inst->state;

    (void) canon;
    if (st == NULL || !st->refs) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return pblock_refs_dedup_existing(st, path) < 0 ? NGX_ERROR : NGX_OK;
}

/* ---- the driver descriptor ------------------------------------------------ */

/* Atomic two-name exchange (phase-107 C6): one catalog transaction swaps both
 * subtrees (pblock_catalog_exchange), so a concurrent reader never sees either
 * name absent. Lives here rather than sd_pblock_namespace.c because that file
 * sits at the 600-line cap. Side tables (nearline residency, anomaly history,
 * lease rows) swap post-commit through the catalog's reserved temp name —
 * exact-path, best-effort, the same discipline pblock_rename_observe applies
 * after pblock_catalog_rename. Lease checks come first, like rename. */
ngx_int_t
sd_pblock_exchange(brix_sd_instance_t *inst, const char *a, const char *b)
{
    static const char tmp[] = "/\001brix-xchg\001";
    pblock_state_t   *st = inst->state;
    ngx_int_t         rc;

    if (st->locks
        && (pblock_locks_ns_check(st, a, 0) != 0
            || pblock_locks_ns_check(st, b, 0) != 0))
    {
        return NGX_ERROR;
    }

    rc = pblock_catalog_exchange(st->cat, a, b) == 0 ? NGX_OK : NGX_ERROR;
    if (rc == NGX_OK) {
        if (st->nearline) {
            pblock_nearline_rename(st, a, tmp);
            pblock_nearline_rename(st, b, a);
            pblock_nearline_rename(st, tmp, b);
        }
        if (st->lab != NULL) {
            pblock_anomaly_rename(st, a, tmp);
            pblock_anomaly_rename(st, b, a);
            pblock_anomaly_rename(st, tmp, b);
        }
        if (st->locks) {
            pblock_locks_rename(st, a, tmp);
            pblock_locks_rename(st, b, a);
            pblock_locks_rename(st, tmp, b);
        }
    }
    if (st->audit) {
        pblock_audit_log(st->cat, "exchange", a, b, 0, 0,
                         rc == NGX_OK ? 0 : -1, rc == NGX_OK ? 0 : errno);
    }
    return rc;
}

/* Full POSIX-parity capabilities: block 0 is a real kernel file, so the backend
 * is fd-backed, sendfile-able and io_uring-submittable; the catalog provides
 * atomic rename, real directories, server copy and object xattrs. */
const brix_sd_driver_t brix_sd_pblock_driver = {
    .name = "pblock",
    /* pblock consumes the request IDENTITY (principal + VO list): the catalog
     * is its own identity registry, and the *_cred slots below enforce POSIX
     * mode bits against the catalog-internal synthetic uid/gids. */
    .cred_accept = BRIX_SD_CRED_IDENTITY,
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_SENDFILE
          | BRIX_SD_CAP_RANDOM_WRITE | BRIX_SD_CAP_RANGE_READ
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_APPEND
          | BRIX_SD_CAP_IOURING | BRIX_SD_CAP_SERVER_COPY
          | BRIX_SD_CAP_XATTR | BRIX_SD_CAP_XATTR_WRITE
          | BRIX_SD_CAP_HARD_RENAME
          /* C6: ABSENT + MATCH_* atomic — one BEGIN IMMEDIATE spans the
           * compare and the publishing catalog_put (sd_pblock_staged.c). */
          | BRIX_SD_CAP_PRECOND
          | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE
          | BRIX_SD_CAP_CATALOG,   /* F14: native object enumeration */

    .init    = sd_pblock_init,
    .cleanup = sd_pblock_cleanup,
    .open    = sd_pblock_open,
    .close   = sd_pblock_close,

    .pread            = sd_pblock_pread,
    .pwrite           = sd_pblock_pwrite,
    .preadv           = sd_pblock_preadv,
    .preadv2          = sd_pblock_preadv2,
    .copy_range       = sd_pblock_copy_range,
    .read_sendfile_fd = sd_pblock_read_sendfile_fd,
    .read_advise      = sd_pblock_read_advise,
    .ftruncate        = sd_pblock_ftruncate,
    .reserve          = sd_pblock_reserve,   /* phase-107 C5 quota+space admit */
    .fsync            = sd_pblock_fsync,
    .fstat            = sd_pblock_fstat,

    .stat        = sd_pblock_stat,
    .unlink      = sd_pblock_unlink,
    /* C4: one SQLite transaction per window; no CAP_BULK_DELETE - the win is
     * commit count, not round trips, so only the flat client batch
     * (brix_vfs_delete_many) reaches it wide. */
    .unlink_many = sd_pblock_unlink_many,
    .mkdir       = sd_pblock_mkdir,
    .rename      = sd_pblock_rename,
    .sync_publish = sd_pblock_sync_publish, /* phase-107 C3: catalog-dir flush */
    .exchange    = sd_pblock_exchange,      /* C6: one catalog transaction */
    .server_copy = sd_pblock_server_copy,
    .setattr     = sd_pblock_setattr,

    .opendir  = sd_pblock_opendir,
    .readdir  = sd_pblock_readdir,
    .closedir = sd_pblock_closedir,

    .enumerate = sd_pblock_enumerate,
    .space     = sd_pblock_space,        /* F5: quota-aware capacity */
    .recall    = sd_pblock_recall,       /* F4: simulated tape recall */
    .recall_cred = sd_pblock_recall_cred, /* C2: R-gated twin */
    .residency = sd_pblock_residency,    /* F4: simulated residency model */
    .evict     = sd_pblock_evict,        /* C2: demote the row to NEARLINE */
    .evict_cred = sd_pblock_evict_cred,  /* C2: W-gated twin */

    .getxattr    = sd_pblock_getxattr,
    .listxattr   = sd_pblock_listxattr,
    .setxattr    = sd_pblock_setxattr,
    .removexattr = sd_pblock_removexattr,

    .staged_open   = sd_pblock_staged_open,
    .staged_write  = sd_pblock_staged_write,
    .staged_commit = sd_pblock_staged_commit,
    .staged_abort  = sd_pblock_staged_abort,
    .staged_path   = sd_pblock_staged_path,   /* phase-88 W1: single-block
                                               * fills verify like a .part */
    .dedup_publish = sd_pblock_dedup_publish, /* phase-88 W1: refs-based G13;
                                               * dedup_gc stays NULL — eviction
                                               * is refcount-driven */

    /* identity-enforcing slots (sd_pblock_cred.c): POSIX mode-bit checks
     * against catalog ownership when the request carries an identity;
     * identity-less requests fall through to service semantics. */
    .open_cred        = sd_pblock_open_cred,
    .staged_open_cred = sd_pblock_staged_open_cred,
    .stat_cred        = sd_pblock_stat_cred,
    .unlink_cred      = sd_pblock_unlink_cred,
    .unlink_many_cred = sd_pblock_unlink_many_cred,   /* C4: gate per key, one txn */
    .mkdir_cred       = sd_pblock_mkdir_cred,
    .rename_cred      = sd_pblock_rename_cred,
    .exchange_cred    = sd_pblock_exchange_cred,      /* C6: remove-gate both */
    .setattr_cred     = sd_pblock_setattr_cred,
    .getxattr_cred    = sd_pblock_getxattr_cred,
    .listxattr_cred   = sd_pblock_listxattr_cred,
    .setxattr_cred    = sd_pblock_setxattr_cred,
    .removexattr_cred = sd_pblock_removexattr_cred,
    .server_copy_cred = sd_pblock_server_copy_cred,
    .opendir_cred     = sd_pblock_opendir_cred,
};

#endif /* BRIX_HAVE_SQLITE */
