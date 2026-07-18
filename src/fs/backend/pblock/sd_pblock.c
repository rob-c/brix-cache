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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

/* The per-open object state (pblock_obj_t), the directory/staged state structs
 * and the split-out vtable-slot prototypes live in sd_pblock_internal.h; this
 * file keeps the instance + object lifecycle and the driver descriptor. */

/* ---- instance lifecycle --------------------------------------------------- */

static ngx_int_t
sd_pblock_init(brix_sd_instance_t *inst, void *driver_conf)
{
    const brix_sd_pblock_conf_t *conf = driver_conf;
    pblock_state_t                *st;
    char                           db[PATH_MAX];

    if (conf == NULL || conf->root == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    st = calloc(1, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    snprintf(st->root, sizeof(st->root), "%s", conf->root);
    snprintf(st->data_dir, sizeof(st->data_dir), "%s/data", conf->root);
    st->block_size = conf->block_size > 0 ? conf->block_size
                                          : PBLOCK_DEFAULT_BLOCK_SIZE;

    if (pblock_mkdir_p(st->root) != 0 || pblock_mkdir_p(st->data_dir) != 0) {
        int err = errno;

        free(st);
        errno = err;
        return NGX_ERROR;
    }

    snprintf(db, sizeof(db), "%s/catalog.db", conf->root);
    st->cat = pblock_catalog_open(db, conf->busy_timeout_ms);
    if (st->cat == NULL) {
        int err = errno;

        free(st);
        errno = err;
        return NGX_ERROR;
    }

    /* Phase-83 lab control plane. The static opts sidecar (<root>/pblock.opts,
     * written by the config finaliser when it strips a `?tail` off a pblock://
     * root) selects the fail-closed master gate and the caps/mem knobs. With
     * lab OFF (the default — no sidecar) the driver stays byte-for-byte the
     * production backend: st->lab is NULL and the hot path never consults it. */
    {
        pblock_opts_t opts;

        (void) pblock_opts_load_sidecar(st->root, &opts);   /* absent ⇒ all-zero */

        if (opts.mem) {                                      /* F16 */
            (void) pblock_ctl_mem_pragmas(st->cat);
        }
        if (opts.lab) {
            inst->caps = pblock_caps_apply(inst->caps, &opts);   /* F2 */
            st->lab = pblock_lab_state_create(st->cat);          /* F1/F8 */
            if (st->lab != NULL) {
                /* F9 rides the lab master gate (an anomaly simulator is a lab
                 * toy by definition). Best-effort: with no `recent` table the
                 * event writers no-op and consultation finds nothing. */
                (void) pblock_anomaly_init(st);
            }
        }
        if (opts.audit) {                                    /* F17 */
            /* Independent of the lab gate (its own opt): only turn audit on if
             * the oplog table is actually present, so a create failure leaves
             * the driver in the byte-for-byte production path (audit off). */
            st->audit = (pblock_audit_init(st->cat) == 0);
        }
        if (opts.csi) {                                      /* F3 */
            /* Its own opt (integrity, not a lab toy). Advertise CAP_FSCS only
             * when the csi table is actually present — an honest per-instance
             * capability the driver will really honour. */
            if (pblock_csi_init(st->cat) == 0) {
                st->csi = 1;
                inst->caps |= BRIX_SD_CAP_FSCS;
            }
        }
        if (opts.nearline) {                                 /* F4 */
            /* Its own opt: advertise CAP_NEARLINE only when the residency
             * table actually installed — an honest per-instance capability
             * (the residency seam and the cache tier's recall-at-fill key off
             * it). Init failure ⇒ production driver, no nearline claims. */
            if (pblock_nearline_init(st) == 0) {
                st->nearline = 1;
                inst->caps |= BRIX_SD_CAP_NEARLINE;
            }
        }
        if (opts.locks) {                                    /* F15 */
            /* Its own opt: mandatory lease enforcement only arms when the
             * locks table actually installed — an init failure leaves the
             * byte-for-byte production path (no lease reads anywhere). */
            st->locks = (pblock_locks_init(st) == 0);
        }
        if (opts.dedup) {                                    /* F10 */
            /* Its own opt: refcounted blobs + dedup only arm when the blobs
             * table actually installed — an init failure leaves the
             * byte-for-byte production path (no refcount reads anywhere). */
            st->refs = (pblock_refs_init(st) == 0);
        }
        if (opts.snapshots) {                                /* F6 */
            /* Snapshots build ON refcounted blobs (F10): a delete between take
             * and restore must decrement a shared blob, never physically remove
             * it. Arm refs first (idempotent), then the snapshot tables — armed
             * only when both installed, else the production path is untouched. */
            if (!st->refs) {
                st->refs = (pblock_refs_init(st) == 0);
            }
            if (st->refs && pblock_snap_init(st) == 0) {
                st->snap = 1;
            }
        }
        if (opts.versions > 0 || opts.trash) {               /* F11 */
            /* Versioning and trash both HOLD prior blobs (an overwrite/unlink
             * decrements a shared blob instead of freeing it), so they build ON
             * refcounted blobs (F10) exactly like snapshots. Arm refs first
             * (idempotent), then the history tables — armed only when both
             * installed, else the byte-for-byte production path is untouched. */
            if (!st->refs) {
                st->refs = (pblock_refs_init(st) == 0);
            }
            if (st->refs && pblock_hist_init(st) == 0) {
                st->versions = opts.versions;
                st->trash    = opts.trash;
            }
        }
        if (opts.xform_len > 0) {                            /* F12/F13 */
            /* Per-block transform. Unlike the lab toys this is a hard config
             * gate: a bad spec (unknown transform, unreadable crypt keyfile,
             * `zstd` without libzstd) fails instance init fail-closed — the
             * pblock store is never built for the export (logged "backend init
             * failed"), rather than silently serving unreadable transformed
             * bytes as raw. A transformed export cannot hand out a block-0 fd,
             * so drop the zero-copy caps at build (per-export mask, doc §5). */
            if (pblock_xform_config(&st->xform, opts.xform, opts.xform_len)
                != 0)
            {
                int err = errno;

                pblock_catalog_close(st->cat);
                free(st);
                errno = err;
                return NGX_ERROR;
            }
            if (pblock_xform_active(&st->xform)) {
                inst->caps &= ~(uint32_t) (BRIX_SD_CAP_SENDFILE
                                           | BRIX_SD_CAP_IOURING);
            }
        }
        if (opts.quota_bytes > 0 || opts.quota_inodes > 0) {  /* F5 */
            /* Its own opt like csi/audit: quota only arms when the rollup
             * table + triggers actually installed, so an init failure leaves
             * the byte-for-byte production catalog path. */
            if (pblock_quota_init(st) == 0) {
                st->quota        = 1;
                st->quota_bytes  = opts.quota_bytes;
                st->quota_inodes = opts.quota_inodes;
            }
        }
    }

    /* The export root "/" always exists (a directory), like a POSIX mount point —
     * so stat("/")/opendir("/")/PROPFIND on the root succeed before anything is
     * written. Created once; harmless if a concurrent worker also creates it.
     * Sticky world-writable (/tmp semantics) so identity-enforced multi-user
     * exports work out of the box: anyone may create top-level entries, only
     * owners may remove them (pblock_ident_sticky_gate). Operators wanting a
     * stricter top level chmod "/" or pre-create VO directories. */
    if (pblock_catalog_lookup(st->cat, "/", NULL) == 1) {
        pblock_meta root_meta;

        memset(&root_meta, 0, sizeof(root_meta));
        root_meta.is_dir = 1;
        root_meta.mtime  = root_meta.ctime = pblock_now();
        root_meta.mode   = S_IFDIR | S_ISVTX | 0777;
        (void) pblock_catalog_put(st->cat, "/", &root_meta);
    }

    inst->state = st;
    return NGX_OK;
}

static void
sd_pblock_cleanup(brix_sd_instance_t *inst)
{
    pblock_state_t *st = inst->state;

    if (st != NULL) {
        pblock_lab_state_destroy(st->lab);
        pblock_catalog_close(st->cat);
        free(st);
        inst->state = NULL;
    }
}

/* ---- object lifecycle ----------------------------------------------------- */

/* pblock_make_obj — wrap a block-0 fd + cached metadata in a heap object. On
 * failure the fd is closed and NULL/errno returned. */
static brix_sd_obj_t *
pblock_make_obj(brix_sd_instance_t *inst, const char *path, int fd,
    const pblock_meta *meta)
{
    brix_sd_obj_t *obj;
    pblock_obj_t    *os;

    obj = calloc(1, sizeof(*obj));
    os  = calloc(1, sizeof(*os));
    if (obj == NULL || os == NULL) {
        free(obj);
        free(os);
        if (fd >= 0) {
            close(fd);
        }
        errno = ENOMEM;
        return NULL;
    }

    os->st         = inst->state;
    os->meta       = *meta;
    os->block_size = meta->block_size;
    snprintf(os->path, sizeof(os->path), "%s", path);
    snprintf(os->blob_id, sizeof(os->blob_id), "%s", meta->blob_id);

    /* Phase-83: resolve any lab fault/shape rule for this handle ONCE, at open
     * (a metadata boundary). NULL when lab is off or no rule applies — the hot
     * byte path then skips the gate entirely. */
    os->lab = pblock_lab_snapshot(os->st->lab, path);

    /* F3: snapshot the at-rest per-block CRCs ONCE at open so the hot read path
     * verifies against memory (no DB). csi_dlo/dhi is the empty written extent
     * (dlo > dhi) until the first write widens it. */
    os->csi_dlo = INT64_MAX;
    os->csi_dhi = 0;
    if (os->st->csi && !meta->is_dir) {
        int64_t nblk = meta->size > 0
            ? pblock_last_block(meta->size, os->block_size) + 1 : 0;

        (void) pblock_csi_load(os->st->cat, os->blob_id, nblk,
                               &os->csi_crc, &os->csi_n);
    }

    /* F5: snapshot how far this handle may grow the file ONCE at open (quota
     * off ⇒ INT64_MAX) — pwrite/copy_range enforce it without touching the DB. */
    os->quota_max = pblock_quota_max_size(os->st, meta->uid, meta->size);

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = fd >= 0 ? fd : NGX_INVALID_FILE;
    obj->state      = os;
    obj->heap_shell = 1;   /* malloc'd shell; a VFS adopter frees it after copy */

    /* Capture the open-time metadata snapshot the VFS reports to callers (file
     * size, mode, mtime) — without this the adopting handle would see a zeroed
     * snap and treat the file as empty (immediate EOF on read). */
    ngx_memzero(&obj->snap, sizeof(obj->snap));
    obj->snap.size   = meta->size;
    obj->snap.mtime  = meta->mtime;
    obj->snap.ctime  = meta->ctime;
    obj->snap.mode   = meta->mode;
    obj->snap.ino    = (ino_t) pblock_fnv(path);
    obj->snap.uid    = meta->uid;
    obj->snap.gid    = meta->gid;
    obj->snap.is_dir = meta->is_dir ? 1 : 0;
    obj->snap.is_reg = meta->is_dir ? 0 : 1;

    /* F6: count live regular-file handles so a snapshot restore can refuse
     * (EBUSY) rather than swap the namespace out from under an open file.
     * Balanced by the matching decrement in sd_pblock_close. */
    if (os->st->snap && !meta->is_dir) {
        __atomic_add_fetch(&os->st->open_files, 1, __ATOMIC_RELEASE);
    }
    return obj;
}

/* pblock_open_create — create a brand-new file: a fresh per-object dir + block 0,
 * plus its catalog row owned by (uid, gid) — 0/0 for the service itself.
 * Returns the object or NULL/errno (*err_out set). */
static brix_sd_obj_t *
pblock_open_create(brix_sd_instance_t *inst, const char *path, mode_t mode,
    uint32_t uid, uint32_t gid, int *err_out)
{
    pblock_state_t  *st = inst->state;
    pblock_meta      meta;
    brix_sd_obj_t *obj;
    char             block0[PATH_MAX];
    int              fd;

    if (pblock_quota_admit(st, uid, 0, 1) != 0) {            /* F5 */
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    memset(&meta, 0, sizeof(meta));
    if (pblock_gen_blob_id(meta.blob_id) != 0
        || pblock_ensure_obj_dir(st, meta.blob_id) != 0
        || pblock_block_path(st, meta.blob_id, 0, block0, sizeof(block0)) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    fd = open(block0, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    meta.is_dir     = 0;
    meta.size       = 0;
    meta.block_size = st->block_size;
    meta.mtime      = meta.ctime = pblock_now();
    meta.mode       = S_IFREG | (mode & 0777);
    meta.uid        = uid;
    meta.gid        = gid;
    snprintf(meta.xform, sizeof(meta.xform), "%s",   /* F12/F13: record kind */
             pblock_xform_name(st->xform.kind));

    if (pblock_catalog_put(st->cat, path, &meta) != 0) {
        int err = errno;

        close(fd);
        pblock_remove_blocks(st, meta.blob_id, 0, st->block_size);
        if (err_out != NULL) { *err_out = err; }
        return NULL;
    }

    obj = pblock_make_obj(inst, path, fd, &meta);
    if (obj == NULL && err_out != NULL) {
        *err_out = errno;
    }
    if (obj != NULL && st->refs) {                            /* F10 */
        (void) pblock_refs_track(st, meta.blob_id, 0, meta.block_size, 0, 0);
        ((pblock_obj_t *) obj->state)->wv = brix_wverify_begin();
    }
    return obj;
}

/* pblock_open_existing — open an existing file's block 0; honours O_TRUNC on
 * write via the block-aware truncate. Returns the object or NULL/errno. */
static brix_sd_obj_t *
pblock_open_existing(brix_sd_instance_t *inst, const char *path,
    pblock_meta *meta, int sd_flags, int *err_out)
{
    pblock_state_t  *st = inst->state;
    brix_sd_obj_t *obj;
    char             block0[PATH_MAX];
    int              want_write = sd_flags & BRIX_SD_O_WRITE;
    int              fd;

    /* F12/F13: refuse to serve a file whose recorded transform does not match the
     * export's configured one (wrong key/codec ⇒ garbage). A config error, not a
     * data error — fail the open rather than hand back undecodable bytes. */
    if (pblock_xform_kind_from_name(meta->xform) != st->xform.kind) {
        if (err_out != NULL) { *err_out = EIO; }
        return NULL;
    }

    /* F10: never write through a shared blob — a write-intent open first gives
     * this object a private copy (empty on O_TRUNC: the bytes are doomed). */
    if (st->refs && want_write
        && pblock_refs_break_share(st, path, meta,
                                   (sd_flags & BRIX_SD_O_TRUNC) != 0) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    if (pblock_block_path(st, meta->blob_id, 0, block0, sizeof(block0)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    fd = open(block0, want_write ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    obj = pblock_make_obj(inst, path, fd, meta);
    if (obj == NULL) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    if (want_write && (sd_flags & BRIX_SD_O_TRUNC) && meta->size > 0) {
        if (sd_pblock_ftruncate(obj, 0) != NGX_OK) {
            int err = errno;

            obj->driver->close(obj);   /* frees state + closes fd */
            free(obj);                 /* … and the malloc'd shell */
            if (err_out != NULL) { *err_out = err; }
            return NULL;
        }
    }
    if (st->refs && want_write && (sd_flags & BRIX_SD_O_TRUNC)) {
        /* F10: content is being rewritten from scratch — this handle can grow
         * an honest whole-object CRC, making the blob a dedup candidate. */
        ((pblock_obj_t *) obj->state)->wv = brix_wverify_begin();
    }
    return obj;
}

/* sd_pblock_open_as — the open implementation, parameterized by the owner
 * (uid, gid) recorded on a CREATE. The plain vtable slot passes 0/0 (the
 * service); the identity-aware open_cred slot (sd_pblock_cred.c) passes the
 * requester's resolved catalog ids so new files are owned by their creator. */
static brix_sd_obj_t *
pblock_open_as_inner(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, uint32_t uid, uint32_t gid, int *err_out)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    /* F15: mandatory lease gate — before both branches, since a whole-file
     * lease guards the *name* (a create under a foreign lease is as much a
     * conflicting write as an overwrite). Live foreign 'X' refuses everyone;
     * a live foreign whole-file 'W' refuses write-intent opens. EBUSY maps
     * to kXR_FileLocked / HTTP 423 at the protocol edge. */
    if (st->locks
        && pblock_locks_open_check(st, path,
               (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                            | BRIX_SD_O_TRUNC | BRIX_SD_O_APPEND)) != 0,
               uid) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    if (rc == 0 && meta.is_dir) {
        if (sd_flags & BRIX_SD_O_WRITE) {
            if (err_out != NULL) { *err_out = EISDIR; }
            return NULL;
        }
        return pblock_make_obj(inst, path, NGX_INVALID_FILE, &meta);
    }

    if (rc == 0) {   /* existing file */
        /* F9: visibility lag — a freshly created path is ENOENT to other
         * readers for the armed window. Write-intent opens are exempt: the
         * writer/overwriter lane must never see its own phantom ENOENT (the
         * S3 session monotonic-read guarantee — a handle that wrote reads
         * through its own open snapshot and is untouched by design). */
        if (st->lab != NULL
            && !(sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                             | BRIX_SD_O_TRUNC))
            && pblock_anomaly_hidden(st, path))
        {
            if (err_out != NULL) { *err_out = ENOENT; }
            return NULL;
        }
        if ((sd_flags & BRIX_SD_O_CREATE) && (sd_flags & BRIX_SD_O_EXCL)) {
            if (err_out != NULL) { *err_out = EEXIST; }
            return NULL;
        }
        /* F4: a demoted (nearline/offline) file must be recalled before it
         * serves — a bounded synchronous recall like sd_frm's, so a plain
         * export exercises the lane without a cache tier in front. A LOST
         * object or failed recall errors out (never silently serves the bytes
         * a real tape system could not). O_TRUNC replaces the content, so it
         * skips the recall and comes back ONLINE below via the write path. */
        if (st->nearline && !(sd_flags & BRIX_SD_O_TRUNC)
            && pblock_nearline_recall(st, path) != 0)
        {
            if (err_out != NULL) { *err_out = errno; }
            return NULL;
        }
        return pblock_open_existing(inst, path, &meta, sd_flags, err_out);
    }

    /* absent */
    if (!(sd_flags & BRIX_SD_O_CREATE)) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    {
        brix_sd_obj_t *obj;

        obj = pblock_open_create(inst, path, mode, uid, gid, err_out);
        if (obj != NULL && st->lab != NULL) {
            pblock_anomaly_created(st, path);                     /* F9 */
        }
        return obj;
    }
}

/* sd_pblock_open_as — the identity-parameterised open, wrapping the real
 * implementation with the F17 audit record. The wrapper (not the inner) is the
 * audit boundary so every terminal outcome — dir open, existing file, create,
 * or an error — is recorded exactly once with the actor identity and result. */
brix_sd_obj_t *
sd_pblock_open_as(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, uint32_t uid, uint32_t gid, int *err_out)
{
    pblock_state_t *st = inst->state;
    brix_sd_obj_t  *obj;
    int             myerr = 0;

    obj = pblock_open_as_inner(inst, path, sd_flags, mode, uid, gid, &myerr);
    if (obj != NULL && st->locks) {
        /* F15: snapshot the foreign range leases into the handle — the pwrite
         * check is then a pure scan (per the phase design, a conflicting
         * later open is refused at *its* open, so no per-I/O DB hits). */
        pblock_locks_snapshot(st, obj->state, uid);
    }
    if (st->audit) {
        char aux[32];

        snprintf(aux, sizeof(aux), "flags=%d", sd_flags);
        pblock_audit_log(st->cat, "open", path, aux, uid, gid,
                         obj ? 0 : -1, obj ? 0 : myerr);
    }
    if (obj == NULL && err_out != NULL) {
        *err_out = myerr;
    }
    return obj;
}

static brix_sd_obj_t *
sd_pblock_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    /* No identity on the plain slot: creations belong to the service (0/0). */
    return sd_pblock_open_as(inst, path, sd_flags, mode, 0, 0, err_out);
}

static ngx_int_t
sd_pblock_close(brix_sd_obj_t *obj)
{
    pblock_obj_t *os;
    ngx_int_t     rc = NGX_OK;

    if (obj == NULL) {
        return NGX_OK;
    }
    os = obj->state;

    if (os != NULL && os->dirty) {
        pblock_meta old;
        int         have_old = 0;

        /* F9: the pre-update row is what a stale stat will serve — capture it
         * before the touch publishes the new size/mtime. */
        if (os->st->lab != NULL) {
            have_old = pblock_catalog_lookup(os->st->cat, os->path, &old) == 0;
        }
        pblock_lab_crash(os->st->lab, "before_catalog_update");   /* F7 */
        if (pblock_quota_touch_admit(os->st, os->path, os->meta.uid,
                                     os->meta.size) != 0             /* F5 */
            || pblock_catalog_touch(os->st->cat, os->path, os->meta.size,
                                 os->meta.mtime) != 0)
        {
            rc = NGX_ERROR;
        }
        pblock_lab_crash(os->st->lab, "after_catalog_update");    /* F7 */
        if (rc == NGX_OK && have_old) {
            pblock_anomaly_updated(os->st, os->path, old.size,
                                   old.mtime);                    /* F9 */
        }
        os->dirty = 0;
    }
    if (obj->fd != NGX_INVALID_FILE) {
        if (close(obj->fd) != 0) {
            rc = NGX_ERROR;
        }
        obj->fd = NGX_INVALID_FILE;
    }
    if (os != NULL) {
        if (os->st->audit) {                 /* F17: fold per-I/O totals here */
            char aux[64];

            snprintf(aux, sizeof(aux), "r=%lld w=%lld mb=%lld",
                     (long long) os->a_rbytes, (long long) os->a_wbytes,
                     (long long) os->a_maxblock);
            pblock_audit_log(os->st->cat, "close", os->path, aux,
                             os->meta.uid, os->meta.gid,
                             rc == NGX_OK ? 0 : -1, 0);
        }
        if (os->st->csi) {              /* F3: persist CRCs for written blocks */
            (void) pblock_csi_flush(os->st, os->blob_id, os->meta.size,
                                    os->block_size, os->csi_dlo, os->csi_dhi);
        }
        if (os->wv != NULL) {           /* F10: publish-time dedup fold */
            if (os->st->refs && rc == NGX_OK) {
                uint32_t crc   = 0;
                off_t    total = 0;
                int      ok;

                ok = brix_wverify_expected(os->wv, &crc, &total) == 0
                         && (int64_t) total == os->meta.size;
                (void) pblock_refs_dedup_publish(os->st, os->path, &os->meta,
                                                 crc, ok);
            }
            brix_wverify_free(os->wv);
        }
        if (os->st->snap && !os->meta.is_dir) {   /* F6: release the handle count */
            __atomic_sub_fetch(&os->st->open_files, 1, __ATOMIC_RELEASE);
        }
        free(os->csi_crc);
        free(os->lock_rng);             /* F15 per-open lease snapshot */
        pblock_lab_obj_free(os->lab);   /* Phase-83 per-open snapshot */
    }
    free(os);
    obj->state = NULL;
    /* The obj shell is NOT freed here: it may be embedded in the adopter's
     * handle (the VFS copies *obj by value). Its owner — the VFS adopter (via
     * obj->heap_shell), the internal open-error paths, or the standalone test —
     * frees the malloc'd shell. */
    return rc;
}

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
static ngx_int_t
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

/* ---- the driver descriptor ------------------------------------------------ */

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
    .ftruncate        = sd_pblock_ftruncate,
    .fsync            = sd_pblock_fsync,
    .fstat            = sd_pblock_fstat,

    .stat        = sd_pblock_stat,
    .unlink      = sd_pblock_unlink,
    .mkdir       = sd_pblock_mkdir,
    .rename      = sd_pblock_rename,
    .server_copy = sd_pblock_server_copy,
    .setattr     = sd_pblock_setattr,

    .opendir  = sd_pblock_opendir,
    .readdir  = sd_pblock_readdir,
    .closedir = sd_pblock_closedir,

    .enumerate = sd_pblock_enumerate,
    .space     = sd_pblock_space,        /* F5: quota-aware capacity */
    .recall    = sd_pblock_recall,       /* F4: simulated tape recall */
    .residency = sd_pblock_residency,    /* F4: simulated residency model */

    .getxattr    = sd_pblock_getxattr,
    .listxattr   = sd_pblock_listxattr,
    .setxattr    = sd_pblock_setxattr,
    .removexattr = sd_pblock_removexattr,

    .staged_open   = sd_pblock_staged_open,
    .staged_write  = sd_pblock_staged_write,
    .staged_commit = sd_pblock_staged_commit,
    .staged_abort  = sd_pblock_staged_abort,

    /* identity-enforcing slots (sd_pblock_cred.c): POSIX mode-bit checks
     * against catalog ownership when the request carries an identity;
     * identity-less requests fall through to service semantics. */
    .open_cred        = sd_pblock_open_cred,
    .staged_open_cred = sd_pblock_staged_open_cred,
    .stat_cred        = sd_pblock_stat_cred,
    .unlink_cred      = sd_pblock_unlink_cred,
    .mkdir_cred       = sd_pblock_mkdir_cred,
    .rename_cred      = sd_pblock_rename_cred,
    .setattr_cred     = sd_pblock_setattr_cred,
    .getxattr_cred    = sd_pblock_getxattr_cred,
    .listxattr_cred   = sd_pblock_listxattr_cred,
    .setxattr_cred    = sd_pblock_setxattr_cred,
    .removexattr_cred = sd_pblock_removexattr_cred,
    .server_copy_cred = sd_pblock_server_copy_cred,
    .opendir_cred     = sd_pblock_opendir_cred,
};

#endif /* BRIX_HAVE_SQLITE */
