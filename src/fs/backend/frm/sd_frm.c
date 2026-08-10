/*
 * sd_frm.c - the nearline (tape/MSS) backend FS driver (SP5). See header.
 *
 * The driver is a thin residency layer over a pluggable MSS adapter. A read of an
 * offline object RECALLS it into the MSS online buffer (synchronously in this
 * increment - the stub recall is a local copy), then serves from the buffer via a
 * real fd; a staged write lands in the online buffer and is MIGRATED to tape on
 * commit. The composing registry requires a cache tier in front (G8), so the
 * recall is in practice the cache miss-fill sourced from tape.
 *
 * The built-in "stub" MSS adapter simulates tape with two local directories under
 * a base: <base>/<key> is "on tape" (offline) and <base>/.online/<key> is the
 * online buffer. It is what the SP5 tests drive; a real MSS (exec stagecmd, HPSS,
 * CTA) is another adapter selected on the tape:// store-URL.
 */
#include "sd_frm.h"
#include "sd_frm_mss.h"     /* MSS adapters (stub/exec) split out */
#include "sd_frm_internal.h" /* sd_frm_state + adapter selection seam */
#include "fs/xfer/xfer.h"   /* brix_xfer_finish — the unified kind=tape recall
                             * ledger line (one record per terminal transfer) */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;


/* ===================== the sd_frm driver ===================== */

typedef struct {
    sd_frm_state *fst;
    int           fd;
    char          key[1024];
} sd_frm_staged_state;

#define SD_FRM_ST(inst)  ((sd_frm_state *) (inst)->state)

/* Bounded synchronous recall: ensure `key` is online in the MSS buffer. Returns 0
 * (online), or -1 (errno: ENOENT absent, EAGAIN still in-flight, EIO error). A
 * genuinely slow MSS would return EAGAIN and the cache tier would park the open on
 * the stage_engine waiter (the deferred async path); the stub completes at once.
 *
 * `*recalled` (when non-NULL) is set to 1 iff a tape->cache recall was actually
 * initiated on this call (a real nearline miss-fill), so the caller can book the
 * one unified `kind=tape` ledger line only for genuine recalls — never for an
 * already-online cache hit (residency ONLINE) or an absent object. */
static int
frm_ensure_online(sd_frm_state *st, const char *key, int *recalled)
{
    off_t  sz = 0;
    time_t mt = 0;
    int    res = st->mss->residency(st->mss_ctx, key, &sz, &mt);

    if (recalled != NULL) { *recalled = 0; }
    if (res == BRIX_RESIDENCY_ONLINE) {
        return 0;
    }
    if (res == BRIX_RESIDENCY_ABSENT) {
        errno = ENOENT;
        return -1;
    }
    if (recalled != NULL) { *recalled = 1; }
    if (st->mss->recall_begin(st->mss_ctx, key) != 0) {
        errno = EIO;
        return -1;
    }
    /* One poll: a synchronous adapter (begin copied) is online now; an async MSS is
     * still staging, so return EAGAIN and let the HTTP plane answer 202 (the open
     * "parks" via client retry, §9.2). A later retry re-polls and completes. */
    {
        int p = st->mss->recall_poll(st->mss_ctx, key);

        if (p == 1) {
            return 0;
        }
        if (p < 0) {
            errno = EIO;
            return -1;
        }
    }
    errno = EAGAIN;
    return -1;
}

/* Fail an open: book ONE terminal tape-recall error line when this open really
 * did trigger a recall (the caller filters EAGAIN, which is not terminal — the
 * open parks and the client retries, §9.2 — so it is never double-counted),
 * publish errno to the caller, and return the NULL the driver contract wants. */
static brix_sd_obj_t *
sd_frm_open_fail(const char *path, int book, int e, int *err_out, ngx_log_t *log)
{
    if (book) {
        brix_xfer_finish(BRIX_XFER_TAPE, "in", path, NULL, 0,
            BRIX_XFER_SRC_ERR, e, log);
    }
    if (err_out) {
        *err_out = e;
    }
    return NULL;
}


/* Wrap a now-online fd in a heap object shell, seeding its stat snapshot. */
static brix_sd_obj_t *
sd_frm_obj_new(brix_sd_instance_t *inst, int fd)
{
    brix_sd_obj_t *o = calloc(1, sizeof(*o));
    struct stat    sb;

    if (o == NULL) {
        return NULL;
    }
    o->driver     = inst->driver;
    o->inst       = inst;
    o->fd         = fd;
    o->heap_shell = 1;
    if (fstat(fd, &sb) == 0) {
        o->snap.size   = sb.st_size;
        o->snap.mtime  = sb.st_mtime;
        o->snap.mode   = sb.st_mode;
        o->snap.is_reg = 1;
    }
    return o;
}


static brix_sd_obj_t *
sd_frm_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_frm_state    *st = SD_FRM_ST(inst);
    brix_sd_obj_t *o;
    int              fd;
    int              e;
    int              recalled = 0;
    ngx_log_t       *log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;

    (void) mode;
    if ((sd_flags & BRIX_SD_O_WRITE) != 0) {
        /* writes go through the staged path (migrate); a direct write-open is not
         * supported on a nearline backend. */
        return sd_frm_open_fail(path, 0, EROFS, err_out, log);
    }
    if (frm_ensure_online(st, path, &recalled) != 0) {
        /* An already-online cache hit (recalled==0) is no recall at all. */
        e = errno;
        return sd_frm_open_fail(path, recalled && e != EAGAIN, e, err_out, log);
    }
    fd = st->mss->open_online(st->mss_ctx, path);
    if (fd < 0) {
        e = errno ? errno : EIO;
        return sd_frm_open_fail(path, recalled, e, err_out, log);
    }
    o = sd_frm_obj_new(inst, fd);
    if (o == NULL) {
        (void) close(fd);
        return sd_frm_open_fail(path, recalled, ENOMEM, err_out, log);
    }
    /* Terminal success of a genuine tape->cache recall: one unified ledger line
     * (kind=tape, dir=in), byte count from the now-online object. Mirrors the
     * async stage_engine RECALL emit so the sync read-fault path is auditable in
     * the same schema (finding #12). */
    if (recalled) {
        brix_xfer_finish(BRIX_XFER_TAPE, "in", path, NULL,
            (size_t) o->snap.size, BRIX_XFER_OK, 0, log);
    }
    return o;
}

static ngx_int_t
sd_frm_close(brix_sd_obj_t *obj)
{
    if (obj == NULL) {
        return NGX_OK;
    }
    if (obj->fd >= 0) {
        (void) close(obj->fd);
        obj->fd = -1;
    }
    /* The shell is NOT freed here. driver->close closes the fd/state only; the
     * malloc'd shell (heap_shell) is owned by the caller that holds the object
     * by pointer — brix_sd_obj_release() and the VFS adopt paths both do
     * `close(o); if (o->heap_shell) free(o);`, and brix_vfs_adopt_obj() frees
     * the original after copying it by value. Freeing it here double-frees the
     * shell the moment the object is released or adopt fails (matches the posix
     * / http / remote / pblock drivers, which all leave the shell to the owner).
     */
    return NGX_OK;
}

static ssize_t
sd_frm_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return pread(obj->fd, buf, len, off);
}

static ngx_int_t
sd_frm_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    struct stat sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sb.st_size;
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->mode   = sb.st_mode;
    out->ino    = sb.st_ino;
    out->is_reg = 1;
    return NGX_OK;
}

static ngx_int_t
sd_frm_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    off_t         sz = 0;
    time_t        mt = 0;
    int           res = st->mss->residency(st->mss_ctx, path, &sz, &mt);

    if (res == BRIX_RESIDENCY_ABSENT) {
        return NGX_ERROR;            /* ENOENT - errno set by the caller's mapping */
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sz;
    out->mtime  = mt;
    out->mode   = S_IFREG | 0644;
    out->is_reg = 1;
    return NGX_OK;
}

/* Residency (the VFS residency seam, phase-64 §9) — classify `key` via the MSS
 * adapter WITHOUT initiating a recall, mapping the adapter's residency model onto
 * the SD residency enum the protocol handlers consume. ABSENT ⇒ LOST (errno ENOENT
 * so the seam can surface a missing object); ONLINE/NEARLINE/OFFLINE pass through. */
static ngx_int_t
sd_frm_residency(brix_sd_instance_t *inst, const char *key,
                 brix_sd_residency_t *out)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    off_t         sz = 0;
    time_t        mt = 0;
    int           res = st->mss->residency(st->mss_ctx, key, &sz, &mt);

    switch (res) {
    case BRIX_RESIDENCY_ONLINE:   *out = BRIX_SD_RES_ONLINE;   break;
    case BRIX_RESIDENCY_NEARLINE: *out = BRIX_SD_RES_NEARLINE; break;
    case BRIX_RESIDENCY_OFFLINE:  *out = BRIX_SD_RES_OFFLINE;  break;
    default:                        errno = ENOENT; return NGX_ERROR;  /* ABSENT */
    }
    return NGX_OK;
}

static ngx_int_t
sd_frm_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    sd_frm_state *st  = SD_FRM_ST(inst);
    ngx_log_t    *log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;
    int           recalled = 0;

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';         /* synchronous recall: no parking handle */
    }
    if (frm_ensure_online(st, key, &recalled) == 0) {
        /* The cache-fill path (sd_cache) drives every nearline miss through this
         * verb, so a genuine tape->cache recall books its one unified ledger
         * line here (kind=tape, dir=in) — the sync counterpart to the async
         * stage_engine RECALL emit (finding #12). Byte count = the now-online
         * object size. An already-online object (recalled==0) is a plain fill. */
        if (recalled) {
            off_t  sz = 0;
            time_t mt = 0;

            (void) st->mss->residency(st->mss_ctx, key, &sz, &mt);
            brix_xfer_finish(BRIX_XFER_TAPE, "in", key, NULL,
                (size_t) (sz > 0 ? sz : 0), BRIX_XFER_OK, 0, log);
        }
        return NGX_OK;               /* online now - the cache tier does a normal fill */
    }
    {
        int e = errno;

        /* Terminal recall failure books a kind=tape/error line; EAGAIN (async
         * still in flight) is non-terminal and must not be recorded. */
        if (recalled && e != EAGAIN) {
            brix_xfer_finish(BRIX_XFER_TAPE, "in", key, NULL, 0,
                BRIX_XFER_SRC_ERR, e, log);
        }
        return (e == EAGAIN) ? NGX_AGAIN : NGX_ERROR;
    }
}

/* ---- migrate via the staged-write path (online buffer -> tape on commit) ---- */

static brix_sd_staged_t *
sd_frm_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_frm_state        *st = SD_FRM_ST(inst);
    sd_frm_staged_state *ss;
    brix_sd_staged_t  *h;
    int                  fd;

    fd = st->mss->create_online(st->mss_ctx, final_path, mode);
    if (fd < 0) {
        if (err_out) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        (void) close(fd);
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->fst = st;
    ss->fd  = fd;
    ngx_cpystrn((u_char *) ss->key, (u_char *) final_path, sizeof(ss->key));
    h->inst  = inst;
    h->state = ss;
    return h;
}

static ssize_t
sd_frm_staged_write(brix_sd_staged_t *st, const void *buf, size_t len, off_t off)
{
    sd_frm_staged_state *ss = st->state;

    return pwrite(ss->fd, buf, len, off);
}

static ngx_int_t
sd_frm_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    sd_frm_staged_state *ss = st->state;
    int                  rc;

    (void) noreplace;
    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    /* Publish: migrate the online-buffer object to tape. */
    rc = ss->fst->mss->migrate(ss->fst->mss_ctx, ss->key);
    if (rc != 0) {
        /* Ownership contract: only a SUCCESSFUL commit consumes the handle. A
         * failed migrate must leave st+ss valid — every caller aborts a failed
         * commit (stage_engine, cstb_pump_and_commit, cache fetch), and abort
         * frees them. Freeing here made that mandatory abort a use-after-free,
         * a double free, and a second purge of the online buffer. */
        return NGX_ERROR;
    }
    free(ss);
    free(st);
    return NGX_OK;
}

static void
sd_frm_staged_abort(brix_sd_staged_t *st)
{
    sd_frm_staged_state *ss = st->state;

    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    (void) ss->fst->mss->purge(ss->fst->mss_ctx, ss->key);
    free(ss);
    free(st);
}

/* §3.7 pure-tape enumeration: the dir cursor snapshots the MSS listing at
 * opendir via the adapter's `list` verb (see sd_frm.h); no verb ⇒ ENOTSUP.
 * Malloc-owned throughout (no pool); closedir frees snapshot+cursor+dir. */

typedef struct {
    brix_sd_dirent_t *ents;
    size_t              n;
    size_t              cap;
    size_t              next;
} frm_dir_state;

static int
sd_frm_list_cb(void *ud, const char *name, int is_dir)
{
    frm_dir_state *ds = ud;

    if (ds->n == ds->cap) {
        size_t              ncap = ds->cap ? ds->cap * 2 : 64;
        brix_sd_dirent_t *ne = realloc(ds->ents, ncap * sizeof(*ne));

        if (ne == NULL) {
            return 1;   /* stop early; serve what we have */
        }
        ds->ents = ne;
        ds->cap  = ncap;
    }
    snprintf(ds->ents[ds->n].name, sizeof(ds->ents[ds->n].name), "%s", name);
    ds->ents[ds->n].d_type = is_dir ? DT_DIR : DT_REG;
    ds->n++;
    return 0;
}

static brix_sd_dir_t *
sd_frm_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_frm_state  *st = inst->state;
    frm_dir_state *ds;
    brix_sd_dir_t *dir;

    if (st->mss->list == NULL) {
        if (err_out != NULL) { *err_out = ENOTSUP; }
        return NULL;
    }
    ds = calloc(1, sizeof(*ds));
    dir = calloc(1, sizeof(*dir));
    if (ds == NULL || dir == NULL) {
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    if (st->mss->list(st->mss_ctx, path, sd_frm_list_cb, ds) != 0) {
        int e = errno != 0 ? errno : EIO;

        free(ds->ents);
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = e; }
        return NULL;
    }
    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

static ngx_int_t
sd_frm_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    frm_dir_state *ds = d->state;

    if (ds->next >= ds->n) {
        return NGX_DONE;
    }
    *out = ds->ents[ds->next++];
    return NGX_OK;
}

static ngx_int_t
sd_frm_closedir(brix_sd_dir_t *d)
{
    if (d != NULL) {
        frm_dir_state *ds = d->state;

        if (ds != NULL) {
            free(ds->ents);
            free(ds);
        }
        free(d);
    }
    return NGX_OK;
}

/* §3.7 rcreate analog: MSS-side mkdir via the adapter's mkpath verb (see
 * sd_frm.h); no verb ⇒ ENOTSUP. */
static ngx_int_t
sd_frm_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_frm_state *st = inst->state;

    if (st->mss->mkpath == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return (st->mss->mkpath(st->mss_ctx, path, mode) == 0) ? NGX_OK : NGX_ERROR;
}

static const brix_sd_driver_t brix_sd_frm_driver = {
    .name = "frm",
    .caps = BRIX_SD_CAP_NEARLINE | BRIX_SD_CAP_RANGE_READ
          | BRIX_SD_CAP_RANDOM_WRITE | BRIX_SD_CAP_FD | BRIX_SD_CAP_DIRS
          | BRIX_SD_CAP_DIRS_WRITE,   /* §3.7 rcreate: mkdir via mss->mkpath */
    .open          = sd_frm_open,
    .close         = sd_frm_close,
    .pread         = sd_frm_pread,
    .fstat         = sd_frm_fstat,
    .stat          = sd_frm_stat,
    .recall        = sd_frm_recall,
    .residency     = sd_frm_residency,
    .opendir       = sd_frm_opendir,
    .readdir       = sd_frm_readdir,
    .closedir      = sd_frm_closedir,
    .mkdir         = sd_frm_mkdir,
    .staged_open   = sd_frm_staged_open,
    .staged_write  = sd_frm_staged_write,
    .staged_commit = sd_frm_staged_commit,
    .staged_abort  = sd_frm_staged_abort,
};


/* ---- Construct an sd_frm nearline backend instance ----
 *
 * WHAT: Allocates the sd_frm instance and state, selects the MSS adapter (exec if
 * requested and usable, otherwise the built-in stub), and wires the state to the
 * frm driver. Returns the instance, or NULL with errno set (EINVAL for an empty
 * location, ENOMEM for any allocation failure) after freeing partial state.
 *
 * WHY: The single public entry point for the nearline (tape/MSS) backend; the two
 * adapter choices are delegated to helpers so this stays a linear early-return
 * sequence below the complexity cap.
 *
 * HOW:
 *   1. Reject an empty `location` with EINVAL.
 *   2. Allocate inst + state; on failure free both and return ENOMEM.
 *   3. Try the exec adapter; on hard failure free both and return NULL.
 *   4. If no adapter is set yet, fall back to the stub; on failure free and return.
 *   5. Publish the driver and state onto the instance and return it.
 */
brix_sd_instance_t *
brix_sd_frm_create(const char *adapter, const char *location, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_frm_state         *st;

    if (location == NULL || location[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    st   = calloc(1, sizeof(*st));
    if (inst == NULL || st == NULL) {
        free(inst);
        free(st);
        errno = ENOMEM;
        return NULL;
    }
    st->log = log;

    /* Adapter precedence: library-native (dlopen) → exec (stagecmd) → stub. The
     * lib select never hard-fails (an absent vendor .so degrades gracefully), so
     * only the exec/stub selects can abort the create on a real allocation error. */
    (void) frm_select_lib_adapter(st, adapter, location, log);

    if (st->mss == NULL
        && frm_select_exec_adapter(st, adapter, location, log) != 0)
    {
        free(inst);
        free(st);
        return NULL;
    }
    if (st->mss == NULL
        && frm_select_stub_adapter(st, adapter, location, log) != 0)
    {
        free(inst);
        free(st);
        return NULL;
    }

    inst->driver = &brix_sd_frm_driver;
    inst->caps   = brix_sd_frm_driver.caps;  /* effective caps default = descriptor
                                              * caps (matches brix_sd_instance_create);
                                              * without this brix_sd_caps() reports 0
                                              * and the CAP_NEARLINE residency/recall
                                              * gates never see the tape driver. */
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = st;
    return inst;
}

void
brix_sd_frm_destroy(brix_sd_instance_t *inst)
{
    sd_frm_state *st;

    if (inst == NULL) {
        return;
    }
    st = inst->state;
    if (st != NULL) {
        if (st->mss != NULL && st->mss->destroy != NULL) {
            st->mss->destroy(st->mss_ctx);
        }
        free(st);
    }
    free(inst);
}
