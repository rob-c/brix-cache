/*
 * sd_ceph_object.c — Ceph/RADOS driver: object lifecycle + object metadata.
 *
 * WHAT: The namespace/metadata half of the driver split out of sd_ceph.c
 *       (file-size guard): the open path (existence probe, create/excl/trunc
 *       intent, handle build) shared by the plain and cred-scoped opens
 *       (sd_ceph_open_on_ioctx), the vtable open/close/stat/unlink slots, and
 *       the four xattr slots (get/list/set/removexattr) that let a RADOS object
 *       carry the cinfo/checksum-at-rest records.
 *
 * WHY:  These map a logical path to an object id and apply open policy against a
 *       stat probe — a distinct concern from the raw byte ops (sd_ceph_io.c) and
 *       the credential machinery (sd_ceph_cred.c); isolating it keeps every file
 *       under the source-size guard while preserving byte-for-byte behaviour.
 *
 * HOW:  The private struct definitions and the cross-TU helper/op declarations
 *       come from sd_ceph_internal.h. The whole body is gated on BRIX_HAVE_CEPH,
 *       exactly like the driver it was split from.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* pure striper-layout helpers (catalog enumeration) */

#include <errno.h>
#include <string.h>

#include "sd_ceph_internal.h"

#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* libradosstriper read path (stock XrdCeph layout) */
#include <time.h>

/* object lifecycle */

/* sd_ceph_probe_t — result of probing an object's existence at open time:
 * whether it exists (`present`), its size/mtime if so, and whether it is a
 * stock-XrdCeph striper object (so pread reassembles via libradosstriper). */
typedef struct {
    int      present;
    int      striped;
    uint64_t size;
    time_t   mtime;
} sd_ceph_probe_t;

/* sd_ceph_probe_object — establish whether the object already exists.
 *
 * WHAT: Fills `pr` from a stat probe. On a read open it first consults the
 *       stock-XrdCeph striper view (marking `striped` when a striped object of
 *       that name exists); otherwise, or on a miss, it falls back to a flat
 *       rados_stat. Returns 0 on success (object present or cleanly absent) or
 *       a negative errno for a hard stat error the caller must surface.
 *
 * WHY:  The existence probe is the branchiest part of the open path; isolating
 *       it lets the orchestrator apply create/excl/trunc intent as a flat
 *       sequence instead of interleaving I/O with policy.
 *
 * HOW:  1. Zero the result. 2. For a non-write open, try the shared striper
 *          stat; a hit sets present+striped. 3. Otherwise flat rados_stat:
 *          0 → present; -ENOENT → cleanly absent; any other negative → error. */
static int
sd_ceph_probe_object(const sd_ceph_open_req_t *req, const char *oid,
    sd_ceph_probe_t *pr)
{
    int rc = -ENOENT;

    ngx_memzero(pr, sizeof(*pr));

#if defined(BRIX_HAVE_RADOSSTRIPER)
    /* On a read open, prefer the stock-XrdCeph striper view: if a striped object
     * exists for this name, mark it so pread reassembles via libradosstriper.
     * The striper handle is bound to the EXPORT's service ioctx (lazily created
     * on `st`, shared across users) — a per-user cred-scoped open still reads
     * striped objects through it; only the raw rados_read/write/stat/trunc calls
     * use the per-user `ioctx`. */
    if (!(req->sd_flags & BRIX_SD_O_WRITE)) {
        rados_striper_t s = sd_ceph_striper(req->st);
        if (s != NULL
            && sd_ceph_striper_stat(s, oid, &pr->size, &pr->mtime) == 0)
        {
            pr->present = 1;
            pr->striped = 1;
            return 0;
        }
    }
#endif
    rc = rados_stat(req->ioctx, oid, &pr->size, &pr->mtime);
    if (rc == 0) {
        pr->present = 1;
        return 0;
    }
    if (rc == -ENOENT) {
        return 0;                     /* cleanly absent */
    }
    return rc;                        /* hard stat error */
}

/* sd_ceph_apply_intent — enforce create/excl/trunc open flags against the
 * probe result. Returns 0 if the open may proceed, or a positive errno the
 * caller surfaces (ENOENT for absent-without-create, EEXIST for excl-collision,
 * or a truncate failure). On a successful truncate the probe size is reset. */
static int
sd_ceph_apply_intent(const sd_ceph_open_req_t *req, const char *oid,
    sd_ceph_probe_t *pr)
{
    if (!pr->present && !(req->sd_flags & BRIX_SD_O_CREATE)) {
        return ENOENT;
    }
    if (pr->present && (req->sd_flags & BRIX_SD_O_EXCL)) {
        return EEXIST;
    }
    if (req->sd_flags & BRIX_SD_O_TRUNC) {
        if (sd_ceph_set_errno(rados_trunc(req->ioctx, oid, 0))) {
            return errno;
        }
        pr->size = 0;
    }
    return 0;
}

/* sd_ceph_obj_build — allocate and populate the open object + its driver state
 * from a completed probe. Pins a cred-scoped connection (req->pin_conn) so the
 * cred-conn LRU cannot free its ioctx while the handle is open (the UAF fix).
 * Returns the handle, or NULL with *err_out on allocation failure. */
static brix_sd_obj_t *
sd_ceph_obj_build(const sd_ceph_open_req_t *req, const char *oid,
    const sd_ceph_probe_t *pr, int *err_out)
{
    brix_sd_obj_t       *obj;
    sd_ceph_obj_state_t *os;

    obj = ngx_pcalloc(req->inst->pool, sizeof(*obj));
    os  = ngx_pcalloc(req->inst->pool, sizeof(*os));
    if (obj == NULL || os == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    memcpy(os->oid, oid, strlen(oid) + 1);
    os->size      = pr->present ? pr->size : 0;
    os->striped   = pr->striped;
    os->ioctx     = req->ioctx;
    os->conn      = req->pin_conn;
    os->for_write = (req->sd_flags & BRIX_SD_O_WRITE) ? 1 : 0;
    obj->driver   = req->inst->driver;
    obj->inst     = req->inst;
    obj->fd       = NGX_INVALID_FILE;
    obj->state    = os;

    if (req->pin_conn != NULL) {
        sd_ceph_conn_pin(req->pin_conn);   /* UAF fix: keep alive until close() */
    }

    /* Populate the metadata snapshot the caller copies into its handle and uses
     * to build the open reply (open_resolved_file.c). RADOS has no fd/inode, so
     * synthesize a stable inode from the object id and present a regular file. */
    obj->snap.size   = (off_t) os->size;
    obj->snap.mtime  = pr->mtime;
    obj->snap.ctime  = pr->mtime;
    obj->snap.mode   = S_IFREG | 0644;
    obj->snap.ino    = (ino_t) sd_ceph_ino(os->oid);
    obj->snap.is_reg = 1;
    return obj;
}

/* sd_ceph_open_on_ioctx — shared body for plain and cred-scoped opens: resolve
 * the LFN to an object id against the SUPPLIED ioctx, honour create/excl/trunc
 * intent against a stat probe, and return a handle carrying the id + cached
 * size. There is no fd: obj->fd stays NGX_INVALID_FILE (the VFS serves such
 * handles memory-backed).
 *
 * WHAT: Resolves `req->path` to an object id, probes its existence, applies the
 *       open intent, and builds the handle. Returns the object, or NULL with
 *       *err_out set on any failure.
 * WHY:  A cred-scoped open (sd_ceph_open_cred) must issue every rados_* /
 *       striper call against the PER-USER connection's ioctx, not the
 *       export's static service ioctx — otherwise the "per-user" open would
 *       silently authenticate as the service account, defeating the whole
 *       point of the ceph-peruser credential kind. Factoring the object-open
 *       body into one function (fed a bundled request) keeps the plain and
 *       cred-scoped paths from diverging in error handling or metadata.
 * HOW:  1. Map the logical path to an object id (sd_ceph_key). 2. Probe
 *          existence (sd_ceph_probe_object). 3. Enforce create/excl/trunc
 *          (sd_ceph_apply_intent). 4. Allocate + populate the handle, pinning
 *          req->pin_conn for a cred-scoped open (sd_ceph_obj_build). On any
 *          failure path nothing is pinned (the caller still owns releasing
 *          req->pin_conn itself, e.g. sd_ceph_open_cred's pin bookkeeping). */
brix_sd_obj_t *
sd_ceph_open_on_ioctx(const sd_ceph_open_req_t *req, int *err_out)
{
    char            oid[1024];
    sd_ceph_probe_t pr = {0};
    int             rc;
    int             intent_err;

    (void) req->mode;

    if (sd_ceph_key(req->st->key_prefix, req->path, oid, sizeof(oid)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    rc = sd_ceph_probe_object(req, oid, &pr);
    if (rc < 0) {
        if (err_out != NULL) { *err_out = -rc; }
        return NULL;
    }

    intent_err = sd_ceph_apply_intent(req, oid, &pr);
    if (intent_err != 0) {
        if (err_out != NULL) { *err_out = intent_err; }
        return NULL;
    }

    return sd_ceph_obj_build(req, oid, &pr, err_out);
}

/* sd_ceph_open — vtable open slot: service credential.
 *
 * WHAT: Plain open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; uses the export's
 *       static service ioctx (inst->state->ioctx).
 * HOW:  Delegates to sd_ceph_open_on_ioctx with the instance's own ioctx. */
brix_sd_obj_t *
sd_ceph_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_ceph_state_t   *st = inst->state;
    sd_ceph_open_req_t req = {
        .inst     = inst,
        .st       = st,
        .ioctx    = st->ioctx,
        .pin_conn = NULL,
        .path     = path,
        .sd_flags = sd_flags,
        .mode     = mode,
    };

    return sd_ceph_open_on_ioctx(&req, err_out);
}

/* sd_ceph_close — release this handle's pin (if any) on its cred-scoped
 * connection. A plain (service-credential) open has os->conn == NULL — the
 * export's own ioctx is instance-lived and is torn down only by
 * sd_ceph_cleanup, so there is nothing to release. A cred-scoped open's
 * os->conn is non-NULL: sd_ceph_conn_unpin drops the pin taken at open, and
 * if this was the connection's last pin AND it had already been evicted
 * from the cred-conn cache table (doomed) while still in use, the deferred
 * rados_ioctx_destroy/rados_shutdown happens right here — this is the fix
 * for the historical UAF (the connection used to be destroyed by the LRU
 * evictor regardless of whether a handle was still reading/writing through
 * it). Idempotent-safe: the VFS never calls close twice on the same handle,
 * but sd_ceph_conn_unpin tolerates refs already at 0. */
ngx_int_t
sd_ceph_close(brix_sd_obj_t *obj)
{
    sd_ceph_obj_state_t *os = obj->state;

    if (os->conn != NULL) {
        sd_ceph_conn_unpin(os->conn);
        os->conn = NULL;
    }
    return NGX_OK;
}

/* namespace (logical paths) */

/* sd_ceph_stat — rados_stat on the object id for a logical path. The export
 * root ("/") is the one always-present SYNTHETIC directory (phase-89 ADR-1:
 * directories are prefixes, not objects) and is answered without touching the
 * cluster; deeper synthetic directories are served by opendir only — a
 * per-stat child probe would turn every stat-miss into a pool scan. */
ngx_int_t
sd_ceph_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];
    char             norm[1024];
    uint64_t         size = 0;
    time_t           mtime = 0;

    if (sd_ceph_normalize(path, norm, sizeof(norm)) == 0
        && norm[0] == '/' && norm[1] == '\0')
    {
        ngx_memzero(out, sizeof(*out));
        out->mode   = S_IFDIR | 0755;
        out->is_dir = 1;
        out->ino    = (ino_t) sd_ceph_ino(
                          st->key_prefix != NULL ? st->key_prefix : "/");
        return NGX_OK;
    }

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_stat(st->ioctx, oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    sd_ceph_fill_stat(oid, size, mtime, out);
    return NGX_OK;
}

/* sd_ceph_child_probe_t / _cb — bounded "does this prefix have any child?"
 * probe over the catalog enumeration, aborting on the first hit. */
typedef struct {
    const char *dir;
    int         found;
} sd_ceph_child_probe_t;

static int
sd_ceph_child_probe_cb(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    sd_ceph_child_probe_t *c = ctx;
    char                   name[sizeof(((brix_sd_dirent_t *) 0)->name)];

    if (ent->path != NULL
        && sd_ceph_path_child(c->dir, ent->path, name, sizeof(name)) != 0)
    {
        c->found = 1;
        return 1;                              /* first hit — stop the pass */
    }
    return 0;
}

/* sd_ceph_rmdir_synthetic — directory removal on a flat namespace (phase-89
 * ADR-1): a synthetic directory holds no object of its own, so "removing" an
 * empty one succeeds without touching the cluster, a non-empty one is
 * ENOTEMPTY, and the export root is never removable (EBUSY). */
static ngx_int_t
sd_ceph_rmdir_synthetic(brix_sd_instance_t *inst, const char *path)
{
    char                  norm[1024];
    sd_ceph_child_probe_t c;

    if (sd_ceph_normalize(path, norm, sizeof(norm)) != 0) {
        return NGX_ERROR;
    }
    if (norm[0] == '/' && norm[1] == '\0') {
        errno = EBUSY;
        return NGX_ERROR;
    }

    c.dir   = norm;
    c.found = 0;
    if (sd_ceph_enumerate(inst, 0, sd_ceph_child_probe_cb, &c) != NGX_OK) {
        return NGX_ERROR;
    }
    if (c.found) {
        errno = ENOTEMPTY;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* sd_ceph_unlink — remove the object for a logical path. A directory unlink
 * dispatches to the synthetic-directory semantics (nothing stored to remove;
 * non-empty prefixes refuse with ENOTEMPTY). */
ngx_int_t
sd_ceph_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    if (is_dir) {
        return sd_ceph_rmdir_synthetic(inst, path);
    }

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_remove(st->ioctx, oid))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* sd_ceph_mkdir — synthetic-directory create (phase-89 ADR-1: no marker
 * objects). A directory exists iff objects live under its prefix, so creating
 * one is a confined no-op success: the path is validated/confined through the
 * key map and nothing is stored. WebDAV MKCOL / mkpath flows over a rados
 * export succeed and the subsequent PUTs materialize the prefix. */
ngx_int_t
sd_ceph_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    (void) mode;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;                      /* escape/overflow — confined */
    }
    return NGX_OK;
}

/* ---- rename (copy + delete; phase-89 §B.2 / ADR-5) ----------------------- */

/* Chunk size for the rename copy loop (matches the striper object-size class). */
#define SD_CEPH_COPY_CHUNK (4u * 1024 * 1024)

/* sd_ceph_path_probe_t / sd_ceph_probe_oid — existence/layout probe for a
 * bare oid (no open request): striper view first (a striped object must be
 * copied through the striper to reassemble), then flat. 0 on success (present
 * or cleanly absent), negative errno on a hard stat error. */
typedef struct {
    int      present;
    int      striped;
    uint64_t size;
} sd_ceph_path_probe_t;

static int
sd_ceph_probe_oid(sd_ceph_state_t *st, const char *oid,
    sd_ceph_path_probe_t *pr)
{
    uint64_t size = 0;
    time_t   mtime = 0;
    int      rc;

    ngx_memzero(pr, sizeof(*pr));

#if defined(BRIX_HAVE_RADOSSTRIPER)
    {
        rados_striper_t s = sd_ceph_striper(st);

        if (s != NULL && sd_ceph_striper_stat(s, oid, &size, &mtime) == 0) {
            pr->present = 1;
            pr->striped = 1;
            pr->size    = size;
            return 0;
        }
    }
#endif
    rc = rados_stat(st->ioctx, oid, &size, &mtime);
    if (rc == 0) {
        pr->present = 1;
        pr->size    = size;
        return 0;
    }
    return (rc == -ENOENT) ? 0 : rc;
}

/* sd_ceph_remove_oid — remove an object through the layout it was found in. */
static int
sd_ceph_remove_oid(sd_ceph_state_t *st, const char *oid, int striped)
{
#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (striped) {
        rados_striper_t s = sd_ceph_striper(st);

        return (s != NULL) ? sd_ceph_striper_remove(s, oid) : -EIO;
    }
#else
    (void) striped;
#endif
    return rados_remove(st->ioctx, oid);
}

/* sd_ceph_copy_bytes — chunked byte copy src → dst. A striped source is read
 * AND written through the striper so the destination keeps the stock-XrdCeph
 * layout; a flat source copies flat. An empty source is created flat (the
 * caller forces striped=0 for size 0 — a zero-length striper write would not
 * materialize the first stripe). 0 or negative errno. */
static int
sd_ceph_copy_bytes(sd_ceph_state_t *st, const char *src, int striped,
    uint64_t size, const char *dst)
{
    char     *buf;
    uint64_t  off = 0;

    if (size == 0) {
        return rados_write_full(st->ioctx, dst, "", 0);
    }

    buf = malloc(SD_CEPH_COPY_CHUNK);
    if (buf == NULL) {
        return -ENOMEM;
    }

    while (off < size) {
        size_t  want = (size - off < SD_CEPH_COPY_CHUNK)
                       ? (size_t) (size - off) : SD_CEPH_COPY_CHUNK;
        ssize_t n;
        ssize_t wrc;

#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (striped) {
            rados_striper_t s = sd_ceph_striper(st);

            if (s == NULL) {
                free(buf);
                return -EIO;
            }
            n = sd_ceph_striper_read(s, src, buf, want, off);
            if (n > 0) {
                wrc = sd_ceph_striper_write(s, dst, buf, (size_t) n, off);
            } else {
                wrc = 0;
            }
        } else
#endif
        {
            n = rados_read(st->ioctx, src, buf, want, off);
            wrc = (n > 0) ? rados_write(st->ioctx, dst, buf, (size_t) n, off)
                          : 0;
        }

        if (n < 0) {
            free(buf);
            return (int) n;
        }
        if (n == 0) {
            free(buf);
            return -EIO;                       /* source shrank mid-copy */
        }
        if (wrc < 0) {
            free(buf);
            return (int) wrc;
        }
        off += (uint64_t) n;
    }

    free(buf);
    return 0;
}

#if defined(BRIX_HAVE_RADOSSTRIPER)
/* sd_ceph_copy_xattrs_striped — the striped-source leg of the xattr copy:
 * list the striper object's names, then get/set each one. Striper-internal
 * "striper.*" layout attrs are never copied — the destination's own write path
 * stamps its layout. 0 or negative errno. */
static int
sd_ceph_copy_xattrs_striped(sd_ceph_state_t *st, const char *src,
    const char *dst, int dst_striped)
{
    rados_striper_t s = sd_ceph_striper(st);
    char           *names;
    char           *val;
    ssize_t         total;
    ssize_t         used = 0;
    int             rc = 0;

    if (s == NULL) {
        return -EIO;
    }
    names = malloc(SD_CEPH_XATTR_MAX);
    val   = malloc(SD_CEPH_XATTR_MAX);
    if (names == NULL || val == NULL) {
        free(names);
        free(val);
        return -ENOMEM;
    }
    total = sd_ceph_striper_listxattr(s, src, names, SD_CEPH_XATTR_MAX);
    if (total < 0) {
        free(names);
        free(val);
        return (int) total;
    }
    while (rc == 0 && used < total) {
        const char *nm = names + used;
        ssize_t     vlen;

        used += (ssize_t) strlen(nm) + 1;
        if (strncmp(nm, "striper.", 8) == 0) {
            continue;                      /* layout attrs: never copied */
        }
        vlen = sd_ceph_striper_getxattr(s, src, nm, val,
                                        SD_CEPH_XATTR_MAX);
        if (vlen < 0) {
            rc = (int) vlen;
            break;
        }
        rc = dst_striped
             ? sd_ceph_striper_setxattr(s, dst, nm, val, (size_t) vlen)
             : rados_setxattr(st->ioctx, dst, nm, val, (size_t) vlen);
    }
    free(names);
    free(val);
    return rc;
}
#endif

/* sd_ceph_copy_xattrs_plain — the flat-object leg of the xattr copy: walk the
 * source's xattr iterator and stamp each pair onto the destination (striper
 * or flat, per dst_striped). 0 or negative errno. */
static int
sd_ceph_copy_xattrs_plain(sd_ceph_state_t *st, const char *src,
    const char *dst, int dst_striped)
{
    rados_xattrs_iter_t it;
    int                 rc;

    rc = rados_getxattrs(st->ioctx, src, &it);
    if (rc < 0) {
        return rc;
    }
    for (;;) {
        const char *nm = NULL;
        const char *vv = NULL;
        size_t      vlen = 0;

        rc = rados_getxattrs_next(it, &nm, &vv, &vlen);
        if (rc < 0 || nm == NULL) {
            break;
        }
#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (dst_striped) {
            rados_striper_t s = sd_ceph_striper(st);

            rc = (s != NULL)
                 ? sd_ceph_striper_setxattr(s, dst, nm, vv, vlen) : -EIO;
        } else
#endif
        {
            rc = rados_setxattr(st->ioctx, dst, nm, vv, vlen);
        }
        if (rc < 0) {
            break;
        }
    }
    rados_getxattrs_end(it);
#if !defined(BRIX_HAVE_RADOSSTRIPER)
    (void) dst_striped;
#endif
    return (rc < 0) ? rc : 0;
}

/* sd_ceph_copy_xattrs — carry the object xattrs across the copy (the cache
 * cinfo/meta/checksum-at-rest records must survive a rename). Dispatches on
 * the source's layout to the striped or plain leg above. Values are bounded
 * by SD_CEPH_XATTR_MAX (the driver's existing xattr value bound). 0 or
 * negative errno. */
static int
sd_ceph_copy_xattrs(sd_ceph_state_t *st, const char *src, int src_striped,
    const char *dst, int dst_striped)
{
#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (src_striped) {
        return sd_ceph_copy_xattrs_striped(st, src, dst, dst_striped);
    }
#else
    (void) src_striped;
#endif
    return sd_ceph_copy_xattrs_plain(st, src, dst, dst_striped);
}

/* sd_ceph_rename_missing_src — classify a rename whose source object is
 * absent. A populated synthetic-directory source is EISDIR (no collection
 * rename on a flat namespace), a bare miss is ENOENT. Always NGX_ERROR with
 * errno set. */
static ngx_int_t
sd_ceph_rename_missing_src(brix_sd_instance_t *inst, const char *src)
{
    char                  norm[1024];
    sd_ceph_child_probe_t c;

    errno = ENOENT;
    if (sd_ceph_normalize(src, norm, sizeof(norm)) == 0) {
        c.dir   = norm;
        c.found = 0;
        if (sd_ceph_enumerate(inst, 0, sd_ceph_child_probe_cb, &c)
                == NGX_OK && c.found)
        {
            errno = EISDIR;
        }
    }
    return NGX_ERROR;
}

/* sd_ceph_rename_prep_dst — probe the destination oid and clear the way:
 * honour noreplace (EEXIST) and remove a pre-existing destination object.
 * NGX_OK or NGX_ERROR with errno set. */
static ngx_int_t
sd_ceph_rename_prep_dst(sd_ceph_state_t *st, const char *dm, int noreplace)
{
    sd_ceph_path_probe_t dp;
    int                  rc;

    rc = sd_ceph_probe_oid(st, dm, &dp);
    if (rc < 0) {
        errno = -rc;
        return NGX_ERROR;
    }
    if (dp.present && noreplace) {
        errno = EEXIST;
        return NGX_ERROR;
    }
    if (dp.present) {
        rc = sd_ceph_remove_oid(st, dm, dp.striped);
        if (rc < 0) {
            errno = -rc;
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* sd_ceph_rename_copy_verify — land the destination's bytes AND xattrs, then
 * size-verify it against the source probe. 0 or negative errno (the caller
 * cleans up the partial destination on failure). */
static int
sd_ceph_rename_copy_verify(sd_ceph_state_t *st, const char *so,
    const char *dm, const sd_ceph_path_probe_t *sp, int dst_striped)
{
    int rc;

    rc = sd_ceph_copy_bytes(st, so, dst_striped, sp->size, dm);
    if (rc == 0) {
        rc = sd_ceph_copy_xattrs(st, so, sp->striped, dm, dst_striped);
    }
    if (rc == 0) {
        sd_ceph_path_probe_t vp;

        rc = sd_ceph_probe_oid(st, dm, &vp);
        if (rc == 0 && (!vp.present || vp.size != sp->size)) {
            rc = -EIO;                         /* verify: dst must hold src's bytes */
        }
    }
    return rc;
}

/* sd_ceph_rename — copy + delete on the flat namespace (phase-89 §B.2).
 * NON-ATOMIC by design (the driver honestly does not advertise
 * CAP_HARD_RENAME — same posture as the other object backends): the source is
 * removed only after the destination's bytes AND xattrs landed and a size
 * verify passed, so a mid-copy failure leaves the source intact (the partial
 * destination is cleaned up best-effort). `noreplace` is honoured by a probe
 * (racy by nature on an object store — documented). Directory rename is
 * refused (EISDIR): a flat namespace has no atomic prefix move, and a
 * recursive key rewrite is out of scope (ADR-5). */
ngx_int_t
sd_ceph_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_ceph_state_t     *st = inst->state;
    char                 so[1024];
    char                 dm[1024];
    sd_ceph_path_probe_t sp;
    int                  dst_striped;
    int                  rc;

    if (sd_ceph_key(st->key_prefix, src, so, sizeof(so)) != 0
        || sd_ceph_key(st->key_prefix, dst, dm, sizeof(dm)) != 0)
    {
        return NGX_ERROR;
    }
    if (strcmp(so, dm) == 0) {
        return NGX_OK;                         /* same object — nothing to do */
    }

    rc = sd_ceph_probe_oid(st, so, &sp);
    if (rc < 0) {
        errno = -rc;
        return NGX_ERROR;
    }
    if (!sp.present) {
        return sd_ceph_rename_missing_src(inst, src);
    }

    if (sd_ceph_rename_prep_dst(st, dm, noreplace) != NGX_OK) {
        return NGX_ERROR;
    }

    dst_striped = (sp.striped && sp.size > 0);
    rc = sd_ceph_rename_copy_verify(st, so, dm, &sp, dst_striped);
    if (rc < 0) {
        (void) sd_ceph_remove_oid(st, dm, dst_striped);  /* best-effort cleanup */
        errno = -rc;
        return NGX_ERROR;
    }

    rc = sd_ceph_remove_oid(st, so, sp.striped);
    if (rc < 0) {
        errno = -rc;                           /* dst intact; src survived too */
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* xattr / object metadata — RADOS objects carry their own xattrs, so the
 * checksum-at-rest seam (user.XrdCks.*) and protocol GETFATTR/SETFATTR work on a
 * Ceph export exactly as on POSIX. All four key the object id off the logical
 * path; the object must already exist (set/get/list/remove on a missing oid
 * return -ENOENT via librados). */

ssize_t
sd_ceph_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];
    char             tmp[SD_CEPH_XATTR_MAX];
    int              n;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return -1;
    }
    n = rados_getxattr(st->ioctx, oid, name, tmp, sizeof(tmp));
    if (n < 0) {
        errno = -n;
        return -1;
    }
    if (cap == 0) {
        return n;                  /* size probe (getxattr(2) convention) */
    }
    if ((size_t) n > cap) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, tmp, (size_t) n);
    return n;
}

ssize_t
sd_ceph_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap)
{
    sd_ceph_state_t    *st = inst->state;
    char                oid[1024];
    rados_xattrs_iter_t it;
    char               *out = buf;
    size_t              total = 0;

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return -1;
    }
    if (sd_ceph_set_errno(rados_getxattrs(st->ioctx, oid, &it))) {
        return -1;
    }
    for (;;) {
        const char *nm = NULL;
        const char *val = NULL;
        size_t      vlen = 0;
        size_t      nlen;

        if (sd_ceph_set_errno(rados_getxattrs_next(it, &nm, &val, &vlen))) {
            rados_getxattrs_end(it);
            return -1;
        }
        if (nm == NULL) {
            break;                 /* end of iteration */
        }
        nlen = strlen(nm) + 1;     /* listxattr(2): names are NUL-separated */
        if (cap != 0) {
            if (total + nlen > cap) {
                rados_getxattrs_end(it);
                errno = ERANGE;
                return -1;
            }
            memcpy(out + total, nm, nlen);
        }
        total += nlen;
    }
    rados_getxattrs_end(it);
    return (ssize_t) total;
}

ngx_int_t
sd_ceph_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    (void) flags;   /* RADOS has no XATTR_CREATE/REPLACE; a plain set is applied */

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_setxattr(st->ioctx, oid, name, val, len))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
sd_ceph_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_ceph_state_t *st = inst->state;
    char             oid[1024];

    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_rmxattr(st->ioctx, oid, name))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

#endif /* BRIX_HAVE_CEPH */
