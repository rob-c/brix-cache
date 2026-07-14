/*
 * sd_ceph_io.c — Ceph/RADOS driver: worker-safe raw byte I/O + staged write +
 * the shared oid-level connection layer.
 *
 * WHAT: The data-plane half of the driver split out of sd_ceph.c (file-size
 *       guard): the vtable's raw byte ops (pread/pwrite/preadv/ftruncate/fsync/
 *       fstat, plus the memory-backed read_sendfile_fd and the libradosstriper
 *       reassembly helper), the staged-write slots (WebDAV PUT / staged upload),
 *       and the reference-counted librados connection primitives
 *       (sd_ceph_conn_create/_destroy/_ioctx/_pin/_unpin) reused by the flat
 *       driver, the cephfsro driver and the recovery tools, plus the .enumerate
 *       catalog walk (inventory/drift, byte-compatible with stock XrdCeph's
 *       striper layout).
 *
 * WHY:  These operate purely on an already-open object's ioctx (or a bare
 *       connection) with no pool/log/metrics, so they are the parts meant to run
 *       on the nginx thread pool; keeping them in their own TU keeps each file
 *       under the source-size guard while preserving byte-for-byte behaviour.
 *
 * HOW:  Shared internals (the struct definitions, sd_ceph_set_errno,
 *       sd_ceph_cluster_connect and the cross-TU declarations) come from
 *       sd_ceph_internal.h. The whole body is gated on BRIX_HAVE_CEPH, exactly
 *       like the driver it was split from.
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

/* Driver-private staged-write state (staged->state): the final object id. RADOS
 * has no atomic rename, so — like the root:// write path — the staged target IS
 * the final object (trunc-on-open, write in place, commit is a no-op). */
typedef struct {
    char oid[1024];
} sd_ceph_staged_t;

/* worker-safe raw byte I/O (no pool/log/metrics) */

#if defined(BRIX_HAVE_RADOSSTRIPER)
/* Lazily create (once per export) the libradosstriper handle bound to this
 * instance's ioctx, so reads of stock-XrdCeph striped objects reassemble the file
 * byte-for-byte. NULL on failure (the caller falls back to a raw read). */
rados_striper_t
sd_ceph_striper(sd_ceph_state_t *st)
{
    if (!st->striper_ready) {
        if (sd_ceph_striper_create(st->ioctx, NULL, &st->striper) != 0) {
            return NULL;
        }
        st->striper_ready = 1;
    }
    return st->striper;
}

#endif /* BRIX_HAVE_RADOSSTRIPER */

/* sd_ceph_pread — read at off from the object. A striper-format object (stock
 * XrdCeph) is read through libradosstriper so its bytes reassemble exactly;
 * everything else is a flat rados_read. Returns bytes read (>=0, 0 = at/after
 * EOF) or -1 with errno. The VFS owns the EINTR/short-read loop (vfs_core). */
ssize_t
sd_ceph_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_ceph_obj_state_t *os = obj->state;
    int                  rc;

#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (os->striped) {
        sd_ceph_state_t *st = obj->inst->state;
        rados_striper_t   s = sd_ceph_striper(st);
        ssize_t         n;

        if (s == NULL) {
            errno = EIO;
            return -1;
        }
        n = sd_ceph_striper_read(s, os->oid, buf, len, (uint64_t) off);
        if (n < 0) {
            errno = (int) -n;
            return -1;
        }
        return n;
    }
#endif

    rc = rados_read(os->ioctx, os->oid, buf, len, (uint64_t) off);
    if (rc < 0) {
        errno = -rc;
        return -1;
    }
    return (ssize_t) rc;
}

/* sd_ceph_pwrite — one rados_write at off; returns len on success or -1. Bumps
 * the cached object size so a subsequent fstat reflects in-flight writes. */
ssize_t
sd_ceph_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_ceph_obj_state_t *os = obj->state;
    int                  rc;

    rc = rados_write(os->ioctx, os->oid, buf, len, (uint64_t) off);
    if (sd_ceph_set_errno(rc)) {
        return -1;
    }
    if ((uint64_t) off + len > os->size) {
        os->size = (uint64_t) off + len;
    }
    return (ssize_t) len;
}

/* sd_ceph_preadv — vectored read as a loop of sd_ceph_pread (RADOS has no native
 * preadv); stops at the first short/EOF segment. Bytes read or -1. */
ssize_t
sd_ceph_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_ceph_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                  off + total);
        if (n < 0) {
            return -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                    /* short read / EOF */
        }
    }
    return total;
}

/* sd_ceph_preadv2 — RADOS has no per-read flags (e.g. RWF_NOWAIT); ignore them
 * and serve via the plain vectored read. */
ssize_t
sd_ceph_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    (void) flags;
    return sd_ceph_preadv(obj, iov, iovcnt, off);
}

/* sd_ceph_read_sendfile_fd — RADOS exposes no kernel fd, so reads are always
 * served memory-backed; signal that to the VFS with NGX_INVALID_FILE. */
ngx_fd_t
sd_ceph_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) obj; (void) off; (void) len; (void) want_zerocopy;
    return NGX_INVALID_FILE;
}

/* sd_ceph_ftruncate — rados_trunc to len; updates the cached size. */
ngx_int_t
sd_ceph_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    sd_ceph_obj_state_t *os = obj->state;

    if (sd_ceph_set_errno(rados_trunc(os->ioctx, os->oid, (uint64_t) len))) {
        return NGX_ERROR;
    }
    os->size = (uint64_t) len;
    return NGX_OK;
}

/* sd_ceph_fsync — a synchronous rados_write is durably acked on return, so there
 * is nothing to flush; succeed. (aio flush belongs to the async follow-on.) */
ngx_int_t
sd_ceph_fsync(brix_sd_obj_t *obj)
{
    (void) obj;
    return NGX_OK;
}

/* sd_ceph_fill_stat — shape a RADOS (size, mtime) pair into the neutral stat the
 * VFS consumes: a regular object, mode 0644, a stable synthesized inode. */
void
sd_ceph_fill_stat(const char *oid, uint64_t size, time_t mtime,
    brix_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = (off_t) size;
    out->mtime  = mtime;
    out->ctime  = mtime;
    out->mode   = 0100644;            /* S_IFREG | 0644 */
    out->ino    = (ino_t) sd_ceph_ino(oid);
    out->is_reg = 1;
}

/* sd_ceph_fstat — rados_stat on the open object's id. */
ngx_int_t
sd_ceph_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_ceph_obj_state_t *os = obj->state;
    uint64_t             size = 0;
    time_t               mtime = 0;

    if (sd_ceph_set_errno(rados_stat(os->ioctx, os->oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    sd_ceph_fill_stat(os->oid, size, mtime, out);
    return NGX_OK;
}

/* staged/atomic write — WebDAV PUT and other staged-upload paths.
 *
 * RADOS has no atomic rename, so (matching the root:// write path, which writes
 * straight to the final object) the staged target IS the final object: trunc it
 * to zero at open, write in place, commit is a no-op, abort removes it. A
 * temp-object + server-side copy-on-commit would add true atomicity at O(size)
 * cost; that is a follow-on, not needed for basic PUT parity with root://. */
brix_sd_staged_t *
sd_ceph_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_ceph_state_t    *st = inst->state;
    brix_sd_staged_t *handle;
    sd_ceph_staged_t   *ps;

    (void) mode;

    handle = ngx_pcalloc(inst->pool, sizeof(*handle));
    ps     = ngx_pcalloc(inst->pool, sizeof(*ps));
    if (handle == NULL || ps == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    if (sd_ceph_key(st->key_prefix, final_path, ps->oid, sizeof(ps->oid)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (sd_ceph_set_errno(rados_trunc(st->ioctx, ps->oid, 0))) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    handle->inst  = inst;
    handle->state = ps;
    return handle;
}

ssize_t
sd_ceph_staged_write(brix_sd_staged_t *sh, const void *buf, size_t len,
    off_t off)
{
    sd_ceph_state_t  *st = sh->inst->state;
    sd_ceph_staged_t *ps = sh->state;

    if (sd_ceph_set_errno(rados_write(st->ioctx, ps->oid, buf, len,
                                      (uint64_t) off)))
    {
        return -1;
    }
    return (ssize_t) len;
}

ngx_int_t
sd_ceph_staged_commit(brix_sd_staged_t *sh, int noreplace)
{
    (void) sh;
    (void) noreplace;   /* the object is already written in place */
    return NGX_OK;
}

void
sd_ceph_staged_abort(brix_sd_staged_t *sh)
{
    sd_ceph_state_t  *st = sh->inst->state;
    sd_ceph_staged_t *ps = sh->state;

    (void) rados_remove(st->ioctx, ps->oid);
}

/* ---- shared oid-level connection layer (reused by cephfsro + recovery tools)
 * The bare connection primitives declared in sd_ceph.h, plus the pin/unpin
 * reference-counting that the cred-conn cache and the object open/close path
 * rely on (sd_ceph_internal.h). --------------------------------------------- */

sd_ceph_conn_t *
sd_ceph_conn_create(const brix_sd_ceph_conf_t *conf, ngx_pool_t *pool, int *err)
{
    sd_ceph_conn_t *c;

    if (conf == NULL || conf->pool == NULL) {
        if (err != NULL) { *err = EINVAL; }
        return NULL;
    }
    c = ngx_pcalloc(pool, sizeof(*c));
    if (c == NULL) {
        if (err != NULL) { *err = ENOMEM; }
        return NULL;
    }
    c->pool = pool;
    if (sd_ceph_cluster_connect(conf->conf_file, conf->user, conf->keyring,
                                conf->pool, &c->cluster, &c->ioctx) != 0)
    {
        if (err != NULL) { *err = errno; }
        return NULL;
    }
    c->connected = 1;
    return c;
}

void
sd_ceph_conn_destroy(sd_ceph_conn_t *c)
{
    if (c != NULL && c->connected) {
        rados_ioctx_destroy(c->ioctx);
        rados_shutdown(c->cluster);
        c->connected = 0;
    }
}

rados_ioctx_t
sd_ceph_conn_ioctx(sd_ceph_conn_t *c)
{
    return c->ioctx;
}

/* sd_ceph_conn_pin — take one reference on a cred-scoped connection for an
 * open object that resolved onto it. Must be matched by exactly one
 * sd_ceph_conn_unpin (from sd_ceph_close) for the object's lifetime. */
void
sd_ceph_conn_pin(sd_ceph_conn_t *c)
{
    c->refs++;
}

/* sd_ceph_conn_unpin — drop one reference. If the connection is `doomed`
 * (either evicted from the cred-conn cache table while still pinned, or a
 * transient all-slots-pinned connection that was never inserted into the
 * table at all — see sd_ceph_cred_conn) and this was the last pin (refs
 * reaches 0), complete the deferred destroy now — this is the ONLY place a
 * doomed connection is actually torn down, guaranteeing no pread/pwrite/
 * fstat on a still-open handle can ever run against a freed ioctx, AND
 * guaranteeing a transient connection's mon session/ioctx/fds are freed
 * exactly once instead of leaking. A non-doomed connection simply loses a
 * pin and stays live in the cache for reuse. */
void
sd_ceph_conn_unpin(sd_ceph_conn_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->refs > 0) {
        c->refs--;
    }
    if (c->doomed && c->refs == 0) {
        sd_ceph_conn_destroy(c);
    }
}

/* sd_ceph_enumerate — backend-catalog enumeration (inventory/drift, §E1/D2).
 * Lists the pool's RADOS objects and reports ONE catalog entry per logical file,
 * byte-compatibly with stock XrdCeph's libradosstriper layout:
 *   - a striper FIRST stripe ("<name>.0000000000000000") represents one file →
 *     recover its physical name by stripping the suffix and report it once;
 *   - striper DATA stripes ("<name>.%016x", index > 0) are skipped (already
 *     accounted by their first stripe);
 *   - a flat object (this basic driver's own, no 16-hex stripe suffix) is itself.
 * The logical path is recovered by stripping the export key_prefix; a key outside
 * the prefix yields path=NULL (an orphan candidate). want_stat adds a rados_stat
 * per reported object. Worker-safe: synchronous librados, no pool/log/metrics.
 * Returns NGX_OK (enumeration ran; the callback may have aborted early) or
 * NGX_ERROR (errno set) if the pool list could not be opened. */
ngx_int_t
sd_ceph_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    sd_ceph_state_t  *st = inst->state;
    rados_list_ctx_t  lc;
    const char       *oid;
    size_t            plen = (st->key_prefix != NULL) ? strlen(st->key_prefix) : 0;

    if (sd_ceph_set_errno(rados_nobjects_list_open(st->ioctx, &lc))) {
        return NGX_ERROR;
    }

    while (rados_nobjects_list_next(lc, &oid, NULL, NULL) == 0) {
        char                    pfn[1024];
        const char             *key_name;
        brix_sd_catalog_ent_t ent;
        uint64_t                size = 0;
        time_t                  mtime = 0;

        if (sd_ceph_oid_is_stripe_data(oid)) {
            continue;                  /* data stripe → counted by its first stripe */
        }
        if (sd_ceph_oid_is_first_stripe(oid)) {
            if (sd_ceph_oid_to_pfn(oid, pfn, sizeof(pfn)) != 0) {
                continue;              /* unrepresentable physical name → skip */
            }
            key_name = pfn;            /* the striper file's physical name */
        } else {
            key_name = oid;            /* flat object: it IS its own key */
        }

        ngx_memzero(&ent, sizeof(ent));
        ent.key  = key_name;
        ent.path = (plen == 0)
                   ? key_name
                   : (strncmp(key_name, st->key_prefix, plen) == 0
                          ? key_name + plen     /* recovered logical path */
                          : NULL);              /* outside prefix → orphan candidate */
        if (want_stat && rados_stat(st->ioctx, oid, &size, &mtime) == 0) {
            ent.have_stat = 1;
            ent.size  = (off_t) size;
            ent.mtime = mtime;
        }
        if (cb(ctx, &ent) != 0) {
            break;                     /* caller asked to stop — not an error */
        }
    }

    rados_nobjects_list_close(lc);
    return NGX_OK;
}

#endif /* BRIX_HAVE_CEPH */
