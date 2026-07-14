/*
 * sd_ceph.c — Ceph/RADOS Storage Driver (phase-60, basic librados backend).
 *
 * WHAT: brix_sd_ceph_driver — a backend that maps the VFS's logical paths onto
 *       flat RADOS objects via raw librados (rados_read/write/trunc/stat/remove).
 *       Two layers live here:
 *         1. The pure LFN->object-key map (sd_ceph_normalize/_key/_ino) — libc
 *            only, always compiled, unit-tested standalone (sd_ceph_unittest.c).
 *         2. The driver vtable — only when the build found librados
 *            (BRIX_HAVE_CEPH); otherwise this file is just the pure helpers and
 *            the build is byte-for-byte unchanged (the driver row in
 *            sd_registry.c is #if-guarded too).
 *
 *       The driver body has been split (source-size guard) across four TUs:
 *       sd_ceph.c keeps the pure helpers, the instance lifecycle (init/cleanup +
 *       the cluster-connect primitive) and the driver descriptor; sd_ceph_io.c
 *       holds the raw byte ops, staged write and the shared connection layer;
 *       sd_ceph_object.c the object open/close/stat/unlink + xattr slots; and
 *       sd_ceph_cred.c the per-user cred-conn cache, cred-scoped open, the
 *       oid-keyed byte/xattr layer and catalog enumeration. The shared struct
 *       definitions and cross-TU declarations live in sd_ceph_internal.h.
 *
 * WHY:  RADOS has no kernel fd, no sendfile, no directory tree and no atomic
 *       rename, so this driver advertises only range-read / random-write /
 *       truncate (see .caps). The VFS already serves a no-CAP_FD backend memory-
 *       backed and degrades the absent namespace/rename/xattr ops — the data
 *       plane (root:// read/write, WebDAV/S3 GET/PUT) rides the same VFS seam as
 *       POSIX once the handle path is de-fd'd (phase-60 W0).
 *
 * HOW:  One rados_t + ioctx per export instance, connected at init() on the event
 *       loop (worker init); the blocking rados_* calls are meant to run on the
 *       nginx thread pool (phase-60 §8 / ADR-4). Object handles carry the object
 *       id + a cached size; the raw byte ops are worker-safe (no pool/log/metrics).
 *       libradosstriper (large-object striping + stock XrdCeph on-disk interop,
 *       ADR-3) is a deliberate follow-on; this basic backend uses raw librados.
 *       Per-user credential scoping (ceph-peruser item): the driver also
 *       implements .open_cred (sd_ceph_open_cred), which authenticates to
 *       RADOS as a specific CephX user (parsed from a <key>.keyring file by
 *       fs/backend/ucred.c) instead of the export's static service
 *       credential. A bounded per-(user,keyring) connection-cache LRU on the
 *       instance state amortizes the rados_connect cost across repeated
 *       opens by the same user; every raw byte op (pread/pwrite/ftruncate/
 *       fstat) is keyed off the OPEN object's own ioctx (sd_ceph_obj_state_t.
 *       ioctx), not the export's, so a cred-scoped open stays scoped to that
 *       user for its whole lifetime.
 *
 *       Cred-conn lifetime (pin/refcount, fixes a UAF): a cred-scoped
 *       sd_ceph_conn_t is reference-counted (sd_ceph_conn_t.refs), pinned by
 *       every open object that resolved onto it (sd_ceph_obj_state_t.conn)
 *       and released in sd_ceph_close. The bounded LRU never destroys a
 *       pinned (refs>0) connection: eviction skips pinned slots, and if a
 *       pinned slot is chosen to make room in the cache table it is marked
 *       `doomed` and removed from the table WITHOUT destroying the
 *       connection — the connection is destroyed by whichever sd_ceph_close
 *       drops its refcount to zero. If every cache slot is pinned, a fresh
 *       *uncached* connection is created for that one open (never inserted
 *       into the table, pinned for the object's lifetime, destroyed on
 *       close) so a legitimate concurrent identity beyond the cache bound
 *       still works instead of failing the open.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* pure striper-layout helpers (catalog enumeration) */

#include <errno.h>
#include <string.h>

/* ===================================================================== *
 * Pure LFN -> object-key mapping (always compiled; no librados, no nginx) *
 * ===================================================================== */

/* sd_ceph_seg_t — one path segment carved out of an LFN during normalization:
 * the pointer into the source string and its length (not NUL-terminated). */
typedef struct {
    const char *start;
    size_t      len;
} sd_ceph_seg_t;

/* sd_ceph_next_seg — advance a cursor to the next non-empty path segment.
 *
 * WHAT: From `*cursor`, skip the run of '/' separators, then capture the next
 *       run of non-'/' bytes into `*seg`. Returns 1 when a segment was found
 *       (and advances `*cursor` past it), or 0 at end of string.
 *
 * WHY:  Isolates the pointer-walking tokenizer from the segment-classification
 *       logic in sd_ceph_normalize, so that function reads as a flat loop over
 *       already-carved segments instead of interleaving scan and decision.
 *
 * HOW:  1. Skip leading '/' separators. 2. If at end, report no segment.
 *       3. Mark the segment start, walk to the next '/' or NUL, record the
 *          length, and leave the cursor at the delimiter. */
static int
sd_ceph_next_seg(const char **cursor, sd_ceph_seg_t *seg)
{
    const char *p = *cursor;

    while (*p == '/') {               /* skip run of slashes */
        p++;
    }
    if (*p == '\0') {
        *cursor = p;
        return 0;
    }

    seg->start = p;
    while (*p != '\0' && *p != '/') {
        p++;
    }
    seg->len = (size_t) (p - seg->start);
    *cursor  = p;
    return 1;
}

/* sd_ceph_norm_pop — remove the last component from the canonical buffer for a
 * ".." segment. Returns the new write cursor, or (size_t)-1 for an escape above
 * the root (nothing to pop) so the caller can fail the normalization. */
static size_t
sd_ceph_norm_pop(char *out, size_t w)
{
    if (w == 0) {
        return (size_t) -1;           /* escape above the root */
    }
    while (w > 0 && out[w - 1] != '/') {
        w--;                          /* back over the last component */
    }
    if (w > 0) {
        w--;                          /* drop its leading '/' */
    }
    out[w] = '\0';
    return w;
}

/* sd_ceph_norm_append — append one ordinary segment (as "/<seg>") to the
 * canonical buffer at write cursor `w`. Returns the new cursor, or (size_t)-1
 * when the segment would not fit within `cap` (caller sets ENAMETOOLONG). */
static size_t
sd_ceph_norm_append(char *out, size_t cap, size_t w, const sd_ceph_seg_t *seg)
{
    if (w + 1 + seg->len + 1 > cap) {
        return (size_t) -1;
    }
    out[w++] = '/';
    memcpy(out + w, seg->start, seg->len);
    w += seg->len;
    out[w] = '\0';
    return w;
}

/* sd_ceph_seg_is_dot / sd_ceph_seg_is_dotdot — classify a carved segment as the
 * "." (self) or ".." (parent) special components. */
static int
sd_ceph_seg_is_dot(const sd_ceph_seg_t *seg)
{
    return seg->len == 1 && seg->start[0] == '.';
}

static int
sd_ceph_seg_is_dotdot(const sd_ceph_seg_t *seg)
{
    return seg->len == 2 && seg->start[0] == '.' && seg->start[1] == '.';
}

/* sd_ceph_normalize — see sd_ceph.h. Builds the canonical path in `out` by
 * walking segments: skip empties and ".", pop on "..", append otherwise. A ".."
 * with nothing to pop is an escape above the root and is rejected. */
int
sd_ceph_normalize(const char *lfn, char *out, size_t cap)
{
    const char   *cursor = lfn;
    sd_ceph_seg_t seg = {0};
    size_t        w = 0;

    if (lfn == NULL || out == NULL || cap < 2) {
        errno = EINVAL;
        return -1;
    }
    out[0] = '\0';

    while (sd_ceph_next_seg(&cursor, &seg)) {
        if (sd_ceph_seg_is_dot(&seg)) {
            continue;                 /* "." — no-op */
        }
        if (sd_ceph_seg_is_dotdot(&seg)) {
            w = sd_ceph_norm_pop(out, w);
            if (w == (size_t) -1) {
                errno = EINVAL;       /* escape above the root */
                return -1;
            }
            continue;
        }
        w = sd_ceph_norm_append(out, cap, w, &seg);
        if (w == (size_t) -1) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }

    if (w == 0) {                     /* everything collapsed -> bare root */
        out[0] = '/';
        out[1] = '\0';
    }
    return 0;
}

/* sd_ceph_key — prefix + sd_ceph_normalize(lfn). See sd_ceph.h. */
int
sd_ceph_key(const char *key_prefix, const char *lfn, char *out, size_t cap)
{
    char   norm[1024];
    size_t plen = (key_prefix != NULL) ? strlen(key_prefix) : 0;
    size_t nlen;

    if (sd_ceph_normalize(lfn, norm, sizeof(norm)) != 0) {
        return -1;
    }
    nlen = strlen(norm);

    if (plen + nlen + 1 > cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (plen > 0) {
        /* phase74-fp: prefix copy is intentionally unterminated — the next
         * memcpy appends norm with its NUL (nlen + 1), and the cap check above
         * guarantees room for plen + nlen + 1. */
        memcpy(out, key_prefix, plen);  /* NOLINT(bugprone-not-null-terminated-result) */
    }
    memcpy(out + plen, norm, nlen + 1);
    return 0;
}

/* sd_ceph_ino — FNV-1a/64 over the object id. See sd_ceph.h. */
uint64_t
sd_ceph_ino(const char *oid)
{
    const unsigned char *p = (const unsigned char *) oid;
    uint64_t             h = 1469598103934665603ULL;   /* FNV offset basis */

    while (*p != '\0') {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;                          /* FNV prime */
    }
    return h;
}

/* ===================================================================== *
 * librados driver (only when the build found librados)                   *
 * ===================================================================== */
#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* libradosstriper read path (stock XrdCeph layout) */
#include <time.h>

#include "sd_ceph_internal.h"  /* shared struct defs + cross-TU declarations */

/* sd_ceph_pstrdup — copy a C string onto the instance pool (NULL-safe source
 * yields NULL). Keeps the driver's retained strings on the export-lifetime pool. */
static char *
sd_ceph_pstrdup(ngx_pool_t *pool, const char *s)
{
    size_t  n;
    char   *d;

    if (s == NULL) {
        return NULL;
    }
    n = strlen(s) + 1;
    d = ngx_pnalloc(pool, n);
    if (d != NULL) {
        memcpy(d, s, n);
    }
    return d;
}

/* sd_ceph_set_errno — librados returns 0/negative-errno; translate a negative rc
 * into errno and the driver's failure code, returning 1 iff rc indicated error.
 * Non-static: shared across the driver's four TUs (sd_ceph_internal.h). */
int
sd_ceph_set_errno(int rc)
{
    if (rc < 0) {
        errno = -rc;
        return 1;
    }
    return 0;
}

/* instance lifecycle (event loop / worker init) */

/* sd_ceph_user_id — librados wants the entity id without the "client." prefix
 * (rados_create prepends "client."); a NULL id selects the default client.admin. */
static const char *
sd_ceph_user_id(const char *user)
{
    if (user != NULL && strncmp(user, "client.", 7) == 0) {
        return user + 7;
    }
    return user;
}

/* sd_ceph_cluster_connect — create + configure + connect a rados cluster handle
 * and open the pool ioctx. Shared by the flat driver's init and the oid-level
 * connection (sd_ceph_conn_create). 0 / -1 with errno; on failure nothing leaks.
 * Non-static: sd_ceph_conn_create lives in sd_ceph_io.c (sd_ceph_internal.h). */
int
sd_ceph_cluster_connect(const char *conf_file, const char *user,
    const char *keyring, const char *pool,
    rados_t *cluster_out, rados_ioctx_t *ioctx_out)
{
    rados_t       cluster;
    rados_ioctx_t ioctx;

    if (sd_ceph_set_errno(rados_create(&cluster, sd_ceph_user_id(user)))) {
        return -1;
    }
    if (sd_ceph_set_errno(rados_conf_read_file(cluster,
            conf_file ? conf_file : "/etc/ceph/ceph.conf")))
    {
        rados_shutdown(cluster);
        return -1;
    }
    if (keyring != NULL) {
        rados_conf_set(cluster, "keyring", keyring);
    }
    if (sd_ceph_set_errno(rados_connect(cluster))) {
        rados_shutdown(cluster);
        return -1;
    }
    if (sd_ceph_set_errno(rados_ioctx_create(cluster, pool, &ioctx))) {
        rados_shutdown(cluster);
        return -1;
    }
    *cluster_out = cluster;
    *ioctx_out   = ioctx;
    return 0;
}

/* sd_ceph_init — resolve config onto the pool, create + configure + connect the
 * cluster handle, and open the pool ioctx. Any failure tears down what was built
 * and returns NGX_ERROR with errno set so the export fails closed at init. */
static ngx_int_t
sd_ceph_init(brix_sd_instance_t *inst, void *driver_conf)
{
    brix_sd_ceph_conf_t *dc = driver_conf;
    sd_ceph_state_t       *st;

    if (dc == NULL || dc->pool == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    st->pool       = sd_ceph_pstrdup(inst->pool, dc->pool);
    st->user       = sd_ceph_pstrdup(inst->pool, dc->user);
    st->conf_file  = sd_ceph_pstrdup(inst->pool,
                         dc->conf_file ? dc->conf_file : "/etc/ceph/ceph.conf");
    st->keyring    = sd_ceph_pstrdup(inst->pool, dc->keyring);
    st->key_prefix = sd_ceph_pstrdup(inst->pool,
                         dc->key_prefix ? dc->key_prefix : "");
    inst->state = st;

    if (sd_ceph_cluster_connect(st->conf_file, st->user, st->keyring, st->pool,
                                &st->cluster, &st->ioctx) != 0)
    {
        return NGX_ERROR;
    }
    st->connected = 1;
    return NGX_OK;
}

/* sd_ceph_cleanup — destroy the ioctx and shut the cluster handle down (a kernel/
 * network resource that must not leak across reconfig); the pool reclaims state.
 * Also destroys every cached per-user cred connection (ceph-peruser item) — each
 * holds its own rados_t/ioctx that would otherwise leak across a reconfig/reload
 * just like the export's own cluster handle would.
 *
 * A connection in the cache table at cleanup time is expected to have
 * refs==0: instance teardown only runs once every request/handle on this
 * export has drained (the VFS/protocol layers close all handles before an
 * instance is torn down), so nothing should still be pinning a cached
 * connection here. If that invariant were ever violated (an object somehow
 * outliving its instance), destroying it anyway is still the right call —
 * the instance and its pool are going away regardless, so there is no
 * "later close()" left to do the deferred destroy — but it is flagged with
 * a WARN so the anomaly is visible rather than silently masked. */
static void
sd_ceph_cleanup(brix_sd_instance_t *inst)
{
    sd_ceph_state_t *st = inst->state;
    ngx_uint_t        i;

    if (st == NULL) {
        return;
    }

    for (i = 0; i < st->cred_conn_count; i++) {
        if (st->cred_conns[i].conn != NULL) {
#if !defined(XRDPROTO_NO_NGX)
            /* ngx_log_error/NGX_LOG_WARN are unavailable in the ngx-free
             * standalone build (tests/ceph/'s live-test drivers link this
             * file directly with -DXRDPROTO_NO_NGX); the anomaly this warns
             * about is a should-never-happen invariant violation, not
             * something the standalone driver tests need to observe. */
            if (st->cred_conns[i].conn->refs > 0 && inst->log != NULL) {
                ngx_log_error(NGX_LOG_WARN, inst->log, 0,
                    "sd_ceph_cleanup: cred connection for user \"%s\" still "
                    "had %ui open handle(s) pinned at instance teardown "
                    "(destroying anyway)",
                    st->cred_conns[i].user,
                    (ngx_uint_t) st->cred_conns[i].conn->refs);
            }
#endif
            sd_ceph_conn_destroy(st->cred_conns[i].conn);
            st->cred_conns[i].conn = NULL;
        }
    }
    st->cred_conn_count = 0;

    if (st->connected) {
#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (st->striper_ready) {
            sd_ceph_striper_destroy(st->striper);
            st->striper_ready = 0;
        }
#endif
        rados_ioctx_destroy(st->ioctx);
        rados_shutdown(st->cluster);
        st->connected = 0;
    }
}

/* The Ceph driver descriptor. Honest caps: range read, random write, truncate —
 * no CAP_FD/SENDFILE (no fd; VFS serves memory-backed), no CAP_DIRS (flat key
 * namespace), no CAP_HARD_RENAME (no atomic rename). Directory iteration, rename,
 * xattr and staged commit are deliberately absent from this basic backend.
 * The op functions live in the sibling TUs (sd_ceph_io.c / sd_ceph_object.c /
 * sd_ceph_cred.c) and are declared in sd_ceph_internal.h. */
const brix_sd_driver_t brix_sd_ceph_driver = {
    .name = "ceph",
    /* XATTR: the get/set/removexattr slots store object xattrs via rados_*xattr,
     * so a ceph object can carry the cinfo/meta records (phase-64 SP3 cache-store
     * role, XATTR cinfo mode - the cache state lives on the RADOS object itself). */
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_XATTR_WRITE | BRIX_SD_CAP_MEMFILE
          | BRIX_SD_CAP_CATALOG,

    .init    = sd_ceph_init,
    .cleanup = sd_ceph_cleanup,
    .open    = sd_ceph_open,
    .open_cred = sd_ceph_open_cred,   /* per-user CephX keyring (ceph-peruser) */
    .close   = sd_ceph_close,

    .pread            = sd_ceph_pread,
    .pwrite           = sd_ceph_pwrite,
    .preadv           = sd_ceph_preadv,
    .preadv2          = sd_ceph_preadv2,
    .read_sendfile_fd = sd_ceph_read_sendfile_fd,
    .ftruncate        = sd_ceph_ftruncate,
    .fsync            = sd_ceph_fsync,
    .fstat            = sd_ceph_fstat,

    .stat   = sd_ceph_stat,
    .unlink = sd_ceph_unlink,

    .getxattr    = sd_ceph_getxattr,
    .listxattr   = sd_ceph_listxattr,
    .setxattr    = sd_ceph_setxattr,
    .removexattr = sd_ceph_removexattr,

    .staged_open   = sd_ceph_staged_open,
    .staged_write  = sd_ceph_staged_write,
    .staged_commit = sd_ceph_staged_commit,
    .staged_abort  = sd_ceph_staged_abort,

    .enumerate     = sd_ceph_enumerate,
};

#endif /* BRIX_HAVE_CEPH */
