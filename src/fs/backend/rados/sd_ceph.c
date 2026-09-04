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
#include "fs/path/site_n2n.h" /* brix_n2n_canonicalize — the shared canonicalizer */

#include <errno.h>
#include <string.h>

/* ===================================================================== *
 * Pure LFN -> object-key mapping (always compiled; no librados, no nginx) *
 * ===================================================================== */

/* sd_ceph_normalize — see sd_ceph.h. The RADOS key map's canonicalizer is now
 * the single shared one in site_n2n.c (brix_n2n_canonicalize): it folds empty
 * "//" segments and "." components and REJECTS any ".." (phase-108 C13 — the
 * driver no longer resolves ".." by popping; a confined path never carries one,
 * and one that arrives some other way is refused, not silently rewritten).
 * errno is set by the shared canonicalizer (EINVAL / ENAMETOOLONG). */
int
sd_ceph_normalize(const char *lfn, char *out, size_t cap)
{
    return brix_n2n_canonicalize(lfn, out, cap);
}

/* sd_ceph_prefix_cfg — build the driver's CEPHFS_PATH translation cfg from a
 * `key_prefix`. A RADOS object name is that prefix followed by the canonicalized
 * LFN (the pool is bound at the ioctx, not emitted in the name), which is exactly
 * the shared CEPHFS_PATH scheme. Shared by the forward key composition
 * (sd_ceph_key) and the reverse listing recovery (sd_ceph_enumerate_io) so both
 * directions read one definition. Returns 0, or -1/ENAMETOOLONG when the prefix
 * would not fit the scheme's field (composing it would silently address a
 * DIFFERENT object — fail closed). */
int
sd_ceph_prefix_cfg(const char *key_prefix, brix_n2n_cfg_t *cfg)
{
    size_t plen = (key_prefix != NULL) ? strlen(key_prefix) : 0;

    if (plen >= sizeof(cfg->prefix)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(cfg, 0, sizeof(*cfg));       /* zero pool/prefix; unused for this scheme */
    cfg->scheme = BRIX_N2N_CEPHFS_PATH;
    if (plen > 0) {
        memcpy(cfg->prefix, key_prefix, plen + 1);   /* incl. NUL */
    }
    return 0;
}

/* sd_ceph_key — the object key is `key_prefix` followed by the canonicalized
 * LFN. This is exactly the shared translation's CEPHFS_PATH scheme (prefix +
 * canonical path), so the body delegates to brix_n2n_lfn2pfn rather than carry a
 * second copy of the compose-and-bound logic (phase-108 C13). The 14 call sites,
 * their `oid` buffers, and their error handling are untouched. See sd_ceph.h. */
int
sd_ceph_key(const char *key_prefix, const char *lfn, char *out, size_t cap)
{
    brix_n2n_cfg_t cfg;

    if (sd_ceph_prefix_cfg(key_prefix, &cfg) != 0) {
        return -1;                                   /* errno set (ENAMETOOLONG) */
    }
    return brix_n2n_lfn2pfn(&cfg, lfn, out, cap);
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

/* The Ceph driver descriptor. Honest caps: range read, random write, truncate,
 * xattr, staged write, catalog enumeration, and synthetic directories (CAP_DIRS,
 * phase-89 §B: the opendir/readdir slots collapse the flat key namespace to one
 * hierarchical level per listing). No CAP_FD/SENDFILE (no fd; VFS serves
 * memory-backed) and no CAP_HARD_RENAME — rename is copy+delete (ADR-5).
 * The op functions live in the sibling TUs (sd_ceph_io.c / sd_ceph_object.c /
 * sd_ceph_dir.c / sd_ceph_cred.c) and are declared in sd_ceph_internal.h. */
const brix_sd_driver_t brix_sd_ceph_driver = {
    .name = "ceph",
    /* XATTR: the get/set/removexattr slots store object xattrs via rados_*xattr,
     * so a ceph object can carry the cinfo/meta records (phase-64 SP3 cache-store
     * role, XATTR cinfo mode - the cache state lives on the RADOS object itself). */
    .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_XATTR
          | BRIX_SD_CAP_XATTR_WRITE | BRIX_SD_CAP_MEMFILE
          | BRIX_SD_CAP_CATALOG | BRIX_SD_CAP_DIRS,

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
    /* C4: N rados_remove on one ioctx; no CAP_BULK_DELETE - a loop, not a
     * wire batch, so only the flat client batch reaches it wide. */
    .unlink_many = sd_ceph_unlink_many,
    .mkdir  = sd_ceph_mkdir,      /* synthetic no-op create (phase-89 ADR-1) */
    .rename = sd_ceph_rename,     /* copy+delete, no CAP_HARD_RENAME (ADR-5) */
    .truncate_path = sd_ceph_truncate_path,   /* rados_trunc needs no handle */

    .opendir  = sd_ceph_opendir,  /* stripe-collapse listing (phase-89 §B.1) */
    .readdir  = sd_ceph_readdir,
    .closedir = sd_ceph_closedir,

    .getxattr    = sd_ceph_getxattr,
    .listxattr   = sd_ceph_listxattr,
    .setxattr    = sd_ceph_setxattr,
    .removexattr = sd_ceph_removexattr,

    /* Advisory POSIX metadata (sd_ceph_meta.c): RADOS has no mode/owner of its
     * own, so chmod/kXR_setattr is persisted as the reserved xattr blob every
     * object backend shares and overlaid on stat. Without the slot the VFS
     * treated the absence as "nothing to do" and the client was told a change
     * it never got had succeeded. */
    .setattr     = sd_ceph_setattr,

    /* Checksum offload (sd_ceph_meta.c): the OSDs hash the bytes where they
     * already are, instead of the gateway pulling the whole object back to hash
     * it. crc32c only — see the slot for why a striped object declines. */
    .query_checksum = sd_ceph_query_checksum,

    .staged_open   = sd_ceph_staged_open,
    .staged_write  = sd_ceph_staged_write,
    .staged_commit = sd_ceph_staged_commit,
    .staged_abort  = sd_ceph_staged_abort,

    .enumerate     = sd_ceph_enumerate,

    /* Capacity is the CLUSTER's, not the gateway spool statvfs would measure. */
    .space         = sd_ceph_space,

    /* Credential-scoped NAMESPACE slots (sd_ceph_ns_cred.c). Without these the
     * per-user keyring reached only the data plane and every metadata op ran as
     * the export service account — the confused deputy documented there. The
     * absentees are deliberate: rename_cred (the copy runs on the export's
     * striper), staged_open_cred (the stage would have to pin a connection
     * across commit and abort) and mkdir_cred (a synthetic mkdir touches no
     * object, so there is no cluster-side authority to scope). */
    .stat_cred           = sd_ceph_stat_cred,
    .unlink_cred         = sd_ceph_unlink_cred,
    .unlink_many_cred    = sd_ceph_unlink_many_cred,   /* C4: one ioctx per window */
    .truncate_path_cred  = sd_ceph_truncate_path_cred,
    .getxattr_cred       = sd_ceph_getxattr_cred,
    .listxattr_cred      = sd_ceph_listxattr_cred,
    .setxattr_cred       = sd_ceph_setxattr_cred,
    .removexattr_cred    = sd_ceph_removexattr_cred,
    .setattr_cred        = sd_ceph_setattr_cred,
    .opendir_cred        = sd_ceph_opendir_cred,
};

#endif /* BRIX_HAVE_CEPH */
