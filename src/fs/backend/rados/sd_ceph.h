/*
 * sd_ceph.h — Ceph/RADOS storage driver (phase-60, basic librados backend).
 *
 * WHAT: Declares (a) the always-available, dependency-free LFN->object-key
 *       helpers (lexical path normalization + key composition + a stable inode
 *       hash) that map a confined logical path to a flat RADOS object id, and
 *       (b) — only when the build found librados (BRIX_HAVE_CEPH) — the
 *       per-export config struct the config layer fills and the driver vtable
 *       symbol the registry registers.
 *
 * WHY:  RADOS is a flat object store: there is no kernel fd, no directory tree,
 *       no atomic rename. The driver therefore needs a deterministic, injective,
 *       escape-proof LFN->oid map (two logical paths must never alias one object,
 *       and no `..` may address an object outside the export's key prefix). That
 *       map is pure string logic with no librados/nginx dependency, so it is
 *       split out here and unit-tested standalone (sd_ceph_unittest.c) without a
 *       live cluster.
 *
 * HOW:  The helpers are plain C (libc only). The driver body (sd_ceph.c, under
 *       #if BRIX_HAVE_CEPH) implements the worker-safe raw byte ops and the
 *       minimal namespace ops against raw librados (rados_read/write/trunc/stat/
 *       remove). libradosstriper interop with stock XrdCeph (ADR-3) is a follow-on.
 */
#ifndef BRIX_SD_CEPH_H
#define BRIX_SD_CEPH_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * sd_ceph_normalize — lexically canonicalize a logical path into `out` (cap
 * bytes): collapse repeated/leading/trailing '/', drop "." components, and apply
 * ".." by popping the previous component. A ".." that would climb above the root
 * is rejected (escape attempt). The result always begins with '/', has no "."/
 * ".." and no "//", and never ends in '/' (except the bare root "/"). Returns 0,
 * or -1 with errno set (EINVAL on bad args / escape, ENAMETOOLONG if it won't
 * fit). This is the single point that guarantees the LFN->oid map is injective
 * and prefix-confined.
 */
int sd_ceph_normalize(const char *lfn, char *out, size_t cap);

/*
 * sd_ceph_key — compose the RADOS object id for a logical path:
 * `key_prefix` followed by sd_ceph_normalize(lfn). Returns 0, or -1 (errno) when
 * normalization fails or the result won't fit in `out` (cap bytes).
 */
int sd_ceph_key(const char *key_prefix, const char *lfn, char *out, size_t cap);

/*
 * sd_ceph_ino — a stable 64-bit inode number synthesized from an object id
 * (FNV-1a). RADOS objects have no inode; protocol stat needs a stable, distinct
 * value per object, and a content-independent hash of the (already-confined) oid
 * provides one.
 */
uint64_t sd_ceph_ino(const char *oid);

#if BRIX_HAVE_CEPH
#include "fs/backend/sd.h"
#include <rados/librados.h>   /* rados_ioctx_t in the shared oid-level API */

/*
 * Per-export Ceph configuration, populated by the config/merge layer and passed
 * to the driver's init() as driver_conf. Strings are borrowed for the duration
 * of init() (the driver copies what it keeps). `pool` is required; the rest take
 * the documented defaults when NULL.
 */
typedef struct {
    const char *conf_file;    /* ceph.conf (default /etc/ceph/ceph.conf) */
    const char *pool;         /* RADOS pool (REQUIRED)                    */
    const char *user;         /* ceph user (default client.admin)        */
    const char *keyring;      /* optional keyring path override           */
    const char *key_prefix;   /* object-key prefix (default "")           */
} brix_sd_ceph_conf_t;

/* The Ceph driver descriptor (defined in sd_ceph.c, registered by sd_registry.c). */
extern const brix_sd_driver_t brix_sd_ceph_driver;

/* ---- shared oid-level layer ------------------------------------------------
 * A bare cluster connection + ioctx, plus byte/xattr operations keyed by an
 * explicit RADOS object id (rather than a logical path). The flat sd_ceph driver
 * builds its connection through sd_ceph_conn_create() and issues object I/O
 * through these; the read-only cephfs driver and the recovery tools reuse this
 * layer to read raw RADOS objects and omaps. All return -1/errno (or a short
 * count) on failure, mirroring the flat driver's conventions. */
typedef struct sd_ceph_conn_s sd_ceph_conn_t;

sd_ceph_conn_t *sd_ceph_conn_create(const brix_sd_ceph_conf_t *conf,
                                    ngx_pool_t *pool, int *err);
void            sd_ceph_conn_destroy(sd_ceph_conn_t *c);
rados_ioctx_t   sd_ceph_conn_ioctx(sd_ceph_conn_t *c);

ssize_t sd_ceph_oid_read (sd_ceph_conn_t *c, const char *oid, void *buf,
                          size_t len, off_t off);
ssize_t sd_ceph_oid_write(sd_ceph_conn_t *c, const char *oid, const void *buf,
                          size_t len, off_t off);
int     sd_ceph_oid_stat (sd_ceph_conn_t *c, const char *oid, uint64_t *size,
                          time_t *mtime);
int     sd_ceph_oid_trunc(sd_ceph_conn_t *c, const char *oid, uint64_t len);
int     sd_ceph_oid_remove(sd_ceph_conn_t *c, const char *oid);

ssize_t sd_ceph_oid_getxattr (sd_ceph_conn_t *c, const char *oid,
                              const char *name, void *buf, size_t cap);
ssize_t sd_ceph_oid_listxattr(sd_ceph_conn_t *c, const char *oid,
                              void *buf, size_t cap);
int     sd_ceph_oid_setxattr (sd_ceph_conn_t *c, const char *oid,
                              const char *name, const void *val, size_t len);
int     sd_ceph_oid_rmxattr  (sd_ceph_conn_t *c, const char *oid,
                              const char *name);

/* ---- cephfsro: read-only CephFS-via-RADOS driver (sd_cephfs_ro.c) ----------
 * Serves a real CephFS by reading its metadata-pool omaps + data-pool objects
 * directly, for when CephFS cannot be mounted. READ-ONLY: every mutating slot is
 * absent. The filesystem MUST be quiesced (MDS down / fs failed, journal flushed)
 * — the namespace a pure-RADOS reader sees is only consistent then — so init
 * refuses to bind unless `assume_quiesced` is set (operator assertion; there is
 * no active MDS probing). See docs/superpowers/specs/2026-06-30-cephfs-rados-
 * program-design.md. */
typedef struct {
    const char *meta_pool;    /* CephFS metadata pool (REQUIRED)              */
    const char *data_pool;    /* CephFS data pool (REQUIRED)                  */
    const char *conf_file;    /* ceph.conf (default /etc/ceph/ceph.conf)      */
    const char *user;         /* ceph user (default client.admin)            */
    const char *keyring;      /* optional keyring path override               */
    int         assume_quiesced; /* operator assertion: fs is frozen          */
    int         live;            /* operator assertion: fs still mounted —
                                  * best-effort eventually-consistent reads with
                                  * optimistic revalidation + retry. One of
                                  * assume_quiesced / live MUST be set.        */
} brix_sd_cephfs_ro_conf_t;

extern const brix_sd_driver_t brix_sd_cephfs_ro_driver;

#endif /* BRIX_HAVE_CEPH */

#endif /* BRIX_SD_CEPH_H */
