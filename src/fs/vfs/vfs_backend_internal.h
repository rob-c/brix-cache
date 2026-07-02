/*
 * vfs_backend_internal.h — the backend-registry entry table, shared between the
 * registry's two translation units.
 *
 * WHAT: The per-export entry type and the two table accessors that
 *       vfs_backend_config.c (config-time: directive parsing, per-driver
 *       builders, credential/tier setters) and vfs_backend_registry.c
 *       (runtime: source build, decorator composition, resolve) both need.
 * WHY:  Phase-38 file-size split of the former single vfs_backend_registry.c.
 *       The entry table itself stays private to vfs_backend_registry.c; the
 *       config side reaches it only through the accessors, so ownership of
 *       the storage (and the resolve/build lifecycle) remains in one file.
 * HOW:  Nothing here is part of the public API — include
 *       fs/vfs_backend_registry.h for that.
 */
#ifndef XROOTD_VFS_BACKEND_INTERNAL_H
#define XROOTD_VFS_BACKEND_INTERNAL_H

#include "vfs_backend_registry.h"
#include "fs/tier/tier.h"

#include <limits.h>

/* One registered export. `inst` is per-worker (copy-on-write after fork): the
 * master leaves it NULL at config time; each worker fills its own on first use. */
typedef struct {
    char                  root_canon[PATH_MAX];
    char                  backend[16];   /* "pblock" | "xroot" */
    int64_t               block_size;
    char                  origin_host[256];   /* xroot/http: remote origin host */
    int                   origin_port;
    int                   origin_tls;
    int                   origin_family;       /* xrootd_af_policy_t for origin connect */
    char                  origin_path[1024];  /* http: URL base path ("" / "/sub") */
    /* phase-68 T11: additional ranked http endpoints (endpoint 0 is
     * origin_host/port/tls/path above; these are the remaining pipe-separated
     * failover origins in configured order). */
    struct {
        char host[128];
        int  port;
        int  tls;
        char base[256];
    }                     http_extra[7];
    int                   n_http_extra;
    char                  origin_token[4096]; /* §14: bearer token for the source
                                               * upstream ("" = anonymous) */
    char                  origin_x509_proxy[1024]; /* §14/C-3 GSI: proxy PEM path */
    char                  origin_ca_dir[1024];      /* §14/C-3 GSI: origin-cert CA */
    char                  origin_s3_access_key[256]; /* §14 S3 SigV4: access-key id */
    char                  origin_s3_secret_key[256]; /* §14 S3 SigV4: secret key    */
    char                  origin_s3_region[64];      /* §14 S3 SigV4: region scope  */
    char                  origin_sss_keytab[1024];   /* §14 SSS: shared-secret keytab*/
    int                   staging;       /* xroot: stage local + promote on commit */
    /* ceph backend: the export's namespace + data live in a RADOS pool (no local
     * dir); root_canon is just the logical mount point. */
    char                  ceph_pool[256];
    char                  ceph_conf[1024];
    char                  ceph_key_prefix[256];
    /* cephfsro (read-only CephFS-via-RADOS): ceph_pool holds the METADATA pool,
     * ceph_data_pool the DATA pool; cephfs_quiesced is the operator's safety
     * assertion (carried in the backend URI as "?assume_quiesced=1"). */
    char                  ceph_data_pool[256];
    int                   cephfs_quiesced;
    int                   cephfs_live;
    /* phase-64 composable tiers (additive over the flat backend above): when a
     * cache/stage tier is configured, entry_build wraps the source in the
     * sd_stage / sd_cache decorators. */
    xrootd_tier_cfg_t      cache_tier;
    xrootd_cache_policy_t  cache_policy;
    xrootd_tier_cfg_t      stage_tier;
    xrootd_stage_policy_t  stage_policy;
    xrootd_sd_instance_t *inst;          /* lazily built per worker, or NULL */
} xrootd_vfs_backend_entry_t;

/* Exports are few (one per location/server block); a small fixed table avoids any
 * allocation and is scanned linearly. */
#define XROOTD_VFS_BACKEND_MAX 64

/* Find a registered entry by exact root_canon, or NULL. */
xrootd_vfs_backend_entry_t *xrootd_vfs_backend_entry_find(const char *root_canon);

/* Find or create the entry for root_canon (backend "" = default POSIX source);
 * NULL when the table is full. */
xrootd_vfs_backend_entry_t *xrootd_vfs_backend_entry_get_or_create(
    const char *root_canon);

#endif /* XROOTD_VFS_BACKEND_INTERNAL_H */
