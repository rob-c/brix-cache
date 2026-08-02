/*
 * brixcvmfs_split.h — private Phase-38 split contract for the CVMFS-brix FUSE
 * driver, shared ONLY between brixcvmfs.c and its siblings
 * (brixcvmfs_transport.c / _prefetch.c / _ops.c / _mount.c).
 *
 * WHAT: the process-global mount state and the handful of routines that cross a
 *       TU boundary after the driver was split by concern (transport, prefetch,
 *       FUSE ops, mount bring-up, front-end).
 * WHY:  not a public API — the rw union driver still binds through
 *       brixcvmfs_internal.h's accessor seam. This header exists so the split
 *       TUs can reach one another's globals/entry points without widening the
 *       rw contract or reintroducing a monolith.
 * HOW:  each extern names the TU that DEFINES it; every consumer includes this
 *       header. Single-threaded mount (-s), so the globals need no locking
 *       beyond what the transport's own dict mutex already provides.
 */
#ifndef BRIXCVMFS_SPLIT_H
#define BRIXCVMFS_SPLIT_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif
#include <fuse3/fuse.h>
#include <stddef.h>

#include "cvmfs/client/client.h"   /* cvmfs_client_t */
#include "net/cpool.h"             /* brix_status (via brix.h) */

/* ---- transport config — DEFINED in brixcvmfs_transport.c ----------------- *
 * Seeded by the mount pipeline (brixcvmfs_build_transport_cfg) before the
 * first fetch; read on every libcurl request. */
typedef struct {
    char repo[256];
    long connect_timeout_s;
    long low_speed_time_s;
    long low_speed_bytes;
    int  max_retries;      /* per-mirror retries (CVMFS_MAX_RETRIES) */
    int  fresh_connect;    /* -o fresh: FRESH_CONNECT + FORBID_REUSE (defeat DPI) */
    int  prefer_tls;       /* -o tls: try https:// before http:// */
} brixcvmfs_transport_cfg_t;
extern brixcvmfs_transport_cfg_t g_tcfg;

/* ---- process-global mounted client — DEFINED in brixcvmfs.c ------------- */
extern cvmfs_client_t *g_cl;
const char *cat_path(const char *p);   /* FUSE "/" → catalog root "" */
long        mono_now(void);            /* CLOCK_MONOTONIC seconds */

/* CAS object size class; shared with --prewarm's whole-tree sweep. */
#define BRIX_PF_OBJCAP (32u * 1024u * 1024u)

/* ---- libcurl transport seam (brixcvmfs_transport.c) --------------------- */
int  brixcvmfs_transport(const char *proxy, const char *host, const char *rel,
                         unsigned char *out, size_t outcap, size_t *outlen, void *ud);
int  bundle_http_post(const char *proxy, const char *host,
                      const char *body, size_t body_len,
                      unsigned char *out, size_t outcap, size_t *outlen);
int  brixcvmfs_transport_pool_init(brix_status *st);   /* mount-time pool bring-up */
void transport_cleanup(void);
void brixcvmfs_dict_arm(void);    /* G3: arm shared-dict coding for this mount */
void brixcvmfs_dict_free(void);   /* release the memory-pinned dict at unmount */

/* ---- predictive prefetch worker (brixcvmfs_prefetch.c) ------------------ */
void pf_enqueue(const char *path);
void pf_start(int depth, long budget, const char *tmp_dir, const char *cache_dir,
              int cache_dirfd, long quota, int bundle);

/* ---- read-only FUSE op table (brixcvmfs_ops.c) -------------------------- */
extern const struct fuse_operations brixcvmfs_ops;

/* ---- trust-chain mount + verify/prewarm commands (brixcvmfs_mount.c) ---- */
cvmfs_client_t *brixcvmfs_open(const char *repo, const char *cache_dir_override,
                               int cache_dirfd, long quota_override, int retries_override,
                               const char *pin_opt, int packed_opt, int tiering_opt);
int  brixcvmfs_check(const char *repo);
int  brixcvmfs_prewarm(const char *repo);
void brixcvmfs_prepare_cache_dir(const char *repo, const char *cache_dir_override,
                                 int cache_dirfd, char *cache_dir, size_t cap);

#endif /* BRIXCVMFS_SPLIT_H */
