/*
 * sd_cephfs_ro_internal.h — private declarations shared across the read-only
 * CephFS-via-RADOS driver's translation units.
 *
 * WHAT: The "cephfsro" driver is split across three .c files for file size and
 *       auditability — sd_cephfs_ro.c (lifecycle + open/read/stat/xattr + the
 *       driver descriptor), sd_cephfs_ro_resolve.c (the metadata-decode +
 *       inode-resolution path) and sd_cephfs_ro_dir.c (directory iteration). This
 *       header carries only the handful of symbols one file DEFINES and another
 *       REFERENCES: the per-export driver state, the retry/resolve helpers the
 *       data + directory paths call, and the directory vtable ops the descriptor
 *       wires up. Everything used within a single file stays static there.
 *
 * WHY:  Keeping cross-TU coupling to one small header makes the split auditable —
 *       no symbol leaks except the ones listed here.
 *
 * This header is only ever included from within a `#if BRIX_HAVE_CEPH` region
 * (the whole driver is an empty TU otherwise); it references librados-gated types
 * (sd_ceph_conn_t, brix_sd_* ) that exist only under that guard.
 */
#ifndef BRIX_SD_CEPHFS_RO_INTERNAL_H
#define BRIX_SD_CEPHFS_RO_INTERNAL_H

#include "sd_ceph.h"
#include "cephfs_layout.h"

/* per-export: connections to the metadata + data pools, plus the consistency
 * mode. `live` enables best-effort tracking of a still-mounted fs: optimistic
 * walk-version revalidation (detect an MDS write that landed mid-walk and retry)
 * and a bounded retry of a not-found whose path raced. `quiesced` mode trusts the
 * fs is frozen and only retries genuinely transient cluster errors. */
typedef struct {
    sd_ceph_conn_t *meta;
    sd_ceph_conn_t *data;
    int             live;
    int             max_retry;
} cephfsro_state_t;

/* ---- resolve/retry helpers (defined in sd_cephfs_ro_resolve.c) ------------- */

/* A transient cluster error is worth retrying regardless of consistency mode;
 * a permanent one is fast-failed. */
int  cephfsro_is_transient(int err);

/* Sleep an exponentially-growing, jittered, capped backoff before a retry. */
void cephfsro_backoff(int attempt);

/* Resolve an absolute logical path to its dentry with the consistency policy
 * applied (bounded transient retries always; live-mode optimistic revalidation).
 * Returns 0 (found) / 1 (absent, ENOENT) / -1 (error), with errno set. */
int  cephfsro_resolve_retry(cephfsro_state_t *st, const char *path,
                            cephfs_dentry_t *out);

/* Fill an SD stat from a decoded primary inode. */
void cephfsro_stat_from_inode(const cephfs_inode_t *in, brix_sd_stat_t *out);

/* ---- directory vtable ops (defined in sd_cephfs_ro_dir.c) ------------------ */

brix_sd_dir_t *cephfsro_opendir(brix_sd_instance_t *inst, const char *path,
                                int *err_out);
ngx_int_t      cephfsro_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t      cephfsro_closedir(brix_sd_dir_t *d);

#endif /* BRIX_SD_CEPHFS_RO_INTERNAL_H */
