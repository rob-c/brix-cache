#ifndef NGX_BRIX_CMS_CNS_H
#define NGX_BRIX_CMS_CNS_H

/*
 * cns.h — minimal Composite Cluster Name Space (§6).
 *
 * WHAT: data servers report namespace mutations (file create/closew, unlink, …)
 *       to the manager, which keeps a path→{size,mtime,server} inventory and can
 *       answer kXR_stat for any cluster file locally — without redirecting the
 *       client to the data server that holds it.
 * WHY:  XrdCnsd-style global namespace: a redirector can stat/size any file in the
 *       federation it manages. The existing CMS registry is prefix-based routing
 *       (which server exports which subtree); CNS adds per-file metadata.
 * HOW:  a new raw CMS frame (CMS_RR_CNS) carries one fixed-layout event over the
 *       existing data-server→manager CMS link. The data server emits on closew
 *       (brix_cns_emit); the manager applies into an in-memory inventory
 *       (brix_cns_apply) and looks it up from the stat handler (brix_cns_stat).
 *
 * Scope (v1): in-memory, per-worker inventory — correct for a single-worker
 * manager (the common redirector config). A cross-worker SHM inventory and full
 * emit coverage (unlink/mkdir/rmdir/mv) are documented follow-ups.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>
#include <sys/stat.h>

/* Private CMS frame code for nginx-manager↔nginx-data-server CNS events. Outside
 * the stock XrdCms kYR_* range (which tops out in the 20s); only our own peers
 * parse it, and the manager ignores it unless brix_cns collect is set. */
#define CMS_RR_CNS  40

/* Namespace-mutation opcodes. */
#define BRIX_CNS_ADD     1   /* file created / closed-after-write (size known) */
#define BRIX_CNS_DEL     2   /* file unlinked */
#define BRIX_CNS_MKDIR   3
#define BRIX_CNS_RMDIR   4

/* brix_cns modes (conf->cns_mode). */
#define BRIX_CNS_OFF     0
#define BRIX_CNS_EMIT    1   /* data server: report mutations to the manager */
#define BRIX_CNS_COLLECT 2   /* manager: maintain the inventory + answer stat */

#define BRIX_CNS_PATH_MAX 512

/*
 * Fixed wire layout (raw, big-endian), followed by `name_len` path bytes:
 *   op[1] rsvd[3] size[8] mtime[8] name_len[2]
 */
#define BRIX_CNS_HDR_LEN 22

/* EITHER. Encode an event into buf (>= BRIX_CNS_HDR_LEN + strlen(path)); returns
 * the total length, or 0 on overflow / oversize path. */
size_t brix_cns_event_encode(uint8_t op, const char *path, uint64_t size,
                               uint64_t mtime, uint8_t *buf, size_t bufsz);

/* EITHER. Decode a raw CNS frame payload. Fills op/size/mtime and copies the path
 * (NUL-terminated) into path[pathsz]. Returns NGX_OK / NGX_ERROR (malformed). */
ngx_int_t brix_cns_event_decode(const uint8_t *buf, size_t len, uint8_t *op,
                                  uint64_t *size, uint64_t *mtime,
                                  char *path, size_t pathsz);

/* LOOP-ONLY (manager). Apply a decoded event to the inventory (upsert on ADD/MKDIR,
 * remove on DEL/RMDIR). server_id tags the origin. NGX_OK / NGX_ERROR. */
ngx_int_t brix_cns_apply(uint8_t op, const char *path, uint64_t size,
                           uint64_t mtime, uint32_t server_id);

/* LOOP-ONLY (manager). Look a path up in the inventory; fills *out (S_IFREG/S_IFDIR
 * + size + mtime). NGX_OK on hit, NGX_DECLINED on miss. */
ngx_int_t brix_cns_stat(const char *path, struct stat *out);

/* Number of live inventory entries (observability / tests). */
ngx_uint_t brix_cns_count(void);

/* Process-global "this node is a CNS collector" flag, set at config time when any
 * server block has `brix_cns collect`. The CMS-server frame handler (a separate
 * module from the one that owns cns_mode) gates inventory updates on it. */
void      brix_cns_set_collect(ngx_flag_t on);
ngx_flag_t brix_cns_collecting(void);

#endif /* NGX_BRIX_CMS_CNS_H */
