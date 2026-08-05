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
 * Scope: the inventory is a fixed-slot POD table (cns_inventory.h). When a
 * `brix_cns_zone` is registered (any collector block; wired in
 * postconfiguration) it lives in an nginx SHM slab shared across every manager
 * worker, so a mutation on worker A is visible to a stat on worker B; without a
 * zone it falls back to a per-worker heap table (correct for the common
 * single-worker redirector). Emit coverage is add/del/mkdir/rmdir.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>
#include <sys/stat.h>

#include "cns_inventory.h"    /* BRIX_CNS_{ADD,DEL,MKDIR,RMDIR}, BRIX_CNS_PATH_MAX */

/* Private CMS frame code for nginx-manager↔nginx-data-server CNS events. Outside
 * the stock XrdCms kYR_* range (which tops out in the 20s); only our own peers
 * parse it, and the manager ignores it unless brix_cns collect is set. */
#define CMS_RR_CNS  40

/* Namespace-mutation opcodes (BRIX_CNS_{ADD,DEL,MKDIR,RMDIR}) and
 * BRIX_CNS_PATH_MAX come from cns_inventory.h (shared with the table ops). */

/* brix_cns modes (conf->cns_mode). */
#define BRIX_CNS_OFF     0
#define BRIX_CNS_EMIT    1   /* data server: report mutations to the manager */
#define BRIX_CNS_COLLECT 2   /* manager: maintain the inventory + answer stat */

/*
 * Fixed wire layout (raw, big-endian), followed by `name_len` path bytes:
 *   op[1] rsvd[3] size[8] mtime[8] name_len[2]
 *
 * BRIX_CNS_MV appends a second, length-prefixed path after the first:
 *   … name_len[2] oldpath[name_len] name2_len[2] newpath[name2_len]
 * and carries the destination's directory-ness in the first reserved byte
 * (rsvd[0], which every other op leaves zero). Extending the frame this way is
 * safe in both directions: CMS_RR_CNS is a private frame only our own peers
 * parse, a pre-MV manager's decoder ignores the trailing bytes and then rejects
 * the unknown op in brix_cns_inv_apply (a no-op, not a corrupt entry), and a
 * pre-MV data server simply never emits one.
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

/* EITHER. Encode a BRIX_CNS_MV event (two paths). size/mtime/is_dir describe the
 * destination as the data server observed it after the rename. Returns the total
 * length, or 0 on overflow / an empty or oversize path. */
size_t brix_cns_event_encode_mv(const char *oldpath, const char *newpath,
                                  uint64_t size, uint64_t mtime, int is_dir,
                                  uint8_t *buf, size_t bufsz);

/* EITHER. Decode the second path of a BRIX_CNS_MV frame previously accepted by
 * brix_cns_event_decode (which yields the FIRST path and ignores the tail).
 * Fills is_dir and copies the new path into newpath[newsz]. NGX_OK / NGX_ERROR
 * (a frame that carries no well-formed second path). */
ngx_int_t brix_cns_event_decode_mv(const uint8_t *buf, size_t len, int *is_dir,
                                     char *newpath, size_t newsz);

/* LOOP-ONLY (manager). Apply a decoded event to the inventory (upsert on ADD/MKDIR,
 * remove on DEL/RMDIR). server_id tags the origin. NGX_OK / NGX_ERROR. */
ngx_int_t brix_cns_apply(uint8_t op, const char *path, uint64_t size,
                           uint64_t mtime, uint32_t server_id);

/* LOOP-ONLY (manager). Apply a decoded BRIX_CNS_MV event: move `oldpath` (and the
 * whole recorded subtree beneath it) to `newpath`. NGX_OK / NGX_ERROR. */
ngx_int_t brix_cns_rename(const char *oldpath, const char *newpath,
                            uint64_t size, uint64_t mtime, int is_dir,
                            uint32_t server_id);

/* LOOP-ONLY (manager). Look a path up in the inventory; fills *out (S_IFREG/S_IFDIR
 * + size + mtime). NGX_OK on hit, NGX_DECLINED on miss. */
ngx_int_t brix_cns_stat(const char *path, struct stat *out);

/* Process-global "this node is a CNS collector" flag, set at config time when any
 * server block has `brix_cns collect`. The CMS-server frame handler (a separate
 * module from the one that owns cns_mode) gates inventory updates on it. */
void      brix_cns_set_collect(ngx_flag_t on);
ngx_flag_t brix_cns_collecting(void);

/* CONFIG-TIME (manager). Register the cross-worker SHM inventory zone sized for
 * `slots` entries. Call once from postconfiguration when any block collects, so
 * every manager worker shares one inventory. Without it the inventory falls back
 * to a per-worker heap table (single-worker-correct). NGX_OK / NGX_ERROR. */
ngx_int_t brix_cns_configure(ngx_conf_t *cf, ngx_uint_t slots);

/* Default SHM inventory capacity when postconfiguration does not size it. */
#define BRIX_CNS_DEFAULT_SLOTS 8192

#endif /* NGX_BRIX_CMS_CNS_H */
