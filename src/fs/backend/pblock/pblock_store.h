#ifndef BRIX_FS_BACKEND_PBLOCK_STORE_H
#define BRIX_FS_BACKEND_PBLOCK_STORE_H

/*
 * pblock_store.h — the packed-block storage engine.
 *
 * How a pblock backend lays a blob out on disk (blob-id generation, object-dir
 * and per-block path computation) and moves bytes into and out of the fixed-size
 * block files that make up a blob (write/read/remove/copy).  Split out of
 * sd_pblock.c so the on-disk block format is reviewable on its own, independent
 * of the brix_sd_driver_t vtable adapters (open/pread/pwrite/…) that call into
 * it.  Pure engine: every function takes the export state explicitly and holds
 * no globals.
 */

#include "fs/backend/sd.h"            /* brix_sd_stat_t */
#include "sd_pblock_catalog.h"        /* pblock_catalog, pblock_meta, PBLOCK_* */
#include "pblock_xform.h"             /* F12/F13 per-block transform seam */

#include <limits.h>                   /* PATH_MAX */
#include <stdint.h>
#include <sys/types.h>               /* ssize_t, off_t, size_t */

/* Per-export instance state (inst->state); borrowed by every open object. */
typedef struct {
    char            root[PATH_MAX];
    char            data_dir[PATH_MAX];   /* <root>/data */
    int64_t         block_size;           /* default stripe size for new files */
    pblock_catalog *cat;                  /* <root>/catalog.db */
    void           *lab;                  /* pblock_lab_state_t* (Phase-83);
                                           * NULL ⇒ lab OFF, hot path skips it */
    int             audit;                /* F17: 1 ⇒ append oplog rows at
                                           * metadata boundaries (opts audit=1) */
    int             csi;                  /* F3: 1 ⇒ per-block CRC32c integrity
                                           * (csi table); verify on read, flush  *
                                           * on close (opts csi=1)                */
    int             quota;                /* F5: 1 ⇒ usage rollup + quota gates
                                           * live (opts quota=/quota_inodes=)     */
    int64_t         quota_bytes;          /* F5: export byte quota (0 = none)     */
    int64_t         quota_inodes;         /* F5: export inode quota (0 = none)    */
    int             nearline;             /* F4: 1 ⇒ tape-residency simulation
                                           * (nearline table; opts nearline=1)    */
    int             locks;                /* F15: 1 ⇒ mandatory lease enforcement
                                           * (locks table; opts locks=1)          */
    int             refs;                 /* F10: 1 ⇒ refcounted blobs + dedup
                                           * (blobs table; opts dedup=1)          */
    int             snap;                 /* F6: 1 ⇒ snapshots armed (implies refs;
                                           * snapshots/snap_* tables; opts snap=1) */
    int             open_files;           /* F6: live regular-file handle count on
                                           * this export (atomic; snap gate only) —
                                           * restore refuses (EBUSY) while > 0     */
    int             versions;             /* F11: prior-blob generations kept on
                                           * overwrite (0 = off; implies refs;
                                           * versions table; opts versions=N)      */
    int             trash;                /* F11: 1 ⇒ unlink moves to trash instead
                                           * of freeing (implies refs; trash table;
                                           * opts trash=1)                          */
    pblock_xform_t  xform;                /* F12/F13: per-block transform (crypt/
                                           * zstd). kind NONE ⇒ raw block files, hot
                                           * path unchanged (opts xform=crypt:…/zstd)*/
} pblock_state_t;

/* ---- block-store engine (pblock_store.c) ---------------------------------- */
int64_t  pblock_now(void);
int64_t  pblock_last_block(int64_t size, int64_t bs);
uint64_t pblock_fnv(const char *s);
int      pblock_mkdir_p(const char *path);
int      pblock_gen_blob_id(char out[PBLOCK_BLOB_ID_CAP]);
int      pblock_obj_dir(const pblock_state_t *st, const char *blob_id, char *out,
             size_t cap);
int      pblock_block_path(const pblock_state_t *st, const char *blob_id,
             int64_t idx, char *out, size_t cap);
int      pblock_ensure_obj_dir(const pblock_state_t *st, const char *blob_id);
void     pblock_fill_sd_stat(const pblock_meta *m, const char *path,
             brix_sd_stat_t *out);
ssize_t  pblock_write_blocks(const pblock_state_t *st, const char *blob_id,
             int64_t bs, int blk0_fd, const void *buf, size_t len, off_t off);
ssize_t  pblock_read_blocks(const pblock_state_t *st, const char *blob_id,
             int64_t bs, int blk0_fd, void *buf, size_t len, off_t off);
void     pblock_remove_blocks(const pblock_state_t *st, const char *blob_id,
             int64_t size, int64_t bs);
ssize_t  pblock_copy_one_block(const char *src_path, const char *dst_path);

#endif /* BRIX_FS_BACKEND_PBLOCK_STORE_H */
