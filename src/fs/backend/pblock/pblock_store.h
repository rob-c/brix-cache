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

#include <limits.h>                   /* PATH_MAX */
#include <stdint.h>
#include <sys/types.h>               /* ssize_t, off_t, size_t */

/* Per-export instance state (inst->state); borrowed by every open object. */
typedef struct {
    char            root[PATH_MAX];
    char            data_dir[PATH_MAX];   /* <root>/data */
    int64_t         block_size;           /* default stripe size for new files */
    pblock_catalog *cat;                  /* <root>/catalog.db */
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
