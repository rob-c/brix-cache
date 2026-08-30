/*
 * sd_block_internal.h — internals shared by the block driver's two translation
 * units.
 *
 * WHAT: The per-open extent window (sd_block_obj_t), the window helper the raw
 *       byte ops and the advisory hint both use, and the declarations of the
 *       server-plane namespace slots that sd_block_ns.c defines and the vtable
 *       in sd_block.c wires up.
 * WHY:  sd_block.c carried both planes and reached the 600-line file cap. The
 *       split mirrors the POSIX driver (sd_posix.c / sd_posix_io.c /
 *       sd_posix_ns.c): the raw byte plane compiles into libxrdproto for the
 *       userland clients, the namespace plane is module-only.
 * HOW:  Include-guarded; the namespace declarations are gated on the same
 *       XRDPROTO_NO_NGX switch that gates their definitions, so the client build
 *       never sees a declaration it has no definition for.
 */
#ifndef BRIX_SD_BLOCK_INTERNAL_H
#define BRIX_SD_BLOCK_INTERNAL_H

#include "fs/backend/sd.h"

/* Per-open extent window (obj->state). base/len confine an opened extent to its
 * slice of the device; a NULL obj->state is the client/unconfined path (a bare
 * fd wrapped for raw I/O) where offsets are absolute and unclamped. */
typedef struct {
    off_t base;   /* absolute device offset of this extent            */
    off_t len;    /* extent length in bytes (device tail may be short) */
} sd_block_obj_t;

/* sd_block_read_window — translate a logical read [*off, *len) within an extent
 * to an absolute device range. Returns 0 when the request starts at/after the
 * extent end (the caller returns a 0-byte EOF read), else clamps *len to the
 * extent tail and shifts *off by the extent base. os == NULL (client path) is a
 * no-op pass-through: the offset stays absolute. */
int sd_block_read_window(const sd_block_obj_t *os, off_t *off, size_t *len);

#ifndef XRDPROTO_NO_NGX   /* server plane: instance + fixed-extent namespace */

ngx_int_t      sd_block_init(brix_sd_instance_t *inst, void *driver_conf);
brix_sd_obj_t *sd_block_open(brix_sd_instance_t *inst, const char *path,
                             int sd_flags, mode_t mode, int *err_out);
ngx_int_t      sd_block_close(brix_sd_obj_t *obj);
ngx_int_t      sd_block_stat(brix_sd_instance_t *inst, const char *path,
                             brix_sd_stat_t *out);
brix_sd_dir_t *sd_block_opendir(brix_sd_instance_t *inst, const char *path,
                                int *err_out);
ngx_int_t      sd_block_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t      sd_block_closedir(brix_sd_dir_t *d);
ngx_int_t      sd_block_space(brix_sd_instance_t *inst, brix_sd_space_t *out);

#endif /* !XRDPROTO_NO_NGX */

#endif /* BRIX_SD_BLOCK_INTERNAL_H */
