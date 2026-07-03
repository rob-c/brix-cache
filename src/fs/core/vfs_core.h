/*
 * vfs_core.h — shared, ngx-free VFS I/O verbs over the storage backend driver.
 *
 * WHAT: The storage-neutral byte-I/O verbs (full read, single read, full write,
 *       sync, truncate, fstat) that both the nginx server data plane and the
 *       userland clients run. They operate on an already-opened backend object
 *       (brix_sd_obj_t) — the OPEN, with its per-side policy (server: export-
 *       confined RESOLVE_BENEATH; client: unconfined URL path), stays in the
 *       caller's layer (vfs_server / client adapter). These verbs own only the
 *       EINTR / short-I/O loop policy; the raw syscalls live in the backend.
 * WHY:  The verb loops were maintained twice (src/fs/vfs/vfs_read.c +
 *       vfs_io_core.c on the server; client/lib/vfs_posix.c + vfs_block.c on the
 *       client). One copy removes the drift risk and is the `vfs` layer of the
 *       module->vfs_server->vfs->backend / client->vfs->backend topology.
 * HOW:  Pure C, ngx-free (dual-build via sd.h's XRDPROTO_NO_NGX fallback), in
 *       libxrdproto. Backend-neutral: every op dispatches through obj->driver, so
 *       a non-POSIX backend (block/object) works unchanged.
 *
 * See docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md.
 */
#ifndef BRIX_VFS_CORE_H
#define BRIX_VFS_CORE_H

#include "fs/backend/sd.h"   /* brix_sd_obj_t + driver vtable (ngx-free fallback) */

#include <stddef.h>
#include <sys/types.h>   /* ssize_t, off_t */

/*
 * Convention: all int-returning verbs return 0 on success and -1 on error with
 * errno set. This is value-compatible with the server's NGX_OK/NGX_ERROR (0/-1).
 */

/*
 * Full read: loop (EINTR-retried) until `len` bytes are read or EOF. A short
 * read at EOF is success with *nread < len. *nread (if non-NULL) reports the
 * byte count even on error. Returns 0 / -1 (errno).
 */
int xvfs_pread_full(brix_sd_obj_t *obj, void *buf, size_t len, off_t off,
                    size_t *nread);

/*
 * Single read with EINTR retry: returns the byte count (>= 0, may be short,
 * 0 = EOF) or -1 (errno). The caller owns any short-read loop (transfer pump).
 */
ssize_t xvfs_pread_once(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);

/*
 * Full write: loop (EINTR-retried) until all `len` bytes are written. *written
 * (if non-NULL) reports bytes written; *short_io (if non-NULL) is set when a
 * 0-byte write or a partial-then-error truncates the write. Returns 0 / -1.
 */
int xvfs_pwrite_full(brix_sd_obj_t *obj, const void *buf, size_t len,
                     off_t off, size_t *written, int *short_io);

/* Durability / metadata verbs (single backend op). Return 0 / -1 (errno). */
int xvfs_fsync(brix_sd_obj_t *obj);
int xvfs_ftruncate(brix_sd_obj_t *obj, off_t len);
int xvfs_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);

/*
 * Drain: copy the whole of `src` into `dst` through the driver, chunked via the
 * caller-provided scratch `buf` (`bufsz` bytes). Positional pread->pwrite reusing
 * xvfs_pread_once / xvfs_pwrite_full, so EINTR and short writes are handled and
 * the bytes never leave the backend. *total (if non-NULL) reports bytes copied.
 * The single primitive every auxiliary-storage scratch copy shares (serve
 * offload, xvfs_stage_fd). Returns 0 / -1 (errno; EINVAL on a NULL/zero buffer).
 */
int xvfs_drain(brix_sd_obj_t *src, brix_sd_obj_t *dst, void *buf,
               size_t bufsz, off_t *total);

/*
 * Materialize an already-open source fd into a LOCAL anonymous scratch fd under
 * `stage_dir`: mkstemp + immediate unlink (the bytes live only behind the fd),
 * copy src->scratch through the driver (xvfs_drain), then reopen the unlinked
 * inode O_RDONLY at offset 0 for the consumer. For readers that need a real
 * kernel fd (random access / sendfile) over a backend object that has none.
 * Returns the read fd, or -1 (errno). The caller still owns/closes `src_fd`.
 */
int xvfs_stage_fd(int src_fd, const char *stage_dir);

#endif /* BRIX_VFS_CORE_H */
