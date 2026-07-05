/*
 * posix_map.h — backend-agnostic XRootD↔POSIX translation shared by the FUSE
 * drivers (xrootdfs.c async + xrootdfs_legacy.c) and the preload shim.
 *
 * These are pure functions over libbrix data structures with NO connection model
 * baked in, so both FUSE backends (pool / mfile / webfile) call one copy:
 *   - statinfo → struct stat   (dir/regular/symlink mode, stable st_ino, blocks)
 *   - kXR_Qspace text → byte totals
 *   - server fattr list ("U.<x>\0…") → FUSE "user.<x>\0…" listxattr buffer
 */
#ifndef XRDC_POSIX_MAP_H
#define XRDC_POSIX_MAP_H

#include "brix.h"

#include <sys/stat.h>
#include <stddef.h>

/* Fill *stbuf from a server statinfo. allow_symlink!=0 presents a kXR_other entry
 * as S_IFLNK (the async driver's lstat-based getattr); 0 keeps the legacy
 * regular/dir-only mapping. Sets a stable st_ino from si->id and a 1 MiB blksize. */
void brix_statinfo_to_stat(const brix_statinfo *si, int allow_symlink,
                           struct stat *stbuf);

/* Parse a kXR_Qspace reply ("…oss.space=<bytes>&oss.free=<bytes>…") into byte
 * totals; either out-param is set to 0 when its key is absent. */
void brix_parse_qspace(const char *text, unsigned long long *total,
                       unsigned long long *freeb);

/* Translate a server fattr name list `raw[rawlen]` ("U.<x>\0U.<y>\0…") into the
 * FUSE listxattr form ("user.<x>\0user.<y>\0…"). Mirrors the listxattr contract:
 * size==0 → return the total bytes needed; else write into list[size] and return
 * the total, or -ERANGE if it does not fit. */
int  brix_fattr_listxattr_xlate(const char *raw, size_t rawlen,
                                char *list, size_t size);

#endif /* XRDC_POSIX_MAP_H */
