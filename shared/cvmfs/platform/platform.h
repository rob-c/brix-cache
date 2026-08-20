/* platform.h — OS feature shim for the shared CVMFS core (pure C, no ngx).
 *
 * WHAT: the ONE place target-divergent primitives live (phase-87 directive 7:
 *       Linux / macOS / Windows branches go behind a thin probe shim, never
 *       scattered #ifdefs). Currently: anonymous fds and data-only fsync.
 * WHY:  the packed cache store (cache/cas_pack.c) hands out object bytes as
 *       plain fds so read-to-EOF callers work unchanged; how an anonymous fd
 *       is minted (memfd_create / O_TMPFILE / mkstemp+unlink) and how data is
 *       made durable (fdatasync / F_FULLFSYNC / FlushFileBuffers) is per-OS.
 * HOW:  compile-time branches INSIDE this shim only; every caller sees one
 *       portable contract.
 */
#ifndef BRIX_CVMFS_PLATFORM_H
#define BRIX_CVMFS_PLATFORM_H

/* Mint an anonymous read-write fd (no name on disk once returned). `label` is
 * a debugging hint; `spill_dir` is a writable directory for fallbacks that
 * need a filesystem (NULL → /tmp). Returns fd or -1 (errno set). */
int brix_plat_anon_fd(const char *label, const char *spill_dir);

/* Flush file DATA to stable storage (metadata only as required to read it
 * back). Returns 0/-1 (errno set). */
int brix_plat_fsync_data(int fd);

/* Durability barrier for a whole tree: flush the filesystem holding `dirfd`
 * (syncfs on Linux; sync() elsewhere — coarser, same guarantee). Pairs with
 * a no_fsync CAS store: call once before publishing any reference to the
 * batched objects. Returns 0/-1 (errno set). */
int brix_plat_sync_tree(int dirfd);

/* Map `len` bytes of `fd` read-only, shared (paged on demand — the G6 mmap
 * path index reads through this). Returns the mapping or NULL (errno set). */
void *brix_plat_map_ro(int fd, unsigned long len);

/* Release a brix_plat_map_ro mapping. NULL/0 is a no-op. */
void brix_plat_unmap(void *p, unsigned long len);

#endif /* BRIX_CVMFS_PLATFORM_H */
