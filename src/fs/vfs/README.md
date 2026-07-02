# fs/vfs — the VFS facade (public API + per-op implementations)

The `xrootd_vfs_*` surface every protocol handler calls: `vfs.h` (the only
header handlers should include), the per-op implementation files
(`vfs_open.c`, `vfs_read.c`, `vfs_write.c`, `vfs_stat.c`, `vfs_dir.c`,
`vfs_unlink.c`, `vfs_rename.c`, `vfs_mkdir.c`, `vfs_sync.c`, `vfs_xattr.c`,
`vfs_copy.c`, `vfs_staged.c`), the thread-safe worker surfaces
(`vfs_io_core.c`, `vfs_walk.c`), and the per-export storage-backend registry
(`vfs_backend_config.c` = directive parsing, `vfs_backend_registry.c` =
source build + decorator composition + resolve).

Moved off the `src/fs/` root in phase-67. The full per-file responsibility
table, the layer diagram (`module → vfs_server → vfs → backend`), invariants,
and the seam-guard rules all live in [`../README.md`](../README.md) — read
that first; this file is just the signpost.
