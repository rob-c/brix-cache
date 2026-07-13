# fs/vfs — the VFS facade (public API + per-op implementations)

The `brix_vfs_*` surface every protocol handler calls: `vfs.h` (the only
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

## Additional file

| File | Responsibility |
|---|---|
| `vfs_cred.c` | Per-user backend credential gate (phase-1 + phase-2 T1/T3/T9). `brix_vfs_ctx_bind_backend_cred`/`_mint` wire the conf's credential dir/fallback/mint-CA onto a VFS ctx; a single shared decision body serves both `brix_vfs_backend_cred` (data-plane open/staged_open) and `brix_vfs_ns_cred` (namespace stat/unlink/rename/xattr) — calls `brix_sd_ucred_select`, optionally attempts one opt-in mint on a DECLINED select, then either grants a user credential, allows a service-credential fallback, or refuses (EACCES/403); emits the Phase-2 T3 Prometheus counters on every terminal outcome. See [docs/10-reference/per-user-backend-credentials.md](../../../docs/10-reference/per-user-backend-credentials.md). |
