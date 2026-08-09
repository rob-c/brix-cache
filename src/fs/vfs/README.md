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
| `vfs_secgate.c` | Generic per-capability TLS gating (`brix_tls_require`, stock `xrootd.tls` parity). The BRIX_TLSREQ_LOGIN/SESSION/DATA/TPC mask, the pure directive-grammar parser (`none \| [all\|login\|session\|data\|tpc\|-<cap>]...`), the pure gate check `brix_tls_gate_refused()`, and the offset-based conf setter shared by the stream and HTTP directive tables. Enforced in the stream pre-dispatch (`brix_tls_require_enforce`, src/protocols/root/handshake/policy.c), the native-TPC choke point (src/protocols/root/read/open_tpc.c), the WebDAV dispatcher, and the S3 handler; advertised as kXR_tls* bits at kXR_protocol (src/protocols/root/session/protocol.c). |
| `vfs_cred.c` | Per-user backend credential gate (phase-1 + phase-2 T1/T3/T9). `brix_vfs_ctx_bind_backend_cred`/`_mint` wire the conf's credential dir/fallback/mint-CA onto a VFS ctx; a single shared decision body serves both `brix_vfs_backend_cred` (data-plane open/staged_open) and `brix_vfs_ns_cred` (namespace stat/unlink/rename/xattr) — calls `brix_sd_ucred_select`, optionally attempts one opt-in mint on a DECLINED select, then either grants a user credential, allows a service-credential fallback, or refuses (EACCES/403); emits the Phase-2 T3 Prometheus counters on every terminal outcome. See [docs/10-reference/per-user-backend-credentials.md](../../../docs/10-reference/per-user-backend-credentials.md). |

### Other files

| File | Responsibility |
|---|---|
| `fd_cache.c` | Phase 3 keeps protocol-specific fd-cache behavior in place while introducing the shared VFS handle. |
| `vfs_backend_config_ceph.c` | Parses the RADOS/CephFS/nearline backend origin strings — "ceph:<pool>...", "rados://<pool>...", "cephfsro:<meta>+<data>...", and "tape://<adapter>/<base>" (alias "frm://...") — into registry entries, plus the three stat. |
| `vfs_backend_config_http.c` | Parses "http://host[:port][/base]" / "https://..." backend origins — including a pipe-separated ordered list that registers a ranked multi-endpoint origin set (phase-68 T11) — into registry entries, and registers each en. |
| `vfs_backend_config_internal.h` | The shared origin-segment parse record (vfs_origin_parse_t) plus the extern declarations for the per-scheme origin parsers that the brix_vfs_backend_config_str dispatcher (vfs_backend_config.c) calls across translation u. |
| `vfs_backend_config_s3.c` | Parses "s3://host[:port]/bucket" into an S3 source backend and "root://host:port" / "roots://host:port" into a remote root:// primary backend (any other value falling through to the local driver name via brix_vfs_backend. |
| `vfs_backend_internal.h` | The per-export entry type and the two table accessors that vfs_backend_config.c (config-time: directive parsing, per-driver builders, credential/tier setters) and vfs_backend_registry.c (runtime: source build, decorator. |
| `vfs_backend_registry.h` | A tiny per-worker table mapping an export's canonical root to its selected non-POSIX storage backend (today: pblock). |
| `vfs_backend_registry_source.c` | one static builder per storage-backend kind. |
| `vfs_cred_internal.h` | The per-user backend/namespace credential gates (vfs_cred.c) and the delegation live-cred materialiser plus its shared failure terminal and STS/krb5 hooks (vfs_deleg*.c). |
| `vfs_deleg.c` | Implements the per-request delegation seam that turns the raw forwardable credential the front door captured (a bearer JWT, or a user-supplied full x509 proxy PEM) into the exact brix_sd_cred_t form the backend GSI/ZTN p. |
| `vfs_deleg_bind.c` | The capture-side seam that constructs the per-request live-cred bag and reports the resolved delegation mode back to the cred gate: brix_vfs_ctx_bind_backend_deleg() — hang a borrowed bag on a VFS ctx. |
| `vfs_deleg_hooks.c` | The two origin-leg delegation seams that compile and are call-ready but are NOT yet driven from brix_vfs_deleg_live_cred: brix_vfs_deleg_sts_cred() — S3 STS assume-role → sd_remote cred form. |
| `vfs_deleg_internal.h` | Declarations shared by vfs_deleg.c (strategy dispatch, SSS/krb5/STS arms) and vfs_deleg_x509.c (RFC-3820 proxy-chain trust gate). |
| `vfs_deleg_x509.c` | The X.509 half of the delegation live-cred materialiser: parse the captured proxy PEM into a certificate chain, re-verify it against the CA store bound on the bag (phase-70 §5.1 / P90-70.4), and stage the PEM into a requ. |
| `vfs_internal.h` | Defines the real handle structs hidden behind vfs.h's opaque typedefs (brix_vfs_file_s, brix_vfs_dir_s), the inline confinement/write guards (brix_vfs_require_confined, brix_vfs_require_write), the ctx-path accessor (bri. |
| `vfs_io_core.h` | Declares the POD job descriptor and small segment descriptor types used by worker-thread and inline-fallback disk I/O. |
| `vfs_io_core_dirlist.c` | Implements brix_vfs_io_execute_opendir(), the OPENDIR arm of the POD-only VFS I/O execution core. |
| `vfs_io_core_internal.h` | Declares the handful of symbols shared between vfs_io_core.c (the dispatch + read/write/vector/sync/truncate executors) and its vfs_io_core_dirlist.c sibling (the kXR_dirlist OPENDIR builder), plus the wire-chunk cap the. |
| `vfs_open_adopt.c` | Hosts the handle-construction half of the VFS open unit: brix_vfs_ctx_init() (prime a per-request ctx), brix_vfs_fill_stat() (struct stat -> brix_vfs_stat_t), brix_vfs_copy_path() (pool-dup a C string), brix_vfs_adopt_fd. |
| `vfs_open_handle.c` | Implements brix_vfs_close() and every read-only accessor over an open brix_vfs_file_t: fd / sd_obj / pread / sendfile-fd / can-sendfile / backend-name / path / size / mtime / from_cache / file_stat, plus the phase-71 mem. |
| `vfs_ops.h` | confined walk / thread-safe open-unlink / raw fd read-write / xattr / single-file-copy / atomic-staged-write VFS declarations, split (phase-79 file-size burndown) out of the oversized vfs.h with zero behaviour change. |
| `vfs_secgate.h` | The capability mask (BRIX_TLSREQ_LOGIN/SESSION/DATA/TPC), the pure parser for the `brix_tls_require` directive grammar (`none \| [all\|login\|session\|data\|tpc].. |
| `vfs_walk_copy.c` | Implements brix_vfs_copyfile() (one confined regular file src→dst) and brix_vfs_copytree() (a confined directory tree src→dst), both impersonation-aware via the confined-canon helpers and thread-safe (no pool allocation. |
| `vfs_writer.c` | brix_vfs_writer_open/write/commit/abort — one write entry point a protocol path (GridFTP STOR) uses regardless of backend, with an optional self-computed read-back integrity check folded in. |
| `vfs_wverify.c` | brix_vfs_wverify_check() — given a write-side CRC accumulator and a FRESH read-only handle on the just-written object, re-read the object through its storage driver and confirm the persisted bytes match what was written. |
