# src/fs/core — the shared `vfs` I/O verb layer

`vfs_core.{c,h}` is the **`vfs`** layer of the unified storage topology:

```
module ─▶ vfs_server ─▶ vfs ─▶ backend      (nginx server data plane)
client ──────────────▶ vfs ─▶ backend      (userland tools: xrdcp, xrootdfs, …)
```

It holds the storage-neutral byte-I/O verbs that **both** the nginx server and the
userland clients run, over the shared Storage Driver (`../backend/sd.h`):

| Verb | Semantics |
|---|---|
| `xvfs_pread_full`  | loop until `len` or EOF (short read at EOF = success) |
| `xvfs_pread_once`  | single EINTR-retried read; returns bytes (may be short / 0=EOF) |
| `xvfs_pwrite_full` | loop until all written; reports `*written` / `*short_io` |
| `xvfs_fsync` / `xvfs_ftruncate` / `xvfs_fstat` | single backend op |

**Invariants**
- **ngx-free**: compiled `-DXRDPROTO_NO_NGX` into `libxrdproto` (and into the
  module via `./config`). `check-ngx-free.sh` guards it. Clients keep 0 `ngx_`
  symbols.
- **The verbs own the loop policy; the backend owns the syscall.** Every byte op
  dispatches through `obj->driver->…`, so a non-POSIX backend (block/object) works
  unchanged.
- **OPEN is NOT here.** The open — and its per-side policy — stays in the caller's
  layer: the server's `vfs_server` does the export-confined `openat2(RESOLVE_BENEATH)`
  open; the client adapter does the unconfined URL-path open. Both then run these
  shared verbs on the resulting fd. Confinement never mixes with unconfined opens.

**Consumers**
- Server: `../vfs_read.c` (`xrootd_vfs_pread_full` wrapper), `../vfs_io_core.c`
  (write-counted / sync / truncate executors).
- Client: `client/lib/vfs_posix.c`, `client/lib/vfs_block.c` (plain, non-io_uring
  paths; io_uring stays a client-only fast-path override).

**Test**: `vfs_core_unittest.c` — standalone `gcc`, round-trips every verb over a
temp fd (see the file header for the build line).

Design: `docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md`.
Full reference (object model, capability matrix, every data flow, the S3
transport-vtable trick, the dual-build mechanism, invariants):
[`docs/09-developer-guide/vfs-shared-architecture.md`](../../../docs/09-developer-guide/vfs-shared-architecture.md).
