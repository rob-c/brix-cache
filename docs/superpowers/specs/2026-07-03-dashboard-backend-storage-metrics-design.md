# Backend Storage metrics — dashboard panel + per-backend byte-I/O counters

**Date:** 2026-07-03
**Status:** design (approved for planning)

## Problem

The monitoring dashboard has a **Cache** panel that reports the read-through /
write-through cache: `enabled`, listener count, eviction thresholds,
`cache_root` filesystem occupancy, and write-through flush health. It reads
per-listener SHM slots where `cache_enabled` is set.

There is **no equivalent view of the storage plane** — the SD/VFS backend that
actually holds the bytes (posix, pblock, ceph, …). An operator cannot see, from
the dashboard or `/metrics`, how full each backend's export is, nor how many
bytes are flowing through each backend.

## Goal

Add a second, independent **Backend Storage** view alongside Cache — the Cache
panel is untouched — reporting the storage plane:

1. **Capacity/occupancy** per listener export (live `statvfs`), grouped by
   backend driver name.
2. **Per-backend byte-I/O counters** — total bytes read and written attributed
   to each backend driver, covering *all* storage-plane I/O including
   sendfile-served WebDAV/S3 GETs.

Every separable metric is exposed on **both** the dashboard JSON snapshot and
the Prometheus `/metrics` exporter (with a low-cardinality `backend="…"` label).

## Non-goals

- No change to the existing Cache panel or its data source.
- No per-path / per-object / per-bucket cardinality (INVARIANT #8).
- No new storage subsystem — this is pure observability plumbing over the
  existing VFS/SD seam.

## Architecture

The design mirrors the proven cache-metrics seam one layer down onto the
storage plane. Two data sources feed the panel, matching how the Cache panel
already blends per-slot config with live `statvfs`:

- **Per-export VFS backend registry** (`src/fs/vfs/vfs_backend_registry.c`,
  existing) — carries backend identity + export root for live capacity
  `statvfs`; already powers the `/vfs` browser and the phase-63 info gauge.
- **Unified SHM block** — carries the per-backend byte counters, indexed by a
  bounded backend enum, exactly as `io_bytes_read[proto]` does today.

### Component 1 — backend identity enum (fs_list.h)

`src/core/types/fs_list.h` already reserves its `ID` column "for future enum
surfaces". Activate it: generate

```c
typedef enum {
    XROOTD_FS_POSIX,
    XROOTD_FS_BLOCK,
    ...            /* one per XROOTD_FS_DRIVER_LIST_* row, build-gated as today */
    XROOTD_FS_COUNT
} xrootd_fs_id_t;
```

Add name-keyed lookups `int xrootd_fs_id_from_name(const char *name)` and
`const char *xrootd_fs_id_name(xrootd_fs_id_t)` in a new **ngx-free**
`src/fs/backend/sd_fs_id.c` (X-macro generated tables, no driver externs — so
it unit-tests standalone). Attribution sites resolve the driver's `.name`
string; a short strcmp scan over ≤13 short names per *completed op* is
negligible against the syscall it accounts. The enum is append-only and
inherits the build gates from the X-macro lists (the gate macros are global
`-D` CFLAGS, so every server TU sees the same `XROOTD_FS_ID_COUNT` — the SHM
layout is consistent within a build). Bounded + low-cardinality — INVARIANT #8
clean.

### Component 2 — per-export identity: the existing VFS backend registry
*(revised at implementation-research time — supersedes the original "SHM slot
fields" approach)*

The codebase already has exactly the identity table this panel needs:
`src/fs/vfs/vfs_backend_registry.{h,c}` — a per-worker, config-time census of
exports (`xrootd_vfs_backend_export_count()` / `xrootd_vfs_backend_export_info()`
→ `{root_canon, backend, host, port, tls, staging, has_token, has_proxy}`).
It already feeds the phase-63 `xrootd_storage_backend_info` Prometheus gauge and
the dashboard `/vfs` export browser, and it covers stream AND HTTP exports (both
`runtime_server.c` and `webdav/config.c` register through
`xrootd_vfs_backend_config_str`). No new SHM slot fields; no `handler.c` change.

**One gap to close:** an export that names no backend (default POSIX) is a
registration no-op, so the registry — and therefore the existing info gauge and
`/vfs` browser — misses the most common configuration. Phase-68 already made an
*explicit* `posix` register; extend `xrootd_vfs_backend_config_str` so an empty
`xrootd_storage_backend` registers as `posix` too (guarded: never register a
`root_canon` of `"/"`, the pure-cache-node namespace anchor).

`statvfs` capacity is emitted only for local backends (`posix`/`pblock`);
remote/origin backends (`xroot`/`http`/`s3`/`ceph`…) report identity + byte
counters but no local filesystem numbers.

### Component 3 — per-backend byte counters (metrics.h unified block)

Next to `io_bytes_read[XROOTD_PROTO_COUNT]`:

```c
ngx_atomic_t io_bytes_read_backend[XROOTD_FS_ID_COUNT];
ngx_atomic_t io_bytes_written_backend[XROOTD_FS_ID_COUNT];
```

A sibling accounting helper (keeps `xrootd_metric_op_done`'s signature stable);
pure lock-free SHM atomics, safe from thread-pool workers:

```c
void xrootd_metric_backend_bytes(const char *backend_name,
    xrootd_metric_op_t op, size_t bytes);   /* NULL name ⇒ "posix" */
```

### Component 4 — attribute bytes at three seams
*(revised at implementation-research time: READ/WRITE **bytes** do not flow
through `observe_ctx_op` today — that chokepoint carries metadata ops plus the
staged-upload commit; the data plane splits across `vfs_io_core.c` (root://)
and the shared HTTP file-serve helper.)*

**(a) VFS observe chokepoint — staged-upload commits + VFS copies.**
`xrootd_vfs_observe_ctx_op()` (`src/fs/vfs/vfs_internal.h`) already receives
`bytes` for the staged-PUT commit WRITE (`vfs_staged.c`) and holds `ctx->sd`.
Beside `xrootd_metric_op_done`, for READ/WRITE ops with `bytes > 0` call
`xrootd_metric_backend_bytes(backend_name, op, bytes)` where `backend_name` is
`xrootd_sd_backend_name(ctx->sd)` (NULL instance ⇒ `"posix"`).

**(b) root:// data plane — `xrootd_vfs_io_execute()`.**
Every root:// read/write/readv/writev/pgread routes through this single
executor (`src/fs/vfs/vfs_io_core.c`), and the job carries the handle's
storage object (`job->obj.driver`, NULL ⇒ POSIX). After the op switch, on
`job->nio > 0`, attribute read-direction ops (READ/PGREAD/READV) and
write-direction ops (WRITE/WRITEV) to the job's backend. The helper is a pure
lock-free SHM atomic add — safe from thread-pool workers, a deliberate,
documented exception to the file's "no metrics" note. (READV segments can in
principle span handles; the whole total attributes to the job's primary obj —
bounded, documented approximation.)

**(c) HTTP GET serve seam — `xrootd_http_serve_file_ranged()`.**
Both WebDAV GET and S3 GetObject (inline AND thread-pool-offloaded via
`http_serve_offload.c`) delegate the body send to this one function
(`src/protocols/shared/file_serve.c`), which owns the VFS handle and computes
`result->bytes_sent` at exactly three exit sites (compressed / memory-backed /
sendfile). Capture the backend name from the handle at entry (new accessor
`xrootd_vfs_file_backend_name(fh)`) and attribute `bytes_sent` as READ at each
site. This covers zero-copy sendfile GETs with no per-protocol changes.

Semantics: the counters measure **bytes the backend instance moved**, not
client-visible bytes — a staged upload legitimately counts once into the stage
store and once into the final backend at promote. Non-storage I/O (proxy relay,
cache-fill WAN pulls) is intentionally not counted here — those have their own
counters. Cache-hit GETs attribute to the composed instance's driver (`cache`),
which is itself a meaningful label.

### Component 5 — snapshot builder (api_snapshot.c)

New `dashboard_fill_storage(json_t *target, ngx_uint_t redact)` mirroring
`dashboard_fill_cache`:

- Iterate the VFS backend registry → an `exports[]` array. Per entry:
  `{ backend, remote, staging }` always; `root` and `origin` only when
  authenticated (`!redact`); for local backends (`posix`/`pblock`, root ≠ "/"),
  live `xrootd_fs_usage_stat(root_canon)` →
  `{ bytes_total, bytes_used, bytes_available, occupancy_ratio }`.
- An `io` object keyed by backend name with
  `{ bytes_read_total, bytes_written_total }` from the per-backend SHM arrays
  (zero-zero backends omitted).

Attach as `storage` on the snapshot root next to `cache`
(`dashboard_build_snapshot`).

### Component 6 — Prometheus exporter (writer.c)
*(revised: the per-proto family names `xrootd_io_bytes_read{proto=}` cannot be
reused with a different label set — Prometheus forbids one metric name with
conflicting label sets — so the per-backend families get their own names,
co-located with the existing `xrootd_storage_backend_info` gauge in
`xrootd_storage_backend_metrics_emit()`.)*

```
xrootd_storage_io_bytes_read{backend="posix"}     <n>   (counter)
xrootd_storage_io_bytes_written{backend="posix"}  <n>   (counter)

xrootd_storage_bytes_total{export="/data",backend="posix"}      <n>   (gauge, live statvfs)
xrootd_storage_bytes_used{export="/data",backend="posix"}       <n>
xrootd_storage_bytes_available{export="/data",backend="posix"}  <n>
xrootd_storage_occupancy_ratio{export="/data",backend="posix"}  <0..1>
```

The `export` label matches the existing `xrootd_storage_backend_info`
convention (exports are config-fixed and few — low-cardinality).

"All separable metrics on both surfaces" = every per-backend value above appears
on both the dashboard snapshot and `/metrics`.

### Component 7 — dashboard UI (page.c)

Add a `<div class="panel"><h2>Backend Storage</h2><div id="storage-panel">` next
to the Cache panel, and a renderer in `renderPanels()` reading
`lastSnapshot.storage.backends`: show backend name(s), listener count, per-backend
used/total occupancy (or "remote" for origin-backed listeners), and
read/written byte totals.

## Data flow

```
config load ──► VFS backend registry (root_canon, backend, origin, staging)
storage I/O ──► unified.io_bytes_*_backend[id]   (via xrootd_metric_backend_bytes)
                                   │
HTTP dashboard worker ── registry + SHM + live statvfs ──► JSON snapshot ──► browser poll
Prometheus scrape ────── registry + SHM + live statvfs ──► /metrics text
```

Identical lifecycle to the existing cache panel + per-proto io counters.

## Redaction / security

- Anonymous snapshots omit `root` and `origin` (no filesystem path or upstream
  host leaves the process); authenticated snapshots carry them — parity with
  the authed-only `/vfs` browser. `/metrics` keeps the `export` path label,
  matching the existing `xrootd_storage_backend_info` gauge (the metrics
  endpoint is operator-scoped, not anonymous-tier).
- Backend names are a fixed, bounded set — safe as labels and in anonymous
  output.

## Testing (≥3 per change, per project rule)

1. **Capacity success:** default-posix export → `/snapshot` `storage.exports[]`
   has `backend:"posix"`, `bytes_total`/`bytes_used > 0`; `/metrics` has
   `xrootd_storage_bytes_total{export=…,backend="posix"}` (also proves the
   default-POSIX registration gap is closed).
2. **Per-backend byte accounting:** PUT then GET *N* bytes on posix →
   `xrootd_storage_io_bytes_written{backend="posix"}` and
   `…_read{backend="posix"}` each advance ≥ *N* on both surfaces.
3. **Sendfile read attribution:** WebDAV GET (zero-copy sendfile path) of *N*
   bytes → read counter advances ≥ *N* (guards the Component-4c seam
   specifically).
4. **Remote-backend edge:** xroot origin backend → `remote:true`, no `statvfs`
   numbers, no crash; capacity gauges absent for that export.
5. **Security-negative:** anonymous/redacted snapshot → no `root`/`origin`
   keys, no filesystem path anywhere in the `storage` payload; authed snapshot
   carries them (parity with `/vfs`).
6. **fs-id unit test:** standalone C test — name→id→name roundtrip for every
   row, unknown name → -1.

## Files touched

| File | Change |
|---|---|
| `src/core/types/fs_list.h` | activate `ID` column → `xrootd_fs_id_t` enum + name/lookup decls |
| `src/fs/backend/sd_fs_id.c` (new, ngx-free) | `xrootd_fs_id_name()`, `xrootd_fs_id_from_name()` (X-macro generated) |
| `./config` | add `sd_fs_id.c` to the module source list |
| `src/observability/metrics/metrics.h` | unified `io_bytes_read_backend[]` / `io_bytes_written_backend[]` |
| `src/observability/metrics/unified.{c,h}` | `xrootd_metric_backend_bytes()` |
| `src/fs/vfs/vfs_internal.h` | attribution at the observe chokepoint (staged commits) |
| `src/fs/vfs/vfs_io_core.c` | attribution in `xrootd_vfs_io_execute()` (root:// data plane) |
| `src/fs/vfs/vfs.h` + `vfs_open.c` | `xrootd_vfs_file_backend_name()` accessor |
| `src/protocols/shared/file_serve.c` | attribution at the three `bytes_sent` sites (HTTP GET incl. sendfile) |
| `src/fs/vfs/vfs_backend_config.c` | register default-POSIX exports (census gap) |
| `src/observability/metrics/writer.c` | per-backend io counters + per-export capacity gauges |
| `src/observability/dashboard/api_snapshot.c` | `dashboard_fill_storage()` + attach `storage` |
| `src/observability/dashboard/page.c` | Backend Storage panel + renderer |
| `tests/` | 5 tests above + fs-id unit test |

## Build note

`fs_list.h`, `metrics.h`, and `unified.h` are widely included, and new SHM
fields change the shared struct layout. This is a full rebuild
(`rm -rf objs && ./configure && make`), not incremental — an incremental build
over stale objects yields mixed-ABI SHM garbage.
