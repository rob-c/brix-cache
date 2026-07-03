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

- **Per-listener SHM slot** (`ngx_xrootd_srv_metrics_t`) — carries the backend
  identity and export root for live capacity `statvfs`, exactly as `cache_root`
  does today.
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

Add `xrootd_fs_id_t xrootd_sd_backend_id(const xrootd_sd_instance_t *inst)`
next to the existing `xrootd_sd_backend_name()` (`src/fs/backend/sd.h`), and a
`const char *xrootd_fs_id_name(xrootd_fs_id_t)` for the exporter label. The enum
is append-only and inherits the build gates from the X-macro lists, so a
`./configure` without CEPH/SQLITE simply yields a smaller `XROOTD_FS_COUNT`.
Bounded + low-cardinality — INVARIANT #8 clean.

### Component 2 — per-listener storage slot fields (metrics.h)

In `ngx_xrootd_srv_metrics_t`, next to `cache_root`:

```c
char       storage_backend[16];  /* SD driver name label ("posix"…) */
char       storage_root[PATH_MAX]; /* export root_canon, for live statvfs; never emitted raw */
ngx_uint_t storage_remote;       /* 1 = remote backend (no local FS to statvfs) */
```

Populated at listener bind in `src/protocols/root/connection/handler.c`, inside
the existing `mconf->metrics_slot` guard block that already copies `cache_root`:
copy `mconf->storage_backend` (default `"posix"` when empty), `mconf->root_canon`,
and `xrootd_storage_backend_is_remote(mconf)`. No new call site.

### Component 3 — per-backend byte counters (metrics.h unified block)

Next to `io_bytes_read[XROOTD_PROTO_COUNT]`:

```c
ngx_atomic_t io_bytes_read_backend[XROOTD_FS_COUNT];
ngx_atomic_t io_bytes_written_backend[XROOTD_FS_COUNT];
```

A sibling accounting helper (keeps `xrootd_metric_op_done`'s signature stable):

```c
void xrootd_metric_backend_bytes(xrootd_fs_id_t backend, xrootd_metric_op_t op, size_t bytes);
```

### Component 4 — attribute bytes at two seams

**(a) VFS chokepoint — non-sendfile reads + all writes.**
`xrootd_vfs_observe_ctx_op()` (`src/fs/vfs/vfs_internal.h:335`) fires for every
VFS I/O op and holds `ctx`, from which the backend is reachable
(`ctx->sd->driver`). Beside the existing `xrootd_metric_op_done` call, derive
`backend_id = xrootd_sd_backend_id(ctx->sd)` and call
`xrootd_metric_backend_bytes(backend_id, op, bytes)` for READ/WRITE ops.

**(b) Sendfile read seam — WebDAV/S3 GET served via zero-copy.**
`xrootd_vfs_file_sendfile_fd()` only hands the raw fd to the HTTP layer; nginx
performs the transfer and the byte count is recorded at the WebDAV/S3
read-completion metric site (`src/protocols/webdav/metrics.c`,
`src/protocols/s3/metrics.c`), which is proto-keyed and does **not** know the
backend. Fix: capture `backend_id` from the open `fh` (`fh->obj` → driver) when
the GET opens the file, stash it on the request/handler ctx, and call
`xrootd_metric_backend_bytes(backend_id, XROOTD_METRIC_OP_READ, bytes)` at that
completion site in addition to the existing proto counter. This closes the gap
so sendfile-served reads are attributed per-backend.

Attribution covers exactly the storage plane (INVARIANT #11): VFS-routed and
sendfile-served backend I/O. Non-storage I/O (proxy relay, cache-fill WAN pulls)
is intentionally not counted here — those have their own counters.

### Component 5 — snapshot builder (api_snapshot.c)

New `dashboard_fill_storage(json_t *target, ngx_uint_t redact)` mirroring
`dashboard_fill_cache`:

- Iterate `in_use` slots → a `backends[]` array. Per entry:
  `{ backend, auth, remote, port(omitted when redact) }`, and for non-remote,
  live `xrootd_fs_usage_stat(storage_root)` →
  `{ bytes_total, bytes_used, bytes_available, occupancy_ratio }`. Never emits
  the raw path (matches Cache).
- Join per-backend `bytes_read_total` / `bytes_written_total` from
  `unified.io_bytes_*_backend[id]` onto each backend.

Attach as `storage` on the snapshot root next to `cache`
(`dashboard_build_snapshot`).

### Component 6 — Prometheus exporter (unified.c)

Export the per-backend counters with a bounded `backend` label, mirroring the
existing per-`proto` families:

```
xrootd_io_bytes_read{backend="posix"}     <n>
xrootd_io_bytes_written{backend="posix"}  <n>
```

Storage capacity/occupancy gauges are exported per backend the same way the
cache occupancy is exported today (`stream_cache.c` pattern, live `statvfs`):

```
xrootd_storage_bytes_total{backend="posix"}      <n>
xrootd_storage_bytes_used{backend="posix"}       <n>
xrootd_storage_bytes_available{backend="posix"}  <n>
xrootd_storage_occupancy_ratio{backend="posix"}  <0..1>
```

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
listener bind ──► SHM slot (backend, root, remote)
VFS/sendfile I/O ──► unified.io_bytes_*_backend[id]   (via xrootd_metric_backend_bytes)
                                   │
HTTP dashboard worker ── reads SHM + live statvfs ──► JSON snapshot ──► browser poll
Prometheus scrape ───── reads SHM + live statvfs ──► /metrics text
```

Identical lifecycle to the existing cache panel + per-proto io counters.

## Redaction / security

- Raw filesystem paths are never emitted (matches Cache: only `statvfs`-derived
  numbers leave the process). `port` is omitted from anonymous snapshots.
- Backend names are a fixed, bounded set — safe as labels and in anonymous
  output.

## Testing (≥3 per change, per project rule)

1. **Capacity success:** posix backend configured → `/snapshot`
   `storage.backends[]` has `backend:"posix"`, `bytes_total`/`bytes_used > 0`;
   `/metrics` has `xrootd_storage_bytes_total{backend="posix"}`.
2. **Per-backend byte accounting:** PUT then GET *N* bytes on posix →
   `bytes_written_total` and `bytes_read_total` each advance ~*N* on both
   surfaces. A second backend (pblock) accounts independently
   (`{backend="pblock"}` distinct from `{backend="posix"}`).
3. **Sendfile read attribution:** WebDAV/S3 GET (zero-copy sendfile path) of *N*
   bytes → `bytes_read_total{backend}` advances ~*N* (guards the Component-4b
   seam specifically).
4. **Remote-backend edge:** xroot/http origin backend → `remote:true`, no
   `statvfs` numbers, no crash; capacity gauges absent for that backend.
5. **Security-negative:** anonymous/redacted snapshot → `port` omitted, no
   filesystem path anywhere in the payload; `/metrics` carries no path label.

## Files touched

| File | Change |
|---|---|
| `src/core/types/fs_list.h` | activate `ID` column → `xrootd_fs_id_t` enum surface |
| `src/fs/backend/sd.h` / registry | `xrootd_sd_backend_id()`, `xrootd_fs_id_name()` |
| `src/observability/metrics/metrics.h` | slot `storage_*` fields + unified `io_bytes_*_backend[]` |
| `src/observability/metrics/unified.{c,h}` | `xrootd_metric_backend_bytes()` + Prometheus families |
| `src/fs/vfs/vfs_internal.h` | per-backend accounting at the observe chokepoint |
| `src/protocols/root/connection/handler.c` | populate slot `storage_*` at bind |
| `src/protocols/webdav/metrics.c`, `src/protocols/s3/metrics.c` | sendfile-read per-backend attribution |
| `src/observability/dashboard/api_snapshot.c` | `dashboard_fill_storage()` + attach `storage` |
| `src/observability/dashboard/page.c` | Backend Storage panel + renderer |
| `tests/` | 5 tests above |

## Build note

`fs_list.h`, `metrics.h`, and `unified.h` are widely included, and new SHM
fields change the shared struct layout. This is a full rebuild
(`rm -rf objs && ./configure && make`), not incremental — an incremental build
over stale objects yields mixed-ABI SHM garbage.
