# Write-Through PFC Cache Mode

Status: implemented as a close/sync whole-file origin mirror.

## Goal

Allow BriX-Cache to accept write-mode XRootD handles while write-through is
enabled, keep the local filesystem copy authoritative during the request, and
mirror dirty data to an origin XRootD data server when the client issues
`kXR_sync` or `kXR_close`.

This is intentionally not a persistent per-write dual-dispatch design. The
module mirrors the final local file to the origin in bounded chunks, then sends
origin `kXR_truncate`, `kXR_sync`, and `kXR_close`.

```text
  DURING the request: local copy is authoritative, origin untouched
  ─────────────────────────────────────────────────────────────────
   client ── kXR_write ──▶ local /data file ── mark handle dirty
   client ── kXR_write ──▶ local /data file    (wt_dirty_offset ≥ 0)
   client ── kXR_write ──▶ local /data file
                                        no origin traffic yet

  ON kXR_sync / kXR_close: mirror the whole file once
  ─────────────────────────────────────────────────────────────────
   client ── kXR_sync/close ─▶ ┌─ writethrough_flush.c ─────────────┐
                               │ local file ──bounded chunks──▶      │
                               │   origin: open → write* → truncate  │
                               │           → sync → close            │
                               └──────────────┬──────────────────────┘
                       sync mode: origin error ──▶ kXR_IOError to client
                      async mode: handle released now, flush on thread pool
```

Why whole-file-on-close rather than per-write dual-dispatch? It is robust and
simple for **ingest-style** workflows (write once, sync, done) and never leaves
the origin in a half-written intermediate state — at the cost of being a poor
fit for very large random-write files (see Limitations).

## Configuration

```nginx
thread_pool xrootd_cache_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_thread_pool xrootd_cache_io;

        xrootd_write_through on;
        xrootd_wt_mode sync;                  # sync | async
        xrootd_wt_origin origin.example.org:1094;
        xrootd_wt_allow_prefix /data/ingest/;
        xrootd_wt_deny_prefix /data/private/;
    }
}
```

Directives:
- `xrootd_write_through on|off` enables WT policy evaluation for write opens.
- `xrootd_wt_mode sync|async` chooses close behavior. `kXR_sync` is always
  synchronous.
- `xrootd_wt_origin host:port` sets the write-back data server. If omitted,
  the read-through `xrootd_cache_origin` is used when configured.
- `xrootd_wt_allow_prefix` and `xrootd_wt_deny_prefix` are repeatable prefix
  filters. Deny entries win over allow entries.

## Implementation

Key files:
- `src/fs/cache/writethrough_decision.c` — open-time allow/deny decision.
- `src/protocols/root/read/open_resolved_file.c` — stores WT policy and mode bits on the
  `xrootd_file_t` handle.
- `src/protocols/root/write/write.c`, `src/protocols/root/write/pgwrite.c`, `src/protocols/root/write/writev.c`,
  `src/protocols/root/write/truncate.c`, `src/core/aio/write.c` — mark handles dirty after local
  write completion.
- `src/fs/cache/origin_connection.c` — connects to `xrootd_wt_origin` or the
  configured cache origin.
- `src/fs/cache/origin_protocol.c` — sends origin write-open, write, truncate,
  sync, and close operations.
- `src/fs/cache/writethrough_flush.c` — mirrors the local file to origin.
- `src/protocols/root/write/sync.c` — flushes dirty WT handles synchronously and returns a
  client error if the origin flush fails.
- `src/protocols/root/read/close.c` — runs sync close flush, or posts an async flush task when
  `xrootd_wt_mode async` and a thread pool are configured.

## Semantics

The open-time decision gates whether a handle ever participates:

```text
  write-open /data/...      global xrootd_write_through on?
        │                          │ no ──▶ plain local write, no WT
        ▼ yes                      ▼ yes
  deny_prefix match? ──yes──▶ wt_enabled = 0   (writes locally, never mirrors)
        │ no                                    ← the security-negative case
        ▼
  allow_prefix match? ──no──▶ wt_enabled = 0
        │ yes
        ▼
  wt_enabled = 1   (deny wins over allow)
```

Dirty tracking is handle-local:
- `wt_enabled` is set only when global WT is on and the decision callback
  allows the path.
- `wt_dirty_offset >= 0` means a write, pgwrite, writev, or truncate has
  modified the local file since the last successful WT flush.
- `wt_bytes_written` is reset after a successful explicit `kXR_sync` flush.

Flush behavior:
- `kXR_sync` mirrors the full local file to origin before returning `kXR_ok`.
  Origin errors are returned to the client as `kXR_IOError`.
- `kXR_close` mirrors dirty data before releasing the handle in `sync` mode.
  Close-time origin errors are logged and access-logged with `WT flush` but do
  not turn a successful local write into a failed close.
- `async` close posts the same mirror operation to the nginx thread pool. The
  handle is released immediately; completion is logged from the task callback.
- POSC writes are renamed to their final local path before WT flush, so the
  origin receives the final file name, not the temporary staging name.

## Limitations

- The origin client requires a direct data-server origin. `kXR_redirect` from
  the WT origin open is treated as unsupported.
- The write-back strategy is whole-file replacement, not per-write
  dual-dispatch. This is simpler and robust for ingest-style workflows, but it
  is not ideal for very large random-write workloads.
- Origin authentication follows the cache-origin machinery, not the native TPC
  client. Cache/write-through origins may use configured origin TLS, but login
  is still anonymous and `kXR_authmore` is not completed. Do not confuse this
  with native root:// TPC, which has its own ztn/GSI outbound auth path under
  `src/tpc/gsi_outbound_*`.
- There is no dynamic STS-style credential forwarding directive yet.

## Verification

Current verification used for this implementation:
- Full nginx module build after regenerating the nginx source list with
  `./configure --with-stream --with-http_ssl_module --with-threads --add-module=$REPO`.
- Incremental `make -j2` after final code edits.
- `nginx -t -c /tmp/xrd-test/conf/nginx.conf` passed once after the source-list
  regeneration. A later repeat was blocked by the sandbox escalation budget,
  but the final code-only patch was compile-verified.

Recommended integration coverage:
- Success: write, `kXR_sync`, verify origin content and truncation match local.
- Error: origin unavailable during explicit sync returns `kXR_IOError`.
- Security negative: denied prefix writes locally but emits no WT origin flush.
