# `src/frm/` — FRM durable tape-staging queue

The File Residency Manager subsystem: a **durable, crash-safe queue of tape
stage-in requests** that backs `kXR_prepare`/`kXR_QPrep`, residency-aware opens,
and the WLCG HTTP Tape REST API. It replaces the old fire-and-forget staging
stub — where `reqid` was the literal `"0"`, state lived on the connection
(freed at disconnect), and `kXR_cancel`/`kXR_evict` were no-ops — so a tape
recall can outlive the client connection **and** a worker / master restart.

The implementation follows the Phase 35 plan in
[`docs/refactor/phase-35-frm-tape-staging.md`](../../docs/refactor/phase-35-frm-tape-staging.md):
durable queueing, prepare/QPrep rewrite, transfer worker, residency model,
`kXR_offline` reporting, HTTP Tape REST, async open completion, and parity
follow-ups are present. It is still intentionally narrower than the complete
upstream XrdFrm/MSS daemon ecosystem.

## The load-bearing invariant: file = truth, SHM = cache

The queue is a **file-backed fixed-record log** (`frm_format.h`), modeled on the
official `XrdFrcReqFile`, with a per-record CRC32c + a self-offset field so a
torn write is *detectable* on reconciliation. nginx shared memory is
process-group-lifetime and is **not** fsync'd, so it is treated strictly as a
**hot index** that is reconciled from the file at master start (before workers
fork). Any mutation:

1. takes the in-process `ngx_shmtx` fast-path, then the `fcntl(F_SETLKW)`
   whole-file lock on a `<path>.lock` sidecar (serialises across workers — and
   across hosts that share the filesystem). **Lock order is always
   `ngx_shmtx → fcntl`.**
2. writes the record body + `fdatasync`, then writes the header + `fsync`. **The
   header write is the commit point** (WAL ordering); a crash in between leaves
   an orphan body that no chain references — harmless, reclaimed on the next
   scan.

A reader (`frm_request_get`/`_find_by_path`/`_list`) takes the shared lock so it
never observes a half-written record; a CRC/self mismatch is treated as a free
slot.

## Files

| File | Responsibility |
|---|---|
| `frm_format.h` | On-disk layout: `frm_file_hdr_t`, `frm_record_t`, the status/option/cstype enums, and `FRM_REC_SIZE` size asserts. |
| `frm.h` | Public API + the `xrootd_frm_conf_t` directive struct (core-only header, safe to include from `types/config.h`). |
| `frm_internal.h` | Internal contract shared by the engine units (+ the umbrella include). |
| `reqfile.c` | Durable file engine: open/close, fcntl lock, header/record `pread`/`pwrite` + CRC + fsync, torn-write check. |
| `reqid.c` | Durable `"<seq>.<pid>@<host>"` reqid generation (seq lives in the header → monotonic across restarts). |
| `index.c` | SHM hot index (linear-scan table cloned from `tpc/key_registry.c`) + the zone-init callback that drives reconciliation + LRU reap-on-full. |
| `reconcile.c` | Master-start rebuild of the index from the file (linear scan; reclaims torn/cancelled slots, re-queues orphaned STAGING). |
| `compact.c` | Compaction hook for the fixed-record queue. Slot reuse bounds normal growth; dense rewrite is not required for the current queue model. |
| `queue.c` | Façade: `frm_queue_get/init` + `frm_request_add/get/set_status/delete/find_by_path/list` (file-of-truth then index, in authority order). |
| `reaper.c` | Worker-0 timer driving `frm_reap_expired` (deletes records past `tod_expire`). |
| `directives.c` | Directive defaults/merge (+ the stagecmd→prepare_command fallback) and the `xrootd_frm_purge_watermark` custom setter. |

## Configuration

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /export/data;
        xrootd_frm on;
        xrootd_frm_queue_path /var/spool/xrootd/frm.queue;   # absolute, durable
        xrootd_frm_max_inflight 256;
        # xrootd_frm_stagecmd defaults to xrootd_prepare_command
    }
}
```

When `xrootd_frm off` (default), `kXR_prepare` keeps its legacy behaviour and the
legacy `xrootd_prepare_command` still fires.

## Prepare / QPrep semantics

- `kXR_prepare(kXR_stage)` enqueues one durable record per resolved path and
  returns the **first record's reqid** as the request handle (single-path FTS
  stages — the common case — map exactly; multi-path grouping is a later
  refinement). The queue `lfn` is the confined absolute export path, which
  `kXR_QPrep` re-derives identically.
- `kXR_QPrep` is **stat-first** (a resident file is `A`) then **queue-fallback**
  (a not-yet-resident file with a live record reports `q`/`s`/`f`); unknown →
  `M`. The auth chain runs before the probe — no residency oracle for
  unauthorized callers.
- `kXR_prepare(kXR_cancel)` deletes the named reqid (idempotent). `kXR_evict`
  releases the durable pin/record and delegates physical disk purge to the
  backend policy.
- The stage agent (`stage.c`) can run the configured recall/copy path, update
  queue state, verify optional checksums, and wake parked opens when async
  recall is enabled. The legacy `prepare_command` fallback remains for FRM-off
  mode and as the default `xrootd_frm_stagecmd` when configured.

Tests: `tests/test_frm_queue.py` (durable reqid, QPrep state, **restart
durability**, cancel, unknown-reqid).

## Phases 1–4 (implemented)

- **Phase 1 — synchronous gateway.** `residency.c` probes `user.frm.residency`
  (absent ⇒ ONLINE); `read/stat.c`/`statx.c` OR `kXR_offline|kXR_bkpexist` for
  nearline; `read/open_request.c` recalls a nearline file via the **stage agent**
  (`stage.c` — a double-forked, init-reparented process so nginx never reaps the
  copycmd; see the fork/SHM-crash note) and stalls the client with `kXR_wait`.
  HTTP faces report locality too: WebDAV PROPFIND `<xrd:locality>` (opt-in prop,
  no cost on allprop) and S3 HEAD `x-amz-storage-class: GLACIER` / GET 403
  `InvalidObjectState`. Prometheus `xrootd_frm_*` via `metrics.c`.
  Tests: `test_frm_staging.py`, `test_frm_phase1_http.py`.
- **Phase 2 — WLCG HTTP Tape REST** (`../webdav/tape_rest.c`): `/api/v1/{stage,
  release,unpin,archiveinfo,fileinfo,stage/{id}[/cancel]}` over the same queue
  via the `frm_*` façade. Off by default (`xrootd_webdav_tape_rest`).
  Test: `test_tape_rest.py`.
- **Phase 3 — async completion** (`waiter.c`, behind `xrootd_frm_async_recall`):
  a nearline open is parked with `kXR_waitresp` and satisfied in place via
  `kXR_attn(asynresp)` when the recall lands. Same-worker deliveries are inline;
  cross-worker completions are marked ready in the SHM waiter table and delivered
  by the owning worker's scheduler tick (no IPC). Test: `test_frm_async.py`.
- **Phase 4 — parity (all of F1–F6).** F2 (selector/DN on requests), F4
  (`xrootd_frm_max_per_source` per-DN admission cap), and F6 (`migrate_purge.c`
  Category-2 **scaffold** — a worker-0 watermark monitor that only logs; the
  engine is delegated to the MSS backend). The remaining three live in the
  **stage agent** (`stage.c`): **F1** registers the now-resident path with the
  manager on stage completion in manager mode (cmsd Have); **F3** consults
  `xrootd_frm_residency_cmd` as an out-of-band oracle before copying (exit 0 =
  already resident → skip copy; exit 2 = offline → fail); **F5** verifies the
  recalled file's checksum (`cs_type`/`cs_value`, via `../compat/checksum.c`) and
  fails the recall on mismatch — the Tape REST `/stage` body carries the optional
  per-file `checksum`/`checksumType`. Tests: `test_frm_phase4.py`,
  `test_frm_phase4_engines.py`.

Every SHM zone here (`index.c`, `waiter.c`) is slab-allocated via
`../compat/shm_slots.h` so it never clobbers nginx's slab-pool header — enforced
by `tests/test_shm_slab_safety_lint.py`.
