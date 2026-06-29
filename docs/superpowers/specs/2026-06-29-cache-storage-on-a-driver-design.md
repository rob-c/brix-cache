# Cache Storage on a Storage Driver + Exclusive-VFS Cache (Phase 2)

**Date:** 2026-06-29 · **Status:** Design — expanded; for spec review · **Owner:** Rob Currie

## Context

Phase 1 made the cache **front** a driver-backed primary (the write-through flush
reads the locally-written file through the export's driver). Phase 2 makes the
cache's **own stored bytes** live on a storage driver and, per Rob's directive,
routes **all** of the cache's disk I/O through the VFS/SD seam — no raw libc disk
calls — so every storage role (primary, read cache, write-staging cache) is
independently backend-pluggable (POSIX driver by default, pblock when configured,
object/tape later). See [[unified_cache_state_engine]] and [[pblock_layer3_4_data_plane]].

The enabler exists: the SD seam's **`staged_*` commit abstraction** (`staged_open`
→ `staged_write` → `staged_commit(noreplace)` / `staged_abort`) — the same
backend-neutral staged-write-then-atomic-publish primitive the primary write path
already uses. Each driver implements the publish its own way (POSIX/pblock: temp +
rename; object: multipart-complete / copy-to-final).

## Core principle: the cache uses the SD seam EXCLUSIVELY

The cache ALWAYS operates through an `xrootd_sd_instance_t` for disk I/O — the
**POSIX driver bound automatically** when no backend is named, the configured
driver otherwise. There is **no raw-libc disk path** in the cache: fill, hit-serve,
eviction, the stale-dirty reaper, the per-file lock, and the `.cinfo`/`.meta`
sidecar bytes all go through driver vtable ops (`open`/`pread`/`pwrite`/`fstat`/
`rename`/`unlink`/`opendir`/`readdir`/`staged_*`). Pure in-memory helpers (cinfo
struct pack/unpack, bitmap ops, path arithmetic) stay; only their **byte I/O**
moves onto the driver. This is the cache's analogue of the export-side VFS seam
closure ([[vfs_seam_closure_progress]]).

## The three storage roles

Each is an independent registry-bound driver instance (own root ⇒ own catalog):

| Role | Directive (backend) | Root directive | Holds |
|---|---|---|---|
| Primary export | `xrootd_storage_backend` | `xrootd_root` | the authoritative bytes (done: Layer 3) |
| Read cache | `xrootd_cache_storage_backend` | `xrootd_cache_root` | origin fills (read-through) |
| Write-staging cache | `xrootd_cache_wt_stage_backend` | `xrootd_cache_wt_stage_root` | durable write-back staging |

Unset backend ⇒ that role uses the POSIX driver on its root (default, unchanged
behaviour). A driver-backed role REQUIRES a separate POSIX `xrootd_cache_state_root`
for its `.cinfo`/`.meta` sidecars (they cannot live in a non-POSIX data root) —
config-time validation enforces this.

## Goals & non-goals

**Goals**
1. The cache performs **all** disk byte I/O through the SD driver seam — POSIX
   driver by default, zero behavioural change when no backend is named.
2. Read cache and write-staging cache are independently backend-pluggable (pblock
   built/tested; object-ready seam).
3. Write-back staging: a write lands in the primary AND a copy is staged in the
   write-staging cache; the write-through flush mirrors to the origin **from the
   staging copy**, decoupled from the live primary; the `.cinfo` dirty record +
   stale-dirty reaper bound abandoned staging.
4. The two acceptance tests below pass.

**Non-goals (this spec)**
- No S3/object cache driver *implementation* (seam stays ready).
- No driver-backing of the **slice cache** (`slice_fill.c`) — whole-file only.
- No change to the `.cinfo`/`.meta` engine *format* — it stays POSIX in
  `cache_state_root`, now read/written via the (POSIX) driver.

## Component 1 — cache storage instances (always a driver)

`src/cache/cache_storage.{c,h}` (new): config-time registration + per-worker
resolution of the three role instances. `xrootd_cache_storage(conf)` and
`xrootd_cache_wt_stage(conf)` return the bound `xrootd_sd_instance_t *` (POSIX
driver bound to the role's root when no backend named — never NULL when the role
is active). The export-relative cache key (server-controlled, no raw client path)
keys each driver's namespace. Config validation: a driver-backed cache/stage role
requires `xrootd_cache_state_root` set to a distinct POSIX dir.

## Component 2 — fill via the driver + `staged_*`

`fetch.c` (whole-file). Replace `open(.part)`→write→`fsync`→`rename` with:
`staged_open(cache_key)` on the read-cache instance → `staged_write` each
downloaded chunk → `staged_commit(noreplace=0)`. **Verify**: AFTER commit, read the
committed entry back through the driver and checksum it; on mismatch
`driver->unlink` + `NGX_DECLINED` (commit-then-verify-then-evict, Rob's choice).
The origin read loop targets a small **sink** (`xrootd_cache_sink_t { staged; off }`)
with one `sink_write()` so the loop is not duplicated. On any failure: `staged_abort`.

The default POSIX role uses the POSIX driver's `staged_*` (temp + rename) — same
atomic-publish guarantee as today, now via the vtable. `.cinfo`/`.meta` writes go
through the driver bound to `cache_state_root`.

## Component 3 — hit-serve via the driver

`open.c` `xrootd_cache_open`: `driver->stat(cache_key)` readiness → `driver->open`
(READ) → `validate_meta` against the `.cinfo`/`.meta` at the state path →
`xrootd_vfs_adopt_obj` (Layer-3 helper) into the VFS handle. The normal read path
serves it, memory-serving when `xrootd_vfs_file_sendfile_fd` is INVALID (the exact
root:// pblock gating). Multi-block entries serve via the driver's `preadv`.

## Component 4 — eviction + reaper via the driver namespace

`evict_candidates.c`/`evict_policy.c`/`cache_reap.c`: enumerate via
`driver->opendir`/`readdir` (a POSIX scan can't see driver-backed entries), score
by the `.cinfo` `last_access`/`access_count` (no `atime` on objects), skip DIRTY
entries (existing guard), remove via `driver->unlink` + sidecar `unlink` (driver).
`evict_policy.c`'s `statvfs` occupancy gate + two-pass LRU are reused.

## Component 5 — write-back staging cache (builds on the EXISTING FRM journal)

**Reuse the existing write-back state engine, do not add a parallel one.** The
codebase already tracks in-flight write-backs durably in the **FRM journal**
(`src/frm/`): `writethrough_flush.c` records each async flush via
`xrootd_wt_journal_begin` (`frm_request_add` + `frm_request_set_status(STAGING)`,
kind `FRM_XFER_WT`) and resolves it via `xrootd_wt_journal_finish` (delete on
success / `FAILED` for replay); `writethrough_replay.c` is the per-worker consumer
that, after a crash, requeues `FAILED`/claims `QUEUED` `wt` records and re-drives
the flush (`frm_reconcile` resets crashed `STAGING`→`QUEUED`). This Component adds
**durable bytes** for that journal to read from — it does not invent new state.

When `xrootd_write_through` is on and a write-staging role is active:
- **On write/sync**: in addition to the primary write, stage the written extent
  into the write-staging instance via `staged_*`/driver `pwrite`, keyed by the
  logical path (the same key the FRM `wt` record's `lfn` already identifies). This
  is the durable copy the journaled flush will mirror from.
- **Flush + replay** (`writethrough_flush.c` + `writethrough_replay.c`): read the
  to-be-mirrored bytes from the **staged copy** (driver `open`+`pread`) instead of
  re-opening the primary. Phase 1's primary read becomes the fallback when no
  staging role is configured. Crucially this makes the **existing replay correct**:
  a record re-driven after a restart reads the immutable staged bytes, not a
  primary that may have changed or been evicted since.
- **Lifecycle is the journal's**: on a successful flush, `xrootd_wt_journal_finish`
  deletes the FRM record (as today) AND the staged copy is removed; on failure the
  record stays `FAILED` and the staged copy persists for `writethrough_replay` to
  re-drive. The `.cinfo` dirty record + stale-dirty reaper remain the READ-cache
  eviction guard; the FRM journal remains the authoritative WRITE-BACK state engine
  (the two are complementary, not duplicated).

## Error handling & confinement

Every driver-op failure is best-effort decline/skip (client falls back to origin /
the op is retried later). The driver owns confinement (catalog-keyed, no raw client
path); `O_NOFOLLOW` is POSIX-specific and N/A to a driver namespace. The POSIX
driver preserves today's `O_NOFOLLOW`/`O_NOCTTY` safety internally.

## Testing (the two acceptance tests)

**Test 1 — `tests/run_cache_pblock_posix.sh`:** pblock PRIMARY + **POSIX** read
cache + **POSIX** write-staging cache. A read miss fills the POSIX read cache and
the second GET hits byte-exact; a write to the pblock primary mirrors to the origin
via the POSIX write-staging copy (byte-exact). Asserts the cache trees are POSIX
files and the primary is pblock.

**Test 2 — `tests/run_cache_pblock_pblock.sh`:** pblock PRIMARY + **pblock** read
cache (location B) + **pblock** write-staging cache (location C), a separate POSIX
`cache_state_root`. Read miss fills the pblock read cache (bytes in B's `data/` +
catalog, not POSIX) and the second GET hits byte-exact; a write to the primary
stages into C and mirrors to the origin from C (byte-exact). Asserts B and C hold
pblock catalogs/data, the sidecars are POSIX under `cache_state_root`.

**Regression:** with no cache backends named, fill/serve/evict/write-through are
byte-for-byte unchanged (existing cache pytest + `run_pblock_writethrough.sh` +
`run_pblock_root.sh`/`_webdav.sh` + the cinfo/admit unit tests stay green).

## Files touched (high level)

- `src/cache/cache_storage.{c,h}` (new) — the three role instances + resolution.
- `src/cache/directives.c`/`module.c`/`src/types/config.h`/`server_conf.c` —
  `xrootd_cache_storage_backend`, `xrootd_cache_wt_stage_backend`,
  `xrootd_cache_wt_stage_root`; state-root validation.
- `src/cache/fetch.c` — `staged_*` fill + sink + commit-then-verify.
- `src/cache/origin_protocol.c`/`origin_response.c` — read into the sink.
- `src/cache/open.c` — driver hit-open + obj-adopt.
- `src/cache/evict_candidates.c`/`evict_policy.c`/`cache_reap.c` — driver enumeration.
- `src/cache/meta.c`/`cinfo.c` — sidecar byte I/O via the (POSIX) driver (pure
  helpers unchanged; the standalone unit test keeps a raw-fd shim).
- `src/cache/lock.c`/`paths.c` — lock sentinel + mkdir/stat via the driver.
- `src/cache/writethrough_flush.c` — flush reads from the write-staging copy.
- `config`, `tests/run_cache_pblock_posix.sh`, `tests/run_cache_pblock_pblock.sh`.

## Follow-on (north star, not here)

1. S3/object cache + stage drivers (seam ready). 2. Driver-backed slice cache.
3. The driver catalog subsuming the `.cinfo`/`.meta` sidecars.
