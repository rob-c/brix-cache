# Unified Cache Persistence-State Engine + Decision Parity

**Date:** 2026-06-28 · **Status:** Design — approved for spec review · **Owner:** Rob Currie

## North star (context, not all in this spec)

Grow `src/fs/cache/` from two loosely-related halves (XCache-style read-through fill;
write-through origin mirroring) into a **universal caching layer** that any backend
can turn on — POSIX, tape, S3, or as a classic standalone read/write cache in front
of remote storage — with **one shared persistence-state engine** underneath both the
read-fill and write-back halves.

That north star is several sub-projects. **This spec is the foundation only:**

- **In scope:** a unified per-file persistence-state engine (per-block *present* +
  file-level *dirty*/write-back state), wiring the existing read-fill and
  write-through flush to it on the current **POSIX** cache path, and config/decision
  **parity** between the read and write halves. Backend-agnostic by construction (it
  lives at the cache/state layer, above the VFS).
- **Explicitly deferred to follow-on specs:** routing the cache's own data I/O through
  the VFS/driver seam so the cache can front pblock/S3/tape primaries; making the
  cache's *storage* itself pluggable (e.g. pblock-backed cache data); a standalone
  remote-cache deployment mode; per-block (rather than file-level) dirty tracking.

## Goals & non-goals

**Goals**
1. One state record per logical file that both halves consult: read-fill records which
   blocks are *present*; the write path records the file as *dirty*; write-through
   flush records it *clean*.
2. Durable write-back state: a pending write-back survives a restart (today it is
   tracked only in memory on the open handle).
3. Eviction safety: a file with un-flushed local writes is never evicted.
4. Config/decision parity: read-caching is configured with the same shape as
   write-through (shared prefix/size/regex admission filter, symmetric directives).
5. Bounded accumulation: a stale-dirty reaper removes abandoned write-back staging older
   than a configurable age (default 7 days) so dirty-file eviction protection cannot leak
   disk indefinitely.
6. **Zero regression** on the existing POSIX read-through and write-through paths when
   no state root is configured.

**Non-goals (this spec)**
- No change to where cached *bytes* live (still POSIX files under `cache_root`).
- No per-block dirty tracking (file-level dirty extent, mirroring today's handle state).
- No new served-read behavior driven by the record (it stays record-keeping, as the
  present bitmap is today).
- No backend (S3/tape/pblock) fronting work.

## Component 1 — the unified state record (`.cinfo` v3)

Generalize the existing `.cinfo` sidecar (`src/fs/cache/cinfo.{c,h}`) — today a per-block
**present** bitmap with a fixed header — to also carry **file-level write-back state**.
Keep the sidecar name, path, and the `flock(2)`-serialized read-modify-write (it
already works cross-process and cross-UID). Bump `XROOTD_CACHE_CINFO_VERSION` 2 → 3 and
append fields to the fixed header; the per-block present bitmap that follows the header
is unchanged in meaning and layout.

**New header fields** (appended; struct stays largest-alignment-first with explicit
`reserved` pad so the on-disk layout is deterministic):

| Field | Type | Meaning |
|---|---|---|
| `flags |= XROOTD_CINFO_F_DIRTY` | bit | local writes pending write-back |
| `dirty_lo` | `uint64` | dirty byte-extent start (inclusive) |
| `dirty_hi` | `uint64` | dirty byte-extent end (exclusive); `lo==hi` ⇒ clean |
| `dirty_since` | `uint64` | unix secs the file first went dirty this episode; set on the clean→dirty transition, cleared by `mark_clean`. The age basis for the stale-dirty reaper (works even when a flush never succeeded). |
| `flush_gen` | `uint64` | bumped on each successful write-back (resume/stats) |
| `last_flush` | `uint64` | unix secs of the last successful write-back |
| `bytes_flushed` | `uint64` | cumulative mirrored bytes (parity w/ wt metrics) |

The existing fields (`size`, `mtime`, `nblocks`, access stats, `etag`, `cks_*`,
`COMPLETE`/`PARTIAL`/`VERIFIED` flags) and the trailing present bitmap are retained.

**Migration:** a v2 sidecar loads as present-only with `dirty=clean` — correct, because
pre-upgrade caches tracked write-back only in memory. A short/garbage record still
returns `NGX_DECLINED` ⇒ "nothing recorded," exactly as today, so a torn write is
always safe. No operator action; cache files are regenerable.

**New engine API** (alongside the existing `record_block`/`mark_block`/`block_present`/
`load`/`store`):

- `ngx_int_t xrootd_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
  uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, ngx_log_t *log)`
  — flock RMW: set `DIRTY`, widen `[dirty_lo,dirty_hi)` to cover `[off,off+len)`, set
  `dirty_since=now` **only on the clean→dirty transition** (a widen of an already-dirty
  record leaves `dirty_since` untouched so age reflects the oldest pending write),
  resetting validity if `size`/`mtime`/`block_size` changed (same reset rule as
  `record_block`).
- `ngx_int_t xrootd_cache_cinfo_mark_clean(const char *cache_path, uint64_t bytes,
  ngx_log_t *log)` — flock RMW: clear `DIRTY`, set `dirty_lo=dirty_hi=0`,
  `dirty_since=0`, bump `flush_gen`, set `last_flush=now`, add `bytes` to
  `bytes_flushed`.
- `ngx_int_t xrootd_cache_cinfo_dirty_extent(const char *cache_path, uint64_t *lo,
  uint64_t *hi, uint64_t *dirty_since)` — query for the flush path, the eviction guard,
  and the stale-dirty reaper. `NGX_DECLINED` when no record / clean.

The present-bitmap RMW preserves the new dirty fields and vice-versa (both are
load → mutate-one-half → store under the same flock), so the halves never clobber.

## Component 2 — read-fill + write-flush wiring

**State root.** The record lives under a **state root**, resolved via the existing
`xrootd_cache_path_for_resolved()` (logical export path → cache path → `.cinfo`). A new
directive `xrootd_cache_state_root <path>` names it; when **unset it defaults to
`cache_root`** (if configured). When neither resolves, the persistent dirty record is
skipped and write-through keeps today's in-memory handle state — **no regression**, no
new required config.

**Read fill** (`slice_fill.c`, `fetch.c`): already calls
`xrootd_cache_cinfo_record_block()` → marks blocks present. Unchanged; the RMW now
preserves the new dirty fields automatically.

**Write path.** The in-memory handle dirty marking (`writethrough_metrics.h`
`xrootd_wt_mark_dirty`) is unchanged and stays per-write (it is a cheap field update).
The **persistent** record is updated at *coarse* points only — never per write, since a
flock RMW per write would be a performance landmine. The persist call
(`xrootd_cache_cinfo_mark_dirty()`, made from the write/sync handler `.c`, not from the
hot header inline) fires on:
1. the **clean → dirty transition** (the first write of a dirty episode), and
2. each **`kXR_sync`/checkpoint** point (widen the recorded extent),

and only when (a) the handle is `wt_enabled` and (b) a state root resolves. Best-effort:
a record failure logs and continues (never fails the client write). This is enough to
keep the durable record ahead of any eviction or crash without per-write cost.

**Write-through flush** (`writethrough_flush.c` done path): on a *successful* flush call
`xrootd_cache_cinfo_mark_clean(bytes_flushed)`. A short-read/abort leaves `DIRTY` set
(correct — still pending). (Resume-on-open of a leftover dirty record is noted as a
natural follow-on; not wired in this spec.)

**Eviction guard** (`evict_candidates.c` / `evict_policy.c`): when collecting
candidates, skip any file whose `.cinfo` reports a dirty extent (`dirty_lo<dirty_hi`).
A dirty file must never be evicted before its write-back lands. This is the central
correctness win of unifying the state.

**Stale-dirty reaper** (`cache_reap.c` — new). The eviction guard protects dirty files
*indefinitely*, so an abandoned write-back (origin permanently gone, client vanished)
would accumulate forever. A **periodic per-worker reaper** bounds this. It runs on a
maintenance timer (independent of occupancy — eviction only fires under disk pressure,
which a low-occupancy node may never reach) armed in `init_process`, reusing the
existing recursive cache-tree scan (`evict_candidates.c`, with its skip-list +
same-device guard). For each `.cinfo` it loads: if `DIRTY` and
`now - dirty_since > xrootd_cache_dirty_max_age`, it **removes unconditionally** — the
cached/staging data file plus its `.cinfo`/`.meta`/slice sidecars — and emits a `WARN`
(path + age + dirty bytes discarded) and bumps a metric. This is intentional data loss
of writes that never reached the authoritative store within the window; the WARN makes
it auditable. Default age **604800 s (7 days)**; `xrootd_cache_dirty_max_age 0` disables
the reaper entirely. The same scan also reaps a dirty record whose data file has already
vanished (orphan `.cinfo`).

## Component 3 — config/decision parity

Extract the write-through's prefix/size/regex matcher into **one shared admission
filter** and give read-caching the symmetric directives.

**Shared filter** (lift the logic out of `writethrough_decision.c` into a small,
unit-testable unit — `cache_admit.{c,h}`):

```
typedef struct { /* prefixes are NUL-terminated arrays from config */
    xrootd_str_array_t  deny_prefix;
    xrootd_str_array_t  allow_prefix;
    off_t               size_limit;     /* 0 = no limit */
    ngx_regex_t        *include_regex;  /* NULL = match all */
} xrootd_cache_admit_cfg_t;

xrootd_cache_admit_e xrootd_cache_admit(const xrootd_cache_admit_cfg_t *cfg,
    const char *path, off_t size);   /* ADMIT | DECLINE */
```

Rules (exactly today's `xrootd_wt_default_decide` filter, lifted): deny beats allow; a
non-empty allow list makes it a whitelist; size over limit or `include_regex` miss ⇒
DECLINE; NULL cfg/path ⇒ DECLINE (fail-closed).

**Two thin wrappers** preserve each side's distinct outcome:
- Write: `xrootd_wt_decide()` → `DENY | ALLOW_SYNC | ALLOW_ASYNC` (= `admit` + `wt_mode`).
- Read: `xrootd_cache_admit_read()` → `ADMIT (fill) | DECLINE (redirect to origin)` —
  today's `fetch.c` admission, now using the shared filter.

**Symmetric directives** (read side gains parity with the write side):
- `xrootd_cache_allow_prefix <p>` / `xrootd_cache_deny_prefix <p>` — **new**, mirror
  `xrootd_wt_allow_prefix` / `xrootd_wt_deny_prefix`.
- `xrootd_cache_max_file_size`, `xrootd_cache_include_regex` — already exist; route them
  through the shared cfg.
- `xrootd_cache_state_root <path>` — **new** (Component 2), defaults to `cache_root`.
- `xrootd_cache_dirty_max_age <secs>` — **new** (Component 2 reaper); default `604800`
  (7 days); `0` disables the stale-dirty reaper.

**Deliberate asymmetry (documented, not papered over):** there is no new read "mode"
directive. Read fills are inherently async (thread-pool), and whole-vs-slice is already
`xrootd_cache_slice`; inventing an `xrootd_cache_mode` knob that does nothing would be
noise. The write side keeps `xrootd_wt_mode sync|async`.

## Error handling

Every state-engine call is best-effort and flock-guarded. A missing/garbage record ⇒
`NGX_DECLINED` ("nothing recorded") and the caller proceeds (blocks look absent /
file looks clean — both safe). A dirty-record write failure logs and falls back to the
in-memory handle state; it never fails the client operation. The eviction guard
fails *safe*: if it cannot read a `.cinfo`, it treats the file as **not** evictable only
when a record exists and is dirty; an unreadable/absent record is evictable as today
(a file with no record has no tracked dirty writes).

## Testing

**Unit (standalone, no nginx) — extend `tests/c/test_cinfo.c`:**
- v3 round-trip: header+bitmap store/load with the new fields.
- dirty lifecycle: `mark_dirty` sets flag + extent + `dirty_since` (only on the
  clean→dirty transition; a second widen leaves `dirty_since` unchanged); `mark_clean`
  clears the extent + `dirty_since` and bumps `flush_gen`/`last_flush`/`bytes_flushed`.
- RMW non-interference: mark present → mark dirty → mark present; both survive.
- v2→v3: a v2 sidecar loads as present-only/clean.
- validity reset: changed size/mtime resets present + dirty.

**Unit — new `tests/c/test_cache_admit.c`:** deny-beats-allow, whitelist, size limit,
regex include/exclude — asserted identically through the read and write wrappers.

**e2e (pytest, existing harness):**
- write-through flush leaves the record clean with `flush_gen` bumped.
- a file with a pending dirty extent is NOT evicted under occupancy pressure; once
  flushed (clean) it becomes evictable.
- a read fill marks blocks present without clearing a concurrent dirty flag.
- `xrootd_cache_{allow,deny}_prefix` admit/redirect behavior matches the write-side
  prefixes.
- **stale-dirty reaper:** a record forced dirty with `dirty_since` older than a small
  test `xrootd_cache_dirty_max_age` is removed (data file + sidecars gone, WARN logged,
  metric bumped); a fresh dirty record and a clean record are both left untouched;
  `xrootd_cache_dirty_max_age 0` disables removal.

**Regression:** existing read-through + write-through suites stay green; the POSIX
path is byte-for-byte unchanged when no state root is configured.

## Files touched

- `src/fs/cache/cinfo.{c,h}` — v3 record + dirty API.
- `src/fs/cache/cache_admit.{c,h}` — **new** shared admission filter.
- `src/fs/cache/writethrough_decision.c` — `xrootd_wt_decide` delegates to the shared filter.
- `src/fs/cache/writethrough_flush.c` — `mark_clean` on successful flush.
- `src/write/sync.c`, `src/read/close.c` (and the clean→dirty transition in the write
  handler) — `mark_dirty` at coarse points only (NOT per write; NOT in the
  `writethrough_metrics.h` hot inline, which keeps only the in-memory field update).
- `src/fs/cache/fetch.c` — read admission via the shared filter.
- `src/fs/cache/evict_candidates.c` / `evict_policy.c` — dirty-file eviction guard;
  expose the recursive scan for reuse by the reaper.
- `src/fs/cache/cache_reap.{c,h}` — **new** stale-dirty reaper + its maintenance timer
  (armed in `init_process`, like `pelican_register`'s advertise timer).
- `src/fs/cache/directives.c` + config struct — `xrootd_cache_state_root`,
  `xrootd_cache_dirty_max_age`, `xrootd_cache_allow_prefix`, `xrootd_cache_deny_prefix`;
  route existing size/regex through the shared cfg.
- `src/fs/cache/paths.c` — state-root resolution (default to `cache_root`).
- `src/metrics/` — a `cache_dirty_reaped` counter (count + bytes), low-cardinality.
- `config` (NGX_ADDON_SRCS) — register `cache_admit.c`, `cache_reap.c`; `./configure` once.
- `tests/c/test_cinfo.c`, `tests/c/test_cache_admit.c`, e2e tests.

## Follow-on specs (north star, not here)

1. Route the cache's own data I/O through the VFS/driver seam → cache can front
   pblock/S3/tape primaries (subsumes the deferred pblock Layer-5 write-through-via-driver
   gap).
2. Pluggable cache *storage* (e.g. pblock-backed cache data; the catalog as the state
   engine).
3. Standalone remote-cache deployment mode + per-block dirty tracking (partial flush,
   resume-on-open).
