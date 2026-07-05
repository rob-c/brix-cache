# CVMFS-brix "clever client" — design (reaping + overlay cache + DPI hardening)

**Date:** 2026-07-04
**Status:** approved → implementation
**Builds on:** [2026-07-04-brix-mount-platform-design.md](2026-07-04-brix-mount-platform-design.md)

Three enhancements to the CVMFS-brix FUSE client.

## a) In-process cache reaper (quota watermark)

`shared/cache/cas_store.c` already has `brix_cas_reap()` (LRU by atime) + `brix_cas_size()`.
Add:
- Running `cur_bytes` counter → O(1) fill-guard (incremented in `brix_cas_put`, adjusted by
  reap, seeded from `brix_cas_size` at init).
- `quota_bytes` becomes a real high watermark; `brix_cas_put` auto-reaps to a **low watermark
  = 75% of quota** when a store pushes over quota (fill-guard).
- `cvmfs_client_reap_tick(cl, now)` — time-gated (~30s) safety net for a cache adopted
  over-quota from a prior run; called opportunistically from `getattr`/`read`.
- Quota source: `CVMFS_QUOTA_LIMIT` (MB, stock) or `-o quota=<MB>`. Entirely in-process, so it
  works under unprivileged fusermount (the process owns the cache files — no quota daemon).

## b) Clever overlay mount — DEFAULT ON (opt-out)

`brix_cas_store` gains a **dirfd mode**: when `dirfd >= 0`, every op uses
`openat/mkdirat/renameat/fstatat/unlinkat` on dirfd-relative paths (atomic put =
`openat(O_CREAT|O_EXCL)` temp + `fsync` + `renameat`). New `brix_cas_init_at(store, dirfd,
quota)`. Absolute mode unchanged.

Front-end default: **before** `fuse_main` → `mkdir <target>/.brixcache`, `open()` a dirfd to
it, init the CAS store via that dirfd, **then** mount FUSE over `<target>`. The overlay hides
`.brixcache` from users; the process keeps reading/writing it through the preserved fd (no
recursion into its own mount). On unmount the cache persists in `<target>/.brixcache`. Catalog
spill temp files stay in a normal `/tmp` dir (independent of the overlay).

**Opt-out:** `-o noclever`, or an explicit cache dir (`-o cache=DIR` / `BRIXCVMFS_CACHE`), uses
a separate absolute cache dir (the pre-existing behaviour). An explicit cache dir implies
non-clever, which keeps existing live tests unchanged.

`cvmfs_client_mount` gains two params — `quota_bytes` + `cache_dirfd` (`-1` = use `cache_dir`
path); its two callers (client_unittest, brixcvmfs) are updated.

## c) DPI / transfer hardening

Within-mirror retries in the transport; across-mirror failover already in `fetch`.
- `brixcvmfs_transport` retries the same URL up to `CVMFS_MAX_RETRIES` (default 2) with
  exponential backoff on the retryable libcurl errors a DPI causes: `PARTIAL_FILE`,
  `RECV_ERROR`, `GOT_NOTHING`, `OPERATION_TIMEDOUT`, `COULDNT_CONNECT`. (Hash mismatch is
  still caught in `fetch` → blacklist + failover.)
- **Fresh connection per request** (`-o fresh`): `CURLOPT_FRESH_CONNECT` + `FORBID_REUSE` to
  defeat stateful/connection-reaping DPI.
- **Prefer TLS** (`-o tls`): for an `http://` host, try `https://` first, fall back to
  `http://` — hides object bytes from a content-inspecting DPI (integrity already
  hash-guaranteed).
- Knobs via a small brix `-o` extractor (`clever`/`noclever`, `quota=`, `fresh`, `tls`,
  `retries=`, `cache=`; remaining `-o` opts forwarded to fuse) + `CVMFS_QUOTA_LIMIT` /
  `CVMFS_MAX_RETRIES` from the config cascade.

**Out of scope (YAGNI):** HTTP range-resume — objects are content-addressed and large files
are chunked, so retry-from-scratch + hash-verify is correct and far simpler.

## Testing
- cas_store unit: dirfd-mode put/get/reap + quota auto-reap fill-guard (extend
  `run_cache_unit.sh`).
- transport unit: retryable-error classifier + http→https rewrite (pure helpers, no network).
- live: `-o clever` (default) mount — assert `.brixcache` populated + hidden while mounted +
  persists after unmount; quota-reap live check.
