# root:// slice-read → cstore/sd_cache Migration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fold the legacy Phase-26 root:// slice cache (`src/read/slice_read.c` + `src/cache/slice_fill.c` + `src/cache/slice.c`) into the unified phase-64 `sd_cache` partial mechanism, so §6.5's "there is no separate `slice_fill.c`" holds — one slice/partial implementation shared by root:// and WebDAV/S3.

**Architecture:** The root:// read path already serves driver-backed cache objects: `xrootd_open_resolved_via_driver` adopts an `sd_cache` object into `fh->sd_obj`, and `src/read/read.c` serves it through `sd_obj.driver->pread` (the non-sendfile path). `sd_cache` already implements sparse slice fill (`sd_cache_partial_open` + the cstore serve loop). So the migration routes the slice branch in `open_cache.c` through an `sd_cache` decorator (source = the origin, store = `cache_root`, `slice_size` set) instead of `xrootd_open_slice_handle`, then deletes the three legacy files. The legacy `cache_origin_host`+`cache_slice_size` config is mapped onto an internally-composed `sd_cache` instance so no user-facing config changes.

**Tech Stack:** C (nginx stream module), `sd_cache`/`cstore` (`src/fs/backend/cache/`, `src/cache/`), the tier composition (`src/fs/tier/tier_build.c`, `xrootd_sd_cache_create`, `xrootd_sd_xroot_create_origin`), the driver-backed open/read path (`src/read/open_resolved_file.c`, `read.c`), and the existing slice tests (`tests/test_slice_cache.py`, `tests/c/run_cinfo_tests.sh`) plus a new root:// slice harness as the parity gate.

## Global Constraints

- **Behavior-preserving for the user:** the `xrootd_cache_slice_size` + `xrootd_cache_origin` config keeps working; only the internal mechanism changes. root:// slice reads must remain byte-exact and range-filled (sparse), verified against the pre-migration behavior.
- **NO `goto`**; **raw byte I/O stays in `src/fs/backend/`** (the seam guard) — the new path serves through `sd_obj.driver`, not raw fds in `src/read/`.
- **The hot path is `read.c`/`open_cache.c`** — no new per-read allocation or syscalls; the driver-backed serve path already exists, reuse it.
- **Do not delete the legacy files until parity is proven** (Phase 4 is gated on Phase 3 passing).
- **`slice.c` vs `slice_fill.c` vs `slice_read.c`:** confirm each file's exact role before deleting (grep every exported symbol for external callers — `src/read/slice_read.h`, `cache_internal.h` slice decls). A symbol still used elsewhere blocks the delete until its caller is migrated.
- Build: incremental `make -j$(nproc)`; `./configure` only when a source file is removed from the `config` addon list (Phase 4).

---

### Task 1: Compose an `sd_cache` partial instance from the legacy slice config

Give the stream config an `sd_cache` decorator (source = origin, store = `cache_root` posix, `slice_size` set) built at config time when `cache_slice_size > 0` and an origin is configured — reachable from `open_cache.c` at open time. Reuses the existing `tier_build` composition rather than the legacy `slice_read` machinery.

**Files:**
- Modify: `src/cache/cache_storage.c` (build the slice `sd_cache` instance beside `cache_storage_inst`)
- Modify: `src/core/types/config.h` (a field to hold it, e.g. `void *cache_slice_inst`)
- Test: config validation + a startup smoke (no serve yet)

**Interfaces:**
- Consumes: `xrootd_sd_xroot_create_origin(host, port, tls, ...)` (`tier_build.c:107`), `xrootd_sd_cache_create(source, store, policy, local_root, log)` (`tier_build.c:241`), the legacy `conf->cache_origin_host/_port`, `conf->cache_slice_size`, `conf->cache_root`.
- Produces: `conf->cache_slice_inst` — an `sd_cache` instance in slice mode (policy `slice_size = cache_slice_size`), or NULL when slice caching is off. Accessor `xrootd_sd_instance_t *xrootd_cache_slice_inst(const ngx_stream_xrootd_srv_conf_t *conf)`.

- [ ] **Step 1: Add the conf field + accessor** (mirror `cache_storage_cstore` from the cache-policy plan): `void *cache_slice_inst;` in `config.h`; declare/define `xrootd_cache_slice_inst` in `cache_storage.{h,c}`.

- [ ] **Step 2: Build it at config time.** In `xrootd_cache_storage_init`, when `conf->cache_slice_size > 0 && conf->cache_origin_host.len > 0`: build the origin source (`xrootd_sd_xroot_create_origin` from `cache_origin_host/_port/_tls`), the posix store over `cache_root` (`xrootd_sd_posix_borrow_instance`), then `xrootd_sd_cache_create(source, store, &policy, cache_root, log)` with `policy.slice_size = cache_slice_size`. Store on `conf->cache_slice_inst`. Free in `xrootd_cache_storage_cleanup`.

- [ ] **Step 3: Build + startup smoke.** `make -j$(nproc)`; start a stream server with `xrootd_cache_origin` + `xrootd_cache_slice_size` and confirm it boots (the instance is built but not yet serving). Expected: clean start, no regression in existing slice tests (still on the legacy path).

---

### Task 2: Serve the root:// slice branch through the `sd_cache` instance

Route `open_cache.c`'s slice branch through the composed `sd_cache` partial object (adopted via the existing driver-backed open) instead of `xrootd_open_slice_handle`, behind a runtime toggle so the legacy path remains as a fallback until parity is proven.

**Files:**
- Modify: `src/read/open_cache.c` (the `cache_slice_size > 0 && cache_origin_host` branch, ~line 44)
- Reuse: `xrootd_open_resolved_via_driver` (`open_resolved_file.c`) to adopt the partial obj into `fh->sd_obj`
- Test: `tests/run_root_slice_fill.sh` (new — see Task 3)

**Interfaces:**
- Consumes: `xrootd_cache_slice_inst(conf)`, `xrootd_open_resolved_via_driver(inst, key, oflags, is_readable, is_write, mode, fh, &fd, &st)`, `xrootd_cache_key_under_root(conf, resolved)` (the export-relative key).
- Produces: a root:// read handle whose `sd_obj` is the `sd_cache` partial object; subsequent `kXR_read`/`readv`/`pgread` serve through `sd_obj.driver->pread` (the range-fill happens in the cstore serve loop).

- [ ] **Step 1: Write the parity test first** (Task 3's harness) and run it against the LEGACY path — capture the byte-exact + sparse-fill baseline.

- [ ] **Step 2: Route through the driver.** In `open_cache.c`, replace the `return xrootd_open_slice_handle(...)` with: resolve the slice key, `xrootd_open_resolved_via_driver(xrootd_cache_slice_inst(conf), key, ...)` into the handle, and return. Gate on `xrootd_cache_slice_inst(conf) != NULL`; fall back to `xrootd_open_slice_handle` when NULL (defensive during migration).

- [ ] **Step 3: Build + parity.** `make -j$(nproc)`; run the new root:// slice harness (Task 3). Expected: byte-exact reads, sparse fill (only-touched-blocks), matching the legacy baseline. Fix serve gaps (e.g., readv/pgread over a partial obj) until green.

- [ ] **Step 4: Guard + existing slice tests.** `bash tools/ci/check_vfs_seam.sh`; `PYTHONPATH=tests pytest tests/test_slice_cache.py -q`. Expected: guard GREEN; slice tests pass on the new path.

---

### Task 3: root:// slice parity harness

A self-starting harness proving root:// slice reads over the new `sd_cache` path are byte-exact and sparse (only touched blocks filled), mirroring `run_tier_slice_fill.sh` but over the stream protocol (xrdcp/xrdfs or raw-wire kXR_read ranges).

**Files:**
- Create: `tests/run_root_slice_fill.sh`

**Interfaces:**
- Consumes: an origin stream node + a cache stream node with `xrootd_cache_origin` + `xrootd_cache_slice_size`; a root:// client that can read a byte range (raw-wire `kXR_read`, or `xrdcp` of the whole file for byte-exactness + `du` on the cache file for sparseness).

- [ ] **Step 1: Origin + cache node configs** (two stream servers: O with `xrootd_root`, C with `xrootd_cache_origin root://O` + `xrootd_cache_slice_size 65536` + `xrootd_cache_root`).
- [ ] **Step 2: Assertions:** a partial read fills only the touched blocks (`du` on the cache file ≪ logical size); a full read is byte-exact; the cache file grows incrementally across reads (the re-open sparseness the WebDAV path proved).
- [ ] **Step 3: Run it — green on the new path.**

---

### Task 4: Delete the legacy slice subsystem (gated on Task 3 parity)

Once the new path passes parity, remove `slice_read.c`, `slice_fill.c`, `slice.c` (+ headers), their `config` entries, the legacy config plumbing they alone used, and the now-dead fallback in `open_cache.c`.

**Files:**
- Delete: `src/read/slice_read.{c,h}`, `src/cache/slice_fill.c`, `src/cache/slice.{c,h}`
- Modify: `config` (remove the three `.c` from `NGX_ADDON_SRCS`), `open_cache.c` (drop the fallback), `cache_internal.h` (remove `xrootd_cache_slice_*` decls), `src/read/slice_read.h` includers, `src/core/types/file.h` (`slice_cache_path`/`slice_clean_path` if now unused)
- Modify: `src/read/slice_read.c` callers (`src/read/slice_read.c` was called from `open_cache.c` only — confirm)

- [ ] **Step 1: Prove each symbol is dead.** For every exported symbol of the three files (`xrootd_open_slice_handle`, `xrootd_read_from_slices`, `xrootd_cache_slice_fetch_origin`, `xrootd_cache_slice_fill_thread`, and `slice.c`'s exports), `grep -rn` across `src/` → only self-references. Any live caller blocks deletion (migrate it first).
- [ ] **Step 2: Remove the fallback** in `open_cache.c` (the `xrootd_cache_slice_inst == NULL` branch that called `xrootd_open_slice_handle`).
- [ ] **Step 3: Delete the files + deregister** from `config`; remove dead decls from `cache_internal.h`/`file.h`.
- [ ] **Step 4: `./configure` + `make -j$(nproc)`** (a source file was removed). Expected: clean link, no undefined references.
- [ ] **Step 5: Full gate.** guard GREEN; `run_root_slice_fill.sh`, `run_tier_slice_fill.sh`, `test_slice_cache.py`, `run_cinfo_tests.sh` all pass; a root:// read smoke (`xrdcp`) byte-exact.

---

## Risks & sequencing notes

- **Hot path:** `read.c`/`open_cache.c` are the busiest code in the module. Task 2 keeps the legacy path as a runtime fallback until Task 3 proves parity — do **not** delete (Task 4) before that.
- **Serving parity unknowns:** the legacy slice path had its own readv/pgread handling; verify `kXR_readv` and `kXR_pgread` over a partial `sd_obj` (not just `kXR_read`) in Task 3 — the vectored ops are the most likely gap.
- **Config reconciliation:** `cache_origin_host` (legacy) vs `cache_store` (composable) — Task 1 maps the legacy config onto an internal `sd_cache`; a follow-up (out of scope) could deprecate `cache_origin_host` in favor of `cache_store` entirely.
- **`test_slice_cache.py`** notes the original C/D slice design "needs redesign" — treat its currently-skipped cases as informational; the new parity harness (Task 3) is the authoritative gate.

## Self-Review

- **Spec coverage (§6.5 "no separate slice_fill.c"):** Task 1 composes the unified instance, Task 2 routes to it, Task 3 proves parity, Task 4 deletes the legacy files. ✔
- **Feasibility grounded:** the root:// read path already serves driver-backed objects via `fh->sd_obj`/`read.c` (confirmed), and `sd_cache` already does sparse slice fill (confirmed + tested by `run_tier_slice_fill.sh`) — so no new serving mechanism is invented. ✔
- **Placeholder scan:** the config-build (Task 1) mirrors the proven `cache_storage_cstore` pattern; the serve-route (Task 2) reuses `xrootd_open_resolved_via_driver`. The two "confirm the symbol/role by grep" steps are verification of existing names, not logic gaps. ✔
- **Risk containment:** deletion is gated behind a runtime fallback + a parity harness; the vectored-read gap is explicitly called out for Task 3. ✔
