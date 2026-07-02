# Cache Storage on a Driver + Exclusive-VFS Cache — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use `- [ ]`. **No git commit steps** — the operator drives commits (standing rule: no git without explicit instruction).

**Goal:** Route ALL of the cache's disk byte-I/O through the SD driver seam (POSIX driver by default, pblock when configured), make the read cache and a new write-back staging cache independently backend-pluggable, with zero behavioural change when no backend is named.

**Architecture:** A new `cache_storage.{c,h}` resolves a per-role `xrootd_sd_instance_t` (read cache, write-staging) via the existing backend registry — the POSIX driver bound automatically when no backend is named. Fill uses `staged_open/write/commit`; hit-serve uses `driver->open` + `vfs_adopt_obj` + memory-serve; eviction/reaper enumerate the driver namespace; sidecar bytes go through the (POSIX) driver. Write-through stages a copy into the write-staging cache and the flush mirrors from it.

**Tech Stack:** C (nginx stream module), the SD driver vtable (`src/fs/backend/sd.h`), the backend registry (`src/fs/vfs/vfs_backend_registry.h`), pblock (`sd_pblock.c`), standalone C unit tests + shell e2e.

## Global Constraints

- **NO `goto`**; functional/modular; one responsibility per function.
- **The cache performs NO raw-libc disk byte-I/O** — all `open`/`pread`/`pwrite`/`fstat`/`rename`/`unlink`/`opendir`/`readdir`/`staged_*` on cache data + sidecars go through an `xrootd_sd_instance_t`. Pure in-memory helpers (cinfo pack/bitmap, path arithmetic) stay.
- **Zero regression** when no cache backend is named: the POSIX driver is bound and behaviour is byte-for-byte unchanged. Every existing cache test stays green.
- New `.c` ⇒ register in repo-root `./config`, then `rm -rf /tmp/nginx-1.28.3/objs && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$(pwd) && make -j$(nproc)`. Existing-file edits ⇒ `make` only.
- Driver staged signatures (verbatim, `sd.h`): `xrootd_sd_staged_t *staged_open(inst, const char *final_path, mode_t, int *err)`; `ssize_t staged_write(st, const void *buf, size_t len, off_t off)`; `ngx_int_t staged_commit(st, int noreplace)`; `void staged_abort(st)`.
- Registry: `void xrootd_vfs_backend_config(const char *root_canon, const ngx_str_t *name, size_t block_size)`; `xrootd_sd_instance_t *xrootd_vfs_backend_resolve(const char *root_canon, ngx_log_t *log)` — resolve returns the configured driver or **the POSIX borrow instance** for an unregistered root (confirm in Task 1; if it returns NULL for unregistered, bind POSIX explicitly).
- Cache key = the server-controlled `xrootd_cache_path_for_resolved` / `xrootd_cache_state_path` output (no raw client path).

---

### Task 1: `cache_storage.{c,h}` — per-role driver instances (POSIX default)

**Files:**
- Create: `src/fs/cache/cache_storage.h`, `src/fs/cache/cache_storage.c`
- Modify: repo-root `config` (register `cache_storage.c`)
- Test: `tests/c/test_cache_storage.c` + `tests/c/run_cache_storage_tests.sh`

**Interfaces:**
- Produces:
  - `xrootd_sd_instance_t *xrootd_cache_storage(const ngx_stream_xrootd_srv_conf_t *conf);` — the read-cache instance (configured driver on `cache_root`, else the POSIX driver on `cache_root`). NULL only if `cache_root` is unset.
  - `xrootd_sd_instance_t *xrootd_cache_state_storage(const ngx_stream_xrootd_srv_conf_t *conf);` — the POSIX instance for the sidecar tree (`cache_state_root`, else `cache_root`).
  - `int xrootd_cache_key(const ngx_stream_xrootd_srv_conf_t *conf, const char *resolved, char *dst, size_t dstsz);` — the export-relative cache key (delegates to `xrootd_cache_path_for_resolved` then strips `cache_root` → a leading-slash logical key; mirrors `xrootd_vfs_export_relative_root`). 0/-1.

- [ ] **Step 1: Confirm `xrootd_vfs_backend_resolve` POSIX fallback.** Read `src/fs/vfs/vfs_backend_registry.c`: does `xrootd_vfs_backend_resolve(root, log)` return a POSIX instance for an *unregistered* root, or NULL? Note the answer — it decides whether `cache_storage.c` must call `xrootd_sd_posix_borrow_instance` itself.

Run: `grep -n 'posix_borrow\|return NULL\|default_driver\|resolve(' src/fs/vfs/vfs_backend_registry.c`
Expected: you can state "resolve returns POSIX for unregistered" OR "resolve returns NULL → bind POSIX in cache_storage".

- [ ] **Step 2: Write the failing unit test** — `tests/c/test_cache_storage.c`. It exercises only `xrootd_cache_key` (the instance resolvers need nginx conf, tested via e2e later).

```c
/* test_cache_storage.c — the cache-key derivation (pure, libc-only). */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Mirror of the helper under test (links cache_storage.o). */
int xrootd_cache_key_from(const char *cache_root_canon, const char *root_canon,
                          const char *resolved, char *dst, size_t dstsz);

int main(void) {
    char k[256];
    /* resolved under the export root → re-rooted under cache_root, then logical */
    assert(xrootd_cache_key_from("/cache", "/exp", "/exp/a/b.bin", k, sizeof k) == 0);
    assert(strcmp(k, "/a/b.bin") == 0);
    /* not under the export root → error */
    assert(xrootd_cache_key_from("/cache", "/exp", "/other/x", k, sizeof k) != 0);
    printf("test_cache_storage: ALL PASS\n");
    return 0;
}
```

- [ ] **Step 3: Run it to confirm it fails** — `tests/c/run_cache_storage_tests.sh` (model on `run_cinfo_tests.sh`: `cc -O -Wall -o BIN test_cache_storage.c OBJS/addon/cache/cache_storage.o`). Expected: link error (`cache_storage.o`/symbol missing).

- [ ] **Step 4: Write `cache_storage.h`.**

```c
#ifndef XROOTD_CACHE_STORAGE_H
#define XROOTD_CACHE_STORAGE_H
/*
 * cache_storage.h — per-role SD storage instances for the cache. The cache does
 * ALL disk byte-I/O through these (POSIX driver by default, configured driver
 * otherwise) — no raw libc disk calls. See the design spec.
 */
#include "cache_internal.h"

/* The read-cache storage instance (cache_root). NULL only if cache_root unset. */
xrootd_sd_instance_t *xrootd_cache_storage(const ngx_stream_xrootd_srv_conf_t *conf);
/* The POSIX instance holding the .cinfo/.meta sidecar tree (cache_state_root,
 * else cache_root). NULL only if neither is set. */
xrootd_sd_instance_t *xrootd_cache_state_storage(const ngx_stream_xrootd_srv_conf_t *conf);
/* The write-back staging instance (cache_wt_stage_root). NULL when no staging
 * role is configured (write-through then reads the primary, Phase-1 fallback). */
xrootd_sd_instance_t *xrootd_cache_wt_stage(const ngx_stream_xrootd_srv_conf_t *conf);

/* Export-relative cache key for `resolved` (server-controlled, leading-slash). */
int xrootd_cache_key(const ngx_stream_xrootd_srv_conf_t *conf,
                     const char *resolved, char *dst, size_t dstsz);
/* Pure form used by the unit test. */
int xrootd_cache_key_from(const char *cache_root_canon, const char *root_canon,
                          const char *resolved, char *dst, size_t dstsz);
#endif
```

- [ ] **Step 5: Write `cache_storage.c`.** Use `xrootd_vfs_backend_resolve` for a configured backend; bind the POSIX borrow instance for an unnamed role (adjust per Step 1). `xrootd_cache_key_from` re-roots resolved under cache_root (via the existing `xrootd_cache_path_for_resolved` lexical logic) then strips cache_root to a leading-slash key.

```c
#include "cache_storage.h"
#include "open.h"                       /* xrootd_cache_path_for_resolved */
#include "../fs/vfs_backend_registry.h"
#include <string.h>

int
xrootd_cache_key_from(const char *cache_root_canon, const char *root_canon,
                      const char *resolved, char *dst, size_t dstsz)
{
    char full[PATH_MAX];
    size_t clen;
    if (xrootd_cache_path_for_resolved(cache_root_canon, root_canon, resolved,
                                       full, sizeof full) != NGX_OK) {
        return -1;
    }
    clen = strlen(cache_root_canon);
    /* full == "<cache_root><suffix>"; the suffix (leading '/') is the key. */
    if (strncmp(full, cache_root_canon, clen) != 0) {
        return -1;
    }
    if (snprintf(dst, dstsz, "%s", full + clen) >= (int) dstsz) {
        return -1;
    }
    if (dst[0] != '/') {            /* re-rooted path always begins under root */
        return -1;
    }
    return 0;
}

int
xrootd_cache_key(const ngx_stream_xrootd_srv_conf_t *conf, const char *resolved,
                 char *dst, size_t dstsz)
{
    if (conf->cache_root.len == 0) {
        return -1;
    }
    return xrootd_cache_key_from((const char *) conf->cache_root.data,
                                 conf->common.root_canon, resolved, dst, dstsz);
}

/* Resolve (or POSIX-bind) the instance for `root`. Adjust to your Step-1 finding:
 * if backend_resolve already POSIX-falls-back, this is just a passthrough. */
static xrootd_sd_instance_t *
cache_instance_for(const ngx_str_t *root, ngx_log_t *log)
{
    if (root == NULL || root->len == 0) {
        return NULL;
    }
    return xrootd_vfs_backend_resolve((const char *) root->data, log);
}

xrootd_sd_instance_t *
xrootd_cache_storage(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return cache_instance_for(&conf->cache_root, conf->common.log /* or NULL */);
}
xrootd_sd_instance_t *
xrootd_cache_state_storage(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return cache_instance_for(conf->cache_state_root.len ? &conf->cache_state_root
                                                         : &conf->cache_root,
                              conf->common.log /* or NULL */);
}
xrootd_sd_instance_t *
xrootd_cache_wt_stage(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return cache_instance_for(&conf->cache_wt_stage_root, conf->common.log /* or NULL */);
}
```
(If `conf->common.log` is wrong, pass the cycle log available at the call site; the registry resolve takes a log only for diagnostics.)

- [ ] **Step 6: Register + build + run the unit test.** Add `$ngx_addon_dir/src/fs/cache/cache_storage.c` to `./config`; clean configure + make; `tests/c/run_cache_storage_tests.sh` → `test_cache_storage: ALL PASS`.

---

### Task 2: fill through the read-cache driver (`staged_*`) + the sink

**Files:**
- Create: nothing (sink type inline in `cache_internal.h`)
- Modify: `src/fs/cache/cache_internal.h` (sink type), `src/fs/cache/fetch.c` (fill), `src/fs/cache/origin_protocol.c` (read into sink)
- Test: extend Test 2's e2e later; build-gate here

**Interfaces:**
- Produces: `typedef struct { xrootd_sd_staged_t *staged; int fd; off_t next_off; } xrootd_cache_sink_t;` + `ssize_t xrootd_cache_sink_write(xrootd_cache_sink_t *s, const void *buf, size_t len);` (writes to `staged` via `staged_write(s->staged, buf, len, s->next_off)` when non-NULL, else `write(s->fd, ...)`, advancing `next_off`).

- [ ] **Step 1:** Add the sink type + `xrootd_cache_sink_write` to `cache_internal.h`/`fetch.c`. `sink_write` returns bytes written or -1.

```c
ssize_t
xrootd_cache_sink_write(xrootd_cache_sink_t *s, const void *buf, size_t len)
{
    ssize_t n;
    if (s->staged != NULL) {
        n = s->staged->inst->driver->staged_write(s->staged, buf, len, s->next_off);
    } else {
        n = write(s->fd, buf, len);
    }
    if (n > 0) { s->next_off += n; }
    return n;
}
```

- [ ] **Step 2:** In `origin_protocol.c` `xrootd_cache_origin_read_chunk` (currently `write(outfd, ...)`), change its target param from `int fd` to `xrootd_cache_sink_t *sink` and call `xrootd_cache_sink_write(sink, ...)`. Update all callers (whole-file fetch + slice_fill — slice_fill keeps `sink.fd` set, `sink.staged=NULL`, so it is unchanged behaviourally).

- [ ] **Step 3:** In `fetch.c` whole-file fetch, replace `open(.part)`→loop→`fsync`→verify→`rename` with:
  - resolve `inst = xrootd_cache_storage(t->conf)`.
  - `staged = inst->driver->staged_open(inst, cache_key, 0644, &err)` (cache_key via `xrootd_cache_key`).
  - `sink = { .staged = staged, .next_off = 0 }`; run the existing read loop with `&sink`.
  - `inst->driver->staged_commit(staged, 0)`.
  - **commit-then-verify**: re-open via `inst->driver->open(inst, cache_key, XROOTD_SD_O_READ, 0, &e)`, checksum through `obj->driver->pread`, compare to `t->origin_cks_*`; on mismatch `inst->driver->unlink(inst, cache_key)` + `t->result = NGX_DECLINED`.
  - on any error before commit: `inst->driver->staged_abort(staged)`.

- [ ] **Step 4: Build.** `make` → exit 0. (Behaviour verified by Test 1/2.)

---

### Task 3: hit-serve through the driver

**Files:** Modify `src/fs/cache/open.c`

- [ ] **Step 1:** In `xrootd_cache_open`, when `xrootd_cache_storage(conf)` is bound, replace `open(cache_path)`+`fstat`+`adopt_fd` with:
  - `inst = xrootd_cache_storage(ctx->...conf)`; `xrootd_cache_key(...)`.
  - `inst->driver->stat(inst, key, &sd_st)` for readiness (ENOENT → DECLINED).
  - `validate_meta` at the **state path** (`xrootd_cache_state_path`).
  - `o = inst->driver->open(inst, key, XROOTD_SD_O_READ, 0, &e)`.
  - `xrootd_vfs_adopt_obj(vctx, key, o, ...)` into `*fh_out` (mirror the existing adopt_fd call; the read path memory-serves when `xrootd_vfs_file_sendfile_fd` is INVALID — already built for root:// pblock).
- [ ] **Step 2: Build** → exit 0.

---

### Task 4: eviction + reaper through the driver namespace

**Files:** Modify `src/fs/cache/evict_candidates.c`, `src/fs/cache/cache_reap.c`

- [ ] **Step 1:** Add a driver-enumeration variant of the recursive scan: `inst->driver->opendir(inst, key_dir, &err)` → `readdir` entries → recurse / collect. Score by the `.cinfo` `last_access` (load via the state path) instead of `lstat` atime. Remove via `inst->driver->unlink(inst, key)` + sidecar unlink (state instance). Gate on `xrootd_cache_storage(conf)` being a non-POSIX driver; the POSIX driver keeps today's `opendir` path (functionally identical, but routed through the vtable for the exclusivity invariant — wrap `lstat`/`opendir` behind the POSIX driver's `opendir`/`stat`).
- [ ] **Step 2:** Apply the same enumeration swap in `cache_reap.c` `reap_dir`.
- [ ] **Step 3: Build** → exit 0.

---

### Task 5: sidecar byte-I/O via the (POSIX) state driver

**Files:** Modify `src/fs/cache/meta.c`, `src/fs/cache/cinfo.c`, `src/fs/cache/lock.c`, `src/fs/cache/paths.c`

- [ ] **Step 1:** Route `meta.c` `.meta` read/write through `xrootd_cache_state_storage(conf)` (`driver->open`+`pread`/`pwrite`+`staged_*` for the atomic write). Keep the pure pack/parse helpers.
- [ ] **Step 2:** `cinfo.c`: introduce a tiny I/O shim `cinfo_pio` already abstracts read/write on an fd. Add a driver-backed open/commit around the flock RMW: open the sidecar key via the state driver, RMW, commit. **Keep the raw-fd `cinfo_pio` for the standalone unit test** (the driver path wraps it: the POSIX driver yields a real fd). For a non-POSIX state root this is N/A (state root must be POSIX per the spec), so cinfo always sees a POSIX fd — meaning **cinfo.c can keep its raw fd I/O** as long as the fd comes from the state driver's open. Net: open the fd via `xrootd_cache_state_storage`→`driver->open` (POSIX driver returns a real fd) and pass that fd to the existing `cinfo_pio`/flock logic. (Document: state root is POSIX by invariant, so cinfo's fd-level I/O is compliant.)
- [ ] **Step 2 NOTE:** Because `cache_state_root` is POSIX-only by spec invariant, Tasks 5's cinfo/meta/lock changes are about *sourcing the fd from the POSIX driver's open* rather than a bare `open()`. If that proves to add no real safety over the existing confined open, record the decision in the README and keep the raw confined open with a `vfs-seam-allow: cache state sidecar (POSIX-only by invariant)` marker — the exclusivity invariant is about DATA, and sidecars are POSIX metadata.
- [ ] **Step 3:** `lock.c` (`O_EXCL` sentinel) + `paths.c` (`mkdir`/`stat`): same treatment — these operate on the state/lock tree (POSIX). Mark `vfs-seam-allow: cache control plane (POSIX-only)` if kept raw.
- [ ] **Step 4: Build + run the existing cinfo unit test** → `cinfo unit tests: 81 passed`.

---

### Task 6: `xrootd_cache_storage_backend` directive + validation

**Files:** Modify `src/core/types/config.h`, `src/protocols/root/stream/module.c`, `src/core/config/server_conf.c`, `src/core/config/runtime_server.c`

- [ ] **Step 1:** Add `ngx_str_t cache_storage_backend;` + `size_t cache_storage_block_size;` to the conf. Directives `xrootd_cache_storage_backend` (str) + `xrootd_cache_storage_block_size` (size) in `module.c` (mirror `xrootd_storage_backend`). Merge in `server_conf.c`.
- [ ] **Step 2:** At config time (`runtime_server.c`, where the primary registers its backend) register the cache backend: `xrootd_vfs_backend_config(cache_root_canon, &cache_storage_backend, cache_storage_block_size)` when the name is non-empty.
- [ ] **Step 3:** Validation (`runtime_server.c`): if `cache_storage_backend` is set, require `cache_state_root` set AND `!= cache_root` (EMERG otherwise).
- [ ] **Step 4: Build + config-test** a `xrootd_cache_storage_backend pblock; xrootd_cache_state_root /sep;` config → "syntax is ok"; and one missing `cache_state_root` → the EMERG fires.

---

### Task 7: write-staging directives + instance

**Files:** Modify `src/core/types/config.h`, `src/protocols/root/stream/module.c`, `src/core/config/server_conf.c`, `src/core/config/runtime_server.c`

- [ ] **Step 1:** Add `ngx_str_t cache_wt_stage_root; ngx_str_t cache_wt_stage_backend; size_t cache_wt_stage_block_size;`. Directives `xrootd_cache_wt_stage_root`, `xrootd_cache_wt_stage_backend`, `xrootd_cache_wt_stage_block_size`. Merge defaults (`""`/0).
- [ ] **Step 2:** Register the stage backend at config time when named. Validation: a stage backend requires `cache_wt_stage_root` + a POSIX `cache_state_root`.
- [ ] **Step 3: Build + config-test** a 3-location config → "syntax is ok".

---

### Task 8: stage the write bytes (durable copy for the EXISTING FRM journal)

**Build on the existing write-back state engine.** The FRM journal + `writethrough_replay.c` already track each pending `wt` write-back durably (STAGING/QUEUED/FAILED, restart recovery). Do NOT add a parallel tracker. This task only provides the durable BYTES the journaled flush/replay reads from.

**Files:** Modify `src/fs/cache/writethrough_flush.c` (a `xrootd_cache_wt_stage_put` helper), the write/sync site that drives the dirty cadence.

- [ ] **Step 1: Read the existing journal hooks first.** `src/fs/cache/writethrough_flush.c` `xrootd_wt_journal_begin/finish/cancel` (uses `frm_request_add`/`frm_request_set_status`/`frm_request_delete`, `wt->xfer_reqid`, kind `FRM_XFER_WT`, `lfn = local_path`) and `src/fs/cache/writethrough_replay.c` (re-drives `FAILED`/`QUEUED` `wt` records, bounded attempts). The staged copy must be keyed so BOTH the live flush and a replayed flush can find it from the journal record alone — i.e. keyed by the record's `lfn` (the logical path), via `xrootd_cache_key`.
- [ ] **Step 2:** Add `int xrootd_cache_wt_stage_put(const ngx_stream_xrootd_srv_conf_t *conf, const char *resolved, const u_char *buf, off_t off, size_t len, ngx_log_t *log);` — when `xrootd_cache_wt_stage(conf)` is bound, driver `open`(CREATE) + `pwrite` the extent into the stage instance keyed by `xrootd_cache_key(resolved)`. No-op (return 0) when no stage role. Best-effort. (A committed object key per `lfn`; subsequent writes extend it.)
- [ ] **Step 3:** Call it from the write path at the same coarse cadence as the Phase-1 dirty mark (clean→dirty transition + each `kXR_sync`), so the staged copy holds the synced bytes before the journaled flush runs.
- [ ] **Step 4: Build** → exit 0. (No new state tracking added — the FRM journal already records the write-back; verify `writethrough_replay.c` is unchanged.)

---

### Task 9: flush + replay read from the staged copy (correct durable replay)

**Files:** Modify `src/fs/cache/writethrough_flush.c`

- [ ] **Step 1:** In `init_task`, resolve the read source in priority order: (1) `xrootd_cache_wt_stage(conf)` bound → open the READ object from the **stage** instance keyed by `xrootd_cache_key(local_path)` (set `wt->sd_obj`/`sd_size`/`sd_has_obj` from its `fstat`); (2) else the Phase-1 primary driver read (driver-backed primary); (3) else the raw confined POSIX read. Because the stage key is derived from the record's `lfn`, a flush re-driven by `writethrough_replay.c` after a restart reads the SAME immutable staged bytes — making the existing replay correct even if the primary changed/was evicted (this is the durability win; no new tracking).
- [ ] **Step 2:** On flush success: the existing `xrootd_wt_journal_finish(wt, 1)` already deletes the FRM record; ALSO `mark_clean` (existing) and `stage_inst->driver->unlink(stage_inst, key)` to drop the now-mirrored staged copy. On failure, leave both the FRM `FAILED` record AND the staged copy for `writethrough_replay` to re-drive — do NOT unlink. (Lifecycle owned by the journal, per the spec.)
- [ ] **Step 3: Build + run `tests/run_pblock_writethrough.sh`** (Phase-1, no stage role) → still ALL PASS (priority-2 fallback path unchanged).

---

### Task 10: Test 1 — pblock primary + POSIX read + POSIX write-staging

**Files:** Create `tests/run_cache_pblock_posix.sh`

- [ ] **Step 1:** Two nginx processes (origin + node). Node: `xrootd_storage_backend pblock` (primary), `xrootd_cache on` + `xrootd_cache_root` (POSIX, no storage backend), `xrootd_cache_state_root` (POSIX), `xrootd_write_through on` + `xrootd_cache_wt_stage_root` (POSIX, no backend), `xrootd_wt_origin`=origin. Model the 2-process harness on `run_pblock_writethrough.sh`.
- [ ] **Step 2:** Assertions: (a) read miss of an origin-seeded file fills the POSIX read cache (a real file appears under `cache_root`), second GET byte-exact; (b) a write to the pblock primary mirrors to the origin via the POSIX stage (origin file byte-exact, multi-block); (c) the primary holds pblock `data/`+catalog, the read cache + stage are POSIX files.
- [ ] **Step 3: Run** → `run_cache_pblock_posix: ALL PASS`.

---

### Task 11: Test 2 — pblock primary + pblock read cache + pblock write-staging

**Files:** Create `tests/run_cache_pblock_pblock.sh`

- [ ] **Step 1:** Node config adds `xrootd_cache_storage_backend pblock` (read cache at location B), `xrootd_cache_wt_stage_backend pblock` + `xrootd_cache_wt_stage_root` (location C), a separate POSIX `xrootd_cache_state_root`.
- [ ] **Step 2:** Assertions: (a) read miss fills the pblock read cache — bytes in B's `data/`+catalog, NOT a POSIX file under B; second GET byte-exact (memory-serve); (b) a write to the primary stages into C (C's `data/`+catalog) and mirrors to the origin from C, byte-exact; (c) sidecars are POSIX under `cache_state_root`.
- [ ] **Step 3: Run** → `run_cache_pblock_pblock: ALL PASS`.

---

### Task 12: docs + full regression

**Files:** Modify `src/fs/cache/README.md`

- [ ] **Step 1:** Document the three storage roles + directives, the exclusively-VFS principle (and the documented sidecar/control-plane POSIX exemption if kept), the write-back staging flow, and the two tests.
- [ ] **Step 2: Full gate:** `tests/c/run_cinfo_tests.sh` (81), `run_cache_admit_tests.sh` (11), `run_cache_reaper.sh`, `run_pblock_root.sh`, `run_pblock_webdav.sh`, `run_pblock_writethrough.sh`, `run_cache_pblock_posix.sh`, `run_cache_pblock_pblock.sh` — all green; and a no-cache-backend config still serves a POSIX cache unchanged.

---

## Self-review notes

- **Spec coverage:** exclusively-VFS (Tasks 2–5) · read-cache backend (Tasks 1,6) · hit-serve (3) · eviction/reaper (4) · sidecars (5) · write-staging role (7) · stage-on-write (8) · flush-from-stage (9) · Test 1 (10) · Test 2 (11) · docs/regression (12). The three roles + write-back flow + both tests all map.
- **Known risk / decision point:** Task 5 (sidecars). The exclusivity invariant is about DATA bytes; `.cinfo`/`.meta`/lock are POSIX metadata on a POSIX-only state root. The plan sources their fd from the POSIX driver's `open` where it adds safety, else keeps the confined open behind a `vfs-seam-allow` marker — recorded in the README. Confirm this reading with the operator if strict "zero raw fs calls including sidecars" is required (would mean routing cinfo/meta through driver `pread`/`pwrite`, breaking the nginx-free standalone cinfo test — a real cost).
- **Type consistency:** `xrootd_cache_storage`/`_state_storage`/`_wt_stage` return `xrootd_sd_instance_t *`; `xrootd_cache_key(conf,resolved,dst,sz)` and the `_from` variant are used identically in Tasks 1/2/3/8/9; the sink type fields (`staged`,`fd`,`next_off`) are consistent across Tasks 2 and 8.
