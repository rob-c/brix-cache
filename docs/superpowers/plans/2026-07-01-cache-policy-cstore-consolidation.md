# Cache Policy → `cstore` Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **STATUS — IMPLEMENTED 2026-07-01 (Tasks 1–5 done, verified, working tree).** Build clean (`-Werror`), `check_vfs_seam.sh` green, `run_cache_watermark.sh` / `run_cache_watermark_config.sh` / `run_cache_reaper.sh` ALL PASS, `test_http_cache_hit.py` 8 passed. Three deviations from the as-written plan, each detailed at its task:
> - **Task 2** — `cstore_scan`'s visitor signature was **extended** to `(key, ci, stx, ctx)` (add the object's `sd_stat`; visit no-cinfo objects with `ci=NULL`) so eviction keeps its exact sort signal + coverage. Zero prior callers, so nothing else changed.
> - **Task 4** — the reaper scans the **state root** (sidecar tree) via raw POSIX, a different domain than the data store, so `cstore_scan` does not fit. Adapted to route only the data **removal** through `cstore_evict` (the one store-driver touch); the state-tree scan stays raw (guard-exempt POSIX state plane).
> - **Task 5** — implemented as a **cstore-preferring helper with a `statvfs` fallback** (`xrootd_cache_usage_measure`), not a naive `cstore_freespace` swap: `cstore_freespace` returns `NGX_DECLINED` for non-LOCAL stores (statf slot is SP2), so a blind swap would regress them. Scoped to the three eviction-decision measurements; the TTL sampler / `stage_admit` (different root) are left as-is.
>
> Still deferred (active phase-64 SP2): `fetch.c`, `writethrough_flush.c`, `slice_fill.c` — see "Deferred".

**Goal:** Make the legacy `conf`-driven cache **policy** modules (eviction, reaper, free-space) drive the cache store through the `cstore` adapter instead of `inst->driver->*` directly — closing the phase-64 P3/G5 rule ("every cache policy module drives the store through `cstore` and never through a driver directly") for the isolable policy paths.

**Architecture:** `conf->cache_storage_inst` is a **bare store** SD instance with no `cstore`. We build one `xrootd_cstore_t` over it at config time (`conf->cache_storage_cstore`), in AUTO→LOCAL mode (byte-identical to today's co-located cache), and thread it into the eviction list / reaper / free-space measurement. Each policy site then calls `xrootd_cstore_scan` / `_evict` / `_freespace` instead of the bare driver. The hot-path fill/flush modules (`fetch.c`, `writethrough_flush.c`) are **explicitly out of scope** (active phase-64 SP2 work — see "Deferred").

**Tech Stack:** C (nginx stream module), the `cstore` adapter (`src/fs/cache/cstore.{c,h}`), the SD driver vtable (`src/fs/backend/sd.h`), the existing cache integration harnesses (`tests/run_cache_reaper.sh`, `tests/run_cinfo_tests`, eviction/watermark tests) as the behavior-preserving gate, and `tools/ci/check_vfs_seam.sh`.

## Global Constraints

- **NO `goto`** anywhere in `src/` (`docs/09-developer-guide/coding-standards.md` §4) — early-return + helper decomposition.
- **P3/G5 (phase-64):** only `cstore.c` and `tier_build.c` may `strcmp`/branch on a driver; **policy modules must not call `inst->driver->*` directly** for store ops.
- **Behavior-preserving:** a posix store auto-resolves `meta_mode=LOCAL`, `batch_cinfo=0` — byte-identical to the pre-change co-located tree (`cstore.h` §6.3/§6.4). All existing cache tests must still pass unchanged.
- **Functional + modular** — one responsibility per function, pass state explicitly (thread the `cstore` handle; **no new globals**).
- **Section-level WHAT/WHY/HOW doc block on every new/changed function.**
- **Dirty-data safety invariant:** never evict an object with un-flushed local writes (a dirty `.cinfo`). The existing scan enforces this; the migrated scan MUST preserve it (the `cstore_scan` visitor receives the loaded cinfo — check its dirty extent there).
- Build: incremental `make -j$(nproc)`; no `./configure` (no new `.c` file, no new directive — `cache_storage_cstore` is a runtime-built conf field, not a directive).
- The cache `cstore` lives in `sd_cache_inst_state` for the VFS world; **do not** confuse it with the new config-time `conf->cache_storage_cstore` this plan adds for the legacy policy world.

---

### Task 1: Build a config-time `cstore` over the bare cache store

Give the legacy policy layer a `cstore` to drive. Build one `xrootd_cstore_t` over `conf->cache_storage_inst` when the read cache is configured, store it on the conf, and tear it down on cleanup.

**Files:**
- Modify: `src/core/types/config.h` (add the `cache_storage_cstore` field to `ngx_stream_xrootd_srv_conf_t`)
- Modify: `src/fs/cache/cache_storage.c` (build it after `cache_storage_inst`; free it)
- Modify: `src/fs/cache/cache_storage.h` (declare an accessor `xrootd_cache_storage_cstore`)
- Test: `tests/run_cache_reaper.sh` (existing; must still pass) + a new assertion added in Task 4

**Interfaces:**
- Consumes: `xrootd_cstore_init(xrootd_cstore_t *cs, xrootd_sd_instance_t *store, const char *local_root, int meta_mode, size_t l1_entries, int batch_cinfo, ngx_log_t *log)` → `NGX_OK`/`NGX_ERROR` (`cstore.h`); `xrootd_cstore_cleanup(xrootd_cstore_t *cs)`; `XROOTD_CMETA_AUTO` (=0); `conf->cache_storage_inst`, `conf->cache_root`, `conf->cache_index_cache` (L1 size, default 4096).
- Produces: `xrootd_cstore_t *xrootd_cache_storage_cstore(const ngx_stream_xrootd_srv_conf_t *conf)` — the policy-layer cstore, or `NULL` if the cache is off.

- [ ] **Step 1: Add the conf field**

In `src/core/types/config.h`, in `ngx_stream_xrootd_srv_conf_t`, next to `cache_storage_inst`, add:

```c
    /* Policy-layer cstore adapter built over cache_storage_inst at config time
     * (eviction / reaper / free-space drive the store through this, never the
     * bare driver — phase-64 P3/G5). NULL when the read cache is off. */
    void  *cache_storage_cstore;   /* xrootd_cstore_t * */
```

(Use `void *` to avoid pulling `cstore.h` into the broad `config.h`, mirroring how `cache_storage_inst` is a `void *`-style opaque handle in the policy layer.)

- [ ] **Step 2: Build it after the store instance**

In `src/fs/cache/cache_storage.c`, immediately after the `conf->cache_storage_inst = cache_build_instance(...)` assignment (and only when non-NULL), add:

```c
    if (conf->cache_storage_inst != NULL) {
        xrootd_cstore_t *cs = ngx_pcalloc(pool, sizeof(*cs));

        if (cs == NULL) {
            return NGX_ERROR;
        }
        /* LOCAL/AUTO over the co-located posix cache_root: meta_mode AUTO
         * resolves to LOCAL (byte-identical sidecars), batch_cinfo=0 = the old
         * per-op behaviour. l1 size from the existing index-cache tunable. */
        if (xrootd_cstore_init(cs, conf->cache_storage_inst,
                               (const char *) conf->cache_root.data,
                               XROOTD_CMETA_AUTO,
                               (size_t) conf->cache_index_cache,
                               0 /* batch_cinfo: per-op, matches today */,
                               log) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                "xrootd: cache policy cstore init failed for \"%V\"",
                &conf->cache_root);
            return NGX_ERROR;
        }
        conf->cache_storage_cstore = cs;
    }
```

Add `#include "cstore.h"` to `cache_storage.c` if not already present. (`conf->cache_index_cache` is the existing `xrootd_cache_index_cache` directive, default 4096; if the field name differs, grep `index_cache` in `config.h` and use the actual member.)

- [ ] **Step 3: Free it on cleanup**

In `cache_storage.c`, wherever `cache_storage_inst` is torn down / reset to `NULL` (the cleanup path near the `conf->cache_storage_inst = NULL;` lines), add before clearing the inst:

```c
    if (conf->cache_storage_cstore != NULL) {
        xrootd_cstore_cleanup((xrootd_cstore_t *) conf->cache_storage_cstore);
        conf->cache_storage_cstore = NULL;
    }
```

- [ ] **Step 4: Add the accessor**

In `src/fs/cache/cache_storage.h`, declare (with a WHAT/WHY/HOW block):

```c
/* The policy-layer cstore adapter over the read cache's store (eviction, reaper,
 * free-space drive the store through this). NULL when the cache is off. */
xrootd_cstore_t *xrootd_cache_storage_cstore(
    const ngx_stream_xrootd_srv_conf_t *conf);
```

In `cache_storage.c`, define it next to `xrootd_cache_storage`:

```c
xrootd_cstore_t *
xrootd_cache_storage_cstore(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return (xrootd_cstore_t *) conf->cache_storage_cstore;
}
```

Add the `xrootd_cstore_t` forward type to `cache_storage.h` via `#include "cstore.h"` (or a forward `typedef struct ... xrootd_cstore_t;` if include cycles bite — `cstore.h` already includes `sd.h`/`cinfo.h`, so a direct include is fine).

- [ ] **Step 5: Build**

Run: `make -j$(nproc)`
Expected: clean compile (the module is `-Werror`).

- [ ] **Step 6: Smoke — cache still starts and reaps**

Run: `bash tests/run_cache_reaper.sh`
Expected: existing reaper harness still **ALL PASS** (we only built an unused handle so far; this proves init/cleanup don't regress startup).

---

### Task 2: Route the eviction scan through `cstore_scan`

> **IMPLEMENTED (deviation):** `cstore_scan`'s visitor was extended to `ngx_int_t (*)(const char *key, const xrootd_cache_cinfo_t *ci, const xrootd_sd_stat_t *stx, void *ctx)` and `cstore_scan_dir` now visits **every** regular object (passing `ci=NULL` when no `.cinfo` loads) and always the store `stx`. Reason: the eviction candidate sort needs the object's own `size`/`mtime` (the as-written plan's cinfo-only visitor would have changed the sort signal and skipped no-cinfo objects). The visitor keeps the **exact** dirty guard by reading the state-root sidecar via `xrootd_cache_cinfo_dirty_extent` (so a separate `cache_state_root` is honored), and synthesizes the candidate stat from `stx` exactly as the old code did from `sd_st`.

`xrootd_cache_collect_dir` recurses the store with `inst->driver->opendir/readdir/stat` directly and separately loads each `.cinfo` for the dirty guard. Replace it with a single `xrootd_cstore_scan` whose visitor collects candidates — `cstore_scan` already does the opendir/readdir/stat walk **and** hands the visitor the loaded cinfo, so the dirty guard reads it directly.

**Files:**
- Modify: `src/fs/cache/evict_internal.h` (add `cstore` to the list struct; the visitor ctx)
- Modify: `src/fs/cache/evict_candidates.c` (`xrootd_cache_collect_dir` → a `cstore_scan` visitor)
- Modify: `src/fs/cache/evict_policy.c:206` (populate `list.cstore`)
- Test: `tests/run_cache_reaper.sh` + the eviction/watermark suite

**Interfaces:**
- Consumes: `xrootd_cstore_scan(xrootd_cstore_t *cs, xrootd_cstore_visit_fn visit, void *ctx)`; visitor `ngx_int_t (*)(const char *key, const xrootd_cache_cinfo_t *ci, void *ctx)`; the existing `xrootd_cache_add_candidate(list, ...)`, `xrootd_cache_skip_name(name)`, and the dirty-extent check the current scan uses (`cinfo` dirty fields).
- Produces: behavior-identical candidate list, now built via `cstore_scan`. `xrootd_cache_collect_dir`'s signature is unchanged for callers (it becomes a thin wrapper that runs the scan).

- [ ] **Step 1: Add `cstore` to the eviction list struct**

In `src/fs/cache/evict_internal.h`, in `xrootd_cache_evict_list_t` (next to `void *inst;`), add:

```c
    void  *cstore;   /* xrootd_cstore_t* — policy-layer store adapter (P3/G5) */
```

- [ ] **Step 2: Write the candidate-collecting visitor + rewrite `collect_dir`**

In `src/fs/cache/evict_candidates.c`, replace the body of `xrootd_cache_collect_dir` (the `inst->driver->opendir/readdir/stat` recursion) with a `cstore_scan` driven by a file-scoped visitor. The visitor reuses the existing skip-name + dirty-guard + `xrootd_cache_add_candidate` logic, lifted from the current loop:

```c
/* cstore_scan visitor: one call per cached key with its loaded cinfo. Applies the
 * same policy the raw scan did — skip control/sidecar names, never collect a key
 * with un-flushed local writes (dirty cinfo), add the rest as eviction
 * candidates. Returns NGX_OK to continue the scan. */
static ngx_int_t
evict_collect_visit(const char *key, const xrootd_cache_cinfo_t *ci, void *ctx)
{
    xrootd_cache_evict_list_t *list = ctx;
    const char                *name = strrchr(key, '/');
    char                       path[PATH_MAX];
    int                        n;

    name = (name != NULL) ? name + 1 : key;
    if (xrootd_cache_skip_name(name)) {
        return NGX_OK;
    }
    if (ci != NULL && xrootd_cinfo_has_dirty(ci)) {
        return NGX_OK;                     /* never evict un-flushed data */
    }

    n = snprintf(path, sizeof(path), "%s%s", list->cache_root, key);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        return NGX_OK;                     /* skip the unrepresentable key */
    }
    (void) xrootd_cache_add_candidate(list, path, key, ci);
    return NGX_OK;
}

ngx_int_t
xrootd_cache_collect_dir(xrootd_cache_evict_list_t *list, const char *keydir,
    ngx_log_t *log)
{
    (void) keydir;                         /* cstore_scan walks the whole store */
    if (list->cstore == NULL) {
        return NGX_ERROR;
    }
    return xrootd_cstore_scan((xrootd_cstore_t *) list->cstore,
                              evict_collect_visit, list);
}
```

Notes for the implementer:
- `xrootd_cinfo_has_dirty(ci)` — use the existing dirty-extent predicate the current scan calls (grep `dirty` in `cinfo.h`/`evict_candidates.c`; if it is an inline check on `ci->dirty_lo < ci->dirty_hi`, write that expression instead of inventing a helper).
- `xrootd_cache_add_candidate`'s real signature — match it exactly (grep its definition at `evict_candidates.c:34`); it may take `(list, path)` only. If it does not currently take the key/cinfo, pass what it takes; the `path` is the load-bearing argument (the actor unlinks by `path` / maps back to `key`).
- `#include "cstore.h"` and `#include "cinfo.h"` at the top of `evict_candidates.c` (cinfo is already included per its line 3).
- Delete the now-unused `xrootd_cache_skip_name` only if nothing else uses it (it is still used here — keep it).

- [ ] **Step 3: Populate `list.cstore` at the eviction entry**

In `src/fs/cache/evict_policy.c` around line 206, beside `list.inst = xrootd_cache_storage(conf);`, add:

```c
    list.cstore = xrootd_cache_storage_cstore(conf);
```

and extend the guard at line 212 (`if (list.inst == NULL ...)`) to also bail when `list.cstore == NULL`:

```c
    if (list.inst == NULL || list.cstore == NULL
        /* ...existing conditions... */) {
```

- [ ] **Step 4: Build**

Run: `make -j$(nproc)`
Expected: clean compile.

- [ ] **Step 5: Eviction still evicts (behavior-preserving)**

Run:
```bash
bash tests/run_cache_reaper.sh
PYTHONPATH=tests pytest tests/ -k "evict or watermark or cache_admit" -q
```
Expected: all pass — same files evicted, dirty files still protected.

- [ ] **Step 6: Guard stays green**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: `GUARD_GREEN` (we removed direct-driver calls; added none).

---

### Task 3: Route the eviction remove through `cstore_evict`

`xrootd_cache_evict_one` removes a candidate via the bare driver / raw unlink. Route it through `xrootd_cstore_evict(cs, key)` (which unlinks the object **and** its cinfo via the store driver).

**Files:**
- Modify: `src/fs/cache/evict_policy.c` (`xrootd_cache_evict_one`, ~line 46)
- Test: `tests/run_cache_reaper.sh` + eviction suite

**Interfaces:**
- Consumes: `xrootd_cstore_evict(xrootd_cstore_t *cs, const char *key)` → `NGX_OK`/`NGX_ERROR`; the candidate's store **key** (the list stores `path = cache_root + key`; recover the key as `path + strlen(cache_root)`, per the `evict_internal.h` struct comment).
- Produces: identical eviction accounting; removal now driver-routed via cstore.

- [ ] **Step 1: Replace the remove call**

In `xrootd_cache_evict_one` (`src/fs/cache/evict_policy.c`), locate the per-file removal (the `driver->unlink` / `unlink(path)` of the candidate at `list`/`idx`) and replace it with:

```c
    {
        xrootd_cstore_t *cs = (xrootd_cstore_t *) list->cstore;
        const char      *key = list->paths[idx] + ngx_strlen(list->cache_root);

        if (xrootd_cstore_evict(cs, key) != NGX_OK) {
            /* preserve the existing error handling/log + accounting on failure */
            ...
        }
    }
```

Match `list->paths[idx]` to the real candidate-array member name (grep the struct in `evict_internal.h` — it may be `list->items[idx].path`). Keep the existing size-accounting (the bytes-freed bump) exactly as-is; only the removal syscall path changes.

- [ ] **Step 2: Build + behavior**

Run:
```bash
make -j$(nproc)
bash tests/run_cache_reaper.sh
PYTHONPATH=tests pytest tests/ -k "evict or watermark" -q
```
Expected: clean build; eviction removes the same files; counts unchanged.

- [ ] **Step 3: Guard**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: `GUARD_GREEN`.

---

### Task 4: Route the reaper through `cstore_scan` + `cstore_evict`

> **IMPLEMENTED (deviation — removal only):** the reaper walks the **state root** (the `.cinfo` sidecar tree) via raw `opendir`/`readdir`/`lstat` and classifies by cinfo *state* (`dirty_since`/`flush_gen`/`last_flush`). That is the POSIX state plane (guard-exempt), a different tree than the data store — so `cstore_scan` (which walks the data store and is coupled to deferred SP4 write-back semantics) does **not** fit. Only the reaper's one store-driver touch was migrated: `reap_dir` now takes a `xrootd_cstore_t *` and removes the data object via `xrootd_cstore_evict` instead of `data_inst->driver->unlink`; `xrootd_cache_reap_dirty` passes `xrootd_cache_storage_cstore(conf)`. The raw state-tree scan is intentionally unchanged.

`cache_reap.c` (the stale-dirty / TTL reaper) calls `xrootd_cache_storage(conf)` + `inst->driver->*` (one direct driver call at the scan). Give it the cstore and run its sweep through `cstore_scan` with a reaper visitor that removes via `cstore_evict`.

**Files:**
- Modify: `src/fs/cache/cache_reap.c` (~line 190 where it passes `xrootd_cache_storage(conf)`)
- Test: `tests/run_cache_reaper.sh`

**Interfaces:**
- Consumes: `xrootd_cache_storage_cstore(conf)`; `xrootd_cstore_scan`; `xrootd_cstore_evict`; the reaper's existing age/TTL predicate.
- Produces: identical reap behavior, cstore-routed.

- [ ] **Step 1: Add a "remove via cstore" assertion to the harness**

Extend `tests/run_cache_reaper.sh` with a case that seeds the cache via the **store driver** path (so a non-co-located removal is exercised) and asserts the reaped object is gone *and* its `.cinfo` is gone. (Add an `ok`/`bad` check mirroring the file's existing style; this is the red test for the migration — it passes today only if removal also drops the cinfo, which `cstore_evict` guarantees.)

Run: `bash tests/run_cache_reaper.sh`
Expected: the new check **FAILS** if the reaper currently leaves an orphan cinfo; PASS otherwise (record which — it gates Step 3).

- [ ] **Step 2: Thread the cstore + use the visitor**

In `cache_reap.c`, replace the `xrootd_cache_storage(conf)` + direct driver scan with `xrootd_cstore_scan(xrootd_cache_storage_cstore(conf), reap_visit, &ctx)`, where `reap_visit` applies the existing age/TTL test and calls `xrootd_cstore_evict(cs, key)` on a match. Reuse the visitor shape from Task 2.

- [ ] **Step 3: Build + reap behavior**

Run:
```bash
make -j$(nproc)
bash tests/run_cache_reaper.sh
```
Expected: clean build; reaper harness **ALL PASS** including the Step-1 check (now removes object + cinfo atomically via cstore).

- [ ] **Step 4: Guard**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: `GUARD_GREEN`.

---

### Task 5: Route free-space measurement through `cstore_freespace`

> **IMPLEMENTED (deviation — preferring helper, not a blind swap):** a new `xrootd_cache_usage_measure(xrootd_cstore_t *cs, const char *root, xrootd_cache_fs_usage_t *usage)` (in `evict_candidates.c`) prefers `xrootd_cstore_freespace(cs)` and **falls back to `xrootd_cache_fs_usage(root)`** when the cstore is absent or returns `NGX_DECLINED`. Reason: `cstore_freespace` answers only for LOCAL stores today (non-local statf is SP2), so a blind replacement would regress non-local stores; a LOCAL store statvfs's the same dir, so the result is byte-identical now. Routed the **three** eviction-decision measurements in `evict_policy.c` (`evict_one` via `list->cstore`; `evict_if_needed` and the threaded pass via `xrootd_cache_storage_cstore(conf)`). The TTL `cache_fs_sampler.c` and `stage_admit.c` (a **different** root — the write-back stage, which has no cstore) are intentionally left on the raw sampler.

The eviction watermark check measures occupancy/free space (the `evict_policy.c` / `evict_candidates.c` free-space path, and `cache_fs_sampler.c`). Replace the direct `statvfs` / `driver->statf` with `xrootd_cstore_freespace(cs, &total, &avail)`.

**Files:**
- Modify: `src/fs/cache/evict_policy.c` (the free-space measurement before the watermark decision)
- Modify: `src/fs/cache/cache_fs_sampler.c` if it independently samples free space
- Test: eviction/watermark suite

**Interfaces:**
- Consumes: `xrootd_cstore_freespace(xrootd_cstore_t *cs, uint64_t *total, uint64_t *avail)` → `NGX_OK`/`NGX_ERROR`.
- Produces: identical watermark decisions, cstore-routed free-space.

- [ ] **Step 1: Replace the measurement**

At the free-space site, replace the `statvfs`/`driver->statf` block with:

```c
    {
        uint64_t total = 0, avail = 0;

        if (xrootd_cstore_freespace((xrootd_cstore_t *) list->cstore,
                                    &total, &avail) != NGX_OK) {
            /* keep the existing fallback/skip-eviction-on-error behaviour */
            ...
        }
        /* feed total/avail into the existing watermark math unchanged */
    }
```

- [ ] **Step 2: Build + watermark behavior**

Run:
```bash
make -j$(nproc)
PYTHONPATH=tests pytest tests/ -k "watermark or evict" -q
```
Expected: clean build; watermark triggers eviction at the same thresholds.

- [ ] **Step 3: Guard + full cache suite**

Run:
```bash
bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN
bash tests/run_cinfo_tests
PYTHONPATH=tests pytest tests/ -k "cache" -q
```
Expected: `GUARD_GREEN`; cinfo unit tests pass; cache suite green (behavior fully preserved).

---

## Deferred — out of scope for this plan (active phase-64 SP2 overlap)

These remain on direct `inst->driver->*` and are **intentionally not migrated here** — they are the active async fill/flush hot path and converging them is owned by phase-64 SP2/SP3. Migrating them now would collide with in-flight work.

| Module | Direct `driver->*` calls | Why deferred |
|--------|--------------------------|--------------|
| `src/fs/cache/fetch.c` | 16 | Origin fetch / async miss-fill spine — SP2 "shell→full" + remote-store path |
| `src/fs/cache/writethrough_flush.c` | 22 | Write-back flush to origin — SP2/SP4 durable staging engine |
| `src/fs/cache/slice_fill.c` | leaf | §6.5 folds slice-fill INTO `cstore_serve_pread` — a redesign, not a wiring change |

When SP2 stabilizes, each becomes its own plan whose acceptance is: the module calls `cstore_*` (or the `sd_cache` decorator) only, and `tools/ci/check_vfs_seam.sh` plus the cache suite stay green.

---

## Self-Review

**Spec coverage:** The phase-64 P3/G5 rule ("policy modules drive the store through `cstore`, never the bare driver") maps to: Task 1 (build the adapter), Task 2 (eviction scan), Task 3 (eviction remove), Task 4 (reaper), Task 5 (free-space). The fill/flush/slice paths are explicitly deferred with the SP2 rationale — matching the plan's stated scope. ✔

**Placeholder scan:** Tasks carry real signatures (`xrootd_cstore_init/scan/evict/freespace/cleanup`, the `xrootd_cstore_visit_fn` shape, `xrootd_cache_storage`, the `evict_list` struct). Three sites are flagged "match the real member/predicate name by grep" (`xrootd_cache_add_candidate`'s arity, the candidate-array member, the dirty predicate) because they are existing internal names the implementer must read at the callsite — these are verification instructions, not placeholders for logic. ✔

**Type consistency:** `xrootd_cstore_t *` is used identically as the conf field (`void *cache_storage_cstore`), the accessor return (`xrootd_cache_storage_cstore`), the list member (`void *cstore`), and every `cstore_*` first argument (cast at the boundary). `meta_mode=XROOTD_CMETA_AUTO`, `batch_cinfo=0` match `cstore.h` §6.3/§6.4. ✔

**Risk:** the only behavioral risk is the dirty-data guard (Task 2 visitor) — the plan pins it as a Global Constraint and routes the cinfo through the visitor so the check is preserved. The free-space and remove paths are arithmetic/­syscall-path swaps, behavior-preserving by `LOCAL`+`batch_cinfo=0`.
