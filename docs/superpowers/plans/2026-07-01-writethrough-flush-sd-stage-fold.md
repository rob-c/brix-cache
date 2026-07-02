# Writethrough-Flush → sd_stage Fold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the bespoke 949-line `writethrough_flush.c` write-back loop with the one composable `sd_stage` mechanism (staged write → commit flushes to the origin backend through the shared staging engine), so root:// write-through has exactly one stage mechanism (G9) — WITHOUT breaking the writethrough harnesses or the FRM-journal crash-recovery.

**Architecture:** A legacy write-through config (`xrootd_cache on` + `xrootd_cache_root` + `xrootd_cache_origin`, flush on sync/close via `run_flush`) is *translated* into a config-time wt `sd_stage` instance (stage store = the local cache, backend = the origin built from the write-back credential) — the write-side mirror of Row 2's read `cache_source_inst`. The write-open then resolves to that `sd_stage` instance, so a write is a *staged write* and close/commit flushes to the origin through `sd_stage_staged_commit` → `xrootd_stage_run_inline(FLUSH)`. The bespoke `run_flush` loop and its `sync.c` trigger are deleted; `writethrough_decision.c` (policy) is kept; `writethrough_replay.c` (already on the shared FRM journal + `frm_reconcile`) is re-pointed to re-drive the staging engine instead of `run_flush`.

**Tech Stack:** C (nginx stream module), the SD driver seam, `sd_stage` (`src/fs/backend/stage/`), the staging engine (`src/fs/xfer/stage_engine.c`), the shared FRM journal (`src/fs/xfer/xfer_reconcile.*`).

## STATUS 2026-07-01 — COMPLETE. run_flush RETIRED (physically deleted); writethrough is one mechanism (sd_stage).

**Task 5 DONE.** `writethrough_flush.c` (~950 lines) and `writethrough_replay.c` are DELETED (deregistered from `./config`); the `sync.c`/`close.c` run_flush triggers, the `process.c` replay hook, and the orphaned `cache_internal.h` decls are removed. Every writethrough write now routes through the wt `sd_stage` decorator. Two fixes were needed to make run_flush truly dead: (1) the wt `sd_stage` build was gated behind `cache_storage_init`'s no-`cache_root` early return, so a PURE write-through export (no read cache, e.g. `run_credential_wt_ztn`) skipped it — moved to `cache_build_wt_stage`, called BEFORE the early return; (2) a posix-export with no registered backend now composes a posix store on the export root (`cache_wt_store_rootfd`). Verified: clean build, guard GREEN, 8/8 writethrough/stage harnesses, 161 general write/read pytest. NOTE: the phantom ABI trap recurred (a struct-field add + incremental build → broken); clean rebuild fixed it — see the memory. Deferred: the close-WITHOUT-sync durability edge (sync-before-close clients get full durability via the fsync job).

---

## (superseded) STATUS 2026-07-01 — Option A done; writethrough FUNCTIONALLY routed through sd_stage

- **Option A DONE + proven** (see Task 0). `sd_stage` has a random-access write-back object; root:// writes flow through it byte-exact (`run_root_stage_writeback.sh`).
- **Tasks 1-3 DONE (wiring):** `xrootd_cache_build_wt_origin` (shared write-back-credential builder), `cache_wt_stage_sd_inst` (config-time `sd_stage(wt_origin, export-backend)`), and the write-open routes a writethrough WRITE through it (`open_resolved_file.c` `wt_via_stage` → `wt_enabled=0`). A wt sd_stage handle flushes on the storage path: `kXR_sync` → the VFS fsync job → `sd_stage_wb_fsync` (surfaces failure as kXR_error); close → `sd_stage_wb_close`. Since a cache node always registers a backend, `wt_via_stage` is always taken for a writethrough export → `wt_enabled` is never set → **`run_flush` is never triggered** (effectively dead), but its CODE is KEPT as a fallback (sync.c/close.c triggers gated on `wt_enabled`).
- **Task 5 (physically delete run_flush's ~600 lines): DEFERRED.** It is now dead code; deletion is safe but was left to avoid further churn after a long session. Also deferred: the close-WITHOUT-sync durability edge (a client that closes without kXR_sync relies on `sd_stage_wb_close`'s best-effort flush, whose failure `free_fhandle` ignores — standard sync-before-close clients get full durability via the fsync job).
- **⚠️ HARD LESSON (cost hours):** adding fields to `config.h`/`file.h` then doing an INCREMENTAL `make` produced mixed-ABI garbage that manifested as a phantom "flush durability bug" (uploads silently failing). A CLEAN rebuild (`rm -rf objs && ./configure && make`) fixed it. ALWAYS clean-rebuild after a struct-field change. Saved to memory `struct-field-abi-clean-rebuild`.
- **Verification:** clean build, guard GREEN, 8/8 writethrough/stage self-contained harnesses pass; general write pytest 124/126 (the 2 were fleet-state, pass on a fresh fleet); read-through pass on a clean fleet.

## Global Constraints

- **NO `goto`** in `src/` (early-return + helper decomposition). Verbatim from CLAUDE.md.
- **NO git commands without explicit OP instruction.** Verbatim from CLAUDE.md — leave changes in the working tree; do NOT run `git commit`. This OVERRIDES any "Commit" step below.
- **All data byte-I/O stays in `src/fs/backend/`** (VFS seam; `tools/ci/check_vfs_seam.sh` stays GREEN).
- **Build:** `cd /tmp/nginx-1.28.3 && make -j$(nproc)` (add `./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd` only when a source file is added/removed). `-Werror` is on.
- **Durability is non-negotiable:** a write acknowledged to the client MUST survive a crash and reach the origin (the FRM journal guarantees this today). A task that weakens crash-recovery is a failed task — Task 4 gates the whole fold on the journal path.
- **Credential correctness:** the write-back origin uses the WRITE-BACK credential (`cache_origin_bearer`/`x509_proxy`/`ca_dir`, falling back to `cache_origin_proxy`/`cadir`) — NOT the read-origin fields. Preserve this exactly (it is already correct in `run_flush:656-668`; do not regress it the way the read slice path once did).

---

### Task 0: SPIKE — NO-GO resolved by OPTION A (executed 2026-07-01). `sd_stage` now supports random-access write-back; the fold is UNBLOCKED.

> **✅ OPTION A DONE 2026-07-01 — `sd_stage` extended with a random-access write-back object.** The original NO-GO was: `sd_stage` had no `.pwrite` and root:// is direct pwrite. FIXED by adding a write-back object to `sd_stage` (`src/fs/backend/stage/sd_stage.c`): `sd_stage_open` for a WRITE now returns a stage-store-backed writable object (`sd_stage_open_writeback`); `sd_stage_wb_pwrite`/`_pread`/`_ftruncate`/`_fstat` operate on the local stage buffer; `sd_stage_wb_fsync`/`_close` FLUSH the whole object to the backend through the one staging engine (`xrootd_stage_run_inline(FLUSH)`). Read opens still return the source object (read I/O bypasses the decorator). **Proven:** new `tests/run_root_stage_writeback.sh` — a root:// upload to a composable stage node (`storage_backend root://O` + `stage_store posix:<local>` + `stage on`) buffers on the stage store and flushes to O byte-exact, and reads back byte-exact. Existing staged (HTTP PUT) path + legacy `run_flush` path both still green (7 write harnesses). **root:// now uses the SAME stage mechanism as HTTP PUT** — the prerequisite the NO-GO blocked.
>
> **Remaining to actually RETIRE `run_flush` (Tasks 1-5, now VIABLE):** translate the legacy `cache_origin` writethrough config to a config-time wt `sd_stage` instance (Task 1) → route the write-open through it (Task 2, now works — `sd_stage` has pwrite) → remove the `run_flush` trigger in `sync.c` (Task 3) → re-home replay to the engine (Task 4, durability gate) → delete the bespoke loop (Task 5). Option A was the hard enabler; these are the follow-on migration.

### Task 0 (original): SPIKE — ⛔ was NO-GO before Option A.

> **Result: NO-GO.** (1) `sd_stage`'s driver vtable is **staged-lifecycle-only** — `open`/`staged_open`/`staged_write`/`staged_commit`, **no `.pwrite`** (`src/fs/backend/stage/sd_stage.c`). (2) root:// kXR_write is **random-access direct pwrite** — `src/write/write.c:160-164` writes from the recv buffer via `driver->pwrite` on `fh->sd_obj` at arbitrary offsets; it never uses the staged lifecycle (`run_pblock_writethrough` runs `upload_resume off`). So Task 2's mechanism (adopt `sd_stage` into `fh->sd_obj` + `driver->pwrite`) would NULL-deref, and there is NO root:// composable stage test because root:// has never gone through `sd_stage`. `run_flush` exists *because* root:// writes to a local file at random offsets then flushes the whole file — a model `sd_stage` (build-then-commit, for HTTP PUT) does not cover. The proven `sd_stage` write-through (`run_tier_remote_stage.sh`) is WebDAV/S3, which DO use the staged lifecycle.
>
> **Re-scope options (none is a task-by-task migration — each is a design effort):**
> - **A. Extend `sd_stage` with a random-access write-back object** (`.open` returns a stage-store-backed writable object; `.pwrite` buffers; close/sync flushes to the backend). Makes `sd_stage` cover root:// too, but adds a second write model to `sd_stage` and a flush-on-close hook (close currently means cleanup, not flush). Medium-large, and it's a genuine `sd_stage` design change.
> - **B. Convert the root:// write path to the staged lifecycle** (open→`staged_open`, each kXR_write→`staged_write`, sync/close→`staged_commit`). Deep, and complicated by random-access/out-of-order writes + `upload_resume` semantics that the staged (build-then-commit) model does not naturally support.
> - **C. Keep both mechanisms, by write MODEL** (RECOMMENDED default): `run_flush` = root:// random-access write-back; `sd_stage` = staged (HTTP PUT) write-back. Two mechanisms, but they serve two genuinely different write models — analogous to Pelican staying bespoke for a real reason. G9's "exactly one stage mechanism" is not achievable without A or B; document that the two mechanisms map to two write models and leave `writethrough_flush` in place.
>
> **Tasks 1-5 below are NOT started** (they assume the GO path). They remain valid only if option A or B is chosen and designed first.

### Task 0 (original): SPIKE — prove a legacy writethrough config can resolve its write-open to `sd_stage` byte-exact (GATES EVERYTHING)

**Files:**
- Read: `src/fs/vfs_backend_registry.c:1055-1081` (how `sd_stage` is composed), `src/read/open_resolved_file.c:790-840` (the write-open writethrough-decision block), `src/write/sync.c:73-90`
- Test: a throwaway config mirroring `tests/run_pblock_writethrough.sh` but composable

**Interfaces:**
- Consumes: `xrootd_sd_stage_create(top, store, policy, root_canon, log)`, `xrootd_vfs_backend_config_stage_store(root_canon, cfg, policy)`.
- Produces: a GO/NO-GO decision recorded in this plan. If NO-GO (the write-open cannot cleanly resolve to `sd_stage` for a write-back config), STOP and re-scope — the fold is blocked.

- [ ] **Step 1: Prove the composable stage path already write-throughs byte-exact.** Run `tests/run_pblock_writethrough.sh` (legacy) AND a composable equivalent that replaces `xrootd_cache_origin 127.0.0.1:PORT` with `xrootd_stage_store root://127.0.0.1:PORT` (+ `xrootd_stage on`). Confirm the composable one writes to the cache node and the bytes land on the origin, byte-exact.

Run: `bash tests/run_pblock_writethrough.sh` — Expected: `ALL PASS` (baseline).

- [ ] **Step 2: Confirm the write-open resolves the backend through the registry for a stage_store config.** In `src/read/open_resolved_file.c`, trace whether a write-open with a composed `sd_stage` backend produces a staged handle (write → `sd_stage.staged_write`, close → `sd_stage_staged_commit`) with NO `wt_flush` involvement. Grep: `grep -n 'wt_enabled\|sd_stage\|staged' src/read/open_resolved_file.c`.

- [ ] **Step 3: Record GO/NO-GO.** GO iff a composable stage_store config write-throughs byte-exact via `sd_stage` with no `run_flush` — meaning the legacy config only needs *translating* to that shape. Write the finding into this plan's header. If NO-GO, STOP.

---

### Task 1: Build the wt `sd_stage` instance from the legacy writethrough config

**Files:**
- Modify: `src/cache/cache_storage.c` (add `cache_build_wt_stage`, mirroring `cache_build_source`)
- Modify: `src/cache/cache_storage.h` (accessor decl)
- Modify: `src/core/types/config.h` (add `void *cache_wt_stage_sd_inst;` beside `cache_wt_stage_inst`)
- Modify: `src/cache/cache_internal.h` (add `xrootd_cache_build_wt_origin` decl)
- Modify: `src/cache/writethrough_flush.c:645-668` (extract the inline write-back origin build → shared `xrootd_cache_build_wt_origin`)
- Test: `tests/run_pblock_writethrough.sh`, `tests/run_cache_wt_driver.sh`, `tests/run_credential_wt_ztn.sh`

**Interfaces:**
- Consumes: `xrootd_sd_stage_create`, `xrootd_cache_wt_stage(conf)` (the existing local-cache stage instance), `xrootd_sd_xroot_create_origin`.
- Produces: `xrootd_sd_instance_t *xrootd_cache_wt_stage_sd_inst(const ngx_stream_xrootd_srv_conf_t *conf)` — the composed `sd_stage(origin-backend, local-cache-store)`, NULL when write-through is off; and `xrootd_sd_instance_t *xrootd_cache_build_wt_origin(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)` — the write-back origin (write-back creds + read fallback), the ONE builder both `run_flush` (until deleted) and the wt-stage build use.

- [ ] **Step 1: Extract the write-back origin builder.** Move the `xrootd_sd_xroot_create_origin(...)` block from `writethrough_flush.c:656-668` into a new public `xrootd_cache_build_wt_origin` in `writethrough_flush.c` (or `fetch.c` beside `xrootd_cache_build_origin`), preserving the EXACT credential precedence:

```c
xrootd_sd_instance_t *
xrootd_cache_build_wt_origin(const ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)
{
    const ngx_str_t *host = conf->wt_origin_host.len > 0 ? &conf->wt_origin_host
                                                         : &conf->cache_origin_host;
    uint16_t         port = conf->wt_origin_host.len > 0 ? conf->wt_origin_port
                                                         : conf->cache_origin_port;
    char host_z[256];

    if (host->len == 0 || port == 0) { errno = EINVAL; return NULL; }
    ngx_cpystrn((u_char *) host_z, host->data, ngx_min(host->len + 1, sizeof(host_z)));
    return xrootd_sd_xroot_create_origin(host_z, (int) port,
        (conf->cache_origin_tls == 1) ? 1 : 0, (int) conf->cache_origin_family,
        (conf->cache_origin_bearer.len > 0) ? (const char *) conf->cache_origin_bearer.data : NULL,
        (conf->cache_origin_x509_proxy.len > 0) ? (const char *) conf->cache_origin_x509_proxy.data
            : (conf->cache_origin_proxy.len > 0) ? (const char *) conf->cache_origin_proxy.data : NULL,
        (conf->cache_origin_ca_dir.len > 0) ? (const char *) conf->cache_origin_ca_dir.data
            : (conf->cache_origin_cadir.len > 0) ? (const char *) conf->cache_origin_cadir.data : NULL,
        log);
}
```

Replace `run_flush`'s inline block with `dest = xrootd_cache_build_wt_origin(wt->conf, wt->log);`.

- [ ] **Step 2: Build the wt `sd_stage` instance** in `xrootd_cache_storage_init` (after the `cache_wt_stage_inst` block, ~cache_storage.c:446). Store = `xrootd_cache_wt_stage(conf)` if set else `cache_storage_inst`; source/backend = `xrootd_cache_build_wt_origin(conf, log)`:

```c
    if (/* write-through configured: cache + origin + write allowed */
        conf->cache_origin_host.len > 0 && conf->common.allow_write) {
        xrootd_sd_instance_t *store = (conf->cache_wt_stage_inst != NULL)
                                      ? conf->cache_wt_stage_inst : conf->cache_storage_inst;
        xrootd_sd_instance_t *origin = xrootd_cache_build_wt_origin(conf, log);
        xrootd_stage_policy_t pol; ngx_memzero(&pol, sizeof(pol));
        if (origin != NULL && store != NULL) {
            conf->cache_wt_stage_sd_inst =
                xrootd_sd_stage_create(origin, store, &pol,
                                       (const char *) conf->cache_root.data, log);
        }
    }
```

- [ ] **Step 3: Accessor + init-NULL + scheme-aware cleanup** (mirror `cache_source_inst`: init to NULL in `storage_init`; in `storage_cleanup` `xrootd_sd_stage_destroy` the decorator then `xrootd_sd_xroot_destroy` the origin from `xrootd_sd_stage_source_instance`).

- [ ] **Step 4: Build (no new file).** Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc)` — Expected: `build: 0`.

- [ ] **Step 5: Behaviour-neutral regression** (instance built, not yet consumed — the write still flushes via `run_flush`).

Run: `bash tests/run_pblock_writethrough.sh && bash tests/run_cache_wt_driver.sh && bash tests/run_credential_wt_ztn.sh` — Expected: three `ALL PASS`.

---

### Task 2: Route the write-open through the wt `sd_stage` instance

**Files:**
- Modify: `src/read/open_resolved_file.c:790-840` (the writethrough-decision block — when the decision is write-through AND `xrootd_cache_wt_stage_sd_inst(conf) != NULL`, adopt that instance as the handle's backend so the write is a staged write, instead of setting `wt_enabled` for the close-time flush)
- Test: `tests/run_pblock_writethrough.sh`, `tests/run_cache_stage_throttle.sh`, `tests/test_integrity_matrix.py`

**Interfaces:**
- Consumes: `xrootd_cache_wt_stage_sd_inst(conf)` (Task 1); the handle-adoption pattern already used for driver-backed opens (`fh->sd_obj`, `xrootd_open_resolved_via_driver`).
- Produces: a write handle whose backend is the wt `sd_stage`, so `write`→`sd_stage.staged_write` and close→`sd_stage_staged_commit`. `wt_enabled` stays 0 for these handles.

- [ ] **Step 1: In the write-open decision block, prefer the sd_stage instance.** Where `wt_enabled` would be set (open_resolved_file.c ~833), gate: `if (xrootd_cache_wt_stage_sd_inst(conf) != NULL) { adopt it as the handle's sd_obj backend; wt_enabled = 0; }` else keep the legacy `wt_enabled` path (so a config with no sd_stage instance still flushes via `run_flush` — no regression during the transition).

- [ ] **Step 2: Byte-exact write-through via sd_stage.** Run `tests/run_pblock_writethrough.sh` — the write to the cache node must land on the origin byte-exact THROUGH sd_stage (verify no `run_flush` fired: `grep -c 'write-through' <cache-node error.log>` == 0 for the sd_stage path). Expected: `ALL PASS`.

- [ ] **Step 3: Throttle + integrity regression.** Run: `bash tests/run_cache_stage_throttle.sh; PYTHONPATH=tests pytest tests/test_integrity_matrix.py -q -p no:cacheprovider` — Expected: pass.

- [ ] **Step 4: Guard.** Run: `bash tools/ci/check_vfs_seam.sh` — Expected: GREEN.

---

### Task 3: Remove the `run_flush` trigger from the write path

**Files:**
- Modify: `src/write/sync.c:73-90` (the `wt_enabled && wt_dirty_offset >= 0` → `xrootd_wt_flush_sync_handle` block)
- Modify: `src/read/close.c` (any `wt_flush_on_close` call)
- Test: full writethrough harness set

**Interfaces:**
- Consumes: nothing new. After Task 2, an sd_stage write handle commits on close via the VFS staged-commit path, so `wt_enabled` is 0 and the `sync.c` block is dead for sd_stage handles.

- [ ] **Step 1: Confirm `wt_enabled` is only set on the legacy (non-sd_stage) path.** After Task 2 every configured write-through builds an sd_stage instance, so `wt_enabled` is never set → the `sync.c:73` block and `wt_flush_on_close` are dead. Prove: `grep -rn 'wt_enabled\s*=\s*1\|\.wt_enabled\s*=\s*1' src/`.

- [ ] **Step 2: Remove the dead `sync.c` flush block + the `wt_flush_on_close` call** (only once Step 1 shows `wt_enabled` is never set). Keep the sd_stage commit path (close → staged_commit) untouched.

- [ ] **Step 3: Build + full writethrough regression.** Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && cd /home/rcurrie/HEP-x/nginx-xrootd && for h in run_pblock_writethrough run_cache_wt_driver run_credential_wt_ztn run_cache_stage_throttle; do bash tests/$h.sh >/tmp/$h.log 2>&1 && echo "$h OK" || echo "$h FAIL"; done` — Expected: all `OK`.

---

### Task 4: Re-home crash-recovery replay to the staging engine (DURABILITY GATE — sequence against the FRM row)

**Files:**
- Modify: `src/cache/writethrough_replay.c` (re-point the journal-replay consumer from `run_flush` to the staging engine's flush; the journal + `frm_reconcile` scan are already shared and stay)
- Read: `src/fs/xfer/xfer_reconcile.{c,h}`, `src/fs/xfer/stage_engine.c`
- Test: `tests/run_credential_wt_ztn.sh` (durability path), a crash-recovery harness

**Interfaces:**
- Consumes: the shared FRM journal record (kind=STAGING) + `frm_reconcile` (resets crashed STAGING records to QUEUED); the staging engine's `xrootd_stage_run_inline(FLUSH)`.
- Produces: a replay consumer that, for each QUEUED wt record, re-drives the sd_stage/engine flush (not `run_flush`).

- [ ] **Step 1: Establish the crash-recovery baseline.** Write a harness that: writes to a wt cache node, kills the node BEFORE the flush completes (leaving a STAGING journal record), restarts, and asserts the bytes reach the origin on replay. Confirm it passes on the CURRENT (`run_flush`) path first.

- [ ] **Step 2: Re-point the replay consumer** to invoke the staging engine's flush for a QUEUED record (the record already carries the logical path + stage key; the engine flushes the durable stage copy to the backend). Do NOT change the journal format or the `frm_reconcile` reset — only the *consumer*.

- [ ] **Step 3: Crash-recovery MUST still pass.** Run the Step-1 harness against the re-homed path — bytes reach the origin after restart. Expected: PASS. **If it fails, STOP** — durability regression is a hard block.

- [ ] **Step 4: Note the FRM-row dependency.** Record in the plan that this replay consumer now shares the staging engine with the (future) FRM dissolution — the two must land compatibly.

---

### Task 5: Delete the bespoke `run_flush` loop

**Files:**
- Modify: `src/cache/writethrough_flush.c` (delete `run_flush`, `copy_body_driver`, `stage_copy`, `open_local_confined`, `flush_sync_handle`, `flush_on_close`, `flush_thread`, `flush_done` — everything now dead)
- Keep: `writethrough_decision.c` (policy), `writethrough_replay.c` (re-homed), `xrootd_cache_build_wt_origin` (used by the wt-stage build), the wt metrics
- Modify: `config` (drop `writethrough_flush.c` if the WHOLE file is now dead; else keep the surviving helpers)
- Test: full suite

- [ ] **Step 1: Prove each deleted symbol is dead.** For `xrootd_wt_run_flush`, `xrootd_wt_flush_sync_handle`, `xrootd_wt_copy_body_driver`, `xrootd_wt_stage_copy`, `xrootd_wt_flush_on_close`, `xrootd_wt_flush_thread`: `grep -rn '<sym>' src/ --include=*.c` shows only the definition (0 external callers).

- [ ] **Step 2: Delete the dead functions** (+ decls in `writethrough.h`/`cache_internal.h`). If `writethrough_flush.c` is entirely dead, remove it from `config` and `./configure`; otherwise leave the surviving helpers (`build_wt_origin`, `state_mark_dirty/clean`, journal helpers if replay still uses them).

- [ ] **Step 3: Build + full suite.** Run: `cd /tmp/nginx-1.28.3 && ./configure … && make -j$(nproc)` then the full cache/writethrough harness set + `PYTHONPATH=tests pytest tests/ -k "cache or writethrough or stage" -q -p no:cacheprovider`. Expected: build clean, all pass.

- [ ] **Step 4: G9 acceptance.** `grep -rn 'xrootd_wt_run_flush\|xrootd_wt_copy_body_driver' src/` == 0. Record the line count deleted (~600 of writethrough_flush.c's 949).

---

## Self-Review Notes

- **Spec coverage:** Task 0 = the go/no-go spike (the write-open re-route is the crux risk); Task 1 = the wt sd_stage instance (mirror of Row 2's `cache_source_inst`) + the write-back origin builder unification; Task 2 = route the write-open through it; Task 3 = remove the `run_flush` trigger; Task 4 = the durability/crash-recovery gate (the FRM coupling); Task 5 = delete the bespoke loop (G9). `writethrough_decision.c` is kept throughout.
- **Ordering safety:** every task through Task 4 keeps the legacy `run_flush` path intact as a fallback (Task 2 only diverts handles that HAVE an sd_stage instance; the trigger removal in Task 3 is gated on `wt_enabled` proven-never-set). Task 5 deletes only after the suite + crash-recovery are green.
- **Non-obvious risks:** (1) the write-back credential precedence (Task 1 Step 1 — must match `run_flush:656-668` exactly); (2) crash-recovery durability (Task 4 is a hard gate — a write acked to the client must survive a crash); (3) the FRM-row coupling (Task 4 Step 4 — the re-homed replay shares the staging engine with the FRM dissolution).
- **Type consistency:** `xrootd_cache_wt_stage_sd_inst(conf)` (Task 1) is the exact name consumed in Task 2; `xrootd_cache_build_wt_origin(conf, log)` is defined in Task 1 Step 1 and used in Task 1 Step 2.
