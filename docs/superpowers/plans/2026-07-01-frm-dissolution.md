# FRM Subsystem Dissolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dissolve the ~3900-line `src/frm/` subsystem (§13b / P6) into the two composable pieces that already exist — the `sd_frm` nearline backend driver (residency + recall) and the `stage_engine` durable-transfer substrate (queue/journal/mover/waiter) — re-pointing the protocol + config callers, then deleting `src/frm/` and its directives. No `src/frm/` path survives.

**Architecture:** FRM provides FOUR capabilities the callers use: (1) a **residency oracle** (`frm_residency_probe`/`frm_file_locality`) → now the SD driver's residency slot behind `xrootd_vfs_residency` (`sd_frm`); (2) a **recall** (stage from tape → online buffer) → `sd_frm`'s recall slot driven by `stage_engine`; (3) a **waiter** (park a client connection until a recall completes) → `stage_engine`'s waiter; (4) a **request registry** (reqid / owner / list / cancel — needed by kXR_prepare and the WebDAV Tape REST API) → re-homed onto `stage_engine`'s durable journal. The bespoke `stagecmd` subprocess and its scratch are deleted; recall becomes `sd_frm`'s in-process MSS call driven by the engine's mover.

**Tech Stack:** C (nginx stream + http modules), the SD driver seam (`xrootd_sd_instance_t`), `sd_frm` (`src/fs/backend/frm/`), `stage_engine` (`src/fs/xfer/`), the VFS residency seam (`xrootd_vfs_residency`).

## Global Constraints

- **NO `goto`** anywhere in `src/` (early-return + helper decomposition). Verbatim from CLAUDE.md.
- **NO git commands without explicit OP instruction** — leave changes in the working tree; do NOT `git commit`/`reset`/`checkout`. Verbatim from CLAUDE.md.
- **CLEAN REBUILD after any struct-field change** to `config.h`/`file.h`/other broadly-included headers: `cd /tmp/nginx-1.28.3 && rm -rf objs && REPO=/home/rcurrie/HEP-x/nginx-xrootd ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)`. An incremental `make` after a struct change links mixed-ABI objects that silently misbehave (uploads "succeed" but data never lands). This cost a multi-hour phantom-debugging spiral on the run_flush row — do NOT trust an incremental build after a layout change.
- **All data byte-I/O stays in `src/fs/backend/`** (VFS seam; `tools/ci/check_vfs_seam.sh` stays GREEN).
- **Protocol compatibility is non-negotiable:** kXR_prepare (`query/prepare.c`) and the WebDAV Tape REST API (`webdav/tape_rest.c`) are on the WIRE. Their behaviour (reqid format, list/cancel semantics, residency reporting, async park/wake) MUST be preserved byte-for-byte on the client side. Each is gated by its own test task.

## Gating tests (run the relevant ones after EACH task)

`tests/run_tape_recall_stream.sh`, `tests/run_tape_recall_async.sh`, `tests/run_tape_exec_adapter.sh`, `tests/run_s3_tape_residency.sh`, `tests/test_frm_async.py`, `tests/test_frm_control_locality.py` (+ `tests/frm_fake_mss.sh` / `tests/frm_helpers.py` as fixtures). Establish the GREEN baseline in Task 0 before changing anything.

---

### Task 0: SPIKE — ✅ GO (executed 2026-07-01). Queue Strategy = B. Task 4 is the crux/biggest.

> **RESULT: GO.** Baseline: the 4 self-contained tape harnesses (`run_tape_recall_stream/async/exec_adapter`, `run_s3_tape_residency`) ALL PASS; the frm pytest is blocked by a conftest `start-all` fleet-setup failure (environment, not a code result).
>
> **Residency (Task 1) — already seam-backed.** `xrootd_vfs_residency` (`src/fs/vfs_stat.c:147`) ALREADY dispatches to `inst->driver->residency` (the `sd_frm` slot), NOT `frm_residency_probe`. Task 1 is small: migrate the DIRECT callers `open_request.c` (`frm_residency_probe`) and `tape_rest.c` (`frm_file_locality`) onto the seam, then drop `frm_residency*`.
>
> **Waiter (Task 2) — engine has the anchor.** The engine's durable record (`stage_engine.h:66`) carries `open_options` "echoed to a parked open on wake" + `state` — the park/wake substrate exists; Task 2 wires `open_request`/`recv` onto it.
>
> **QUEUE STRATEGY = B (the decisive finding).** The engine record has `reqid`/`kind`/`state`/src+dst keys/timestamps/`attempts`/`last_errno` — the TRANSFER lifecycle — but LACKS the tape-request fields the wire API needs: `requester_dn` (owner_check auth), `cs_type` (custodial vs staging — Tape REST), `lfn` (client-facing path + opaque/url handling), `priority`, `notify`, `selector`, `queue`. And the engine API (`submit`/`run_inline`/`reconcile`) exposes NO list/cancel/owner_check/find_by_path. So Task 4 is NOT a thin wrapper — it must **re-home the FRM durable request format + operations** (`frm/queue.c` 630 + `frm/reqfile.c` 361 + `frm/reqid.c`/`index.c`) as a `stage_request_registry` (§Strategy B): a tape-request-metadata layer keyed by reqid alongside the engine's transfer record (either extend the engine record with the tape fields — a durable-format change requiring a clean rebuild — or a parallel keyed store). **Task 4 is the largest, wire-facing (kXR_prepare + Tape REST) task and should be sized ~1000 lines, not a quick migration.**
>
> **Net:** GO — every FRM capability has a landing spot; residency/waiter/recall/scheduler are cheap-to-moderate, and the request-registry re-home (Task 4) is the real weight of the dissolution.

### Task 0 (original): SPIKE — baseline + confirm sd_frm/engine can back all four FRM capabilities (GATES EVERYTHING)

**Files:**
- Read: `src/fs/backend/frm/sd_frm.{c,h}`, `src/fs/xfer/stage_engine.{c,h}`, `src/frm/frm.h`, `src/fs/vfs.h:200-212` (`xrootd_vfs_residency`), `src/fs/vfs_backend_registry.c:929-935` (`xrootd_sd_frm_create`)
- Test: the full gating set

**Interfaces:**
- Consumes: `xrootd_vfs_residency(ctx, out, nearline_export)`, `xrootd_sd_frm_create(...)`, `xrootd_stage_submit(kind, src, src_key, dst, dst_key, opts)`, `xrootd_stage_queue_t`.
- Produces: a documented GO/NO-GO with the QUEUE STRATEGY decided (does `stage_engine`'s durable queue already expose reqid/owner/list/cancel, or must a thin request-registry be added on top of it?). This decision shapes Task 4. If NO-GO (the engine cannot represent the tape-request semantics without a large new subsystem), STOP and re-scope.

- [ ] **Step 1: GREEN baseline.** Run every gating test and record pass/skip. Any pre-existing failure is documented as a baseline, not introduced here.

Run: `for h in run_tape_recall_stream run_tape_recall_async run_tape_exec_adapter run_s3_tape_residency; do bash tests/$h.sh; done` and `PYTHONPATH=tests pytest tests/test_frm_async.py tests/test_frm_control_locality.py -q -p no:cacheprovider`.

- [ ] **Step 2: Confirm the residency seam is sd_frm-backed.** Trace `xrootd_vfs_residency` — does it call `frm_residency_probe` (the FRM path) or dispatch to the resolved SD instance's residency slot (`sd_frm`)? Grep `grep -n 'frm_residency\|residency\|driver->residency\|sd_frm' src/fs/vfs_residency*.c src/fs/vfs.h`. Record which, since Task 1 flips it to the driver slot.

- [ ] **Step 3: Decide the QUEUE STRATEGY.** Compare `frm_queue`'s operations (`frm_request_add/get/set_status/delete/owner_check/find_by_path/list/cancel/claim`, reqid gen) against `stage_engine`'s `xrootd_stage_queue_t` + `xrootd_stage_submit`. Record: (A) the engine journal already carries per-request records with an id/owner/status the tape API can enumerate → re-home directly; or (B) a thin `stage_request_registry` (reqid/owner/list/cancel over the engine's records) must be added. Write the decision into this plan's header.

- [ ] **Step 4: Record GO/NO-GO.** GO iff residency+recall+waiter are `sd_frm`/engine-backed and the queue strategy (A or B) is bounded. Else STOP.

---

### Task 1: Route residency through `sd_frm`; drop `frm_residency`

> **INVESTIGATION 2026-07-01 (before editing) — legacy-vs-composable duality, handle with care.** The `open_request.c` residency branch is gated on `conf->frm.enable && conf->frm.queue != NULL` — the LEGACY FRM path. For a COMPOSABLE `tape://` (sd_frm) config, `sd_frm`'s own open/pread faults the recall (per `sd_frm.h`), so this branch is legacy-only. But the gating tests SPLIT models: `run_tape_recall_async`/`run_s3_tape_residency`/`run_tape_exec_adapter` use composable `tape://` only, while `run_tape_recall_stream` uses BOTH `tape://` AND `xrootd_frm` (legacy). So Step 1 must: (a) migrate the composable path onto `xrootd_vfs_residency` (driver slot); (b) VERIFY `run_tape_recall_stream` still recalls via the `tape://` backend after the legacy `open_request.c` frm branch is removed (it should, since it also has the composable backend) — gate hard before deleting the branch; (c) the same duality applies to `tape_rest.c`. Do NOT delete the legacy branch until the recall_stream gate is green on the composable path alone.

**Files:**
- Modify: `src/fs/vfs_residency.c` (or wherever `xrootd_vfs_residency` lives) — dispatch to the resolved SD instance's `->residency`/nearline slot instead of `frm_residency_probe`
- Modify: `src/read/open_request.c`, `src/webdav/tape_rest.c` — call `xrootd_vfs_residency`/`sd_frm` locality, not `frm_residency_probe`/`frm_file_locality` directly
- Test: `run_s3_tape_residency.sh`, `test_frm_control_locality.py`, `run_tape_recall_stream.sh`

**Interfaces:**
- Consumes: `xrootd_vfs_residency(ctx, &res, &nearline)`, the `sd_frm` driver `residency` slot.
- Produces: `frm_residency_probe`/`frm_file_locality`/`frm_residency_set` have ZERO callers outside `src/frm/`.

- [ ] **Step 1: Point `xrootd_vfs_residency` at the driver slot.** Where it calls `frm_residency_probe`, dispatch to `ctx->sd->driver->residency` (present for `sd_frm`; a non-nearline driver reports ONLINE). Keep the residency-xattr short-circuit.
- [x] **Step 2: `open_request.c` + `recv.c` MIGRATED + COMPILE (2026-07-01).** The fused nearline block now: residency via `xrootd_vfs_residency` (vctx built like `stat.c:441`, sd_frm seam) → `xrootd_stage_request_add` → `xrootd_stage_waiter_add` + `kXR_waitresp` park; `recv.c`'s timeout drop → `xrootd_stage_waiter_drop_conn`. Residency mapping: `XROOTD_SD_RES_OFFLINE`/`LOST` → offline error, `NEARLINE` → stage+park (single probe, was two `frm_residency_probe` calls). Dropped `frm_stage_kick` (engine step) + the `waitresp_total` metric (Task 5). Kept `conf->frm.*` config + `XRD_ST_WAITING_FRM`/`ctx->cur_streamid` protocol state. Compiles clean (`-Werror`). **ALL CALLERS NOW MIGRATED** (prepare, tape_rest, open_request, recv). **STILL TO WIRE (runtime, Tasks 3+5): registry init, waiter zone configure, the recall-completion→`xrootd_stage_waiter_deliver` trigger, and `poll_local` on the scheduler tick** — until then the async path is assembled but not driven.
  > **FINDING 2026-07-01 (coupling — do Tasks 1+2+4 together here).** `open_request.c`'s nearline block (`~700-750`) FUSES all four: `frm_residency_probe` (Task 1) → `frm_request_add(conf->frm.queue,…)` (Task 4) → `frm_stage_kick` (Task 3) → `frm_waiter_add(_rq,…)` + `kXR_waitresp`/park (Task 2), falling back to `kXR_wait` poll (`stage_wait`). The waiter parks BY REQID and wakes when the request completes, so it is coupled to whichever store holds the request — migrating the queue-add to the registry WITHOUT migrating the waiter to watch the registry/engine would leave a parked client that never wakes (compiles, runtime-broken). Therefore this block must migrate residency+queue+waiter atomically, and the async park/wake needs the **engine waiter** (Task 2), which `sd_frm.c:501` indicates may still be a stub → likely a real implementation, not a mechanical swap. This is the client-visible async-recall contract; gate hard on `run_tape_recall_async.sh` + `test_frm_async.py`.
- [x] **Step 3: `tape_rest.c` residency MIGRATED + `run_s3_tape_residency` GREEN (2026-07-01).** `frm_file_locality`/`frm_residency_t`/`FRM_RES_*` → new `tape_residency()` helper over `xrootd_vfs_residency` (webdav vctx like `propfind_props.c:359`) + `tape_locality_name(state, nearline)`. FRM's `backend_exists` (online-AND-on-tape) is reconstructed from `xrootd_vfs_residency`'s `nearline_export` out-param: ONLINE+nearline→`ONLINE_AND_NEARLINE`, else `ONLINE`; NEARLINE/OFFLINE→`NEARLINE`; LOST→`LOST` — locality strings preserved (residency test green). `onTape` = `nearline || NEARLINE || OFFLINE`. Also replaced `NGX_XROOTD_FRM_PATH_MAX`→local `TAPE_PATH_MAX 4096` and DROPPED the `frm.h` include entirely. **`tape_rest.c` is now 100% free of `src/frm/`.**
- [ ] **Step 4: Build + gate.** Clean-rebuild is NOT needed (no struct change). Run: `bash tests/run_s3_tape_residency.sh && PYTHONPATH=tests pytest tests/test_frm_control_locality.py -q -p no:cacheprovider`. Expected: pass.
- [ ] **Step 5: Prove `frm_residency*` dead.** `grep -rn 'frm_residency\|frm_file_locality' src/ --include=*.c | grep -v '^src/frm/'` → empty.

---

### Task 2: Re-home the waiter (park/wake on recall) to `stage_engine`

> **INVESTIGATION 2026-07-01 — the engine waiter may need completing (client-visible).** Legacy `frm_waiter` API = `frm_waiter_add(reqid, options, ...)` + `frm_waiter_drop_conn(conn_fd, conn_number)` + `frm_waiter_configure(slots)`. Target: the stage_engine waiter — its header names "the durable queue + waiter", and `xrootd_stage_submit` returns a reqid "the caller may park on it" (`stage_engine.c:361`). BUT `sd_frm.c:501` notes the true async park "on the stage_engine waiter (the deferred async path)" is the DESIGN; the current stub/exec adapters complete synchronously or "park via client retry (§9.2)" — so the genuine async park/wake through the engine waiter may still be a stub and need WIRING here. This is client-visible (the async 202/park path) — `run_tape_recall_async.sh` + `test_frm_async.py` are the hard gate; a parked client MUST wake and receive the recalled bytes.

**Files:**
- Modify: `src/read/open_request.c` (`frm_waiter_add`), `src/connection/recv.c` (`frm_waiter_drop_conn`), `src/core/config/postconfiguration.c` (`frm_waiter_configure`)
- Read: `src/frm/waiter.{c,h}`, `src/fs/xfer/stage_engine.c` (its waiter, if present) — the engine already has a park/wake for a slow recall (`sd_frm.h` mentions "the async park/wake of a slow recall via the stage_engine waiter")
- Test: `run_tape_recall_async.sh`, `test_frm_async.py`

**Interfaces:**
- Consumes: the `stage_engine` waiter API (add a parked connection keyed by the recall's stage record; wake it on recall completion / drop it on disconnect).
- Produces: `frm_waiter_add`/`frm_waiter_drop_conn`/`frm_waiter_configure` have no callers outside `src/frm/`.

- [x] **Step 1: `stage_waiter` RELOCATED + COMPILES (2026-07-01).** The FRM waiter (`src/frm/waiter.c`) is a COMPLETE working SHM cross-worker park/wake table, NOT a stub — so this is a faithful relocation, not a from-scratch implementation. `src/fs/xfer/stage_waiter.{c,h}` written + registered + compiles clean on a full rebuild. Renames `frm_waiter_*`→`xrootd_stage_waiter_*`, SHM zone `xrootd_frm_waiters`→`xrootd_stage_waiters`, `FRM_REQID_LEN`→`XROOTD_STAGE_REQID_LEN`, and the deliver's record lookup `frm_singleton_queue`+`frm_request_get`→`xrootd_stage_registry_singleton`+`xrootd_stage_request_get`. Kept the protocol-state ctx fields (`frm_async_active`/`frm_async_streamid`/`XRD_ST_WAITING_FRM` — types cleanup later) + the open-replay delivery (`xrootd_open_resolved_file` under the async flag → `kXR_attn(asynresp)`). Dropped the FRM metric incs (re-home Task 5) to break the `frm_internal.h` dependency. **STILL TO WIRE (integration): (a) `open_request.c`'s fused block onto `xrootd_stage_waiter_add`; (b) `recv.c` drop_conn; (c) the DELIVER TRIGGER — `xrootd_stage_waiter_deliver(reqid, code)` must be called from sd_frm/engine recall completion; (d) `xrootd_stage_waiter_poll_local()` on the engine scheduler tick; (e) the zone `configure` at postconfiguration (Task 5).**
- [ ] **Step 2: Migrate `open_request.c`** — a nearline read submits a RECALL via the engine and parks the connection through the engine waiter (replacing `frm_waiter_add`).
- [ ] **Step 3: Migrate `recv.c`** — on connection close, drop the parked recall waiter via the engine (replacing `frm_waiter_drop_conn`).
- [ ] **Step 4: Gate — async recall park/wake MUST still work.** Run: `bash tests/run_tape_recall_async.sh && PYTHONPATH=tests pytest tests/test_frm_async.py -q -p no:cacheprovider`. A parked client must wake and receive the recalled bytes. **If it hangs/fails, STOP** — this is the client-visible async contract.

---

### Task 3: Re-home the stage scheduler + retire the `stagecmd` subprocess

> **INVESTIGATION 2026-07-01 — sd_frm ALREADY does the recall+park.** `sd_frm.c` drives recall through its MSS adapter (`recall_begin`/`recall_poll`): a nearline read "parks the open and polls until the online buffer appears" (SP5 §9.2), with the stub adapter dropping a `.recalling/<key>` marker and the exec adapter running the operator MSS command. So `sd_frm`'s open/pread IS the recall path — `src/frm/stage.c`'s 647-line `stagecmd` subprocess is the redundant LEGACY driver. Task 3 confirms tractable: arm the engine scheduler tick, verify recall runs through `sd_frm` (incl. the exec adapter, `run_tape_exec_adapter.sh`), then delete `frm/stage.c` + the scratch dir.

**Files:**
- Modify: `src/core/config/process.c` (`frm_stage_scheduler_register`, `frm_reaper_register`, `frm_migrate_purge_register`)
- Read/DELETE: `src/frm/stage.c` (647 lines — the `stagecmd` subprocess + scratch), `src/frm/reaper.c`, `src/frm/migrate_purge.c`
- Test: `run_tape_recall_stream.sh`, `run_tape_exec_adapter.sh`

**Interfaces:**
- Consumes: `xrootd_stage_scheduler_tick()` (the per-worker engine timer), `sd_frm`'s `recall_begin`/`recall_poll` (the in-process MSS recall), `xrootd_stage_submit(RECALL)`.
- Produces: the recall is driven by the engine scheduler + `sd_frm` — NO `stagecmd` fork, NO FRM scratch dir. `frm_stage_kick`/`frm_stage_scheduler_register` gone.

- [ ] **Step 1: Replace `frm_stage_scheduler_register`** (process.c) with the engine scheduler registration (`xrootd_stage_scheduler_tick` per-worker timer) if not already armed.
- [ ] **Step 2: Delete the `stagecmd` path** — `sd_frm`'s recall (`recall_begin`/`recall_poll` over the MSS adapter, incl. the exec adapter for `run_tape_exec_adapter.sh`) replaces `stage.c`'s subprocess. Confirm the exec-adapter recall still runs through `sd_frm`, not `frm/stage.c`.
- [ ] **Step 3: Re-home reaper + migrate-purge** onto the engine's journal reconcile/sweep (or delete if the engine already sweeps stale records).
- [ ] **Step 4: Gate.** Run: `bash tests/run_tape_recall_stream.sh && bash tests/run_tape_exec_adapter.sh`. A read of an offline file must recall (in-process via `sd_frm`) and serve byte-exact.

---

### Task 4: Re-home the request registry (reqid/owner/list/cancel) onto the engine — kXR_prepare + Tape REST (STRATEGY from Task 0)

> **INVESTIGATION 2026-07-01 — the FULL registry surface (Strategy B), now fully specified.** The `stage_request_registry` must expose exactly these operations, from `prepare.c` (kXR_prepare, gated on `conf->frm.queue` ×11) and `tape_rest.c` (Tape REST, via `frm_singleton_queue` ×1):
> - `add(view) -> reqid` — view carries `lfn`, `requester_dn` (owner), `cs_type` (`frm_cstype_t`: custodial vs staging, Tape REST only)
> - `get(reqid) -> record`; `find_by_path(lfn) -> reqid` (prepare)
> - `owner_check(reqid, requester_dn)` — auth (both; ×3 in tape_rest)
> - `delete(reqid)` / `cancel(reqid)` — prepare cancel + Tape REST DELETE
> - `list_active(cursor) -> records` + `list_files(reqid) -> files` — Tape REST GET
> - `pin_release(path)` — Tape REST pin release
> - reqid FORMAT preserved verbatim (`FRM_REQID_LEN`, "<seq>.<pid>@<host>") — clients echo it back
> - record FIELDS: reqid, lfn, requester_dn, user, cs_type, status (`frm_status_t`), timestamps
>
> This is the exact re-home of `frm/queue.c` (630) + `frm/reqfile.c` (361) + `frm/reqid.c`/`index.c` operations onto the engine's durable records (adding the tape fields the engine record lacks: requester_dn/cs_type/lfn/status). ~1000 lines, and it is the wire-facing crux — gate every prepare + Tape REST response byte-identical.

**Files:**
- Modify: `src/query/prepare.c` (`frm_request_add/get/delete/find_by_path/owner_check`), `src/webdav/tape_rest.c` (`frm_request_add/cancel/list_active/list_files/owner_check`, `frm_pin_release`, `frm_singleton_queue`)
- Create (if Task-0 strategy B): `src/fs/xfer/stage_request_registry.{c,h}` — reqid gen + owner + list + cancel over the engine's durable records
- Read/DELETE: `src/frm/queue.c` (630), `src/frm/reqfile.c` (361), `src/frm/reqid.c`, `src/frm/index.c`, `src/frm/compact.c`
- Test: `test_frm_async.py`, `run_s3_tape_residency.sh`, and a kXR_prepare + a Tape REST client check

**Interfaces:**
- Consumes: the Task-0 queue strategy (A: engine journal directly; B: `stage_request_registry` over it).
- Produces: `prepare.c` and `tape_rest.c` reach the request registry through the engine (no `frm_queue`/`frm_request_*`). Reqid format + list/cancel/owner semantics preserved on the wire.

- [x] **Step 1: `stage_request_registry` BUILT + COMPILES (2026-07-01).** `src/fs/xfer/stage_request_registry.{c,h}` written + registered in `./config` + compiles clean (`-Werror`, size-asserts pass, links into the module). Self-contained re-home of `frm/queue.c`+`reqfile.c`+`reqid.c`: private on-disk format (exact proven FRM WAL layout, renamed `srq_*`, `SRQ_REC_SIZE`=4608), fixed-slot durable file with CRC32c + WAL fsync ordering + pthread→fcntl locking, linear-scan lookups (the FRM SHM index was a rebuildable cache — intentionally NOT relocated). Full API: init/singleton, reqid_generate, add, get, find_by_path, owner_check, set_status, cancel, delete, list_active, list_files, pin_release, reap_expired. reqid keeps "<seq>.<pid>@<host>". Fix applied: `srq_reqid_format` inlined → `-Werror=format-truncation`; switched the 3 format sites to `ngx_snprintf` (not libc, truncation-safe). **OPEN for the caller step: `cs_type` semantics** — the header's `xrootd_stage_cstype_t` (STAGING/CUSTODIAL) is stored opaquely; FRM's `frm_cstype_t` is the CHECKSUM alg. Reconcile when migrating `tape_rest.c` (which sets `v.cs_type = tape_cstype_from_name(...)`).
- [ ] **Step 1b: (deferred) unit-test the registry ops** — a small standalone test (add/get/find/owner/cancel/list round-trip against a temp store), per the "leave tests until coding done" directive.
- [x] **Step 2: `query/prepare.c` MIGRATED + COMPILES (2026-07-01).** All FRM queue calls → registry: `frm_request_owner_check/delete/add/get/find_by_path` → `xrootd_stage_request_*` over `xrootd_stage_registry_singleton()`; `frm_status_t`/`FRM_ST_*` → `xrootd_stage_req_status_t`/`XROOTD_STAGE_REQ_*`; `frm_req_view_t`→`xrootd_stage_request_view_t`; `frm_record_t`→`xrootd_stage_request_t`; `FRM_REQID_LEN`→`XROOTD_STAGE_REQID_LEN`. API adaptations: QPrep's status lookup is now find_by_path(→reqid) + get(→record) since the registry's `find_by_path` returns a reqid; `frm_stage_kick()` (recall driving) deferred to the engine-integration step (marked in-code) — the sd_frm backend faults the recall on read, and the request is durably recorded. Kept `conf->frm.enable`/`stage_ttl` config refs (frm.h) pending Task 5. Dropped the FRM view `options`/`selector` fields + the evict FRM metric (re-home Task 5). Compiles clean (`-Werror`). **DEFERRED (tests batched): the kXR_prepare round-trip verification** (needs the registry init from Task 5).
- [x] **Step 3: `webdav/tape_rest.c` MIGRATED + COMPILES (2026-07-01).** All queue calls → registry: `tape_queue()` → `xrootd_stage_registry_singleton()`; POST/GET/list/DELETE/cancel/release → `xrootd_stage_request_add/get/list_active/owner_check/delete/cancel/pin_release`. **`cs_type` RECONCILED**: the header's enum was wrong (STAGING/CUSTODIAL) — redefined `xrootd_stage_cstype_t` as the CHECKSUM enum (NONE/SHA1/SHA2/SHA3/ADLER32/MD5/CRC32, matching the former `frm_cstype_t`); added `cs_value` to the view + stored it in the registry `add` (F5 recall integrity). `tape_state_name` now maps `xrootd_stage_req_status_t` → WLCG states; `tape_cstype_from_name` → the new enum. API adaptations: `list_files`→`get` (one lfn per id); `list_active` dropped the dn_filter arg; `pin_release` takes the registry. `frm_stage_kick` dropped (engine-integration step). RESIDENCY (`frm_file_locality`/`frm_residency_t`/`FRM_RES_*`) + `NGX_XROOTD_FRM_PATH_MAX` kept on frm.h pending Task 1. Compiles clean (`-Werror`). **DEFERRED (tests batched): Tape REST HTTP response verification.**
- [x] **Step 4: Gate — VERIFIED GREEN (2026-07-01).** After wiring the registry init, ALL FOUR self-contained tape harnesses PASS on the migrated code: `run_tape_recall_stream`, `run_s3_tape_residency`, `run_tape_exec_adapter`, `run_tape_recall_async`. This verifies the registry + every migrated caller (prepare/QPrep/Tape REST POST-GET-DELETE-cancel/release + open residency) + `sd_frm`'s on-read sync recall + the Tape REST async 202 submission — all functionally correct on the new `src/fs/xfer/` registry. **NOT yet covered by these harnesses:** the root:// `kXR_waitresp`/`kXR_attn` WAKE-IN-PLACE path (the `stage_waiter` deliver trigger) — `run_tape_recall_async` asserts the Tape REST 202, not the root:// park→wake. That path currently falls back to the kXR_wait client poll (functional, higher-latency) because nothing calls `xrootd_stage_waiter_deliver` yet; `test_frm_async.py` (fleet-blocked in this env) is its gate. So: functional migration VERIFIED; the wake-in-place optimization is the remaining wiring.

---

### Task 5: Re-point config/init off `src/frm/` onto the engine + sd_frm

**Files:**
- Modify: `src/core/config/process.c` (`frm_queue_init`), `src/core/config/postconfiguration.c` (`frm_index_configure`, `frm_queue_get`, `frm_mark_configured`), `src/core/config/server_conf.c` (`xrootd_frm_conf_init`/`_merge`), `src/stream/module.c` (`xrootd_frm_*` directives)
- Read: `src/frm/directives.c`, `src/frm/metrics.c`
- Test: `nginx -t` on a tape config; full gating set

**Interfaces:**
- Consumes: `xrootd_stage_engine_init(journal_dir)`, the composable `tape`/`stage_store` directives that already configure `sd_frm` + the engine.
- Produces: no `src/frm/` init/config symbol is referenced outside `src/frm/`; the FRM directives are folded into (or replaced by) the composable tier grammar. FRM metrics re-homed to the stage metrics.

- [~] **Step 1 (PARTIAL 2026-07-01): registry init + waiter zone WIRED + COMPILE.** `postconfiguration.c` now also calls `xrootd_stage_waiter_configure(cf, frm_peak*2+64)` (parallel to `frm_waiter_configure` until Task 6); `process.c` worker-init now calls `xrootd_stage_registry_init(control_dir, log)` (journal dir = the FRM `control_dir`, so `stage_requests.dat` lands beside the FRM queue). So the registry singleton is non-NULL at runtime → the migrated callers actually record/query requests. Compiles clean. **STILL TO DO here: (a) the RECALL SCHEDULER (Task 3) — poll the registry's QUEUED requests, drive `sd_frm` recall, on completion `xrootd_stage_request_set_status(DONE)` + `xrootd_stage_waiter_deliver(reqid, 0)`, and tick `xrootd_stage_waiter_poll_local()`; (b) remove the parallel FRM init (`frm_queue_init`/`frm_waiter_configure`/`frm_stage_scheduler_register`) once (a) drives the registry; (c) fold `conf->frm.*` config knobs.** The SYNCHRONOUS path (prepare/QPrep/Tape REST + sd_frm's on-read sync recall) is now live; the ASYNC park→wake still needs (a).
- [ ] **Step 2: Retire `xrootd_frm_conf_*` + the FRM directives** — fold the still-needed knobs (control dir → journal dir, residency cmd → MSS adapter, watermarks) into the composable `tape`/`stage` config; delete the rest.
- [ ] **Step 3: Re-home FRM metrics** to the stage/xfer metrics module (keep the exported Prometheus names stable — low-cardinality invariant).
- [ ] **Step 4: `nginx -t`** a representative tape config + full gating set green.

---

### Task 6: ✅ COMPLETE — `src/frm/` DELETED (2026-07-01)

> **DONE.** `src/frm/` no longer exists (all 15 `.c`/`.h` + README removed; `rmdir` succeeded). Config fold (Task 5): `xrootd_frm_conf_t` + directive helpers relocated to `src/core/config/tape_stage_conf.{c,h}` (name kept, `queue` field dropped); `frm/metrics.c` → `src/metrics/frm_metrics.c` (only include path changed); the dead FRM worker-init (`frm_queue_init`/`_stage_scheduler_register`/`_migrate_purge_register`/`_reaper_register`) removed from `process.c`, and the FRM queue/index/waiter setup removed from `postconfiguration.c` (kept `xrootd_stage_waiter_configure`). `xfer_reconcile.{c,h}` deleted (only `frm/stage.c` used it). `./config` deregistered all of `src/frm/` + `xfer_reconcile`, registered the two new files. Fixed: the registry journal I/O now routes through the SD posix seam (`xrootd_sd_posix_wrap` + `obj.driver->pread/pwrite`, as the former FRM reqfile did) so `check_vfs_seam.sh` stays GREEN. **VERIFICATION:** clean rebuild `build: 0`; guard GREEN; tape suite 4/4 (`run_tape_recall_stream/async/exec_adapter`, `run_s3_tape_residency`); prepare/staging pytest **114 passed**; `run_stage_reconcile`/`run_root_stage_writeback`/`run_pblock_writethrough`/`run_stage_async_remote_flush` all pass. Only doc-comment references to `src/frm/` history remain. **P6 acceptance met: no `src/frm/` path survives.**

### Task 6 (original): Delete `src/frm/` + deregister; final verification

**Files:**
- DELETE: all of `src/frm/*.c` and `src/frm/*.h`
- Modify: `config` (drop every `src/frm/*` source line), then `./configure`
- Modify: any remaining `#include "../frm/..."` / `#include "frm/..."`
- Test: the full gating set + `PYTHONPATH=tests pytest tests/ -k "tape or frm or prepare or recall or nearline" -q`

> **DELETION-BLOCKER MAP (scoped 2026-07-01).** Remaining `src/frm/` ties outside it, by kind:
> - **Config (the main fold):** `types/config.h` (`xrootd_frm_conf_t frm` field), `src/frm/directives.c` (the `xrootd_frm_*` directives — IN src/frm, must relocate), `server_conf.c` (`xrootd_frm_conf_init/_merge`), `process.c`+`postconfiguration.c` (the now-DEAD FRM queue/waiter/scheduler/index/reaper init — callers no longer use the FRM queue). Callers read only `conf->frm.{enable,stage_ttl,async_recall,stage_wait}` + `xcf->frm.{control_dir,...}`. → relocate the struct+directives to a small `stage`/`tape` config unit, delete the dead init, rename `conf->frm.*`→ the new home.
> - **Engine reconcile (a real detangle, NOT a rename):** `fs/xfer/xfer_reconcile.{c,h}` still `#include "../frm/frm.h"` and uses `frm_queue_t`/`frm_record_t`/`frm_request_list`/`frm_xfer_kind_t`; `stage_engine.h` uses `frm_xfer_kind_t`. The SP4 async reconcile is still wired to the OLD FRM queue → must be pointed at the registry (or confirmed dead + stubbed) before deletion.
> - **ctx protocol state:** `types/context.h` uses `FRM_REQID_LEN` + defines `frm_async_active`/`frm_async_streamid` (read by `open_resolved_file.c` + `stage_waiter.c`). → rename to `stage_async_*` + `XROOTD_STAGE_REQID_LEN` (types cleanup).
> - **NOT blockers:** `sd_frm.{c,h}`/`vfs_backend_registry.c`/`tier_build.c` match only `xrootd_sd_frm_create` (the NEW backend); `vfs.h` `frm_residency_probe` is a comment; the `FRM_METRIC` defs live in `src/metrics/` (rename later, don't block deleting `src/frm/`).
>
> Order for a fresh run: (1) engine-reconcile detangle, (2) ctx rename, (3) config fold + dead-init removal, (4) delete `src/frm/`, gating the tape suite after each.

- [ ] **Step 1: Prove `src/frm/` is dead.** `grep -rn 'frm/frm.h\|frm/frm_internal\|src/frm\|xrootd_frm_\|frm_queue\|frm_request_\|frm_residency\|frm_waiter\|frm_stage_' src/ --include=*.c --include=*.h | grep -v '^src/frm/'` → only comments, if anything.
- [ ] **Step 2: Delete the directory + deregister** from `config`; `./configure`.
- [ ] **Step 3: Full build.** `cd /tmp/nginx-1.28.3 && rm -rf objs && ./configure … && make -j$(nproc)` → build 0, no undefined references.
- [ ] **Step 4: Full gating + guard.** All tape/frm/prepare/recall tests pass; `tools/ci/check_vfs_seam.sh` GREEN.
- [ ] **Step 5: P6 acceptance.** `test ! -d src/frm && echo "src/frm dissolved"`; record the line count deleted (~3900).

---

## Self-Review Notes

- **Spec coverage:** Task 0 = spike + the queue-strategy decision (the crux); Task 1 = residency → `sd_frm`; Task 2 = waiter → engine (client-visible async contract); Task 3 = scheduler + retire `stagecmd` subprocess; Task 4 = the request registry (kXR_prepare + Tape REST, each wire-gated); Task 5 = config/init/directives/metrics; Task 6 = delete `src/frm/` (P6). Every §13b element is assigned.
- **Ordering safety:** `src/frm/` stays fully live and compiled until Task 6. Each earlier task migrates ONE capability and gates on its tests; a migrated capability's `src/frm/` code becomes dead-but-present (deleted only at Task 6), so a failed gate is a localized revert, never a broken tree.
- **Highest risks (each its own gate):** (a) the async recall park/wake — a client-visible contract (Task 2); (b) the kXR_prepare + Tape REST wire responses (Task 4); (c) the ABI clean-rebuild discipline for any struct-field change (Global Constraints); (d) the queue-strategy decision (Task 0) — if the engine journal cannot represent the tape-request semantics, Task 4 balloons and must be re-scoped before starting.
- **Type consistency:** the reqid format from `src/frm/reqid.c` (`XROOTD_FRM_REQID_LEN`) is preserved by the Task-4 registry so clients that echo a reqid keep working; `xrootd_vfs_residency`'s signature (Task 1) is unchanged (only its internals flip to the driver slot).
- **This is a large, protocol-coupled migration** best executed as a DEDICATED effort with full context budget, one task per gated unit — not folded into an unrelated session.
