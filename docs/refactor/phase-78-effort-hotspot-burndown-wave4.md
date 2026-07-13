# Phase 78 — Effort-Hotspot Burndown, Wave 4 (top-100)

> **For agentic workers:** decomposition-only refactor. Each task takes ONE file to
> `lizard -C 15 -L 100 -a 5 -w` clean (or documented frozen-signature param residuals),
> with **zero behavior change**. Run in bounded parallel waves (12–15 files), full
> module/client build after each wave (the build is the only cross-file oracle). Steps use
> checkbox (`- [ ]`) syntax.

**Goal:** Drive the 100 highest-effort files below the complexity gate (CCN ≤15, function
NLOC ≤100, params ≤5) and triage the single live analyzer finding — without changing any
observable behavior.

**Architecture:** Extract cohesive branches into static helpers with WHAT/WHY/HOW doc
blocks; table/descriptor-driven dispatch over branch ladders; file-local args-structs for
param bloat; early-return over nesting. No `goto`. Public/extern/vtable/FUSE signatures are
frozen — their param-count residuals are ACCEPTABLE and reported, not forced.

**Tech Stack:** C (nginx module + `client/` CLI), lizard 1.23, CodeChecker 6.28 (clangsa +
clang-tidy).

## Global Constraints (copied verbatim — apply to EVERY task)

- **Zero behavior change.** Identical syscalls, wire bytes, error codes, ordering, side
  effects. Pure refactor. The decomposition is byte-frozen against the original.
- **NO `goto`** anywhere in `src/`/`client/`. Early-return + helper decomposition only
  ([coding-standards §4](../09-developer-guide/coding-standards.md)).
- **Functional + modular** — one job per function, explicit data flow (pass `ctx`, no new
  globals), pure helpers with side effects at the edges ([§8](../09-developer-guide/coding-standards.md)).
- **Edit ONLY the task's own `.c`/`.h`.** No cross-file signature changes (would break
  callers and other agents' files in the same wave).
- Every new helper MUST be called (`-Wunused-function -Werror`). Watch `-Wcomment`
  (never let `*/` form inside a doc comment — e.g. `a/*b` → space it). Zero-init locals
  split across an out-param/struct boundary (`-Wmaybe-uninitialized`).
- **`BRIX_RETURN_ERR` / `brix_send_error` / `brix_send_ok` return `NGX_OK`.** When splitting
  a dispatch branch into an `ngx_int_t` helper, never let an error-send's `NGX_OK` be read
  as "continue" — use `NGX_DONE`/`NGX_DECLINED` sentinels to distinguish handled-stop from
  continue. Preserve the exact original control flow.
- **3 tests per behavioral change:** success + error + security-negative. Pure
  decompositions with no behavior change ride the existing suite; only the analyzer-triage
  task adds new tests.
- Use HELPERS — never reimplement path/auth/metrics/framing.
- **No git writes** without explicit OP approval in-conversation. `check_complexity.sh
  --regen` (backlog rebaseline) and any commit are OP-owned END steps.

## Effort model (ranking oracle)

Per file: `Σ_fns [ 2.0·max(0,CCN−15) + 0.10·max(0,NLOC−100) + 1.0·max(0,params−5) ]`
plus CodeChecker debt (HIGH 10 / MED 4 / LOW 1), deduped by (file,line,checker), excluding
noise checkers `misc-header-include-cycle` + `clang-diagnostic-unused-parameter`. Full
ranking: `scratchpad/top100_v4.json`; per-file offenders: `top100_fns.json`.

## Baseline (post phase-72/75/77 + complexity-gate sweep)

Peak file effort is **39.3** (was 138.8 at phase-72 start). Analyzer surface is 10 findings
total (5 HIGH / 4 MED / 1 LOW) — **9 are previously-verified false positives** (writev
ArrayBound ×2, helpers.c ArrayBound, auth_request NullDeref, relay_guard/dead_props
redundant-expr, pool.c/gsi_core Malloc). Effort is now almost entirely lizard complexity
debt. 253 over-threshold functions across the 100 files; ~90 are single-offender files.

### Task 0 — snapshot
- [ ] `lizard --csv src client > baseline.csv`; `check_complexity.sh` (dry) captured; full
  suite green vs which this wave is diffed. Fleet rules: attach mode, seed data files,
  clean stop-all/start-all after any src fix that runs start-all (token/GSI dedicated ports
  desync otherwise).

## Phase 78.A — Analyzer triage (do FIRST; 3 tests or FP-proof each)

### Task A1: `src/protocols/s3/object.c:473` — `core.CallAndMessage` (the one NOT on record)
- [ ] Adversarially verify: is the flagged arg genuinely uninitialized on some path, or is it
  populated by a helper the analyzer can't see across the phase-77 split? If real → zero-init
  / reorder at the definition (behavior-neutral) + 3 tests (GET success, error, auth-neg). If
  FP → add a phase-78-fp comment + `NOLINT` with the proof (which prior call populates it).

### Task A2: analyzer FP ledger (no code change — confirm still-FP)
- [ ] Confirm the 9 known FPs are unchanged after this wave's edits: `writev.c:243,339`
  (hidx bounds-checked by `writev_validate_handles`), `fs/path/helpers.c:63`,
  `sss/auth_request.c:228` (fail-closed guard present), `relay_guard.c:41`,
  `webdav/dead_props.c:348`, `net/proxy/pool.c:200`, `auth/gsi/gsi_core.c:642`. Any that a
  decomposition perturbs must be re-marked in the touched file.

## Decomposition task template (78.B–78.I)

For each task file: (1) read the offending function(s); (2) extract each cohesive
branch/stage into a static helper with a WHAT/WHY/HOW doc block, one responsibility, ≤5
params (introduce a file-local `*_ctx`/`*_desc` struct if needed to stay ≤5); (3) the
original function becomes a thin driver; (4) verify `lizard -C 15 -L 100 -a 5 -w <file>`
shows only frozen-signature param residuals; (5) the wave build is the cross-file oracle.
Frozen-residual class (report, don't force): param-count-only on extern signatures,
`brix_sd_driver_t` vtable slots, FUSE-callback typedefs, nginx-registered handler
signatures, opcode-dispatch-table entries.

---

## Phase 78.C — root:// + tpc — wire hot paths (3 tests each: success+error+security-neg)

### Task C1: `src/protocols/root/zip/zip_member.c`
effort **27.2** · maxCCN 26 · 1/8 fns over-threshold
- [ ] Decompose: `brix_zip_open_member` CCN26+NLOC132+7p @L213-375

### Task C2: `src/protocols/root/fattr/list.c`
effort **23.0** · maxCCN 25 · 2/4 fns over-threshold
- [ ] Decompose: `fattr_list` CCN25+6p @L274-379; `fattr_recurse_dir` CCN16 @L84-201

### Task C3: `src/protocols/root/session/login.c`
effort **20.1** · maxCCN 24 · 1/2 fns over-threshold
- [ ] Decompose: `brix_handle_login` CCN24+NLOC121 @L22-202

### Task C4: `src/protocols/root/write/writev.c`
effort **20.0** · maxCCN 9 · 0/9 fns over-threshold  ·  **analyzer: {'HIGH': 2}**
- [ ] Decompose: _no lizard offenders — analyzer-only entry_

### Task C5: `src/protocols/root/zip/zip_dir.c`
effort **16.0** · maxCCN 23 · 1/5 fns over-threshold
- [ ] Decompose: `brix_zip_find_member` CCN23 @L75-181

### Task C6: `src/protocols/root/write/chkpoint_xeq.c`
effort **15.0** · maxCCN 20 · 5/7 fns over-threshold
- [ ] Decompose: `ckp_xeq` CCN20 @L498-598; `ckp_xeq_vfs_write_full` 7p @L16-55; `ckp_xeq_write` 6p @L64-119; `ckp_xeq_pgwrite` 6p @L128-250; `ckp_xeq_writev` 6p @L307-397

### Task C7: `src/tpc/outbound/bootstrap.c`
effort **14.0** · maxCCN 22 · 1/1 fns over-threshold
- [ ] Decompose: `tpc_bootstrap` CCN22 @L27-169

### Task C8: `src/tpc/common/credential.c`
effort **14.0** · maxCCN 22 · 1/6 fns over-threshold
- [ ] Decompose: `brix_tpc_credential_parse` CCN22 @L117-186

### Task C9: `src/tpc/gsi/gsi_outbound_exchange.c`
effort **13.2** · maxCCN 19 · 1/2 fns over-threshold
- [ ] Decompose: `tpc_outbound_gsi_exchange` CCN19+NLOC102+10p @L71-203

### Task C10: `src/protocols/root/session/handles.c`
effort **12.0** · maxCCN 21 · 1/8 fns over-threshold
- [ ] Decompose: `brix_session_handle_publish` CCN21 @L84-168

### Task C11: `src/protocols/root/protocol/stat_flags.h`
effort **12.0** · maxCCN 21 · 1/3 fns over-threshold
- [ ] Decompose: `brix_stat_flags_from_stat` CCN21 @L73-105


---

## Phase 78.D — s3 + webdav — HTTP methods (3 tests each)

### Task D1: `src/protocols/webdav/xrdhttp.c`
effort **24.0** · maxCCN 21 · 3/13 fns over-threshold
- [ ] Decompose: `xrdhttp_http_to_xrd_status` CCN21 @L266-297; `xrdhttp_parse_request` CCN18 @L146-262; `xrdhttp_send_redirect` CCN18 @L357-443

### Task D2: `src/protocols/s3/delete_objects.c`
effort **23.7** · maxCCN 22 · 2/10 fns over-threshold
- [ ] Decompose: `s3_delete_objects_body_handler_inner` CCN22+NLOC187 @L278-495; `s3_delete_xml_append_error` 6p @L139-154

### Task D3: `src/protocols/webdav/propfind_walk.c`
effort **22.0** · maxCCN 21 · 2/4 fns over-threshold
- [ ] Decompose: `propfind_do` CCN21 @L188-302; `propfind_walk` CCN18+9p @L57-173

### Task D4: `src/protocols/webdav/lock.c`
effort **20.1** · maxCCN 22 · 2/15 fns over-threshold
- [ ] Decompose: `webdav_handle_lock_inner` CCN22+NLOC101 @L475-625; `webdav_check_locks` CCN18 @L269-335

### Task D5: `src/protocols/s3/tagging.c`
effort **20.0** · maxCCN 24 · 2/13 fns over-threshold
- [ ] Decompose: `s3_tag_blob_from_xml` CCN24+6p @L276-348; `s3_tag_store` 6p @L105-135

### Task D6: `src/protocols/webdav/move.c`
effort **19.0** · maxCCN 23 · 3/6 fns over-threshold
- [ ] Decompose: `webdav_handle_move` CCN23 @L287-416; `webdav_move_execute_cred` 7p @L100-149; `webdav_move_collection_post_task` 6p @L200-268

### Task D7: `src/protocols/s3/list_cache.c`
effort **19.0** · maxCCN 22 · 2/5 fns over-threshold
- [ ] Decompose: `s3_list_cache_put` CCN22+7p @L123-203; `s3_list_cache_get` 8p @L73-120

### Task D8: `src/protocols/s3/multipart_complete_list_uploads.c`
effort **18.3** · maxCCN 19 · 2/3 fns over-threshold
- [ ] Decompose: `s3_handle_list_multipart_uploads` CCN19+NLOC113 @L188-329; `mpu_collect` CCN18+8p @L95-185

### Task D9: `src/protocols/webdav/tpc.c`
effort **17.0** · maxCCN 12 · 7/30 fns over-threshold
- [ ] Decompose: `webdav_tpc_prepare_pull_target` 9p @L709-755; `webdav_tpc_pull_marker_exec` 9p @L771-807; `webdav_tpc_pull_thread_exec` 9p @L810-830; `webdav_tpc_pull_sync_exec` 7p @L833-868; `webdav_tpc_push_sync_exec` 6p @L405-443; +2 more param-residual fns

### Task D10: `src/protocols/webdav/postconfig.c`
effort **16.8** · maxCCN 23 · 1/1 fns over-threshold
- [ ] Decompose: `ngx_http_brix_webdav_postconfiguration` CCN23+NLOC108 @L20-176

### Task D11: `src/protocols/webdav/search.c`
effort **14.0** · maxCCN 20 · 2/9 fns over-threshold
- [ ] Decompose: `webdav_search_walk` CCN20+7p @L205-327; `webdav_search_do` CCN16 @L336-413

### Task D12: `src/protocols/webdav/dead_props.c`
effort **13.0** · maxCCN 18 · 3/12 fns over-threshold  ·  **analyzer: {'MEDIUM': 1}**
- [ ] Decompose: `webdav_dead_prop_xml_name_ok` CCN18 @L84-109; `webdav_dead_prop_append_value` 7p @L369-415; `webdav_dead_prop_set` 6p @L299-321

### Task D13: `src/protocols/s3/multipart_complete_upload_part_copy.c`
effort **12.8** · maxCCN 19 · 1/2 fns over-threshold
- [ ] Decompose: `s3_handle_upload_part_copy` CCN19+NLOC148 @L54-238

### Task D14: `src/protocols/webdav/tpc_thread.c`
effort **12.3** · maxCCN 16 · 2/4 fns over-threshold
- [ ] Decompose: `tpc_thread_func` CCN16+NLOC153 @L93-262; `webdav_tpc_post_thread_task` 10p @L326-389


---

## Phase 78.E — auth — identity/authz/crypto (security-load-bearing; 3 tests each)

### Task E1: `src/auth/crypto/ocsp.c`
effort **26.1** · maxCCN 22 · 4/7 fns over-threshold
- [ ] Decompose: `do_ocsp_request` CCN22+NLOC121 @L178-322; `brix_ocsp_check_cert` CCN17 @L419-499; `brix_ocsp_staple_fetch` CCN17 @L511-633; `parse_ocsp_url` 7p @L120-168

### Task E2: `src/auth/token/macaroon_issue.c`
effort **24.2** · maxCCN 22 · 2/2 fns over-threshold
- [ ] Decompose: `brix_macaroon_issue` CCN22+NLOC132+10p @L70-224; `write_packet` 7p @L40-67

### Task E3: `src/auth/unix/auth.c`
effort **24.0** · maxCCN 27 · 1/5 fns over-threshold
- [ ] Decompose: `brix_handle_unix_auth` CCN27 @L157-255

### Task E4: `src/auth/voms/extract.c`
effort **20.0** · maxCCN 23 · 1/1 fns over-threshold
- [ ] Decompose: `brix_extract_voms_info` CCN23+9p @L32-112

### Task E5: `src/auth/gsi/gsi_core.c`
effort **20.0** · maxCCN 12 · 4/23 fns over-threshold  ·  **analyzer: {'MEDIUM': 1}**
- [ ] Decompose: `brix_gsi_build_cert_response_ex` 14p @L702-759; `brix_gsi_build_cert_response` 9p @L764-775; `brix_gsi_build_certreq` 7p @L113-151; `brix_gsi_parse_parms` 6p @L78-100

### Task E6: `src/auth/crypto/pki_build.c`
effort **19.0** · maxCCN 20 · 3/5 fns over-threshold
- [ ] Decompose: `pki_load_crls` CCN20 @L66-135; `brix_build_ca_store_cached` CCN16+9p @L242-292; `brix_build_ca_store` 8p @L150-220

### Task E7: `src/auth/sss/sss_keytab_kernel.c`
effort **18.0** · maxCCN 24 · 1/5 fns over-threshold
- [ ] Decompose: `sss_keytab_parse_line` CCN24 @L68-138

### Task E8: `src/auth/impersonate/broker_creds.c`
effort **16.0** · maxCCN 23 · 1/6 fns over-threshold
- [ ] Decompose: `imp_drop_to_service_user` CCN23 @L59-133

### Task E9: `src/auth/impersonate/broker.c`
effort **16.0** · maxCCN 20 · 2/5 fns over-threshold
- [ ] Decompose: `imp_serve_one` CCN20 @L106-231; `brix_imp_broker_run` CCN18 @L236-324

### Task E10: `src/auth/token/macaroon.c`
effort **15.0** · maxCCN 14 · 8/34 fns over-threshold
- [ ] Decompose: `macaroon_parse_core` 9p @L662-727; `macaroon_parse_state_init` 8p @L644-656; `macaroon_validate_one_discharge` 7p @L849-893; `macaroon_validate_discharges` 7p @L896-921; `macaroon_decrypt_vid_inner` 6p @L173-206; +3 more param-residual fns

### Task E11: `src/auth/krb5/auth.c`
effort **14.2** · maxCCN 21 · 1/6 fns over-threshold
- [ ] Decompose: `brix_handle_krb5_auth` CCN21+NLOC122 @L165-315

### Task E12: `src/auth/crypto/store_policy.c`
effort **14.0** · maxCCN 20 · 3/25 fns over-threshold
- [ ] Decompose: `brix_cert_policy_violation` CCN20 @L404-457; `brix_store_configure` 8p @L595-639; `sp_ex_free` 6p @L648-660

### Task E13: `src/auth/impersonate/lifecycle.c`
effort **13.5** · maxCCN 21 · 1/17 fns over-threshold
- [ ] Decompose: `brix_imp_init_module` CCN21+NLOC115 @L324-467

### Task E14: `src/auth/token/file.c`
effort **13.0** · maxCCN 21 · 1/1 fns over-threshold
- [ ] Decompose: `brix_token_read_file` CCN21+6p @L34-105

### Task E15: `src/auth/gsi/proxy_req_unittest.c`
effort **12.4** · maxCCN 19 · 1/6 fns over-threshold
- [ ] Decompose: `main` CCN19+NLOC144 @L128-296


---

## Phase 78.F — fs — storage plane, VFS seam (preserve confinement/impersonation; 3 tests each)

### Task F1: `src/fs/scan/scan_engine.c`
effort **27.0** · maxCCN 10 · 10/17 fns over-threshold
- [ ] Decompose: `brix_scan_run` 11p @L304-352; `brix_scan_run_inventory` 10p @L391-423; `brix_scan_run_verify_catalog` 10p @L531-563; `scan_action_dump` 7p @L107-118; `scan_action_verify` 7p @L122-163; +5 more param-residual fns

### Task F2: `src/fs/xfer/stage_engine.c`
effort **25.0** · maxCCN 23 · 6/24 fns over-threshold
- [ ] Decompose: `stage_engine_move` CCN23+7p @L351-470; `stage_complete` 7p @L691-734; `brix_stage_reconcile` CCN16 @L994-1052; `stage_engine_run` 6p @L497-554; `brix_stage_submit` 6p @L559-610; +1 more param-residual fns

### Task F3: `src/fs/vfs/vfs_copy.c`
effort **24.0** · maxCCN 27 · 1/1 fns over-threshold
- [ ] Decompose: `brix_vfs_copy` CCN27 @L29-141

### Task F4: `src/fs/cache/open.c`
effort **24.0** · maxCCN 23 · 2/4 fns over-threshold
- [ ] Decompose: `brix_cache_open` CCN23 @L139-241; `brix_cache_path_for_resolved` CCN19 @L50-99

### Task F5: `src/fs/cache/cache_reap.c`
effort **22.0** · maxCCN 25 · 1/5 fns over-threshold
- [ ] Decompose: `reap_dir` CCN25+7p @L71-170

### Task F6: `src/fs/path/mkdir.c`
effort **21.0** · maxCCN 19 · 3/4 fns over-threshold
- [ ] Decompose: `brix_mkdir_recursive_beneath` CCN19+6p @L162-224; `brix_mkdir_recursive_confined_canon` CCN19 @L95-159; `brix_mkdir_recursive_policy` CCN17 @L34-84

### Task F7: `src/fs/cache/evict_policy.c`
effort **21.0** · maxCCN 22 · 2/3 fns over-threshold
- [ ] Decompose: `brix_cache_purge_to_target` CCN22+8p @L171-268; `brix_cache_evict_one` 9p @L46-132

### Task F8: `src/fs/vfs/vfs_staged.c`
effort **20.2** · maxCCN 25 · 1/8 fns over-threshold
- [ ] Decompose: `brix_vfs_staged_open` CCN25+NLOC102 @L65-191

### Task F9: `src/fs/vfs/vfs_backend_config.c`
effort **17.0** · maxCCN 15 · 9/31 fns over-threshold
- [ ] Decompose: `vfs_parse_cephfsro_parts` 10p @L435-456; `vfs_parse_http_origin` 9p @L348-390; `vfs_parse_s3_url` 7p @L726-767; `brix_vfs_backend_config_cephfs_ro` 6p @L178-203; `vfs_http_origin_strip_scheme` 6p @L289-312; +4 more param-residual fns

### Task F10: `src/fs/cache/origin/s3_transport.c`
effort **17.0** · maxCCN 13 · 2/25 fns over-threshold
- [ ] Decompose: `s3o_request_cred` 14p @L621-642; `s3o_request` 13p @L596-616

### Task F11: `src/fs/path/unified.c`
effort **16.0** · maxCCN 18 · 5/13 fns over-threshold
- [ ] Decompose: `brix_build_candidate` CCN18+6p @L198-262; `brix_finish_resolved` 8p @L280-320; `brix_resolve_missing_tail` 7p @L323-391; `brix_resolve_missing_parents` 7p @L394-467; `brix_path_resolve_cstr` 7p @L486-536

### Task F12: `src/fs/cache/fetch.c`
effort **16.0** · maxCCN 23 · 1/5 fns over-threshold
- [ ] Decompose: `brix_cache_fill_from_source` CCN23 @L170-282

### Task F13: `src/fs/backend/cred_mint.c`
effort **15.0** · maxCCN 18 · 4/6 fns over-threshold
- [ ] Decompose: `brix_cred_mint` CCN18+7p @L353-415; `mint_write_pem` CCN16+6p @L269-347; `mint_sanitize_cn` CCN16 @L147-163; `mint_build_cert` 7p @L178-249

### Task F14: `src/fs/cache/cstore.c`
effort **14.0** · maxCCN 18 · 4/19 fns over-threshold
- [ ] Decompose: `cstore_scan_dir` CCN18 @L411-465; `brix_cstore_serve_pread` 10p @L189-226; `brix_cstore_init` 7p @L45-88; `brix_cstore_partial_open` 6p @L229-261


---

## Phase 78.G — net — proxy/mirror/upstream/ratelimit

### Task G1: `src/net/manager/registry_select.c`
effort **25.0** · maxCCN 27 · 1/8 fns over-threshold
- [ ] Decompose: `srv_select_core` CCN27+6p @L80-180

### Task G2: `src/net/proxy/events_write.c`
effort **20.0** · maxCCN 25 · 1/1 fns over-threshold
- [ ] Decompose: `brix_proxy_write_handler` CCN25 @L19-146

### Task G3: `src/net/proxy/events_splice.c`
effort **20.0** · maxCCN 20 · 2/6 fns over-threshold
- [ ] Decompose: `brix_proxy_splice_pump` CCN20 @L93-204; `brix_proxy_try_splice` CCN20 @L332-460

### Task G4: `src/net/mirror/stream_wmirror.c`
effort **20.0** · maxCCN 20 · 2/19 fns over-threshold
- [ ] Decompose: `wmir_dispatch` CCN20 @L242-310; `brix_stream_wmirror_observe` CCN20 @L630-709

### Task G5: `src/net/upstream/start.c`
effort **16.9** · maxCCN 21 · 1/1 fns over-threshold
- [ ] Decompose: `brix_upstream_start` CCN21+NLOC149 @L34-233

### Task G6: `src/net/mirror/stream_mirror.c`
effort **16.0** · maxCCN 20 · 2/17 fns over-threshold
- [ ] Decompose: `brix_stream_mirror_maybe` CCN20 @L483-580; `brix_mirror_parse_opcode_args` CCN18 @L666-702

### Task G7: `src/net/proxy/forward_rewrite_helpers.c`
effort **14.0** · maxCCN 21 · 2/4 fns over-threshold
- [ ] Decompose: `proxy_rewrite_prepare_payload` CCN21 @L80-173; `proxy_rewrite_path` 7p @L22-73


---

## Phase 78.H — observability — dashboard/metrics

### Task H1: `src/observability/dashboard/api_snapshot.c`
effort **26.0** · maxCCN 22 · 2/17 fns over-threshold
- [ ] Decompose: `dashboard_fill_cache` CCN22 @L362-458; `dashboard_fill_storage` CCN21 @L470-553

### Task H2: `src/observability/dashboard/http_tracking.c`
effort **24.0** · maxCCN 25 · 3/11 fns over-threshold
- [ ] Decompose: `dashboard_redact_url` CCN25 @L210-293; `brix_dashboard_http_start_identity` 8p @L95-149; `brix_dashboard_http_start` 6p @L152-159

### Task H3: `src/observability/dashboard/api_admin_cluster.c`
effort **21.0** · maxCCN 25 · 1/5 fns over-threshold
- [ ] Decompose: `admin_parse_server_uri` CCN25+6p @L14-91

### Task H4: `src/observability/dashboard/api_transfers.c`
effort **17.3** · maxCCN 23 · 1/7 fns over-threshold
- [ ] Decompose: `dashboard_build_transfer_object` CCN23+NLOC103+6p @L21-152

### Task H5: `src/observability/dashboard/noop.c`
effort **12.0** · maxCCN 1 · 5/25 fns over-threshold
- [ ] Decompose: `brix_transfer_slot_alloc_ex` 10p @L79-97; `brix_dashboard_http_start_identity` 8p @L225-238; `brix_transfer_slot_alloc` 7p @L62-76; `brix_transfer_slot_set_tpc_remote` 6p @L140-150; `brix_dashboard_http_start` 6p @L212-222


---

## Phase 78.I — core — compat/http/aio/types primitives

### Task I1: `src/core/types/identity.c`
effort **26.0** · maxCCN 28 · 1/19 fns over-threshold
- [ ] Decompose: `brix_identity_derive_attrs` CCN28 @L273-344

### Task I2: `src/core/compat/fs_walk.c`
effort **25.0** · maxCCN 26 · 2/6 fns over-threshold
- [ ] Decompose: `brix_fs_walk_dir` CCN26+6p @L130-211; `brix_fs_remove_tree_confined` CCN16 @L255-370

### Task I3: `src/core/compat/error_mapping.c`
effort **24.0** · maxCCN 27 · 1/6 fns over-threshold
- [ ] Decompose: `brix_errno_from_kxr` CCN27 @L88-119

### Task I4: `src/core/compat/sss_bf.c`
effort **22.0** · maxCCN 23 · 2/3 fns over-threshold
- [ ] Decompose: `brix_sss_bf_crypt` CCN23+8p @L42-86; `brix_sss_build_credential` 8p @L89-166

### Task I5: `src/core/http/http_conditionals.c`
effort **21.0** · maxCCN 20 · 3/8 fns over-threshold
- [ ] Decompose: `brix_http_eval_preconditions` CCN20+6p @L193-260; `brix_http_etag_list_contains` CCN19 @L47-105; `brix_http_check_etag_preconditions` CCN16 @L108-161

### Task I6: `src/core/compat/integrity_info.c`
effort **16.0** · maxCCN 22 · 1/14 fns over-threshold
- [ ] Decompose: `brix_integrity_get_fd` CCN22+7p @L409-495

### Task I7: `src/core/compat/checksum.c`
effort **14.0** · maxCCN 19 · 5/12 fns over-threshold
- [ ] Decompose: `brix_checksum_parse` CCN19 @L114-169; `brix_checksum_hex_name_fd` 8p @L414-428; `brix_checksum_digest_fd` 6p @L247-262; `brix_checksum_hex_fd` 6p @L293-343; `brix_checksum_hex_obj` 6p @L356-401

### Task I8: `src/core/aio/buffers.c`
effort **14.0** · maxCCN 19 · 3/11 fns over-threshold
- [ ] Decompose: `brix_build_sendfile_chain` CCN19+7p @L598-729; `brix_build_single_sendfile_chain` 7p @L380-440; `brix_build_chunked_chain` CCN16 @L456-572

### Task I9: `src/core/compat/namespace_ops.c`
effort **13.1** · maxCCN 19 · 3/8 fns over-threshold
- [ ] Decompose: `brix_ns_local_copy` CCN19+NLOC121 @L341-490; `brix_ns_delete` CCN16 @L157-236; `brix_xattr_copy_by_prefix` 6p @L102-146

### Task I10: `src/core/compat/xml.c`
effort **13.0** · maxCCN 18 · 3/11 fns over-threshold
- [ ] Decompose: `brix_xml_escape` CCN18+6p @L99-168; `brix_xml_parse_lockinfo` CCN17 @L381-445; `brix_xml_write_text_element` 7p @L236-280

### Task I11: `src/core/compat/range_vector.c`
effort **13.0** · maxCCN 21 · 2/4 fns over-threshold
- [ ] Decompose: `range_vector_parse_one` CCN21 @L22-86; `brix_http_parse_range_vector` 6p @L105-142


---

## Phase 78.B — client lib + apps — CLI+wire frozen (`make -C client && make -C client test`)

### Task B1: `client/lib/protocols/http/http_upload.c`
effort **33.0** · maxCCN 14 · 5/14 fns over-threshold
- [ ] Decompose: `httpx_upload_chunk` 14p @L318-334; `brix_http_upload_resumable` 14p @L388-445; `brix_http_upload` 13p @L449-475; `httpx_upload_exchange` 11p @L182-194; `httpx_upload_body` 6p @L71-96

### Task B2: `client/lib/protocols/root/ops_meta.c`
effort **27.0** · maxCCN 27 · 3/10 fns over-threshold
- [ ] Decompose: `dirlist_once` CCN27+6p @L164-279; `next_line` 6p @L127-141; `brix_dirlist` 6p @L300-306

### Task B3: `client/lib/protocols/http/webfile.c`
effort **27.0** · maxCCN 22 · 4/11 fns over-threshold
- [ ] Decompose: `has_collection_element` CCN22 @L252-283; `next_response_open` CCN19 @L187-217; `brix_web_readdir` 8p @L308-376; `brix_web_stat` 7p @L121-170

### Task B4: `client/lib/fs/rmtree.c`
effort **27.0** · maxCCN 27 · 2/3 fns over-threshold
- [ ] Decompose: `rmtree_depth` CCN27+7p @L50-128; `brix_rmtree` 6p @L139-157

### Task B5: `client/apps/fs/xrdfs_meta.c`
effort **27.0** · maxCCN 23 · 3/24 fns over-threshold
- [ ] Decompose: `do_touch` CCN23 @L479-542; `ls_print_dir` CCN18+6p @L46-94; `do_xattr` CCN17 @L678-730

### Task B6: `client/apps/copy/xrdcp_transfer.c`
effort **27.0** · maxCCN 21 · 5/10 fns over-threshold
- [ ] Decompose: `transfer_one` CCN21+7p @L212-274; `batch_parallel` 12p @L432-466; `batch_copy_one` 9p @L336-351; `copy_one_with_retry` 6p @L51-89; `relay_web_to_web` 6p @L287-330

### Task B7: `client/apps/diag/diag_misc.c`
effort **26.4** · maxCCN 24 · 2/4 fns over-threshold
- [ ] Decompose: `do_probe_robustness` CCN24+NLOC144 @L9-172; `do_tape` CCN17 @L253-316

### Task B8: `client/apps/diag/diag_topology.c`
effort **26.0** · maxCCN 27 · 3/6 fns over-threshold
- [ ] Decompose: `do_topology` CCN27 @L69-175; `resolve_target` 6p @L13-54; `resolve_once` 6p @L212-245

### Task B9: `client/lib/core/aio/aio_mgr.c`
effort **25.0** · maxCCN 20 · 4/18 fns over-threshold
- [ ] Decompose: `brix_mgr_create` CCN20+8p @L120-202; `brix_mgr_call` 9p @L273-280; `mfile_do_open` CCN17 @L316-408; `brix_mfile_open` 9p @L411-440

### Task B10: `client/apps/fs/xrdfs_walk.c`
effort **24.0** · maxCCN 20 · 4/11 fns over-threshold
- [ ] Decompose: `tree_recurse` CCN20+6p @L237-282; `do_du` CCN20 @L131-175; `do_find` CCN16 @L201-231; `walk_dir` 6p @L13-42

### Task B11: `client/apps/diag/xrd_battery.c`
effort **24.0** · maxCCN 13 · 9/26 fns over-threshold
- [ ] Decompose: `s3_put` 10p @L510-532; `s3_get_verify` 10p @L536-562; `web_move_delete` 8p @L425-454; `s3_delete` 8p @L566-587; `write_symlink_ops` 7p @L204-235; +4 more param-residual fns

### Task B12: `client/lib/protocols/http/http_download.c`
effort **23.0** · maxCCN 17 · 4/8 fns over-threshold
- [ ] Decompose: `brix_http_download` CCN17+12p @L264-329; `httpx_download_exchange` 11p @L197-260; `read_resp_headers` 8p @L87-113; `httpx_download_body` 8p @L154-190

### Task B13: `client/apps/prep/xrdprep.c`
effort **22.0** · maxCCN 26 · 1/1 fns over-threshold
- [ ] Decompose: `main` CCN26 @L21-87

### Task B14: `client/lib/net/conn.c`
effort **20.0** · maxCCN 24 · 2/16 fns over-threshold
- [ ] Decompose: `brix_explain_conn` CCN24 @L597-659; `recv_raw` 7p @L101-125

### Task B15: `client/apps/cksum/xrdckverify.c`
effort **20.0** · maxCCN 25 · 1/3 fns over-threshold
- [ ] Decompose: `brix_xrdckverify_main` CCN25 @L48-123

### Task B16: `client/lib/xfer/copy_remote.c`
effort **15.0** · maxCCN 11 · 4/15 fns over-threshold
- [ ] Decompose: `tpc_teardown` 12p @L377-394; `r2r_teardown` 10p @L27-48; `r2r_stream_body` 7p @L61-70; `cksum_verify` 6p @L269-308

### Task B17: `client/lib/protocols/shared/cks_verify.c`
effort **15.0** · maxCCN 21 · 2/8 fns over-threshold
- [ ] Decompose: `brix_cks_verify_file` CCN21 @L262-348; `ckv_add_cache_record` 8p @L228-240

### Task B18: `client/lib/protocols/s3/s3.c`
effort **15.0** · maxCCN 18 · 2/3 fns over-threshold
- [ ] Decompose: `brix_s3_sign_v4_q` CCN18+10p @L36-111; `brix_s3_sign_v4` 9p @L114-121

### Task B19: `client/lib/core/aio/aio.c`
effort **15.0** · maxCCN 11 · 5/23 fns over-threshold
- [ ] Decompose: `brix_aio_call_ex` 9p @L595-639; `brix_aio_call` 9p @L643-650; `brix_aio_submit_ex` 8p @L524-560; `brix_aio_submit` 8p @L564-570; `call_cb` 6p @L576-591

### Task B20: `client/lib/protocols/http/http_req.c`
effort **14.0** · maxCCN 11 · 2/8 fns over-threshold
- [ ] Decompose: `brix_http_req` 13p @L316-349; `httpx_exchange` 11p @L295-312

### Task B21: `client/lib/net/url.c`
effort **14.0** · maxCCN 22 · 1/8 fns over-threshold
- [ ] Decompose: `brix_weburl_parse` CCN22 @L280-355


---

## Phase 78.Z — Python tools — OUT OF C-GATE SCOPE (advisory only, do NOT decompose to C rubric)

### Task Z1: `client/apps/ceph/xrdceph_striper_migrate.py`
effort **39.3** · maxCCN 34 · 1/19 fns over-threshold
- [ ] Decompose: `migrate_one` CCN34+NLOC113 @L294-431

### Task Z2: `client/apps/ceph/xrdceph_cephfs_to_striper.py`
effort **20.0** · maxCCN 25 · 1/16 fns over-threshold
- [ ] Decompose: `process` CCN25 @L368-458

---

## Wave sequencing (bounded ≤15 files, build after each)

1. **Wave 1 — 78.A analyzer** (1 real triage + FP confirm) then **78.C root/tpc** (11).
2. **Wave 2 — 78.D s3/webdav** (14).
3. **Wave 3 — 78.E auth** (15).
4. **Wave 4 — 78.F fs** (14).
5. **Wave 5 — 78.G net + 78.H observability + 78.I core** (7+5+11 = 23; split into 2 sub-waves of ~12).
6. **Wave 6 — 78.B client** (21; split into 2 sub-waves of ~11). `make -C client && make -C client test`.
7. **78.Z Python** (2) — advisory only; do NOT apply the C rubric. Skip unless OP asks for a Python-idiomatic pass.

Full module `-Werror` build + `nginx -t` after each src wave; client build+test after 78.B.

## Phase-78 exit criteria

- [ ] `lizard -C 15 -L 100 -a 5 -w` over all 100 files: clean or documented frozen-signature
  param residuals only.
- [ ] `tools/ci/check_complexity.sh` (dry) GREEN — no new/growing CCN>15 functions.
- [ ] Module `-Werror` build + `nginx -t` green; `make -C client` + `make -C client test` green.
- [ ] Full suite: no regressions vs Task-0 baseline (fleet rules; clean stop/start after src fixes).
- [ ] 78.A: `s3/object.c:473` fixed+3-tests OR FP-proven; 9-FP ledger reconfirmed.
- [ ] CodeChecker exit gate: no NEW findings introduced by the decompositions.
- [ ] `tools/ci/check_vfs_seam.sh` green (78.F must not add raw FS in handlers).
- [ ] `check_complexity.sh --regen` run ONCE at END (OP-approved ratchet) + commit (OP-approved).

## Deliberately out of scope

- **Frozen param-count residuals** on extern/vtable/FUSE/handler/opcode-table signatures —
  permanent class, reported not forced (`http_upload.c` resumable family, `sd_*` driver
  slots, `brixcvmfs.c` FUSE ops, nginx access-handler signatures).
- **The 2 Python files** (`xrdceph_striper_migrate.py`, `xrdceph_cephfs_to_striper.py`) —
  lizard scores them but the CCN≤15 gate + coding-standards are C-only.
- **The 9 documented analyzer FPs** — proven false in phases 74/77; no action beyond
  re-confirming the marks survive this wave.
- Files ranked 101+ (next wave).

## Execution record

_(appended after implementation)_
