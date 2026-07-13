# Complexity Refactor Plan — Top 20 Hotspots

**Generated:** 2026-07-08 · **Source ranking:** `tools/readability.py` (McCabe CCN via lizard)
**Enforcement:** `tools/ci/check_complexity.sh` (CCN-15 ratchet) — every file below is a frozen
backlog entry that may only ratchet *down*. Land a refactor, run `--regen`, ceiling drops.

## Method

All 20 are **god-functions inside oversized files**, not tangled architecture. The treatment is
uniform: **extract single-responsibility helpers** (early-return, no `goto`, explicit data flow)
and, where a file is >800 LOC, **split by concern into sibling `.c` files**. No rewrites — the
working code carries hard-won wire/auth/VFS invariants; we relocate it behind seams, we don't
re-derive it. Seams below were mapped from the actual source (line ranges are current).

## Per-file recipe (apply to every entry)

1. **Characterize first.** Before touching a hot function, write/confirm tests that pin its
   current behavior — success + error + security-negative (the mandated 3-per-change). For server
   hot paths this means the relevant `tests/` suite is green *before* you start.
2. **Extract leaf-first.** Pull the innermost single-responsibility blocks into named helpers
   (signatures given below). Build after each extraction — the compiler is the refactor oracle.
3. **Split file if >800 LOC** once helpers exist: move cohesive helper groups to the new `.c`,
   add them to `./config` `ngx_module_srcs`, re-run `./configure` (new source file → configure
   required), rebuild.
4. **Verify.** `make -j$(nproc)` + `nginx -t` + the file's test suite. For 🔴 hot paths run the
   full suite (`run_suite.sh --pr`). Then `tools/ci/check_complexity.sh --regen` to drop the ceiling.
5. **One file per PR/commit.** These are independent; never batch two hot files into one change.

## Execution waves (ordered by pain-to-effort payoff)

| Wave | Theme | Files | Rationale |
|------|-------|-------|-----------|
| **0 — warm-up** | self-contained monsters | #11, #17, #1 | High CCN, low coupling → biggest drop per day, proves the recipe |
| **1 — client tools** | no wire risk, parallelizable | #6, #8, #13, #14, #15 | Independent of server; a second engineer can own this wave entirely |
| **2 — config** | mechanical, table-driven | #4, #5, #9 | Merge/parse ladders → grouping + dispatch tables; moderate risk |
| **3 — server hot paths** | wire/framing | #2, #3, #7, #12 | Highest risk; do with full suite running; serialize these |
| **4 — auth/security** | signature-load-bearing | #10, #20 | Extract must not reorder a single crypto/verify step; pair-review |
| **5 — HTTP handlers** | dispatch ladders | #16, #18, #19 | Table-driven dispatch; S3/WebDAV auth separation preserved |

Waves 1–5 are mutually independent and can run concurrently across people. Within wave 3/4,
serialize (shared subsystems, shared test fleet). The CI ratchet guarantees no wave regresses another.

---

# The 20 files

Legend: 🔴 server wire/auth/proxy hot path (full-suite + 3-tests discipline) · 🟡 server config/HTTP
(suite-scoped) · ⚪ client tool (low wire risk). Effort in engineer-days (~6 focused hrs).

## #1 — `client/apps/copy/xrdcp.c` ⚪ — `main` CCN 187 · 875 LOC · **2.5–3d**
The single worst function in the tree (527 lines). Wave 0/1.
- **Seams (extract from `main`):**
  - `parse_and_validate_args()` — CLI + flag-interaction validation (388–539)
  - `build_credential_store()` — alias-fold, diagnose, auto-refresh, store build (635–670)
  - `dispatch_transfer()` — web-recursive vs batch vs single routing + journal lifecycle (673–865)
  - `do_single_transfer_with_progress()` (745–779), `do_batch_transfer()` (813–858)
- **New files:** `xrdcp_cred.c` (moves `merge_alias_auth` + cred build), `xrdcp_mode.c` (dispatch).
- **Order:** args → cred → dispatch (dispatch depends on the first two).
- **Invariants:** cred store built *after* all parsing, *before* any transfer; `--sync`⇒`--force`;
  journal opened batch-only (never dry-run); globs expand *after* alias fold; web dispatch exits
  before root:// batch. **Flag-interaction matrix is the hard part** (known from prior work).
- **Tests:** client `make test` busybox symlink battery + flag-combo matrix; no fleet needed.

## #2 — `src/protocols/root/read/open_request.c` 🔴 — `brix_handle_open` CCN 114 · 885 LOC · **2–2.5d**
Wave 3. XRootD open orchestrator; 10 braided concerns.
- **Seams:** `_parse_request` (279–292), `_validate_paths` (524–574, reuses `reject_dotdot`/
  `count_path_depth`/`is_internal_name`), `_read_resolve` (664–788), `_write_resolve` (789–823),
  `_pmark_flow` (832–857), `_cache_offload_probe` (865–879).
- **New files:** `open_tpc.c` (TPC-context detection 331–494), `open_manager.c` (manager/CMS/
  static-map redirect 576–657).
- **Order:** TPC extraction first (it intercepts before normal resolve), then manager, then the
  read/write resolve split.
- **Invariants:** auth gate **before** existence probe (sole checkpoint); TPC dest handling before
  normal resolve; `clean_path` vs `full_path` separation; collapse-redir keyed on `clean_path`;
  FRM residency gate runs *after* auth.
- **Tests:** root open/stat suites + TPC + multi-user auth conformance; full `--pr` before regen.

## #3 — `src/protocols/root/read/open_resolved_file.c` 🔴 — `brix_open_resolved_file` CCN 85 · 1152 LOC · **2.5–3d**
Wave 3. Largest file; 9 hotspots; guards symlink-escape + staged-write invariants.
- **Seams:** `_pre_checks` (write-target + backpressure + exclusive-create + stage-temp, 691–730),
  `_resume_decide` (748–780), `_execute_posix` (flags→open dispatch, 794–903),
  `_post_fd_setup` (init handle, CSI, throttle, codec, WRTS, monitor, group, retstat, WT — 961–1064),
  `_build_response` (ServerOpenBody, 1079–1151).
- **New files:** none — refactor in place (the concerns are cohesive to this file).
- **Order:** pre-checks → execute-posix → post-fd-setup → build-response (data-flow order).
- **Invariants:** fd-table 0–255 slot straight into `body.fhandle[0]`; VFS seam (raw `open()` only
  for cache_root/stage_dir, export paths via `brix_vfs_open_fd_at`); driver-backed opens bypass VFS;
  POSC temp fresh `O_CREAT` no `O_EXCL`; `O_NONBLOCK` cleared post-fstat; handle publish only when
  `!is_bound`.
- **Tests:** cache partial-fill + staged-write + VFS-seam symlink-escape regression; full `--pr`.

## #4 — `src/protocols/webdav/config.c` 🟡 — `merge_loc_conf` CCN 98 · 888 LOC · **1.5–2d**
Wave 2. ~80-directive merge ladder across 11 tiers.
- **Seams (semantic-group helpers):** `webdav_merge_base_conf` (common/CORS/lock/zip/cksum, 318–370),
  `webdav_merge_auth_token_conf` (token + JWKS load + registry, 401–417 + 711–747),
  `webdav_merge_upstream_conf` (proxy URL/backend build, 748–849),
  `webdav_validate_webdav_enabled` (all path checks + CA store + TPC when enabled, 604–708),
  `webdav_startup_summary` (883–885).
- **New files:** none (keep one TU; extract to statics).
- **Invariants:** main→srv→loc order via `ngx_conf_merge_*`; `NGX_CONF_UNSET` only in create; CA
  store + upstream backends built **once** (pool-cleanup tied); lock sweep skipped under `nginx -t`;
  credential lookup must stay symmetric with runtime_server.c (#9).
- **Tests:** WebDAV config-reload matrix + `nginx -t` on representative site configs.

## #5 — `src/fs/vfs/vfs_backend_config.c` 🟡 — `config_str` CCN 99 · 890 LOC · **1.5–2d**
Wave 2. 9-scheme URL parser — the textbook table-driven case.
- **Seams:** one `vfs_parse_<scheme>_origin()` per scheme (cephfsro/ceph/rados/tape/http/s3/xroot,
  436–740) + a `scheme_parsers[]` dispatch table; `config_str` shrinks 339→~30 LOC.
- **New files:** optional `vfs_backend_parse.c` if it approaches 1000 LOC after adding helpers;
  move the credential/staging/tier setters (232–273, 743–890) to `vfs_backend_registry.c`.
- **Invariants:** dedup on `root_canon` in **every** branch (append-on-reload bug guard); HTTP
  failover endpoint list built *after* primary http config; error messages cite the failing token.
- **Tests:** per-scheme backend-config unit + `sd_driver_conformance` guard.

## #6 — `client/apps/ceph/xrdceph_cephfs_to_striper.cpp` ⚪ — `main` CCN 50 · 461 LOC · **1.5d**
Wave 1.
- **Seams:** `parse_cli_args`, `resolve_config`, `init_rados`, `run_worker_pool` (from `main`).
- **New files:** `cephfs_walk.cpp` (walk/index/classify ~250 LOC), `striper_ops.cpp` (process/stamp/
  verify ~100 LOC).
- **Invariants:** **detach-before-unlink** ordering in `process()` (delete-through hazard);
  `g_data_pool_id` set before walk; stamp idempotency atomic.
- **Tests:** ceph Docker harness (`tests/ceph_harness.sh`) round-trip.

## #7 — `src/protocols/root/connection/recv.c` 🔴 — `ngx_stream_brix_recv` CCN 84 · 820 LOC · **2d**
Wave 3. Three-state receive machine.
- **Seams:** `_teardown_gate` (148–214), `_state_machine` core, `_handshake_frame` (20-byte, 340–499),
  `_header_frame` (24-byte ClientRequestHdr, 501–602), `_payload_frame` (432–736),
  `_drain_barrier` (587–602 + 739–754), `_pipelining_decision` (642–805).
- **New files:** none.
- **Invariants:** strict handshake(20)→header(24)→payload(dlen) sequencing; dlen checked via
  `brix_max_payload_for_request` **before** any alloc; drain-barrier defers non-read/write ops when
  `out_count>0 || wr_inflight>0`; write-pipelining keeps kXR_write in REQ_HEADER during AIO; deadline
  arm/disarm parity.
- **Tests:** framing/writev/chkpoint suites + pipelining backpressure; full `--pr`.

## #8 — `client/apps/fs/xrdfs_data.c` ⚪ — `do_download` CCN 42 · 1275 LOC · **2–2.5d**
Wave 1. Largest file overall; 10 hotspots; `do_upload`/`do_download` are near-duplicates.
- **Seams:** `parse_io_args()` (shared), `open_local_dest()`/`open_local_source()`,
  `io_loop_read_remote_write_local()`/`..._read_local_write_remote()`, `finalize_download()`/
  `finalize_upload()`; then collapse both into a parametric `do_io_transfer(direction,…)`. Also split
  `tail_follow` into `tail_poll_and_read()` + `tail_stat_with_resilience()`.
- **New files:** `xrdfs_io.c` (I/O primitives), optional `xrdfs_tail.c`.
- **Invariants:** io-uring mode parsed before VFS open; stdin/stdout raw-fd vs VFS never mix;
  `rate_pace()` after successful write; download derives default basename, upload has no default;
  commit only on rc==0.
- **Tests:** client `make test` + rfile close-once semantics.

## #9 — `src/core/config/runtime_server.c` 🟡 — `prepare_server` CCN 85 · 677 LOC · **1.5d**
Wave 2.
- **Seams:** `brix_server_setup_export` (250–430), `brix_server_validate_cache` (433–540),
  `brix_server_set_storage_credential` + `_set_wt_credential` (295–341 / 346–392, de-dup),
  `brix_server_setup_logging` (570–612), `brix_server_setup_tls` (614–673). Main → guard+dispatch (~40 LOC).
- **Invariants:** credential resolve at postconfig (after merge); read-cache vs write-back watermarks
  validated **separately** (0<low<high<1.0 each); `wt_stage_backend` needs *both* `wt_stage_root`
  AND `state_root` (3-way gate); legacy `cache_origin` rejected loudly; TLS ctx on `cf->pool`.
- **Tests:** server config-reload + cache-config validation matrix.

## #10 — `src/auth/token/macaroon.c` 🔴🔒 — `macaroon_parse_core` CCN 64 · 825 LOC · **1.5–2d**
Wave 4. **Security-load-bearing — extract must preserve every HMAC/verify step exactly.**
- **Seams:** per-packet handlers `_packet_identifier/_cid/_vid/_signature` → `macaroon_packet_handlers.c`;
  caveat parsers `_caveat_activity/_before/_path` → own files; `_expiry_check` (fail-closed root-vs-discharge).
- **Invariants (do not reorder):** HMAC chain `sig = HMAC(sig_prev, packet)` byte-exact; identifier
  first; **`sig_before_cid` captured before `HMAC(sig,cid)`** (it's the AES key for vid); **constant-time
  `CRYPTO_memcmp`** for signature (memcmp = timing oracle); expiry fail-closed (root must carry
  `before:`); scope finalize *after* path-caveat application.
- **Tests:** WLCG token conformance suite (510 cases) + macaroon discharge-bundle cases; full `--pr`.
  Pair-review the diff.

## #11 — `src/net/proxy/forward_request.c` 🔴 — `brix_proxy_forward_request` CCN 93 · 437 LOC · **1.5d**
**Wave 0 warm-up** — one 400-line function, self-contained, biggest CCN-drop per day.
- **Seams:** `_fh_translate_opcode_single` (112–178) + `_fh_translate_readv_or_writev` (205–263)
  → `forward_fh_translate.c`; `_path_rewrite_and_audit_open`/`_default` → `forward_path_audit.c`;
  `_dispatch_queued_request` (396–432) → `forward_dispatch.c`.
- **Invariants:** fh slot pre-alloc before any error-free path (255 sentinel matches open-response
  check); path rewrite before audit capture; bound-secondary lazy-open must **not** free `req`;
  kXR_ckpXeq translates all 3 fhandle positions; retry buffer only <128KB, free-before-malloc.
- **Tests:** `run_tap_proxy.sh` + proxy parity (token/SSS/anon forwarding).

## #12 — `src/protocols/root/query/prepare.c` 🔴 — `brix_handle_prepare` CCN 53 · 802 LOC · **1.5d**
Wave 3.
- **Seams (outer):** `_pre_checks` (mode/write + cancel/evict, 344–379), `_collect_paths` (388–495),
  `_stage_response` (513–607). **(inner `check_path` CCN 22):** `_path_extract` (151–174),
  `_path_auth` (three-tier authdb+vo_acl+token_scope, 196–245), `_path_stat_check` (184–260).
- **Invariants:** reject `..` before resolve; same three-tier auth gate for existent *and* noerrs-missing
  paths; noerrs increments missing-count but succeeds; S_ISDIR rejected; NGX_DONE⇒continue vs other⇒abort.
- **Tests:** prepare/stage suite + multi-user auth on missing paths.

## #13 — `client/apps/ceph/xrdceph_striper_migrate.cpp` ⚪ — `main` CCN 75 · 953 LOC · **2d**
Wave 1.
- **Seams:** `parse_cli_args`, `resolve_config`, `init_cluster_and_fs`, `run_worker_pool` (from `main`).
- **New files:** `estimate.cpp` (probe/estimate/scale ~170 LOC), `migrate_ops.cpp` (migrate/rollback/
  finalize ~220 LOC).
- **Invariants:** `--delete-source` forbidden with `MODE_REDIRECT` (delete-through); source index built
  once, read-only; dry-run sample snapshots/restores global counters; target-size idempotency check.
- **Tests:** ceph Docker harness migrate + dry-run estimate parity.

## #14 — `client/apps/diag/xrd_battery.c` ⚪ — `battery_root` CCN 64 · 540 LOC · **1d**
Wave 1.
- **Seams:** `probe_read_suite` (102–120), `probe_path_confinement` (123–128), `probe_write_suite`
  decomposed into `write_verify`/`write_readv`/`write_checksum`/`write_xattr_ops`/`write_symlink_ops`/
  `write_rename_truncate_rm`/`cleanup_temp_dir`.
- **Invariants:** read probes before write-gate; ext_* probes gate later ops; symlink-leak flag
  (`sym_left`) drives rmdir skip — don't lose it; temp file/file2 both under dir.
- **Tests:** run battery against local fleet; assert probe ordering unchanged.

## #15 — `client/apps/diag/diag_check.c` ⚪ — `do_check` CCN 86 · 801 LOC · **1.5d**
Wave 1. 10 probes + JSON/prose dual output in one function.
- **Seams:** one `probe_*` per check (`_auth_as_advertised`, `_tls`, `_path_confinement`,
  `_dirlist_and_dstat`, `_integrity_ops`, `_posc_atomicity`, `_handle_limits`) + `emit_json_report`
  + `emit_prose_cred_validity`.
- **Invariants:** auth/TLS/confinement always run; file-dependent probes gate on `have_file`; POSC
  2-conn dance must restore main-conn state; handle-limit loop closes all opened fds even on later
  failure; JSON accumulated then emitted once.
- **Tests:** diag JSON schema snapshot + prose output on live fleet.

## #16 — `src/net/proxy/forward_relay_response.c` 🔴 — `relay_to_client` CCN 62 · 588 LOC · **1d**
Wave 5 (proxy). 
- **Seams:** `_wait_retry` (318–355), `_fhandle_translate`/`_fhandle_error` (388–425),
  `_metric_track` (427–454), `_streaming_state` (516–571), `_response_build` (466–495).
- **Invariants:** lazy-open pending-fh queue is LIFO — don't reorder; wait-retry counter+timer move
  together (misalignment = DoS); redirect `<3` hops, steal+NULL `saved_req` (no double-free); kXR_open
  writes translated fh to `body[0]` + zero bytes 1–3; kXR_status header dlen=24 fixed; kXR_PartialResult
  ⇒ stay FORWARDING; cancel wait-timer before final response (UAF risk).
- **Tests:** tap-proxy streaming + redirect-follow + wait-retry absorption.

## #17 — `src/protocols/webdav/propfind_props.c` 🟡 — `propfind_entry` CCN 68 · 456 LOC · **1d**
**Wave 0/5** — compact, self-contained, clean seams.
- **Seams:** `propfind_emit_standard_props()` (11-prop mask ladder, 226–379),
  `propfind_dead_props_resolve_and_emit()` (385–405), `propfind_emit_404_propstat()` (413–448).
  Keep the mask-ladder (bitmask, per-prop FS logic — not a table fit).
- **Invariants:** PROPNAME fast-path skips FS ops; quota props on directories only (RFC 4331);
  `xrd:locality` VFS call only when explicitly named; `unknown_found[]` bitmap drives atomic 404.
- **Tests:** PROPFIND depth/allprop/propname + dead-property + gfal2/davix client compat.

## #18 — `src/protocols/s3/handler.c` 🔴 — `s3_dispatch_after_auth` CCN 67 · 862 LOC · **1.5d**
Wave 5. 11+ route dispatcher — the table-driven case.
- **Seams:** `s3_handle_bucket_level_get()` (612–631), `s3_handle_object_get/put/delete/post()`
  (653–857) + an `s3_object_handlers[]` method→handler table. Keep token-scope check (503–532) inline
  as its own concern.
- **Invariants:** SigV4 verified in `ngx_http_s3_handler` **before** dispatch — never in handler path;
  **SigV4 ≠ WLCG token** (separate logic); CopyObject before `s3_get_mpu_dir()` overwrites `fs_path`
  (order-bug risk); conditional PutObject evaluated before body read; MPU initiate uses exclusive
  rename (EEXIST→412); per-object ACL write = 501.
- **Tests:** S3 conformance (list/multipart/copy/conditional) + SigV4 + S3-bearer scope; full `--pr`.

## #19 — `src/protocols/webdav/tpc.c` 🟡 — `tpc_handle_copy` CCN 46 · 867 LOC · **1d**
Wave 5.
- **Seams:** `webdav_tpc_pull_exec()` (3-tier marker→thread→sync, 702–788),
  `webdav_tpc_commit_pulled_file()` (link vs rename, 789–835),
  `webdav_tpc_finish_pull_success()` (metrics/ledger/dashboard, 837–866),
  `webdav_tpc_push_build_auth_header()` (from push, 286–345).
- **Invariants:** pull uses `link()` atomic no-overwrite / `rename()` overwrite; **OAuth2 token-exchange
  ≠ S3 SigV4**; subject token from Authorization header; 3-tier fallback via NGX_DECLINED (keep ladder,
  not table); staged temp created before curl, confined to root_canon.
- **Tests:** TPC pull/push (curl COPY) + delegation-credential + overwrite-race.

## #20 — `src/auth/gsi/gsi_core.c` 🔴🔒 — `build_cert_response_ex` CCN 45 · 527 LOC · **1–1.5d**
Wave 4. **Security-load-bearing.**
- **Seams:** `_extract_server_pubkey` (257–284), `_negotiate_session_cipher` (286–306),
  `_agree_session_key` (308–325), `_sign_server_tag` (327–347), `_build_inner_cert` (encrypt, 349–388),
  `_build_outer_cert` (390–432).
- **Invariants (do not reorder):** cred null-check before any crypto; `signed_dh` decided once, reused
  everywhere; **aeskey `OPENSSL_cleanse` before every early return**; sign server rtag (replay defense);
  new rtag from secure RNG; inner is encrypted / outer carries blob (never mix = plaintext cred leak);
  cipher preference aes-128-cbc first; echo server MD alg; ownership transfer (`outer.p→*payload`, NULL
  source) so `gsi_cresp_fail` won't double-free.
- **Tests:** WLCG x509 conformance (558+ cases) + GSI handshake e2e; full `--pr`. Pair-review.

---

# Effort rollup

| Wave | Files | Days |
|------|-------|------|
| 0 warm-up | #11, #17 (+ start #1) | ~2.5 |
| 1 client | #1, #6, #8, #13, #14, #15 | ~10.5 |
| 2 config | #4, #5, #9 | ~5 |
| 3 hot paths | #2, #3, #7, #12 | ~8 |
| 4 auth/security | #10, #20 | ~3 |
| 5 HTTP handlers | #16, #18, #19 | ~3.5 |
| **Total** | **20** | **~33 engineer-days (≈6.5 wks solo; ≈3 wks with 2–3 in parallel)** |

# Guardrails

- **CI ratchet is the safety net.** `check_complexity.sh` blocks any *new* over-CCN function and any
  *growth* — so partial progress can't regress. Land one file, `--regen`, ceiling drops permanently.
- **Never `--regen` to accept a growth** — only after a genuine simplification. It's the escape hatch
  the file-size guard uses too; same discipline.
- **This ranks branch density only.** It won't flag files hard-to-read for other reasons (macro soup,
  deep pointer chains). Treat as the CCN worklist, not a total readability verdict.
- **Security files (#10, #20) are extract-only, pair-reviewed.** A reordered verify step is a
  vulnerability, not a style nit. The seams are pure code motion — prove behavioral equivalence.
```
