# Phase 77 — Effort-Hotspot Burndown, Wave 3 (+ regression triage)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (A) Verify and fix the 5 analyzer HIGH findings — 4 of which sit in files the
phase-75 decomposition just touched, so they are prime regression suspects — then (B)
drive the 50 highest fix-effort files (re-measured 2026-07-10, post phase-75/76) below the
complexity gate (CCN ≤ 15, fn NLOC ≤ 100, params ≤ 5) without behavior change.

**Architecture:** Phase A is correctness (bug triage, 3-test rule, behavior may change only
to fix a proven defect). Phases B–H are equal-behavior decomposition, one file per task,
independently buildable/testable/committable. This wave is almost pure complexity —
CodeChecker debt is otherwise empty (5 HIGH / 3 MEDIUM / 1 LOW repo-wide; the top-50 files
carry zero findings). Peak effort is 42.0 (down from wave-2's 68.4, phase-72's 138.8): the
distribution keeps compressing, so tasks here are smaller (mostly one CCN-25-to-34 function
per file).

**Tech Stack:** C (nginx module + ngx-free client), lizard 1.23.0, CodeChecker 6.28.2
(clangsa + clang-tidy), pytest fleet + client unit tests.

## Global Constraints

- **NO `goto`** anywhere in `src/`, `shared/`, `client/`.
- **Phase B–H: NO behavior change.** Wire bytes/order, error codes, log strings, metric
  calls, exit codes frozen. Move code, don't rewrite logic. (Phase A fixes proven bugs and
  carries the 3-test rule: success + error + security-negative.)
- **Helpers** `static` in-file, state passed explicitly (no new globals), each with a
  WHAT/WHY/HOW doc block. `static const` tables allowed.
- **Every helper you add must be CALLED** — the build is `-Werror`; the agent gate
  (`-fsyntax-only`) does NOT catch gcc `-Wunused-function`. Debug-only helpers whose sole
  caller is `ngx_log_debug*` go under `#if (NGX_DEBUG)`.
- **Zero-init through struct/out-param splits** — gcc `-Wmaybe-uninitialized` fires where
  `-fsyntax-only` is silent; initialise at declaration.
- **Extern signatures frozen** unless a task explicitly promotes a struct into the owning
  header (then update ALL callers 1:1, hoisting side-effecting args to locals first). A
  param-count-only residual on a frozen extern / `brix_sd_driver_t` vtable slot / FUSE
  callback typedef is acceptable and must be reported, not forced.
- **The build is the only reliable cross-file oracle after header-touching work** — the
  `-fsyntax-only` agent gate cannot see caller mismatches in other translation units.
- **Doc-comment `-Wcomment` trap:** `*a/*b` in a comment forms `/*`; write `*a / *b`.
- **NEVER run any git write command.** Commit steps are STOP-and-ask-OP gates.
- **Build:** `cd /tmp/nginx-1.28.3 && make -j$(nproc)` (module, -Werror). Client:
  `make -C client -j$(nproc)`. No `./configure` (no new source files this phase).
- **Per-file gate:** `lizard <FILE> -l c -C 15 -L 100 -a 5 -w` → empty (or reported frozen
  residual). **Analyzer gate (Phase A):** re-analyze the touched TU, confirm the finding is
  gone.
- Baseline data: `docs/refactor/phase-77-baseline/` (Task 0). Fleet notes: seed
  `random.bin`/`large200.bin` in attach mode (conftest.py:337); clean stop-all/start-all
  after any src fix that runs start-all to avoid token-port JWKS desync; -n12 xdist cap.

## Effort model

Per function `2.0*max(0,CCN−15) + 0.10*max(0,NLOC−100) + 1.0*max(0,params−5)`; per file +
severity-weighted findings (HIGH 10 / MED 4 / LOW 1), deduped by (file,line,checker),
excluding two noise checkers. All 50 files scored 0 on the finding term.

## Phase map

| Phase | Scope | Files | Risk |
|---|---|---|---|
| 77.0 | Baseline | — | none |
| 77.A | Analyzer HIGH triage (regression suspects) | 4 (+1 FP) | correctness |
| 77.B | client lib + apps | 14 | CLI/wire frozen |
| 77.C | root:// + tpc | 10 | wire hot paths |
| 77.D | s3 + webdav | 8 | HTTP semantics |
| 77.E | auth | 6 | security-load-bearing |
| 77.F | core + fs | 7 | storage/startup |
| 77.G | observability + net | 5 | low risk |

77.0 → 77.A strictly first (fix regressions before decomposing more). 77.B–77.G are
independent, one file per session, parallelizable — but launch in bounded waves (~12) and
**run a full build after each wave**: the session limit has repeatedly killed agents
mid-edit, and only the build catches the resulting cross-file mismatches.

---

## Phase 77.0 — Baseline

### Task 0
**Files:** Create `docs/refactor/phase-77-baseline/top50.json` (current ranking) + reuse
`docs/refactor/phase-75-baseline/regen.sh` into `phase-77-baseline/`.
- [ ] Run regen into `run0/`; save the top-50 table; confirm CodeChecker in-repo = 9
  findings (5 HIGH / 3 MEDIUM / 1 LOW). **Commit gate — ask OP** (docs only).

Per-task gate (replace `<FILE>`):
```bash
lizard <FILE> -l c -C 15 -L 100 -a 5 -w                    # expect empty
python3 docs/refactor/phase-77-baseline/synchk.py <FILE>   # exit 0 (carry from phase-75 scratch)
```

---

## Phase 77.A — Analyzer HIGH triage (do first; 3 tests each)

Each finding is adversarially verified: reproduce with `clang --analyze
-analyzer-checker=<checker>` (or CodeChecker on the single TU), decide real-bug vs
false-positive. Real → fix + 3 tests. FP → `/* phase77-fp: <proof> */` + `// NOLINT(<checker>)`.

### Task A1: `src/auth/sss/auth_request.c:137` — `core.NullDereference` on `out->key->key_len`
**Regression suspect** (phase-75 D2 `sss_cred_t` split). At L137 `out->key->key_len` is
dereferenced; the analyzer proves a path where `out->key` (the resolved keytab entry) is
NULL. Trace `sss_parse_header`/`sss_verify_keytab`: if key lookup can leave `out->key`
NULL while `out->cipher_len` was set, the decrypt path derefs NULL.
Fix: guard `if (out->key == NULL) return brix_sss_auth_failed(ctx, c);` before the crypt
call (fail-closed, matches every other SSS deny path). 3 tests: valid SSS auth OK;
unknown-key-name → clean deny (no crash); security-neg: forged header with absent key →
`brix_sss_auth_failed`, not SIGSEGV. Test: `pytest tests/ -k sss -v`.

### Task A2: `src/protocols/root/write/writev.c:239,335` — `security.ArrayBound` on `ctx->files[hidx]`
**Regression suspect** (phase-75 E2 writev split). `hidx = (int)(unsigned char)
wl[i].fhandle[0]` ranges 0–255; if `ctx->files[]` is smaller than 256 OR the per-segment
handle isn't validated before indexing, this reads/writes past the array. The phase-75
split moved handle validation into `writev_validate_handles` — verify EVERY `hidx` used at
:239 (descriptor build) and :335 (replay check) was bounds-checked first. If the analyzer
is right (a segment index escapes validation), add `if (hidx < 0 || hidx >= BRIX_MAX_FILES
|| ...invalid...) → kXR error` before both uses; if validation is complete and the
analyzer just can't see it, FP-mark with the proof that `writev_validate_handles` rejects
out-of-range hidx for all i. 3 tests: normal writev OK; writev with an out-of-range fhandle
→ clean kXR_ArgInvalid (no OOB); security-neg: fhandle=0xFF unopened → rejected. Preserve
INVARIANT: writev stock-framing (descriptors framed, body streamed after). Test:
`pytest tests/ -k writev -v`.

### Task A3: `src/protocols/webdav/get.c:412` — `core.CallAndMessage` 2nd arg uninitialized (`st->sb.st_mtime`)
**Regression suspect** (phase-75 B5 get split). `get_eval_conditionals` reads
`st->sb.st_mtime` into `brix_http_check_if_modified_since`; the analyzer proves a path
reaching it where `get_serve_state_t st`'s `sb` (a `struct stat`) was never populated
(`get_resolve_and_stat` skipped/failed but the conditional still ran). Fix: either
zero-init `st` (`get_serve_state_t st = {0};` in the orchestrator — likely already done,
verify) AND ensure `get_eval_conditionals` runs only after a successful stat, or gate it on
a `st->have_stat` flag. 3 tests: GET with If-Modified-Since on an existing file → correct
304/200; GET on a path whose stat failed → no uninitialized-mtime read (clean 404);
security-neg: conditional GET on a directory → unchanged. Test: `pytest tests/ -k "webdav and get" -v`.

### Task A4: `src/fs/path/helpers.c:63` — `security.ArrayBound` (documented FP)
Already dispositioned in phase-74 (loop-widening over the `"-"` string literal; the NOLINT
is at line 62-63). clang-sa doesn't honor the clang-tidy NOLINT in an analyze run — confirm
the `phase74-fp` comment + NOLINT are intact; no code change. Re-report as permanent FP.

### Task A5: Phase-77.A exit gate
- [ ] Re-run CodeChecker on the touched TUs; assert 0 HIGH remain except the helpers.c FP.
  Record delta in `docs/refactor/phase-77-baseline/after-77A.md`. **Commit gate — ask OP.**

---

## Decomposition task template (77.B–77.G)

1. Read the whole file + `docs/09-developer-guide/coding-standards.md` §4/§8.
2. Characterize: run the task's test command, capture the pass baseline (add a
   characterization test first if the file has none).
3. Extract `static` helpers / promote a file-local struct per the recipe; early-return over
   nesting; table-driven dispatch for switch/if ladders; no `goto`; state passed explicitly.
4. Gate: `lizard <FILE> -l c -C 15 -L 100 -a 5 -w` → empty (or reported frozen residual).
5. Build: module `make -j$(nproc)` (or `make -C client`) — exit 0, -Werror clean, every
   helper called.
6. Test: task's command → identical pass set to step 2.
7. **Commit gate** — STOP, ask OP; one commit per file.

---

## Phase 77.B — client lib + apps (CLI + wire frozen; `make -C client && make -C client test`)

### Task B1: `client/lib/protocols/http/http_req.c` — `httpx_exchange` CCN 29/92 NLOC/**11p** (L76-173); `brix_http_req` 13p
Recipe: promote a file-local `httpx_exchange_t` (host/port/tls/method/path/headers/body/
timeout/verify/ca) for the 11p+13p family; split exchange into send-request / read-response
/ map-status. HTTP client wire frozen. Test: `make -C client test` + `pytest tests/ -k "http and client" -v`.

### Task B2: `client/lib/xfer/copy_remote.c` — `cksum_verify` CCN 22 (L126-217); `copy_tpc` CCN 21 (L307-417); r2r_teardown 10p; tpc_teardown 12p
Recipe: split cksum_verify (resolve-algo / fetch-remote / compare) and copy_tpc
(setup / run / verify); the 10-12p teardown helpers → a `r2r_ctx_t` struct. TPC + checksum
semantics frozen. Test: `make -C client test` + `pytest tests/ -k "recursive or tpc" -v`.

### Task B3: `client/lib/observability/capture.c` — `brix_capture_replay` CCN 24 (L175-250); `brix_capture_playback` CCN 24 (L262-340); capture_frame 9p
Recipe: replay/playback each → parse-frame / apply / advance; capture_frame 9p → a frame
struct. Capture wire format frozen. Test: `make -C client test`.

### Task B4: `client/apps/fs/brixcvmfs.c` — `brixcvmfs_main` CCN 26 (L535-612); `brixcvmfs_open` CCN 22 (L410-490); transport 7p
Recipe: main → arg-parse + mount-bring-up (phase-72 H3 pattern); open → resolve/transport/
attach; transport 7p → struct. CLI frozen; FUSE callbacks stay (report). Test:
`make -C client test` + cvmfs client smoke.

### Task B5: `client/lib/xfer/copy.c` — `brix_copy` CCN 34/83 NLOC (L237-339); `resilient_setup` 6p
Recipe: `brix_copy` → classify (local/web/s3/tpc scheme table) + dispatch; resilient_setup
6p → struct. Transfer routing frozen. Test: `make -C client test` + `pytest tests/ -k xrdcp -v`.

### Task B6: `client/apps/fs/xrdfs.c` — `main` CCN 33/94 NLOC (L243-345); `dispatch` CCN 16/6p
Recipe: busybox dispatcher — subcommand `{name, fn}` table + per-cmd helpers (mirror the
phase-72 H8 xrd.c pattern). CLI/exit codes frozen. Test: `make -C client test`.

### Task B7: `client/lib/protocols/http/http_upload.c` — `brix_http_upload_resumable` CCN 13/**14p**; several 11-14p externs
Recipe: this is the phase-76 residual set — promote `httpx_upload_ctx_t` into
`http_internal.h`/`brix_net.h` and thread through the whole family, updating ALL callers
(grep across src+client; caution copy_local.c is a sibling — coordinate or report). Resume
semantics frozen. Test: `make -C client test` + `pytest tests/ -k "http_upload or resumable" -v`.

### Task B8: `client/lib/protocols/http/http.c` — `brix_http_get` CCN 27/105 NLOC/9p (L8-126)
Recipe: get → connect / send / read-headers / read-body; 9p → the B1 `httpx_exchange_t` if
shared, else file-local. Test: `make -C client test`.

### Task B9: `client/lib/protocols/http/webfile_io.c` — `web_get_range` CCN 29/114 NLOC (L101-235); brix_webfile_open 8p
Recipe: range GET → build-range-req / stream-body / handle-206; open 8p → struct. Test:
`make -C client test` + `pytest tests/ -k "webfile or range" -v`.

### Task B10: `client/lib/protocols/shared/zip.c` — `brix_zip_member_extract` CCN 26 (L230-329); `brix_zip_open` CCN 17; read_eocd/sink 7p
Recipe: member_extract → locate / inflate / sink; open → read-eocd / parse-central-dir; the
7p helpers → structs. ZIP byte layout frozen. Test: `make -C client test` + `pytest tests/ -k zip -v`.

### Task B11: `client/apps/auth/xrdsssadmin.c` — `main` CCN 29 (L205-262); `cmd_add` CCN 16/7p
Recipe: main → subcommand table; cmd_add 7p → an add-args struct. keytab format frozen.
Test: `make -C client test`.

### Task B12: `client/lib/core/aio/aio.c` — `loop_process_timeouts` CCN 23 (L169-239); submit_ex 8p; call_ex 9p
Recipe: timeouts loop → scan-expired / fire-callback; the 8-9p submit/call → an
`aio_op_t` struct. Event-loop semantics frozen. Test: `make -C client test` + `pytest tests/ -k "aio and client" -v`.

### Task B13: `client/apps/fs/xrdfs_data.c` — 39 fns, worst CCN 15, param bloat (dd_parse_args 7p, xfer_common_arg 8p, tail_start_for_lines 6p, stream_file 6p)
Recipe: PARAM-bloat + one CCN-15 fn — introduce per-subcommand arg structs (`dd_args_t`,
`tail_args_t`, `xfer_args_t`); thread through. CLI frozen. Test: `make -C client test`.

### Task B14: `client/apps/auth/xrdgsiproxy.c` — `main` CCN 33/63 NLOC (L51-123)
Recipe: main → subcommand table (init/info/destroy) + per-cmd helpers. CLI frozen. Test:
`make -C client test`.

### Task B15: `client/lib/fs/glob.c` — `brix_glob` CCN 29/98 NLOC (L30-132); `client/apps/diag/diag_compare.c` — `do_compare` CCN 29/92 (L134-230)
Two small files, one task. glob → segment-match / recurse / collect; do_compare →
fetch-both / diff / render. Behavior frozen. Test: `make -C client test` + `pytest tests/ -k "glob or compare" -v`.

---

## Phase 77.C — root:// + tpc (wire hot paths)

### Task C1: `src/protocols/shared/http_serve_offload.c` — `brix_http_serve_offload_remote` CCN 29/113 NLOC/8p (L288-424); `serve_offload_thread` CCN 18
Recipe: offload_remote → resolve-origin / build-request / stream-pump; the 8p extern — if
callers are few, promote a struct; else split body + report. Never capture `c->log` into a
long-lived struct. Test: `pytest tests/ -k "offload or cvmfs" -v`.

### Task C2: `src/tpc/outbound/source.c` — `tpc_stream_to_dst` CCN 28/141 NLOC (L332-529); `tpc_open_resolve` CCN 17/7p; `tpc_open_source` CCN 16
Recipe: stream_to_dst → open / pump / finalize; open_resolve 7p → struct. TPC outbound
wire frozen. Test: `pytest tests/ -k tpc -v`.

### Task C3: `src/core/aio/write.c` — `brix_write_aio_done` CCN 32/142 NLOC (L37-253)
Recipe: the write-completion callback → per-outcome helpers (success-commit / error-teardown
/ writethrough-flush / reply). Mirror the phase-72 B11 tpc/done.c split; watch the same
client-gone null-safety (nullable log). Test: `pytest tests/ -k "write and aio" -v`.

### Task C4: `src/protocols/root/write/pgwrite.c` — `brix_handle_pgwrite` CCN 30/171 NLOC (L99-334)
Recipe: parse+CRC-verify (per-page CRC32c, INVARIANT 1 frozen) / validate / execute / reply.
Test: `pytest tests/ -k pgwrite -v`.

### Task C5: `src/protocols/root/read/readv.c` — `brix_handle_readv` CCN 26/197 NLOC (L164-429); `brix_readv_read_segments` CCN 18/104 NLOC/5p
Recipe: readv → parse-vector / serve-segments / frame-reply; read_segments → per-segment
loop body. TLS/cleartext split (INVARIANT 2) frozen. Test: `pytest tests/ -k readv -v`.

### Task C6: `src/protocols/root/read/locate.c` — `brix_handle_locate` CCN 30/146 NLOC (L44-224)
Recipe: locate → resolve / query-cms-or-local / format-response. Test: `pytest tests/ -k locate -v`.

### Task C7: `src/tpc/engine/parse.c` — `tpc_parse_token` CCN 29/64 NLOC (L193-268); `tpc_parse_src_spec` 6p
Recipe: token parser → descriptor table of `{key, apply_fn}`; src_spec 6p → struct. TPC
directive grammar frozen. Test: `pytest tests/ -k "tpc and parse" -v`.

### Task C8: `src/protocols/webdav/tpc_marker.c` — `webdav_tpc_marker_start` CCN 21/**11p** (L416-549); `tpc_marker_finish` CCN 20
Recipe: 11p start → a marker-ctx struct; finish → classify / emit-marker / cleanup.
Performance-marker wire frozen. Test: `pytest tests/ -k "tpc and marker" -v`.

### Task C9: `src/tpc/engine/launch.c` — `brix_tpc_start_pull` CCN 21/107 NLOC (L453-595); `brix_tpc_prepare_pull` CCN 20/114 NLOC/7p
Recipe: start_pull → key-register / spawn / arm; prepare_pull 7p → struct. Native-TPC key
registry semantics frozen. Test: `pytest tests/ -k tpc -v`.

### Task C10: `src/protocols/root/relay/relay_guard.c` — `opcode_to_op` CCN 29/36 NLOC (L38-73)
Recipe: pure opcode→op switch ladder → `static const` lookup table (phase-72 D4 kxr_names
pattern). Generate the expected pairs from HEAD first, verify identical. Test: `pytest tests/ -k "relay or guard" -v`.

---

## Phase 77.D — s3 + webdav (SigV4 ≠ token; HTTP semantics frozen)

### Task D1: `src/protocols/s3/post_policy.c` — `s3_post_policy_condition` CCN 25 (L100-192); `s3_post_verify_policy` CCN 22 (L339-440); parse_credential 6p
Recipe: condition → per-condition-type table; verify_policy → decode / check-conditions /
check-signature (SigV4, no token sharing — INVARIANT 6). POST-policy verdict byte-frozen.
Test: `pytest tests/ -k "s3 and (post or policy)" -v`.

### Task D2: `src/protocols/s3/object.c` — `s3_handle_get` CCN 29/166 NLOC (L112-333)
Recipe: get → resolve / conditionals / serve-range / serve-full (TLS/cleartext split frozen).
Test: `pytest tests/ -k "s3 and get" -v`.

### Task D3: `src/protocols/s3/list_walk.c` — `s3_walk` CCN 29/106 NLOC/**8p** (L131-282)
Recipe: 8p walk → a walk-ctx struct + enumerate / filter / emit split. ListObjects XML
frozen. Test: `pytest tests/ -k "s3 and list" -v`.

### Task D4: `src/protocols/s3/module.c` — `ngx_http_s3_merge_loc_conf` CCN 28/144 NLOC (L83-262)
Recipe: per-concern `s3_merge_<group>()` helpers called in sequence (phase-72 F3/cvmfs
pattern). Merge order + defaults frozen (`nginx -t`). Test: `nginx -t` + `pytest tests/ -k s3 -v`.

### Task D5: `src/protocols/webdav/xrdhttp_multipart.c` — `xrdhttp_handle_multipart_get` CCN 29/144 NLOC (L88-267)
Recipe: multipart/byteranges GET → parse-ranges / emit-part-headers / stream-part / close.
multipart boundary bytes frozen. Test: `pytest tests/ -k "multipart or byterange" -v`.

### Task D6: `src/protocols/webdav/tpc_cred.c` — `tpc_cred_oidc_agent_fetch` CCN 29/159 NLOC (L112-324); `webdav_tpc_cred_obtain_token` CCN 14/6p
Recipe: oidc_fetch → connect-agent / request / parse-response; obtain_token 6p → struct.
OIDC/RFC8693 exchange frozen. Test: `pytest tests/ -k "tpc and (cred or oidc)" -v`.

### Task D7: `src/fs/scan/scan_http.c` — `ngx_http_brix_dashboard_scan_handler` CCN 31/118 NLOC (L170-305); scan_arg 6p
Recipe: scan handler → parse-query / walk / render (JSON frozen); scan_arg 6p → struct.
Test: `pytest tests/ -k "scan and http" -v`.

### Task D8: `src/protocols/webdav/tpc_cred.c` moved to D6. This slot: `src/observability/dashboard/files.c` — `files_handler` CCN 25 (L167-255); `download_handler` CCN 19
Recipe: files_handler → auth / list / render; download_handler → auth / resolve / serve.
Dashboard output frozen. Test: `pytest tests/ -k "dashboard and files" -v`.

---

## Phase 77.E — auth (security-load-bearing; keep a security-negative each)

### Task E1: `src/auth/gsi/parse_x509.c` — `brix_gsi_parse_x509` CCN 28/173 NLOC (L333-579); `brix_gsi_parse_x509_signed` CCN 18/88 NLOC
Recipe: parse_x509 → extract-chain / validate-proxy-policy / build-identity (RFC3820
monotonicity frozen). This is the WLCG-x509-conformance oracle path — 530-case suite must be
identical. Test: `pytest tests/ -k "x509_conformance or gsi" -v`.

### Task E2: `src/auth/gsi/cert_response.c` — `brix_gsi_send_cert` CCN 28/210 NLOC (L143-425)
Recipe: send_cert → build-body / add-extensions / sign / frame (GSI wire chunks byte-frozen).
Test: `pytest tests/ -k "gsi and cert" -v`.

### Task E3: `src/protocols/s3/post_policy.c` moved to D1. This slot: `src/auth/sss/auth_crypto_helpers.c` — `brix_sss_verify_blob` CCN 27/93 NLOC/**8p** (L119-226)
Recipe: verify_blob 8p → a blob-ctx struct + decrypt / crc-check / parse-identity. Blowfish
+ CRC + replay-window frozen. Security-neg: wrong-key → clean deny. Test: `pytest tests/ -k sss -v`.

### Task E4: `src/auth/authz/auth_gate.c` — `brix_acc_gate_engine` CCN 20/7p (L26-104); `brix_auth_gate_op` CCN 17/**10p** (L213-322); cache_key 7p
Recipe: the auth-gate cluster is param-bloat — promote an `auth_gate_ctx_t` (identity/path/
op/conf/caches) threaded through engine/op/cache_key. Default-deny + verdict frozen.
Security-neg: cross-user deny holds. Test: `pytest tests/ -k "auth_gate or mu_authz" -v`.

### Task E5: `src/tpc/gsi/gsi_outbound_certreq.c` — `tpc_outbound_gsi` CCN 26/135 NLOC (L49-266); finish 7p
Recipe: outbound GSI handshake → per-step certreq/cert/sigpxy helpers (phase-72 C1 pattern);
finish 7p → struct. Delegation wire frozen. Test: `pytest tests/ -k "tpc and gsi" -v`.

### Task E6: `src/protocols/s3/module.c` moved to D4. This slot: verify E1–E5 landed; re-run
`lizard src/auth -l c -C 15 -L 100 -a 5 -w` and confirm only files outside this top-50 remain.

---

## Phase 77.F — core + fs (storage/startup)

### Task F1: `src/fs/backend/rados/sd_ceph.c` — `sd_ceph_open_on_ioctx` CCN 26/8p (L544-631); `sd_ceph_normalize` CCN 20; `sd_ceph_open_cred` CCN 16/6p (51 fns, 889 NLOC)
Recipe: open_on_ioctx 8p → an open-req struct + striper-vs-plain open split; normalize →
scheme/key parse halves. The 6p `_open_cred` is a `brix_sd_driver_t` vtable slot — report
frozen. Test: Ceph harness (`tests/ceph_harness.sh`) + `pytest tests/ -k ceph -v`.

### Task F2: `src/core/config/server_conf.c` — `brix_merge_srv_cluster` CCN 29/120 NLOC (L587-749); `brix_merge_srv_security` CCN 16/115 NLOC; `brix_merge_srv_storage` CCN 12/104 NLOC
Recipe: each merge_srv_* → per-directive-group helpers; the CCN-3/158-NLOC create_srv_conf
is length-only (split into field-group initializers). Merge order + error strings frozen.
Test: `nginx -t` + `pytest tests/ -k "reload or config" -v`.

### Task F3: `src/core/http/http_compress.c` — `brix_http_send_file_compressed` CCN 26/8p (L170-273); `accept_encoding_has` CCN 22
Recipe: send_compressed 8p → struct + negotiate / stream; accept_encoding_has → q-value
parser table. Codec selection frozen. Test: `pytest tests/ -k "compress or encoding" -v`.

### Task F4: `src/core/compat/net_target.c` — `brix_net_target_parse` CCN 32/107 NLOC/5p (L175-320); `check_dns_pin` CCN 16/6p
Recipe: target parse → scheme / host / port / opaque split (grammar table); check_dns_pin
6p → struct. Parse acceptance + DNS-pin semantics frozen. Test: `pytest tests/ -k "net_target or dns" -v` + C unit if present.

### Task F5: `src/core/http/http_body.c` — `brix_http_body_decode_to_fd` CCN 19/7p (L593-668); `write_to_staged` CCN 18; `codec_decode_bufs` CCN 16/8p; `codec_feed` 11p
Recipe: the codec pipeline is param-bloat — promote a `codec_ctx_t` threaded through
decode_to_fd / decode_bufs / feed. Decode semantics + error mapping frozen. Test:
`pytest tests/ -k "body or codec or compress" -v`.

### Task F6: `src/fs/vfs/vfs_walk.c` — `vfs_walk_dir` CCN 20/**10p** (L89-180); `brix_vfs_copytree` CCN 16/7p; `brix_vfs_walk` 9p; copyfile 7p
Recipe: PARAM-bloat cluster — promote a `vfs_walk_ctx_t` (root/cb/filters/depth) threaded
through walk_dir / walk / copytree / copyfile / emit_file. Confinement seam + entry order
frozen; outward symlink stays invisible. Test: `pytest tests/ -k "vfs and (walk or copy)" -v`.

### Task F7: `src/tpc/engine/launch.c` moved to C9. This slot: `src/core/config/server_conf.c`
create_srv_conf length split — folded into F2. Verify F1–F6 landed; re-run
`lizard src/core src/fs -l c -C 15 -L 100 -a 5 -w`, confirm only out-of-top-50 files remain.

---

## Phase 77.G — observability + net (low risk)

### Task G1: `src/observability/accesslog/access_log.c` — `brix_access_sess_mode` CCN 24 (L244-300); `brix_log_access` CCN 23/87 NLOC/9p (L348-447); maybe_sesslog 8p
Recipe: sess_mode → mode-decision table; log_access 9p → an access-log-record struct +
format helpers; maybe_sesslog 8p → same struct. Access-log line bytes frozen (tests grep
them). Test: `pytest tests/ -k "accesslog or access_log" -v`.

### Task G2: `src/observability/dashboard/api_admin.c` — `brix_admin_dispatch` CCN 22 (L328-407); `admin_validate_url` CCN 21; `check_auth` CCN 20; `validate_paths` CCN 16
Recipe: dispatch → endpoint table; validate_url/paths → per-rule predicate helpers;
check_auth → per-source try helpers. Admin authz frozen (security-neg: forged session
rejected). Test: `pytest tests/ -k "dashboard and (admin or api)" -v`.

### Task G3: `src/observability/dashboard/module.c` — `main_handler` CCN 26 (L521-648); `set_users` CCN 17; `merge_loc_conf` CCN 16
Recipe: main_handler → route table; set_users → parse-user-line loop; merge → per-group.
Dashboard routing + config frozen. Test: `pytest tests/ -k dashboard -v` + `nginx -t`.

### Task G4: `src/protocols/root/read/locate.c` moved to C6. This slot:
`src/observability/dashboard/files.c` moved to D8. Verify the dashboard/observability files
(G1–G3 + D8) landed; re-run `lizard src/observability -l c -C 15 -L 100 -a 5 -w`, confirm
only out-of-top-50 remain.

---

## Phase-77 exit criteria

- [ ] `regen.sh final/`: every one of the 50 files passes `lizard -C 15 -L 100 -a 5 -w`
  clean or shows only reported frozen-signature param residuals.
- [ ] Full builds green: module (`-Werror`) + `make -C client` + `make -C client test`.
- [ ] `PYTHONPATH=tests pytest tests/ -v --tb=short` — no regressions vs Task-0 baseline
  (fleet rules apply; seed data files in attach mode; clean stop/start after src fixes).
- [ ] Phase-A: 0 HIGH analyzer findings remain except the helpers.c documented FP; the 4
  triaged sites each carry their fix + 3 tests (or an FP proof).
- [ ] `tools/ci/check_vfs_seam.sh` green; `tools/ci/check_complexity.sh --regen` run once at
  the END (OP-approved ratchet acceptance).
- [ ] CodeChecker exit gate: no NEW findings introduced by the decompositions.
- [ ] Delta table appended here; `docs/refactor/phase-77-baseline/final/` committed.
- [ ] Every commit had explicit OP approval.

## Execution record (2026-07-10)

IMPLEMENTED (uncommitted). **Phase 77.A** (analyzer HIGH triage): all 4 regression-suspect
findings in phase-75-decomposed files were adversarially verified as FALSE POSITIVES — the
splits were correct (sss key-NULL guarded by parse_header; writev hidx bounds-checked by
validate_handles; get.c sb populated before conditionals). Cleared 2 cleanly with
behavior-neutral hardening (sss fail-closed key guard, get.c `st = {0}` zero-init) and
FP-marked writev; helpers.c:63 stays the documented phase-74 FP. Regression tests
(writev/readv/pgwrite/sss/locate + security variants) 410/0.

**Phases 77.B–77.G** (50-file decomposition) run in 4 bounded waves (client 15, root/tpc 10,
s3/webdav+auth 13, core/fs+observability 9, + 2 stragglers srr/builder & file_serve) with a
full build after each wave. Every CCN/NLOC violation cleared; ~59 residuals remain, all
param-count-only (CCN ≤14, NLOC ≤98) on frozen extern / `brix_sd_driver_t` vtable slot /
FUSE-callback signatures. Standouts: relay_guard opcode ladder → table (33-opcode oracle
verified dense+exact); auth_gate param-bloat cluster → one ctx struct; write-completion
callback split with done.c's nullable-log discipline; GSI parse_x509/cert_response wire
byte-frozen. Several agents caught the `-Wcomment` `*a/*b`→`/*` trap and the
BRIX_RETURN_ERR-in-int-helper trap themselves.

Module (-Werror) + client builds green each wave; `nginx -t` green; client unit tests ALL
PASS; serial smoke 440 + 410 (Phase-A sites) with zero failures. No agent died at the
session limit this phase (bounded waves + per-wave builds worked). CodeChecker exit gate
unchanged. The complexity-backlog `--regen` and commit remain OP-owned.

## Known frozen-residual ledger (expected param-only survivors)

| File | Function | Why frozen |
|---|---|---|
| sd_ceph.c | sd_ceph_open_cred (6p) | brix_sd_driver_t vtable slot |
| brixcvmfs.c | FUSE op callbacks (6p) | FUSE 3 typedef |
| http_upload.c | resumable/upload family (11-14p) | extern in brix_net.h, cross-file callers (B7 may clear) |
| (others) | discovered during execution | append here |

## Deliberately out of scope

- Files ranked 51+ (next wave). The phase-74/76 documented-FP analyzer findings
  (helpers.c ArrayBound, pool.c unix.Malloc, dead_props.c redundant, multipart arg-order) —
  proven false, no action.
- `brix_vfs_ctx_init` (~50 callers), gsi_core cross-plane externs, and the vtable/FUSE
  param residuals from phase-76 — permanent frozen class.
- The `misc-header-include-cycle` include-graph checker — its own future phase.
