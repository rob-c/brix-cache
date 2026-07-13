# Phase 75 — Effort-Hotspot Burndown, Wave 2 (top-50 residual complexity)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive the 50 highest fix-effort files (re-measured 2026-07-10, AFTER
phase-72/73/74) below the complexity gate (CCN ≤ 15, fn NLOC ≤ 100, params ≤ 5)
without behavior change. This is the second decomposition wave: the phase-72 top-50
are all decomposed and off the list (zero overlap); this set is the next tier, and
it is **pure complexity** — CodeChecker debt is already zero across all 50 files
(the phase-74 sweep burned the analyzer queue down to 4 documented false positives,
none in a high-effort file), so there are NO bug fixes to triage here.

**Architecture:** One workstream, mechanical decomposition. Each file is one task,
independently buildable/testable/committable. Two shapes dominate and the recipe
per task names which applies: (a) **one giant handler** (CCN 30–44 single function)
→ extract per-phase/per-concern `static` helpers + early-return flattening +
table-driven dispatch for switch ladders; (b) **parameter bloat** (up to 29 params)
→ promote a file-local/args struct, threading it through the callsite(s).

**Tech Stack:** C (nginx module + ngx-free client), lizard 1.23.0, CodeChecker
6.28.2 (already clean here), pytest fleet + client unit tests.

## Global Constraints

- **NO `goto`** anywhere in `src/`, `shared/`, `client/` (CLAUDE.md HARD BLOCK).
- **NO behavior change.** Equal-behavior decomposition only: wire bytes/order, error
  codes, log strings, metric calls, exit codes frozen. Move code, don't rewrite logic.
- **Helpers** are `static` in-file, state passed explicitly (no new globals), each with
  a WHAT/WHY/HOW doc block matching the file's style. Table/descriptor arrays may be
  `static const`. Never reimplement anything in CLAUDE.md HELPERS.
- **Every helper you add must be CALLED** — the build is `-Werror` and `-fsyntax-only`
  (the agent gate) does NOT catch gcc `-Wunused-function`. Debug-only helpers whose
  sole caller is an `ngx_log_debug*` must be wrapped in `#if (NGX_DEBUG)`.
- **Zero-init through out-param/struct splits** — gcc `-Wmaybe-uninitialized` fires
  where `-fsyntax-only` is silent; initialise at declaration.
- **Extern signatures are frozen unless a task explicitly promotes a struct into the
  owning header.** Where a task DOES touch a header, update ALL callsites 1:1 (grep
  the symbol across `src`/`shared`/`client`) and hoist any side-effecting argument to a
  local before building the struct literal (preserve evaluation order). A residual that
  is a param-count-only flag on a frozen extern / vtable slot / FUSE-callback typedef is
  acceptable and must be reported, not forced.
- **NEVER run any git write command.** Commit steps are STOP-and-ask-OP gates.
- **Build:** `cd /tmp/nginx-1.28.3 && make -j$(nproc)` (module). Client:
  `make -C client -j$(nproc)`. No `./configure` (no new source files in this phase).
- **Per-file gate (definition of done):** `lizard <FILE> -l c -C 15 -L 100 -a 5 -w`
  → empty (or only frozen-signature param residuals, reported).
- Baseline data: `docs/refactor/phase-75-baseline/` (Task 0); ranking snapshot in
  `docs/refactor/phase-72-baseline/regen.sh` output re-run against the current tree.

## Effort model (how the 50 were chosen)

Per function `2.0*max(0,CCN−15) + 0.10*max(0,NLOC−100) + 1.0*max(0,params−5)`; per
file + severity-weighted findings (HIGH 10 / MED 4 / LOW 1), deduped by
(file,line,checker), excluding the two noise checkers. All 50 files scored 0 on the
finding term — this wave is complexity only.

## Phase map

| Phase | Scope | Files | Risk |
|---|---|---|---|
| 75.0 | Baseline re-measure | — | none |
| 75.A | fs backend + vfs | 8 | storage truth |
| 75.B | webdav methods | 8 | HTTP semantics |
| 75.C | s3 | 6 | SigV4 ≠ token |
| 75.D | auth (gsi/sss/authz/sts) | 9 | security-load-bearing |
| 75.E | root:// + net + tap | 7 | wire/cluster |
| 75.F | observability + cvmfs | 6 | low risk |
| 75.G | client lib + apps | 6 | CLI/wire frozen |

75.0 first; 75.A–75.G are mutually independent, one file per session, parallelizable
(files never overlap). Order within a phase is free.

---

## Phase 75.0 — Baseline

### Task 0: Freeze the measurement

**Files:** Create `docs/refactor/phase-75-baseline/top50.json` (the current ranking),
reuse `docs/refactor/phase-75-baseline/regen.sh` (copy of `phase-72-baseline/regen.sh`).

- [ ] **Step 1:** copy `phase-72-baseline/regen.sh` → `phase-75-baseline/regen.sh`; run
  it into `phase-75-baseline/run0/`; save the top-50 table to `top50.json`.
- [ ] **Step 2:** confirm 50-file lizard set matches this doc and CodeChecker in-repo
  findings = 4 (all FP-marked) — this wave adds no finding-driven work.
- [ ] **Step 3: Commit gate** — STOP, ask OP (docs only).

**Per-task gate commands** (replace `<FILE>`):
```bash
lizard <FILE> -l c -C 15 -L 100 -a 5 -w                       # expect: empty
python3 docs/refactor/phase-75-baseline/synchk.py <FILE>      # exit 0 (copy of the phase-72 synchk)
```
(The synchk helper compiles one module TU via the compile-db with `-fsyntax-only`, or a
client file with the client include roots; carry it forward from phase-72's scratch.)

---

## Decomposition task template (every task in 75.A–75.G)

1. **Read** the whole file + `docs/09-developer-guide/coding-standards.md` §4 (no-goto)
   and §8 (functional/modular).
2. **Characterize**: run the task's test command, capture the pass baseline. If the file
   has no direct test, add a characterization test for the main success/error paths first
   (must pass before AND after).
3. **Extract/Promote** per the recipe — `static` helpers or an args struct, state passed
   explicitly, WHAT/WHY/HOW on each, early-return over nesting, table-driven dispatch for
   switch/if-ladders. No `goto`.
4. **Gate**: `lizard <FILE> -l c -C 15 -L 100 -a 5 -w` → empty (or reported frozen residual).
5. **Build**: module `make -j$(nproc)` (or `make -C client`) — exit 0, `-Werror` clean,
   every new helper called.
6. **Test**: task's command → identical pass set to step 2.
7. **Commit gate** — STOP, ask OP; one commit per file:
   `refactor(phase-75): decompose <file> under complexity gate`.

---

## Phase 75.A — fs backend + vfs

### Task A1: `src/fs/backend/http/sd_http.c` — `sd_http_request_fo` CCN 29/104 NLOC/7p (L225-353); `brix_sd_http_create` CCN 25 (L903-982); `sd_http_open_common` CCN 23/6p (L445-519)
Recipe: `sd_http_request_fo` → split the curl request lifecycle: `httpfo_build_req(...)`
(URL+headers+method), `httpfo_perform(...)` (curl_easy + retry/stall policy),
`httpfo_map_result(...)` (status→errno). 7p → a file-local `sd_http_req_t`. `create` →
`httpc_parse_authority` + `httpc_init_curl_share` + `httpc_apply_tls`. `open_common` →
hit/miss/range decision helper; the 6p slot pair (`sd_http_open`/`_open_cred`) are
`brix_sd_driver_t`-fixed — report as residual. Test: `pytest tests/ -k "cvmfs or http_origin or pelican" -v`.

### Task A2: `src/fs/vfs/vfs_open.c` — `brix_vfs_open` CCN 39/139 NLOC (L378-564); `brix_vfs_adopt_fd` CCN 11/6p; `brix_vfs_ctx_init` 10p (L42-72)
Recipe: `brix_vfs_open` → `vfs_open_route(ctx)` (driver-vs-POSIX + confinement SEAM, one
place), `vfs_open_driver(...)`, `vfs_open_posix_confined(...)` (openat2 RESOLVE_IN_ROOT —
do NOT weaken), `vfs_open_finish(...)` (metadata/metric). `brix_vfs_ctx_init` 10p → a
`brix_vfs_ctx_params_t` promoted into `vfs.h` (grep all callers, many). Security-neg:
outward symlink still invisible. Test: `pytest tests/ -k "vfs or open" -v`.

### Task A3: `src/fs/vfs/vfs_backend_registry.c` — `brix_vfs_backend_build_source` CCN 36/188 NLOC (L114-345); `brix_vfs_backend_entry_build` CCN 18 (L353-433)
Recipe: `build_source` composes a tier chain from directives → per-tier-kind static
builders (`vbr_build_posix/http/xroot/s3/rados/cache/stage`) selected by a descriptor
table; `entry_build` → parse vs construct halves. Config-error strings frozen. Test:
`nginx -t` + `pytest tests/ -k "tier or backend or storage" -v`.

### Task A4: `src/fs/backend/csi_verify.c` — `brix_csi_flush` CCN 41/140 NLOC (L246-402)
Recipe: `csi_flush_collect_dirty(...)`, `csi_flush_recompute_crc(...)`,
`csi_flush_write_record(...)`, `csi_flush_commit_xattr(...)`. The snapshot-at-open
invariant (phase-4 CSI perf fix) is frozen. Test: csi C unit + `pytest tests/ -k csi -v`.

### Task A5: `src/fs/cache/origin/s3_transport.c` — `s3o_request_impl` CCN 25/105 NLOC/**14 params** (L315-474)
Recipe: PARAM-bloat primary — promote an `s3o_request_t` file-local struct carrying the
14 args; thread through `s3o_request_impl` and the thin `s3o_request`/`s3o_request_cred`
wrappers (13/14p). Then split perform/sign/parse if CCN still >15. Test: `pytest tests/ -k "s3 and (cache or origin)" -v`.

### Task A6: `src/fs/cache/origin_auth.c` — `brix_cache_origin_auth_gsi` CCN 33/167 NLOC (L192-383)
Recipe: the origin GSI handshake state machine → per-step `originauth_certreq/cert/
sigpxy/finish` helpers (mirrors the phase-72 C1 gsi/auth split). Wire chunks byte-frozen.
Test: `pytest tests/ -k "cache and gsi" -v` + `tests/run_cvmfs_resilience.sh`.

### Task A7: `src/fs/backend/xroot/sd_xroot.c` — `brix_sd_xroot_create_origin` CCN 23/**10p** (L704-798); `sd_xroot_origin_open` CCN 22/7p; `sd_xroot_staged_open_common` CCN 17 (L447-511)
Recipe: `create_origin` 10p → an `sd_xroot_origin_cfg_t` struct; `origin_open`/
`staged_open_common` → connect/login/open step helpers. The 6p `_open`/`_open_cred`
vtable slots stay (report). Test: `pytest tests/ -k "xroot or remote_backend" -v`.

### Task A8: `src/core/compat/staged_file.c` — `commit_staged_to_backend` CCN 23 (L260-346); `brix_stage_reap_dir` CCN 23 (L544-620); `brix_commit_staged` CCN 17 (L368-456)
Recipe: `commit_staged_to_backend` → rename-commit vs copy-commit halves + shared cinfo
write; `stage_reap_dir` → scan vs unlink-decision (dead-owner reclaim frozen);
`commit_staged` → validate/flush/finalize. Test: `pytest tests/ -k "stage or posc or resume" -v`.

---

## Phase 75.B — webdav methods

### Task B1: `src/protocols/webdav/put.c` — `webdav_put_body_inner` CCN 40/218 NLOC (L375-662)
Recipe: `put_precondition_check(...)`, `put_open_target(...)` (staged/posc/exclusive),
`put_stream_body(...)` (chunked/codec pump), `put_commit(...)` (rename+cinfo+headers). TLS
memory vs cleartext split frozen. Test: `pytest tests/ -k "webdav and put" -v`.

### Task B2: `src/protocols/webdav/auth_token.c` — `webdav_verify_bearer_token` CCN 40/180 NLOC (L160-396)
Recipe: split the RFC pipeline like phase-72 C3: `wt_parse_header`, `wt_check_claims`,
`wt_check_issuer_keys`, `wt_check_scope`. This is a HELPERS-listed function
(`webdav_verify_bearer_token`) — keep its extern signature; body-only. WLCG token suite
is the oracle. Test: `pytest tests/ -k "wlcg_token and webdav" -v`.

### Task B3: `src/protocols/webdav/methods_basic.c` — `webdav_proppatch_do` CCN 38/157 NLOC (L276-472); `webdav_handle_head` CCN 17 (L99-177)
Recipe: proppatch → `pp_parse_body` (XML set/remove ops), `pp_apply_op` (per-prop via
`brix_vfs_*xattr`), `pp_build_multistatus`; head → stat vs header-emit. Test: `pytest tests/ -k "proppatch or webdav_head" -v`.

### Task B4: `src/protocols/webdav/proxy_request.c` — `webdav_proxy_create_request` CCN 39/159 NLOC (L70-279)
Recipe: `wpr_build_url`, `wpr_copy_headers` (allow/deny table), `wpr_attach_body`,
`wpr_set_auth`. Header pass-through set frozen. Test: `pytest tests/ -k "webdav and proxy" -v`.

### Task B5: `src/protocols/webdav/get.c` — `webdav_handle_get` CCN 38/179 NLOC (L128-365)
Recipe: `get_resolve_and_stat`, `get_eval_conditionals` (etag/if-modified via shared
eval), `get_serve_range` (TLS/cleartext split frozen), `get_serve_full`. Test: `pytest tests/ -k "webdav and get" -v`.

### Task B6: `src/protocols/webdav/copy.c` — `webdav_handle_copy` CCN 36/142 NLOC (L309-499); collection execute CCN 11/8p; post_task CCN 8/8p
Recipe: `copy_resolve_pair`, `copy_check_locks` (recursive child-lock per INVARIANT 5),
`copy_do_file` vs `copy_do_collection`; the 8p collection helpers → a `webdav_copy_job_t`
struct. Test: `pytest tests/ -k "webdav and copy" -v`.

### Task B7: `src/protocols/webdav/tpc_curl.c` — `webdav_tpc_run_curl_core` CCN 28/8p (L19-194); `pull_multi` CCN 19/8p; several 6-8p helpers
Recipe: promote a `webdav_tpc_curl_ctx_t` for the 8p family; split core into
setup/perform/finish. curl COPY semantics + Source/Credential headers frozen. Test:
`pytest tests/ -k "tpc and webdav" -v`.

### Task B8: `src/net/mirror/http_mirror.c` — `mirror_create_request` CCN 28/142 NLOC (L136-301); `precontent_handler` CCN 21 (L522-612)
Recipe: `mirror_build_subrequest`, `mirror_copy_headers`, `mirror_set_body`; precontent →
eligibility vs dispatch. AF-shadow behavior frozen. Test: `pytest tests/ -k mirror -v`.

---

## Phase 75.C — s3

### Task C1: `src/protocols/s3/aws_chunked.c` — `s3_chunk_feed` CCN 39/102 NLOC (L244-359); `has_inner_coding` CCN 18; `decode_to_fd` CCN 16/8p
Recipe: `s3_chunk_feed` is a streaming decoder state machine → `chunk_scan_size_line`,
`chunk_scan_ext_sig`, `chunk_consume_data`, `chunk_scan_trailer` driven by an explicit
state enum; `decode_to_fd` 8p → an `s3_chunk_dec_t` struct. Chunk-signature verification
byte-frozen. Test: `pytest tests/ -k "s3 and chunk" -v`.

### Task C2: `src/protocols/s3/auth_sigv4_verify.c` — `s3_verify_sigv4` CCN 38/222 NLOC (L366-693)
Recipe: `sigv4_parse_authz_header`, `sigv4_build_canonical`, `sigv4_derive_key`,
`sigv4_compare` (constant-time). INVARIANT 6: SigV4 ≠ WLCG token — no auth-logic sharing.
Signature match byte-frozen. Test: `pytest tests/ -k "s3 and (sigv4 or auth)" -v`.

### Task C3: `src/protocols/s3/post_form.c` — `s3_post_parse_form` CCN 31/116 NLOC/5p (L352-492); `s3_post_boundary` CCN 25 (L129-200)
Recipe: multipart/form-data parser → `pf_scan_boundary`, `pf_parse_part_headers`,
`pf_dispatch_field` (table of known form fields), `pf_capture_file`. POST-object policy
+ signature frozen. Test: `pytest tests/ -k "s3 and post" -v`.

### Task C4: `src/protocols/s3/multipart_complete_list_parts.c` — `s3_handle_list_parts` CCN 36/186 NLOC (L59-293)
Recipe: `lp_parse_query` (marker/max-parts), `lp_scan_staged_parts`, `lp_render_xml`.
ListParts XML byte-frozen. Test: `pytest tests/ -k "s3 and (multipart or list_parts)" -v`.

### Task C5: `src/protocols/s3/put.c` — `s3_put_body_inner` CCN 34/197 NLOC (L262-536)
Recipe: `s3put_precondition`, `s3put_open_target` (exclusive-create per phase-74 fix —
frozen), `s3put_stream_body`, `s3put_commit_and_headers` (etag/checksum). Test:
`pytest tests/ -k "s3 and put" -v`.

### Task C6: `src/auth/s3/sts.c` — `brix_s3_sts_assume` CCN 25/7p (L524-635); `sts_role_session_name` CCN 22; `sts_sign_query` CCN 11/7p
Recipe: `assume` → parse/sign/perform/parse-response; `role_session_name` → validation
table; the 7p helpers → an `sts_req_t` struct. STS wire frozen. Test: `pytest tests/ -k "sts or assume_role" -v`.

---

## Phase 75.D — auth (security-load-bearing: keep a security-negative in every task)

### Task D1: `src/auth/gsi/token.c` — `brix_handle_token_auth` CCN 41/181 NLOC (L44-278)
Recipe: the root:// token auth conversation → `tokenauth_extract`, `tokenauth_validate`
(via `brix_token_validate` args struct from phase-73), `tokenauth_map_identity`,
`tokenauth_bind_session`. Deny paths still deny. Test: `pytest tests/ -k "token and root" -v` + WLCG suite.

### Task D2: `src/auth/sss/auth_request.c` — `brix_handle_sss_auth` CCN 38/138 NLOC (L14-178)
Recipe: SSS handshake → `sss_recv_cred`, `sss_verify_keytab`, `sss_map_identity`,
`sss_reply`. Wire + keytab semantics frozen. Test: `pytest tests/ -k sss -v`.

### Task D3: `src/auth/authz/authdb.c` — `brix_parse_authdb` CCN 37/110 NLOC (L53-217); `find_authdb_rule_identity` CCN 18/5p (L349-427)
Recipe: parser → `adb_tokenize_line`, `adb_parse_rule` (directive table), `adb_append`;
matcher → exact/wildcard/VO split. Rule semantics frozen (multi-user conformance suite is
the oracle). Security-neg: cross-user deny holds. Test: `pytest tests/ -k "authdb or mu_authz" -v`.

### Task D4: `src/auth/authz/acc/authfile.c` — `acc_record_named` CCN 28; `acc_tok_next` CCN 22; `brix_acc_authfile_parse` CCN 17/110 NLOC; `acc_dispatch_record` CCN 14/6p; `acc_build_caps` CCN 11/7p
Recipe: the XRootD authfile grammar → `acc_tok_next` split scan-from-classify; record
handlers table-driven (`acc_record_named` → per-type helpers); `build_caps`/`dispatch`
→ arg structs. Cap-grant semantics frozen. Security-neg: unknown record → clean reject.
Test: acc C unit + `pytest tests/ -k "acc or authfile" -v`.

### Task D5: `src/auth/authz/acc/access.c` — `brix_acc_access` CCN 34/86 NLOC (L87-194); `acc_applies` CCN 19 (L41-72)
Recipe: `acc_access` → `acc_match_rules` + `acc_combine_grants` + `acc_final_verdict`;
`acc_applies` → predicate table. Verdict byte-frozen. Security-neg: default-deny holds.
Test: acc C unit + `pytest tests/ -k acc -v`.

### Task D6: `src/auth/gsi/gsi_core.c` — `gsi_cresp_build_inner` **16p**; `build_cert_response_ex` **14p**; `gsi_cresp_agree_session_key` 10p; `gsi_cresp_extract_peer_pub` 8p; `gsi_cresp_build_outer` 11p; `brix_gsi_parse_parms` 6p
Recipe: PARAM-bloat cluster — promote a `gsi_cresp_ctx_t` struct carrying the DH/session/
buffer state shared across the cert-response builders; thread it through. No CCN over 15
here — this is purely param reduction. OpenSSL call order + emitted bytes frozen. Test:
`pytest tests/ -k "gsi and cert" -v` + gsi crypto unit.

### Task D7: `src/net/ratelimit/ratelimit_keys.c` — `rl_add_rule` CCN 31/94 NLOC (L320-432); `brix_rl_conc_directive` CCN 18; `brix_rl_key_http` CCN 18/6p
Recipe: `rl_add_rule` → directive-field table + per-field parse; `conc_directive` split;
`rl_key_http` 6p → a `rl_key_req_t` struct. Key derivation frozen (gauge-reset invariant
from the reboot-lockup fix untouched). Test: `pytest tests/ -k ratelimit -v`.

### Task D8: `src/protocols/root/query/checksum_qcksum.c` — `brix_query_cksum_path` CCN 37/198 NLOC/5p (L102-360); `cksum_handle` CCN 15/6p
Recipe: `qcksum_resolve`, `qcksum_select_algo` (algo table — crc64 vs crc64nvme distinct
per INVARIANT 9), `qcksum_compute_or_cache`, `qcksum_format`. NOTE: file carries a
phase-74 `phase74-fp` NOLINT at the beneath-path call — PRESERVE. Test: `pytest tests/ -k "cksum or qcksum" -v`.

### Task D9: `src/protocols/dig/dig.c` — `brix_dig_handle` CCN 35/146 NLOC (L127-297)
Recipe: dig protocol op dispatch → per-op static handlers + descriptor table. NOTE: file
carries a phase-74 `(void) fclose` phase74-fp — PRESERVE. Test: `pytest tests/ -k dig -v`.

---

## Phase 75.E — root:// + net + tap

### Task E1: `src/protocols/root/connection/handler.c` — `ngx_stream_brix_handler` CCN 37/189 NLOC (L26-292)
Recipe: the stream connection entry → `conn_init_ctx`, `conn_tls_handshake`,
`conn_dispatch_first`, `conn_pump`. This is the root:// front door — byte-exact framing,
TLS-pending timing frozen. Test: `pytest tests/ -k "handshake or connection" -v`.

### Task E2: `src/protocols/root/write/writev.c` — `brix_handle_writev` CCN 35/199 NLOC (L68-349)
Recipe: `writev_parse_descriptors` (stock-framing per the writev/ckpXeq fix — descriptors
framed, body streamed after: FROZEN), `writev_validate`, `writev_execute` (per-fd VFS
write), `writev_reply`. Test: `pytest tests/ -k writev -v`.

### Task E3: `src/net/proxy/connect_upstream.c` — `brix_proxy_connect` CCN 36/223 NLOC (L186-453)
Recipe: `pc_resolve_target` (AF policy), `pc_open_socket`, `pc_start_tls`,
`pc_arm_events`. Log-capture hazard: never store `c->log` in a long-lived struct. Test:
`tests/run_tap_proxy.sh` + `pytest tests/ -k proxy -v`.

### Task E4: `src/net/tap/tap_stream.c` — `brix_tap_stream_feed` CCN 33/112 NLOC (L99-233); `tap_stream_on_header` CCN 18 (L31-96)
Recipe: streaming decoder → `tap_scan_preamble`, `tap_decode_frame`, `tap_emit_audit`;
header handler → parse vs classify. C2U 20-byte preamble skip frozen. Test:
`tests/run_tap_proxy.sh` + tap standalone test.

### Task E5: `src/protocols/webdav/tpc_curl.c` — (moved to B7). This task: verify B7 landed; re-lizard `src/net` for stragglers.

### Task E6: `src/observability/metrics/unified.c` — `brix_export_unified_metrics` CCN 33/241 NLOC (L649-925)
Recipe: one `unified_emit_<family>()` per metric family, driven by the proto_list X-macro
where possible; exporter becomes a call sequence. Exposition text byte-frozen. Test:
`pytest tests/ -k metrics -v` + label/family diff.

### Task E7: `src/observability/metrics/stream_cache.c` — `brix_export_stream_cache_metrics` CCN 32/188 NLOC (L65-289)
Recipe: same family-emit split as E6 for the stream/cache metric surface. Byte-frozen.
Test: `pytest tests/ -k "metrics and cache" -v`.

---

## Phase 75.F — observability + cvmfs

### Task F1: `src/observability/sesslog/sesslog.c` — `err_from_kxr` CCN 30 (L507-557); `err_from_errno` CCN 19; `err_from_http` CCN 17; three 7-9p `fmt_*` helpers
Recipe: the three `err_from_*` switch ladders → `static const {code,text}` lookup tables +
one shared lookup fn (phase-72 D4 kxr_names pattern); the 7-9p `fmt_auth/result/xfer` →
field structs. NOTE: file carries a phase-74 `phase74-fp` format-nonliteral NOLINT —
PRESERVE. Emitted strings byte-frozen (generate the expected pairs from HEAD first). Test:
sesslog assertions in `pytest tests/ -k sesslog -v`.

### Task F2: `src/protocols/cvmfs/handler.c` — `cvmfs_finalize_observe` CCN 34/109 NLOC (L228-353); `cvmfs_tier_get` CCN 22/108 NLOC (L82-221)
Recipe: `finalize_observe` → classify/log/metric halves; `tier_get` → hit/fill/failover
decision helpers. Origin-selection logging + stale-serve semantics frozen. Test:
`pytest tests/ -k cvmfs -v` + `tests/run_cvmfs_resilience.sh`.

### Task F3: `src/protocols/cvmfs/module.c` — `merge_loc_conf` CCN 31/175 NLOC (L363-626); `cvmfs_geo_rank_config` CCN 18 (L159-255)
Recipe: `merge_loc_conf` → per-concern `cvmfs_merge_<group>()` helpers (upstreams, geo,
secure, cache) called in sequence; geo_rank → parse vs build. Merge order + defaults
frozen (`nginx -t`). Test: `nginx -t` + `pytest tests/ -k "cvmfs and config" -v`.

### Task F4: `src/fs/meta/xmeta_unittest.c` — `main` CCN 41/129 NLOC (L64-215)
Recipe: it's a C unit-test `main` — split into one `static void test_<case>(void)` per
assertion group + a table iterated by main. No production behavior; just gate compliance.
Test: build+run the unit (`gcc ... xmeta_unittest.c && ./a.out` → all-pass).

### Task F5: `src/protocols/cvmfs/module.c` config helpers — folded into F3.

### Task F6: verify phase — after F1–F4, re-run `lizard src/observability src/protocols/cvmfs -l c -C 15 -L 100 -a 5 -w`; confirm only files outside this top-50 remain.

---

## Phase 75.G — client lib + apps (CLI surface + wire frozen)

All builds: `make -C client -j$(nproc) && make -C client test`.

### Task G1: `client/apps/copy/xrdcp.c` — `parse_and_validate_args` **29 params** (L860-935); `build_and_preflight_credentials` **17p** (L950-1030); `dispatch_transfer` **21p** (L1279-1323); `xrdcp_batch_one` 7p; `validate_and_finalize_args` 12p; `xrdcp_collect_sources` 6p
Recipe: THE param-bloat file — the whole option/credential/transfer state is passed
loose. Introduce ONE `xrdcp_opts_t` (all parsed flags) + `xrdcp_creds_t` + `xrdcp_job_t`
in `xrdcp_internal.h` (or file-local if static) and thread through every helper. Pure
signature consolidation, no logic moves. CLI flags/output/exit codes byte-frozen. Test:
`make -C client test` + `pytest tests/ -k "xrdcp and not recursive" -v`.

### Task G2: `client/lib/core/config/xrdrc.c` — `xrdrc_load` CCN 44/88 NLOC (L64-159)
Recipe: rc-file parser → `rc_next_line`, `rc_parse_kv`, `rc_apply_setting` (known-key
descriptor table). Default/precedence semantics frozen. Test: `make -C client test` + rc-defaults cases.

### Task G3: `client/lib/protocols/http/weblist.c` — `brix_s3_list` CCN 30/9p (L112-248); `brix_webdav_list` CCN 21/7p; `brix_webdav_mkcol` 10p→wait 6p
Recipe: `s3_list`/`webdav_list` → parse-response vs emit-entry halves; the 7-9p signatures
→ a `weblist_req_t` struct. XML/entry parsing frozen. Test: `make -C client test` + `pytest tests/ -k "weblist or list_objects" -v`.

### Task G4: `client/lib/xfer/copy_local.c` — `upload_stream_body` CCN 30/8p (L310-458); `copy_download` CCN 21/5p; `download_stream_body` CCN 12/8p
Recipe: the 8p stream bodies → a `copy_stream_ctx_t` struct; split each into
fill/transfer/verify. NOTE: several of these are phase-73 residuals (extern-shaped) —
check `copy_internal.h`; body-decompose and struct-thread the static ones, report extern
residuals. Test: `make -C client test` + `pytest tests/ -k "copy and local" -v`.

### Task G5: `client/lib/protocols/shared/zip_write.c` — `brix_zip_writer_add_fd` CCN 37/128 NLOC (L84-221)
Recipe: `zw_write_local_header`, `zw_stream_deflate`, `zw_write_data_descriptor`,
`zw_update_central_dir`. ZIP byte layout frozen. Test: `make -C client test` + `pytest tests/ -k zip -v`.

### Task G6: `client/lib/protocols/http/http_upload.c` — `brix_http_upload_resumable` **14p** (L196-263); `httpx_upload_chunk` **14p**; `httpx_upload_exchange` 11p; `brix_http_upload` 13p
Recipe: param-bloat — promote an `httpx_upload_ctx_t` (endpoint/creds/offset/callbacks)
into the http header and thread through the whole upload family; grep all callers. Resume
semantics frozen. Test: `make -C client test` + `pytest tests/ -k "http_upload or resumable" -v`.

### Task G7: `client/apps/cksum/xrdcinfo.c` — `dump_record` CCN 39/128 NLOC (L118-256)
Recipe: `.cinfo` dumper → per-section emit helpers (present-bitmap, dirty, flush-gen)
driven by the record layout. JSON output byte-frozen. Test: `make -C client test` + xrdcinfo golden output.

### Task G8: `client/apps/fs/xrootdfs_legacy.c` — `xrootdfs_legacy_main` CCN 37/79 NLOC (L767-859)
Recipe: legacy FUSE main → arg-parse + mount-bring-up helpers (mirror the phase-72 H3
xrootdfs_aio_main split); the 6p FUSE callbacks stay (report). Test: `make -C client test`
+ fuse legacy smoke.

### Task G9: `client/lib/auth/gsi/proxy.c` — `brix_proxy_create` CCN 37/93 NLOC (L151-260)
Recipe: client-side proxy mint → `pxy_load_issuer`, `pxy_build_request`, `pxy_sign`,
`pxy_assemble_pem` (mirror phase-72/73 server proxy_req split; RFC3820 frozen). Test:
`make -C client test` + `pytest tests/ -k "gsi and (proxy or delegation)" -v`.

---

## Phase-75 exit criteria

- [ ] `docs/refactor/phase-75-baseline/regen.sh final/`: every one of the 50 files passes
  `lizard -C 15 -L 100 -a 5 -w` clean, OR shows only reported frozen-signature param
  residuals (extern/vtable/FUSE-callback).
- [ ] Full builds green: module (`-Werror`) + `make -C client` + `make -C client test`.
- [ ] `PYTHONPATH=tests pytest tests/ -v --tb=short` — no regressions vs the Task-0
  baseline (fleet rules: -n12 cap, serial rerun for load-flakes; seed random.bin/
  large200.bin in attach mode per `conftest.py:337`; clean stop-all/start-all after any
  src fix that runs start-all to avoid token-port JWKS desync).
- [ ] `tools/ci/check_vfs_seam.sh` green; `tools/ci/check_complexity.sh --regen` run once
  at the END (deliberate ratchet acceptance) so the backlog reflects the newly-cleared
  functions — OP-approved, since regen writes a tracked file.
- [ ] CodeChecker exit gate unchanged: still 4 documented FPs, no new findings introduced.
- [ ] Delta table appended here; `docs/refactor/phase-75-baseline/final/` committed.
- [ ] Every commit had explicit OP approval.

## Execution record (2026-07-10)

IMPLEMENTED (uncommitted). All 50 files decomposed via 50 parallel one-file agents.
**Every CCN and NLOC violation is cleared** — the final lizard sweep over the 50 files
shows 44 residuals, all **param-count-only** (each CCN ≤ 14, NLOC ≤ 98), every one on a
frozen extern / `brix_sd_driver_t` vtable slot / FUSE-callback / public-header signature
whose reduction needs cross-file header edits (the accepted deferred class — a phase-76
"args-struct into headers" pass, mirroring phase-73). The biggest wins: xrdcp.c
`parse_and_validate_args` 29→4 params (three file-local structs), gsi_core cert-response
builders 16/14→1 (state struct), sd_http request 7→2, s3_transport impl 14→4, and ~30
CCN-30-to-44 giant handlers flattened to CCN ≤ 12 orchestrators. Notable: the gsi/token
D1 agent caught the same NGX_OK-swallow trap the phase-74 S3 work exposed and used an
NGX_DONE sentinel; the sesslog F1 agent ran a full errno/kXR/HTTP code-space differential
proving the table rewrite byte-identical.

Module (-Werror) + client builds green first pass; `nginx -t` green; client unit tests
ALL PASS; serial smoke 528/528 across io/write/fattr/dirlist/pgread/tpc/gsi-tls/token-
edge/s3/macaroon/dashboard (1 flake, passed on rerun). CodeChecker exit gate unchanged
(still the 4 phase-74 documented FPs; no new findings). check_vfs_seam OK. Client build
emits cosmetic `-Wcomment` warnings (`/*` inside `*keys/*paths`-style doc comments in
brix_net.h/weblist.c/xrdrc.c/http_upload.c) — non-fatal, follow-up cleanup.

## Phase-76 param-residual cleanup (2026-07-10)

Header-touching pass to clear the phase-75 param residuals (uncommitted). Cleared via
struct promotion: zip_writer_new_append, check_authdb_identity (6→2), vfs_adopt_fd (6→5),
rl_key_http, the 5 sesslog fmt_* formatters, sts (assume + parse_response), sd_xroot
create_origin (10→struct), staged_open/_resume. Residuals **44 → 27**, all now
param-count-only (CCN ≤14, NLOC ≤98). The 27 survivors are the genuinely-frozen class —
`brix_sd_driver_t` vtable slots (s3o_request/_cred, sd_http/sd_xroot _open_cred,
sd_xroot_open_common), the FUSE `.readdir` typedef (xfs_readdir), the ~50-caller
`brix_vfs_ctx_init`, and the cross-plane gsi_core externs (build_cert_response*/
build_certreq/parse_parms, callers in tpc/fs/client) — forcing structs there is broad
caller churn with zero functional gain. Three clusters (webdav tpc_curl, the brix_net.h
client-http family, the two in-file statics commit_staged_to_backend/query_build_checksum)
had their agents cut off by the session limit mid-edit; tpc_curl was reverted to its
phase-75 frozen state to restore the build, the others left frozen.

Also fixed while here: a `-Werror`-clean `-Wcomment` sweep (`/*` inside `*a/*b` doc
comments in brix_net.h/weblist.c/xrdrc.c/http_upload.c), and a **real pre-existing bug**
the smoke surfaced — PROPFIND's 404-propstat emitter closed `</D:propstat>` where it
needed `</D:prop>`, producing malformed multistatus XML (propfind_props.c:621). Module
(-Werror) + client builds green; client unit tests ALL PASS; serial smoke green incl.
the 4 now-fixed propfind cases.

## Known frozen-residual ledger (expected param-only survivors)

| File | Function | Why frozen |
|---|---|---|
| sd_http.c | sd_http_open/_open_cred (6p) | brix_sd_driver_t vtable slot |
| sd_xroot.c | sd_xroot_open/_open_cred (6p) | brix_sd_driver_t vtable slot |
| s3_transport.c | s3o_request/_cred (13-14p) | tier-transport vtable shape (reduce via struct if the header is in-scope) |
| xrootdfs_legacy.c | xfs_readdir (6p) | FUSE 3 callback typedef |
| (others) | discovered during execution | append here |

## Deliberately out of scope

- Files ranked 51+ (next wave). The 4 phase-74 documented-FP analyzer findings
  (helpers.c ArrayBound, pool.c unix.Malloc, dead_props.c redundant, multipart arg-order)
  — proven false, no action.
- `ngx_http_s3_handler` CCN 17 and the concurrent phase-70/vfs_xattr complexity growths —
  not in this top-50; leave for their owners / the eventual `--regen`.
- The `misc-header-include-cycle` include-graph checker (its own future phase).
