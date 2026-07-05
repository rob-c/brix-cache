# context.h `brix_ctx_t` Sub-struct Migration Implementation Plan

> **For agentic workers:** This plan is executed **inline, without git** (per user standing instruction "don't use git"). Each task's checkpoint is **build + `nginx -t` + targeted test run**, NOT a commit. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose the flat 556-line `brix_ctx_t` per-connection runtime struct (`src/core/types/context.h`) into named concern sub-structs (e.g. `ctx->gsi.sess_key`, `ctx->recv.payload`, `ctx->out.pipeline_depth`) so a reviewer can navigate it by concept instead of a wall of ~100 fields — mirroring the completed `config.h` grouping, but on hot-path runtime state.

**Architecture:** Pure mechanical field-grouping. Each concern's fields move into a `typedef struct { ... } brix_ctx_<group>_t;` (defined in a new `src/core/types/ctx_structs.h`, included by `context.h` before `brix_ctx_t`), and every `ctx-><field>` reference is rewritten to `ctx-><group>.<field>`. Semantics are identical; the compiler is the primary correctness oracle (a missed rename → "no member named" error). No behavior changes, no new allocations, no wire changes.

**Tech Stack:** C, nginx stream module, GNU `sed`/`grep` (note: the shell's `grep` is **ugrep** — see Global Constraints). Build tree at `/tmp/nginx-1.28.3`.

## Global Constraints

- **NO GIT.** Never run any git command. Checkpoints are build + `nginx -t` + tests, not commits.
- **`grep` is `ugrep` on this host.** A pattern starting with `->` is parsed as an option and errors (silently yielding an empty result → seds skip). ALWAYS use `grep -rlE -e "[-]>..."` for `->`-anchored searches.
- **Target the ctx pointer, not the field alone.** Some `brix_ctx_t` field names ALSO exist on `ngx_stream_brix_srv_conf_t` (`pipeline_depth`: ctx 18 / conf 7; `gsi_signed_dh`: ctx 2 / conf 5). The migration sed MUST match `<ctxvar>-><field>`, never a bare `->field`. The ctx pointer variable is `ctx` (488 decls), plus rare `client_ctx` (2) and `xrd_ctx` (1) — handle all three.
- **CRITICAL: the variable name `ctx` is OVERLOADED across struct types.** The webdav (`ngx_http_brix_webdav_req_ctx_t`) and S3 request-ctx planes also name their pointer `ctx`, and share field names with `brix_ctx_t` (e.g. `token_auth`, `token_scopes`). A `\bctx->field` match is therefore NOT sufficient — it can hit a non-`brix_ctx_t` `ctx`. **Per-group R4 file selection MUST intersect {files with the ref} with {files that declare `brix_ctx_t *<var>`}**: `for f in <hits>; do grep -qE '(brix_ctx_t)\s*\*\s*ctx\b' "$f" && echo "$f"; done` (repeat for client_ctx/xrd_ctx). Exclude any file whose `ctx` is `ngx_http_brix_webdav_req_ctx_t`/`ngx_http_brix_s3_req_ctx_t`. `\bctx` does NOT match `rctx` (word boundary), so `rctx`-named webdav ctx is already safe; the danger is only same-named `ctx` on a different struct.
- **Verify BEFORE building.** After each group's sed, grep for flat `<ctxvar>->cur_<field>` remainders and confirm zero (a half-applied sed leaves the struct nested but call-sites flat → won't build; catch it early). Then build.
- **Build is the oracle, tests are the safety net.** For a pure rename, a clean compile of all 156 consumer files proves completeness. Because this is hot-path runtime state, ALSO run the relevant pytest subset after each group and the fast suite after the hot groups.
- **File-size guard:** after moving typedefs into `ctx_structs.h` and shrinking `context.h`, run `tools/ci/check_file_size.sh --regen` and confirm green. `context.h` may stay >500 (large struct is legit, like config.h).
- **Coding standard:** `docs/09-developer-guide/coding-standards.md` — no `goto`, section doc-blocks on the new sub-structs, consistent formatting.
- **Registration:** `ctx_structs.h` must be added to `./config`'s `context.h` dependency line(s). A new HEADER (not `.c`) still needs `./configure` for dep tracking to take effect; a change to `context.h` itself triggers consumer rebuilds via `make`.

---

## Background & Risk Profile

`brix_ctx_t` is the per-connection state machine struct, dereferenced on every hot path: **~2939 `ctx->` references across 156 files**. Unlike `config.h` (config-time, loud failure on error), a mis-migration here could in principle compile yet misbehave — but only if a rename is *wrong*, not *missed* (missed → compile error). A field rename `ctx->x → ctx->g.x` is semantically identical, so the risk is bounded to: (a) accidentally rewriting a same-named field on a *different* struct (mitigated by the ctx-pointer-anchored sed + exact-name collision check), or (b) leaving a stale reference (mitigated by build-as-oracle). Tests are the backstop for anything subtle.

Order groups **coldest/smallest → hottest/largest** so the recipe is battle-tested before touching the recv/read/output pipeline.

---

## Grouping Design

**Single-field / trivially-local fields stay FLAT** (not worth a wrapper, consistent with the config.h decision on 2-field groups): `session`, `state`, `identity`, `metrics`, `destroyed`, `tls_pending`, `upstream`, `proxy`, `proxy_fail_count`, `bearer_token`, `wmirror`, `cms_wait_streamid`, `write_rc`, `req_start`, `budget_charged`, `handoff`, `relay`, `is_bound`/`pathid`/`bound_sessid` (bind — keep flat, only 3 and touched in few places), `protocol_label`/`ip_version`, `files[]`.

**14 concern groups** (member name → fields, current line refs in `context.h`):

| # | Member | Fields (drop the group prefix where present) | Heat |
|---|---|---|---|
| G1 | `pwd` | `pwd_session_key→session_key`, `pwd_round→round`, `pwd_user→user` | cold (login only) |
| G2 | `token` | `token_auth→auth`, `token_scope_count→scope_count`, `token_scopes→scopes` | warm |
| G3 | `throttle` | `throttle_open_held→open_held`, `throttle_conn_counted→conn_counted` | warm |
| G4 | `deadline` | `read_deadline_armed→read_armed`, `send_deadline_armed→send_armed`, `read_timeout_ms→read_ms`, `handshake_timeout_ms→handshake_ms`, `send_timeout_ms→send_ms` | warm |
| G5 | `totals` | `session_bytes→bytes`, `session_bytes_written→bytes_written`, `session_bytes_tx_ipv4→bytes_tx_ipv4`, `session_bytes_rx_ipv4→bytes_rx_ipv4`, `session_bytes_tx_ipv6→bytes_tx_ipv6`, `session_bytes_rx_ipv6→bytes_rx_ipv6`, `session_start→start` | warm |
| G6 | `prepare` | `prepare_reqid→reqid`, `prepare_paths→paths`, `prepare_paths_len→paths_len`, `stage_async_active→stage_async_active`, `stage_async_streamid→stage_async_streamid` | cold |
| G7 | `pmark` | `pmark_flow→flow`, `pmark_echo_ev→echo_ev`, `pmark_echo_ms→echo_ms` | warm |
| G8 | `sigver` | `signing_key→signing_key`, `signing_active→signing_active`, `last_seqno→last_seqno`, `sigver_pending→pending`, `verified_signing→verified`, `sigver_expectrid→expectrid`, `sigver_seqno→seqno`, `sigver_nodata→nodata`, `sigver_hmac→hmac`, `sigver_mac→mac`, `sigver_mac_ctx→mac_ctx` | warm |
| G9 | `gsi` | `gsi_dh_key→dh_key`, `gsi_signed_dh→signed_dh` **(collides w/ conf)**, `gsi_sess_cipher→sess_cipher`, `gsi_sess_key→sess_key`, `gsi_sess_keylen→sess_keylen`, `gsi_sess_use_iv→sess_use_iv`, `gsi_deleg_reqkey→deleg_reqkey`, `gsi_clnt_opts→clnt_opts`, `gsi_deleg_await→deleg_await`, `gsi_deleg_chain_pem→deleg_chain_pem`, `gsi_deleg_chain_len→deleg_chain_len`, `gsi_deleg_proxy_pem→deleg_proxy_pem`, `gsi_deleg_proxy_len→deleg_proxy_len`, `gsi_deleg_client_rtag→deleg_client_rtag`, `gsi_deleg_client_rtag_len→deleg_client_rtag_len`, `gsi_counted→counted` | warm |
| G10 | `rl` (rate limit) | `rl_bw_rule→bw_rule`, `rl_bw_key→bw_key`, `rl_conc_rule→conc_rule`, `rl_conc_key→conc_key`, `rl_key_cache→key_cache`, `rl_key_cache_valid→key_cache_valid` | hot |
| G11 | `login` | `sessid`, `logged_in`, `auth_done`, `login_user`, `login_pid`, `auth_fail_count`, `pool_bytes_used`, `dn`, `primary_vo`, `vo_list`, `peer_ip`, `acc_host`, `acc_host_done` | hot |
| G12 | `recv` | `hdr_buf`, `hdr_pos`, `cur_streamid`, `cur_reqid`, `cur_body`, `cur_dlen`, `cur_body_extra`, `cur_body_extended`, `payload`, `payload_pos`, `payload_buf`, `payload_buf_size`, `recv_deferred` | **hottest** |
| G13 | `out` (output pipeline) | `pipeline_depth` **(collides w/ conf)**, `out_ring`, `out_head`, `out_tail`, `out_count`, `resp_pipelinable`, `wr_inflight`, `resp_async`, `finalize_pending`, `finalize_status` | **hottest** |
| G14 | `rd` (read pipeline/scratch) | `read_scratch`, `read_scratch_size`, `read_hdr_scratch`, `read_hdr_scratch_size`, `write_scratch`, `write_scratch_size`, `cmp_scratch`, `cmp_scratch_size`, `read_aio_task`, `pgread_aio_task`, `readv_aio_task`, `rd_pool`, `rd_inflight`, `rd_backpressured`, `rd_win_active`, `rd_win_idx`, `rd_win_fd`, `rd_win_offset`, `rd_win_remaining`, `rd_win_streamid` | **hottest** |

> Naming note: where the group name equals a field prefix (e.g. `pwd_*`, `gsi_*`, `rl_*`, `throttle_*`, `token_*`, `pmark_*`, `session_*`), drop the prefix. Where fields have no shared prefix (G11 `login`, G13 `out`, G14 `rd`) keep the field name as-is under the new member. `rd_win_*`/`rd_pool`/`rd_inflight` already share `rd_` — under member `rd` they become `rd.win_*`/`rd.pool`/`rd.inflight` (drop `rd_`); `read_*`/`write_scratch`/`cmp_*`/`*_aio_task` keep their names under `rd`.

---

## The Uniform Per-Group Migration Recipe

Every task (G1–G14) follows this exact procedure. It is the proven `config.h` recipe adapted for a runtime struct.

**R1 — Collision check (MANDATORY, per group):** For every exact field name in the group, confirm it appears only on ctx-typed pointers:
```bash
FIELDS='fieldA|fieldB|...'   # exact current field names
grep -rlE -e "[-]>(${FIELDS})\b" src --include='*.c' --include='*.h' \
  | xargs grep -nE -e "[-]>(${FIELDS})\b" \
  | grep -vE '\b(ctx|client_ctx|xrd_ctx)->' || echo "CLEAN: ctx-only"
```
If any non-ctx pointer appears (e.g. `conf->gsi_signed_dh`), the sed MUST be pointer-anchored to `ctx`/`client_ctx`/`xrd_ctx` only (never a bare `->field`). Note which fields collide.

**R2 — Add the sub-struct** to `src/core/types/ctx_structs.h` (create it in G1; append in G2+). Guarded `BRIX_TYPES_CTX_STRUCTS_H`, doc-block per struct. Included by `context.h` right before `brix_ctx_t` (after `context.h`'s own includes, same TU position the fields occupy now — so all member types like `EVP_PKEY`, `ngx_thread_task_t`, `brix_token_scope_t`, `brix_read_slot_t`, `brix_resp_slot_t`, `ngx_event_t` are already available).

**R3 — Replace the flat fields** in `brix_ctx_t` with the single member `brix_ctx_<group>_t <member>;`.

**R4 — Migrate call sites** across the ctx-pointer variables (longest field names first, `\b`-anchored, per-field mapping when prefixes are mixed):
```bash
files=$(grep -rlE -e "[-]>(${FIELDS})\b" src --include='*.c' --include='*.h')
for f in $files; do
  sed -i -E \
    -e 's/\b(ctx|client_ctx|xrd_ctx)->OLDFIELD\b/\1->MEMBER.NEWFIELD/g' \
    ... (one -e per field, longest-first) \
    "$f"
done
```

**R5 — Verify no flat remainder:**
```bash
grep -rnE -e "[-]>(${FIELDS})\b" src --include='*.c' --include='*.h' \
  | grep -vE '\b(conf|prev|xcf|mconf)->' || echo "NONE — all ctx refs migrated"
```
(Excludes srv_conf pointers for the colliding fields, which correctly stay flat.)

**R6 — Build:** `cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | grep -iE 'error:' | grep -ivE 'clock skew|modification time'` → expect none, `make exit: 0`.

**R7 — Targeted test + parse:** `PYTHONPATH=tests pytest tests/ -k "<area>" -q` for the group's area, plus a plain `nginx -t` smoke. Hot groups (G10–G14) additionally run `tests/run_suite.sh --fast`.

---

## Tasks

### Task 0: Scaffold `ctx_structs.h` + register

**Files:**
- Create: `src/core/types/ctx_structs.h`
- Modify: `src/core/types/context.h` (add `#include "ctx_structs.h"` before `brix_ctx_t`)
- Modify: `config` (add `ctx_structs.h` to the `context.h` dep line)

- [ ] **Step 1:** Create `ctx_structs.h` with the guard + a leading doc-block (mirror `conf_structs.h`: "not self-contained; included by context.h after its prereq includes; include context.h, not this"). Empty body for now.
- [ ] **Step 2:** Add `#include "ctx_structs.h"` in `context.h` immediately before `typedef struct { ... } brix_ctx_t;` (bare, same dir).
- [ ] **Step 3:** `grep -nE '/src/core/types/context\.h' config` → add a `ctx_structs.h` line beside it.
- [ ] **Step 4:** `./configure … && make -j$(nproc)` → exit 0 (no-op struct-wise, proves wiring).
- [ ] **Step 5 (checkpoint):** `nginx -t` on a minimal stream config → successful.

### Tasks G1–G14: one per group, each applying R1–R7

For each group in the order **G1 pwd → G2 token → G3 throttle → G4 deadline → G5 totals → G6 prepare → G7 pmark → G8 sigver → G9 gsi → G10 rl → G11 login → G12 recv → G13 out → G14 rd**:

- [ ] **Step 1 (R1):** Run the collision check for the group's exact field names. Record collisions (known: G9 `gsi_signed_dh`, G13 `pipeline_depth`).
- [ ] **Step 2 (R2):** Append `brix_ctx_<group>_t` to `ctx_structs.h` with a WHAT/WHY doc-block and the fields (prefix dropped per the naming note).
- [ ] **Step 3 (R3):** Replace the flat field block in `brix_ctx_t` with the single member. (For groups whose fields are non-contiguous — G5/G6/G8/G9/G13/G14 have interspersed comments — replace each field's line; keep the section's lead comment as a one-liner above the member.)
- [ ] **Step 4 (R4):** Run the per-field, ctx-anchored sed across the file set.
- [ ] **Step 5 (R5):** Verify zero flat ctx remainders (srv_conf `conf->`/`prev->` stay flat for colliding fields).
- [ ] **Step 6 (R6):** Build → exit 0, no `error:`.
- [ ] **Step 7 (R7 checkpoint):** Targeted pytest for the area + `nginx -t`. For G10–G14 also `tests/run_suite.sh --fast`. Then `tools/ci/check_file_size.sh --regen`.

**Per-group area hints for the pytest `-k` filter (Step 7):**
G1 `pwd`; G2 `token`; G3 `throttle`; G4 `timeout or resilience`; G5 `accesslog or metrics`; G6 `prepare or stage`; G7 `pmark or scitag`; G8 `sigver or signing`; G9 `gsi or delegation`; G10 `ratelimit`; G11 `auth or login`; G12 `read or write or framing` (broad — pair with `run_suite.sh --fast`); G13 `pipeline or read`; G14 `read or readv or pgread`.

### Task 15: Final full verification

- [ ] **Step 1:** `grep -rlE -e '[-]>(ctx|client_ctx|xrd_ctx)->[a-z_]+'` sanity: confirm remaining flat ctx fields are exactly the intended-flat set from "Grouping Design".
- [ ] **Step 2:** `./configure && make -j$(nproc)` clean from scratch → exit 0.
- [ ] **Step 3:** `tests/run_suite.sh --pr` (the <5min gate) → green.
- [ ] **Step 4:** `xrdcp` round-trip smoke (root:// in + out, byte-identical) per coding-standards §10.
- [ ] **Step 5:** `tools/ci/check_file_size.sh --regen`; record final `context.h` and `ctx_structs.h` LOC.

---

## Verification Strategy

- **Primary oracle:** clean compile of all 156 consumers (missed/wrong rename → hard error).
- **Runtime backstop:** per-group targeted pytest; fast suite after each hot group (G10–G14); `--pr` gate + xrdcp smoke at the end.
- **Guard:** `check_file_size.sh` stays green throughout.

## Rollback Strategy (no git)

Work group-by-group; the tree is always buildable between groups. If a group's build fails and the fix isn't obvious within 2 attempts, revert THAT group only by reversing its sed (swap `MEMBER.NEWFIELD` → `OLDFIELD` on the same file set) and restoring the flat fields in `brix_ctx_t`/`ctx_structs.h`, returning to the last green state. Never proceed to the next group on a red build.

## Self-Review Notes

- **Coverage:** every non-flat field in `brix_ctx_t` (lines 86–642) is assigned to exactly one of G1–G14; the explicitly-flat list covers the remainder. No field is in two groups.
- **Collisions flagged:** G9 `gsi_signed_dh`, G13 `pipeline_depth` (both also on srv_conf) — mitigated by ctx-pointer-anchored seds + R1 check.
- **Naming consistency:** member names are unique (`pwd`,`token`,`throttle`,`deadline`,`totals`,`prepare`,`pmark`,`sigver`,`gsi`,`rl`,`login`,`recv`,`out`,`rd`); none collide with an existing flat ctx field or with the `common`/sub-struct names already on `brix_ctx_t` (there are none — brix_ctx_t currently embeds only `brix_file_t files[]`, `brix_resp_slot_t *out_ring`, `brix_read_slot_t *rd_pool`, `ngx_event_t pmark_echo_ev` — note `pmark_echo_ev` moves under `pmark`, and `out_ring`/`rd_pool` move under `out`/`rd`).
