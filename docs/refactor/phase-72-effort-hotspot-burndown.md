# Phase 72 — Effort-Hotspot Burndown (top-50 lizard + CodeChecker files)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive the 50 highest fix-effort files (measured 2026-07-09 by lizard complexity
debt + severity-weighted CodeChecker findings) down to zero analyzer HIGH/MEDIUM findings
and zero functions over the complexity gate (CCN ≤ 15, fn NLOC ≤ 100, params ≤ 5), without
behavior change.

**Architecture:** Two workstreams. (A) Correctness triage first — every clang-sa/clang-tidy
HIGH/MEDIUM finding in the 50 files is fixed or explicitly dispositioned as false-positive
with a source comment. (B) Complexity burndown — each over-gate function is decomposed with
the three no-goto recipes from `docs/09-developer-guide/coding-standards.md` §4/§8
(extract-helper, early-return flattening, table/descriptor-driven dispatch). Every task is
one file, independently buildable, testable, and committable.

**Tech Stack:** C (nginx module + ngx-free client), lizard 1.23.0, CodeChecker 6.28.2
(clang 21 clangsa + clang-tidy), pytest fleet suite.

## Global Constraints

- **NO `goto`** anywhere in `src/`, `shared/`, `client/` (CLAUDE.md HARD BLOCK).
- **NO behavior change.** These are refactors + proven-bug fixes only. Wire formats,
  error codes, log lines, and metrics are frozen unless a task says otherwise.
- **Helpers:** never reimplement anything in CLAUDE.md HELPERS; new helpers are
  `static` in-file unless ≥2 files need them.
- **3 tests per change** (success + error + security-negative) for every task that
  changes behavior (Phase 72.A bug fixes). Pure equal-behavior decompositions rely on
  the existing suite for the touched subsystem plus the per-task test commands below.
- **Every commit requires explicit OP approval in the executing conversation**
  (CLAUDE.md HARD BLOCK). Commit steps below are gates: STOP and ask.
- **Build:** `cd /tmp/nginx-1.28.3 && make -j$(nproc)` (module is -Werror). Client:
  `make -C client -j$(nproc)`. No `./configure` needed — no new source files are
  created in this phase EXCEPT where a task says "add to `./config`".
- **Per-file complexity gate (the phase's definition of done for a file):**
  `lizard <file> -l c -C 15 -L 100 -a 5 -w` → prints nothing, exit 0.
- **Analyzer gate:** re-run CodeChecker on the touched file's TU and confirm the listed
  findings are gone (commands in §72.0).
- Baseline data: `docs/refactor/phase-72-baseline/` (created by Task 0).

## Effort model (how the 50 were chosen)

Per function: `2.0*max(0,CCN−15) + 0.10*max(0,NLOC−100) + 1.0*max(0,params−5)`;
per file add CodeChecker findings at HIGH=10 / MEDIUM=4 / LOW=1, deduped by
(file,line,checker), excluding two noise checkers (`misc-header-include-cycle`,
`clang-diagnostic-unused-parameter` — the build uses `-Wno-unused-parameter` by design).

## Phase map

| Phase | Scope | Files | Risk |
|---|---|---|---|
| 72.0 | Baseline + regen tooling | — | none |
| 72.A | Analyzer HIGH/MEDIUM correctness triage | 8 files | behavior-affecting (bug fixes) |
| 72.B | root:// protocol handler decomposition | 11 files | high-traffic hot paths |
| 72.C | auth plane decomposition | 8 files | security-load-bearing |
| 72.D | core/config + compat decomposition | 5 files | startup/reload paths |
| 72.E | net plane (cms/proxy) decomposition | 5 files | cluster protocol |
| 72.F | fs plane decomposition | 6 files | storage truth |
| 72.G | observability decomposition | 4 files | low risk |
| 72.H | client lib + apps decomposition | 11 files | CLI UX frozen |

Order: 72.0 → 72.A strictly first (bug fixes must not be entangled with refactor diffs).
72.B–72.H are mutually independent and may be executed in any order or in parallel
sessions **one file per session** (files never overlap).

---

## Phase 72.0 — Baseline

### Task 0: Freeze the measurement

**Files:**
- Create: `docs/refactor/phase-72-baseline/top50.json` (copy of scratchpad top50.json)
- Create: `docs/refactor/phase-72-baseline/regen.sh`

**Steps:**

- [ ] **Step 1: Write `regen.sh`** — reproduces both scans so any executor can re-measure:

```bash
#!/usr/bin/env bash
# Phase-72 measurement: lizard + CodeChecker over the module sources.
# Usage: docs/refactor/phase-72-baseline/regen.sh <outdir>
set -euo pipefail
OUT=${1:?outdir}; REPO=$(git rev-parse --show-toplevel); BUILD=/tmp/nginx-1.28.3
mkdir -p "$OUT"
lizard "$REPO"/src "$REPO"/shared "$REPO"/client -l c --csv > "$OUT/lizard.csv"
( cd "$BUILD" && make -Bn ) > "$OUT/make_dryrun.txt"
python3 - "$OUT" "$REPO" "$BUILD" <<'EOF'
import json,re,sys
out,repo,build=sys.argv[1],sys.argv[2],sys.argv[3]
lines=open(f"{out}/make_dryrun.txt").read().splitlines()
cmds,cur=[],""
for ln in lines:
    if ln.endswith("\\"): cur+=ln[:-1]+" "
    else: cmds.append(cur+ln); cur=""
ent=[]
for c in cmds:
    c=c.strip()
    if not re.match(r"^(cc|gcc|clang)\b",c) or " -c " not in c: continue
    srcs=[t for t in c.split() if t.endswith(".c")]
    if srcs and srcs[-1].startswith(repo):
        ent.append({"directory":build,"command":c,"file":srcs[-1]})
json.dump(ent,open(f"{out}/compile_commands.json","w"))
print(len(ent),"entries")
EOF
CodeChecker analyze "$OUT/compile_commands.json" -o "$OUT/cc_reports" \
    -j "$(nproc)" --analyzers clangsa clang-tidy
CodeChecker parse "$OUT/cc_reports" -e json > "$OUT/cc_reports.json" || true
```

- [ ] **Step 2:** `chmod +x`, run it once into `docs/refactor/phase-72-baseline/run0/`,
  copy the current top50 table into `top50.json`.
- [ ] **Step 3:** Verify `run0/cc_reports.json` parses and in-repo finding counts match
  this doc (4023 raw in-repo; 235 after noise-filter + dedupe; 53 raw HIGH).
- [ ] **Step 4: Commit gate** — STOP; request OP approval to commit
  `docs/refactor/phase-72-*` (docs only).

**Single-file re-check used by every task below** (replace `<FILE>`):

```bash
# complexity gate
lizard <FILE> -l c -C 15 -L 100 -a 5 -w   # expect: no output
# analyzer gate (single TU)
python3 -c "
import json;d=json.load(open('docs/refactor/phase-72-baseline/run0/compile_commands.json'))
print([e for e in d if e['file'].endswith('<FILE>')][0]['command'])"
# then: CodeChecker analyze on a compile db filtered to that entry, parse, grep the file
```

---

## Phase 72.A — Analyzer correctness triage

Fix or disposition every HIGH/MEDIUM finding in the 50 files. Each fix gets the full
3-test treatment. False positives get a `/* phase72-fp: <why> */` comment at the flagged
line plus (where supported) a `// NOLINT(<checker>)` so the finding is suppressed at
source, not in tooling config.

### Task A1: `src/fs/backend/sd.h` — null driver-op dispatch (11× HIGH core.CallAndMessage)

**Files:** Modify: `src/fs/backend/sd.h:546-800` (the `brix_sd_*_maybe_cred` inline wrappers).

**Finding:** each wrapper's final fallback dispatches the plain slot unconditionally, e.g.
`sd.h:562` `return inst->driver->open(inst, path, sd_flags, mode, err_out);` — the deny
branch explicitly handles `open_cred==NULL && open!=NULL`, proving the analyzer's point
that `open` may be NULL on the fallthrough (cred==NULL, or fallback_deny==0). A driver
registered without the capability turns a client op into a worker SIGSEGV.

**Fix pattern** (apply identically to all 11 wrappers — lines 562, 583, 614, 630, 664,
704, 721, 740, 757, 774, 793; the ops are open/staged_open/pread-family/xattr-family):

```c
    if (inst->driver->open == NULL) {          /* capability not implemented */
        if (err_out != NULL) {
            *err_out = ENOTSUP;
        }
        errno = ENOTSUP;
        return NULL;                            /* int-returning wrappers: return -1 */
    }
    return inst->driver->open(inst, path, sd_flags, mode, err_out);
```

- [ ] **Step 1: Failing test.** Extend the existing sd unit test harness (see
  `tests/` C-unit runners, e.g. the pattern of `run_cinfo_tests`) with
  `tests/unit/test_sd_null_ops.c`: register a `brix_sd_driver_t` with only `.name` set,
  call each `brix_sd_*_maybe_cred` wrapper, assert return NULL/-1 with errno==ENOTSUP
  (success-case test: a full driver still dispatches; error-case: null slot → ENOTSUP;
  security-neg: `fallback_deny=1` with cred still returns EACCES, not ENOTSUP).
- [ ] **Step 2:** Run it → SIGSEGV/failure expected before the fix.
- [ ] **Step 3:** Apply the guard to all 11 wrappers.
- [ ] **Step 4:** Rebuild module + run the new unit + `pytest tests/ -k "vfs or backend" -v`.
- [ ] **Step 5:** Single-TU analyzer re-check on any sd.h includer (e.g. `sd_posix.c`):
  0 remaining `core.CallAndMessage` in sd.h. **Commit gate — ask OP.**

### Task A2: `src/tpc/engine/done.c` — 4× HIGH core.NullDereference (lines 128, 139, 168, 204)

**Files:** Modify: `src/tpc/engine/done.c:40-317` (`brix_tpc_pull_done`).

**Finding:** the function guards `c != NULL ? c->log : NULL` at 121/205 then dereferences
`c->log` unconditionally at 128/204 and `ctx->...` at 139/168 — the guard itself proves
`c` (and `ctx`) can be NULL when the client disconnected before the pull thread finished.

**Fix:** hoist one nullable-safe log handle at the top of the completion handler and use
it everywhere; make the ctx-dependent accounting conditional:

```c
    ngx_log_t *log = (c != NULL) ? c->log : ngx_cycle->log;
```

Replace every `c->log` in the failure/success paths with `log`; wrap the
`BRIX_OP_ERR/BRIX_OP_OK/brix_log_access/brix_send_*/brix_aio_resume` block in
`if (ctx != NULL && c != NULL) { ... }` (registry update/metric/remove keep running with
`log` — the transfer bookkeeping must complete even when the client is gone).

- [ ] **Step 1: Failing test.** `tests/test_tpc_client_gone.py`: start a native-TPC pull,
  kill the client connection mid-transfer, assert the worker survives (no SIGSEGV in
  `error.log`), the registry entry is removed, and the partial destination is unlinked
  (success: normal pull still completes; error: client-gone path; security-neg: transfer
  id cannot be reused after error removal).
- [ ] **Step 2:** Run → today this is a latent crash; the test must at least exercise the
  path (assert on log line `TPC-PULL`).
- [ ] **Step 3:** Apply fix. **Step 4:** build + `pytest tests/ -k tpc -v`.
- [ ] **Step 5:** analyzer re-check: 0 NullDereference in done.c. This function is also
  72.B scope (CCN 39) — do NOT decompose here; fix only. **Commit gate — ask OP.**

### Task A3: `src/protocols/root/read/pgread.c` — 3× HIGH conditional-uninitialized (367, 368, 370)

**Files:** Modify: `src/protocols/root/read/pgread.c:164-393` (`brix_handle_pgread`).

**Finding:** `out_buf`, `out_size`, `flat_buf` are assigned in the warm-hit path and the
sync-fallback (`!warm_hit`) path; the compiler proves a route to their use at 367-370
(`brix_build_pgread_chain(..., out_buf, out_size)` / `brix_release_read_buffer(..., flat_buf)`)
where neither assignment ran.

**Fix:** initialize at declaration and add a defensive invariant before use:

```c
    u_char  *out_buf  = NULL;
    u_char  *flat_buf = NULL;
    size_t   out_size = 0;
    ...
    if (out_buf == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_PGREAD, "PGREAD",
                          ctx->files[idx].path, "-",
                          kXR_ServerError, "pgread: no output produced");
    }
    rsp_chain = brix_build_pgread_chain(...);
```

- [ ] **Step 1: Tests.** pgread has wire tests already; add to the pgread suite: success
  (normal pgread, CRC-verified), error (pgread on a handle whose warm-cache and AIO paths
  are both bypassed — force `thread_pool` off + cold file), security-neg (pgread beyond
  EOF returns clean kXR error, not garbage frame). Remember INVARIANT 1: kXR_status(4007)
  framing + per-page CRC32c.
- [ ] **Step 2-4:** fail → fix → `pytest tests/ -k pgread -v` + build.
- [ ] **Step 5:** analyzer re-check → 0 findings. Decomposition of this file happens in
  Task B4, not here. **Commit gate — ask OP.**

### Task A4: `src/fs/backend/s3/sd_s3_meta.c` — 4× HIGH misplaced-widening-cast (158, 171, 203, 212)

**Files:** Modify: `src/fs/backend/s3/sd_s3_meta.c:114-216` (`sd_s3_sign_ext`).

**Finding:** `(size_t) (off + cn)` widens AFTER the `int + int` addition — the guard
comparisons at 158/171/203/212 are computed in `int` and can wrap before the cast on
adversarially long header sets, defeating the overflow check in the SigV4 canonical
buffer builder.

**Fix (all 4 sites):** `if (cn < 0 || (size_t) off + (size_t) cn >= sizeof(canon))`
(resp. `>= hdrsz`). Same one-token change per site; `off += cn` stays.

- [ ] **Step 1:** unit-style test via the S3 suite: success (SigV4 signature still matches
  a known-good vector — existing `pytest tests/ -k "s3 and sign"` cases), error
  (oversized synthetic header list → clean -1, not a wrapped guard), security-neg
  (signature mismatch still rejected upstream).
- [ ] **Step 2-5:** fail → fix → build + `pytest tests/ -k s3 -v` → analyzer 0. Also fix
  the same checker's sibling hits **in this file only**. **Commit gate — ask OP.**

### Task A5: `src/protocols/root/read/open_resolved_file.c` — 2× HIGH (462 fstat on fd<0; 1056 garbage `st`)

**Files:** Modify: `src/protocols/root/read/open_resolved_file.c:458-504`
(`brix_open_validate_fd`), `:1048-1102` (`brix_open_init_handle`).

**Finding:** (a) `:462` — `brix_open_validate_fd` calls `fstat(fd, st)` in the
`!driver_backed` branch; the analyzer proves a caller path where a no-fd handle
(fd = −1/−99 sentinel) reaches it. (b) `:1056` — `brix_open_init_handle` reads
`st->st_mode` (`S_ISREG(st->st_mode)`) on a path where the fstat that fills `st` was
skipped, so `st` is uninitialized garbage.

**Fix:** (a) add `if (fd < 0) { BRIX_RETURN_ERR(..., kXR_IOError, "open: no fd to validate"); }`
at the top of the `!driver_backed` branch. (b) require callers of
`brix_open_init_handle` to pass a populated `st`; zero-init the local
`struct stat st = {0};` at the declaration in the affected caller
(`brix_open_dispatch_open` path) and populate via the existing retstat helper for
no-fd driver handles (the 2026-06 sd_ceph fix in this file shows the intended pattern).

- [ ] **Steps:** 3 tests (open regular file OK; open via no-fd driver handle → stat
  fields correct, not garbage; security-neg: open of dir-as-file still rejected EISDIR)
  → fix → build + `pytest tests/ -k "open" -v` → analyzer 0 HIGH. **Commit gate — ask OP.**

### Task A6: `src/fs/tier/tier_config.c:55` + `src/auth/impersonate/idmap.c:156,169,180` — 4× MEDIUM cert-err33-c

**Files:** Modify both files at the listed lines.

**Finding:** return value of a stdlib call discarded (the checker names the call at each
line — inspect and handle). In parse/load functions an ignored `snprintf`/`fclose`/`strtol`
result means truncated tier authority strings or silently half-parsed gridmap lines.

**Fix:** check and propagate: parse-context lines return the function's existing error
value (`NGX_CONF_ERROR` / `NGX_ERROR`) on failure; where the result is genuinely
irrelevant, write `(void) call(...);` with a `/* phase72-fp: result irrelevant because
<reason> */` comment.

- [ ] **Steps:** 3 tests per file (valid config parses; malformed line at exactly the
  flagged call path → clean config error not silent acceptance; security-neg: gridmap
  line with truncated DN must NOT map to a uid) → fix → build + `pytest tests/ -k
  "tier or idmap or imperson" -v` → analyzer 0 MEDIUM in both files. **Commit gate — ask OP.**

### Task A7: LOW disposition sweep (broker_ops.c:171,178; fattr/dispatch.c:193; mv.c:167)

**Files:** Modify the 4 lines (comments/NOLINT only, or a real fix if the check is right).

`readability-suspicious-call-argument`: verify against the callee prototypes —
`broker_ops.c` passes `sfd`→`__oldfd`, `dfd`→`__newfd` on `dup2`-family calls (confirm
direction is copy-source→dest, then FP-mark); `fattr/dispatch.c:193` and `mv.c:167` pass
`(pathbuf, full_path)` to `(reqpath, ...)` (confirm request-path vs resolved-path order —
INVARIANT 4 says the RESOLVED path must be the one opened). If any is genuinely swapped it
becomes a full Task-A6-style fix with 3 tests; expected outcome is 4× FP markers.

- [ ] **Steps:** verify each callee signature → mark or fix → build → analyzer LOW=0 in
  these files. **Commit gate — ask OP.**

### Task A8: Phase-72.A exit gate

- [ ] Re-run `regen.sh run_a/`; assert: 0 HIGH, 0 MEDIUM findings in all 50 files
  (LOW only where FP-marked). Record the delta table in
  `docs/refactor/phase-72-baseline/after-72A.md`. **Commit gate — ask OP.**

---

## Decomposition task template (applies to every task in 72.B–72.H)

Each task below lists the file, the over-gate functions (name/CCN/NLOC/params/lines), and
a named decomposition recipe. Every task executes the same 7 steps:

1. **Read** the whole file + `coding-standards.md` §4/§8.
2. **Characterize**: run the listed test command; capture pass baseline. If the file has
   no direct tests, FIRST add a characterization test for the function's main
   success/error paths (this is the "failing test" step of TDD for refactors — it must
   pass before AND after).
3. **Extract** the named helpers exactly as specified — `static` functions in the same
   file, state passed explicitly (ctx/conf/request pointers — no new globals), each new
   helper gets a WHAT/WHY/HOW doc block. Early-return instead of nesting. No `goto`.
4. **Gate**: `lizard <FILE> -l c -C 15 -L 100 -a 5 -w` → empty.
5. **Build**: module `make -j$(nproc)` in `/tmp/nginx-1.28.3` (or `make -C client`) — exit 0,
   -Werror clean.
6. **Test**: run the task's listed test command → identical pass set to step 2.
7. **Commit gate** — STOP, ask OP approval, one commit per file:
   `refactor(phase-72): decompose <file> under complexity gate`.

Behavioral freeze: byte-identical wire responses, error codes, and log formats. Where a
handler builds a response, keep the response-assembly order unchanged.

---

## Phase 72.B — root:// protocol handlers

### Task B1: `src/protocols/root/session/protocol.c` — `brix_handle_protocol` CCN 58, 143 NLOC (L19-192)

Recipe: kXR_protocol negotiation is a flag-matrix. Extract:
`protocol_parse_client_req(ctx, req, &want)` (request decode + version clamp),
`protocol_negotiate_flags(conf, ctx, want, &resp_flags)` (the entire capability/TLS
bit-ladder — table-drive it with a `{cond_fn, flag}` descriptor array),
`protocol_build_resp(ctx, c, resp_flags)` (response framing). Target: dispatcher ≤ CCN 8.
Test: `PYTHONPATH=tests pytest tests/ -k "protocol" -v`.

### Task B2: `src/protocols/root/read/read.c` — `brix_handle_read` CCN 50, 243 NLOC (L156-563)

Recipe: split by serve strategy, mirroring the existing `brix_read_serve_sendfile`:
`read_validate_req(ctx, c, req, &idx, &off, &len)` (handle/range/authz checks, all
early-return), `read_serve_warm(...)`, `read_serve_aio(...)` (thread-pool post + fallback
decision), `read_serve_sync(...)`. Keep INVARIANT 2 (TLS `b->memory=1` vs cleartext
sendfile) inside the serve helpers — never mixed. Test:
`pytest tests/ -k "read and not pgread and not readv" -v`.

### Task B3: `src/protocols/root/read/stat.c` — `brix_handle_stat` CCN 50, 213 NLOC (L106-410)

Recipe: `stat_resolve_target(ctx, req, &resolved)` → `stat_query_vfs(...)` (brix_vfs_stat
+ open-handle metadata short-circuit per INVARIANT 7) → `stat_format_response(...)` (the
mode/flags/size text encoding). Test: `pytest tests/ -k "stat and not statx" -v`.

### Task B4: `src/protocols/root/read/pgread.c` — `brix_handle_pgread` CCN 25 (L164-393), `brix_pgread_read_encode_inplace` CCN 17 (L49-147)

(After A3 lands.) Recipe: `pgread_try_warm(...)`, `pgread_post_aio(...)`,
`pgread_sync_fill(...)` — the three producer paths each set `{out_buf,out_size,flat_buf}`
through one `pgread_result_t` struct so the A3 invariant becomes structural. Encode
helper: split CRC loop from gap-layout math (`pgread_page_layout()` pure function).
Test: `pytest tests/ -k pgread -v`.

### Task B5: `src/protocols/root/read/open_resolved_file.c` — 18 borderline fns, worst CCN 15; param bloat (dispatch 17 params, finalize 21 params)

(After A5 lands.) The CCN is fine; the debt is PARAMETER BLOAT. Recipe: introduce ONE
`brix_open_args_t` struct (file-local, in this .c) carrying
{resolved path, flags, mode, cred, csi, writethrough decision, stat, from_cache, codec,
create_mode…}; thread it through `brix_open_dispatch_open` (17→2 params),
`brix_open_finalize_handle` (21→3), `brix_open_init_handle` (10→3),
`brix_open_via_driver` (10→3). No logic moves — signature consolidation only.
Test: `pytest tests/ -k "open" -v`.

### Task B6: `src/protocols/root/query/config.c` — `brix_query_config` CCN 52 (L99-338)

Recipe: kXR_Qconfig is a name→value lookup — replace the if/else ladder with a static
descriptor table `{ const char *key; ngx_int_t (*emit)(ctx, conf, buf, len); }` and one
loop. Each emitter ≤ CCN 5. Test: `pytest tests/ -k "query or qconfig" -v`.

### Task B7: `src/protocols/root/dirlist/handler.c` — `brix_handle_dirlist` CCN 46, 249 NLOC (L71-386)

Recipe: `dirlist_open(ctx, req, &walk)` (resolve + brix_vfs_opendir + authz),
`dirlist_emit_entry(walk, ent, buf)` (per-entry stat/format incl. dstat mode),
`dirlist_stream_chunks(ctx, c, walk)` (chunked kXR_oksofar framing loop).
Test: `pytest tests/ -k dirlist -v`.

### Task B8: `src/protocols/root/fattr/dispatch.c` — `brix_handle_fattr` CCN 42, 193 NLOC (L35-305)

(After A7 disposition.) Recipe: fattr has 4 subcommands (get/set/del/list) — split
`fattr_do_get/set/del/list(ctx, c, req, resolved)` + shared
`fattr_decode_names(req, &names)`; dispatcher becomes a switch of calls. Uses
`brix_vfs_{get,set,list,remove}xattr` only (INVARIANT 11b).
Test: `pytest tests/ -k fattr -v`.

### Task B9: `src/protocols/root/write/mv.c` — `brix_handle_mv` CCN 42, 171 NLOC (L27-269)

(After A7.) Recipe: `mv_resolve_pair(ctx, req, &src, &dst)` (both paths through
resolve_path — INVARIANT 4), `mv_check_locks_and_authz(...)` (WebDAV-parity lock checks,
subtle-bug rule 5), `mv_execute(...)` (brix_vfs_rename_path + errno→kXR mapping table).
Test: `pytest tests/ -k "mv or rename" -v`.

### Task B10: `src/protocols/root/zip/zip_http.c` — `brix_zip_http_serve` CCN 44, 143 NLOC (L79-244)

Recipe: `ziphttp_parse_range(...)`, `ziphttp_locate_member(...)` (central-directory walk),
`ziphttp_send_member(...)` (TLS/cleartext buffer split per INVARIANT 2).
Test: `pytest tests/ -k zip -v`.

### Task B11: `src/tpc/engine/done.c` — `brix_tpc_pull_done` CCN 39, 190 NLOC (L40-317)

(After A2.) Recipe: the function is {sync-reply success, sync-reply failure, async-reply
success, async-reply failure} × shared bookkeeping. Extract
`tpc_done_teardown_dst(t, ctx, idx, log)` (close/unlink/free-fhandle — the A2-fixed
block), `tpc_done_account(t, ok, log)` (registry update + metric + registry remove),
`tpc_done_reply_sync(...)`, `tpc_done_reply_open(...)`. Dispatcher ≤ CCN 10.
Test: `pytest tests/ -k tpc -v`.

---

## Phase 72.C — auth plane

Security-load-bearing: every task here keeps the 3-test rule INCLUDING a security-negative
even for pure decomposition (prove deny paths still deny).

### Task C1: `src/auth/gsi/auth.c` — `brix_handle_auth_inner` CCN 64, 219 NLOC (L226-503)

Recipe: the GSI kXR_auth conversation is a state machine — extract per-step helpers
`gsi_auth_step_certreq(...)`, `gsi_auth_step_cert(...)`, `gsi_auth_step_sigpxy(...)`
(delegation), plus `gsi_auth_finish(ctx, c, ident)` (idmap + session bind). Keep the
step order and wire chunks byte-identical (differential suite exists).
Test: `pytest tests/ -k "gsi" -v` + the WLCG x509 conformance suite
(`pytest tests/ -k "x509_conformance" -v`).

### Task C2: `src/auth/gsi/proxy_req.c` — sign CCN 37 (L448-566), build CCN 23, assemble CCN 18, pci_ext CCN 17

Recipe: OpenSSL assembly ladders. `pxr_sign_prepare_names(...)`,
`pxr_sign_set_validity(...)`, `pxr_sign_add_extensions(...)` (each an early-return
OpenSSL sequence with single cleanup tail via the no-goto recipe: allocate-in-struct +
one `pxr_free_all(&s)` on every return). RFC3820 limited-proxy monotonicity behavior
frozen. Test: `pytest tests/ -k "proxy and gsi" -v` + delegation cases.

### Task C3: `src/auth/token/validate.c` — `brix_token_validate` CCN 44, 222 NLOC, 11 params (L190-479)

Recipe: introduce `token_validate_args_t` (11→2 params), then split the RFC pipeline:
`token_check_header(...)` (alg/kid/crit — RFC7515), `token_check_claims(...)`
(exp/nbf/iat/aud with clock_skew), `token_check_issuer_keys(...)` (JWKS + rotation),
`token_check_scope_authz(...)`. The 510-case WLCG token conformance suite is the oracle:
`pytest tests/ -k "wlcg_token" -v` must be 100% identical before/after.

### Task C4: `src/auth/impersonate/broker_ops.c` — `imp_do_op` CCN 71, 223 NLOC, 8 params (L192-472)

(After A7.) Recipe: `imp_do_op` is an opcode switch executing privileged fs ops in the
broker child. Table-drive: `static const imp_op_desc_t imp_ops[] = { {IMP_OP_OPEN,
imp_op_open}, {IMP_OP_STAT, imp_op_stat}, ... }` — one `static int imp_op_<name>(imp_req_t
*rq, imp_rsp_t *rs)` per opcode (each currently a case block). Security-neg test: an
op outside the table → clean EPERM reply, and the userns/broker suite
(`pytest tests/ -k "imperson or broker" -v`; note root needed for full map).

### Task C5: `src/auth/impersonate/idmap.c` — 5 fns CCN 19-21

(After A6.) Recipe: `idmap_gridmap_parse_line` → split DN-unescape from field-split
(`gridmap_unescape_dn()` pure). `brix_idmap_resolve` → `idmap_lookup_exact` /
`idmap_lookup_wildcard` / `idmap_apply_collapse` (the mu_authz collapse semantics are
covered by `idmap_collapse` C unit — run it). `brix_idmap_init` → file-load vs table-build
halves. Test: existing idmap C unit + `pytest tests/ -k idmap -v`.

### Task C6: `src/protocols/webdav/macaroon_endpoint.c` — 5 fns CCN 18-31 (token CCN 31 L271-505, request CCN 30 L610-803)

Recipe: both handlers share {parse JSON body, validate caveats, mint/serialize}. Extract
`mac_parse_request_body(r, &req)` (jansson decode + validity caps),
`mac_authorize_request(r, conf, &req)` (path/activity authz),
`mac_mint_and_respond(r, &req)`. `mac_iso8601_secs` CCN 22 → replace hand-rolled date
math with `strptime`/`timegm` bounded parse. `scope_to_activities` CCN 20 → static
scope→activity descriptor table. Test: `pytest tests/ -k macaroon -v`.

### Task C7: `src/protocols/webdav/access.c` — `ngx_http_brix_webdav_access_handler` CCN 48, 156 NLOC (L129-338)

Recipe: the access-phase gate is method→required-privilege mapping + N auth sources.
Extract `access_required_priv(r)` (method/URI → priv bitmask, table-driven),
`access_try_cert(...)`, `access_try_token(...)`, `access_apply_authdb(...)`. `conf->allow_write`
global check stays FIRST (INVARIANT 3). Security-neg: unauthenticated PROPFIND on a
protected export → 401/403 unchanged. Test: `pytest tests/ -k "webdav and (access or auth)" -v`.

### Task C8: `src/observability/dashboard/auth.c` — 4 fns CCN 16-28 (login body handler 148 NLOC)

Recipe: `dashboard_form_value` CCN 27 → use one urlencoded-pair scanner helper
(`dash_form_next_pair()`); `check_auth` → `dash_auth_try_cookie` / `dash_auth_try_basic`
/ `dash_auth_try_cert`; `login_post_body_handler` → parse/verify/set-cookie trio.
Security-neg: forged session cookie rejected. Test: `pytest tests/ -k dashboard -v`.

---

## Phase 72.D — core/config + compat

### Task D1: `src/core/config/process.c` — `ngx_stream_brix_init_process` CCN 53, 207 NLOC (L194-536)

Recipe: worker-init is a sequence of independent subsystem initializations — extract one
`static ngx_int_t init_<subsys>(ngx_cycle_t *cycle, ...)` per block (shm attach, metrics,
uring/thread-pool, cache reaper timer, cms, guard, pmark…), called from a flat
`for (i; init_steps[i]; i++)`-style ladder with early-return on NGX_ERROR. Reload
semantics doc (`reload-semantics.md`) is the contract — behavior frozen.
Test: `tests/manage_test_servers.sh restart` + `pytest tests/ -k "reload or healthz" -v`.

### Task D2: `src/core/config/postconfiguration.c` — `ngx_stream_brix_postconfiguration` CCN 54, 175 NLOC (L96-364)

Recipe: same shape as D1 — per-concern `postconf_<concern>()` helpers (handler install,
shm zone ensure, directive cross-validation). Config-validation error strings frozen
(tests grep them). Test: `/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`
+ full fleet start.

### Task D3: `src/core/compat/json_min.c` — jm_string CCN 38, brix_json_get_str CCN 26, jm_skip_value CCN 21

Recipe: `jm_string` (escape decoder) → split `jm_unescape_char()` (single-escape decode
incl. \uXXXX → `jm_utf16_pair()`) from the scan loop. `jm_skip_value` → small recursive
descent with explicit depth cap (document the cap). This is a parser — add a C unit
(`tests/unit/test_json_min.c`, register beside existing unit runners) with malformed-input
security-negatives (truncated escapes, deep nesting, NUL embedding) BEFORE refactoring.
Test: new unit + `pytest tests/ -k "json" -v`.

### Task D4: `src/core/compat/kxr_names.c` — 2 switch ladders CCN 34/31

Recipe: replace both `switch` ladders with static lookup tables:
`static const struct { uint16_t code; const char *name; } kxr_req_names[] = {...}` +
one bsearch/linear lookup fn (`kxr_lookup(table, n, code, "unknown")`). CCN → 3.
Test: C unit asserting every existing code→name pair unchanged (generate the expected
list from the CURRENT implementation before touching it).

### Task D5: `src/core/aio/uring.c` — `brix_uring_init_worker` CCN 47, 196 NLOC (L487-754); eventfd handler CCN 16

Recipe: `uring_probe_features(...)` (kernel capability probes),
`uring_setup_rings(...)`, `uring_register_buffers(...)`, `uring_install_eventfd(...)` —
each early-returns to the existing "fall back to thread-pool AIO" path; the fallback
decision point stays single. eventfd handler: split CQE-drain loop body into
`uring_complete_one(cqe)`. Test: `pytest tests/ -k "uring or aio" -v` on a kernel with
io_uring; verify fallback boot on `ulimit`-restricted run.

---

## Phase 72.E — net plane

### Task E1: `src/net/cms/recv.c` — process_frame CCN 35 (L321-543), exec_driver CCN 24, read_handler CCN 18, exec_forward CCN 18

Recipe: `ngx_brix_cms_process_frame` is an opcode switch → descriptor table
`{opcode, min_len, handler}` like C4. `cms_node_exec_driver/forward` → shared
`cms_exec_common()` for the request-marshal prologue. Read handler: extract
`cms_recv_accumulate()` (buffer/framing) from dispatch. Test: `pytest tests/ -k cms -v`.

### Task E2: `src/net/cms/server_recv.c` — process_frame CCN 34 (L448-675), parse_login CCN 26, read CCN 18

Recipe: mirror E1's table on the server side; `cms_srv_parse_login` → split
credential-block parse from capability negotiation. Test: `pytest tests/ -k "cms and (login or server)" -v`.

### Task E3: `src/net/cms/rrdata.c` — parse CCN 39 (L93-164), encode CCN 23, 8 params

Recipe: rrdata is a tag-length-value codec: table of `{tag, decode_fn, encode_fn}`;
`brix_cms_rrdata_encode` 8 params → `cms_rr_fields_t` struct (also fixes
`brix_cms_statfs_encode` 8 params). Round-trip C unit (encode→parse == identity) BEFORE
refactor. Test: new unit + `pytest tests/ -k cms -v`.

### Task E4: `src/net/proxy/events_read.c` — `brix_proxy_read_handler` CCN 47, 200 NLOC (L18-302)

Recipe: split the pump: `proxy_read_fill(...)` (recv + framing accumulation),
`proxy_read_dispatch(...)` (per-frame tap + forward decision),
`proxy_read_flush_upstream(...)`. GOTCHA from memory: never capture `c->log` into a sink
(stale handler SIGSEGV) — keep the relay-struct `ngx_log_t` copy pattern.
Test: `tests/run_tap_proxy.sh` PASS + `pytest tests/ -k "proxy or tap" -v`.

### Task E5: `src/net/proxy/events_bootstrap.c` — bs_login CCN 42, 213 NLOC (L207-473); handle_bootstrap CCN 17

Recipe: `proxy_bs_send_handshake(...)`, `proxy_bs_do_auth(...)` (per-mech branch →
per-mech helpers incl. the threaded GSI login), `proxy_bs_adopt_conn(...)` (fd handoff at
IDLE). Test: `tests/run_tap_proxy.sh` + `pytest tests/ -k proxy -v`.

---

## Phase 72.F — fs plane

### Task F1: `src/fs/vfs/vfs_dir.c` — opendir_impl CCN 29 (L31-171), readdir_kind CCN 26, readdir CCN 25

Recipe: `vfs_dir_route(...)` (export-root confinement + driver/broker selection — the
security seam, keep in one place), `vfs_dir_open_confined(...)` (openat2
RESOLVE_IN_ROOT path per the symlink-escape fix — do not weaken),
`vfs_readdir_fill_entry(...)` (shared by both readdir variants; kills the copy-paste
between readdir/readdir_kind). Security-neg: outward symlink in export still invisible.
Test: `pytest tests/ -k "vfs or dirlist or propfind" -v`.

### Task F2: `src/fs/meta/xmeta.c` — decode CCN 33 (L519-645), encode CCN 27, decode_section CCN 18

Recipe: section codec table `{section_id, encode_fn, decode_fn, min_ver}` — one
static fn pair per xmeta section; version gates data-driven. Round-trip C unit
(encode(decode(x))==x over the csi_unittest fixtures) before refactor.
Test: `tests/` csi/xmeta C units + `pytest tests/ -k "xmeta or csi" -v`.

### Task F3: `src/fs/backend/cache/sd_cache.c` — fill CCN 30, 148 NLOC (L49-249); partial_open CCN 20; fill_block CCN 19; open_common CCN 19

Recipe: `sd_cache_fill` → `cache_fill_acquire_lock(...)` (O_EXCL + dead-owner reclaim —
behavior from the reboot-lockup fix is frozen), `cache_fill_pump(...)` (origin read loop),
`cache_fill_commit(...)` (rename + cinfo + fstat mode fix). `open_common` →
hit/miss/partial decision helper + shared handle-build. Test:
`pytest tests/ -k "cache and (fill or partial)" -v` (21-node partial-fill suite).

### Task F4: `src/fs/cache/origin_protocol.c` — bootstrap CCN 38, 166 NLOC (L58-265); query_checksum CCN 19

Recipe: `origin_bs_handshake(...)`, `origin_bs_login(...)`, `origin_bs_open(...)` — the
root:// origin-client conversation, one wire step per helper, shared
`origin_expect_frame(...)` reply validator. Stall-timeout behavior (LOW_SPEED) frozen.
Test: `pytest tests/ -k "origin" -v` + `tests/run_cvmfs_resilience.sh`.

### Task F5: `src/fs/tier/tier_config.c` — parse_authority CCN 35 (L106-192), parse_store CCN 24

(After A6.) Recipe: authority grammar `scheme://host:port/params` → `tier_split_scheme`,
`tier_split_hostport`, `tier_parse_params` (k=v loop, descriptor table of known keys).
Config-error message text frozen. Test: `pytest tests/ -k "tier or stage" -v` + `nginx -t`.

### Task F6: `src/fs/backend/s3/sd_s3_meta.c` — sd_s3_sign_ext CCN 28, 98 NLOC (L114-216)

(After A4.) Recipe: `s3_canonical_request(...)` (canon buffer build — the A4-fixed code),
`s3_string_to_sign(...)`, `s3_derive_key_and_sign(...)`, `s3_emit_auth_header(...)`.
SigV4 vectors are the oracle (S3 SigV4 ≠ WLCG token — INVARIANT 6, no auth-logic
sharing). Test: `pytest tests/ -k "s3 and sign" -v`.

---

## Phase 72.G — observability

### Task G1: `src/observability/metrics/stream.c` — `brix_export_prometheus_metrics` CCN 34, 342 NLOC (L75-528)

Recipe: one `metrics_emit_<family>(buf)` per metric family (ops/bytes/sessions/auth/
cache/tpc/guard…), driven by the existing proto_list X-macro where possible; the
exporter becomes a call sequence. Exposition format byte-frozen (dashboards parse it).
Test: `pytest tests/ -k metrics -v` + `curl -s localhost:9100/metrics | promtool check metrics`
(if promtool absent, diff family/label sets before/after).

### Task G2: `src/observability/pmark/mapping.c` — map_codes CCN 38 (L285-377), runtime_ensure CCN 29

Recipe: `map_codes` is experiment/activity-code mapping — descriptor table + one lookup;
`runtime_ensure` → split shm-ensure / file-load / defaults-apply.
Test: `pytest tests/ -k pmark -v`.

### Task G3: `src/observability/dashboard/config_download.c` — scrub_value_creds CCN 39 (L265-337), redact_config CCN 22

Recipe: secret-redaction MUST stay fail-closed: replace the keyword if-ladder with a
static table of `{directive_substring, redact_mode}` + default-redact for unknown
credential-shaped values; add C-unit security-negs (every credential directive in
`credential_block.c` gets redacted; unknown `*_key`/`*_secret`/`*_pass` too).
Test: new unit + `pytest tests/ -k "dashboard and config" -v`.

### Task G4: `src/net/cms/rrdata.c` — moved to E3 (net). `src/observability/dashboard/auth.c` — moved to C8 (auth). This task: verify both done, re-run `lizard src/observability -l c -C 15 -L 100 -a 5 -w` and confirm only files outside the top-50 remain.

---

## Phase 72.H — client lib + apps

CLI surface (flags, output text, exit codes, man pages) is FROZEN — `client/` has
completion + man contracts. All builds: `make -C client -j$(nproc) && make -C client test`.

### Task H1: `client/apps/diag/xrddiag.c` — main CCN 67 (L558-691), dx_url_parse CCN 27 8-params

Recipe: `main` → getopt loop + `static const dx_cmd_t cmds[] = {{"probe", cmd_probe},...}`
subcommand table. `dx_url_parse` 8 out-params → `dx_url_t` struct. `dx_connect_as`/`dx_record`
/`s3_sign` param bloat → same struct-threading. Test: `make -C client test` + the diag
battery (`client/apps/diag/xrd_battery.c` fixtures).

### Task H2: `client/lib/xfer/copy_recursive.c` — 7 fns CCN 16-34

Recipe: download/upload trees share {enumerate, filter, place, transfer, verify} — extract
shared `copy_tree_walk(dir_iter, filters, per_entry_cb, ctx)` and per-direction callbacks;
`web_auth_headers` CCN 34 → per-scheme helpers (`auth_hdr_token/x509/s3`).
`mirror_delete_*` share one tombstone-scan helper. Test: `make -C client test` +
`pytest tests/ -k "recursive or mirror" -v`.

### Task H3: `client/apps/fs/xrootdfs.c` — `xrootdfs_aio_main` CCN 77, 181 NLOC (L251-462)

Recipe: the FUSE AIO worker loop → `aio_fetch_job()`, `aio_exec_read/write/flush()`
(per-op helpers), `aio_complete(job, rc)`. Signal/teardown handling isolated in
`aio_should_stop()`. Test: fuse suite (`pytest tests/ -k fuse -v`; remember orphaned-mount
hazard — `fusermount -u -z` on failure).

### Task H4: `client/apps/diag/xrd_doctor.c` — xrd_doctor CCN 58 (L201-345), _json CCN 31

Recipe: each doctor check becomes `static const doctor_check_t checks[] = {{"dns",
check_dns}, {"tcp", check_tcp}, {"tls", ...}, {"auth", ...}, {"io", ...}}`; text and JSON
renderers iterate the same results array (kills the duplicated branch ladders).
Test: `make -C client test` + `client/apps/diag` battery.

### Task H5: `client/apps/scan/xrdstorascan.c` — cmd_bench CCN 35, cmd_scan CCN 28, cmd_verify CCN 21, bench_cell 11 params

Recipe: `bench_cell` 11 params → `bench_cell_cfg_t`. `cmd_bench` → arg-parse /
matrix-build / run-loop / render quarters. `cmd_scan` → walk / classify / aggregate.
Test: existing xrdstorascan tests (6) + `make -C client test`.

### Task H6: `client/lib/protocols/root/frame.c` — brix_recv CCN 36 (L229-337), roundtrip_loop CCN 25, recv_after_waitresp CCN 24

Recipe: this is the client wire core — characterization first (`make -C client test`
covers roundtrip; add cases for oksofar-chaining, waitresp, redirect). Extract
`frame_read_header()`, `frame_read_body()`, `frame_handle_partial()` shared by all three
receivers; `roundtrip_loop` keeps only the retry/redirect state machine.
9-param `roundtrip_loop` → `rt_opts_t`. Test: `make -C client test` + any root:// e2e.

### Task H7: `client/apps/diag/diag_doctor.c` — 7 fns CCN 13-32

Recipe: same table-driven shape as H4 (`doctor_one` iterates target×check matrix;
per-protocol probes `doctor_http/s3/auth_suite/cross` each split request-build from
verdict-render). Test: `make -C client test`.

### Task H8: `client/apps/diag/xrd.c` — main CCN 58, 172 NLOC (L144-369)

Recipe: busybox-style dispatcher — subcommand table + per-cmd `cmd_<name>(argc, argv)`
(same pattern the busybox symlink family already uses in xrdcksum/xrddiag). Test:
`make -C client test` + symlink-dispatch cases.

### Task H9: `client/apps/cksum/xrdcktree.c` — ckcheck_main CCN 37 (L466-645), cktree_main CCN 30, walk_local_tree CCN 18

Recipe: shared `cktree_walk(root, cb)` for local tree; mains split into parse/plan/run/
report. Digest selection table (crc32c/crc64/adler/md5) replaces the branch ladder —
NOTE crc64 vs crc64nvme are different polys (INVARIANT 9), keep the mapping exact.
Test: `make -C client test` + `pytest tests/ -k cksum -v`.

### Task H10: `client/apps/fs/brixcvmfs_rw.c` — rw_rename CCN 37 (L473-538), rw_open_common CCN 24, rw_rmdir CCN 24

Recipe: overlay union logic — extract `ov_locate(path, &where)` (upper/lower/whiteout
resolution used by rename/rmdir/open alike), `ov_whiteout_create/clear`,
`rw_rename` → same-layer fast path + cross-layer copy-up path helpers. Weak-linked rw
hooks must keep ro-only builds green (memory: brixmount gotcha). Test:
`tests/run_cvmfs_core_unit.sh` (29) + rw overlay tests.

### Task H11: `client/apps/copy/xrdcp_recursive.c` — web_upload_walk CCN 27, s3/web download CCN 25/24

Recipe: reuse H2's `copy_tree_walk` if exported via `client/lib/xfer` header (only if H2
landed; else file-local mirror). `recursive_place` 7 params → `place_ctx_t`. Test:
`make -C client test` + `pytest tests/ -k "xrdcp and recursive" -v`.

---

## Phase-72 exit criteria

- [ ] `regen.sh final/` run: every one of the 50 files has **0 HIGH, 0 MEDIUM** findings
  and passes `lizard -C 15 -L 100 -a 5 -w` clean.
- [ ] Full builds green: module (762-obj, -Werror) + `make -C client` + `make -C client test`.
- [ ] `PYTHONPATH=tests pytest tests/ -v --tb=short` (full suite) — no regressions vs the
  Task-0 baseline run (fleet flake rules from CLAUDE.md apply: -n12 cap, serial rerun for
  load-flakes).
- [ ] `tools/ci/check_vfs_seam.sh` and `tools/ci/check_file_size.sh` guards still green
  (decompositions must not push files past the size ratchet — split the FILE too if a
  task's helpers would).
- [ ] Delta table appended to this doc; `docs/refactor/phase-72-baseline/final/` committed.
- [ ] Every commit had explicit OP approval.

## Known false-positive ledger (running)

| File:line | Checker | Disposition |
|---|---|---|
| src/auth/impersonate/broker_ops.c:171,178 | readability-suspicious-call-argument | FP — `renameat(sfd=oldfd, dfd=newfd)` order verified correct; NOLINT-marked |
| src/protocols/root/fattr/dispatch.c:193 | readability-suspicious-call-argument | FP — `brix_beneath_full_path(root, reqpath=pathbuf, buf=full_path)` order verified vs `beneath.h:114`; NOLINT-marked |
| src/protocols/root/write/mv.c:167 | readability-suspicious-call-argument | FP — same helper, `dst_buf`=reqpath, `dst_full`=output; NOLINT-marked |
| src/fs/tier/tier_config.c:55 | cert-err33-c | FP — vsnprintf truncation of an operator-error message acceptable; `(void)`-marked |
| src/auth/impersonate/idmap.c:156,169,180 | cert-err33-c | FP — fclose of read-only stream, no data loss; `(void)`-marked |

## Execution record (2026-07-10)

Phases 72.A (2026-07-09) and 72.B–72.H (2026-07-10) are IMPLEMENTED (uncommitted).
All 49 decomposition files pass `lizard -C 15 -L 100 -a 5 -w` except **39
parameter-count-only residuals**, every one on a signature frozen by an extern
declaration, a `brix_sd_driver_t` vtable slot, or a FUSE callback typedef —
zero CCN/NLOC/length violations remain. Clearing them needs a follow-up phase
allowed to touch headers (candidates: `token_validate_args_t` promotion into
token.h; `dx_url_t` into diag_internal.h; rrdata/statfs field structs;
pgread io-result struct in read.h). Module (-Werror) + client builds green;
`nginx -t` green; serial smoke 398/399 across pgread/tpc/s3/fattr/read/gsi-tls/
dashboard/token-edge/macaroon/dirlist (1 flake: exp-at-skew-boundary mint race,
comparison provably unchanged). Two -Werror stragglers fixed post-agent:
protocol.c debug-only helper now under `#if (NGX_DEBUG)`; tier_config.c
loc/loclen zero-init (gcc maybe-uninitialized through the out-param split).

## Phase-73 follow-up record (2026-07-10)

The header-touching param cleanup is DONE (uncommitted): 13 clusters converted the
extern signatures to args/out structs with all callsites updated 1:1 —
token (brix_token_validate_args_t/brix_token_registry_args_t), GSI proxy
(brix_gsi_blob_t/buf_t/err_t; crypto unit re-run 25/25), open path
(brix_open_request_t, 6 callsites), pgread (brix_pgread_io_t), cms rrdata
(fwd/statfs field structs; round-trip unit re-run), origin (cksum-out + read-range
structs), tier (brix_tier_parse_t), pmark (brix_pmark_flow_id_t), broker
(imp_op_ctx_t promoted), s3 meta (sd_s3_meta_buf), client copy (7 fns → structs),
client diag (dx_url_t/dx_note/dx_cred_sel/…; 72 dx_record callsites), client wire
core (brix_payload/brix_payload_ext/brix_resp_out across 13 files).
**Residuals: 4** — rw_read_lower/rw_readdir (FUSE/overlay-typedef-fixed),
sd_cache_open_cred/sd_cache_setxattr (brix_sd_driver_t vtable slots). Structural,
permanent.
**Exit gate (CodeChecker re-run, post-73 tree): ZERO findings of any severity in
all 50 phase-72 files** (repo-wide remainder: 23 HIGH / 79 MEDIUM / 18 LOW, all in
files outside the set — see "Deliberately out of scope" for the queue).
Builds green (module -Werror + client + client tests), fleet smoke 399/400 serial
(1 registry-port first-request flake, passes 3/3 isolated). check_vfs_seam OK.
check_file_size FAILs on webdav.h/launch.c are pre-existing concurrent phase-70
per-user-credential WIP growth, not this phase — left un-regenerated deliberately.

## Phase-74 analyzer-finding sweep (2026-07-10)

The out-of-scope analyzer queue is now BURNED DOWN (uncommitted). 8 disjoint-file
agents dispositioned all 120 deduped findings across ~70 files. **Real bugs fixed
(21+):** a genuine **use-after-free chain** in the proxy forward path (rejected
requests returned NGX_OK → freed request buffers forwarded upstream and later
double-freed; fixed with an explicit `proxy_reject_request`→NGX_ABORT ownership
contract across 7 sites); a **security.ArrayBound size_t-wrap** in macaroon
caveat-scope append (hostile offset could write past scope_buf; overflow-proof
subtraction guard, analyzer-reproduced clean); **three S3 dispatch-continuation
bugs** (scope-deny 403 / confinement-deny / URI-reject all sent a response then
*continued* executing the operation — incl. DELETE/PUT after a 403); a
**vfs_deleg NULL-deref** (now fail-closed EACCES); **five garbage-read / uninit
sites** (pmark sockaddr_storage ×2, s3 key, qprep, zip last, upstream addrlen);
**five fstatat(fd<0) guards** (vfs_io_core, vfs_walk, chkpoint); **six
misplaced-widening-casts** (gsi_cipher, parse_x509, b64url, sss_bf, meta_advisory,
shm/kv); a **file_serve NULL-deref guard**; **cvmfs origin_probe uninit array**;
plus dead-store removals, 4 reserved-macro/identifier renames, and ~45 cert-err33
return-value handlings. **~18 verified false positives** carry `/* phase74-fp */`
+ NOLINT with the proof (renameat arg-order, ENOTSUP==EOPNOTSUPP portability,
length-tracked memcpy, loop-widening ArrayBound, etc.).

**Exit gate (full-repo CodeChecker re-run): 23H/79M/18L → 4 findings, ALL
in-source-proven false positives** (helpers.c loop-widening ArrayBound, pool.c
drain-loop unix.Malloc, dead_props.c ENOATTR==ENODATA portability,
multipart copy_range arg-order — each carries a phase74-fp/NOLINT proof;
clang-sa/clang-tidy just don't honor the suppressions in an analyze run). Two
HIGH garbage-reads the first pass missed were then fixed directly: s3
handler `key[]` uninit on a parse NGX_DECLINED path (zero-init) and
xrdhttp_stats.c getsockname `sockaddr_storage` (ngx_memzero, same class as pmark)
— both confirmed gone by targeted re-analysis. **Net: zero real analyzer findings
remain anywhere in the repo.**

Follow-on regressions I fixed directly (the S3 dispatch decomposition had the same
swallow-NGX_OK defect on the put-precondition and bare-POST paths): both now use
the NGX_DECLINED sentinel → conditional-PUT and exclusive-create enforce again,
bare POST-to-object → 405. Builds green (module -Werror + client + client tests);
S3 handler suites 181/181, token conformance 144/144, tap-proxy byte-exact
(stat + ckpXeq), serial smoke 406/406. Remaining test failures are Python-3.9
`datetime.UTC` (test_s3_presigned) and the pre-existing proxy_large_read perf
timeout (tap-proxy correctness proven via run_tap_proxy.sh). Top-50 lizard: 5
permanent param-only residuals (the 4 FUSE/vtable-fixed + brix_open_probe, a
file-local CCN-4 probe). check_vfs_seam OK.

## Deliberately out of scope

- Files outside the top-50 with HIGH findings (`src/auth/token/macaroon.c:390`
  ArrayBound, `src/protocols/root/read/statx.c:138` ArrayBound, `src/fs/path/helpers.c:59`,
  `src/fs/vfs/vfs_walk.c:143`, `src/fs/vfs/vfs_io_core.c:495`, `src/fs/vfs/vfs_deleg.c:301`,
  `src/net/upstream/start.c:191`, `src/protocols/root/zip/zip_dir.c:178`,
  `src/protocols/root/write/chkpoint.c:458`, `src/protocols/s3/handler.c:888`,
  `src/protocols/webdav/xrdhttp_stats.c:82`, `src/protocols/shared/file_serve.c:178`,
  pmark `flowlabel.c:162`/`sockstats.c:132`, `query/prepare_qprep.c:270`, remaining
  widening-cast sites) — **queue these as phase-73 candidates**; they are bugs-by-evidence
  but outside this phase's file set.
- `misc-header-include-cycle` (3,788 findings) — needs its own include-graph phase.
- The `-Wno-unused-parameter` policy — deliberate, unchanged.
