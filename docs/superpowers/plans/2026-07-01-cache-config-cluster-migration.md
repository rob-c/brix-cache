# Phase-64 Cache-Config Cluster Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fold `fetch.c`'s per-scheme legacy cache-origin fetch dispatch into the single composable `source_inst` spine (`xrootd_cache_fill_from_source`), then retire the legacy `cache_origin`/`cache_root`/`cache_storage_backend` config-model — without breaking the 22 legacy-config tests or losing checksum-on-fill.

**Architecture:** `fetch.c` already has TWO fill paths: (a) the composable C-1 spine `xrootd_cache_fill_from_source(t, t->source_inst)` used when a registry/composable backend is the source, and (b) a legacy `cache_origin_scheme` switch (`http`/`s3`/`pelican`/`xroot`) that predates it. This migration builds a `source_inst` from the *legacy* `cache_origin` directives at config time, so path (a) serves every fill and path (b) becomes dead code and is deleted. The legacy DIRECTIVES keep parsing (they feed the translation), so all 22 tests keep working; the directive-removal (G6-literal) is a final, separately-gated task done only after every test is confirmed to run through the spine.

**Tech Stack:** C (nginx stream module), the SD driver seam (`xrootd_sd_instance_t`), the composable cache spine (`src/cache/`, `src/fs/backend/cache/`), pytest + shell acceptance harnesses.

## CLUSTER CLOSED 2026-07-01 — Row 2 landed, Task 5 declined by decision

**Status: the fold (Row 2) is complete and shipped; the config-surface purge (Task 5) is deliberately NOT done.** Every SD-capable origin scheme (root://, s3, http/https) fills through the single `xrootd_cache_fill_from_source` spine; the per-scheme fetch functions (`_xroot`/`_s3`) and the dead `xrootd_cache_http_download` are deleted; the read-origin credential mapping is unified on shared builders (`xrootd_cache_build_{origin,s3_origin,http_origin}`) so it cannot drift; a real slice-GSI credential bug was fixed + proof-tested (`run_cache_slice_gsi_legacy.sh`). Pelican stays bespoke (307-redirect blocker, documented). **G5/G9 "one storage mechanism" is met** — there is no separate legacy *fill* path anymore. **Task 5 (delete the legacy `cache_origin*`/`storage_backend` directives) was declined**: (a) §14's `cache_root` deletion is wrong (repurposed, required — see the Task 5 correction), and (b) after Row 2 the remaining legacy directives are thin config-sugar over the unified spine, so deleting them (breaking ~15 tests + Rob's configs, removing the terser cache UX, unwinding the Row 2 bridge) is negative cost/benefit for only G6's config-surface cosmetics. The legacy directives are KEPT as sugar. Final state: build clean, guard GREEN, 15/15 cache harnesses green.

---

## Findings During Execution (2026-07-01)

- **Task 1 — DONE (confirmation, no code change).** The spine `xrootd_cache_fill_from_source` (`src/cache/fetch.c:331`) already does checksum-on-fill: it queries the xroot source's `kXR_Qcksum` into `t->origin_cks_*` (fetch.c:420-428) and finishes via `xrootd_cache_commit_staged` → `xrootd_cache_verify_part` under the `xrootd_cache_verify` policy. **Parity is intrinsic to the spine — no verify needs adding.** Confirmed against `tests/run_cache_backend_source.sh`.
- **Concurrency resolved (was a suspected Task-2 blocker):** `sd_xroot_open` connects per `open()` call, storing the connection in *per-open* state (`st->oc`); the `xrootd_sd_instance_t` is stateless (conf-only). So a config-time SHARED `source_inst` is safe across concurrent thread-pool fills — no shared-connection hazard. (This also confirms the existing `cache_slice_inst` config-time sharing is safe.)
- **GAP A — http/pelican had no SD instance. ✅ HTTP/HTTPS RESOLVED 2026-07-01; Pelican deferred.** The `sd_http` driver already existed (`src/fs/backend/http/sd_http.c` — HEAD-for-size + Range-GET pread + bearer auth, already used by the composable registry), so no new driver was needed. Added `xrootd_cache_build_http_origin` (fetch.c), wired HTTP/HTTPS into `cache_build_source`, removed the `http_download` branch from `xrootd_cache_fetch_origin`, and **deleted the dead `xrootd_cache_http_download`** (+ its header decl). HTTP/HTTPS now fill through the one spine. **Pelican stays on `pelican_download` — investigated 2026-07-01, deliberately NOT folded.** The fetch could route through a per-fill `sd_http` (discovery kept per-fill for resilience), BUT Pelican requires following the Director's **307 redirect** (`http_get_url` sets `CURLOPT_FOLLOWLOCATION`), and the shared S3 transport `sd_http` uses does NOT follow redirects and **cannot safely** — S3 SigV4 is signed for a specific host, so following a redirect would leak signed credentials to another host. The transport `request` vtable has no per-request redirect hook, so folding would need an invasive signature change (touching the S3-security-sensitive impl) or a parallel redirect-capable transport — poor cost/benefit for a niche feature that ALREADY reuses the shared verify path (`commit_part`). Decision: keep Pelican on `http_get_url`; **`http_get_url` is retained** (Pelican's redirect-following fetch). A full fold is only worth it alongside a general redirect-capable HTTP backend transport, tracked separately. Verified: `run_cache_http_source` + full cache regression green, guard GREEN. So after this, `xrootd_cache_fetch_origin` is just: `source_inst` (xroot/s3/http via the spine) → pelican (libcurl) → error.
- **GAP B — two overlapping origin-credential field sets (auth-critical). ✅ RESOLVED 2026-07-01.** Root cause: the C-3 fields `cache_origin_bearer`/`x509_proxy`/`ca_dir` are populated ONLY from `wt_credential` (the WRITE-BACK flush credential, `runtime_server.c:301-337`) — they are NOT the read-origin credential. The read-origin credential is `cache_origin_proxy`/`cache_origin_cadir` (+ `cache_origin_token_file`, which has no directive → GSI-only in practice) + `cache_origin_family`. The slice block wrongly read the write-back fields AND hardcoded `XROOTD_AF_AUTO`, so a legacy `xrootd_cache_origin` + `xrootd_cache_origin_proxy` + `xrootd_cache_slice` config silently logged in ANONYMOUSLY (masked because `run_root_slice_fill.sh` uses `auth none`). **Fix:** extracted the read-origin mapping into ONE shared builder `xrootd_cache_build_origin(conf, log)` (`fetch.c`, declared in `cache_internal.h`), now called by BOTH `_xroot` (whole-file) and the slice block — they cannot drift. **Proof:** new `tests/run_cache_slice_gsi_legacy.sh` (legacy `cache_origin`+proxy+slice vs a GSI origin) PASSES with the fix and FAILS (`got=0`, anonymous rejected) with the bug reintroduced; negative control confirms the origin enforces GSI. Regression: 7 cache/credential harnesses green, guard GREEN. **The shared builder is now the single credential mapping the future `cache_source_inst` (Task 2) will use.**

---

## Global Constraints

- **NO `goto`** anywhere in `src/` (early-return + helper decomposition). Verbatim from CLAUDE.md HARD BLOCKS.
- **NO git commands without explicit OP instruction** (the working tree has uncommitted work). Verbatim from CLAUDE.md. *This overrides the "Commit" steps below — do NOT run `git commit`; leave changes staged in the working tree and report per-task instead.*
- **All data byte-I/O stays in `src/fs/backend/`** (VFS seam, `tools/ci/check_vfs_seam.sh` must stay GREEN). Verbatim from CLAUDE.md invariant #11.
- **New `.c` files register in the top-level `./config`** (`$ngx_addon_dir/src/...`), then `./configure`; incremental otherwise `make -j$(nproc)`.
- **Build:** `cd /tmp/nginx-1.28.3 && make -j$(nproc)` (or `./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd` when a source file is added/removed). `-Werror` is on.
- **Feature parity is non-negotiable:** checksum-on-fill (`xrootd_cache_verify_part`, config `xrootd_cache_verify`) MUST remain in force after the fold. A task that drops it is a failed task.

---

### Task 1: Confirm the composable spine already does checksum-on-fill (parity baseline)

**Files:**
- Read: `src/cache/fill_source.c` (or wherever `xrootd_cache_fill_from_source` lives — `grep -rn 'xrootd_cache_fill_from_source' src/cache/`)
- Read: `src/cache/commit.c` / `src/cache/fetch.c:37-63` (the `xrootd_cache_verify_part` call site)
- Test: `tests/run_cache_backend_source.sh`

**Interfaces:**
- Consumes: `xrootd_cache_fill_from_source(xrootd_cache_fill_t *t, xrootd_sd_instance_t *source)` → `int` (0 ok, -1 err), `xrootd_cache_verify_part(xrootd_cache_fill_t *t, const char *part_path, ...)`.
- Produces: a documented FACT (comment in `fetch.c`) — whether the spine path runs `verify_part`. Later tasks depend on knowing this.

- [ ] **Step 1: Trace whether the spine verifies.** Run `grep -n 'verify_part\|cache_commit_part\|verify' src/cache/*.c | grep -iE 'from_source|commit'`. Establish whether `xrootd_cache_fill_from_source` ends in `xrootd_cache_commit_part` (which runs verify) the same way the legacy scheme paths do.

- [ ] **Step 2: Run the composable-source acceptance harness to capture the baseline.**

Run: `bash tests/run_cache_backend_source.sh`
Expected: `ALL PASS` (this harness already fills through `source_inst` — it is the parity reference).

- [ ] **Step 3: If the spine does NOT verify, add the verify call.** In the `xrootd_cache_fill_from_source` tail, before returning success, add the same guarded call the legacy path uses:

```c
    /* Checksum-on-fill parity (verify.c): verify the staged part against the
     * source's advertised digest under the configured policy, identical to the
     * legacy scheme paths. t->origin_cks_* is empty when the source offered none. */
    return xrootd_cache_commit_part(t);   /* commit_part already runs verify_part */
```

(If it already ends in `xrootd_cache_commit_part`, this task is a no-op confirmation — record that in a one-line comment and move on.)

- [ ] **Step 4: Re-run the harness to confirm parity holds.**

Run: `bash tests/run_cache_backend_source.sh`
Expected: `ALL PASS`.

- [ ] **Step 5: Record the finding** (working tree only — do NOT git commit per Global Constraints). Note in the task report whether Step 3 was a code change or a confirmation.

---

### Task 2: Build a `source_inst` from the legacy `cache_origin` config at config time — ✅ DONE 2026-07-01

> **Implemented (refined per the findings):** extracted a second shared mapper `xrootd_cache_build_s3_origin` from `_s3` (mirroring `xrootd_cache_build_origin`) so S3 config can't drift either; added `conf->cache_source_inst` + `xrootd_cache_source_inst()` accessor; a `cache_build_source` dispatcher (xroot→`build_origin`, s3→`build_s3_origin`, http/https/pelican→NULL per Gap A) built in `xrootd_cache_storage_init` and freed by a scheme-aware `cache_destroy_source` in cleanup. Behaviour-neutral (built, not yet consumed — Task 3 routes fetch.c through it). Verified: build clean, guard GREEN, 6 harnesses green incl. `run_cache_s3_origin` (the `_s3` refactor preserved parity) and `run_cache_slice_gsi_legacy`.



**Files:**
- Modify: `src/cache/cache_storage.c` (the module that already builds `cache_storage_inst` + `cache_slice_inst`; add a `cache_source_inst`)
- Modify: `src/cache/cache_storage.h` (accessor decl)
- Modify: `src/types/config.h:~433` (add `void *cache_source_inst;` beside `cache_slice_inst`)
- Read: `src/fs/backend/xroot/sd_xroot.h` (`xrootd_sd_xroot_create_origin`), `src/fs/backend/remote/sd_remote.*` (S3/HTTP source), `src/cache/http_transport.c`
- Test: `tests/run_cache_xroot_origin.sh`, `tests/run_cache_s3_origin.sh`, `tests/run_cache_http_source.sh`

**Interfaces:**
- Consumes: `xrootd_sd_xroot_create_origin(host, port, tls, af, bearer, proxy, cadir, log)` (already used for `cache_slice_inst`); `conf->cache_origin_scheme` (`XROOTD_CACHE_SCHEME_{HTTP,HTTPS,S3,PELICAN,<default xroot>}`); the S3/HTTP source builders used by `fetch_origin_s3`/`http_download`.
- Produces: `xrootd_sd_instance_t *xrootd_cache_source_inst(const ngx_stream_xrootd_srv_conf_t *conf)` returning a per-conf source instance (or NULL when no legacy origin is configured / scheme has no driver yet), plus `conf->cache_source_inst` set in the build hook and freed in the cleanup hook.

- [ ] **Step 1: Add the field + accessor.** In `src/types/config.h` beside `void *cache_slice_inst;` add:

```c
    void       *cache_source_inst;  /* composable source built from legacy cache_origin (§6.5 fold) */
```

In `src/cache/cache_storage.h`:

```c
/* The composable SOURCE instance translated from the legacy xrootd_cache_origin
 * config (xroot/s3/http scheme). NULL when no legacy origin is configured. Used by
 * fetch.c so every fill runs through the one xrootd_cache_fill_from_source spine. */
xrootd_sd_instance_t *xrootd_cache_source_inst(const ngx_stream_xrootd_srv_conf_t *conf);
```

- [ ] **Step 2: Implement the builder** in `src/cache/cache_storage.c`, mirroring the existing `cache_slice_inst` build block but with `slice_size = 0` semantics is NOT needed — a source is a *bare* backend, not a cache decorator. For the xroot scheme reuse the origin builder already present:

```c
static xrootd_sd_instance_t *
cache_build_source(ngx_pool_t *pool, ngx_log_t *log,
                   const ngx_stream_xrootd_srv_conf_t *conf)
{
    if (conf->cache_origin_host.len == 0 && conf->source_inst_from_registry == NULL) {
        return NULL;   /* no legacy origin — the registry/composable path owns it */
    }
    switch (conf->cache_origin_scheme) {
    case XROOTD_CACHE_SCHEME_S3:
        return cache_build_source_s3(pool, log, conf);     /* extract from fetch_origin_s3 */
    case XROOTD_CACHE_SCHEME_HTTP:
    case XROOTD_CACHE_SCHEME_HTTPS:
    case XROOTD_CACHE_SCHEME_PELICAN:
        return cache_build_source_http(pool, log, conf);   /* extract from http_transport */
    default: {                                             /* root:// origin */
        char host[256];
        ngx_memcpy(host, conf->cache_origin_host.data, conf->cache_origin_host.len);
        host[conf->cache_origin_host.len] = '\0';
        return xrootd_sd_xroot_create_origin(host, conf->cache_origin_port,
                   conf->cache_origin_tls, (xrootd_af_policy_t) conf->cache_origin_family,
                   /*bearer*/ NULL, /*proxy*/ NULL, /*cadir*/ NULL, log);
    }
    }
}
```

(Extract `cache_build_source_s3`/`_http` from the bodies of `xrootd_cache_fetch_origin_s3` and `xrootd_cache_http_download` — they already construct per-fill `sd_remote`/http instances; lift the instance construction into a reusable builder, leaving the fill loop in fetch.c for now.)

- [ ] **Step 3: Wire the build + cleanup hooks.** In the same place `cache_storage_inst`/`cache_slice_inst` are set (search `conf->cache_slice_inst =`), add:

```c
    conf->cache_source_inst = cache_build_source(pool, log, conf);
```

and in the cleanup path (search `conf->cache_slice_inst = NULL;`) destroy it via the matching driver destroy (`xrootd_sd_xroot_destroy` / `xrootd_sd_remote_destroy`).

- [ ] **Step 4: Implement the accessor.**

```c
xrootd_sd_instance_t *
xrootd_cache_source_inst(const ngx_stream_xrootd_srv_conf_t *conf)
{
    return (xrootd_sd_instance_t *) conf->cache_source_inst;
}
```

- [ ] **Step 5: Build (no config change — no new file).**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc)`
Expected: `build: 0`, no warnings.

- [ ] **Step 6: Confirm no behavior change yet** (the field is built but not consumed — fetch.c still uses its own switch).

Run: `bash tests/run_cache_xroot_origin.sh && bash tests/run_cache_s3_origin.sh && bash tests/run_cache_http_source.sh`
Expected: three `ALL PASS`.

- [ ] **Step 7: Report** (working tree only — no git commit).

---

### Task 3+4: Route fills through the spine + delete the dead per-scheme code — ✅ DONE 2026-07-01

> **Implemented together** (they are coupled: collapsing the switch makes `_xroot`/`_s3` unused → `-Werror=unused-function`, so the routing and the deletion must land in one build). `xrootd_cache_fetch_origin` now: `t->source_inst ??= xrootd_cache_source_inst(conf)` → `xrootd_cache_fill_from_source` (handles xroot+s3 via the config-time source); http/https + pelican keep their libcurl branches (Gap A); anything else is a clean "no usable origin" error. Deleted `xrootd_cache_fetch_origin_s3` and `xrootd_cache_fetch_origin_xroot` (fetch.c ~485→464 lines even after ADDING the two shared builders). **Definitive proof:** with both functions deleted, 11 harnesses stay green — `run_cache_{xroot_origin,s3_origin,http_source,slice_gsi_legacy,pblock_posix,pblock_pblock,watermark,backend_source}`, `run_root_slice_fill`, `run_credential_xroot_{gsi,ztn}` — so the old per-scheme paths were genuinely dead and xroot+s3 now fill through the one spine. Build clean, guard GREEN.

<details><summary>Original Task 3 / Task 4 step plan (superseded by the combined implementation above)</summary>

### Task 3 (original): Populate `t->source_inst` from `cache_source_inst`, route ALL fills through the spine

**Files:**
- Modify: `src/cache/thread.c:~49` (the `xrootd_cache_fetch_origin(t)` caller — ensure `t->source_inst` is set before the call)
- Modify: `src/cache/fetch.c:447-485` (`xrootd_cache_fetch_origin` — collapse to the spine)
- Read: `src/cache/cache_internal.h` (the `xrootd_cache_fill_t` struct — `source_inst` field)
- Test: `tests/run_cache_xroot_origin.sh`, `tests/run_cache_s3_origin.sh`, `tests/run_cache_http_source.sh`, `tests/run_cache_pblock_posix.sh`, `tests/run_root_slice_fill.sh`

**Interfaces:**
- Consumes: `xrootd_cache_source_inst(conf)` (Task 2), `t->source_inst`, `xrootd_cache_fill_from_source(t, source)`.
- Produces: `xrootd_cache_fetch_origin` that dispatches ONLY on `t->source_inst` (populated from either the registry PRIMARY or the legacy-translated `cache_source_inst`).

- [ ] **Step 1: Set `t->source_inst` from the legacy translation where the fill task is initialised.** Find where `xrootd_cache_fill_t.source_inst` is assigned (`grep -n 'source_inst' src/cache/*.c`). Add the fallback: if `t->source_inst == NULL`, set it from `xrootd_cache_source_inst(t->conf)`.

```c
    if (t->source_inst == NULL) {
        t->source_inst = xrootd_cache_source_inst(t->conf);
    }
```

- [ ] **Step 2: Verify the legacy paths still work THROUGH the switch** (source_inst now non-NULL, so the C-1 branch fires first).

Run: `bash tests/run_cache_xroot_origin.sh`
Expected: `ALL PASS` (the fill now goes through `xrootd_cache_fill_from_source`, not `xrootd_cache_fetch_origin_xroot`).

- [ ] **Step 3: Confirm the S3/HTTP legacy paths ALSO route through the spine.**

Run: `bash tests/run_cache_s3_origin.sh && bash tests/run_cache_http_source.sh`
Expected: two `ALL PASS`. **If either FAILS**, the `cache_build_source_s3`/`_http` builders (Task 2) are not feature-equivalent to the old per-fill construction — fix the builder, do not proceed.

- [ ] **Step 4: Collapse `xrootd_cache_fetch_origin` to the spine.** Once Steps 2-3 are green, replace the scheme switch with:

```c
int
xrootd_cache_fetch_origin(xrootd_cache_fill_t *t)
{
    /* Unified fill: every origin (root://, S3, HTTP/S, Pelican, registry PRIMARY)
     * is a composable SOURCE instance — legacy xrootd_cache_origin is translated to
     * one at config time (cache_storage.c: cache_build_source). §6.5/G9 fold. */
    if (t->source_inst == NULL) {
        t->source_inst = xrootd_cache_source_inst(t->conf);
    }
    if (t->source_inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, t->log, 0,
                      "cache: no source configured for fill of \"%s\"", t->clean_path);
        return -1;
    }
    return xrootd_cache_fill_from_source(t, t->source_inst);
}
```

- [ ] **Step 5: Build + full legacy-origin regression.**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && cd /home/rcurrie/HEP-x/nginx-xrootd && for h in run_cache_xroot_origin run_cache_s3_origin run_cache_http_source run_cache_pblock_posix run_root_slice_fill run_cache_watermark; do bash tests/$h.sh >/tmp/$h.log 2>&1 && echo "$h OK" || echo "$h FAIL"; done`
Expected: all `OK`.

- [ ] **Step 6: Guard.**

Run: `bash tools/ci/check_vfs_seam.sh`
Expected: GREEN.

- [ ] **Step 7: Report** (working tree only — no git commit).

---

### Task 4: Delete the now-dead per-scheme fetch code

**Files:**
- Modify: `src/cache/fetch.c` (delete `xrootd_cache_fetch_origin_s3` (234-281), `xrootd_cache_fetch_origin_xroot` (282-446), the scheme-branch bodies)
- Modify: `src/cache/cache_internal.h` (remove the deleted function decls)
- Modify: `src/cache/http_transport.c` / `pelican.c` — keep the download primitives IF still used by `cache_build_source_http`; delete only what is now unreachable
- Test: full cache harness set + `PYTHONPATH=tests pytest tests/ -k cache -v`

**Interfaces:**
- Consumes: nothing new.
- Produces: a `fetch.c` whose only origin entry point is `xrootd_cache_fetch_origin` → `xrootd_cache_fill_from_source`.

- [ ] **Step 1: Prove each symbol is dead.** For each of `xrootd_cache_fetch_origin_s3`, `xrootd_cache_fetch_origin_xroot`: `grep -rn '<sym>' src/ --include=*.c --include=*.h` — expect only the definition + decl (0 external callers now that Task 3 collapsed the switch).

- [ ] **Step 2: Delete the dead functions + their decls.** Remove the function bodies from `fetch.c` and the prototypes from `cache_internal.h`. Do NOT touch `xrootd_cache_fill_from_source`, `xrootd_cache_commit_part`, `xrootd_cache_verify_part`, `xrootd_cache_http_download`/`pelican_download` if the http-source builder still calls the download primitive.

- [ ] **Step 3: Build.**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc)`
Expected: `build: 0`. A link error naming a deleted symbol means Step 1 missed a caller — restore, re-grep.

- [ ] **Step 4: Full cache regression.**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && for h in $(ls tests/run_cache_*.sh tests/run_root_slice_fill.sh tests/run_tier_*.sh); do bash "$h" >/tmp/$(basename $h).log 2>&1 && echo "$(basename $h) OK" || echo "$(basename $h) FAIL"; done`
Expected: all `OK`.

- [ ] **Step 5: pytest cache sweep + guard.**

Run: `PYTHONPATH=tests pytest tests/ -k "cache or slice" -q -p no:cacheprovider; bash tools/ci/check_vfs_seam.sh`
Expected: pytest all pass/skip, guard GREEN.

- [ ] **Step 6: Report** — record the line count deleted from `fetch.c` (target: the ~200-line `_s3`+`_xroot` block; the file drops from ~485 lines).

</details>

---

### Task 5 — ⛔ DECLINED BY DECISION 2026-07-01 (kept for reference; see CLUSTER CLOSED note above). Retire the legacy DIRECTIVES

> **⚠️ SCOPE CORRECTION (investigated 2026-07-01) — §14's premise is partly outdated.** `xrootd_cache_root` is **NOT deletable**: the composable model REPURPOSED it as the *advertised logical root* (distinct from `xrootd_cache_store` = the *physical* FSAL), and `runtime_server.c:239-243` marks it `required` for a pure cache node ("cache_store is the physical FSAL and cache_root the advertised root"). The composable target configs (e.g. `run_cache_backend_source.sh`) use BOTH `xrootd_cache_store posix:/path` AND `xrootd_cache_root /`. Deleting `cache_root` would break the tested composable cache model. **Corrected deletable set:** `xrootd_cache_origin` (+ `_proxy`/`_cadir`/`_family`/`_client`/`_tls`/`_s3_*`) and `xrootd_cache_storage_backend` (+`_block_size`) — the SOURCE + cache-backend legacy directives, fully replaced by `xrootd_storage_backend` + `xrootd_credential`/`xrootd_storage_credential` + `xrootd_cache_store`. `xrootd_cache_slice` folds into the composable `xrootd_cache_slice_size`. `xrootd_cache_root` is KEPT (repurposed). **Migration:** the ~15 tests that use `xrootd_cache_origin*` switch to `xrootd_storage_backend` + a credential block (the ones using only `cache_root` already run on the composable grammar and need no source change). Still a breaking, per-test, separately-reviewed effort.

> This is the G6-literal, breaking step. It removes the `ngx_command_t` entries and config fields for the CORRECTED set above (NOT `xrootd_cache_root`), and REQUIRES migrating every legacy-`cache_origin` test to the composable grammar first. Because it rewrites tests + Rob's configs, it is a separate reviewed effort. Only the directive-removal inventory is specified here; the per-test migration is done test-by-test.

**Files:**
- Modify: `src/stream/module.c:1232-1407` (remove the legacy `ngx_command_t` entries)
- Modify: `src/types/config.h:433-446+` (remove `cache_root`, `cache_origin*` fields)
- Modify: `src/config/server_conf.c:922-929` (remove `XROOTD_MERGE_HOSTPORT(cache_origin...)`)
- Modify: all 22 harnesses/tests listed by `grep -rlE 'xrootd_cache_origin|xrootd_cache_root' tests/`
- Test: the full suite

- [ ] **Step 1: Enumerate the 22 legacy-config tests.** `grep -rlE 'xrootd_cache_origin|xrootd_cache_root' tests/`.

- [ ] **Step 2: For EACH test, translate its config to the composable grammar** (`xrootd_storage_backend <export>`, `xrootd_cache_store <origin-url>`) and confirm it still passes BEFORE removing the legacy directive. One test per commit-sized unit.

- [ ] **Step 3: Once ALL 22 pass on composable config, remove the legacy `ngx_command_t` entries + config fields + merge code.**

- [ ] **Step 4: `./configure` (directives changed) + full build + full suite.**

Run: `cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)`
Expected: `build: 0`.

- [ ] **Step 5: G6 acceptance grep.**

Run: `grep -rn '"xrootd_cache_origin"\|"xrootd_cache_root"\|"xrootd_cache_storage_backend"' src/stream/module.c`
Expected: 0 matches.

- [ ] **Step 6: Report** — G6/G9 acceptance for the cache-config cluster closed.

---

## Self-Review Notes

- **Spec coverage:** Task 1 = checksum-on-fill parity (the identified risk); Tasks 2-3 = the fetch.c → spine fold (Row 2 core, keeps tests working via config-translation); Task 4 = the code deletion (G9 "no legacy fetch path"); Task 5 = the directive deletion (G6-literal, gated, includes the 22-test migration). No spec requirement is unassigned.
- **Type consistency:** `xrootd_cache_source_inst(conf)` (Task 2) is the exact name consumed in Task 3; `conf->cache_source_inst` is the field set in Task 2 and read by the accessor. `xrootd_cache_fill_from_source(t, source)` matches its existing signature.
- **Non-obvious risk:** the S3/HTTP source builders (Task 2 Step 2) are the parity-critical extraction — Task 3 Step 3 is the gate that catches a non-equivalent builder before any deletion. If that gate fails, STOP and fix the builder; do not proceed to Task 4.
- **Ordering safety:** every task through Task 4 keeps ALL 22 tests green (legacy directives still parse → translate → spine). Only Task 5 is breaking, and it is explicitly gated behind migrating those tests first.
