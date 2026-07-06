# Unified brix Config Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Historical note (2026-07-06):** this plan documents a hard RENAME and therefore
> deliberately contains the OLD directive names throughout (rename tables, sed patterns,
> pre-flip test snippets). Repo-wide rename sweeps must exclude this file — it was
> collateral-damaged once by its own Task-5 migration sed and restored. Tasks 1–5 are
> complete on main (commits 716e203, 82af896, bd43a20+190bb3c, ed6cac4, 89f8d12, plus
> hotfix 538dec5); Tasks 6–7 remain.

**Goal:** One guessable directive grammar across root://, WebDAV, S3, and cvmfs — per-protocol enables plus a unified bare storage directive set (`brix_export`, `brix_cache_store`, `brix_stage`, …) owned by a new HTTP common module — with a production-grade 3-line cvmfs site cache, loud config errors for unsupported combinations, and matching docs.

**Architecture:** A new `ngx_http_brix_common_module` registers the unified storage/namespace directives exactly once for the HTTP plane, storing them in an `ngx_http_brix_shared_conf_t` it owns; webdav/s3/cvmfs copy the merged values into their embedded `common` structs at `merge_loc_conf` time (module emission order in `./config` guarantees the common module merges first). The stream plane already uses the bare names and only renames its enable (`xrootd`→`brix_root`) and export path (`brix_root`→`brix_export`). Old names are hard-renamed — no aliases.

**Tech Stack:** nginx module C (no goto, functional/modular per `docs/09-developer-guide/coding-standards.md`), bash test harnesses, pytest fleet.

**Spec:** `docs/superpowers/specs/2026-07-05-unified-brix-config-grammar-design.md`

## Global Constraints

- **NO `goto`**; early-return + helper decomposition; WHAT/WHY/HOW doc blocks on every function.
- 3 tests per change-class: success + error + security-negative.
- Never reimplement HELPERS (CLAUDE.md list); use `ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, …); return NGX_CONF_ERROR;` for config rejections.
- New source file ⇒ update `./config`, then `rm -rf /tmp/nginx-1.28.3/objs && (cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd) && make -j$(nproc)` — configure over old objs produces mixed-ABI garbage. No new file ⇒ `make -j$(nproc)` only. Build is `-Werror`.
- Commit directly to `main` after each task (Rob: no feature branches). Do NOT run destructive git commands (stash/reset/checkout/clean).
- `site/src/pages/for/sysadmins.astro` and `site/src/pages/index.astro` carry UNCOMMITTED user edits — touch only directive-name occurrences, via Edit tool, never git-restore.
- Test fleet: `tests/manage_test_servers.sh start|restart|stop`; heavy suites cap xdist at `-n12`; `TEST_OWN_FLEET=1` runs must be SERIAL.
- Hard rename means NO alias code and NO "renamed to X" messages anywhere.

---

### Tasks 1–5 (COMPLETE — see git history and .superpowers/sdd/progress.md)

Task 1 `ngx_http_brix_common_module` (716e203) · Task 2 proto exclusivity (82af896) ·
Task 3 cvmfs rejections (bd43a20, 190bb3c) · Task 4 default flips (ed6cac4) ·
Hotfix shared_merge root_default pointer bug (538dec5) · Task 5 hard-rename flip +
repo-wide migration via `tools/refactor/config_rename_2026_07.sh` (89f8d12).

The original step-by-step text for Tasks 1–5 is preserved in git history
(`git show b9ba81e:docs/superpowers/plans/2026-07-05-unified-brix-config-grammar.md`);
it was trimmed here after the Task-5 sed collateral damage to keep this file's live
content (Tasks 6–7) authoritative and sweep-safe.

---

### Task 6: Docs — cvmfs reference, 3-line examples, migration table

**Files:**
- Modify: `docs/03-configuration/directives.md` (new "Unified storage grammar" intro + full cvmfs directive table with defaults)
- Modify: `docs/03-configuration/examples.md` (cvmfs minimal + production examples)
- Modify: `docs/03-configuration/quick-reference.md` (cvmfs entries)
- Modify: `deploy/cvmfs/README.md` (shrink examples; defaults table)
- Create: `docs/03-configuration/migration-unified-grammar.md` (old→new table)
- Modify: `CLAUDE.md` (grep for renamed directives in ROUTING/RECIPES/FAQ; update hits)

**Interfaces:** consumes the final directive surface from Task 5 and defaults from Task 4 (cvmfs: manifest_ttl 61, negative_ttl 10, client_hold 25, fill_max_life 300, upstream_max 8, origin_connect_timeout 2s, origin_stall_timeout 4s / 1 B, rtt_interval 60, cache_evict_at 90 / evict_to 80, cache_verify cvmfs-cas, origin_select rtt).

- [ ] **Step 1: directives.md** — add the grammar rules (three bullets from the spec §1) at the top of the storage section; add a cvmfs table: every `brix_cvmfs_*` + `brix_scvmfs_*` directive with args, default, one-line purpose (source: `src/protocols/cvmfs/directives_core.inc`, `directives_resilience.inc`, merge defaults in `module.c`). Mark unified directives once, not per protocol.
- [ ] **Step 2: examples.md** — lead the cvmfs section with the 3-line config (spec §3 verbatim), then a "tuned" variant showing ONLY non-default knobs (`brix_cache_verify off`, `brix_cvmfs_origin_select static`, eviction overrides), each with a comment saying what the default already does.
- [ ] **Step 3: quick-reference.md** — one cvmfs row-block mirroring the webdav/s3 style.
- [ ] **Step 4: deploy/cvmfs/README.md** — replace the ~30-line production example with minimal + defaults table; keep monitoring/client/troubleshooting sections; keep the Squid mapping table (Task 5's script already did the mechanical rename; this step is prose coherence).
- [ ] **Step 5: migration-unified-grammar.md** — the full old→new table (from Task 5's commit-message delete-list + stream renames: `xrootd`→`brix_root`, stream `brix_root <path>`→`brix_export`, `brix_webdav_root`/`brix_s3_root`→`brix_export`, per-proto tier+preamble de-prefixing, `brix_cache_root`→`brix_cache_export`), one line of context per family, statement that old names are gone (stock `unknown directive` error). Mark the file sweep-exempt with a note like the spec's.
- [ ] **Step 6: Verify docs contain no stale names:**

```bash
grep -rn 'brix_webdav_root\|brix_s3_root\|brix_cvmfs_cache_store\|brix_webdav_cache_store\|brix_s3_cache_store' docs/ deploy/ --include='*.md' | grep -v 'migration-unified-grammar\|2026-07-05-unified-brix' && echo STALE || echo CLEAN
```
Expected: CLEAN (the migration table and the two superpowers docs legitimately contain old names).

- [ ] **Step 7: Commit** — `git commit -m "docs(config): unified grammar reference, 3-line cvmfs examples, migration table"`

---

### Task 7: New behavior tests + full verification

**Files:**
- Create: `tests/run_cvmfs_minimal.sh` (3-line-config e2e)
- Create: `tests/run_cvmfs_evict.sh` (eviction under cvmfs)
- Test: full suites

- [ ] **Step 1: `run_cvmfs_minimal.sh`** — clone the harness skeleton of `tests/run_cvmfs_reverse.sh` (mock origin + nginx + curl) but the nginx location block contains ONLY the three directives (`brix_cvmfs on; brix_cache_store …; brix_storage_backend …;`). Assert: (success) a CAS object fetch round-trips byte-exact and lands in the cache store; (security-neg) a corrupt object from the mock origin is rejected (verify is on by default — reuse the corrupt-fill trick from `run_cvmfs_verify.sh`); (error) a 404 path returns 404 and the negative-TTL caches it (model `run_cvmfs_manifest.sh` assertions).
- [ ] **Step 2: `run_cvmfs_evict.sh`** — model `tests/run_tier_remote_evict.sh` + `run_cvmfs_reverse.sh`: tiny cache store with low `brix_cache_evict_at 50; brix_cache_evict_to 20;` and a few MB of objects, fill past the threshold via the mock origin, assert the reaper evicts (object count/bytes drop; eviction runs on a per-worker timer — poke via enough fills + wait, mirroring how the watermark tests wait). Assert manifest/pinned objects survive per existing eviction-guard semantics.
- [ ] **Step 3: Run both new scripts** — expected PASS (they test behavior already landed in Tasks 1–5; if eviction proves un-triggerable in a quick script, mark the eviction assertion clearly and check with Rob rather than shipping a fake-green test).
- [ ] **Step 4: Full verification sweep:**

```bash
tests/manage_test_servers.sh restart
PYTHONPATH=tests pytest tests/ -n12 -m "not slow" -q --tb=short   # --pr gate
for s in tests/run_cvmfs_*.sh tests/run_unified_conf.sh; do bash "$s" || echo "FAILED: $s"; done
tools/ci/check_config_coverage.sh && tools/ci/check_vfs_seam.sh && tools/ci/check_file_size.sh
```
Expected: gate green (known load-flakes pass serially), all scripts green, all guards green.
- [ ] **Step 5: Update CLAUDE.md AGENT GUIDE** — OP→FILE: add `unified config / common module | src/core/config/http_common.c, src/protocols/shared/proto_exclusive.c`; RECIPES "New config directive": note unified storage names live in the common module; ROUTING/example directives if any renamed ones appear.
- [ ] **Step 6: Commit** — `git commit -m "test(cvmfs): 3-line-config e2e + eviction coverage; agent-guide updates"`

---

## Self-review notes (already applied)

- Spec §1 (grammar+renames)→Tasks 1+5; §2 (foot-guns+exclusivity)→Tasks 2+3 (+eviction exposure free via Task 1); §3 (defaults)→Task 4; §4 (docs)→Task 6; §5 (tests)→every task + Task 7. Coverage complete.
- Deliberate sequencing: unified names become VALID (Task 1) → validations/defaults on the new surface (2–4) → old names removed atomically with config migration (5) → docs (6) → behavior tests + sweep (7). Every commit leaves the tree green.
