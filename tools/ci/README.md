# tools/ci — invariant guards

Every script here encodes a project invariant as a red/green check. All of
them run in CI on every PR/push (`.github/workflows/guards.yml`) and — bar the
minutes-long ones — in the pre-push hook (`tools/git-hooks/pre-push`, install
once with `git config core.hooksPath tools/git-hooks`). Run any of them locally
with no arguments; exit 0 = clean.

**Which guards run where is answered by one script, not by a filename glob:**
`guard_set.py` prints the pre-push set (default), the CI-enforced set (`--ci`,
= every guard `guards.yml` names), or the whole fleet (`--all`); `--explain`
shows each guard's lane and why anything is excluded. The pre-push exclusions
live in its `PREPUSH_SKIP` map, each with a written reason. Nothing else may
pattern-match guard filenames: the hook used to glob `tools/ci/check_*.sh` and
kept doing so after the 2026-07-21 port to Python, so it enforced zero guards
while failing every push on the unmatched pattern (fixed 2026-08-03; regression
tests in `tests/test_ci_guards.py`). Adding a guard means dropping the file in,
naming it in `guards.yml`, and `chmod +x` — the hook and the tests pick it up.

These guards are **pure Python** — the fleet was ported from bash `.sh` to
`.py` on 2026-07-21 (locale-independent, testable, no shell parsing traps); no
bash remains. Each is self-contained with a `run(root) -> (ok, lines)` verdict
plus a `main()`; the ratchets keep a `--regen` mode.

The guards also run inside the normal pytest gate, so a violation reddens the
local test loop, not just CI:
- `tests/test_ci_guards.py` executes the real `tools/ci/*.py` scripts
  end-to-end — the fast static guards every run, the lizard-backed ratchets
  (`check_complexity`, `check_duplication`) when `lizard` is installed, and the
  analyzer/coverage/sanitizer runners (`run_fanalyzer`, `run_codechecker`,
  `coverage`, `asan`) in the `slow`/nightly lane when a configured build + tool
  are present (the `asan` runner has its own `tests/test_ci_asan_lane.py`).
- `tests/test_source_guards.py` asserts the fast in-process verdict twins
  (`source_guards_lib`) and drives their injected-tree negative cases.

Run just the guard gate with
`PYTHONPATH=tests pytest tests/test_ci_guards.py tests/test_source_guards.py -v`.

The tool-backed guards (`check_complexity`, `check_duplication`,
`run_codechecker`) need their analysers: `pip install --user -r
requirements-dev.txt` from the repo root. They self-skip when a tool is absent,
so a missing install degrades to "not checked", never to a false green — which
is also why those versions are bounded: a new major that redefines a metric
would move a frozen baseline under us.

| Script | Invariant enforced | Backlog / baseline | Regen |
|---|---|---|---|
| `check_config_coverage.py` | every `src/**/*.c` is built via `./config`, or allowlisted with a reason; no stale `./config` entries | inline allowlist | edit allowlist |
| `check_client_build_coverage.py` | every `.c` under `client/` + the client-only `shared/{cvmfs,cache}` is named by `client/Makefile`, directly included as a continuation, is a `*_unit.c`/`*_unittest.c` driver, or is allowlisted with a reason | inline allowlist (empty) | edit allowlist |
| `check_make_recipes.py` | no target in a hand-maintained Makefile carries two recipes — make keeps the last and silently drops the other copy's prerequisites, so the object stops rebuilding when they change (SKIPs where `make` is absent) | inline `MAKEFILES` | edit list |
| `check_vfs_seam.py` | no new storage-plane bypasses of the VFS (tier-2 confined-helper calls, tier-1.5 direct SD vtable I/O) | `vfs_seam_backlog.txt`, `_ns`, `_client` | `--regen` |
| `check_http_helper_reimpl.py` | protocols must not regrow private copies of the shared HTTP helpers (header scan, preconditions, ETag) | inline allowlist | edit allowlist |
| `check_curl_enum_ifdef.py` | no `#ifdef`/`#ifndef`/`defined()` preprocessor test on a `CURLOPT_*`/`CURLINFO_*` name — those are enum constants, so the test is always false and silently deletes the branch it guards; gate on `CURL_AT_LEAST_VERSION(maj, min, patch)` instead | — | — |
| `check_auth_verdict_sentinel.py` | the session verdict `login.auth_done = 1` may be raised only by a credential handler / session login-bind path — not from a proxy/TPC/dispatch/op file (C-3 `NGX_OK`-on-deny discipline) | inline `ALLOW` | edit allowlist |
| `check_sd_driver_conformance.py` | every `fs_list.h` storage driver ships a conforming `brix_sd_driver_t` (+ prints the op-coverage matrix) | — | — |
| `check_vfs_identity_branch.py` | the VFS branches on capabilities (`brix_sd_caps`/`_supports`/`_cred_accept`), never on a concrete backend or protocol identity (phase-71) | `vfs_identity_backlog.txt` (target 0) | `--regen` |
| `check_metric_cardinality.py` | no Prometheus label whose VALUE is string-interpolated under a name outside the curated low-cardinality vocabulary (INVARIANT #8, CWE-770) | inline vocabulary + per-line `metric-cardinality-allow:` | edit vocabulary |
| `check_metric_names.py` | every `brix_*` metric the docs, the site and `contrib/` cite exists in the exposition, with the labels it really carries — a fabricated family matches nothing in Prometheus, so the alert built on it never fires | `metric_names_backlog.txt` (empty — keep it that way) + per-line `metric-names-allow:` | `--regen` |
| `check_client_flags_doc.py` | every `--flag` the docs, the man pages and the plans write against a shipped client tool is one that tool's argv walk actually matches — the row that mattered offered `--require-digest` as a registry-MITM mitigation before it existed, and a mitigation nobody can type reads as closed | none (the tree is at zero) + per-line `client-flags-allow:` | `--dump` |
| `check_brix_namespace.py` | no pre-rebrand `xrootd_`/`XROOTD_`/`ngx_xrootd*`/`xrdc_`/`libxrdc` token reintroduced under `src/`, `config`, or `client/` | inline EXCLUDE | — |
| `check_gridftp_interop_image.py` | the GridFTP interop lab's client-image / runner / matrix contract stays in agreement — no reference client stack, listener, or env-var name silently dropped | — | — |
| `check_shm_mutex.py` | SHM tables are created via `brix_shm_table_*` — no bare `ngx_shmtx_create()` call outside `src/core/compat/shm_slots.c` (INVARIANT #10) | — | — |
| `check_file_size.py` | no `src/`/`client/` file crosses the 600-line cap; the backlog is EMPTY — split, never grandfather | `file_size_backlog.txt` | `--regen` |
| `check_complexity.py` | every native function under `src/`+`client/`+`shared/` must have CCN ≤15 (lizard/McCabe) | — (no exemptions) | fix the function |
| `check_python_quality.py` | every Python function under the pytest suite, `client/`, `shared/`, `src/`, and the remaining Python project trees must meet CCN (15), cognitive complexity (10), NPath (15), Halstead difficulty (5), and maximum nesting (10) | — (no exemptions) | fix the function |
| `check_todo_fixme.py` | no NEW `TODO`/`FIXME`/`XXX`/`HACK` marker in `src/`+`client/`+`shared/`; frozen per-file counts may only shrink | `todo_fixme_backlog.txt` | `--regen` |
| `check_duplication.py` | no NEW copy-pasted code block (lizard `-Eduplicate`) across `src/`+`client/`+`shared/`; frozen blocks may only be fixed out | `duplication_backlog.txt` | `--regen` |
| `check_doc_paths.py` | CLAUDE.md / README.md / docs/index.md reference only paths that exist AND are git-tracked | `<!-- doc-paths:off/on -->` markers for deliberate dead refs | — |
| `check_doc_links.py` | every relative markdown link in docs/ + src READMEs resolves to a git-tracked target | `doc_links_backlog.txt` (currently empty — keep it that way) | `--regen` |
| `check_readme_coverage.py` | any depth≤2 `src/` dir with ≥2 C sources carries a README.md | — | — |
| `check_ports_doc.py` | every `*_PORT*` constant in `tests/settings.py` has a row in `docs/10-reference/test-fleet-ports.md` | — | — |
| `check_template_refs.py` | no NEW `tests/configs/*.conf` that nothing in the repo names; frozen dead templates may only be wired up or deleted | `template_refs_backlog.txt` | `--regen` (shrink-only) |
| `check_python_deps.py` | every third-party Python import is declared in a requirements file; every requirement has a **lower AND upper** bound; nothing declared *optional* is imported at module scope | inline `IMPORT_TO_DIST` / `SYSTEM_MODULES` | edit the requirements file |
| `check_version_sync.py` | the RPM spec's `%global upstream_version` fallback, the spec's newest `%changelog` entry and `CHANGELOG.md`'s newest entry all equal `BRIX_SERVER_VERSION_BARE` in `src/core/ident.h`; both changelogs are newest-first | — | `--show` prints all four |
| `check_import_direction.py` | the packaged framework (`brixtest/src/`) never imports back into the flat `tests/` tree — a package that reaches into its own consumers cannot be installed anywhere else (testsuite-modernization-plan §7.2/§12) | — | — |
| `check_shim_completeness.py` | every name a §10.2 self-replacement shim used to export is still reachable after its body moved into a package, against the frozen `docs/refactor/testsuite-shim-baseline.json` | `testsuite-shim-baseline.json` | regenerate the baseline |
| `check_shard_entrypoints.py` | a shard carrying `if __name__ == "__main__"` is still exec-composed by a parent that calls `_load_continuations` — break the composition without moving the CLI and the entry point silently stops running | — | move the CLI to a named `main()` |
| `check_shim_entrypoints.py` | a §10.2 shim keeps the CLI its flat body had, so `python3 tests/<name>.py` still does what it did before the move | — | add a `__main__` delegation |
| `check_shard_name_collisions.py` | one composed module, one namespace: no top-level name is bound twice across a parent and the shards it execs into its own globals — a shard's `_expression_1` rebinds the parent's, and the parent's call sites (resolved at call time) reach the shard's function | — (no exemptions) | rename them to say what they do |
| `check_ratchet_monotonic.py` | guards the guards: no ratchet backlog above may GROW vs the PR's base revision — no new grandfathered entry, no raised allowance. Analyzer baselines and `duplication_backlog.txt` are deliberately out of scope (see its header) | every other backlog in this table | — (fix the code) |
| `smoke.py` | the built `objs/nginx` + `client/bin/xrdcp` serve one byte-exact `root://` read on an ephemeral port; fails — never skips — when an artefact is missing. Run by `.github/workflows/build.yml`, not by `guards.yml` | — | — |
| `run_fanalyzer.py` | no NEW gcc `-fanalyzer` finding (UAF/leak/NULL-deref) vs baseline; needs a configured nginx build (`NGX_BUILD`) | `fanalyzer_baseline.txt` | `--regen` |
| `run_codechecker.py` | no NEW Clang Static Analyzer + clang-tidy finding vs baseline; needs a configured nginx build (`NGX_BUILD`) + `CodeChecker` + clang/clang-tidy | `codechecker_baseline.txt` | `--regen` |
| `asan.py` | ASan+UBSan build (`build_sanitizer`) boots the fleet + drives real root:// I/O; FAILS on any heap error / UB / unsuppressed leak (hyper-hardening B-2); needs a compiler + configured nginx build (`NGINX_SRC`) | `tests/lsan.supp` | — |

## The ratchet pattern

Several guards freeze pre-existing violations in a backlog file and fail
only on NEW ones. Rules:

- Backlog entries may only **shrink** — fixing a violation and regenerating
  is the only sanctioned edit.
- `--regen` only after a deliberate, reviewed change (e.g. you split an
  oversized file, or fixed a batch of links). Review the diff before
  committing it.
- Never hand-edit a backlog to silence a failure. The failure is the point.
- A red-and-ignored gate is worse than no gate: both size ratchets drifted
  (18 and 12 violations respectively) during the period nothing ran them.

Those first two rules are no longer honour-system: `check_ratchet_monotonic.py`
diffs every backlog against the PR's base revision and fails on any growth, so
"append the offending file to the backlog" — the one edit that turns any of
these guards green while making the code worse — is itself a red build.

## Two file-size regimes (both intentional)

- **`python3 -m cmdscripts.lint_loc --strict`** (run with `PYTHONPATH=tests`;
  source `tests/cmdscripts/lint_loc.py`) is the **hard wall**: 800 logical LOC,
  baseline `tests/loc_baseline.txt`, enforced by `.github/workflows/loc.yml`.
  Scope includes `src/`, `client/`, plus `tests/`/`utils/`/`k8s-tests/`
  shell and Python. Per-file exemption marker: `loc-lint: exempt` in the
  first 40 lines.
- **`tools/ci/check_file_size.py`** is the **soft target**: ~500 lines
  (coding-standards §1, one concept per file), `src/` only, backlog-
  ratcheted, enforced by `guards.yml`.

A file under the 800 wall can still fail the 500 ratchet. The soft cap is
where files should live; the hard wall is where growth stops being a
review-taste question and becomes a CI failure.

## Code duplication ratchet

`check_duplication.py` runs lizard's copy-paste detector (`-Eduplicate`)
over `src/`, `client/` and `shared/` (per-tree — one combined invocation
produces no duplicate output) and fails on any duplicated block whose key
is not frozen in `duplication_backlog.txt`. Keys are the sorted member
spans of a block (`path:start-end+path:start-end`), so they are stable
against reordering but NOT against line-number churn: an unrelated edit
that shifts a grandfathered block re-surfaces it as "new". Treat that as
a prompt to either extract the shared helper (the right fix) or `--regen`
after review. Duplicates that disappear are always OK; `--regen` ratchets
them out of the backlog.

**What "after review" means, from the 2026-08-09 sweep.** The guard is
advisory — deliberately not wired into `guards.yml` — because most of what
it reports on this codebase is not extractable: an `ngx_command_t` table,
an `ngx_conf_enum_t` name table, a `{ errno, "token" }` map, a chain of
`ngx_strncmp` token tests and nginx's module-registration boilerplate are
all mandatory literal forms, and a macro that collapsed them would destroy
the grep-ability of directive names, which is worth more than the line
count. That sweep read all 162 live blocks: **one** was genuine algorithmic
duplication (`tpc_send_all` / `tpc_recv_exact` — the same transfer loop with
send/recv swapped, extracted to `src/tpc/outbound/io_xfer.c` and now
unit-tested over a socketpair), and the other 161 were the shapes above,
self-overlaps, or grandfathered blocks that had merely shifted. So: read the
report before regenerating, fix what is real, and regenerate the rest —
"regen because it is red" is how a ratchet becomes decoration. One
category is worth attacking if this file is ever revisited:
`src/fs/backend/xroot/sd_xroot_ns_cred.c`, where five credential-scoped
VFS entry points repeat the same session-open / call / errno / close / free
scaffolding around a single differing `brix_cache_origin_*` call.

## Coverage (report-only lane)

`coverage.py` builds a gcov-instrumented module + client
(`cmdscripts.operator_build build_coverage` → `./configure --with-cc-opt='--coverage
-O0 -g'`), runs a test command against it (default the fast fleet tier;
override with `COVERAGE_TEST_CMD`), and emits an lcov line/branch report for
`src/` + `client/` under `coverage/` (html + `coverage.info`). It is
**report-only** — it enforces a floor only when `COVERAGE_MIN` is set, and skips
cleanly (exit 0) if `lcov`/`gcov` or the nginx source are absent. Runs weekly +
on dispatch (`.github/workflows/coverage.yml`, `continue-on-error`, artifact
upload). Graduation to a blocking gate follows the same discipline as the
static-analysis lanes: read a stable baseline on the runner first, THEN set
`COVERAGE_MIN` a few points under it and drop `continue-on-error` — never flip a
numeric gate to blocking pre-baseline.

## ASan + UBSan (dynamic-sanitizer lane, B-2)

`asan.py` is the hyper-hardening **B-2** lane — the dynamic complement to the
static analyzers above. It builds the module + client with
`-fsanitize=address,undefined` (`cmdscripts.operator_build build_sanitizer`),
boots the test fleet against that instrumented binary
(`SANITIZE=1 manage_test_servers restart`, which routes findings to
`$SANITIZE_LOG_DIR/asan.<pid>` with `abort_on_error=0` so a worker keeps
serving), drives real root:// I/O through it in **attach** mode (default the
deterministic `test_sanitizer_smoke.py`; override with `ASAN_TEST_CMD` — the
nightly cron widens it to the `not slow and not serial` fast tier), then
`stop-all` (LSan fires at process exit) and **scans every report for a hard
sanitizer signature**. A match — heap error, UB, or an *unsuppressed* leak (the
third-party library leaks are curated out by `tests/lsan.supp`) — fails the job;
the scan, not `abort_on_error`, is the gate, and it covers both the fleet and
the sanitized client `xrdcp` the smoke spawns. Unlike the report-only coverage
lane it is **blocking on PRs** and a required status check on `main`. Run by
hand it self-skips cleanly (exit 0) when the compiler / configured nginx source
(`NGINX_SRC`) / a bootable fleet are absent, so a laptop missing infra is never
reddened. On the workflow that tolerance is wrong — a skipped required check
reports green — so `.github/workflows/asan.yml` sets `BRIX_CI_STRICT: "1"` and
every skip path (`asan.skip_or_fail()`) becomes a failure naming the unmet
prerequisite (`.github/workflows/asan.yml` — PR/push smoke + nightly fast-tier
cron, artifact upload of any reports). Guarded locally by
`tests/test_ci_asan_lane.py`, which also pins statically that no new
prerequisite can reintroduce a bare skip-then-`return 0`.

An optional `ASAN_TEST_CMD2` runs a **second** driver command in the same
sanitized+attached fleet after `ASAN_TEST_CMD` and before stop+scan (both legs'
reports scanned together; a non-zero exit from *either* fails the job). The
nightly cron sets it to `pytest test_phase24_mirror.py -k data_write` — the
**serial** write-mirror suite the `not serial` fast tier drops. That suite drives
the phase-24 / 57-W3 detached-replay **disconnect-mid-write** UAF / heap-ownership
paths (a replay outliving its client and owning a stolen buffer; a
teardown-cleanup racing a launch), closing the phase-88 audit § 4 write-mirroring
residual under the sanitizer.

## Static analysis

`run_fanalyzer.py` compiles the module under gcc `-fanalyzer` and diffs
findings against `fanalyzer_baseline.txt`. It needs a configured nginx
build tree (`NGX_BUILD=/path/to/nginx-1.28.3`, default `/tmp/nginx-1.28.3`).
It runs weekly + on dispatch in CI (`.github/workflows/fanalyzer.yml`,
non-blocking until proven stable across GCC versions); local runs against
the dev build remain the authoritative gate. `--filter <path-prefix>` for
a fast scoped scan.

`run_codechecker.py` is the orthogonal Clang half: it synthesizes a
`compile_commands.json` from the same build-tree `$(CFLAGS)`/`$(ALL_INCS)`
(no build interception needed), runs Ericsson **CodeChecker** (`clangsa`
+ `clang-tidy`) over the addon sources, and diffs findings against
`codechecker_baseline.txt`. Each finding is keyed by CodeChecker's
content-based `report_hash`, so the baseline does not churn when unrelated
lines move. Same `--regen` / `--filter` / `NGX_BUILD` interface as the
`-fanalyzer` guard. Install once with `pip install --user codechecker`
(needs `clang` + `clang-tidy` on PATH). Runs weekly + on dispatch
(`.github/workflows/codechecker.yml`, non-blocking until the CI clang
version is pinned to the dev toolchain). The two static-analysis guards are
complementary: `-fanalyzer` excels at ownership/leak/UAF along error
branches; clangsa + clang-tidy add a large orthogonal checker set (dead
stores, logic errors, API misuse, bugprone-*, security-*). Two clang-tidy
checks are disabled by policy at the top of the script (each with a reason):
`clang-diagnostic-unused-parameter` (the build sets `-Wno-unused-parameter`)
and `misc-header-include-cycle` (the nginx module include graph is
legitimately cyclic). Override with `CC_DISABLE=""` to see the full profile.
