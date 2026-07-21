# tools/ci — invariant guards

Every script here encodes a project invariant as a red/green check. All of
them run in CI on every PR/push (`.github/workflows/guards.yml`) and in the
pre-push hook (`tools/git-hooks/pre-push`, install once with
`git config core.hooksPath tools/git-hooks`). Run any of them locally with
no arguments; exit 0 = clean.

These guards are **pure Python** — the fleet was ported from bash `.sh` to
`.py` on 2026-07-21 (locale-independent, testable, no shell parsing traps); no
bash remains. Each is self-contained with a `run(root) -> (ok, lines)` verdict
plus a `main()`; the ratchets keep a `--regen` mode.

The guards also run inside the normal pytest gate, so a violation reddens the
local test loop, not just CI:
- `tests/test_ci_guards.py` executes the real `tools/ci/*.py` scripts
  end-to-end — the fast static guards every run, the lizard-backed ratchets
  (`check_complexity`, `check_duplication`) when `lizard` is installed, and the
  analyzer/coverage runners (`run_fanalyzer`, `run_codechecker`, `coverage`)
  in the `slow`/nightly lane when a configured build + tool are present.
- `tests/test_source_guards.py` asserts the fast in-process verdict twins
  (`source_guards_lib`) and drives their injected-tree negative cases.

Run just the guard gate with
`PYTHONPATH=tests pytest tests/test_ci_guards.py tests/test_source_guards.py -v`.

| Script | Invariant enforced | Backlog / baseline | Regen |
|---|---|---|---|
| `check_config_coverage.py` | every `src/**/*.c` is built via `./config`, or allowlisted with a reason; no stale `./config` entries | inline allowlist | edit allowlist |
| `check_vfs_seam.py` | no new storage-plane bypasses of the VFS (tier-2 confined-helper calls, tier-1.5 direct SD vtable I/O) | `vfs_seam_backlog.txt`, `_ns`, `_client` | `--regen` |
| `check_http_helper_reimpl.py` | protocols must not regrow private copies of the shared HTTP helpers (header scan, preconditions, ETag) | inline allowlist | edit allowlist |
| `check_auth_verdict_sentinel.py` | the session verdict `login.auth_done = 1` may be raised only by a credential handler / session login-bind path — not from a proxy/TPC/dispatch/op file (C-3 `NGX_OK`-on-deny discipline) | inline `ALLOW` | edit allowlist |
| `check_sd_driver_conformance.py` | every `fs_list.h` storage driver ships a conforming `brix_sd_driver_t` (+ prints the op-coverage matrix) | — | — |
| `check_shm_mutex.py` | SHM tables are created via `brix_shm_table_*` — no bare `ngx_shmtx_create()` call outside `src/core/compat/shm_slots.c` (INVARIANT #10) | — | — |
| `check_file_size.py` | no `src/` file crosses the ~500-line soft cap; frozen offenders may only shrink | `file_size_backlog.txt` | `--regen` |
| `check_complexity.py` | no function over `src/`+`client/` crosses CCN 15 (lizard/McCabe); frozen offenders may only get simpler | `complexity_backlog.txt` | `--regen` |
| `check_todo_fixme.py` | no NEW `TODO`/`FIXME`/`XXX`/`HACK` marker in `src/`+`client/`+`shared/`; frozen per-file counts may only shrink | `todo_fixme_backlog.txt` | `--regen` |
| `check_duplication.py` | no NEW copy-pasted code block (lizard `-Eduplicate`) across `src/`+`client/`+`shared/`; frozen blocks may only be fixed out | `duplication_backlog.txt` | `--regen` |
| `check_doc_paths.py` | CLAUDE.md / README.md / docs/index.md reference only paths that exist AND are git-tracked | `<!-- doc-paths:off/on -->` markers for deliberate dead refs | — |
| `check_doc_links.py` | every relative markdown link in docs/ + src READMEs resolves to a git-tracked target | `doc_links_backlog.txt` (currently empty — keep it that way) | `--regen` |
| `check_readme_coverage.py` | any depth≤2 `src/` dir with ≥2 C sources carries a README.md | — | — |
| `check_ports_doc.py` | every `*_PORT*` constant in `tests/settings.py` has a row in `docs/10-reference/test-fleet-ports.md` | — | — |
| `run_fanalyzer.py` | no NEW gcc `-fanalyzer` finding (UAF/leak/NULL-deref) vs baseline; needs a configured nginx build (`NGX_BUILD`) | `fanalyzer_baseline.txt` | `--regen` |
| `run_codechecker.py` | no NEW Clang Static Analyzer + clang-tidy finding vs baseline; needs a configured nginx build (`NGX_BUILD`) + `CodeChecker` + clang/clang-tidy | `codechecker_baseline.txt` | `--regen` |

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
