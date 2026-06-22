# Phase 38 — File-Size Discipline / Unix-Style Modularity

**Status:** PLAN ONLY (no code yet) · **Authored:** 2026-06-14 · **Owner:** OP (Rob)

> *"Write programs that do one thing and do it well."* This phase operationalizes
> a principle the project **already states but does not enforce**:
> [`coding-standards.md` §"Smaller files are preferred"](../09-developer-guide/coding-standards.md)
> (lines 23–25) — *"If a file exceeds ~500 lines, consider whether it owns more
> than one concept and split accordingly."*

The goal: every hand-written source/header/script in the repo should, **where
sensible**, live in a file of **≤ ~500 logical lines of code**, so each file owns
one nameable responsibility that fits in a reviewer's head and can be audited in
one sitting. This is **guidance, not a mandate** — a 583-line file with one clear
job is fine; a 650+-line file almost always hides two or more jobs and should be
split.

---

## 1. Why

- **Auditability** — security-sensitive code (auth, path confinement, wire
  parsing, TPC credentials) is reviewed file-by-file. A 1,300-line file is not
  auditable in one pass; a 250-line file is.
- **Single responsibility** — large files are where unrelated concerns
  accumulate. The line count is a *proxy metric* for "this file owns too much".
- **Unix ethos** — small, composable units with explicit data flow (the same
  reason `goto` is banned and functional/modular design is required —
  coding-standards §4, §8).
- **Cheap to keep, expensive to recover** — once a linter + ratchet is in place,
  the cost is bounded; without it, files only ever grow.

This is a **proxy, not a goal in itself.** We never split a genuinely cohesive
unit (one state machine, one wire-format codec) just to hit a number. The metric
flags candidates; a human decides.

---

## 2. Policy

### 2.1 Tiers (logical LoC = non-blank, non-pure-comment lines; see §4)

| Tier | Range | Meaning | Action |
|---|---|---|---|
| ✅ Ideal | ≤ 500 | One responsibility | none |
| 🟡 Watch | 501–650 | Acceptable; keep an eye on it | none required; don't grow it |
| 🟠 Should-split | 651–800 | Almost certainly ≥ 2 concepts | split when next touched ("refactor-on-touch"); planned burn-down |
| 🔴 Must-split | > 800 | Monolith | scheduled split, P0/P1 below |

The linter (§4) **fails CI only above the hard threshold for NEW files**
(ratchet); existing offenders are grandfathered into a baseline and burned down
deliberately.

### 2.2 In scope

- C source `src/**/*.c` and headers `src/**/*.h`
- Shell scripts `tests/**/*.sh`, `k8s-tests/**/*.sh`, `utils/**/*.sh`
- Python: tooling `utils/**/*.py` and tests `tests/**/*.py` (separate, lower-risk
  track — see §6.4)

### 2.3 Out of scope (exempt — declared in the linter allowlist)

- **Markdown / docs** (`docs/**`, `*.md`) — prose, not code; long is fine.
  (Sprawling docs are handled by the existing
  [doc-tree standard](../09-developer-guide/), not by LoC.)
- **The root `config` build manifest** (729 lines) — a single declarative
  `NGX_ADDON_SRCS` list; it *grows as we add files* (so this phase will lengthen
  it). Splitting a flat list hurts, not helps.
- **Declarative config** — `*.conf`, `*.yaml`, `*.cf`, `*.spec`, `*.tpl`. These
  are data, not control flow.
- **Generated / vendored** — none currently tracked (nginx core lives outside the
  repo in `/tmp/nginx-1.28.3`), but the allowlist reserves a pattern for any
  future generated file.
- **Test fixtures / data blobs.**

### 2.4 Hard rules carried from `CLAUDE.md` (every split must honor)

1. **Register new `.c` in the root `config`** (`NGX_ADDON_SRCS`) — `./configure`
   won't compile an unregistered file. New header → no configure needed.
2. **Mixed-ABI rebuild gotcha** — when a split moves a `struct`/inline between a
   header and its users, touch all dependent `.c` and do a **full rebuild**
   (stale objects → SIGSEGV; see [build_header_dep_mixed_abi]).
3. **No `goto` introduced**; refactor any `goto` *out* of code you touch.
4. **Update the directory `README.md` table** — every `src/` subdir lists each
   file's responsibility (doc-tree standard). A new file → a new row.
5. **Every new file gets a WHAT/WHY/HOW header doc-block** (coding-standards §doc).
6. **Pure refactor = zero behavior change** — the split must be byte-for-byte
   behaviorally identical; verify with the existing test suite (3-tests rule
   applies only to *new* behavior, of which there is none).

---

## 3. Current inventory (measured 2026-06-14, `git ls-files`)

| Type | Total | >500 | >650 | >800 |
|---|---|---|---|---|
| `.c` | 404 | 46 | 19 | **11** |
| `.h` | 177 | 2 | 1 | 0 |
| `.py` | 177 | 55 | 32 | many |
| `.sh` | 31 | 2 | 1 | 1 |

**C source headroom is good** — 90% of `.c` files are already ≤ 500. The work is
concentrated in a **long tail of 19 files**, 11 of them monoliths.

### 3.1 C source > 650 LoC (the split list)

| LoC | File | Tier | Hypothesized seams (confirm by reading) |
|---|---|---|---|
| 1380 | `src/s3/post_object.c` | 🔴 | POST-policy parse · multipart form decode · object write · response |
| 1222 | `src/dashboard/api.c` | 🔴 | snapshot builder · transfer-object builder · protocol/summary roll-up · foundation endpoints *(worked example, §5.3)* |
| 1154 | `src/stream/module.c` | 🔴 | directive table · conf create/merge · handler registration · lifecycle |
| 1128 | `src/dashboard/api_admin.c` | 🔴 | admin auth · write endpoints · proxy-pool admin |
| 1081 | `src/webdav/propfind.c` | 🔴 | request/XML parse · property gather · XML response build |
| 1009 | `src/manager/registry.c` | 🔴 | node registry · tried/triedrc redirect logic · selection |
| 926 | `src/webdav/module.c` | 🔴 | directives · conf merge · phase handlers |
| 844 | `src/mirror/http_mirror.c` | 🔴 | method-bit gate · subrequest build · body forwarding · divergence |
| 827 | `src/dashboard/auth.c` | 🔴 | password/login · session cookie · user table |
| 826 | `src/webdav/tpc_curl.c` | 🔴 | curl handle setup · header build · transfer loop · result map |
| 803 | `src/mirror/stream_wmirror.c` | 🔴 | session bootstrap · fhandle map · write replay · teardown |
| 787 | `src/mirror/stream_mirror.c` | 🟠 | connect/bootstrap · replay · recv/finish |
| 785 | `src/token/macaroon.c` | 🟠 | mint · verify · caveat eval |
| 776 | `src/webdav/tpc.c` | 🟠 | COPY parse · cred resolve · launch |
| 691 | `src/webdav/xrdhttp.c` | 🟠 | — |
| 686 | `src/query/prepare.c` | 🟠 | kXR_prepare opcode · queue/stage logic |
| 681 | `src/metrics/unified.c` | 🟠 | per-surface exporters (natural split by surface) |
| 672 | `src/manager/health_check.c` | 🟠 | probe scheduling · result handling |
| 660 | `src/aio/buffers.c` | 🟠 | — |

*(27 more C files in the 🟡 501–650 watch tier — listed by the linter; no action
beyond "don't grow", refactor-on-touch.)*

### 3.2 Headers > 500 LoC

| LoC | File | Note |
|---|---|---|
| 744 | `src/webdav/webdav.h` | Split by concern: conf struct · TPC decls · method decls · helper decls. Header splits hit the mixed-ABI gotcha — full rebuild. |
| 586 | `src/metrics/metrics.h` | Watch; split metric enums vs struct vs inline INC macros if it grows. |

### 3.3 Shell > 500 LoC

| LoC | File | Note |
|---|---|---|
| 1777 | `tests/manage_test_servers.sh` | The monster. Split into sourced libs: `lib/pki.sh`, `lib/nginx.sh`, `lib/refxrootd.sh`, `lib/ports.sh`, thin dispatcher. |
| 648 | `k8s-tests/Dockerfiles/client/run-integration-tests.sh` | 🟡 watch. |

### 3.4 Python (separate track — §6.4)

55 files > 500, 32 > 650; largest `tests/test_xrootd_performance_conformance.py`
(2121), `tests/test_proxy_mode.py` (1651), `utils/xrd_sec_probe.py` (730, tooling).
Test files split cleanly along **test-class / concern** boundaries and share
fixtures via `conftest.py` — low risk, high audit value, but **not on the
critical path**; do after the C work or in parallel by a separate effort.

---

## 4. Checking — the linter + ratchet + CI

### 4.1 `tests/lint_loc.sh` (new; model on `tests/lint_alloc.sh`)

A cheap, dependency-free bash script:

- Enumerates tracked in-scope files (`git ls-files` filtered by §2.2/§2.3
  allowlist).
- Counts **logical LoC** per file: total minus blank lines minus pure-comment
  lines (`grep -cE` exclusion of `^\s*$`, `^\s*//`, `^\s*/?\*`). Rationale: a file
  that is 600 lines but 250 of them are the mandatory WHAT/WHY/HOW doc-blocks is
  *not* a monolith — we measure code, not documentation, so the standard's own
  doc requirement never pushes a file over the line.
- Classifies each into the §2.1 tiers; prints a per-tier report sorted by size.
- **Flags:**
  - `--report` (default) — print tiers, exit 0 (advisory).
  - `--strict` — exit non-zero if any file exceeds the **hard threshold** (>800,
    tunable) **and is not in the baseline** (ratchet).
  - `--baseline` — regenerate `tests/loc_baseline.txt`.

### 4.2 The ratchet (baseline burn-down)

- `tests/loc_baseline.txt` = the grandfathered set of current offenders (file +
  recorded LoC).
- CI rule: **a file may not newly cross the hard threshold, and a baselined file
  may not grow.** New code is born compliant; the baseline only shrinks.
- Each split PR removes its target(s) from the baseline. The phase is "done" when
  the baseline is empty (or only documented, justified exemptions remain).

### 4.3 CI integration

- The repo has **no top-level `.github/workflows`** yet (only `k8s-tests` has
  one). Add `.github/workflows/loc.yml` running `tests/lint_loc.sh --strict`, OR
  fold it into the existing lint stage alongside `lint_alloc.sh`.
- Optional: a `pre-commit` hook (advisory `--report`) so authors see it locally.

### 4.4 Exemption mechanism

A file that is genuinely cohesive yet long carries a one-line magic comment near
the top, e.g. `/* loc-lint: exempt — single wire-format codec, splitting harms cohesion */`,
which the linter honors and records. Exemptions are visible in review (grep-able),
not silent.

---

## 5. Implementation — how to split one file

### 5.1 Method (per file)

1. **Read the whole file. Name its concepts.** If you cannot name 2+ distinct
   responsibilities, it is *not* a split candidate — exempt it (§4.4) and move on.
2. **Find the seams** — groups of functions that share state/purpose and are
   loosely coupled to the rest (e.g. "everything that builds the XML response" vs
   "everything that parses the request").
3. **Extract a sibling file in the same directory** (`foo.c` → `foo.c` +
   `foo_response.c`, etc.). Keep names descriptive and consistent with existing
   siblings (`src/cache/fetch.c`, `src/cache/evict.c` is the model).
4. **Shared internal contract** → a private `*_internal.h` (pattern already used:
   `cms_internal.h`, `metrics_internal.h`, `cache_internal.h`). Static functions
   that must cross the new boundary lose `static` and gain a prototype there.
5. **Register** new `.c` in the root `config` `NGX_ADDON_SRCS`; **header-only**
   changes need no `./configure`.
6. **Update the directory `README.md`** responsibility table.
7. **Doc-block** the new file (WHAT/WHY/HOW).
8. **Build + test + verify identical behavior** (§7).

### 5.2 Anti-patterns (do NOT)

- ❌ Split at an arbitrary line number ("file2 starts at line 500").
- ❌ Reach into another file's privates instead of a clean `*_internal.h`.
- ❌ Introduce a `goto`, a new global, or change behavior "while I'm here".
- ❌ Reimplement a HELPER (path/auth/metrics/framing) during a move.
- ❌ Split a single state machine / codec just to hit the number (exempt it).

### 5.3 Worked example — `src/dashboard/api.c` (1222 → ~4 files)

From direct inspection, `api.c` already contains four near-independent concerns
that share only small static helpers:

- `api.c` — endpoint routing + the small format helpers (`dashboard_avg_bps`,
  state/proto/dir name maps) → keep, ~250 LoC.
- `api_transfers.c` — `dashboard_build_transfer_object` + the per-slot summary
  roll-up + stale-GC scan (the live-transfer model) → ~400 LoC.
- `api_snapshot.c` — the top-level snapshot assembly (`protocols`, `cluster`,
  `events`, `history`, `totals` wiring) → ~350 LoC.
- `api_ratelimit.c` — `dashboard_build_v1_ratelimit` and the Phase-25 zone
  snapshot → ~250 LoC.

Shared decls (the `summary` struct, helper prototypes) move to the existing
`dashboard.h` or a new `dashboard_api_internal.h`. Register three new `.c` in
`config`; update `src/dashboard/README.md`. No behavior change → existing
`tests/test_dashboard.py` (13 tests) must stay green.

---

## 6. Prioritized work plan

### 6.0 Gate 0 — tooling first (do before any split)

Land `tests/lint_loc.sh` + `tests/loc_baseline.txt` + CI wiring. This *locks the
ratchet* so the tail stops growing while we burn it down, and gives an objective
"done" signal.

### 6.1 P0 — C monoliths > 800 LoC (11 files)

The §3.1 🔴 rows. Each is its own focused PR. Order by **audit value first**
(security/auth/wire), then size: `dashboard/auth.c`, `webdav/tpc_curl.c`,
`s3/post_object.c`, `webdav/propfind.c`, `manager/registry.c`,
`mirror/{http_mirror,stream_wmirror}.c`, `dashboard/{api,api_admin}.c`,
`stream/module.c`, `webdav/module.c`.

### 6.2 P1 — C 651–800 LoC (8 files)

The §3.1 🟠 rows. `metrics/unified.c` (split by surface) and `webdav/tpc.c` are
the cleanest wins.

### 6.3 P2 — the header + the shell monster

- `src/webdav/webdav.h` (744) — split by concern; **full rebuild** (mixed-ABI).
- `tests/manage_test_servers.sh` (1777) — extract sourced libs; this is the
  single highest-LoC file in the repo and central to every test run, so do it
  carefully with a smoke run of `start-all`/`restart`.

### 6.4 P3 — Python track (independent, parallelizable)

Split `tests/*.py` > 650 along test-class/concern lines, sharing fixtures via
`conftest.py`. Lower risk (no build, no ABI), high audit value. Can run
concurrently with P0–P2 by a separate effort. `utils/xrd_sec_probe.py` (tooling)
splits into a small package.

---

## 7. Verification (per split PR)

- `./configure … && make -j$(nproc)` **clean** (configure only when a new `.c`
  was registered; full rebuild when a header/struct moved — mixed-ABI gotcha).
- `grep -rn 'goto' <new files>` → none.
- Directory `README.md` row added; new file has a doc-block.
- `tests/lint_loc.sh --report` shows the target dropped a tier; baseline updated.
- **Behavioral identity:** the subsystem's existing tests pass unchanged
  (`pytest tests/test_<area>.py`), plus a full `pytest tests/ -q` before merge.
  ASAN/UBSan run for memory-touching splits (mirror, aio, s3, tpc).
- Binary health: server starts, `nginx -t` OK, a smoke transfer round-trips.

Because these are **pure refactors**, the strongest signal is "the entire test
suite is byte-for-byte green before and after."

---

## 8. Risks & non-goals

| Risk | Mitigation |
|---|---|
| Mixed-ABI SIGSEGV from header/struct moves | Touch all dependents + full rebuild; prefer moving *code* not *layout*; ([build_header_dep_mixed_abi]) |
| Churn for churn's sake / cohesion loss | Tier metric is advisory; exempt genuinely-cohesive long files (§4.4); human decides seams |
| Over-fragmentation (50-line files everywhere) | Target is *one responsibility*, not minimum size; ≤500 is a ceiling, not a quota |
| Test-suite split losing shared fixtures | Keep fixtures in `conftest.py`; never duplicate setup |
| Reviewer fatigue from many PRs | One file per PR, but batch trivially-mechanical ones; the ratchet makes the end state objective |
| Breaking `config` registration | Linter could also check every `src/**/*.c` appears in `config` (bonus check) |

**Non-goals:** reformatting, renaming for style, touching declarative config/docs,
or changing any runtime behavior. This phase moves code; it does not modify it.

---

## 9. Milestones & effort

| Milestone | Content | Rough effort |
|---|---|---|
| M0 | `lint_loc.sh` + baseline + CI ratchet | 0.5–1 day |
| M1 | P0: 11 C monoliths split | ~1–1.5 days each → 2–3 weeks |
| M2 | P1: 8 C files (651–800) | ~1 week |
| M3 | P2: `webdav.h` + `manage_test_servers.sh` | ~2–3 days |
| M4 | P3: Python test/tooling track | parallel; ~1–2 weeks |

**Definition of done:** `tests/lint_loc.sh --strict` is green on a clean tree with
an empty (or fully-justified-exemption) baseline, the CI ratchet is enforced, and
the whole test suite is green. From then on, file-size discipline is *maintained
by tooling*, not vigilance.

---

## Appendix A — one-shot commands used to build this inventory

```bash
# Per-type threshold counts
for e in c h py sh; do
  echo ".$e >500=$(git ls-files "*.$e" | xargs wc -l | awk '$1>500&&$2!="total"' | wc -l)"
done
# Worst C offenders
git ls-files 'src/*.c' | xargs wc -l | awk '$1>650&&$2!="total"' | sort -rn
```

## Appendix B — related standards & memories

- [`coding-standards.md`](../09-developer-guide/coding-standards.md) §"Smaller
  files are preferred" (the principle this phase enforces), §4 no-goto, §8
  functional/modular, §doc WHAT/WHY/HOW.
- Build governance: root `config` `NGX_ADDON_SRCS` (`CLAUDE.md` BUILD GOVERNANCE).
- Doc-tree standard: `README.md` per `src/` subdir.
- `tests/lint_alloc.sh` — the linter pattern to model `lint_loc.sh` on.
- Gotcha: editing a header's struct layout + incremental make = stale-object
  SIGSEGV → always full rebuild ([build_header_dep_mixed_abi]).
