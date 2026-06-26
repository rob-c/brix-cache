# Phase 38 — File-Size Discipline / Unix-Style Modularity

**Status:** PLAN ONLY (no code yet) · **Authored:** 2026-06-14 · **Revised:** 2026-06-26 (scope extended to `shared/` + `client/`; inventory re-measured on *logical* LoC) · **Owner:** OP (Rob)

> *"Write programs that do one thing and do it well."* This phase operationalizes
> a principle the project **already states but does not enforce**:
> [`coding-standards.md` §"Smaller files are preferred"](../09-developer-guide/coding-standards.md)
> — *"If a file exceeds ~500 lines, consider whether it owns more than one concept
> and split accordingly."*

**The one-paragraph version.** Every hand-written C/header/script in `src/`,
`shared/`, and `client/` should, *where sensible*, live in a file of **≤ ~500
logical lines** so each file owns one nameable responsibility that fits in a
reviewer's head and can be audited in one sitting. We make that measurable
(`tests/lint_loc.sh`), grandfather today's offenders into a baseline, ratchet so
nothing new crosses the line, and burn the baseline down one focused, behavior-
preserving PR at a time. The same standard applies to all three trees — there is
one code standard, not a per-tree one (`CLAUDE.md`/`AGENTS.md`).

This is **guidance, not a mandate.** A 560-line file with one clear job is fine; a
900-line file almost always hides two or more jobs and should be split. The metric
flags *candidates*; a human decides the seams.

---

## Table of contents

1. [Why](#1-why)
2. [Policy](#2-policy) — tiers, scope, the measurement definition, the directive-table special case, hard rules
3. [Current inventory](#3-current-inventory-measured-2026-06-26) — measured 2026-06-26
4. [Checking](#4-checking--the-linter--ratchet--ci) — the linter, baseline, CI, exemptions (with full script source)
5. [How to split one file](#5-how-to-split-one-file--the-runbook) — runbook + `*_internal.h` pattern + a worked before→after
6. [Per-file split specifications](#6-per-file-split-specifications) — all 22 offenders, grounded in measured function inventories (§6.1–§6.21)
7. [Prioritized work plan](#7-prioritized-work-plan) — P0–P4
8. [Verification](#8-verification-per-split-pr) — exact commands per PR
9. [Risks & non-goals](#9-risks--non-goals)
10. [Milestones & effort](#10-milestones--effort)
- [Appendix A — measurement commands](#appendix-a--one-shot-measurement-commands)
- [Appendix B — function-inventory method](#appendix-b--how-the-function-inventories-were-built)
- [Appendix C — glossary](#appendix-c--glossary)
- [Appendix D — related standards & memories](#appendix-d--related-standards--memories)
- [Appendix E — audit hotspots (largest function per monolith)](#appendix-e--audit-hotspots-largest-function-per-monolith)

---

## 1. Why

- **Auditability.** Security-sensitive code (auth, path confinement, wire parsing,
  TPC credentials, impersonation) is reviewed file-by-file. A 1,300-line file is
  not auditable in one pass; a 250-line file is. The five biggest security-
  adjacent monoliths today — `gsi/gsi_core.c`, `s3/post_object.c`,
  `webdav/propfind.c`, `impersonate/broker.c`, `client/lib/copy.c` — are exactly
  where a reviewer's attention is most needed and most easily exhausted.
- **Single responsibility.** Large files are where unrelated concerns accumulate.
  Line count is a *proxy metric* for "this file owns too much"; it is wrong
  sometimes (a 600-line state machine is fine) and right most of the time.
- **Unix ethos.** Small, composable units with explicit data flow — the same
  reason `goto` is banned and functional/modular design is required
  (coding-standards §4, §8). A split that introduces a `goto` or a global has made
  things worse, not better.
- **Cheap to keep, expensive to recover.** Once a linter + ratchet is in place the
  cost is bounded and paid once per PR; without it, files only ever grow. The
  module's `config` source list has grown from 729 → 1057 lines since this plan
  was first drafted — the tail grows unless something holds it.

This is a **proxy, not a goal in itself.** We never split a genuinely cohesive
unit (one state machine, one wire-format codec) just to hit a number. When in
doubt, the test is *"can I give each resulting file a one-line responsibility that
does not contain the word 'and'?"* If not, do not split.

---

## 2. Policy

### 2.1 Tiers

Tiers are evaluated on **logical LoC** (defined in §2.5), not raw line count, so the
mandatory WHAT/WHY/HOW doc-blocks never push a file over the line.

| Tier | Logical LoC | Meaning | Action |
|---|---|---|---|
| ✅ Ideal | ≤ 500 | One responsibility | none |
| 🟡 Watch | 501–650 | Acceptable; keep an eye on it | none required; **don't grow it** |
| 🟠 Should-split | 651–800 | Almost certainly ≥ 2 concepts | split when next touched ("refactor-on-touch"); planned burn-down |
| 🔴 Must-split | > 800 | Monolith | scheduled split (P0/P3 below) |

The linter (§4) **fails CI only above the hard threshold (>800 logical) for files
not in the baseline** (the ratchet); existing offenders are grandfathered and
burned down deliberately.

### 2.2 In scope

The same coding-standards formatting / file-size rules apply **uniformly across
`src/`, `shared/`, and `client/`** — one standard, not a per-tree one
(`CLAUDE.md`/`AGENTS.md`). Concretely:

- **C source** `src/**/*.c` + `client/**/*.c` and **headers** `src/**/*.h` +
  `client/**/*.h`.
- **`shared/` (libxrdproto)** — the shared C is *build-in-place*: the `.c`/`.h`
  files physically live under `src/` (e.g. `src/compat/`, `src/gsi/`,
  `src/token/`, `src/fs/backend/`) and are compiled into both the nginx module
  *and* the ngx-free client/tools via `shared/xrdproto/Makefile`. They are
  therefore **already counted under the `src/**` globs** — no extra path is
  needed. Only the `shared/xrdproto/` build harness itself is exempt (§2.3).
- **Shell** `tests/**/*.sh`, `k8s-tests/**/*.sh`, `utils/**/*.sh`.
- **Python** tooling `utils/**/*.py` and tests `tests/**/*.py` (separate, lower-
  risk track — see §7.5).

### 2.3 Out of scope (exempt — declared in the linter allowlist)

- **Markdown / docs** (`docs/**`, `*.md`) — prose, not code; long is fine.
  Sprawling docs are handled by the existing
  [doc-tree standard](../09-developer-guide/), not by LoC.
- **The root `config` build manifest** (1057 lines) — a single declarative
  `NGX_ADDON_SRCS` list; it *grows as we add files* (so this phase will lengthen
  it). Splitting a flat list hurts, not helps.
- **The `shared/xrdproto/` build harness** (`Makefile` + `check-ngx-free.sh` +
  `check-shared-coverage.sh`) — a declarative build/coverage manifest for the
  build-in-place shared sources, not control flow (same rationale as `config`).
  The shared `.c` it compiles is in scope via `src/**` (§2.2).
- **Declarative config** — `*.conf`, `*.yaml`, `*.cf`, `*.spec`, `*.tpl`. Data,
  not control flow.
- **Generated / vendored** — none currently tracked (nginx core lives outside the
  repo in `/tmp/nginx-1.28.3`), but the allowlist reserves a pattern for any
  future generated file.
- **Test fixtures / data blobs.**

### 2.4 Hard rules carried from `CLAUDE.md` (every split must honor)

1. **Register new `.c` in the right build manifest.**
   - `src/**` (including the build-in-place *shared* sources) → the root `config`
     `NGX_ADDON_SRCS` list. `./configure` will not compile an unregistered file.
   - `client/**` → `client/Makefile` (its own object list, *not* the root
     `config`).
   - A split that adds a **shared** source also needs a rule in
     `shared/xrdproto/Makefile` so the ngx-free tools pick it up, and must stay
     inside the `check-shared-coverage.sh` guard.
   - A **new header** needs no `./configure` — but see rule 2.
2. **Mixed-ABI rebuild gotcha.** When a split moves a `struct`/inline between a
   header and its users, touch all dependent `.c` and do a **full rebuild** (stale
   objects → SIGSEGV; see [build_header_dep_mixed_abi]). This is acute for
   `client/lib/xrdc.h` (every `client/` TU includes it) and `src/types/config.h`.
3. **No `goto` introduced**; refactor any `goto` *out* of code you touch.
   `src/`, the shared sources, and `client/` are **all `goto`-free as of
   2026-06-26** — every split must keep it that way (the linter does not check
   this; `git grep -nE 'goto[[:space:]]+[A-Za-z_]'` does, and so does review).
4. **Update / create the directory `README.md` responsibility table.** Every
   `src/` subdir lists each file's responsibility (doc-tree standard); a new file
   → a new row. **`client/` has no README tables yet** — the client track (§7.4)
   must *create* `client/README.md`, `client/lib/README.md`, and
   `client/apps/README.md` as it goes (a prerequisite, not an afterthought).
5. **Every new file gets a WHAT/WHY/HOW header doc-block** (coding-standards §doc).
6. **Pure refactor = zero behavior change.** The split must be byte-for-byte
   behaviorally identical; verify with the existing test suite (the 3-tests rule
   applies only to *new* behavior, of which there is none here).

### 2.5 The measurement definition (precise)

**Logical LoC** = total lines − blank lines − pure-comment lines. The exact,
dependency-free definition the linter uses:

```bash
# logical LoC of one file
grep -cvE '^[[:space:]]*$|^[[:space:]]*//|^[[:space:]]*/?\*' "$file"
```

That excludes: empty/whitespace-only lines; `//` line comments; and lines whose
first non-space character begins a `/*`…`*/` block-comment line (`/*`, ` *`, ` */`).
It deliberately **does not** strip trailing `//` comments after code, multi-line
string literals, or `#if 0` blocks — those are rare enough to ignore and erring
toward *over*-counting keeps the metric conservative (a file the linter calls
clean is genuinely clean).

**Why logical, not raw.** Worked proof from this very repo: `src/webdav/webdav.h`
is **827 raw** lines but **372 logical** — it is almost entirely the mandatory
declaration doc-blocks. By raw count it looks like a must-split header; by the
metric that matters it is comfortably ideal. Measuring raw would punish the
standard's *own* documentation requirement. Every table in §3 shows **logical
(authoritative) and raw (context)**.

### 2.6 Directive-table files — a special case (`ngx_command_t[]`)

An nginx module's directive table is a single `static ngx_command_t name[] = { … };`
array terminated by `ngx_null_command`. It is **declarative data, not control
flow** — the same category as the root `config` `NGX_ADDON_SRCS` list (§2.3) — yet
the logical-LoC counter scores every `{ ngx_string("…"), … }` row as a "code"
line, so a large table inflates the count without being a logic monolith. Two
files in this repo are table-dominated, measured:

- **`src/stream/module.c`** — **1251 of 1316 logical (95%) is the 213-entry
  directive table.** Its conf lifecycle is *already* extracted to
  `src/config/server_conf.c` (create/merge) and `src/stream/module_definition.c`
  (the `ngx_module_t` struct); what remains is essentially pure table + 8
  `ngx_conf_enum_t` value maps. There is nothing left to split — a C array cannot
  be cut across files without ugly macro re-assembly, and per-directive doc-blocks
  are the bulk.
- **`src/webdav/module.c`** — **618 logical table + 286 logical logic** (setters
  `webdav_conf_*`, phase handlers, module ctx). Here the logic *can* and should
  move out, dropping the residual table file to the watch tier.

**The rule for a `ngx_command_t`-dominated file:**

1. Extract **all logic** — directive setter callbacks, `create/merge_*_conf`, the
   `ngx_module_t`/`ngx_*_module_t` structs, phase handlers — into sibling files
   (`module_directives.c`, `module_init.c`, a `*_conf.c`). For `stream/module.c`
   this is already done.
2. If the **residual pure-table file is still over a tier**, it is an **exemption**
   (§4.4) with the documented rationale `single declarative ngx_command_t table`,
   exactly like the root `config`. Do **not** macro-shard the array to chase the
   number.

This reclassifies `stream/module.c` out of P0 (it becomes a documented exemption)
and turns `webdav/module.c` into a logic-extraction that lands it at ~618 (watch),
not a true monolith split. See §6.10–§6.11.

---

## 3. Current inventory (measured 2026-06-26)

Measured with `git ls-files` + the §2.5 logical-LoC counter. **`shared/` C is
build-in-place under `src/` and is counted in the `src/` rows.** `.py`/`.sh` are
repo-wide. The 2026-06-14 raw-LoC snapshot in earlier revisions of this doc is
**superseded** by these logical-LoC numbers.

### 3.1 Repo-wide tier counts

| Tree / type | Total files | 🟡 >500 | 🟠 >650 | 🔴 >800 |
|---|---|---|---|---|
| `src/**/*.c` | 478 | 29 | 11 | **7** |
| `src/**/*.h` | 231 | 1 | 0 | 0 |
| `client/**/*.c` | 73 | 12 | 11 | **8** |
| `client/**/*.h` | 10 | 1 | 0 | 0 |
| `*.py` (tests + tooling) | 348 | 103 | 65 | many |
| `*.sh` (tests/k8s/utils) | 31 | 3 | 2 | 2 |

**Reading the table.** `src/` C headroom is good — 94% of `.c` are ≤ 500 logical;
the work is a **tail of 11 files, 7 of them monoliths.** `client/` is far denser
per-file: out of only 73 files, **11 are over 650 logical and 8 are monoliths** —
the CLI apps (`xrddiag`, `xrdfs`, `xrd`, `xrdcp`, `xrootdfs`) and the lib engines
(`copy`, `aio`, `http`). Headers are nearly clean by the logical metric: only two
exceed 500 (`client/lib/xrdc.h`, `src/types/config.h`).

### 3.2 `src/` C source > 650 logical LoC — the split list

Seams below are **derived from the measured function inventory** of each file
(Appendix B), not guessed. Per-file specs with proposed filenames and function
assignments are in §6.

| Logical | Raw | File | Tier | Seams (from function inventory) |
|---|---|---|---|---|
| 1316 | 1734 | `src/stream/module.c` | 🔴→**exempt** | **95% (1251) is the 213-entry `ngx_command_t` directive table**; conf lifecycle already in `config/server_conf.c` + `stream/module_definition.c` → declarative, exempt (§2.6, §6.10) |
| 1033 | 1284 | `src/gsi/gsi_core.c` | 🔴 | bucket/buffer codec · DH keygen/derive · cipher negotiation · RSA sign/verify · cert-request/response build (**shared** — also linked into client) |
| 986 | 1290 | `src/dashboard/api.c` | 🔴 | name/format helpers · live-transfer model · snapshot assembly · ratelimit view · JSON send/dispatch *(worked example §6.1)* |
| 973 | 1452 | `src/s3/post_object.c` | 🔴 | multipart-form decode · POST-policy parse/verify · object write · response build *(worked example §6.2)* |
| 904 | 1153 | `src/webdav/module.c` | 🔴→🟡 | **618 table + 286 logic**; extract the `webdav_conf_*` setters + phase handlers + module ctx → residual table drops to ~618 (watch) (§6.11) |
| 894 | 1198 | `src/dashboard/api_admin.c` | 🔴 | admin auth · write endpoints · proxy-pool admin |
| 811 | 1149 | `src/webdav/propfind.c` | 🔴 | request/XML parse · property gather (`propfind_entry` is 308 lines alone) · tree walk · response build *(worked example §6.3)* |
| 796 | 1186 | `src/s3/put.c` | 🟠 | body-mode/aio plumbing · finalize-result family (12 `s3_put_finalize_*`) · aws-chunked decode |
| 725 | 1104 | `src/impersonate/broker.c` | 🟠 | peer/cap gate · `imp_do_op` dispatch (288 lines) · xattr filter · request loop *(worked example §6.5)* |
| 686 | 1123 | `src/manager/registry.c` | 🟠 | registry table · selection core · health-check state · locate/aggregate/snapshot *(worked example §6.4)* |
| 662 | 900 | `src/webdav/tpc_curl.c` | 🟠 | curl handle setup · header build · transfer loop · result map |

### 3.3 `client/` C source > 650 logical LoC — the client split list

Newly in scope (2026-06-26). Registration is `client/Makefile`, not the root
`config` (§2.4). Per-file specs in §6.6–§6.9.

| Logical | Raw | File | Tier | Seams (from function inventory) |
|---|---|---|---|---|
| 2968 | 3600 | `client/apps/xrddiag.c` | 🔴 | one file per subcommand: `check` · `bench` · `topology` · `status` · `compare` + shared opt parse (the `dx_*` probe family is 21 funcs) |
| 2401 | 2818 | `client/apps/xrdfs.c` | 🔴 | arg/REPL driver · per-command handlers (stat/ls/mkdir/rm/mv/cat/tail/locate/query/…) · output formatting |
| 1886 | 2582 | `client/lib/copy.c` | 🔴 | direction inference · download · upload · remote→remote · TPC · recursive walk · web-auth *(worked example §6.6)* |
| 1580 | 1938 | `client/lib/aio.c` | 🔴 | already section-marked: `xbuf` · `reqmap` · `areq` · io/parser · `io_engine` (epoll/uring) · `aconn` · reconnect · loop · public API *(worked example §6.7)* |
| 1566 | 1872 | `client/apps/xrd.c` | 🔴 | dispatcher core · verb→tool maps (fs vs cp/get/put vs diag) · future verbs (doctor/login) |
| 1224 | 1480 | `client/apps/xrdcp.c` | 🔴 | arg grammar · source expansion/glob · single-transfer · batch-parallel · recursive (web/s3) walk |
| 921 | 1116 | `client/apps/xrootdfs.c` | 🔴 | FUSE op table · path mapping · conn-pool wiring · mount/CLI |
| 919 | 1139 | `client/lib/http.c` | 🔴 | GET (`xrdc_http_get`) · request/response codec (`httpx_*`) · download engine · resumable upload engine *(worked example §6.8)* |
| 743 | 941 | `client/lib/ops_file.c` | 🟠 | open family · read/readv + inflate · write/writev + deflate · pgread/pgwrite · sync/close |
| 686 | 864 | `client/apps/xrootdfs_legacy.c` | 🟠 | legacy FUSE driver — split parallel to `xrootdfs.c` or **retire if superseded** |
| 666 | 783 | `client/lib/zip.c` | 🟠 | central-dir read · member access · inflate plumbing |

### 3.4 Headers > 500 logical LoC

| Logical | Raw | File | Note |
|---|---|---|---|
| 579 | 1183 | `client/lib/xrdc.h` | The client spine — split by concern: connection/session decls · metadata/file-op decls · wire-struct helpers · config/types. **Mixed-ABI** (every `client/` TU includes it) → full rebuild. |
| 518 | 790 | `src/types/config.h` | Module config structs. **Mixed-ABI** → full rebuild. Split by plane (stream conf · http/webdav conf · s3 conf · shared tunables) only if it grows; currently borderline. |

> **Dropped from the old must-split list:** `src/webdav/webdav.h` (372 logical /
> 827 raw) and `src/metrics/metrics.h` (390 logical / 639 raw) are **not** offenders
> by the logical metric — they are mostly declaration doc-blocks. Earlier revisions
> flagged them on raw count; §2.5 explains why that was wrong. Leave them.

### 3.5 Shell > 500 raw LoC

(Shell has no doc-block convention, so raw ≈ logical; measured on raw.)

| Raw | File | Note |
|---|---|---|
| 1868 | `tests/manage_test_servers.sh` | The monster, and central to every test run. Split into sourced libs: `lib/pki.sh`, `lib/nginx.sh`, `lib/refxrootd.sh`, `lib/ports.sh` + a thin dispatcher. Do it with a smoke run of `start-all`/`restart`. |
| 648 | `k8s-tests/Dockerfiles/client/run-integration-tests.sh` | 🟠 watch. |
| 509 | `tests/run_load_test.sh` | 🟡 watch. |

### 3.6 Python (separate track — §7.5)

103 files > 500, 65 > 650. Extremes: `tests/userns/e2e_redteam.py` (**29,053** —
a real full-stack red-team driver with 553 def/class, not generated data; the
single highest-priority Python split), `tests/test_xrootd_performance_conformance.py`
(2121), `tests/test_proxy_mode.py` (1659), `tests/test_privilege_escalation.py`
(1604), `tests/test_conf_framing.py` (1604). Test files split cleanly along
**test-class / concern** boundaries and share fixtures via `conftest.py` — low risk
(no build, no ABI), high audit value, but **not on the critical path**.

### 3.7 The 🟡 watch tier (don't-grow list, refactor-on-touch)

No scheduled work, but the linter lists them and they must not grow. `src/` C
(18): `mirror/http_mirror.c` (649), `config/server_conf.c` (608),
`webdav/tape_rest.c` (600), `dashboard/auth.c` (588), `webdav/tpc.c` (588),
`webdav/macaroon_endpoint.c` (572), `s3/handler.c` (554), `query/prepare.c` (547),
`token/macaroon.c` (546), `webdav/config.c` (539), `metrics/unified.c` (535),
`frm/stage.c` (534), `mirror/stream_mirror.c` (531), `acc/authfile.c` (527),
`cache/writethrough_flush.c` (520), `fs/vfs_io_core.c` (515),
`read/open_request.c` (509), `webdav/lock.c` (505). `client/` C (1):
`lib/webfile.c` (636). Headers (0 beyond §3.4).

---

## 4. Checking — the linter + ratchet + CI

### 4.1 `tests/lint_loc.sh` (new; modeled on `tests/lint_alloc.sh`)

A cheap, dependency-free bash script. Full proposed source (≈ ideal-tier itself):

```bash
#!/usr/bin/env bash
#
# lint_loc.sh — Phase 38: file-size discipline lint + ratchet.
#
# Counts LOGICAL LoC (total - blank - pure-comment) for in-scope hand-written
# source and classifies each file into the §2.1 tiers.  Advisory by default;
# --strict gates a merge by failing when a non-baselined file exceeds the hard
# threshold.  See docs/refactor/phase-38-file-size-unix-modularity.md.
#
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARD=800                 # 🔴 must-split threshold (tunable)
BASELINE="$ROOT/tests/loc_baseline.txt"
MODE="report"           # report | strict | baseline
case "${1:-}" in
  --strict)   MODE=strict ;;
  --baseline) MODE=baseline ;;
  --report|"") MODE=report ;;
  *) echo "usage: lint_loc.sh [--report|--strict|--baseline]" >&2; exit 2 ;;
esac

# In-scope file set (§2.2/§2.3).  Exemptions are honored via a magic comment
# (see §4.4) and the explicit out-of-scope globs below.
in_scope() {
  git -C "$ROOT" ls-files \
      'src/*.c' 'src/*.h' 'client/*.c' 'client/*.h' \
      'tests/*.sh' 'k8s-tests/*.sh' 'utils/*.sh' \
      'tests/*.py' 'utils/*.py' \
    | grep -vE '^(shared/xrdproto/)'        # build harness is data, not code
}

logical_loc() { grep -cvE '^[[:space:]]*$|^[[:space:]]*//|^[[:space:]]*/?\*' "$1"; }
is_exempt()   { head -40 "$1" | grep -q 'loc-lint:[[:space:]]*exempt'; }
tier() { # $1=loc -> name
  if   [ "$1" -le 500 ]; then echo "ideal"
  elif [ "$1" -le 650 ]; then echo "watch"
  elif [ "$1" -le 800 ]; then echo "should"
  else                        echo "must"; fi
}

# Build the current measurement table: "<loc>\t<path>" sorted desc.
measure() {
  while IFS= read -r f; do
    [ -f "$ROOT/$f" ] || continue
    is_exempt "$ROOT/$f" && continue
    printf '%s\t%s\n' "$(logical_loc "$ROOT/$f")" "$f"
  done < <(in_scope) | sort -rn
}

case "$MODE" in
  baseline)
    measure | awk -F'\t' -v h="$HARD" '$1>h {print $2"\t"$1}' > "$BASELINE"
    echo "wrote $(wc -l < "$BASELINE") baselined offender(s) to $BASELINE"
    exit 0 ;;
esac

# Report: per-tier counts + the should/must lists.
echo "== file-size tiers (logical LoC) =="
measure | awk -F'\t' '
  {n++; t=($1<=500?"ideal":($1<=650?"watch":($1<=800?"should":"must")))
   c[t]++; if(t=="should"||t=="must") printf "  %-6s %5d  %s\n", toupper(t), $1, $2}
  END{printf "\n  total=%d  ideal=%d watch=%d should=%d must=%d\n",
             n, c["ideal"], c["watch"], c["should"], c["must"]}'

[ "$MODE" = report ] && exit 0

# Strict (ratchet): fail if a NON-baselined file exceeds HARD, or a baselined
# file grew beyond its recorded size.
fail=0
declare -A base
if [ -f "$BASELINE" ]; then
  while IFS=$'\t' read -r path loc; do base["$path"]=$loc; done < "$BASELINE"
fi
while IFS=$'\t' read -r loc path; do
  rec="${base[$path]:-}"
  if [ -z "$rec" ]; then
    [ "$loc" -gt "$HARD" ] && { echo "NEW over-threshold: $path ($loc > $HARD)"; fail=1; }
  elif [ "$loc" -gt "$rec" ]; then
    echo "baselined file grew: $path ($loc > recorded $rec)"; fail=1
  fi
done < <(measure)
[ "$fail" = 0 ] && echo "lint_loc: ratchet OK" || echo "lint_loc: ratchet FAILED"
exit "$fail"
```

Notes: counts **logical** LoC so doc-blocks never trip it; honors the §4.4
exemption comment; the ratchet compares against `tests/loc_baseline.txt`.

### 4.2 The ratchet (baseline burn-down)

- `tests/loc_baseline.txt` = the grandfathered offender set, one `"<path>\t<loc>"`
  per line, generated by `lint_loc.sh --baseline`. A raw `--baseline` today finds
  **44 files** over 800 logical: **15 C** (7 `src/` + 8 `client/`, per §3.1), **28
  Python**, **1 shell** (`manage_test_servers.sh`). After the M0 step applies the
  **`stream/module.c` exemption** (§6.10), the linter skips it and the baseline is
  **43** (14 C + 28 py + 1 sh). The C+shell are the P0–P3 critical path; the Python
  is the parallel P4 track (§7.5).
- CI rule: **a non-baselined file may not newly cross 800 logical, and a
  baselined file may not grow past its recorded size.** New code is born
  compliant; the baseline only shrinks.
- Each split PR removes its target(s) from the baseline (regenerate with
  `--baseline`, commit the smaller file). The phase is **done** when the baseline
  is empty or holds only documented, justified exemptions.

### 4.3 CI integration

- The repo has **no top-level `.github/workflows`** yet (only `k8s-tests` has one).
  Either fold `tests/lint_loc.sh --strict` into the existing lint stage alongside
  `lint_alloc.sh`, or add a dedicated workflow:

```yaml
# .github/workflows/loc.yml
name: file-size ratchet
on: [pull_request]
jobs:
  loc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }      # lint_loc.sh uses git ls-files
      - name: file-size ratchet
        run: tests/lint_loc.sh --strict
```

- Optional `pre-commit` hook running the advisory `--report` so authors see tiers
  locally before pushing.

### 4.4 Exemption mechanism

A genuinely-cohesive-yet-long file carries a one-line magic comment in its first
40 lines:

```c
/* loc-lint: exempt — single GSI cert-response state machine; splitting harms cohesion */
```

`lint_loc.sh` skips exempt files entirely (they neither count nor gate).
Exemptions are **grep-able and visible in review** (`git grep 'loc-lint: exempt'`),
never silent. Use sparingly; the bar is "splitting would create a worse design,"
not "splitting is work."

---

## 5. How to split one file — the runbook

### 5.1 Method (per file)

1. **Read the whole file. Name its concepts out loud.** If you cannot name 2+
   distinct responsibilities whose one-line descriptions contain no "and", it is
   *not* a split candidate — exempt it (§4.4) and move on.
2. **Build the function inventory** (Appendix B): names + line spans. Cluster by
   shared prefix and shared state. Clusters are your seam candidates — e.g. in
   `s3/post_object.c` the `s3_post_send_*` trio is the response seam; the
   `s3_post_*policy*`/`*credential*` group is the verify seam.
3. **Find the seams** — groups of functions that share state/purpose and are
   loosely coupled to the rest. Prefer seams that minimize the cross-file surface
   (few functions need to lose `static`).
4. **Extract sibling files in the same directory** (`foo.c` → `foo.c` +
   `foo_response.c`, …). Keep names descriptive and consistent with existing
   siblings (`src/cache/{fetch,evict,slice}.c` is the model).
5. **Shared internal contract** → a private `*_internal.h` (existing pattern:
   `cms_internal.h`, `metrics_internal.h`, `cache_internal.h`, `evict_internal.h`).
   Functions that must cross the new boundary lose `static` and gain a prototype
   there; nothing new becomes public API.
6. **Register** new `.c` (root `config` for `src/**`, `client/Makefile` for
   `client/**`, plus `shared/xrdproto/Makefile` for shared sources). Header-only
   changes need no `./configure`.
7. **Update / create the directory `README.md`** responsibility table (create the
   three `client/` READMEs if absent — rule 2.4#4).
8. **Doc-block** each new file (WHAT/WHY/HOW).
9. **Build + test + verify identical behavior** (§8).

### 5.2 The `*_internal.h` pattern (template)

```c
/*
 * foo_internal.h — private contract shared between foo.c and its split siblings.
 *
 * WHAT: prototypes + shared types for the foo subsystem's internal split; NOT a
 *       public API (no callers outside src/<dir>/).
 * WHY:  splitting foo.c (Phase 38) means functions that were `static` now cross a
 *       file boundary; this header is the single place that contract lives.
 * HOW:  include from foo.c and each foo_*.c sibling; never from another subsystem.
 */
#ifndef XROOTD_FOO_INTERNAL_H
#define XROOTD_FOO_INTERNAL_H
#include "..."                 /* the minimal shared types */

/* response builders (foo_response.c) */
ngx_int_t foo_send_created(ngx_http_request_t *r, ...);

/* policy verification (foo_policy.c) */
ngx_int_t foo_verify_policy(foo_ctx_t *ctx, ...);

#endif /* XROOTD_FOO_INTERNAL_H */
```

### 5.3 A worked extraction (before → after)

Concrete shape of one cut — pulling the live-transfer model out of
`src/dashboard/api.c` (§6.1). **Before:** one file, the function `static`:

```c
/* src/dashboard/api.c (before) */
static json_t *
dashboard_build_transfer_object(ngx_pool_t *pool, const xrootd_xfer_t *x,
                                int64_t now_ms, ngx_uint_t redact)
{
    /* …134 lines… */
}
/* …caller a few hundred lines down… */
rows = dashboard_build_transfer_rows(now_ms, pool, redact);
```

**After:** the cluster moves to `api_transfers.c`, loses `static`, and gains a
prototype in a *new* private header that both files include:

```c
/* src/dashboard/dashboard_api_internal.h (new) */
#ifndef XROOTD_DASHBOARD_API_INTERNAL_H
#define XROOTD_DASHBOARD_API_INTERNAL_H
#include "dashboard.h"
/* live-transfer model — api_transfers.c */
json_t *dashboard_build_transfer_object(ngx_pool_t *pool, const xrootd_xfer_t *x,
                                        int64_t now_ms, ngx_uint_t redact);
json_t *dashboard_build_transfer_rows(int64_t now_ms, ngx_pool_t *pool,
                                      ngx_uint_t redact);
#endif
```

```c
/* src/dashboard/api_transfers.c (new) — note: NO 'static' now */
#include "dashboard_api_internal.h"
json_t *
dashboard_build_transfer_object(ngx_pool_t *pool, const xrootd_xfer_t *x,
                                int64_t now_ms, ngx_uint_t redact)
{
    /* …the same 134 lines, unchanged… */
}
```

Then: add `$ngx_addon_dir/src/dashboard/api_transfers.c` to the root `config`
`NGX_ADDON_SRCS`; add a row to `src/dashboard/README.md`; `./configure && make`;
`tests/test_dashboard.py` green; `git grep -n 'goto' src/dashboard/api_transfers.c`
empty. **Zero behavior change** — the bytes the endpoint emits are identical.

### 5.4 Anti-patterns (do NOT)

- ❌ Split at an arbitrary line number ("file2 starts at line 500").
- ❌ Reach into another file's privates instead of a clean `*_internal.h`.
- ❌ Introduce a `goto`, a new global, or change behavior "while I'm here".
- ❌ Reimplement a HELPER (path/auth/metrics/framing) during a move.
- ❌ Split a single state machine / codec just to hit the number (exempt it).
- ❌ Promote a `static` function to public API when `*_internal.h` would do.

---

## 6. Per-file split specifications

Each spec below is grounded in the **measured function inventory** (Appendix B) of
the file as of 2026-06-26 — function names and line spans are real, so the
proposed LoC per resulting file is an estimate from actual spans, not a guess.
Confirm against the file before cutting (functions move between revisions).

### 6.1 `src/dashboard/api.c` (986 logical / 1290 raw → ~4 files) — worked example

Four near-independent concerns sharing only small static helpers:

| New file | Functions moved | ~Raw LoC |
|---|---|---|
| `api.c` (keep) | name/format maps (`dashboard_{direction,proto,state,tpc_*}_name`, `dashboard_avg_bps`, `dashboard_session_hash`), `dashboard_send_json`, `dashboard_endpoint_is_anon_allowed`, `ngx_http_xrootd_dashboard_api_handler` (routing) | ~300 |
| `api_transfers.c` | `dashboard_build_transfer_object` (134), `dashboard_build_transfer_rows`, `dashboard_build_tpc_registry`, `dashboard_build_compat_transfers`, `dashboard_build_v1_transfers`, `dashboard_parse_detail_id`, `dashboard_build_v1_transfer_detail` | ~330 |
| `api_snapshot.c` | `dashboard_collect_totals`, `dashboard_collect_protocols`, `dashboard_build_{limits,totals,proto_summary,protocols,events}`, `dashboard_fill_{history,cache,cluster}`, `dashboard_new_v1_root`, `dashboard_build_v1_{snapshot,events,history,cluster,cache}` | ~480 |
| `api_ratelimit.c` | `dashboard_build_v1_ratelimit` (66) + `dashboard_build_v1_{not_found,truncated}` | ~120 |

Shared decls (the `summary` struct, helper prototypes) → new
`dashboard_api_internal.h`. Register three new `.c` in `config`; update
`src/dashboard/README.md`. No behavior change → `tests/test_dashboard.py` stays
green. (`api_snapshot.c` at ~480 is near the line; if `fill_cache`'s 104 lines
push it over, peel `api_cache.c` out as a fifth file.)

### 6.2 `src/s3/post_object.c` (973 / 1452 → ~4 files)

POST-object (browser-upload) handler with four phases:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `post_object.c` (keep) | body handler + `s3_post_error`, small helpers (`s3_memmem`, `s3_post_basename`, `s3_post_copy_text`) | ~200 |
| `post_form.c` | `s3_post_field_value`, `s3_post_store_field`, `s3_post_boundary`, `s3_post_extract_param`, `s3_post_expand_filename`, `s3_post_parse_form` (156) | ~470 |
| `post_policy.c` | `s3_post_{days_from_civil,parse_iso8601,check_field_eq,policy_condition,validate_policy_json,parse_credential,verify_policy}` | ~500 |
| `post_response.c` | `s3_post_send_{empty,created,success}` | ~160 |

`post_policy.c` lands at ~500 — acceptable; do not over-split the policy state.
Shared decls → `post_internal.h`. Tests: `tests/test_s3_post_object.py` (+ the S3
conformance batch) unchanged.

### 6.3 `src/webdav/propfind.c` (811 / 1149 → ~3 files)

Dominated by two large functions — `propfind_entry` (308) and `propfind_do`
(215). Seam is parse vs property-emit vs walk:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `propfind.c` (keep) | `webdav_handle_propfind`, `propfind_body_handler`, `propfind_parse_{request,depth}`, `propfind_name_to_bit`, `propfind_assemble_body` | ~330 |
| `propfind_props.c` | `propfind_entry` (308), `propfind_append_acl_properties` (135) — the per-resource property emitter | ~470 |
| `propfind_walk.c` | `propfind_walk` (129), `propfind_do` (215) — depth traversal + response orchestration | ~360 |

`propfind_entry` is the auditability win: 308 lines of property serialization in
its own file. Shared decls → `propfind_internal.h`. Tests:
`tests/test_webdav_propfind.py`.

### 6.4 `src/manager/registry.c` (686 / 1123 → ~3 files)

Clean functional clusters by prefix:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `registry.c` (keep) | SHM zone/init (`xrootd_srv_shm_init_zone`, `srv_table`, `configure_registry`, `set_stale_after`), register/update/unregister | ~430 |
| `registry_select.c` | `srv_select_core` (107), `xrootd_srv_select{,_or_blacklisted}`, `srv_path_matches`, `srv_count_matching`, `xrootd_manager_tried_exhausted`, `blacklist`/`undrain` | ~430 |
| `registry_health.c` | `xrootd_srv_hc_{claim,pass,fail}`, `locate_all`, `unregister_path`, `aggregate_space`, `snapshot` | ~340 |

Shared decls already partly in `manager_internal.h` if present; otherwise add it.
Tests: the CMS/manager cluster suite.

### 6.5 `src/impersonate/broker.c` (725 / 1104 → ~3 files) — security-critical

The privileged broker — highest audit value. `imp_do_op` (288) is the heart.

| New file | Functions | ~Raw LoC |
|---|---|---|
| `broker.c` (keep) | `xrootd_imp_broker_run`, `imp_serve_one` (123), `imp_read_full`, `imp_send_reply`, `imp_peer_allowed` (the trust gate) | ~310 |
| `broker_creds.c` | `imp_capset_setuid_setgid`, `imp_drop_to_service_user`, `xrootd_imp_broker_drop_caps`, `imp_become`, `imp_restore`, `imp_rel` — the privilege transitions | ~280 |
| `broker_ops.c` | `imp_do_op` (288), `imp_openat2`, `imp_open_parent`, `imp_fill_stat`, `imp_do_rename`, `imp_xattr_*` | ~430 |

Keep the **trust boundary** (`imp_peer_allowed`) and the **privilege transitions**
(`broker_creds.c`) each in one small, separately-reviewable file — that is the
whole point. Shared decls → `broker_internal.h`. Tests:
`tests/test_impersonation*.py` + `tests/userns/e2e_redteam.py` (the red-team must
stay green — this is the file it exists to guard).

### 6.6 `client/lib/copy.c` (1886 / 2582 → ~5 files) — the xrdcp engine

Direction/orchestration vs the pumps vs each transfer mode:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `copy.c` (keep) | `xrdc_copy` entry + direction inference, `copy_one_{r2l,l2r}`, signal/quit handling | ~300 |
| `copy_pump.c` | `transfer_pump` (163) + all `pump_{src,sink}_*` + `write_all` | ~350 |
| `copy_local.c` | `copy_download` (128), `copy_upload`, `upload_stream_body` (151), temp-file/atomic-dest helpers (`make_temp_path`, `open_download_temp`, `atomic_dest_finish`) | ~520 |
| `copy_remote.c` | `copy_remote_to_remote`, `copy_tpc` (75), `gen_tpc_key`, r2r/tpc teardown, `cksum_verify` | ~330 |
| `copy_recursive.c` | `copy_tree_{download,upload}`, `copy_recursive`, `recursive_dest_root`, `web_auth_headers`, `copy_web_download` | ~400 |

Shared decls → `copy_internal.h`. `copy_local.c` (~520) is near the line — keep
upload/download together only if they share the atomic-dest helpers, else peel.
Tests: the client conformance suite + `tests/test_integrity_matrix.py`.

### 6.7 `client/lib/aio.c` (1580 / 1938 → ~5 files) — already section-marked

This file *already* carries `/* ---- section ---- */` banners (`buffers`, `reqmap`,
`request`, `io`, `conn`, `reconnect`, `keepalive`, …) — the seams are pre-drawn.
Cut on them:

| New file | Section/functions | ~Raw LoC |
|---|---|---|
| `aio_buffers.c` | `xbuf_*` (4) + `reqmap_*` (4, incl. `reqmap_del` 144) + `areq_*` | ~430 |
| `aio_io.c` | `aconn_do_{read,write}`, `aconn_parse`, `aconn_dispatch_frame`, rtt/rto | ~330 |
| `aio_engine.c` | `io_engine_*` (epoll + io_uring poll: `uring_*`, `io_engine_{setup,arm,del,wait,teardown}`) | ~330 |
| `aio_conn.c` | `aconn_*` lifecycle: reconnect, ping/keepalive, destroy, attach/close, deadlines | ~430 |
| `aio.c` (keep) | the loop (`loop_*`, `rc_worker_main`, `loop_thread`) + public API (`xrdc_loop_*`, `xrdc_aio_*`, `xrdc_aconn_*`) | ~420 |

Shared decls (`aconn_t`, `areq_t`, the loop struct) → `aio_internal.h`. This is a
hot data-plane path — run ASAN/UBSan (§8). Tests: client conformance + resilience.

### 6.8 `client/lib/http.c` (919 / 1139 → ~4 files)

Three independent transports grew in one file (the `xrdc_http_get` doc-block warns
"keep tiny"; it didn't stay tiny):

| New file | Functions | ~Raw LoC |
|---|---|---|
| `http.c` (keep) | `xrdc_http_get` (the original minimal GET), `httpx_connect`, `httpx_parse`, header helpers, `dechunk`, `ci_contains` | ~330 |
| `http_req.c` | `xrdc_http_req`, `httpx_exchange`, `httpx_body_complete`, `httpx_read_some` (the generic request/response codec) | ~220 |
| `http_download.c` | `xrdc_http_download`, `httpx_download_{body,exchange}`, `stream_{clen,eof,chunked}`, `read_resp_headers` | ~320 |
| `http_upload.c` | `xrdc_http_upload{,_resumable}`, `httpx_upload_{body,response,exchange,chunk}`, `httpx_parse_upload_offset` | ~280 |

Shared decls → `http_internal.h`. Tests: `tests/test_fuse_http_transport.py` + the
WebDAV/S3 client paths.

### 6.9 The two big CLI apps — `xrddiag.c` (2968) and `xrdfs.c` (2401)

These are the largest files in the repo after the Python red-team. Both split on
**one file per subcommand**, the cleanest possible seam:

- **`xrddiag.c`** → `xrddiag.c` (arg parse + dispatch + shared `dx_*` probe
  helpers) + `diag_check.c`, `diag_bench.c`, `diag_topology.c`, `diag_status.c`,
  `diag_compare.c`. The shared probe/record helpers (`dx_record_status`,
  `dx_probe_checksum`, `dx_http_status`, …) and the parsed-args struct go in
  `diag_internal.h`. Order this **last** in the client track — it is large but
  mechanical and low-risk (a diagnostic tool, not a data path).
- **`xrdfs.c`** → `xrdfs.c` (REPL + arg driver + dispatch table) + grouped command
  files: `xrdfs_meta.c` (stat/ls/locate/query/statvfs), `xrdfs_mutate.c`
  (mkdir/rm/rmdir/mv/chmod/truncate), `xrdfs_data.c` (cat/tail incl. the
  `tail_*` follow loop), with shared output formatting in `xrdfs_fmt.c`.

### 6.10 `src/stream/module.c` (1316 / 1734 → **exempt**)

Per §2.6 this is **1251/1316 logical = 95% a single 213-entry `ngx_command_t`
directive table** plus 8 `ngx_conf_enum_t` value maps. Its logic is *already*
extracted: `ngx_stream_xrootd_create_srv_conf`/`merge_srv_conf` live in
`src/config/server_conf.c`, and the `ngx_module_t` struct in
`src/stream/module_definition.c`. **No split.** Add the exemption comment and
record the rationale:

```c
/* loc-lint: exempt — single declarative ngx_command_t table; conf logic already
   in config/server_conf.c + stream/module_definition.c (Phase 38 §2.6) */
```

This removes it from the baseline. *(If the table is ever felt to be too big to
read, the right move is documentation/grouping comments within the array — which
it already has — not sharding the C array.)*

### 6.11 `src/webdav/module.c` (904 / 1153 → ~3 files, residual table → watch)

**618 logical table + 286 logical logic.** Extract the logic; the residual table
file lands at ~618 (🟡 watch — green for the ratchet):

| New file | Functions | ~Raw LoC |
|---|---|---|
| `module.c` (keep) | the `ngx_command_t` table + `ngx_http_xrootd_webdav_module_ctx` | ~760 raw / ~618 logical |
| `module_directives.c` | the 4 setter callbacks `webdav_conf_{add_cors_origin,dig_export,proxy_auth,proxy_upstream}` (L45–L266) | ~220 |
| `module_init.c` | the phase handlers + `*_init`/postconfig (L1056–L1128) | ~120 |

Shared decls → `webdav.h` (already present) or a small `module_internal.h`.
*(Alternatively, exempt the residual table per §2.6 — but extracting the four
setters is cheap and keeps the table file genuinely table-only.)*

### 6.12 `src/dashboard/api_admin.c` (894 / 1198 → ~4 files)

Admin write-plane, four concerns by prefix cluster:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `api_admin.c` (keep) | `xrootd_admin_dispatch` (93), `xrootd_admin_check_auth`, `admin_audit`, body read/callback, `admin_send_{ok,error}`, `admin_validate_{hostname,paths,url}`, `admin_uri_*` | ~360 |
| `api_admin_cluster.c` | `admin_parse_server_uri` (88), `admin_cluster_{register,drain,delete,undrain}` | ~230 |
| `api_admin_proxy.c` | `admin_parse_proxy_uri`, `admin_proxy_{backend_json,add,list,one}`, `admin_url_host_allowed` | ~290 |
| `api_admin_config.c` | `admin_io_uring_{set,get}`, `xrootd_admin_set_{allow,secret,proxy_allow}` | ~220 |

Shared decls → `dashboard_api_internal.h` (§5.3). **Security-sensitive** (admin
auth) — keep `check_auth`/`audit` in the kept file. Tests:
`tests/test_dashboard_admin*.py`.

### 6.13 `src/s3/put.c` (796 / 1186 → ~4 files)

Dominated by a 12-function `s3_put_finalize_*` result family:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `put.c` (keep) | `s3_put_body_handler`, `s3_put_body_inner`, `s3_put_body_mode`, `s3_put_streaming` (89), dashboard helpers | ~310 |
| `put_finalize.c` | the 12 `s3_put_finalize_*` + `s3_put_checksum_failed` + `s3_commit_put`/`conflict` | ~330 |
| `put_chunk.c` | `s3_chunk_{finalize,decode_failed,aio_thread,aio_done}`, `s3_build_chunk_verify` (aws-chunked) | ~210 |
| `put_aio.c` | `s3_put_aio_thread`/`done`, `s3_put_vfs_ctx`, `s3_thread_pool` | ~190 |

Shared decls → `s3_put_internal.h`. **Invariant 6** (SigV4 ≠ WLCG) — no auth logic
moves. Tests: S3 conformance batch + `tests/test_s3_write_concurrency.py`.

### 6.14 `src/webdav/tpc_curl.c` (662 / 900 → ~3 files)

`webdav_tpc_run_curl_core` (178) is the heart; SciTags pmark and curl-setup are
separable:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `tpc_curl.c` (keep) | `webdav_tpc_run_curl_core` (178) + `_pull`/`_push`/`_multi_finish`/`_pull_multi` | ~360 |
| `tpc_curl_setup.c` | `tpc_curl_secure` (93), `tpc_curl_apply_conf`, `apply_stall_bounds`, `head_size` | ~220 |
| `tpc_curl_pmark.c` | `webdav_tpc_pmark_{opensocket,closesocket,attach}` + callbacks `ms_write_cb`, `progress`, `finish` | ~220 |

Shared decls → `tpc_internal.h` (likely exists). Tests: `tests/test_tpc*.py`.

### 6.15 `client/apps/xrd.c` (1566 / 1872 → ~5 files) — the swiss-army front-end

A multi-verb tool; split per verb group (each is independent):

| New file | Functions | ~Raw LoC |
|---|---|---|
| `xrd.c` (keep) | dispatcher: `is_fs_verb`, `exec_tool`, `map_fs_arg`, `usage`, `main` | ~260 |
| `xrd_battery.c` | `battery_root` (210), `battery_web` (118), `battery_s3` (87), `xrd_run_battery`, `bat_add`, `fill_pattern`, `tmpfile_with` | ~520 |
| `xrd_doctor.c` | `xrd_doctor` (151), `xrd_doctor_json` (112), `xrd_doctor_probe`, `xrd_json_str`, `xrd_certinfo`, `xrd_probe_caps` | ~420 |
| `xrd_clockskew.c` | `xrd_clockskew{,_http,_root}`, `xrd_measure_clock_skew`, `xrd_parse_http_date`, `xrd_fmt_epoch`, `xrd_fabs` | ~190 |
| `xrd_mount.c` | `xrd_{list_mounts,mount,unmount}`, `mountinfo_unescape`, `run_cmd`, plus `xrd_{login,ping,whoami,caps,role_str}` | ~430 |

Shared decls + the parsed-opts struct → `xrd_internal.h`. Tests: client diag suite.

### 6.16 `client/apps/xrdcp.c` (1224 / 1480 → ~3 files)

| New file | Functions | ~Raw LoC |
|---|---|---|
| `xrdcp.c` (keep) | `usage`, arg/`str_*` helpers, url predicates (`is_*_url`, `uses_cred_auth`, `is_local_dir`), `merge_alias_auth`, `xrdcp_progress`, `main` | ~360 |
| `xrdcp_transfer.c` | `copy_one_with_retry`, `transfer_one`, `entry_size`, `relay_web_to_web`, `batch_{copy_one,worker,parallel}` | ~330 |
| `xrdcp_recursive.c` | `expand_source`, `source_has_glob`, `mkdirs_for`, `mkcol_parents`, `recursive_place`, `ensure_web_dst_base`, `recursive_{s3,web}_download`, `web_upload_walk`, `recursive_web_upload`, `web_join` | ~430 |

Shared decls → `xrdcp_internal.h`. Tests: client conformance + `test_client_xrdcp_bulk.py`.

### 6.17 `client/apps/xrootdfs.c` (921 / 1116) + `xrootdfs_legacy.c` (686 / 864)

The FUSE driver — split the `xfs_*` op table by op family:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `xrootdfs.c` (keep) | the FUSE op struct, `xfs_init`, `usage`, `xrootdfs_aio_main`, small ops | ~300 |
| `xrootdfs_meta.c` | `xfs_{getattr,readdir,statfs,access,chmod,chown,truncate,utimens,rename,symlink,link,readlink,mkdir,unlink,rmdir}` | ~360 |
| `xrootdfs_io.c` | `afh_*` (file-handle), `xfs_{open,create,read,write,flush,fsync,release}` | ~280 |
| `xrootdfs_xattr.c` | `xfs_{getxattr,setxattr,removexattr,listxattr}`, `xfs_xattr_to_fattr`, `op_*` | ~160 |

`xrootdfs_legacy.c` has the **same `xfs_*` shape** — **decide first whether to
retire it** (if `xrootdfs.c` fully supersedes it) rather than split a soon-dead
file. If kept, mirror the split. Tests: `tests/test_xrootdfs*.py`.

### 6.18 `client/lib/ops_file.c` (743 / 941 → ~3 files)

Wire file-op verbs; split by verb family:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `ops_file.c` (keep) | open family (`xrdc_file_open_{read,write,update,opaque}`), `xrdc_file_{close,sync}` | ~250 |
| `ops_file_rw.c` | `xrdc_file_{read,write,readv,writev}` + `xrdc_{inflate,deflate}_frame` | ~370 |
| `ops_file_pg.c` | `xrdc_file_{pgread,pgwrite}`, `read_status_frame`, `decode_pages`, `pgwrite_retry_one` | ~320 |

`ops_file_pg.c` carries **Invariant 1** (pgread/pgwrite CRC32c + kXR_status
framing) — keep it whole and well-doc'd. Shared decls → `ops_internal.h` or
`xrdc.h`. Tests: client conformance + `test_readv_security.py` analogue.

### 6.19 `client/lib/zip.c` (666 / 783 → ~2 files) — clean reader/writer split

| New file | Functions | ~Raw LoC |
|---|---|---|
| `zip.c` (keep, reader) | `le*`, `read_exact`, `find_eocd`, `apply_zip64_extra`, `xrdc_zip_{open,find,dir_free,member_extract,read_eocd}`, `member_data_offset`, `sink_output` | ~440 |
| `zip_write.c` | `put*`, `cd_append`, `xrdc_zip_writer_{new,new_append,add_fd,finish,free}`, `w_emit` | ~340 |

The reader/writer boundary is already implicit (the `put*` vs `le*` helpers). Tests:
client ZIP suite.

### 6.20 `client/lib/webfile.c` (636 / 787 → 🟡 watch, refactor-on-touch)

Watch-tier — no scheduled split, but if touched: `webfile.c` (PROPFIND/stat:
`xrdc_web_stat`, `xrdc_web_readdir`, `parse_response`, XML helpers) +
`webfile_io.c` (range GET: `web_{connect,disconnect,read_some,get_range}`,
`xrdc_webfile_{open,size,pread,close}`). ~330 / ~320.

### 6.21 Exemption candidates (split would harm — use `loc-lint: exempt`)

- **`src/stream/module.c`** — declarative `ngx_command_t` table (§2.6, §6.10).
- **Large single functions that must stay whole** (not file exemptions, but
  "don't cut mid-function" notes for the splits above):
  `xrootd_gsi_build_cert_response` (210 lines, one cert-response assembly —
  §6 P0 gsi split keeps it intact in its target file); `propfind_entry` (308, one
  property serializer — §6.3); `webdav_tpc_run_curl_core` (178, one transfer
  driver — §6.14); `imp_do_op` (288, the broker op dispatcher — §6.5, keep whole
  in `broker_ops.c`). Splitting any of these mid-body to hit a per-file number
  would create exactly the spaghetti this phase exists to prevent.
- **Any future single wire-format codec** that is one cohesive state machine.

---

## 7. Prioritized work plan

### 7.0 Gate 0 — tooling first (do before any split)

Land `tests/lint_loc.sh` (§4.1) + `tests/loc_baseline.txt` (`--baseline`, 44
entries) + CI wiring (§4.3). This *locks the ratchet* so the tail stops growing
while we burn it down, and gives an objective "done" signal. **No source split
happens before Gate 0.**

### 7.1 P0 — `src/` C monoliths > 800 logical (7 files)

The §3.2 🔴 rows, minus the two `module.c` directive-table special cases (§2.6).
That leaves **5 genuine logic monoliths** + 1 logic-extraction, one focused PR
each, ordered **audit value first**, then size:

1. `gsi/gsi_core.c` (1033) — **shared**; split also touches
   `shared/xrdproto/Makefile` and must keep the ngx-free client build green (run
   `shared/xrdproto/check-ngx-free.sh`).
2. `s3/post_object.c` (973) — §6.2.
3. `webdav/propfind.c` (811) — §6.3.
4. `dashboard/api.c` (986) — §6.1 (the worked example).
5. `dashboard/api_admin.c` (894) — §6.12.
6. `webdav/module.c` (904) — **logic-extract only** (§6.11): pull the 4 setters +
   phase handlers out; the residual table drops to ~618 (watch).

Special cases handled separately: **`stream/module.c` is exempted** (§6.10 — a
one-line `loc-lint` comment, do it in M0). The privileged `impersonate/broker.c`
(725 logical, 🟠) leads **P1**, not P0, but is the single highest-audit-value split
in the whole phase (§6.5).

### 7.2 P1 — `src/` C 651–800 logical (4 files)

The §3.2 🟠 rows (the 4 files 651–800 logical), audit-value first:
`impersonate/broker.c` (privileged — do it first; §6.5), then `s3/put.c`,
`manager/registry.c`, `webdav/tpc_curl.c`. `registry.c` (clean prefix clusters)
and `s3/put.c` (the `s3_put_finalize_*` family) are the cleanest mechanical wins.

### 7.3 P2 — the two real headers + the shell monster

- `client/lib/xrdc.h` (579) — split by concern; **full rebuild** (mixed-ABI, every
  `client/` TU includes it). Riskiest single item in the client track.
- `src/types/config.h` (518) — borderline; split by plane only if it grows.
  **Full rebuild** (mixed-ABI).
- `tests/manage_test_servers.sh` (1868) — extract sourced libs; the single
  highest-LoC shell file and central to every test run, so do it carefully with a
  smoke run of `start-all`/`restart`.
- *(Note: `src/webdav/webdav.h`/`metrics.h` are NOT split — §3.4.)*

### 7.4 P3 — `client/` native-client track (independent, parallelizable)

The §3.3 list (11 C files > 650, 8 monoliths). Separate build (`client/Makefile`,
no nginx ABI), so it runs **concurrently with P0–P2** by a separate effort. **First
create the missing `client/README.md` + `client/{lib,apps}/README.md` tables**
(rule 2.4#4), then order by audit value: the wire/transport engines
`client/lib/{copy,aio,ops_file,http}.c` first, then the CLI apps
`client/apps/{xrdcp,xrootdfs,xrd,xrdfs,xrddiag}.c` (xrddiag last — biggest but
lowest-risk). Each split lands its new `.c` in `client/Makefile`, updates the
relevant `README.md`, and re-runs the client conformance track + a smoke
`xrdcp`/`xrdfs` round-trip. `client/lib/xrdc.h` (§7.3) is the one mixed-ABI item —
do it on a quiet tree with a full client rebuild. Decide early whether
`xrootdfs_legacy.c` is **retired** rather than split.

### 7.5 P4 — Python track (independent, parallelizable)

Split `tests/*.py` > 650 along test-class/concern lines, sharing fixtures via
`conftest.py`. Lower risk (no build, no ABI), high audit value. Runs concurrently
with P0–P3 by a separate effort. **Start with `tests/userns/e2e_redteam.py`
(29,053)** — split per attack-scenario class into a package under
`tests/userns/redteam/`. `utils/xrd_sec_probe.py` (tooling) splits into a small
package.

---

## 8. Verification (per split PR)

Because these are **pure refactors**, the strongest signal is "the entire test
suite is byte-for-byte green before and after." Per PR:

```bash
# 1. Build clean (configure only when a new .c was registered; full rebuild when a
#    header/struct moved — mixed-ABI gotcha).
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
            --with-http_dav_module --with-threads --add-module=$REPO && make -j"$(nproc)"
# client tree:
make -C client -j"$(nproc)"
# shared sources touched? prove the ngx-free build still links:
shared/xrdproto/check-ngx-free.sh && shared/xrdproto/check-shared-coverage.sh

# 2. No goto introduced anywhere in the new files.
git grep -nE 'goto[[:space:]]+[A-Za-z_]' -- 'src/**' 'client/**'   # → empty

# 3. The target dropped a tier and the ratchet still passes.
tests/lint_loc.sh --report          # target now ≤ its new tier
tests/lint_loc.sh --baseline        # regenerate; commit the SHRUNK baseline

# 4. Behavioral identity: the subsystem's own tests, then the whole suite.
PYTHONPATH=tests pytest tests/test_<area>.py -v
PYTHONPATH=tests pytest tests/ -q
# ASAN/UBSan for memory-touching splits (aio, copy, s3, tpc, broker):
#   build with -fsanitize=address,undefined and re-run the area tests.

# 5. Binary health.
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf   # OK
# smoke transfer round-trips (root:// + a client CLI):
xrdcp root://localhost:11094//file /tmp/out && cmp /path/file /tmp/out
```

Checklist: new `.c` registered in the right manifest · directory `README.md` row
added (or the three `client/` READMEs created) · each new file has a WHAT/WHY/HOW
doc-block · `tests/lint_loc.sh --report` shows the drop · baseline regenerated and
smaller · no `goto`, no new global, no behavior change.

---

## 9. Risks & non-goals

| Risk | Mitigation |
|---|---|
| Mixed-ABI SIGSEGV from header/struct moves (`xrdc.h`, `types/config.h`) | Touch all dependents + full rebuild; prefer moving *code* not *layout*; ([build_header_dep_mixed_abi]) |
| Churn for churn's sake / cohesion loss | Tier metric is advisory; exempt genuinely-cohesive long files (§4.4); a human decides seams; the "no 'and' in the one-line responsibility" test |
| Over-fragmentation (50-line files everywhere) | Target is *one responsibility*, not minimum size; ≤500 is a ceiling, not a quota |
| Breaking the privileged broker during its split | `broker.c` keeps the trust gate + privilege transitions each in one small file; `e2e_redteam.py` must stay green; ASAN |
| `client/` has no README tables to update | The client track *creates* them first (rule 2.4#4) — a prerequisite, not optional |
| Shared-source split breaks the ngx-free client build | `check-ngx-free.sh` + `check-shared-coverage.sh` in CI for any `src/{compat,gsi,token,fs/backend}` change |
| Reviewer fatigue from many PRs | One file per PR, but batch trivially-mechanical ones; the ratchet makes the end state objective |
| Test-suite split losing shared fixtures | Keep fixtures in `conftest.py`; never duplicate setup |
| Breaking `config`/`client/Makefile` registration | The linter could also assert every `src/**/*.c` appears in `config` and every `client/**/*.c` in `client/Makefile` (bonus check) |

**Non-goals:** reformatting, renaming for style, touching declarative config/docs,
or changing any runtime behavior. This phase **moves** code; it does not modify it.

---

## 10. Milestones & effort

| Milestone | Content | Rough effort |
|---|---|---|
| M0 | `lint_loc.sh` + apply `stream/module.c` exemption + baseline (43: 14 C + 28 py + 1 sh) + CI ratchet | 0.5–1 day |
| M1 | P0: 5 `src/` logic monoliths + `webdav/module.c` logic-extract (audit-value order) | ~1–1.5 days each → ~1.5 weeks |
| M2 | P1: 4 `src/` C files (651–800) | ~3–4 days |
| M3 | P2: `client/lib/xrdc.h` + `src/types/config.h` + `manage_test_servers.sh` | ~3–4 days |
| M4 | P3: `client/` native-client track (11 C files + 3 READMEs) | parallel; ~2–3 weeks |
| M5 | P4: Python track (start with `e2e_redteam.py`) | parallel; ~1–2 weeks |

**Definition of done:** `tests/lint_loc.sh --strict` is green on a clean tree with
an empty (or fully-justified-exemption) baseline, the CI ratchet is enforced, and
the whole test suite is green. From then on, file-size discipline is *maintained
by tooling*, not vigilance.

---

## Appendix A — one-shot measurement commands

```bash
# logical LoC of one file (the §2.5 definition)
logical() { grep -cvE '^[[:space:]]*$|^[[:space:]]*//|^[[:space:]]*/?\*' "$1"; }

# Per-tree tier counts (src + client, .c and .h)
for tree in src client; do for ext in c h; do
  git ls-files "$tree/*.$ext" | while read -r f; do printf '%s\t%s\n' "$(logical "$f")" "$f"; done
done; done | sort -rn \
  | awk -F'\t' '{n++; if($1>500)a++; if($1>650)b++; if($1>800)c++}
                END{printf "files=%d >500=%d >650=%d >800=%d\n",n,a,b,c}'

# The split list: every in-scope C file over 650 logical, with raw for context
for f in $(git ls-files 'src/*.c' 'client/*.c'); do
  printf '%s\t%s\t%s\n' "$(logical "$f")" "$(wc -l < "$f")" "$f"
done | awk -F'\t' '$1>650' | sort -rn
```

## Appendix B — how the function inventories were built

The §6 seam tables are grounded in a real per-function inventory. With `ctags`
absent, functions are extracted by the codebase's K&R style — the function name
sits at column 0 (return type on the previous line):

```bash
# top-level function defs (name + line) for one C file, with approximate spans
funcs() {
  awk '/^[A-Za-z_]/ && /\(/ && !/;[[:space:]]*$/ {
        if ($0 ~ /^(if|for|while|switch|return|sizeof|typedef|struct|union|enum|else|case|do|static_assert|extern|#)/) next
        s=$0; sub(/\(.*/,"",s); n=split(s,p," "); name=p[n]; gsub(/\*/,"",name)
        if (name!="") print NR"\t"name
      }' "$1"
}
# span of each function ≈ (next def line − this def line)
funcs "$1" | awk -F'\t' 'NR>1{print prevl"\t"($1-prevl)"\t"prevn} {prevl=$1;prevn=$2}'
```

This is a heuristic (it misses K&R defs whose name is not at column 0, and counts
a trailing static-data block toward the last function), but it is accurate enough
to *find seams*, which is all §6 needs. Re-run it before cutting a file — the
spans drift as code changes.

## Appendix C — glossary

- **Logical LoC** — total − blank − pure-comment lines (§2.5). The authoritative
  metric for tiers.
- **Tier** — ideal/watch/should/must bands (§2.1).
- **Ratchet** — the CI rule that no non-baselined file crosses 800 logical and no
  baselined file grows (§4.2).
- **Baseline** — `tests/loc_baseline.txt`, the grandfathered offender set that only
  shrinks.
- **Seam** — a cluster of functions sharing state/purpose, loosely coupled to the
  rest; the natural cut line for a split.
- **`*_internal.h`** — a private contract header shared only between a file and its
  split siblings; not public API.
- **Build-in-place (shared)** — shared libxrdproto C that physically lives under
  `src/` and is compiled into both the module and the ngx-free tools via
  `shared/xrdproto/Makefile`.
- **Mixed-ABI gotcha** — moving a struct/inline between a header and its users
  without a full rebuild → stale objects → SIGSEGV.

## Appendix D — related standards & memories

- [`coding-standards.md`](../09-developer-guide/coding-standards.md) §"Smaller files
  are preferred" (the principle this phase enforces), §4 no-goto, §8
  functional/modular, §doc WHAT/WHY/HOW.
- Build governance: root `config` `NGX_ADDON_SRCS`, `client/Makefile`,
  `shared/xrdproto/Makefile` (`CLAUDE.md`/`AGENTS.md` BUILD GOVERNANCE; §2.2 scope).
- Doc-tree standard: `README.md` per `src/` subdir (and, after P3, per `client/`
  subdir).
- `tests/lint_alloc.sh` — the linter pattern `lint_loc.sh` is modeled on.
- Gotcha: editing a header's struct layout + incremental make = stale-object
  SIGSEGV → always full rebuild ([build_header_dep_mixed_abi]).

## Appendix E — audit hotspots (largest function per monolith)

Measured 2026-06-26 (Appendix B method). The **single largest function** in each
monolith is where review attention concentrates; the split's job is to isolate it
in a small, named file so it can be read on its own. Sizes are approximate raw
spans. This doubles as a sanity check on the §6 seam choices — every hotspot below
lands in a dedicated target file, never split mid-body (§6.21).

| File | Largest function | ~Lines | Isolated into (§6) |
|---|---|---|---|
| `src/gsi/gsi_core.c` | `xrootd_gsi_build_cert_response` | 210 | cert-response file (P0) |
| `src/dashboard/api.c` | `dashboard_build_transfer_object` | 134 | `api_transfers.c` (§6.1) |
| `src/s3/post_object.c` | `s3_post_parse_form` | 156 | `post_form.c` (§6.2) |
| `src/webdav/propfind.c` | `propfind_entry` | 308 | `propfind_props.c` (§6.3) |
| `src/dashboard/api_admin.c` | `xrootd_admin_dispatch` | 93 | kept `api_admin.c` (§6.12) |
| `src/manager/registry.c` | `srv_select_core` | 107 | `registry_select.c` (§6.4) |
| `src/impersonate/broker.c` | `imp_do_op` | 288 | `broker_ops.c` (§6.5) |
| `src/s3/put.c` | `s3_put_streaming` | 89 | kept `put.c` (§6.13) |
| `src/webdav/tpc_curl.c` | `webdav_tpc_run_curl_core` | 178 | kept `tpc_curl.c` (§6.14) |
| `client/lib/copy.c` | `transfer_pump` | 163 | `copy_pump.c` (§6.6) |
| `client/lib/aio.c` | `reqmap_del` | 144 | `aio_buffers.c` (§6.7) |
| `client/lib/http.c` | `xrdc_http_get` | 129 | kept `http.c` (§6.8) |
| `client/lib/ops_file.c` | `xrdc_file_readv` | 100 | `ops_file_rw.c` (§6.18) |
| `client/apps/xrd.c` | `battery_root` | 210 | `xrd_battery.c` (§6.15) |
| `client/apps/xrdcp.c` | `recursive_web_download` | 100 | `xrdcp_recursive.c` (§6.16) |
| `client/lib/zip.c` | `xrdc_zip_writer_add_fd` | 143 | `zip_write.c` (§6.19) |
| `client/lib/webfile.c` | `web_get_range` | 137 | `webfile_io.c` (§6.20) |

Three hotspots — `propfind_entry` (308), `imp_do_op` (288), and
`xrootd_gsi_build_cert_response` (210) — are large *single* functions that stay
whole (§6.21); the split moves them into a focused file, it does **not** carve them
up. They are the strongest argument for this phase: each is a security-relevant
function currently buried in a 1,000+-line file, and each becomes the headline of a
~300–500-line file a reviewer can hold in their head.
