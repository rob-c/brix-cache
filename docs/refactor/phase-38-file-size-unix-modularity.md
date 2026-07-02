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
- [Appendix F — exhaustive per-file split mechanics](#appendix-f--exhaustive-per-file-split-mechanics) — every function's move range + a literal `*_internal.h` for all 20 splittable files

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
  files physically live under `src/` (e.g. `src/core/compat/`, `src/auth/gsi/`,
  `src/auth/token/`, `src/fs/backend/`) and are compiled into both the nginx module
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
   `client/lib/xrdc.h` (every `client/` TU includes it) and `src/core/types/config.h`.
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

**Why logical, not raw.** Worked proof from this very repo: `src/protocols/webdav/webdav.h`
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
  `src/core/config/server_conf.c` (create/merge) and `src/stream/module_definition.c`
  (the `ngx_module_t` struct); what remains is essentially pure table + 8
  `ngx_conf_enum_t` value maps. There is nothing left to split — a C array cannot
  be cut across files without ugly macro re-assembly, and per-directive doc-blocks
  are the bulk.
- **`src/protocols/webdav/module.c`** — **618 logical table + 286 logical logic** (setters
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
exceed 500 (`client/lib/xrdc.h`, `src/core/types/config.h`).

### 3.2 `src/` C source > 650 logical LoC — the split list

Seams below are **derived from the measured function inventory** of each file
(Appendix B), not guessed. Per-file specs with proposed filenames and function
assignments are in §6.

| Logical | Raw | File | Tier | Seams (from function inventory) |
|---|---|---|---|---|
| 1316 | 1734 | `src/stream/module.c` | 🔴→**exempt** | **95% (1251) is the 213-entry `ngx_command_t` directive table**; conf lifecycle already in `config/server_conf.c` + `stream/module_definition.c` → declarative, exempt (§2.6, §6.10) |
| 1033 | 1284 | `src/auth/gsi/gsi_core.c` | 🔴 | bucket/buffer codec · DH keygen/derive · cipher negotiation · RSA sign/verify · cert-request/response build (**shared** — also linked into client) |
| 986 | 1290 | `src/observability/dashboard/api.c` | 🔴 | name/format helpers · live-transfer model · snapshot assembly · ratelimit view · JSON send/dispatch *(worked example §6.1)* |
| 973 | 1452 | `src/protocols/s3/post_object.c` | 🔴 | multipart-form decode · POST-policy parse/verify · object write · response build *(worked example §6.2)* |
| 904 | 1153 | `src/protocols/webdav/module.c` | 🔴→🟡 | **618 table + 286 logic**; extract the `webdav_conf_*` setters + phase handlers + module ctx → residual table drops to ~618 (watch) (§6.11) |
| 894 | 1198 | `src/observability/dashboard/api_admin.c` | 🔴 | admin auth · write endpoints · proxy-pool admin |
| 811 | 1149 | `src/protocols/webdav/propfind.c` | 🔴 | request/XML parse · property gather (`propfind_entry` is 308 lines alone) · tree walk · response build *(worked example §6.3)* |
| 796 | 1186 | `src/protocols/s3/put.c` | 🟠 | body-mode/aio plumbing · finalize-result family (12 `s3_put_finalize_*`) · aws-chunked decode |
| 725 | 1104 | `src/auth/impersonate/broker.c` | 🟠 | peer/cap gate · `imp_do_op` dispatch (288 lines) · xattr filter · request loop *(worked example §6.5)* |
| 686 | 1123 | `src/net/manager/registry.c` | 🟠 | registry table · selection core · health-check state · locate/aggregate/snapshot *(worked example §6.4)* |
| 662 | 900 | `src/protocols/webdav/tpc_curl.c` | 🟠 | curl handle setup · header build · transfer loop · result map |

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
| 518 | 790 | `src/core/types/config.h` | Module config structs. **Mixed-ABI** → full rebuild. Split by plane (stream conf · http/webdav conf · s3 conf · shared tunables) only if it grows; currently borderline. |

> **Dropped from the old must-split list:** `src/protocols/webdav/webdav.h` (372 logical /
> 827 raw) and `src/observability/metrics/metrics.h` (390 logical / 639 raw) are **not** offenders
> by the logical metric — they are mostly declaration doc-blocks. Earlier revisions
> flagged them on raw count; §2.5 explains why that was wrong. Leave them.

### 3.5 Shell > 500 raw LoC

(Shell has no doc-block convention, so raw ≈ logical; measured on raw.)

| Raw | File | Note |
|---|---|---|
| 1868→206 | `tests/manage_test_servers.sh` | ✅ **DONE 2026-06-27.** 37 functions extracted (heredoc-aware) into six sourced concern libs under `tests/lib/`: `util.sh` (115), `pki.sh` (150), `nginx.sh` (396), `refxrootd.sh` (390), `xrdhttp.sh` (200), `dedicated.sh` (426) — all <800. The main keeps the global-config block + `source` lines + the dispatch `case` (**206 raw / 146 logical**). Sourced libs share the parent's globals; function-definition order is irrelevant. Verified end-to-end: `force-stop`→`start-all` (rc=0, core ports up)→73 tests pass→`stop` (rc=0, ports clear). |
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
  per line, generated by `lint_loc.sh --baseline`. **Implemented 2026-06-26 (M0
  done):** the initial baseline (after the `stream/module.c` exemption, §6.10) was
  **44 files** over 800 logical — 15 C + 28 Python + 1 shell. **Burned down to 33**
  as the P0/P1/P3 splits landed: 14 of 15 C monoliths split (build + tests green),
  leaving only **2 C entries** — `client/apps/xrootdfs.c` (FUSE, deferred) and
  `client/lib/vfs_s3.c` (drifted in post-snapshot, not yet specced). The remaining
  31 are the Python (P4) + shell tracks. The ratchet only ever shrinks it.
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
   siblings (`src/fs/cache/{fetch,evict,slice}.c` is the model).
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
`src/observability/dashboard/api.c` (§6.1). **Before:** one file, the function `static`:

```c
/* src/observability/dashboard/api.c (before) */
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
/* src/observability/dashboard/dashboard_api_internal.h (new) */
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
/* src/observability/dashboard/api_transfers.c (new) — note: NO 'static' now */
#include "dashboard_api_internal.h"
json_t *
dashboard_build_transfer_object(ngx_pool_t *pool, const xrootd_xfer_t *x,
                                int64_t now_ms, ngx_uint_t redact)
{
    /* …the same 134 lines, unchanged… */
}
```

Then: add `$ngx_addon_dir/src/observability/dashboard/api_transfers.c` to the root `config`
`NGX_ADDON_SRCS`; add a row to `src/observability/dashboard/README.md`; `./configure && make`;
`tests/test_dashboard.py` green; `git grep -n 'goto' src/observability/dashboard/api_transfers.c`
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

> **The exhaustive mechanics live in [Appendix F](#appendix-f--exhaustive-per-file-split-mechanics):** for every file below, a per-function
> move table (function → current line range → target file) and a literal,
> de-`static`'d `*_internal.h`. The subsections here give the *shape and rationale*;
> Appendix F gives the *copy-pasteable* line-by-line plan.

### 6.1 `src/observability/dashboard/api.c` (986 logical / 1290 raw → ~4 files) — worked example

Four near-independent concerns sharing only small static helpers:

| New file | Functions moved | ~Raw LoC |
|---|---|---|
| `api.c` (keep) | name/format maps (`dashboard_{direction,proto,state,tpc_*}_name`, `dashboard_avg_bps`, `dashboard_session_hash`), `dashboard_send_json`, `dashboard_endpoint_is_anon_allowed`, `ngx_http_xrootd_dashboard_api_handler` (routing) | ~300 |
| `api_transfers.c` | `dashboard_build_transfer_object` (134), `dashboard_build_transfer_rows`, `dashboard_build_tpc_registry`, `dashboard_build_compat_transfers`, `dashboard_build_v1_transfers`, `dashboard_parse_detail_id`, `dashboard_build_v1_transfer_detail` | ~330 |
| `api_snapshot.c` | `dashboard_collect_totals`, `dashboard_collect_protocols`, `dashboard_build_{limits,totals,proto_summary,protocols,events}`, `dashboard_fill_{history,cache,cluster}`, `dashboard_new_v1_root`, `dashboard_build_v1_{snapshot,events,history,cluster,cache}` | ~480 |
| `api_ratelimit.c` | `dashboard_build_v1_ratelimit` (66) + `dashboard_build_v1_{not_found,truncated}` | ~120 |

Shared decls (the `summary` struct, helper prototypes) → new
`dashboard_api_internal.h`. Register three new `.c` in `config`; update
`src/observability/dashboard/README.md`. No behavior change → `tests/test_dashboard.py` stays
green. (`api_snapshot.c` at ~480 is near the line; if `fill_cache`'s 104 lines
push it over, peel `api_cache.c` out as a fifth file.)

### 6.2 `src/protocols/s3/post_object.c` (973 / 1452 → ~4 files)

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

### 6.3 `src/protocols/webdav/propfind.c` (811 / 1149 → ~3 files)

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

### 6.4 `src/net/manager/registry.c` (686 / 1123 → ~3 files)

Clean functional clusters by prefix:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `registry.c` (keep) | SHM zone/init (`xrootd_srv_shm_init_zone`, `srv_table`, `configure_registry`, `set_stale_after`), register/update/unregister | ~430 |
| `registry_select.c` | `srv_select_core` (107), `xrootd_srv_select{,_or_blacklisted}`, `srv_path_matches`, `srv_count_matching`, `xrootd_manager_tried_exhausted`, `blacklist`/`undrain` | ~430 |
| `registry_health.c` | `xrootd_srv_hc_{claim,pass,fail}`, `locate_all`, `unregister_path`, `aggregate_space`, `snapshot` | ~340 |

Shared decls already partly in `manager_internal.h` if present; otherwise add it.
Tests: the CMS/manager cluster suite.

### 6.5 `src/auth/impersonate/broker.c` (725 / 1104 → ~3 files) — security-critical

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
`src/core/config/server_conf.c`, and the `ngx_module_t` struct in
`src/stream/module_definition.c`. **No split.** Add the exemption comment and
record the rationale:

```c
/* loc-lint: exempt — single declarative ngx_command_t table; conf logic already
   in config/server_conf.c + stream/module_definition.c (Phase 38 §2.6) */
```

This removes it from the baseline. *(If the table is ever felt to be too big to
read, the right move is documentation/grouping comments within the array — which
it already has — not sharding the C array.)*

### 6.11 `src/protocols/webdav/module.c` (904 / 1153 → ~3 files, residual table → watch)

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

### 6.12 `src/observability/dashboard/api_admin.c` (894 / 1198 → ~4 files)

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

### 6.13 `src/protocols/s3/put.c` (796 / 1186 → ~4 files)

Dominated by a 12-function `s3_put_finalize_*` result family:

| New file | Functions | ~Raw LoC |
|---|---|---|
| `put.c` (keep) | `s3_put_body_handler`, `s3_put_body_inner`, `s3_put_body_mode`, `s3_put_streaming` (89), dashboard helpers | ~310 |
| `put_finalize.c` | the 12 `s3_put_finalize_*` + `s3_put_checksum_failed` + `s3_commit_put`/`conflict` | ~330 |
| `put_chunk.c` | `s3_chunk_{finalize,decode_failed,aio_thread,aio_done}`, `s3_build_chunk_verify` (aws-chunked) | ~210 |
| `put_aio.c` | `s3_put_aio_thread`/`done`, `s3_put_vfs_ctx`, `s3_thread_pool` | ~190 |

Shared decls → `s3_put_internal.h`. **Invariant 6** (SigV4 ≠ WLCG) — no auth logic
moves. Tests: S3 conformance batch + `tests/test_s3_write_concurrency.py`.

### 6.14 `src/protocols/webdav/tpc_curl.c` (662 / 900 → ~3 files)

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

### 7.0 Gate 0 — tooling first (do before any split) — ✅ DONE 2026-06-26

Landed `tests/lint_loc.sh` (§4.1) + `tests/loc_baseline.txt` (44 entries) +
`.github/workflows/loc.yml` (§4.3) + the `stream/module.c` exemption (§6.10). This
*locks the ratchet* so the tail stops growing while we burn it down, and gives an
objective "done" signal. Verified: `--strict` passes on the clean tree, catches a
new >800 file and a baselined-file growth, and the module build still links.
**No source split happens before Gate 0.** The remaining P0–P4 splits are the
burn-down.

### 7.1 P0 — `src/` C monoliths > 800 logical (7 files)

The §3.2 🔴 rows, minus the two `module.c` directive-table special cases (§2.6).
That leaves **5 genuine logic monoliths** + 1 logic-extraction, one focused PR
each, ordered **audit value first**, then size:

1. `gsi/gsi_core.c` (1033) — **shared**. ✅ **DONE** → `gsi_core.c` (402, cert/
   sigver) + `gsi_buf.c` + `gsi_dh.c` + `gsi_cipher.c` + `gsi_rsa.c`
   (+ `gsi_core_internal.h`). Registered in **both** `config` *and*
   `shared/xrdproto/Makefile`; shared ngx-free build green (33 objects) + 115 GSI
   tests pass. The DH-params PEM static data is relocated as `extern`.
2. `s3/post_object.c` (973) — §6.2. ✅ **DONE** → `post_object.c` +
   `post_form.c` + `post_policy.c` + `post_response.c` (+ `s3_post_internal.h`).
3. `webdav/propfind.c` (811) — §6.3. ✅ **DONE** → `propfind.c` + `propfind_props.c`
   + `propfind_walk.c` (+ `propfind_internal.h`).
4. `dashboard/api.c` (986) — §6.1. ✅ **DONE** → `api.c` + `api_transfers.c` +
   `api_snapshot.c` + `api_ratelimit.c` (+ `dashboard_api_internal.h`).
5. `dashboard/api_admin.c` (894) — §6.12. ✅ **DONE** → `api_admin.c` +
   `api_admin_cluster.c` + `api_admin_proxy.c` + `api_admin_config.c`
   (+ `dashboard_api_admin_internal.h`).
6. `webdav/module.c` (904) — logic-extract (§6.11). ✅ **DONE** → `module.c` (637,
   the `ngx_command_t` table + module struct/ctx — watch tier, as predicted) +
   `module_directives.c` (the `webdav_conf_*` setters) + `module_init.c` (phase
   handlers). `nginx -t` passes (module loads + directives parse).

**P0 status: 6 of 6 done** — all verified (build + tests; gsi shared ngx-free
build green; webdav `nginx -t` ok). The carver gained file-scope-static-data
`extern` relocation, non-static-global preservation, and trailing-content→kept
handling along the way. Remaining P0: none.
(directive table).

Special cases handled separately: **`stream/module.c` is exempted** (§6.10 — a
one-line `loc-lint` comment, done in M0). The privileged `impersonate/broker.c`
(725 logical, 🟠) leads **P1**, not P0, but is the single highest-audit-value split
in the whole phase (§6.5).

### 7.2 P1 — `src/` C 651–800 logical (4 files)

The §3.2 🟠 rows (the 4 files 651–800 logical), audit-value first:
`impersonate/broker.c` (privileged — do it first; §6.5), then `s3/put.c`,
`manager/registry.c`, `webdav/tpc_curl.c`.

**P1 status: 4 of 4 done** (all verified — build + 34 manager/cms/impersonate tests):
- `s3/put.c` ✅ **DONE** → `put.c` + `put_finalize.c` + `put_chunk.c` + `put_aio.c`.
- `webdav/tpc_curl.c` ✅ **DONE** → `tpc_curl.c` + `tpc_curl_setup.c` + `tpc_curl_pmark.c`.
- `impersonate/broker.c` ✅ **DONE** → `broker.c` (trust gate + loop + `imp_base_*`
  state) + `broker_creds.c` (privilege transitions) + `broker_ops.c` (`imp_do_op`).
  The shared mutable static state is relocated as `extern` (decl in
  `broker_internal.h`, def in the kept `broker.c`) — the carver now does this.
- `manager/registry.c` ✅ **DONE** → `registry.c` + `registry_select.c` +
  `registry_health.c`; the SHM-state globals handled the same `extern` way.

### 7.3 P2 — the two real headers + the shell monster

- `client/lib/xrdc.h` (579) — split by concern; **full rebuild** (mixed-ABI, every
  `client/` TU includes it). Riskiest single item in the client track.
- `src/core/types/config.h` (518) — borderline; split by plane only if it grows.
  **Full rebuild** (mixed-ABI).
- `tests/manage_test_servers.sh` (1868) — extract sourced libs; the single
  highest-LoC shell file and central to every test run, so do it carefully with a
  smoke run of `start-all`/`restart`.
- *(Note: `src/protocols/webdav/webdav.h`/`metrics.h` are NOT split — §3.4.)*

### 7.4 P3 — `client/` native-client track (independent, parallelizable)

The §3.3 list (11 C files > 650, 8 monoliths). Separate build (`client/Makefile`,
no nginx ABI), so it runs **concurrently with P0–P2**.

**P3 status: 5 of 6 lib files + 5 of 5 CLI apps done** (build clean; native
xrdcp/xrdfs/xrddiag + FUSE verified):
- **Library** — `aio.c`, `http.c`, `ops_file.c`, `zip.c`, and **`copy.c`** ✅
  (7-way: pump/local/remote/recursive/zip/block). The `copy.c` **weak-symbol
  anchors** (`s_vfs_*_anchor`, `__attribute__((used))`) are kept **in `copy.o`**
  by hand — the carver must not relocate them.
- **CLI apps** — `xrdcp`, `xrd`, `xrdfs`, `xrddiag`, and **`xrootdfs`** ✅. Each gets
  a **per-binary link rule** in `client/Makefile` linking the extracted `apps/*.o`
  siblings. `xrootdfs` (FUSE) additionally needed the `FUSE3_CFLAGS` compile rule
  for its siblings, and a **hand consolidation** of its heavy shared state — 6
  op-context structs + 26 `g_*` globals moved to `xrootdfs_internal.h` (the carver
  can't auto-relocate that interdependent a preamble). Verified behavior-identical
  by A/B test: split and unsplit both give 12 pass / 4 pre-existing FUSE-write
  env-fails. Kept files all <800 (copy 218, xrdfs 244, xrddiag 508, xrootdfs 318).
- `client/lib/README.md` created.

**Remaining client work:** `client/lib/webfile.c` (🟡 watch) and `client/lib/xrdc.h`
(§7.3, mixed-ABI header); `client/lib/vfs_s3.c` (drifted in post-snapshot).

### 7.5 P4 — Python track (independent, parallelizable) — **attempted; needs per-file run-verify**

Split `tests/*.py` > 650 along test-class/concern lines, sharing the module
header/helpers/fixtures. **Attempted 2026-06-27, then reverted** — lessons that
shape how this track must be done:

- **A mechanical class-split + `from _helpers import *` works for some files but
  silently breaks others.** Two real gotchas: (1) `import *` skips `_`-prefixed
  helpers and imported names unless the helper module ends with
  `__all__ = [n for n in dir() if not n.startswith('__')]`; (2) even with that,
  files with **module-level coupling** (a `pytestmark`/parametrize or a
  module-scoped setup fixture the classes depend on) change behavior when classes
  move to a sibling module. `test_io_edge_cases` split fine (50 tests still pass);
  `test_webdav` collect-matched but **failed 100/120 at runtime** (the original
  passes 120 in-place — proven by A/B).
- **Therefore `--collect-only` count-match is necessary but NOT sufficient** —
  each split must be **run-verified** (same pass count before/after, in-place),
  which needs the test harness. A broken test split is worse than a long file.
- The of-the-shelf 28 baselined files are heterogeneous: **~8 are clean
  class-based** (auto-splittable with the `__all__` helper + a run-verify gate),
  **~14 are function/parametrize-based with 0–1 top-level classes** (need a
  by-function-group split, not by class), and a few are class-based but
  module-coupled (`test_webdav`, `test_privilege_escalation`) needing hand work.

**Status: 20 of 28 files split + run-verified, 2 exempted** (2026-06-27) — the
Python baseline is down from 28 to **6**.  Method: the `__all__`-export helper
pattern behind a **run-verify gate** (in-place pass count must match exactly
before/after, against a freshly-started harness with `TEST_SKIP_SERVER_SETUP=1`
for ~2 s/run); two tooling advances unlocked the bulk:

- An **AST-based** function-unit splitter (`pysplit_func.py`) replaced the
  line-based one — robust to top-level `class`, multi-line constructs and
  `@parametrize` data; this unlocked 8 of 9 `conf_*` files at once.
- A **relaxed gate** (keep iff `before == after`, *allowing* unchanged
  pre-existing failures rather than requiring 0) unlocked files like
  `test_new_opcodes` (3 reds) and `test_cross_protocol_shared_helpers` (12 reds) —
  the split provably preserves the exact red/green set.

**Done (20):** file_api, http_webdav_status_codes, io_edge_cases, a_robustness,
gsi_handshake, proxy_mode, new_opcodes, cross_protocol_shared_helpers (class) +
conf_errors, conf_client2, conf_framing, conf_rename, conf_sessions, conf_prepfattr,
conf_pgio, conf_fattr, conf_stattypes, evil_actor_v3, proxy_protocol_edges (function).

**Exempted (2, §4.4):** `test_webdav`, `test_evil_paths` — a single module-scoped
autouse `params=` fixture mutates module globals (`BASE_URL`, …) that every test
reads directly; `from helpers import *` imports a *copy*, so the fixture's
mutation never reaches a sibling module (proven: webdav 120→100). The
parametrize-fixture + globals + tests are one cohesive unit; splitting requires a
fixture rewrite.

**Remaining (6), genuinely hand-only:** `manager_mode`, `dropin_byte_for_byte`,
`cms_wire_pup_conformance` (module-coupling, different from the webdav pattern —
need per-file fixture/state untangling); `conf_sequences` (a test-ordering
dependency — split introduces 1 red); `privilege_escalation`, `userns/e2e_redteam`
(can only run under an in-namespace-root userns harness, unverifiable here; the
latter also has no top-level `def test_` — a per-attack-scenario package by hand).
The tooling (`pysplit.py`/`pysplit_func.py` + the run-verify gate) finishes these
as the documented separate effort.

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
| M0 | ✅ **DONE** — `tests/lint_loc.sh` + `stream/module.c` exemption + baseline (44: 15 C + 28 py + 1 sh) + `.github/workflows/loc.yml` ratchet | 0.5–1 day |
| M1 | P0/P1: **ALL 10 `src/` splits done** (api, api_admin, post_object, propfind, put, tpc_curl, broker, registry, gsi_core[shared], webdav/module → ~40 files; build + 164+34+115 GSI tests + nginx -t; shared ngx-free green). No `src/` C monoliths remain | ✅ done |
| M2 | P1: 4 `src/` C files (651–800) | ~3–4 days |
| M3 | P2: `client/lib/xrdc.h` ✅ + `manage_test_servers.sh` ✅ (1868→206, 6 sourced libs, verified) | done |
| M4 | P3: `client/` track — **5 of 6 lib + ALL 5 CLI apps done**, kept files <800 (copy 218, xrdfs 244, xrddiag 508, xrootdfs 318). build clean + native + FUSE A/B verified. Remaining: webfile (watch), vfs_s3, xrdc.h | parallel; mostly done |
| M5 | P4: Python track — **attempted, reverted** (collect-match ≠ run-safe; needs per-file run-verify on a stable harness). Tooling + lessons captured (§7.5) | parallel; deferred |

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
| `src/auth/gsi/gsi_core.c` | `xrootd_gsi_build_cert_response` | 210 | cert-response file (P0) |
| `src/observability/dashboard/api.c` | `dashboard_build_transfer_object` | 134 | `api_transfers.c` (§6.1) |
| `src/protocols/s3/post_object.c` | `s3_post_parse_form` | 156 | `post_form.c` (§6.2) |
| `src/protocols/webdav/propfind.c` | `propfind_entry` | 308 | `propfind_props.c` (§6.3) |
| `src/observability/dashboard/api_admin.c` | `xrootd_admin_dispatch` | 93 | kept `api_admin.c` (§6.12) |
| `src/net/manager/registry.c` | `srv_select_core` | 107 | `registry_select.c` (§6.4) |
| `src/auth/impersonate/broker.c` | `imp_do_op` | 288 | `broker_ops.c` (§6.5) |
| `src/protocols/s3/put.c` | `s3_put_streaming` | 89 | kept `put.c` (§6.13) |
| `src/protocols/webdav/tpc_curl.c` | `webdav_tpc_run_curl_core` | 178 | kept `tpc_curl.c` (§6.14) |
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

## Appendix F — Exhaustive per-file split mechanics

*(The §6.1–§6.21 specs, expanded to per-function move tables + literal headers.)*

For each splittable offender: the **move table** (every function → its current line
range → target file) and the literal **`*_internal.h`** (de-`static`'d prototypes
for the boundary-crossing functions, grouped by target file). This is the
copy-pasteable mechanical layer under the §6 specs.

**How to read it / caveats (important):**

- **Ranges are a contiguous partition.** Each function's range runs from its
  signature start to the line before the next *detected* function (Appendix B
  method). Two consequences to confirm before cutting:
  1. A **mid-file data table** (e.g. a `static ngx_command_t[]`) is not a function,
     so it is absorbed into the *preceding* function's range. This happens once
     here — **F.9** `webdav_conf_open_file_cache` truly ends at **L287**; the
     L298–1046 block is the directive **table** (data) that **stays in `module.c`**.
  2. A large range may hide a helper the heuristic merged; re-run the extractor (or
     read) before cutting. The late `xrddiag` ranges (F.20) are the main example.
- **Prototypes are generated** from the real signatures (multi-line arg lists are
  joined to one line). Drop the `static`, keep the type — that is exactly what the
  `*_internal.h` needs. Verify the prototype compiles against the moved `.c`.
- **Duplicate names** (e.g. `s3_put_*` in F.7, `cksum_verify` in F.10) are a
  forward declaration + the definition — collapse to one prototype.
- The target-file column reflects the §6 seam choices; a function not matching any
  seam stays in the **kept** file (no prototype needed).

Regenerate any block with the Appendix A/B commands — the data drifts as code
changes; treat these tables as a 2026-06-26 snapshot, not a contract.

#### F.1 `src/observability/dashboard/api.c` (986/1290 → 4 files; §6.1)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `dashboard_direction_name` | L55–64 | `api.c` |
| `dashboard_proto_name` | L65–74 | `api.c` |
| `dashboard_state_name` | L75–97 | `api.c` |
| `dashboard_tpc_protocol_name` | L98–107 | `api.c` |
| `dashboard_tpc_direction_name` | L108–117 | `api.c` |
| `dashboard_tpc_state_name` | L118–129 | `api.c` |
| `dashboard_event_class_name` | L130–149 | `api.c` |
| `dashboard_session_hash` | L150–172 | `api.c` |
| `dashboard_collect_totals` | L173–222 | `api_snapshot.c` |
| `dashboard_avg_bps` | L223–239 | `api.c` |
| `dashboard_collect_protocols` | L240–288 | `api_snapshot.c` |
| `dashboard_build_limits` | L289–303 | `api_snapshot.c` |
| `dashboard_build_totals` | L304–334 | `api_snapshot.c` |
| `dashboard_build_transfer_object` | L335–468 | `api_transfers.c` |
| `dashboard_build_transfer_rows` | L469–515 | `api_transfers.c` |
| `dashboard_build_tpc_registry` | L516–547 | `api_transfers.c` |
| `dashboard_build_proto_summary` | L548–563 | `api_snapshot.c` |
| `dashboard_build_protocols` | L564–590 | `api_snapshot.c` |
| `dashboard_build_events` | L591–625 | `api_snapshot.c` |
| `dashboard_fill_history` | L626–669 | `api_snapshot.c` |
| `dashboard_fill_cache` | L670–773 | `api_snapshot.c` |
| `dashboard_fill_cluster` | L774–821 | `api_snapshot.c` |
| `dashboard_new_v1_root` | L822–833 | `api_snapshot.c` |
| `dashboard_build_compat_transfers` | L834–847 | `api_transfers.c` |
| `dashboard_build_v1_transfers` | L848–867 | `api_transfers.c` |
| `dashboard_parse_detail_id` | L868–892 | `api_transfers.c` |
| `dashboard_build_v1_transfer_detail` | L893–935 | `api_transfers.c` |
| `dashboard_build_v1_snapshot` | L936–976 | `api_snapshot.c` |
| `dashboard_build_v1_events` | L977–988 | `api_snapshot.c` |
| `dashboard_build_v1_history` | L989–1000 | `api_snapshot.c` |
| `dashboard_build_v1_cluster` | L1001–1012 | `api_snapshot.c` |
| `dashboard_build_v1_cache` | L1013–1024 | `api_snapshot.c` |
| `dashboard_build_v1_ratelimit` | L1025–1090 | `api_ratelimit.c` |
| `dashboard_build_v1_not_found` | L1091–1101 | `api_ratelimit.c` |
| `dashboard_build_v1_truncated` | L1102–1126 | `api_ratelimit.c` |
| `dashboard_endpoint_is_anon_allowed` | L1127–1146 | `api.c` |
| `ngx_http_xrootd_dashboard_api_handler` | L1147–1229 | `api.c` |

**`dashboard_api_internal.h`**:

```c
#ifndef XROOTD_DASHBOARD_API_INTERNAL_H
#define XROOTD_DASHBOARD_API_INTERNAL_H
/* api_snapshot.c */
void dashboard_collect_totals(xrootd_dashboard_totals_t *totals);
void dashboard_collect_protocols(xrootd_dashboard_protocols_t *out, int64_t now_ms);
json_t * dashboard_build_limits(const ngx_http_xrootd_dashboard_loc_conf_t *conf);
json_t * dashboard_build_totals(const xrootd_dashboard_totals_t *totals);
json_t * dashboard_build_proto_summary(const xrootd_dashboard_proto_summary_t *s, uint64_t bytes_rx, uint64_t bytes_tx);
json_t * dashboard_build_protocols(int64_t now_ms, const xrootd_dashboard_totals_t *totals);
json_t * dashboard_build_events(ngx_pool_t *pool, ngx_uint_t redact);
void dashboard_fill_history(json_t *target, ngx_pool_t *pool);
void dashboard_fill_cache(json_t *target, ngx_uint_t redact);
void dashboard_fill_cluster(json_t *target, ngx_pool_t *pool, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_new_v1_root(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf);
json_t * dashboard_build_v1_snapshot(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_dashboard_totals_t *totals, ngx_uint_t redact);
json_t * dashboard_build_v1_events(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_history(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_cluster(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_cache(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
/* api_transfers.c */
json_t * dashboard_build_transfer_object( const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_transfer_slot_t *slot, int64_t now_ms, ngx_uint_t v1_fields, ngx_uint_t detail_fields, ngx_uint_t redact);
json_t * dashboard_build_transfer_rows(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields, ngx_uint_t redact);
json_t * dashboard_build_tpc_registry(ngx_pool_t *pool, ngx_uint_t redact);
json_t * dashboard_build_compat_transfers(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_dashboard_totals_t *totals, ngx_uint_t redact);
json_t * dashboard_build_v1_transfers(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, const xrootd_dashboard_totals_t *totals, ngx_uint_t redact);
ngx_int_t dashboard_parse_detail_id(ngx_http_request_t *r, uint32_t *id);
json_t * dashboard_build_v1_transfer_detail(ngx_http_request_t *r, int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_int_t *status);
/* api_ratelimit.c */
json_t * dashboard_build_v1_ratelimit(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_not_found(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t redact);
json_t * dashboard_build_v1_truncated(int64_t now_ms, const ngx_http_xrootd_dashboard_loc_conf_t *conf);
#endif
```

#### F.2 `src/protocols/s3/post_object.c` (973/1452 → 4 files; §6.2)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `s3_post_error` | L61–76 | `post_object.c` |
| `s3_post_copy_text` | L77–106 | `post_object.c` |
| `s3_post_field_value` | L107–143 | `post_form.c` |
| `s3_post_store_field` | L144–215 | `post_form.c` |
| `s3_post_boundary` | L216–296 | `post_form.c` |
| `s3_memmem` | L297–327 | `post_object.c` |
| `s3_post_extract_param` | L328–390 | `post_form.c` |
| `s3_post_basename` | L391–417 | `post_object.c` |
| `s3_post_expand_filename` | L418–488 | `post_form.c` |
| `s3_post_parse_form` | L489–644 | `post_form.c` |
| `s3_post_days_from_civil` | L645–669 | `post_policy.c` |
| `s3_post_parse_iso8601` | L670–696 | `post_policy.c` |
| `s3_post_check_field_eq` | L697–719 | `post_policy.c` |
| `s3_post_policy_condition` | L720–827 | `post_policy.c` |
| `s3_post_validate_policy_json` | L828–892 | `post_policy.c` |
| `s3_post_parse_credential` | L893–955 | `post_policy.c` |
| `s3_post_verify_policy` | L956–1072 | `post_policy.c` |
| `s3_post_write_object` | L1073–1166 | `post_object.c` |
| `s3_post_send_empty` | L1167–1181 | `post_response.c` |
| `s3_post_send_created` | L1182–1251 | `post_response.c` |
| `s3_post_send_success` | L1252–1312 | `post_response.c` |
| `s3_post_object_body_handler` | L1313–1323 | `post_object.c` |
| `s3_post_object_body_handler_inner` | L1324–1428 | `post_object.c` |

**`s3_post_internal.h`**:

```c
#ifndef XROOTD_S3_POST_INTERNAL_H
#define XROOTD_S3_POST_INTERNAL_H
/* post_form.c */
const char * s3_post_field_value(const s3_post_form_t *form, const char *name);
ngx_int_t s3_post_store_field(s3_post_form_t *form, const char *name, const u_char *data, size_t len);
ngx_int_t s3_post_boundary(ngx_http_request_t *r, char *boundary, size_t boundary_sz);
ngx_int_t s3_post_extract_param(const char *line, const char *name, char *out, size_t outsz);
ngx_int_t s3_post_expand_filename(ngx_http_request_t *r, s3_post_form_t *form);
ngx_int_t s3_post_parse_form(ngx_http_request_t *r, u_char *body, size_t body_len, const char *boundary, s3_post_form_t *form);
/* post_policy.c */
int64_t s3_post_days_from_civil(int y, unsigned m, unsigned d);
ngx_int_t s3_post_parse_iso8601(const char *s, time_t *out);
ngx_int_t s3_post_check_field_eq(const char *actual, const char *expected);
ngx_int_t s3_post_policy_condition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, json_t *cond);
ngx_int_t s3_post_validate_policy_json(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, u_char *policy_json, size_t policy_len);
ngx_int_t s3_post_parse_credential(const char *credential, char *date, size_t date_sz, char *region, size_t region_sz, const char **akid);
ngx_int_t s3_post_verify_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form);
/* post_response.c */
ngx_int_t s3_post_send_empty(ngx_http_request_t *r, ngx_uint_t status);
ngx_int_t s3_post_send_created(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, const char *etag);
ngx_int_t s3_post_send_success(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form, const char *etag);
#endif
```

#### F.3 `src/protocols/webdav/propfind.c` (811/1149 → 3 files; §6.3)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `propfind_name_to_bit` | L101–140 | `propfind.c` |
| `propfind_assemble_body` | L141–164 | `propfind.c` |
| `propfind_parse_request` | L165–312 | `propfind.c` |
| `propfind_append_acl_properties` | L313–447 | `propfind_props.c` |
| `propfind_entry` | L448–755 | `propfind_props.c` |
| `propfind_parse_depth` | L756–781 | `propfind.c` |
| `propfind_walk` | L782–910 | `propfind_walk.c` |
| `propfind_do` | L911–1125 | `propfind_walk.c` |
| `propfind_body_handler` | L1126–1144 | `propfind.c` |
| `webdav_handle_propfind` | L1145–1149 | `propfind.c` |

**`propfind_internal.h`**:

```c
#ifndef XROOTD_PROPFIND_INTERNAL_H
#define XROOTD_PROPFIND_INTERNAL_H
/* propfind_props.c */
ngx_int_t propfind_append_acl_properties(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail, unsigned mask);
ngx_int_t propfind_entry(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail, const char *href, const char *path, struct stat *sb, const propfind_req_t *req);
/* propfind_walk.c */
ngx_int_t propfind_walk(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail, const char *dir_path, const char *base_href, ngx_uint_t *entry_count, ngx_uint_t max_entries, const propfind_req_t *req);
ngx_int_t propfind_do(ngx_http_request_t *r);
#endif
```

#### F.4 `src/observability/dashboard/api_admin.c` (894/1198 → 4 files; §6.12)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `admin_send_ok` | L32–43 | `api_admin.c` |
| `admin_send_error` | L44–64 | `api_admin.c` |
| `admin_validate_hostname` | L65–90 | `api_admin.c` |
| `admin_validate_paths` | L91–136 | `api_admin.c` |
| `xrootd_admin_check_auth` | L137–183 | `api_admin.c` |
| `admin_audit` | L184–217 | `api_admin.c` |
| `xrootd_admin_body_callback` | L218–285 | `api_admin.c` |
| `xrootd_admin_read_body` | L286–316 | `api_admin.c` |
| `admin_parse_server_uri` | L317–404 | `api_admin_cluster.c` |
| `admin_cluster_register` | L405–435 | `api_admin_cluster.c` |
| `admin_cluster_drain` | L436–460 | `api_admin_cluster.c` |
| `admin_cluster_delete` | L461–481 | `api_admin_cluster.c` |
| `admin_cluster_undrain` | L482–513 | `api_admin_cluster.c` |
| `admin_validate_url` | L514–550 | `api_admin.c` |
| `admin_parse_proxy_uri` | L551–596 | `api_admin_proxy.c` |
| `admin_proxy_backend_json` | L597–629 | `api_admin_proxy.c` |
| `admin_url_host_allowed` | L630–668 | `api_admin_proxy.c` |
| `admin_proxy_add` | L669–722 | `api_admin_proxy.c` |
| `admin_proxy_list` | L723–756 | `api_admin_proxy.c` |
| `admin_proxy_one` | L757–819 | `api_admin_proxy.c` |
| `admin_uri_eq` | L820–828 | `api_admin.c` |
| `admin_uri_has_action` | L829–849 | `api_admin.c` |
| `admin_io_uring_set` | L850–880 | `api_admin_config.c` |
| `admin_io_uring_get` | L881–894 | `api_admin_config.c` |
| `xrootd_admin_dispatch` | L895–987 | `api_admin.c` |
| `xrootd_admin_set_allow` | L988–1036 | `api_admin_config.c` |
| `xrootd_admin_set_secret` | L1037–1113 | `api_admin_config.c` |
| `xrootd_admin_set_proxy_allow` | L1114–1140 | `api_admin_proxy.c` |

**`dashboard_api_internal.h`**:

```c
#ifndef XROOTD_DASHBOARD_API_INTERNAL_H
#define XROOTD_DASHBOARD_API_INTERNAL_H
/* api_admin_cluster.c */
ngx_int_t admin_parse_server_uri(ngx_http_request_t *r, char *host_out, size_t host_size, uint16_t *port_out, char *action_out, size_t action_size);
ngx_int_t admin_cluster_register(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_cluster_drain(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_cluster_delete(ngx_http_request_t *r);
ngx_int_t admin_cluster_undrain(ngx_http_request_t *r);
/* api_admin_proxy.c */
ngx_int_t admin_parse_proxy_uri(ngx_http_request_t *r, uint32_t *id_out, char *action_out, size_t action_size);
json_t * admin_proxy_backend_json(const xrootd_proxy_be_snapshot_t *e);
int admin_url_host_allowed(ngx_http_xrootd_dashboard_loc_conf_t *conf, const char *url);
ngx_int_t admin_proxy_add(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_proxy_list(ngx_http_request_t *r);
ngx_int_t admin_proxy_one(ngx_http_request_t *r, const char *action, uint32_t id);
char * xrootd_admin_set_proxy_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* api_admin_config.c */
ngx_int_t admin_io_uring_set(ngx_http_request_t *r, json_t *body);
ngx_int_t admin_io_uring_get(ngx_http_request_t *r);
char * xrootd_admin_set_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * xrootd_admin_set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif
```

#### F.5 `src/net/manager/registry.c` (686/1123 → 3 files; §6.4)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `xrootd_srv_set_stale_after` | L53–58 | `registry.c` |
| `srv_table` | L59–90 | `registry.c` |
| `xrootd_srv_shm_init_zone` | L91–130 | `registry.c` |
| `xrootd_srv_configure_registry` | L131–157 | `registry.c` |
| `srv_path_matches` | L158–220 | `registry_select.c` |
| `xrootd_srv_register` | L221–320 | `registry.c` |
| `xrootd_srv_update_load` | L321–364 | `registry.c` |
| `xrootd_srv_unregister` | L365–415 | `registry.c` |
| `srv_select_core` | L416–522 | `registry_select.c` |
| `xrootd_srv_select` | L523–533 | `registry_select.c` |
| `xrootd_srv_select_or_blacklisted` | L534–556 | `registry_select.c` |
| `xrootd_srv_count_matching` | L557–600 | `registry_select.c` |
| `xrootd_manager_tried_exhausted` | L601–667 | `registry_select.c` |
| `xrootd_srv_blacklist` | L668–702 | `registry_select.c` |
| `xrootd_srv_undrain` | L703–737 | `registry_select.c` |
| `xrootd_srv_hc_claim` | L738–792 | `registry_health.c` |
| `xrootd_srv_hc_pass` | L793–827 | `registry_health.c` |
| `xrootd_srv_hc_fail` | L828–885 | `registry_health.c` |
| `xrootd_srv_locate_all` | L886–961 | `registry_health.c` |
| `xrootd_srv_unregister_path` | L962–1036 | `registry_health.c` |
| `xrootd_srv_aggregate_space` | L1037–1076 | `registry_health.c` |
| `xrootd_srv_snapshot` | L1077–1123 | `registry_health.c` |

**`manager_internal.h`**:

```c
#ifndef XROOTD_MANAGER_INTERNAL_H
#define XROOTD_MANAGER_INTERNAL_H
/* registry_select.c */
int srv_path_matches(const char *paths, const char *path);
int srv_select_core(const char *path, int for_write, int allow_blacklisted, char *host_out, size_t host_size, uint16_t *port_out);
int xrootd_srv_select(const char *path, int for_write, char *host_out, size_t host_size, uint16_t *port_out);
int xrootd_srv_select_or_blacklisted(const char *path, int for_write, char *host_out, size_t host_size, uint16_t *port_out);
int xrootd_srv_count_matching(const char *path);
int xrootd_manager_tried_exhausted(const u_char *payload, size_t payload_len, const char *clean_path);
void xrootd_srv_blacklist(const char *host, uint16_t port, ngx_msec_t duration_ms);
int xrootd_srv_undrain(const char *host, uint16_t port);
/* registry_health.c */
int xrootd_srv_hc_claim(char *host_out, size_t host_size, uint16_t *port_out, ngx_msec_t interval_ms, ngx_msec_t *next_due_ms);
void xrootd_srv_hc_pass(const char *host, uint16_t port);
int xrootd_srv_hc_fail(const char *host, uint16_t port, uint32_t threshold, ngx_msec_t blacklist_ms);
int xrootd_srv_locate_all(const char *path, int for_write, char *buf, size_t bufsz);
void xrootd_srv_unregister_path(const char *host, uint16_t port, const char *path);
void xrootd_srv_aggregate_space(uint32_t *total_free_mb, uint32_t *avg_util_pct);
ngx_uint_t xrootd_srv_snapshot(xrootd_srv_snapshot_entry_t *out, ngx_uint_t max_entries, ngx_msec_t now);
#endif
```

#### F.6 `src/auth/impersonate/broker.c` (725/1104 → 3 files; §6.5)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `imp_peer_allowed` | L66–104 | `broker.c` |
| `imp_capset_setuid_setgid` | L105–137 | `broker_creds.c` |
| `imp_drop_to_service_user` | L138–214 | `broker_creds.c` |
| `xrootd_imp_broker_drop_caps` | L215–282 | `broker_creds.c` |
| `imp_become` | L283–330 | `broker_creds.c` |
| `imp_restore` | L331–343 | `broker_creds.c` |
| `imp_rel` | L344–353 | `broker_creds.c` |
| `imp_openat2` | L354–383 | `broker_ops.c` |
| `imp_open_parent` | L384–414 | `broker_ops.c` |
| `imp_fill_stat` | L415–445 | `broker_ops.c` |
| `imp_xattr_open` | L446–458 | `broker_ops.c` |
| `imp_xattr_name_ok` | L459–473 | `broker_ops.c` |
| `imp_xattr_filter_user` | L474–510 | `broker_ops.c` |
| `imp_do_rename` | L511–534 | `broker_ops.c` |
| `imp_do_op` | L535–822 | `broker_ops.c` |
| `imp_read_full` | L823–844 | `broker.c` |
| `imp_send_reply` | L845–891 | `broker.c` |
| `imp_serve_one` | L892–1014 | `broker.c` |
| `xrootd_imp_broker_run` | L1015–1104 | `broker.c` |

**`broker_internal.h`**:

```c
#ifndef XROOTD_BROKER_INTERNAL_H
#define XROOTD_BROKER_INTERNAL_H
/* broker_creds.c */
int imp_capset_setuid_setgid(int with_effective, ngx_log_t *log);
int imp_drop_to_service_user(ngx_log_t *log);
int xrootd_imp_broker_drop_caps(ngx_log_t *log);
int imp_become(const xrootd_idmap_creds_t *cr);
void imp_restore(void);
const char * imp_rel(const char *path);
/* broker_ops.c */
int imp_openat2(int rootfd, const char *rel, uint32_t flags, uint32_t mode);
int imp_open_parent(int rootfd, const char *rel, char *scratch, const char **base);
void imp_fill_stat(imp_stat_t *o, const struct stat *s);
int imp_xattr_open(int rootfd, const char *rel);
int imp_xattr_name_ok(const char *name);
size_t imp_xattr_filter_user(char *list, size_t len);
int imp_do_rename(int sfd, const char *sbase, int dfd, const char *dbase, int noreplace);
int imp_do_op(int rootfd, const imp_req_t *req, imp_rep_t *rep, int *out_fd, char *data_out, size_t data_max, const char *data_in, size_t data_in_len);
#endif
```

#### F.7 `src/protocols/s3/put.c` (796/1186 → 4 files; §6.13). Duplicate names = forward-decl + definition.

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `s3_put_checksum_failed` | L72–73 | `put_finalize.c` |
| `s3_put_streaming` | L74–76 | `put.c` |
| `s3_dashboard_put_op` | L77–91 | `put.c` |
| `s3_dashboard_identity` | L92–146 | `put.c` |
| `s3_thread_pool` | L147–165 | `put_aio.c` |
| `s3_put_finalize_client_error` | L166–176 | `put_finalize.c` |
| `s3_commit_put` | L177–194 | `put_finalize.c` |
| `s3_put_commit_conflict` | L195–207 | `put_finalize.c` |
| `s3_put_aio_thread` | L208–234 | `put_aio.c` |
| `s3_put_aio_done` | L235–309 | `put_aio.c` |
| `s3_put_body_mode` | L310–331 | `put.c` |
| `s3_put_finalize_error` | L332–357 | `put_finalize.c` |
| `s3_put_finalize_fs_error` | L358–404 | `put_finalize.c` |
| `s3_put_finalize_empty_ok` | L405–428 | `put_finalize.c` |
| `s3_put_finalize_ok` | L429–449 | `put_finalize.c` |
| `s3_put_finalize_bad_digest` | L450–465 | `put_finalize.c` |
| `s3_put_finalize_invalid_request` | L466–485 | `put_finalize.c` |
| `s3_put_finalize_codec_error` | L486–510 | `put_finalize.c` |
| `s3_put_checksum_failed` | L511–564 | `put_finalize.c` |
| `s3_put_finalize_client_error` | L565–581 | `put_finalize.c` |
| `s3_chunk_finalize` | L582–631 | `put_chunk.c` |
| `s3_chunk_decode_failed` | L632–669 | `put_chunk.c` |
| `s3_chunk_aio_thread` | L670–688 | `put_chunk.c` |
| `s3_build_chunk_verify` | L689–712 | `put_chunk.c` |
| `s3_chunk_aio_done` | L713–735 | `put_chunk.c` |
| `s3_put_streaming` | L736–824 | `put.c` |
| `s3_put_body_handler` | L825–835 | `put.c` |
| `s3_put_body_inner` | L836–1160 | `put.c` |

**`s3_put_internal.h`**:

```c
#ifndef XROOTD_S3_PUT_INTERNAL_H
#define XROOTD_S3_PUT_INTERNAL_H
/* put_finalize.c */
int s3_put_checksum_failed(ngx_http_request_t *r, const char *fs_path, const char *root_canon); static void s3_put_streaming(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, xrootd_staged_file_t *staged, const char *fs_path, ngx_uint_t body_mode); static const char * s3_dashboard_put_op(ngx_http_request_t *r);
void s3_put_finalize_client_error(ngx_http_request_t *r, int status, const char *code, const char *message); /* * s3_commit_put — W6b: commit the staged temp file to its final path, honouring * an exclusive (create-if-absent) PutObject. When the request carried * `If-None-Match: *` the commit uses renameat2(RENAME_NOREPLACE); otherwise the * plain rename. Returns NGX_OK; or NGX_ERROR with ngx_errno preserved (EEXIST * when an exclusive create lost the race — the caller maps that to 412). Runs * on the event loop (all three PUT commit sites do), so the request ctx is live. */ static ngx_int_t s3_commit_put(ngx_http_request_t *r, ngx_log_t *log, const char *root_canon, xrootd_staged_file_t *staged, const char *final_path);
ngx_int_t s3_commit_put(ngx_http_request_t *r, ngx_log_t *log, const char *root_canon, xrootd_staged_file_t *staged, const char *final_path);
int s3_put_commit_conflict(ngx_http_request_t *r);
void s3_put_finalize_error(ngx_http_request_t *r);
void s3_put_finalize_fs_error(ngx_http_request_t *r, int saved_errno);
void s3_put_finalize_empty_ok(ngx_http_request_t *r);
void s3_put_finalize_ok(ngx_http_request_t *r, size_t body_bytes, ngx_uint_t body_mode);
void s3_put_finalize_bad_digest(ngx_http_request_t *r);
void s3_put_finalize_invalid_request(ngx_http_request_t *r);
void s3_put_finalize_codec_error(ngx_http_request_t *r, ngx_int_t status);
int s3_put_checksum_failed(ngx_http_request_t *r, const char *fs_path, const char *root_canon);
void s3_put_finalize_client_error(ngx_http_request_t *r, int status, const char *code, const char *message);
/* put_aio.c */
ngx_thread_pool_t * s3_thread_pool(ngx_http_s3_loc_conf_t *cf);
void s3_put_aio_thread(void *data, ngx_log_t *log);
void s3_put_aio_done(ngx_event_t *ev);
/* put_chunk.c */
void s3_chunk_finalize(ngx_http_request_t *r, const char *root_canon, const char *fs_path, xrootd_staged_file_t *staged, const s3_chunk_trailer_t *trailer, uint64_t expected, ngx_uint_t body_mode);
void s3_chunk_decode_failed(ngx_http_request_t *r, const char *root_canon, xrootd_staged_file_t *staged, int http_status);
void s3_chunk_aio_thread(void *data, ngx_log_t *log);
void s3_build_chunk_verify(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, s3_chunk_verify_t *v);
void s3_chunk_aio_done(ngx_event_t *ev);
#endif
```

#### F.8 `src/protocols/webdav/tpc_curl.c` (662/900 → 3 files; §6.14)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `webdav_tpc_pmark_opensocket` | L54–74 | `tpc_curl_pmark.c` |
| `webdav_tpc_pmark_closesocket` | L75–92 | `tpc_curl_pmark.c` |
| `webdav_tpc_pmark_attach` | L93–149 | `tpc_curl_pmark.c` |
| `tpc_curl_secure` | L150–242 | `tpc_curl_setup.c` |
| `tpc_curl_apply_stall_bounds` | L243–256 | `tpc_curl_setup.c` |
| `tpc_curl_apply_conf` | L257–324 | `tpc_curl_setup.c` |
| `tpc_curl_head_size` | L325–374 | `tpc_curl_setup.c` |
| `ms_write_cb` | L375–406 | `tpc_curl_pmark.c` |
| `webdav_tpc_curl_progress` | L407–457 | `tpc_curl_pmark.c` |
| `webdav_tpc_curl_finish` | L458–491 | `tpc_curl_pmark.c` |
| `webdav_tpc_run_curl_core` | L492–669 | `tpc_curl.c` |
| `webdav_tpc_run_curl_pull` | L670–681 | `tpc_curl.c` |
| `webdav_tpc_run_curl_push` | L682–703 | `tpc_curl.c` |
| `webdav_tpc_run_curl_multi_finish` | L704–748 | `tpc_curl.c` |
| `webdav_tpc_run_curl_pull_multi` | L749–900 | `tpc_curl.c` |

**`tpc_internal.h`**:

```c
#ifndef XROOTD_TPC_INTERNAL_H
#define XROOTD_TPC_INTERNAL_H
/* tpc_curl_pmark.c */
curl_socket_t webdav_tpc_pmark_opensocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
int webdav_tpc_pmark_closesocket(void *clientp, curl_socket_t item);
void webdav_tpc_pmark_attach(CURL *curl, webdav_tpc_pmark_rec_t *rec, ngx_http_xrootd_webdav_loc_conf_t *conf, int is_push, const char *file_path, ngx_log_t *log);
size_t ms_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);
int webdav_tpc_curl_progress(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
ngx_int_t webdav_tpc_curl_finish(ngx_int_t rc, CURL *curl, struct curl_slist *hdrs, struct curl_slist *resolve, FILE *fp);
/* tpc_curl_setup.c */
int tpc_curl_secure(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf, const char *url, ngx_log_t *log, struct curl_slist **resolve_out);
void tpc_curl_apply_stall_bounds(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf);
int tpc_curl_apply_conf(CURL *curl, ngx_http_xrootd_webdav_loc_conf_t *conf, const char *url, ngx_array_t *transfer_headers, ngx_log_t *log, struct curl_slist **hdrs_out, struct curl_slist **resolve_out);
off_t tpc_curl_head_size(ngx_log_t *log, ngx_http_xrootd_webdav_loc_conf_t *conf, const char *url, ngx_array_t *transfer_headers);
#endif
```

#### F.9 `src/protocols/webdav/module.c` (904/1153 → table + 2 logic files; §6.11). Residual = pure table (~618, watch).

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `webdav_conf_add_cors_origin` | L45–78 | `module_directives.c` |
| `webdav_conf_dig_export` | L79–126 | `module_directives.c` |
| `webdav_conf_proxy_auth` | L127–164 | `module_directives.c` |
| `webdav_conf_proxy_upstream` | L165–207 | `module_directives.c` |
| `webdav_open_file_cache_arg` | L208–233 | `module_directives.c` |
| `webdav_conf_open_file_cache` | L234–**287** | `module_directives.c` |
| *(the `ngx_command_t` table)* | L298–1046 | `module.c` (**stays** — data, not a function; the L234–1055 the extractor shows for the row above is the partition artifact from §Appendix F caveat 1) |
| `xrootd_http_protocol_variable` | L1056–1090 | `module_init.c` |
| `xrootd_http_add_protocol_variables` | L1091–1107 | `module_init.c` |
| `ngx_http_xrootd_webdav_preconfiguration` | L1108–1113 | `module_init.c` |
| `ngx_http_xrootd_webdav_init_process` | L1114–1121 | `module_init.c` |
| `ngx_http_xrootd_webdav_exit_process` | L1122–1153 | `module_init.c` |

**`webdav_module_internal.h`**:

```c
#ifndef XROOTD_WEBDAV_MODULE_INTERNAL_H
#define XROOTD_WEBDAV_MODULE_INTERNAL_H
/* module_directives.c */
char * webdav_conf_add_cors_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * webdav_conf_dig_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * webdav_conf_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr);
char * webdav_conf_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr);
ngx_int_t webdav_open_file_cache_arg(ngx_str_t *arg, ngx_int_t *max, time_t *inactive, ngx_flag_t *off);
char * webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* module_init.c */
ngx_int_t xrootd_http_protocol_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t xrootd_http_add_protocol_variables(ngx_conf_t *cf);
ngx_int_t ngx_http_xrootd_webdav_preconfiguration(ngx_conf_t *cf);
ngx_int_t ngx_http_xrootd_webdav_init_process(ngx_cycle_t *cycle);
void ngx_http_xrootd_webdav_exit_process(ngx_cycle_t *cycle);
#endif
```

#### F.10 `client/lib/copy.c` (1886/2582 → 5 files; §6.6). Duplicate `cksum_verify` = fwd-decl + def.

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `cksum_verify` | L80–93 | `copy_remote.c` |
| `copy_signal_handler` | L94–100 | `copy.c` |
| `xrdc_copy_quit_requested` | L101–106 | `copy.c` |
| `xrdc_copy_install_signal_handlers` | L107–134 | `copy.c` |
| `make_temp_path` | L135–158 | `copy_local.c` |
| `open_download_temp` | L159–190 | `copy_local.c` |
| `atomic_dest_finish` | L191–206 | `copy_local.c` |
| `write_all` | L207–261 | `copy_pump.c` |
| `copy_stall_ms` | L262–298 | `copy.c` |
| `pump_remote_reopen` | L299–317 | `copy_pump.c` |
| `pump_src_remote` | L318–352 | `copy_pump.c` |
| `pump_sink_reopen` | L353–368 | `copy_pump.c` |
| `pump_sink_remote` | L369–403 | `copy_pump.c` |
| `pump_src_local` | L404–421 | `copy_pump.c` |
| `pump_sink_local` | L422–441 | `copy_pump.c` |
| `pump_src_local_vfs` | L442–449 | `copy_pump.c` |
| `pump_sink_local_vfs` | L450–465 | `copy_pump.c` |
| `transfer_pump` | L466–551 | `copy_pump.c` |
| `download_stream_body` | L552–628 | `copy.c` |
| `resilient_setup` | L629–666 | `copy.c` |
| `copy_download` | L667–794 | `copy_local.c` |
| `upload_stream_body` | L795–945 | `copy_local.c` |
| `copy_upload` | L946–1004 | `copy_local.c` |
| `r2r_teardown` | L1005–1037 | `copy_remote.c` |
| `r2r_stream_body` | L1038–1049 | `copy_remote.c` |
| `copy_remote_to_remote` | L1050–1100 | `copy_remote.c` |
| `cksum_verify` | L1101–1195 | `copy_remote.c` |
| `gen_tpc_key` | L1196–1239 | `copy_remote.c` |
| `tpc_teardown` | L1240–1259 | `copy_remote.c` |
| `copy_tpc` | L1260–1334 | `copy_remote.c` |
| `copy_one_r2l` | L1335–1380 | `copy.c` |
| `copy_one_l2r` | L1381–1421 | `copy.c` |
| `copy_tree_download` | L1422–1474 | `copy_recursive.c` |
| `copy_tree_upload` | L1475–1534 | `copy_recursive.c` |
| `recursive_dest_root` | L1535–1560 | `copy_recursive.c` |
| `copy_recursive` | L1561–1600 | `copy_recursive.c` |
| `web_auth_headers` | L1601–1677 | `copy_recursive.c` |
| `copy_web_download` | L1678–1723 | `copy_recursive.c` |
| `copy_web_upload` | L1724–1780 | `copy.c` |
| `copy_web` | L1781–1835 | `copy.c` |
| `zip_remote_pread` | L1836–1844 | `copy.c` |
| `unzip_sink_write` | L1845–1863 | `copy.c` |
| `copy_unzip` | L1864–1951 | `copy.c` |
| `unzip_member_from_src` | L1952–1991 | `copy.c` |
| `zipw_local_write` | L1992–2004 | `copy.c` |
| `zipw_remote_write` | L2005–2015 | `copy.c` |
| `zipw_local_pread` | L2016–2021 | `copy.c` |
| `zip_member_basename` | L2022–2031 | `copy.c` |
| `zip_read_seed` | L2032–2069 | `copy.c` |
| `zip_emit_member` | L2070–2085 | `copy.c` |
| `copy_zip_store_local` | L2086–2127 | `copy.c` |
| `copy_zip_store_remote` | L2128–2201 | `copy.c` |
| `copy_remote_to_block` | L2202–2271 | `copy.c` |
| `copy_block_to_remote` | L2272–2333 | `copy.c` |
| `copy_vfs_to_vfs` | L2334–2397 | `copy.c` |
| `copy_block` | L2398–2451 | `copy.c` |
| `copy_zip_store` | L2452–2480 | `copy.c` |
| `xrdc_copy` | L2481–2582 | `copy.c` |

**`copy_internal.h`**:

```c
#ifndef XROOTD_COPY_INTERNAL_H
#define XROOTD_COPY_INTERNAL_H
/* copy_remote.c */
int cksum_verify(xrdc_conn *c, const char *remote_path, const char *local_path, const char *spec, int silent, xrdc_status *st); /* * Phase 40 (a): cooperative cancellation. A SIGINT/SIGTERM handler sets this * flag — the ONLY async-signal-safe action it takes. The synchronous transfer * loops poll it and abort with an error status, so the normal teardown unlinks * the temp destination; the actual unlink/rename always runs in normal context, * never inside the handler (unlink IS async-signal-safe, but knowing WHICH path * to remove is not, hence the mark-then-reclaim discipline). */ static volatile sig_atomic_t g_xrdc_copy_quit; static void copy_signal_handler(int sig);
int r2r_teardown(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df, int src_up, int dst_up, int sopen, int dopen, int rc, xrdc_status *st);
int r2r_stream_body(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df, const xrdc_statinfo *si, const xrdc_copy_opts *o, xrdc_status *st);
int copy_remote_to_remote(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st);
int cksum_verify(xrdc_conn *c, const char *remote_path, const char *local_path, const char *spec, int silent, xrdc_status *st);
int gen_tpc_key(char *out, size_t outsz);
int tpc_teardown(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df, char *src_opaque, char *dst_opaque, int su_up, int du_up, int sopen, int dopen, int rc, xrdc_status *st);
int copy_tpc(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st);
/* copy_local.c */
int make_temp_path(const char *dst, char *out, size_t outsz);
int open_download_temp(const char *dst, char *tmp, size_t tmpsz, xrdc_status *st);
int atomic_dest_finish(const char *tmp, const char *dest, int rc, xrdc_status *st);
int copy_download(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st);
int upload_stream_body(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co, pump_src_fn src, void *srcctx, int64_t total, xrdc_status *st);
int copy_upload(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st);
/* copy_pump.c */
int write_all(int fd, const uint8_t *buf, size_t n, xrdc_status *st);
int pump_remote_reopen(pump_remote_t *r, xrdc_status *st);
ssize_t pump_src_remote(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st);
int pump_sink_reopen(pump_remote_t *r, xrdc_status *st);
int pump_sink_remote(void *ctx, const uint8_t *buf, int64_t off, size_t n, xrdc_status *st);
ssize_t pump_src_local(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st);
int pump_sink_local(void *ctx, const uint8_t *buf, int64_t off, size_t n, xrdc_status *st);
ssize_t pump_src_local_vfs(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st);
int pump_sink_local_vfs(void *ctx, const uint8_t *buf, int64_t off, size_t n, xrdc_status *st);
int transfer_pump(pump_src_fn src, void *sctx, pump_sink_fn sink, void *kctx, int64_t expected, const xrdc_copy_opts *o, int64_t progress_total, xrdc_status *st);
/* copy_recursive.c */
int copy_tree_download(xrdc_conn *c, const char *rpath, const char *lpath, const xrdc_copy_opts *o, xrdc_status *st);
int copy_tree_upload(xrdc_conn *c, const char *lpath, const char *rpath, const xrdc_copy_opts *o, xrdc_status *st);
int recursive_dest_root(const char *dstdir, const char *srcpath, char *out, size_t outsz);
int copy_recursive(const xrdc_url *su, const xrdc_url *du, int download, const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st);
int web_auth_headers(const xrdc_weburl *u, const char *method, const xrdc_copy_opts *o, const xrdc_opts *co, char *hdrs, size_t hdrsz, xrdc_status *st);
int copy_web_download(const xrdc_weburl *su, const xrdc_url *du, int to_stdout, const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st);
#endif
```

#### F.11 `client/lib/aio.c` (1580/1938 → 5 files; §6.7). Cuts follow the existing `/* ---- section ---- */` banners.

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `xbuf_reserve` | L64–82 | `aio_buffers.c` |
| `xbuf_append` | L83–97 | `aio_buffers.c` |
| `xbuf_compact` | L98–112 | `aio_buffers.c` |
| `xbuf_free` | L113–149 | `aio_buffers.c` |
| `areq_free` | L150–160 | `aio_buffers.c` |
| `areq_accumulate` | L161–185 | `aio_buffers.c` |
| `areq_complete` | L186–215 | `aio_buffers.c` |
| `reqmap_rehash` | L216–240 | `aio_buffers.c` |
| `reqmap_put` | L241–269 | `aio_buffers.c` |
| `reqmap_get` | L270–289 | `aio_buffers.c` |
| `reqmap_del` | L290–433 | `aio_buffers.c` |
| `aconn_do_write` | L434–498 | `aio_io.c` |
| `aconn_note_rtt` | L499–521 | `aio_io.c` |
| `aconn_rto_ns` | L522–538 | `aio_io.c` |
| `aconn_dispatch_frame` | L539–591 | `aio_io.c` |
| `aconn_parse` | L592–623 | `aio_io.c` |
| `aconn_do_read` | L624–700 | `aio_io.c` |
| `aconn_handle_io` | L701–752 | `aio_io.c` |
| `uring_pollmask` | L753–762 | `aio_engine.c` |
| `uring_slot_alloc` | L763–778 | `aio_engine.c` |
| `uring_poll_submit` | L779–795 | `aio_engine.c` |
| `uring_poll_cancel` | L796–823 | `aio_engine.c` |
| `io_engine_setup` | L824–875 | `aio_engine.c` |
| `io_engine_teardown` | L876–894 | `aio_engine.c` |
| `io_engine_arm` | L895–924 | `aio_engine.c` |
| `io_engine_del` | L925–943 | `aio_engine.c` |
| `io_engine_wait` | L944–1006 | `aio_engine.c` |
| `aconn_update_epoll` | L1007–1022 | `aio_conn.c` |
| `aconn_drain_inflight` | L1023–1048 | `aio_conn.c` |
| `aconn_pending_fail_all` | L1049–1065 | `aio_conn.c` |
| `rc_worker_main` | L1066–1125 | `aio.c` |
| `aconn_on_transport_error` | L1126–1177 | `aio_conn.c` |
| `aconn_reconnect_succeeded` | L1178–1217 | `aio_conn.c` |
| `aconn_poll_reconnect` | L1218–1243 | `aio_conn.c` |
| `aconn_ping_cb` | L1244–1254 | `aio_conn.c` |
| `aconn_maybe_ping` | L1255–1285 | `aio_conn.c` |
| `aconn_destroy` | L1286–1316 | `aio_conn.c` |
| `aconn_alloc_sid` | L1317–1338 | `aio_conn.c` |
| `aconn_issue_areq` | L1339–1366 | `aio_conn.c` |
| `aconn_deadline_ns` | L1367–1389 | `aio_conn.c` |
| `aconn_submit_cmd` | L1390–1432 | `aio_conn.c` |
| `loop_push_cmd` | L1433–1451 | `aio.c` |
| `loop_run_control` | L1452–1477 | `aio.c` |
| `loop_drain_commands` | L1478–1526 | `aio.c` |
| `loop_process_timeouts` | L1527–1601 | `aio.c` |
| `loop_thread` | L1602–1653 | `aio.c` |
| `xrdc_loop_create_fail` | L1654–1666 | `aio.c` |
| `xrdc_loop_want_uring` | L1667–1680 | `aio.c` |
| `xrdc_loop_create` | L1681–1704 | `aio.c` |
| `xrdc_loop_destroy` | L1705–1728 | `aio.c` |
| `xrdc_aconn_attach` | L1729–1778 | `aio.c` |
| `xrdc_aconn_close` | L1779–1788 | `aio.c` |
| `xrdc_aconn_set_resilience` | L1789–1803 | `aio.c` |
| `xrdc_aio_submit_ex` | L1804–1842 | `aio.c` |
| `xrdc_aio_submit` | L1843–1864 | `aio.c` |
| `call_cb` | L1865–1882 | `aio.c` |
| `xrdc_aio_call_ex` | L1883–1929 | `aio.c` |
| `xrdc_aio_call` | L1930–1938 | `aio.c` |

**`aio_internal.h`**:

```c
#ifndef XROOTD_AIO_INTERNAL_H
#define XROOTD_AIO_INTERNAL_H
/* aio_buffers.c */
int xbuf_reserve(xbuf *b, size_t need);
int xbuf_append(xbuf *b, const void *data, size_t n);
void xbuf_compact(xbuf *b);
void xbuf_free(xbuf *b);
void areq_free(xrdc_areq *r);
int areq_accumulate(xrdc_areq *r, const uint8_t *body, uint32_t n);
void areq_complete(xrdc_areq *r, int rc, uint16_t kxr, const xrdc_status *st);
int reqmap_rehash(reqmap *m, uint32_t newcap);
int reqmap_put(reqmap *m, xrdc_areq *r);
xrdc_areq * reqmap_get(reqmap *m, uint16_t sid);
void reqmap_del(reqmap *m, uint16_t sid);
/* aio_io.c */
void aconn_do_write(xrdc_aconn *ac);
void aconn_note_rtt(xrdc_aconn *ac, const xrdc_areq *r);
uint64_t aconn_rto_ns(const xrdc_aconn *ac);
void aconn_dispatch_frame(xrdc_aconn *ac, uint16_t sid, uint16_t stat, const uint8_t *body, uint32_t dlen);
void aconn_parse(xrdc_aconn *ac);
void aconn_do_read(xrdc_aconn *ac);
void aconn_handle_io(xrdc_aconn *ac, uint32_t events);
/* aio_engine.c */
unsigned uring_pollmask(int want);
int uring_slot_alloc(xrdc_loop *l, xrdc_aconn *ac);
int uring_poll_submit(xrdc_loop *l, xrdc_aconn *ac, int want);
void uring_poll_cancel(xrdc_loop *l, xrdc_aconn *ac, int freeing);
int io_engine_setup(xrdc_loop *l, xrdc_status *st);
void io_engine_teardown(xrdc_loop *l);
int io_engine_arm(xrdc_loop *l, xrdc_aconn *ac, int want);
void io_engine_del(xrdc_loop *l, xrdc_aconn *ac);
int io_engine_wait(xrdc_loop *l, struct epoll_event *evs, int max, int timeout_ms);
/* aio_conn.c */
void aconn_update_epoll(xrdc_aconn *ac);
void aconn_drain_inflight(xrdc_aconn *ac, const xrdc_status *st);
void aconn_pending_fail_all(xrdc_aconn *ac, const xrdc_status *st);
void aconn_on_transport_error(xrdc_aconn *ac, const xrdc_status *st);
void aconn_reconnect_succeeded(xrdc_aconn *ac);
void aconn_poll_reconnect(xrdc_aconn *ac);
void aconn_ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen, const xrdc_status *st);
void aconn_maybe_ping(xrdc_aconn *ac);
void aconn_destroy(xrdc_aconn *ac);
uint16_t aconn_alloc_sid(xrdc_aconn *ac);
void aconn_issue_areq(xrdc_aconn *ac, xrdc_areq *r);
uint64_t aconn_deadline_ns(xrdc_aconn *ac, int deadline_ms);
void aconn_submit_cmd(xrdc_aconn *ac, cmd *c);
#endif
```

#### F.12 `client/lib/http.c` (919/1139 → 4 files; §6.8)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `xrdc_http_get` | L30–158 | `http.c` |
| `httpx_read_some` | L159–189 | `http_req.c` |
| `ci_contains` | L190–200 | `http.c` |
| `dechunk` | L201–221 | `http.c` |
| `xrdc_http_resp_free` | L222–234 | `http.c` |
| `xrdc_http_header` | L235–241 | `http.c` |
| `httpx_parse` | L242–290 | `http.c` |
| `httpx_body_complete` | L291–313 | `http_req.c` |
| `httpx_exchange` | L314–416 | `http_req.c` |
| `httpx_connect` | L417–435 | `http.c` |
| `xrdc_http_req` | L436–490 | `http_req.c` |
| `bsrc_read` | L491–505 | `http.c` |
| `bsrc_getline` | L506–522 | `http.c` |
| `write_all_fd` | L523–539 | `http.c` |
| `stream_clen` | L540–562 | `http_download.c` |
| `stream_eof` | L563–577 | `http_download.c` |
| `stream_chunked` | L578–613 | `http_download.c` |
| `read_resp_headers` | L614–644 | `http_download.c` |
| `raw_header` | L645–678 | `http_download.c` |
| `httpx_download_body` | L679–720 | `http_download.c` |
| `httpx_download_exchange` | L721–789 | `http_download.c` |
| `httpx_window_ms` | L790–800 | `http.c` |
| `xrdc_http_download` | L801–871 | `http_download.c` |
| `httpx_upload_body` | L872–900 | `http_upload.c` |
| `httpx_upload_response` | L901–932 | `http_upload.c` |
| `httpx_upload_exchange` | L933–958 | `http_upload.c` |
| `httpx_parse_upload_offset` | L959–989 | `http_upload.c` |
| `httpx_upload_chunk` | L990–1047 | `http_upload.c` |
| `xrdc_http_upload_resumable` | L1048–1116 | `http_upload.c` |
| `xrdc_http_upload` | L1117–1139 | `http_upload.c` |

**`http_internal.h`**:

```c
#ifndef XROOTD_HTTP_INTERNAL_H
#define XROOTD_HTTP_INTERNAL_H
/* http_req.c */
ssize_t httpx_read_some(xrdc_io *io, void *buf, size_t n, int timeout_ms, xrdc_status *st);
int httpx_body_complete(const char *buf, size_t total, size_t body_off, long long clen, int chunked);
int httpx_exchange(xrdc_io *io, const char *host, int port, const char *method, const char *path, const char *extra_headers, const void *body, size_t blen, int timeout_ms, xrdc_http_resp *resp, xrdc_status *st);
int xrdc_http_req(const char *host, int port, int tls, const char *method, const char *path, const char *extra_headers, const void *body, size_t blen, int timeout_ms, int verify, const char *ca_dir, xrdc_http_resp *resp, xrdc_status *st);
/* http_download.c */
int stream_clen(body_src *src, long long remaining, int out_fd, long long *written, xrdc_status *st);
int stream_eof(body_src *src, int out_fd, long long *written, xrdc_status *st);
int stream_chunked(body_src *src, int out_fd, long long *written, xrdc_status *st);
int read_resp_headers(xrdc_io *io, char *hdr, size_t hdrcap, int timeout_ms, int *status, size_t *total, size_t *body_off, xrdc_status *st);
int raw_header(const char *hdr, const char *name, char *out, size_t outsz);
int httpx_download_body(xrdc_io *io, char *hdr, size_t total, size_t body_off, int out_fd, int timeout_ms, long long *body_len, xrdc_status *st);
int httpx_download_exchange(xrdc_io *io, const char *host, int port, const char *path, const char *extra_headers, long long start_off, int out_fd, int timeout_ms, int *http_status, long long *body_len, xrdc_status *st);
int xrdc_http_download(const char *host, int port, int tls, const char *path, const char *extra_headers, int verify, const char *ca_dir, int out_fd, int timeout_ms, int *http_status, long long *body_len, xrdc_status *st);
/* http_upload.c */
int httpx_upload_body(xrdc_io *io, int in_fd, long long clen, xrdc_status *st);
int httpx_upload_response(xrdc_io *io, int timeout_ms, int *http_status, xrdc_status *st);
int httpx_upload_exchange(xrdc_io *io, const char *host, int port, const char *path, const char *extra_headers, int in_fd, long long clen, int timeout_ms, int *http_status, xrdc_status *st);
long long httpx_parse_upload_offset(const char *hdr, size_t len);
int httpx_upload_chunk(xrdc_io *io, const char *host, int port, const char *path, const char *extra_headers, int in_fd, long long off, long long chunk_len, long long total, int timeout_ms, int *status_out, long long *srv_off_out, xrdc_status *st);
int xrdc_http_upload_resumable(const char *host, int port, int tls, const char *path, const char *extra_headers, int in_fd, long long clen, int verify, const char *ca_dir, int timeout_ms, int max_stall_ms, int *http_status, xrdc_status *st);
int xrdc_http_upload(const char *host, int port, int tls, const char *path, const char *extra_headers, int in_fd, long long clen, int verify, const char *ca_dir, int timeout_ms, int *http_status, xrdc_status *st);
#endif
```

#### F.13 `client/lib/ops_file.c` (743/941 → 3 files; §6.18). `ops_file_pg.c` carries Invariant 1 (CRC32c).

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `xrdc_file_open_read` | L32–37 | `ops_file.c` |
| `xrdc_file_open_write` | L38–44 | `ops_file.c` |
| `xrdc_file_open_update` | L45–60 | `ops_file.c` |
| `xrdc_inflate_frame` | L61–107 | `ops_file_rw.c` |
| `xrdc_file_read` | L108–202 | `ops_file_rw.c` |
| `xrdc_deflate_frame` | L203–262 | `ops_file_rw.c` |
| `xrdc_file_write` | L263–313 | `ops_file_rw.c` |
| `xrdc_file_readv` | L314–413 | `ops_file_rw.c` |
| `xrdc_file_writev` | L414–473 | `ops_file_rw.c` |
| `xrdc_file_close` | L474–497 | `ops_file.c` |
| `xrdc_file_open_opaque` | L498–589 | `ops_file.c` |
| `xrdc_file_sync` | L590–629 | `ops_file.c` |
| `read_status_frame` | L630–705 | `ops_file_pg.c` |
| `decode_pages` | L706–724 | `ops_file_pg.c` |
| `xrdc_file_pgread` | L725–791 | `ops_file_pg.c` |
| `pgwrite_retry_one` | L792–841 | `ops_file_pg.c` |
| `xrdc_file_pgwrite` | L842–941 | `ops_file_pg.c` |

**`ops_internal.h`**:

```c
#ifndef XROOTD_OPS_INTERNAL_H
#define XROOTD_OPS_INTERNAL_H
/* ops_file_rw.c */
ssize_t xrdc_inflate_frame(uint8_t codec, const uint8_t *comp, size_t comp_len, void *out, size_t out_cap, xrdc_status *st);
ssize_t xrdc_file_read(xrdc_conn *c, xrdc_file *f, int64_t offset, void *buf, size_t len, xrdc_status *st);
uint8_t * xrdc_deflate_frame(uint8_t codec, const void *in, size_t in_len, size_t *out_len, xrdc_status *st);
int xrdc_file_write(xrdc_conn *c, xrdc_file *f, int64_t offset, const void *buf, size_t len, xrdc_status *st);
ssize_t xrdc_file_readv(xrdc_conn *c, xrdc_file *f, xrdc_readv_seg *segs, size_t nseg, xrdc_status *st);
int xrdc_file_writev(xrdc_conn *c, xrdc_file *f, const xrdc_writev_seg *segs, size_t nseg, int do_sync, xrdc_status *st);
/* ops_file_pg.c */
int read_status_frame(xrdc_conn *c, uint16_t want_sid, uint8_t *resptype, uint32_t *pgdlen, int64_t *foff, xrdc_status *st);
ssize_t decode_pages(const uint8_t *pg, uint32_t pglen, int64_t file_off, uint8_t *dst, size_t dstcap, xrdc_status *st);
ssize_t xrdc_file_pgread(xrdc_conn *c, xrdc_file *f, int64_t offset, void *buf, size_t len, xrdc_status *st);
int pgwrite_retry_one(xrdc_conn *c, xrdc_file *f, const uint8_t *buf, int64_t base, size_t len, int64_t pgoff, xrdc_status *st);
int xrdc_file_pgwrite(xrdc_conn *c, xrdc_file *f, int64_t offset, const void *buf, size_t len, xrdc_status *st);
#endif
```

#### F.14 `client/lib/zip.c` (666/783 → reader + writer; §6.19)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `read_exact` | L39–59 | `zip.c` |
| `find_eocd` | L60–136 | `zip.c` |
| `apply_zip64_extra` | L137–165 | `zip.c` |
| `xrdc_zip_open` | L166–260 | `zip.c` |
| `xrdc_zip_find` | L261–276 | `zip.c` |
| `xrdc_zip_dir_free` | L277–293 | `zip.c` |
| `member_data_offset` | L294–317 | `zip.c` |
| `sink_output` | L318–335 | `zip.c` |
| `xrdc_zip_member_extract` | L336–445 | `zip.c` |
| `cd_append` | L472–492 | `zip_write.c` |
| `xrdc_zip_writer_new` | L493–507 | `zip_write.c` |
| `xrdc_zip_writer_new_append` | L508–526 | `zip_write.c` |
| `w_emit` | L527–540 | `zip_write.c` |
| `xrdc_zip_writer_add_fd` | L541–683 | `zip_write.c` |
| `xrdc_zip_writer_finish` | L684–755 | `zip_write.c` |
| `xrdc_zip_writer_free` | L756–765 | `zip_write.c` |
| `xrdc_zip_read_eocd` | L766–783 | `zip.c` |

**`zip_internal.h`**:

```c
#ifndef XROOTD_ZIP_INTERNAL_H
#define XROOTD_ZIP_INTERNAL_H
/* zip_write.c */
int cd_append(xrdc_zip_writer *w, const uint8_t *p, size_t len);
xrdc_zip_writer * xrdc_zip_writer_new(xrdc_zip_write_fn wr, void *ctx);
xrdc_zip_writer * xrdc_zip_writer_new_append(xrdc_zip_write_fn wr, void *ctx, uint64_t base_offset, const uint8_t *seed_cd, size_t seed_cd_len, size_t seed_n);
int w_emit(xrdc_zip_writer *w, const void *p, size_t len);
int xrdc_zip_writer_add_fd(xrdc_zip_writer *w, const char *name, int fd);
int xrdc_zip_writer_finish(xrdc_zip_writer *w);
void xrdc_zip_writer_free(xrdc_zip_writer *w);
#endif
```

#### F.15 `client/lib/webfile.c` (636/787, 🟡 watch — refactor-on-touch; §6.20)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `tag_val` | L47–73 | `webfile.c` |
| `parse_http_date` | L74–92 | `webfile.c` |
| `parse_response` | L93–148 | `webfile.c` |
| `web_auth` | L149–158 | `webfile.c` |
| `xrdc_web_stat` | L159–211 | `webfile.c` |
| `xml_name_char` | L212–222 | `webfile.c` |
| `next_response_open` | L223–257 | `webfile.c` |
| `next_response_close` | L258–285 | `webfile.c` |
| `has_collection_element` | L286–320 | `webfile.c` |
| `path_basename` | L321–339 | `webfile.c` |
| `xrdc_web_readdir` | L340–431 | `webfile.c` |
| `web_disconnect` | L432–448 | `webfile_io.c` |
| `web_connect` | L449–469 | `webfile_io.c` |
| `web_read_some` | L470–497 | `webfile_io.c` |
| `hdr_clen` | L498–516 | `webfile_io.c` |
| `web_get_range` | L517–653 | `webfile_io.c` |
| `xrdc_webfile_open` | L654–694 | `webfile_io.c` |
| `xrdc_webfile_size` | L695–704 | `webfile_io.c` |
| `webfile_window_ms` | L705–715 | `webfile_io.c` |
| `xrdc_webfile_pread` | L716–777 | `webfile_io.c` |
| `xrdc_webfile_close` | L778–787 | `webfile_io.c` |

**`webfile_internal.h`**:

```c
#ifndef XROOTD_WEBFILE_INTERNAL_H
#define XROOTD_WEBFILE_INTERNAL_H
/* webfile_io.c */
void web_disconnect(xrdc_webfile *wf);
int web_connect(xrdc_webfile *wf, xrdc_status *st);
ssize_t web_read_some(xrdc_webfile *wf, void *buf, size_t n, xrdc_status *st);
long long hdr_clen(const char *hdrs);
ssize_t web_get_range(xrdc_webfile *wf, int64_t off, void *buf, size_t len, xrdc_status *st);
xrdc_webfile * xrdc_webfile_open(const xrdc_weburl *u, const char *path, const char *bearer, int verify, const char *ca_dir, int timeout_ms, xrdc_statinfo *si_out, xrdc_status *st);
int64_t xrdc_webfile_size(const xrdc_webfile *wf);
int webfile_window_ms(void);
ssize_t xrdc_webfile_pread(xrdc_webfile *wf, int64_t off, void *buf, size_t len, xrdc_status *st);
void xrdc_webfile_close(xrdc_webfile *wf, xrdc_status *st);
#endif
```

#### F.16 `client/apps/xrd.c` (1566/1872 → 5 files; §6.15)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `is_fs_verb` | L41–50 | `xrd.c` |
| `usage` | L51–91 | `xrd.c` |
| `exec_tool` | L92–118 | `xrd.c` |
| `map_fs_arg` | L119–174 | `xrd.c` |
| `xrd_measure_clock_skew` | L175–199 | `xrd_clockskew.c` |
| `bat_add` | L200–218 | `xrd_battery.c` |
| `fill_pattern` | L219–226 | `xrd_battery.c` |
| `tmpfile_with` | L227–242 | `xrd_battery.c` |
| `battery_root` | L243–452 | `xrd_battery.c` |
| `battery_web` | L453–570 | `xrd_battery.c` |
| `battery_s3` | L571–657 | `xrd_battery.c` |
| `xrd_run_battery` | L658–702 | `xrd_battery.c` |
| `xrd_doctor_probe` | L703–759 | `xrd_doctor.c` |
| `xrd_json_str` | L760–776 | `xrd_doctor.c` |
| `xrd_doctor_json` | L777–888 | `xrd_doctor.c` |
| `xrd_doctor` | L889–1039 | `xrd_doctor.c` |
| `xrd_login` | L1040–1069 | `xrd_mount.c` |
| `xrd_ping` | L1070–1144 | `xrd_mount.c` |
| `xrd_role_str` | L1145–1155 | `xrd_mount.c` |
| `xrd_fmt_epoch` | L1156–1165 | `xrd_clockskew.c` |
| `xrd_fabs` | L1166–1169 | `xrd_clockskew.c` |
| `xrd_probe_caps` | L1170–1194 | `xrd_doctor.c` |
| `xrd_parse_http_date` | L1195–1216 | `xrd_clockskew.c` |
| `xrd_clockskew_http` | L1217–1256 | `xrd_clockskew.c` |
| `xrd_clockskew_root` | L1257–1297 | `xrd_clockskew.c` |
| `xrd_measure_clock_skew` | L1298–1310 | `xrd_clockskew.c` |
| `xrd_certinfo` | L1311–1363 | `xrd_doctor.c` |
| `xrd_clockskew` | L1364–1396 | `xrd_clockskew.c` |
| `xrd_whoami` | L1397–1433 | `xrd_mount.c` |
| `xrd_caps` | L1434–1472 | `xrd_mount.c` |
| `run_cmd` | L1473–1493 | `xrd_mount.c` |
| `mountinfo_unescape` | L1494–1514 | `xrd_mount.c` |
| `xrd_list_mounts` | L1515–1579 | `xrd_mount.c` |
| `xrd_mount` | L1580–1649 | `xrd_mount.c` |
| `xrd_unmount` | L1650–1697 | `xrd_mount.c` |
| `main` | L1698–1872 | `xrd.c` |

**`xrd_internal.h`**:

```c
#ifndef XROOTD_XRD_INTERNAL_H
#define XROOTD_XRD_INTERNAL_H
/* xrd_clockskew.c */
int xrd_measure_clock_skew(const char *endpoint, const xrdc_opts *o, xrd_probe *p, char *err, size_t errsz); #define XRD_MAX_CHECKS 40 typedef struct { char name[40]; int ok; int skipped; char detail[200]; } xrd_check; typedef struct { char endpoint[320]; char protocol[12]; int reachable; char err[XRDC_MSG_MAX]; xrd_check checks[XRD_MAX_CHECKS]; int n, npass, nfail, nskip; } xrd_battery; static void bat_add(xrd_battery *b, const char *name, int status, const char *fmt, ...);
void xrd_fmt_epoch(long e, char *buf, size_t sz);
double xrd_fabs(double x) { return x < 0.0 ? -x : x; } static void xrd_probe_caps(xrdc_conn *c, xrd_probe *p);
int xrd_parse_http_date(const char *s, time_t *out);
int xrd_clockskew_http(const char *endpoint, xrd_probe *p, char *err, size_t errsz);
int xrd_clockskew_root(const char *endpoint, const xrdc_opts *o, xrd_probe *p, char *err, size_t errsz);
int xrd_measure_clock_skew(const char *endpoint, const xrdc_opts *o, xrd_probe *p, char *err, size_t errsz);
int xrd_clockskew(int argc, char **argv);
/* xrd_battery.c */
void bat_add(xrd_battery *b, const char *name, int status, const char *fmt, ...);
void fill_pattern(uint8_t *buf, size_t n);
int tmpfile_with(const uint8_t *buf, size_t n);
void battery_root(const xrdc_url *u, const xrdc_opts *o, int do_write, xrd_battery *b);
void battery_web(const xrdc_weburl *u, int do_write, const char *bearer, int verify, xrd_battery *b);
void battery_s3(const xrdc_weburl *u, int do_write, const char *ak, const char *sk, const char *region, int verify, xrd_battery *b);
void xrd_run_battery(const char *endpoint, int do_write, int verify, xrd_battery *b);
/* xrd_doctor.c */
void xrd_doctor_probe(const char *endpoint, xrd_probe *p);
void xrd_json_str(FILE *f, const char *s);
void xrd_doctor_json(const xrd_probe *p, int token_present, const char *token_path, int proxy_present, const char *proxy_path, const xrd_battery *bats, int nbats);
int xrd_doctor(int argc, char **argv);
void xrd_probe_caps(xrdc_conn *c, xrd_probe *p);
int xrd_certinfo(int argc, char **argv);
/* xrd_mount.c */
int xrd_login(int argc, char **argv);
int xrd_ping(int argc, char **argv);
const char * xrd_role_str(uint32_t flags);
int xrd_whoami(int argc, char **argv);
int xrd_caps(int argc, char **argv);
int run_cmd(char *const cmd_argv[]);
void mountinfo_unescape(const char *in, char *out, size_t outsz);
int xrd_list_mounts(void);
int xrd_mount(int argc, char **argv);
int xrd_unmount(int argc, char **argv);
#endif
```

#### F.17 `client/apps/xrdcp.c` (1224/1480 → 3 files; §6.16)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `usage` | L30–80 | `xrdcp.c` |
| `str_append` | L81–96 | `xrdcp.c` |
| `str_free` | L97–107 | `xrdcp.c` |
| `merge_alias_auth` | L108–152 | `xrdcp.c` |
| `path_basename` | L153–168 | `xrdcp.c` |
| `read_manifest` | L169–196 | `xrdcp.c` |
| `is_root_url` | L197–206 | `xrdcp.c` |
| `is_s3_url` | L207–214 | `xrdcp.c` |
| `uses_cred_auth` | L215–221 | `xrdcp.c` |
| `is_local_dir` | L222–234 | `xrdcp.c` |
| `source_has_glob` | L235–251 | `xrdcp_recursive.c` |
| `expand_source` | L252–305 | `xrdcp_recursive.c` |
| `dest_is_dir` | L306–329 | `xrdcp.c` |
| `join_dest` | L330–339 | `xrdcp.c` |
| `both_web` | L340–347 | `xrdcp.c` |
| `relay_web_to_web` | L348–351 | `xrdcp_transfer.c` |
| `copy_one_with_retry` | L352–394 | `xrdcp_transfer.c` |
| `entry_size` | L395–427 | `xrdcp_transfer.c` |
| `transfer_one` | L428–450 | `xrdcp_transfer.c` |
| `relay_web_to_web` | L451–498 | `xrdcp_transfer.c` |
| `batch_copy_one` | L499–534 | `xrdcp_transfer.c` |
| `batch_worker` | L535–576 | `xrdcp_transfer.c` |
| `batch_parallel` | L577–614 | `xrdcp_transfer.c` |
| `web_scheme_str` | L615–630 | `xrdcp.c` |
| `mkdirs_for` | L631–656 | `xrdcp_recursive.c` |
| `rel_is_unsafe` | L657–667 | `xrdcp.c` |
| `mkcol_parents` | L668–695 | `xrdcp_recursive.c` |
| `recursive_place` | L696–739 | `xrdcp_recursive.c` |
| `ensure_web_dst_base` | L740–767 | `xrdcp_recursive.c` |
| `recursive_s3_download` | L768–857 | `xrdcp_recursive.c` |
| `recursive_web_download` | L858–957 | `xrdcp_recursive.c` |
| `web_join` | L958–968 | `xrdcp_recursive.c` |
| `web_upload_walk` | L969–1053 | `xrdcp_recursive.c` |
| `recursive_web_upload` | L1054–1114 | `xrdcp_recursive.c` |
| `xrdcp_progress` | L1115–1144 | `xrdcp.c` |
| `main` | L1145–1480 | `xrdcp.c` |

**`xrdcp_internal.h`**:

```c
#ifndef XROOTD_XRDCP_INTERNAL_H
#define XROOTD_XRDCP_INTERNAL_H
/* xrdcp_recursive.c */
int source_has_glob(const char *s);
int expand_source(const char *s_in, const xrdc_opts *co, char ***out, size_t *n, size_t *cap);
void mkdirs_for(const char *filepath);
int mkcol_parents(const xrdc_weburl *du, const char *base, const char *rel, const char *bearer, const xrdc_opts *co, xrdc_status *st);
int recursive_place(const char *dstroot, const char *rel, const char *srcurl, const xrdc_copy_opts *fo, const xrdc_opts *co, int retries, xrdc_status *st);
void ensure_web_dst_base(const char *dstroot, const xrdc_copy_opts *fo, const xrdc_opts *co);
int recursive_s3_download(const xrdc_weburl *u, const char *dstdir, const xrdc_copy_opts *fo, const xrdc_opts *co, int retries);
int recursive_web_download(const char *src, const char *dstdir, const xrdc_copy_opts *o, const xrdc_opts *co, int retries);
int web_join(const char *base, const char *rel, char *out, size_t outsz);
void web_upload_walk(web_upload_ctx *c, const char *localdir, const char *rel);
int recursive_web_upload(const char *localdir, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries);
/* xrdcp_transfer.c */
int relay_web_to_web(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, xrdc_status *st); static int copy_one_with_retry(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, xrdc_status *st);
int copy_one_with_retry(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, xrdc_status *st);
int entry_size(const char *url, const xrdc_opts *co, long long *size);
int transfer_one(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, int sync_mode, xrdc_status *st);
int relay_web_to_web(const char *src, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, xrdc_status *st);
int batch_copy_one(const char *item, const char *dstdir, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, int sync_mode, char *dpath, size_t dpsz, xrdc_status *st);
void * batch_worker(void *arg);
void batch_parallel(char **items, size_t n, const char *dst, const xrdc_copy_opts *o, const xrdc_opts *co, int retries, int sync_mode, int jobs, size_t *ok, size_t *skip, size_t *fail);
#endif
```

#### F.18 `client/apps/xrootdfs.c` (921/1116 → 4 files; §6.17). `xrootdfs_legacy.c` mirrors this — or retire it.

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `$BEARER_TOKEN` | L71–71 | `xrootdfs.c` |
| `verification` | L72–72 | `xrootdfs.c` |
| `dir` | L73–73 | `xrootdfs.c` |
| `prefix` | L74–79 | `xrootdfs.c` |
| `srv_path` | L80–138 | `xrootdfs_meta.c` |
| `xfs_err` | L139–144 | `xrootdfs.c` |
| `xfs_conn_healthy` | L145–150 | `xrootdfs.c` |
| `xfs_meta` | L151–156 | `xrootdfs.c` |
| `xfs_fill_stat` | L157–167 | `xrootdfs.c` |
| `xfs_getattr` | L168–199 | `xrootdfs_meta.c` |
| `xfs_readdir` | L200–239 | `xrootdfs_meta.c` |
| `xfs_mkdir` | L240–249 | `xrootdfs_meta.c` |
| `xfs_unlink` | L250–258 | `xrootdfs_meta.c` |
| `xfs_rmdir` | L259–267 | `xrootdfs_meta.c` |
| `xfs_rename` | L268–281 | `xrootdfs_meta.c` |
| `xfs_chmod` | L282–292 | `xrootdfs_meta.c` |
| `xfs_truncate` | L293–306 | `xrootdfs_meta.c` |
| `xfs_utimens` | L307–322 | `xrootdfs_meta.c` |
| `xfs_chown` | L323–342 | `xrootdfs_meta.c` |
| `xfs_symlink` | L343–357 | `xrootdfs_meta.c` |
| `xfs_link` | L358–371 | `xrootdfs.c` |
| `xfs_readlink` | L372–402 | `xrootdfs_meta.c` |
| `op_qspace` | L403–405 | `xrootdfs_xattr.c` |
| `xfs_statfs` | L406–437 | `xrootdfs_meta.c` |
| `xfs_access` | L438–466 | `xrootdfs_meta.c` |
| `afh_pread` | L467–477 | `xrootdfs_io.c` |
| `afh_io_pread` | L478–482 | `xrootdfs_io.c` |
| `afh_io_pwrite` | L483–489 | `xrootdfs_io.c` |
| `afh_flush_wbuf` | L490–495 | `xrootdfs_io.c` |
| `afh_free` | L496–504 | `xrootdfs_io.c` |
| `afh_open` | L505–558 | `xrootdfs_io.c` |
| `xfs_open` | L559–569 | `xrootdfs_io.c` |
| `xfs_create` | L570–577 | `xrootdfs_io.c` |
| `xfs_read` | L578–596 | `xrootdfs_io.c` |
| `xfs_write` | L597–616 | `xrootdfs_io.c` |
| `xfs_flush` | L617–634 | `xrootdfs_io.c` |
| `xfs_fsync` | L635–655 | `xrootdfs_io.c` |
| `xfs_release` | L656–683 | `xrootdfs_io.c` |
| `xfs_xattr_to_fattr` | L684–693 | `xrootdfs_xattr.c` |
| `op_cks` | L694–697 | `xrootdfs_xattr.c` |
| `op_faget` | L698–700 | `xrootdfs_xattr.c` |
| `xfs_getxattr` | L701–757 | `xrootdfs_xattr.c` |
| `op_faset` | L758–761 | `xrootdfs_xattr.c` |
| `xfs_setxattr` | L762–786 | `xrootdfs_xattr.c` |
| `op_fadel` | L787–789 | `xrootdfs_xattr.c` |
| `xfs_removexattr` | L790–812 | `xrootdfs_xattr.c` |
| `op_falist` | L813–815 | `xrootdfs_xattr.c` |
| `xfs_listxattr` | L816–841 | `xrootdfs_xattr.c` |
| `xfs_init` | L842–887 | `xrootdfs.c` |
| `usage` | L888–923 | `xrootdfs.c` |
| `xrootdfs_aio_main` | L924–1116 | `xrootdfs.c` |

**`xrootdfs_internal.h`**:

```c
#ifndef XROOTD_XROOTDFS_INTERNAL_H
#define XROOTD_XROOTDFS_INTERNAL_H
/* xrootdfs_meta.c */
const char * srv_path(const char *p, char *buf, size_t sz);
int xfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int xfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
int xfs_mkdir(const char *path, mode_t mode);
int xfs_unlink(const char *path);
int xfs_rmdir(const char *path);
int xfs_rename(const char *from, const char *to, unsigned int flags);
int xfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);
int xfs_truncate(const char *path, off_t size, struct fuse_file_info *fi);
int xfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi);
int xfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi);
int xfs_symlink(const char *target, const char *linkpath);
int xfs_readlink(const char *path, char *buf, size_t size);
int xfs_statfs(const char *path, struct statvfs *stbuf);
int xfs_access(const char *path, int mask);
/* xrootdfs_xattr.c */
int op_qspace(xrdc_conn *c, void *v, xrdc_status *st);
const char * xfs_xattr_to_fattr(const char *name);
int op_cks(xrdc_conn *c, void *v, xrdc_status *st);
int op_faget(xrdc_conn *c, void *v, xrdc_status *st);
int xfs_getxattr(const char *path, const char *name, char *value, size_t size);
int op_faset(xrdc_conn *c, void *v, xrdc_status *st);
int xfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
int op_fadel(xrdc_conn *c, void *v, xrdc_status *st);
int xfs_removexattr(const char *path, const char *name);
int op_falist(xrdc_conn *c, void *v, xrdc_status *st);
int xfs_listxattr(const char *path, char *list, size_t size);
/* xrootdfs_io.c */
ssize_t afh_pread(afh *h, int64_t off, void *buf, size_t len, xrdc_status *st);
ssize_t afh_io_pread(void *be, int64_t off, void *buf, size_t n, xrdc_status *st);
int afh_io_pwrite(void *be, int64_t off, const void *buf, size_t n, xrdc_status *st);
int afh_flush_wbuf(afh *h, xrdc_status *st);
void afh_free(afh *h);
int afh_open(const char *path, int writable, int force, struct fuse_file_info *fi);
int xfs_open(const char *path, struct fuse_file_info *fi);
int xfs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int xfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int xfs_flush(const char *path, struct fuse_file_info *fi);
int xfs_fsync(const char *path, int datasync, struct fuse_file_info *fi);
int xfs_release(const char *path, struct fuse_file_info *fi);
#endif
```

#### F.19 `client/apps/xrdfs.c` (2401/2818 → 4 files; §6.9)

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `endpoint_to_url` | L43–52 | `xrdfs_fmt.c` |
| `build_path` | L53–58 | `xrdfs_fmt.c` |
| `flags_to_str` | L59–91 | `xrdfs_fmt.c` |
| `chmod_recursive` | L92–100 | `xrdfs_walk.c` |
| `print_stat_time` | L101–117 | `xrdfs_fmt.c` |
| `print_statinfo` | L118–139 | `xrdfs_fmt.c` |
| `do_stat` | L140–163 | `xrdfs.c` |
| `ls_print_dir` | L164–214 | `xrdfs.c` |
| `do_ls` | L215–262 | `xrdfs.c` |
| `web_build_path` | L263–276 | `xrdfs_fmt.c` |
| `web_ls_print_dir` | L277–327 | `xrdfs.c` |
| `web_ls` | L328–353 | `xrdfs.c` |
| `web_stat` | L354–373 | `xrdfs.c` |
| `web_dispatch` | L374–385 | `xrdfs.c` |
| `do_mkdir` | L386–411 | `xrdfs.c` |
| `do_rm` | L412–428 | `xrdfs.c` |
| `do_rmdir` | L429–445 | `xrdfs.c` |
| `do_mv` | L446–469 | `xrdfs.c` |
| `parse_chmod_mode` | L470–504 | `xrdfs_fmt.c` |
| `do_chmod` | L505–548 | `xrdfs.c` |
| `do_truncate` | L549–570 | `xrdfs.c` |
| `stream_file` | L571–618 | `xrdfs_data.c` |
| `do_cat` | L619–637 | `xrdfs.c` |
| `head_lines` | L638–686 | `xrdfs_data.c` |
| `do_head` | L687–728 | `xrdfs.c` |
| `tail_sigint` | L729–739 | `xrdfs_data.c` |
| `tail_start_for_lines` | L740–790 | `xrdfs_data.c` |
| `tail_follow` | L791–828 | `xrdfs_data.c` |
| `do_tail` | L829–884 | `xrdfs.c` |
| `do_locate` | L885–901 | `xrdfs.c` |
| `do_statvfs` | L902–919 | `xrdfs.c` |
| `df_field` | L920–928 | `xrdfs_fmt.c` |
| `df_parse_space` | L929–943 | `xrdfs_fmt.c` |
| `do_df` | L944–986 | `xrdfs.c` |
| `two_digits` | L987–994 | `xrdfs_fmt.c` |
| `touch_parse_time` | L995–1052 | `xrdfs_fmt.c` |
| `do_touch` | L1053–1121 | `xrdfs.c` |
| `do_ln` | L1122–1166 | `xrdfs.c` |
| `do_readlink` | L1167–1192 | `xrdfs.c` |
| `do_cksum` | L1193–1218 | `xrdfs.c` |
| `do_wc` | L1219–1289 | `xrdfs.c` |
| `slurp_file` | L1290–1321 | `xrdfs_data.c` |
| `do_cmp` | L1322–1383 | `xrdfs.c` |
| `xattr_ls` | L1384–1407 | `xrdfs.c` |
| `do_xattr` | L1408–1465 | `xrdfs.c` |
| `do_grep` | L1466–1553 | `xrdfs.c` |
| `do_hexdump` | L1554–1623 | `xrdfs.c` |
| `parse_bytes` | L1624–1629 | `xrdfs_fmt.c` |
| `rate_pace` | L1630–1639 | `xrdfs_fmt.c` |
| `do_dd` | L1640–1725 | `xrdfs.c` |
| `do_upload` | L1726–1807 | `xrdfs.c` |
| `do_download` | L1808–1907 | `xrdfs.c` |
| `do_query` | L1908–1946 | `xrdfs.c` |
| `do_prepare` | L1947–1982 | `xrdfs.c` |
| `wait_online` | L1983–2001 | `xrdfs.c` |
| `do_stage` | L2002–2046 | `xrdfs.c` |
| `do_evict` | L2047–2074 | `xrdfs.c` |
| `do_explain` | L2075–2084 | `xrdfs.c` |
| `parse_u64_strict` | L2085–2104 | `xrdfs_fmt.c` |
| `do_readv` | L2105–2164 | `xrdfs.c` |
| `do_writev` | L2165–2240 | `xrdfs.c` |
| `is_dot` | L2241–2248 | `xrdfs_fmt.c` |
| `fmt_size` | L2249–2255 | `xrdfs_fmt.c` |
| `join_path` | L2256–2268 | `xrdfs_fmt.c` |
| `walk_dir` | L2269–2310 | `xrdfs_walk.c` |
| `chmod_visit` | L2311–2326 | `xrdfs_walk.c` |
| `chmod_recursive` | L2327–2346 | `xrdfs_walk.c` |
| `du_visit` | L2347–2362 | `xrdfs_walk.c` |
| `do_du` | L2363–2411 | `xrdfs.c` |
| `find_visit` | L2412–2430 | `xrdfs_walk.c` |
| `do_find` | L2431–2472 | `xrdfs.c` |
| `tree_recurse` | L2473–2521 | `xrdfs_walk.c` |
| `do_tree` | L2522–2598 | `xrdfs.c` |
| `find_command` | L2599–2611 | `xrdfs_walk.c` |
| `dispatch` | L2612–2653 | `xrdfs.c` |
| `tokenize` | L2654–2669 | `xrdfs.c` |
| `repl` | L2670–2704 | `xrdfs.c` |
| `usage` | L2705–2722 | `xrdfs.c` |
| `main` | L2723–2818 | `xrdfs.c` |

**`xrdfs_internal.h`**:

```c
#ifndef XROOTD_XRDFS_INTERNAL_H
#define XROOTD_XRDFS_INTERNAL_H
/* xrdfs_fmt.c */
int endpoint_to_url(const char *ep, xrdc_url *u, xrdc_status *st);
void build_path(const char *cwd, const char *arg, char *out, size_t outsz);
void flags_to_str(int f, char *out, size_t sz);
void print_stat_time(const char *label, long epoch);
void print_statinfo(const char *path, const xrdc_statinfo *si);
void web_build_path(const char *base, const char *cwd, const char *arg, char *out, size_t outsz);
int parse_chmod_mode(const char *s);
int64_t df_field(const char *reply, const char *key);
int df_parse_space(const char *reply, int64_t *total, int64_t *avail, int64_t *used, int64_t *largest);
int two_digits(const char *p);
int touch_parse_time(const char *s, struct timespec *out);
int64_t parse_bytes(const char *s);
void rate_pace(const struct timespec *start, int64_t sent, double rate);
int parse_u64_strict(const char *s, unsigned long long *out);
int is_dot(const char *name);
void fmt_size(int64_t n, char *out, size_t sz, int human);
int join_path(const char *dir, const char *name, char *out, size_t sz);
/* xrdfs_walk.c */
int chmod_recursive(xrdc_conn *c, const char *path, int mode, int *failures, xrdc_status *st); /* Print one labelled "%Y-%m-%d %H:%M:%S" time line in UTC (matching official * xrdfs, which formats stat times with gmtime); falls back to the raw epoch. */ static void print_stat_time(const char *label, long epoch);
int walk_dir(xrdc_conn *c, const char *path, int depth, xrdfs_visit visit, void *u, xrdc_status *st);
int chmod_visit(const char *full, const xrdc_dirent *e, int depth, void *u);
int chmod_recursive(xrdc_conn *c, const char *path, int mode, int *failures, xrdc_status *st);
int du_visit(const char *full, const xrdc_dirent *e, int depth, void *u);
int find_visit(const char *full, const xrdc_dirent *e, int depth, void *u);
int tree_recurse(xrdc_conn *c, const char *path, const char *prefix, int depth, tree_opts *o, xrdc_status *st);
const xrdfs_cmd * find_command(const char *name);
/* xrdfs_data.c */
int stream_file(xrdc_conn *c, const char *path, int64_t start, int64_t limit, xrdc_status *st);
int head_lines(xrdc_conn *c, const char *path, long nlines, xrdc_status *st);
void tail_sigint(int sig);
int tail_start_for_lines(xrdc_conn *c, const char *path, int64_t size, long nlines, int64_t *start, xrdc_status *st);
int tail_follow(xrdc_conn *c, const char *path, int64_t from, double interval, xrdc_status *st);
int slurp_file(xrdc_conn *c, const char *path, uint8_t **out, int64_t *len, xrdc_status *st);
#endif
```

#### F.20 `client/apps/xrddiag.c` (2968/3600 → 6+ files; §6.9). `do_<sub>` are the subcommand entry points; `dx_*` shared layer stays in `diag_internal.h`.

> **Note:** the extractor reveals xrddiag actually has **~12 `do_<sub>` subcommands**
> (not the 5 the §6.9 sketch named): beyond check/bench/topology/status/compare there
> are `do_probe_robustness`, `do_replay`, `do_srr`, `do_tape`, `do_remote_doctor`,
> `do_watch`. The principle is unchanged — **one `diag_<sub>.c` per subcommand** — so
> the map below routes the five headline ones and the rest follow identically (they
> show as `xrddiag.c` here only because they aren't in the map). Late ranges are
> approximate (caveat 2).

**Move table** — current lines → target file:

| Function | Lines | → file |
|---|---|---|
| `probe` | L72–87 | `diag_compare.c` |
| `note` | L88–106 | `xrddiag.c` |
| `download_to_fd` | L107–156 | `xrddiag.c` |
| `resolve_target` | L157–204 | `diag_topology.c` |
| `do_check` | L205–448 | `diag_check.c` |
| `bench_one` | L449–484 | `diag_bench.c` |
| `bench_sweep` | L485–529 | `diag_bench.c` |
| `do_bench` | L530–608 | `diag_bench.c` |
| `do_topology` | L609–674 | `diag_topology.c` |
| `do_status` | L675–723 | `diag_watch.c` |
| `remote_md5` | L724–745 | `diag_compare.c` |
| `parse_http_hostport` | L746–775 | `diag_topology.c` |
| `do_compare_davs` | L776–851 | `diag_compare.c` |
| `do_compare` | L852–960 | `diag_compare.c` |
| `resolve_once` | L961–998 | `diag_topology.c` |
| `probe_open` | L999–1020 | `diag_topology.c` |
| `raw_send_expect_reject` | L1021–1057 | `diag_topology.c` |
| `do_probe_robustness` | L1058–1227 | `xrddiag.c` |
| `do_replay` | L1228–1307 | `xrddiag.c` |
| `doc_issue` | L1308–1324 | `xrddiag.c` |
| `doctor_xfer` | L1325–1365 | `xrddiag.c` |
| `doctor_metrics` | L1366–1495 | `xrddiag.c` |
| `dx_record` | L1496–1519 | `xrddiag.c` |
| `dx_record_status` | L1520–1553 | `xrddiag.c` |
| `dx_is_loopback` | L1554–1564 | `xrddiag.c` |
| `dx_probe_auth` | L1565–1579 | `diag_check.c` |
| `dx_probe_namespace` | L1580–1620 | `diag_check.c` |
| `dx_probe_read` | L1621–1664 | `diag_check.c` |
| `dx_probe_checksum` | L1665–1707 | `diag_check.c` |
| `dx_probe_write` | L1708–1784 | `diag_check.c` |
| `dx_probe_stage` | L1785–1808 | `diag_check.c` |
| `dx_b64url_enc` | L1809–1835 | `xrddiag.c` |
| `dx_make_jwt` | L1836–1857 | `xrddiag.c` |
| `dx_connect_as` | L1858–1892 | `xrddiag.c` |
| `dx_authz_anon` | L1893–1948 | `diag_check.c` |
| `dx_authz_forged` | L1949–1978 | `diag_check.c` |
| `dx_authz_expired` | L1979–2006 | `diag_check.c` |
| `dx_authz_scope` | L2007–2058 | `diag_check.c` |
| `doctor_auth_suite` | L2059–2119 | `xrddiag.c` |
| `doctor_diagnose` | L2120–2171 | `xrddiag.c` |
| `dx_proto_name` | L2172–2190 | `xrddiag.c` |
| `dx_url_parse` | L2191–2243 | `xrddiag.c` |
| `dx_http_status` | L2244–2270 | `xrddiag.c` |
| `dx_http_fail` | L2271–2296 | `xrddiag.c` |
| `doctor_http` | L2297–2410 | `xrddiag.c` |
| `s3_sign` | L2411–2426 | `xrddiag.c` |
| `doctor_s3` | L2427–2528 | `xrddiag.c` |
| `doctor_cms` | L2529–2607 | `xrddiag.c` |
| `doctor_one` | L2608–2722 | `xrddiag.c` |
| `doc_color` | L2723–2729 | `xrddiag.c` |
| `doctor_cross` | L2730–2772 | `xrddiag.c` |
| `fjson_str` | L2773–2794 | `xrddiag.c` |
| `dx_verdict_name` | L2795–2800 | `xrddiag.c` |
| `doctor_emit_json` | L2801–2847 | `xrddiag.c` |
| `doctor_print_diagnosis` | L2848–2872 | `xrddiag.c` |
| `js_str` | L2873–2910 | `xrddiag.c` |
| `js_sum` | L2911–2937 | `xrddiag.c` |
| `js_count` | L2938–2952 | `xrddiag.c` |
| `do_srr` | L2953–3005 | `xrddiag.c` |
| `do_tape` | L3006–3076 | `xrddiag.c` |
| `doctor_dispatch` | L3077–3098 | `xrddiag.c` |
| `do_remote_doctor` | L3099–3201 | `xrddiag.c` |
| `watch_on_signal` | L3202–3210 | `diag_watch.c` |
| `watch_count_tokens` | L3211–3225 | `diag_watch.c` |
| `watch_prom_label` | L3226–3242 | `diag_watch.c` |
| `watch_probe_once` | L3243–3317 | `diag_watch.c` |
| `watch_emit_human` | L3318–3330 | `diag_watch.c` |
| `watch_emit_json` | L3331–3343 | `diag_watch.c` |
| `watch_emit_prom` | L3344–3388 | `diag_watch.c` |
| `watch_write_prom_atomic` | L3389–3424 | `diag_watch.c` |
| `watch_sleep` | L3425–3434 | `diag_watch.c` |
| `do_watch` | L3435–3478 | `xrddiag.c` |
| `usage` | L3479–3511 | `xrddiag.c` |
| `main` | L3512–3600 | `xrddiag.c` |

**`diag_internal.h`**:

```c
#ifndef XROOTD_DIAG_INTERNAL_H
#define XROOTD_DIAG_INTERNAL_H
/* diag_compare.c */
void probe(const char *name, int ok, const char *fmt, ...);
int remote_md5(xrdc_conn *c, const char *path, char *hex, size_t hexsz, xrdc_status *st);
int do_compare_davs(const diag_args *a);
int do_compare(const diag_args *a);
/* diag_topology.c */
int resolve_target(xrdc_conn *c, const xrdc_url *u, char *target, size_t tsz, xrdc_statinfo *sti, xrdc_status *st);
int do_topology(const diag_args *a);
void parse_http_hostport(const char *s, char *host, size_t hsz, int *port);
int resolve_once(const char *host, int port, char *ip, size_t ipsz, int *is_loop, xrdc_status *st);
int probe_open(xrdc_conn *c, const char *urlbuf, const diag_args *a, int tmo, xrdc_status *st);
int raw_send_expect_reject(xrdc_conn *c, const uint8_t hdr24[24], const uint8_t *body, uint32_t bodylen, int lie_dlen, uint32_t fake_dlen);
/* diag_check.c */
int do_check(const diag_args *a);
void dx_probe_auth(const xrdc_conn *c, doctor_ep *e);
void dx_probe_namespace(xrdc_conn *c, doctor_ep *e);
void dx_probe_read(xrdc_conn *c, const char *target, doctor_ep *e);
void dx_probe_checksum(xrdc_conn *c, const char *target, doctor_ep *e);
void dx_probe_write(xrdc_conn *c, doctor_ep *e);
void dx_probe_stage(xrdc_conn *c, const char *target, doctor_ep *e);
int dx_authz_anon(const diag_args *a, const xrdc_url *u, const char *target, int have_target, char *sec_out, size_t sec_sz, doctor_ep *e);
void dx_authz_forged(const diag_args *a, const xrdc_url *u, const char *probe, const char *bad_token, doctor_ep *e);
void dx_authz_expired(const diag_args *a, const xrdc_url *u, const char *tok, doctor_ep *e);
void dx_authz_scope(const diag_args *a, const xrdc_url *u, const char *tok, doctor_ep *e);
/* diag_bench.c */
double bench_one(xrdc_conn *c, const char *target, xrdc_status *st);
void bench_sweep(xrdc_conn *c, const char *target);
int do_bench(const diag_args *a);
/* diag_watch.c */
int do_status(const diag_args *a);
void watch_on_signal(int sig);
int watch_count_tokens(const char *s);
void watch_prom_label(const char *s, char *out, size_t osz);
int watch_probe_once(const diag_args *a, const char *url, watch_sample *out);
void watch_emit_human(const watch_sample *s, FILE *out);
void watch_emit_json(const watch_sample *s, FILE *out);
void watch_emit_prom(const watch_sample *samples, int n, FILE *out);
int watch_write_prom_atomic(const char *path, const watch_sample *samples, int n, xrdc_status *st);
void watch_sleep(int seconds);
#endif
```

