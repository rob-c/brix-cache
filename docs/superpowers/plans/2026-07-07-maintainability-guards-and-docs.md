# Maintainability Without Touching Product Code — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the project's existing invariant guards self-enforcing in CI, close the documentation gaps that slow human auditing (missing READMEs in the hardest directories, no ports registry, no symptom-indexed runbook), and add drift guards so navigation docs stop rotting after tree reorganizations.

**Architecture:** Everything lands in `.github/workflows/`, `tools/ci/`, `tools/git-hooks/`, and `docs/` + `src/**/README.md` — zero changes to product code (`src/**/*.c`, `src/**/*.h`, `shared/`, `client/`). New guards follow the house backlog-ratchet pattern (`check_vfs_seam.sh` model): freeze pre-existing violations, fail only on new ones. New READMEs follow the house format exemplified by `src/protocols/root/connection/README.md`.

**Tech Stack:** bash guard scripts (GNU coreutils + `grep -P`), python3 (stdlib only, for the link checker), GitHub Actions, doxygen/graphviz.

## Global Constraints

- **NO changes to any `.c`/`.h` file under `src/`, `shared/`, or `client/`.** READMEs inside `src/` are documentation, not code — allowed.
- **Commit directly to `main`, no branches, no PRs** (standing OP instruction).
- Every `tools/ci/check_*.sh` guard must exit 0 on `main` after each task's commit — never leave the tree red.
- New guard scripts copy the house header style: `WHAT:` / `WHY:` / `HOW:` / `USAGE:` comment block, `set -euo pipefail`, exit 1 on violation, exit 0 with a one-line `OK` on success.
- Do not edit `tests/lint_loc.sh`, `tests/loc_baseline.txt`, or any existing guard's logic — only baselines via their own `--regen` flags, and only where a task says so.
- Commit message style (from git log): `ci(scope): ...` / `docs(scope): ...`, imperative mood.
- This box's `grep` is ugrep — verify each guard also works with `grep -P`/`grep -E` semantics used by GNU grep (CI runs GNU grep). Test locally with `command grep` if in doubt.

---

### Task 1: Re-baseline the file-size ratchet so CI can land green

`tools/ci/check_file_size.sh` currently FAILS with 18 violations (14 files grew past frozen ceilings, 4 new >500-line offenders: `src/auth/crypto/store_policy.c` 732, `src/protocols/s3/s3.h` 507, `src/protocols/webdav/auth_cert.c` 537, `src/protocols/webdav/webdav.h` 514). They accumulated precisely because the guard never ran automatically. Fixing the files means touching product code (excluded), so we accept the current tree as the new frozen ceiling and let Task 2 prevent any further growth.

**Files:**
- Modify: `tools/ci/file_size_backlog.txt` (via the script's own `--regen`, no hand edits)

**Interfaces:**
- Produces: a green `tools/ci/check_file_size.sh` (exit 0) that Task 2's workflow depends on.

- [ ] **Step 1: Confirm the current failure set**

Run: `tools/ci/check_file_size.sh; echo "exit=$?"`
Expected: 18 `FAIL` lines, `exit=1`.

- [ ] **Step 2: Regenerate the backlog**

Run: `tools/ci/check_file_size.sh --regen`
Expected: message about rewriting the backlog.

- [ ] **Step 3: Review the diff — it must contain ONLY the 18 known entries (new or raised), nothing removed that still exists**

Run: `git diff tools/ci/file_size_backlog.txt`
Expected: added lines for the 4 new offenders; raised `loc` values for the 14 grown files; no unrelated churn. If anything else appears, stop and investigate before committing.

- [ ] **Step 4: Verify green**

Run: `tools/ci/check_file_size.sh; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add tools/ci/file_size_backlog.txt
git commit -m "ci(guards): re-freeze file-size backlog — 18 violations accumulated while the guard was manual-only

Accepts the current tree as the ratchet ceiling so the guard can enter CI
(next commit). The growth happened because nothing ran the guard; the CI
wiring is the actual fix. No file may grow past these ceilings again."
```

---

### Task 2: `guards.yml` — run the five static invariant guards on every PR/push

**Files:**
- Create: `.github/workflows/guards.yml`

**Interfaces:**
- Consumes: green `check_file_size.sh` from Task 1.
- Produces: the workflow file that Tasks 3, 4, 8, 9 append steps to (step names below are load-bearing for those tasks).

- [ ] **Step 1: Verify all five guards pass locally (the workflow must land green)**

Run: `for s in check_config_coverage check_vfs_seam check_http_helper_reimpl check_sd_driver_conformance check_file_size; do tools/ci/$s.sh >/dev/null && echo "PASS $s" || echo "FAIL $s"; done`
Expected: five `PASS` lines.

- [ ] **Step 2: Create the workflow**

```yaml
# Run the tools/ci/ invariant guards on every PR and push to main.
#
# These guards encode the project's hardest-won invariants (VFS seam,
# config coverage, shared-helper discipline, SD driver conformance,
# file-size ratchet). They were manual-only until 2026-07-07 — and the
# file-size ratchet accumulated 18 violations in that time. Never remove
# a step here without removing the invariant it enforces.
#
# `if: '!cancelled()'` on each step so ALL guards report, not just the
# first failure.
name: guards
on:
  pull_request:
  push:
    branches: [main]
jobs:
  guards:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # guards use `git ls-files`
      - name: config coverage — every .c built or reasoned
        run: tools/ci/check_config_coverage.sh
      - name: vfs seam — no new storage-plane bypasses
        if: '!cancelled()'
        run: tools/ci/check_vfs_seam.sh
      - name: http helper reimplementation
        if: '!cancelled()'
        run: tools/ci/check_http_helper_reimpl.sh
      - name: sd driver conformance
        if: '!cancelled()'
        run: tools/ci/check_sd_driver_conformance.sh
      - name: file-size ratchet (500-line soft cap)
        if: '!cancelled()'
        run: tools/ci/check_file_size.sh
```

- [ ] **Step 3: Commit and verify the run**

```bash
git add .github/workflows/guards.yml
git commit -m "ci(guards): run the tools/ci invariant guards on every PR/push

The five static guards (config coverage, vfs seam, http helper reimpl,
sd driver conformance, file-size ratchet) were manual-only; the ratchet
drifted 18 violations as a result. Now enforced."
git push
gh run watch --exit-status "$(gh run list --workflow=guards.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```
Expected: run concludes `success`. If a guard fails only on CI (GNU grep vs ugrep divergence), fix the *script invocation portability* in the workflow — never weaken the guard.

---

### Task 3: `check_doc_paths.sh` — navigation docs must reference real paths

CLAUDE.md's OP→FILE tables are the primary entry point for humans and agents; after tree reorganizations (phases 66/67/69) they rot silently.

**Files:**
- Create: `tools/ci/check_doc_paths.sh`
- Modify: `.github/workflows/guards.yml` (append step)
- Possibly modify: `CLAUDE.md`, `README.md`, `docs/index.md` (fix any stale refs the guard finds — doc edits only)

**Interfaces:**
- Produces: `tools/ci/check_doc_paths.sh` (no args, exit 0/1) — referenced by Task 10's pre-push hook list.

- [ ] **Step 1: Write the guard**

```bash
#!/usr/bin/env bash
#
# check_doc_paths.sh — repo paths referenced by the navigation docs must exist.
#
# WHAT: Fails (exit 1) when CLAUDE.md, README.md, or docs/index.md references
#       a repo-relative path (src/…, tools/…, tests/…, docs/…, …) that does
#       not exist in the working tree.
#
# WHY:  The OP→FILE tables in CLAUDE.md are the fastest entry point into the
#       codebase for humans and agents. After tree-reorganization phases
#       (66/67/69 moved nearly every file) these references rot silently and
#       send readers to dead paths — the opposite of a fast entry point.
#
# HOW:  Extract path-shaped tokens rooted at a known top-level directory
#       (negative lookbehind so /tmp/foo/src/x.h does not match src/x.h),
#       drop globs/ellipses/placeholders, `test -e` each against the repo.
#
# USAGE:
#   tools/ci/check_doc_paths.sh    # exit 0 = clean, exit 1 = stale reference
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCS=("$REPO/CLAUDE.md" "$REPO/README.md" "$REPO/docs/index.md")

viol=0
for doc in "${DOCS[@]}"; do
    [ -f "$doc" ] || continue
    rel="${doc#"$REPO"/}"
    while IFS= read -r p; do
        p="${p%/}"                       # tolerate trailing slash on dir refs
        if [ ! -e "$REPO/$p" ]; then
            echo "FAIL $rel references missing path: $p"
            viol=1
        fi
    done < <(
        grep -oP '(?<![\w./-])(src|shared|client|tools|tests|docs|deploy|contrib|packaging|k8s-tests|utils)/[\w./-]+' "$doc" \
        | sed 's/[).,:;]*$//' \
        | grep -vE '[*<>]|…|\.\.\.' \
        | sort -u
    )
done

[ "$viol" -eq 0 ] && echo "check_doc_paths: OK"
exit "$viol"
```

Run: `chmod +x tools/ci/check_doc_paths.sh`

- [ ] **Step 2: Self-test — verify it FAILS on a fabricated stale reference**

```bash
cp CLAUDE.md /tmp/claude_backup.md
printf '\nBogus ref: `src/does/not/exist.c`\n' >> CLAUDE.md
tools/ci/check_doc_paths.sh; echo "exit=$?"
cp /tmp/claude_backup.md CLAUDE.md
```
Expected: `FAIL CLAUDE.md references missing path: src/does/not/exist.c`, `exit=1`. (Restore via `cp` — never `git checkout`.)

- [ ] **Step 3: Run for real; fix any genuine stale references it finds**

Run: `tools/ci/check_doc_paths.sh`
For each `FAIL`: find where the file moved (`git log --diff-filter=R --follow --oneline -- <old-path>` or `ls` the new bucket per `docs/refactor/phase-66-map.tsv`) and Edit the doc to the current path. If a reference is intentionally illustrative (not a real path), rewrite it so it doesn't look path-shaped — a `<placeholder>` segment right after the top-level dir stops the match. Known case: CLAUDE.md's BUILD & TEST examples use `tests/test_X.py` — rewrite as `tests/<test-file>.py` (verify the guard then passes). Re-run until `check_doc_paths: OK`.

- [ ] **Step 4: Add to guards.yml**

Append to the `steps:` list in `.github/workflows/guards.yml`:

```yaml
      - name: doc path drift — CLAUDE.md/README/index reference real paths
        if: '!cancelled()'
        run: tools/ci/check_doc_paths.sh
```

- [ ] **Step 5: Commit**

```bash
git add tools/ci/check_doc_paths.sh .github/workflows/guards.yml CLAUDE.md README.md docs/index.md
git commit -m "ci(guards): fail CI when navigation docs reference moved/deleted paths

CLAUDE.md's OP->FILE tables are the primary code entry point; phases
66/67/69 moved nearly every file and nothing caught the resulting rot."
```

---

### Task 4: `check_doc_links.sh` — relative markdown links must resolve (ratcheted)

**Files:**
- Create: `tools/ci/check_doc_links.sh`
- Create: `tools/ci/doc_links_backlog.txt` (generated by `--regen`)
- Modify: `.github/workflows/guards.yml` (append step)

**Interfaces:**
- Produces: `tools/ci/check_doc_links.sh [--regen]` — Task 5 (renumber) uses it as its verification oracle; Task 10 adds it to the pre-push hook.

- [ ] **Step 1: Write the guard**

```bash
#!/usr/bin/env bash
#
# check_doc_links.sh — relative markdown links must resolve.
#
# WHAT: Fails (exit 1) when a relative link target in docs/**/*.md, README.md,
#       or any src/**/README.md does not exist on disk. Pre-existing dead
#       links are frozen in doc_links_backlog.txt (ratchet: entries may only
#       disappear as links are fixed); anything NEW fails.
#
# WHY:  447+ markdown files and heavy cross-linking (docs/index.md routes by
#       link); nothing enforced link integrity, so every file move quietly
#       broke an unknown number of routes.
#
# HOW:  python3 stdlib walk; extract ](target) tokens; skip absolute URLs,
#       mailto:, in-page #anchors; resolve against the linking file's dir;
#       diff dead set against the backlog. Excluded: docs/_archive (archived
#       rot is accepted), docs/doxygen (generated), docs/superpowers
#       (plans/specs quote illustrative links inside code blocks).
#
# USAGE:
#   tools/ci/check_doc_links.sh            # gate; exit 1 on a NEW dead link
#   tools/ci/check_doc_links.sh --regen    # rewrite the backlog (review diff!)
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKLOG="$REPO/tools/ci/doc_links_backlog.txt"
MODE="${1:-check}"

python3 - "$REPO" "$BACKLOG" "$MODE" <<'PY'
import os, re, sys

repo, backlog_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
link_re = re.compile(r'\]\(([^)\s]+)\)')
SKIP_PREFIX = ('http://', 'https://', 'mailto:', '#', '/')
EXCLUDED = (os.path.join('docs', '_archive'), os.path.join('docs', 'doxygen'),
            os.path.join('docs', 'superpowers'))

def md_files():
    yield os.path.join(repo, 'README.md')
    for root in ('docs', 'src'):
        for base, _dirs, files in os.walk(os.path.join(repo, root)):
            rel = os.path.relpath(base, repo)
            if any(rel == e or rel.startswith(e + os.sep) for e in EXCLUDED):
                continue
            for f in files:
                if f.endswith('.md') and (root == 'docs' or f == 'README.md'):
                    yield os.path.join(base, f)

dead = set()
for path in md_files():
    if not os.path.isfile(path):
        continue
    rel = os.path.relpath(path, repo)
    with open(path, encoding='utf-8', errors='replace') as fh:
        text = fh.read()
    for m in link_re.finditer(text):
        target = m.group(1).split('#', 1)[0]
        if not target or target.startswith(SKIP_PREFIX) or '://' in target:
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
        if not os.path.exists(resolved):
            dead.add(f"{rel}\t{target}")

if mode == '--regen':
    with open(backlog_path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(sorted(dead)) + ('\n' if dead else ''))
    print(f"check_doc_links: wrote {len(dead)} frozen dead link(s) to backlog")
    sys.exit(0)

backlog = set()
if os.path.isfile(backlog_path):
    with open(backlog_path, encoding='utf-8') as fh:
        backlog = {l.rstrip('\n') for l in fh if l.strip()}

new = sorted(dead - backlog)
for entry in new:
    src, tgt = entry.split('\t', 1)
    print(f"FAIL new dead link: {src} -> {tgt}")
if new:
    print("check_doc_links: fix the link, or (pre-existing only) --regen after review")
    sys.exit(1)
print(f"check_doc_links: OK ({len(dead)} frozen in backlog)")
PY
```

Run: `chmod +x tools/ci/check_doc_links.sh`

- [ ] **Step 2: Generate the initial backlog and eyeball it**

Run: `tools/ci/check_doc_links.sh --regen && wc -l tools/ci/doc_links_backlog.txt && head -20 tools/ci/doc_links_backlog.txt`
Expected: some frozen count (unknown today — could be 0, could be dozens). Spot-check 3 entries: confirm each really is a dead relative link, not a parser false positive (if false positives appear, fix the regex/skip rules before freezing).

- [ ] **Step 3: Fix the cheap ones**

For backlog entries where the target obviously moved (e.g. old pre-phase-66 paths), Edit the linking doc to the current path, then `tools/ci/check_doc_links.sh --regen` to shrink the backlog. Time-box this to the obvious cases; the ratchet handles the rest over time.

- [ ] **Step 4: Verify gate mode passes and self-test failure mode**

```bash
tools/ci/check_doc_links.sh; echo "exit=$?"          # expect OK, exit=0
printf '\n[bogus](no/such/file.md)\n' >> docs/index.md
tools/ci/check_doc_links.sh; echo "exit=$?"          # expect FAIL new dead link, exit=1
# remove the bogus line again with the Edit tool (never git checkout)
tools/ci/check_doc_links.sh                          # expect OK
```

- [ ] **Step 5: Add to guards.yml and commit**

Append to `.github/workflows/guards.yml` steps:

```yaml
      - name: doc links — relative markdown links resolve
        if: '!cancelled()'
        run: tools/ci/check_doc_links.sh
```

```bash
git add tools/ci/check_doc_links.sh tools/ci/doc_links_backlog.txt .github/workflows/guards.yml docs
git commit -m "ci(guards): ratchet markdown link integrity across docs/ and src READMEs

Pre-existing dead links frozen in doc_links_backlog.txt (shrink-only);
new dead links fail CI. docs/_archive and generated doxygen excluded."
```

---

### Task 5: Renumber `docs/10-architecture` → `docs/11-architecture`

Two directories share the number 10 (`10-architecture`, `10-reference`), undermining the numeric navigation scheme. `10-architecture` has 39 inbound references vs 127 for `10-reference`, so it moves.

**Files:**
- Rename: `docs/10-architecture/` → `docs/11-architecture/` (git mv)
- Modify: every file referencing `10-architecture` (39 refs across ~17 files, incl. `README.md`, `docs/index.md`, `docs/_archive/`, `docs/refactor/`)

**Interfaces:**
- Consumes: `tools/ci/check_doc_links.sh` (Task 4) and `tools/ci/check_doc_paths.sh` (Task 3) as verification oracles.

- [ ] **Step 1: Move the directory**

Run: `git mv docs/10-architecture docs/11-architecture`

- [ ] **Step 2: Rewrite all references**

```bash
# docs/superpowers/ is excluded: plans/specs quote historical paths and this
# plan's own instructions must not be rewritten mid-execution.
command grep -rl '10-architecture' --include='*.md' --exclude-dir=superpowers . \
  | xargs sed -i 's/10-architecture/11-architecture/g'
command grep -rn '10-architecture' . --include='*.md' --exclude-dir=superpowers | wc -l   # expect 0
```

- [ ] **Step 3: Verify with the link and path guards**

```bash
tools/ci/check_doc_links.sh && tools/ci/check_doc_paths.sh
```
Expected: both OK. If the backlog contained `10-architecture` targets, run `tools/ci/check_doc_links.sh --regen` and confirm the diff only rewrites those entries.

- [ ] **Step 4: Commit**

```bash
git add -A docs README.md CLAUDE.md tools/ci/doc_links_backlog.txt
git commit -m "docs: renumber 10-architecture -> 11-architecture (numbering collision with 10-reference)"
```

---

### Task 6: Repair the stalled `docs-refresh.md` process

436 permanently-unchecked "Source Check 2" boxes signal an abandoned process and erode trust in the checks that *were* done.

**Files:**
- Modify: `docs/10-reference/docs-refresh.md`

- [ ] **Step 1: Drop the dead column and add a status note**

```bash
python3 - <<'PY'
import re
p = 'docs/10-reference/docs-refresh.md'
out = []
for line in open(p, encoding='utf-8'):
    cells = line.rstrip('\n').split('|')
    # table rows have 6 pipes: ['', ' File ', ' Check1 ', ' Check2 ', ' Verified ', '']
    if len(cells) == 6:
        del cells[3]
        line = '|'.join(cells) + '\n'
    out.append(line)
open(p, 'w', encoding='utf-8').write(''.join(out))
PY
```

Then Edit the header area (below the `**Purpose:**` line) to add:

```markdown
> **Status (2026-07-07):** the planned second verification pass never ran and
> its column has been removed. Every file below has one completed source check.
> Re-verification now happens opportunistically: when you materially edit a
> file, re-check its docs and update its row.
```

- [ ] **Step 2: Verify the table still renders (all rows same column count) and commit**

```bash
awk -F'|' 'NF>1 && NF!=6 {print NR": "NF" cols: "$0}' docs/10-reference/docs-refresh.md | head
```
Expected: only non-table lines (or nothing). Fix stragglers with Edit if any row has the wrong count.

```bash
git add docs/10-reference/docs-refresh.md
git commit -m "docs(refresh): drop the never-run second-check column; re-verify on touch instead"
```

---

### Task 7: READMEs for the root:// protocol tree

`src/protocols/root/` — the largest, most intricate subsystem — has no top-level README. Its *subdirectories* mostly do (e.g. `connection/README.md`); first enumerate which are missing, then write the top-level map plus any missing subdir READMEs.

House format (from `src/protocols/root/connection/README.md`): title `# dirname — one-line description`; **Overview** (3–5 paragraphs: purpose, entry point, lifecycle); **Files** table (file → one-sentence responsibility); **Control & data flow**; **Invariants, security & gotchas** (numbered); **See also** (relative links). Match that register — factual, load-bearing, no filler.

**Files:**
- Create: `src/protocols/root/README.md`
- Create: `src/protocols/root/<subdir>/README.md` for each subdir missing one (enumerate in Step 1)

**Interfaces:**
- Produces: READMEs that Task 9's coverage guard (and `check_doc_links.sh`) will validate.

- [ ] **Step 1: Enumerate missing subdir READMEs**

Run: `for d in src/protocols/root/*/; do [ -f "$d/README.md" ] || echo "MISSING $d"; done`

- [ ] **Step 2: Write `src/protocols/root/README.md`**

Content requirements — a subsystem map, not a tutorial:

```markdown
# root — the XRootD (`root://` / `roots://`) protocol plane

## Overview

Everything needed to speak the XRootD wire protocol lives under this
directory: TCP/TLS connection lifecycle, request framing, opcode dispatch,
the session/auth handshake, and one subdirectory per opcode family. The
per-connection entry point is `ngx_stream_brix_handler()`
(connection/handler.c), installed by the stream module descriptor in
stream/module.c. After framing (connection/recv.c), every complete request
passes through `brix_dispatch()` (handshake/dispatch.c), which routes by
opcode to the family dispatchers and on to the handlers below. All storage
access goes through the VFS seam (../../fs/vfs/) — no raw I/O here.

## Subdirectories

| Dir | Responsibility | Entry point |
|---|---|---|
| connection/ | TCP lifecycle, recv/send state machine, fd table, TLS upgrade | handler.c |
| stream/ | nginx stream-module descriptor + config lifecycle | module.c |
| handshake/ | opcode routers (read/write/session/signing) + auth gate + policy | dispatch.c |
| session/ | login, protocol negotiation, bind, ping/endsess, sigver, SHM session registry | (dispatched) |
| protocol/ | header-only wire-format constants, opcodes, codecs (mirror of XProtocol.hh) | — |
| read/ | kXR_open/read/readv/pgread/stat/locate/close/clone + prefetch | open_request.c |
| write/ | kXR_write/pgwrite/writev/sync/truncate + namespace ops (mkdir/rm/mv/chmod) + chkpoint | (dispatched) |
| dirlist/ | kXR_dirlist + per-entry checksum (cks.type CGI) | handler.c |
| fattr/ | kXR_fattr get/set/del/list via the VFS xattr seam | dispatch.c |
| zip/ | ?xrdcl.unzip= archive-member serving (security-critical read-only ZIP locator) | zip_http.c |
| path/ | wire-path extraction, sanitization, CGI stripping, stat-body formatting | extract.c |
| response/ | wire response framing: basic, async kXR_attn, kXR_status(4007), CRC32c | basic.c |
| handoff/ | non-XRootD clients on a root:// port handed off to HTTP | handoff.c |
| relay/ | transparent pass-through relay + tap + bad-actor guard hook | relay.c |
| query/ | kXR_query / kXR_prepare | (dispatched) |

## Control & data flow

accept → connection/handler.c (ctx + session id) → connection/recv.c
(frame: 20B hello → 24B header → dlen payload) → handshake/dispatch.c →
dispatch_{read,write,session,signing}.c → opcode handler → response/*.c →
connection/write_helpers.c (out_ring FIFO) → send.

## Invariants, security & gotchas

1. Every wire path is resolved through the VFS/`resolve_path()` seam before
   any open — no exceptions (CLAUDE.md INVARIANT 4).
2. pgread/pgwrite responses use kXR_status(4007) framing with per-page
   CRC32c (INVARIANT 1).
3. TLS buffers are memory-backed only; cleartext uses file-backed+sendfile;
   never mix (INVARIANT 2).
4. File handles are 0–255 indexes into the per-session fd table
   (connection/fd_table.c) — never kernel fds on the wire.
5. SHM tables (session registry, TPC keys) use spin+yield mutexes via
   brix_shm_table_alloc() — never POSIX-semaphore mode (INVARIANT 10).

## See also

- [connection/README.md](connection/README.md) — the async I/O spine
- [../../fs/README.md](../../fs/README.md) — the VFS storage seam
- [../../tpc/](../../tpc/) — third-party-copy engine reached from read/open_request.c
- Wire spec: XProtocol.hh (see CLAUDE.md header)
```

Verify each table row against reality before writing (e.g. confirm `query/` exists: `ls src/protocols/root/`). Adjust rows to the actual directory list from Step 1.

- [ ] **Step 3: Write READMEs for missing subdirs found in Step 1**

For each, use the per-file purposes below (already extracted from the files' own doc headers) as the Files-table content, in the house format. Full inventories:

**session/** — login.c (LOGIN metric + login handling), protocol.c (kXR_protocol capability negotiation), bind.c (kXR_bind secondary data channel), handles.c (SHM handle table for bind validation), lifecycle.c (kXR_ping/kXR_endsess), signing.c (kXR_sigver HMAC verification), registry.c/.h (SHM cross-worker session registry), session.h (login-sequence contract), tls_config.c (SSL ctx for in-protocol TLS upgrade). Entry: dispatched from handshake/dispatch_session.c; auth gate enforced before login completes.

**protocol/** — header-only. protocol.h (wire constants/structs), wire*.h (layout fragments: core requests, extended writes, vendor ext), frame_hdr.h (unaligned-safe BE accessors, pure codecs), opcodes.h, types.h (XProtocol.hh aliases), bootstrap_pack.h, flags.h/open_flags.h, gsi.h, sec_protocol.h, sss.h, qspace.h, readv_seg.h, stat_flags.h/stat_line.h, dirlist_fmt.h. Note: mirror of the canonical XProtocol.hh — change only against the wire spec.

**handshake/** — dispatch.c (main opcode router, per-request timing origin), dispatch_read.c / dispatch_write.c / dispatch_session.c (auth-gate before login) / dispatch_signing.c, client_hello.c (v5 handshake), policy.c (per-connection policy enforcement), sigver.c (request-signing verify half), handshake.h.

**read/** — open_request.c (kXR_open: TPC detect, manager redirect, cache), open_overview.c, open_cache.c (XCache-style read-open + full auth gate), open_resolved_file.c (VFS confined open/probe), read.c/readv.c/pgread.c (I/O via SD seam; pgread pages + CRC), read_compress.c, close.c, clone.c (kXR_clone range copy), locate.c, stat.c/statx.c (VFS stat), prefetch.c (FADV_WILLNEED), plus headers.

**write/** — write.c (+dirty-state tracking), writev.c (descriptor-framed; body streamed — see writev framing fix), pgwrite.c (+uncorrected-page registry), pgw_fob.c, write_compress.c, wrts_journal.c (per-handle write ring), chkpoint.c/chkpoint_xeq.c (checkpoint + execute via VFS), sync.c, truncate.c, mkdir.c, rmdir.c, rm.c, mv.c (VFS confined rename), chmod.c, common.c, op_table.c, ext_ops.c (POSIX-completeness setattr/symlink/link), plus headers.

**zip/** — zip_kernel.c/.h (security-critical read-only ZIP record locator), zip_dir.c (directory reads via SD), zip_http.c (confined archive open; extracts ?xrdcl.unzip=), zip_member.c (member as standalone read handle), zip_dir_unittest.c.

**stream/** — module.c (stream module descriptor + config lifecycle), module_definition.c, module_enums.c/.h.

**handoff/** — handoff.c/.h (non-XRootD client on root:// port → HTTP handoff pump, stall detection).

**relay/** — relay.c (transparent pass-through when brix_transparent_proxy set; engages at top of stream handler), relay_guard.c (tap frames → pure-C guard core), relay.h.

**response/** — basic.c (ServerResponseHdr framing), async.c (kXR_attn server push), control.c (incl. brix_format_host IPv6 bracketing), crc32c.c (compat wrappers), status.c (kXR_status 4007 for paged ops), response.h.

**path/** — extract.c (wire path extraction + sanitize), op_path.c (existence/type pre-gate via VFS; note trailing-slash parent-gate fix), stat_body.c, strip_cgi.c, op_path.h.

**dirlist/** — handler.c (kXR_dirlist + dstat lead-in sentinel), dcksm.c/.h (cks.type= CGI per-entry checksum), dirlist.h.

**fattr/** — dispatch.c (validate fattr header; open- vs path-based target), get.c/set.c/del.c/list.c, helpers.c (POSIX→kXR error mapping), ngx_brix_fattr.h (VFS xattr seam decls), fattr.h.

- [ ] **Step 4: Verify links and commit**

```bash
tools/ci/check_doc_links.sh
git add src/protocols/root
git commit -m "docs(root): subsystem map README + missing subdir READMEs for the root:// protocol tree"
```

---### Task 8: READMEs for auth/authz, tpc/*, cvmfs, net/tap, fs/tier, fs/meta, accesslog + bucket indexes

**Files:**
- Create: `src/auth/authz/README.md`, `src/tpc/engine/README.md`, `src/tpc/gsi/README.md`, `src/tpc/outbound/README.md`, `src/protocols/cvmfs/README.md`, `src/net/tap/README.md`, `src/fs/tier/README.md`, `src/fs/meta/README.md`, `src/observability/accesslog/README.md`
- Create (short bucket indexes): `src/auth/README.md`, `src/core/README.md`, `src/net/README.md`, `src/observability/README.md`, `src/protocols/README.md`

**Interfaces:**
- Produces: the README set Task 9's guard requires.

- [ ] **Step 1: Write `src/auth/authz/README.md`** (complete exemplar — write verbatim, verifying each claim against the files first):

```markdown
# authz — path-level authorization: ACL rules, authdb, and the auth gate

## Overview

This directory decides *whether an authenticated identity may perform an
operation on a path*. Identity establishment (GSI, tokens, SSS, krb5…)
lives in the sibling directories; everything here runs after identity is
known. It is security-load-bearing: the auth gate is the SOLE authorization
checkpoint for cached serves (see the 2026-07-06 cache-authz fix — serve
and fill helpers are deliberately auth-free so this gate cannot be
bypassed).

Two rule sources are compiled at postconfig: VO ACL rules (acl.c) and
authdb rules (authdb.c), both resolved against the export root so runtime
matching is pure string work. Runtime lookups use longest-prefix matching
(find_rule.c). A tiny lockless direct-mapped L1 cache (auth_gate_l1.c,
~48 B/entry) short-circuits repeated identical checks on hot paths; its
counters are exported via auth_gate.c.

## Files

| File | Responsibility |
|---|---|
| acl.c | postconfig finalization of the VO-rule array (resolve against root) |
| authdb.c | postconfig finalization of the authdb rule array |
| find_rule.c | longest-prefix rule matching for path policies |
| group_policy.c | parent-directory group-policy inheritance for mkdir |
| auth_gate.c / auth_gate.h | the gate entry point + L1 counters |
| auth_gate_l1.c / auth_gate_l1.h | lockless direct-mapped L1 auth-decision cache |
| auth_cache.c / auth_cache.h | per-conf auth cache settings (brix_auth_cache directive) |

## Invariants, security & gotchas

1. The gate is the sole authorization checkpoint on the cached-read path
   (root/read/open_cache.c runs the FULL gate, not VO-only). Never add a
   serve path that skips it.
2. `conf->allow_write` is checked globally before token scope
   (CLAUDE.md INVARIANT 3).
3. Longest-prefix semantics: a more specific rule always wins; ordering in
   the config must not matter.
4. The L1 cache stores *decisions*, keyed by identity+path — any change to
   rule semantics must consider stale-entry lifetime.

## See also

- [../gsi/README.md](../gsi/README.md), [../token/README.md](../token/README.md) — identity establishment
- [../../protocols/root/read/](../../protocols/root/read/) — open_cache.c, the hot caller
- docs/09-developer-guide/cache-authz-best-practice.md
```

Before committing, verify: the directive name in auth_cache.h, the L1 entry size, and that the See-also targets exist (`check_doc_links.sh` will catch missing ones).

- [ ] **Step 2: Write the remaining eight subsystem READMEs** in the same format, from these inventories (verify against file doc headers while writing):

**src/tpc/engine/** — the native-TPC control plane on the destination side. launch.c (TPC pull entry, called from root/read/open_request.c), parse.c (TPC opaque query-string → structs), done.c (thread-pool→event-loop completion handoff), key_registry.c/.h (SHM TPC key table — cross-process, zero-copy rendezvous; INVARIANT: SHM spin+yield mutex), noop.c (refusing stand-ins when native TPC compiled out), tpc_internal.h. See-also: ../outbound/, ../gsi/, src/protocols/webdav/tpc.c (the *other*, curl-based TPC).

**src/tpc/gsi/** — outbound GSI auth for the TPC pull socket: gsi_outbound_certreq.c (initiate handshake), gsi_outbound_exchange.c (complete handshake), gsi_outbound_common.c (kXR_authmore continuation, JWT or GSI), gsi_outbound_finish.c (auth-path selection from server response). Called from ../outbound/bootstrap.c; runs on the blocking thread-pool path, never the event loop.

**src/tpc/outbound/** — the source-session client (blocking, thread-pool): thread.c (worker: full source-side pull), bootstrap.c (anonymous session 3-step handshake), connect.c (getaddrinfo + candidate validation), io.c (blocking I/O primitives), source.c (complete the pull), tls.c (blocking client TLS handshake), tpc_token.c (OAuth2/OIDC token fetch). Entry: brix_tpc_pull_thread() posted by ../engine/launch.c. Gotcha: event-loop code must never call into here.

**src/protocols/cvmfs/** — cvmfs:// site cache (+ experimental scvmfs://): module.c (config lifecycle + directive table + handler install), handler.c (location entry point), gate.c (access restriction, first step), secure.c (transport + client-authz gate before the cvmfs gate), classify.h, request.c (absolute-form request lines), geo.c (forward to upstream), geo_answer.c (RTT-measured upstream ranking, port-guard 80/443/8000), origin_geo.c/.h (haversine + stable argsort), origin_probe.c (per-worker origin latency timer), upstreams.c ((host,port)→synthetic VFS backend export). Fill path: src/protocols/shared/http_cache_fill.c (coalescing+hold) + src/fs/cache/verify.c (cvmfs-cas). Test ports 12831–12904.

**src/net/tap/** — ngx-free protocol observation tap: tap.h (frame descriptor + sink fan-out contract), tap_decode.c (wire→frames, path vs non-path opcodes), tap_stream.c (streaming decoder; C2U skips the 20-byte handshake preamble; kXR_writev/chkpoint descriptor-only framing), tap_emit.c (sink fan-out), tap_audit.c (opcode→name for audit JSON). Consumers: root/relay/, net/proxy/. Gotcha: never capture a connection's ngx_log_t into a sink (stale handler → SIGSEGV) — keep a scrubbed copy.

**src/fs/tier/** — composable storage tiers (phase-64 SP1): tier.h (POD types, up to three tiers), tier_config.c (directive → tier spec; brix_prepare_export_root), tier_build.c (compose SD decorators via the registry, e.g. cache_store over origin). Consumed by all three protocols' unified storage directives (src/core/config/http_common.c).

**src/fs/meta/** — unified per-file metadata sidecar: xmeta.c/.h (encode/decode; byte-identical successor to .cinfo/XCI1/.xrdt), xmeta_carrier.c/.h (sidecar key "<key>.cinfo" persist/load for store objects), xmeta_path.c/.h (load/save/remove by absolute local path), xmeta_unittest.c. Invariant: encoding is an on-disk compatibility contract — never change layout without a versioned reader.

**src/observability/accesslog/** — run `ls src/observability/accesslog/` and read each file's doc header (same extraction as above); write the README from those. If the directory turns out to have <2 C files, skip it (the Task 9 guard won't require it).

- [ ] **Step 3: Write the five bucket-index READMEs** — short (10–20 lines each): one paragraph on the bucket's concept (crib from the SRC TOPOLOGY block in CLAUDE.md) + a table linking each subdir to its README. Example shape for `src/net/README.md`:

```markdown
# net — clustering, proxying, shadowing, and connection defense

Everything that makes one brix node talk to *other servers* (or defend
itself from clients): CMS cluster membership, manager-mode redirection,
upstream proxying, rate limiting, the observation tap, mirroring, and the
bad-actor guard.

| Dir | What | README |
|---|---|---|
| cms/ | CMS protocol client (manager heartbeat/registration) | [cms/README.md](cms/README.md) |
| manager/ | manager-mode registry + redirection | [manager/README.md](manager/README.md) |
| upstream/ | upstream session handling for proxy mode | [upstream/README.md](upstream/README.md) |
| proxy/ | terminating reverse proxy (tap-enabled) | [proxy/README.md](proxy/README.md) |
| ratelimit/ | SHM token-bucket rate limiting | [ratelimit/README.md](ratelimit/README.md) |
| tap/ | ngx-free wire observation tap | [tap/README.md](tap/README.md) |
| mirror/ | request mirroring | [mirror/README.md](mirror/README.md) |
| guard/ + httpguard/ | bad-actor detection core + HTTP module | [guard/README.md](guard/README.md) |
```

Verify each row against `ls src/net/` and the actual README filenames before writing; same pattern for auth, core, observability, protocols.

- [ ] **Step 4: Verify and commit**

```bash
tools/ci/check_doc_links.sh
git add src/auth src/core src/net src/observability src/protocols src/tpc src/fs
git commit -m "docs(src): READMEs for authz, tpc, cvmfs, tap, tier, meta + bucket indexes"
```

---

### Task 9: `check_readme_coverage.sh` — README coverage becomes a ratchet

**Files:**
- Create: `tools/ci/check_readme_coverage.sh`
- Modify: `.github/workflows/guards.yml` (append step)

**Interfaces:**
- Consumes: the READMEs from Tasks 7–8 (guard must land green).
- Produces: `tools/ci/check_readme_coverage.sh` (no args, exit 0/1) for Task 10's hook list.

- [ ] **Step 1: Write the guard**

```bash
#!/usr/bin/env bash
#
# check_readme_coverage.sh — substantial src/ directories must carry a README.
#
# WHAT: Fails (exit 1) when a directory at depth 1–2 under src/ contains two
#       or more C sources (*.c/*.h, non-recursive) but no README.md.
#
# WHY:  READMEs are the orientation layer for auditors; coverage decayed
#       exactly on the hardest directories (protocols/root, auth/authz,
#       tpc/*) until 2026-07-07. This makes coverage a ratchet: a new
#       subsystem directory ships with its README or CI is red.
#
# HOW:  find depth-1/2 dirs, count immediate C sources, require README.md
#       when the count is >= 2. Depth-3+ (e.g. protocols/root/*) is
#       encouraged but not gated.
#
# USAGE:
#   tools/ci/check_readme_coverage.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

viol=0
while IFS= read -r d; do
    n="$(find "$d" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) | wc -l)"
    if [ "$n" -ge 2 ] && [ ! -f "$d/README.md" ]; then
        echo "FAIL missing README.md: ${d#"$REPO"/}/ ($n C sources)"
        viol=1
    fi
done < <(find "$REPO/src" -mindepth 1 -maxdepth 2 -type d | sort)

[ "$viol" -eq 0 ] && echo "check_readme_coverage: OK"
exit "$viol"
```

Run: `chmod +x tools/ci/check_readme_coverage.sh && tools/ci/check_readme_coverage.sh`
Expected: `OK`. If it reports a directory Tasks 7–8 missed, write that README now (same method) rather than weakening the guard.

- [ ] **Step 2: Add to guards.yml and commit**

```yaml
      - name: readme coverage — substantial src/ dirs are documented
        if: '!cancelled()'
        run: tools/ci/check_readme_coverage.sh
```

```bash
git add tools/ci/check_readme_coverage.sh .github/workflows/guards.yml
git commit -m "ci(guards): require a README in any depth<=2 src/ dir with >=2 C sources"
```

---

### Task 10: Ports registry doc + settings.py consistency guard

`tests/settings.py` (lines ~111–519) is already the single source of truth: 95+ named `*_PORT*` constants, env-overridable. The doc makes the map human-scannable; the guard keeps it complete.

**Files:**
- Create: `docs/10-reference/test-fleet-ports.md`
- Create: `tools/ci/check_ports_doc.sh`
- Modify: `.github/workflows/guards.yml` (append step)

- [ ] **Step 1: Write `docs/10-reference/test-fleet-ports.md`**

Header (verbatim):

```markdown
# Test-fleet ports registry

**Source of truth:** [`tests/settings.py`](../../tests/settings.py) — every
constant below is env-overridable (`TEST_<NAME>`). Secondary allocators:
`tests/cms_mesh_lib.py` (21610–21749), `tests/hybrid_mesh_lib.py`
(11300–11330), `tests/lib/dedicated.sh` (launch orchestration),
`tests/run_cvmfs_*.sh` (ad-hoc 12831–12904).
`tools/ci/check_ports_doc.sh` fails CI when a settings.py port constant is
missing from this page.

First stop when a test fails with a connection error: find the port here,
then `ss -tlnp | grep <port>` to see whether that instance is actually up.
```

Then one table per service family, columns `Port | Constant | Protocol | Auth | Purpose`. Populate from this inventory (verified against settings.py on 2026-07-07 — spot-check ~5 rows against the file while writing):

- **Primary fleet:** 11094 NGINX_ANON_PORT root/anon (main entry, resume-ON); 11095 NGINX_GSI_PORT root/GSI; 11096 NGINX_GSI_TLS_PORT roots/GSI+TLS; 11097 NGINX_TOKEN_PORT root/token; 11119 NGINX_TOKEN_STRICT_PORT root/token zero-skew; 8443 NGINX_WEBDAV_PORT davs/no-auth; 8444 NGINX_WEBDAV_GSI_TLS_PORT davs/GSI; 8080 NGINX_HTTP_WEBDAV_PORT http/anon; 9001 NGINX_S3_PORT; 9002 NGINX_S3_TOKEN_PORT; 9100 NGINX_METRICS_PORT.
- **Token conformance:** 11250 NGINX_TOKEN_MULTIKEY_PORT (jwks_multi.json); 11251 NGINX_TOKEN_REGISTRY_PORT (scitokens.cfg); 8446 NGINX_WEBDAV_TOKEN_PORT.
- **Reference/stock fleet:** 11098 REF_BRIX_PORT; 11099 REF_BRIX_GSI_PORT; 11100 REF_BRIX_GSI_SHARED_PORT; 11112 XRDHTTP_ROOT_PORT; 11113 XRDHTTP_HTTP_PORT; 12988 XRDHTTP_DIGEST_PORT.
- **krb5 tier:** 11116 NGINX_KRB5_PORT; 11117 KRB5_KDC_PORT (skipped cleanly without MIT KDC tooling).
- **CRL/PKI:** 11104 CRL_PORT; 11105 WEBDAV_CRL_PORT; 11106 CRL_DIR_PORT; 11107 WEBDAV_DIR_PORT; 11108 CRL_RELOAD_PORT; 11109 CRL_RELOAD_HTTP_PORT.
- **TPC & SSRF:** 11110 ROOT_TPC_NGINX_PORT; 11111 ROOT_TPC_REF_PORT; 11180–11182 TPC_SSRF_{DEFAULT,ALLOW_LOCAL,DENY_PRIVATE}_PORT; 18450–18456 WEBDAV_TPC_* (source required/open, dest cafile/cadir/no-service-cert/disabled/readonly).
- **Upstream proxy tier:** 11120–11126 UPSTREAM_*_NGINX_PORT (redirect/wait/waitresp/error/auth/auth-nofile/gotoTLS-noTLS) ↔ 12120–12126 UPSTREAM_*_BACKEND_PORT (real xrootd backends); 13120–13126 STUB_*_BACKEND_PORT (python protocol stubs) ↔ 11130–11136 STUB_*_NGINX_PORT.
- **Cluster/CMS topologies:** 11160–11199 + 12399–12608 (CLUSTER_*, CHAOS_*, CMS_TEST_*) — copy every constant from settings.py lines ~306–383; 29000–29012 phantom-DS stub ports.
- **Features:** 11101 MANAGER_PORT; 11102 READONLY_PORT; 11103 VO_PORT; 11114 AUTHDB_PORT; 11115 NGINX_JWKS_REFRESH_PORT; 11183–11184 S3_PRESIGNED{,_STS}_PORT; 11191–11192 SECURITY_LEVEL_{STANDARD,PEDANTIC}_PORT; 11200–11202 CACHE_ONLY/WT_SYNC/WT_ASYNC; 11203 PROXY_DEAD_NGINX_PORT (+19999 PROXY_DEAD_UPSTREAM_PORT); 11204–11205 PREPARE_{CMD,NOCMD}_PORT; 11206–11209 META_ONLY/SUPERVISOR/VIRTUAL_REDIR/COLLAPSE_REDIR; 11210–11212 HA_*; 11213–11215 PROXY_PURE/PROXY_BRIDGE/CREDENTIAL_BRIDGE; 11216–11217 READONLY_HTTP_{DAV,S3}_PORT; 18444–18445 WEBDAV_AUTH_CACHE_*; 18457 NGINX_HTTP_CACHE_PORT; 18458 NGINX_WEBDAV_VOMS_PORT.
- **Migrated dedicated instances:** 12980 OPEN_FLAGS_LIFECYCLE_NGINX_PORT; 13210 WEBDAV_DELLOCK_PORT; 22014 WEBDAV_UNLOCK_OWNERSHIP_PORT; 22017 S3_MPU_PORT.
- **IPv6 tier ([::1]):** 11240–11247 IPV6_* (stream, mgr+cms+http, webdav, s3, upstream, proxy).
- **Mesh bands:** cms_mesh_lib.py 21610–21749 (18 topologies, table of ranges); hybrid_mesh_lib.py 11300–11330 (tier-1 nginx redirector → tier-2 xrootd, per-port table).
- **cvmfs suites:** 12831–12904 ad-hoc per `tests/run_cvmfs_*.sh` (range table per script).

The full 95+ constant list MUST come from `command grep -oE '^[A-Z][A-Z0-9_]*PORT[A-Z0-9_]*' tests/settings.py | sort -u` — the guard in Step 2 enforces completeness, so write the doc until the guard passes rather than trusting this plan's snapshot.

- [ ] **Step 2: Write `tools/ci/check_ports_doc.sh`**

```bash
#!/usr/bin/env bash
#
# check_ports_doc.sh — every named port constant is in the ports registry doc.
#
# WHAT: Fails (exit 1) when a *_PORT* constant assigned in tests/settings.py
#       does not appear (by name) in docs/10-reference/test-fleet-ports.md.
#
# WHY:  settings.py is the machine source of truth; the registry doc is the
#       human map. A constant added without a registry row is undocumented
#       infrastructure — exactly the drift this doc exists to prevent.
#
# HOW:  Extract assigned ALL-CAPS names containing PORT from settings.py,
#       grep each in the doc.
#
# USAGE:
#   tools/ci/check_ports_doc.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="$REPO/docs/10-reference/test-fleet-ports.md"
SRC="$REPO/tests/settings.py"

[ -f "$DOC" ] || { echo "FAIL registry doc missing: ${DOC#"$REPO"/}"; exit 1; }

viol=0
while IFS= read -r name; do
    if ! grep -q "$name" "$DOC"; then
        echo "FAIL undocumented port constant: $name (add a row to ${DOC#"$REPO"/})"
        viol=1
    fi
done < <(grep -oE '^[A-Z][A-Z0-9_]*PORT[A-Z0-9_]*[[:space:]]*=' "$SRC" | tr -d ' =' | sort -u)

[ "$viol" -eq 0 ] && echo "check_ports_doc: OK"
exit "$viol"
```

Run: `chmod +x tools/ci/check_ports_doc.sh && tools/ci/check_ports_doc.sh`
Iterate on the doc until `OK` (every reported constant gets a row — that's the doc-writing loop, guard-driven).

- [ ] **Step 3: Add to guards.yml, verify links, commit**

```yaml
      - name: ports registry — settings.py constants all documented
        if: '!cancelled()'
        run: tools/ci/check_ports_doc.sh
```

```bash
tools/ci/check_doc_links.sh
git add docs/10-reference/test-fleet-ports.md tools/ci/check_ports_doc.sh .github/workflows/guards.yml
git commit -m "docs(tests): guard-enforced test-fleet ports registry (settings.py is source of truth)"
```

---

### Task 11: Symptom-indexed troubleshooting runbook

**Files:**
- Create: `docs/05-operations/troubleshooting-runbook.md`
- Modify: `CLAUDE.md` (one line in the DEBUG section linking to the runbook)

- [ ] **Step 1: Write the runbook.** Structure: a symptom index table up top (Symptom | First check | Section), then one short section per failure mode: what you see, root cause, diagnosis commands, fix, and a link to the postmortem/doc if one exists. Cover at minimum these known failure modes (each is real, previously diagnosed here):

1. **Worker frozen / connections stall under multi-worker concurrency** — `ss -tn` Recv-Q, `/proc/PID/wchan` (`futex_do_wait` = lock; `do_epoll_wait` = lost notify), GDB `thread apply all bt`; SHM semaphore lost-wakeup → `docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md`; INVARIANT 10.
2. **kXR_FileLocked hangs / cache-fill pool exhaustion** — orphaned workers from a killed test run poisoning locks; check `pgrep -af nginx`, stale pidfiles; dead-owner O_EXCL lock reclaim exists (kill(pid,0)==ESRCH) but orphans must be killed via killpg on the *correct* pidfile.
3. **root:// handshake timeouts + phantom EXDEV on staged PUT/MOVE** — orphaned dead FUSE mount (`/tmp/fusetest/mnt`, wchan=`request_wait_answer`) wedging unrelated workers; fix `fusermount -u -z` + restart the node. Looks like a cache/staging regression; isn't.
4. **Dedicated token-fleet ports desync after rebuilding src** — a start-all from a src-fix session leaves dedicated instances on the old binary; clean `stop-all` + `start-all`, then re-run.
5. **Whole pytest run aborts "Different tests collected"** — xdist worker cwd wiped (fixed in conftest, but the signature is worth documenting); also `-n16` crashes workers on this fleet — cap at `-n12`; repeated heavy runs degrade the box → reset between runs.
6. **Manual TPC/fleet suddenly dead after a pytest run** — conftest previously wiped the fleet on teardown (fixed: auto-attach; `TEST_OWN_FLEET=1` forces clean restart and must run SERIAL).
7. **`./configure` builds a bare nginx (module silently absent)** — `REPO` unset/empty in `--add-module=$REPO`; export REPO or use a literal path; check `objs/nginx -V` output for the module.
8. **Connection refused on a test port** — the ports registry (`docs/10-reference/test-fleet-ports.md`) + `ss -tlnp | grep <port>` + `tests/manage_test_servers.sh start-all`.
9. **Auth failures** — cert dates (`openssl x509 -noout -dates`), `brix_trusted_ca` expects a FILE not a dir, proxy certs need RFC3820 path, token clock-skew port (11119) intentionally strict.
10. **Debug tooling quick reference** — `XRD_LOGLEVEL=Debug xrdcp`, nginx `error_log ... debug`, log locations `/tmp/xrd-test/logs/`, `pkill -9 nginx` (never `-f objs/nginx` — misses workers).

- [ ] **Step 2: Link it from CLAUDE.md.** In the `## DEBUG` section, after the table, add:

```markdown
**Full symptom-indexed runbook:** [docs/05-operations/troubleshooting-runbook.md](docs/05-operations/troubleshooting-runbook.md)
```

- [ ] **Step 3: Verify guards and commit**

```bash
tools/ci/check_doc_links.sh && tools/ci/check_doc_paths.sh
git add docs/05-operations/troubleshooting-runbook.md CLAUDE.md
git commit -m "docs(ops): symptom-indexed troubleshooting runbook from accumulated postmortems"
```

---

### Task 12: Publish Doxygen API docs alongside the site

`tools/gen-docs.sh` already builds browsable API docs (`doxygen Doxyfile` → `docs/doxygen/html/`), but only locally. `site.yml` publishes `site/dist` to `gh-pages` via peaceiris (which replaces branch content), so the doxygen output must ride in the same publish step.

**Files:**
- Modify: `.github/workflows/site.yml`

- [ ] **Step 1: Extend the trigger paths**

Change the `on.push.paths` line to:

```yaml
    paths: ['site/**', 'src/**', 'client/**', 'shared/**', 'Doxyfile', '.github/workflows/site.yml']
```

- [ ] **Step 2: Insert the doxygen build between the site `Build` step and `Publish to gh-pages`**

```yaml
      - name: Install doxygen
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends doxygen graphviz

      - name: Build API docs
        run: doxygen Doxyfile

      - name: Stage API docs under /apidocs
        run: |
          mkdir -p site/dist/apidocs
          cp -r docs/doxygen/html/. site/dist/apidocs/
```

- [ ] **Step 3: Sanity-check the Doxyfile output path assumption**

Run: `command grep -E '^(OUTPUT_DIRECTORY|HTML_OUTPUT)' Doxyfile`
Expected: resolves to `docs/doxygen` + `html` (matching `tools/gen-docs.sh`). If different, adjust the `cp` path in Step 2 to match.

- [ ] **Step 4: Commit, push, verify**

```bash
git add .github/workflows/site.yml
git commit -m "ci(site): build and publish doxygen API docs at /apidocs on gh-pages"
git push
gh run watch --exit-status "$(gh run list --workflow=site.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```
Then confirm the published page serves (URL = the existing gh-pages URL + `/apidocs/`). If doxygen errors on CI (version differences), pin the failing config keys in Doxyfile rather than skipping the step.

---

### Task 13: `tools/ci/README.md`, dual size-regime documentation, hook install docs, guards in pre-push

**Files:**
- Create: `tools/ci/README.md`
- Modify: `tools/git-hooks/pre-push` (add guard loop before the fast test tier)
- Modify: `docs/09-developer-guide/dev-workflow.md` (hooks + clangd section)

- [ ] **Step 1: Write `tools/ci/README.md`.** Contents: one table of all guards (script | invariant enforced | backlog file | regen flag) covering `check_config_coverage.sh`, `check_vfs_seam.sh` (backlogs: `vfs_seam_backlog.txt`, `_ns`, `_client`), `check_http_helper_reimpl.sh`, `check_sd_driver_conformance.sh`, `check_file_size.sh` (`file_size_backlog.txt`), `check_doc_paths.sh`, `check_doc_links.sh` (`doc_links_backlog.txt`), `check_readme_coverage.sh`, `check_ports_doc.sh`, `run_fanalyzer.sh` (`fanalyzer_baseline.txt`, needs a configured nginx build). Then two prose sections, verbatim requirements:

**"The ratchet pattern"**: backlogs freeze pre-existing violations; entries may only shrink; `--regen` only after a deliberate reviewed change; never hand-edit a backlog to silence a failure.

**"Two file-size regimes (both intentional)"**: `tests/lint_loc.sh --strict` is the *hard* cap — 800 logical LOC, baseline `tests/loc_baseline.txt`, enforced by `.github/workflows/loc.yml`, scope includes tests/utils/client shell+python. `tools/ci/check_file_size.sh` is the *soft* cap — 500 lines over `src/` only, per coding-standards §1, backlog-ratcheted, enforced by `guards.yml`. The soft cap is the target; the hard cap is the wall. A file passing the 800 wall can still fail the 500 ratchet.

Also: how to run everything locally (`for s in tools/ci/check_*.sh; do "$s"; done`), and hook install (`git config core.hooksPath tools/git-hooks`).

- [ ] **Step 2: Add the guard loop to `tools/git-hooks/pre-push`.** Insert after the `RUNNER` existence check and before the "running fast test tier" echo:

```bash
# Static invariant guards first — they take seconds and catch what the
# test tier can't (seam bypasses, size ratchet, doc drift).
for g in "$REPO"/tools/ci/check_*.sh; do
    if ! "$g"; then
        echo "[pre-push] ✗ guard failed: ${g##*/} — push blocked (bypass: --no-verify)"
        exit 1
    fi
done
```

- [ ] **Step 3: Add a "Local setup" section to `docs/09-developer-guide/dev-workflow.md`** (read the file first; place it near the top, matching its heading style):

```markdown
## Local setup — hooks and IDE navigation

- **Git hooks (once per clone):** `git config core.hooksPath tools/git-hooks`
  — pre-push then runs the tools/ci guards (seconds) plus the fast test tier
  (~4 min). Bypass: `git push --no-verify`.
- **clangd navigation:** `tools/clangd/gen_compile_commands.py` generates
  `compile_commands.json` so clangd/LSP can cross-reference all 660+ C files.
  Regenerate after `./configure`.
- **Guard reference:** [tools/ci/README.md](../../tools/ci/README.md) — what
  each CI guard enforces and how the backlog ratchets work.
```

- [ ] **Step 4: Verify hook + guards, commit**

```bash
bash -n tools/git-hooks/pre-push          # syntax check
tools/ci/check_doc_links.sh && tools/ci/check_doc_paths.sh
git add tools/ci/README.md tools/git-hooks/pre-push docs/09-developer-guide/dev-workflow.md
git commit -m "docs(ci): guard reference README, dual size-regime explanation, hook install docs; run guards in pre-push"
```

---

### Task 14 (experimental, last): weekly non-blocking fanalyzer workflow

`run_fanalyzer.sh` needs a configured nginx build tree, and its baseline was generated with the local GCC — a different CI GCC may produce different findings. So: non-blocking (`continue-on-error`), weekly + manual dispatch, artifact upload. Tighten to blocking only once it's proven stable across 2+ green weekly runs.

**Files:**
- Create: `.github/workflows/fanalyzer.yml`

- [ ] **Step 1: Create the workflow**

```yaml
# Weekly GCC -fanalyzer ratchet (use-after-free / leak / NULL-deref findings
# vs tools/ci/fanalyzer_baseline.txt). NON-BLOCKING for now: the baseline was
# generated with a local GCC and CI's GCC may differ; promote to a blocking
# gate after two consecutive clean scheduled runs (remove continue-on-error).
name: fanalyzer
on:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * 1'
jobs:
  fanalyzer:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
      - name: Install build deps
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends build-essential \
            libssl-dev zlib1g-dev libpcre3-dev libpcre2-dev \
            libcurl4-openssl-dev libsqlite3-dev libkrb5-dev
      - name: Fetch and configure nginx with the module
        run: |
          curl -fsSL https://nginx.org/download/nginx-1.28.3.tar.gz | tar -xz -C /tmp
          cd /tmp/nginx-1.28.3
          ./configure --with-stream --with-stream_ssl_module \
            --with-http_ssl_module --with-http_dav_module --with-threads \
            --add-module="$GITHUB_WORKSPACE"
      - name: Run analyzer ratchet
        run: NGX_BUILD=/tmp/nginx-1.28.3 tools/ci/run_fanalyzer.sh 2>&1 | tee /tmp/fanalyzer-report.txt
      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: fanalyzer-report
          path: /tmp/fanalyzer-report.txt
```

- [ ] **Step 2: Commit, dispatch once, inspect**

```bash
git add .github/workflows/fanalyzer.yml
git commit -m "ci(analyzer): weekly non-blocking gcc -fanalyzer ratchet run"
git push
gh workflow run fanalyzer.yml
sleep 30 && gh run watch "$(gh run list --workflow=fanalyzer.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```
Inspect the artifact. Outcomes: (a) green → note "promote after next scheduled run" in the workflow comment; (b) configure fails on a missing dep → add the package and re-dispatch (max 3 iterations); (c) findings differ purely from GCC version → leave non-blocking, add a comment in the workflow naming the GCC delta, and stop — local runs remain the authoritative gate. Never `--regen` the baseline from CI.

---

## Verification (whole plan)

- [ ] `for s in tools/ci/check_*.sh; do "$s" || echo "RED: $s"; done` — all green.
- [ ] `gh run list --limit 5` — `guards` and `site` workflows green on main.
- [ ] Published gh-pages serves `/apidocs/index.html`.
- [ ] `git status` clean except Rob's pre-existing WIP (client/Makefile, contrib, packaging, site, tests/ceph — DO NOT touch or commit those files; commit only plan files, listed per-task above).
