# Lessons Learned — The Migration Era (phases 55–66, May–July 2026)

**Date:** 2026-07-02
**Status:** Living retrospective — covers every landed structural migration through
phase-66 plus the post-migration sweeps of 2026-07-02.
**Scope:** the storage-driver abstraction (55/56), the VFS namespace/metadata seam
closure (62), the composable tier + FRM dissolution (64), the seven-bucket `src/`
conceptual realignment (66), the codebase-hardening pass (June), and the two
post-migration findings from 2026-07-02 (the docs-residue sweep and the
`kXR_writev` wire-parity fix).

**Related:**
[postmortem-refactor-regressions.md](postmortem-refactor-regressions.md) ·
[lessons-tpc-vfs.md](lessons-tpc-vfs.md) ·
[lessons-codebase-hardening-2026-06.md](lessons-codebase-hardening-2026-06.md) ·
[lessons-security-reaudit-and-cleanup.md](lessons-security-reaudit-and-cleanup.md) ·
[../refactor/phase-66-src-conceptual-realignment.md](../refactor/phase-66-src-conceptual-realignment.md) ·
[../refactor/phase-62-vfs-namespace-metadata-seam-closure.md](../refactor/phase-62-vfs-namespace-metadata-seam-closure.md) ·
[postmortem-shmtx-semaphore-stall.md](postmortem-shmtx-semaphore-stall.md)

This document is the *synthesis*: the *class*-level lessons that repeated across
migrations, each with the concrete incident(s) that taught it and the guardrail
that now prevents it. Individual incidents keep their own postmortems (linked);
read this first, drill down as needed.

---

## 0. What migrated, and how it went

| Phase | Migration | Scale | Outcome |
|---|---|---|---|
| 55/56 | Storage plane onto a capability-typed pluggable driver seam (`xrootd_sd_driver_t`); "zero data-POSIX outside `src/fs/backend/`" invariant | data plane of all 3 protocols | Landed; one reverted over-reach (A-1: `vfs_read`/`write`/`io_core` moved *off* the driver, put back) |
| 62 | Namespace + metadata seam closure — every handler `open`/`stat`/`unlink`/`rename`/xattr on an export path through `xrootd_vfs_*` | backlog 56 → 0 raw call sites | Landed; guard `tools/ci/check_vfs_seam.sh` keeps it closed |
| 64 | Composable tier layer (`cache_store`/`stage`/... decorators) + **dissolution of the ~3,900-line standalone `src/frm/`** into `fs/xfer/` + `fs/backend/frm/` | one whole subsystem deleted | Landed; tape suite 4/4, 114 staging tests green, no `src/frm/` path survives |
| 66 | `src/` conceptual realignment into seven buckets (`core/ protocols/ fs/ auth/ net/ observability/ tpc/`), src-rooted includes | ~850 files, 8 commits | Landed 2026-07-02; full fast suite green modulo pre-existing baseline failures |
| June | Codebase hardening (link-time, `safe_size.h` adoption, libFuzzer, sanitizer lane, exec/deployment sandboxing) | 11 tasks | Merge-ready; 0 critical findings in final review |
| 2026-07-02 | Post-migration docs sweep + `kXR_writev` stock-framing parity fix | 20 doc files; client+server+proxy+tap | Both complete; produced lessons §3 and §9 below |

---

## 1. The meta-lesson: build the gate before the move

*(Source: [lessons-tpc-vfs.md](lessons-tpc-vfs.md) §1; re-confirmed by every phase since.)*

Every migration stage that went smoothly had a **red-on-main verification gate
written first**; every stage that wasted days did not.

The canonical incident: native TPC-over-GSI *looked* done for weeks because the
only test used `xrdcp --tpc first`, which **silently falls back to a
client-mediated copy** when server-side TPC fails. The test passed `rc=0` while
the destination never performed a server-side pull at all. A `--tpc only` test
(no fallback) would have been red on day one.

Rules that came out of this and now function as house rules:

1. **A passing test that can pass for the wrong reason is worse than no test.**
   Prefer the strict mode (`--tpc only`, `strict=True` xfail) that a fallback
   path cannot satisfy.
2. **Stand up the interop gate before writing the protocol code.** The F6
   delegation gate (a real stock `xrootd` driven from
   `tests/test_tpc_delegation.py`) surfaced five separate blockers that no
   amount of reading our own code would have revealed.
3. **Assert on the peer's observable state, not just `rc`.** The delegation
   gate asserts the *source's* access log shows the delegated user's DN — the
   only observation that proves delegation end-to-end.
4. **Make the migration invariant machine-checkable, then migrate against the
   checker** (see §5). A guard that turns red is a gate; a convention in a doc
   is a hope.

---

## 2. Mechanical migrations succeed when they are map-driven, idempotent, and sequenced

*(Source: phase-66 execution, [../refactor/phase-66-src-conceptual-realignment.md](../refactor/phase-66-src-conceptual-realignment.md).)*

Phase-66 moved ~850 files across 8 commits with essentially zero breakage.
The properties that made that possible are a reusable playbook:

- **One map as the single source of truth.** `docs/refactor/phase-66-map.tsv`
  (columns: step, kind, old, new) drove *everything*: the `git mv`s, the include
  rewrites, the test/script path rewrites, the doc sweeps, and the final
  verification. No second list to drift.
- **Normalize before moving.** Step 0 rewrote every cross-directory `#include`
  in `src/` to the canonical src-rooted form *without moving anything*. After
  that, every later move is a pure prefix substitution — depth-independent,
  trivially verifiable.
- **Preserve content-identity.** Each move commit shows 100% rename similarity
  (`git show --stat`) with zero content hunks outside `#include` lines. The
  tool has a `--verify` mode asserting exactly that. This is what makes an
  850-file change *reviewable*.
- **Sequence smallest/least-coupled first, the monster last.** `core/` (152
  files) proved the machinery; `protocols/root/` (165 files, 91 inbound
  cross-dir includes on just three of its dirs) went last, when every include
  was already depth-independent.
- **Validate per bucket commit**, not at the end: `nginx -t`, the seam guard,
  `run_suite.sh --fast`, the C unit tests, **and** `make -C shared/xrdproto &&
  make -C client` (the surface `make` never exercises those — see §6), plus one
  cross-backend data-plane sample.
- **Dry-run diff first, always.** The rewriter is idempotent and prints its
  diff before applying.

**Counter-example that proves the rule:** the phase-56 A-1 sub-migration
(moving `vfs_read`/`vfs_write`/`io_core` off the driver) was *not* gated by a
red test expressing the intended invariant, over-reached, and was reverted.
The invariant it violated ("all data byte I/O routes through the SD driver")
was Rob's, is now written down
(memory + [../../src/fs/backend/README.md](../../src/fs/backend/README.md)),
and the seam guard enforces the enforceable half of it.

---

## 3. The precise limit of map-driven tooling: splits and dissolutions leave judgment-residue

*(Source: the 2026-07-02 docs sweep, immediately after phase-66's own "docs/guard sweep" commit.)*

The phase-66 final commit mechanically rewrote paths across CLAUDE.md,
AGENTS.md, `src/README.md`, tests, tools, and docs — and still left ~60 stale
references in ~20 live documents. Every single one belonged to one of two
categories the map cannot express:

1. **Splits.** `src/path/` divided *by file* into `src/fs/path/` (confinement,
   canonicalization), `src/auth/authz/` (ACL/authdb/VO policy),
   `src/protocols/root/path/` (wire-path extraction), and
   `src/observability/accesslog/`. A doc sentence saying "`src/path/` does X"
   needs a human to decide *which successor* X refers to. About 25 references,
   each individually judged during the sweep.
2. **Dissolutions.** `src/frm/` no longer exists as a unit; its capabilities
   live in `src/fs/xfer/` (durable registry/engine/waiter),
   `src/fs/backend/frm/sd_frm.c` (residency/recall driver),
   `src/core/config/tape_stage_conf.c`, and
   `src/observability/metrics/frm_metrics.c`. Worse, some referenced *files were
   deleted outright* (`migrate_purge.c`, the `stage.c` double-fork agent), so
   the referencing prose had to change from "is a scaffold" to "not implemented
   in-process" — a **semantic** update no rewriter can make. About 30 references.

Rules going forward:

- **Budget an explicit manual docs/guardrail pass for every split or
  dissolve.** Renames are free; splits and dissolutions are not.
- **Grep with the *old-directory alternation*, not just the moved paths.**
  The sweep's working query was
  `src/(acc|aio|cache|...|frm|pki|path|...)/` over `README.md` + `docs/`
  — i.e., derived from the map's *old* column plus every dissolved dir the map
  never contained (`frm`, `pki`).
- **Historical documents are exempt — deliberately.** `docs/refactor/*`,
  `docs/_archive/*`, `docs/superpowers/` plans, and past-tense narrative in
  lessons docs are point-in-time records; rewriting paths in them falsifies
  history. Live reference/comparison/operator docs get rewritten; records do
  not. When a live doc must mention the old name, write "the former
  `src/frm/`, dissolved in phase-64" — signposting, not scrubbing.
- **Check relative links mechanically after any sweep.** A one-liner that
  resolves every `](...)` target under `src|tools|tests` caught the one broken
  link (`quick-reference.md` → `src/frm/README.md`) that the grep missed
  because the *prose* around it had already been half-updated.
- **Prefer directory-glob guardrails over exact-file markers.** Dozens of
  "assert marker M in file F" tests false-failed across the era purely because
  code moved ([postmortem-refactor-regressions.md](postmortem-refactor-regressions.md) §3).
  If the intent is "this helper is used", assert over a module glob.

Known residue accepted at time of writing: `src/fs/xfer/README.md`'s own file
table slightly predates the final dissolution state (mentions
`xfer_journal.c`/`xfer_reconcile.c`, since folded/deleted) — it is a living dev
doc under active edit and was deliberately not rewritten mid-flight.

---

## 4. Dissolve subsystems capability-by-capability; the old code stays live until the last task

*(Source: the phase-64 FRM dissolution, `docs/superpowers/plans/2026-07-01-frm-dissolution.md`.)*

The FRM dissolution is the model for retiring a subsystem without ever having a
broken tree:

- **`src/frm/` stayed fully live and compiled until the final task.** Each
  earlier task migrated exactly **one capability** — residency probing →
  `sd_frm`, the async waiter → `stage_waiter`, the durable request records →
  `stage_request_registry` — and gated on that capability's tests. A failed
  gate was a localized revert, never a broken tree. Migrated code became
  dead-but-present until the single deletion commit.
- **Spike the crux first.** Task 0 was an investigation ("is the queue strategy
  viable? is `sd_frm`'s recall path already sufficient?") whose answer
  ("`sd_frm` ALREADY does the recall+park; `frm/stage.c`'s 647-line subprocess
  is the redundant legacy driver") *reshaped* the remaining tasks and licensed
  deleting rather than porting a third of the subsystem.
- **Preserve external contracts across the dissolution and say so.** The reqid
  wire format survived verbatim (clients that echo a reqid keep working); the
  `xrootd_frm_*` directives survived (relocated to `tape_stage_conf.c`); the
  registry journal kept routing through the SD posix seam so the seam guard
  stayed green. Behavior-preserving moves get to lean on the *existing* test
  suite as their gate.
- **Prove death before deletion.** The deletion gate was a grep:
  "`frm_*` symbols have ZERO callers outside `src/frm/`" — mechanical, not
  vibes. Then delete, deregister from `./config`, full rebuild, full tape +
  staging suites.

The same shape closed the VFS seam (§5) and should be the default for any
future "retire X into Y" work: **one capability per gate, old unit live till
last, external contract explicitly inventoried.**

---

## 5. Guard-driven migration: backlog files + allow-markers make invariants enforceable

*(Source: phase-62 seam closure; `tools/ci/check_vfs_seam.sh`.)*

The namespace/metadata seam closure worked because the invariant ("no raw libc
namespace call on an export path outside the VFS") was **encoded as a CI guard
with an explicit backlog**:

- The guard scans for raw call sites; a checked-in backlog file
  (`vfs_seam_backlog*.txt`) enumerates the *currently tolerated* violations.
  Migration = burning the backlog 56 → 0. New violations fail CI immediately
  because they're not in the backlog.
- Deliberate permanent exceptions carry a same-line
  `/* vfs-seam-allow: <reason> */` marker — the exception is visible at the
  call site, greppable, and carries its justification. (Legitimate exceptions
  exist: non-export resources like certs/`/dev/null`/sockets, and separate
  svc-owned storage domains — cache fill, upload staging, S3 multipart — where
  the VFS's confinement root and impersonation identity would be *wrong*.)
- `--regen` exists but is culturally reserved for deliberate migrations, never
  for "make CI green".

Two transferable points:

1. **A backlog file turns an open-ended cleanup into a monotone counter.**
   Progress is visible, regressions are impossible, and "done" is `wc -l == 0`.
2. **Enablers first, then the sites fall.** The backlog stalled several times
   until a missing primitive was built (`xrootd_vfs_walk`, thread-safe
   `vfs_open_fd`/`vfs_rename_path`, raw-`O_*` confined-open wrappers) — after
   which whole clusters of call sites migrated trivially. When a migration
   stalls, look for the missing enabler rather than grinding call sites.

---

## 6. The build system actively lies during migrations

*(Sources: [postmortem-refactor-regressions.md](postmortem-refactor-regressions.md) §2/§4, [lessons-tpc-vfs.md](lessons-tpc-vfs.md) §5, phase-66 execution notes.)*

Every one of these cost at least one full debugging cycle; several cost days:

- **Stale objects mask a non-compiling tree.** A linter flipped `->` to `.` in
  `session/lifecycle.c`; the tree did not compile, but incremental `make`
  reused the stale `.o` and nginx "built" — every behavioral test ran against
  code that no longer matched the source, for many iterations. *Guardrails:*
  confirm changed TUs actually recompiled; CI builds from a clean object tree;
  the auto-formatter must never touch `.c/.h`.
- **Configure-over-stale-objs produces mixed-ABI garbage.** After any tree
  move or mid-struct edit: `rm -rf objs && ./configure && make`. The failure
  mode is not a link error — it is a *runtime* `thread_pool=0x1` SIGSEGV or
  spurious `EBADF`, which looks exactly like a real bug in your new code.
- **`rm -rf objs/addon` alone breaks `make`** (`./configure` creates those
  directories). Clean ⇒ re-configure, always.
- **The surface `make` does not build everything.** `shared/xrdproto` and
  `client/` have their own Makefiles with their own `-I` expectations; phase-66
  validated `make -C shared/xrdproto && make -C client` on every bucket commit
  because the top-level build alone had previously hidden client breakage for
  days.
- **New `.c` files register in the top-level `./config`** (the
  `$ngx_addon_dir/src/…` lists) — not `src/core/config/config.h`, which is the
  directive/struct home. (CLAUDE.md was imprecise on this for months.)
- **A `-Werror` tree makes configure-triggered full rebuilds expose *other
  people's* latent warnings** — including in uncommitted work-in-progress files
  you never touched. Distinguish "I broke it" from "the full rebuild finally
  compiled it" before touching anything (see §7, last bullet).
- **Module `config` CFLAGS apply to the nginx core too.** Any `-Werror`-adjacent
  warning flag added for the module must be clean against nginx's own sources;
  noisier flags stay opt-in via `--with-cc-opt`.

---

## 7. Test hygiene during long migrations

*(Source: [postmortem-refactor-regressions.md](postmortem-refactor-regressions.md); run_suite lane design.)*

- **Don't live on `-x`.** It masks every deterministic failure after the first;
  it hid a *silent data corruption* bug (>1 MiB cache fills truncating at each
  1 MiB chunk boundary) for many iterations because earlier failures always
  stopped the run first.
- **After fixing a shared helper, re-run every sibling caller.** The
  cache-fill offset fix regressed the *slice* fill — a sibling caller with a
  different read-base/write-base relationship — which a single-test re-run
  could never catch. Corollary now baked into review: **routines that copy
  bytes between two files take the read offset and write offset as separate
  parameters**, and every chunked loop gets a test with input larger than the
  chunk size.
- **Keep checksum-on-fill ON in cache test topologies.** It was the only thing
  standing between the offset-conflation bug and silently serving corrupt
  physics data.
- **Load-correlated flakes need a re-run lane, not inline retries.** ~0.3% of
  the ~6,900-test suite transiently fails under a saturated pool (shared
  single-worker daemons respond slowly). `tests/run_suite.sh` re-runs *only*
  the failures on a quiet box (`--lf`); a load flake passes alone, a real bug
  stays red. Inline `--reruns` is wrong for this class — the immediate retry
  lands inside the same saturated window.
- **Serial-lane the tests that can't share:** timing/throughput assertions,
  multi-node meshes, destructive chaos/evil suites, subprocess-heavy
  `clientconf`. Also: repeated heavy runs degrade the box itself — reset
  between big runs.
- **Distinguish your breakage from concurrent breakage.** During overlapping
  migrations the tree was repeatedly red from an *unrelated* in-flight edit.
  Before concluding "my change did this", check the failing file is one you
  touched and the failure mode matches your change.
- **Environment failures impersonate product failures.** Recurring cases now
  documented: orphaned FUSE mounts wedging unrelated cache workers (fake
  `EXDEV`), pytest teardown wiping a shared fleet another session was using,
  proxy files with wrong permissions failing GSI ("No protocols left to try"),
  and — from this week — the conftest fleet-attach path not exporting
  `X509_USER_PROXY`, so pyxrootd GSI tests fail unless the env is set
  explicitly. Triage environment *first* when the failure is auth- or
  mount-shaped.

---

## 8. Concurrency/state lessons the migrations surfaced

Structural migrations kept flushing out latent shared-state bugs, because
moving code forces re-reading it:

- **Never use nginx's POSIX-semaphore shmtx mode.** Stock
  `ngx_shmtx_create(…, NULL)` silently enables a semaphore whose wakeup path
  loses wakeups under cross-worker contention: a worker blocks in `sem_wait`
  forever *with the lock free*, freezing its whole event loop (60–450 s
  connection stalls on the hot `kXR_open` path). Every module SHM mutex now
  goes through `xrootd_shm_table_alloc()` (spin+yield). Full analysis:
  [postmortem-shmtx-semaphore-stall.md](postmortem-shmtx-semaphore-stall.md).
- **SHM state must survive worker death.** Dead-holder mutex stranding, cache
  fill locks owned by killed pids (permanent `kXR_FileLocked`), and rate-limit
  in-use gauges that only decrement on clean release (leak → cap rejects the
  key forever, *surviving reloads*) were all found and fixed in one audit.
  Pattern: any `++`/lock in SHM needs a story for "the process that owns this
  was SIGKILLed" — reclamation by `kill(pid,0)==ESRCH`, binding the mutex where
  nginx's per-worker-death force-unlock can see it, or zeroing gauges on
  reload-adoption.
- **Blocking calls need *stall* timeouts, not just connect timeouts.** The
  HTTP origin client had only `CONNECTTIMEOUT`; a stalled (not refused) origin
  wedged a fill-pool thread forever and stalled the fleet. `LOW_SPEED_LIMIT`/
  `LOW_SPEED_TIME` (or equivalent) on every outbound transfer.
- **Zero-copy paths need a self-healing fallback.** `splice()` under
  edge-triggered epoll under-drains on some kernels (WSL2), crawling reads past
  client timeouts; only splice a body that is already fully buffered
  (`FIONREAD >= dlen`) and fall back to buffered relay otherwise.

---

## 9. Case study — internal self-consistency masks wire divergence (`kXR_writev`, fixed 2026-07-02)

The freshest lesson, and the sharpest expression of §1's differential-testing
rule.

**The bug class.** Our client (`libxrdc`) and our server agreed with each other
perfectly on `kXR_writev` framing, every in-tree test was green — and both were
**wrong against the reference implementation**. Stock XRootD
(`XrdXrootdProtocol::do_WriteV` + `XrdCl::FileStateHandler::VectorWrite`)
frames writev as: header `dlen` covers **only** the `N*16`-byte `write_list`
descriptor block; the concatenated segment data streams *after* the frame, its
length recovered by the server as `sum(wlen)`. Our stack counted the data
inside `dlen`. Stock servers reject that with `kXR_ArgInvalid` "Write vector is
invalid" and drop the link; only our server accepted it — because our server
had been written against our client.

**Why it survived so long.** Nothing inside the repo could ever notice: the
suite's raw-wire writev builders used our layout, the client used our layout,
and the server parsed our layout (with a clever-but-wrong "recover N by size
matching" heuristic). The only test that could catch it is one where exactly
one endpoint is the reference implementation — and writev happened to sit
outside the cross-backend conformance surface.

**The fix's shape is itself a lesson.** Because the data now arrives *outside*
`dlen`, accepting the stock layout required a framing-layer change (extend the
read obligation after the descriptor block completes), and that pulled in
every plane that touches frames:

| Plane | Change |
|---|---|
| Client | `ops_file_rw.c` via new `xrdc_send_ext()` — wire `dlen` ≠ bytes sent; sigver signs the `dlen` span, matching stock |
| Server framing | `recv.c` extension: validate descriptors (`xrootd_writev_body_extra()`), grow the payload buffer **preserving received bytes**, extend the expected length; caps enforced *before* any allocation |
| Server handler | `writev.c`: `N = dlen/16`; stock-parity errors; framing violations send the error **then drop the link** (mandatory — once the descriptor block is in doubt, the trailing byte count is unknowable and no resync exists) |
| Proxy | `forward_request.c` forwards descriptors + trailing data (incidentally fixing a latent bug where fh-translation walked into data bytes) |
| Tap/observability | `tap_stream.c` sums `wlen` on the fly to skip the trailing data and stay frame-aligned |

Design constraint worth remembering: **the framing layer never rejects** — a
malformed vector still dispatches so the login/auth/write gates run first; the
*handler* produces the parity error. Rejecting in framing would have bypassed
the auth gate and changed pre-auth behavior.

**Rules extracted:**

1. **Every opcode our stack speaks needs at least one test where the other end
   is stock.** Green client↔server proves consistency, not correctness. (The
   fix's acceptance test was literally `xrdfs writev` against the stock server
   on port 11112.)
2. **"Recover the layout by size heuristics" is a red flag.** The old server
   derived N from `n*16 + sum(wlen) == dlen` — a heuristic that only exists
   because the layout was ambiguous, and whose ambiguity was itself the
   divergence. The stock contract has no ambiguity to recover from.
3. **When a wire frame can carry trailing out-of-dlen data, audit every frame
   consumer**: main framing, the transparent proxy, the tap/relay decoders,
   sigver coverage, and the chkpoint-embedded variant. Four of the five needed
   changes.
4. **Known open item of the same class:** chkpoint `kXR_ckpXeq`. Stock
   requires the chkpoint frame's `dlen == 24` (the embedded sub-request header
   only) and streams the sub-request's payload after the frame
   (`XrdXrootdXeqChkPnt.cc`); our `chkpoint_xeq.c` expects the whole
   sub-request inline. libxrdc↔nginx are self-consistent (the trap of this
   very section), so nothing in-tree is red. Fixing it needs multi-stage
   framing (header-in-frame, then descriptors, then data). Tracked here until
   scheduled.

---

## 10. Documentation lessons

- **Docs describing *structure* rot faster than docs describing *behavior*.**
  The 2026-07-02 sweep found the behavioral claims in the tape/cache comparison
  docs still accurate after two subsystem migrations — but every path,
  file-name, and "lives in X" statement was stale. When writing docs, prefer
  behavior + a single code-map table (easy to sweep) over paths woven through
  prose.
- **The README's architecture section is a migration deliverable.** The
  seven-bucket realignment wasn't "done" until the README stopped describing
  the old organically-grown four-plane layout. If the top-level docs still
  describe the old shape, the migration hasn't shipped its main benefit
  (findability).
- **Per-directory READMEs + one full map scale well.** `src/README.md` (the
  subsystem map) plus per-directory READMEs survived the realignment almost
  intact because each README moved *with* its directory; only cross-tree
  references broke. Keep ownership of a doc as close to the code it describes
  as possible.
- **Update guardrail/marker tests in the same commit as the move** — and when
  a doc must reference history, name it as history ("the former `src/frm/`,
  dissolved in phase-64") rather than leaving a bare stale path.

---

## 11. Process lessons (how the work itself was run)

*(Source: [lessons-codebase-hardening-2026-06.md](lessons-codebase-hardening-2026-06.md) §5; FRM dissolution plan.)*

- **A detailed plan is a hypothesis, not a spec.** The hardening plan's own
  draft code contained four bugs (wrong configure cwd, sanitizer flags silently
  dropping link hardening, two systemd-semantics conflations) — all caught by
  the per-task implement→review loop, two of them *corrections that
  contradicted the plan text* and were verified tighter. The review gate
  applies to the plan.
- **Audit before building.** The hardening exercise's first finding was that
  the posture was already strong; the value was *adoption discipline*
  (routing wire-driven allocations through the existing `safe_size.h`), not new
  infrastructure. Distinguish attacker-controlled ingress from locally
  generated egress; guarding egress lengths is dead code and a review finding
  in itself.
- **Investigation tasks (spikes) earn their keep.** The FRM Task-0 spike and
  the CephFS/RADOS interop spike both *changed the plan* (delete rather than
  port; read-only rescue is GO, zero-copy upgrade is NO-GO). A day of spike
  saved weeks of porting the wrong thing.
- **Write the lessons down immediately, in-repo, with the incident attached.**
  This era produced four postmortems and three lessons docs; every one of them
  has already been cited to stop a repeat (the shmtx rule is now CLAUDE.md
  invariant #10; the stale-object rule is in the phase-66 playbook). A lesson
  that lives only in chat history will be re-learned at full price.

---

## 12. Consolidated pre-merge checklist for any future structural migration

Distilled from all of the above; treat as the gate for "the migration is done":

- [ ] **Map file** (old→new, kind=rename/split/dissolve) checked in as the
      single source of truth; rewriter idempotent with dry-run diff.
- [ ] **Red gate first**: a test that fails on main expressing the migration's
      invariant (guard script + backlog file for multi-week efforts).
- [ ] Includes normalized (src-rooted) *before* any file moves.
- [ ] Move commits are 100% rename-similar; content changes ride separately.
- [ ] Per-commit validation: `nginx -t`, seam guard, fast suite, C unit tests,
      `make -C shared/xrdproto && make -C client`, one cross-backend sample.
- [ ] **Clean rebuild** (`rm -rf objs && ./configure && make`) — never trust
      incremental across a move; confirm changed TUs recompiled.
- [ ] `./config` source lists updated for every added/removed/moved `.c`.
- [ ] Guardrail/marker tests updated in the same commit as the move.
- [ ] **Manual sweep for splits/dissolutions**: grep docs + tests with the
      old-directory alternation; resolve each hit with judgment; verify all
      relative links resolve; historical docs exempt.
- [ ] External contracts inventoried and preserved (wire formats, directive
      names, reqid formats, file formats) — or the break explicitly documented.
- [ ] Full suite **without `-x`**; failures triaged in isolation (real vs
      load-flake vs environment); `--lf` quiet-box re-run for the flake class.
- [ ] **Differential run against stock** for anything that touched framing,
      dispatch triggers, or staging decisions (§9).
- [ ] README / top-level architecture docs describe the *new* shape.
- [ ] Lessons/postmortem entry written if anything above was violated and bit.

---

## 13. Open items carried out of the era

| Item | Class | Where tracked |
|---|---|---|
| chkpoint `kXR_ckpXeq` sub-request framing diverges from stock (same class as the writev bug) | wire parity | §9.4 above; memory `writev-stock-framing-fix` |
| `src/fs/xfer/README.md` file table predates final FRM dissolution state | doc residue | §3 above |
| conftest fleet-attach does not export `X509_USER_PROXY` → pyxrootd GSI tests need env set manually | test env | §7 above |
| 9 test files fail pytest *collection* on Python 3.9 (`dict \| None` PEP-604 annotations at import) | test env | §7; pre-existing, unrelated to migrations |
| Migrate/purge engine intentionally not re-implemented in-process after FRM dissolution (delegated to MSS/operator) | scoped-out capability | comparison docs (07-storage-cache-tape) |
