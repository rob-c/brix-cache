# Phase 108 — VFS consolidation: the mutation work BriX-Cache does without the VFS

**Date:** 2026-08-31

**Status:** 📋 **PLANNED** — no code written. This document is the specification
the implementation will be judged against.

**Document version:** v1. Split out of
[phase 107](phase-107-vfs-mutation-surface-completion.md) v2, whose §13 made the
case for two documents: phase 107 adds verbs the VFS does not have and is judged
by "does it work on twelve drivers"; this phase stops four subsystems from
having privately re-invented the ones it does, and is judged by "is the shared
version at least as strong as every copy it replaced". Different risk profile,
different review audience, different definition of done.

**Tree inspected:** `480ded2e4` ("close the storage-driver slot wave") plus the
working tree present on 2026-08-30. Every `file:line` below was read on that
tree; re-verify before starting each wave.

**Prerequisites — this phase does not start until they are met:**

- [phase 107 — VFS mutation surface completion](phase-107-vfs-mutation-surface-completion.md)
  must have landed **W9** (the typed storage domain `brix_vfs_domain_t`, its
  runtime assert and the enforcing seam guard) and, for C10, **W3** (`sync_publish`,
  the durable publish barrier), **W7** (`exchange` and the typed precondition)
  and **W1** (the CAS gate). Phase 107 creates the verbs; this phase points them
  at the subsystems that hand-rolled them. Consolidating first would consolidate
  onto a surface that is about to change.
- [phase 105 — VFS-authoritative read-only mutation gate](phase-105-vfs-read-only-mutation-gate.md):
  the policy kernel, the vocabulary, the `_cred` discipline, the
  `brix_vfs_export_op_ctx_t` bundle and the ordering rule (Appendix I.5: `EROFS`
  before every other refusal) are load-bearing here.
- [the storage-driver slot matrix](../09-developer-guide/storage-driver-slot-matrix.md),
  [`src/fs/README.md`](../../src/fs/README.md),
  [`src/fs/backend/README.md`](../../src/fs/backend/README.md).
- `tools/ci/check_vfs_seam.py` **after** phase-107 W9 — the entitlement table it
  grows there is what this phase's waiver deletions are measured against.

---

## Contents

1. [Outcome](#1-outcome)
2. [The gaps](#2-the-gaps)
3. [Normative model](#3-normative-model)
4. [Per-item design](#4-per-item-design)
5. [What this phase deliberately leaves alone](#5-what-this-phase-deliberately-leaves-alone)
6. [Observability](#6-observability)
7. [Implementation waves](#7-implementation-waves)
8. [Test matrix](#8-test-matrix)
9. [Expected file map](#9-expected-file-map)
10. [Compatibility and rollout](#10-compatibility-and-rollout)
11. [Definition of done](#11-definition-of-done)

Appendices:

- [A. Proposed types and API contracts](#appendix-a--proposed-types-and-api-contracts)
- [B. Risk register and deliberately rejected alternatives](#appendix-b--risk-register-and-deliberately-rejected-alternatives)
- [C. CI guards and static enforcement](#appendix-c--ci-guards-and-static-enforcement)
- [D. Requirement traceability](#appendix-d--requirement-traceability)

---

## 0. Where this comes from

Phase 107 read the VFS mutation surface against what the five protocol planes
ask of it, and found eight places where the layer cannot express an operation a
backend can perform. Reading the same surface from the other direction asks a
different question: **where does BriX-Cache already do VFS work without the
VFS?**

The answer is an OCI registry that has privately rebuilt staged publish and
atomic tag swap over raw syscalls with no `fsync` anywhere, ~25 sites in eleven
files that materialise a secret to disk by hand, an authorization decision taken
at 37 protocol-edge call sites over a rule engine that already lives in
`src/fs/path/`, and a name-translation module that is compiled, unit-tested,
listed in `config`, and called by nothing.

None of these is a feature a user cannot get. They are places where the cost of
*not* having gone through the VFS has already been paid — in a durability bug
the registry does not know it has, in a security invariant restated 25 times, in
an authorization check that one code path forgot in 2026-07 and had to be told
about — and where it will keep being paid.

The item numbering continues phase 107's (C10–C13) rather than restarting, so
that document's traceability table, its §2.2 evidence and its risk register
still point at the right things after the split. **C9** — the typed storage
domain that every item here depends on — stayed in phase 107, because it is
cheap, it is enabling, and it belongs with the kernel work.

---

## 1. Outcome

### 1.1 User-visible result

Almost nothing, which is the point. Consolidation that changes a wire answer has
overstepped. What changes:

- An OCI tag pointer **survives a power loss**, because the registry publishes
  through the same staged-commit path as everything else instead of its own
  `open`/`write`/`rename` with no fsync (`oci_store.c:318`). This is a live bug
  and it is the only user-visible defect this phase fixes.
- A credential written to disk gets the same mode, the same no-follow open, the
  same reap-on-failure and the same audit line **wherever it is written** —
  today that is ~25 hand-rolled sites in eleven files, each with its own comment
  explaining why it is safe.
- A namespace handler that forgets `brix_auth_gate` **still cannot reach
  storage**, because the VFS re-checks. This is what the 2026-07-06 cache-authz
  fix had to do by hand for one path. It ships in `observe` and this phase
  closes without flipping it.
- A site running RAL-style `<pool>:<prefix><lfn>` object naming gets it from the
  path layer on every driver, and directory listings render back in logical
  terms — which is what `site_n2n.c` was written for and has never once been
  asked to do.

And the tree is smaller: every wave here deletes more than it adds, and the
`vfs-seam-allow` waiver count drops below what phase-107 W9 annotated.

### 1.2 Non-goals

Each is the obvious over-reach of one of the four items:

- **Moving authorization off the protocol edge.** C12 makes the VFS a
  *backstop*, not the decision point. The edge gate keeps its job: it rejects
  early, before path resolution and backend work, and it emits the
  protocol-correct refusal (`kXR_NotAuthorized` + `NGX_DONE`, a WebDAV `403`, an
  S3 `AccessDenied`) that a storage layer has no business composing. Relocating
  it would also move the SHM verdict cache and its per-worker L1 away from the
  hot path they were built for. Defence in depth, not a migration.
- **An admin API that edits authz rules, gridmaps or ACLs.** That is phase-107
  §1.2's rejected `setacl` wearing a different hat, and the reasoning applies
  unchanged. Rules are compiled at postconfig and stay that way.
- **Hot-reloading the gridmap and identity-mapping files.**
  `idmap_gridmap_load()` reads the mapfile once at init with no mtime watch, so
  adding a user needs a reload. That is a genuine operational gap and it is a
  *configuration* concern: the file is operator-owned host config, not storage
  the VFS mediates. It belongs to a reload phase, and putting it here would be
  the exact category error this phase exists to fix, run in reverse.
- **Moving the OCI registry model behind the seam.** C10 moves file mechanics.
  What a tag pointer contains, when a referrers index is rewritten and how a
  session is sealed stay in `src/protocols/oci/`.
- **Changing what phase 105 classifies as a mutation.** Appendix E.5 of that
  document stands. This phase adds one vocabulary member; it reclassifies
  nothing that was called a read.

---

## 2. The gaps

### 2.1 The consolidation gaps

| # | Gap | Evidence | Class |
|---|---|---|---|
| C10 | The OCI registry has privately rebuilt staged publish, atomic tag swap, CAS presence and index listing over raw syscalls — with no fsync anywhere | `oci_store.c:295–324`, ~14 waivers in `oci_store.c`/`oci_meta.c`/`oci_referrers.c` | correctness / duplication |
| C11 | ~25 sites in eleven files hand-roll "write a secret to a private file safely" | `vfs_deleg_x509.c`, `tpc_token_exchange.c` ×6, `tpc_user_proxy.c` ×3, `webdav/delegation.c` ×4, `origin_auth*.c`, `credential_block.c`, `cvmfs/attest.c`, `cred_mint.c` | security / duplication |
| C12 | Authorization is decided at 37 protocol-edge call sites over a rule engine that already lives in `src/fs/path/`, while the VFS holds the identity and never asks | `brix_auth_gate` ×26, direct rule matching ×11, `vfs.h:104`, `path.h:45,80` | security |
| C13 | `site_n2n.c` — compiled, unit-tested, config-listed, and called by nothing; `sd_ceph.c` carries a partial one-way duplicate | `config:988`, `tests/c/test_site_n2n.c`, zero callers; `sd_ceph.c:206` | dead seam |

**C10** is the one with a live bug in it. `oci_store.c:295–324` is the
publish primitive for tag pointers and reference marks: open a temp, write in a
loop, close, `rename`, unlink on error. There is no `fsync` of the temp and no
directory flush, so an OCI tag survives a crash only by luck — the same defect
phase-107 C3 fixes for exports, in code C3 as written does not reach. Its
neighbours are just as recognisable: `"atomic tag/mark swap — a concurrent
reader sees old or new, never torn"` is C6's `exchange` with a hand-written
comment where the slot should be, `"store presence probe (CAS existence, no
bytes read)"` is C8's dedup plane, and `"registry's own store index, not a VFS
export listing"` is `enumerate`. The registry did not do anything wrong: those
verbs either did not exist or were not reachable for service storage. Phase 107
creates them; C10 is what makes creating them pay twice.

**C11** is a security invariant with 25 copies. Every site opens with `O_EXCL`
and `0600`, writes, sometimes fsyncs, renames, and unlinks on failure — and
every site decides independently whether to fsync, whether to `O_NOFOLLOW`,
whether to reap on the error path, and what to log. `webdav/delegation.c:47`
even documents the sequence in a comment block, which is the tell: a pattern
worth documenting in one file is worth extracting for the other ten.
`src/core/compat/staged_file.h` already exists and already does most of this;
its users are the VFS and the POSIX driver, and nobody else.

**C12** is the structural one. Read it against phase 105's own §2: before that
phase, "may this endpoint write?" was a bare `allow_write` bit tested in a
handful of places, so a mutator that forgot the test reached a storage driver.
Authorization today is in exactly that state — 26 `brix_auth_gate` calls plus 11
direct rule-matching sites across the root, WebDAV, S3 and GridFTP planes — with
one difference that makes it *more* tractable, not less: the rule engine is
already in the fs layer (`brix_find_authdb_rule`, `brix_check_authdb`,
`brix_finalize_authdb_rules` in `src/fs/path/path.h`), the rules are compiled at
postconfig so runtime matching is pure string work, a decision-only entry point
already exists (`brix_authz_check`, "sends nothing on the wire"), and
`brix_vfs_ctx_t` has carried `brix_identity_t *identity` since phase 55 — using
it only to pick a backend credential (`vfs_cred.c:242,338,351`), never to decide
anything. Every ingredient for a pure authorization kernel is present and
unassembled.

The proof that the class bites is in the authz README: the 2026-07-06 cache-authz
fix made `open_cache.c` run the *full* gate because "serve and fill helpers are
deliberately auth-free so this gate cannot be bypassed." That is a correct fix
and a fragile one — it is a convention that the next helper must also be told
about.

**C13** is small and slightly embarrassing. `site_n2n.c` implements the two real
GridPP naming schemes (RAL/Glasgow `<pool>:<prefix><lfn>`, CephFS
`<localroot><lfn>`), rejects `..` traversal, has a reverse `pfn2lfn` for
rendering listings in logical terms, has a standalone unit test
(`tests/c/test_site_n2n.c`), and is listed in `config:988`. It has no callers.
Meanwhile `sd_ceph.c:206` carries `sd_ceph_key(key_prefix, lfn)` — prefix plus
normalize, forward direction only, no pool scheme, no reverse. The mapping
concern was built once generally, wired nowhere, and then re-solved partially
inside one driver.

### 2.2 Why now, and in this order

1. **Phase 107 creates the verbs this phase needs.** `exchange` (C6),
   `sync_publish` (C3), the CAS gate (C8) and the typed precondition (C6) are
   precisely the four things `oci_store.c` hand-rolled. Building them for
   exports and not pointing them at the registry means shipping the fix next to
   the bug.
2. **Every item here is a place a phase-107 invariant is currently
   unenforced.** The registry publishes without durability; the credential sites
   restate a security invariant 25 times; the authorization decision has no
   backstop. Phase 107 hardens the export path and leaves these at their current
   strength, which widens the gap between "the way the VFS does it" and "the way
   this subsystem does it".
3. **The consolidation is bounded and mostly mechanical.** Three of the four
   items delete code. Only C12 adds a decision.

---

## 3. Normative model

### 3.1 The vocabulary grows by one

`brix_vfs_mutation_op_t` (`src/fs/vfs/vfs_policy.h`) is append-only by contract
and mirrored in `unified.h` with a compile-time equality check
(`BRIX_VFS_MUTATE_OP_METRIC_COUNT`, 11 today, **15** after phase 107). This
phase appends exactly one:

| value | covers | introduced by |
|---|---|---|
| `BRIX_VFS_MUTATE_CREDENTIAL` | materialise or reap a credential file in the service domain | C11 |

`BRIX_VFS_MUTATE_OP_COUNT` becomes 16 and the metric mirror moves with it, or
the static assert in `vfs_policy.c` fails the build — which is the point of the
assert.

The other three items add no vocabulary: C10 reuses `PUBLISH` and `RENAME` on a
different domain, C12 is an authorization axis rather than a mutation, and C13
is a path transformation, not a mutation at all.

The values are labels for diagnostics and low-cardinality metrics
(INVARIANT #8). As phase 105 states and this phase repeats: they never exempt a
backend, a protocol or a path.

### 3.2 The domain type is inherited, not defined here

`brix_vfs_domain_t` and `brix_vfs_domain_mutation()` land in phase-107 W9
(that document's §3.7, Appendix A.3 and Appendix G). This phase consumes them:

- C10 publishes into `REGISTRY`, `STAGE` and `CACHE`.
- C11 writes into `CREDENTIAL` (and `CONFIG` for a trust anchor).
- Every waiver this phase deletes is one the W9 entitlement table had to accept.

Nothing here redefines the domain, and nothing here treats a domain as
authority. A domain is a statement about *what the storage is*. It grants
nothing; it makes a claim checkable.

### 3.3 Durability is a property of the domain

Phase-107 C3 makes a publish durable on demand (`brix_durable_publish`). For
service storage the question is not per-operator, it is per-domain, and this
phase fixes it in three classes:

- `REGISTRY`, `CREDENTIAL`, `JOURNAL` — **durable**. Losing a tag pointer, a
  minted proxy or a journal record on a power cut is a correctness failure.
- `CACHE`, `STAGE` — **not durable by default**. A lost cache entry is a
  re-fetch; a lost transfer temp is a retried transfer. Both are reaped on
  startup already.
- `EXPORT` — governed by `brix_durable_publish`, because that one is the
  operator's cost/safety call.

The classes are recorded in phase-107 Appendix G alongside the domains
themselves, so there is one table and not two.

### 3.4 The ordering rule gains position 1.5

Phase-107 §3.4 fixes the order every mutator obeys. C12 fills the position that
document reserves:

1. **Policy** — `brix_vfs_require_confined_mutation()`. `EROFS`, before anything
   else, disclosing nothing about the gates behind it.
1.5. **Authorization** — `brix_vfs_require_authorized()` (C12). `EACCES`, and
   *after* the policy kernel so a read-only endpoint still says only `EROFS`.
   Pure, like the kernel, because the rules are pre-resolved.
2. **Lock** — `brix_vfs_require_unlocked()` (phase-107 C7).
3. …unchanged from there: confinement, leaf resolution, capability probe,
   credential resolution, backend work, cache invalidation.

The ordering is asserted by test, not by convention — the same spy-recorded
sequence phase 105 used to find four defects.

### 3.5 The parity-table discipline

This is the method of the whole phase, and it is the reason the waves are shaped
the way they are.

A consolidation lands only when the shared version is **at least as strong** as
every copy it replaces. A helper that loses `webdav/delegation.c`'s fsync, or
drops `oci_store.c`'s unlink-on-error, is not a consolidation — it is a
regression with fewer lines.

So every migration wave **opens** by pinning, in a table, what each copy it
intends to delete actually does today — mode, follow behaviour, fsync, dirfsync,
error-path reaping, logging — with a test per row asserting it. The wave
**closes** by re-running that table against the shared implementation. A wave
that cannot produce the table has not established its bar and does not land.

The table is written before the first caller moves, not after, because the
properties being pinned are exactly the ones that are easy to lose silently and
impossible to notice missing.

---

## 4. Per-item design

### C10 — The staged-publish surface reaches service storage

**Today.** `oci_store.c` re-implements, over raw syscalls:

| registry code | the VFS verb it is | phase-107 item |
|---|---|---|
| open temp → write loop → close → `rename` → unlink on error (`:295–324`) | staged publish | C3 (durability), existing `brix_staged_*` |
| `"atomic tag/mark swap — a concurrent reader sees old or new, never torn"` | `exchange` | C6 |
| `"store presence probe (CAS existence, no bytes read)"` | CAS presence | C8 |
| `"registry's own store index, not a VFS export listing"` | `enumerate` | slot wave item U |
| `"seal-time hash of the staged upload, before it becomes an object"` | ingest digest at commit | existing `brix_integrity_*` |
| `"session directory teardown (abort / reap / seal)"` | staged abort + reap | existing `staged_file_reap.c` |

None of it fsyncs. `webdav/tpc_marker.c`, `tpc_curl_multi.c` and
`tpc_cred_exchange.c` carry smaller versions of the same pattern.

**Design.** Give `src/core/compat/staged_file.h` a domain-aware entry point —
it already implements staged create, exclusive commit, cross-device commit
(`staged_file_commit.c`, which handles the `EXDEV` case none of the copies do)
and reaping — and migrate the copies onto it (contract in
[A.1](#a1-domain-aware-publish-c10)), with `sync_publish` (phase-107 C3) applied
when the domain's durability class (§3.3) requires it.

**Migration order, strongest copy first.** `oci_store.c` sets the bar for
error-path reaping (unlink on every failure branch); `webdav/delegation.c` sets
it for fsync-before-rename and 0600; `staged_file_commit.c` sets it for `EXDEV`.
The consolidated helper must do all three before the first caller moves, and the
parity pin for this wave is a test per abandoned copy asserting the behaviour
that copy had (§3.5).

**What stays.** The OCI *semantics* — what a tag pointer contains, when a
referrers index is rewritten, how a session is sealed — stay in
`src/protocols/oci/`. C10 moves the file mechanics, not the registry model.

### C11 — Credential materialization is one verb

**Today.** ~25 sites across eleven files write a secret to disk. Each opens with
`O_EXCL` and `0600`, writes, and renames. They differ in whether they fsync,
whether they pass `O_NOFOLLOW`, whether they unlink on the error path, whether
they log, and whether the containing directory is created with a checked mode.
`webdav/delegation.c:47` documents the intended sequence in a header comment —
"write, fsync, close, then rename() over the final path" — which is the right
sequence and is not what all eleven files do.

**Design.** One verb over the `CREDENTIAL` domain
([A.2](#a2-credential-materialization-c11)), with the invariants asserted in one
place: `O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode `0600` (`0700` for a directory),
fsync before rename, dirfsync after (durable class, §3.3), unlink on every
failure branch, one structured audit line, and `MUTATE_CREDENTIAL` booked.
`kind` distinguishes a bearer token from an X.509 proxy from a keytab for the
audit line and for the reaper's TTL policy — not for the file mechanics, which
are identical.

**Why the `export_op_ctx` and not a `brix_vfs_ctx_t`.** Several of these sites
run off the event loop or before a request context exists — `cred_mint.c`,
`runtime_server_backend_cache.c`, the CVMFS attest path. Phase 105 already built
the answer for exactly this shape (`brix_vfs_export_op_ctx_t`, §A of that
document), and reusing it keeps one authority-carrying type rather than two.

**Security bar.** The consolidated verb must be strictly stronger than the
strongest current copy on every axis, and the test that proves it is the parity
table of §3.5: for each of the ~25 abandoned sites, assert mode, follow
behaviour, fsync, and error-path reaping. A consolidation that quietly drops
`O_NOFOLLOW` from one site is a symlink attack the tree did not have yesterday.

**Bonus that falls out.** With one writer, credential *reaping* becomes uniform
too — today TTL handling is per-subsystem, and a proxy left behind by a failed
delegation is cleaned up by whichever path happens to own it.

### C12 — Authorization becomes a VFS backstop

**Today.** 26 `brix_auth_gate` / `brix_auth_gate_op` call sites plus 11 direct
`brix_check_authdb` / rule-matching sites, across `src/protocols/root/`,
`webdav/`, `s3/` and `gridftp/`. The gate is the sole authorization checkpoint
on the cached-serve path *by convention*: `open_cache.c` runs the full gate
because the 2026-07-06 cache-authz fix made it, and the serve and fill helpers
are deliberately auth-free so the gate cannot be bypassed. Correct, and held in
place by a comment.

Meanwhile the ingredients for a kernel are all present:

| ingredient | where it already is |
|---|---|
| the rule engine | `src/fs/path/path.h:45,80` — `brix_find_authdb_rule`, `brix_check_authdb` |
| rules resolved against the export root at postconfig | `acl.c`, `authdb.c` — "runtime matching is pure string work" |
| a decision-only entry point that emits nothing | `brix_authz_check` (`auth_gate.h:62`) |
| the identity | `brix_vfs_ctx_t.identity` (`vfs.h:104`), used today only to pick a backend credential |
| the required privilege level | `BRIX_AUTH_READ/_LOOKUP/_UPDATE/_DELETE/_MKDIR` (`config.h:55–59`) |

**Design.** A second pure kernel beside the mutation kernel
([A.3](#a3-authorization-backstop-c12)). It derives the privilege level from the
operation the VFS is *already* gating — the mapping is not invented, it is the
one the 37 call sites already pass by hand:

| mutation op | `BRIX_AUTH_*` |
|---|---|
| `OPEN` (create/truncate), `WRITE`, `TRUNCATE`, `SYNC`, `SETATTR`, `XATTR`, `PUBLISH` | `UPDATE` |
| `MKDIR` | `MKDIR` |
| `REMOVE` | `DELETE` |
| `RENAME`, `COPY` | `UPDATE` **and** `DELETE` on the source |
| `STAGE`, `EVICT` (phase-107 C2) | `UPDATE` (staging consumes site resources) |
| `CREDENTIAL` | not export storage — no rule applies; the domain assert governs |
| reads, via the read-side twin `brix_vfs_require_authorized_read()` | `READ` / `LOOKUP` |

It is pure in the phase-105 sense — the rules are pre-resolved, matching is
string work, no allocation and no I/O — so it can sit at ordering position 1.5
(§3.4): after the mutation policy, before the lock check.

**Backstop, not relocation.** The edge gate stays exactly where it is and keeps
doing three things the VFS should not: rejecting before path resolution and
backend work, composing the protocol-correct refusal, and hosting the SHM
verdict cache with its per-worker L1 on the GSI hot path. The VFS kernel is the
thing that cannot be forgotten. In the normal case it re-runs a decision the
edge already made and agrees; the interesting case is when it disagrees, which
means a handler reached storage without asking.

**Which is why the rollout is inverted.** `brix_authz_backstop
observe|enforce`, default **`observe`** for one release — the kernel runs, and a
disagreement increments `brix_vfs_authz_backstop_total{result=agree|edge_missing}`
and logs, but does not refuse. Enforcing from day one against 37 call sites,
five protocol planes and an SHM verdict cache would turn any modelling error
into a site outage. `observe` produces the evidence that the model is right,
and `enforce` is a one-line flip once the counter has been flat across the fleet
lanes.

**The failure mode to design against.** A backstop that is *more* permissive than
the edge is worse than none, because it looks like coverage. The kernel therefore
refuses when it cannot decide — no rules bound to the ctx, an identity it cannot
interpret, an operation with no mapping — rather than passing. Under `observe`
that refusal is a log line; under `enforce` it is a denial. Fail-closed, like
everything else on this path.

### C13 — Name mapping is a path-layer stage

**Today.** `site_n2n.c`: two real site schemes, traversal rejection, a reverse
direction, a standalone unit test, an entry in `config:988`, and zero callers.
`sd_ceph.c:206`: `sd_ceph_key(key_prefix, lfn)` — forward only, prefix only.

**Design.** Wire the translation as a stage in the path layer, between
confinement and driver dispatch ([A.4](#a4-name-translation-stage-c13)):

- **LFN → PFN** after `resolve_path()` succeeds and before the driver sees a
  key. Confinement runs on the *logical* path, which is the security-relevant
  one: the translation may only be applied to a path that already resolved
  inside the export, never as a way of getting there. This ordering is the whole
  security content of C13 — a translation that ran first could compose
  `<localroot>` with a client string and land outside.
- **PFN → LFN** on the listing path, so `enumerate` and directory reads render
  in logical terms. This is the direction that does not exist anywhere today and
  the reason a RAL-style export currently cannot present a coherent listing.
- Per-export configuration (`brix_n2n_scheme`, `brix_n2n_pool`,
  `brix_n2n_prefix`), validated at `nginx -t`.
- `sd_ceph_key` becomes the identity case of the shared translation, so the
  driver keeps working unchanged when the scheme is `IDENTITY`.

**Verification bar.** `site_n2n` has never run in production and its unit test is
the only thing that has ever executed it. Before it becomes load-bearing it gets
the treatment a new security-relevant path gets: traversal fuzzing on both
directions, round-trip property tests (`pfn2lfn(lfn2pfn(x)) == x` for every
scheme), and an explicit test that a `..` in the LFN is rejected *before* the
prefix is applied and not after.

**Honest scoping.** C13 benefits Ceph/RADOS sites and nothing else today. It is
in this phase because the alternative — a second partial copy inside the next
driver that needs it — is exactly the pattern the other three items are about,
and because a compiled, tested, config-listed module with no callers is a
maintenance liability regardless: it either gets wired or it gets deleted, and
this document takes the position that it gets wired.

---

## 5. What this phase deliberately leaves alone

- **The cache store's own file mechanics** (`cstore.c`, `meta.c`, `verify.c`,
  ~15 waivers). They are already a coherent, single-owner implementation of one
  domain, and `verify.c`'s nine waivers are one function's worth of staging I/O.
  Phase-107 C9 types them; C10 does not move them. Consolidating a subsystem
  that is already internally consistent buys churn, not safety.
- **The FRM and stage journals.** Append-only WAL records with their own
  crash-recovery model and their own tests. A journal is not a staged publish
  and pretending it is would lose the append semantics.
- **`recv_forward.c`'s four "metadata on a VFS-opened confined fd" waivers.**
  Those are already the correct pattern — the fd came from the VFS, and the
  waiver documents that the metadata call rides on it. Nothing to fold.
- **Operator config reads** (CMS blacklist, trust anchors, CA bundles). Host
  configuration, read-mostly. Typed by phase-107 C9, untouched otherwise
  (§1.2).
- **Anything in `client/`.** The native client has its own VFS backends and its
  own seam guard; this phase is server-side.

---

## 6. Observability

Three new signals, and deliberately no more — the point of consolidation is
fewer things to watch, not more:

- `brix_vfs_authz_backstop_total{result=agree|edge_missing|undecidable}` (C12) —
  the number the `observe` release exists to produce. `edge_missing` is the one
  that matters: non-zero means a path reached storage without the edge gate.
- One structured audit line per credential materialization (C11), with kind,
  path, principal and outcome. Today some sites log and none log alike, so
  "which credentials did this worker write" has no answer.
- `MUTATE_CREDENTIAL` joins the existing `brix_metric_vfs_mutation_denied` label
  set (C11). No new metric family and no new cardinality: the label vocabulary
  is bounded and the mirror's compile-time assert keeps it that way.

C10 and C13 add nothing. C10 reuses the publish counters it consolidates onto,
which is the tell that it is the same operation; C13 is a pure transformation
with no event to count.

The `domain` label on the mutation counter arrives with phase-107 C9, not here.
It is what turns "something wrote outside the export" from an audit question
into a graph, and this phase is its first heavy user.

---

## 7. Implementation waves

Each wave lands with success, error and security-negative tests (three per
change, per the standing rule). Every migration wave opens with its parity pin
(§3.5) and closes by re-running it.

Phase 107 v2 numbered these W10–W13; they are renumbered here and the mapping is
noted per wave so the older cross-references still resolve.

### W0 — Parity pins and the domain prerequisite *(new)*

- [ ] Verify phase-107 W9 has landed: `brix_vfs_domain_t`,
      `brix_vfs_domain_mutation()`, and `check_vfs_seam.py` enforcing the
      entitlement table. Nothing in this phase starts before that.
- [ ] Pin today's behaviour as tests that pass now: an OCI tag publish issues no
      fsync of any kind; each of the ~25 credential sites' mode, follow
      behaviour, fsync and error-path reaping; `site_n2n` has zero callers; a
      handler with its edge gate removed reaches storage.
- [ ] Record the waiver count per domain from the W9 annotation as the baseline
      the definition of done measures against.

### W1 — C11 credential materialization *(was W10)*

- [ ] `brix_vfs_cred_materialize()` / `_reap()` over the `CREDENTIAL` domain,
      taking a `brix_vfs_export_op_ctx_t` so the off-loop sites can use it.
- [ ] `MUTATE_CREDENTIAL` in the vocabulary; metric mirror 15 → 16; audit line.
- [ ] Parity table **before** migrating: for each of the ~25 sites, record mode,
      follow behaviour, fsync, and error-path reaping as it is today.
- [ ] Migrate the eleven files; the helper must be at least as strong as the
      strongest copy on every axis in the table.
- [ ] Uniform TTL reaping falls out; wire it and delete the per-subsystem
      cleanups it replaces.

### W2 — C10 staged publish for service storage *(was W11)*

- [ ] `brix_staged_publish_domain()` on `staged_file.h` with the three
      durability classes; `sync_publish` (phase-107 C3) applied per class.
- [ ] Parity table for each abandoned copy first (`oci_store.c` error-path
      reaping, `webdav/delegation.c` fsync+0600, `staged_file_commit.c` EXDEV).
- [ ] Migrate `oci_store.c`, `oci_meta.c`, `oci_referrers.c`, `tpc_marker.c`,
      `tpc_curl_multi.c`, `tpc_cred_exchange.c`.
- [ ] Point the OCI tag swap at phase-107 C6's `exchange`; the CAS presence
      probe at C8; the store index at `enumerate`.
- [ ] Prove the OCI tag pointer is durable — the bug this wave exists to close.

### W3 — C13 name mapping *(was W12)*

- [ ] Wire `site_n2n` as a path-layer stage: LFN→PFN **after** confinement,
      PFN→LFN on the listing path.
- [ ] `brix_n2n_scheme` / `_pool` / `_prefix` per-export directives, validated at
      `nginx -t`.
- [ ] `sd_ceph_key` becomes the `IDENTITY` case of the shared translation.
- [ ] Traversal fuzzing both directions; round-trip property test per scheme; an
      explicit test that `..` is rejected before the prefix is applied.

### W4 — C12 authorization backstop, observe only *(was W13)*

- [ ] Bind the compiled rule set onto `brix_vfs_ctx_t` at ctx init, the way
      phase 105 bound the mutation policy.
- [ ] `brix_vfs_require_authorized()` + the read-side twin; the op→`BRIX_AUTH_*`
      mapping table; fail-closed when it cannot decide.
- [ ] Slot it into the ordering rule at 1.5 — after policy, before the lock
      check — at every mutator and every read entry point.
- [ ] `brix_authz_backstop observe|enforce`, default `observe`;
      `brix_vfs_authz_backstop_total{result}`; `check_authz_backstop.py`.
- [ ] Run `observe` across all five live protocol lanes; the counter must be
      flat on `edge_missing`.
- [ ] The phase closes here. Proposing `enforce` as the default is the **first
      change of whatever comes next**, with its own release note and its own
      evidence from the fleet.

W1 and W2 are independent of each other and both depend only on phase-107 W9
(plus W3/W7/W1 of that phase for C10's verbs). W3 is independent of everything.
W4 ships last because it is the only item that can refuse traffic, and it ships
unable to.

---

## 8. Test matrix

### 8.1 Per-item, three tests minimum

| item | success | error | security-negative |
|---|---|---|---|
| C10 | OCI tag publish is durable and atomic through the shared path | EXDEV commit still works; error path still unlinks | the registry cannot publish into the `EXPORT` domain; each abandoned copy's guarantee is re-asserted |
| C11 | all ~25 sites materialize through one verb | write failure reaps the temp on every branch | tabular per-site assertion of mode/`O_NOFOLLOW`/fsync/reap — no site loses a property it had |
| C12 | backstop agrees with the edge on every allowed op, all five planes | cannot-decide (no rules bound, unmapped op) refuses, not passes | a handler with its edge gate removed is still refused by the VFS; the backstop is never more permissive than the edge |
| C13 | round-trip `pfn2lfn(lfn2pfn(x)) == x` per scheme; listings render logical | unknown scheme rejected at `nginx -t` | `..` rejected **before** the prefix is applied; translation cannot be reached by an unconfined path |

### 8.2 Cross-cutting

- **Consolidation parity**: every migration wave (W1, W2) opens with the table
  pinning the behaviour of each copy it will delete, and closes by re-running
  that table against the shared implementation. A consolidation that cannot
  produce this table has not established its bar (§3.5).
- **Backstop agreement (C12)**: a lane-wide `observe` run over the existing
  suite, asserting `edge_missing` stays at zero. This is a *test of the model*,
  not of the code: a non-zero counter means either a real uncovered path or a
  wrong op→privilege mapping, and both must be resolved before `enforce` is
  proposed.
- **Ordering**: position 1.5 asserted with the same spy that records
  policy → authz → lock → leaf → capability → credential → backend →
  invalidation. `EROFS` must still precede `EACCES` on a read-only export — a
  direct phase-105 Appendix I.5 obligation, and the easiest thing in this phase
  to break.
- **Domain entitlement**: after each wave, `check_vfs_seam.py` green **and** the
  waiver count in the migrated domain strictly lower than the W0 baseline.
- **Crash injection (C10)**: kill between write and rename, and between rename
  and the next read, on a registry publish. The pre-phase tree loses the tag.
- **Fleet**: the OCI lane for C10, the TPC/delegation lanes for C11, all five
  live protocol lanes for C12's `observe` run.

---

## 9. Expected file map

New:

```
src/fs/vfs/vfs_cred_file.c        C11 — credential materialize / reap
src/fs/vfs/vfs_authz.c            C12 — brix_vfs_require_authorized
src/fs/path/n2n_stage.c           C13 — the LFN<->PFN path stage
tools/ci/check_authz_backstop.py  C12 — every mutator calls the backstop
```

This phase is mostly subtraction. Each consolidating wave should end with a
smaller tree than it started:

```
src/protocols/oci/oci_store.c         -~120 lines of hand-rolled publish
src/protocols/oci/oci_meta.c          sidecar staging -> shared helper
src/protocols/oci/oci_referrers.c     index writes -> shared helper
src/protocols/webdav/delegation.c     -4 waivers, -1 documented sequence
src/protocols/webdav/tpc_*.c          TPC temps -> shared helper
src/tpc/outbound/tpc_token_exchange.c -6 waivers
src/net/proxy/gsi_upstream_login.c    -2 waivers
src/fs/cache/origin_auth*.c           -3 waivers
src/core/config/credential_block.c    -1 waiver
src/protocols/cvmfs/attest.c          -2 waivers
src/fs/backend/cred_mint.c            mechanics -> shared helper
```

Modified:

```
src/fs/vfs/vfs_policy.h/.c           vocabulary +1 (CREDENTIAL)
src/fs/vfs/vfs.h                     compiled rule set bound at ctx init (C12)
src/observability/metrics/unified.h  metric mirror 15 -> 16
src/core/compat/staged_file.h/.c     C10 — domain-aware publish entry point
src/auth/authz/auth_gate.h           C12 — protocol-neutral decision form
src/fs/path/path.h                   C13 — the translation stage's entry points
src/fs/backend/rados/sd_ceph.c       C13 — sd_ceph_key becomes the IDENTITY case
tools/ci/check_vfs_seam.py           entitlement table shrinks as waivers go
config                               new .c files (guard: check_config_coverage.py)
```

Every new `src/` `.c` file goes in the repo-root `./config` and requires a
re-`./configure --add-module=$REPO`; the coverage guard fails the build
otherwise.

---

## 10. Compatibility and rollout

**Behaviour changes visible to a running deployment**, in descending order of
risk:

1. **`brix_authz_backstop` (C12).** The highest-risk change in this phase and in
   phase 107, which is why it ships in `observe` and stays there. In `observe`
   it cannot refuse anything; the only way it affects a running deployment is a
   counter and a log line. `enforce` becomes the default only after the counter
   has been flat across the fleet lanes, and that flip is its own change with
   its own release note — not part of this phase.
2. **OCI publishes become durable (C10).** One extra fsync and one dirfsync per
   tag pointer, reference mark and index write. Registry writes are low-rate by
   nature; this is the intended cost of not losing a tag.
3. **Everything else is invisible.** C11 replaces implementations with a
   stronger shared one. C13 is inert unless an operator sets a scheme. Neither
   changes a wire answer, a directive default, or a supported configuration.

**Rollout order** follows the waves: W0 is a test-only wave and can land as soon
as phase-107 W9 does. W1 and W2 are independent and either may ship first. W3 is
independent of both. W4 ships last, in `observe`, and the phase closes without
flipping it.

**Rollback.** W1 and W2 are behaviour-preserving by construction — the parity
table is what makes that claim checkable — so a revert is a revert. W4's revert
is the directive: setting `brix_authz_backstop off` disables the kernel without
a rebuild, and that is why the directive has three values and not two.

---

## 11. Definition of done

- [ ] All four items implemented, or explicitly deferred here with the reason
      and the ceiling recorded.
- [ ] Vocabulary is 16 members; the metric mirror asserts equal at compile time.
- [ ] Every consolidation wave produced its parity table, and the shared
      implementation is at least as strong as every copy it replaced on every
      axis in that table.
- [ ] The `vfs-seam-allow` waiver count has **dropped** below the W0 baseline —
      C10 and C11 remove more waivers than phase-107 W9 annotated in their
      domains. A phase that leaves the count flat has typed the duplication
      instead of removing it.
- [ ] An OCI tag pointer survives a simulated crash between write and read.
- [ ] `brix_authz_backstop observe` runs clean — `edge_missing` at zero across
      all five live lanes — and `enforce` is **not** the default at the close of
      this phase.
- [ ] `site_n2n` has callers, a round-trip property test per scheme, and traversal
      fuzzing on both directions — or it has been deleted, and this document says
      which.
- [ ] `check_vfs_seam.py`, `check_vfs_mutation_gate.py`, `check_authz_backstop.py`,
      `check_config_coverage.py`, `check_duplication` all green with no new
      backlog entries.
- [ ] `objs/nginx -t` green for every new directive, including the negative
      config cases.
- [ ] The `--pr` tier is green; the five live protocol lanes are green.
- [ ] `src/fs/README.md`, `src/fs/backend/README.md`, the authz README and
      `agent-guide-extended.md` updated **after** the code matches them, never
      before.
- [ ] An implementation record appended to this document, in the shape phase 105
      used, **including the parity tables** — the properties each deleted copy
      had, and the evidence the shared implementation has them all.

---

## Appendix A — proposed types and API contracts

Sketches, not final code. Each carries the reasoning that constrains the final
signature.

### A.1 Domain-aware publish (C10)

```c
ngx_int_t brix_staged_publish_domain(ngx_log_t *log, const char *root_canon,
                                     brix_vfs_domain_t domain,
                                     brix_staged_t *staged,
                                     const char *final_path,
                                     const brix_sd_precond_t *pre);
```

Extends the existing `staged_file.h` family rather than replacing it:
`brix_staged_commit_excl()` becomes `brix_staged_publish_domain(..., EXPORT, ...,
&(brix_sd_precond_t){.kind = ABSENT})` and keeps its current callers working
through a thin wrapper until they move.

Applies `sync_publish` (phase-107 C3) when the domain is durable (§3.3), and
routes `EXDEV` to the existing `commit_cross_device` path — which is the one
guarantee none of the copies being deleted have, and the reason this
consolidation is a strict improvement rather than a lateral move.

`brix_sd_precond_t` is phase-107 C6's type; a NULL `pre` means "no precondition"
and is what the cache and stage domains pass.

### A.2 Credential materialization (C11)

```c
typedef enum {
    BRIX_VFS_CRED_BEARER = 0,   /* bearer token text                        */
    BRIX_VFS_CRED_X509_PROXY,   /* full proxy PEM (cert chain + key)        */
    BRIX_VFS_CRED_X509_KEY,     /* private key alone                        */
    BRIX_VFS_CRED_KEYTAB,       /* krb5 / SSS keytab bytes                  */
    BRIX_VFS_CRED_PEM_ANCHOR    /* trust anchor / CA bundle (CONFIG domain) */
} brix_vfs_cred_kind_t;

ngx_int_t brix_vfs_cred_materialize(const brix_vfs_export_op_ctx_t *opctx,
                                    const char *dir, const char *name,
                                    const u_char *bytes, size_t len,
                                    brix_vfs_cred_kind_t kind,
                                    char *path_out, size_t cap);
ngx_int_t brix_vfs_cred_reap(const brix_vfs_export_op_ctx_t *opctx,
                             const char *path);
```

Invariants, asserted once and tested per abandoned site:

| property | value | why it is not per-caller |
|---|---|---|
| open flags | `O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC` | `O_NOFOLLOW` is a symlink-attack defence; a site that omits it is a hole, not a variant |
| file mode | `0600` | a credential readable by the worker group is a credential leak |
| directory mode | `0700`, created if absent, mode verified if present | an inherited `0755` cred dir defeats the file mode |
| durability | fsync file, rename, dirfsync parent | `CREDENTIAL` is a durable domain (§3.3) |
| failure | unlink the temp on **every** error branch | a half-written proxy left on disk is worse than no proxy |
| audit | one structured line: kind, path, principal, outcome | today only some sites log, and none log uniformly |
| accounting | `MUTATE_CREDENTIAL` booked once | credential writes are currently invisible |

`kind` selects the audit label and the reaper's TTL class. It does **not** select
file mechanics — those are identical for all five, which is the finding that
makes one verb correct.

### A.3 Authorization backstop (C12)

```c
ngx_int_t brix_vfs_require_authorized(const brix_vfs_ctx_t *ctx,
                                      brix_vfs_mutation_op_t op);
ngx_int_t brix_vfs_require_authorized_read(const brix_vfs_ctx_t *ctx,
                                           int lookup_only);
```

`NGX_OK` when the ctx's identity holds the privilege the operation implies on the
resolved path. `NGX_ERROR` with `EACCES` when it does not, and `NGX_ERROR` with
`EACCES` when the kernel **cannot decide** — no rules bound, an uninterpretable
identity, an unmapped operation. Never `NGX_OK` on uncertainty.

Note the errno: `EACCES`, and it is emitted *after* the mutation kernel's
`EROFS`. Phase-105 Appendix I.5 requires that ordering, and it survives here
unchanged — a read-only endpoint still says only "read-only", never "you would
also have failed authorization".

Purity, and why it holds: rules are compiled and resolved against the export root
at postconfig (`acl.c`, `authdb.c`), so runtime matching is longest-prefix string
work (`find_rule.c`). No allocation, no I/O, no backend lookup — the same
properties the mutation kernel has, and the same reason it can run at ordering
position 1.5 before leaf resolution.

Binding: the compiled rule set is bound onto `brix_vfs_ctx_t` at ctx init, the way
`mutation_policy` and `storage_cred_dir` already are. A ctx with no rule set bound
is a ctx that cannot decide, which under `enforce` refuses — so binding is not
optional and the ctx-init tests assert it for every protocol front end.

### A.4 Name-translation stage (C13)

```c
/* src/fs/path/n2n_stage.c */
ngx_int_t brix_path_lfn_to_pfn(const brix_vfs_ctx_t *ctx,
                               const char *lfn, char *pfn, size_t cap);
ngx_int_t brix_path_pfn_to_lfn(const brix_vfs_ctx_t *ctx,
                               const char *pfn, char *lfn, size_t cap);
```

Thin wrappers binding the export's `brix_n2n_cfg_t` to the existing pure
`brix_n2n_lfn2pfn` / `brix_n2n_pfn2lfn`. The wrappers add the context; they must
not add logic — `site_n2n.c` stays pure and standalone-testable, which is the one
property it currently has and is worth keeping.

**Ordering is the security content.** `brix_path_lfn_to_pfn` may only be called
on a path that `resolve_path()` has already confined. The translation composes an
operator-configured prefix with a client-influenced string; running it before
confinement would let the prefix carry the result outside the export. The guard
for this is a call-order test, not a comment.

---

## Appendix B — risk register and deliberately rejected alternatives

### B.1 Risks

| risk | item | mitigation |
|---|---|---|
| A consolidation silently drops a property one copy had (`O_NOFOLLOW`, an fsync, an error-path unlink) | C10, C11 | the parity table is a wave entry criterion (§3.5): pin every copy's behaviour before deleting it, re-run the table after |
| The authz backstop is *more* permissive than the edge and reads as coverage | C12 | fail-closed on cannot-decide; the `observe` release exists to find exactly this; `edge_missing` at zero gates any future default flip |
| The op→privilege mapping is wrong for one protocol plane | C12 | `observe` across all five live lanes; a non-zero counter blocks the flip whether it is a real gap or a mapping error |
| `EACCES` leaks ahead of `EROFS` on a read-only export | C12 | phase-105 Appendix I.5 ordering asserted by the spy test at every mutator, not sampled |
| `site_n2n` becomes load-bearing having never run outside a unit test | C13 | traversal fuzzing both directions, round-trip property tests, and the confinement-ordering call-order test before it is wired |
| The registry's durability change slows a high-rate push | C10 | registry writes are tag pointers and indexes, not layer blobs; measured in the wave's exit criteria, and the domain class is the knob if it is wrong |
| Scope creeps into an ACL or admin API | C12 | §1.2 names it a non-goal; the domain type explicitly grants no authority (phase-107 §3.7) |
| Phase 107 slips and this phase starts anyway | all | W0's first checkbox is the prerequisite check; C10 without `exchange` and `sync_publish` would rebuild them a second time |

### B.2 Rejected alternatives

**Making the VFS the only authorization decision point (C12).** Rejected in
§1.2. The edge gate rejects before path resolution and backend work, composes
the protocol-correct refusal, and hosts the SHM verdict cache with its
per-worker L1 on the GSI hot path. Moving all three into the storage layer
trades a cheap backstop for an expensive migration and a worse hot path.

**Enforcing the authz backstop from day one (C12).** Rejected: 37 call sites,
five planes and a verdict cache means any modelling error is a site outage. One
release in `observe` converts that risk into a counter.

**Shipping `enforce` inside this phase once `observe` is clean (C12).**
Rejected: "clean across the lanes" is evidence from a test fleet, and the flip
needs evidence from real deployments. The phase closes with the counter, and the
flip is the next change.

**Deleting `site_n2n.c` instead of wiring it (C13).** Considered seriously —
deleting dead code is usually right. Rejected because the code is not wrong, it
is unwired: it implements two real GridPP schemes with a reverse direction that
nothing else in the tree has, and `sd_ceph.c` has already begun re-deriving a
partial version of it. Deleting it guarantees the second copy finishes growing.
The document takes a position either way, because the one outcome that must not
happen is a third year of it sitting compiled and uncalled.

**Consolidating the cache store's file mechanics (§5).** Rejected: it is
already a single-owner, internally consistent implementation of one domain.
Consolidation is for duplication, not for tidiness.

**Moving the OCI registry model, not just its file mechanics (C10).** Rejected:
the registry's semantics are protocol semantics. A VFS that knows what a
referrers index is has absorbed a protocol, which is the mirror image of the
mistake this phase is correcting.

**One `brix_vfs_secret_write()` that also handles in-memory credentials (C11).**
Rejected as speculative generality: the ~25 sites all write a file, and a verb
that sometimes writes a file and sometimes does not needs a caller to know which,
which is the ambiguity the consolidation exists to remove.

---

## Appendix C — CI guards and static enforcement

- **`check_vfs_seam.py`** — the guard that measures this phase. After phase-107
  W9 it parses a domain constant and checks a directory-prefix entitlement
  table; here, every wave should make its entitlement rows *shorter*. A wave
  that adds a waiver has to say why in review.
- **`check_vfs_mutation_gate.py`** — unchanged in contract. `MUTATE_CREDENTIAL`
  is booked through the domain form, so the guard sees it without modification.
- **A new guard, `check_authz_backstop.py` (C12)** — every VFS mutation entry
  point calls `brix_vfs_require_authorized` exactly as
  `check_vfs_mutation_gate.py` requires the policy kernel. Same shape, same
  waiver mechanism, and it is what stops the backstop from itself becoming a
  convention held in place by a comment.
- **`check_duplication`** — absolute, 0 backlog. Worth recording as a *limit* of
  the tool rather than a failure of it: the gate that ought to have caught C10
  and C11 did not, because a hand-rolled `open`/`write`/`rename` in
  `oci_store.c` is not textually similar enough to `staged_file.c` to trip a
  token-based detector. Structural duplication of a *contract* is invisible to
  it, and the census that does see it is the seam-waiver table (phase-107
  Appendix G). A rising waiver count in a domain is the signal
  `check_duplication` cannot give.
- **`check_config_coverage.py`** — three new `.c` files in the repo-root
  `config` and a re-`./configure`.
- **`check_vfs_identity_branch.py`** — C11's credential verb is on the identity
  path and must not grow a `_cred`-style asymmetry of its own.
- **Complexity contract** — absolute CCN/NPath. The authz mapping table is the
  one that will push a function over; it splits at the design stage rather than
  after the guard complains.

---

## Appendix D — requirement traceability

| item | §design | wave | tests | metric | guard |
|---|---|---|---|---|---|
| C10 service publish | §4 C10, A.1 | W2 | §8.1 C10, parity table, crash injection | reuses publish counters | seam guard, duplication census |
| C11 credential verb | §4 C11, A.2 | W1 | §8.1 C11, per-site parity table | `vfs_mutation_denied{op=credential}` + audit line | seam guard, identity branch |
| C12 authz backstop | §4 C12, A.3 | W4 | §8.1 C12, lane-wide observe, ordering spy | `vfs_authz_backstop_total{result}` | `check_authz_backstop.py` (new) |
| C13 n2n stage | §4 C13, A.4 | W3 | §8.1 C13, round-trip + traversal fuzz | — | config coverage, call-order test |

Prerequisites from phase 107, for the same table read the other way:

| this phase needs | phase-107 item | phase-107 wave |
|---|---|---|
| `brix_vfs_domain_t` + domain assert + enforcing seam guard | C9 | W9 |
| `sync_publish` (durable publish barrier) | C3 | W3 |
| `exchange` + typed precondition (`brix_sd_precond_t`) | C6 | W7 |
| the CAS/dedup gate | C8 | W1 |

---

*End of plan. Nothing in this document has been implemented. When a wave lands,
append its record here in the shape phase 105 used — what the sweep actually
found, not what it set out to find. That record must include the parity table:
the properties each deleted copy had, and the evidence the shared implementation
has them all.*
