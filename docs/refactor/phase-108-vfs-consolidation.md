# Phase 108 — VFS consolidation: the mutation work BriX-Cache does without the VFS

**Date:** 2026-08-31

**Status:** 📋 **PLANNED** — no code written. This document is the specification
the implementation will be judged against.

**Document version:** v2 — hyper-detailed pass over every section against the tree. Split out of
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
atomic tag swap over raw syscalls with no `fsync` anywhere, four independent
implementations of "write a secret to a file safely" that disagree on five of
the eight properties that make it safe, an authorization decision taken at 29
protocol-edge call sites in five different vocabularies over a rule engine that
already lives in `src/fs/path/`, and a name-translation module that is compiled,
unit-tested, listed in `config`, and called by nothing.

None of these is a feature a user cannot get. They are places where the cost of
*not* having gone through the VFS has already been paid — in a durability bug
the registry does not know it has, in a threat model restated four times and
implemented four different ways, in an authorization check that one code path
forgot in 2026-07 and had to be told about — and where it will keep being paid.

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
  today it is written by four implementations that agree on the mode and on
  nothing else, one of which stages a forwarded Kerberos TGT in an unvalidated
  `$TMPDIR` (§2.1).
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
| C10 | The OCI registry privately rebuilt staged publish, atomic tag swap, CAS presence and index listing over raw syscalls — **with no `fsync` anywhere**, in the one domain phase 107 marks durable | `oci_store.c:280–324` (`put_text`), `:262–275` (`publish`); 25 markers across five `oci/` files | correctness / duplication |
| C11 | One security invariant, **four implementations** that disagree on four properties; the weakest holds a forwarded Kerberos TGT | `core/compat/cred_stage.c:66`, `webdav/delegation.c:270–320`, `auth/krb5/deleg_capture.c:210–236`, `fs/backend/cred_mint.c:186` | security / duplication |
| C12 | Authorization is decided at **28 protocol-edge call sites**, 26 of them on one plane, plus **four other schemes on four other planes** — over a rule engine already living in `src/fs/path/` that the VFS never asks | `brix_auth_gate` ×19, `_op` ×3, `brix_authz_check` ×4, `brix_acc_http_authorize` ×2; `oci_authz.c:182`, `dig.c:58`, `ftp_ev_path.c:118`, `cvmfs/gate.c:298`; `vfs.h:104`; `path.h:45,80` | security |
| C13 | `site_n2n.c` — compiled, unit-tested, config-listed, and called by nothing; `sd_ceph.c` carries a one-way near-duplicate at 14 call sites that **disagrees with it about `..`** | `config:988`, `tests/c/test_site_n2n.c`, zero callers; `sd_ceph.c:204–228`, `:166–201` | dead seam |

#### C10 — the registry publishes nothing durably

`brix_oci_store_put_text` (`oci_store.c:280–324`) is the registry's publish
primitive. In full: `mkparent`, format a temp name `"%s.tmp.%ld"` from the final
path and `ngx_pid`, `open(tmp, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644)`
(`:296`), an `EINTR`-safe write loop, `close`, `rename` (`:318`), `unlink` on
either error path. Four things are missing and each one is a defect on its own:

1. **No `fsync` of the temp before the rename.** The rename can reach stable
   storage before the bytes do, so a crash publishes an empty or short file at
   a name that claims to hold a manifest. This is the same defect phase-107 C3
   fixes for exports, in code C3 as written does not reach.
2. **No directory flush after the rename** — phase-107 C3's other half.
3. **`close(fd)`'s result is discarded** (`(void) close(fd)`, `:315`). On a
   network or quota-limited filesystem the write error surfaces at `close`, and
   here it is thrown away immediately before the rename publishes the file.
4. **`O_TRUNC`, not `O_EXCL`, and no `O_NOFOLLOW`.** Every other staged writer
   in this tree creates exclusively; this one truncates whatever it finds at a
   predictable path. A same-worker retry silently truncates its own previous
   temp, and a symlink at that path is followed.

What travels through this primitive is not incidental bookkeeping. Six call
sites:

| call site | what is published |
|---|---|
| `oci_manifest_put.c:189` | **the manifest body itself** |
| `oci_store.c:417` (`brix_oci_store_tag_set`) | **the tag pointer** — `<digest>\n` |
| `oci_store.c:476` | a layer reference mark (empty file; the name is the fact) |
| `oci_referrers.c:224`, `:244` | referrers index entries |
| `oci_upload.c:266` | an upload part marker |

plus `brix_oci_store_publish` (`:262–275`, `mkparent` + `rename`, no flush of
anything) which seals **the blob** at `oci_upload_seal.c:107`.

So a power loss between a `201 Created` and the next flush can lose a manifest,
a tag, a referrers entry, an upload part or a sealed blob, and the client has
already been told the push succeeded. `REGISTRY` is one of the three domains
[phase 107 Appendix G.1](phase-107-vfs-mutation-surface-completion.md#g1-the-seven-domains)
marks **durable: yes**, and it is the domain with the least durability in the
tree.

The neighbouring waivers name the missing verbs almost exactly:
`"atomic tag/mark swap — a concurrent reader sees old or new, never torn"`
(`:318`) is C6's `exchange` with a hand-written comment where the slot should
be; `"store presence probe (CAS existence, no bytes read)"` is C8's dedup
plane; `"registry's own store index, not a VFS export listing"` is `enumerate`.
The 25 markers cluster the same way: `oci_store.c` 14, `oci_upload.c` 4,
`oci_meta.c` 4, `oci_referrers.c` 2, `oci_upload_seal.c` 1. The registry did
not do anything wrong — those verbs either did not exist or were not reachable
for service storage. Phase 107 creates them; C10 is what makes creating them
pay twice.

#### C11 — one invariant, four implementations

The framing that matters: **the shared helper already exists and is good.**
`brix_cred_stage_write` (`core/compat/cred_stage.c:66`) stages a secret into a
per-uid tmpfs directory, and `brix_cred_stage_dir` (`:26`) validates that
directory fail-closed — `mkdir 0700`, then `lstat` and refuse unless it is a
real directory, owned by the effective uid, with `(mode & 0077) == 0`. Its
comment says what it is defending against: `/dev/shm` is `1777`, so the
boundary is the subdirectory's own mode and ownership, and a squatter, a
loosened mode or a symlink fails closed rather than being trusted.

Six call sites reach it, through two entry points:

| entry point | call sites |
|---|---|
| `brix_cred_stage_write` directly | `tpc/outbound/tpc_token_exchange.c:104`, `net/proxy/gsi_upstream.c:26`, `webdav/tpc_cred_exchange.c:59` |
| `brix_proxy_gsi_write_pem_temp` (a 10-line wrapper, `gsi_upstream.c:18–27`) | `fs/vfs/vfs_deleg_x509.c:189`, `net/proxy/gsi_upstream_login.c:208`, `webdav/tpc_user_proxy.c:84` |

Three other places do it themselves, and they disagree:

| property | `cred_stage.c:66` | `delegation.c:270` | `deleg_capture.c:210` | `cred_mint.c:186` |
|---|---|---|---|---|
| directory | per-uid `/dev/shm/brix-creds.<uid>`, **validated fail-closed** | the configured credential dir (same-dir temp) | **`$TMPDIR` or `/tmp`, unvalidated** | the configured credential dir |
| create | `mkstemp` | `O_CREAT\|O_EXCL\|O_WRONLY\|O_NOFOLLOW`, 0600 | `mkstemp` | `O_CREAT\|O_EXCL\|O_WRONLY\|O_NOFOLLOW`, 0600 (×5) |
| mode | defensive `fchmod` 0600 after create | 0600 at create | 0600 from `mkstemp`, then **closed and rewritten by name** | 0600 at create |
| write | `EINTR`-safe loop, full length | one `write()`, short = error, **no `EINTR` retry** (`:303`) | delegated to libkrb5 | one `write()`, short = error, **no `EINTR` retry** (`:195`) |
| `fsync` | no — **correctly**, it is tmpfs | yes (`:303`) | no | yes (×7) |
| temp name | `mkstemp` random suffix | **deterministic** `.<key>.pem.upload.<pid>` (`:276`) | `mkstemp` random suffix | **deterministic** `.mint-<stem>.<pid>.tmp` |
| publish | none — the temp *is* the artifact | `rename` (`:312`) | none | `rename` (`:284`) |
| dir fsync after rename | n/a (no publish) | **no** | n/a | **no** |
| reap on error | `unlink` on every path | `unlink` on every path | **none** | `unlink` |
| `close()` checked | yes (`:121`) | no (×2) | n/a | **no** (`:203`) |
| holds | bearer bodies, GSI proxy PEM | delegated proxy PEM | **a forwarded Kerberos TGT** | minted credentials |

`cred_mint.c` is the strongest and `deleg_capture.c` is the weakest, and they
are inversely matched to the value of what they hold. `brix_krb5_deleg_mkccache`
(`:210–236`) writes a **forwarded TGT** — the highest-value secret this server
ever touches — into `$TMPDIR` or `/tmp` with no ownership or mode check on the
directory, `close()`s the descriptor immediately (`:235`), and hands the *path*
to libkrb5 to rewrite by name. The comment says "keeping mode 0600", which is
true of the file libkrb5 finds; the property that is not established is that
the name still refers to the file `mkstemp` created. That is CWE-377 in the
one place the tree already built a fail-closed answer for it, six lines away in
a different file.

So C11 is not "extract a helper from twenty-five copies". The helper exists;
the work is to make it the **only** way a credential reaches a file, to give it
the durable-publish arm that `delegation.c` and `cred_mint.c` need (which is
phase-107 C3, already built), and to delete three implementations — starting
with the one holding the TGT.

#### C12 — authorization has no backstop

Read this against phase 105's own §2. Before that phase, "may this endpoint
write?" was a bare `allow_write` bit tested in a handful of places, so a mutator
that forgot the test reached a storage driver. Authorization today is in exactly
that state, and the census says so precisely:

| entry point | sites | planes |
|---|---|---|
| `brix_auth_gate` | 20 | root |
| `brix_auth_gate_op` | 3 | root (`open_request_resolve.c:299`, `mv.c:409`, `:428`) |
| `brix_authz_check` (decision-only) | 4 | root (`statx.c:139`, `open_tpc.c:113`, `prepare_check.c:79`, `prepare_qprep.c:52`) |
| `brix_acc_http_authorize` | 2 | webdav (`access.c:109`), s3 (`handler.c:113`) |
| **total** | **29** | **27 root · 1 webdav · 1 s3** |

**The other four planes each authorize by a scheme of their own, and none of
the four calls into the table above:**

| plane | its scheme | site | covers |
|---|---|---|---|
| `oci` | its own registry authz (Basic/bearer principal → repository scope) | `oci_authz.c:182`, called once at `oci_registry.c:316` | the whole registry surface |
| `dig` | a fail-closed principal→export **allow-file**; anonymous, unset or unreadable all deny 403 | `dig.c:58`, called at `:263` | export enumeration only |
| `gridftp` | **tier 2 only** — `brix_check_vo_acl_identity`, no authdb and no token scope | `ftp_ev_path.c:118` | every path op on the plane |
| `cvmfs` | **no principal authz at all** — a method gate (`GET`/`HEAD`, `gate.c:298`) plus URI classification | `gate.c` | read-only cache serve |

That is the finding, and it is deliberately not "four planes are unprotected".
Three of the four have a defensible scheme and the fourth is read-only. The
finding is that there are **five authorization vocabularies in one server**
— the three-tier gate, an OCI repository scope, a `dig` allow-file, a bare VO
ACL — and **no single place knows whether any of them ran**. Each one may be
individually correct; nothing checks, and nothing fails if the answer changes.

`gridftp` is the row that should worry a reviewer most, because it is the only
one that looks like the main gate and is not: the same matcher, tier 2 of three,
on a plane whose whole purpose is bulk data movement. Its own comment says so
(`ftp_ev_path.c:115`: "Same matcher/semantics as the HTTP/root planes
(`brix_auth_gate`)") — which is true of the matcher and not of the gate.

A backstop in the VFS is what turns "we believe these planes are covered" into
"an ungated mutation cannot reach a driver".

One difference from phase 105 makes this *more* tractable, not less: every
ingredient is already present and unassembled.

- The rule engine is already in the fs layer — `brix_find_authdb_rule`
  (`path.h:45`), `brix_find_authdb_rule_identity` (`:49`), `brix_check_authdb`
  (`:80`), `brix_check_authdb_identity` (`:110`), with `brix_authdb_query_t`
  (`:105`) as the typed query.
- The rules are compiled at postconfig (`brix_finalize_authdb_rules`,
  `path.h:25`; `brix_authdb_rules_finalize_copy`, `:30`), so runtime matching is
  pure string work — no allocation, no I/O, which is exactly the property that
  let phase 105's kernel run before leaf resolution.
- A decision-only entry point already exists: `brix_authz_check`, documented as
  sending nothing on the wire.
- `brix_vfs_ctx_t` has carried `brix_identity_t *identity` since phase 55
  (`vfs.h:104`) and uses it **only** to pick a backend credential
  (`vfs_cred.c:242`, `:338`, `:351`) — never to decide anything.

Only two sites outside `src/auth/` touch the rule engine directly
(`core/config/policy.c:293`, `webdav/config_merge.c:182`), and both are
config-time finalization, not runtime decisions. The runtime surface really is
the 29.

The proof that the class bites is in the authz README: the 2026-07-06
cache-authz fix made `open_cache.c` run the *full* gate because "serve and fill
helpers are deliberately auth-free so this gate cannot be bypassed." That is a
correct fix and a fragile one — it is a convention the next helper must also be
told about, and a convention is what a backstop replaces.

#### C13 — a mapping seam built once and wired nowhere

`site_n2n.c` implements the two real GridPP naming schemes
(`BRIX_N2N_RAL`: `<pool>:<prefix><lfn>`; `BRIX_N2N_CEPHFS_PATH`:
`<localroot><lfn>`), rejects `..` traversal, has a reverse `pfn2lfn` for
rendering listings in logical terms, ships a standalone unit test
(`tests/c/test_site_n2n.c`), and is listed in `config:988`. It has **no
production callers** — `BRIX_N2N_IDENTITY` is the only behaviour anything gets,
by never asking.

Meanwhile `sd_ceph_key()` (`sd_ceph.c:204–228`) carries prefix-plus-normalize:
forward direction only, no pool scheme, no reverse. It has **14 production call
sites** across five files inside the RADOS driver (§4/C13.1), and `key_prefix`
as a concept exists nowhere else in the tree except `src/fs/backend/rados/`.

It is not a *strict* subset, which is what makes this item more than tidying.
`sd_ceph_normalize` (`sd_ceph.c:166–201`) **resolves** `..` by popping and
rejects only an escape above the root; `site_n2n` **rejects** any `..`
component outright. `/a/../b` is `<prefix>/b` under one and an error under the
other. The two implementations of one concern disagree about a
security-relevant input, and neither knows the other exists — §4/C13.2 is where
that gets decided.

The mapping concern was built once generally, wired nowhere, and then re-solved
partially and differently inside one driver. C13 is the smallest item here and
the only one whose success condition is partly measured in deleted lines.

### 2.2 Why now, and in this order

1. **Phase 107 creates the verbs this phase needs.** `exchange` (C6),
   `sync_publish` (C3), the CAS gate (C8) and the typed precondition (C6) are
   precisely the four things `oci_store.c` hand-rolled. Building them for
   exports and not pointing them at the registry means shipping the fix next to
   the bug.
2. **Every item here is a place a phase-107 invariant is currently
   unenforced.** The registry publishes without durability; four credential
   implementations restate one security invariant and disagree; authorization has no
   backstop. Phase 107 hardens the export path and leaves these at their current
   strength, which widens the gap between "the way the VFS does it" and "the way
   this subsystem does it".
3. **The consolidation is bounded and mostly mechanical.** Three of the four
   items delete code. Only C12 adds a decision.

---

## 3. Normative model

### 3.1 The vocabulary grows by one

`brix_vfs_mutation_op_t` (`src/fs/vfs/vfs_policy.h`) is append-only by contract.
It has 11 members today, becomes **15** after phase-107 W1 (`STAGE`, `EVICT`,
`LOCK`, `DEDUP`), and this phase appends exactly one more:

| value | covers | introduced by |
|---|---|---|
| `BRIX_VFS_MUTATE_CREDENTIAL` | materialise or reap a credential file in the service domain | C11 |

`BRIX_VFS_MUTATE_OP_COUNT` becomes **16**.

#### The six files that must move together

Appending one enum member touches six files, and five of them are outside
`src/fs/`. Phase-107 §7.1 calls this the six-file mirror; the anchors as
measured on `480ded2e4` are:

| # | file | what changes | why it cannot be deferred |
|---|---|---|---|
| 1 | `src/fs/vfs/vfs_policy.h` | the enum member + `_OP_COUNT` | the vocabulary itself |
| 2 | `src/observability/metrics/metrics.h:414` | the SHM cube's second dimension | a stale bound writes past the array or drops a column |
| 3 | `src/observability/metrics/unified_record.c:354–383` | the record path's bounds check | records for the new op silently vanish |
| 4 | `src/observability/metrics/unified_export.c:140–171` | the emit loop (registered at `:435`) | the family stops matching the cube |
| 5 | `src/observability/metrics/unified.c:163` | the label-names array | an off-by-one renders the wrong label for **every** op above the insertion point |
| 6 | `src/observability/metrics/unified.h:275` | `BRIX_VFS_MUTATE_OP_METRIC_COUNT` | — |

and `src/fs/vfs/vfs_policy.c:33` holds the `_Static_assert` that ties 1 to 6.
**A commit that changes 1 without 6 does not compile**, which is the design: the
assert exists so this can never be a runtime surprise. Files 2–5 are the ones an
incomplete commit *would* let through, so W1 changes all six or none.

The metric label for the new member is `"credential"`, appended to the array at
`unified.c:163` in enum order. Appending — never inserting — is what keeps every
existing series' label stable across the upgrade.

#### The other three items add no vocabulary

- **C10** reuses `PUBLISH` and `RENAME` on a different *domain*. That is exactly
  what the domain label (phase-107 §7.5) is for: the same op in a different
  place is a different series, not a different word.
- **C12** is an authorization axis, not a mutation. It gets its own family
  (§6), not a vocabulary entry.
- **C13** is a path transformation and not a mutation at all.

The values are labels for diagnostics and low-cardinality metrics
(INVARIANT #8). As phase 105 states and this phase repeats: **they never exempt
a backend, a protocol or a path.** A reviewer who sees a `switch` on
`brix_vfs_mutation_op_t` that changes behaviour rather than a label should
reject it.
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

Phase-107 C3 makes a publish durable on demand. For **export** storage that is
an operator's cost/safety call, which is why it is a directive. For **service**
storage it is not a per-operator question at all — it is a property of what the
storage *is* — so this phase fixes it per domain, and phase-107
[Appendix G.1](phase-107-vfs-mutation-surface-completion.md#g1-the-seven-domains)
carries the column so there is one table and not two.

| domain | class | consequence of loss | what the verb does |
|---|---|---|---|
| `REGISTRY` | **durable** | a manifest, tag or blob the client was told was `201 Created` | fsync temp → rename → fsync parent |
| `JOURNAL` | **durable** | a stage/FRM record whose replay is the recovery mechanism | same |
| `CREDENTIAL` | **durable — on the persistent arm only** (see below) | a minted proxy or delegated PEM that must outlive a restart | same, on `[PERSISTENT]` |
| `CACHE` | not durable | a re-fetch | no fsync; rename only |
| `STAGE` | not durable | a retried transfer or upload | no fsync; rename only |
| `CONFIG` | n/a | read-mostly; this phase writes none | — |
| `EXPORT` | per `brix_durable_publish` | the operator's call | phase-107 C3 |

#### The `CREDENTIAL` carve-out, which is a security property and not an exception

`brix_cred_stage_write` (`cred_stage.c:66`) does **not** fsync, and must not
start. Its artifact lives in `/dev/shm/brix-creds.<euid>` and is handed to a
fork/exec'd helper that reads it by path; it is deliberately volatile, and the
fact that it does not survive a reboot is one of the reasons the design chose
tmpfs (`cred_stage.h:14–18`: "tmpfs keeps nothing on disk or in backups").
Making the `CREDENTIAL` domain uniformly durable would take a secret that is
currently guaranteed not to persist and persist it.

So the domain's durability is a property of the **arm**, not of the domain
alone — `[VOLATILE]` never syncs, `[PERSISTENT]` always does — and C11's request
type makes the arm explicit rather than inferring it from the path. Inference
would be the wrong mechanism twice over: it would depend on a `statfs` probe of
the destination, and a filesystem type is not an authorization for a durability
decision.

The general rule the table encodes: **durability is a claim about what a caller
was told, not about the medium.** `REGISTRY` is durable because the registry
answers `201 Created`. `CACHE` is not, because a cache miss is a correct answer.
`[VOLATILE]` credentials are not, because nothing is ever told they persist.
### 3.4 The ordering rule gains position 1.5

Phase-107 §3.4 fixes the order every mutator obeys. C12 fills the position that
document reserves. The full order, with the new step marked:

| # | step | entry point | refusal |
|---|---|---|---|
| 1 | **policy** | `brix_vfs_require_confined_mutation()` (phase 105) | `EROFS` |
| **1.5** | **authorization** *(new — C12)* | `brix_vfs_require_authorized()` | `EACCES` |
| 2 | lock | `brix_vfs_require_unlocked()` (phase-107 C7) | `EBUSY` / `423` |
| 3 | confinement | `brix_*_beneath` | `EINVAL` |
| 4 | leaf resolution | `brix_vfs_ns_leaf()` (`vfs_cred.c:510`) | driver errno |
| 5 | capability probe | `brix_sd_caps()` | `ENOSYS` |
| 6 | credential resolution | the `_cred` slot family | driver errno |
| 7 | backend work | the driver slot | driver errno |
| 8 | cache invalidation | the decorator | — |

Three properties of that order matter and each is testable:

- **1 before 1.5.** A read-only endpoint answers `EROFS` and nothing else. If
  authorization spoke first, a read-only endpoint would leak, through the
  difference between `EACCES` and `EROFS`, whether the caller *would* have been
  authorized. Phase 105 built the non-disclosure property; C12 must not spend
  it.
- **1.5 before 2.** Authorization is a property of the caller; a lock is a
  property of the resource. An unauthorized caller must not learn that a
  resource is locked, and must not be able to probe lock state by attempting
  writes.
- **1.5 before 4.** The kernel is pure — pre-resolved rules, string matching, no
  allocation once the `xrdacc` entity is memoized (§4/C12.1) — which is what
  lets it run before leaf resolution, exactly as phase 105's purity is what let
  the mutation kernel run there.

The ordering is asserted by test, not by convention: the same spy-recorded
sequence phase 105 used to find four defects, extended with the 1.5 slot
(§8.2).
### 3.5 The parity-table discipline

This is the method of the whole phase, and it is the reason the waves are shaped
the way they are.

A consolidation lands only when the shared version is **at least as strong** as
every copy it replaces, on **every** axis. A helper that loses
`webdav/delegation.c`'s fsync, or drops `oci_store.c`'s unlink-on-error, is not
a consolidation — it is a regression with fewer lines, and it is a regression
nothing will notice, because the property that vanished was never asserted.

#### The table's columns are fixed

| column | question |
|---|---|
| create flags | `O_EXCL`? `O_NOFOLLOW`? `O_TRUNC`? `O_CLOEXEC`? |
| file mode | what mode does the object carry when it becomes visible? |
| dir mode / validation | is the containing directory created, and is its owner/mode checked? |
| write | full length? `EINTR`-safe? short-write handling? |
| `close()` | is the result checked, or discarded? |
| `fsync` (data) | before the publish, or not at all? |
| `fsync` (dir) | after the publish, or not at all? |
| publish | `rename`, `RENAME_NOREPLACE`, or none? |
| reap on error | is the temp unlinked on **every** failure branch? |
| logging | which failure branches log, at what level? |
| accounting | is a metric booked, and on which outcomes? |

§2.1's four-implementation credential table is that table, already filled in for
C11. C10 and C13 each open with their own.

#### The discipline

Every migration wave **opens** by filling the table for each copy it intends to
delete, **with a test per row** asserting today's behaviour — against today's
code, before anything moves. The wave **closes** by re-running the same tests
against the shared implementation.

Three rules make this more than paperwork:

1. **The tests are written against the copy, not the helper.** A test authored
   after the migration tests what was built; a test authored before tests what
   was there. Only the second can detect a silently dropped property.
2. **A cell that is worse in the shared version is a blocker, not a note.** The
   only sanctioned way past it is to state in the wave's section why the
   property was wrong to have — as §3.3 does for `cred_stage.c`'s absent
   `fsync`, which is a *correct* absence and is recorded as such rather than
   "fixed".
3. **A wave that cannot produce the table has not established its bar and does
   not land.** This is the clause that stops "consolidate first, verify later",
   which is how a security invariant becomes a security incident.

The table is written before the first caller moves because the properties being
pinned — `O_NOFOLLOW`, a checked `close()`, an unlink on the third failure
branch — are exactly the ones that are easy to lose silently and impossible to
notice missing.
---

## 4. Per-item design

### C10 — The staged-publish surface reaches service storage

#### C10.1 What is actually there today

Two functions in `src/protocols/oci/oci_store.c` are the registry's entire
publish surface. Both are short enough to quote in full in §2.1, and both are
reproduced here as the migration target:

| function | lines | body | callers |
|---|---|---|---|
| `brix_oci_store_publish` | `:262–275` | `mkparent` → `rename` | 1 (`oci_upload_seal.c:107`, sealing **the blob**) |
| `brix_oci_store_put_text` | `:280–324` | `mkparent` → `oci_store_fmt("%s.tmp.%ld", final, ngx_pid)` → `open(O_WRONLY\|O_CREAT\|O_TRUNC\|O_CLOEXEC, 0600)` → `EINTR` write loop → `(void) close` → `rename` → `unlink` on both error paths | 6 |

`OCI_STORE_FILE_MODE` is `0600` and `OCI_STORE_DIR_MODE` is `0700`
(`oci_store.c:41–42`) — the modes are already right, and are the one property
this item does not have to fix.

Five defects, in the order a reviewer meets them:

| # | defect | site | consequence |
|---|---|---|---|
| D1 | no `fsync` of the temp before the `rename` | `:315` | a crash publishes a **short or empty** manifest/tag at a name that claims to hold it |
| D2 | no `fsync` of the parent directory after the `rename` | `:318` | the rename itself can be lost; the object reverts to its previous version with no error anywhere |
| D3 | `close()`'s result discarded (`(void) close(fd)`) | `:315` | on a network or quota-limited store the write error surfaces at `close` and is thrown away **one line before** the rename publishes the file |
| D4 | `O_TRUNC` and no `O_NOFOLLOW`, at a **predictable** name (`<final>.tmp.<pid>`) | `:296` | a symlink planted at that name is followed; a same-worker retry truncates its own previous temp instead of failing |
| D5 | the write-loop failure branch returns `NGX_ERROR` with **no log line** | `:302–309` | the only publish failure in the tree that is silent; the client sees `500` and the operator sees nothing |

D5 is the one that is invisible in review: the two `rename`/`open` branches do
log (`:299`, `:319`), so the function *looks* uniformly instrumented.

#### C10.2 What the neighbouring waivers already say

The four `vfs-seam-allow` reasons on these two functions name the missing verbs
almost exactly, in the tree's own words:

| waiver text | the verb it is describing | phase-107 item |
|---|---|---|
| `"atomic tag/mark swap — a concurrent reader sees old or new, never torn"` (`:318`) | `exchange` | [C6](phase-107-vfs-mutation-surface-completion.md#c6--conditional-publish-and-atomic-exchange) |
| `"atomic store publish; the object never exists partially at its final path"` (`:268`) | durable publish | [C3](phase-107-vfs-mutation-surface-completion.md#c3--durable-publish-barrier) |
| `"store bookkeeping record (tag pointer / ref mark), staged for the rename below"` (`:296`) | staged publish | existing `brix_staged_*` |
| `"drop our own failed staging file"` (`:307`, `:321`) | staged abort | existing `brix_staged_abort` |

A waiver that describes a verb the VFS does not have is a design note. A waiver
that describes a verb the VFS *does* have is a consolidation gap. Phase 107 is
what moves each of these rows from the first category to the second — which is
the whole reason this phase is sequenced after it.

There is a fifth, in `oci_upload_seal.c:104–110`:

```c
if (!brix_oci_store_exists(blob, NULL)
    && brix_oci_store_publish(part, blob, log) != NGX_OK)
```

a presence probe followed by a non-atomic publish. The comment argues, correctly,
that a CAS race is benign because both writers hash to the same digest. That
argument is sound for the *bytes* and silent about the *inode*: two workers can
both pass `exists()`, and the loser's `rename` replaces a blob another request
may already have opened. `brix_staged_commit_excl` (`staged_file.h:118`,
`RENAME_NOREPLACE` with a documented `EEXIST` return) expresses the same
intent atomically and is already in the tree.

#### C10.3 The consolidated verb

A new unit, `src/core/compat/service_publish.{c,h}`, sitting **beside**
`staged_file.c` rather than inside it — `staged_file.c` is 388 lines against the
600-line cap (`check_file_size.py`), and the domain-aware arm is a different
concern from the export staging state machine.

```c
/* src/core/compat/service_publish.h */
#include "fs/vfs/vfs_policy.h"   /* brix_vfs_domain_t — precedent: core/types/file.h:5 */

typedef struct {
    ngx_log_t         *log;
    brix_vfs_domain_t  domain;       /* REGISTRY / CREDENTIAL / CACHE / STAGE / CONFIG / JOURNAL */
    const char        *root_canon;   /* confinement root (the store root, never "/") */
    const char        *final_path;
    mode_t             mode;         /* published mode; 0 keeps the temp's */
    unsigned           excl:1;       /* publish only if absent (RENAME_NOREPLACE) */
} brix_service_publish_req_t;

/* Stage `len` bytes and publish them at req->final_path atomically, with the
 * durability class of req->domain (§3.3). NGX_OK, or NGX_ERROR with errno:
 *   EROFS      — the domain assert refused (brix_vfs_domain_mutation)
 *   EINVAL     — req NULL, domain out of range, final_path outside root_canon
 *   EEXIST     — req->excl and the final path exists (caller maps to 409/412)
 *   ENOSPC/EIO/EDQUOT — surfaced verbatim from the write, close or fsync
 * No file is left behind on any failure path. */
ngx_int_t brix_service_publish_bytes(const brix_service_publish_req_t *req,
    const void *bytes, size_t len);

/* Publish an already-written staged file (the caller owns its fd and has
 * finished writing). Same contract; `fd` is fsynced before the rename when the
 * domain is durable, and may be NGX_INVALID_FILE when it is not. */
ngx_int_t brix_service_publish_fd(const brix_service_publish_req_t *req,
    ngx_fd_t fd, const char *stage_path);
```

The body is a composition of things that already exist, not new mechanism:

1. `brix_vfs_domain_mutation(NULL, req->domain, BRIX_VFS_MUTATE_PUBLISH)` —
   phase-107 [A.3](phase-107-vfs-mutation-surface-completion.md#a3-domain-assert-c8-c9).
   First, before any syscall, so a refusal discloses nothing (§3.4).
2. `brix_staged_open()` with `req->root_canon` / `req->final_path` /
   `req->mode` (`staged_file.h:76`) — which gives `O_EXCL`, `O_NOFOLLOW`, the
   random suffix, the confinement check and the retry budget **for free**, and
   closes D4 by construction.
3. The `EINTR` write loop, lifted verbatim from `oci_store.c:302–309` with the
   missing `ERR` line added (D5).
4. A **checked** `close()` (D3) — `cred_stage.c:121` is the precedent for
   treating the close as a write error rather than a cleanup step.
5. `fsync(fd)` before the rename when `§3.3` classes the domain durable (D1),
   modelled on `staged_file.c:274–281`, which already unlinks the temp and
   refuses to publish if the data fsync fails.
6. `brix_staged_commit()` or `brix_staged_commit_excl()` per `req->excl`
   (`staged_file.h:113`/`:118`), which routes through
   `brix_rename_beneath{,_excl}` (`staged_file.c:306`) — confined, and on the
   `excl` arm `RENAME_NOREPLACE` with the documented `ENOSYS` fallback
   (`beneath.c:308–333`).
7. The directory flush (D2) — **and this is the one place C10 must not copy an
   existing line.** `staged_file.c:317–319` already attempts it and is inert:

   ```c
   /* C1: persist the directory entry so the rename itself survives a crash
    * (best-effort — the data is already durable above). */
   (void) fsync(rootfd);
   ```

   `rootfd` comes from `brix_beneath_open_root()` (`beneath.c:79`), which opens
   with `O_PATH|O_DIRECTORY|O_CLOEXEC`. `fsync` on an `O_PATH` descriptor
   returns `EBADF`, and the `(void)` discards it — so the flush has never
   happened, anywhere, for any caller. It is also the wrong directory: `rootfd`
   is the export root while `final_rel` may be several levels below it.
   Phase-107 C3's `sync_publish` fixes this for exports by deriving the parent
   fd through the confined path and opening it `O_RDONLY`. C10 uses the same
   derivation and **must not** reuse `rootfd`.
8. `brix_staged_abort()` on every failure branch (`staged_file.h:121`), which is
   what `oci_store.c` was hand-rolling with its two `unlink` calls.

Nothing in that list is new code except the composition and the parent-fd
derivation shared with C3.

#### C10.4 Call-site migration

Seven sites, in the order W2 moves them:

| # | site | publishes | `excl` | domain | note |
|---|---|---|---|---|---|
| 1 | `oci_store.c:476` (`brix_oci_store_mark_layer`) | a layer ref mark (empty file — the *name* is the fact) | no | `REGISTRY` | zero-length; the smallest possible first mover |
| 2 | `oci_referrers.c:224`, `:244` | referrers index entries | no | `REGISTRY` | two sites, one shape |
| 3 | `oci_upload.c:266` | an upload part marker | no | `STAGE` | **not** `REGISTRY` — a lost part marker is a retried upload (§3.3) |
| 4 | `oci_store.c:417` (`brix_oci_store_tag_set`) | the tag pointer, `<digest>\n` | no | `REGISTRY` | a tag swap is deliberately *not* `excl`: overwriting is the operation |
| 5 | `oci_manifest_put.c:189` | **the manifest body** | no | `REGISTRY` | the highest-value row |
| 6 | `oci_upload_seal.c:107` (via `brix_oci_store_publish`) | **the sealed blob** | **yes** | `REGISTRY` | `excl` replaces the `exists()`-then-`publish` race of C10.2; `EEXIST` becomes the benign "already have these bytes" path the comment already describes |

`brix_oci_store_publish` and `brix_oci_store_put_text` are then deleted, taking
`oci_store.c` from 512 lines to roughly 450 — more headroom under the 600 cap
than the `mkparent` helper they leave behind needs.

**The one behaviour change, and it is a real one.** Today `put_text` opens with
`O_TRUNC` at the deterministic name `<final>.tmp.<pid>`. Tomorrow it opens
`O_EXCL` at a random name. A worker that crashed mid-publish used to silently
truncate its own leftover on the next attempt; now the leftover is simply never
in the way, because the name is not reused. The stale temp is instead reaped by
`brix_stage_reap_dir` / `brix_stage_reap_all` (`staged_file.h`), which requires
the OCI store root to be registered once at postconfig via
`brix_stage_dir_register()` (`staged_file.h:99`). **That registration is part of
W2, not an optimisation**: without it, `<final>.tmp.XXXXXX` files accumulate in
the store tree after every crash, and the registry's own `enumerate` would list
them as objects.

#### C10.5 What stays in `src/protocols/oci/`

The registry *model* — what a tag pointer contains, when a referrers index is
rewritten, how a session is sealed, which digest algorithms are accepted. C10
moves file mechanics and nothing else. The test for whether a line belongs in
the new unit is whether it would read identically if the caller were the FRM
journal instead of the registry.

Also unchanged: **the wire.** All seven call sites map a publish failure to
`NGX_HTTP_INTERNAL_SERVER_ERROR` today (`oci_manifest_put.c:192`,
`oci_upload_seal.c:111`, and their four siblings), and they keep doing so. The
only new wire behaviour is the `excl` arm at site 6, where `EEXIST` is handled
in the caller as success — the outcome the current code already intends.
### C11 — Credential materialization is one verb

#### C11.1 The shape of the problem

Not "extract a helper from N copies" — **the helper exists and is the best of
the four.** `brix_cred_stage_write` (`core/compat/cred_stage.c:66`) and its
directory guard `brix_cred_stage_dir` (`:26`) already implement the fail-closed
answer, and its header states the threat model in the tree's own words
(`cred_stage.h:6–21`): a secret handed to a fork/exec'd helper that reads a
*path*, written into world-traversable `/tmp`, is CWE-377; the answer is a
per-uid `0700` tmpfs directory, validated on every use, **with no `/tmp`
fallback**.

Six sites reach it (§2.1). Three do not, and the disagreement table in §2.1 is
the bar this item has to clear. Read down its rows and the shape is:

- **`cred_stage.c`** is right about *where* (validated private tmpfs) and right
  to have no `fsync` — the artifact is deliberately volatile, and a credential
  that does not survive a reboot is a security property, not a gap.
- **`delegation.c:270–320`** and **`cred_mint.c:186`** are right about
  *durability* (`fsync` before `rename`) and right about `O_EXCL|O_NOFOLLOW`,
  and wrong about the two `close()` results, the missing `EINTR` retry, and the
  directory flush that neither does.
- **`deleg_capture.c:210–236`** is wrong about *where*, and it is the one
  holding a forwarded Kerberos TGT.

So the consolidated verb is not one behaviour. It is **two**, and the split is
along the axis phase-107 [Appendix G.1](phase-107-vfs-mutation-surface-completion.md#g1-the-seven-domains)
already draws.

#### C11.2 Two arms, one gate

```c
/* src/core/compat/cred_stage.h — additions */

typedef enum {
    BRIX_CRED_ARM_VOLATILE = 0,  /* private tmpfs handoff; the temp IS the artifact */
    BRIX_CRED_ARM_PERSISTENT     /* durable publish into the configured credential dir */
} brix_cred_arm_t;

typedef enum {
    BRIX_CRED_KIND_BEARER = 0,   /* OAuth2 subject/bearer body */
    BRIX_CRED_KIND_PROXY,        /* X.509 (delegated or minted) PEM */
    BRIX_CRED_KIND_CCACHE,       /* Kerberos credential cache */
    BRIX_CRED_KIND_KEYTAB
} brix_cred_kind_t;

typedef struct {
    ngx_log_t        *log;
    brix_cred_arm_t   arm;
    brix_cred_kind_t  kind;      /* audit line + reap TTL only — never mechanics */
    const char       *dir;       /* [PERSISTENT] the configured credential dir */
    const char       *name;      /* [PERSISTENT] final basename, e.g. "<key>.pem" */
    const char       *prefix;    /* [VOLATILE]   mkstemp prefix, e.g. "tpc_token_body_" */
} brix_cred_write_req_t;

/* Materialise `len` bytes as a credential file and return its path.
 * NGX_OK, or NGX_ERROR with errno:
 *   EROFS  — brix_vfs_domain_mutation(CREDENTIAL, MUTATE_CREDENTIAL) refused
 *   EPERM  — [VOLATILE] the staging dir failed the owner/mode check (fail closed)
 *   EINVAL — bad request shape (arm/kind out of range, missing dir or prefix)
 *   ENOSPC/EIO/EDQUOT — surfaced verbatim from write, close, fsync or rename
 * No file is left behind on any failure path, on either arm. */
ngx_int_t brix_cred_write(const brix_cred_write_req_t *req,
    const void *bytes, size_t len, char *path_out, size_t path_outsz);
```

Invariants asserted in **one** place, for both arms:

| property | value | closes |
|---|---|---|
| create flags | `O_CREAT\|O_EXCL\|O_WRONLY\|O_NOFOLLOW\|O_CLOEXEC` | `deleg_capture.c`'s `mkstemp`-then-rewrite-by-name |
| file mode | `0600`, pinned by a defensive `fchmod` after create | `cred_stage.c:97–104`'s existing belt-and-braces |
| directory | `0700`, owner = euid, `(mode & 0077) == 0`, re-checked every call | `deleg_capture.c`'s unvalidated `$TMPDIR` |
| write | `EINTR`-safe loop to full length | the two single-`write()` sites |
| `close()` | **checked**, treated as a write error | `delegation.c` (×2), `cred_mint.c:203` |
| `fsync` | `[PERSISTENT]` before the rename; `[VOLATILE]` never | the tmpfs carve-out of §3.3 |
| dir flush | `[PERSISTENT]` after the rename, parent fd derived as in C10.3 step 7 | all four |
| publish | `[PERSISTENT]` `rename`; `[VOLATILE]` none | — |
| reap on error | `unlink` on **every** failure branch | `deleg_capture.c` (none) |
| audit | exactly one structured line: `arm`, `kind`, outcome — **never the bytes, never the path's secret component** | three sites that log nothing |
| accounting | one `BRIX_VFS_MUTATE_CREDENTIAL` sample | — |

`kind` exists for the audit line and the reaper's TTL policy. It does **not**
select mechanics: a keytab and a bearer body are written identically, and a
verb that branched on kind would be four verbs wearing one name.

#### C11.3 Why `brix_vfs_export_op_ctx_t` is not the carrier

Phase 105 built `brix_vfs_export_op_ctx_t` (`vfs_policy.h:129–134`) precisely
for helpers that run where a request context does not exist, and it is the right
*precedent*. It is the wrong *type* here, for one reason: its `root_canon` field
means the **export** root, and every one of these writes is outside every export
by construction. Passing an export context to a credential writer would make
the type mean two things.

Instead `brix_cred_write_req_t` carries what this domain actually needs
(`dir` + `name`, or `prefix`), and the authority it consults is the domain
assert — `brix_vfs_domain_mutation(NULL, BRIX_VFS_DOMAIN_CREDENTIAL,
BRIX_VFS_MUTATE_CREDENTIAL)`, phase-107
[A.3](phase-107-vfs-mutation-surface-completion.md#a3-domain-assert-c8-c9) —
not an endpoint policy. That is the correct authority: a read-only *export*
must not stop a credential from being minted, because minting is not an export
mutation. Getting this wrong in the other direction would be a functional
regression that looks like hardening.

#### C11.4 Migration, weakest-holding-most first

| # | site | arm | kind | what it writes | why this order |
|---|---|---|---|---|---|
| 1 | `auth/krb5/deleg_capture.c:210–236` (`brix_krb5_deleg_mkccache`) | VOLATILE | `CCACHE` | **a forwarded Kerberos TGT** | the CWE-377 site; highest value, weakest guard |
| 2 | `webdav/delegation.c:270–320` | PERSISTENT | `PROXY` | an uploaded delegated proxy PEM | second-strongest today; sets the fsync bar |
| 3 | `fs/backend/cred_mint.c:186` (`mint_write_tmp`) + `:284` (`rename`) | PERSISTENT | `PROXY` | minted credentials | strongest today; last, so the bar is already met when it moves |
| 4 | the six existing `brix_cred_stage_write` / `brix_proxy_gsi_write_pem_temp` callers | VOLATILE | `BEARER`/`PROXY` | token bodies, GSI proxy PEMs | mechanical — `brix_cred_stage_write` becomes a thin wrapper over the VOLATILE arm and its callers need not change at all |

Site 1 is the item's reason for existing and is deliberately first. It also
carries the one real subtlety in C11: libkrb5 wants a *path* it can rewrite by
name (`krb5_cc_resolve` on a `FILE:` cache), so the VOLATILE arm cannot hand it
an fd. What changes is not that — it is **where** the path lives: a validated
per-uid `0700` tmpfs directory instead of `$TMPDIR` or `/tmp`. The window in
which a co-tenant could `open()` the name closes because the *parent* is
unreachable, which is exactly the argument `cred_stage.h` already makes.

Site 1 also gains what it has today by accident: reaping. A `mkccache` that
fails after `mkstemp` currently leaks a file holding TGT-adjacent material with
no owner; the consolidated verb unlinks on every failure branch, and the
registered stage dir is swept.

#### C11.5 The bonus that falls out

With one writer there is one reaper. TTL handling today is per-subsystem — a
proxy left behind by a failed delegation is cleaned up by whichever path happens
to own it, and `deleg_capture.c` owns none. `kind` gives the reaper the only
input it needs to apply a per-class TTL, and `brix_stage_dir_register()`
(`staged_file.h:99`) is already the mechanism for telling the sweeper where to
look.

This is a consequence, not a goal. C11 lands when the four implementations are
one; the unified reaper is W1's stretch and may slip to phase 109 without
weakening anything above.
### C12 — Authorization becomes a VFS backstop

#### C12.1 What the gate actually is

`brix_auth_gate` (`auth_gate.h:31`) is not one check. Its evaluator
(`auth_gate.c:451–481`) runs **three tiers in a frozen order**, returning on the
first denial:

| tier | native format | `xrdacc` format | identity-only twin already in the tree |
|---|---|---|---|
| 1 | `brix_check_authdb(ctx, resolved, auth_level)` (`auth_gate.c:464`) | `brix_acc_gate_engine(g, reqpath)` (`:456`) | `brix_check_authdb_identity(log, &query)` (`path.h:110`) / — |
| 2 | `brix_check_vo_acl_identity(log, resolved, vo_rules, identity)` (`:470`) | same | **already identity-only** |
| 3 | `brix_check_token_scope(ctx, reqpath, need_write)` (`:476`) | same | `brix_identity_check_token_scope(identity, path, need_write)` (`policy.c:27`) |

Two details from that table decide the whole design of this item.

**First: tiers 2 and 3 already have identity-only forms, and tier 1 has one for
the native arm.** `brix_check_authdb_identity` takes a `brix_authdb_query_t`
(`path.h:105`) whose five fields — `rules`, `identity`, `peer_ip`,
`resolved_path`, `needed_privs` — are exactly what a `brix_vfs_ctx_t` can carry.
The backstop is not a reimplementation of the gate; it is the same three
functions called with an identity instead of a `brix_ctx_t`.

**Second: the `xrdacc` arm is the one that is not pure.** `brix_acc_gate_engine`
builds a `brix_acc_entity_t` on `c->pool` before it can call
`brix_acc_access(tables, ent, path, op)` (`auth_gate.c:220–226`). The *decision*
is pure; the *entity construction* allocates. Since the entity is derived
entirely from identity fields (`name`, `host`, `vorg`, `role`, `grp` —
`auth_gate.c:217`), it is a per-connection value being rebuilt per request. C12
memoizes it on `brix_identity_t`, following the pattern that struct already
uses for exactly this shape: `mapped_user[256]` + `mapped_resolved:1`
(`identity.h:69–70`), a lazily resolved, connection-lifetime cached derivation.
With the memo in place the backstop's `xrdacc` arm is a table lookup and
position 1.5 stays allocation-free.

`auth_level` is the `BRIX_AUTH_*` bitmask (`config.h:55–60`:
`READ 0x01`, `LOOKUP 0x02`, `UPDATE 0x04`, `DELETE 0x08`, `MKDIR 0x10`,
`ADMIN 0x20`) and it is passed **unchanged** as `brix_check_authdb`'s
`needed_privs` (`auth_gate.c:266`, `:464`). There is no second vocabulary to
translate into for the native arm; the `xrdacc` arm's `brix_acc_op_t` is derived
from the same bitmask by `brix_acc_gate_select_op` (`auth_gate.c:59–67`), a pure
function C12 reuses verbatim rather than restating.

#### C12.2 The ctx binding — the actual mechanism

`brix_vfs_ctx_t` (`vfs.h:100–136`) carries `pool`, `log`, `identity`,
`metrics_proto`, `root_canon`, `resolved` and the phase-105 `mutation_policy`.
It does **not** carry the rule sets — those live on
`ngx_stream_brix_srv_conf_t`. So C12's real mechanism is one more binder in a
struct that already has three:

```c
/* src/fs/vfs/vfs.h — new bundle, borrowed pointers, no ownership */
typedef struct {
    ngx_array_t        *authdb_rules;   /* finalized at postconfig */
    ngx_array_t        *vo_rules;       /* finalized at postconfig */
    void               *acc_tables;     /* brix_acc_tables_t*, NULL under native */
    ngx_uint_t          acc_format;     /* BRIX_AUTHDB_FORMAT_* */
    const char         *peer_ip;        /* for host ('p') rules */
    unsigned            bound:1;        /* set by the binder; 0 = never bound */
} brix_vfs_authz_t;
```

bound by `brix_vfs_ctx_bind_authz()`, in the same shape and the same file as the
three binders already there — `brix_vfs_ctx_bind_backend_cred()` (`vfs.h:165`),
`_bind_backend_mint()` (`:173`), `_bind_backend_deleg()` (`:182`), whose fields
sit at `:116`, `:120` and `:127` of the same struct.

`bound:1` is load-bearing and is the reason this bundle is not just three
nullable pointers. "No rules configured for this export" and "the binder was
never called" are the same pointer state and completely different facts. With
the flag they are distinguishable, and the kernel can be honest about which one
it is looking at:

| state | `observe` | `enforce` |
|---|---|---|
| bound, rules present, allow | agree | allow |
| bound, rules present, deny | `edge_missing` + WARN | **`EACCES`** |
| bound, no rules | `no_rules` | allow (an export with no rules is allow-all today, and C12 does not change that policy) |
| **not bound** | `unbound` + WARN | **`EACCES`** — fail closed |

That last row is why the rollout has three states and not two.

#### C12.3 The privilege mapping

Not invented. Each row below is the `auth_level` the 28 edge sites already pass
by hand for the operation the VFS is *already* gating:

| `brix_vfs_mutation_op_t` | `auth_level` | edge precedent |
|---|---|---|
| `OPEN` (create/truncate), `WRITE`, `TRUNCATE`, `SYNC`, `SETATTR`, `XATTR`, `PUBLISH` | `BRIX_AUTH_UPDATE` | the write-path gate sites |
| `MKDIR` | `BRIX_AUTH_MKDIR` | `auth_gate.h:14–17`'s own worked example |
| `REMOVE` | `BRIX_AUTH_DELETE` | the `rm`/`rmdir` sites |
| `RENAME`, `COPY` | `BRIX_AUTH_UPDATE` on the destination **and** `BRIX_AUTH_DELETE` on the source | `mv.c:409` and `:428` — the two `brix_auth_gate_op` calls that already check both ends |
| `STAGE`, `EVICT` (phase-107 C2) | `BRIX_AUTH_UPDATE` | staging consumes site resources; `BRIX_AOP_STAGE` already exists (`privs.h:56`) for the `xrdacc` arm |
| `LOCK` (phase-107 C7) | `BRIX_AUTH_UPDATE` | a lock is a write reservation |
| `DEDUP` (phase-107 C8) | — | service storage; the domain assert governs, not a rule |
| `CREDENTIAL` (C11) | — | not export storage; same |
| reads, via `brix_vfs_require_authorized_read()` | `BRIX_AUTH_READ` / `BRIX_AUTH_LOOKUP` | `statx.c:139`'s `brix_authz_check` |

`mv.c:409`/`:428` are the important precedent: the tree already treats a rename
as two decisions on two paths. A backstop that checked only the destination
would be *more permissive than the edge*, which §C12.5 says is worse than
having none.

#### C12.4 Backstop, not relocation

The edge gate stays exactly where it is, and it keeps three things the VFS must
not take:

1. **Refusing before path resolution and backend work.** The gate rejects a
   `mkdir` before anything touches storage; the backstop by construction runs
   later. Moving the decision would make every denial more expensive.
2. **Composing the protocol-correct refusal.** `brix_auth_gate` sends
   `kXR_NotAuthorized` and stashes `ctx->write_rc` (`auth_gate.h:8–18`); the
   WebDAV and S3 edges compose their own. The VFS returns `EACCES` and knows
   nothing about wire formats — which is correct and is also why it can never
   be the only checkpoint.
3. **The SHM verdict cache.** `brix_auth_cache` (`auth_cache.h`) folds
   `auth_level`, `need_write`, both paths, DN, VO list and the raw scope claim
   into one key with a 30 s TTL, so a pilot hammering the same tuple pays for
   three rule scans once. The backstop deliberately does **not** consult it: a
   cache is a performance structure, and a backstop that trusts a cache the edge
   populated is checking the edge's memo rather than the edge's decision.

The VFS kernel is the thing that **cannot be forgotten**. In the normal case it
re-derives a decision the edge already made and agrees. The interesting case is
disagreement, which means a handler reached storage without asking.

The evidence that this class bites: the 2026-07-06 cache-authz fix made
`open_cache.c` run the full gate, and the authz README records why the serve and
fill helpers are "deliberately auth-free so this gate cannot be bypassed." That
is a correct fix held in place by a comment — a convention the next helper's
author must also be told about. A backstop is what replaces a convention.

#### C12.5 Rollout is inverted, and why

`brix_authz_backstop off | observe | enforce`, default **`observe`** for one
release.

Enforcing from day one against 28 call sites, 26 on one plane, four other schemes on
four other planes, and every VFS entry point that has never bound a rule set
would convert any modelling error into a site outage — and the modelling errors
that matter here are precisely the ones nobody can enumerate in advance, because
they live on the planes whose schemes are not the gate's.

`observe` produces the evidence:
`brix_vfs_authz_backstop_total{result=agree|edge_missing|no_rules|unbound}`
(§6). `enforce` is a one-line flip once `edge_missing` and `unbound` have been
flat across the fleet lanes for a release. `off` exists so an operator who hits
a modelling bug in `observe` can silence the log without redeploying.

**The failure mode to design against.** A backstop that is *more permissive*
than the edge is worse than no backstop, because it reads as coverage. So the
kernel refuses whenever it cannot decide — an unbound ctx, an identity it cannot
interpret, an operation with no mapping in §C12.3 — rather than passing.
Under `observe` that refusal is a counter and a log line; under `enforce` it is
`EACCES`. Fail-closed, exactly like `BRIX_VFS_MUTATION_READ_ONLY = 0`.

**Ordering.** Position 1.5 (§3.4): after the phase-105 mutation kernel, before
the lock check. The order is not cosmetic — a read-only endpoint must answer
`EROFS` and nothing else, so the policy kernel's non-disclosure property
survives only if authorization cannot speak first.
### C13 — Name mapping is a path-layer stage

#### C13.1 The two implementations, precisely

`site_n2n.c` — 153 lines, `src/fs/backend/`, listed at `config:988`, unit-tested
by `tests/c/test_site_n2n.c` (79 lines) through the `site_n2n` spec in
`tests/cmdscripts/c_simple_units.py:75–85`. Its surface (`site_n2n.h`):

```c
typedef enum { BRIX_N2N_IDENTITY = 0, BRIX_N2N_RAL, BRIX_N2N_CEPHFS_PATH } brix_n2n_scheme_t;
typedef struct { brix_n2n_scheme_t scheme; char pool[128]; char prefix[256]; } brix_n2n_cfg_t;

int brix_n2n_lfn2pfn(const brix_n2n_cfg_t *, const char *lfn, char *pfn, size_t cap);
int brix_n2n_pfn2lfn(const brix_n2n_cfg_t *, const char *pfn, char *lfn, size_t cap);
int brix_n2n_extract_pool(const char *objname, char *pool, size_t cap, const char **rest);
```

`BRIX_N2N_RAL` composes `<pool>:<prefix><lfn>`; `BRIX_N2N_CEPHFS_PATH` composes
`<localroot><lfn>`; `brix_n2n_extract_pool` is faithful to stock
`XrdCephOss::extractPool`, **including its quirk** — with no colon present the
*whole string* is the pool and `*rest` points at `""`. Production callers: zero.
`BRIX_N2N_IDENTITY` is the only behaviour anything in the tree gets, by never
asking.

`sd_ceph_key(key_prefix, lfn, out, cap)` (`sd_ceph.c:204–228`, declared
`sd_ceph.h:48`) — `key_prefix` concatenated with `sd_ceph_normalize(lfn)`
(`sd_ceph.c:166–201`). **14 production call sites**, all inside the RADOS
driver:

| file | sites |
|---|---|
| `sd_ceph_object.c` | 8 (`:200`, `:295`, `:375`, `:405`, `:425`, `:462`, `:511`, `:537`) |
| `sd_ceph_object_rename.c` | 2 (`:383`, `:384` — source and destination) |
| `sd_ceph_io.c` | 2 (`:239`, `:520`) |
| `sd_ceph_meta.c` | 1 |
| `sd_ceph.c` | 1 |

`key_prefix` as a concept exists nowhere in the tree outside
`src/fs/backend/rados/`.

#### C13.2 The semantic conflict, which is the real content of this item

The two implementations do **not** agree on what a `..` means, and this is not a
detail:

| input | `brix_n2n_lfn2pfn` | `sd_ceph_key` |
|---|---|---|
| `/a/b/c` | `<prefix>/a/b/c` | `<prefix>/a/b/c` |
| `/a/./b` | `<prefix>/a/./b` — **passed through unnormalized** | `<prefix>/a/b` — `.` collapsed |
| `/a//b` | `<prefix>/a//b` — passed through | `<prefix>/a/b` — empty segment collapsed |
| `/a/../b` | **rejected** (`n2n_has_traversal`, `site_n2n.c:12–31`) | `<prefix>/b` — `..` **resolved by popping** |
| `/../x` | rejected | rejected (`EINVAL`, escape above root) |

`site_n2n` **rejects** any `..` component; `sd_ceph_normalize` **resolves** it
and rejects only an escape above the root. Both are defensible in isolation and
they cannot both be the mapping. `sd_ceph.h:38–40` states the property the
driver depends on — "the single point that guarantees the LFN→oid map is
injective and prefix-confined" — and that injectivity is over *canonical* paths:
under `sd_ceph_key`, `/a/../b` and `/b` are the same object; under `site_n2n`
one of them does not exist.

Swapping one for the other therefore changes behaviour, and W3 must decide
deliberately rather than inherit. **The decision this document takes: reject,
i.e. `site_n2n` semantics**, for two reasons.

1. INVARIANT #4 puts `resolve_path()` before every `open()`, so by the time a
   path reaches a storage driver it has already been canonicalized against the
   export root. A `..` still present at the driver is not a path the resolver
   produced — it is a path that arrived some other way, and rejecting it is
   correct.
2. Normalizing a second time inside the driver is a *second* canonicalizer with
   its own bugs, on the security-relevant side of the seam.

**W3's first obligation is therefore a proof, not a patch**: demonstrate that no
`sd_ceph_key` call site can be reached with a non-canonical path — instrument
all 14 and run the Ceph live lane — *before* the semantics change. If a site can
be, that site is a defect that predates C13, and C13 stops until it is fixed.

#### C13.3 Where the stage goes

Not inside the driver. The path layer, as a stage between confinement and driver
dispatch (contract in [A.4](#a4-name-translation-stage-c13)):

- **LFN → PFN**, applied **after** `resolve_path()` has succeeded and before the
  driver sees a key. This ordering is the entire security content of C13:
  confinement runs on the **logical** path, and the translation may only be
  applied to a path that has *already* resolved inside the export. A translation
  that ran first could compose `<localroot>` with a client-supplied string and
  land outside the root with the confinement check having examined something
  else.
- **PFN → LFN**, on the listing path, so `enumerate` and directory reads render
  in logical terms. This direction exists nowhere today and is the reason a
  RAL-style export cannot presently present a coherent listing: the driver
  returns object ids and the protocol layer has no way back.
- Per-export configuration — `brix_n2n_scheme identity|ral|cephfs_path`,
  `brix_n2n_pool <name>`, `brix_n2n_prefix <path>` — registered in
  `check_directive_registry.py`'s registry and validated at `nginx -t`, with the
  negative cases in §8: `ral` with no `brix_n2n_pool` is a config error; a
  `brix_n2n_pool` longer than 127 bytes or a `brix_n2n_prefix` longer than 255
  is a config error, not a runtime truncation.
- `sd_ceph_key` becomes the `IDENTITY`-plus-prefix case of the shared
  translation. The 14 call sites keep calling `sd_ceph_key`; its **body**
  becomes a call into the path-layer stage. That keeps the diff at one function
  and keeps the driver's `oid` buffers and error handling untouched.

#### C13.4 The verification bar

`site_n2n` has never executed in production. Its unit test is the only thing
that has ever run it. Before it becomes load-bearing on the security-relevant
side of a path resolution it gets what any new path-handling code gets:

| test | asserts |
|---|---|
| round-trip property, all three schemes | `pfn2lfn(lfn2pfn(x)) == x` over a generated corpus, including UTF-8, `%`-sequences and embedded `:` |
| traversal, both directions | every `..` form rejected, and rejected **before** the prefix is applied — the failing-first version of this test is what proves the ordering, not a comment |
| `extract_pool` quirk | the no-colon case still yields pool = whole string, `*rest == ""`, because a "fix" here silently breaks interop with stock XrdCeph |
| overflow | `pool` at 128 and `prefix` at 256 boundaries, `ENAMETOOLONG` not truncation |
| the C13.2 decision | `/a/../b` is rejected, with a named test so the behaviour change is discoverable from the test list |
| a negative fuzz arm | the existing protocol-fuzz corpus pointed at the LFN input, asserting no crash and no escape |

#### C13.5 Honest scoping

C13 benefits Ceph/RADOS sites and nothing else today, and it is the smallest
item in this phase — the only one whose success is partly measured in deleted
lines. It is here for two reasons and neither is "Ceph needs it":

- The alternative is a second partial copy inside the next driver that needs a
  name scheme, which is the exact pattern C10, C11 and C12 are each about.
- A compiled, config-listed, unit-tested module with zero callers is a
  maintenance liability regardless of who benefits. It either gets wired or it
  gets deleted. This document takes the position that it gets wired — and states
  the alternative plainly, because "delete `site_n2n.c` and the `config:988`
  line and the unit spec" is a legitimate outcome that costs one commit and
  leaves the tree honest. What is not legitimate is leaving it where it is.
---

## 5. What this phase deliberately leaves alone

**The cache store's own file mechanics** (`cstore.c`, `meta.c`, `verify.c`,
~15 waivers). They are already a coherent, single-owner implementation of one
domain, and `verify.c`'s nine waivers are one function's worth of staging I/O.
Phase-107 C9 types them; C10 does not move them. Consolidating a subsystem that
is already internally consistent buys churn, not safety.

**The FRM and stage journals.** Append-only WAL records with their own
crash-recovery model and their own tests. A journal is not a staged publish, and
pretending it is would lose the append semantics that make recovery possible.

**`recv_forward.c`'s four "metadata on a VFS-opened confined fd" waivers.**
Those are already the correct pattern — the fd came from the VFS, and the waiver
documents that the metadata call rides on it. Nothing to fold.

**Operator config reads** (CMS blacklist, trust anchors, CA bundles). Host
configuration, read-mostly. Typed by phase-107 C9, untouched otherwise (§1.2).

**Anything in `client/`.** The native client has its own VFS backends and its
own seam guard; this phase is server-side.

### 5.1 Two sites that look like C10 and are not

An earlier draft of this document listed both of these in W2's migration set.
Reading them removed both, and the reasons are worth keeping, because the next
reader will make the same guess.

**`src/protocols/webdav/tpc_marker.c:184–195` — already correct.** It publishes
a TPC progress marker and it already goes through
`brix_rename_confined_canon()` / `brix_unlink_confined_canon()`. It is not a
hand-rolled publish; it is the pattern C10 is generalizing, written out at one
site. C10 may later absorb it for the fsync, but it is not a *consolidation*
target: there is no duplicated safety property to recover, only a durability
improvement, and that is phase-107 C3's subject rather than this phase's.

**`src/protocols/webdav/tpc_curl_multi.c:66` — a staged open, not a publish.**

```c
open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
```

followed by `brix_sd_posix_driver.ftruncate` and then concurrent `pwrite()`s
from the multi-handle callbacks. C10's verb takes a complete buffer or a
finished fd and publishes it; this site needs a *writable staged fd held open
across many callbacks*, which is exactly `brix_staged_open()`
(`staged_file.h:76`) — an existing surface it should adopt on its own schedule.
Forcing it into `brix_service_publish_bytes()` would mean buffering an entire
third-party-copy in memory. Recorded here so the mismatch is a decision and not
an oversight.

**`src/protocols/webdav/tpc_cred_exchange.c` belongs to C11, not C10.** Its temp
files hold exchanged tokens. It is credential materialization; W1 covers it.
---

## 6. Observability

**One new family, one new label value, one new audit line — and deliberately no
more.** The point of a consolidation phase is fewer things to watch, not more;
a phase that deletes four implementations and adds four dashboards has not
consolidated anything.

### 6.1 The new family (C12)

Declared in the tree's own style — a `# HELP`/`# TYPE` pair, one `mw_printf`
loop over an SHM cube, low-cardinality labels only (INVARIANT #8), following
`unified_emit_vfs_mutation_denied` (`unified_export.c:151–171`) line for line:

```
# HELP brix_vfs_authz_backstop_total VFS authorization backstop outcomes, by protocol and result.
# TYPE brix_vfs_authz_backstop_total counter
brix_vfs_authz_backstop_total{proto="root",result="agree"} 0
```

| label | values | bounded by |
|---|---|---|
| `proto` | the `BRIX_PROTO_*` set | `BRIX_PROTO_COUNT` |
| `result` | `agree`, `edge_missing`, `no_rules`, `unbound` | a literal set chosen in the emitter |

The cube is `ngx_atomic_t authz_backstop_total[BRIX_PROTO_COUNT][4]` beside
`vfs_mutation_denied_total` in `metrics.h`. Four `result` values, matching the
four states of §4/C12.2's table:

| value | meaning | operator action |
|---|---|---|
| `agree` | the backstop re-derived the edge's decision and matched | none — this is the boring series and it should be ~100% |
| `edge_missing` | the backstop would have **denied** and the request got through | **the finding.** A handler reached storage without asking. Non-zero on a real workload is a bug with a name attached, because `proto` says which plane |
| `no_rules` | bound, but the export has no rules — allow-all, unchanged behaviour | confirms coverage is a config question, not a code question |
| `unbound` | the ctx never had a rule set bound | a wiring gap in W4, not a policy finding. Must be zero before `enforce` is proposed |

`edge_missing` and `unbound` are separated on purpose. Folding them into one
`undecidable` bucket — which an earlier draft of this document did — would mean
the number that gates the `enforce` flip could be moved by a wiring bug, and an
operator could not tell a missing gate from a missing binder.

### 6.2 The new label value (C11)

`MUTATE_CREDENTIAL` joins the existing `brix_vfs_mutation_denied_total`
`op` label set. **No new family and no new cardinality**: the label vocabulary
is bounded by `BRIX_VFS_MUTATE_OP_METRIC_COUNT`, and the mirror's
`_Static_assert` (`vfs_policy.c:33`) keeps the array and the enum the same
length (§3.1).

### 6.3 The audit line (C11)

Exactly one structured line per credential materialization, from one place:

```
brix: cred: arm=persistent kind=proxy dir="/var/lib/brix/creds" outcome=ok
```

Today three of the four implementations log nothing on success and none log
alike, so "which credentials did this worker write, and when" has no answer.
The rule that constrains the line's content is the same one that constrains the
metric labels: **never the bytes, and never the secret-bearing component of the
path.** `dir` is the configured directory; the key stem is not logged, because a
credential key derived from a DN is a subject identifier.

### 6.4 What adds nothing

- **C10.** It reuses the publish accounting it consolidates onto. That it needs
  no new counter is the tell that it really is the same operation — a
  consolidation that required its own metric would be evidence it was not one.
- **C13.** A pure transformation with no event to count.

### 6.5 The signal this phase is measured by

The `domain` label on the mutation counter arrives with **phase-107 C9**, not
here (that document's §7.5). This phase is its first heavy user, and it is the
one number that says whether the consolidations did what they claimed: a write
that moves from a hand-rolled copy onto a domain-aware verb should appear as a
shift between two series. **If the series do not move, the consolidation did not
happen** — the code was replaced and the write still goes somewhere the VFS
cannot see.
---

## 7. Implementation waves

Each wave lands with success, error and security-negative tests (three per
change, per the standing rule). Every migration wave opens with its parity pin
(§3.5) and closes by re-running it.

Phase 107 v2 numbered these W10–W13; they are renumbered here and the old number
is noted per wave so older cross-references still resolve.

**Dependencies.** W1 and W2 are independent of each other; both need phase-107
W9 (the domain type), and W2 additionally needs phase-107 W3 (`sync_publish`)
and W7 (the typed precondition, for C10's `excl` arm). W3 is independent of
everything, including phase 107 — it could ship first if the Ceph lane were the
priority. W4 ships last because it is the only item that can refuse traffic,
and it ships unable to.

### W0 — Parity pins and the domain prerequisite *(new)*

- [ ] Verify phase-107 W9 has landed: `brix_vfs_domain_t`,
      `brix_vfs_domain_mutation()`, and `check_vfs_seam.py` enforcing the
      entitlement table. **Nothing in this phase starts before that** — every
      item's first call is the domain assert.
- [ ] Confirm phase-107's 108-vs-117 waiver distinction was resolved in W9 and
      record the per-domain waiver census as this phase's baseline. §11 measures
      against this number, so it is taken once, from the annotated tree, not
      re-derived per wave.
- [ ] **Pin today's behaviour as tests that pass now** (this is the wave's real
      product):
  - `test_oci_publish_parity` — an OCI tag publish issues **no** fsync of any
    kind, `close()`'s result is discarded, and the temp name is
    `<final>.tmp.<pid>`. Pinning a *defect* is deliberate: W2's diff must show
    these assertions inverting, in the same commit, or it changed something
    else.
  - `test_cred_write_parity` — the four-row table of §2.1, one assertion per
    cell: create flags, mode, dir validation, write shape, `close()` handling,
    fsync, publish, error-path reaping.
  - `test_site_n2n_unwired` — `site_n2n` has zero production callers, asserted
    by the same mechanism the census used, so W3 flips it.
  - `test_authz_edge_removed_reaches_storage` — with the edge gate stubbed out,
    a mutation reaches a driver. This is C12's reason for existing expressed as
    a currently-passing test; W4 makes it fail.

### W1 — C11 credential materialization *(was W10)*

- [ ] `brix_cred_write()` on `core/compat/cred_stage.h` with the two arms
      (`VOLATILE`, `PERSISTENT`) and the `brix_cred_kind_t` vocabulary
      ([A.2](#a2-credential-materialization-c11)).
- [ ] `BRIX_VFS_MUTATE_CREDENTIAL` in the vocabulary; **all six mirror files in
      the same commit** (§3.1); label `"credential"`.
- [ ] Migrate in the order of §4/C11.4 — `deleg_capture.c:210–236` **first**,
      because it is the CWE-377 site and it holds the forwarded TGT.
- [ ] `brix_cred_stage_write` becomes a thin wrapper over the `VOLATILE` arm so
      its six existing callers do not change at all.
- [ ] Migrate `delegation.c:270–320`, then `cred_mint.c:186`/`:284`.
- [ ] Re-run `test_cred_write_parity` against the shared verb; every cell must
      be equal or stronger, with §3.3's tmpfs carve-out as the one recorded
      "weaker on purpose".
- [ ] *(stretch)* Uniform TTL reaping keyed on `kind`; may slip to phase 109.

**Files:** `src/core/compat/cred_stage.{c,h}`, `src/auth/krb5/deleg_capture.c`,
`src/protocols/webdav/delegation.c`, `src/fs/backend/cred_mint.c`,
`src/fs/vfs/vfs_policy.h`, the five metrics files, `tests/c/test_cred_stage.c`,
`tests/cmdscripts/c_simple_units.py`.

### W2 — C10 staged publish for service storage *(was W11)*

- [ ] New unit `src/core/compat/service_publish.{c,h}` — `_bytes` and `_fd`
      forms ([A.1](#a1-service-storage-publish-c10)) — added to `config` beside
      `staged_file.c` (`config:798–800`); `check_config_coverage.py` is the
      guard that catches a forgotten line.
- [ ] The parent-directory fsync, derived through the confined path and opened
      `O_RDONLY`. **Not** `rootfd` — `staged_file.c:317–319`'s existing attempt
      is inert on an `O_PATH` fd and is fixed by phase-107 C3 in the same shape
      (§4/C10.3 step 7).
- [ ] Register the OCI store root with `brix_stage_dir_register()`
      (`staged_file.h:99`) at postconfig, so the `O_EXCL` temps have a reaper.
      This is a **requirement**, not an optimisation (§4/C10.4).
- [ ] Migrate the seven call sites in §4/C10.4's order, smallest first
      (`mark_layer` → referrers → upload part → tag → manifest → blob).
- [ ] Site 6 takes the `excl` arm: `brix_staged_commit_excl` replaces
      `exists()`-then-`publish`, and `EEXIST` becomes the benign "already have
      these bytes" path the existing comment already argues for.
- [ ] Delete `brix_oci_store_publish` and `brix_oci_store_put_text`.
- [ ] Re-run `test_oci_publish_parity` — every pinned defect assertion inverts.
- [ ] **Prove the tag pointer is durable.** The crash test, not the unit test:
      publish, `SIGKILL` the worker between rename and the next flush, remount,
      assert the tag resolves. This is the bug the wave exists to close and the
      only evidence that closes it.

**Files:** `src/core/compat/service_publish.{c,h}` (new), `config`,
`src/protocols/oci/oci_store.c`, `oci_manifest_put.c`, `oci_referrers.c`,
`oci_upload.c`, `oci_upload_seal.c`, `src/protocols/oci/README.md`,
`tests/c/` + `tests/test_oci_*.py`.

### W3 — C13 name mapping *(was W12)*

- [ ] **First, the proof, not the patch** (§4/C13.2): instrument all 14
      `sd_ceph_key` call sites and demonstrate on the Ceph live lane that none
      can be reached with a non-canonical path. If one can, that is a defect
      predating C13 and W3 stops until it is fixed.
- [ ] Wire `site_n2n` as a path-layer stage: LFN→PFN **after** `resolve_path()`
      succeeds, PFN→LFN on the listing path
      ([A.4](#a4-name-translation-stage-c13)).
- [ ] `brix_n2n_scheme` / `_pool` / `_prefix` per-export directives, in
      `check_directive_registry.py`'s registry, validated at `nginx -t`:
      `ral` without a pool is a config error; over-length pool or prefix is a
      config error, not a runtime truncation.
- [ ] `sd_ceph_key`'s **body** becomes a call into the shared stage; its 14 call
      sites and its `oid` buffers are untouched.
- [ ] The six tests of §4/C13.4, including the named `/a/../b` test that makes
      the semantic change discoverable from the test list.
- [ ] Move `site_n2n.{c,h}` out of `src/fs/backend/` if the stage lands in
      `src/fs/path/` — and if it does, `check_readme_coverage.py` and the
      `config` source list both move with it.

**Files:** `src/fs/backend/site_n2n.{c,h}` (possibly relocated),
`src/fs/path/`, `src/fs/backend/rados/sd_ceph.c`, `config`,
`tests/c/test_site_n2n.c`, `tests/cmdscripts/c_simple_units.py:75–85`.

### W4 — C12 authorization backstop, observe only *(was W13)*

- [ ] `brix_vfs_authz_t` + `brix_vfs_ctx_bind_authz()` on `brix_vfs_ctx_t`, in
      the shape of the three binders already at `vfs.h:165`, `:173`, `:182`.
      `bound:1` is part of the bundle, not inferred from a NULL pointer
      (§4/C12.2).
- [ ] Memoize the `xrdacc` entity on `brix_identity_t`, following
      `mapped_user`/`mapped_resolved` (`identity.h:69–70`), so position 1.5 is
      allocation-free.
- [ ] `brix_vfs_require_authorized()` + the read-side twin
      `_authorized_read()`; the op→`BRIX_AUTH_*` mapping of §4/C12.3; fail
      closed when it cannot decide.
- [ ] Slot it in at ordering position 1.5 (§3.4) at every mutator and every read
      entry point, and extend the phase-105 ordering spy to assert the slot.
- [ ] `brix_authz_backstop off|observe|enforce`, default **`observe`**;
      `brix_vfs_authz_backstop_total{proto,result}` (§6.1);
      `check_authz_backstop.py`.
- [ ] Bind the rule set on **every** VFS ctx construction site — the census is
      part of the wave, and `unbound` going to zero is how it is verified.
- [ ] Run `observe` across all five live protocol lanes; `edge_missing` and
      `unbound` must both be flat.
- [ ] **The phase closes here.** Proposing `enforce` as the default is the first
      change of whatever comes next, with its own release note and its own
      fleet evidence.

**Files:** `src/fs/vfs/vfs.h`, `vfs_policy.{c,h}`, a new
`src/fs/vfs/vfs_authz.c`, `src/core/types/identity.h`, `src/auth/authz/`,
every VFS ctx construction site, `tools/ci/check_authz_backstop.py`,
`docs/08-metrics-monitoring/metrics-overview.md`.
---

## 8. Test matrix

Every test below is named as it will appear in the suite, in the file it will
live in. A test with no home is a test that does not get written.

### 8.1 Where each item's tests live

| item | C unit | registration | pytest |
|---|---|---|---|
| C10 | `tests/c/test_service_publish.c` | `c_simple_units.py` `SPECS["service_publish"]` | `tests/test_oci_registry_push.py`, `tests/test_oci_registry_referrers.py` |
| C11 | `tests/c/test_cred_stage.c` (extended) | `SPECS["cred_stage"]` exists (`c_simple_units.py:183–195`) | `tests/test_delegated_cred.py`, `tests/test_delegation_t4_credential.py`, `tests/test_credential_translation.py` |
| C12 | `tests/c/test_vfs_authz_backstop.c` | new `SPECS` entry | new `tests/test_vfs_authz_backstop.py` |
| C13 | `tests/c/test_site_n2n.c` (extended) | `SPECS["site_n2n"]` exists (`c_simple_units.py:75–85`) | `tests/test_ceph_live.py`, `tests/test_ceph_harness.py` |

**Registration is not optional and not a formality.** `tests/test_c_simple_units.py`
parametrizes over `sorted(SPECS)`; a unit compiled by a runner but absent from
the table runs only when someone invokes the runner by hand. The comment at
`tests/test_c_regression_units.py:8–13` records what that costs — "19 units were
registered and unreachable", and the kXR_prepare packer went missing from a link
closure with no red anywhere. Adding `tests/c/test_service_publish.c` without
adding `SPECS["service_publish"]` produces a file that compiles in review and
never runs in CI.

### 8.2 Per-item: success, error, security-negative

Three per change is the floor, not the target. The named tests below are the
ones that would have to fail for the item to be wrong.

#### C10

| kind | test | asserts |
|---|---|---|
| success | `test_service_publish_bytes_is_durable` | after return, the data fd **and** the parent directory have been fsynced; the final name resolves; the temp is gone |
| success | `test_oci_tag_publish_survives_kill` (pytest, OCI lane) | publish a tag, `SIGKILL` the worker between rename and any later flush, remount the store, resolve the tag |
| error | `test_service_publish_short_write_reaps_and_logs` | a write cut short returns `NGX_ERROR`, unlinks the temp, **and emits a log line** — the D5 branch that is silent today |
| error | `test_service_publish_exdev_still_commits` | a cross-device final path still commits through the existing `staged_file.c` EXDEV path |
| error | `test_service_publish_excl_eexist_is_benign` | the `excl` arm returns `EEXIST` and the blob-seal caller treats it as success |
| security-neg | `test_service_publish_rejects_export_domain` | `BRIX_VFS_DOMAIN_EXPORT` passed to the service verb is refused, not silently accepted |
| security-neg | `test_service_publish_temp_is_unpredictable` | two concurrent publishes of the same final path do not collide, and neither temp name is derivable from pid + final path |
| security-neg | `test_service_publish_no_follow` | a symlink pre-planted at the temp name is not followed (`O_EXCL` on a fresh random name makes this structural; the test pins the structure) |
| parity | `test_oci_publish_parity` (from W0) | the four W0 assertions **invert** in W2's commit |

#### C11

| kind | test | asserts |
|---|---|---|
| success | `test_cred_write_volatile_matches_stage_write` | the `VOLATILE` arm is byte-for-byte the behaviour of today's `brix_cred_stage_write`, including the defensive `fchmod` at `cred_stage.c:98` |
| success | `test_cred_write_persistent_fsyncs_data_and_parent` | the `PERSISTENT` arm adds both fsyncs; the `VOLATILE` arm adds neither |
| error | `test_cred_write_reaps_on_every_branch` | one parametrized case per failure point (open, write, fchmod, close, rename) — the temp is gone in all five |
| error | `test_cred_write_short_write_is_an_error` | a short write is an error, never a truncated credential on disk |
| error | `test_cred_write_close_failure_is_reported` | `close()` failing is an error — the property `cred_stage.c:121` has and `cred_mint.c:203` and `delegation.c` do not |
| security-neg | `test_cred_write_rejects_group_or_other_bits` | any requested mode with `& 0077` is `EPERM` before any fd exists |
| security-neg | `test_cred_write_rejects_foreign_dir_owner` | the `lstat` + uid check of `cred_stage.c:26` applies to **every** arm, including `deleg_capture.c`'s former `$TMPDIR` path |
| security-neg | `test_cred_write_no_tmpdir_fallback` | `$TMPDIR` and `/tmp` are never used; the header's "deliberately NO /tmp fallback" (`cred_stage.h:6–21`) becomes an executable claim |
| security-neg | `test_krb5_deleg_ccache_not_in_world_dir` (pytest) | the forwarded TGT's ccache is not created under a world-writable directory — the CWE-377 regression test for `deleg_capture.c:210–236` |
| parity | `test_cred_write_parity` (from W0) | the §2.1 four-row table, one assertion per cell, equal-or-stronger after migration |

#### C12

| kind | test | asserts |
|---|---|---|
| success | `test_backstop_agrees_with_edge` | for a matrix of {identity × path × op}, the backstop's verdict equals `brix_auth_gate`'s on all five planes |
| success | `test_backstop_reads_are_gated_too` | the read-side twin refuses an unauthorized read; a backstop that only covers mutations is a half-backstop |
| error | `test_backstop_unbound_refuses` | `bound == 0` refuses — a wiring bug fails closed |
| error | `test_backstop_unmapped_op_refuses` | an op with no `BRIX_AUTH_*` mapping refuses rather than defaulting to a permissive privilege |
| error | `test_backstop_no_rules_is_distinguishable` | "bound, but the export configured no rules" reports `no_rules`, not `unbound` — the two are the same pointer state today (§4/C12.2) |
| security-neg | `test_edge_gate_removed_still_refused` | with the protocol-edge gate stubbed, a mutation is still refused; this is W0's `test_authz_edge_removed_reaches_storage` inverted |
| security-neg | `test_backstop_never_more_permissive` | over the whole matrix, no {identity, path, op} triple is allowed by the backstop and denied by the edge |
| security-neg | `test_backstop_after_erofs` | on a read-only export, `EROFS` still precedes the backstop's `EACCES` — the phase-105 Appendix I.5 non-disclosure obligation, and the easiest thing here to break |
| observability | `test_backstop_observe_never_refuses` | in `observe`, a disagreement increments the counter and returns `NGX_OK` |

#### C13

| kind | test | asserts |
|---|---|---|
| success | `test_n2n_roundtrip_per_scheme` | `pfn2lfn(lfn2pfn(x)) == x` for `IDENTITY`, `RAL`, `CEPHFS_PATH` over a corpus including multi-slash and trailing-slash forms |
| success | `test_n2n_listing_renders_logical` | a `dirlist` over a translated export shows LFNs, not PFNs |
| success | `test_ceph_key_equals_stage_output` | for every input in the existing `sd_ceph_normalize` corpus, the shared stage produces the identical key — the migration is behaviour-preserving before it is anything else |
| error | `test_n2n_unknown_scheme_rejected_at_config` | `nginx -t` fails on an unknown scheme name |
| error | `test_n2n_ral_without_pool_rejected` | `ral` with no `brix_n2n_pool` is a config error, not a runtime surprise |
| error | `test_n2n_overlong_prefix_rejected` | a prefix longer than `brix_n2n_cfg_t`'s 256-byte field is a config error, never a silent truncation |
| security-neg | `test_n2n_dotdot_rejected_before_prefix` | `..` is rejected **before** the prefix is applied; `n2n_has_traversal` (`site_n2n.c:12–31`) keeps its semantics |
| security-neg | `test_n2n_a_dotdot_b_is_rejected_not_resolved` | the named test for the §4/C13.2 conflict: `/a/../b` is **rejected**, where `sd_ceph_normalize` resolves it to `/b`. The name states the behaviour change so it is discoverable from the test list alone |
| security-neg | `test_n2n_unreachable_without_resolve_path` | the stage cannot be reached by a path that did not come through `resolve_path()` — INVARIANT #4 |

### 8.3 Cross-cutting

- **Consolidation parity.** Every migration wave (W1, W2) opens with the table
  pinning the behaviour of each copy it will delete, and closes by re-running
  that table against the shared implementation (§3.5). A wave that cannot
  produce this table has not established its bar and does not land.
- **Backstop agreement.** A lane-wide `observe` run over the existing suite,
  asserting `edge_missing` and `unbound` both stay at zero. This is a test *of
  the model*: a non-zero counter means either a real uncovered path or a wrong
  op→privilege mapping, and both must be resolved before `enforce` is proposed.
- **Ordering.** Position 1.5 asserted with the phase-105 ordering spy
  (`tests/c/test_vfs_read_only_spy.c`), extended to record the authz slot.
  `EROFS` before `EACCES` on a read-only export is asserted in the same run.
- **Domain entitlement.** After each wave, `check_vfs_seam.py` green **and** the
  waiver count in the migrated domain strictly lower than the W0 baseline.
- **Crash injection.** C10's `SIGKILL`-between-rename-and-flush test, run
  against the pre-phase tree first to prove it loses the tag. A durability test
  that has never failed has not been shown to test durability.
- **Fleet.** The OCI lane for C10; the delegation and TPC lanes for C11; the
  Ceph live lane for C13's key-equality corpus; all five live protocol lanes for
  C12's `observe` run.

### 8.4 Two suite-mechanics rules that apply to every test above

- **`serial` is not authoritative** — only the `@group` nodeid suffix keeps a
  module on one xdist worker. C10's crash test and C13's Ceph lane both bind
  fixed resources and need the group suffix, not the marker.
- **A `Skipped` escapes `pytest.raises(Exception)`** — `Skipped` derives from
  `BaseException`, so a negative test written as "this must raise" silently
  passes when the environment skips it. Every security-negative above asserts
  the *specific* refusal (`EROFS`, `EACCES`, `EPERM`, `EINVAL`), never merely
  that something was raised.
---

## 9. Expected file map

### 9.1 New files

```
src/core/compat/service_publish.c   C10 — brix_service_publish_bytes/_fd
src/core/compat/service_publish.h        (beside staged_file.{c,h}, same unit family)
src/fs/vfs/vfs_authz.c              C12 — brix_vfs_require_authorized + _read
tools/ci/check_authz_backstop.py    C12 — every mutator calls the backstop
tests/c/test_service_publish.c      C10 unit
tests/c/test_vfs_authz_backstop.c   C12 unit
tests/test_vfs_authz_backstop.py    C12 lane test
```

Four new `src/` `.c` files. Each needs a line in the repo-root `./config`
(`staged_file.h` is at `config:593`, `cred_stage.c` at `:739`,
`staged_file*.c` at `:798–800`, `site_n2n.c` at `:988` — the new units go
beside their neighbours) and a re-`./configure --add-module=$REPO` before the
next `make`. `check_config_coverage.py` is what catches a forgotten line;
without the re-configure the symbol is simply absent at link time, which reads
as an unrelated failure.

C11 adds **no** new file: it extends `src/core/compat/cred_stage.{c,h}`, which
is already in `config` and already has a registered unit test.

C13 adds no new file either if the stage lands inside `src/fs/path/`; if it
instead moves `site_n2n.{c,h}` out of `src/fs/backend/`, that is a move, and the
`config` line, the `README.md` coverage entry and the `SPECS["site_n2n"]`
compile args all move with it (§4/C13.3).

### 9.2 Modified — the shared surfaces

```
src/fs/vfs/vfs_policy.h            +BRIX_VFS_MUTATE_CREDENTIAL (vocabulary 15->16)
src/fs/vfs/vfs_policy.c            _Static_assert:33 — fails the build if the
                                   mirror is incomplete
src/fs/vfs/vfs.h                   +brix_vfs_authz_t, +brix_vfs_ctx_bind_authz()
                                   in the shape of the binders at :165/:173/:182
src/core/compat/cred_stage.h/.c    C11 — brix_cred_write() + the two arms;
                                   brix_cred_stage_write becomes a wrapper
src/core/compat/staged_file.c      C10 — the parent-dir fsync at :317-319 is
                                   fixed here (phase-107 C3), not duplicated
src/core/types/identity.h          C12 — the memoized xrdacc entity, following
                                   mapped_user/mapped_resolved at :69-70
src/auth/authz/auth_gate.h/.c      C12 — the identity-only decision form
src/fs/path/path.h                 C13 — the translation stage's entry points
src/fs/backend/rados/sd_ceph.c     C13 — sd_ceph_key's body calls the stage;
                                   its 14 call sites are untouched
src/fs/backend/site_n2n.c/.h       C13 — wired; possibly relocated
config                             four new .c files
```

The five metric-mirror files move together in W1 and in no other wave:

```
src/observability/metrics/metrics.h           the SHM cube (:405-415)
src/observability/metrics/unified_record.c    the record path (:354-383)
src/observability/metrics/unified_export.c    the emitter (:140-171, reg :435)
src/observability/metrics/unified.c           the names array (:163)
src/observability/metrics/unified.h           BRIX_VFS_MUTATE_OP_METRIC_COUNT (:275)
```

### 9.3 Modified — the migration sites

C10, seven call sites in five files, all in `src/protocols/oci/`:

```
oci_store.c          -brix_oci_store_publish, -brix_oci_store_put_text
                     (:262-275 and :280-324, ~85 lines), and the two internal
                     callers at :417 (tag pointer) and :476 (layer ref mark)
oci_manifest_put.c   :189  manifest body
oci_referrers.c      :224, :244  referrers index
oci_upload.c         :266  upload part
oci_upload_seal.c    :104-110  blob seal — exists()-then-publish becomes the
                     excl arm; this is the only site whose control flow changes
```

C11, four implementations collapsing to one:

```
src/auth/krb5/deleg_capture.c        :210-236  brix_krb5_deleg_mkccache —
                                     $TMPDIR//tmp, unvalidated; migrated FIRST
src/protocols/webdav/delegation.c    :265-320  no EINTR retry, close() unchecked
src/fs/backend/cred_mint.c           :179-208 + :284  close() unchecked at :203
src/core/compat/cred_stage.c         becomes the one implementation
```

Its six existing call sites do not change at all — three direct
(`tpc/outbound/tpc_token_exchange.c:104`, `net/proxy/gsi_upstream.c:26`,
`protocols/webdav/tpc_cred_exchange.c:59`) and three through the
`brix_proxy_gsi_write_pem_temp` wrapper (`fs/vfs/vfs_deleg_x509.c:189`,
`net/proxy/gsi_upstream_login.c:208`, `protocols/webdav/tpc_user_proxy.c:84`).
That is the point of routing the `VOLATILE` arm under the existing name: the
migration is four bodies, not ten edits.

C12 touches no protocol handler. It adds a binder call at every
`brix_vfs_ctx_t` construction site — the census is part of W4 and `unbound`
falling to zero is how it is verified.

### 9.4 The subtraction ledger

This phase is mostly subtraction, and §11 measures it. Expected direction, per
area, measured against the W0 baseline:

| area | expected change |
|---|---|
| `src/protocols/oci/oci_store.c` | −~85 lines, −2 waivers |
| `src/protocols/oci/` other four files | 7 call sites simplified, no net growth |
| `src/protocols/webdav/delegation.c` | −~55 lines, −4 waivers |
| `src/fs/backend/cred_mint.c` | −~35 lines of mechanics, −2 waivers |
| `src/auth/krb5/deleg_capture.c` | −~25 lines, −1 waiver, −1 CWE-377 exposure |
| `src/core/compat/cred_stage.c` | **+**~120 lines — the one place that grows |
| `src/core/compat/service_publish.c` | **+**~180 lines — new, and the only home for publish mechanics outside `src/fs/backend/` |
| `src/fs/backend/site_n2n.c` | ±0 lines, 0 → *n* callers |

A wave whose diff grows the migrated area is a wave that added an abstraction
over a duplication instead of removing the duplication. That is the failure mode
this ledger exists to catch, and it is checked at the wave's close, not at the
phase's.
---

## 10. Compatibility and rollout

### 10.1 What a running deployment can observe

In descending order of risk.

**1. `brix_authz_backstop` (C12)** — the highest-risk change in this phase and
in phase 107, which is why it ships in `observe` and stays there. In `observe`
it cannot refuse anything: it computes a verdict, compares it to the edge's,
increments `brix_vfs_authz_backstop_total{proto,result}` and returns `NGX_OK`
regardless. The only way it reaches a client is through latency, and the
position-1.5 evaluation is allocation-free by construction (§4/C12.2's memoized
entity) precisely so that claim holds under load. `enforce` becomes the default
only after the counter has been flat across the fleet lanes, and that flip is
its own change with its own release note — **not part of this phase**.

**2. OCI publishes become durable (C10)** — one data fsync and one parent-dir
fsync per tag pointer, reference mark, referrers index and manifest body.
Registry writes are low-rate by nature (a push, not a data path), so this is the
intended cost of not losing a tag. The one visible latency change is a `push`
under a slow backing filesystem; the one visible *behaviour* change is that a
push which previously returned 201 and then vanished on power loss now either
returns 201 durably or returns 500.

**3. The blob-seal race closes (C10, site 6)** — `oci_upload_seal.c:104–110`
today does `exists()`-then-`publish`; after W2 it does
`brix_staged_commit_excl` and treats `EEXIST` as success. Two concurrent pushes
of the same blob previously raced to overwrite; now one wins and the other is
told, correctly, that the bytes are already there. Content-addressed storage
makes this indistinguishable to the client — that is the argument the existing
comment already makes, now enforced instead of assumed.

**4. Everything else is invisible.** C11 replaces four implementations with a
stronger shared one and does not change any file's final path, name or mode.
C13 is inert unless an operator sets a scheme — with no `brix_n2n_scheme`
directive the stage is `IDENTITY` and the path is unchanged, byte for byte.
Neither changes a wire answer, a directive default, or a supported
configuration.

### 10.2 What does *not* change

- **No ABI break.** Phase-107 W7 has the one ABI-visible change in this pair
  (`staged_commit`'s boolean `noreplace` → typed precondition, clean rebuild).
  This phase adds struct **members** — `brix_vfs_authz_t` on `brix_vfs_ctx_t`,
  the memoized entity on `brix_identity_t` — which still require a clean
  rebuild rather than an incremental one, for the usual reason: a stale object
  file compiled against the old struct layout reads garbage from the new
  offsets and the symptom is nowhere near the change.
- **No directive is removed or repurposed.** Four are added
  (`brix_authz_backstop`, `brix_n2n_scheme`, `brix_n2n_pool`, `brix_n2n_prefix`),
  all with defaults that reproduce today's behaviour exactly.
- **No metric is removed or renamed.** One family is added
  (`brix_vfs_authz_backstop_total`) and one label value
  (`op="credential"` on the existing `brix_vfs_mutation_denied_total`).
  A dashboard that sums over `op` will see the new value appear; that is the
  documented behaviour of a low-cardinality label set and the reason INVARIANT
  #8 caps it.
- **No configuration becomes invalid.** Every negative `nginx -t` case in §8.2
  rejects a configuration that could not have been written before this phase.

### 10.3 Rollout order

W0 is test-only and lands as soon as phase-107 W9 does. W1 and W2 are
independent and either may ship first. W3 is independent of both — and of
phase 107 entirely — so it can be pulled forward if the Ceph lane is the
priority. W4 ships last, in `observe`, and the phase closes without flipping it.

Each wave is independently revertible, which is the property that makes the
order negotiable at all. Nothing in W2 depends on W1 having landed; nothing in
W4 depends on either.

### 10.4 Rollback

| wave | revert mechanism | residue |
|---|---|---|
| W1 | git revert | none — the `VOLATILE` arm was byte-for-byte the old behaviour, pinned by `test_cred_write_parity` |
| W2 | git revert | temps named `<final>.tmp.XXXXXX` may exist under the store root; `brix_stage_dir_register` reaps them, and if the registration is reverted too they are inert files with no reader |
| W3 | `brix_n2n_scheme identity` (no rebuild) or git revert | none |
| W4 | `brix_authz_backstop off` (no rebuild) or git revert | none |

W1 and W2 are behaviour-preserving-or-stronger by construction, and the parity
table (§3.5) is what makes that claim checkable rather than asserted. W4's
revert is a directive value, which is the whole reason the directive has three
values and not two: `off` must be reachable without a rebuild, from a
configuration reload, by an operator who is watching a latency graph move at
03:00.

### 10.5 The one-way door

C10's `O_TRUNC` → `O_EXCL` change (§4/C10.4) is the only item here that cannot
be fully undone by reverting the code: temp files written under the new naming
scheme before a revert will not be found by the old code, which only ever looks
for `<final>.tmp.<pid>`. They are harmless — no reader, no client-visible name —
but they persist until reaped. Registering the store root with
`brix_stage_dir_register()` **in the same commit** as the naming change is what
keeps this a footnote instead of an incident, which is why §7/W2 lists it as a
requirement rather than an optimisation.
---

## 11. Definition of done

Each box is checkable by running something. A box that can only be checked by
reading the diff is a box that will be ticked by whoever wrote the diff.

### 11.1 The four items

- [ ] **C10** — `brix_oci_store_publish` and `brix_oci_store_put_text` no longer
      exist; `grep -rn "brix_oci_store_put_text\|brix_oci_store_publish" src/`
      is empty; all seven call sites go through
      `brix_service_publish_bytes()`/`_fd()`; the five defects D1–D5 of §4/C10.1
      are each closed by a named test in §8.2.
- [ ] **C11** — `brix_cred_write()` is the only credential materializer;
      `grep -rn "mkstemp\|O_CREAT.*0600" src/auth/ src/protocols/webdav/delegation.c src/fs/backend/cred_mint.c`
      returns nothing outside `core/compat/cred_stage.c`; the four
      implementations of §2.1 are one.
- [ ] **C12** — `brix_vfs_require_authorized()` is called at every mutator and
      every read entry point, asserted by `check_authz_backstop.py` and by the
      extended ordering spy; the directive exists with three values and defaults
      to `observe`.
- [ ] **C13** — `site_n2n` has production callers; `sd_ceph_key`'s body calls
      the shared stage; the round-trip property holds per scheme — **or** the
      unit has been deleted and §4/C13.5's honest-scoping paragraph has been
      rewritten to say so.

Any item not implemented is recorded here with its reason and its ceiling, in
the same shape phase 105 used. "Deferred" with no ceiling is not a record.

### 11.2 The invariants

- [ ] Vocabulary is **16** members; the `_Static_assert` at `vfs_policy.c:33`
      passes, which means all six mirror files moved together (§3.1).
- [ ] `EROFS` still precedes `EACCES` on a read-only export, asserted by
      `test_backstop_after_erofs` — the phase-105 Appendix I.5 non-disclosure
      obligation and the single easiest thing in this phase to break.
- [ ] Position 1.5 is where the backstop runs, asserted by the ordering spy in
      `tests/c/test_vfs_read_only_spy.c`, not by inspection.
- [ ] INVARIANT #4 holds through C13: the translation stage is unreachable by a
      path that did not come through `resolve_path()`
      (`test_n2n_unreachable_without_resolve_path`).
- [ ] INVARIANT #8 holds through §6: no new label is unbounded;
      `check_metric_cardinality.py` green.

### 11.3 The measurable outcome

- [ ] The `vfs-seam-allow` waiver count has **dropped** below the W0 baseline,
      per domain, not just in total. C10 and C11 must remove more waivers than
      phase-107 W9 annotated in their domains. A phase that leaves the count
      flat has typed the duplication instead of removing it.
- [ ] The §9.4 subtraction ledger holds: every migrated area is smaller, and the
      two shared units (`cred_stage.c`, `service_publish.c`) are the only files
      that grew.
- [ ] `check_duplication.py` reports **no new backlog entries** — the gate is
      absolute and the backlog is 0; a consolidation phase that adds to it has
      inverted its own thesis.
- [ ] The phase-107 C9 `domain` label shows service-storage mutations flowing
      through the shared verbs (§6.5). **If the series do not move, the
      consolidation did not happen.**

### 11.4 The evidence

- [ ] Every parity table from §3.5 is filled in, per wave, and appended to this
      document — the properties each deleted copy had, and the evidence the
      shared implementation has them all. This is the deliverable, not the
      paperwork.
- [ ] An OCI tag pointer survives `SIGKILL` between rename and flush — **and the
      same test was demonstrated to fail on the pre-phase tree**. A durability
      test that has never failed has not been shown to test durability.
- [ ] The CWE-377 regression test for `deleg_capture.c` passes and is registered
      in the suite, not merely written.
- [ ] `brix_authz_backstop observe` runs clean — `edge_missing` **and**
      `unbound` at zero across all five live lanes — and `enforce` is **not**
      the default at the close of this phase.

### 11.5 The gates

- [ ] `check_vfs_seam.py`, `check_vfs_mutation_gate.py`, `check_authz_backstop.py`,
      `check_sd_driver_conformance.py`, `check_config_coverage.py`,
      `check_directive_registry.py`, `check_metric_names.py`,
      `check_metric_cardinality.py`, `check_complexity.py` (CCN ≤ 15),
      `check_file_size.py` (600), `check_readme_coverage.py` — all green.
- [ ] Every new C unit appears in `SPECS`/`RUNNERS` **and** therefore in the
      parametrized pytest wrapper (§8.1). A unit that compiles but is not in the
      table does not run.
- [ ] `objs/nginx -t` green for every new directive, and **red** for every
      negative config case in §8.2 — both directions asserted.
- [ ] The `--pr` tier is green; the five live protocol lanes are green; the OCI
      and Ceph lanes are green.
- [ ] `src/fs/README.md`, `src/fs/backend/README.md`, `src/protocols/oci/README.md`,
      the authz README and `agent-guide-extended.md` updated **after** the code
      matches them, never before.
---

## Appendix A — proposed types and API contracts

Consolidated from §4, which carries the reasoning. This appendix is the
signature reference: if the two disagree, §4 is the design and this is the
transcription error.

Every contract below shares four properties, and they are properties of the
phase rather than of any one item:

1. **The first call is an authority check** — `brix_vfs_domain_mutation()` for
   the service-storage verbs (C10, C11), the mutation policy already at
   ordering position 1 for C12's backstop at 1.5. Before any syscall, so a
   refusal discloses nothing.
2. **Errno is the contract**, not a bespoke enum. `EROFS` for a refused
   mutation, `EINVAL` for a malformed request, `EACCES` for a refused
   authorization, and the underlying errno surfaced verbatim for I/O failures.
3. **No artifact is left behind on any failure path.** Every one of these verbs
   replaces a hand-rolled implementation that got this partly right.
4. **Cannot-decide is a refusal.** No verb here returns success on uncertainty.

### A.1 Service-storage publish (C10)

```c
/* src/core/compat/service_publish.h — new unit, beside staged_file.{c,h} */
#include "fs/vfs/vfs_policy.h"   /* brix_vfs_domain_t */

typedef struct {
    ngx_log_t         *log;
    brix_vfs_domain_t  domain;       /* REGISTRY / CACHE / STAGE / CONFIG / JOURNAL */
    const char        *root_canon;   /* confinement root (the store root, never "/") */
    const char        *final_path;
    mode_t             mode;         /* published mode; 0 keeps the temp's */
    unsigned           excl:1;       /* publish only if absent (RENAME_NOREPLACE) */
} brix_service_publish_req_t;

ngx_int_t brix_service_publish_bytes(const brix_service_publish_req_t *req,
    const void *bytes, size_t len);

ngx_int_t brix_service_publish_fd(const brix_service_publish_req_t *req,
    ngx_fd_t fd, const char *stage_path);
```

| return | errno | meaning |
|---|---|---|
| `NGX_OK` | — | the bytes are at `final_path`, durably if the domain is durable |
| `NGX_ERROR` | `EROFS` | the domain assert refused |
| `NGX_ERROR` | `EINVAL` | `req` NULL, domain out of range, `final_path` outside `root_canon` |
| `NGX_ERROR` | `EEXIST` | `req->excl` and the final path exists — caller maps to 409/412 |
| `NGX_ERROR` | `ENOSPC`/`EIO`/`EDQUOT`/… | surfaced verbatim from write, close, fsync or rename |

**Composition, not mechanism** — steps 1–8 of §4/C10.3. The only line C10 writes
from scratch is the parent-directory fd derivation, which it shares with
phase-107 C3 and which explicitly must **not** reuse `rootfd`
(`staged_file.c:317–319` is inert on an `O_PATH` descriptor).

**Relationship to `staged_file.h`.** This is an addition, not a replacement.
`brix_staged_open()`/`_commit()`/`_commit_excl()`/`_abort()` keep every current
caller. C10's verb is the complete-buffer / finished-fd case, which is what all
seven OCI sites are; a caller that needs a writable staged fd held across many
callbacks uses `brix_staged_open()` directly (§5.1).

### A.2 Credential materialization (C11)

```c
/* src/core/compat/cred_stage.h — additions to an existing unit */

typedef enum {
    BRIX_CRED_ARM_VOLATILE = 0,  /* private tmpfs handoff; the temp IS the artifact */
    BRIX_CRED_ARM_PERSISTENT     /* durable publish into the configured credential dir */
} brix_cred_arm_t;

typedef enum {
    BRIX_CRED_KIND_BEARER = 0,   /* OAuth2 subject/bearer body */
    BRIX_CRED_KIND_PROXY,        /* X.509 (delegated or minted) PEM */
    BRIX_CRED_KIND_CCACHE,       /* Kerberos credential cache */
    BRIX_CRED_KIND_KEYTAB
} brix_cred_kind_t;

typedef struct {
    ngx_log_t        *log;
    brix_cred_arm_t   arm;
    brix_cred_kind_t  kind;      /* audit line + reap TTL only — never mechanics */
    const char       *dir;       /* [PERSISTENT] the configured credential dir */
    const char       *name;      /* [PERSISTENT] final basename, e.g. "<key>.pem" */
    const char       *prefix;    /* [VOLATILE]   mkstemp prefix, e.g. "tpc_token_body_" */
} brix_cred_write_req_t;

ngx_int_t brix_cred_write(const brix_cred_write_req_t *req,
    const void *bytes, size_t len, char *path_out, size_t path_outsz);
```

| return | errno | meaning |
|---|---|---|
| `NGX_OK` | — | `path_out` holds the credential's path |
| `NGX_ERROR` | `EROFS` | `brix_vfs_domain_mutation(CREDENTIAL, MUTATE_CREDENTIAL)` refused |
| `NGX_ERROR` | `EPERM` | the staging directory failed the owner/mode check — fail closed |
| `NGX_ERROR` | `EINVAL` | bad request shape (arm/kind out of range, missing `dir`/`name`/`prefix` for the arm, `path_outsz` too small) |
| `NGX_ERROR` | `ENOSPC`/`EIO`/`EDQUOT`/… | surfaced verbatim from write, close, fsync or rename |

**The arm is explicit and is never inferred.** `VOLATILE` does not fsync;
`PERSISTENT` does. The temptation is to probe the filesystem type and decide —
§3.3 rejects that: *a filesystem type is not an authorization for a durability
decision*. The caller knows whether its artifact is meant to survive a reboot;
the verb does not guess.

**`kind` selects the audit label and the reaper's TTL class, and nothing else.**
A keytab and a bearer body are written identically. A verb that branched on
`kind` for mechanics would be four verbs wearing one name.

**Compatibility.** `brix_cred_stage_write()` keeps its signature and becomes a
thin wrapper over the `VOLATILE` arm, so its three direct callers and the three
through `brix_proxy_gsi_write_pem_temp()` do not change (§9.3).

**Why not `brix_vfs_export_op_ctx_t`** — §4/C11.3. Its `root_canon` means the
*export* root; every credential write is outside every export by construction.

### A.3 Authorization backstop (C12)

```c
/* src/fs/vfs/vfs.h — a fourth binder beside :165, :173, :182 */
typedef struct {
    ngx_array_t        *authdb_rules;   /* finalized at postconfig */
    ngx_array_t        *vo_rules;       /* finalized at postconfig */
    void               *acc_tables;     /* brix_acc_tables_t*, NULL under native */
    ngx_uint_t          acc_format;     /* BRIX_AUTHDB_FORMAT_* */
    const char         *peer_ip;        /* for host ('p') rules */
    unsigned            bound:1;        /* set by the binder; 0 = never bound */
} brix_vfs_authz_t;

void brix_vfs_ctx_bind_authz(brix_vfs_ctx_t *ctx, const brix_vfs_authz_t *authz);

/* src/fs/vfs/vfs_authz.c */
ngx_int_t brix_vfs_require_authorized(const brix_vfs_ctx_t *ctx,
                                      brix_vfs_mutation_op_t op);
ngx_int_t brix_vfs_require_authorized_read(const brix_vfs_ctx_t *ctx,
                                           int lookup_only);
```

| return | errno | condition |
|---|---|---|
| `NGX_OK` | — | the ctx's identity holds the implied privilege on `ctx->resolved` |
| `NGX_OK` | — | bound, but the export configured no rules (`no_rules`) — allow-all is today's policy and C12 does not change it |
| `NGX_OK` | — | mode is `observe`, whatever the verdict; the disagreement is counted, not enforced |
| `NGX_ERROR` | `EACCES` | bound, rules present, denied |
| `NGX_ERROR` | `EACCES` | **cannot decide** — never bound, uninterpretable identity, unmapped op |

**`EACCES`, and always after `EROFS`.** Position 1.5 is *after* the mutation
kernel at position 1 (§3.4). On a read-only export the client is told
"read-only" and nothing else — phase-105 Appendix I.5's non-disclosure
obligation, asserted by `test_backstop_after_erofs` and not by review.

**Purity, and why it holds.** Rules are compiled and resolved against the export
root at postconfig, so runtime matching is longest-prefix string work. The one
arm that was *not* pure is `xrdacc`: `brix_acc_entity_build()` allocates on
`c->pool`. C12 memoizes the built entity on `brix_identity_t`, following the
`mapped_user[256]` / `mapped_resolved:1` precedent at `identity.h:69–70`, so
position 1.5 is allocation-free — the same property the mutation kernel has, and
the reason both can run before leaf resolution.

**It is the same three functions the edge calls.** All three tiers already have
identity-only twins — `brix_check_authdb_identity()` (`path.h:110`),
`brix_check_vo_acl_identity()` (already identity-only), and
`brix_identity_check_token_scope()` (reached via `policy.c:27`). The backstop
composes those in the frozen tier order; it does not reimplement a matcher, and
a divergence between edge and backstop verdicts would therefore be a *binding*
bug, not a *logic* bug. That is what makes `edge_missing` interpretable.

**Three-state directive**, `brix_authz_backstop off | observe | enforce`,
default `observe`. `off` must be reachable from a config reload without a
rebuild (§10.4).

### A.4 Name-translation stage (C13)

```c
/* src/fs/path/ — thin context wrappers over the pure site_n2n core */
ngx_int_t brix_path_lfn_to_pfn(const brix_vfs_ctx_t *ctx,
                               const char *lfn, char *pfn, size_t cap);
ngx_int_t brix_path_pfn_to_lfn(const brix_vfs_ctx_t *ctx,
                               const char *pfn, char *lfn, size_t cap);
```

| return | errno | condition |
|---|---|---|
| `NGX_OK` | — | translated; `IDENTITY` scheme copies through unchanged |
| `NGX_ERROR` | `EINVAL` | a `..` component (`n2n_has_traversal`, `site_n2n.c:12–31`) |
| `NGX_ERROR` | `ENAMETOOLONG` | the result does not fit `cap` — never a truncation |

The wrappers bind the export's `brix_n2n_cfg_t` to the existing pure
`brix_n2n_lfn2pfn()` / `brix_n2n_pfn2lfn()`. **They must not add logic.**
`site_n2n.c` stays pure and standalone-testable — the one property it currently
has, and the reason its unit test is worth keeping when it finally gets callers.

**Ordering is the security content.** `brix_path_lfn_to_pfn()` may only be
called on a path `resolve_path()` has already confined (INVARIANT #4). The
translation composes an operator-configured prefix with a client-influenced
string; running it before confinement would let the prefix carry the result
outside the export. The guard is `test_n2n_unreachable_without_resolve_path`, a
call-order test, not a comment.

**`sd_ceph_key`'s body** becomes a call into this stage. Its 14 call sites, its
`oid` buffers and its error handling are untouched — and the behaviour change
this implies (`/a/../b` rejected rather than resolved to `/b`) is §4/C13.2's
subject and W3's proof obligation, not a side effect to be discovered later.
---

## Appendix B — risk register and deliberately rejected alternatives

### B.1 Risks

| # | risk | item | mitigation | how it is detected |
|---|---|---|---|---|
| R1 | A consolidation silently drops a property one copy had — `O_NOFOLLOW`, an fsync, an error-path unlink, a checked `close()` | C10, C11 | the parity table is a wave **entry** criterion (§3.5): pin every copy's behaviour before deleting it, re-run the table after | `test_oci_publish_parity`, `test_cred_write_parity` — both written in W0 and both required to invert or hold, explicitly, per cell |
| R2 | The authz backstop is *more* permissive than the edge, and its green counter reads as coverage | C12 | fail-closed on cannot-decide; the whole point of the `observe` release | `test_backstop_never_more_permissive` over the full {identity × path × op} matrix — a directional assertion, not an equality one |
| R3 | The op→privilege mapping is wrong for one protocol plane | C12 | `observe` across all five live lanes | a non-zero `edge_missing` blocks the flip whether it is a real gap or a mapping error; the two are indistinguishable from the counter and both must be resolved |
| R4 | `EACCES` leaks ahead of `EROFS` on a read-only export | C12 | position 1.5 is *after* position 1, by construction | the phase-105 ordering spy, extended — asserted at every mutator, not sampled |
| R5 | `site_n2n` becomes load-bearing having never run outside a unit test | C13 | traversal fuzzing both directions, round-trip property tests, and the call-order test, all **before** it is wired | §8.2 C13's nine tests; the fuzz arm points the existing protocol-fuzz corpus at the LFN input |
| R6 | C13's `..` semantics change breaks a live Ceph deployment that depended on resolution | C13 | W3's proof obligation runs **first**: instrument all 14 `sd_ceph_key` call sites and demonstrate none can be reached with a non-canonical path | if one can, that is a pre-existing defect and W3 stops until it is fixed — the instrumentation is the evidence, not the argument |
| R7 | The registry's durability change slows a push | C10 | registry writes are tag pointers, marks and indexes — not layer blobs | measured in W2's exit criteria; the domain class is the knob if the measurement disagrees |
| R8 | The `O_EXCL` rename leaves temps accumulating after crashes | C10 | `brix_stage_dir_register()` on the store root, **in the same commit** as the naming change | §10.5 records it as the phase's one one-way door; §7/W2 lists it as a requirement |
| R9 | Scope creeps into an ACL or admin API | C12 | §1.2 names it a non-goal; the domain type explicitly grants no authority (phase-107 §3.7) | review, and the absence of any write path to a rule set in the file map (§9) |
| R10 | Phase 107 slips and this phase starts anyway | all | W0's first checkbox is the prerequisite check | C10 without `sync_publish` and the typed precondition would rebuild both a second time, which is the failure this phase is named after |
| R11 | The vocabulary grows to 16 in one file and not the other five | C11 | the `_Static_assert` at `vfs_policy.c:33` | the build fails; this is the one risk in the phase that cannot reach a running deployment |

### B.2 Rejected alternatives

**Making the VFS the only authorization decision point (C12).** Rejected in
§1.2. The edge gate rejects before path resolution and backend work, composes
the protocol-correct refusal — `kXR_NotAuthorized` vs 403 vs an FTP reply code —
and hosts the SHM verdict cache with its per-worker L1 on the GSI hot path.
Moving all three into the storage layer trades a cheap backstop for an expensive
migration and a worse hot path. The backstop *is* the cheap half; taking it is
not an argument for taking the rest.

**Enforcing the authz backstop from day one (C12).** Rejected: five planes, a
verdict cache, and a per-op privilege mapping that is being written for the
first time. Any modelling error is a site outage. One release in `observe`
converts that risk into a counter, and the counter is cheap enough to leave on.

**Shipping `enforce` inside this phase once `observe` is clean (C12).**
Rejected: "clean across the lanes" is evidence from a test fleet, and the flip
needs evidence from real deployments carrying real gridmaps and real VO
structures. The phase closes with the counter; the flip is the next change, with
its own release note.

**Folding `edge_missing` and `unbound` into one `undecidable` bucket (C12).**
Rejected, and an earlier draft of this document had it wrong. They are different
facts: `edge_missing` means the model found a path the edge does not cover;
`unbound` means the binder was not called. Folding them means the number that
gates the `enforce` flip can be moved by a wiring bug (§6.1).

**Deleting `site_n2n.c` instead of wiring it (C13).** Considered seriously —
deleting dead code is usually right. Rejected because the code is not wrong, it
is unwired: it implements two real GridPP schemes with a reverse direction
nothing else in the tree has, and `sd_ceph.c:166–228` has already begun
re-deriving a partial, one-way, *semantically divergent* version of it. Deleting
it guarantees the second copy finishes growing. §4/C13.5 states the alternative
plainly anyway, because the one outcome that must not happen is a third year of
it sitting compiled and uncalled.

**Consolidating the cache store's file mechanics (§5).** Rejected: it is already
a single-owner, internally consistent implementation of one domain.
Consolidation is for duplication, not for tidiness.

**Moving the OCI registry model, not just its file mechanics (C10).** Rejected:
the registry's semantics are protocol semantics. A VFS that knows what a
referrers index is has absorbed a protocol, which is the mirror image of the
mistake this phase is correcting. §4/C10.5's test — would this line read
identically if the caller were the FRM journal? — is where the boundary sits.

**One `brix_vfs_secret_write()` that also handles in-memory credentials (C11).**
Rejected as speculative generality. All four implementations write a file; a
verb that sometimes writes a file and sometimes does not needs its caller to
know which, which is exactly the ambiguity the consolidation exists to remove.

**Deciding C11's durability by probing the filesystem (C11).** Rejected on
principle, not on cost: a `statfs` returning `TMPFS_MAGIC` is not an
authorization to skip an fsync. The caller states the arm; §3.3 and A.2 both
record this, because it is the kind of shortcut that looks like cleverness in
review.

**Extending `brix_vfs_export_op_ctx_t` to carry a credential directory (C11).**
Rejected: its `root_canon` means the export root, and every credential write is
outside every export by construction. Overloading it would make one field mean
two things in a security-relevant type (§4/C11.3).

**Absorbing `tpc_marker.c` and `tpc_curl_multi.c:66` into C10's verb (§5.1).**
Rejected on inspection: the first already uses `brix_rename_confined_canon` and
has no duplicated safety property to recover; the second needs a writable staged
fd held across many callbacks, and forcing it through
`brix_service_publish_bytes()` would mean buffering an entire third-party copy
in memory. Recorded so the mismatch is a decision rather than an oversight.
---

## Appendix C — CI guards and static enforcement

### C.1 Guards this phase must keep green

| guard | what it checks here | wave |
|---|---|---|
| `check_vfs_seam.py` | the guard that **measures** this phase: after phase-107 W9 it parses a domain constant and checks a directory-prefix entitlement table. Every wave should make its entitlement rows *shorter*; a wave that adds a waiver says why in review | W1, W2 |
| `check_vfs_mutation_gate.py` | unchanged in contract. `MUTATE_CREDENTIAL` is booked through the domain form, so the guard sees it with no modification | W1 |
| `check_vfs_identity_branch.py` | C11's credential verb sits on the identity path and must not grow a `_cred`-style asymmetry of its own — the class of defect the storage-driver slot wave spent a week on | W1 |
| `check_config_coverage.py` | four new `.c` files in the repo-root `config` (§9.1) and a re-`./configure --add-module=$REPO` | W2, W4 |
| `check_directive_registry.py` | four new directives (`brix_authz_backstop`, `brix_n2n_scheme`, `brix_n2n_pool`, `brix_n2n_prefix`) registered, not merely parsed | W3, W4 |
| `check_metric_names.py` / `check_metric_cardinality.py` | one new family, one new label value, INVARIANT #8 intact | W1, W4 |
| `check_complexity.py` | absolute CCN ≤ 15. The op→privilege mapping (§4/C12.3) is the function that will push over; it splits at the design stage, not after the guard complains | W4 |
| `check_file_size.py` | 600-line cap. `oci_store.c` shrinks; `cred_stage.c` grows by ~120 lines from a low base; `service_publish.c` is new and sized deliberately under the cap, which is why it is a separate unit from `staged_file.c` (388 lines) at all | W1, W2 |
| `check_readme_coverage.py` | every touched directory's README, updated **after** the code matches it | all |
| `check_sd_driver_conformance.py` | unchanged — this phase adds no driver slot. Listed because a green run is the evidence of that claim | all |

### C.2 The new guard

**`tools/ci/check_authz_backstop.py` (C12)** — every VFS mutation entry point
calls `brix_vfs_require_authorized()`, and every read entry point calls
`brix_vfs_require_authorized_read()`, exactly as `check_vfs_mutation_gate.py`
requires the policy kernel. Same shape, same waiver mechanism, same failure
mode when someone adds an entry point and forgets. It is what stops the backstop
from itself becoming a convention held in place by a comment — which is,
precisely, the condition C12 exists because authorization is currently in.

It must also assert the **ordering**: the backstop call appears after the
mutation-policy call in the same function. A guard that checks presence but not
position would pass a tree that leaks `EACCES` ahead of `EROFS`.

### C.3 What `check_duplication.py` cannot see, and why that matters

The duplication gate is absolute with a backlog of 0, and it did not catch C10
or C11. That is worth recording as a **limit of the tool** rather than a failure
of it.

A hand-rolled `open`/`write`/`rename` in `oci_store.c` is not textually similar
enough to `staged_file.c` to trip a token-based detector: different variable
names, different error handling, different logging, different call shape. What
is duplicated is the *contract* — "stage, then publish atomically, then reap on
failure" — and structural duplication of a contract is invisible to a
token-window comparison. The same is true of the four credential writers, which
share a threat model and share almost no tokens.

The census that *does* see it is the seam-waiver table (phase-107 Appendix G): a
rising waiver count in a domain means someone is re-implementing storage
mechanics outside the layer that owns them. **A rising waiver count is the
signal `check_duplication` structurally cannot give**, which is why §11.3 gates
on the count per domain and not just in total.

This is also the argument for phase-107 C9 landing first. Before the domain
type, the waiver count is one undifferentiated number and a rise in it says
nothing about where.
---

## Appendix D — requirement traceability

### D.1 Item → design → wave → evidence

| item | design | API | wave | tests | metric | guard |
|---|---|---|---|---|---|---|
| C10 service publish | §4 C10.1–.5 | [A.1](#a1-service-storage-publish-c10) | W2 | §8.2 C10 (9 tests), `test_oci_publish_parity`, the `SIGKILL` crash test | reuses phase-107 C9's `domain` label | seam guard, config coverage, file size |
| C11 credential verb | §4 C11.1–.5 | [A.2](#a2-credential-materialization-c11) | W1 | §8.2 C11 (10 tests), `test_cred_write_parity` | `vfs_mutation_denied_total{op="credential"}` + one audit line | seam guard, identity branch, mutation gate, metric names |
| C12 authz backstop | §4 C12.1–.5 | [A.3](#a3-authorization-backstop-c12) | W4 | §8.2 C12 (9 tests), lane-wide `observe`, the ordering spy | `vfs_authz_backstop_total{proto,result}` | **`check_authz_backstop.py`** (new), complexity, cardinality |
| C13 n2n stage | §4 C13.1–.5 | [A.4](#a4-name-translation-stage-c13) | W3 | §8.2 C13 (9 tests), round-trip property, traversal fuzz, the 14-site instrumentation | — | directive registry, config coverage, call-order test |

### D.2 Defect → item → test

Every specific defect this document found, and the single test that closes it.
A defect with no row here is a defect this phase did not actually fix.

| defect | where | item | closing test |
|---|---|---|---|
| D1 no data fsync before publish | `oci_store.c:296–318` | C10 | `test_service_publish_bytes_is_durable` |
| D2 no parent-directory fsync | `oci_store.c`, and **inert everywhere** at `staged_file.c:317–319` | C10 + phase-107 C3 | `test_service_publish_bytes_is_durable`, `test_oci_tag_publish_survives_kill` |
| D3 `close()` result discarded | `oci_store.c:315` | C10 | `test_service_publish_short_write_reaps_and_logs` |
| D4 `O_TRUNC` at a predictable name, no `O_NOFOLLOW` | `oci_store.c:296` | C10 | `test_service_publish_temp_is_unpredictable`, `test_service_publish_no_follow` |
| D5 write-failure branch returns with no log line | `oci_store.c:302–309` | C10 | `test_service_publish_short_write_reaps_and_logs` |
| non-atomic blob CAS (`exists()`-then-`publish`) | `oci_upload_seal.c:104–110` | C10 | `test_service_publish_excl_eexist_is_benign` |
| CWE-377: forwarded TGT staged in unvalidated `$TMPDIR`//`tmp` | `deleg_capture.c:210–236` | C11 | `test_cred_write_no_tmpdir_fallback`, `test_krb5_deleg_ccache_not_in_world_dir` |
| `close()` unchecked on a credential file | `cred_mint.c:203`, `delegation.c` (×2) | C11 | `test_cred_write_close_failure_is_reported` |
| single `write()`, no `EINTR` retry | `delegation.c:303`, `cred_mint.c:195` | C11 | `test_cred_write_short_write_is_an_error` |
| no reaping on the `mkccache` failure path | `deleg_capture.c` | C11 | `test_cred_write_reaps_on_every_branch` |
| authorization has no storage-layer backstop | 28 edge sites, five vocabularies | C12 | `test_edge_gate_removed_still_refused` |
| "no rules" and "never bound" are the same state | `brix_vfs_ctx_t` today | C12 | `test_backstop_no_rules_is_distinguishable`, `test_backstop_unbound_refuses` |
| two divergent `..` semantics for one concept | `site_n2n.c:12–31` rejects, `sd_ceph.c:166–201` resolves | C13 | `test_n2n_a_dotdot_b_is_rejected_not_resolved`, preceded by W3's 14-site instrumentation |
| a compiled, config-listed, unit-tested module with zero callers | `site_n2n.c`, `config:988` | C13 | `test_site_n2n_unwired` (W0) inverting in W3 |

### D.3 Prerequisites from phase 107

The same table read the other way. Nothing in this phase starts before W9.

| this phase needs | for | phase-107 item | phase-107 wave |
|---|---|---|---|
| `brix_vfs_domain_t`, `brix_vfs_domain_mutation()`, the enforcing seam guard | every item's first call | C9 | W9 |
| `sync_publish` (the durable publish barrier) and the parent-fd derivation | C10 step 7, C11's `PERSISTENT` dir flush | C3 | W3 |
| `brix_sd_precond_t` (typed precondition) | C10's `excl` arm | C6 | W7 |
| the CAS/dedup gate | C10's blob-seal semantics | C8 | W1 |
| `BRIX_VFS_MUTATE_STAGE`/`EVICT`/`LOCK`/`DEDUP` | C12's op→privilege mapping covering the full vocabulary | C2, C7, C8 | W1, W5 |

### D.4 Non-goals, and where each is recorded

| deliberately not done | recorded in | why it is not an omission |
|---|---|---|
| move authorization off the protocol edge | §1.2, B.2 | the edge keeps refusal composition, early rejection and the verdict cache |
| an ACL or admin write API | §1.2, B.2 | the domain type grants no authority (phase-107 §3.7) |
| gridmap hot-reload | §1.2 | orthogonal to consolidation; a config-lifecycle concern |
| flip the backstop to `enforce` | §7/W4, §10.1, §11.4 | needs deployment evidence, not lane evidence |
| consolidate the cache store's mechanics | §5, B.2 | already single-owner and internally consistent |
| absorb `tpc_marker.c` / `tpc_curl_multi.c` | §5.1, B.2 | one is already correct; the other is a staged *open* |
| `client/` | §5 | its own VFS backends, its own seam guard |
---

*End of plan. Nothing in this document has been implemented. When a wave lands,
append its record here in the shape phase 105 used — what the sweep actually
found, not what it set out to find. That record must include the parity table:
the properties each deleted copy had, and the evidence the shared implementation
has them all.*
