# Phase 105 — VFS-authoritative read-only mutation gate

**Date:** 2026-08-28, revised 2026-08-30

**Status:** 📋 **PLAN ONLY — no implementation is claimed by this document.**

**Document version:** v3 — v2's implementation-grade expansion (policy types,
configuration precedence, complete mutation and driver-slot ledgers, protocol
matrices, delayed-work semantics, observability, CI enforcement, function-level
delivery, threat analysis, evidence traceability) reconciled against the storage
driver gap wave that landed after it. See
[§0 What the driver wave changed](#0-what-the-driver-wave-changed-for-this-plan).

**Tree inspected:** `875a4e6db` plus the working tree present on 2026-08-30.
v2 was written against `201ac9fdb` while the storage-driver gap wave was still in
flight; that wave has since completed, and it moved several of the surfaces this
plan gates. Symbol locations below were re-verified on 2026-08-30, but re-check
them again before each implementation wave.

**Prerequisites:** [phase 55](phase-55-storage-backend-abstraction.md),
[phase 62](phase-62-vfs-namespace-metadata-seam-closure.md),
[phase 71](phase-71-vfs-capability-uniformity.md),
[the VFS overview](../../src/fs/README.md),
[the backend-driver contract](../../src/fs/backend/README.md), and — new since
v2 — [the storage-driver slot
matrix](../09-developer-guide/storage-driver-slot-matrix.md), which is now the
census this plan's zero-call contract is enumerated from.

---

## Contents

Read first — [§0 What the driver wave changed for this
plan](#0-what-the-driver-wave-changed-for-this-plan): the deltas between v2's
baseline and the current tree, and the ones that move a gate point.

Core plan:

1. [Outcome](#1-outcome)
2. [Current state and the gap](#2-current-state-and-the-gap)
3. [Normative policy model](#3-normative-policy-model)
4. [Mutation coverage contract](#4-mutation-coverage-contract)
5. [Protocol behavior](#5-protocol-behavior)
6. [Backend independence](#6-backend-independence)
7. [Observability](#7-observability)
8. [Implementation waves](#8-implementation-waves)
9. [Test matrix](#9-test-matrix)
10. [Expected file map](#10-expected-file-map)
11. [Compatibility and rollout](#11-compatibility-and-rollout)
12. [Definition of done](#12-definition-of-done)

Implementation-grade appendices:

- [A. Terms, ownership domains, and hard invariants](#appendix-a--terms-ownership-domains-and-hard-invariants)
- [B. Configuration grammar and truth tables](#appendix-b--configuration-grammar-and-truth-tables)
- [C. Proposed VFS types and API contracts](#appendix-c--proposed-vfs-types-and-api-contracts)
- [D. End-to-end call flows](#appendix-d--end-to-end-call-flows)
- [E. Complete mutation ledger](#appendix-e--complete-mutation-ledger)
- [F. Protocol-specific behavior matrices](#appendix-f--protocol-specific-behavior-matrices)
- [G. Backend and decorator conformance](#appendix-g--backend-and-decorator-conformance)
- [H. Xattrs, locks, staging, and service-owned state](#appendix-h--xattrs-locks-staging-and-service-owned-state)
- [I. Async, concurrency, reload, and failure semantics](#appendix-i--async-concurrency-reload-and-failure-semantics)
- [J. Metrics, logs, and diagnostics](#appendix-j--metrics-logs-and-diagnostics)
- [K. Detailed verification design](#appendix-k--detailed-verification-design)
- [L. CI guards and static enforcement](#appendix-l--ci-guards-and-static-enforcement)
- [M. Function-level delivery manifest](#appendix-m--function-level-delivery-manifest)
- [N. Threat model and risk register](#appendix-n--threat-model-and-risk-register)
- [O. Requirement traceability and evidence ledger](#appendix-o--requirement-traceability-and-evidence-ledger)
- [P. Normative decisions and deliberately rejected alternatives](#appendix-p--normative-decisions-and-deliberately-rejected-alternatives)

---

## 0. What the driver wave changed for this plan

v2 was drafted mid-wave and said so. The wave has since landed, and it did not
merely add slots — it moved *where* the decision is taken for several verbs this
phase must gate. None of it invalidates the plan; all of it changes the surface
the plan has to cover. Read this section before costing any wave in §8.

### 0.1 The vtable is bigger, and the census is now published

`struct brix_sd_driver_s` (`src/fs/backend/sd.h`) carries **54 function-pointer
slots**, of which the published matrix censuses **52** — see the caveat below.
The wave brought the matrixed half to **364 of 572 cells with zero open gaps**,
recorded per cell in
[`storage-driver-slot-matrix.md`](../09-developer-guide/storage-driver-slot-matrix.md)
and regenerated/drift-checked by `tools/diag/sd_slot_matrix.py`. Slots that were
absent or partial when v2 enumerated the spy contract and are now live on real
drivers:

`server_copy` / `server_copy_cred`, `setattr` / `setattr_cred`,
`truncate_path` / `truncate_path_cred`, `space`, `query_checksum`, `enumerate`,
`read_advise`, `getxattr`/`listxattr`/`setxattr`/`removexattr` on `http`, and
the `_cred` twins across `sd_remote`, both Ceph drivers, `sd_xroot`, and both
decorators.

Most of that list is read-side and stays legal on a read-only endpoint. The
**mutation** additions a read-only endpoint must never reach are
`server_copy`/`server_copy_cred`, `setattr`/`setattr_cred`,
`truncate_path_cred`, and `setxattr`/`removexattr` (plus `_cred`) on `http` as
RFC-4918 dead properties. v2's Appendix E.3 was written before any of them were
implemented; it is updated accordingly.

**The caveat: the published census is not the whole vtable.** Diffing
`struct brix_sd_driver_s` against the matrix's rows gives 54 slots against 52
matrix rows, and the two missing ones are `dedup_publish` and `dedup_gc` — the
CAS alias-publish and alias-reap verbs. `dedup_publish` *is* a namespace
mutation (on `posix` it materialises a hardlink in the `/.gcas` farm), so a
zero-call contract enumerated from the matrix rather than from the header would
omit a mutation slot outright. Both verbs run on cache-fill worker threads
against the **cache store**, which makes them service-owned storage under §3.4
rather than export mutation — that is why they are not a live hole today, and it
is also exactly the kind of reasoning that has to be written down rather than
re-derived. Appendix G.1 records this alongside the `mirage` roster omission;
they are two independent ways the same census under-covers the vtable, and
Phase 105 enumerates from the header and the registry macro for that reason.

### 0.2 Namespace mutation now dispatches on the LEAF, not the top driver

This is the change with the most consequence for Phase 105. To reach a leaf
driver's `_cred` slot (decorators relay only the plain slots), several VFS
mutators now resolve `brix_vfs_ns_leaf(ctx->sd)` and dispatch there, stepping
*past* the cache decorator. Because the decorator no longer sees the call, each
site compensates by hand with `brix_sd_cache_evict()`:

| Site | Verb | Compensating evict |
|---|---|---|
| `src/fs/vfs/vfs_unlink.c:170` | unlink | pre-existing |
| `src/fs/vfs/vfs_rename.c:108-109` | rename (src + dst) | pre-existing |
| `src/fs/vfs/vfs_copy.c:123` | copy destination | added by the wave |
| `src/fs/vfs/vfs_mkdir.c:353` | `brix_vfs_chmod` | added by the wave |
| `src/fs/vfs/vfs_mkdir.c:422` | `brix_vfs_setattr` | added by the wave |
| `src/fs/vfs/vfs_sync.c:132` | `brix_vfs_truncate_path` | added by the wave |
| `src/fs/vfs/vfs_xattr.c:272` | set/remove xattr | added by the wave |

Four consequences this plan must absorb:

1. **The gate cannot sit on the decorator.** Any design that enforced read-only
   by refusing at the top of the driver chain would now be stepped over by all
   seven sites in that table (eight `brix_sd_cache_evict()` calls — `rename`
   compensates both ends). The policy kernel must run in the VFS function *before* the leaf
   is resolved — which is what §3 already specifies, and which is now load-bearing
   rather than merely tidy.
2. **Cache eviction is a mutation side effect.** A rejected request must produce
   zero `brix_sd_cache_evict()` calls and zero `brix_metric_cache_evicted`
   observations. Appendix G.2's spy contract and Appendix J's "no successful
   backend observation" rule both extend to this counter.
3. **Compensation is hand-written, therefore it is a checklist.** Every future
   leaf-dispatching mutator adds an eighth, ninth, tenth row to that table. The
   Phase-105 guard (Appendix L) is the natural place to assert that a leaf
   dispatch and a policy gate always appear in the same function.
4. **`brix_vfs_truncate_path()` already carries `brix_vfs_require_write()`**
   (`vfs_sync.c:89`, before the leaf lookup). Its E.1 row is therefore partly
   satisfied today; what it still lacks is the typed policy object rather than
   the `allow_write` bit.

### 0.3 A capability gate that asked the wrong driver — the shape to avoid

The wave's `truncate_path` defect is the exact failure mode Phase 105 is trying
to make structurally impossible, arriving one layer down. `brix_vfs_truncate_path`
gated on `brix_vfs_ctx_driver(ctx)` — the **top** driver — while dispatching on
the leaf. The `stage` decorator relayed `truncate_path` and `cache` did not, so
whether a `root://` export got path-native truncate depended on which decorator
happened to be composed on top of it.

Note the fix's shape, because it constrains this plan: the gate moved **to the
leaf**, not to the decorator. Publishing the slot on `cache` alone would have
turned the working `open` + `ftruncate` fallback into `ENOSYS` for every backend
without a path-native truncate (POSIX, http, s3). The general rule this phase
inherits: *a capability question is asked of the driver that will answer it; a
policy question is asked before any driver is chosen at all.* Conflating the two
is how the composition-dependent behaviour got in.

The asymmetry is now gated. `tools/ci/check_sd_driver_conformance.py` grew a
**decorator parity** check: for a 15-verb namespace/xattr/space base plus its
`_cred` twins (30 slots), `cache` and `stage` must publish the same set or the
guard fails. The byte plane is deliberately excluded. §6 and Appendix G.4 are
updated to reference the gate rather than describing parity as a nice-to-have.

### 0.4 The `_cred` plane is a live confused-deputy surface

The wave found and closed real confused deputies: `sd_remote` xattr reads,
`opendir`, and `server_copy` were signed as the **export** even when a per-user
credential was present. Deny mode was always safe; the *permitted* path was the
hole. Every namespace slot on the Ceph pair had the same shape for a different
reason — **in RADOS the ioctx IS the identity at the OSDs**, so a slot reaching
`st->ioctx` ran as the export while the keyring guarded only the data plane.

Two rules for this plan:

* **Policy ordering.** `sd_cred_forward.h` refuses with `EACCES` when the caller
  is in deny mode (`cred->fallback_deny`) and only a plain slot exists. That is a
  second denial reason arriving at the same seam as `EROFS`. Appendix I.5 now
  pins the precedence: endpoint read-only wins, because a read-only endpoint must
  not disclose whether the backend has a per-user identity for the caller.
* **Test assertions.** The `sd_remote` deputy was invisible to a body-diff test
  and obvious the moment the test asserted on *which credential signed the
  request*. Appendix G.2's spy record already carries credential-slot selection
  and K.4 already asserts it is zero; G.2 now states what the assertion is made
  *on* — the signing key, never the request bytes.

### 0.5 Read verbs that walk, and a read that writes

Two more wave outcomes touch this plan's read/mutation boundary:

* **`brix_vfs_enumerate_catalog()` now descends the decorator chain**
  (`vfs_walk.c`), joining `brix_vfs_residency`/`brix_vfs_space`: a question about
  the *backing store* is answered by the first instance that implements it, so a
  cache tier in front cannot demote a catalog-bearing export to a namespace walk.
  These are reads and stay in E.5 — but the descent is now a third place the
  decorator is bypassed, and a read-only endpoint must still answer them
  normally.
* **A cache fill seeds the digest it already proved** into the cached copy's
  `user.XrdCks.<alg>` xattr (`brix_cstore_seed_checksum`, `src/fs/cache/cstore.h`),
  because a cache HIT is served by the *store's* driver and never reaches the
  origin's `query_checksum` slot. This is a metadata write triggered by a read
  request — precisely the pattern E.5's last paragraph forbids — and it is
  **legal only because the target is the cache store, which is service-owned
  storage under §3.4, not the export**. §3.4 and E.5 now name it explicitly, so a
  later reviewer does not have to re-derive why one such write is allowed.

### 0.6 What did not change

Re-verified on 2026-08-30, still exactly as v2 described them:

* `brix_vfs_setxattr()` / `brix_vfs_removexattr()` still do **not** call
  `brix_vfs_require_write()`. `vfs_xattr.c`'s `brix_vfs_xattr_write_gate()` is a
  *capability* gate (`BRIX_SD_CAP_XATTR_WRITE`) plus the credential gate — not a
  mutation-policy gate. §2 item 4 stands unchanged.
* The forward `brix_kxr_from_errno()` table in
  `src/core/compat/error_mapping.c` still has no `EROFS -> kXR_fsReadOnly` row;
  only the reverse table (line 109) knows the pair. §2 item 8 stands.
* `brix_shared_apply_read_only()` still collapses to `common.allow_write = 0`.
* The confinement-only raw helper family is unchanged and still carries no
  endpoint policy.

---

## 1. Outcome

Every client-originated operation which can modify an exported storage
namespace, object, or object metadata is rejected by the VFS with `EROFS`
when that request's storage endpoint is configured read-only. The rejection
happens **before** the POSIX fallback, storage-driver slot, decorator,
thread-pool job, write-stage, or remote origin can observe the operation.

The phase is complete only when this statement is true for every protocol and
every registered backend:

> The protocol may reject a read-only mutation early, but the VFS is the final
> authority. No backend can be mutated merely because a protocol edge forgot
> its own gate.

“Read-only mutator” in this phase means a generic **mutation-policy gate**, not
a storage-driver decorator. A driver-level read-only wrapper is too late: it
would duplicate policy across driver stacks and would allow staging, queueing,
cache invalidation, and other VFS-side work to occur before rejection.

### 1.1 User-visible result

No new nginx directive is required. Existing endpoint settings select the VFS
policy after configuration inheritance and merge:

| Effective endpoint configuration | VFS mutation policy |
|---|---|
| `brix_read_only on` | read-only |
| `brix_read_only_public on` | read-only; public-introspection restrictions remain unchanged |
| `brix_allow_write off` | read-only |
| `brix_allow_write on` and neither hard read-only flag set | mutation allowed, subject to existing authn/authz |
| intrinsically read-only endpoint such as an OCI mirror, RPM mirror, CVMFS serving location, or diagnostic export | read-only |
| `brix_gridftp_allow_write off` | read-only |

`brix_read_only` continues to override `brix_allow_write on`, and
`brix_read_only_public` continues to imply `brix_read_only`. Authentication,
token scope, ACLs, and backend credentials remain separate authorization
layers; they do not promote a read-only endpoint and continue to report their
existing authorization errors.

### 1.2 Non-goals

- No replacement authn, authz, token-scope, ACL, or impersonation model.
- No new backend capability and no per-backend read-only implementation.
- No prohibition on writes to **separate service-owned domains** such as a
  read-through cache store, metrics database, control journal, or unpublished
  staging area. Those domains are not the exported filesystem. Their use must
  remain explicit and cannot publish or alter an export object while the
  endpoint policy is read-only.
- No change to nginx reload semantics. New workers use the new merged policy;
  old workers drain with their immutable old configuration. This phase does
  not add cross-generation revocation of already-open sessions.
- No removal of protocol-edge gates that avoid consuming a rejected request
  body or preserve the required `allow_write`-before-token-scope ordering.
- No success-by-backlog: policy-seam and conformance guards finish with no
  exception list for in-scope export mutations.

---

## 2. Current state and the gap

The tree already has most of the right pieces, but not one complete invariant.

1. `brix_read_only` and `brix_read_only_public` are merged by
   `brix_shared_apply_read_only()`, which currently collapses the result to
   `common.allow_write = 0` and documents enforcement at protocol edges.
2. `brix_vfs_ctx_t` carries an `allow_write` bit. Path mutators commonly call
   `brix_vfs_require_write()`, which currently returns `EACCES` when that bit
   is clear.
3. `brix_vfs_open_precheck()` duplicates that test for write opens instead of
   using one mutation-policy service.
4. Path xattr setters/removers and their fd variants intentionally bypass the
   write gate today so WebDAV lock bookkeeping can occur on read requests.
5. Handle mutation (`brix_vfs_file_pwrite()`, `brix_vfs_truncate()`, and
   `brix_vfs_sync()`) can reach a driver or I/O job without a fresh policy
   check. `brix_vfs_truncate_path()` is the exception: it gained
   `brix_vfs_require_write()` ahead of the leaf lookup during the driver wave
   (`vfs_sync.c:89`), so it needs the typed policy rather than a first gate.
6. The thread-safe/raw VFS helper family (`brix_vfs_open_fd[_at]`,
   `brix_vfs_unlink_path`, `brix_vfs_rmdir_path`, `brix_vfs_mkdir_path`,
   `brix_vfs_rename_path`, and tree-copy helpers) carries confinement but not
   endpoint mutation policy. Several protocol, TPC, CMS, and async-queue paths
   call it.
7. Protocol edges already fail fast, but they do so independently: root uses
   `kXR_fsReadOnly`, HTTP planes use protocol-shaped 403 responses, and
   GridFTP uses 550. A missed edge can therefore reach a weaker VFS result.
8. `brix_http_errno_to_status(EROFS)` already returns 403 and the reverse kXR
   map already knows `kXR_fsReadOnly -> EROFS`; the canonical forward
   `brix_kxr_from_errno()` table does not yet contain
   `EROFS -> kXR_fsReadOnly`. The root open path also has a local mapping that
   falls through to `kXR_IOError` for `EROFS`.

9. Seven VFS mutators now resolve `brix_vfs_ns_leaf()` and dispatch on the
   **leaf** instance so a per-user credential reaches the leaf driver's `_cred`
   slot, stepping past the cache decorator; each compensates by hand with
   `brix_sd_cache_evict()`. See [§0.2](#02-namespace-mutation-now-dispatches-on-the-leaf-not-the-top-driver)
   for the site table. Any gate placed on the driver chain rather than in the
   VFS function would be bypassed by every one of them.
10. `sd_cred_forward.h` refuses with `EACCES` when the caller is in deny mode
    and only a plain slot exists. That gives the same seam two denial reasons
    with no stated precedence between them.

The central defect is not a missing check in one handler. It is that mutation
authority is not an immutable, mandatory property of every VFS mutation path.
The driver wave made that sharper rather than softer: `server_copy`, `setattr`,
path-native `truncate_path` and their credential twins became real mutation
verbs on live drivers instead of NULL slots, and the dispatch for several of
them moved a layer *below* where a chain-level gate could see it.

---

## 3. Normative policy model

### 3.1 A typed, immutable policy

Replace the positional boolean meaning of `allow_write` inside the VFS with a
small typed policy. The exact names can follow coding review, but the shape is
normative:

```c
typedef enum {
    BRIX_VFS_MUTATION_READ_ONLY = 0,
    BRIX_VFS_MUTATION_ALLOWED
} brix_vfs_mutation_policy_t;
```

The existing `allow_write` argument position in `brix_vfs_ctx_init()` should
be replaced, not followed by another boolean. Every constructor must supply a
policy explicitly. No optional “bind later” setter is acceptable: it would
make an omitted call a writable-policy bug.

A single config helper derives this enum from the **effective merged endpoint
configuration**. Read-only helper contexts use the read-only enum directly.
Hand-built contexts, including the current WebDAV resource context, must be
migrated to a canonical initializer or builder.

The policy is copied by value into every object that can outlive setup:

- request/session VFS contexts;
- open file handles;
- staged handles and unified writers;
- TPC destination operations;
- async/backend queue records and thread-pool jobs;
- recursive namespace/copy contexts.

It is immutable for that operation/session. A delayed worker must not
reconstruct policy from a global or from a later nginx configuration.

### 3.2 One policy kernel

Add one low-complexity VFS policy service, conceptually:

```c
ngx_int_t brix_vfs_require_mutation(
    const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);
```

The bounded operation enum exists for diagnostics and low-cardinality metrics,
not for deciding whether one backend is exempt. Its values cover open/write,
truncate, sync, create, mkdir, remove, rename, copy/publish, setattr, xattr,
and staged commit.

The decision order is fixed:

1. validate the policy-bearing object/context;
2. validate path confinement where the operation is path based;
3. if mutation policy is read-only, fail with `errno = EROFS`;
4. otherwise continue into existing authz/credential/capability checks;
5. dispatch only after all gates pass.

`brix_vfs_require_write()` may remain as a compatibility wrapper during the
wave, but it must delegate to the policy kernel. `brix_vfs_open_precheck()`
must use the same kernel rather than spelling the condition again.

### 3.3 Enforcement twice where work is delayed

A mutation is checked at the earliest VFS entry point and again at the last
safe boundary before backend dispatch when a handle or queued job separates
those moments. The second check uses the copied immutable policy; it is not a
new configuration lookup.

This prevents:

- a writable-looking handle being created from a read-only context;
- a direct handle API bypassing its open-time check;
- a job losing policy while crossing into a thread pool;
- a staged upload publishing after only its initial open was checked;
- a recursive operation checking only the top-level directory and mutating
  children through an unguarded helper.

The duplicate check is defense-in-depth, not duplicate error reporting. Only
the boundary which rejects emits the denial observation.

### 3.4 Export storage versus service-owned storage

Hard read-only means **no mutation to exported storage**, regardless of
whether a call describes itself as bookkeeping. This includes data,
namespace entries, mode/ownership metadata, user metadata, dead properties,
tags, lock xattrs, and other backend-visible xattrs.

The existing xattr exception is therefore removed from export-facing APIs:

- `brix_vfs_setxattr()` and `brix_vfs_removexattr()` require mutation policy;
- fd mutation variants require a non-NULL policy-bearing handle/context;
- a NULL context is valid only for read-only fd xattr operations;
- expired-lock discovery on a read-only export treats an expired lock as
  absent but does not remove the xattr inline;
- if lock/control persistence must remain writable, it moves to a clearly
  separate service-owned control store rather than receiving an “internal”
  bypass to export storage.

Rollback may delete an unpublished VFS-owned temporary object created by an
operation which had already passed a writable policy. It may not create,
replace, rename into, or publish an export object. This narrow cleanup rule
must be represented by ownership of the staged handle, not a public bypass
flag.

Read-through cache fill remains legal because the cache store is a separate
service domain and the client requested a read. Cache fill must never update
export metadata or cause write-through while the endpoint is read-only.

The driver wave added a second, sharper instance of the same rule, and it is
worth naming so a reviewer does not read it as a violation.
`brix_cstore_seed_checksum()` (`src/fs/cache/cstore.h`) writes the digest a fill
already proved over the bytes into the *cached copy's* `user.XrdCks.<alg>`
xattr, so the first checksum request on a cache hit is answered from metadata
instead of re-reading the object. It exists because a cache HIT is served by the
**store's** driver and therefore never reaches the origin's `query_checksum`
slot. This is a metadata write caused by a read request — legal here, and only
here, because the target is the cache store:

- it writes to service-owned storage, never to the export;
- it is best-effort and silent, so a read-only endpoint that refuses it loses a
  recompute and nothing else;
- it must remain unreachable as a route to export metadata. A seeding
  implementation that ever resolved to the export instance would be an
  export mutation on a read path, and the spy contract must catch it.

---

## 4. Mutation coverage contract

The following inventory is the minimum gate surface. New VFS APIs capable of
mutation automatically join it.

| Mutation family | Required gate point | “No backend touch” includes |
|---|---|---|
| write/create/truncate/append open | before mkdir-parent, staging, cache eviction, or driver `open` | POSIX `open`, driver open, write-stage recall |
| byte write, writev, pgwrite | handle check before I/O job/driver call | `pwrite`, driver `pwrite`, block routing |
| truncate and sync | handle/path check before job/driver call | `ftruncate`, path truncate, flush/sync slots |
| mkdir/rmdir/unlink | before recursive locks or driver namespace slot | default POSIX and remote namespace ops |
| rename/move | before child locks, source mutation, or destination creation | same-backend and cross-backend paths |
| copy/publish | before destination creation or recursive copy | server-side copy and fallback copy loops |
| chmod/chown/setattr | before driver/POSIX metadata call | all setattr variants, plain and `_cred`, on every driver that now publishes the slot |
| path-native truncate | before the leaf lookup, not before the fallback | `truncate_path`/`truncate_path_cred`, and the open+`ftruncate` fallback taken when the leaf has neither |
| server-side copy | before the destination is named to the backend | `server_copy`/`server_copy_cred` on http, remote, xroot, and both decorators |
| set/remove xattr | before fd/path xattr dispatch | WebDAV locks/dead props, S3 tags/usermeta, root fattr, and http dead properties |
| decorator cache invalidation | never runs for a rejected request | `brix_sd_cache_evict()` at every leaf-dispatch site ([§0.2](#02-namespace-mutation-now-dispatches-on-the-leaf-not-the-top-driver)) |
| staged/writer lifecycle | open and publish/commit boundaries | temp creation, multipart completion, writeback promotion |
| TPC destination | before local destination setup or remote pull | markers, local temp, final publish |
| async namespace queue | before enqueue and before drain dispatch | queue record creation may occur; storage mutation may not |
| recursive/batch operations | parent gate plus policy copied through recursion | every child operation and partial-result cleanup |

Read-only operations remain valid: open/read/pread/readv/pgread, stat/statx,
list/readdir, checksum, get/list xattr, locate, and protocol-specific discovery.
The driver wave added four more that stay on this side of the line:
`space` (RFC 4331 / `kXR_Qspace`), `query_checksum`, `enumerate`, and
`residency`. Three of them — `query_checksum`, `enumerate`, `residency` —
descend the decorator chain to answer about the backing store rather than the
cached copy; `space` is answered by the decorator itself, which publishes the
slot. A read-only endpoint answers all four normally, because refusing them
would leak the endpoint's write posture into unrelated discovery.

`recall` is the one that does not follow its neighbours: as a query it is a
read, but a recall *initiated by a mutation request* creates a nearline
marker, so E.3 classifies it by its caller rather than by its name. An operation
that combines read and write intent is a mutation.

### 4.1 Raw VFS helper split

Confinement-only helpers are still necessary for explicitly service-owned
domains and low-level VFS internals. They must not remain an easy alternate
route for exported storage mutation.

- Add policy-bearing export wrappers for every mutating raw helper.
- Inventory every current caller and classify it as export storage,
  service-owned storage, or rollback of an already-owned temporary.
- Migrate all export-storage callers to policy-bearing wrappers.
- Keep confinement-only mutators internal to the VFS/service-domain layer;
  names and headers must make their restricted purpose evident.
- Extend `tools/ci/check_vfs_seam.py`, or add a focused
  `check_vfs_mutation_gate.py`, so protocol/TPC/CMS code cannot call an
  unguarded export mutation helper.
- Finish with an empty exception/backlog file. Same-line `vfs-seam-allow`
  comments do not waive mutation policy for export storage.

---

## 5. Protocol behavior

Protocol gates remain for fast failure and wire quality. They consume the same
effective policy as the VFS and must not invent storage-specific decisions.

| Plane | Read-only result | Required semantics |
|---|---|---|
| root/XRootD | `kXR_fsReadOnly` | stable read-only message; never `kXR_IOError` or `kXR_NotAuthorized` for endpoint policy |
| WebDAV/HTTP | HTTP 403 | supported method forbidden by endpoint policy; reject before body read |
| S3 | HTTP 403, S3-shaped `AccessDenied`/write-disabled XML | request ID and normal S3 response shape retained |
| OCI registry | HTTP 403, OCI `DENIED` body | mirror method gate remains fail-fast |
| GridFTP | FTP 550 | stable “read-only export” text |
| internal errno | `EROFS` | the sole VFS read-only mutation result |

Required mapping work:

- add `EROFS -> kXR_fsReadOnly` to `brix_kxr_from_errno()`;
- make root open failures use the canonical mapper or explicitly handle
  `EROFS` with the same stable message;
- retain `EROFS -> HTTP 403` in `brix_http_errno_to_status()`;
- keep S3 and OCI response shaping at their protocol edge while deriving the
  classification from the same read-only result;
- document `EROFS -> kXR_fsReadOnly -> HTTP 403` in the developer error table.

Ordering remains security-sensitive, but Phase 105 does not gratuitously
reorder protocol authentication challenges. The common contract is:

1. perform the minimum framing/parsing needed to classify the operation;
2. perform any base authentication which that protocol already requires
   before revealing policy (root and WebDAV currently do this; OCI may reject
   the endpoint policy earlier);
3. check endpoint mutation policy/global write enable **before** fine-grained
   token/path scope, mutation-body consumption, or storage setup;
4. perform remaining ACL/token/path authorization for a writable endpoint;
5. check VFS mutation policy immediately before storage dispatch.

This preserves INVARIANT 3 without changing authentication information
disclosure: no write-scoped token can promote an endpoint the operator
configured read-only.

---

## 6. Backend independence

No backend implements this policy. The VFS gate runs before resolution into
the default POSIX path or any `brix_sd_driver_t` slot, so the behavior is
identical for POSIX, block/pblock, RADOS/CephFS, HTTP, remote, S3, XRootD,
GridFTP/GSIFTP, and future registered drivers.

The mutation surface is now enumerable rather than estimated: the vtable is 54
slots, 52 of which the published matrix censuses across 11 drivers, and
[`storage-driver-slot-matrix.md`](../09-developer-guide/storage-driver-slot-matrix.md)
carries a verdict for every one of those 572 cells. The zero-call contract is
generated from the header and the registry macro rather than from that matrix or
any hand-written roster — see Appendix G.1 for the driver and the two slots the
matrix's own rosters omit.

Decorator compositions are part of the contract, not exceptions. Cache,
stage/writeback, FRM/nearline, and tier stacks must receive zero mutating calls
for a rejected request. That is now a stronger statement than it was in v2,
because several mutators dispatch on the leaf and step past the decorator
entirely: the proof cannot be "the decorator saw nothing", it must be "the leaf
saw nothing, and the decorator's compensating eviction did not run either". In
particular, denial occurs before:

- cache invalidation or write-through;
- stage recall or temporary creation;
- nearline request/marker creation;
- remote credential selection or network I/O;
- async queue enqueue;
- backend capability probing whose result could leak backend details;
- `brix_sd_cache_evict()` and its `brix_metric_cache_evicted` observation at any
  of the leaf-dispatch sites;
- leaf resolution itself where that resolution would select or copy a
  per-user credential.

A spy/counting driver is the primary proof: every mutation slot increments a
counter and fails the test if a read-only request reaches it. The storage
driver conformance catalogue must run the same policy contract for every
registered driver and decorator stack so a new driver inherits coverage
without a new hand-written read-only suite.

`tools/ci/check_sd_driver_conformance.py` is the place that contract belongs.
It already grew a **decorator parity** gate during the driver wave — `cache` and
`stage` must publish the same 15 namespace/xattr/space verbs plus their `_cred`
twins, or the guard fails, the byte plane deliberately excluded. Phase 105's
read-only row is the same kind of assertion one level up, and adding it there
means a new driver cannot register without it.

---

## 7. Observability

Read-only denial must be diagnosable without creating high-cardinality data.

- Record protocol, bounded mutation operation, and reason `read_only` through
  existing VFS/protocol operation metrics where possible.
- If no existing family can express the reason, add one bounded counter such
  as `vfs_mutation_denied_total{proto,op,reason}`. Never label by path, user,
  object key, backend URL, token subject, or error text.
- Emit one structured access/error event carrying operation, `EROFS`, and the
  read-only reason. Existing safe path logging rules still apply.
- Do not double-count when a protocol edge rejects before VFS. A VFS denial is
  counted only when the defense-in-depth gate is the rejecting boundary.
- A rejected request records zero bytes written, zero staged bytes, and no
  successful backend latency observation.

---

## 8. Implementation waves

Each wave lands with success, error, and security-negative tests. No wave may
leave a protocol path depending solely on an edge check.

### W0 — Freeze the contract with failing tests

- [ ] Add a pure policy unit test for allowed versus read-only contexts.
- [ ] Add the missing `EROFS` mapping assertions for root and HTTP.
- [ ] Build a spy backend covering every mutation slot and zero-call checks —
      generated from `struct brix_sd_driver_s` so the slots the driver wave
      added (`server_copy`, `setattr`, `truncate_path`, and every `_cred` twin)
      are covered by construction rather than by transcription.
- [ ] Add static inventory tests for current mutating VFS entry points and raw
      helper callers, including the seven leaf-dispatch sites in
      [§0.2](#02-namespace-mutation-now-dispatches-on-the-leaf-not-the-top-driver).
- [ ] Pin the current composition-order behaviour of every mutating verb before
      changing it, so a Phase-105 regression is distinguishable from the
      decorator-parity behaviour the driver wave just fixed.
- [ ] Pin existing default, inheritance, override, and
      `read_only_public -> read_only` configuration behavior.

### W1 — Carry endpoint policy into the VFS

- [ ] Introduce `brix_vfs_mutation_policy_t` in the public VFS contract.
- [ ] Replace the initializer's positional `allow_write` boolean with the
      typed policy; do not add another argument.
- [ ] Add one shared conversion from merged endpoint configuration.
- [ ] Migrate every `brix_vfs_ctx_init()` call and remove hand-built contexts.
- [ ] Copy policy into file, staged, writer, recursive, TPC, and async objects.
- [ ] Add constructor tests proving policy cannot be omitted or default to
      writable through zero/unset confusion.

### W2 — Make all VFS mutation entry points authoritative

- [ ] Add the central mutation-policy kernel in a small `vfs_policy` module.
- [ ] Route write-open precheck and every path mutation through it.
- [ ] Gate handle `pwrite`, truncate, and sync before I/O-core submission.
- [ ] Gate staged open/write/commit and unified writer open/write/commit.
- [ ] Gate set/remove xattr, including fd variants; remove nullable-policy
      mutation.
- [ ] Recheck policy in delayed/recursive execution boundaries without
      duplicate observations.
- [ ] Gate `brix_vfs_truncate_path`, `brix_vfs_chmod`, `brix_vfs_setattr`, and
      the `server_copy` arm of `brix_vfs_copy` **before** they resolve
      `brix_vfs_ns_leaf()` — these dispatch past the decorator and are the sites
      a chain-level gate would miss.
- [ ] Prove policy failure occurs before mkdir-parent, temp creation, leaf
      resolution, cache invalidation (`brix_sd_cache_evict`), capability
      probing, credential lookup, and network I/O — in that order, since the
      wave moved several of these ahead of where v2 assumed they sat.
- [ ] Land the gate ahead of `brix_vfs_xattr_write_gate()`, not inside it: that
      helper checks `BRIX_SD_CAP_XATTR_WRITE` first, and a capability `ENOTSUP`
      arriving before `EROFS` is the disclosure Appendix I.5 forbids.

### W3 — Close raw-helper and service-domain bypasses

- [ ] Classify every confinement-only mutator caller.
- [ ] Add policy-bearing export variants and migrate protocol/TPC/CMS/queue
      export callers.
- [ ] Restrict service-domain primitives to internal headers or explicit
      service-domain APIs.
- [ ] Remove inline read-time mutation of expired WebDAV lock xattrs on a
      read-only export; preserve read semantics.
- [ ] Verify cleanup can only remove an owned unpublished temporary.
- [ ] Add the no-backlog mutation-seam CI guard.

### W4 — Unify edge behavior and mappings

- [ ] Root: open/write/fattr/prepare/TPC/namespace paths use the same policy
      and report `kXR_fsReadOnly`.
- [ ] WebDAV: all mutating methods, including LOCK/UNLOCK, PROPPATCH, COPY,
      MOVE, and TPC destinations, return 403 before bodies/work.
- [ ] S3: object writes, tagging/usermeta, batch delete, multipart lifecycle,
      and server-side copy return S3-shaped 403 responses.
- [ ] OCI: registry push/upload/manifest/delete/referrer mutation reports
      `DENIED`; mirror mutation remains blocked.
- [ ] GridFTP: STOR/APPE/DELE/MKD/RMD/RNFR-RNTO/SITE CHMOD return 550.
- [ ] Intrinsically read-only CVMFS/RPM/diagnostic planes bind a read-only VFS
      policy even though their method gates should make it unreachable.
- [ ] Canonical errno mappings and documentation are updated.

### W5 — Backend, reload, and end-to-end proof

- [ ] Run the spy contract against every registered driver — enumerated from
      `BRIX_FS_DRIVER_LIST`, all twelve rows including `mirage` — and every
      decorator composition in both orders.
- [ ] Assert credential-slot proof on the signing key, not on request bytes.
- [ ] Verify reads still work through every representative backend.
- [ ] Verify no export digest/stat/xattr changes after every rejected request,
      and no cache eviction: a rejected mutation must leave
      `brix_metric_cache_evicted` untouched.
- [ ] Verify no stage, multipart, queue, nearline, or remote-origin side effect.
- [ ] Exercise nginx config inheritance and reload: new workers use new policy;
      old workers drain under their captured generation.
- [ ] Run raw root wire, WebDAV, S3, OCI, and GridFTP oracle lanes.
- [ ] Update VFS/backend READMEs, configuration docs, error tables, and the
      agent guide only after implementation matches them.

---

## 9. Test matrix

### 9.1 Configuration matrix

At minimum, exercise:

- [ ] default `allow_write off`;
- [ ] explicit `brix_allow_write off`;
- [ ] `brix_allow_write on`;
- [ ] `brix_allow_write on` plus `brix_read_only on` (hard read-only wins);
- [ ] inherited read-only from parent scope;
- [ ] child scope made writable only where hard read-only is not inherited;
- [ ] `brix_read_only_public on` implication and introspection behavior;
- [ ] GridFTP write enable off/on;
- [ ] intrinsically read-only endpoint mode.

### 9.2 Operation matrix

For every applicable protocol, cover at least one operation from each family:

- [ ] create/write/append;
- [ ] overwrite/truncate/sync;
- [ ] mkdir/rmdir/delete;
- [ ] rename/move/copy;
- [ ] chmod/setattr, on a driver that publishes the `setattr` slot and on one
      that falls back;
- [ ] path-native truncate on a leaf that publishes `truncate_path`, and the
      open+`ftruncate` fallback on one that does not — both behind a cache tier
      and without one, since composition decided this verb's behaviour once
      already;
- [ ] server-side copy (`server_copy`) with the destination inside the
      read-only endpoint;
- [ ] set/remove xattr or protocol metadata, including http dead properties;
- [ ] staged/multipart commit and abort;
- [ ] TPC destination and async execution;
- [ ] batch/recursive mutation;
- [ ] ordinary read/stat/list/checksum as the positive control;
- [ ] `space`, `query_checksum`, `enumerate`, and `residency` as a second
      positive control — each descends the decorator chain, and each must keep
      answering normally on a read-only endpoint.

### 9.3 Security-negative assertions

- [ ] a valid write-scoped token cannot bypass endpoint read-only;
- [ ] admin/manager credentials cannot bypass it accidentally;
- [ ] a hand-built or zeroed context fails closed;
- [ ] fd-based and handle-based APIs cannot bypass a path gate;
- [ ] a queued job cannot shed or replace its captured policy;
- [ ] recursive children cannot use a weaker policy than their parent;
- [ ] cross-backend copy cannot mutate its destination after checking only its
      source;
- [ ] remote backend credentials are not selected or transmitted on denial;
- [ ] no temp filename, cache invalidation, lock xattr, or partial object is
      observable after denial;
- [ ] `EROFS` is not collapsed to 500/`kXR_IOError` at any response edge.

### 9.4 Three-test rule applied to the policy kernel

1. **Success:** writable policy reaches a spy mutation slot once and preserves
   existing result/metrics.
2. **Error:** read-only policy returns `EROFS` and the correct protocol result.
3. **Security-negative:** fully authorized credentials plus write scope still
   produce `EROFS`, with zero calls and zero side effects below VFS.

---

## 10. Expected file map

Names are design guidance, not permission to ignore the live topology.

| Area | Expected work |
|---|---|
| `src/fs/vfs/vfs.h` | typed policy, context/handle contract |
| `src/fs/vfs/vfs_policy.[ch]` | single low-complexity policy kernel; add new `.c` to repo-root `config` |
| `src/fs/vfs/vfs_internal.h` | internal wrapper and handle policy access |
| `vfs_open*`, `vfs_writer`, `vfs_staged`, `vfs_sync`, `vfs_xattr` | open/handle/staged/metadata gates |
| `vfs_mkdir`, `vfs_unlink`, `vfs_rename`, `vfs_copy`, `vfs_walk*` | namespace and raw-helper closure |
| `vfs_io_core*`, backend async queue | immutable job-policy propagation and final dispatch check |
| shared config types/merge | derive effective endpoint policy without losing hard-read-only precedence |
| root/WebDAV/S3/OCI/GridFTP front doors | bind policy once and retain fail-fast edge responses |
| `src/core/compat/error_mapping.c` | `EROFS` forward mapping parity |
| `tools/ci/check_vfs_seam.py` or sibling guard | forbid unguarded export mutations |
| `tools/ci/check_sd_driver_conformance.py` | read-only row per registered driver, beside the existing decorator-parity gate |
| `tools/diag/sd_slot_matrix.py` | roster reconciled with `BRIX_FS_DRIVER_LIST`; a mutation-class column per slot |
| `docs/09-developer-guide/storage-driver-slot-matrix.md` | regenerated once the read-only column exists |
| `src/fs/cache/cstore.[ch]` | prove checksum seeding targets the store instance, never the export |
| C unit tests and Python wire/config tests | policy, zero-call, backend, protocol, composition-order, and reload proof |

All edited C must follow the current coding standards: no new globals, no
`goto`, no helper reimplementation, early-return structure, files below the
project size limit, and functions within all active complexity thresholds.

---

## 11. Compatibility and rollout

1. Land the typed policy and tests before deleting any existing edge gate.
2. Preserve current response bodies/messages where they already correctly
   identify a read-only endpoint.
3. Treat a newly exposed `EROFS` in a path that previously became generic
   `EACCES`/500 as a correctness fix; enumerate such wire-visible changes in
   release notes and golden tests.
4. Do not change active old-worker policy during nginx reload. Document that
   normal nginx generation draining is the boundary.
5. A new backend cannot register as conformant unless its read-only spy row
   proves the VFS prevents every mutation slot from being called.
6. Keep protocol checks after VFS authority lands: they protect bandwidth,
   auth ordering, and protocol-specific error bodies.

Rollback is straightforward while waves are separate: restore the previous
context policy representation and retain the protocol-edge gates. Never roll
back by leaving half the mutators policy-aware; that state recreates the exact
bypass class this phase exists to remove.

---

## 12. Definition of done

- [ ] Effective endpoint configuration selects one immutable typed VFS policy.
- [ ] All export mutations, including handle, xattr, staged, recursive, TPC,
      and queued forms, consult that policy.
- [ ] Read-only denial is `EROFS` and happens before every backend/default
      POSIX mutation and before all mutation side effects.
- [ ] Root reports `kXR_fsReadOnly`; WebDAV/S3/OCI report their correct 403
      form; GridFTP reports 550.
- [ ] All protocol fast gates remain and cannot disagree with VFS policy.
- [ ] All registered backends and decorator stacks pass the zero-call contract,
      in both composition orders, enumerated from `BRIX_FS_DRIVER_LIST`.
- [ ] No mutator resolves a leaf instance, selects a credential, or evicts a
      cache entry ahead of the policy decision.
- [ ] `EROFS` precedes deny-mode `EACCES` and capability `ENOTSUP` at every
      seam that can produce more than one denial reason.
- [ ] Reads remain functional, including read-through cache fill in its
      separate service-owned domain.
- [ ] There is no general “internal metadata” bypass into export storage.
- [ ] The policy-seam guard has no backlog or exception for export mutations.
- [ ] Success, error, and security-negative suites pass for every changed
      surface.
- [ ] `make -j$(nproc)`, `objs/nginx -t`, relevant unit/wire suites, VFS seam
      guards, storage-driver conformance (including the decorator-parity gate),
      `tools/diag/sd_slot_matrix.py` drift check, and documentation-link checks
      pass.
- [ ] VFS, backend, configuration, error-mapping, and operator documentation
      describe the implementation that actually landed —
      [`storage-driver-slot-matrix.md`](../09-developer-guide/storage-driver-slot-matrix.md)
      regenerated, and §0 of this document folded into §2 rather than left as a
      delta against a superseded baseline.

Until every box above is checked by implementation evidence, Phase 105 remains
open.

---

## Appendix A — Terms, ownership domains, and hard invariants

This appendix removes the ambiguity that otherwise turns “read-only” into a
collection of unrelated handler checks.

### A.1 Terms

| Term | Normative meaning in this phase |
|---|---|
| endpoint | One effective nginx server/location storage configuration after inheritance and merge |
| export | The client-visible namespace rooted at `common.root_canon` or the equivalent GridFTP root |
| mutation | Any operation capable of changing export bytes, names, topology, metadata, durability state, or a published object |
| read-only policy | A VFS capability which rejects export mutation with `EROFS` |
| protocol-edge gate | An early protocol-specific rejection used for ordering, bandwidth, and correct response shape |
| VFS authority | The mandatory storage-neutral decision immediately above default POSIX and storage-driver dispatch |
| backend touch | Calling a mutating driver slot, issuing an export mutation syscall, starting remote mutation I/O, or initiating mutation-specific decorator work |
| service-owned domain | A root distinct from the export, owned by BriX-Cache for cache, staging, journals, queues, or operational state |
| published state | Client-visible export content or metadata; an unpublished temporary is not published state |
| operation policy | The immutable read-only/allowed value captured from one effective endpoint generation |
| storage capability | A `BRIX_SD_CAP_*` fact describing what a backend can do; never permission to do it |

“Read-only backend” and “read-only endpoint” are deliberately different. A
CephFS-read-only driver may reject writes itself, but an endpoint using a
writable POSIX driver can also be read-only. Phase 105 makes the latter a VFS
property, and never relies on the former for protection.

### A.2 Ownership domains

Every path-bearing mutation must be classified before implementation review:

| Domain | Example | Endpoint policy applies? | Why |
|---|---|---:|---|
| export data | `/export/a.dat` bytes | yes | directly client-visible storage |
| export namespace | `/export/dir`, rename destination | yes | changes visible topology |
| export metadata | mode, owner, times, `user.*` xattrs | yes | changes the exported object |
| export protocol metadata | WebDAV dead props/locks, S3 tags/usermeta | yes | backend-visible client state |
| read-through cache | configured cache root | no | service-owned derivative of a read |
| upload stage | configured staging root | not by endpoint policy alone | unpublished service state; creation must still never begin for an already-read-only request |
| queue/journal | backend async queue, checkpoint/FRM journal | no direct export rule | service control state; enqueue for a denied mutation is forbidden |
| configuration/credential files | certs, tokens, keytabs | no | not export storage |
| rollback temporary | temp owned by an already-authorized write session | cleanup only | removal restores invariants; publishing remains policy-gated |

The root path alone is not enough to classify a domain. A multipart temporary
may physically live below an export today while semantically being unpublished
service state. Such a layout is a migration warning: the API must carry typed
ownership, and the phase should prefer moving the temporary beneath a distinct
service root where practical.

### A.3 Hard invariants introduced by Phase 105

These become review and test invariants:

1. **VFS-first authority:** every export mutation reaches one VFS mutation
   policy kernel before any backend/default-POSIX mutation.
2. **Fail closed:** zero-initialized, missing, invalid, or unbound mutation
   policy can never mean writable.
3. **Immutable capture:** a request, handle, staged session, or async record
   never re-reads a mutable/global policy later.
4. **EROFS fidelity:** endpoint read-only always becomes `EROFS` inside VFS.
5. **No capability promotion:** backend capabilities can return `ENOTSUP` after
   policy allows a mutation; they can never override read-only.
6. **No credential promotion:** authentication, admin identity, delegation,
   write token scope, and backend credentials cannot override read-only.
7. **No xattr loophole:** export xattr mutation is mutation even when used for
   locks, tags, dead properties, integrity metadata, or internal bookkeeping.
8. **No async laundering:** enqueue, thread-pool, TPC, and recursive work retain
   the initiating policy and cannot convert read-only to allowed.
9. **No partial setup:** a rejected operation creates no parent, temp, marker,
   multipart session, cache invalidation, queue record, or remote request.
10. **One rejection observation:** edge and VFS gates do not double-count or
    emit contradictory outcomes.
11. **Generation semantics:** nginx reload changes policy for new worker
    generations; old generations drain under their captured policy.
12. **New-driver inheritance:** registering a backend automatically subjects it
    to the same zero-mutating-slot conformance lane.

---

## Appendix B — Configuration grammar and truth tables

### B.1 Shared HTTP/root configuration

The existing common fields remain the source of operator intent:

- `common.allow_write` — effective global write enable;
- `common.read_only` — hard read-only role switch;
- `common.read_only_public` — hard read-only plus public introspection posture.

`brix_shared_apply_read_only()` currently forces `allow_write = 0`. Phase 105
does not undo this compatibility behavior. It adds one canonical conversion
after merge:

```text
if read_only_public: read_only = true
if read_only:        allow_write = false
policy = ALLOWED only when allow_write is true
otherwise policy = READ_ONLY
```

The conversion must consume only merged values (`0` or `1`), never
`NGX_CONF_UNSET`. If an unset value reaches it, configuration validation fails
closed rather than treating `-1` as true.

### B.2 Effective truth table

| `allow_write` after ordinary merge | `read_only` | `read_only_public` | Effective write advertisement | VFS policy | Notes |
|---:|---:|---:|---|---|---|
| 0 | 0 | 0 | read-only | READ_ONLY | default posture |
| 1 | 0 | 0 | read-write | ALLOWED | authz still required |
| 0 | 1 | 0 | read-only | READ_ONLY | explicit hard read-only |
| 1 | 1 | 0 | read-only | READ_ONLY | hard flag overrides and logs notice |
| 0 | 0 | 1 | read-only/public | READ_ONLY | public flag implies hard flag |
| 1 | 0 | 1 | read-only/public | READ_ONLY | implication then override |
| 0 | 1 | 1 | read-only/public | READ_ONLY | already normalized |
| 1 | 1 | 1 | read-only/public | READ_ONLY | strongest posture wins |

The VFS does not need separate “hard” and “soft” read-only modes. Both are an
endpoint refusal and both return `EROFS`. `brix_read_only_public` behavior not
related to storage mutation remains in its existing query/introspection gates.

### B.3 Inheritance cases to pin

| Parent | Child | Expected child policy |
|---|---|---|
| no directives | no directives | READ_ONLY |
| `allow_write on` | no override | ALLOWED |
| `allow_write on; read_only on` | no override | READ_ONLY |
| `read_only on` | explicit `read_only off; allow_write on` where grammar permits override | ALLOWED, matching existing merge semantics |
| `read_only_public on` | `read_only off` only | READ_ONLY because inherited public flag implies it again |
| `allow_write off` | `allow_write on` | ALLOWED unless an effective hard flag remains |

The phase must not silently change parent/child override semantics. Tests first
record the live merge behavior, including server/location ownership of the
shared HTTP directives and stream/root equivalents.

### B.4 Intrinsically read-only surfaces

Some modes are read-only independently of common flags:

- OCI pull-through mirror;
- RPM mirror/serving surface;
- CVMFS serving locations;
- diagnostic/digest-only exports;
- build-gated or backend modes explicitly documented read-only;
- GridFTP when `brix_gridftp_allow_write` is off.

Their context builders pass `BRIX_VFS_MUTATION_READ_ONLY` explicitly. They do
not temporarily set a shared config bit, mutate global configuration, or rely
on the default enum value without a named argument.

### B.5 Representative configuration examples

Hard read-only must win even when a shared include enabled writes earlier:

```nginx
server {
    listen 1094;
    brix_export /srv/data;
    include conf.d/site-write-defaults.conf; # may contain brix_allow_write on
    brix_read_only on;
}
```

The equivalent HTTP location remains minimal:

```nginx
location /dav/ {
    brix_export /srv/data;
    brix_webdav on;
    brix_allow_write on;
    brix_read_only on;
}
```

No storage-backend-specific read-only line is introduced:

```nginx
location /objects/ {
    brix_export /srv/object-view;
    brix_storage_backend s3://store.example/bucket;
    brix_s3 on;
    brix_read_only on;
}
```

The same VFS policy applies to POSIX, pblock, Ceph, S3, root-origin, or any
decorator composition selected beneath these examples.

### B.6 Configuration-time validation

Add or extend tests for these conditions:

- normalized policy is never unset by the end of merge;
- `read_only on` plus `allow_write on` is accepted with the existing notice and
  resolves read-only;
- `read_only_public on` implies read-only exactly once, without notice storms;
- root manager mode plus hard read-only remains rejected where currently
  required because manager forwarding could bypass the local storage policy;
- write-through/cache validation sees the normalized effective write state;
- an intrinsically read-only mode rejects a contradictory write-enable setting
  at `nginx -t` when its existing contract says it must;
- `OPTIONS`, capability/query, and locate advertisements report the same
  effective policy as the VFS.

---

## Appendix C — Proposed VFS types and API contracts

The declarations here are design sketches. Their semantics are normative;
final spelling follows coding review and live header organization.

### C.1 Policy and bounded operation types

```c
typedef enum {
    BRIX_VFS_MUTATION_READ_ONLY = 0,
    BRIX_VFS_MUTATION_ALLOWED = 1
} brix_vfs_mutation_policy_t;

typedef enum {
    BRIX_VFS_MUTATE_OPEN = 0,
    BRIX_VFS_MUTATE_WRITE,
    BRIX_VFS_MUTATE_TRUNCATE,
    BRIX_VFS_MUTATE_SYNC,
    BRIX_VFS_MUTATE_MKDIR,
    BRIX_VFS_MUTATE_REMOVE,
    BRIX_VFS_MUTATE_RENAME,
    BRIX_VFS_MUTATE_COPY,
    BRIX_VFS_MUTATE_SETATTR,
    BRIX_VFS_MUTATE_XATTR,
    BRIX_VFS_MUTATE_PUBLISH,
    BRIX_VFS_MUTATE_OP_COUNT
} brix_vfs_mutation_op_t;
```

Rules:

- zero is read-only, so zeroed objects fail closed;
- operation values are append-only and bounded;
- operation names come from one table/helper used by metrics and logs;
- the enum never contains protocol verbs, backend names, paths, or user data;
- `BRIX_VFS_MUTATE_OP_COUNT` is never accepted as a real operation.

### C.2 Context initialization

The existing initializer should replace the boolean in place:

```c
void brix_vfs_ctx_init(brix_vfs_ctx_t *vctx, ngx_pool_t *pool,
    ngx_log_t *log, brix_proto_t proto, const char *root_canon,
    const char *cache_root_canon,
    brix_vfs_mutation_policy_t mutation_policy,
    int is_tls, brix_identity_t *identity, const char *resolved_path);
```

It must:

1. zero the context;
2. normalize/validate policy;
3. store policy before backend resolution;
4. retain current root, cache, protocol, identity, TLS, and resolved-path
   behavior;
5. leave invalid policy read-only and mark initialization invalid or fail in a
   way every caller can test;
6. never infer writable from a non-zero integer outside the enum.

Because the current initializer returns `void`, implementation has two safe
choices:

- retain `void`, coerce unknown values to READ_ONLY, log/assert in test builds;
- introduce a checked initializer returning `ngx_int_t` and migrate every
  caller in the same wave.

The second is stronger but a wider internal API migration. There must not be a
partially migrated interval in which invalid policy means writable.

### C.3 Policy kernel contracts

Suggested separation keeps confinement and handle operations clear:

```c
ngx_int_t brix_vfs_require_mutation_policy(
    brix_vfs_mutation_policy_t policy,
    brix_vfs_mutation_op_t op);

ngx_int_t brix_vfs_require_mutation(
    const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);

ngx_int_t brix_vfs_require_confined_mutation(
    const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);
```

| Input/failure | Return | `errno` |
|---|---:|---:|
| null context where context required | `NGX_ERROR` | `EINVAL` |
| invalid operation enum | `NGX_ERROR` | `EINVAL` |
| unconfined/missing resolved path for path mutation | `NGX_ERROR` | `EINVAL` |
| read-only policy | `NGX_ERROR` | `EROFS` |
| allowed policy | `NGX_OK` | unchanged |

The kernel performs no allocation, blocking I/O, backend lookup, credential
selection, path logging, or protocol response construction. It is pure policy
plus bounded observation hooks. This keeps CCN/NPath low and makes it directly
unit-testable.

### C.4 Handle and staged-session contracts

`brix_vfs_file_t`, `brix_vfs_staged_t`, and `brix_vfs_writer_t` each carry the
policy by value. A retained `ctx` pointer remains useful for metrics/root/path,
but is not the sole source of mutation authority.

| Object | Construction requirement | Recheck points |
|---|---|---|
| file handle | writable open cannot succeed under read-only policy | `file_pwrite`, truncate, sync |
| staged handle | staged open cannot allocate/create under read-only policy | write and commit/publish |
| unified writer | open captures policy; child file/staged object gets same value | write, write-fd, commit/exclusive commit |
| recursive copy context | source read policy and destination mutation policy are explicit | before destination root and each child publish |
| async record | policy copied into serialized/in-memory record | enqueue and drain |

Close and abort are lifecycle operations, not client mutations. They remain
callable under read-only policy so resources can be released. Abort may remove
only its owned unpublished temporary.

### C.5 Policy-bearing raw/export operations

The off-thread helper problem should be solved with a typed operation context,
not by adding another boolean to every function:

```c
typedef struct {
    ngx_log_t                    *log;
    const char                   *root_canon;
    brix_vfs_mutation_policy_t    mutation_policy;
    brix_proto_t                  proto;
} brix_vfs_export_op_ctx_t;
```

Policy-bearing forms then take `const brix_vfs_export_op_ctx_t *`. Examples:

```c
int brix_vfs_export_open_fd(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical, int flags, mode_t mode);
int brix_vfs_export_unlink(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical);
ngx_int_t brix_vfs_export_copytree(const brix_vfs_export_op_ctx_t *opctx,
    const char *src, const char *dst, const brix_vfs_copy_opts_t *opts);
```

Read-only raw opens remain legal when flags are provably read-only. Any of
`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, or a mutation-specific
option triggers the mutation kernel before confinement helper dispatch.

The old context-free names either become private below-seam functions or are
retained only for service-owned roots in an internal header. Protocol code must
not select between protected and unprotected forms itself.

### C.6 Policy derivation helper

One shared helper should express endpoint semantics:

```c
brix_vfs_mutation_policy_t
brix_vfs_policy_from_write_enable(ngx_flag_t allow_write);
```

It maps exactly `1` to ALLOWED and every other value to READ_ONLY. Callers only
use it after config merge. Intrinsic read-only contexts use the named enum
directly. No helper accepts a backend capability as input.

---

## Appendix D — End-to-end call flows

### D.1 Writable request

```text
client request
  -> protocol classifier identifies mutation
  -> protocol's established base-authentication step, where applicable
  -> endpoint/global write gate allows before fine-grained token/path scope
  -> remaining authz and token/path scope allow
  -> path resolution/confinement
  -> VFS context built with MUTATION_ALLOWED
  -> VFS mutation gate allows
  -> capability/credential/backend resolution
  -> optional queue/stage/decorator
  -> backend driver slot or default POSIX backend
  -> protocol-shaped success/error
```

Existing authorization and storage errors after the VFS gate remain intact:
`EACCES`, `ENOTSUP`, `ENOSPC`, `EEXIST`, transport failures, and backend-specific
conditions are not relabeled read-only.

### D.2 Read-only request rejected at the edge

```text
client mutation request
  -> protocol classifier identifies mutation
  -> protocol's established base-authentication step, where applicable
  -> effective endpoint policy is READ_ONLY
  -> protocol emits kXR_fsReadOnly / HTTP 403 / FTP 550
  -> no mutation body read, path authorization/storage work, VFS call,
     backend credential lookup, queue, or backend call
```

The edge records one denial. This is the normal fast path.

### D.3 Read-only request reaching defense-in-depth VFS gate

This is deliberately tested by calling the VFS surface directly or bypassing
the protocol gate in a test harness:

```text
test/protocol regression reaches VFS mutation entry
  -> policy-bearing context is READ_ONLY
  -> brix_vfs_require_* returns NGX_ERROR, errno=EROFS
  -> VFS records one denial
  -> caller maps EROFS to its protocol shape
  -> spy backend counters remain zero
```

This path proves the architectural property; ordinary wire tests alone only
prove protocol gates.

### D.4 Write-open flow

The gate precedes every side effect:

```text
brix_vfs_open(ctx, WRITE|CREATE|TRUNC|APPEND|MKDIRPATH)
  -> validate flags
  -> require confined mutation(OPEN)
  -> only then: create parents
  -> only then: resolve credentials/backend
  -> only then: cache invalidation/stage selection
  -> only then: driver/default open
  -> handle captures policy
```

`BRIX_VFS_O_MKDIRPATH` is itself mutation intent even if the final open is
read-only; it cannot create parents on a read-only endpoint.

### D.5 Handle write flow

```text
brix_vfs_file_pwrite(fh, ...)
  -> validate handle and bounds
  -> require fh.policy WRITE
  -> construct I/O job / choose driver pwrite
  -> execute
```

For root write/pgwrite, the existing file-table mode/capability checks remain.
The VFS policy check is additional and authoritative; neither a stale writable
fd flag nor a bound data stream can bypass it.

### D.6 Staged publish flow

```text
staged_open(ctx)
  -> require OPEN/PUBLISH policy before temp/session allocation
staged_write(st)
  -> require captured WRITE policy before driver/temp write
staged_commit(st)
  -> require captured PUBLISH policy before rename/multipart complete
staged_abort(st)
  -> release state; delete only owned unpublished temp
```

A commit failure with `EROFS` must leave no newly published object. If a backend
supports multipart abort over the network, abort is permitted solely to remove
the already-owned unpublished upload session.

### D.7 Recursive copy/move flow

The destination determines mutation permission. Source readability is a
separate question.

```text
resolve source -> read checks
resolve destination -> destination policy READ_ONLY/ALLOWED
require destination COPY policy
acquire recursive child locks
walk source
for every destination child:
    inherited destination policy check/assert
    create/write/metadata
publish root/final state
```

Cross-backend fallback, server-side copy, WebDAV collection copy, and OCI/S3
copy must all follow this model. Checking only the source context is a security
bug.

### D.8 Async queue flow

```text
mutation request
  -> VFS policy check before enqueue
  -> queue record captures policy + operation + resolved domain
  -> worker/drain validates record and policy again
  -> backend dispatch
```

A read-only request must not create a durable queue record. A record created by
an allowed old nginx generation retains that allowed generation policy and may
finish while the old worker drains; this is consistent with Section 11 reload
semantics.

---

## Appendix E — Complete mutation ledger

This ledger is the starting audit, not a frozen symbol list. W0 regenerates it
from the live tree and W5 proves every row.

### E.1 Public VFS and handle APIs

| Current API/family | Class | Planned enforcement |
|---|---|---|
| `brix_vfs_open()` with write/create/trunc/append | OPEN | common precheck before parent creation/dispatch |
| `brix_vfs_file_pwrite()` | WRITE | file policy before driver `pwrite` |
| `brix_vfs_pwrite_full()` | WRITE | only behind policy-bearing export/service wrapper; not callable as export mutation directly |
| `brix_vfs_truncate()` | TRUNCATE | file policy before capability and I/O job |
| `brix_vfs_truncate_path()` | TRUNCATE | already calls `brix_vfs_require_write()` before the leaf lookup (`vfs_sync.c:89`); convert the bit to the typed policy and keep it ahead of both the leaf branch and the open+`ftruncate` fallback |
| `brix_vfs_sync()` | SYNC | file policy before I/O job |
| `brix_vfs_mkdir()` | MKDIR | existing write guard replaced by policy kernel |
| `brix_vfs_chmod()` | SETATTR | policy before driver/POSIX metadata, before leaf resolution, and before the compensating evict |
| `brix_vfs_setattr()` | SETATTR | policy before driver/POSIX metadata, before leaf resolution, and before the compensating evict |
| `brix_vfs_delete()` | REMOVE | policy before locks, traversal, or driver unlink |
| `brix_vfs_rename()` | RENAME | policy before child locks/source change |
| `brix_vfs_copy()` | COPY | destination policy before any destination work, including the leaf `server_copy` dispatch and its compensating destination evict |
| `brix_vfs_setxattr()` | XATTR | add mandatory policy gate — today `brix_vfs_xattr_write_gate()` checks capability and credentials only |
| `brix_vfs_removexattr()` | XATTR | add mandatory policy gate — same gate, same omission |
| `brix_vfs_fsetxattr()` | XATTR | non-NULL policy-bearing handle/context required |
| `brix_vfs_fremovexattr()` | XATTR | non-NULL policy-bearing handle/context required |
| `brix_vfs_staged_open()` | OPEN/PUBLISH | gate before temp/backend session |
| `brix_vfs_staged_write()` | WRITE | captured policy check |
| `brix_vfs_staged_commit()` | PUBLISH | captured policy check immediately before publish |
| `brix_vfs_staged_abort()` | lifecycle cleanup | owned-temp cleanup only; no public mutation authority |
| `brix_vfs_writer_open()` | OPEN/PUBLISH | gate before branch/capability selection |
| `brix_vfs_writer_write[_fd]()` | WRITE | captured policy check |
| `brix_vfs_writer_commit[_ex]()` | PUBLISH | captured policy check |
| `brix_vfs_writer_abort()` | lifecycle cleanup | same rule as staged abort |

### E.2 Confinement-only/raw helper APIs

| Current helper | Risk | Required disposition |
|---|---|---|
| `brix_vfs_open_fd()` | raw write flags can bypass endpoint policy | protected export wrapper; raw form internal/service-only |
| `brix_vfs_open_fd_at()` | root handle reopen can request write | protected export wrapper or explicit read-only-only public form |
| `brix_vfs_unlink_at()` | direct export deletion | policy-bearing export form |
| `brix_vfs_unlink_path()` | direct export deletion | policy-bearing export form |
| `brix_vfs_rmdir_path()` | direct export namespace mutation | policy-bearing export form |
| `brix_vfs_mkdir_path()` | direct export namespace mutation | policy-bearing export form |
| `brix_vfs_rename_path()` | direct backend/default rename | policy-bearing export form |
| `brix_vfs_copyfile()` | creates/writes destination | destination operation context required |
| `brix_vfs_copytree()` | recursive destination mutation | destination operation context copied through recursion |
| `brix_vfs_backend_mkpath()` | direct driver mkdir | private beneath protected VFS call |

Read-only forms such as `brix_vfs_walk()` and an `open_fd_at(..., O_RDONLY)`
can remain context-light only if the type/API makes write flags impossible or a
static guard proves all calls read-only. A raw `int flags` API exposed to
protocol code is not such a guarantee.

### E.3 Driver slots which must remain unreachable

Enumerated against `struct brix_sd_driver_s` as it stands on 2026-08-30 — all
54 slots, not the 52 the published matrix censuses. The spy backend must cover
plain and credential-scoped variants of:

| Driver slot group | Mutation |
|---|---|
| `open`, `open_cred` with write flags | create/open/truncate/append |
| `pwrite` | bytes/size/catalog state |
| `copy_range` with a writable destination object | destination bytes |
| `ftruncate`, `truncate_path`, `truncate_path_cred` | object length |
| `fsync` when invoked by client write/sync | durability-side write operation |
| `unlink`, `mkdir`, `rename` and their `_cred` twins | namespace |
| `server_copy`, `server_copy_cred` | published destination object |
| `setattr`, `setattr_cred` | mode/owner/times |
| `setxattr`, `removexattr` and their `_cred` twins | object/protocol metadata |
| `staged_open`, `staged_open_cred` | upload/temp session creation |
| `staged_write` | unpublished bytes |
| `staged_commit` | publication |
| `dedup_publish`, `dedup_gc` | CAS alias publish/reclaim — service-domain today (§3.4); a mutation the moment an instance resolves to the export |
| `recall` when initiated by a mutation request | nearline marker/request creation |

Rows the driver wave made real, and which v2 could not have covered as
implemented behaviour: `server_copy`/`server_copy_cred` (http, remote, xroot,
both decorators), `setattr`/`setattr_cred` (xroot over `kXR_chmod`, ceph, http
as dead properties), `truncate_path_cred`, and the http xattr quartet. Each is a
mutation slot that did not exist to be gated when the ledger was first written.

The ledger is enumerated from `struct brix_sd_driver_s` (54 slots), not from the
52-row published matrix, because `dedup_publish`/`dedup_gc` are in the header and
not in the matrix ([§0.1](#01-the-vtable-is-bigger-and-the-census-is-now-published)).
The spy driver is generated from the header for the same reason: a slot added to
the struct must break the build or the test, never merely go uncounted.

`close`, `staged_abort`, and cleanup slots may run only for resources already
owned by an operation that previously passed policy.

Read slots remain legal and must keep working on a read-only endpoint:
`pread`, `preadv`, `preadv2`, `read_sendfile_fd`, `read_advise`, `fstat`,
`stat`/`stat_cred`, `opendir`/`opendir_cred`, `readdir`, `closedir`,
`getxattr`/`listxattr` and their `_cred` twins, `space`, `query_checksum`,
`enumerate`, `residency`, and `staged_path`. Three of those — `enumerate`,
`residency`, `query_checksum` — are answered by descending the decorator chain
to the backing store, so a read-only endpoint with a cache tier in front must
still reach the leaf for them. The zero-call assertion is about *mutation*
slots; it must not be written as "the leaf was never touched".

### E.4 Protocol-facing mutation producers

The implementation audit must include, at minimum:

- root open-write/create/update/append, write, writev/pgwrite, truncate, sync,
  mkdir, rm/rmdir, mv, chmod, fattr set/delete, prepare write mode, TPC
  destination, clone destination, checkpoint recovery, and bound substreams;
- WebDAV PUT, DELETE, MKCOL, COPY, MOVE, PROPPATCH, LOCK, UNLOCK, ACL/property
  mutation, TPC pull destination, tape mutation endpoints, and recursive
  collection work;
- S3 PutObject, DeleteObject, DeleteObjects, CopyObject, tagging, user metadata,
  multipart create/upload-part/upload-part-copy/complete/abort, conditional
  writes, and async PUT/finalize;
- OCI upload start/chunk/finalize/cancel, blob/manifest/tag/referrer publish or
  delete, local registry GC interactions initiated by a request, and copy;
- GridFTP STOR, STOU, APPE, DELE, MKD/XMKD, RMD/XRMD, RNFR/RNTO, SITE CHMOD,
  REST+STOR, Mode-E stores, and cross-protocol destinations;
- CMS/TPC/backend-async code that opens, renames, removes, or creates beneath an
  export outside the ordinary request handler.

### E.5 Operations explicitly not classified as mutation

- close a read handle;
- abort/release an owned unpublished write resource;
- read, range read, vector read, pgread, checksum;
- stat/statx/space/residency/locate;
- list/readdir/walk/enumerate;
- get/list xattr;
- read-side cache fill into a separate cache root;
- access/error logging and metrics;
- protocol negotiation, authentication, and capability advertisement.

- checksum seeding into the **cache store** after a fill
  (`brix_cstore_seed_checksum`) — a metadata write on a read path, permitted
  only because its target is service-owned storage under §3.4. The test that
  proves it must assert the instance written to is the store, not the export.

If any “read” operation performs opportunistic export cleanup or metadata
refresh, that side effect must be removed, moved to service storage, or gated
as mutation. Calling the outer operation a read is not an exemption, and
"the cache does it" is not either — the seeding case above is legal because of
*where it writes*, not because of what called it.

---

## Appendix F — Protocol-specific behavior matrices

### F.1 XRootD/root plane

| Request class | Read-only wire result | Side-effect assertion |
|---|---|---|
| write/create/update/append open | `kXR_error`, `kXR_fsReadOnly` | no object/temp/parent/open slot |
| write/pgwrite on any handle | `kXR_fsReadOnly` for endpoint policy | no pwrite job/driver call |
| truncate path/handle | `kXR_fsReadOnly` | size and mtime unchanged |
| sync write operation | `kXR_fsReadOnly` | no sync job |
| mkdir/rm/rmdir/mv/chmod | `kXR_fsReadOnly` | namespace/stat digest unchanged |
| fattr set/delete | `kXR_fsReadOnly` | xattrs byte-identical |
| prepare with `kXR_wmode` | `kXR_fsReadOnly` | no stage command/record |
| TPC destination open | `kXR_fsReadOnly` | no destination marker/temp |
| read open/read/pgread/stat/dirlist/checksum | unchanged success/auth behavior | data remains readable |

The canonical numeric result is `kXR_fsReadOnly` (3025 in the existing tests).
Root-specific open error helpers must not translate VFS `EROFS` to
`kXR_IOError`. A stable text such as “this is a read-only server” is retained;
tests should primarily pin the code and side effects, then the stable message
where it is already part of the user contract.

Manager forwarding remains a configuration concern: a manager endpoint which
would forward around local VFS authority must continue to reject incompatible
hard-read-only configuration rather than pretending the local gate protects a
remote write.

### F.2 WebDAV/HTTP plane

| Method/feature | Expected result | Notes |
|---|---:|---|
| PUT | 403 | before body read and `100 Continue` where possible |
| DELETE | 403 | file and collection variants |
| MKCOL | 403 | no parent creation |
| COPY | 403 when destination endpoint is read-only | source may remain readable |
| MOVE | 403 when destination/local endpoint is read-only | no source removal |
| PROPPATCH | 403 | dead/live property storage unchanged |
| LOCK | 403 | no lock xattr/control record |
| UNLOCK | 403 for client mutation | expired-lock read cleanup is not performed inline |
| ACL or mutable property extensions | 403 | even if credential is owner/admin |
| TPC pull into endpoint | 403 | no curl launch, temp, marker, or final file |
| GET/HEAD/PROPFIND/OPTIONS | normal | `Allow`/DAV privileges advertise read-only consistently |

403 is intentional: the method exists but this resource policy forbids the
mutation. 405 would incorrectly say the method is not implemented, and 500
would hide a policy decision as a server fault.

### F.3 S3 plane

| S3 operation | Expected response | Must not occur |
|---|---|---|
| PutObject | 403 S3 error XML | body/stage/open/upload |
| DeleteObject | 403 | deletion/tombstone |
| DeleteObjects | 403 for request | partial batch mutation |
| CopyObject | 403 | destination create/server-copy |
| Put/DeleteObjectTagging | 403 | xattr/object metadata mutation |
| user metadata update | 403 | xattr/header sidecar mutation |
| CreateMultipartUpload | 403 | upload ID/session directory |
| UploadPart/UploadPartCopy | 403 | part/temp/network copy |
| CompleteMultipartUpload | 403 | assembly/final publish |
| AbortMultipartUpload | protocol edge follows existing API contract | if an old owned session exists, cleanup may remove only that unpublished session |
| GET/HEAD/List/GetTagging | normal | read-only operation remains available |

Response shaping stays S3-native: status 403, stable error code selected by the
existing S3 response helper, request identifiers, and XML content type. The VFS
does not generate XML.

Abort deserves an explicit test. A client must not use “abort” to delete a
published object, but the service must be able to clean an upload session
created under an earlier allowed generation. The implementation records this
as owned-session cleanup, not general unlink authority.

### F.4 OCI plane

| OCI request | Expected response | Notes |
|---|---|---|
| mirror PUT/POST/PATCH/DELETE | 403 OCI error response | intrinsic read-only gate |
| registry upload start/chunk/finalize | 403 `DENIED` when endpoint policy read-only | no upload UUID/state |
| manifest/blob/tag/referrer mutation | 403 `DENIED` | no store or index mutation |
| client cancellation of owned unpublished upload | existing cleanup contract | cannot affect published blobs |
| pull, HEAD, catalog/tag/referrer reads | normal | policy does not break pulls |

The mirror and registry may share helpers but must not share mutable policy by
accident. Each effective location binds its own named policy.

### F.5 GridFTP plane

| Verb/family | Expected reply |
|---|---|
| STOR/STOU/APPE including REST/Mode-E | 550 read-only export |
| DELE | 550 |
| MKD/XMKD, RMD/XRMD | 550 |
| RNFR/RNTO | 550 before rename state can authorize mutation |
| SITE CHMOD | 550 |
| RETR/LIST/NLST/MLSD/SIZE/MDTM | existing read behavior |

The existing event and compatibility engines must derive identical VFS policy.
Data-channel setup can occur for read operations; a read-only STOR must not
reach writer creation even if a data channel is already established.

### F.6 Cross-protocol and TPC rules

- destination policy always governs destination mutation;
- source policy does not need mutation authority for a read;
- a writable source cannot make a read-only destination writable;
- a read-only source can feed a writable destination if source auth allows;
- protocol translation cannot convert `EROFS` to retry/nearline status;
- no delegated credential or third-party role bypasses destination policy;
- server-side copy optimization and userspace fallback return the same policy
  result before either begins.

---

## Appendix G — Backend and decorator conformance

### G.1 Registry-driven coverage

The driver census in `src/core/types/fs_list.h` is the source of truth. Tests
must enumerate `BRIX_FS_DRIVER_LIST`, respecting build gates, rather than
maintaining a second handwritten roster. As of 2026-08-30 that census is:

| Kind | Drivers | Build gate |
|---|---|---|
| backend | `posix`, `block`, `mirage` | always |
| origin | `http`, `xroot` | always |
| decorator | `cache`, `stage`, `remote` | always |
| nearline | `frm` | always |
| backend | `ceph`, `cephfs_ro` | `BRIX_HAVE_CEPH` |
| backend | `pblock` | `BRIX_HAVE_SQLITE` |

S3 is not a row: it is reached through `remote`/`http` instances registered by
the live configuration path, so its coverage comes from those drivers plus the
configuration matrix in §9.1.

**One caveat the wave surfaced, and it is exactly the failure mode this section
warns against.** The published slot matrix censuses **11** drivers; the registry
holds **12**. `mirage` is excluded by a hardcoded `order` list in
`tools/diag/sd_slot_matrix.py` — a second hand-maintained roster of the kind
this section forbids. `mirage` is harmless for Phase 105 on the merits: it
declares only `BRIX_SD_CAP_RANGE_READ` and publishes seven slots
(`init`, `open`, `close`, `pread`, `preadv`, `fstat`, `stat`), none of them
mutating, so it is read-only by construction. But a read-only conformance suite
generated from the matrix rather than from `BRIX_FS_DRIVER_LIST` would silently
skip a registered driver, and would keep skipping the next one added the same
way. Phase 105 enumerates from the registry macro and asserts the two rosters
agree.

Worth knowing before choosing where to put the check:
`tools/ci/check_sd_driver_conformance.py` is **already** registry-driven and
already reports `mirage` (as 9 ops — 7 function-pointer slots plus the `name`
and `caps` data fields, the arithmetic the slot matrix documents under "the two
counts that do not match"). The omission is the diagnostic script's, not the
guard's. That makes the guard the right home for the Phase-105 read-only row:
it enumerates correctly today, so the row inherits complete driver coverage
instead of importing the matrix's blind spot.

**A second omission, on the slot axis rather than the driver axis.** The same
matrix censuses 52 slots where `struct brix_sd_driver_s` declares 54:
`dedup_publish` and `dedup_gc` have no row. `dedup_publish` is a namespace
mutation on `posix` (the `/.gcas` hardlink farm), so a spy contract enumerated
from the matrix would be missing a mutation slot. Both verbs currently act on
the cache store — service-owned storage under §3.4 — which is why this is a
coverage gap rather than a live bypass. Phase 105 enumerates mutation slots from
the header and drivers from the registry macro, and asserts both against the
matrix so neither omission can widen unnoticed.

If the registry changes during implementation, the generated conformance
matrix changes in the same review.

### G.2 Spy-driver contract

The spy driver records:

```text
slot name
call count
flags/mutation class
logical path hash or fixed sentinel (test-only, never production metric)
credential-slot versus plain-slot selection
thread identity / enqueue versus execute stage
```

For a read-only mutation, assertions are:

- returned `NGX_ERROR`/failure with `errno == EROFS`;
- every mutating slot count is zero;
- read/stat slot counts are zero unless the public VFS contract explicitly
  requires a read before classifying the request (the preferred design does
  not);
- credential selection count is zero — asserted on **which credential would
  have signed the call**, never on request bytes. The `sd_remote` confused
  deputy the driver wave closed was invisible to a body-diff assertion and
  obvious to a signing-key one;
- decorator counters for invalidate/stage/recall/forward are zero, and
  `brix_sd_cache_evict()`/`brix_metric_cache_evicted` are zero — the
  leaf-dispatch sites compensate by hand, so a rejected request that still
  evicted would be a visible, client-observable side effect;
- no allocation-owned backend object or staged handle remains.

For the writable control, exactly the expected slot is called and existing
result semantics are preserved. This avoids a false-green spy that never
dispatches in either mode.

### G.3 Capability interactions

Policy is evaluated before capability:

| Policy | Backend advertises operation | Result |
|---|---:|---|
| READ_ONLY | yes | `EROFS`; no slot |
| READ_ONLY | no | `EROFS`; capability must not leak |
| ALLOWED | yes | dispatch; backend result |
| ALLOWED | no | existing `ENOTSUP`/fallback behavior |

This ordering prevents a remote observer from fingerprinting backend
capabilities through a read-only endpoint and gives a consistent read-only
result across filesystems.

### G.4 Decorator composition matrix

At minimum exercise:

| Composition | Rejected mutation proof |
|---|---|
| direct POSIX | no syscall/backend slot |
| cache -> source | no invalidation, fill-write, or source mutation |
| stage -> source | no stage temp, recall, flush, or source mutation |
| cache -> stage -> source | neither decorator sees mutation |
| stage -> cache -> source where supported | same result independent of order |
| remote/impersonation -> source | no credential broker, no signing-key selection, no remote call |
| FRM/nearline composition | no marker/recall for write request |
| object/multipart backend | no upload session or multipart call |
| leaf-dispatching mutator behind a cache | no leaf slot **and** no compensating `brix_sd_cache_evict()` |

Composition order is a first-class variable now, not a thoroughness flourish.
`tools/ci/check_sd_driver_conformance.py` enforces **decorator parity**: for the
15-verb namespace/xattr/space base (`stat`, `unlink`, `mkdir`, `rename`,
`setattr`, `truncate_path`, `server_copy`, `space`, `opendir`, `readdir`,
`closedir`, `getxattr`, `listxattr`, `setxattr`, `removexattr`) plus each verb's
`_cred` twin, `cache` and `stage` must publish the same set or the guard fails.
The byte plane is deliberately outside the contract — the cache serves reads
from its store and the stage tier owns writes, so their data slots differ by
design.

That gate exists because the asymmetry was a live defect, not a hypothetical:
`truncate_path` was relayed by `stage` and not by `cache`, so a cache-fronted
`root://` export silently lost path-native truncate. Read-only policy still sits
*above* composition — no decorator gains a `read_only` option or a special
policy slot — but a rejected mutation must now be proved rejected in both
composition orders, because the composition determined behaviour once already.

### G.5 Physical side-effect oracle

For real backends, capture before and after:

- namespace listing;
- object byte digest;
- size, mode, owner, mtime/ctime where stable;
- xattr names and values;
- backend object/catalog count;
- multipart/stage directory entries;
- remote mock request ledger;
- async queue depth;
- cache metadata/invalidation counters.

Normalize timestamps and backend-generated fields carefully. The decisive
assertion is no client-visible or mutation-specific service side effect, not a
byte comparison of unrelated access-time/cache state.

---

## Appendix H — Xattrs, locks, staging, and service-owned state

### H.1 Xattr classification

| Xattr use | Read allowed? | Mutation under READ_ONLY? |
|---|---:|---:|
| root fattr/user xattr | yes | no |
| WebDAV dead property | yes | no |
| WebDAV lock token/state | yes | no |
| S3 tag set | yes | no |
| S3 user metadata | yes | no |
| integrity/checksum metadata stored on export object | yes | no |
| service cache metadata below cache root | yes | outside export policy |

The current “protocol already authorized it” rationale is insufficient. The
VFS must protect against a forgotten protocol gate and against non-protocol
callers.

### H.2 Expired WebDAV locks

Read-time lock discovery can encounter expired state. Under read-only policy:

1. parse and validate the stored lock value;
2. treat an expired lock as absent for request semantics;
3. do not call `removexattr` on the export;
4. optionally record a bounded stale-lock observation;
5. allow a later writable maintenance path to remove it, or migrate lock state
   to a separate control database in a distinct phase.

Malformed lock data follows the existing fail-safe behavior. Phase 105 must not
turn “cannot clean stale lock” into permission to mutate arbitrary metadata.

### H.3 Staging state table

| State | Allowed under a request captured READ_ONLY? |
|---|---:|
| allocate new staging file/session | no |
| write a staging file/session | no |
| complete/publish | no |
| abort a session newly presented by an untrusted client | only after ownership validation |
| close/free memory/fd | yes |
| remove owned unpublished temp created by a previously allowed operation | yes |
| rename temp into export | no unless captured policy was ALLOWED |

Ownership must be unforgeable within the process: a staged handle returned by
the VFS constructor, not a client-provided path plus a cleanup flag.

### H.4 Cache behavior

A read-only endpoint may populate a configured read-through cache because the
export itself is not modified. Tests distinguish:

- allowed: cache miss fetches source bytes into cache root, then serves them;
- forbidden: write request evicts, invalidates, promotes, or writes through;
- forbidden: cache metadata stored as an xattr on the export object changes;
- allowed: access statistics and service cache LRU metadata update in their
  service domain.

### H.5 Journals and control records

Checkpoint, TPC, FRM, and backend async records are classified by purpose:

- a record scheduling or enabling a denied export mutation must not be created;
- a read-only health/observation record is permitted;
- a rollback record for an already-authorized old-generation operation may be
  completed;
- control records must never be used later without the captured operation
  policy and ownership identity.

---

## Appendix I — Async, concurrency, reload, and failure semantics

### I.1 Policy lifetime

| Object | Policy source | Lifetime |
|---|---|---|
| HTTP request VFS context | merged location config | request/pool |
| root session/open handle | merged stream server config | session/handle |
| GridFTP transfer/writer | merged FTP server config | command/transfer |
| staged/writer object | constructor context copy | until commit/abort |
| thread-pool job | enclosing handle/context copy | job completion |
| backend async record | initiating operation copy | drain/completion |
| recursive worker context | destination operation copy | traversal |

No row holds a pointer to `ngx_conf_t`, calls a configuration getter off-thread,
or consults a process-global writable switch.

### I.2 Nginx reload semantics

Expected timeline:

```text
generation A: write enabled, request A1 captures ALLOWED
operator reloads with read_only on
generation B: new requests capture READ_ONLY
old generation A drains; A1 may finish/rollback under ALLOWED
generation B rejects all new mutations before storage
```

This is normal nginx configuration-generation behavior. Phase 105 does not
promise immediate revocation inside a request already admitted by an old
worker. Operator documentation should say “effective for connections/requests
handled by the new configuration generation.”

Tests must avoid pretending `nginx -s reload` instantly changes a long-lived
root session. They open a new session against the new worker and separately
prove the old generation drains safely.

### I.3 Thread-pool and I/O-core rules

- policy validation occurs before posting a mutating job;
- job descriptors carry the immutable policy when the executor itself can
  mutate;
- the worker checks policy before driver/syscall execution;
- a policy failure is completed through the normal async completion path with
  `EROFS`, never by throwing across threads or accessing request objects after
  pool destruction;
- no nginx pool allocation or logging helper unsafe for workers is added to the
  raw policy kernel;
- cancellation can release resources but cannot publish state.

### I.4 Recursive and batch atomicity

Read-only policy is checked before a batch begins, so the expected mutation
count is zero rather than a partial prefix. Defense checks in child operations
remain assertions/security barriers.

If policy is ALLOWED and a backend fails mid-batch, existing partial-result or
rollback semantics remain. Phase 105 does not claim to make non-atomic backend
operations atomic; it guarantees a READ_ONLY failure happens before the first
mutation.

### I.5 Error precedence

For a request already classified as mutation, precedence is:

1. malformed wire framing needed to safely classify the request may return the
   protocol's malformed-request error;
2. base authentication retains each protocol's established challenge and
   information-disclosure order;
3. endpoint read-only returns read-only before fine-grained token/path scope,
   mutation body consumption, and backend capability/credential checks;
4. when endpoint is writable, remaining authz/path errors retain their
   precedence;
5. only an allowed, authorized, confined operation observes backend errors.

Rule 3 now has a named competitor at the same seam. `sd_cred_forward.h` refuses
with `EACCES` when the caller is in deny mode (`cred->fallback_deny`) and the
driver publishes only the plain slot, because running a per-user operation on
the shared service credential is exactly what deny mode forbids. On a read-only
endpoint that check must never be reached:

> **Endpoint read-only (`EROFS`) precedes the deny-mode credential refusal
> (`EACCES`), unconditionally.**

The reason is disclosure, not tidiness. Deny-mode `EACCES` is a statement about
whether *this backend* can assume *this caller's* identity — it distinguishes a
driver with a `_cred` twin from one without (the `id` verdict in the slot
matrix). A read-only endpoint must not answer that question at all; letting the
credential gate run first would let a client fingerprint the backend's identity
plane through an endpoint that was never going to perform the operation.

The same ordering applies to the phase-71 capability gate. On a read-only
endpoint, `BRIX_SD_CAP_XATTR_WRITE` absence must not surface as `ENOTSUP` ahead
of `EROFS`; `vfs_xattr.c` checks capability first today, which is one more
reason the mutation gate has to land ahead of `brix_vfs_xattr_write_gate()`
rather than inside it.

This avoids leaking whether a target exists, which backend is selected, which
capability it supports, or whether it can assume the caller's identity, through
a read-only endpoint.

### I.6 Failure cleanup

On `EROFS`:

- preserve `errno` until the protocol mapper consumes it;
- do not run general “open failed” cleanup that assumes a temp was created;
- close only resources acquired before classification (normally request/socket
  resources);
- do not invalidate cache or negative-stat entries as though a mutation ran;
- do not retry, recall, redirect, or enqueue;
- do not rewrite `EROFS` to `EACCES`, `EIO`, or `ENOTSUP` in an intermediate
  wrapper.

---

## Appendix J — Metrics, logs, and diagnostics

### J.1 Metric contract

Prefer extending existing operation outcome accounting. If a new counter is
necessary, its conceptual schema is:

```text
brix_vfs_mutation_denied_total{
    proto="root|webdav|s3|oci|gridftp|...",
    op="open|write|truncate|sync|mkdir|remove|rename|copy|setattr|xattr|publish",
    reason="read_only"
}
```

Cardinality is bounded by compile-time protocol and operation enums. `reason`
is included only if the family is expected to gain other bounded policy
reasons; otherwise a read-only-specific family is simpler.

Forbidden labels:

- path/object key;
- username, DN, VO, token subject, access key;
- backend host, bucket, pool, or URL;
- arbitrary error string;
- request/session/trace ID.

Those details may belong in properly protected structured logs, not metrics.

### J.2 Edge versus VFS accounting

| Rejection site | Edge counter/log | VFS denial counter/log |
|---|---:|---:|
| normal protocol fast gate | one | zero |
| direct VFS test/defense catch | zero or caller error record | one |
| VFS allows, backend returns native `EROFS` | normal backend error | not counted as endpoint-policy denial |

The last row matters: a physically read-only backend mounted beneath a
writable endpoint can return `EROFS`. It maps correctly to the protocol but is
not evidence that the endpoint policy gate fired. Internal outcome metadata may
distinguish `policy_read_only` from `backend_erofs` without changing wire code.

### J.3 Structured log fields

Suggested bounded fields:

```text
event=vfs_mutation_denied
proto=<bounded>
op=<bounded>
reason=read_only
errno=EROFS
policy_source=endpoint|intrinsic
backend_dispatch=0
```

`policy_source` is optional and bounded. Do not log credentials or request
bodies. Existing safe-path redaction/escaping remains authoritative.

### J.4 Operator diagnostics

Documentation should let an operator distinguish:

- endpoint policy refusal (`read_only`, no backend call);
- per-user authz refusal (`EACCES`/protocol authorization result);
- backend physically read-only (`EROFS` returned after an allowed dispatch);
- backend unsupported mutation (`ENOTSUP`);
- configuration contradiction normalized at startup.

An nginx notice already describes `read_only` overriding `allow_write`; retain
it. Avoid one log per request at notice/error severity for expected read-only
traffic. Access/debug/metric paths are appropriate.

---

## Appendix K — Detailed verification design

### K.1 Test layers

| Layer | Purpose | Must prove |
|---|---|---|
| pure C policy unit | enum/error behavior | fail closed, `EROFS`, no allocation/I/O |
| VFS unit with spy driver | architecture | no mutating slot reached |
| config/parser tests | activation | merge/override/intrinsic policy truth table |
| protocol unit/raw-wire | exact mapping | kXR/HTTP/S3/OCI/FTP response |
| real backend contract | portability | same result across drivers/decorators |
| live end-to-end | side effects | readable controls, unchanged storage |
| static guard tests | future-proofing | new bypass/API fails CI |

### K.2 Proposed test assets

Final names follow the test-suite topology, but this phase should produce
equivalents of:

| Proposed asset | Responsibility |
|---|---|
| `tests/c/test_vfs_mutation_policy.c` | pure enum/context/handle guard battery |
| `tests/c/test_vfs_read_only_spy.c` | counting driver, all mutation slots, credential variants |
| `tests/test_vfs_read_only_contract.py` | compile/run C batteries and assert matrix |
| `tests/test_vfs_read_only_static.py` | public API/caller inventory and fail-closed constructor checks |
| extend `tests/c/test_error_mapping.c` | forward/reverse `EROFS` mapping |
| extend `tests/test_audit15_read_only.py` | HTTP/root configuration override control |
| extend `tests/test_readonly_backend_wire.py` | real backend and wire mappings |
| extend `tests/test_cmd_root_readonly_gateway.py` | complete root opcode surface |
| extend WebDAV lock/dead-prop suites | remove read-time xattr mutation loophole |
| extend `tests/test_s3_multipart.py` | no upload/part/finalize side effects |
| extend OCI registry suites | policy-driven registry denial and mirror control |
| extend GridFTP write-gate suites | VFS writer not reached after 550 |
| extend async/TPC/CMS suites | policy copied and checked across delayed work |

Prefer extending authoritative existing suites over adding duplicate shallow
tests. The spy and static inventory are genuinely new because wire suites
cannot prove a backend call did not occur.

### K.3 Pure policy cases

- every valid enum value;
- invalid negative/out-of-range value;
- zeroed context;
- NULL context;
- read-only context with confined path;
- read-only context with unconfined path (pin chosen validation precedence);
- allowed confined context;
- every operation enum value and `OP_COUNT` rejection;
- `errno` unchanged on success and exact on failure;
- operation-name helper covers every enum value and returns bounded fallback.

### K.4 Spy mutation cases

For each mutation entry point:

1. initialize spy counters;
2. construct valid confined read-only context/handle;
3. call the public VFS mutation API;
4. assert failure and `EROFS`;
5. assert all mutating slot counters zero;
6. assert credential and decorator counters zero;
7. repeat with ALLOWED policy;
8. assert the expected slot exactly once;
9. inject backend failure and assert it propagates only in ALLOWED mode.

Test plain and `_cred` slot resolution. A test that stubs only the plain driver
slot can miss a credential-path bypass.

### K.5 Filesystem side-effect snapshot

Build a fixture containing:

```text
root/
  stable.txt            known bytes/mode/xattrs
  source.txt            copy/move source
  collection/child.txt  recursive target source
service/
  cache/
  stage/
  queue/
```

Snapshot export content with deterministic byte digests, relative names,
types, modes, sizes, and xattrs. Do not include atime. Run the mutation matrix,
then compare the export snapshot byte-for-byte. Separately inspect service
roots for forbidden mutation-specific artifacts while allowing documented
read-cache fill.

### K.6 Remote-origin oracle

A mock backend/origin records method, normalized path, and body byte count.
For read-only mutations the ledger is empty. For the writable control exactly
one expected request appears. Credential headers are never recorded verbatim;
the oracle records only `credential_present=0|1` and proves it remains zero on
policy denial.

### K.7 Protocol triples

Each surface follows the three-test rule:

- **success:** a read works on the read-only endpoint, and a mutation works on
  an otherwise identical writable control;
- **error:** the mutation returns its exact read-only protocol result;
- **security-negative:** valid strongest credentials/write scope still fail,
  storage snapshots remain unchanged, and the backend ledger is empty.

### K.8 Race and delayed-work tests

- queue mutation while ALLOWED, then reload READ_ONLY: old captured work follows
  generation semantics and completes safely;
- create a new request after reload: it is rejected before enqueue;
- cancel a previously allowed staged operation during drain: cleanup succeeds,
  no publish;
- attempt recursive copy with destination read-only and a large source: zero
  children appear;
- use a bound root data stream and writable-looking handle against a read-only
  endpoint: VFS handle gate rejects;
- exercise concurrent read requests while mutations are rejected: reads make
  forward progress and no policy lock serializes the data plane.

### K.9 Performance assertions

The allowed hot path gains one enum comparison and predictable branch at each
mutation boundary. Tests/benchmarks should verify:

- no allocation in policy kernel;
- no lock/global lookup;
- no backend registry lookup before read-only denial;
- no measurable read-path regression because reads do not call the mutation
  observer;
- bounded metric update only on denial, unless existing op accounting already
  occurs.

---

## Appendix L — CI guards and static enforcement

### L.1 Guard objective

The existing VFS seam guard proves handlers do not bypass the VFS. Phase 105
needs the next property:

> A handler may call the VFS, yet still be wrong if it selects a
> confinement-only mutator without carrying endpoint policy.

The mutation guard therefore scans **calls between layers**, not raw syscalls
alone.

### L.2 Forbidden caller patterns

Outside approved VFS/service-domain implementation files, fail on calls to
context-free mutators such as:

- write-capable `brix_vfs_open_fd[_at]`;
- `brix_vfs_unlink_path`, `brix_vfs_unlink_at`, `brix_vfs_rmdir_path`;
- `brix_vfs_mkdir_path`, `brix_vfs_rename_path`;
- `brix_vfs_copyfile`, `brix_vfs_copytree` without destination policy;
- direct mutating `brix_sd_*` dispatch from protocol/TPC/CMS code;
- `brix_vfs_fsetxattr`/`fremovexattr` with NULL policy context;
- assignment to a VFS mutation-policy field outside canonical constructors or
  explicitly listed clone functions.

AST/clang-based checking is preferable for flag-sensitive `open_fd` calls.
Until available, conservative lexical checks plus targeted compile-time API
changes make unsafe calls syntactically difficult.

### L.3 Positive structural checks

The guard/test suite also verifies:

- every `BRIX_FS_DRIVER_LIST` row appears in read-only conformance output —
  all twelve, including `mirage`, which the slot matrix's own roster omits
  (Appendix G.1);
- the slot-matrix roster in `tools/diag/sd_slot_matrix.py` and the registry
  macro agree, so the omission above cannot recur silently;
- the matrix's slot axis and `struct brix_sd_driver_s` agree, or the difference
  is declared — today `dedup_publish`/`dedup_gc` are in the header and not the
  matrix (Appendix G.1);
- every mutating slot named in Appendix E.3 is present in the spy driver, driven
  from the vtable rather than a copied list, so a slot added to
  `struct brix_sd_driver_s` cannot join the tree ungated;
- every VFS function that resolves `brix_vfs_ns_leaf()` for a mutating dispatch
  also runs the policy kernel earlier in the same function, and pairs its leaf
  dispatch with the compensating `brix_sd_cache_evict()`
  ([§0.2](#02-namespace-mutation-now-dispatches-on-the-leaf-not-the-top-driver));
- every mutation operation enum appears in name/metric tables and unit tests;
- every public VFS mutation declaration is in the mutation ledger;
- every context constructor initializes policy;
- every object clone/deep-copy copies policy;
- `brix_kxr_from_errno` includes `EROFS` — as of 2026-08-30 only the reverse
  table in `src/core/compat/error_mapping.c` (line 109) carries the pair;
- no comments still claim export xattr mutations bypass `allow_write`;
- no protocol document claims edge checks are the sole enforcement.

The decorator-parity gate already living in
`tools/ci/check_sd_driver_conformance.py` is the precedent for all of the above:
a structural property of the driver tables, asserted from the source rather than
from a doc, that fails the build when the tables drift apart. Phase 105's checks
belong in the same file for the same reason.

### L.4 Backlog policy

There is no permanent backlog for export mutations. During a wave, a temporary
machine-readable inventory may identify unconverted callers, but:

- its count can only decrease;
- no new entry is accepted;
- Phase 105 cannot close while any entry remains;
- `--regen` cannot be used to bless the current tree after adding a bypass;
- service-domain exclusions identify a typed root/API reason, not a free-form
  file-wide exemption.

### L.5 Guard self-tests

Synthetic fixtures must prove the guard:

- accepts a policy-bearing export call;
- accepts a read-only service-domain operation explicitly in its layer;
- rejects a protocol call to an unguarded unlink;
- rejects NULL-policy fd xattr mutation;
- rejects a new backend/direct-driver mutation call;
- rejects an initializer which omits policy;
- reports file, line, symbol, and remediation without rewriting source;
- scans `src/`, relevant shared server code, and test C helpers used as shipped
  harnesses while excluding generated/build output intentionally.

---

## Appendix M — Function-level delivery manifest

This is the implementation handoff map. Re-run `rg` at each wave and annotate
drift rather than trusting line numbers.

### M.1 Configuration and type work

- [ ] `src/core/config/shared_conf.h` — preserve current normalization and add
      effective-policy derivation at the correct post-merge point.
- [ ] `src/core/config/shared_conf_types.h` — document endpoint intent versus
      VFS policy; do not add redundant mutable flags.
- [ ] root stream shared configuration — use the same conversion.
- [ ] GridFTP merge/context builder — map `allow_write` to typed policy.
- [ ] intrinsically read-only HTTP modes — bind named READ_ONLY.

### M.2 VFS core work

- [ ] `src/fs/vfs/vfs.h` — enum, context field, initializer contract, handle
      documentation.
- [ ] `src/fs/vfs/vfs_internal.h` — replace inline boolean guard with canonical
      policy wrappers.
- [ ] new `vfs_policy.c`/header if needed — policy validation, op names, bounded
      observation; add source to repo-root `config`.
- [ ] `vfs_open_adopt.c` — initializer and all handle adoption policy copies.
- [ ] `vfs_open.c` — common open precheck before parent/cache/backend work.
- [ ] `vfs_open_handle.c` — pwrite handle check.
- [ ] `vfs_sync.c` — handle/path truncate and sync checks.
- [ ] `vfs_mkdir.c` — mkdir/chmod/setattr checks.
- [ ] `vfs_unlink.c` — delete check before traversal/driver.
- [ ] `vfs_rename.c` — rename and raw-path protected form.
- [ ] `vfs_copy.c`, `vfs_walk_copy.c` — destination policy through recursion.
- [ ] `vfs_xattr.c` — gate all mutation variants and remove NULL mutation.
- [ ] `vfs_staged.c`, `vfs_writer.c` — open/write/publish checks and owned abort.
- [ ] `vfs_io_core*` — policy-bearing mutating job contract.
- [ ] `vfs_ops.h` — policy-bearing off-thread/export declarations and restricted
      raw service primitives.

### M.3 Delayed and cross-component work

- [ ] backend async queue enqueue/drain — copied policy and no denied record.
- [ ] TPC engine destination setup/done cleanup — destination policy and owned
      cleanup.
- [ ] CMS forwarding/write open — protected export operation context.
- [ ] root handle table/bound streams — handle policy carried and checked.
- [ ] write-stage/cache decorators — tests prove they are below the gate; no
      policy implementation added to drivers.

### M.4 Root protocol work

- [ ] dispatch write table/global gate remains first.
- [ ] open request and resolved-file contexts use typed policy.
- [ ] root open error mapping handles canonical `EROFS`.
- [ ] common write, mkdir, truncate, move/ext ops bind policy.
- [ ] fattr set/delete no longer rely solely on dispatcher.
- [ ] prepare write-mode and TPC destination stay fail-fast.
- [ ] locate/stat/query advertisement uses the same effective config result.

### M.5 HTTP protocol work

- [ ] WebDAV canonical context builder owns policy binding.
- [ ] remove hand-built WebDAV resource context.
- [ ] PUT/namespace/copy/move/TPC/dead-prop/lock callers use protected VFS APIs.
- [ ] S3 common object/tag/usermeta/copy/delete contexts use typed policy.
- [ ] S3 multipart worker/finalization records carry policy.
- [ ] OCI mirror/registry builders use intrinsic/configured policy correctly.
- [ ] CVMFS/RPM/dig read helpers explicitly use READ_ONLY without gaining
      mutation APIs.

### M.6 Compatibility and documentation work

- [ ] `src/core/compat/error_mapping.c` and C tests — forward/reverse parity.
- [ ] VFS and backend READMEs — final architecture and driver independence.
- [ ] read-only configuration/operator docs — activation and reload behavior.
- [ ] developer guide errno table — `EROFS`, kXR, HTTP.
- [ ] agent guide VFS invariant — policy gate in addition to seam.
- [ ] protocol docs — correct wire results and fast-gate/authority distinction.

### M.7 Build-governance work

- [ ] add every new VFS `.c` file to repo-root `config`.
- [ ] run config coverage guard.
- [ ] keep files below project LoC limit and functions under active CCN,
      Cognitive, NPath, Halstead, and nesting thresholds.
- [ ] no `goto`, no new globals, no raw data syscall outside backend, no helper
      reimplementation.
- [ ] perform incremental build; reconfigure only if source list changes.

---

## Appendix N — Threat model and risk register

### N.1 Assets and security properties

Protected assets:

- export object bytes and lengths;
- namespace topology and names;
- modes, owners, timestamps, xattrs, protocol metadata;
- remote origin/bucket state;
- absence of queued/staged work that can publish later;
- operator expectation that a configured read-only endpoint is non-mutating.

Security property: any request originating from a read-only endpoint generation
has no path to modify those assets, regardless of credentials, protocol,
backend, decorator, handle form, async execution, or error path.

### N.2 Attacker capabilities considered

- sends any supported or malformed protocol opcode/method;
- possesses valid authentication and maximum ordinary write scope;
- controls paths, headers, metadata, multipart state, and request timing;
- uses bound/multiplexed data streams and TPC roles;
- races requests with reload and worker draining;
- selects operations that fall back between native and emulated backend paths;
- triggers errors after partial parsing or setup;
- exploits a future handler which forgets its protocol-edge gate.

The attacker does not control nginx configuration or execute arbitrary code in
the worker; those are different threat classes.

### N.3 Primary bypass threats

| Threat | Mitigation | Proof |
|---|---|---|
| missing protocol gate | VFS authority | direct VFS spy tests |
| hand-built context omits policy | typed initializer, zero=RO, static guard | constructor/guard tests |
| handle write bypass | policy copied into handle and rechecked | pwrite/truncate/sync battery |
| xattr “internal” exception | no export-metadata bypass | lock/tag/fattr tests |
| raw helper bypass | policy-bearing export API + CI guard | synthetic guard + caller inventory |
| async record loses policy | immutable field at enqueue/drain | delayed-work race test |
| recursive child uses weaker policy | destination context copied | zero-child copy test |
| capability fallback changes result | policy before capability | supported/unsupported spy rows |
| credential-scoped slot bypass | policy before credential selection | plain/_cred zero counters |
| decorator side effect before source | policy above composition | decorator ledger |
| leaf dispatch steps past a chain-level gate | policy in the VFS function, before `brix_vfs_ns_leaf()` | per-site zero-call rows for the seven leaf-dispatch mutators |
| compensating cache evict runs for a rejected request | evict is downstream of the gate | `brix_metric_cache_evicted` zero-delta assertion |
| deny-mode `EACCES` discloses the backend identity plane | `EROFS` precedes the credential gate (I.5) | precedence test on a read-only endpoint with a `_cred`-less driver |
| capability `ENOTSUP` precedes `EROFS` on xattr | gate ahead of `brix_vfs_xattr_write_gate()` | `CAP_XATTR_WRITE`-absent driver on a read-only endpoint |
| new vtable slot ships ungated | spy driven from the vtable, not a copied list | guard self-test adding a synthetic mutating slot |
| a registered driver is skipped by the conformance roster | enumerate `BRIX_FS_DRIVER_LIST`, assert roster agreement | `mirage`-shaped omission test (Appendix G.1) |
| reload uses wrong generation | captured policy, no global lookup | two-generation test |
| cleanup becomes delete primitive | owned staged handle only | forged/foreign abort negative |

### N.4 Risk register

| Risk | Impact | Control |
|---|---|---|
| broad initializer migration misses a call site | silent read-only mismatch | compiler-visible signature change plus `rg`/static inventory |
| changing `EACCES` to `EROFS` alters golden wire output | compatibility noise or client behavior | enumerate deliberate changes; canonical protocol tests |
| gating `sync` breaks harmless read-handle sync behavior | avoidable behavior change | classify only protocol/client mutation sync; pin controls |
| WebDAV expired locks accumulate | stale metadata growth | treat expired as absent; writable maintenance/separate store plan |
| abort blocked and leaks multipart state | resource leak | owned-unpublished cleanup exception with ownership tests |
| abort too broad deletes published data | data loss | opaque handle ownership; no path-based bypass |
| old worker continues write after reload | operator surprise | document generation semantics; test drain; optional future revocation out of scope |
| new metric duplicates protocol metric | inaccurate alerts | single rejection ownership table |
| guard regex yields false positives | guard ignored/disabled | API typing first; fixture tests; narrow typed exclusions |
| policy check added below credential/network work | secret/traffic side effect | zero credential/mock-origin counters |
| cache fill mistaken for export mutation | read regression | explicit service-domain classification and cache controls |
| physical backend returns native `EROFS` | policy/backend attribution confusion | separate internal outcome source, same wire mapping |

### N.5 Abuse cases which must remain impossible

- PUT to read-only WebDAV creates parents before returning 403;
- S3 multipart initiation returns an upload ID on a read-only location;
- root fattr changes an xattr because the global dispatcher was bypassed;
- an open read handle is handed to `brix_vfs_file_pwrite` and reaches pblock;
- cross-backend COPY checks source readability but not destination policy;
- async DELETE is accepted while writable, loses policy metadata, and executes
  under an unrelated later context;
- WebDAV GET removes an expired lock xattr from a hard read-only export;
- a write-scoped token or delegated proxy promotes a read-only remote backend;
- backend capability error `ENOTSUP` reveals driver shape instead of `EROFS`;
- an abort request names an arbitrary export object as its “temporary.”

---

## Appendix O — Requirement traceability and evidence ledger

### O.1 Requirement IDs

| ID | Requirement | Primary implementation | Primary evidence |
|---|---|---|---|
| RO-01 | policy derives dynamically from effective endpoint config | shared merge/context builders | config truth-table tests |
| RO-02 | VFS is authoritative | policy kernel + all mutation entry points | spy zero-call suite |
| RO-03 | correct internal error | `errno=EROFS` | pure C policy tests |
| RO-04 | correct protocol errors | canonical mappers and edge shaping | raw-wire matrices |
| RO-05 | all backend filesystems | gate above SD/default POSIX | registry-driven conformance |
| RO-06 | no protocol-only dependence | direct VFS defense tests | bypassed-edge harness |
| RO-07 | handle mutations covered | file policy copy/check | pwrite/truncate/sync tests |
| RO-08 | xattr/metadata covered | xattr and setattr gates | lock/tag/fattr snapshots |
| RO-09 | delayed work covered | queue/job policy copy | race and drain tests |
| RO-10 | no side effects before denial | ordering in open/stage/copy | temp/queue/network ledgers |
| RO-11 | reads remain available | read path unchanged | per-protocol positive controls |
| RO-12 | new bypasses prevented | CI mutation-seam guard | guard fixture tests |
| RO-13 | operator can diagnose denial | bounded metrics/logs | exporter/log tests |
| RO-14 | reload semantics defined | immutable config generation | reload lifecycle test |
| RO-15 | implementation remains maintainable | small policy module/helpers | complexity/LoC gates |
| RO-16 | leaf dispatch cannot outrun the gate | policy kernel above `brix_vfs_ns_leaf()` in every mutator | per-site zero-call rows |
| RO-17 | no compensating cache eviction on denial | evict downstream of the gate | `brix_metric_cache_evicted` zero-delta |
| RO-18 | denial reason precedence is fixed | `EROFS` before deny-mode `EACCES` and capability `ENOTSUP` | precedence tests on `_cred`-less and `CAP_XATTR_WRITE`-less drivers |
| RO-19 | result is composition-order independent | policy above composition | both decorator orders per verb |
| RO-20 | the driver roster cannot silently omit a driver | enumerate `BRIX_FS_DRIVER_LIST` | roster-agreement guard (G.1) |

### O.2 Per-wave evidence template

Each completed checkbox in Section 8 records:

```text
Date:
Commit/working-tree identifier:
Requirement IDs:
Files changed:
Success test command/result:
Error test command/result:
Security-negative command/result:
Backend/decorator rows exercised:
Observed protocol response:
Observed errno:
Backend call count:
Export before/after digest:
Known environment skips (with reason):
Documentation updated:
```

Do not mark a wave complete from code inspection alone. A test skipped because
a backend/runtime is absent is recorded as missing evidence, not a pass for
that backend row.

### O.3 Final command ledger

The implementation should record exact live commands, but the required classes
are:

```text
make -j$(nproc)
objs/nginx -t
PYTHONPATH=tests pytest <focused policy/config/protocol files> -v
python3 tools/ci/check_vfs_seam.py
python3 tools/ci/check_vfs_mutation_gate.py        # if added
python3 tools/ci/check_sd_driver_conformance.py
python3 tools/ci/check_config_coverage.py
python3 tools/ci/check_doc_links.py
<project file-size and complexity gates>
```

Live backend lanes run only where their prerequisites exist, but the spy and
pure policy layers are mandatory and non-skippable on every supported build.

### O.4 Closure report

At phase close, add a compact table to Section 12 with:

- implementation commit(s);
- final policy/API spelling;
- number of VFS mutation entry points covered;
- number of raw callers migrated;
- driver/decorator rows passed;
- protocol suites passed;
- metric/log names actually shipped;
- any deliberate wire-visible compatibility changes;
- zero remaining mutation-seam exceptions.

---

## Appendix P — Normative decisions and deliberately rejected alternatives

### P.1 Decisions fixed by this phase

1. Read-only is VFS policy, not a backend feature.
2. The existing nginx user surface is sufficient; no backend-specific
   read-only directive is added.
3. Both effective `allow_write off` and hard read-only flags select VFS
   READ_ONLY.
4. VFS read-only failure is `EROFS`.
5. Root maps it to `kXR_fsReadOnly`; HTTP-style planes use 403; GridFTP uses
   550.
6. Protocol-edge gates remain as fail-fast mirrors, while VFS is authoritative.
7. Policy is typed, immutable, zero-is-read-only, and copied into delayed
   objects.
8. Export xattrs receive no generic internal bypass.
9. Service-owned state is separated by domain/API, not by a caller-supplied
   “trust me” flag.
10. New backends inherit a registry-driven zero-call test.
11. Nginx reload follows configuration generations rather than retroactive
    cross-worker revocation.
12. No backlog/exceptions remain for export mutation bypasses at phase close.

### P.2 Rejected: storage-driver read-only decorator

Rejected because it is below VFS-side staging, queues, cache invalidation,
credential selection, recursive orchestration, and default POSIX decisions. It
would also have to wrap every composition order and could be accidentally
omitted for a new backend.

### P.3 Rejected: protocol gates only

This is the current incomplete posture. It cannot protect direct VFS callers,
new handlers, handle APIs, async workers, or helper paths when one edge check is
forgotten.

### P.4 Rejected: return `EACCES` for endpoint read-only

`EACCES` conflates endpoint storage posture with identity authorization and
maps root to `kXR_NotAuthorized`. The correct filesystem semantic is `EROFS`,
which already has HTTP 403 and reverse kXR support in the shared mapper.

### P.5 Rejected: optional policy binder after context initialization

An optional second call is easy to omit across the many context construction
sites. Replacing the existing boolean with a typed mandatory argument gives a
compiler-visible migration and makes zeroed state fail closed.

### P.6 Rejected: global mutable read-only switch

It violates nginx configuration inheritance, multi-endpoint isolation,
worker-generation semantics, and the no-new-globals rule. It also introduces
races for delayed work.

### P.7 Rejected: general `internal_metadata=true` bypass

It would immediately recreate the xattr hole and invites future callers to
label client-visible changes “internal.” Separate service roots and opaque
owned cleanup handles provide the required functionality without weakening
the export guarantee.

### P.8 Rejected: policy check only at open/enqueue

Handles and delayed jobs are public internal surfaces and may be called
directly. A cheap second check immediately before mutation provides
defense-in-depth and makes the invariant locally reviewable.

### P.9 Rejected: immediate revocation of old nginx generations

True cross-worker immediate revocation would require shared mutable policy,
handle interruption, and carefully defined in-flight transaction semantics.
That is a separate feature with different operational risks. Phase 105 instead
states and tests ordinary nginx generation capture precisely.

### P.10 Future-compatible extensions

The typed policy can later grow only when a real semantic distinction exists,
for example a maintenance-only mode or immutable-object append policy. Such an
extension must define errno, protocol mapping, ordering, metrics, and full
backend conformance. It must not overload READ_ONLY or add untyped booleans.

Phase 105 intentionally lands the smallest policy algebra that completely
solves the requested guarantee: mutation allowed or export read-only.
