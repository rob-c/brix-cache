# Phase 107 — VFS mutation surface completion: the verbs the layer cannot express

**Date:** 2026-08-30

**Status:** 📋 **PLANNED** — no code written. This document is the specification
the implementation will be judged against.

**Document version:** v3 — v1 planned the eight capability gaps. v2 added a
second part: the five places where BriX-Cache already implements a VFS mutation
concern as an isolated per-feature copy. v3 executes the split v2's §13
recommended. This document keeps the eight capability gaps **plus C9**, the
typed storage domain — cheap, enabling, and belonging with the kernel work. The
four consolidation items moved to
[phase 108](phase-108-vfs-consolidation.md), which depends on the verbs built
here; see [§13](#13-what-moved-to-phase-108).

**Tree inspected:** `480ded2e4` ("close the storage-driver slot wave") plus the
working tree present on 2026-08-30. Every `file:line` below was read on that
tree; re-verify before starting each wave — the slot wave moved several of these
surfaces within the last week and this plan touches the same files.

**Prerequisites — read before costing any wave:**

- [phase 105 — VFS-authoritative read-only mutation gate](phase-105-vfs-read-only-mutation-gate.md),
  which this phase extends rather than revises. Its policy kernel, its
  vocabulary, its `_cred` discipline and its ordering rule (Appendix I.5:
  `EROFS` before every other refusal) are load-bearing here.
- [the storage-driver slot matrix](../09-developer-guide/storage-driver-slot-matrix.md) —
  the census this plan adds rows to, and the source of the per-driver verdicts
  in [Appendix B](#appendix-b--driver-verdicts-for-every-new-slot).
- [phase 55](phase-55-storage-backend-abstraction.md),
  [phase 62](phase-62-vfs-namespace-metadata-seam-closure.md),
  [phase 71](phase-71-vfs-capability-uniformity.md),
  [`src/fs/README.md`](../../src/fs/README.md),
  [`src/fs/backend/README.md`](../../src/fs/backend/README.md).
- The driver-addition checklist at the head of
  [`src/core/types/fs_list.h`](../../src/core/types/fs_list.h) — items 1–8 apply
  to every slot added here, not only to new drivers.

---

## Contents

1. [Outcome](#1-outcome)
2. [The gaps](#2-the-gaps)
3. [Normative model](#3-normative-model)
4. [Per-item design](#4-per-item-design)
5. [Protocol behavior](#5-protocol-behavior)
6. [Backend independence and the census](#6-backend-independence-and-the-census)
7. [Observability](#7-observability)
8. [Implementation waves](#8-implementation-waves)
9. [Test matrix](#9-test-matrix)
10. [Expected file map](#10-expected-file-map)
11. [Compatibility and rollout](#11-compatibility-and-rollout)
12. [Definition of done](#12-definition-of-done)
13. [What moved to phase 108](#13-what-moved-to-phase-108)

Appendices:

- [A. Proposed types and API contracts](#appendix-a--proposed-types-and-api-contracts)
- [B. Driver verdicts for every new slot](#appendix-b--driver-verdicts-for-every-new-slot)
- [C. End-to-end call flows](#appendix-c--end-to-end-call-flows)
- [D. Risk register and deliberately rejected alternatives](#appendix-d--risk-register-and-deliberately-rejected-alternatives)
- [E. CI guards and static enforcement](#appendix-e--ci-guards-and-static-enforcement)
- [F. Requirement traceability](#appendix-f--requirement-traceability)
- [G. The storage-domain table](#appendix-g--the-storage-domain-table)

---

## 0. Where this comes from

Two waves landed back to back. The **storage-driver slot wave** (`480ded2e4`)
closed eleven gaps in the driver vtable and published the census that keeps them
closed. **Phase 105** made "may this endpoint mutate the export?" a typed VFS
property with one kernel and a CI guard.

Both were about the verbs the layer *already had*. Neither asked the next
question: **is the set of mutating verbs the right set?**

It is not. Reading the mutation surface end to end against what the five
protocol planes actually ask of it turns up eight places where the VFS either
cannot express an operation a backend can perform, performs it by a route that
bypasses its own contract, or performs it in a way that is honest only for a
subset of the drivers. None of them is a defect in phase 105 — the gate is
correct over the vocabulary it was given. They are the vocabulary's own edges.

Three of the eight are capability holes a user can hit today with stock clients.
Three are cost or correctness-at-scale problems. Two are contract problems that
have not bitten yet and will.

A ninth item joins them, and it is a different kind of thing: the export/service
split that phase 105 drew in prose is carried through the tree in 117 free-text
`vfs-seam-allow` comments that nothing reads. **C9** turns that line into a type
and makes CI check it. It is here rather than in phase 108 because every verb
below has to say which storage it is touching, and because it is the
prerequisite the consolidation phase opens by verifying.

Reading the same surface from the other direction asks a different question —
where does BriX-Cache already do VFS work *without* the VFS? — and finds an OCI
registry that has privately rebuilt staged publish and atomic tag swap over raw
syscalls, ~25 sites that materialise a secret to disk by hand, an authorization
decision taken at 37 protocol-edge call sites, and a name-translation module
compiled, unit-tested, and called by nothing. That is
[phase 108](phase-108-vfs-consolidation.md). It is sequenced after this one on
purpose: three of its four items consolidate onto verbs this phase builds, so
doing it first would consolidate onto a surface that is about to change.

---

## 1. Outcome

### 1.1 User-visible result

When this phase is done:

- An XRootD client writing with parallel substreams, or a GridFTP client in
  mode E with parallel data streams, **completes a transfer to an `http://` or
  `s3://` backed export**. Today it fails with `ESPIPE` at the first
  out-of-order byte.
- A `PUT` of a 200 GB object through an `http` origin **does not allocate
  200 GB of worker heap**.
- `kXR_prepare` with `kXR_stage` **drives the backend's own recall path** on
  every driver that has one, returns a request id the client can poll, and
  answers `kXR_QPrep` from the backend's residency model. `kXR_prepare` with the
  evict flag **actually evicts**. Neither requires a configured subprocess.
- A staged publish or a rename on a POSIX export **survives a power loss**, not
  just a process crash.
- A recursive `DELETE` of a 10 000-object collection on an S3-backed export
  takes ~10 round trips, not 10 000. An S3 `DeleteObjects` batch is served as a
  batch.
- A client that declares its final size (`oss.asize`, `Content-Length`) gets
  `ENOSPC` **at open**, not at 90 % of a two-hour transfer — and a 5 TB
  multipart upload chooses a legal part size instead of hitting the 10 000-part
  ceiling.
- A conditional publish (`If-Match`, `If-None-Match`, create-if-absent) is
  decided **by the storage that performs the publish**, not by a pre-flight stat
  at the protocol edge that another writer can invalidate before the rename.
- A resource locked over WebDAV **cannot be overwritten over XRootD, GridFTP,
  S3, or OCI**. Today it can, silently.
- The content-dedup plane cannot be pointed at an export root without the VFS
  refusing.

And one thing no user sees, which is the point of C9:

- A `vfs-seam-allow` waiver names a **typed storage domain** the file is
  entitled to touch, and CI checks that claim, instead of accepting any prose
  after the colon.

### 1.2 Non-goals

Named so nobody proposes them in review:

- **`symlink` / `link` creation.** No wire verb in XRootD, WebDAV or S3 asks for
  one, and the entire confinement story — `RESOLVE_IN_ROOT` in
  `vfs_open.c:312`, `lstat`-nofollow in `vfs_walk.c:180` and `vfs_stat.c:273`,
  `brix_unlink_beneath`'s never-follow rule in `namespace_ops.c:132` — exists to
  make an outward link unfollowable. A create-side link verb puts an escape
  primitive *inside* the export and hands the attacker the write half. `readlink`
  on the read side is likewise out: the walk already classifies a symlink as
  `DT_OTHER` and skips it, which is the answer.
- **`setacl` / `getacl`.** Authorization is token, gridmap and VO based; the VFS
  has no ACL type and inventing one to carry POSIX ACLs, S3 ACLs and RFC 3744
  ACEs through the same slot produces a lowest-common-denominator that is wrong
  for all three. If a deployment needs backend ACLs it needs the `_cred` plane,
  which it already has.
- **POSIX advisory locks / leases (`flock`, `OFD` locks).** C7 is about the
  *WebDAV* lock that already exists in the export's own metadata. A general
  cross-protocol lock manager is a different phase with a different state
  problem (SHM registry, crash recovery, lock stealing) and no protocol asking
  for it.
- **Multi-object transactions.** C6 gives per-object preconditions and an atomic
  two-name exchange. It does not give "publish these 400 objects or none",
  which no backend in the roster can honour and which cannot be faked above the
  seam without a write-ahead log the VFS has no business owning.
- **Changing what phase 105 classifies as a mutation.** Appendix E.5 of that
  document stands. This phase *adds* members to the vocabulary; it reclassifies
  nothing that was called a read.

C9 adds one more, which is the obvious over-reach of a typed domain:

- **Migrating operator config files behind the seam.** The CMS blacklist, the
  trust anchors, the CA bundles: read-mostly host configuration. A waiver that
  says "operator config file, not managed storage" is *correct*, and C9 gives it
  a typed name rather than taking it away. The domain is a classification, not a
  relocation plan.

[Phase 108](phase-108-vfs-consolidation.md) §1.2 carries the non-goals that
belong to the consolidation items — notably that authorization does **not** move
off the protocol edge, and that gridmap hot-reload is a configuration concern
rather than a storage one.

---

## 2. The gaps

### 2.1 The capability gaps

Every row's evidence was re-read against the working tree at `480ded2e4`; the
`file:line` anchors below are the exact statements that refuse, discard or
duplicate the behaviour named, not approximate neighbourhoods.

| # | Gap | Primary evidence | Class | Blast radius |
|---|---|---|---|---|
| C1 | Out-of-order writes are refused on every backend without `CAP_RANDOM_WRITE`, and the drivers that lack it buffer the whole object in heap | `vfs_writer.c:176` (`errno = EINVAL`), `sd_http_write.c:166` (`errno = ESPIPE`), `sd_s3_write.c:406,434` (both arms of `sd_s3_check_sequential`) | capability hole | a supported configuration fails outright |
| C2 | Prestage runs as a fork/exec subprocess while a `recall` slot sits implemented and uncalled; evict is a documented no-op | `prepare.c:412,422,428`, `sd.h:435` (`recall`), `sd.h:443` (`residency`), `sd_cache.c:128` (the only caller) | capability hole | one feature, one export class |
| C3 | No publish is durable: nothing fsyncs a parent directory after a rename or a staged commit | `vfs_staged.c:302–390`, `oci_store.c:318`, `webdav/delegation.c:312`, `cred_mint.c` (7 fsyncs, none on a directory) | capability hole | silent data loss on power cut |
| C4 | Every namespace delete is one key per round trip, including a client's own explicit batch request | `vfs_unlink.c:44`, `s3/delete_objects.c:37` (`S3_DEL_MAX_KEYS 1000`), `:67` (`brix_vfs_unlink` per key) | cost at scale | 1 000× amplification on one request |
| C5 | The client's declared final size is validated and discarded; no backend preallocates or sizes its parts from it | `opaque_validate.c:235–240`, `write.c:264`, `sd_remote_write.c:66` (`expected_size = -1`) | cost / correctness | 160 GB ceiling, unnecessary reallocation |
| C6 | The only publish precondition is a boolean `noreplace`, and on `remote` it is an admitted check-then-act race | `vfs_staged.c:369–372`, `sd.h:394` (`staged_commit(..., int noreplace)`), `sd_remote_write.c:148–200` | correctness | lost update between two writers |
| C7 | WebDAV locks are enforced at seven WebDAV call sites and nowhere else; four other write planes ignore them | `lock_check.c:129,267`, the seven callers in §4/C7, `webdav/locks/README.md` | security / correctness | the lock stops one of the deployment's clients |
| C8 | The dedup/CAS plane mutates persistent service state with no gate, no vocabulary entry and no metric | `gcas.c:69` (`dedup_publish`), `gcas.c:91` (`dedup_gc`), phase-105 §0.1 | contract | one directive away from an ungated mutation |

Each is designed in [§4](#4-per-item-design). The rest of this section states
what each one costs, because the cost is what orders the waves in [§8](#8-implementation-waves).

**C1** is the only gap in the list that makes a *supported configuration* fail
outright, and it is refused in three independent places, which is why a
one-line driver fix cannot reach it:

1. `writer_random_backend()` (`vfs_writer.c:48`) selects the in-place handle
   path only for a backend advertising `BRIX_SD_CAP_RANDOM_WRITE`. Everything
   else lands in `writer_put()` (`vfs_writer.c:156`), which compares the
   incoming offset against `w->staged_cursor` and sets `errno = EINVAL`
   (`vfs_writer.c:176`) before any driver is consulted.
2. `sd_http_staged_write` (`sd_http_write.c:162–190`) sets `errno = ESPIPE` on
   the same condition, and grows its heap buffer by doubling from a 1 MiB
   floor — so an out-of-order 10 GB upload would need 10 GB of worker heap even
   if the offset check were removed.
3. `sd_s3_pwrite` gates *both* its multipart arm (`sd_s3_write.c:406`) and its
   single-PUT arm (`:434`) on `sd_s3_check_sequential` (`:300–360`).

The requirement is therefore asserted three times and documented as a
limitation in none of the protocol handlers that can violate it. This matters
because the S3 specification *explicitly permits* uploading multipart parts out
of order, and phase-94's bound-write substreams exist precisely to let an
XRootD client write concurrently. Note that `s3` is not a registered driver —
it is reached through `remote` with `brix_s3_origin_curl_transport` — so the
`sd_s3_*` refusals are what a `remote` export hits.

**C2** costs a whole feature on a whole class of export. The `recall` slot
(`sd.h:435`, `recall(inst, key, char reqid_out[40])`) returns `NGX_AGAIN` plus a
40-byte request id — which is exactly the shape of a `kXR_prepare` response —
and `residency` (`sd.h:443`) is exactly the shape of a `kXR_QPrep` answer. The
only caller of `recall` anywhere in the tree is a cache fill
(`sd_cache.c:128`). Meanwhile the protocol plane hands staging to a subprocess
and answers the two management verbs with nothing: `prepare.c:412` gates on
`kXR_wmode`, `:422` accepts and discards a cancel, `:428` accepts and discards
an evict. Tape staging therefore works only where an operator wired a
`prepare_command` script, and not at all through the drivers that already
implement the two slots it would need.

**C3** is the cheapest item and the one with the worst failure mode. Directory
durability is absent tree-wide, not in one place: `brix_vfs_staged_commit`
(`vfs_staged.c:302–390`) writes the temp, optionally fsyncs *the temp's* fd, and
renames; `brix_oci_store_put_text` (`oci_store.c:279–323`) does not fsync at
all before its rename at `:318`; `webdav/delegation.c` fsyncs the file
(`:303`) and renames (`:312`) without ever flushing the parent. On ext4 with
default `data=ordered` the rename is durable only after the parent directory's
metadata reaches disk, which nothing forces. The observable failure is an
object whose bytes are all present and whose name is gone. `cred_mint.c` is the
counter-example that proves the pattern is reachable — it carries seven fsyncs
— and still flushes no directory.

**C4** is pure round-trip arithmetic, and the protocol plane makes it vivid.
`src/protocols/s3/delete_objects.c` parses a `<Delete>` document that may carry
`S3_DEL_MAX_KEYS` = 1 000 keys (`:37`), then calls `brix_vfs_unlink` once per
key (`s3_delete_one`, `:67`). Over a `remote` backend that is 1 000 signed
HTTPS requests to serve one request whose entire purpose was to avoid exactly
that. The same arithmetic governs a recursive WebDAV `DELETE` and an XRootD
`kXR_rmdir` over a wide collection.

**C5** is a hint the code goes out of its way to validate and then throws away.
`opaque_validate.c:235–240` type-checks `oss.asize` as an unsigned integer;
`write.c:264` notes that the cap is enforced at the write plane "rather than
only trusting the client's `oss.asize` hint at open" — which is correct as a
security posture and is not a reason to discard the hint for capacity planning.
The cost is concrete and computable: `sd_remote_write.c:37` fixes
`SD_REMOTE_PART_SIZE` at 16 MiB, and S3 caps a multipart upload at 10 000
parts, so a `remote` export refuses at **160 GB** — while
`sd_s3_open_write(p, expected_size, part_size, …)` already *accepts* an
expected size and is handed `-1` at `sd_remote_write.c:66`. The plumbing exists;
one caller discards the only input it needs.

**C6** is a race the source already documents. `sd_remote_staged_commit`
(`sd_remote_write.c:148–200`) implements `noreplace` as a HEAD followed by a PUT
and says so in a comment: this is check-then-act, racy against a concurrent
external writer landing the object between the HEAD and the PUT. S3 has
supported conditional writes (`If-None-Match: *`, `If-Match: <etag>`) since
2024 and the fix is one header — but the VFS cannot express the request,
because `staged_commit` takes a boolean (`sd.h:394`) and
`brix_vfs_staged_commit(st, unsigned excl)` (`vfs_staged.c:302`) has nowhere to
put an etag.

**C7** is the security item. The lock record lives as an xattr on the resource
(`WEBDAV_LOCK_XATTR_KEY`), so the state is already in the storage layer, visible
to every protocol that can read an xattr. Only WebDAV reads it, at exactly seven
sites (enumerated in [§4/C7](#c7--locks-in-the-mutation-path)). Its own README
says so: "the `root://` stream protocol and S3 REST surface have no notion of
WebDAV locks." A deployment that serves the same export over `davs://` and
`root://` — the common WLCG shape — has a lock primitive that stops exactly one
of its clients. The expiry sweep is already policy-aware
(`lock.c:176` returns early when
`brix_vfs_policy_from_write_enable(conf->common.allow_write) != BRIX_VFS_MUTATION_ALLOWED`),
which is the shape the enforcement path should have had from the start.

**C8** has not bitten and is one configuration line away from biting.
`brix_cstore_publish_dedup` calls `cs->store->driver->dedup_publish` directly
(`gcas.c:69`) and `brix_gcas_evict_gc` calls `dedup_gc` (`:91`); on POSIX that
materialises and reaps a hardlink in the `/.gcas` farm. Phase 105 §0.1 works out
why this is legal — the target is service-owned storage under its §3.4 — and
then has to write the reasoning down *in prose* because nothing enforces it. The
slots themselves are fully accounted for in
`docs/09-developer-guide/storage-driver-slot-matrix.md`; what is missing is not
the census entry but the gate, the vocabulary member and the metric dimension
that would make an accidental re-pointing of the CAS store at an export
observable rather than silent.

---

### 2.2 The enabling gap

| # | Gap | Primary evidence | Class |
|---|---|---|---|
| C9 | 117 seam waivers carry unvalidated prose where a typed storage domain belongs | `check_vfs_seam.py:212` — `_raw_tier3_violation` returns `None` the moment the substring appears | contract |

**C9** is not a capability hole; it is the reason the other eight cannot say
what storage they are touching. `check_vfs_seam.py`'s `_raw_tier3_violation`
returns `None` the moment the substring `vfs-seam-allow` appears on the line;
nothing parses, validates or cross-references the reason that follows it. The
reasons are nevertheless *good* — they are written by people who knew exactly
which storage they meant — which is precisely the evidence that the domain is
real and is being carried in prose instead of in a type.

The 117 waivers as they stand at `480ded2e4`, by owning area:

| Area | Waivers | Dominant reason cluster |
|---|---|---|
| `src/protocols/oci` | 25 | registry store tree, blob/manifest temps, tag pointers |
| `src/protocols/webdav` | 21 | delegated credential dir, lock sidecars, TPC temps |
| `src/protocols/root` | 17 | staged credential temps, prepare spool |
| `src/fs/cache` | 15 | cache-store staging file, svc-owned domain |
| `src/tpc/outbound` | 6 | transfer temps, delegated proxies |
| `src/net/cms` | 6 | cluster-state spool |
| `src/protocols/cvmfs` | 4 | catalogue/whitelist staging |
| `src/protocols/shared` | 3 | shared temp helpers |
| `src/fs/vfs` | 3 | the layer's own internals |
| `src/core/config` | 3 | trust anchors, operator-supplied files |
| `src/protocols/s3` | 2 | multipart bookkeeping |
| `src/net/proxy` | 2 | GSI PEM temps |
| `src/protocols/gridftp` | 1 | transfer temp |
| `src/fs/backend` | 1 | driver-internal |
| `src/core/aio` | 1 | AIO scratch |

Read down the reason column and six domains fall out — "staged credential
temp" ×10, "cache-store staging file, svc-owned domain" ×9, "cred dir is
svc-owned config" ×6, the registry-store family, the TPC temps, the
config/trust-anchor family. Those six, plus `EXPORT` itself, are exactly the
seven members of `brix_vfs_domain_t` in [§3.7](#37-the-domain-is-a-type-not-a-sentence).
C9 gives the prose a type, an entitlement table, and a runtime assert; the
guard then checks the annotation against the table instead of checking that a
string is present.

C9 is also the prerequisite [phase 108](phase-108-vfs-consolidation.md) opens by
checking: every waiver that phase deletes is one this phase had to annotate
first, and the annotation is what proves the deletion did not change which
storage the call reaches.

---

## 3. Normative model

### 3.1 The vocabulary grows by four

`brix_vfs_mutation_op_t` (`src/fs/vfs/vfs_policy.h`) is append-only by contract
and mirrored in `unified.h` with a compile-time equality check
(`BRIX_VFS_MUTATE_OP_METRIC_COUNT`, currently 11). Phase 107 appends:

| value | covers | introduced by |
|---|---|---|
| `BRIX_VFS_MUTATE_STAGE` | prestage / recall from nearline into the online buffer | C2 |
| `BRIX_VFS_MUTATE_EVICT` | drop an online copy: cache eviction, nearline release | C2 |
| `BRIX_VFS_MUTATE_LOCK` | acquire, refresh or release a resource lock | C7 |
| `BRIX_VFS_MUTATE_DEDUP` | CAS alias publish and alias reap | C8 |

`BRIX_VFS_MUTATE_OP_COUNT` becomes 15 and the metric mirror moves with it, or
the static assert in `vfs_policy.c` fails the build — which is the point of the
assert.

C9 adds no vocabulary: a *domain* (§3.7) is an orthogonal axis, not an
operation. [Phase 108](phase-108-vfs-consolidation.md) appends the sixteenth
member (`CREDENTIAL`, for C11); the mirror moves twice and the assert catches
the second move exactly as it catches the first, which is why the assert is the
mechanism and the number in this paragraph is not.

**Nothing else is reclassified.** C1, C3, C5 and C6 all happen inside operations
the vocabulary already names (`WRITE`, `PUBLISH`, `OPEN`, `RENAME`), and adding
a label for "the durable half of a publish" would split one operator-visible
event into two counters that always move together.

The values are labels for diagnostics and low-cardinality metrics
(INVARIANT #8). As phase 105 states and this phase repeats: they never exempt a
backend, a protocol or a path.

### 3.2 Slots the driver vtable gains

Six new *verbs*, four of which carry a `_cred` twin, which expands to **nine new
members** of `struct brix_sd_driver_s` (`src/fs/backend/sd.h`). All are
**optional**: a NULL slot must leave a working generic path above it, or the
slot does not get added (see [§3.5](#35-fallback-doctrine)).

| # | member | signature | verb | for |
|---|---|---|---|---|
| 1 | `reserve` | `ngx_int_t (*reserve)(brix_sd_obj_t *obj, off_t size)` | reserve | C5 |
| 2 | `unlink_many` | `ngx_int_t (*unlink_many)(brix_sd_instance_t *inst, const char *const *paths, size_t n, int *errs, size_t *done)` | bulk delete | C4 |
| 3 | `unlink_many_cred` | as above `+ const brix_sd_cred_t *cred` | bulk delete | C4 |
| 4 | `recall_cred` | `ngx_int_t (*recall_cred)(brix_sd_instance_t *inst, const char *key, const brix_sd_cred_t *cred, char reqid_out[40])` | stage | C2 |
| 5 | `evict` | `ngx_int_t (*evict)(brix_sd_instance_t *inst, const char *path, uint64_t *bytes_out)` | evict | C2 |
| 6 | `evict_cred` | as above `+ const brix_sd_cred_t *cred` | evict | C2 |
| 7 | `sync_publish` | `ngx_int_t (*sync_publish)(brix_sd_instance_t *inst, const char *path)` | durable publish | C3 |
| 8 | `exchange` | `ngx_int_t (*exchange)(brix_sd_instance_t *inst, const char *a, const char *b)` | atomic exchange | C6 |
| 9 | `exchange_cred` | as above `+ const brix_sd_cred_t *cred` | atomic exchange | C6 |

`recall` itself already exists (`sd.h:435`); only its `_cred` twin is new, which
is why the verb count (six) and the member count (nine) differ. The census
arithmetic in [§6](#6-backend-independence-and-the-census) is 54 + 9 = **63**
slots, not 60.

and one **changed** slot, which is why C6 needs its own wave:

- `staged_commit(brix_sd_staged_t *st, int noreplace)` (`sd.h:394`) becomes
  `staged_commit(brix_sd_staged_t *st, const brix_sd_precond_t *pre)`. This is
  an ABI-visible vtable change: every driver's initialiser and every caller
  moves in one commit, and the tree needs a clean rebuild afterwards, not an
  incremental one — the same discipline a struct-field addition demands.

Full contracts, including per-parameter ownership and the complete errno set for
each, are in [Appendix A](#appendix-a--proposed-types-and-api-contracts);
per-driver verdicts for every cell in
[Appendix B](#appendix-b--driver-verdicts-for-every-new-slot).

Two structural constraints govern where the code lands. First, `sd.h` sits under
a 600-LOC ceiling and has already been split once (`sd_cred_types.h`); the nine
declarations plus `brix_sd_precond_t` will not fit, so the precondition type and
the bulk-delete result vector go in a new `src/fs/backend/sd_batch_types.h`
included from `sd.h`. Second, every new `_cred` twin is a candidate confused
deputy: the slot wave found three, and the rule that came out of it —
**assert on the signing key or connection identity, never on request bytes; a
lazy slot copies the borrowed credential, an eager one may release it** — is a
review gate for members 3, 6 and 9 before they land, not an audit afterwards.
### 3.3 Capability bits

Two new bits in `brix_sd_cap_t` (`sd.h:95`), both used to *decline* work rather
than to enable it:

- `BRIX_SD_CAP_BULK_DELETE` (1u << 17) — the driver's `unlink_many` is a real
  batch, not a loop. The VFS uses this only to choose a window size; a driver
  without it still gets the generic per-key loop.
- `BRIX_SD_CAP_PRECOND` (1u << 18) — the driver evaluates a publish precondition
  **atomically at the storage**. A driver without it may still accept a
  precondition and evaluate it non-atomically, but the VFS marks the result
  advisory and the protocol layer must not claim RFC 7232 semantics for it. This
  bit is the difference between "we checked" and "it cannot have changed".

`CAP_NEARLINE` already gates `recall`; C2 adds no bit for it. Eviction is gated
on the presence of the slot, not a bit, because a cache decorator's eviction and
a nearline driver's release are the same verb with different economics and no
caller needs to tell them apart.

### 3.4 The order every new mutator obeys

Phase 105 fixed an order and caught real defects with it. Every verb this phase
adds obeys the same one, and the tests assert the order, not just the outcome:

1. **Policy** — `brix_vfs_require_confined_mutation()` (or the carried form for
   delayed work). `EROFS`, before anything else, disclosing nothing about the
   gates behind it.
1.5. **Authorization** — reserved. `brix_vfs_require_authorized()` fills this
   position in [phase 108](phase-108-vfs-consolidation.md) (C12): `EACCES`,
   *after* the policy kernel so a read-only endpoint still says only `EROFS`.
   The position is named here so the verbs this phase adds are written against
   the final order rather than retrofitted into it.
2. **Lock** — `brix_vfs_require_unlocked()` (new, C7). `EACCES`-free: the errno
   is `EBUSY`, mapped per plane in [§5](#5-protocol-behavior).
3. **Confinement** — already inside step 1's path form.
4. **Leaf resolution** — `brix_vfs_ns_leaf()`, never before step 1. Phase 105 W2
   lists the four sites where this ordering was the defect.
5. **Capability probe** — `ENOTSUP` only after the endpoint was allowed to ask.
6. **Credential resolution** — and a lazy slot **copies** the borrowed
   credential; an eager one may release it. This is the `_cred` asymmetry the
   slot wave found three times, and every new `_cred` twin in this phase is
   audited against it before it lands, not after.
7. **Backend work.**
8. **Cache invalidation** — `brix_sd_cache_evict()` on success, for any verb
   that dispatches on the leaf and therefore skips the decorator's own
   invalidation. Four such sites existed before the slot wave found them; every
   new leaf-dispatching verb here adds one more and must prove it.

### 3.5 Fallback doctrine

A slot earns its place only when the generic path above it is **wrong**, not
merely slower. The slot matrix legend already draws this line: `seam` means the
generic answer is exact and a slot would save a syscall.

Applied to this phase:

- `unlink_many` on `posix` is `seam` — a local unlink loop makes no round trips.
  It is a real slot on `remote` (one request per 1 000 keys) and on `pblock`
  (one SQLite transaction per window).
- `reserve` is `np` on `http` — there is no HTTP verb that reserves space.
- `exchange` is `np` on everything but `posix` and `pblock`, and the VFS
  **refuses** rather than emulating it. Two renames are not an exchange: they
  have a window in which neither name resolves, and a caller that asked for an
  atomic swap would rather have `ENOTSUP` than that window.
- `sync_publish` is `np` on every remote and object backend: the publish is
  atomic at the far end and there is no local metadata to flush.

Each of those verdicts goes into `tools/diag/sd_slot_matrix.py` as an editorial
verdict for the empty cell, and the drift check fails the day one of them stops
being true.

### 3.6 Export storage versus service storage

Phase 105 §3.4 splits exported storage (gated) from service-owned storage
(cache store, stage tier, journals, temp files — not gated, because the endpoint
never named it). This phase leans on that split three times and hardens it once:

- C1's spill temp is service storage. It must be created **after** the mutation
  gate passes, and reclaimed by the existing owned-temp path.
- C2's evict on a cache-fronted export mutates the *store*, and its refusal must
  still be the *export's* policy — a read-only endpoint may not drive eviction
  of a cache it does not own.
- C3's directory fsync touches the export's own parent directory and is
  therefore gated as part of the publish that earned it.
- C8 turns the §3.4 argument into an assertion: `brix_vfs_service_mutation()`
  refuses with `EINVAL` when the instance handed to it is not a service
  instance.

### 3.7 The domain is a type, not a sentence

Phase 105 drew the export/service line and wrote the reasoning into prose; the
tree then carried that reasoning in 117 free-text `vfs-seam-allow` comments,
because prose was all the seam offered. C9 gives the line a type:

```c
typedef enum {
    BRIX_VFS_DOMAIN_EXPORT = 0,   /* client-named storage — the phase-105 gate */
    BRIX_VFS_DOMAIN_CACHE,        /* cache store: cstore, meta sidecars, verify */
    BRIX_VFS_DOMAIN_STAGE,        /* upload stage dir, TPC transfer temps       */
    BRIX_VFS_DOMAIN_REGISTRY,     /* OCI store tree, tag pointers, indexes      */
    BRIX_VFS_DOMAIN_CREDENTIAL,   /* delegated proxies, minted creds, keytabs   */
    BRIX_VFS_DOMAIN_CONFIG,       /* trust anchors, CA bundles, operator files  */
    BRIX_VFS_DOMAIN_JOURNAL,      /* FRM/stage journals and registries          */
    BRIX_VFS_DOMAIN_COUNT
} brix_vfs_domain_t;
```

`EXPORT` is zero, so a domain that is omitted or zero-initialised is the one the
mutation gate protects — the same fail-closed default as the policy enum, on a
different axis. A helper that means "this is not export storage" must say which
kind of not-export it is, and the value it names is checkable.

Two rules follow, and they are the whole of C9:

1. **A waiver names a domain.** `/* vfs-seam-allow: BRIX_VFS_DOMAIN_CACHE —
   cstore tree */` rather than free prose. The reason text stays; the constant is
   what CI reads.
2. **A file is entitled to a domain, or it is not.** `check_vfs_seam.py` grows a
   file-to-domain map — `src/fs/cache/**` may waive `CACHE`, `src/protocols/oci/**`
   may waive `REGISTRY`, the credential sites may waive `CREDENTIAL` — and a
   waiver naming a domain the file has no entitlement to is a hard failure. A
   `CONFIG` waiver appearing in a data-plane file is exactly the drift the
   current guard cannot see.

The domain does **not** create authority. A `CREDENTIAL`-domain write is not
allowed because it named a domain; it is allowed because it is not export
storage, which is what the domain asserts and what the guard now checks.

---

## 4. Per-item design

### C1 — Out-of-order writes on staged-only backends

**Today.** Three independent refusals, each of which must be satisfied before a
reordered write reaches storage:

```
vfs_writer.c:176        writer_put():  off != w->staged_cursor  -> errno = EINVAL, NGX_ERROR
                                       (the driver is never called)
sd_http_write.c:166     sd_http_staged_write():  (size_t) off != ss->len -> errno = ESPIPE
sd_s3_write.c:406       sd_s3_pwrite() multipart arm:  sd_s3_check_sequential(off, f->mpu_write_off)
sd_s3_write.c:434       sd_s3_pwrite() single-PUT arm: sd_s3_check_sequential(off, f->put_write_off)
```

and two heap problems behind them: `sd_http_staged_write`
(`sd_http_write.c:162–190`) grows a `realloc` buffer by doubling from a 1 MiB
floor up to the whole object size, and the S3 single-PUT arm does the same for
any upload that stays under the multipart threshold. Both are reached through
`remote`, which is the only registered driver that composes
`brix_s3_origin_curl_transport`.

**Which drivers are actually affected.** `BRIX_SD_CAP_RANDOM_WRITE`
(`sd.h:101`, `1u << 2`) is advertised by eight of the twelve drivers —
`posix` (`sd_posix.c:256`), `block` (`sd_block.c:308`), `pblock`
(`sd_pblock.c:247`), `cache` (`sd_cache.c:312`), `stage` (`sd_stage.c:394`),
`frm` (`sd_frm.c:494`), `ceph` (`sd_ceph.c:448`) and `xroot`
(`sd_xroot.c:248`). Of the four that do not, `cephfs_ro` is read-only by
construction and `mirage` is synthetic sizes-only; the gap is therefore exactly
**`http` and `remote`** — which are also the two drivers most likely to sit
under a WAN-facing export.

**Design — one reorder buffer in the VFS, not three in the drivers.**

`brix_vfs_writer_t` gains a third mode alongside `random` and
staged-sequential: **spill**. The writer enters it when the backend has no
`CAP_RANDOM_WRITE` and either the caller declared out-of-order delivery at open
(`BRIX_VFS_WRITER_O_UNORDERED`) or the first write arrives with
`off != staged_cursor`. Entering it on the first violation, rather than only on
the declaration, matters: neither the XRootD write path nor GridFTP mode E knows
at open time whether the client will reorder.

**Writer state machine.** Three states, five transitions, no state is ever
re-entered:

```
                    open on CAP_RANDOM_WRITE backend
   [OPEN] ─────────────────────────────────────────────► [RANDOM]
      │                                                      │ commit -> driver close
      │ open on staged-only backend
      ▼
  [SEQUENTIAL] ──── off == staged_cursor ────► stays SEQUENTIAL, driver staged_write
      │                                                      │ commit -> staged_commit
      │ off != staged_cursor, or O_UNORDERED at open
      │ (T1: spill_enter)
      ▼
   [SPILL] ──── any off, brix_vfs_pwrite_full into the spill temp ──► stays SPILL
      │                                                      │
      │ T2: commit  -> drain spill sequentially into a fresh staged session,
      │               then staged_commit; unlink spill
      │ T3: abort   -> unlink spill, abort staged session
      │ T4: ENOSPC on the spill write, or spill_max exceeded
      ▼
   [FAILED]  (errno = ENOSPC; the staged session is aborted, nothing is published)
```

`SEQUENTIAL → SPILL` is one-way: once a writer has spilled, later in-order
writes still go to the spill, because the spill is now the authority on the
object's contents. `RANDOM → SPILL` never happens — a random-capable backend
has no ordering constraint to violate.

In spill mode the writer:

1. creates a POSIX spill temp under the configured spill root — **service
   storage**, so the `EXPORT`-domain gate has already fired at step 1 of
   [§3.4](#34-the-order-every-new-mutator-obeys) and the spill's own creation
   asserts `BRIX_VFS_DOMAIN_STAGE` under C9,
2. absorbs arbitrary-offset writes with the existing `brix_vfs_pwrite_full()`,
3. at commit, drains the spill sequentially into the driver's staged session
   and commits that,
4. on abort, unlinks the spill and aborts the staged session.

The drain is where the object's real size becomes known, which C5 then uses to
choose an S3 part size — the two items compose, and W2 lands before W4 for that
reason.

**Contract.**

| element | value |
|---|---|
| new open flag | `BRIX_VFS_WRITER_O_UNORDERED` — declares reordering up front; optional, the writer self-promotes without it |
| new writer field | `spill_fd`, `spill_path` (pool-allocated), `spill_bytes`, `mode` |
| `brix_vfs_writer_write` | unchanged signature; `EINVAL` at `vfs_writer.c:176` is replaced by the `spill_enter` transition |
| `ENOSPC` | raised at the moment the writer *enters* spill mode when `spill_max` is already exceeded, and on any short spill write |
| `EROFS` | unchanged — the gate at the writer's `MUTATE_WRITE` call sites (`vfs_writer.c:198,262,331`) still fires first |
| commit ordering | drain → `staged_commit` → `sync_publish` (C3) → unlink spill. The spill is unlinked **after** the publish is durable, so a crash mid-publish leaves the bytes recoverable |

**Why not per-driver.** An S3 multipart part must be uploaded whole and is at
least 5 MiB; an out-of-order stream cannot be turned into parts without
buffering somewhere. Buffering once in the VFS is the honest version. It also
deletes the two heap-growth paths above: `sd_http_staged_write` and the S3
single-PUT arm become spill-backed for any object past a threshold, which is a
memory-safety fix independent of ordering.

**Ceiling, stated up front.** A spill needs local scratch. When it will not fit,
the honest answer is a capacity error at the moment the writer enters spill mode
(`ENOSPC` → `kXR_NoSpace` / `507 Insufficient Storage`), not a slow path and not
a truncated object.

**Configuration.**

| directive | context | argument | default | validated at `nginx -t` |
|---|---|---|---|---|
| `brix_vfs_spill_path` | `http`, `server`, `location` | path | the export's staged temp directory | must be absolute; must not be inside any configured export root (that would make service storage reachable as export storage) |
| `brix_vfs_spill_max` | `http`, `server`, `location` | `size` | `0` (unlimited — the filesystem decides) | `ngx_conf_set_size_slot`; `0` or ≥ 1 MiB |

Both are declared in the `BRIX_TIER_DIRECTIVES` X-macro
(`src/core/config/tier_directives.h`), which is what
`tools/ci/check_directive_registry.py` parses for names, so no second
registration site exists to drift.

`nginx -t` negatives, each its own test:

```
brix_vfs_spill_path relative/path;      -> [emerg] brix_vfs_spill_path must be absolute
brix_vfs_spill_path /srv/export/tmp;    -> [emerg] brix_vfs_spill_path is inside export root "/srv/export"
brix_vfs_spill_max 4k;                  -> [emerg] brix_vfs_spill_max must be 0 or at least 1m
```

**Call sites that change.**

| file:line | change |
|---|---|
| `src/fs/vfs/vfs_writer.c:48` | `writer_random_backend()` unchanged; spill is chosen below it |
| `src/fs/vfs/vfs_writer.c:156–186` | `writer_put()` — the `EINVAL` refusal becomes the `spill_enter` transition |
| `src/fs/vfs/vfs_writer.c:188` | `brix_vfs_writer_write()` — dispatch on `mode` |
| `src/fs/vfs/vfs_writer.c:323` | `brix_vfs_writer_commit_ex()` — drain arm |
| `src/fs/backend/http/sd_http_write.c:162–190` | keep the `ESPIPE` refusal (defence in depth); cap the doubling buffer at the spill threshold |
| `src/fs/backend/s3/sd_s3_write.c:406,434` | unchanged — the VFS no longer presents out-of-order offsets |

`vfs_writer.c` is near the 600-LOC ceiling; the spill mode lands in a new
`src/fs/vfs/vfs_writer_spill.c` with its internals in `vfs_writer_internal.h`,
and both go in the repo-root `./config` source list
(guard `check_config_coverage.py`).

**Gate.** `MUTATE_WRITE`, already carried by the writer
(`vfs_writer.c:198,262,331`). No vocabulary change. The spill temp's own
creation carries `BRIX_VFS_DOMAIN_STAGE` (C9), not `EXPORT`.

**Tests** (`tests/test_vfs_writer_spill.py`, plus the C object unit):

| test | asserts |
|---|---|
| success | 8 MiB written in reverse 1 MiB chunks over a `remote` export lands byte-exact; `md5` matches the in-order upload |
| success | in-order writes never create a spill file (`spill_path` stays empty) |
| error | `brix_vfs_spill_max 1m` + a 4 MiB reordered upload → `ENOSPC`, `kXR_NoSpace` on root, `507` on HTTP, and **no** object published |
| security-negative | a read-only endpoint (`brix_write_enable off`) returns `EROFS` **before** any spill file is created — asserted by `stat`ing the spill root, not only by the errno |
| security-negative | `brix_vfs_spill_path` pointing inside an export root is refused at `nginx -t`, so an export can never be written through the spill door |
### C2 — Prestage and evict as VFS mutations

**Today.** `brix_handle_prepare` (`prepare.c:513`) validates paths, then — if
`kXR_stage` is set and `brix_prepare_command` is configured — forks a subprocess
(`prepare_cmd.c`) and returns. `Cancel/evict options` are handled "as noops"
(`prepare.c:22`). The `recall` slot, live on `pblock`, `frm`, `http`, `remote`
and `xroot`, is called from exactly one place: a cache fill (`sd_cache.c:128`).

**Design.** Two new public verbs, both decorator-descending:

```c
ngx_int_t brix_vfs_recall(brix_vfs_ctx_t *ctx, char reqid_out[40]);
ngx_int_t brix_vfs_evict (brix_vfs_ctx_t *ctx, uint64_t *bytes_out);
```

`brix_vfs_recall` walks `brix_vfs_decorator_source()` to the first implementer,
exactly as `brix_vfs_residency` and `brix_vfs_space` already do — asking a cache
to prestage is asking the wrong instance, and the `walk` verdict in the matrix
exists for this shape. It returns `NGX_AGAIN` with a request id when a recall was
queued or joined, `NGX_OK` when the object was already online, `NGX_ERROR`
otherwise.

`brix_vfs_evict` dispatches on the top of the chain, because eviction is a
question *about the cache*. On a nearline leaf with an `evict` slot it releases
the online buffer copy; on a cache decorator it is today's
`brix_sd_cache_evict()` promoted to a first-class verb with its own gate and
metric.

**Protocol wiring.**

- `kXR_prepare` + `kXR_stage` → `brix_vfs_recall()` per resolved path. The
  returned reqid goes into the existing durable registry
  (`fs/xfer/stage_request_registry.c`), which already owns reqid allocation,
  ownership and the WAL. `brix_prepare_command` stays supported and becomes the
  **fallback** for a driver with no `recall` slot; the config advisor
  (phase 93) grows a note when a nearline export has neither.
- `kXR_QPrep` → `brix_vfs_residency()` for the per-path status line, instead of
  answering from the registry alone. The residency model is the truth; the
  registry is the bookkeeping.
- `kXR_prepare` + evict → `brix_vfs_evict()`, subject to the same ownership rule
  the cancel path already enforces (`prepare.c:119`, FRM-1: only the requester
  that created a record may act on it). An anonymous session must not be able to
  evict another identity's staged object.
- WebDAV/HTTP: no standard verb; out of scope. The S3 plane's storage-class
  transitions are likewise out of scope — they are a lifecycle policy, not a
  request.

**Gate.** `MUTATE_STAGE` and `MUTATE_EVICT`. Both are export mutations by the
plain reading — prestage consumes tape drives and disk buffer, eviction destroys
the online copy — and both are today reachable by a reader on a read-only
endpoint, because phase 105 could only gate the `kXR_wmode` arm of prepare
(§F.1). This closes that.

### C3 — Durable publish barrier

**Today.** No directory is fsynced anywhere in `src/`. `brix_vfs_staged_commit`
renames the temp onto the final path and books the bytes.
`brix_cache_fetch`'s `.part` → final rename (`fetch.c:360`) and
`cred_mint`'s temp + fsync + rename (`cred_mint.c:23`) have the same shape: the
file's contents are made durable, the name is not.

**Design.** A `sync_publish(inst, path)` slot, called after a successful
`staged_commit` and after a successful `rename`, on the leaf, when the export's
namespace is POSIX. The POSIX implementation opens the *parent directory*
through the existing confined-fd machinery — never by re-resolving a path by
name, which would reintroduce a TOCTOU the beneath API exists to close — fsyncs
it and closes.

`np` on every remote and object driver: the publish is atomic at the far end and
there is nothing local to flush. `flat`/`syn` for `block`/`mirage`.

**Directive.** `brix_durable_publish on|off`, default `on`. It is a directive
rather than an unconditional step because a dirfsync per commit is a real cost
on a busy write path, and a cache store whose loss is a re-fetch does not need
it. The default is `on` because the failure it prevents is silent data loss and
the cost is one fsync per *publish*, not per write.

**What is actually testable.** Power-loss testing is out of scope. What the test
matrix pins is: the dirfsync is issued (spy driver counter; syscall assertion in
the POSIX unit test), it is issued exactly once per publish, it is skipped for
non-POSIX namespaces and when the directive is off, and a failure to fsync fails
the publish rather than being swallowed — because a publish that reports success
without durability is the bug this item exists to remove.

### C4 — Bulk namespace delete

**Today.** `brix_vfs_driver_rmtree` (`vfs_unlink.c:44`) walks depth-first and
calls `brix_sd_unlink_maybe_cred` per entry. The S3 protocol's `DeleteObjects`
handler parses a batch and loops the same way.

**Design.** `unlink_many` + `unlink_many_cred`, with per-key error reporting, and
a VFS-level chunker that fills a window (default 1 000, the S3 limit) and
flushes. Two callers: `brix_vfs_driver_rmtree` and a new
`brix_vfs_delete_many()` for the S3 batch endpoint.

**The trap worth writing down.** A tree delete may only batch **within one
directory level** on a driver with `CAP_DIRS` — WebDAV collections are real and
a prefix cannot be removed before its children. On a pure key-prefix store
(`remote`) there are no directories to order against and the whole subtree may
go in one window. Getting this backwards produces a delete that succeeds on S3
and leaves a half-removed tree on a WebDAV origin, which is exactly the class of
bug the decorator-parity gate was added for.

**Verdicts.** `remote` ✅ (`DeleteObjects`, 1 000 keys per signed request);
`pblock` ✅ (one SQLite transaction per window — the win is transaction count,
not round trips); `http` `np` — RFC 4918 has no batch DELETE, and the generic
loop is exact, so the ceiling is the protocol's and it gets recorded as such;
`posix`/`ceph` `seam`; the rest by their standing verdict class.

**Gate.** `MUTATE_REMOVE`, one policy check for the whole batch, one metric
observation per batch with the key count — not one per key, which would blow up
the op counters on a 1 000-key delete.

### C5 — Space reservation

**Today.** `oss.asize` is type-checked (`opaque_validate.c:237`) and dropped.
`write_over_quota` (`write.c:275`) probes usage with a 5-second TTL cache and
fails open by design.

**Design.** A `reserve(obj, size)` slot, called once immediately after a
create-open when the client declared a final size, from whichever edge knows it:
`oss.asize` on the root plane, `Content-Length` on PUT, the `SIZE`/`ALLO`
command on GridFTP.

Per driver:

- `posix` — `posix_fallocate` / `fallocate(FALLOC_FL_KEEP_SIZE)`. Early
  `ENOSPC`, no fragmentation.
- `pblock` — preallocate the block chain and charge the catalog quota exactly,
  replacing a probe that is stale by up to five seconds with a number that is
  correct by construction.
- `remote` — **choose the multipart part size from the declared size.** This is
  the item's sharpest edge: with a fixed default part size, a 5 TB upload
  exceeds S3's 10 000-part limit and fails late. A declared size makes the part
  size arithmetic instead of a guess.
- `xroot` — forward `oss.asize` to the origin's open. The origin speaks the same
  dialect; discarding the hint at the gateway is pure loss.
- `ceph` — `np` (no useful preallocation primitive through librados' C API;
  verify against the real headers, as the Ceph slot work did, not the docs).
- `http` — `np`. No verb.

**Failure semantics.** A `reserve` failure with `ENOSPC` **fails the open**; any
other failure is advisory and logged, never fatal — a backend that cannot
reserve is not a backend that cannot write.

**Gate.** Inside an already-gated `MUTATE_OPEN`. No vocabulary change.

### C6 — Conditional publish and atomic exchange

**Today.** `staged_commit(st, int noreplace)`; `noreplace` becomes
`RENAME_NOREPLACE` on POSIX (`beneath.c:308`) and, on `remote`, a HEAD followed
by a PUT that the source itself documents as racy. At the protocol edge, WebDAV
COPY evaluates `If-Match`/`If-None-Match` in `copy_conditionals()`
(`copy.c:280`) — before the staged temp is even created, so any writer that
lands between the check and the rename wins silently.

**Design, half one: a typed precondition.**

```c
typedef enum {
    BRIX_SD_PRECOND_NONE = 0,      /* replace unconditionally           */
    BRIX_SD_PRECOND_ABSENT,        /* create-if-absent (today's excl)   */
    BRIX_SD_PRECOND_MATCH_ETAG,    /* replace iff the entity tag matches*/
    BRIX_SD_PRECOND_MATCH_META     /* replace iff (size, mtime) matches */
} brix_sd_precond_kind_t;
```

carried in a small struct and passed to `staged_commit` in place of the boolean.
Zero is `NONE`, so a zeroed struct is today's behaviour — the same fail-safe
default discipline as the mutation policy, applied to a different question.

- `remote` — `If-None-Match: *` for ABSENT, `If-Match: <etag>` for MATCH_ETAG,
  on the PUT or the MPU completion. Advertises `CAP_PRECOND`: the decision is
  the storage's and it is atomic. The documented race disappears.
- `http` — RFC 7232 conditional PUT. Advertises `CAP_PRECOND` when the origin
  answers `412` rather than ignoring the header, which is a runtime property; the
  driver probes once at init and records it.
- `posix`, `pblock` — `RENAME_NOREPLACE` for ABSENT (atomic, `CAP_PRECOND`);
  MATCH_* compared under the target parent's fd, which is honest but **not
  atomic** and is reported as advisory. The protocol layer must not return an
  RFC 7232 guarantee it did not get; §5 pins the mapping.

**Design, half two: `exchange`.** `renameat2(RENAME_EXCHANGE)` on `posix`, a
catalog transaction on `pblock`, `ENOTSUP` everywhere else with no emulation
(§3.5). Consumers: CVMFS stratum-0 catalog publishing (phase 96), OCI tag
updates (phase 104), and any publish-new-tree-keep-old flow that today does two
renames and hopes.

**Why this needs its own wave.** Changing `staged_commit`'s signature moves
every driver initialiser and every caller at once, and it is an ABI change to a
struct the whole tree links against: incremental builds will link cleanly and
behave wrongly. The wave ends with a clean rebuild and the ABI note in the
agent guide.

### C7 — Locks in the mutation path

**Today.** The lock record is one xattr on the resource; `webdav_check_locks`
walks from the target up to the export root; `webdav_check_locks_tree` adds the
descendant scan for DELETE/COPY/MOVE. Five call sites, all WebDAV
(`dispatch.c:257`, `namespace.c:267,340`, `methods_proppatch.c:415`,
`copy.c:162`). The subsystem README states the limitation plainly.

**Design.** Hoist the *check* — not the lock state machine, not the parsers —
into the VFS:

```c
ngx_int_t brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx,
                                    brix_vfs_mutation_op_t op);
```

called by every path mutator immediately after
`brix_vfs_require_confined_mutation()`. It reads the same xattr through the same
VFS the rest of the layer uses, walks to the export root, and refuses with
`EBUSY` when a live lock covers the target and the request carries no matching
token.

**Why it is a second function and not part of the kernel.** The phase-105 kernel
is *pure*: no allocation, no I/O, no backend lookup. That purity is what lets it
run before leaf resolution at every call site, and it is worth more than the
convenience of one call. The lock check reads xattrs; it cannot live inside the
kernel, and it must run *after* it so that `EROFS` still precedes every other
refusal (Appendix I.5).

**Token presentation.** A WebDAV client defeats its own lock by presenting the
token in an `If:` header. Other planes have nowhere to put one, so for them a
live lock is an unconditional refusal — which is what a lock is for. The
`brix_vfs_ctx_t` gains an optional borrowed lock-token field that the WebDAV
edge fills and nothing else does.

**Expiry interacts with read-only.** Locks carry an expiry, and
`lock_discovery.c:76` reaps expired records by *removing the xattr* — a
mutation. Phase 105 W3 already removed inline expiry reaping on a read-only
export. So the check must treat an expired lock as **absent without removing
it**: the reap is an optimisation that a writable endpoint may perform and a
read-only one must skip, and correctness cannot depend on it.

**Configuration and rollout.** `brix_lock_enforcement strict|advisory|off`:

- `strict` (default) — a live foreign lock refuses the mutation on every plane.
- `advisory` — refuse on WebDAV as today, log-and-allow elsewhere. One release
  of migration cover for a deployment that discovers stale locks.
- `off` — today's behaviour exactly, for a deployment that has decided its
  locks are WebDAV-only.

The compatibility risk is real and §11 owns it: an export carrying stale
non-expiring locks would start refusing XRootD writes on upgrade. Mitigation is a
`tools/diag` lock scanner that lists live locks per export so an operator can
look before upgrading.

**Wire mapping.** `kXR_FileLocked` (3003, `opcodes.h:152`) already exists and is
the right code — not `kXR_IOError`, and not `kXR_fsReadOnly`, which would tell a
client to stop retrying against a condition that is temporary by construction.

### C8 — The dedup/CAS plane under the gate

**Today.** `gcas.c:69` and `:91` call `dedup_publish` / `dedup_gc` on
`cs->store->driver` directly. Legal under phase 105 §3.4 because the target is
the cache store. Nothing enforces that.

**Design.** Three small pieces:

1. `BRIX_VFS_MUTATE_DEDUP` in the vocabulary, with its metric label.
2. `brix_vfs_service_mutation(brix_sd_instance_t *inst, brix_vfs_mutation_op_t op)`
   — asserts the instance is a service instance (cache store or stage tier),
   refuses with `EINVAL` otherwise, and books the metric. `gcas.c` calls it
   before both slots.
3. `tools/diag/sd_slot_matrix.py` censuses slots **from the header**, not from a
   hand-maintained row list, so `dedup_publish` and `dedup_gc` — the two slots
   the published matrix currently omits, per phase 105 §0.1 — appear with
   verdicts like every other cell, and so does every slot this phase adds,
   automatically.

Item 3 is the durable half. A census that can silently omit a mutation slot is a
census that will omit the next one.

---

---

### C9 — The service-storage domain becomes typed

**Today.** `check_vfs_seam.py:212` — `if "vfs-seam-allow" in line: return None`.
The marker is a substring test. 117 waivers carry reasons that are careful,
consistent, and entirely unread by anything.

**Design.** §3.7's `brix_vfs_domain_t`, plus two mechanical passes:

- **Pass 1 — annotate.** Rewrite all 117 waivers to lead with a domain constant.
  This is a comment-only change with no behavioural content, and it is the
  wave's whole risk profile: a mis-assigned domain in pass 1 becomes a false
  entitlement in pass 2. The reasons already cluster cleanly (§2.2), so the
  mapping is mostly transcription — but "mostly" is why the pass gets reviewed
  as a security change and not as a comment tidy.
- **Pass 2 — enforce.** `check_vfs_seam.py` parses the constant, checks it
  against a file-glob entitlement table, and fails on an unknown domain, a
  missing domain, or a domain the path is not entitled to. The entitlement table
  lives in the guard, is reviewed like an allowlist, and is deliberately coarse:
  directories, not files, so it does not re-break on the next move
  (a content-scanning guard allowlisted by exact path has broken on a file move
  in this tree before; keying on directory prefixes is what stops an archive or
  a shard from invalidating the table).

**Runtime half.** The domain assert (Appendix A.3), which ships in W1 rather
than here because C8 needs it immediately. It takes the domain as an argument
instead of inferring "service or not" from the instance:

```c
ngx_int_t brix_vfs_domain_mutation(const brix_sd_instance_t *inst,
                                   brix_vfs_domain_t domain,
                                   brix_vfs_mutation_op_t op);
```

`EXPORT` routes to the phase-105 kernel. Every other domain asserts the instance
actually belongs to that domain and books the metric. The compile-time half
(the guard) and the runtime half (the assert) check the same claim from two
directions, which is the pattern the mutation gate already uses.

**What this is not.** It is not a permission system. A domain is a statement
about *what the storage is*, not about who may touch it. C9 makes that statement
checkable; it grants nothing.

---

## 5. Protocol behavior

The refusal each plane emits for each new condition. Where a mapping already
exists, it is reused; where one is invented, it is named here so the tests pin
it once.

### 5.1 XRootD / root plane

| Condition | Wire result | Notes |
|---|---|---|
| out-of-order write, spill unavailable | `kXR_NoSpace` | never `kXR_IOError`: the client can retry serially |
| prestage on a read-only endpoint | `kXR_fsReadOnly` | closes the phase-105 §F.1 `kXR_wmode`-only gap |
| prestage, no `recall` slot and no `prepare_command` | `kXR_Unsupported` | today: silent success |
| `kXR_QPrep` | per-path status from residency | unchanged shape |
| evict, not the record's owner | `kXR_NotAuthorized` | mirrors the FRM-1 cancel rule |
| mutation against a live foreign lock | `kXR_FileLocked` (3003) | `strict` mode only |
| `oss.asize` beyond free space | `kXR_NoSpace` at open | today: fails mid-transfer |
| publish precondition failed | `kXR_ItExists` (ABSENT) / `kXR_inProgress`→see §5.5 | MATCH_* has no XRootD analogue; §5.5 |
| exchange on a driver without it | `kXR_Unsupported` | never emulated |

### 5.2 WebDAV / HTTP plane

| Condition | Status |
|---|---|
| live foreign lock | `423 Locked` (unchanged for WebDAV; now also for the other planes' writes to the same resource) |
| precondition failed | `412 Precondition Failed` |
| precondition evaluated non-atomically (no `CAP_PRECOND`) | still `412`/`201`, but the response must not carry a strong-guarantee header the backend did not give |
| spill exhausted | `507 Insufficient Storage` |
| batch delete partial failure | `207 Multi-Status` with per-key results |

### 5.3 S3 plane

| Condition | Error code |
|---|---|
| precondition failed | `PreconditionFailed` (412) |
| live foreign lock | `AccessDenied`-shaped 423 is not S3-legal; use `OperationAborted` (409) |
| batch delete partial | per-key `<Error>` in the existing `DeleteResult` |
| out-of-order parts | now **succeeds** (spill), which is what the S3 spec permits |

### 5.4 OCI and GridFTP planes

OCI: blob upload out-of-order chunks succeed via spill; a manifest push against
a locked tag refuses `DENIED`; tag update uses `exchange` where the backend has
it and a plain rename where it does not, with the difference visible only in
whether a concurrent reader can observe an absent tag.

GridFTP: mode E parallel streams succeed via spill; `ALLO` feeds `reserve`;
`DELE` on a locked resource returns `550` with a lock-specific text; a batch
`DELE` has no protocol form, so C4 reaches GridFTP only through recursive
directory removal.

### 5.5 The one mapping with no good answer

XRootD has no "precondition failed" status. `kXR_ItExists` covers ABSENT
correctly. For MATCH_ETAG there is no code that means "the object changed under
you", and the candidates all mislead: `kXR_IOError` invites a retry loop,
`kXR_NotFound` is false. **Decision:** the root plane does not offer MATCH_*
preconditions. `kXR_open` has no header to carry an entity tag in the first
place, so this costs nothing today; if a future CGI key carries one, the mapping
question comes back and gets answered then rather than being guessed now.

---

## 6. Backend independence and the census

Every slot this phase adds is optional, and every empty cell gets a verdict in
the same pass that adds the slot — not afterwards. The rule from the slot matrix
holds: *a real gap gets closed, not catalogued*, and a verdict that outlives its
gap fails the drift check.

The census itself changes shape (C8, item 3): `tools/diag/sd_slot_matrix.py`
derives its row list from `struct brix_sd_driver_s` instead of a maintained
list. After this phase the matrix is 60 slots × 12 drivers, every slot in the
header appears, and `dedup_publish`/`dedup_gc` stop being invisible.

`check_sd_driver_conformance.py` gains the new slots in its decorator-parity
base — with one deliberate exclusion recorded in the script, not in a comment
here: `sync_publish` is a **leaf** verb (it flushes a real directory), so a
decorator that relays it would fsync the wrong filesystem. It joins `dec`
alongside the byte plane.

---

## 7. Observability

- Four new values on the existing `brix_metric_vfs_mutation_denied` label set.
  No new metric family, no new cardinality: the label vocabulary is bounded and
  the mirror's compile-time assert keeps it that way.
- `brix_vfs_spill_bytes` (counter) and `brix_vfs_spill_active` (gauge) — the
  operator question C1 creates is "how much scratch is this costing me", and it
  has no existing answer.
- `brix_vfs_recall_total{result=queued|online|error}` and
  `brix_vfs_evict_bytes` — prestage and eviction become visible for the first
  time; today a tape recall is a fork with no telemetry at all.
- `brix_vfs_precond_failed_total{kind}` — a rising count is a client with a
  stale entity tag or a genuine write conflict, and distinguishing those two is
  the operator's job, not ours.
- `brix_vfs_lock_refused_total{proto}` — the number that tells an operator
  whether flipping `brix_lock_enforcement` to `strict` will break anything, and
  the reason `advisory` mode exists at all.
- Access log: the batch delete books one line with a key count, not N lines. The
  spill books its high-water mark on the commit line.

C9 adds one label and no metric family:

- The mutation counter gains a `domain` label, bounded to the seven values of
  §3.7. This is the one place a low-cardinality label earns its keep: it turns
  "something wrote outside the export" from an audit question into a graph, and
  it is the signal [phase 108](phase-108-vfs-consolidation.md) measures its
  consolidations against.

---

## 8. Implementation waves

Each wave lands with success, error and security-negative tests (three per
change, per the standing rule). No wave leaves a protocol path depending on an
edge check for a condition the VFS now owns.

### W0 — Freeze the contract with failing tests

- [ ] Pin today's behaviour for every one of the eight: an out-of-order write
      to an `http` export fails with `ESPIPE`; prepare-evict returns success and
      does nothing; no dirfsync is issued on any publish; a 1 000-key
      `DeleteObjects` issues 1 000 backend deletes; `oss.asize` reaches no
      driver; `sd_remote` noreplace is a HEAD then a PUT; an XRootD write
      overwrites a WebDAV-locked file; `gcas` publishes with no gate.
      These tests pass now and must keep passing, inverted, at the end.
- [ ] Extend the spy driver to the six new slots, generated from
      `struct brix_sd_driver_s` so the generation is by construction.
- [ ] Add the ordering assertions (§3.4) as reusable test helpers: policy before
      lock before leaf before capability before credential before backend before
      invalidation.
- [ ] Pin the metric mirror's compile-time assert by adding a member and proving
      the build fails until `unified.h` moves.

### W1 — Vocabulary and kernel extension

- [ ] Append `STAGE`, `EVICT`, `LOCK`, `DEDUP` to `brix_vfs_mutation_op_t`;
      move `BRIX_VFS_MUTATE_OP_METRIC_COUNT` to 15; extend the label table.
      ([Phase 108](phase-108-vfs-consolidation.md) appends `CREDENTIAL` and
      takes it to 16.)
- [ ] Add `brix_vfs_require_unlocked()` next to the kernel — separate function,
      kernel stays pure.
- [ ] Add `brix_vfs_domain_t` (§3.7) and `brix_vfs_domain_mutation()` (A.3) —
      the type is trivial and C8 needs the assert now; W9 is the two passes that
      make the claim checkable. Route `gcas.c` through it (C8, items 1–2).
- [ ] Make `sd_slot_matrix.py` header-derived; regenerate; verdict every newly
      visible cell (C8, item 3).

### W2 — C1 spill writer

- [ ] Add the spill mode to `brix_vfs_writer_t` with entry on declaration or on
      first out-of-order write.
- [ ] Config: `brix_vfs_spill_path`, `brix_vfs_spill_max`; validate at
      `nginx -t` that the path is a real filesystem.
- [ ] Drain-on-commit, unlink-on-abort, and the owned-temp reclaim path.
- [ ] Convert `sd_http_staged_write` and `sd_s3_pwrite_buffered` to spill-backed
      above a threshold — the memory-safety half.
- [ ] `ENOSPC` → `kXR_NoSpace` / 507 mappings.
- [ ] Prove: an out-of-order write sequence over `http` and `remote` produces a
      byte-identical object; the spill is created after the gate, never before.

### W3 — C3 durable publish

- [ ] Add the `sync_publish` slot and the POSIX implementation over a confined
      parent fd.
- [ ] Call it after `staged_commit` and `rename`; propagate failure.
- [ ] `brix_durable_publish` directive, default on.
- [ ] Verdicts for all eleven non-POSIX cells.

### W4 — C5 reserve

- [ ] Add the `reserve` slot; implement on `posix`, `pblock`, `remote`, `xroot`.
- [ ] Plumb `oss.asize` from `opaque_validate` through the open path;
      `Content-Length` on PUT; `ALLO` on GridFTP.
- [ ] `remote`: derive the multipart part size from the declared size and prove
      a >5 TB declared upload picks a legal part count.
- [ ] `ENOSPC` fails the open; every other reserve failure is advisory.

### W5 — C4 bulk delete

- [ ] Add `unlink_many` / `_cred` and `CAP_BULK_DELETE`; implement on `remote`
      and `pblock`.
- [ ] VFS chunker; per-level batching on `CAP_DIRS` drivers (the trap in §C4).
- [ ] Rewire `brix_vfs_driver_rmtree` and the S3 `DeleteObjects` handler.
- [ ] One gate check and one metric observation per batch.

### W6 — C2 prestage and evict

- [ ] `brix_vfs_recall` (decorator-descending) and `brix_vfs_evict`
      (top-dispatching); `recall_cred`; the `evict` slot.
- [ ] Rewire `kXR_prepare` stage/evict/cancel and `kXR_QPrep`; keep
      `prepare_command` as the no-slot fallback; advisor note.
- [ ] Ownership rule on evict, mirroring FRM-1.
- [ ] Metrics for both.

### W7 — C6 preconditions and exchange (ABI wave)

- [ ] Change `staged_commit`'s signature across all twelve drivers and every
      caller in one commit; clean rebuild; ABI note in the agent guide.
- [ ] `CAP_PRECOND`; atomic implementations on `remote` and `http`; advisory on
      `posix`/`pblock` and reported as advisory.
- [ ] `exchange` / `_cred` on `posix` and `pblock`; `ENOTSUP` elsewhere with no
      emulation.
- [ ] Move WebDAV COPY/PUT preconditions from the pre-flight check to the
      commit; keep the edge parse.
- [ ] Root plane declines MATCH_* per §5.5, and the test asserts the decline.

### W8 — C7 lock enforcement

- [ ] Route `brix_vfs_require_unlocked()` into every path mutator, after the
      policy check.
- [ ] Optional borrowed lock-token field on the ctx, filled by the WebDAV edge
      only.
- [ ] Expired-lock-is-absent-without-reaping semantics; prove it on a read-only
      export.
- [ ] `brix_lock_enforcement` directive; per-plane refusal mappings (§5).
- [ ] `tools/diag` lock scanner for the pre-upgrade check.
- [ ] Cross-protocol proof: lock over `davs://`, refuse over `root://`,
      GridFTP, S3 and OCI; unlock; all five succeed.

### W9 — C9 typed storage domains

- [ ] Confirm the W1 assert: `EXPORT` routes to the phase-105 kernel unchanged,
      every other domain refuses an instance that does not belong to it.
- [ ] Pass 1: annotate all 117 waivers with a domain constant. Comment-only,
      reviewed as a security change — a mis-assigned domain here becomes a false
      entitlement in pass 2.
- [ ] Pass 2: `check_vfs_seam.py` parses the constant, enforces a
      directory-prefix entitlement table, and fails on unknown / missing /
      unentitled.
- [ ] Retire the narrow service-mutation assert in favour of the domain form;
      `gcas.c` moves with it.
- [ ] This wave is [phase 108](phase-108-vfs-consolidation.md)'s prerequisite:
      that phase's W0 does not start until the entitlement table is enforcing.

---

## 9. Test matrix

### 9.1 Per-item, three tests minimum

| item | success | error | security-negative |
|---|---|---|---|
| C1 | out-of-order write over `http` + `remote` → byte-identical object | spill root full → `ENOSPC`/507, no partial publish | spill temp not created before the mutation gate passes; read-only endpoint reaches no spill |
| C2 | prestage on `frm`/`xroot` returns a reqid; QPrep tracks residency | no slot, no command → `kXR_Unsupported`, not silent success | prestage and evict refused `kXR_fsReadOnly` on a read-only export; evict refused for a non-owner |
| C3 | dirfsync issued once per publish on POSIX | fsync failure fails the publish | not issued for a service-storage temp; not issued on a refused publish |
| C4 | 1 000-key delete → 1 batch on `remote`, 1 transaction on `pblock` | partial failure reports per-key errno and a correct `done` count | one policy check covers the batch; a read-only endpoint deletes zero keys |
| C5 | `oss.asize` reaches the driver; part size derived on `remote` | oversized declaration → `ENOSPC` at open | a declared size cannot raise a quota or bypass `oss.maxsize` |
| C6 | conditional publish atomic on `remote`/`http`; exchange atomic on `posix` | mismatched etag → 412 / `kXR_ItExists` | a non-`CAP_PRECOND` backend never reports an atomic guarantee; exchange never emulated |
| C7 | locked resource refuses on all five planes; matching token succeeds | expired lock treated as absent on a read-only export, without reaping | a lock cannot be bypassed by choosing a different protocol; token from another lock does not match |
| C8 | `gcas` publish/gc succeed against a store instance | export instance → `EINVAL` | a cache store configured at an export root is refused |
| C9 | every waiver names an entitled domain; guard green | unknown/missing domain → guard fails | a `CONFIG` waiver in a data-plane file fails; a domain constant does not grant access |

### 9.2 Cross-cutting

- **Ordering**: for every new mutator, assert policy → lock → leaf → capability
  → credential → backend → invalidation, with a spy that records the sequence.
  Phase 105 found four defects with exactly this assertion; the new verbs get it
  from the start.
- **Decorator composition**: every new slot exercised through `cache`-over-X and
  `stage`-over-X in both orders. `recall` must descend; `evict` must not;
  `sync_publish` must not be relayed at all.
- **`_cred` twins**: for each new `_cred` slot, assert on the *signing key* or
  the connection identity, never on request bytes — and assert that a lazy slot
  copied the credential rather than borrowing it. This is the confused-deputy
  class the slot wave found three times.
- **Census drift**: `sd_slot_matrix.py` and
  `check_sd_driver_conformance.py` both green, with every new empty cell
  carrying a verdict.
- **Fleet**: the live lanes for root, WebDAV, S3, OCI and GridFTP, each
  exercising the plane's own new refusal.
- **Domain entitlement (C9)**: `check_vfs_seam.py` green over the fully
  annotated tree, plus a negative case per domain — a waiver naming a domain its
  directory has no entitlement to must fail the guard, and a domain constant must
  not be readable as a grant.

---

## 10. Expected file map

New:

```
src/fs/vfs/vfs_spill.c            C1 — reorder buffer for staged-only backends
src/fs/vfs/vfs_lock_gate.c        C7 — brix_vfs_require_unlocked
src/fs/vfs/vfs_recall.c           C2 — brix_vfs_recall / brix_vfs_evict
src/fs/vfs/vfs_bulk.c             C4 — chunker + brix_vfs_delete_many
src/fs/backend/posix/sd_posix_durable.c   C3 — parent-directory flush
tools/diag/brix_lock_scan.py      C7 — pre-upgrade live-lock inventory
src/fs/vfs/vfs_domain.c           C9 — brix_vfs_domain_t + domain assert
```

Modified (non-exhaustive; the ABI wave touches every driver):

```
src/fs/vfs/vfs_policy.h/.c        vocabulary +4, service-mutation assert
src/fs/vfs/vfs_writer.c           spill mode
src/fs/vfs/vfs_staged.c           precondition, durable publish
src/fs/vfs/vfs_rename.c           exchange, durable publish
src/fs/vfs/vfs_unlink.c           bulk path
src/fs/vfs/vfs_open.c             reserve
src/fs/backend/sd.h               6 new slots, 2 caps, precond type
src/fs/backend/*/                 per-driver implementations + verdicts
src/fs/cache/gcas.c               service-mutation assert
src/observability/metrics/unified.h  metric mirror 11 -> 15
src/protocols/root/query/prepare*.c  stage/evict/QPrep rewiring
src/protocols/s3/delete_objects.c    batch path
src/protocols/webdav/copy.c          precondition at commit
tools/ci/check_sd_driver_conformance.py
tools/ci/check_vfs_seam.py           C9 — domain parsing + entitlement table
tools/diag/sd_slot_matrix.py         header-derived census
src/fs/vfs/vfs_deleg*, src/fs/cache/*, src/protocols/oci/*, src/tpc/*
                                     C9 pass 1 — waivers gain a domain constant
config                               new .c files (guard: check_config_coverage.py)
```

Every new `src/` `.c` file goes in the repo-root `./config` and requires a
re-`./configure --add-module=$REPO`; the coverage guard fails the build
otherwise.

---

## 11. Compatibility and rollout

**Behaviour changes visible to a running deployment**, in descending order of
risk:

1. **`brix_lock_enforcement` default `strict` (C7).** An export carrying live
   WebDAV locks starts refusing writes from other planes. This is the intended
   behaviour and it is still a behaviour change on upgrade. Mitigation:
   `tools/diag/brix_lock_scan.py` lists live locks per export; `advisory` mode
   gives one release of log-only cover; the release note leads with this.
2. **`brix_durable_publish` default `on` (C3).** One extra fsync per publish on
   POSIX exports. Measurable on a small-file write workload; the directive turns
   it off.
3. **Prepare stops silently succeeding (C2).** A prepare against an export with
   no recall slot and no `prepare_command` used to return success and do
   nothing; it now returns `kXR_Unsupported`. Anything that treated the old
   success as meaningful was already broken; anything that ignored it is
   unaffected.
4. **Out-of-order writes start succeeding (C1).** Strictly additive: no
   configuration that works today stops working. The new cost is scratch space,
   bounded by `brix_vfs_spill_max`.
5. **`staged_commit` ABI (C6).** Internal; no configuration surface. It does
   require a clean rebuild — an incremental build across this wave links and
   misbehaves.

6. **C9 is invisible at runtime.** Comments plus a guard plus an assert that
   fires only on a mismatch nothing should be producing. It changes no wire
   answer, no directive default and no supported configuration. Its risk is
   entirely in review: a mis-assigned domain in pass 1 becomes a false
   entitlement in pass 2.

**Rollout order** follows the waves: W2–W5 are additive and can ship
independently; W6 changes a protocol answer; W7 is the ABI wave and ships alone;
W8 ships behind its directive, because it is the one that can refuse traffic
that used to be accepted. W9 is independent of all of them and gates the whole
of [phase 108](phase-108-vfs-consolidation.md), so it should not be the wave
that slips.

---

## 12. Definition of done

- [ ] All nine items implemented, or explicitly deferred here with the reason
      and the ceiling recorded.
- [ ] Vocabulary is 15 members; the metric mirror asserts equal at compile time.
- [ ] Every new slot has a verdict in every empty cell, the matrix is
      header-derived, and both census guards are green.
- [ ] The ordering assertion (§3.4) passes for every new mutator.
- [ ] Every new `_cred` twin is audited against the borrow-versus-copy rule and
      asserts on the signing key.
- [ ] `check_vfs_seam.py`, `check_vfs_mutation_gate.py`,
      `check_sd_driver_conformance.py`, `check_config_coverage.py` all green
      with no new backlog entries.
- [ ] `objs/nginx -t` green for every new directive, including the negative
      config cases.
- [ ] The `--pr` tier is green; the five live protocol lanes are green.
- [ ] `src/fs/README.md`, `src/fs/backend/README.md`, the slot matrix, the
      errno→kXR→HTTP table and `agent-guide-extended.md` updated **after** the
      code matches them, never before.
- [ ] An implementation record appended to this document, in the shape phase 105
      used: what the sweep actually found, including the defects only a
      plane-by-plane pass surfaced.

C9 adds:

- [ ] Every `vfs-seam-allow` waiver in the tree names a domain constant, that
      constant is one of the seven, and the file's directory prefix is entitled
      to it.
- [ ] `check_vfs_seam.py` rejects a missing domain, an unknown domain and an
      unentitled domain — with a test per case, because a guard that only
      accepts is not a guard.
- [ ] The waiver **count** is recorded per domain and published in this
      document, as the baseline
      [phase 108](phase-108-vfs-consolidation.md) measures its deletions
      against.

---

## 13. What moved to phase 108

v2 of this document carried a second part: four places where BriX-Cache already
implements a VFS mutation concern as an isolated per-feature copy. They are now
[phase 108 — VFS consolidation](phase-108-vfs-consolidation.md), because the two
halves have different risk profiles, different review audiences and different
definitions of done. This phase is nine items of new capability judged by "does
it work on twelve drivers". That one is four waves of consolidation judged by "is
the shared version at least as strong as every copy it replaced" — a
security-review question, not a capability question. C12 alone touches 37 call
sites across five protocol planes and needs a release in `observe` before it
means anything; bundling that schedule with C1's spill writer helped neither.

| moved item | what it consolidates | needs from this phase |
|---|---|---|
| C10 service publish | the OCI registry's private staged publish, atomic tag swap, CAS probe and index listing | C3 `sync_publish`, C6 `exchange` + precondition, C8 CAS gate, C9 domains |
| C11 credential verb | ~25 hand-rolled secret-file writers in eleven files | C9 domains |
| C12 authz backstop | 37 protocol-edge authorization sites over a rule engine already in `src/fs/path/` | the ordering position §3.4 reserves at 1.5 |
| C13 n2n stage | `site_n2n.c`, compiled and called by nothing, versus `sd_ceph.c`'s partial copy | nothing — independent |

**C9 stayed here.** It is cheap, it is enabling, and it belongs with the kernel
work: the typed domain is what lets any of the verbs above say which storage
they touch. It is also phase 108's stated prerequisite, so it lands on this side
of the seam or that phase does not start.

The evidence that motivates the moved items travels with them — phase 108 §2
carries it in full, because separating the argument from the finding is how a
plan loses the reason it was written.

---

## Appendix A — proposed types and API contracts

Sketches, not final code. Each carries the reasoning that constrains the final
signature; where a decision is still open it is marked and the wave that closes
it is named.

### A.1 Vocabulary extension

```c
/* src/fs/vfs/vfs_policy.h — appended, never reordered */
typedef enum {
    BRIX_VFS_MUTATE_OPEN = 0,
    /* … the eleven phase-105 members, unchanged … */
    BRIX_VFS_MUTATE_PUBLISH,
    BRIX_VFS_MUTATE_STAGE,      /* recall from nearline into the online buffer */
    BRIX_VFS_MUTATE_EVICT,      /* drop an online copy (cache or nearline)     */
    BRIX_VFS_MUTATE_LOCK,       /* acquire/refresh/release a resource lock     */
    BRIX_VFS_MUTATE_DEDUP,      /* CAS alias publish and alias reap            */
    BRIX_VFS_MUTATE_OP_COUNT
} brix_vfs_mutation_op_t;
```

`unified.h`'s `BRIX_VFS_MUTATE_OP_METRIC_COUNT` moves 11 → 15 in the same
commit, or the static assert in `vfs_policy.c` fails the build. The label table
in `brix_vfs_mutation_op_name()` gains `"stage"`, `"evict"`, `"lock"` and
`"dedup"`.

[Phase 108](phase-108-vfs-consolidation.md) appends a sixteenth (`CREDENTIAL`).
The mirror therefore moves twice, and the assert catches the second move exactly
as it catches the first — which is why the assert is the mechanism and the
number in this paragraph is not.

### A.2 The lock gate

```c
/* src/fs/vfs/vfs_lock_gate.c — NOT part of the pure kernel */
ngx_int_t brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx,
                                    brix_vfs_mutation_op_t op);
```

`NGX_OK` when no live foreign lock covers `ctx`'s target, or when the ctx
carries a matching token. `NGX_ERROR` with `errno = EBUSY` when a live foreign
lock covers it; `errno = EINVAL` for a missing or unconfined ctx.

It reads xattrs, so it is impure and cannot join the kernel. It is called
**after** `brix_vfs_require_confined_mutation()` at every site so `EROFS`
continues to precede every other refusal. A lock record whose expiry has passed
is treated as absent and is **not** removed — reaping is itself a mutation and a
read-only endpoint must not perform one (phase-105 W3).

Enforcement mode comes from the export's merged config, not from an argument:
callers must not be able to opt a site out.

### A.3 Domain assert (C8, C9)

```c
/* src/fs/vfs/vfs_domain.c */
ngx_int_t brix_vfs_domain_mutation(const brix_sd_instance_t *inst,
                                   brix_vfs_domain_t domain,
                                   brix_vfs_mutation_op_t op);
```

`EXPORT` delegates to the phase-105 kernel and behaves identically. Any other
domain asserts `inst` belongs to that domain and books one metric sample;
`NGX_ERROR` with `EINVAL` on a mismatch. This turns phase-105 §3.4's paragraph
of reasoning into a runtime refusal.

The narrow form C8 needs on its own — "is this a service instance at all?" — is
this function called with the service domain the caller means, so only the
general one ships. Its first callers are `gcas.c`'s two dedup slots (C8), and
after W9 every service-storage mutator in the tree.

The guard half is not a C API: `check_vfs_seam.py` parses
`/* vfs-seam-allow: BRIX_VFS_DOMAIN_<NAME> — <reason> */`, requires the constant
to be one of the seven, and requires the file's directory prefix to appear
against that domain in [Appendix G](#appendix-g--the-storage-domain-table).
Free-text waivers stop being accepted in the same commit that finishes pass 1,
never before — a half-annotated tree with an enforcing guard is a red build with
no information in it.

### A.4 Reserve

```c
/* src/fs/backend/sd.h — optional slot */
ngx_int_t (*reserve)(brix_sd_obj_t *obj, off_t size);
```

Called at most once per object, immediately after a create-open, only when the
client declared a final size. `NGX_OK` on success; `NGX_ERROR` with `ENOSPC`
when the declaration cannot be satisfied — which **fails the open**; `NGX_ERROR`
with any other errno is advisory and the open proceeds. `size` is the *final*
object size, not a delta.

No `_cred` twin in this phase: reserve runs inside an already-open object, whose
credential the driver holds. Revisit only if a driver appears whose reservation
is a namespace operation.

### A.5 Bulk unlink

```c
ngx_int_t (*unlink_many)(brix_sd_instance_t *inst,
                         const char *const *paths, size_t n,
                         int *errs, size_t *done);
ngx_int_t (*unlink_many_cred)(brix_sd_instance_t *inst,
                              const char *const *paths, size_t n,
                              int *errs, size_t *done,
                              const brix_sd_cred_t *cred);
```

`errs` is caller-allocated with `n` entries; the driver writes `0` for each key
removed and an errno for each that was not, including `ENOENT`. `*done` is the
count actually attempted, which may be less than `n` when the driver stops early
— the caller resumes from `*done`. Return is `NGX_OK` when every key succeeded,
`NGX_ERROR` otherwise, with `errs` carrying the detail: a batch that partially
succeeds is not a batch that failed, and the S3 `DeleteResult` needs the
per-key answer.

The VFS never passes more than the driver's advertised window (default 1 000).
Ordering within a window is unspecified: a caller that needs ordering (a tree
delete on a `CAP_DIRS` backend) batches within one directory level, per §C4.

### A.6 Recall and evict

```c
ngx_int_t (*recall_cred)(brix_sd_instance_t *inst, const char *key,
                         const brix_sd_cred_t *cred, char reqid_out[40]);
ngx_int_t (*evict)(brix_sd_instance_t *inst, const char *path,
                   uint64_t *bytes_out);
ngx_int_t (*evict_cred)(brix_sd_instance_t *inst, const char *path,
                        uint64_t *bytes_out, const brix_sd_cred_t *cred);
```

`recall_cred` matches the existing `recall` (`sd.h:435`) contract exactly —
`NGX_AGAIN` + reqid when queued, `NGX_OK` when already online, `NGX_ERROR`
otherwise. It is a **lazy** slot in the sense that matters: the recall outlives
the request, so it **copies** the credential rather than borrowing it. This is
the `sd_remote` opendir asymmetry, and it is written into the contract here so
the first implementer does not rediscover it.

`evict` writes the reclaimed byte count for the metric and returns `NGX_OK` even
when the object was already absent — an evict is idempotent by nature, and
making "already gone" an error would force every caller to special-case it.

VFS entry points:

```c
/* src/fs/vfs/vfs_recall.c */
ngx_int_t brix_vfs_recall(brix_vfs_ctx_t *ctx, char reqid_out[40]);
ngx_int_t brix_vfs_evict (brix_vfs_ctx_t *ctx, uint64_t *bytes_out);
```

`brix_vfs_recall` descends `brix_vfs_decorator_source()` to the first
implementer — a question about the backing store, like `brix_vfs_residency`
(`vfs.h:431`) and `brix_vfs_space` (`vfs.h:439`) before it. `brix_vfs_evict`
dispatches on the top of the chain, because eviction is a question *about the
decorator*.

### A.7 Durable publish

```c
ngx_int_t (*sync_publish)(brix_sd_instance_t *inst, const char *path);
```

Flush whatever the driver needs so that the **name** at `path` survives a power
loss, given that the object's bytes are already durable. On POSIX that is an
fsync of the parent directory, opened through the confined-fd path — never by
re-resolving a path by name, which would reintroduce the TOCTOU
`brix_*_beneath` exists to close.

Called after a successful `staged_commit` and a successful `rename`, on the leaf
instance, gated by `brix_durable_publish`. A failure fails the publish: a
publish that reports success without durability is the defect this slot exists
to remove.

Never relayed by a decorator (`dec`): a decorator's own directory is not the one
whose entry was published.

### A.8 Preconditions and exchange

```c
typedef enum {
    BRIX_SD_PRECOND_NONE = 0,   /* replace unconditionally                    */
    BRIX_SD_PRECOND_ABSENT,     /* create-if-absent — today's noreplace       */
    BRIX_SD_PRECOND_MATCH_ETAG, /* replace iff the entity tag matches         */
    BRIX_SD_PRECOND_MATCH_META  /* replace iff (size, mtime) match            */
} brix_sd_precond_kind_t;

typedef struct {
    brix_sd_precond_kind_t  kind;
    ngx_str_t               etag;   /* MATCH_ETAG only; borrowed              */
    off_t                   size;   /* MATCH_META only                        */
    time_t                  mtime;  /* MATCH_META only                        */
} brix_sd_precond_t;

/* CHANGED SLOT — ABI-visible */
ngx_int_t (*staged_commit)(brix_sd_staged_t *st,
                           const brix_sd_precond_t *pre);

ngx_int_t (*exchange)(brix_sd_instance_t *inst, const char *a, const char *b);
ngx_int_t (*exchange_cred)(brix_sd_instance_t *inst, const char *a,
                           const char *b, const brix_sd_cred_t *cred);
```

A NULL `pre` and a zeroed `pre` both mean `NONE`, which is today's
`noreplace = 0` — the same fail-safe-zero discipline the mutation policy uses,
applied to a different question. Refusal is `NGX_ERROR` with `EEXIST` for
ABSENT and `ECANCELED` for a failed MATCH_*, distinguishable because the two map
to different protocol answers on three of the five planes.

A driver advertising `BRIX_SD_CAP_PRECOND` evaluates the precondition
**atomically at the storage**. One without it may still evaluate it, and the VFS
marks the result advisory so the protocol layer does not claim an RFC 7232
guarantee the backend did not give.

`exchange` swaps two names atomically. `ENOTSUP` where the backend has no
primitive, **never** emulated with two renames: a caller that asked for an
atomic swap would rather have a refusal than a window in which neither name
resolves.

`exchange` has a `_cred` twin because it is a namespace operation on two paths
that may each need the caller's identity; `sync_publish` does not, because it
flushes a directory the driver already holds open.

### A.9 Writer spill mode

```c
/* src/fs/vfs/vfs_spill.c — internal to the writer */
typedef struct {
    ngx_fd_t   fd;          /* the spill temp                                */
    u_char    *path;        /* owned; unlinked on abort and after drain      */
    off_t      high_water;  /* highest offset+len seen — the object size     */
    off_t      written;     /* bytes actually landed, for the metric         */
} brix_vfs_spill_t;
```

Entered when the backend lacks `CAP_RANDOM_WRITE` **and** either the caller
declared unordered delivery at open or a write arrives with
`off != staged_cursor`. Entering on the first violation and not only on the
declaration is required: neither the XRootD write path nor GridFTP mode E knows
at open time whether the client will reorder.

Created **after** the mutation gate passes (§3.6): a read-only endpoint must
never cause a temp file to exist. Drained sequentially into the driver's staged
session at commit; unlinked on abort; reclaimed by the existing owned-temp path
on connection teardown.

A hole in the spill at drain time — a gap the client never filled — is a client
error, not a zero-fill: the drain refuses and the publish fails, because
silently materialising zeros is how a corrupt object gets a checksum.

---

## Appendix B — driver verdicts for every new slot

Verdicts use the slot-matrix legend. `✅` = implement in this phase; `—` = leave
empty with the stated verdict. `seam` means the generic path above the driver is
exact; `np` means the protocol or API has no such operation.

| driver | `reserve` | `unlink_many` | `recall_cred` | `evict` | `sync_publish` | `exchange` | `CAP_PRECOND` |
|---|---|---|---|---|---|---|---|
| posix | ✅ `fallocate` | — `seam` | — `np` | — `np` | ✅ dirfsync | ✅ `RENAME_EXCHANGE` | ✅ ABSENT only |
| block | — `flat` | — `flat` | — `np` | — `np` | — `flat` | — `flat` | — `flat` |
| http | — `np` | — `np` (no batch DELETE in RFC 4918) | ✅ existing `recall` twin | — `np` | — `np` | — `np` | ✅ probed at init |
| xroot | ✅ forward `oss.asize` | — `np` | ✅ existing `recall` twin | — `np` | — `np` | — `np` | — `np` |
| cache | — `dec` | — `dec` | — `walk` | ✅ promote `cache_evict` | — `dec` | — `dec` | — `dec` |
| stage | — `dec` | — `dec` | — `walk` | ✅ release the staged copy | — `dec` | — `dec` | — `dec` |
| remote | ✅ MPU part sizing | ✅ `DeleteObjects` | ✅ existing `recall` twin | — `np` | — `np` | — `np` | ✅ `If-Match`/`If-None-Match` |
| frm | — `tier` | — `seam` | ✅ existing `recall` twin | ✅ release online copy | — `seam` | — `seam` | — `tier` |
| mirage | — `syn` | — `syn` | — `syn` | — `syn` | — `syn` | — `syn` | — `syn` |
| ceph | — `np` (no C-API primitive) | — `seam` | — `np` | — `np` | — `np` | — `np` | — `cas` |
| cephfs_ro | — `ro` | — `ro` | — `ro` | — `ro` | — `ro` | — `ro` | — `ro` |
| pblock | ✅ chain + quota | ✅ one transaction | ✅ existing `recall` twin | — `np` | — `flat` | ✅ catalog transaction | ✅ `RENAME_NOREPLACE` |

Two verdicts carry a standing obligation:

- **`ceph` `reserve` = `np`** must be verified against the **real librados C
  headers** inside the container image layers, the way the Ceph namespace work
  was — the docs describe C++ APIs the C header does not expose, and this
  verdict is exactly the kind that gets written from documentation and is wrong.
- **`http` `CAP_PRECOND` is a runtime property.** An origin that ignores
  `If-Match` rather than answering `412` must not be advertised as atomic. The
  driver probes once at init and records the answer; a probe that cannot reach
  the origin records "not atomic", because failing closed on a *guarantee* means
  claiming less, not more.

---

## Appendix C — end-to-end call flows

### C.1 An out-of-order XRootD write to an S3-backed export

```
kXR_write(off=8M, len=1M) on a substream
  brix_vfs_write(handle, buf, len, off)
    require_carried_mutation(policy, proto, MUTATE_WRITE)      -- EROFS gate
    writer_random_backend(ctx) == 0                            -- no CAP_RANDOM_WRITE
    off != w->staged_cursor
      -> enter spill mode
         mkstemp under brix_vfs_spill_path                     -- AFTER the gate
      brix_vfs_pwrite_full(spill.fd, buf, len, off)
      spill.high_water = max(high_water, off + len)
...
kXR_close
  brix_vfs_staged_commit(st, pre)
    require_carried_mutation(policy, proto, MUTATE_PUBLISH)
    reserve(obj, spill.high_water)                             -- C5: pick part size
    drain: for each 8 MiB chunk in order
             sd_remote_staged_write(st, chunk, len, cursor)    -- now sequential
    driver->staged_commit(st, pre)                             -- C6: If-None-Match
    unlink(spill.path)
```

The two items compose: the spill is what makes the final size known before the
first part is uploaded, and the final size is what makes the part size legal.

### C.2 `kXR_prepare` with `kXR_stage` against a tape-backed export

```
brix_handle_prepare
  for each resolved path:
    brix_vfs_recall(ctx, reqid)
      require_confined_mutation(ctx, MUTATE_STAGE)             -- EROFS gate (NEW)
      require_unlocked(ctx, MUTATE_STAGE)                      -- C7
      inst = decorator_source(ctx->sd)                         -- walk to the leaf
      cap & CAP_NEARLINE ? : ENOTSUP
      cred = resolve(...); COPY into the recall job            -- lazy slot
      driver->recall_cred(inst, key, cred, reqid)  -> NGX_AGAIN
    stage_request_registry_record(reqid, requester)            -- existing WAL
  respond with the registry's reqid

kXR_QPrep
  brix_vfs_residency(ctx, &out)                                -- the truth
  registry lookup                                              -- the bookkeeping
```

`prepare_command` is reached only when the leaf has no `recall` slot, which the
config advisor reports at `nginx -t` time rather than at first prestage.

### C.3 A recursive DELETE of an S3-backed collection

```
brix_vfs_delete(ctx)                    require_confined_mutation(MUTATE_REMOVE)
                                        require_unlocked(ctx, MUTATE_REMOVE)
  brix_vfs_delete_via_driver
    leaf = brix_vfs_ns_leaf(ctx->sd)    -- AFTER the gate
    cred = resolve(...)
    brix_vfs_driver_rmtree(leaf, cred)
      walk depth-first, filling a 1000-key window
        leaf has CAP_DIRS ?  flush at each directory boundary
                          :  flush whenever the window is full
        driver->unlink_many_cred(inst, keys, n, errs, &done, cred)
      one metric observation, key count as the value
    brix_sd_cache_evict(ctx->sd, logical)   -- leaf dispatch skipped the decorator
```

The `CAP_DIRS` branch is the whole correctness content of C4: batching across a
directory boundary on a backend with real collections removes a parent before
its children.

### C.4 A locked resource written over `root://`

```
kXR_open(O_WRONLY) on /export/data/run42.root
  brix_vfs_open(ctx, flags)
    require_confined_mutation(ctx, MUTATE_OPEN)     -- EROFS first, always
    require_unlocked(ctx, MUTATE_OPEN)
      walk target -> export root, reading WEBDAV_LOCK_XATTR_KEY
      found: live, depth-0, owner = another principal
      ctx->lock_token == NULL                       -- root plane carries none
      -> NGX_ERROR, errno = EBUSY
    map: EBUSY -> kXR_FileLocked (3003)
```

The same lock refuses the same write over GridFTP (`550`), S3 (`409
OperationAborted`), OCI (`DENIED`) and WebDAV-without-token (`423`). A WebDAV
client presenting the token in an `If:` header proceeds, because that is what
holding a lock means.

---

## Appendix D — risk register and deliberately rejected alternatives

### D.1 Risks

| risk | item | mitigation |
|---|---|---|
| Strict lock enforcement refuses traffic that worked yesterday | C7 | `advisory` mode for one release; `brix_lock_scan.py` before upgrade; the release note leads with it |
| Spill scratch exhausts a small local filesystem under concurrent uploads | C1 | `brix_vfs_spill_max`; `ENOSPC` at spill entry, not mid-object; spill gauge and high-water metric |
| The ABI change to `staged_commit` links cleanly against a stale object file and misbehaves | C6 | the wave ships alone and ends with a clean rebuild; the ABI note joins the struct-field rule in the agent guide |
| Advisory preconditions get reported as atomic | C6 | `CAP_PRECOND` is the only thing the protocol layer may consult; a test asserts a non-`CAP_PRECOND` driver never yields a strong-guarantee response |
| Batch delete removes a parent before its children on a WebDAV origin | C4 | per-directory-level batching on `CAP_DIRS`; a fleet test against a real WebDAV origin, not a mock |
| A dirfsync per publish regresses a small-file write workload | C3 | `brix_durable_publish off`; benchmark in the wave's exit criteria |
| Prestage now consumes tape drives on behalf of an unauthenticated reader | C2 | `MUTATE_STAGE` is gated like any mutation, which is the change; FRM-1 ownership on evict and cancel |
| A recall job outlives the request and uses a freed credential | C2 | the contract in A.6 requires a copy; the `_cred` audit is a wave exit criterion, not a review comment |
| Four new vocabulary members drift from the metric mirror | W1 | the existing compile-time assert already fails the build; W0 proves it does |
| A typed domain is read as a grant rather than a classification | C9 | §3.7 states it explicitly; the negative test asserts a domain constant confers no access; the runtime assert only ever *refuses* |
| A mis-assigned domain in W9 pass 1 becomes a false entitlement in pass 2 | C9 | pass 1 is reviewed as a security change, not a comment tidy; the entitlement table is coarse and reviewed like an allowlist |

### D.2 Rejected alternatives

**Per-driver reorder buffers instead of one VFS spill (C1).** Rejected: it
duplicates the same buffer in `http`, `remote` and every future staged-only
driver, and it leaves the existing whole-object heap growth in place. One spill
above the seam fixes ordering and memory together.

**Zero-filling spill holes at drain (C1).** Rejected: a client that never sent a
range asked for an object it did not describe. Materialising zeros produces a
plausible object with a wrong checksum, which is worse than a failed publish.

**Emulating `exchange` with two renames (C6).** Rejected in §3.5. `ENOTSUP` is
information; a window in which neither name resolves is a bug the caller cannot
see coming.

**Putting the lock check inside the phase-105 kernel (C7).** Rejected: the
kernel's purity is what lets it run before leaf resolution everywhere. A second,
impure function called immediately after costs one line per site and keeps the
guarantee.

**Reaping expired locks during the check (C7).** Rejected: reaping is a mutation
and phase-105 W3 removed exactly this from read-only read paths. Expired means
absent; reaping is an optimisation a writable endpoint may perform and
correctness may not depend on.

**A generic `brix_vfs_batch(op, paths[])` covering delete, setattr and xattr
(C4).** Rejected as speculative generality: only delete has a protocol batch
form asking for it, and a generic batch verb needs a per-op error model that
would be invented for two operations nothing calls.

**Gating the dedup plane with the export policy (C8).** Rejected: the dedup
target is service storage and no endpoint named it, so the export policy is the
wrong authority. The right assertion is that the instance really is service
storage, which is A.3.

**Typing the domain without enforcing it (C9).** Rejected: a constant nothing
reads is the situation the item exists to fix, in a new syntax. Pass 1 without
pass 2 is not worth doing.

**Deriving `oss.asize` into a quota decision (C5).** Rejected: the hint is
client-supplied and `write.c:264` already documents why it is not trusted for
enforcement. It sizes a reservation; the cap stays where it is.

---

## Appendix E — CI guards and static enforcement

Existing guards that must stay green, with what each one will catch here:

- **`check_vfs_mutation_gate.py`** — every new path mutator must call the
  confined form. The new verbs (`recall`, `evict`, `delete_many`) are mutators
  by the guard's own definition the moment they take a path, so the guard covers
  them without modification. It needs extending only for the lock gate: a path
  mutator that calls the policy kernel and *not* `brix_vfs_require_unlocked`
  should be reported once `brix_lock_enforcement` exists.
- **`check_vfs_seam.py`** — the spill temp is the risk. `vfs_spill.c` performs
  real syscalls outside `src/fs/backend/`, so it carries `vfs-seam-allow` with
  a reason naming service storage, or it moves behind an existing helper.
  Preference is the helper: `brix_vfs_pwrite_full` and the owned-temp path
  already exist and the spill should not be the tree's newest raw-syscall site.
  **C9 changes this guard's contract**: today `_raw_tier3_violation` returns
  `None` on the mere presence of the substring `vfs-seam-allow`, so the reason is
  unread. After W9 it parses a domain constant and checks a directory-prefix
  entitlement table. The switch from "any prose" to "an entitled domain" happens
  in the commit that finishes annotating, not before — an enforcing guard over a
  half-annotated tree is a red build carrying no information.
- **`check_sd_driver_conformance.py`** — the six new slots join the parity base,
  minus `sync_publish` (leaf-only, `dec`), recorded in the script.
- **`check_vfs_identity_branch.py`** — every new `_cred` twin.
- **`check_duplication`** — absolute, 0 backlog. The four `_cred` twins are
  where this bites: the Ceph work needed one tagged acquire/release runner
  because eight longhand bodies failed the gate. Every `_cred` twin here shares
  an `*_io` core with its plain sibling from the first commit.
- **`check_config_coverage.py`** — six new `.c` files in the repo-root `config`
  and a re-`./configure`.
- **`sd_slot_matrix.py --check`** — drift, over a census that is now
  header-derived and therefore cannot omit a slot.
- **Complexity contract** — absolute CCN/NPath. The spill writer and the tree
  batcher are the two that will push a function over; both split at the design
  stage rather than after the guard complains.
- **The seam-waiver table as a census (C9).** Worth recording what `check_duplication`
  cannot do, because W9 is what compensates: a hand-rolled
  `open`/`write`/`rename` is not textually similar enough to `staged_file.c` to
  trip a token-based detector, so structural duplication of a *contract* is
  invisible to it. The census that does see it is the per-domain waiver count
  (Appendix G). After W9 a rising count in a domain is the signal
  `check_duplication` cannot give — and it is the signal
  [phase 108](phase-108-vfs-consolidation.md) is measured by.

---

## Appendix F — requirement traceability

| item | §design | wave | tests | metric | guard |
|---|---|---|---|---|---|
| C1 out-of-order writes | §4 C1, A.9 | W2 | §9.1 C1, spill drain, hole refusal | `vfs_spill_bytes`, `vfs_spill_active` | seam, complexity |
| C2 prestage / evict | §4 C2, A.6, C.2 | W6 | §9.1 C2, ordering, `_cred` copy | `vfs_recall_total`, `vfs_evict_bytes` | mutation gate, identity branch |
| C3 durable publish | §4 C3, A.7 | W3 | §9.1 C3, spy fsync counter | — (failure is an error, not a counter) | conformance (`dec` exclusion) |
| C4 bulk delete | §4 C4, A.5, C.3 | W5 | §9.1 C4, per-level batching on `CAP_DIRS` | batch key count on the existing op counter | conformance, duplication |
| C5 reserve | §4 C5, A.4 | W4 | §9.1 C5, MPU part sizing | — | conformance |
| C6 preconditions / exchange | §4 C6, A.8 | W7 | §9.1 C6, advisory-vs-atomic | `vfs_precond_failed_total{kind}` | conformance, ABI note |
| C7 lock enforcement | §4 C7, A.2, C.4 | W8 | §9.1 C7, five-plane cross-protocol proof | `vfs_lock_refused_total{proto}` | mutation gate (extended) |
| C8 dedup plane | §4 C8, A.3 | W1 | §9.1 C8 | `vfs_mutation_denied{op=dedup}` | slot matrix (header-derived) |
| C9 typed domains | §3.7, §4 C9, A.3, App. G | W9 | §9.1 C9 | domain label on the mutation counter | seam guard (new contract) |

---

## Appendix G — the storage-domain table

The seven domains of §3.7, what each covers, which directories are entitled to
waive it, and whether a publish into it is durable — the last column is
consumed by [phase 108](phase-108-vfs-consolidation.md) §3.3, which is where
durability per domain is enforced.

| domain | covers | entitled paths | durable |
|---|---|---|---|
| `EXPORT` | client-named storage | none — it takes the phase-105 gate, not a waiver | per `brix_durable_publish` |
| `CACHE` | cache store tree, meta sidecars, verify staging | `src/fs/cache/**` | no (loss = re-fetch) |
| `STAGE` | upload stage dir, TPC transfer temps, spill (C1) | `src/fs/xfer/**`, `src/tpc/**`, `src/protocols/webdav/tpc_*` | no (loss = retry) |
| `REGISTRY` | OCI store tree, tag pointers, referrers/store indexes | `src/protocols/oci/**` | **yes** |
| `CREDENTIAL` | delegated proxies, minted creds, keytabs, bearer files | `src/fs/vfs/vfs_deleg*`, `src/fs/backend/cred_mint*`, `src/auth/**`, the TPC/WebDAV delegation sites | **yes** |
| `CONFIG` | trust anchors, CA bundles, operator files (CMS blacklist) | `src/core/config/**`, `src/net/cms/blacklist_file.c` | n/a (read-mostly) |
| `JOURNAL` | FRM and stage journals, request registries | `src/fs/xfer/**`, `src/fs/tier/**` | **yes** |

Counts from the tree at `480ded2e4`, as the starting point for W9 pass 1 — the
prose reasons already cluster this way, which is the evidence the domain is real
and not imposed:

| reason cluster | waivers |
|---|---|
| staged credential temp / cred dir / config-domain proxy, PEM, token, keytab | ~25 |
| cache-store staging, svc-owned cache tree, cache-root sidecar | ~15 |
| registry store tree / indexes / tag pointers / session state | ~14 |
| TPC in-progress temps and assembly | ~6 |
| metadata on a VFS-opened confined fd (already correct — no change) | 4 |
| trust anchors, operator config | ~5 |
| the remainder: probes, scratch, sweeps, forensics | ~48 |
| **total** | **117** |

The remainder is where W9 pass 1 will do actual work rather than transcription,
and it is sized accordingly in the wave.

---

*End of plan. Nothing in this document has been implemented. When a wave lands,
append its record here in the shape phase 105 used — what the sweep actually
found, not what it set out to find. The consolidation half of the original v2
plan now lives in [phase 108](phase-108-vfs-consolidation.md).*
