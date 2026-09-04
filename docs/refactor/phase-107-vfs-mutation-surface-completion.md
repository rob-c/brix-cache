# Phase 107 — VFS mutation surface completion: the verbs the layer cannot express

**Date:** 2026-08-30

**Status:** IMPLEMENTED AND VERIFIED (closed 2026-09-04). C1–C9 and W0–W9 are
landed; the local guards, C units, serial `--pr` acceptance tier, and live
protocol evidence are green. The plan body is retained as the specification and
the checked execution ledger near the end is the as-built record.

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
split that phase 105 drew in prose is carried through the tree in 108 free-text
`vfs-seam-allow` comments that nothing reads. **C9** turns that line into a type
and makes CI check it. It is here rather than in phase 108 because every verb
below has to say which storage it is touching, and because it is the
prerequisite the consolidation phase opens by verifying.

Reading the same surface from the other direction asks a different question —
where does BriX-Cache already do VFS work *without* the VFS? — and finds an OCI
registry that has privately rebuilt staged publish and atomic tag swap over raw
syscalls, four independent implementations of "write a secret to a file
safely" that disagree on most of what makes it safe, an authorization decision
taken at 28 protocol-edge call sites in five different vocabularies, and a
name-translation module compiled, unit-tested, and called by nothing. That is
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
| C9 | 108 seam waivers carry unvalidated prose where a typed storage domain belongs | `check_vfs_seam.py:212` — `_raw_tier3_violation` returns `None` the moment the substring appears | contract |

**C9** is not a capability hole; it is the reason the other eight cannot say
what storage they are touching. `check_vfs_seam.py`'s `_raw_tier3_violation`
returns `None` the moment the substring `vfs-seam-allow` appears on the line;
nothing parses, validates or cross-references the reason that follows it. The
reasons are nevertheless *good* — they are written by people who knew exactly
which storage they meant — which is precisely the evidence that the domain is
real and is being carried in prose instead of in a type.

The **108 real markers**, by owning area. (117 lines in `src/**.{c,h}` mention
`vfs-seam-allow`; nine of those are doc comments explaining the convention, and
the difference matters enough that [Appendix G.2](#g2-the-census-re-derived)
gives it a section — the guard's substring test cannot tell the two apart, and
W9's parser must.)

| Area | Markers | Dominant reason cluster |
|---|---|---|
| `src/protocols/oci` | 25 | registry store tree, blob/manifest temps, tag pointers |
| `src/protocols/webdav` | 20 | delegated credential dir, lock sidecars, TPC temps |
| `src/protocols/root` | 17 | staged credential temps, cache-root reads, prepare spool |
| `src/fs/cache` | 15 | cache-store staging file, svc-owned domain |
| `src/tpc/outbound` | 6 | transfer temps, delegated proxies |
| `src/net/cms` | 6 | metadata on a VFS-opened fd; operator blacklist file |
| `src/protocols/cvmfs` | 4 | catalogue/whitelist staging, origin probe socket |
| `src/protocols/shared` | 3 | transient serve scratch |
| `src/fs/vfs` | 3 | the layer's own internals |
| `src/core/config` | 3 | trust anchors, operator-supplied files |
| `src/protocols/s3` | 2 | multipart bookkeeping |
| `src/net/proxy` | 2 | GSI PEM temps |
| `src/protocols/gridftp` | 1 | transfer temp |
| `src/core/aio` | 1 | AIO scratch |
| **total** | **108** | |

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
tree then carried that reasoning in 108 free-text `vfs-seam-allow` comments,
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

**Today.** `brix_handle_prepare` validates paths, then — if `kXR_stage` is set
and `brix_prepare_command` is configured — forks a subprocess (`prepare_cmd.c`)
and returns. The two management options are accepted and discarded:

```
prepare.c:412   kXR_wmode arm — the only arm phase 105 could gate
prepare.c:422   cancel  -> accepted, treated as a noop
prepare.c:428   evict   -> accepted, treated as a noop
```

Meanwhile the driver vtable already carries the two slots this needs, fully
documented, with exactly the response shapes the protocol wants:

```c
/* sd.h:435 */
ngx_int_t (*recall)(brix_sd_instance_t *inst, const char *key, char reqid_out[40]);
/*   NGX_AGAIN = queued or joined (park the open), NGX_OK = already online,
     NGX_ERROR = errno set.  reqid_out ≤ 39 chars + NUL. */

/* sd.h:443 */
ngx_int_t (*residency)(brix_sd_instance_t *inst, const char *key,
                       brix_sd_residency_t *out);
/*   pure read of the MSS residency model, never initiates a recall. */
```

`recall` is implemented on five drivers — `http` (`sd_http.c:102`), `pblock`
(`sd_pblock.c:284`), `frm` (`sd_frm.c:501`), `remote` (`sd_remote.c:412`),
`xroot` (`sd_xroot.c:277`) — and is called from exactly **one** place in the
tree: a cache fill (`sd_cache.c:128`). `residency` is implemented on the same
five plus the three FRM back-ends (`sd_frm_exec.c:193`, `sd_frm_lib.c:79`,
`sd_frm_stub.c:355`). Tape staging therefore works only where an operator wired
a `prepare_command` script, and not at all through the drivers that already
implement the two slots it would need.

**Design.** Two new public verbs, both decorator-aware but in opposite
directions:

```c
/* src/fs/vfs/vfs_recall.c */
ngx_int_t brix_vfs_recall(brix_vfs_ctx_t *ctx, char reqid_out[40]);
ngx_int_t brix_vfs_evict (brix_vfs_ctx_t *ctx, uint64_t *bytes_out);
```

| verb | dispatch | gate | returns | errno |
|---|---|---|---|---|
| `brix_vfs_recall` | **descends** via `brix_vfs_decorator_source()` to the first implementer — the `walk` verdict in the slot matrix | `MUTATE_STAGE` | `NGX_AGAIN` + reqid (queued or joined), `NGX_OK` (already online), `NGX_ERROR` | `EROFS` (read-only endpoint), `ENOTSUP` (no `recall` and no `prepare_command`), `ENOENT`, `EBUSY` (C7 lock), `EACCES` (ownership, see below) |
| `brix_vfs_evict` | **dispatches on the top** of the chain — eviction is a question *about the cache* | `MUTATE_EVICT` | `NGX_OK` + bytes released, `NGX_ERROR` | `EROFS`, `ENOTSUP`, `ENOENT`, `EACCES` (not the requester's record) |

Asking a cache to prestage is asking the wrong instance, which is why `recall`
descends; asking a nearline leaf to evict a cache copy is equally wrong, which
is why `evict` does not. `brix_vfs_residency` and `brix_vfs_space` already
establish the descending shape, so `recall` adds no new dispatch idiom.

**Recall / reqid lifecycle.** The durable registry
(`src/fs/xfer/stage_request_registry.c`) already owns reqid allocation,
ownership and the WAL, and already models exactly the five states the protocol
reports (`brix_stage_req_status_t`, `stage_request_registry.h:53–60`). C2 wires
the VFS verb to it rather than inventing a second bookkeeping plane:

```
  client kXR_prepare + kXR_stage
        │
        ▼
  brix_vfs_recall()  ── gate MUTATE_STAGE ──► [refused: EROFS, nothing recorded]
        │ allowed
        ▼
  brix_stage_request_find_by_path()          ─── hit ──► join: return existing reqid
        │ miss                                            (status unchanged)
        ▼
  brix_stage_request_reqid_generate()  +  brix_stage_request_add(view)
        │                                    requester_dn = the caller's identity
        ▼
  driver ->recall(inst, key, reqid_out)
        │
        ├─ NGX_OK      -> set_status(DONE)      -> reply "online"
        ├─ NGX_AGAIN   -> set_status(QUEUED)    -> reply reqid, client polls
        │                    │ mover starts     -> set_status(ACTIVE)
        │                    │ mover completes  -> set_status(DONE)
        │                    │ mover fails      -> set_status(FAILED)
        │                    └ owner cancels    -> set_status(CANCELLED)
        └─ NGX_ERROR   -> delete the record, return errno   [no orphan reqid]
```

The last arm is the one worth stating explicitly: a record is created *before*
the driver call so that a concurrent second request joins rather than
duplicating, and is deleted on a synchronous driver failure so a failed recall
never leaves a reqid a client can poll forever.

**Ownership.** `brix_stage_request_owner_check()`
(`stage_request_registry.h:119`) already exists and the cancel path already uses
it (FRM-1: only the requester that created a record may act on it). `evict` and
`cancel` both route through it, so an anonymous session cannot evict another
identity's staged object. The check runs at step 1.5 of
[§3.4](#34-the-order-every-new-mutator-obeys) — *after* the policy kernel — so a
read-only endpoint answers `EROFS` and discloses nothing about whose record
exists.

**Protocol wiring.**

| plane | request | becomes |
|---|---|---|
| root | `kXR_prepare` + `kXR_stage` | `brix_vfs_recall()` per resolved path; the reqid is the registry's, returned as the response body |
| root | `kXR_QPrep` | `brix_vfs_residency()` for the per-path status line, instead of answering from the registry alone — the residency model is the truth, the registry is the bookkeeping |
| root | `kXR_prepare` + evict (`prepare.c:428`) | `brix_vfs_evict()`, behind `brix_stage_request_owner_check()` |
| root | `kXR_prepare` + cancel (`prepare.c:422`) | `brix_stage_request_cancel()`, behind the same ownership check |
| WebDAV/HTTP | — | no standard verb; out of scope |
| S3 | storage-class transition | out of scope — a lifecycle policy, not a request |

`brix_prepare_command` stays supported and becomes the **fallback** for a driver
with no `recall` slot (§3.5). The phase-93 config advisor grows one note: a
nearline export with neither a `recall`-capable driver nor a `prepare_command`
can never stage, and should say so at startup rather than at the first client
request.

**Per-driver verdict.**

| driver | `recall` | `recall_cred` | `evict` | note |
|---|---|---|---|---|
| `posix` | — `flat` | — | ✔ unlink the online copy | no nearline plane |
| `block` | — `flat` | — | — `flat` | fixed extents, nothing to release |
| `pblock` | ✔ exists | ✔ new | ✔ new | simulated tape recall (F4) |
| `http` | ✔ exists | ✔ new | — `ro` | origin is read-only to us |
| `xroot` | ✔ exists | ✔ new | ✔ new — `kXR_prepare` evict upstream | |
| `cache` | `walk` | `walk` | ✔ = today's `brix_sd_cache_evict()` promoted | the top-of-chain case |
| `stage` | `walk` | `walk` | ✔ new | drops the write-back copy only when clean |
| `remote` | ✔ exists | ✔ new — **lazy, must copy the cred** | — `ro` | the `_cred` asymmetry class |
| `frm` | ✔ exists | ✔ new | ✔ new — MSS release | the reference nearline plane |
| `mirage` | — `syn` | — | — `syn` | synthetic |
| `ceph` | — `flat` | — | ✔ new | RADOS: the ioctx **is** the identity at the OSDs |
| `cephfs_ro` | — `ro` | — | — `ro` | |

**Gate.** `MUTATE_STAGE` and `MUTATE_EVICT`, both new in
[§3.1](#31-the-vocabulary-grows-by-four). Both are export mutations by the plain
reading — prestage consumes tape drives and disk buffer, eviction destroys the
online copy — and both are today reachable by a reader on a read-only endpoint,
because phase 105 could only gate the `kXR_wmode` arm of prepare
(`prepare.c:412`; phase-105 §F.1). This closes that.

> **Fallout for test fleets (2026-09-02, observed as 16 fast-tier reds):**
> `brix_allow_write` is stream-server-conf only (`stream_common.c`), so it
> must appear **per server block**. Any pre-C2 fleet config that exercised
> `kXR_prepare`+`kXR_stage` (or evict) without declaring writability — the
> audit16ah FRM configs were the whole class — now correctly gets
> `kXR_fsReadOnly` ("this is a read-only server") from
> `prepare_dispatch_special` before the path scan. The fix is
> `brix_allow_write on;` in each server block of the test face, not a gate
> exemption: a red of this shape after touching prepare/stage paths is the
> gate working, not a regression.

**Tests** (`tests/test_prepare_recall.py`, `tests/test_vfs_evict.py`):

| test | asserts |
|---|---|
| success | `kXR_prepare` + `kXR_stage` on an `frm` export with no `prepare_command` returns a reqid; `kXR_QPrep` reports `QUEUED` then `DONE` |
| success | a second `prepare` for the same path **joins** — same reqid, one registry record |
| error | `recall` returning `NGX_ERROR` deletes the record: `kXR_QPrep` on the reqid says unknown, not "queued forever" |
| error | a nearline export with neither slot nor command returns `kXR_Unsupported`, and the advisor emitted the warning at startup |
| security-negative | `brix_write_enable off` → `kXR_fsReadOnly` for both stage and evict, and **no** registry record is created |
| security-negative | identity B cannot evict or cancel identity A's reqid — `kXR_NotAuthorized`, record untouched |
### C3 — Durable publish barrier

**Today.** Directory durability is attempted in exactly one place in the whole
tree, and that attempt cannot work:

```c
/* src/core/compat/staged_file.c:317-319, in staged_commit_internal() */
/* C1: persist the directory entry so the rename itself survives a crash
 * (best-effort — the data is already durable above). */
(void) fsync(rootfd);
```

`rootfd` comes from `brix_beneath_open_root()` (`src/fs/path/beneath.c:79`),
which returns `open(root_canon, O_PATH | O_DIRECTORY | O_CLOEXEC)`. `fsync` is
not among the operations `open(2)` permits on an `O_PATH` descriptor: on Linux
it fails with `EBADF`. The result is discarded by the `(void)` cast, so the
failure is invisible. Two things are therefore wrong at once, and the second
survives fixing the first:

1. **The fd is unusable for `fsync`.** The barrier is inert.
2. **It is the wrong directory.** Even with a syncable fd, it flushes the
   *export root*, not the parent of `final_rel`. A publish to
   `/srv/export/a/b/c.dat` needs `/srv/export/a/b` flushed; flushing
   `/srv/export` makes the top-level entry durable and says nothing about `b`.

Everywhere else the file's contents are made durable and the name is not:
`brix_vfs_staged_commit` (`vfs_staged.c:302–390`) fsyncs the temp's fd and
renames; `brix_oci_store_put_text` (`oci_store.c:279–323`) does not fsync at
all before its rename at `:318`; `webdav/delegation.c` fsyncs at `:303` and
renames at `:312`. Of the 38 `fsync`/`fdatasync` call sites in `src/`, every one
operates on a file, a journal or a `brix_sd_obj_t` — none on a parent directory.

The observable failure is an object whose bytes are all present and whose name
is gone.

**Design.** A `sync_publish(brix_sd_instance_t *inst, const char *path)` slot,
called after a successful `staged_commit` and after a successful `rename`, on
the **leaf**, when the export's namespace is POSIX.

The POSIX implementation opens the *parent directory of `path`* through the
existing confined-fd machinery — `brix_open_beneath(rootfd, parent_rel,
O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)`, never by re-resolving a path by name,
which would reintroduce the TOCTOU the beneath API exists to close — fsyncs it,
and closes. `O_RDONLY`, not `O_PATH`: that is the whole content of defect (1)
above.

**Contract.**

| element | value |
|---|---|
| signature | `ngx_int_t (*sync_publish)(brix_sd_instance_t *inst, const char *path)` |
| `path` | the **published** path, export-relative and already confined by the caller; the slot derives the parent, never re-resolves |
| returns | `NGX_OK` — the parent directory entry is durable; `NGX_ERROR` with `errno` set |
| `errno` | `EIO` (fsync failed), `ENOENT` (parent vanished — a concurrent rmdir), `EBADF` (must never be seen again; the W0 test asserts it is not) |
| `NULL` slot | the publish is reported durable-to-the-far-end; see the fallback doctrine in [§3.5](#35-fallback-doctrine) |
| failure handling | **a failed `sync_publish` fails the publish.** The name is already visible, so the caller cannot un-rename; it returns `EIO` to the client and logs at `NGX_LOG_CRIT`. A publish that reports success without durability is the bug this item exists to remove |

**Call sites that gain the barrier.**

| file:line | what publishes |
|---|---|
| `src/core/compat/staged_file.c:319` | the inert `fsync(rootfd)` — replaced, not supplemented |
| `src/fs/vfs/vfs_staged.c:369–372` | `brix_vfs_staged_commit` both arms |
| `src/fs/backend/posix/sd_posix_ns.c:497,499` | the POSIX driver's own staged commit |
| `src/core/compat/namespace_ops_copy.c:252` | copy publish |
| `src/protocols/webdav/tpc_pull.c:282` | TPC pull landing |
| `src/protocols/root/write/chkpoint_recover.c:106` | checkpoint recovery |
| `src/fs/vfs/vfs_rename.c` | every `brix_vfs_rename` that publishes into the namespace |

Because all seven route through `brix_staged_commit*` or `brix_vfs_rename`, the
barrier lands in **two** functions, not seven — which is the argument for doing
it in the VFS rather than per protocol.

**Per-driver verdict.**

| driver | verdict | why |
|---|---|---|
| `posix` | ✔ | `openat` the parent, `fsync`, `close` |
| `frm` | ✔ | POSIX online buffer |
| `pblock` | ✔ | already `fdatasync`s its segments (`pblock_pack.c`); the slot flushes the SQLite catalogue's directory |
| `cache`, `stage` | relay to the leaf (`dec`) — and, per the decorator-parity gate, **both** must relay or neither may |
| `http`, `xroot`, `remote` | `np` | the publish is atomic at the far end; there is nothing local to flush |
| `ceph` | `np` | RADOS commits the object; there is no local directory entry |
| `cephfs_ro` | `ro` | |
| `block` | `flat` | fixed extents, no namespace |
| `mirage` | `syn` | synthetic |

**Directive.**

| directive | context | argument | default |
|---|---|---|---|
| `brix_durable_publish` | `http`, `server`, `location` | `on` \| `off` | `on` |

It is a directive rather than an unconditional step because a dirfsync per
commit is a real cost on a busy write path, and a cache store whose loss is a
re-fetch does not need it. The default is `on` because the failure it prevents
is silent data loss and the cost is one fsync per *publish*, not per write.
`nginx -t` negative: `brix_durable_publish maybe;` →
`[emerg] invalid value "maybe" in "brix_durable_publish" directive`.

**What is actually testable.** Power-loss testing is out of scope. What the test
matrix pins:

| test | asserts |
|---|---|
| W0, failing first | `staged_file.c:319`'s `fsync(rootfd)` returns `EBADF` today — the test that proves the barrier is inert before it is fixed |
| success | the dirfsync is issued exactly once per publish, on the **parent of the published path**, not the export root (spy driver counter + `strace`-level assertion in the POSIX C object unit) |
| success | it is skipped for non-POSIX namespaces and when `brix_durable_publish off` |
| error | a forced `fsync` failure (spy driver returning `EIO`) fails the publish, returns `EIO` to the client, and logs at `crit` — it is not swallowed |
| security-negative | `sync_publish` never re-resolves `path`: a test that swaps the parent for a symlink between rename and barrier still flushes the confined parent, because the fd was derived from the same `rootfd` |
### C4 — Bulk namespace delete

**Today.** `brix_vfs_driver_rmtree` (`vfs_unlink.c:43`) walks depth-first, bounded
at `BRIX_FS_TREE_MAX_DEPTH` = 512 (`core/compat/fs_walk.h:23`), and calls
`brix_sd_unlink_maybe_cred` once per entry, threading the credential through the
whole recursion. That is correct and it is one round trip per key.

The S3 plane makes the cost vivid. `src/protocols/s3/delete_objects.c` parses a
`<Delete>` document capped at `S3_DEL_MAX_KEYS` = 1 000 keys (`:37`) and a 1 MiB
body (`:38`), sizes its output XML to hold a `<Deleted>`/`<Error>` element per
key (`:39`) — and then calls `brix_vfs_unlink` once per key in `s3_delete_one`
(`:67`). Over a `remote` backend that is 1 000 signed HTTPS requests to serve one
request whose entire purpose was to avoid exactly that. The per-key error
vocabulary the handler already builds (`AccessDenied`, `BucketNotEmpty`,
`InternalError`, and `ENOENT` as idempotent-success) is precisely the shape a
batch slot must preserve.

**Design.** `unlink_many` + `unlink_many_cred`, with per-key error reporting, and
a VFS-level chunker that fills a window and flushes.

```c
/* src/fs/backend/sd_batch_types.h */
ngx_int_t (*unlink_many)(brix_sd_instance_t *inst,
                         const char *const *paths, size_t n,
                         int *errs, size_t *done);
```

| element | contract |
|---|---|
| `paths` | borrowed, `n` entries, each already confined by the caller; the slot never re-resolves |
| `n` | ≤ the driver's window (see below); the VFS chunker guarantees it |
| `errs` | caller-allocated, `n` entries. The slot writes `0` for success and a positive `errno` per key. `ENOENT` is written as `ENOENT`, not silently mapped — the *caller* decides idempotency, exactly as `s3_delete_one` does today |
| `done` | number of leading entries the slot actually attempted; a transport failure at key `k` sets `*done = k` and returns `NGX_ERROR` with `errno` set, leaving `errs[k..n)` untouched |
| returns | `NGX_OK` — every key attempted, per-key results in `errs` (which may still contain failures); `NGX_ERROR` — the batch itself failed |
| `NULL` slot | the VFS runs the existing per-key loop; behaviour is identical, only slower |

**Two callers.**

1. `brix_vfs_driver_rmtree` (`vfs_unlink.c:43`) — accumulates a level's entries
   and flushes at the level boundary.
2. `brix_vfs_delete_many()` (new, `src/fs/vfs/vfs_unlink_many.c`) — the S3 batch
   endpoint's direct path, replacing the loop at `delete_objects.c:67`.

**The trap worth writing down.** A tree delete may only batch **within one
directory level**, because a prefix cannot be removed before its children. Every
registered driver except `mirage` advertises `BRIX_SD_CAP_DIRS` (`sd.h:107`) —
`posix`, `block`, `pblock`, `http`, `xroot`, `cache`, `stage`, `remote`, `frm`,
`ceph`, `cephfs_ro` — so the per-level rule is not a special case, it is the
rule. There is no "flat key store" shortcut to take in this tree, and the
temptation to add one is the bug: getting it backwards produces a delete that
appears to succeed against an S3 origin and leaves a half-removed tree on a
WebDAV origin, which is the class the decorator-parity gate was added for.

The one path that legitimately batches without ordering is
`brix_vfs_delete_many()`, because there the **client** supplied a flat key list
and asked for exactly those keys — the server is not walking a tree and owes no
ordering guarantee beyond what the client requested.

**Window size.** `BRIX_SD_CAP_BULK_DELETE` (`1u << 17`, the next free bit above
`MEMFILE` at `1u << 16`) selects the window: 1 000 with the bit, 1 without. The
bit means "the driver's `unlink_many` is a real batch, not a loop" — a driver may
implement the slot without the bit (e.g. to get one transaction instead of one
per key) and still be windowed at 1.

**Per-driver verdict.**

| driver | verdict | why |
|---|---|---|
| `remote` | ✔ + `CAP_BULK_DELETE` | S3 `DeleteObjects`, 1 000 keys per signed request — the item's whole motivation |
| `pblock` | ✔, no cap bit | one SQLite transaction per window; the win is transaction count, not round trips |
| `ceph` | ✔, no cap bit | one ioctx, N `rados_remove` — no batch op in the C API (checked against the librados 3.0 header, not the docs), but the ioctx and its identity are established once |
| `http` | `np` | RFC 4918 has no batch DELETE. The generic loop is exact, so the ceiling is the protocol's and it is recorded as such, not worked around |
| `xroot` | `np` | no batch verb in XProtocol |
| `posix` | `seam` | `unlinkat` per entry is already the syscall floor |
| `cache`, `stage` | `dec` → relay to the leaf; **both or neither**, per the parity gate |
| `frm` | `seam` | POSIX online buffer |
| `block` | `flat` | no namespace |
| `mirage` | `syn` | synthetic |
| `cephfs_ro` | `ro` | |

**Gate.** `MUTATE_REMOVE`, unchanged vocabulary. **One** policy check for the
whole batch and **one** metric observation per batch carrying the key count —
not one per key, which would blow up the op counters on a 1 000-key delete and
violate INVARIANT #8's cardinality rule in spirit if not in label count.

**Tests** (`tests/test_s3_delete_objects_batch.py`, `tests/test_vfs_rmtree.py`):

| test | asserts |
|---|---|
| success | a 1 000-key `DeleteObjects` against a `remote` export issues **one** upstream batch request (fault-proxy request count), and the `<DeleteResult>` carries 1 000 `<Deleted>` elements |
| success | a mixed batch — 998 present, 1 absent, 1 forbidden — returns 999 `<Deleted>` (`ENOENT` is idempotent-success) and exactly one `<Error><Code>AccessDenied` at the right key |
| success | a recursive `DELETE` of a 3-level collection over `http` still removes children before parents, and never presents a parent in the same window as its own child |
| error | a transport failure mid-batch sets `*done` short, and the keys past it are reported as untried rather than as deleted |
| security-negative | `brix_write_enable off` → `EROFS` for the whole batch, before any key is examined, with **no** per-key disclosure of which keys exist |
| security-negative | a batch containing `../` in a key is refused at confinement, and the refusal does not leak whether the escaped path exists |
### C5 — Space reservation

**Today.** `oss.asize` is type-checked as an unsigned integer
(`opaque_validate.c:235–240`) and then dropped. `write_over_quota`
(`write.c:275`) probes usage with a 5-second TTL cache and fails open by design;
`write.c:264` records why the cap is enforced at the write plane "rather than
only trusting the client's `oss.asize` hint at open" — correct as a security
posture, and not a reason to discard the hint for capacity planning.

The cost is computable rather than theoretical. `SD_REMOTE_PART_SIZE`
(`sd_remote_write.c:37`) is fixed at 16 MiB and S3 caps a multipart upload at
10 000 parts, so a `remote` export refuses any object past **160 GB** — while
`sd_s3_open_write(p, expected_size, part_size, …)` already *accepts* an expected
size and is handed `-1` at `sd_remote_write.c:66`. The plumbing exists; one
caller discards the only input it needs.

**Design.** A `reserve(obj, size)` slot, called once immediately after a
create-open when the client declared a final size, from whichever edge knows it.

```c
ngx_int_t (*reserve)(brix_sd_obj_t *obj, off_t size);
```

| element | contract |
|---|---|
| when | exactly once, immediately after a successful create-open, before the first write |
| `size` | the client's **declared** final size; advisory, never trusted as a limit — the write-plane quota check at `write.c:275` stays exactly as it is |
| returns | `NGX_OK`, or `NGX_ERROR` with `errno` |
| `ENOSPC` | **fails the open.** This is the entire point: fail at open, not at byte 4 999 999 999 |
| any other errno | advisory. Logged at `NGX_LOG_INFO`, the open proceeds. A backend that cannot reserve is not a backend that cannot write |
| `NULL` slot | no reservation; identical to today |

**Where the declared size comes from.**

| plane | source | file |
|---|---|---|
| root | `oss.asize` opaque key | `opaque_validate.c:235–240` |
| WebDAV / HTTP | `Content-Length` on `PUT` (absent under chunked TE — then no reservation) | `webdav/put_setup.c` |
| GridFTP | `ALLO` command, and `SIZE` on a store | `gridftp/ev/ftp_ev_cmd.c` |
| S3 | `Content-Length`, or the multipart `CreateMultipartUpload` when the client declares parts | `protocols/s3/` |

**Per-driver verdict.**

| driver | verdict | implementation |
|---|---|---|
| `posix` | ✔ | `posix_fallocate` / `fallocate(FALLOC_FL_KEEP_SIZE)` — early `ENOSPC`, no fragmentation |
| `pblock` | ✔ | preallocate the block chain and charge the catalogue quota exactly, replacing a probe that is stale by up to five seconds with a number correct by construction |
| `remote` | ✔ — **the sharpest edge** | choose the multipart part size from the declared size: `part = max(5 MiB, ceil(size / 10000))`. With today's fixed 16 MiB a 5 TB upload exceeds the 10 000-part limit and fails late; with a declared size the part size is arithmetic instead of a guess. Pass `expected_size` at `sd_remote_write.c:66` instead of `-1` |
| `xroot` | ✔ | forward `oss.asize` to the origin's open — the origin speaks the same dialect, and discarding the hint at the gateway is pure loss |
| `block` | ✔ | extent count is already the allocation unit; reserve = claim the extents |
| `frm` | ✔ | POSIX online buffer, same as `posix` |
| `cache`, `stage` | `dec` → relay to the leaf, **both or neither** |
| `ceph` | `np` | no useful preallocation primitive in librados' **C** API — verified against the real librados 3.0 headers inside the image layers, as the Ceph slot work established, not against the documentation |
| `http` | `np` | no verb |
| `cephfs_ro` | `ro` | |
| `mirage` | `syn` | synthetic sizes are the driver's whole purpose |

**Gate.** Inside an already-gated `MUTATE_OPEN`. No vocabulary change: a
reservation is part of the open, not an operator-visible event of its own.

**Tests** (`tests/test_vfs_reserve.py`):

| test | asserts |
|---|---|
| success | a 200 GB `oss.asize` over a `remote` export selects a part size ≥ 20 MiB and completes; today the same upload fails past 160 GB |
| success | `posix` with `oss.asize` larger than the free space fails the **open** with `kXR_NoSpace`, not the 5 000th write |
| success | no declared size ⇒ no `reserve` call at all (spy counter zero) |
| error | a driver returning `EOPNOTSUPP` from `reserve` logs at info and the write proceeds byte-exact |
| security-negative | a declared size of 0 or one far below the bytes actually written does **not** raise the quota ceiling: `write_over_quota` still refuses at the real boundary, proving the hint is advisory in both directions |
| security-negative | `brix_write_enable off` → `EROFS` at open, before `reserve` is reached (spy counter zero) |
### C6 — Conditional publish and atomic exchange

**Today.** `staged_commit(brix_sd_staged_t *st, int noreplace)` (`sd.h:394`),
reached through `brix_vfs_staged_commit(st, unsigned excl)` (`vfs_staged.c:302`,
driver dispatch at `:339`, the two public wrappers at `:369–372`). `noreplace`
becomes `RENAME_NOREPLACE` on POSIX and, on `remote`
(`sd_remote_write.c:148–200`), a HEAD followed by a PUT that the source itself
documents as check-then-act and racy against a concurrent external writer
landing the object in between. At the protocol edge, WebDAV COPY evaluates
`If-Match`/`If-None-Match` in `copy_conditionals()` (`copy.c:280`) — *before*
the staged temp is even created, so any writer that lands between the check and
the rename wins silently.

The VFS cannot carry the client's actual request, because a boolean has nowhere
to put an etag.

**Design, half one: a typed precondition.**

```c
/* src/fs/backend/sd_batch_types.h */
typedef enum {
    BRIX_SD_PRECOND_NONE = 0,      /* replace unconditionally            */
    BRIX_SD_PRECOND_ABSENT,        /* create-if-absent (today's excl)    */
    BRIX_SD_PRECOND_MATCH_ETAG,    /* replace iff the entity tag matches */
    BRIX_SD_PRECOND_MATCH_META     /* replace iff (size, mtime) matches  */
} brix_sd_precond_kind_t;

typedef struct {
    brix_sd_precond_kind_t  kind;
    ngx_str_t               etag;      /* MATCH_ETAG only; borrowed            */
    off_t                   size;      /* MATCH_META only                      */
    time_t                  mtime;     /* MATCH_META only                      */
    unsigned                atomic:1;  /* OUT: the storage decided, atomically */
} brix_sd_precond_t;
```

`kind == 0` is `NONE`, so a zeroed struct is today's unconditional behaviour —
the same fail-safe-by-zero discipline the mutation policy uses for a different
question, applied here so that a caller who forgets to fill the struct gets the
*old* semantics rather than an accidental refusal.

`atomic` is an **output**: the slot sets it when the decision was made at the
storage and could not have raced. This is what `BRIX_SD_CAP_PRECOND`
(`1u << 18`) advertises statically and what the field reports per call, because
on `http` the property is a runtime fact about the origin, not a compile-time
fact about the driver.

| element | contract |
|---|---|
| signature | `staged_commit(brix_sd_staged_t *st, const brix_sd_precond_t *pre)` — `pre` may be `NULL`, meaning `NONE` |
| returns | `NGX_OK` (published), `NGX_ERROR` |
| `EEXIST` | `ABSENT` and the target exists → `kXR_ItExists` / `412` |
| `ECANCELED` | `MATCH_*` and the precondition failed → `412 Precondition Failed`; **new mapping**, see [§5](#5-protocol-behavior) |
| `ENOTSUP` | the driver cannot evaluate this `kind` at all and there is no honest emulation |
| `pre->atomic` | set by the slot; the protocol layer reads it and must not claim RFC 7232 semantics when it is 0 |

**Per-driver verdict.**

| driver | ABSENT | MATCH_ETAG | MATCH_META | `CAP_PRECOND` | how |
|---|---|---|---|---|---|
| `remote` | ✔ atomic | ✔ atomic | `np` | ✔ | `If-None-Match: *` / `If-Match: <etag>` on the PUT or the MPU completion — the documented race disappears |
| `http` | ✔ | ✔ | `np` | probed | RFC 7232 conditional PUT; the driver probes once at init whether the origin answers `412` or ignores the header, and records the result. `atomic` reports the probe |
| `posix` | ✔ atomic | ✔ advisory | ✔ advisory | ✔ (ABSENT only) | `RENAME_NOREPLACE` is atomic; `MATCH_*` is compared under the target parent's fd — honest, and **not** atomic, so `atomic = 0` |
| `pblock` | ✔ atomic | ✔ atomic | ✔ atomic | ✔ | one SQLite transaction covers the compare and the rename |
| `ceph` | ✔ atomic | ✔ atomic | `np` | ✔ | RADOS write-op assertions (`assert_exists` / `cmpxattr`) in the same op |
| `frm` | ✔ atomic | ✔ advisory | ✔ advisory | ✔ (ABSENT) | POSIX online buffer |
| `xroot` | ✔ | `np` | `np` | — | XProtocol has `kXR_new`; no etag verb |
| `block` | `flat` | | | | no namespace |
| `cache`, `stage` | `dec` → relay, both or neither | | | | the parity gate covers the changed signature too |
| `mirage` | `syn` | | | | |
| `cephfs_ro` | `ro` | | | | |

**Design, half two: `exchange`.**

```c
ngx_int_t (*exchange)(brix_sd_instance_t *inst, const char *a, const char *b);
```

`renameat2(RENAME_EXCHANGE)` on `posix` and `frm`, a catalogue transaction on
`pblock`, and `ENOTSUP` everywhere else **with no emulation** — a two-rename
emulation has a window in which neither name resolves, which is worse than
saying no (see [§3.5](#35-fallback-doctrine)). Both paths are confined under the
same `rootfd`; `a` and `b` must be in the same export, and a cross-export
exchange is `EXDEV`.

Consumers: CVMFS stratum-0 catalogue publishing (phase 96), OCI tag updates
(phase 104, and see [phase 108](phase-108-vfs-consolidation.md) C10), and any
publish-new-tree-keep-old flow that today does two renames and hopes.

**Why this needs its own wave (W7).** Changing `staged_commit`'s signature moves
every driver initialiser and every caller at once, and it is an ABI change to a
struct the whole tree links against: **incremental builds will link cleanly and
behave wrongly**, because a stale object file passes an `int` where the new
callee reads a pointer. The wave ends with `rm -rf objs && ./configure && make`
and an ABI note in `docs/09-developer-guide/agent-guide-extended.md`, the same
discipline a struct-field addition demands.

**Call sites that change in W7.**

| file:line | change |
|---|---|
| `src/fs/backend/sd.h:394` | the slot signature |
| every driver's `.staged_commit` initialiser | 12 drivers, one commit |
| `src/fs/vfs/vfs_staged.c:302,339,369–372` | `brix_vfs_staged_commit` carries the struct; the two wrappers stay as compatibility spellings for `NONE`/`ABSENT` |
| `src/protocols/webdav/copy.c:280` | `copy_conditionals()` stops deciding and starts **carrying** — it parses the headers into a `brix_sd_precond_t` and hands it down |
| `src/protocols/s3/` PUT | `If-None-Match` / `If-Match` parsed into the same struct |
| `src/protocols/root/write/` | `kXR_new` maps to `ABSENT` |

**Gate.** `MUTATE_PUBLISH`, unchanged vocabulary. The precondition is evaluated
by the storage, so it sits at step 7 of
[§3.4](#34-the-order-every-new-mutator-obeys) — long after `EROFS`, which is
what keeps a read-only endpoint from leaking whether a target exists via a
`412`-versus-`403` difference.

**Tests** (`tests/test_conditional_publish.py`, `tests/test_vfs_exchange.py`):

| test | asserts |
|---|---|
| success | `If-None-Match: *` PUT over `remote` sends one conditional request and no HEAD (fault-proxy request log), and a second PUT returns `412` |
| success | `renameat2(RENAME_EXCHANGE)` swaps two published trees with no instant at which either name is missing (a reader loop across the exchange never sees `ENOENT`) |
| error | `MATCH_ETAG` against `posix` returns the right answer **and** reports `atomic = 0`; the WebDAV layer answers `412` without claiming atomicity in the response |
| error | `exchange` on `http` returns `ENOTSUP` and is **not** emulated with two renames |
| security-negative | `brix_write_enable off` → `kXR_fsReadOnly` / `403` for every precondition kind, and never `412`, so a reader cannot probe existence through the conditional |
| security-negative | `exchange` across two exports is `EXDEV`, not a confinement escape |
### C7 — Locks in the mutation path

**Today.** The lock record is one xattr on the resource
(`WEBDAV_LOCK_XATTR_KEY`), which means the state is already in the storage layer
and visible to every protocol that can read an xattr. The check machinery lives
in `src/protocols/webdav/lock_check.c`:

```
lock_check.c:64    webdav_check_lock_at()          — one node
lock_check.c:104   webdav_lock_path_ascend()       — target -> export root
lock_check.c:129   webdav_check_locks()            — the ancestor walk
lock_check.c:179   check_locks_descendants()       — the subtree scan
lock_check.c:267   webdav_check_locks_tree()       — ancestors + descendants
```

and is called from **seven** sites, every one of them WebDAV:

| call site | function | request |
|---|---|---|
| `dispatch.c:257` | `webdav_check_locks(r, path, 1)` | the generic mutating-method gate |
| `methods_proppatch.c:415` | `webdav_check_locks(r, path, 1)` | `PROPPATCH` |
| `namespace.c:340` | `webdav_check_locks(r, path, 1)` | `MKCOL` / namespace create |
| `namespace.c:267` | `webdav_check_locks_tree(r, path)` | `DELETE` |
| `copy.c:195` | `webdav_check_locks_tree(r, req->dst_path)` | `COPY` destination |
| `move.c:517` | `webdav_check_locks_tree(r, src_path)` | `MOVE` source |
| `move.c:539` | `webdav_check_locks_tree(r, dst_path)` | `MOVE` destination |

(`copy.c:162` is a doc comment naming the call, not a call — it is easy to
miscount this surface at six or eight, which is why the table is here.)

The subsystem README states the limitation plainly: "the `root://` stream
protocol and S3 REST surface have no notion of WebDAV locks." A deployment that
serves one export over `davs://` and `root://` — the common WLCG shape — has a
lock primitive that stops exactly one of its clients.

**Design.** Hoist the *check* — not the lock state machine, not the XML parsers,
not `LOCK`/`UNLOCK` themselves — into the VFS:

```c
/* src/fs/vfs/vfs_lock_gate.c */
ngx_int_t brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx,
                                    brix_vfs_mutation_op_t op);
```

| element | contract |
|---|---|
| when | immediately after `brix_vfs_require_confined_mutation()`, at step 2 of [§3.4](#34-the-order-every-new-mutator-obeys) |
| reads | `WEBDAV_LOCK_XATTR_KEY` through `brix_vfs_getxattr`, walking target → export root, exactly as `webdav_lock_path_ascend` does today |
| returns | `NGX_OK` — no live foreign lock covers the target; `NGX_ERROR` with `errno = EBUSY` |
| depth scan | the ancestor walk only. The descendant scan stays at the WebDAV edge, because only the collection verbs need it and paying for a subtree scan on every `kXR_write` is not defensible |
| token | `ctx->lock_token` — a new optional borrowed field on `brix_vfs_ctx_t`, filled by the WebDAV edge from the `If:` header and by nothing else |
| `op` | carried for the metric label only; every mutation op is subject to the same check |

**Why it is a second function and not part of the kernel.** The phase-105 kernel
is *pure*: no allocation, no I/O, no backend lookup, no credential selection.
That purity is what lets it run before leaf resolution at every call site, and
it is worth more than the convenience of one call. The lock check reads xattrs;
it cannot live inside the kernel, and it must run *after* it so that `EROFS`
still precedes every other refusal (phase-105 Appendix I.5).

**Token presentation.** A WebDAV client defeats its own lock by presenting the
token in an `If:` header. Other planes have nowhere to put one, so for them a
live lock is an unconditional refusal — which is what a lock is for.

**Expiry interacts with read-only, and the interaction is already solved once.**
Locks carry an expiry, and the read-time cleanup path removes the xattr — a
mutation. `webdav_lock_expired_cleanup` (`lock.c:176`) already declines on a
read-only export:

```c
if (brix_vfs_policy_from_write_enable(conf->common.allow_write)
        != BRIX_VFS_MUTATION_ALLOWED) {
    return;                       /* phase-105: no inline reaping when read-only */
}
```

and the operator-requested startup sweep (`lock_discovery.c:64–80`) is the one
place that passes `BRIX_VFS_MUTATION_ALLOWED` on purpose, with the reasoning in
a comment. So `brix_vfs_require_unlocked` must treat an expired lock as
**absent without removing it**: the reap is an optimisation a writable endpoint
may perform and a read-only one must skip, and correctness cannot depend on it.

**Lock-expiry state, as the gate sees it.**

```
   xattr absent                     -> UNLOCKED   (NGX_OK)
   xattr present, expiry in future,
        token matches ctx->lock_token -> OWNED    (NGX_OK)
   xattr present, expiry in future,
        no/other token                -> HELD     (EBUSY)
   xattr present, expiry in past      -> EXPIRED  (NGX_OK; xattr left in place —
                                         the writable edge may reap it later,
                                         the read-only edge must not)
```

**Configuration.**

| directive | context | argument | default |
|---|---|---|---|
| `brix_lock_enforcement` | `http`, `server`, `location` | `strict` \| `advisory` \| `off` | `strict` |

- `strict` — a live foreign lock refuses the mutation on every plane.
- `advisory` — refuse on WebDAV as today, log-and-allow elsewhere. One release
  of migration cover for a deployment that discovers stale locks.
- `off` — today's behaviour exactly, for a deployment that has decided its
  locks are WebDAV-only.

`nginx -t` negative: `brix_lock_enforcement yes;` →
`[emerg] invalid value "yes" in <conf>:<line>`. Note the shape: nginx's
`ngx_conf_set_enum_slot` does **not** name the offending directive — only the
file and line identify it — where `ngx_conf_set_flag_slot` does (contrast
`brix_durable_publish` in [§3.2](#32-c3-a-durable-publish-barrier)). Verified
against `objs/nginx -t` on 2026-09-03; pinned by
`test_the_new_directive_diagnostics_are_quoted_as_their_setter_emits_them`.

The compatibility risk is real and [§11](#11-compatibility-and-rollout) owns it:
an export carrying stale non-expiring locks would start refusing XRootD writes
on upgrade. Mitigation is a `tools/diag/lock_scan.py` that lists live locks per
export so an operator can look before upgrading — and `advisory` for one release.

**Wire mapping.** This is the item where the existing tables are half right.

| plane | code | status |
|---|---|---|
| root | `EBUSY` → `kXR_FileLocked` | **already present**, `error_mapping.c:61`; the reverse table maps it back to `EAGAIN` at `:116` |
| HTTP/WebDAV | `EBUSY` → `423 Locked` | **missing.** `brix_http_errno_to_status` (`error_mapping.c:198–235`) has no `EBUSY` case, so a locked resource would answer `500` |
| S3 | `EBUSY` → `409 Conflict` + `OperationAborted` | no `423` in the S3 error vocabulary |
| GridFTP | `EBUSY` → `450 Requested file action not taken` | transient by definition, which is correct here |

`kXR_FileLocked` is the right root code — not `kXR_IOError`, and not
`kXR_fsReadOnly`, which would tell a client to stop retrying against a condition
that is temporary by construction.

**Tests** (`tests/test_cross_protocol_locks.py`):

| test | asserts |
|---|---|
| success | `davs://` `LOCK`, then `root://` write → `kXR_FileLocked`; the same write succeeds after `UNLOCK` |
| success | the lock owner writing over `davs://` with the `If:` token still succeeds |
| success | an **expired** lock does not refuse an XRootD write, and the xattr is still present afterwards on a read-only export |
| error | `brix_lock_enforcement advisory` → the `root://` write succeeds and emits one `warn` naming the lock |
| error | `brix_lock_enforcement off` → byte-identical behaviour to today, asserted against a recorded baseline |
| security-negative | a client presenting a **forged** or foreign lock token is refused (`EBUSY`), and the refusal does not echo the real token |
| security-negative | on a read-only export the answer is `kXR_fsReadOnly`, never `kXR_FileLocked` — `EROFS` precedes the lock check, so the lock's existence is not disclosed |
### C8 — The dedup/CAS plane under the gate

**Today.** `brix_cstore_publish_dedup` calls `cs->store->driver->dedup_publish`
directly (`gcas.c:69`) and `brix_gcas_evict_gc` calls `dedup_gc` (`gcas.c:91`).
Both mutate persistent state: on POSIX, `dedup_publish` materialises a hardlink
in the `/.gcas` farm and `dedup_gc` reaps one. Neither passes the mutation
kernel, neither has a vocabulary member, and neither books a metric.

This is *legal* under phase 105 §3.4 — the target is the cache store, which is
service-owned storage, not a client-named export — and phase 105 §0.1 works out
why. But the reasoning lives in a document. What enforces it is nothing.

**What is not the gap.** `dedup_publish` and `dedup_gc` *are* accounted for in
`docs/09-developer-guide/storage-driver-slot-matrix.md`, with per-driver
verdicts like every other cell. Earlier drafts of this document claimed the
matrix omitted them; it does not. The census is complete and the gate is
missing, which is a different and smaller problem than a blind spot in the
census — and worth stating precisely, because "the matrix is wrong" and "the
matrix is right and the code is ungated" call for opposite work.

**Design.** Three small pieces.

**1. `BRIX_VFS_MUTATE_DEDUP`** in the vocabulary (§3.1), with its metric label,
its row in the six-file mirror (§7), and `BRIX_VFS_MUTATE_OP_COUNT` moving with
it.

**2. A service-domain assert.**

```c
/* src/fs/vfs/vfs_policy_domain.c */
ngx_int_t brix_vfs_service_mutation(brix_sd_instance_t *inst,
                                    brix_vfs_mutation_op_t op);
```

| element | contract |
|---|---|
| asserts | `inst->domain != BRIX_VFS_DOMAIN_EXPORT` — the instance is service storage (cache store, stage tier, registry, journal) |
| returns | `NGX_OK`, or `NGX_ERROR` with `errno = EINVAL` |
| why `EINVAL` and not `EROFS` | this is not a policy refusal a client can provoke; it is a **programming error** — service code pointed at export storage. `EROFS` would be a lie and would be caught by the wrong test |
| books | one `brix_vfs_mutation_denied_total{proto,op="dedup",reason="wrong_domain"}` on refusal |
| depends on | C9. `inst->domain` does not exist yet — which is why C9 ships in W1 and C8 in W9 |

`gcas.c` calls it before both slots. It is a two-line change at each of `:69`
and `:91`; the whole item's weight is in the type C9 introduces, not here.

**3. Keep the census generated, not written.** `tools/diag/sd_slot_matrix.py`
already derives its slot list from `sd.h` rather than from a hand-maintained row
list, which is exactly why `dedup_publish`/`dedup_gc` are present today and why
the nine slots [§3.2](#32-slots-the-driver-vtable-gains) adds will appear
automatically. W9's job is to keep it that way: the drift check runs in
`guards.yml`, and the wave's definition of done includes regenerating the matrix
and seeing the diff be exactly the nine new columns.

A census that *can* silently omit a mutation slot is a census that will omit the
next one. This tree's census cannot, and the guard is what keeps that true.

**Gate.** `MUTATE_DEDUP` in the service domain. Note the asymmetry that makes
this item worth doing at all: the *export* mutation kernel refuses with `EROFS`
and discloses nothing, while the *service* assert refuses with `EINVAL` and logs
loudly — because one is a client-facing policy and the other is an internal
invariant, and conflating them is how a service path acquires an export-shaped
refusal that nobody notices.

**Tests** (`tests/c/test_vfs_service_domain.c` via the C object-unit runner,
plus `tests/test_gcas_store_gate.py`):

| test | asserts |
|---|---|
| success | a dedup publish against the cache store passes the assert and books `{op="dedup"}` |
| success | the regenerated slot matrix differs from the committed one by exactly the new columns — `tools/diag/sd_slot_matrix.py --check` |
| error | a `brix_sd_instance_t` carrying `DOMAIN_EXPORT` handed to `brix_vfs_service_mutation` returns `EINVAL` and logs at `crit` |
| security-negative | pointing the CAS store at an export root is refused at `nginx -t` (the directive check, `runtime_server_backend_cache.c` idiom) **and**, if it somehow reaches runtime, by the assert — belt and braces, because the directive check is the one an operator sees and the assert is the one a future refactor trips |

---

### C9 — The service-storage domain becomes typed

**Today.** `check_vfs_seam.py:212` — `_raw_tier3_violation` returns `None` the
moment `"vfs-seam-allow"` appears in the line. The marker is a substring test.
108 markers carry reasons that are careful, consistent, and entirely unread by
anything. On the runtime side there is nothing at all:
`struct brix_sd_instance_s` (`src/fs/backend/sd.h:243–253`) has exactly five
fields — `driver`, `log`, `pool`, `state`, `caps` — and **no domain field**, so
no assert could be written even if one were wanted.

**Design.** [§3.7](#37-the-domain-is-a-type-not-a-sentence)'s
`brix_vfs_domain_t`, a new field on the instance, and two mechanical passes over
the waivers.

**Struct change.** `brix_sd_instance_s` gains

```c
brix_vfs_domain_t   domain;    /* what this storage IS; EXPORT == 0 */
```

set by `brix_sd_instance_create()` (`src/fs/backend/sd_registry.c:113`, assigning
at `:138`) from the creating call site: the tier builder creating a cache store
passes `CACHE`, the OCI registry passes `REGISTRY`, the export path passes
`EXPORT`. `EXPORT` is zero, so an instance created by code that has not been
taught about domains is treated as export storage — the strictest domain, and
therefore the safe default, exactly as `BRIX_VFS_MUTATION_READ_ONLY = 0` is.
This is a struct-field addition to a type the whole tree links against:
**clean rebuild**, not incremental.

**There are nine construction sites, not one — and the `caps` field already
proved it.** `brix_sd_instance_create` is the *pool-allocating* factory; seven
production drivers build an instance themselves because they are called from
tier/registry composition, which has no pool:

| site | driver |
|---|---|
| `src/fs/backend/sd_registry.c:138` | the generic factory |
| `src/fs/backend/posix/sd_posix.c:182` | posix |
| `src/fs/backend/http/sd_http.c:224` | http |
| `src/fs/backend/xroot/sd_xroot.c:346` | xroot |
| `src/fs/backend/xroot/sd_xroot.c:478` | xroot (second factory) |
| `src/fs/backend/cache/sd_cache.c:401` | cache |
| `src/fs/backend/stage/sd_stage.c:480` | stage |
| `src/fs/backend/remote/sd_remote.c:457` | remote |
| `src/fs/backend/frm/sd_frm.c:572` | frm |

plus `src/fs/backend/pblock/sd_pblock_unittest_block.c:69` in the unit tests.
The last time a field was added to this struct the bypassing factories were
missed, and the comment left behind at `sd_http.c:227–232` is the record:
"without this line every cap read through `brix_sd_caps()` came back 0 and
cap-gated branches … silently took their fallback." Three of those factories
still carry a copy of that comment (`sd_remote.c:461`, `sd_xroot.c:482`,
`sd_frm.c:574`) because each rediscovered it independently.

The domain field is safer than `caps` was — a missed site yields `EXPORT`,
which refuses, where a missed `caps` site yielded 0, which silently degraded —
but "safer when forgotten" is not "may be forgotten". W1 touches all nine, and
the wave's error test asserts on an instance built by a **bypassing** factory,
not by `brix_sd_instance_create`, because that is the site class that broke.

**Pass 1 — annotate.** Rewrite all 108 markers to lead with a domain constant:

```c
/* vfs-seam-allow: DOMAIN_CREDENTIAL — delegated proxy staged for the upstream leg */
```

This is a comment-only change with no behavioural content, and it is the wave's
whole risk profile: a mis-assigned domain in pass 1 becomes a false entitlement
in pass 2. The reasons already cluster cleanly ([§2.2](#22-the-enabling-gap)),
so the mapping is mostly transcription — but "mostly" is why the pass gets
reviewed as a security change and not as a comment tidy, and why the wave's
definition of done includes a reviewer signing the domain column, not the diff.

**Pass 2 — enforce.** `check_vfs_seam.py` parses the constant and checks it
against a **directory-prefix** entitlement table. The table is normative in
[Appendix G.1](#g1-the-seven-domains) — it is reproduced there in full with the
durability column phase 108 consumes, and where this summary and Appendix G
disagree, Appendix G is right. Two entries in it are not one of the seven
domains:

| classification | entitled prefixes |
|---|---|
| `NOT_STORAGE` | everywhere, granting nothing — 6 markers that are sockets or `/proc`, not filesystem objects at all ([G.4](#g4-two-classifications-the-seven-domains-do-not-cover)) |
| *(already correct)* | 4 `fstat`-class calls on a VFS-opened fd; annotated, then left alone |

`NOT_STORAGE` exists so that pass 1 is never forced to lie. A probe socket
filed under `CONFIG` would put a false entitlement in the table, which is the
exact failure mode this item's risk row names; the guard therefore reports the
`NOT_STORAGE` count so it cannot quietly become the default classification.

The table lives in the guard, is reviewed like an allowlist, and is deliberately
coarse: **directories, not files**, so it does not re-break on the next move. A
content-scanning guard allowlisted by exact path has broken on a file move in
this tree before, and an archived `_legacy/` copy re-breaks it forever; keying
on directory prefixes is what stops a shard or an archive from invalidating the
table.

The guard fails on: an unknown domain constant, a missing domain, or a domain
the path is not entitled to. It does **not** fail on a waiver whose prose is
thin — the prose is still for humans, and the guard now checks the half a
machine can check.

**Runtime half.** The domain assert (Appendix A.3), which ships in **W1** rather
than here because C8 needs it immediately. It takes the domain as an argument
instead of inferring "service or not" from the instance, so the caller states
its claim and the assert checks it:

```c
ngx_int_t brix_vfs_domain_mutation(const brix_sd_instance_t *inst,
                                   brix_vfs_domain_t domain,
                                   brix_vfs_mutation_op_t op);
```

`EXPORT` routes to the phase-105 kernel. Every other domain asserts
`inst->domain == domain` and books the metric. The compile-time half (the guard)
and the runtime half (the assert) check the same claim from two directions,
which is the pattern the mutation gate already uses and the reason it caught
real defects.

**What this is not.** It is not a permission system. A domain is a statement
about *what the storage is*, not about who may touch it. C9 makes that statement
checkable; it grants nothing, and no code path becomes reachable because of it.

**Tests:**

| test | asserts |
|---|---|
| success | every one of the 108 markers carries a domain the guard accepts — `tools/ci/check_vfs_seam.py` green with the table enabled |
| success | an instance created by the tier builder for a cache store reports `DOMAIN_CACHE`; one created for an export reports `DOMAIN_EXPORT` |
| error | a waiver with `DOMAIN_REGISTRY` in `src/fs/cache/` fails the guard, naming the file, the domain and the entitled set |
| error | a waiver with no domain constant fails the guard (the substring alone is no longer enough) |
| security-negative | `brix_vfs_domain_mutation(inst, DOMAIN_CACHE, …)` on an instance whose `domain` is `EXPORT` returns `EINVAL` — a service path cannot launder an export mutation through a domain claim |
| security-negative | a zero-initialised instance is `EXPORT`, so the untaught call site gets the strict domain, not a permissive one |

---

## 5. Protocol behavior

The refusal each plane emits for each new condition. Where a mapping already
exists, it is reused; where one is invented, it is named here so the tests pin
it once.

### 5.0 The two mapping tables, and what changes in each

Both live in `src/core/compat/error_mapping.c` and both are read-only to this
phase except for the rows named here.

**`brix_kxr_from_errno` (`error_mapping.c:35–74`) — no change required.** Every
errno this phase raises is already mapped:

| errno | kXR code | line |
|---|---|---|
| `EROFS` | `kXR_fsReadOnly` | `:48` |
| `EBUSY` | `kXR_FileLocked` | `:61` |
| `EEXIST` | `kXR_ItExists` | present |
| `ENOSPC` | `kXR_NoSpace` | present |
| `ENOTSUP` | `kXR_Unsupported` | present |

The reverse table maps `kXR_FileLocked` back to `EAGAIN` (`:116`), which is
correct for a client-side retry and is left alone.

**`brix_http_errno_to_status` (`error_mapping.c:198–235`) — two rows added.**
Today the switch handles `ENOENT`/`ENOTDIR` → 404, the
`EACCES`/`EPERM`/`EROFS`/`EXDEV`/`ELOOP` group → 403, `ENOSPC`/`EDQUOT` → 507,
`EEXIST`/`ENOTEMPTY` → 409, `ENAMETOOLONG` → 414, and everything else → **500**.
It has no `EBUSY` case and no `ECANCELED` case, so both of this phase's new
conditions would surface to an HTTP client as an internal server error:

| errno | today | becomes | raised by |
|---|---|---|---|
| `EBUSY` | 500 | **423 Locked** | C7, a live foreign lock |
| `ECANCELED` | 500 | **412 Precondition Failed** | C6, a `MATCH_*` precondition that failed |

`ENOTSUP` deliberately stays at 500 in this phase: changing it to 501 would
alter the status of existing unsupported-operation paths across every HTTP
plane, which is a behavioural change this phase has no reason to make and no
test coverage to justify. It is noted here so the next reader does not have to
re-derive that it was considered.

The two additions are the *entire* wire-format delta of phase 107. Every other
row in §5.1–§5.5 is an existing mapping being reached from a new place.

### 5.1 XRootD / root plane

| Condition | Wire result | Notes |
|---|---|---|
| out-of-order write, spill unavailable | `kXR_NoSpace` | never `kXR_IOError`: the client can retry serially |
| prestage on a read-only endpoint | `kXR_fsReadOnly` | closes the phase-105 §F.1 `kXR_wmode`-only gap |
| prestage, no `recall` slot and no `prepare_command` | `kXR_Unsupported` | today: silent success |
| `kXR_QPrep` | per-path status from residency | unchanged shape |
| evict, not the record's owner | `kXR_NotAuthorized` | mirrors the FRM-1 cancel rule |
| mutation against a live foreign lock | `kXR_FileLocked` | `strict` mode only; mapping already present at `error_mapping.c:61` |
| `oss.asize` beyond free space | `kXR_NoSpace` at open | today: fails mid-transfer |
| publish precondition failed (ABSENT) | `kXR_ItExists` | via the existing `EEXIST` row |
| publish precondition failed (MATCH_*) | *not offered on this plane* | no XRootD code means "the object changed under you"; see [§5.5](#55-the-one-mapping-with-no-good-answer) |
| exchange on a driver without it | `kXR_Unsupported` | never emulated |

### 5.2 WebDAV / HTTP plane

| Condition | Status |
|---|---|
| live foreign lock | `423 Locked` — the new `EBUSY` row in §5.0. WebDAV already answered 423 from its own edge check; this makes the *same* status reachable when the refusal comes from the VFS gate instead |
| precondition failed | `412 Precondition Failed` — the new `ECANCELED` row in §5.0 |
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

**The arithmetic.** The matrix at `480ded2e4` is **54 slots × 12 drivers = 648
cells, 379 implemented, zero open gaps**. [§3.2](#32-slots-the-driver-vtable-gains)
adds six verbs which expand to **nine** vtable members —
`reserve`, `unlink_many`, `unlink_many_cred`, `recall_cred`, `evict`,
`evict_cred`, `sync_publish`, `exchange`, `exchange_cred` — so the matrix becomes
**63 × 12 = 756 cells**. It is 63, not 60: the four `_cred` twins are separate
members with separate verdicts, and collapsing them in the count is how a
confused-deputy gap hides.

Expected implemented cells after the phase, from the per-driver tables in
[§4](#4-per-item-design):

| slot | ✔ | verdict cells | verdicts used |
|---|---|---|---|
| `reserve` | 6 | 6 | `dec` ×2, `np` ×2, `ro`, `syn` |
| `unlink_many` | 3 | 9 | `np` ×2, `seam` ×2, `dec` ×2, `flat`, `syn`, `ro` |
| `unlink_many_cred` | 2 | 10 | as above + `nil` where the leaf has no cred plane |
| `recall_cred` | 5 | 7 | `flat` ×3, `walk` ×2, `syn`, `ro` |
| `evict` | 6 | 6 | `flat` ×2, `ro` ×3, `syn` |
| `evict_cred` | 3 | 9 | as above + `nil` |
| `sync_publish` | 3 | 9 | `np` ×4, `dec` ×2, `flat`, `syn`, `ro` |
| `exchange` | 3 | 9 | `np` ×4, `dec` ×2, `flat`, `syn`, `ro` |
| `exchange_cred` | 2 | 10 | as above + `nil` |

The number that matters is not the total; it is that **no cell is blank**. The
drift check fails on a blank cell exactly as it fails on a stale verdict.

**The census stays generated.** `tools/diag/sd_slot_matrix.py` (156 lines)
already derives its slot list from `struct brix_sd_driver_s` in `sd.h` rather
than from a hand-maintained row list — which is why `dedup_publish` and
`dedup_gc` are present in the published matrix today, and why the nine new
members will appear without anyone adding a row. W9's job is to keep that
property, not to establish it. The wave's definition of done includes running
the regenerator and confirming the diff is **exactly** the nine new columns and
their verdicts.

**`check_sd_driver_conformance.py`.** Its `_PARITY_BASE` (15 ops, expanding to
`PARITY_OPS` = 30 with the `_cred` twins) grows by the new slots, and
`_decorator_parity` (`:188`) then enforces the rule that burned the tree once
already: `cache` and `stage` must relay a slot **both or neither**, because a
slot relayed by one and not the other silently changes behaviour depending on
which decorator an operator configured.

One deliberate exclusion, recorded in the script rather than only here:
`sync_publish` is a **leaf** verb. It flushes a real directory on a real
filesystem, and a decorator that relayed it would fsync the wrong one. It joins
the byte plane's `dec` verdict, and the parity rule for it reads "neither", not
"both".

---

## 7. Observability

### 7.1 The six-file mirror, and why it is one commit

The mutation vocabulary is mirrored across six files with a compile-time
equality check at the end. Growing it from 11 to 15 touches every one of them,
and the build breaks if any is missed — which is the design, not an
inconvenience:

| # | file:line | what moves |
|---|---|---|
| 1 | `src/observability/metrics/metrics.h:414` | the SHM cube `vfs_mutation_denied_total[BRIX_PROTO_COUNT][BRIX_VFS_MUTATE_OP_METRIC_COUNT]` — sized by the constant, so it grows automatically once the constant does; **but the SHM layout changes**, so this is a clean-rebuild + fleet-restart item, not a hot reload |
| 2 | `src/observability/metrics/unified_record.c:354–383` | the recorder `brix_metric_vfs_mutation_denied()` bounds-check |
| 3 | `src/observability/metrics/unified_export.c:140–171` | `unified_emit_vfs_mutation_denied()`, registered in the emit list at `:435` |
| 4 | `src/observability/metrics/unified.c:163` | `brix_unified_vfs_mutate_op_names[]` — four new string literals, in enum order |
| 5 | `src/observability/metrics/unified.h:275` | `#define BRIX_VFS_MUTATE_OP_METRIC_COUNT 11` → `15` |
| 6 | `src/fs/vfs/vfs_policy.c:33` | the `_Static_assert` that fails the build if 4 and 5 disagree with `brix_vfs_mutation_op_t` |

The neighbouring `BRIX_CRED_MODE_METRIC_COUNT` / `brix_cred_fail_t` family
(`unified.c:158`) is the precedent: a bounded enum dimension, a name table, and
an assert. This phase adds nothing new to the pattern; it exercises it twice
(once here, once when [phase 108](phase-108-vfs-consolidation.md) appends
`CREDENTIAL` and takes the count to 16).

### 7.2 The existing family gains values, not cardinality

`brix_vfs_mutation_denied_total{proto,op,reason="read_only"}` gains four `op`
values — `stage`, `evict`, `lock`, `dedup`. No new metric family, no unbounded
label: the `reason` dimension stays the literal `"read_only"` because `EROFS` is
still the sole VFS read-only mutation result, exactly as the emitter's comment
records.

C8's service-domain refusal is the one exception and it is deliberate: it books
`reason="wrong_domain"`, which takes `reason` from one value to two. Both are
literals chosen in the emitter, so the dimension stays bounded and the emitter's
nested loop grows by one literal, not by a runtime string.

### 7.3 New families

Declared in the tree's own style — a `# HELP`/`# TYPE` pair per family, one
`mw_printf` loop over an SHM cube, low-cardinality labels only (INVARIANT #8):

| family | type | labels | question it answers |
|---|---|---|---|
| `brix_vfs_spill_bytes_total` | counter | `proto` | how much scratch is C1 costing me |
| `brix_vfs_spill_active` | gauge | *(none)* | how many writers are spilling right now |
| `brix_vfs_spill_refused_total` | counter | `proto` | how often `spill_max`/`ENOSPC` refused an upload |
| `brix_vfs_recall_total` | counter | `result` ∈ {`queued`,`joined`,`online`,`error`} | prestage volume and join rate — today a tape recall is a fork with no telemetry at all |
| `brix_vfs_evict_bytes_total` | counter | `driver` | what eviction actually reclaims |
| `brix_vfs_precond_failed_total` | counter | `kind` ∈ {`absent`,`etag`,`meta`} | a stale client tag or a genuine write conflict — distinguishing those is the operator's job, and they cannot do it blind |
| `brix_vfs_precond_advisory_total` | counter | `driver` | how often a `412` was answered **without** `CAP_PRECOND`, i.e. non-atomically |
| `brix_vfs_lock_refused_total` | counter | `proto` | whether flipping `brix_lock_enforcement` to `strict` will break anything — the number that makes `advisory` mode useful rather than decorative |
| `brix_vfs_bulk_delete_keys_total` | counter | `driver` | keys removed via the batch path, against `..._batches_total` for the amplification ratio |
| `brix_vfs_durable_publish_total` | counter | `result` ∈ {`ok`,`skipped`,`error`} | that the C3 barrier is actually firing, and how often it fails |

Every `driver` label is bounded by the twelve-row `BRIX_FS_DRIVER_LIST`; every
`proto` label by `BRIX_PROTO_COUNT`; every `result`/`kind` by a literal set
chosen in the emitter. Nothing here can be widened by a client.

### 7.4 Access log

- A batch delete books **one** line carrying the key count, not N lines. The
  op-counter rule in [§4/C4](#c4--bulk-namespace-delete) and the log rule are
  the same rule.
- A spilling writer books its high-water mark on the commit line, so the cost of
  a single reordered upload is attributable after the fact without a gauge
  scrape at the right moment.

### 7.5 C9's one label

The mutation counter gains a `domain` label, bounded to the seven values of
[§3.7](#37-the-domain-is-a-type-not-a-sentence). This is the one place a
low-cardinality label earns its keep: it turns "something wrote outside the
export" from an audit question into a graph, and it is the signal
[phase 108](phase-108-vfs-consolidation.md) measures its consolidations against
— a consolidation that moves a write from one domain to another should show up
as a shift between two series, and if it does not, the consolidation did not do
what it claimed.

---

## 8. Implementation waves

Each wave lands with success, error and security-negative tests (three per
change, per the standing rule). No wave leaves a protocol path depending on an
edge check for a condition the VFS now owns.

Every wave carries a **Files** table. New `src/` `.c` files go in the repo-root
`./config` source list (guard `tools/ci/check_config_coverage.py`) and require a
re-`./configure --add-module=$REPO`; every wave's last step is
`objs/nginx -t`. Files marked **ABI** require `rm -rf objs && ./configure &&
make`, never an incremental build.

### W0 — Freeze the contract with failing tests

- [x] Pin today's behaviour for every one of the eight: an out-of-order write to
      an `http` export fails with `ESPIPE` (`sd_http_write.c:166`) and to a
      `remote` export with `EINVAL` (`vfs_writer.c:176`); prepare-evict returns
      success and does nothing (`prepare.c:428`); no publish flushes a parent
      directory, and `staged_file.c:319`'s `fsync(rootfd)` returns `EBADF`
      because the fd is `O_PATH`; a 1 000-key `DeleteObjects` issues 1 000
      backend deletes; `oss.asize` reaches no driver; `sd_remote` noreplace is a
      HEAD then a PUT; an XRootD write overwrites a WebDAV-locked file; `gcas`
      publishes with no gate. **These tests pass now and must keep passing,
      inverted, at the end.** *(As landed: `tests/test_vfs_mutation_baseline.py`
      exists and each frozen behaviour was inverted by the wave that changed
      it, so the file now pins the NEW contracts.)*
- [x] Extend the spy driver to the nine new members, generated from
      `struct brix_sd_driver_s` so the generation is by construction. *(As
      landed: realized inside `tests/c/test_vfs_read_only_spy.c` rather than a
      separate `test_sd_spy_driver.c` — the ten phase-107 members (`reserve`,
      `unlink_many`, `sync_publish`, `exchange`, `recall`, `evict` and the four
      `_cred` twins) are counted sinks in both `spy_mutations()` and
      `spy_sinks()`, so any verb leaking into a new slot trips the existing
      zero-sink assertions; `exchange` also gained a full OPS-matrix row —
      POSIX arm, driver slot, `_cred` twin × success/error/security-neg.)*
- [x] Add the ordering assertions (§3.4) as reusable test helpers: policy before
      lock before leaf before capability before credential before backend before
      invalidation. *(As landed: `tests/c/vfs_order_spy.h` — C, not the
      table's `tests/brixtest/ordering.py`, because the stages are only
      observable from inside a link-time spy harness. `ord_hit`/`ord_reset`/
      `ord_assert_before`/`ord_assert_absent`/`ord_assert_count` over a
      7-stage tape; wired into `tests/c/test_vfs_new_mutator_gate.c`
      (registered in `SPECS` as `vfs_new_mutator_gate`), which links the real
      `vfs_recall.o` + `vfs_unlink_many.o` + `vfs_unlink.o` + `vfs_policy.o`
      and proves policy-first by exclusion: a refused tape holds ONLY the
      policy stage.)*
- [x] Pin the metric mirror's compile-time assert by adding a member and proving
      the build fails until `unified.h:275` moves. *(Performed 2026-09-02: a
      temporary `PROOF_TEMP` member made `vfs_policy.c`'s `_Static_assert`
      fire; reverted clean, net-zero diff.)*

| file | change |
|---|---|
| `tests/test_vfs_mutation_baseline.py` | new — the eight frozen behaviours |
| `tests/c/test_sd_spy_driver.c` | extend to the nine members *(as landed: extended `tests/c/test_vfs_read_only_spy.c` instead — same harness, no second spy)* |
| `tests/cmdscripts/c_object_units.py` | register the new object units in `SPECS` (they are parametrized from the table, so a unit not listed never runs) |
| `tests/brixtest/ordering.py` | new — the §3.4 ordering assertion helpers *(as landed: `tests/c/vfs_order_spy.h` + `tests/c/test_vfs_new_mutator_gate.c`)* |

**Landed notes (2026-09-02).** Two as-built deviations, both toward the
existing K.4 harness rather than new parallel machinery:

* **One spy, not two.** The nine new vtable members went into the existing
  `test_vfs_read_only_spy.c` spy driver as counted sinks (plus the four
  `_cred` twins, ten counters total — a `_cred` sink decrements its plain
  counter so the exactly-one-sink matrix assertions keep holding). A separate
  `test_sd_spy_driver.c` would have duplicated the whole cross-TU stub
  closure for no additional proof.
* **Ordering is a C header, not a Python helper.** The §3.4 stage order
  (policy → lock → leaf → capability → credential → backend → invalidation)
  is only observable where the stages are — at link-time stubs. So the
  helpers are `tests/c/vfs_order_spy.h` (header-only tape, included by
  exactly one TU per binary), first wired in `test_vfs_new_mutator_gate.c`,
  which covers the three verbs that need the four-TU link closure
  (`recall`/`evict`/`delete_many`); `exchange` ordering rides the old
  harness because `brix_vfs_exchange` lives in the already-linked
  `vfs_rename.o`. Policy-first is proven **by exclusion**: the kernel books
  no observable call on ALLOWED, so a refused tape holding only
  `ORD_POLICY` — with LOCK/LEAF/CAP/CRED/BACKEND/INVALIDATE all asserted
  absent — is the proof.

### W1 — Vocabulary and kernel extension

- [x] Append `STAGE`, `EVICT`, `LOCK`, `DEDUP` to `brix_vfs_mutation_op_t`;
      move `BRIX_VFS_MUTATE_OP_METRIC_COUNT` to 15; extend the label table.
      ([Phase 108](phase-108-vfs-consolidation.md) appends `CREDENTIAL` and
      takes it to 16.)
- [x] Add `brix_vfs_require_unlocked()` next to the kernel — separate function,
      kernel stays pure. *(Plus the `_at` alternate-target form for the
      two-name mutations, and the `brix_vfs_lock_enforcement_t` mode enum with
      STRICT as zero.)*
- [x] Add `brix_vfs_domain_t` (§3.7), the `domain` field on
      `brix_sd_instance_s`, and `brix_vfs_domain_mutation()` (A.3) — the type is
      trivial and C8 needs the assert now; W9 is the two passes that make the
      claim checkable. Route `gcas.c` through it (C8, items 1–2).
      *(`brix_vfs_domain_mutation` at `vfs_policy_domain.c:42`; `domain` field
      at `sd.h:131`.)*
- [x] Confirm `sd_slot_matrix.py` stays header-derived; regenerate. *(Matrix
      regenerated and drift-checked by `tools/diag/sd_slot_matrix.py`.)*

| file | change |
|---|---|
| `src/fs/vfs/vfs_policy.h` | +4 enum members, +`brix_vfs_domain_t`, +`brix_vfs_require_unlocked` decl |
| `src/fs/vfs/vfs_policy.c:33` | the `_Static_assert` moves with the count |
| `src/fs/vfs/vfs_lock_gate.c` | **new** — `brix_vfs_require_unlocked()` (stub until W8) |
| `src/fs/vfs/vfs_policy_domain.c` | **new** — `brix_vfs_domain_mutation()`, `brix_vfs_service_mutation()` |
| `src/fs/backend/sd.h:243–253` | **ABI** — `domain` field on `brix_sd_instance_s` |
| `src/fs/backend/sd_registry.c:113,138` | set it in `brix_sd_instance_create()` |
| `src/fs/backend/{posix,http,xroot,cache,stage,remote,frm}/` | the seven bypassing factories (C9 table) — one line each |
| `src/observability/metrics/{metrics.h,unified.h,unified.c,unified_record.c,unified_export.c}` | the six-file mirror (§7.1) |
| `src/fs/cache/gcas.c:69,91` | route through `brix_vfs_service_mutation()` |
| `./config` | +2 source files |

**Landed notes (2026-09-02).** The wave landed as specified; two additions
beyond the table:

* `brix_vfs_require_unlocked_at()` — the alternate-target form the two-name
  mutations (rename/copy/exchange destination) need, same contract and errno
  mapping; the table only anticipated the single-target form.
* `brix_vfs_lock_enforcement_t` (STRICT=0 / ADVISORY / OFF) rode in with the
  gate declaration rather than waiting for W8, because the enum's zero-value
  choice — an unregistered export fails toward enforcement — is a contract
  the stub already had to honour.

### W2 — C1 spill writer

- [x] Add the spill mode to `brix_vfs_writer_t` with entry on declaration or on
      first out-of-order write; the state machine in [§4/C1](#c1--out-of-order-writes-on-staged-only-backends).
- [x] Config: `brix_vfs_spill_path`, `brix_vfs_spill_max`, with the three
      `nginx -t` negatives from C1.
- [x] Drain-on-commit, unlink-on-abort, and the owned-temp reclaim path.
- [x] Cap the doubling heap buffers in `sd_http_staged_write` and the S3
      single-PUT arm — the memory-safety half, independent of ordering.
- [x] `ENOSPC` → `kXR_NoSpace` / 507 mappings.
- [x] Prove: an out-of-order write sequence over `http` and `remote` produces a
      byte-identical object; the spill is created **after** the gate, never
      before.

| file | change |
|---|---|
| `src/fs/vfs/vfs_writer.c:48,156–186,188,323` | mode dispatch; the `EINVAL` refusal becomes `spill_enter` |
| `src/fs/vfs/vfs_writer_spill.c` | **new** — the spill mode |
| `src/fs/vfs/vfs_writer_internal.h` | **new** — shared writer internals (600-LOC ceiling) |
| `src/core/config/tier_directives.h` | +2 directive rows |
| `src/fs/backend/http/sd_http_write.c:162–190` | cap the doubling buffer |
| `src/fs/backend/s3/sd_s3_write.c` | cap the single-PUT buffer |
| `./config` | +1 source file |

### W3 — C3 durable publish

- [x] Add the `sync_publish` slot and the POSIX implementation over a **confined
      parent fd opened `O_RDONLY|O_DIRECTORY`**, not `O_PATH` — that distinction
      is the whole defect. (`brix_publish_dirsync` in `staged_file.c`; slot on
      posix/pblock/frm + cache/stage relays.)
- [x] Replace the inert `fsync(rootfd)` at `staged_file.c:319`; do not
      supplement it. (The unit's failing-first case pins the old call as EBADF.
      Bonus defect caught by the test: the barrier's first cut re-stripped the
      root off an already-relative `final_rel` — strip_root keeps its leading
      `/` — and EINVAL'd every publish; fixed to accept both path forms.)
- [x] Call the slot after `staged_commit` and after `rename`; propagate failure.
      (Both `vfs_staged.c` commit arms + both `vfs_rename.c` arms; the three
      protocol sites verified to inherit via `brix_staged_commit`.)
- [x] `brix_durable_publish` directive, default `on`, documented in
      `directives.md`; registered per export only when OFF so an absent
      registry entry fails durable.
- [x] Verdicts for all nine non-implementing cells; matrix regenerated to
      55×12 = 660 cells, 384 implemented, 0 open gaps.

| file | change |
|---|---|
| `src/fs/backend/sd.h` | +`sync_publish` slot |
| `src/fs/backend/posix/sd_posix_ns.c:497,499` | implement + call |
| `src/core/compat/staged_file.c:317–319` | replace the `O_PATH` fsync |
| `src/fs/vfs/vfs_staged.c:369–372` | call after both commit arms |
| `src/fs/vfs/vfs_rename.c` | call after a publishing rename |
| `src/core/compat/namespace_ops_copy.c:252`, `src/protocols/webdav/tpc_pull.c:282`, `src/protocols/root/write/chkpoint_recover.c:106` | inherit the barrier via the two shared functions — verify, do not duplicate |
| `src/core/config/tier_directives.h` | +1 directive row |
| `docs/09-developer-guide/storage-driver-slot-matrix.md` | regenerate |

### W4 — C5 reserve

- [x] Add the `reserve` slot; implemented object-keyed on `posix`
      (`fallocate(FALLOC_FL_KEEP_SIZE)` + `ftruncate`-to-`st_size` release of
      the partial allocation a non-atomic failed fallocate leaves), `pblock`
      (F5 quota + statvfs admission, moved to `pblock_quota.c`), `block`
      (extent-capacity admit), and `cache`/`stage` parity slots. On `remote`,
      `xroot` and `frm` the declaration rides `staged_open(declared_size)`
      instead — parts sizing / `oss.asize` forwarding / posix-shell reserve —
      recorded as `sup` in the slot matrix (56×12 = 672 cells, 389
      implemented, 0 gaps).
- [x] Plumbed `oss.asize` through the open path, `Content-Length` on PUT,
      `ALLO` on GridFTP; carrier is the scalar `off_t declared_size` on
      `brix_vfs_ctx_t`, plus `brix_vfs_fd_reserve` for bare fds and the
      demote path declaring the hot object's exact size to the cold tier.
- [x] `remote`: `expected_size` reaches `sd_s3_open_write`, and
      `sd_remote_part_size` = `max(16 MiB, ceil(size/10000))` MiB-aligned
      (16 MiB floor keeps the pre-C5 default; the doc's 5 MiB floor would have
      REDUCED the default). Legality — floor, alignment, ≤10,000 parts, 5 TB —
      pinned hermetically in `tests/c/test_sd_remote_part_size.c`; a live
      200 GB declaration commits byte-exact in `test_vfs_reserve.py`.
      (En route this test exposed a pre-existing S3-origin defect: all three
      async write completions — buffered PUT, streaming chunk, CompleteMPU —
      were missing the `r->main->count--` balance, so every S3 write silently
      poisoned its keepalive connection; fixed in `put_aio.c`/`put_chunk.c`/
      `multipart_complete_body.c`, pinned by
      `tests/test_s3_keepalive_after_write.py` on ONE raw socket.)
- [x] `ENOSPC`/`EDQUOT` fail the open — mapped to `kXR_NoSpace` in
      `brix_open_error_details()` (they fell to the `kXR_IOError` default);
      every other reserve failure is advisory (`NGX_LOG_INFO`, open
      proceeds). Live battery: 7/7 in `tests/test_vfs_reserve.py` incl. the
      RO-front EROFS-before-reserve ordering and the lying-declaration
      quota-release row.

| file | change |
|---|---|
| `src/fs/backend/sd.h` | +`reserve` slot |
| `src/fs/backend/{posix,pblock,block,frm,xroot,remote}/…` | six implementations |
| `src/fs/backend/remote/sd_remote_write.c:37,66` | part-size derivation; stop passing `-1` |
| `src/fs/vfs/vfs_open.c` | call `reserve` once after a create-open |
| `src/protocols/root/path/opaque_validate.c:235–240` | carry the parsed value instead of discarding it |
| `src/protocols/webdav/put_setup.c`, `src/protocols/gridftp/ev/ftp_ev_cmd.c` | edge plumbing |

### W5 — C4 bulk delete

- [x] Add `unlink_many` / `_cred` and `BRIX_SD_CAP_BULK_DELETE` (`1u << 17`);
      implement on `remote`, `pblock`, `ceph`.
- [x] VFS chunker; **per-level** batching, because every driver but `mirage`
      advertises `CAP_DIRS` (the trap in [§4/C4](#c4--bulk-namespace-delete)).
- [x] Rewire `brix_vfs_driver_rmtree` and the S3 `DeleteObjects` handler.
- [x] One gate check and one metric observation per batch.

**Landed notes (2026-09-01).** Four decisions taken during the wave, each
provoked by a live failure in `tests/test_vfs_rmtree.py`:

* **Recursive WebDAV DELETE is `Depth: infinity` opt-in.** RFC 4918 §9.6.1
  makes a collection DELETE recursive, but this front's long-pinned default is
  stricter (require-empty → 409, pinned by
  `test_webdav_delete_lock_security.py`), and silently widening DELETE's blast
  radius would have been a security regression dressed as a spec fix. A client
  sends an explicit `Depth: infinity` to get the RFC walk
  (`webdav_handle_delete`); the pinned 409 default is byte-for-byte unchanged.
* **The export root is a confinement anchor, not a deletable object.** A
  recursive delete whose logical path is `""`/`"/"` is refused in
  `brix_vfs_delete` with `EPERM` (no credential makes it legal — deliberately
  not `EACCES`), mapped to 403 by the WebDAV front. The guard sits AFTER the
  policy kernel, so a read-only export still answers EROFS-first
  (INVARIANT #12).
* **`brix_sd_supports()` returns `NGX_OK` on support** — the dispatch gate
  must test `!= NGX_OK`, never `!`. The inverted form sent every
  `CAP_BULK_DELETE` leaf down the classic walk.
* **`brix_unlink_beneath` now normalizes a trailing slash** (shared
  `beneath_strip_trailing_slash` helper with `brix_mkdir_beneath`): an S3
  folder marker is addressed as `key/`, and the parent/leaf split died with
  `EINVAL` on the empty leaf.

File-size/complexity fallout: the vfs recorders moved to
`unified_record_vfs.c`, the mutation declarations to `vfs_mutate.h` (the
phase-79 `vfs_ops.h` pattern — W6–W8 declarations land there), and
`sd_s3_delete_many` / `brix_vfs_delete_many_via_driver` each gave up a helper
(`s3_batch_post`, `delete_many_dispatch`). Slot matrix regenerated: 58 slots ×
12 drivers, 399 implemented, 0 open gaps.

| file | change |
|---|---|
| `src/fs/backend/sd_batch_types.h` | **new** — the result vector |
| `src/fs/backend/sd.h:95–122` | +`CAP_BULK_DELETE`, +2 slots |
| `src/fs/vfs/vfs_unlink.c:43` | level-batching walk |
| `src/fs/vfs/vfs_unlink_many.c` | **new** — `brix_vfs_delete_many()` |
| `src/protocols/s3/delete_objects.c:67` | one batch call in place of the per-key loop |
| `./config` | +1 source file |

### W6 — C2 prestage and evict

- [x] `brix_vfs_recall` (decorator-**descending**) and `brix_vfs_evict`
      (**top**-dispatching); `recall_cred`; the `evict` slot.
- [x] Rewire `kXR_prepare` stage/evict/cancel and `kXR_QPrep`; keep
      `brix_prepare_command` as the no-slot fallback; advisor note.
- [x] Ownership via `brix_stage_request_owner_check()`, mirroring FRM-1.
- [x] The record-before-driver-call lifecycle, including record deletion on a
      synchronous driver failure so no orphan reqid is pollable.

**Landed notes (2026-09-01).** The decisions taken during the wave, and one
regression this wave introduced elsewhere and had to repair in the driver:

* **`evict` dispatches at the TOP; the `stage`/`cache` decorators RELAY with
  their own semantics.** `cache` invalidates its copy and relays; `stage`
  answers `EBUSY` while the path has a dirty (uncommitted) staged copy and
  relays otherwise (`sd_stage.c:459`) — dropping an online copy that still
  backs unflushed writes would be data loss wearing an admin verb.
* **The §C2-vs-`sd.h` reconciliation: posix/ceph get NO `evict`.** For a flat
  driver the online copy is the ONLY copy — evicting there is a delete wearing
  a different verb, so the slot stays absent and the top-level dispatch
  answers `ENOTSUP` (the rationale now lives in the slot comment,
  `sd.h:452–462`). `pblock` instead DEMOTES the catalog row to NEARLINE
  (extents freed, row kept); `xroot` forwards the verb upstream as
  `kXR_prepare(kXR_evict)`; `frm` purges the online buffer and reports the
  residency-probed size as bytes reclaimed.
* **`frm` has no `evict_cred` twin BY DESIGN** (`sd_frm.c:343`): every MSS
  verb runs as the service — there is no per-user execution leg to carry a
  credential into, and the `*_maybe_cred` forwarder refuses per-user evicts
  in DENY mode. `pblock`'s twin gates `W_OK` against catalog ownership and
  then delegates to the plain slot.
* **`brix_vfs_nearline_export()` (vfs_stat.c:351) exists** so the wire arms
  ask ONE question ("can this export ever have an offline copy?") instead of
  re-walking driver caps: `qprep_status_for_path` is residency-FIRST only on
  nearline exports, and `prepare_recall`'s `kXR_Unsupported` refusal keys on
  it rather than on slot absence alone.
* **`cancel` now marks CANCELLED and KEEPS the record** (was: delete). The
  record survives for status queries (QPrep maps it to 'M'), and the JOIN in
  `brix_prepare_recall_one` had to grow the matching filter: `find_by_path`
  matches ANY non-free slot, so a retired (FAILED/CANCELLED) record must
  never absorb a fresh prepare — the fresh request creates a NEW reqid and
  retries the driver (`prepare_recall.c:157–164`).
* **`cmd_count` vs `stage_count`** (`prepare.c:305–319`): a path the driver
  recall slot accepted never reaches the fork/exec `brix_prepare_command`
  fallback; only the ENOTSUP leftovers do, so the two tallies are distinct
  and the fallback fires on `cmd_count`, not `stage_count`.
* **The advisor note lives in server worker-init**
  (`process_server_init.c:169`, `brix_init_server_stage_advisor`), NOT in the
  phase-93 `config_advisor*.c` family the plan named — that advisor is the
  client-side `-t` surface; this warning needs the built driver chain, which
  exists only after the registry builds it. The warned shape ("nearline but
  no tier implements recall") is UNCONSTRUCTIBLE from a live config today —
  every shipped nearline driver implements the slot — so the probe's truth
  table is proven by the `vfs_nearline_probe` C object unit (synthetic
  chains, real `vfs_recall.o`; registered in `cmdscripts/c_object_units.py`
  and parametrized into the pytest table).
* **CCN fallout:** `prepare.c` gave up `prepare_scan_init` and
  `prepare_next_line`; the frm driver TU hit the 600-line cap and split its
  staged-write family into `sd_frm_staged.c`.
* **Port-ladder rebase:** +3 shared lifecycle slots (the writable frm
  subject, its read-only twin, the posix ownership subject; one serial
  `lc-prepare-recall` xdist group), `LIFECYCLE_SHARED_WIDTH` 956 → 959 with
  the running-sum repair through every downstream offset
  (`port_ladder_offsets.py`).
* **The `frm_env` master-environ snapshot — a regression this wave created
  and fixed at the driver.** W6's cycle-keyed backend memo
  (`vfs_backend_registry.c`: a chain built under an earlier cycle holds that
  cycle's dead log pointer) makes every worker REBUILD its chain — after
  `ngx_worker_process_init` has replaced `environ` with the `env`-directive
  allowlist. The frm dialect probe read `getenv("BRIX_FRM_STAGECMD")` at
  build time, so the rebuild silently degraded every exec/lib dialect to the
  built-in stub (`test_frm_scratch.py` went 5-red with `[3011] file not
  found` while this wave's own tests stayed green). The fix belongs in the
  driver, not in per-template `env` directives: `sd_frm_adapter.c:frm_env()`
  snapshots the six dialect contract vars on every successful read — warmed
  in the master during config parse, inherited by fork, re-warmed on reload —
  so the documented "read from the MASTER environment" contract survives the
  worker-environ wipe. The test template keeps an `env BRIX_FRM_STAGECMD;`
  belt to pin that both mechanisms coexist.

| file | change |
|---|---|
| `src/fs/vfs/vfs_recall.c` | **new** — both verbs + the `brix_vfs_chain_nearline_unstageable` probe |
| `src/fs/vfs/vfs_stat.c:351` | +`brix_vfs_nearline_export()` |
| `src/fs/backend/sd.h` | +`recall_cred`, +`evict`, +`evict_cred` (+ the posix/ceph absence rationale) |
| `src/fs/backend/{pblock,http,xroot,remote,frm,cache,stage}/…` | implementations per the C2 verdict table |
| `src/fs/backend/frm/sd_frm_staged.c` | **new** — 600-line split (staged family + C3 barrier) |
| `src/fs/backend/frm/sd_frm_adapter.c` | +`frm_env()` master-environ snapshot |
| `src/protocols/root/query/prepare_recall.c` | **new** — stage/evict per-path lifecycle |
| `src/protocols/root/query/{prepare.c,prepare_qprep.c,prepare_internal.h}` | the three arms stop being noops; QPrep residency-first |
| `src/fs/xfer/stage_request_registry.c` | no API change — the existing calls are the lifecycle |
| `src/core/config/process_server_init.c:169` | +`brix_init_server_stage_advisor` |
| `tests/{test_prepare_recall.py,test_vfs_evict.py,_test_prepare_recall_helpers.py}` | **new** — 10 tests, one serial group |
| `tests/c/test_vfs_nearline_probe.c` | **new** — the probe truth table |
| `tests/configs/nginx_lc_prepare_recall.conf` | **new** — frm://exec + registry template |
| `./config` | +3 source files |

### W7 — C6 preconditions and exchange (ABI wave)

- [x] **ABI.** Change `staged_commit`'s signature across all twelve drivers and
      every caller in one commit; `rm -rf objs && ./configure && make`; ABI note
      in `docs/09-developer-guide/agent-guide-extended.md`.
- [x] `BRIX_SD_CAP_PRECOND` (`1u << 18`); atomic implementations on `remote`,
      `http`, `pblock`, `ceph`; advisory on `posix`/`frm` and **reported** as
      advisory via `pre->atomic`.
- [x] `exchange` / `_cred` on `posix`, `frm` and `pblock`; `ENOTSUP` elsewhere
      with no emulation.
- [x] Move the WebDAV COPY/PUT precondition **decision** from `copy.c:280` to
      the commit; keep the edge parse.
- [x] `ECANCELED → 412` row in `brix_http_errno_to_status` (§5.0).
- [x] Root plane declines MATCH_* per §5.5, and the test asserts the decline.

**Landed notes (2026-09-01).** The decisions taken during the wave:

* **The errno contract classifies the refusal, atomicity qualifies it.**
  `EEXIST` is only ever the ABSENT verdict, `ECANCELED` only a MATCH_* one,
  `ENOTSUP` an unexpressible/unprobed precondition — which lets ONE observer
  (`brix_vfs_precond_refused_observe`, filtered on that contract) sit on every
  commit/copy failure path without pre-classification. The C6 metric pair
  books there: `brix_vfs_precond_failed_total{kind}` for every refusal,
  `brix_vfs_precond_advisory_total{driver}` for the subset whose verdict came
  from a non-atomic probe (`!pre->atomic`) — the honesty ratio.
* **Atomic-on-refusal.** A verdict is `pre->atomic = 1` when the *refusal
  itself* was race-free, per driver: http's 412 from a conditional PUT,
  compat's `RENAME_NOREPLACE` EEXIST (unless
  `brix_renameat_noreplace_degraded()`), pblock's in-transaction check.
  A stat-then-act refusal stays advisory even when it is correct.
* **Edge refusals are booked too, always as advisory.** The HTTP fronts'
  RFC 9110 pre-checks (`brix_http_precond_refused_edge`, called from
  `http_conditionals.c` and `s3/conditional.c`) feed the same pair with
  `atomic = 0` and the kind chosen by RFC 9110 evaluation precedence — an
  If-Match miss books `etag` even when If-None-Match was also present.
* **§3.5 held everywhere it was tempting to bend.** ceph staged commit
  refuses MATCH_* with `ENOTSUP` (librados' C API has no compare-and-write on
  a whole object); frm is all-advisory; sd_remote's pre-existing ECANCELED on
  a create race was retyped `EEXIST` to match the contract; `kXR_new` rides
  the open intent through to `commit_ex` so the root plane's exclusive create
  is enforced at publish, and the root plane *declines* MATCH_* (no ETag
  vocabulary on the wire) rather than approximating with mtime.
* **Exchange landed with the support matrix as specified** — `posix`, `frm`,
  `pblock` implement; both decorators relay slot + `_cred` twin (the R-wave
  parity lesson, pinned by `test_vfs_exchange.py`); every other driver is
  `ENOTSUP` with no two-rename emulation, refused in the dispatch helper AND
  both engine arms.
* **Cachemx pin backfill.** Nine conformance families
  (`test_cachemx_catalog.py` + schema/data tables) now pin the six new
  unified families' names, types and label sets, so a drive-by rename shows
  up as a catalog red, not a silent scrape change.

Guard fallout (all burned down in-wave): `unified_export.c` gave up the vfs
emitters to a new `unified_export_vfs.c`; the two-name verbs' shared
prologues extracted to `brix_vfs_two_key_gate` / `brix_vfs_two_name_entry`
(vfs_rename.c) and the nine posix abspath sites to `sd_posix_abs_key`
(check_duplication → 0 blocks); CCN decompositions in `sd_http_write.c`
(`sd_http_cond_line` + `sd_http_commit_status`), `vfs_staged.c`
(`vfs_staged_commit_compat`), `vfs_copy.c` (`vfs_copy_driver_dst_gate`) and
`sd_pblock_staged.c` (`pblock_staged_precond`); the phase-105
`vfs_read_only_spy` C unit regained link closure with four new stubs and the
recursive-rmdir row rerouted through `brix_vfs_rmtree_dispatch`.

| file | change |
|---|---|
| `src/fs/backend/sd.h:394` | **ABI** — the slot signature |
| `src/fs/backend/sd_batch_types.h` | +`brix_sd_precond_t`, +`brix_sd_precond_kind_t` |
| all twelve `.staged_commit` initialisers | **ABI** — one commit |
| `src/fs/vfs/vfs_staged.c:302,339,369–372` | carry the struct; keep the two wrappers |
| `src/fs/backend/remote/sd_remote_write.c:148–200` | conditional headers; the documented race disappears |
| `src/protocols/webdav/copy.c:280` | parse and carry, stop deciding |
| `src/core/compat/error_mapping.c:198–235` | +`ECANCELED` |
| `docs/09-developer-guide/agent-guide-extended.md` | ABI note |

### W8 — C7 lock enforcement

- [x] Route `brix_vfs_require_unlocked()` into every path mutator, after the
      policy check and before leaf resolution.
- [x] Optional borrowed lock-token field on `brix_vfs_ctx_t`, filled by the
      WebDAV edge only.
- [x] Expired-lock-is-absent-**without**-reaping semantics; prove it on a
      read-only export.
- [x] `brix_lock_enforcement` directive; the `EBUSY → 423` row (§5.0) and the
      per-plane refusals (§5).
- [x] `tools/diag/lock_scan.py` for the pre-upgrade check.
- [x] Cross-protocol proof: lock over `davs://`, refuse over `root://`, GridFTP,
      S3 and OCI; unlock; all five succeed.

**Landed notes (2026-09-02).** The decisions taken during the wave, and the two
call sites the plan's table did not list:

* **The gate reads through the QUIET xattr path** (`brix_vfs_getxattr_quiet_at`,
  no OP_XATTR observation), so the per-request counter pins in the metrics
  conformance contract stay depth-independent — a 6-deep target and a 1-deep
  target book the same op counts. The absent-class errno list is the WebDAV
  lock DB's own (`brix_vfs_lock_errno_absent`), **including `EACCES`/`EPERM`**:
  a backend that hides the attribute must not be able to wedge every mutation.
  A hard read fault in strict mode fails closed (unlocked cannot be proven);
  advisory admits it. Coverage and ownership are byte-identical to the WebDAV
  edge's `webdav_check_lock_at`: exact match or depth-infinity ancestor on a
  path boundary; ownership by substring match of the presented `If`/token
  header against the recorded token — so the two planes can never disagree
  about who owns a lock.
* **Expired = absent, deliberately NOT reaped.** Reaping is itself a mutation;
  the gate also runs for read-only-adjacent surfaces, and the WebDAV edge's
  own expiry cleanup (which already declines on a read-only export) remains
  the only reaper. Proven live: an expired foreign lock admits a `root://`
  write on a strict export without any xattr write.
* **The enforcement mode comes from the backend registry keyed on
  `root_canon`** (`brix_vfs_backend_lock_enforcement`, registered from the
  same per-export preparation as the C1 spill and C3 durable entries): absence
  = STRICT, failing *toward* enforcement; `off` reads nothing at all. A call
  site cannot opt itself out. `brix_vfs_lock_refused_total{proto}` books in
  BOTH strict and advisory — the advisory count is what tells an operator the
  relaxed mode is masking real contention. The advisory warning names the op
  and path, NEVER the held token (bearer secret).
* **The `root://` plane needed its own gate at open dispatch** — a call site
  beyond the plan's per-mutator list. The driver open
  (`brix_sd_open_maybe_cred`) and the POSIX-fd POSC/resume staging in
  `brix_open_dispatch_open` never pass `brix_vfs_open`/`brix_vfs_staged_open`,
  so a write open there bypassed the gate entirely — and the POSC publish is a
  rename that REPLACES the locked inode. The gate sits after
  `brix_open_select_sd_inst`, on `is_write`, with the staged route EXCLUDED
  (it gates inside `staged_alloc_handle`; gating twice would double-book the
  advisory metric). `EROFS` still precedes `EBUSY` because
  `brix_open_mode_guard` refuses a write on a read-only server at the edge
  (`kXR_fsReadOnly`) before dispatch — a read-only export discloses nothing
  about lock state (§3.4). `EBUSY` maps to `kXR_FileLocked` "file locked".
* **A lock must survive its own admitted publish**
  (`brix_staged_lock_carry`, `core/compat/staged_file.{h,c}`). The lock
  record lives in the `user.nginx_xrootd.lock` xattr ON the inode, and every
  rename publish replaces that inode — so an ADMITTED write under a live lock
  (the owner's `If:` token over WebDAV, where PUT's `BRIX_VFS_O_ATOMIC`
  forces the staged temp+rename route even on posix; or any write admitted by
  `advisory` enforcement) silently discharged the lock, violating RFC 4918
  §7.4. The carry copies the record verbatim (expired included — expiry is
  the gate's question; reap belongs to the WebDAV edge) from the destination
  onto the temp immediately before rename, at all three publish sites:
  `staged_commit_internal` (`!exclusive` only — `RENAME_NOREPLACE` has no
  destination inode to carry from), `brix_commit_staged` (before the
  broker/plain rename; the backend route carries via the driver's own staged
  commit), and `commit_cross_device` (onto the adjacent temp — the data pump
  moves bytes only). A carry failure fails the commit: no lock-stripping
  publish. Backend-upload routes (`remote`, `http`, `pblock`) are out of
  carry scope by design — no POSIX destination inode holds a record there.
* **The five-plane proof is live**: `tests/test_cross_protocol_locks.py`, 9/9
  against a dedicated lifecycle instance with strict/advisory/off/read-only
  fronts — lock over `davs://`, refuse over `root://`/GridFTP/S3/DAV-foreign,
  owner token still writes (and keeps its lock, per the carry), advisory
  warns-and-admits while booking the metric, `off` reads nothing, unlock
  frees every plane.

Guard fallout (burned down in-wave): CCN decompositions —
`brix_vfs_lock_errno_absent` (vfs_lock_gate.c), `staged_commit_confine`
(staged_file.c), `brix_prepare_spill_path` (root_prepare.c), and
`brix_http_errno_to_status` converted from switch to the same table shape as
the file's errno→kXR section; duplication helpers —
`brix_metric_shm_for_proto` (the shared recorder prologue,
unified_record.c/unified_record_vfs.c) and
`brix_mkdir_recursive_confined_core` (the confined/beneath recursive-mkdir
pair). `test_cachemx_catalog.py` + `test_cachemx_exposition.py` pin the
`brix_vfs_lock_refused_total` family (339 conformance tests green).

| file | change |
|---|---|
| `src/fs/vfs/vfs_lock_gate.c` | the real implementation (stubbed in W1), + `brix_vfs_require_unlocked_many` (drill-down) |
| `src/fs/vfs/vfs.h` | +`lock_token` on `brix_vfs_ctx_t` |
| `src/fs/vfs/{vfs_open,vfs_unlink,vfs_rename,vfs_mkdir,vfs_copy,vfs_xattr}.c` | one call each, at position 2 |
| `src/fs/vfs/vfs_writer.c` | **no direct call** — the plan's table listed one, but every writer byte reaches storage through a handle `brix_vfs_open`/`brix_vfs_staged_open` produced, and BOTH gate; a writer-level call would double-book the advisory metric |
| `src/fs/vfs/vfs_sync.c`, `vfs_unlink_many.c` | the two gates the wave missed (drill-down note below) |
| `src/protocols/root/read/open_resolved_file_dispatch.c` | the root-plane gate at open dispatch (see landed notes) |
| `src/core/compat/staged_file.{h,c}`, `staged_file_commit.c` | `brix_staged_lock_carry` at the three rename-publish sites |
| `src/protocols/webdav/dispatch.c:257` etc. | the seven edge checks stay as a fast path; the VFS is now the authority |
| `src/core/compat/error_mapping.c` | +`EBUSY → 423` |
| `src/core/config/tier_directives.h` | +1 directive row |
| `tools/diag/lock_scan.py` | **new** |

**Drill-down completion (2026-09-02).** An adversarial re-verification of the
landed W8 surface found two mutation routes the gate did not cover, and the
fix for the second exposed a scaling defect in the gate itself:

* **`brix_vfs_truncate_path` path-native branch** (`vfs_sync.c`): when the
  leaf carries a `truncate_path`/`truncate_path_cred` slot, the truncate never
  passed `brix_vfs_open` — a locked file could be truncated over `root://`.
  The gate now sits on the path-native branch only, **after** leaf resolution
  (the branch decision needs the leaf, so this unit's pinned order is
  lock-before-slot, not lock-before-leaf) and a refusal does NOT fall through
  to the open+ftruncate fallback — that would be a second door past the gate.
  The fallback route deliberately reads no lock itself: `brix_vfs_open` owns
  that gate, and reading twice would double-book the advisory metric. Proven
  hermetically against the real `vfs_sync.o` in `test_vfs_new_mutator_gate.c`
  (ORD tape: lock before backend before invalidate; refusal runs zero slots,
  zero evictions, zero opens; the fallback route hits no ORD_LOCK) and live
  (`FileSystem.truncate` over `root://` under a DAV lock → `kXR_FileLocked`,
  bytes untouched; succeeds after unlock).
* **`brix_vfs_delete_many`** (`vfs_unlink_many.c`): the S3 DeleteObjects batch
  ran no lock gate at all — a locked key deleted through the batch that its
  single-key twin refused. The gate runs BEFORE any arm touches storage and
  refusal is ATOMIC: no key attempted, `errs` stay `ECANCELED`, `*done` 0 —
  never a partial delete behind a lock conflict. The S3 handler answers an
  atomic `EBUSY` with the same **409 `OperationAborted`** the single-key
  DELETE gives a locked key (`delete_objects_batch.c`; without this the
  refusal rendered as per-key `InternalError` rows at HTTP 200, hiding the
  lock and implying a server fault).
* **Probe amplification (the incident the fix exposed):** gating the batch
  through the per-path entry cost ~3 quiet xattr reads per key over a remote
  leaf — ~3,000 upstream round trips for a 1,000-key request — and ONE
  transient fault among them fail-closed the whole batch (witnessed once in
  the wild as an all-`ECANCELED` response). `brix_vfs_require_unlocked_many`
  now sweeps the window with a parent-chain memo: the exact-node probe always
  runs, the ancestor walk stops on reaching the previous key's proven-clean
  parent — a flat batch costs **n + 2** probes instead of 3n. The memo holds
  only chains walked fully clean (an advisory admit or swallowed fault never
  seeds it), so advisory-mode contention books its refusal metric per key
  exactly as the per-path gate does. `test_vfs_lock_gate.c` pins the probe
  shape (n + 2 flat; 3+1+3 across a parent switch; exact-node never skipped;
  atomic strict refusal; per-key advisory booking).
* The five-plane live proof grew to 11/11 (`test_cross_protocol_locks.py`):
  the two new cases are the `root://` path-native truncate refusal and the S3
  bulk-delete 409 with both keys surviving, `lock_refused_total{proto="s3"}`
  +1, and post-unlock success for both.
* **The DAV token-plumbing defect class (found by the widened regression
  band):** the OWNER's DELETE of its own locked file returned **500**.
  `webdav_vfs_ctx_build` hands the gate the request's If/Lock-Token bytes,
  but three OTHER mutator ctx builders never set `vctx->lock_token`, so the
  VFS — the authority — saw the owner as foreign and refused EBUSY, which no
  renderer mapped: `webdav_ns_vfs_ctx_init` (DELETE/MKCOL, `namespace.c`),
  the rename-exec ctx in `webdav_move_execute_cred` (`move.c`, built by hand
  because it must survive a thread-pool hop — `webdav_lock_token_header` is a
  pure header lookup returning a borrowed pointer into request memory, safe
  on a parked request), and `webdav_dead_prop_vfs_ctx_init` (PROPPATCH
  set/remove, `dead_props.c`). The edge check masks the hole for the FOREIGN
  caller (it 423s first); only the owner's own mutation fell through to the
  gate without its token. Fixes: token plumbed at all three sites, plus the
  missing EBUSY→**423 Locked** rendering rows (`webdav_delete_respond`, the
  MOVE errno map, and the PROPPATCH per-prop propstat — which previously
  called every set/remove failure `507 Insufficient Storage`). The two
  builders my token fix made byte-identical to the canonical constructors
  were then dissolved into them (`webdav_dead_prop_vfs_ctx_init` →
  `webdav_vfs_ctx_build` at its four call sites; `webdav_ns_vfs_ctx_init` →
  a thin `webdav_vfs_ctx_build_ns` delegation), so the token can no longer
  be forgotten per-file. Pinned live by three new owner-plane tests in
  `test_cross_protocol_locks.py`: tokenless DELETE/MOVE/PROPPATCH 423 while
  the owner's same op with `If:` succeeds (204 / 201 / 207-with-200).
* **Two more custom errno maps missed the C7 rendering row** (found by
  auditing every DAV mutator's status path against the shared
  `brix_http_errno_table`, which has carried `{EBUSY, 423}` since W8): the
  MKCOL if-chain fell through to **500** and `webdav_copy_errno_to_status`
  folded EBUSY into its generic **409** — both now return 423 Locked, with
  COPY's map documenting the one deliberate departure from its
  ns-status parity. Pinned live by two more owner-plane tests (tokenless
  MKCOL inside an owned locked collection; tokenless COPY onto an owned
  locked destination — refused bytes stay `stale`, the owner's `If:` COPY
  lands `fresh`), completing the owner-token matrix:
  PUT/DELETE/MOVE/PROPPATCH/MKCOL/COPY each have tokenless-423 + owner-
  success proofs.
* **The C regression units had rotted around the new surface** (link-closure
  rot, the class `tests/cmdscripts/c_regression_units.py`'s own header warns
  about — the driver TABLE names every slot, so a new slot widens every
  hand-maintained object closure at once): 15 of 49 units failed on first
  run. The burndown, each fix choosing stub-vs-link by what the unit
  actually drives: `SD_REMOTE_OBJS` += `sd_s3_batch.o` (C2's DeleteObjects
  plane, named by `sd_remote_write.o` — 9 units at once); the pblock unit
  compiles `sd_pblock_batch.c`; `staged_commit_contract` links the split-out
  `sd_posix_staged.o` and STUBS the fd-relative ns kernels it never
  dispatches (linking `namespace_ops.o` both collided with its existing ns
  stubs and dragged the beneath kernel) plus `brix_renameat_noreplace_degraded`
  as "never degraded"; `sd_xroot_query` carries a faithful one-line copy of
  `brix_sd_caps` (C8's nearline gate) because `sd_registry.o`'s `.rodata`
  names every builtin driver vtable; and `decorator_cred_forward` links the
  REAL `sd_stage_write.o`/`sd_stage_wb.o` — its first "stub the new slots"
  fix aborted at runtime because the truncate_path/exchange/evict relays are
  exactly what the unit dispatches — stubbing only the async engine seam
  beneath them (`brix_stage_submit`). Two traps for the record: a
  coverage-instrumented `libxrdproto.a` (rebuilt by a concurrent session's
  gcov run) breaks every unit that links it without `--coverage` — `make
  clean && make` in `shared/xrdproto/`; and that rebuild surfaced
  `check-shared-coverage.sh` STRANDED failures for `cred_stage.c`/`wverify.c`
  — pre-existing at HEAD (both always ngx-free, never shared), resolved by
  adding both to `NAMES` (the archive stays ngx-free, 239→246 symbols).
  End state: **49/49**, `make check` green.
* **The first full `--pr` tier run (2026-09-02, lane time-sliced with the
  concurrent bench session) came back 566 passed / 6 failed — all six were
  STALE TEST EXPECTATIONS, none a phase-107 regression.** Five in
  `test_backend_caps_negative.py` and one in `test_ns_mutation_gateways.py`
  still asserted that sd_http "has no xattr slots" and that a direct-export
  truncate refuses `kXR_IOError`; both premises died on main before this
  phase — the storage-driver slot wave's item Q (commit `480ded2e4`, pushed)
  gave sd_http all four xattr slots as RFC-4918 dead properties, and
  phase-105's `error_mapping.c` closed EROFS→`kXR_fsReadOnly` (3025), so the
  fattr set now genuinely SUCCEEDS (persisting at the ORIGIN as
  `user.nginx_xrootd.webdav.*` xattrs) and the truncate refusal became honest.
  The tier had simply never been run on `480ded2e4`+. The tests were
  rewritten to pin the NEW contract while keeping their security intent:
  set→get→del round-trips byte-exact and the dead-property xattr lives at
  the origin exactly as long as the attribute does; the world-writable
  local decoy under the export root still gains nothing (the storage-domain
  split assertion now guards a SUCCESS path, which is strictly stronger);
  direct-arm truncate expects `kXR_fsReadOnly`. All rewritten tests green.

- [x] Confirm the W1 assert: `EXPORT` routes to the phase-105 kernel unchanged,
      every other domain refuses an instance that does not belong to it.
- [x] **Pass 1**: annotate all 108 markers with a domain constant. Comment-only,
      reviewed as a security change — a mis-assigned domain here becomes a false
      entitlement in pass 2.
- [x] **Pass 2**: `check_vfs_seam.py` parses the constant, enforces the
      directory-prefix entitlement table, and fails on unknown / missing /
      unentitled.
- [x] Regenerate the slot matrix; the diff must be exactly the nine new columns.
- [x] This wave is [phase 108](phase-108-vfs-consolidation.md)'s prerequisite:
      that phase's W0 does not start until the entitlement table is enforcing.

| file | change |
|---|---|
| 108 marker sites across 14 areas (§2.2) | comment-only domain annotation |
| `tools/ci/check_vfs_seam.py:212` | parse + entitlement table |
| `tools/diag/sd_slot_matrix.py` | regenerate; `--check` in `guards.yml` |
| `docs/09-developer-guide/storage-driver-slot-matrix.md` | regenerated output |
| `tests/test_vfs_seam_domains.py` | the §9.1 C9 row: 13 tests on the guard's own `domain_*` functions |

**Landed notes (2026-09-02).**

- **The census moved 108 → 111 between planning and pass 1.** Concurrent work
  added three markers (among them `src/fs/path/canonical.c:57`, the sendfile
  fd-resolver's `open(O_PATH)` canonicaliser core, classified `SEAM_CORRECT`).
  The doc-comment count is 16, all correctly excluded by the parser — the G.2
  proof holds as "111, not 127". Final split: 94 `DOMAIN_*` claims, 7
  `NOT_STORAGE`, 10 `SEAM_CORRECT`; the guard's success line prints all three
  numbers so the escape valves cannot quietly become the default.
- **G.4's unnamed second valve is now named `SEAM_CORRECT`** — the call is
  already on the right side of the seam (fstat-class on a VFS-opened fd, an
  openat inside a VFS-opened dir stream, a stat of the confinement anchor, or
  compat code that IS the posix storage plane). Entitled everywhere, granting
  nothing, counted.
- **`DOMAIN_JOURNAL` currently has zero markers.** `src/fs/xfer/stage_*` and
  `src/net/cms/` are tier-3-allowed wholesale, so no per-line marker exists to
  carry the constant yet; the entitlement rows are in place for when one does.
- **Census-driven extensions beyond the Appendix G.1 table** (each is an
  allowlist row, reviewed as such): `src/fs/cache/origin_auth*` → `CONFIG`
  (origin credentials, a file-stem bend inside the `CACHE` directory) ·
  `src/tpc/` gains `CREDENTIAL` alongside `STAGE` (token-exchange writes) ·
  webdav file rows `tpc_cred_exchange.c`/`tpc_user_proxy.c`/`delegation.c` →
  `CREDENTIAL`, `put_body_digest.c` and the remaining `tpc_*` → `STAGE` ·
  `src/protocols/shared/http_serve_offload.c` → `STAGE` ·
  `src/protocols/root/read/` and `root/connection/` → `{CACHE, STAGE}` (the
  open path legitimately touches both) · `src/protocols/cvmfs/attest.c` and
  `src/protocols/gridftp/ftp_module_gsi.c` → `CONFIG` ·
  `src/net/cms/blacklist_file.c` → `CONFIG` (file bend inside the `JOURNAL`
  directory). The table matches by longest prefix over directories and file
  stems — never `path:line` — so shards and moves cannot invalidate it.
- **Client markers (13) are out of scope by design**: the client has its own
  `xrdc_vfs` model and no service-storage domains; the client-tier scan is
  unchanged.
- **Verification**: `check_vfs_seam.py` green with the enforcing table
  (`… every domain claim entitled (111 markers: 7 NOT_STORAGE, 10
  SEAM_CORRECT)`) · `tests/test_vfs_seam_domains.py` 13/13 (success: live tree
  + doc-comment exclusion; error: missing/unknown constant, and the legacy
  reason-first form now parses as unknown; security-neg: a `CONFIG` waiver in
  a data-plane file fails, an unlisted path is entitled to nothing, the valves
  widen no entitlement, and `DOMAIN_EXPORT` does not exist) ·
  `vfs_service_domain` C unit green (the W1 assert) · `sd_slot_matrix.py
  --check` exit 0 (63 slots × 12 drivers, 421 implemented, 0 open gaps) ·
  full incremental rebuild clean after the comment-only pass.

---

## 9. Test matrix

### 9.1 Per-item, three tests minimum

Success, error and security-negative for every change, per the standing rule.
The per-item test tables in [§4](#4-per-item-design) are the detail; this is the
index.

| item | file | success | error | security-negative |
|---|---|---|---|---|
| C1 | `tests/test_vfs_writer_spill.py` | out-of-order write over `http` + `remote` → byte-identical object | spill root full → `ENOSPC`/507, no partial publish | spill temp not created before the mutation gate passes; read-only endpoint reaches no spill |
| C2 | `tests/test_prepare_recall.py`, `tests/test_vfs_evict.py` | prestage on `frm`/`xroot` returns a reqid; QPrep tracks residency | no slot, no command → `kXR_Unsupported`, not silent success | prestage and evict refused `kXR_fsReadOnly`; evict refused for a non-owner |
| C3 | `tests/c/test_publish_dirsync.c` (`publish_dirsync` unit) | dirfsync issued once per publish, on the **parent**, on POSIX | fsync failure fails the publish | not issued for a service-storage temp; not issued on a refused publish |
| C4 | `tests/test_s3_delete_objects_batch.py`, `tests/test_vfs_rmtree.py` | 1 000-key delete → 1 batch on `remote`, 1 transaction on `pblock` | partial failure reports per-key errno and a correct `done` count | one policy check covers the batch; a read-only endpoint deletes zero keys and discloses nothing |
| C5 | `tests/test_vfs_reserve.py` | `oss.asize` reaches the driver; part size derived on `remote` | oversized declaration → `ENOSPC` at open | a declared size cannot raise a quota or bypass `oss.maxsize` |
| C6 | `tests/test_conditional_publish.py`, `tests/test_vfs_exchange.py` | conditional publish atomic on `remote`/`http`; exchange atomic on `posix` | mismatched etag → 412 / `kXR_ItExists` | a non-`CAP_PRECOND` backend never reports an atomic guarantee; exchange never emulated |
| C7 | `tests/test_cross_protocol_locks.py` | locked resource refuses on all five planes; matching token succeeds | expired lock treated as absent on a read-only export, without reaping | a lock cannot be bypassed by choosing a different protocol; `EROFS` precedes `EBUSY` |
| C8 | `tests/test_gcas_store_gate.py`, `tests/c/test_vfs_service_domain.c` | `gcas` publish/gc succeed against a store instance | export instance → `EINVAL` | a cache store configured at an export root is refused at `nginx -t` **and** at runtime |
| C9 | `tests/test_vfs_seam_domains.py` | every waiver names an entitled domain; guard green | unknown/missing domain → guard fails | a `CONFIG` waiver in a data-plane file fails; a domain constant does not grant access |

### 9.2 How the C-level units are registered

The C object units go through the existing runner, not a bespoke one.
`tests/cmdscripts/c_object_units.py:170–300` holds the `ObjectUnitSpec` table —
the same table that already carries the phase-105 `vfs_read_only_spy` and
`vfs_mutation_policy` specs — and `tests/test_c_object_units.py` parametrizes
over `sorted(SPECS)`.

The rule that bit this tree once and must not bite it again: **a unit present in
`RUNNERS` but absent from the parametrized table never runs, and the suite still
reports green.** Every new object unit in this phase is added to `SPECS`, and
W0's checklist includes asserting the collected test count grew by exactly the
number of units added.

New specs:

```
vfs_writer_spill        C1 — the three-state machine, transitions only
publish_dirsync         C3 — parent-fd derivation, O_RDONLY not O_PATH
vfs_bulk_chunker        C4 — level boundaries, window fill, short `done`
sd_precond              C6 — kind dispatch, `atomic` reporting
vfs_lock_gate           C7 — the four expiry states
vfs_service_domain      C8/C9 — domain assert, EXPORT-is-zero default
```

As built the six landed as the spec names above (`publish_dirsync`, not the
planned `vfs_sync_publish`); `sorted(SPECS)` is 28 entries and
`tests/test_c_object_units.py` collects 28, which is the count-growth check this
section demands. The two written last — `sd_precond` and `vfs_bulk_chunker` —
were mutation-checked rather than merely run green: removing the C4 boundary
flush, the ECANCELED pre-fill, the window-fill comparison against the constant,
the `done`-bounded success count, or the leaf capability probe each makes the
chunker unit fail, and truncating or extending a generated ETag each makes the
precondition unit fail.

### 9.3 Cross-cutting

- **Ordering.** For every new mutator, assert policy → lock → leaf → capability
  → credential → backend → invalidation, with a spy that records the sequence.
  Phase 105 found four real defects with exactly this assertion; the new verbs
  get it from the start rather than as an audit.
- **Decorator composition.** Every new slot exercised through `cache`-over-X and
  `stage`-over-X in both orders. `recall` must **descend**; `evict` must **not**;
  `sync_publish` must **not be relayed at all**. The parity gate
  (`check_sd_driver_conformance.py:188`) enforces both-or-neither, and the
  `sync_publish` exclusion is recorded in the script.
- **`_cred` twins.** For each of the four new `_cred` slots, assert on the
  *signing key* or the connection identity, never on request bytes — and assert
  that a **lazy** slot copied the credential rather than borrowing it. This is
  the confused-deputy class the slot wave found three times; `recall_cred` on
  `remote` is lazy and is the one to watch.
- **Census drift.** `sd_slot_matrix.py --check` and
  `check_sd_driver_conformance.py` both green, with every new empty cell
  carrying a verdict.
- **Fleet.** The live lanes for root, WebDAV, S3, OCI and GridFTP, each
  exercising the plane's own new refusal. Fixed-port families carry an
  `xdist_group` nodeid suffix — a `serial` marker alone does not keep a module on
  one worker, and `--dist load` ignores every group.
- **Domain entitlement (C9).** `check_vfs_seam.py` green over the fully
  annotated tree, plus a negative case per domain — a waiver naming a domain its
  directory has no entitlement to must fail the guard, and a domain constant must
  not be readable as a grant.
- **Tier placement.** Every new test is either in the `--pr` tier or explicitly
  marked `slow`; a gate named after a slow family gets deselected from the PR
  tier and the run still says green, which is how a gate goes dark.
- **Closure (as built).** `tests/test_phase107_mutation_surface_closure.py`
  (18 tests, hermetic, `xdist_group("phase107-closure")`) pins the facts the
  completion work itself discovered, one assertion each, grouped
  compatibility / feature / security: the C6 evaluator's private copy of the
  ETag grammar must stay equal to `brix_http_etag_str`'s and its buffer no
  narrower than the 48 bytes `etag.h` documents; all seven evaluator callsites
  answer a missing target with `ECANCELED` (412) and never `ENOENT` (404); the
  §9.1 matrix names files that exist and §9.2's promised units are all in the
  parametrized table; the vocabulary is closed, mirrored, uniquely labelled and
  every member is passed by some caller outside the kernel; the bulk-delete
  window and its capability bit are singular; all three refusal enums read
  safest at zero (`READ_ONLY` / `PRECOND_NONE` / `DOMAIN_EXPORT`); the kernel's
  executable text contains no `EACCES`; all eighteen `_maybe_cred` wrappers
  refuse a `fallback_deny` credential; the evaluator's fall-through is
  `ENOTSUP`; and the enum/metric-mirror `_Static_assert` still exists.

  A second wave (2026-09-03) pins what the `_Static_assert` structurally
  **cannot** see, because it compares a count to a count:

  * the two hand-written mutation label tables — the kernel's
    `names[BRIX_VFS_MUTATE_OP_COUNT]` (`vfs_policy.c:70`) and the exporter's
    `brix_unified_vfs_mutate_op_names[]` (`unified.c:179`) — agree word for
    word, closing the fork `vfs_policy.c`'s own WHY comment forbids ("a second
    table would let the two drift") in the one place nothing defended it;
  * every label in **both** vocabularies is its own enum member's suffix,
    lowercased, in enum order.  This is the pin with teeth: inserting a member
    mid-enum and *appending* its label — the append-only reflex — keeps both
    counts equal and both tables identical while silently renaming every series
    after the insertion point (`evict` starts reporting as `lock`).  Six
    mutants were run against a copied tree; this assertion is the only one that
    kills that case;
  * no bounded `static const char *t[N]` label table in `src/` carries a hole
    (fewer initialisers than `N` is legal C, and the tail NULLs never reach the
    `"unknown"` fallback, which is only for an out-of-range index).  Eight
    tables qualify; the `BRIX_PROTO_LIST(X)` expansion is skipped as hole-free
    by shape;
  * the three refusals stay tellable apart on every plane — `EROFS` 403,
    `EBUSY` 423, `ECANCELED` 412 — which is what makes the C7 ordering
    guarantee (`EROFS` before `EBUSY`, so a read-only endpoint never discloses
    that a lock exists) observable at all; `EROFS` round-trips through
    `kXR_fsReadOnly` as the forward table's comment says it must; and the one
    deliberate asymmetry is pinned WITH its reason so a future reader does not
    "fix" it: `EBUSY → kXR_FileLocked` forward, but `kXR_FileLocked → EAGAIN`
    back (fcntl's "held, retry"), with `EBUSY` reserved on the reverse side for
    `kXR_Overloaded`, which is server load, not a resource lock;
  * the forward errno→kXR table has **no** `ECANCELED` row, so a precondition
    failure that reached the root plane would render as `kXR_IOError` — a
    server fault a client retries, for a condition retrying cannot fix.  Today
    nothing defends that but a design fact (the root plane constructs only
    ABSENT preconditions).  The pin is the implication, green in either future:
    the root plane may name `ECANCELED` only once the table can spell it;
  * the `nginx -t` diagnostics this document quotes are the ones the chosen
    setter can actually emit.  §4's original text promised a directive-naming
    `[emerg]` for `brix_lock_enforcement`; only `ngx_conf_set_flag_slot` names
    the directive, so the enum rows log the bad value alone.  Corrected above
    and pinned as the rule, not the string.

---

## 10. Expected file map

New `src/` files (all go in the repo-root `./config`; guard
`tools/ci/check_config_coverage.py`):

```
src/fs/vfs/vfs_writer_spill.c        C1 — reorder buffer for staged-only backends
src/fs/vfs/vfs_writer_internal.h     C1 — shared writer internals (600-LOC ceiling)
src/fs/vfs/vfs_recall.c              C2 — brix_vfs_recall / brix_vfs_evict
src/fs/vfs/vfs_unlink_many.c         C4 — chunker + brix_vfs_delete_many
src/fs/vfs/vfs_lock_gate.c           C7 — brix_vfs_require_unlocked
src/fs/vfs/vfs_policy_domain.c       C8/C9 — brix_vfs_domain_mutation / _service_mutation
src/fs/backend/sd_batch_types.h      C4/C6 — precond type + bulk result vector
```

New tooling:

```
tools/diag/lock_scan.py              C7 — pre-upgrade live-lock inventory per export
```

Modified — the ABI wave (W7) touches every driver; this list names the file and
the reason, not every hunk:

```
src/fs/vfs/vfs_policy.h/.c        vocabulary 11 -> 15; brix_vfs_domain_t; the static assert
src/fs/vfs/vfs_writer.c           spill-mode dispatch (:48, :156-186, :188, :323)
src/fs/vfs/vfs_staged.c           precondition struct; durable publish (:302, :339, :369-372)
src/fs/vfs/vfs_rename.c           exchange; durable publish
src/fs/vfs/vfs_unlink.c           level-batched bulk path (:43)
src/fs/vfs/vfs_open.c             reserve, once after a create-open
src/fs/vfs/vfs.h                  lock_token on brix_vfs_ctx_t
src/fs/backend/sd.h               9 new members, 2 cap bits, staged_commit signature (:394)
src/fs/backend/sd.h               + domain field on brix_sd_instance_s (:243-253)
src/fs/backend/sd_registry.c      assign it in brix_sd_instance_create (:113, :138)
                                  ...and in the 7 bypassing factories (C9)
src/fs/backend/*/                 per-driver implementations + verdicts
src/fs/backend/remote/sd_remote_write.c  part-size derivation (:37, :66); conditional commit (:148-200)
src/fs/backend/http/sd_http_write.c      cap the doubling buffer (:162-190)
src/fs/cache/gcas.c               service-domain assert (:69, :91)
src/core/compat/staged_file.c     replace the inert O_PATH fsync (:317-319)
src/core/compat/error_mapping.c   +EBUSY -> 423, +ECANCELED -> 412 (:198-235)
src/core/config/tier_directives.h +4 directive rows
src/observability/metrics/{metrics.h,unified.h,unified.c,
                           unified_record.c,unified_export.c}
                                  the six-file mirror, 11 -> 15
src/protocols/root/query/prepare.c    stage/evict/cancel/QPrep rewiring (:412, :422, :428)
src/protocols/root/path/opaque_validate.c  carry oss.asize instead of discarding (:235-240)
src/protocols/s3/delete_objects.c     batch path (:67)
src/protocols/webdav/copy.c           precondition parsed at the edge, decided at the commit (:280)
src/protocols/webdav/{dispatch,namespace,move,methods_proppatch}.c
                                      the seven lock checks become a fast path
tools/ci/check_sd_driver_conformance.py   parity base + the sync_publish exclusion
tools/ci/check_vfs_seam.py                C9 — domain parsing + entitlement table (:212)
tools/ci/check_directive_registry.py      picks up the 4 new directives automatically
tools/diag/sd_slot_matrix.py              regenerate; --check in guards.yml
108 marker sites across 14 areas          C9 pass 1 — comment-only domain annotation
config                                    new .c files
docs/09-developer-guide/storage-driver-slot-matrix.md   regenerated: 63 x 12
docs/09-developer-guide/agent-guide-extended.md         W7 ABI note
```

Every new `src/` `.c` file goes in the repo-root `./config` and requires a
re-`./configure --add-module=$REPO`; the coverage guard fails the build
otherwise. `make -j$(nproc)` is incremental **except** after W1 (struct field)
and W7 (vtable signature), where the tree needs `rm -rf objs` first — an
incremental build there links cleanly and behaves wrongly.

---

## 11. Compatibility and rollout

**Behaviour changes visible to a running deployment**, in descending order of
risk:

1. **`brix_lock_enforcement` default `strict` (C7).** An export carrying live
   WebDAV locks starts refusing writes from other planes. This is the intended
   behaviour and it is still a behaviour change on upgrade. Mitigation:
   `tools/diag/lock_scan.py` lists live locks per export; `advisory` mode
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

- [x] All nine items implemented, or explicitly deferred here with the reason
      and the ceiling recorded. *(All nine landed — C1 W2, C2 W6, C3 W3, C4 W5,
      C5 W4, C6 W7, C7 W8, C8 W1+W9, C9 W1+W9; no deferrals.)*
- [x] Vocabulary is 15 members; the metric mirror asserts equal at compile time.
      *(And the assert proven live 2026-09-02 by the W0 compile-fail
      experiment. Now 16 — phase-108's C11 added `CREDENTIAL` — and the
      closure test pins enum == mirror == 16 with one unique label each, so
      the next member cannot land in only one of the three places.)*
- [x] Every new slot has a verdict in every empty cell, the matrix is
      header-derived, and both census guards are green.
- [x] The ordering assertion (§3.4) passes for every new mutator.
      *(`vfs_new_mutator_gate` covers recall/evict/delete_many over the real
      four-TU closure; exchange rides the K.4 spy's OPS matrix in
      `vfs_read_only_spy` — both units green 2026-09-02.)*
- [x] Every new `_cred` twin is audited against the borrow-versus-copy rule and
      asserts on the signing key.
- [x] `check_vfs_seam.py`, `check_vfs_mutation_gate.py`,
      `check_sd_driver_conformance.py`, `check_config_coverage.py` all green
      with no new backlog entries. *(Full guard sweep 2026-09-02; an earlier
      pass carried residual reds from a concurrent session's uncommitted
      throughput work, since fixed by that session — the final sweep is green
      across complexity, file-size, duplication, python-quality, config and
      client-build coverage, and driver conformance.)*
- [x] `objs/nginx -t` green for every new directive, including the negative
      config cases. *(Re-verified 2026-09-03 against a binary built from this
      tree: the four-export `lock_enforcement` config parses clean;
      `brix_lock_enforcement yes`, `brix_durable_publish maybe` and
      `brix_authz_backstop loud` are each refused at `[emerg]`;
      `brix_durable_publish off` — the C3 opt-out — is accepted. The refusal
      TEXT was wrong in §4 and is corrected there; see §12.1.)*
- [x] The `--pr` tier is green; the five live protocol lanes are green.
      *(Closed 2026-09-04 against an isolated post-W9 binary: the serial PR
      acceptance lane completed with **561 passed, 273 skipped, 42,120
      deselected**. The live root/stream, GridFTP, CVMFS, WebDAV and S3 probes
      passed; they exercised the phase's mutator and metrics paths without
      attaching to or replacing the foreign fleet at port 10005.)*
- [x] `src/fs/README.md`, `src/fs/backend/README.md`, the slot matrix, the
      errno→kXR→HTTP table and `agent-guide-extended.md` updated **after** the
      code matches them, never before.
- [x] An implementation record appended to this document, in the shape phase 105
      used: what the sweep actually found, including the defects only a
      plane-by-plane pass surfaced. *(Realized as the per-wave **Landed notes**
      blocks under §8 — W0 through W9 each record what its sweep actually
      found, including the S3 keepalive `r->main->count` leak (W4), the
      strip-root double-strip EINVAL (W3), and the WebDAV `Depth: infinity`
      security decision (W5) — rather than one monolithic appendix; the
      per-wave shape keeps each finding beside the contract it changed.)*

C9 adds:

- [x] Every `vfs-seam-allow` waiver in the tree names a domain constant, that
      constant is one of the seven, and the file's directory prefix is entitled
      to it.
- [x] `check_vfs_seam.py` rejects a missing domain, an unknown domain and an
      unentitled domain — with a test per case, because a guard that only
      accepts is not a guard.
- [x] The waiver **count** is recorded per domain and published in this
      document, as the baseline
      [phase 108](phase-108-vfs-consolidation.md) measures its deletions
      against.

**Waiver census (2026-09-02, `check_vfs_seam.py` live output — 111 markers):**

| domain | waivers |
|---|---:|
| `CREDENTIAL` | 24 |
| `REGISTRY` | 25 |
| `STAGE` | 19 |
| `CACHE` | 16 |
| `CONFIG` | 10 |
| `JOURNAL` | 0 |
| `NOT_STORAGE` | 7 |
| `SEAM_CORRECT` | 10 |
| **total** | **111** |

This table is the phase-108 baseline: its consolidation waves (C10–C13) are
measured by how many of the 94 domain-bearing waivers (111 minus the 7
`NOT_STORAGE` and 10 `SEAM_CORRECT` markers, which are annotations rather than
storage bypasses) they delete.

### 12.1 Post-close verification (2026-09-03)

The ledger above was re-checked against the tree rather than taken on faith.
Five drifts, two of them real coverage gaps:

- **Two promised object units were never written.** §9.2 listed six new specs
  and §12 ticked "all nine items implemented", but `vfs_bulk_chunker` (C4) and
  `sd_precond` (C6) were absent from `SPECS`, so the chunker's recursion and the
  precondition evaluator had **no hermetic coverage at all** while the ledger
  read as if they did — §9.2's own trap ("a unit present in RUNNERS but absent
  from the parametrized table never runs, and the suite still reports green"),
  landing one level up. Both are now written and registered:
  `tests/c/test_vfs_bulk_chunker.c` (13 cases) links the real
  `vfs_unlink_many.o` against an in-memory fake namespace and asserts the
  ordering property no wire test can see — every child is gone **before** its
  directory, at every level — plus the window splitting on
  `BRIX_SD_BULK_DELETE_WINDOW` exactly, the `ECANCELED` pre-fill, `d_type` as a
  hint and never authority, `ELOOP` past the depth cap, deny-mode refusal of a
  whole batch, and a driver writing past `done` being unable to inflate the
  metric. `tests/c/test_sd_precond.c` (13 cases) links the real `http/etag.o`
  and compares generated tags against the evaluator at runtime.
  `sorted(SPECS)` went 26 → 28, and `test_c_object_units.py` collects 28.
- **Both new units were mutation-checked, not merely run green.** Removing the
  C4 boundary flush, the `ECANCELED` pre-fill, the window comparison against the
  constant, or the leaf capability probe each makes the chunker unit fail;
  truncating or extending a generated ETag each makes the precondition unit
  fail. One mutant initially **survived** — replacing the `done`-bounded success
  count with the full window size — because untried keys already read
  `ECANCELED`; case 13 (the metric carries the count in the value) was added to
  kill it.
- **The §9.1 matrix named three files that never shipped** under those names:
  `tests/test_durable_publish.py` (C3 landed as the `publish_dirsync` object
  unit) and two rows naming `tests/test_gcas_gate.py` (shipped as
  `tests/test_gcas_store_gate.py`). Fixed, and
  `test_the_doc_test_matrix_names_files_that_exist` now holds §9 to it.
- **The §4 `nginx -t` refusal text was wrong for the enum directives.** §12
  ticked "`objs/nginx -t` green for every new directive, including the negative
  config cases", and the negatives ARE refused — but §4 quoted the refusal in
  the directive-naming form (`… in "brix_lock_enforcement" directive`), and
  nginx does not say that. Only `ngx_conf_set_flag_slot` names the offending
  directive (`ngx_conf_file.c:1050`); `ngx_conf_set_enum_slot` (`:1382`) logs
  the value alone, so an operator with two enum directives in one server block
  is left with the line number as their only clue. Measured against a binary
  built from this tree: `brix_lock_enforcement yes` →
  `[emerg] invalid value "yes" in <conf>:115`, while `brix_durable_publish
  maybe` → `[emerg] invalid value "maybe" in "brix_durable_publish" directive,
  it must be "on" or "off"` exactly as §3.2 says. §4 corrected;
  `test_the_new_directive_diagnostics_are_quoted_as_their_setter_emits_them`
  now holds the doc to the RULE (a named diagnostic may be quoted only for a
  flag-slot row), so the same wrong promise cannot be written for
  `brix_authz_backstop` either.
- **The discoveries are pinned.** `tests/test_phase107_mutation_surface_closure.py`
  (§9.3) carries all eighteen, one assertion each. Six of the newest were
  themselves mutation-checked against a copied tree, including the case that
  motivated the positional-label pin: a *correct* mid-enum insertion passes
  every test, so the mutant that matters is the realistic mistake — insert
  mid-enum, append the label — which only the positional assertion kills.

Re-verified on a quiet tree: the C1–C9 lanes plus the closure file
(`test_vfs_writer_spill` · `test_prepare_recall` · `test_vfs_reserve` ·
`test_conditional_publish` · `test_cross_protocol_locks` ·
`test_gcas_store_gate` · `test_vfs_mutation_baseline` · `test_c_object_units` ·
`test_phase107_mutation_surface_closure`) run **121 passed / 1 skipped**, six
consecutive times; `test_c_object_units.py` 27 passed / 1 skipped;
`check_vfs_mutation_gate.py` and `check_config_coverage.py` green. Two guards
are red for reasons **outside this phase** and are left to their owner: a
concurrent session's uncommitted `src/fs/backend/gsiftp/gftp_gsi.c` claims
`DOMAIN_CONFIG` from a prefix with no entitlement (`check_vfs_seam.py`, and so
`tests/test_vfs_seam_domains.py`'s two live-tree cases) — the entitlement it
wants is the analogue of the existing `src/protocols/gridftp/ftp_module_gsi.c`
row, but widening a security allowlist for another session's in-flight file is
that session's reviewed change to make, not this phase's; and the same
session's `tests/brix_suite/servers/ftp_origin_server.py:73` exceeds the NPath
limit (`check_python_quality.py`). *(Both closed later the same day by their
owner — `check_vfs_seam.py` now carries a `gftp_gsi` → `DOMAIN_CREDENTIAL`
entitlement row and `check_python_quality.py` reports OK across 235,500
function scores. Neither was touched from this phase.)*

**One unexplained red, recorded rather than waved off.** The first of the six
runs above failed at
`test_vfs_writer_spill.py::test_reverse_order_remote_is_byte_exact` — the
`root://` *open* on `REMOTE_PORT` (the s3-fronted C1 spill export) answered
`[3007] Input/output error`, i.e. `kXR_IOError`, before a single byte was
written. It did not recur: five further runs of the same nine-file set and
eight cold single-test runs are green — 1 red in 15 executions — and the lane's
`error.log` was recycled by the next run before it could be read. The mechanism
is NOT the familiar TCP-ready race: `wait_ready` probes only the primary `PORT`
(`launcher/internal_operations.py:166`, never the six `extra_ports`), but nginx
binds every `listen` in the master before forking, so readiness on one implies
binding on all. No code was changed on a guess. The signature to match on a
recurrence: an `open()` — not a write, not the commit — refused with 3007 on
the s3 front only, at the lane's first operation.

---

## 13. What moved to phase 108

v2 of this document carried a second part: four places where BriX-Cache already
implements a VFS mutation concern as an isolated per-feature copy. They are now
[phase 108 — VFS consolidation](phase-108-vfs-consolidation.md), because the two
halves have different risk profiles, different review audiences and different
definitions of done. This phase is nine items of new capability judged by "does
it work on twelve drivers". That one is four waves of consolidation judged by "is
the shared version at least as strong as every copy it replaced" — a
security-review question, not a capability question. C12 alone rewires 29 call
sites, closes four protocol planes that authorize nothing today, and needs a
release in `observe` before it means anything; bundling that schedule with C1's
spill writer helped neither.

| moved item | what it consolidates | needs from this phase |
|---|---|---|
| C10 service publish | the OCI registry's private staged publish, atomic tag swap, CAS probe and index listing | C3 `sync_publish`, C6 `exchange` + precondition, C8 CAS gate, C9 domains |
| C11 credential verb | four credential writers with different security properties — a hardened shared helper, two same-directory hand-rolled writers, and a raw `mkstemp` under an unvalidated `$TMPDIR` holding a forwarded TGT | C9 domains |
| C12 authz backstop | 28 protocol-edge authorization sites, 26 of them on one plane, plus four *other* authorization schemes on four other planes, over a rule engine already in `src/fs/path/` that the VFS never asks | the ordering position §3.4 reserves at 1.5 |
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
/* src/fs/vfs/vfs_policy_domain.c */
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
    unsigned                atomic:1; /* OUT: set by the slot when the storage
                                       * decided and could not have raced     */
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
/* src/fs/vfs/vfs_writer_spill.c — internal to the writer */
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

Nine new vtable members and two new capability bits (§3.2, §6). Verdicts use the
slot-matrix legend: `seam` = the generic path above the driver is already exact,
`np` = the protocol or API has no such operation, `dec` = decorator, relayed to
the leaf, `walk` = decorator, descends via `brix_vfs_decorator_source()`,
`flat` = the store has no namespace to operate on, `ro` = read-only driver,
`tier` = the nearline tier owns the decision, `syn` = synthetic driver,
`cas` = content-addressed, the operation is meaningless.

`✅` = implement in this phase. Every `—` cell must be written into
`tools/diag/sd_slot_matrix.py`'s verdict table in the same commit that adds the
slot, or `check_sd_driver_conformance.py` reports an unexplained hole.

### B.1 — space, publish and exchange

| driver | `reserve` | `sync_publish` | `exchange` | `exchange_cred` | `CAP_PRECOND` |
|---|---|---|---|---|---|
| posix | ✅ `fallocate(FALLOC_FL_KEEP_SIZE)` | ✅ parent-dir fsync | ✅ `renameat2(RENAME_EXCHANGE)` | — `np` (no per-user posix leg) | ✅ ABSENT only |
| block | — `flat` | — `flat` | — `flat` | — `flat` | — `flat` |
| http | — `np` | — `np` | — `np` | — `np` | ✅ probed at init |
| xroot | ✅ forward `oss.asize` on open | — `np` (no wire verb) | — `np` | — `np` | — `np` |
| cache | — `dec` | — `dec` | — `dec` | — `dec` | — `dec` |
| stage | — `dec` | — `dec` | — `dec` | — `dec` | — `dec` |
| remote | ✅ MPU part sizing | — `np` | — `np` | — `np` | ✅ `If-Match` / `If-None-Match` |
| frm | — `tier` | — `seam` | — `seam` | — `seam` | — `tier` |
| mirage | — `syn` | — `syn` | — `syn` | — `syn` | — `syn` |
| ceph | — `np` (verify, see B.3) | — `np` (no dirent to flush) | — `np` | — `np` | — `cas` |
| cephfs_ro | — `ro` | — `ro` | — `ro` | — `ro` | — `ro` |
| pblock | ✅ chain reserve + quota | — `flat` (catalog is the journal) | ✅ one catalog transaction | ✅ `sd_pblock_cred.c` twin | ✅ `RENAME_NOREPLACE` equivalent |

### B.2 — lifecycle: bulk delete, recall, evict

| driver | `unlink_many` | `unlink_many_cred` | `CAP_BULK_DELETE` | `recall_cred` | `evict` | `evict_cred` |
|---|---|---|---|---|---|---|
| posix | — `seam` | — `seam` | — | — `np` | — `np` | — `np` |
| block | — `flat` | — `flat` | — | — `np` | — `np` | — `np` |
| http | — `np` (RFC 4918 has no batch DELETE) | — `np` | — | ✅ twin of `recall` | — `np` | — `np` |
| xroot | — `np` (one path per `kXR_rm`) | — `np` | — | ✅ twin of `recall` | — `np` | — `np` |
| cache | — `dec` | — `dec` | — `dec` | — `walk` | ✅ promote `sd_cache_maint.c` evict | ✅ instance-keyed twin |
| stage | — `dec` | — `dec` | — `dec` | — `walk` | ✅ release the staged copy | ✅ instance-keyed twin |
| remote | ✅ `POST /?delete` | ✅ signed as the user | ✅ | ✅ twin of `recall` | — `np` | — `np` |
| frm | — `seam` | — `seam` | — | ✅ twin of `recall` | ✅ release the online copy | — `np` (no per-user MSS leg) |
| mirage | — `syn` | — `syn` | — | — `syn` | — `syn` | — `syn` |
| ceph | — `seam` (no batch in the C API) | — `seam` | — | — `np` | — `np` | — `np` |
| cephfs_ro | — `ro` | — `ro` | — | — `ro` | — `ro` | — `ro` |
| pblock | ✅ one transaction | ✅ `sd_pblock_cred.c` twin | ✅ | ✅ twin of `recall` | — `np` (nearline is `pblock_nearline.c`) | — `np` |

`CAP_BULK_DELETE` is advertised only where the batch is **one round trip or one
transaction**. A driver that would loop over the keys internally must leave the
slot empty and the bit clear: the generic per-key loop in
`brix_vfs_delete_many()` already does that, does it under the policy gate, and
reports per-key errno — an in-driver loop would only hide those three properties.

### B.3 — per-driver implementation notes

**posix** (`src/fs/backend/posix/`). `reserve` lands in `sd_posix_io.c` beside
the existing write path; `fallocate` is **already in the seccomp allowlist**
(`src/core/seccomp/seccomp_core.c:119`), so no filter change is needed — and it
is the only `fallocate` reference in the tree today, i.e. the syscall is
permitted and unused. `sync_publish` lands in `sd_posix_ns.c`, which is also
where both `brix_staged_commit` calls live (`:497`, `:499`) — the same two lines
C3's parent-dir fsync has to become correct behind. `exchange` sits beside
`brix_renameat_noreplace_fallback` (`src/fs/path/beneath.c:308–333`), and
**must not copy its fallback**: `RENAME_NOREPLACE` degrades to a plain
`renameat` because the caller had already run a stat-based precondition, but an
`exchange` whose whole contract is atomicity has no such consolation. On
`ENOSYS`/`EINVAL` it reports `ENOTSUP` and the VFS refuses; it never emulates.

**block** (`src/fs/backend/block/`). A fixed-extent device with no namespace:
every namespace-shaped slot is `flat`, as it already is for `mkdir`/`rename`.

**http** (`src/fs/backend/http/`). `recall_cred` is a mechanical twin of the
existing `recall` (`sd.h:435`) and inherits the `_cred` rule from the gap wave:
the origin request is signed with the *user's* credential, and because the slot
is **lazy** — the request is issued after the call returns `NGX_AGAIN` — it must
**copy** the borrowed credential, not retain the caller's pointer.
`CAP_PRECOND` is the one runtime-determined verdict in this appendix: an origin
that ignores `If-Match` rather than answering `412` must not be advertised as
atomic. The driver probes once at init; a probe that cannot reach the origin
records "not atomic", because failing closed on a *guarantee* means claiming
less, not more.

**xroot** (`src/fs/backend/xroot/`). `reserve` forwards as `oss.asize` on the
open request — the same channel the size hint already travels — so it is a
request-building change, not a new round trip. There is no `kXR_*` verb for a
directory fsync or for `RENAME_EXCHANGE`, and `kXR_rm` carries exactly one path,
so bulk delete is `np` rather than `seam`.

**cache / stage** (`src/fs/backend/cache/`, `src/fs/backend/stage/`). Both are
decorators: every namespace-shaped slot relays to the leaf (`dec`) and every
residency-shaped slot descends through `brix_vfs_decorator_source()` (`walk`).
`evict` is the exception and the reason the slot exists: eviction is the
decorator's **own** state, not the leaf's, so `evict` on `cache` promotes the
policy code already in `sd_cache_maint.c` to a first-class slot and `evict` on
`stage` releases the staged copy. Their `_cred` twins are **instance-keyed**:
the forwarder decides on the instance it is called on, which is the trap the
gap wave documented — an object-keyed slot dispatching on the object's driver
would send an evict for a cached object to the *origin*. Both must also honour
`check_sd_driver_conformance.py:188`'s decorator-parity rule: a slot relayed by
`stage` and not by `cache` is a red, and that is exactly how `truncate_path`
was found.

**remote** (`src/fs/backend/remote/`, protocol logic in `src/fs/backend/s3/`).
Three notes, in descending order of how easily they are got wrong:

1. **The transport needs no change.** `brix_s3_transport_t::request`
   (`src/fs/backend/s3/sd_s3_transport.h:39–45`) already carries
   `const void *body, size_t body_len`, so `POST /?delete` with a `<Delete>`
   document is expressible through the injected transport as it stands. Only
   the request builder, the XML writer and the `<DeleteResult>` parser are new.
2. **Do not reach for `Content-MD5`.** S3's original `DeleteObjects` contract
   requires it, and **there is no MD5 implementation anywhere in `src/`** —
   adding one to satisfy a header would be the worst reason to introduce a
   broken hash. Use the modern equivalent instead: `x-amz-checksum-crc32` plus
   `x-amz-sdk-checksum-algorithm: CRC32`, computed with the CRC-32/IEEE kernel
   already in the tree (`brix_crc32_ieee`, `src/core/compat/crc32_ieee.h` —
   note the header's own warning that this is *not* CRC-32C).
3. **The body must be signed.** Both signers default to `UNSIGNED-PAYLOAD`
   (`sd_s3_sign.c:193`, `sd_s3_sign_ext.c:252`); a batch delete is a mutation
   whose payload *is* the request, so it signs the real hash via
   `sd_s3_sha256_hex` (`sd_s3_sign.c:93`). `unlink_many_cred` signs with the
   user's key — and per the confused-deputy rule from the gap wave, the test
   asserts on the **SigV4 signing key**, never on the request bytes.

`reserve` maps to multipart-upload part sizing, which is also where C5's
160 GB ceiling comes from: `sd_remote_write.c:66` starts with
`expected_size = -1`, and a reservation is precisely the missing number.

**frm** (`src/fs/backend/frm/`). The nearline tier owns residency, so `evict`
promotes the existing release path and `recall_cred` twins the existing
`recall`. `reserve` is `tier`, not `np`: the MSS may well have a reservation
concept, but it is the tier's to schedule, not the VFS's to demand.

**mirage** (`src/fs/backend/mirage/`). Synthetic driver, no `CAP_DIRS`, no
storage: every new slot is `syn`.

**ceph / cephfs_ro** (`src/fs/backend/rados/`, plus `sd_ceph.c`). Two standing
obligations. First, `ceph` `reserve = np` **must be verified against the real
librados C headers inside the container image layers**, the way the Ceph
namespace work was: the published docs describe C++ APIs the C header does not
expose, and this verdict is exactly the kind that gets written from
documentation and is wrong — `copy_from` was already found that way. Second,
every namespace slot added here inherits the RADOS identity rule: **the ioctx
IS the identity at the OSDs**, so any `_cred` twin needs an ioctx-explicit
`*_io` core shared with the plain slot plus the tagged acquire/release runner
in `sd_ceph_ns_cred.c` — eight longhand bodies failed `check_duplication` last
time, and the release is the security-relevant half. `cephfs_ro` is read-only:
every mutation slot is `ro`, and the mutation-policy kernel refuses above it
with `EROFS` long before dispatch.

**pblock** (`src/fs/backend/pblock/`). The richest driver and the one that
gets all four namespace-shaped slots. `unlink_many` and `exchange` are single
catalog transactions in `sd_pblock_catalog_ns.c` / `sd_pblock_catalog_objects.c`
— which is the whole argument for the slots: the generic loop would be N
transactions and N fsyncs. `reserve` composes chain reservation with the
existing quota admission (`pblock_quota_admit`, `pblock_quota.h:40`, and
`pblock_quota_max_size`, `:47`) so that a reservation that would exceed the
per-uid ceiling fails **before** any block is chained, with `EDQUOT` rather
than a partial reserve. The `_cred` twins go in `sd_pblock_cred.c`, next to the
ones already there. `sync_publish` is `flat`: the catalog transaction is
already the durability record, so a directory fsync has nothing to flush.

---

## Appendix C — end-to-end call flows

Six flows, one per item that changes a call path. `--` comments carry the file
anchor where one exists today; a line with no anchor is new code.

### C.1 An out-of-order XRootD write to an S3-backed export

```
kXR_write(off=8M, len=1M) on a substream
  brix_vfs_write(handle, buf, len, off)                        -- vfs_writer.c:156
    require_carried_mutation(policy, proto, MUTATE_WRITE)      -- EROFS gate
    writer_random_backend(ctx) == 0                            -- no CAP_RANDOM_WRITE
    off != w->staged_cursor
      TODAY: errno = EINVAL, NGX_ERROR                         -- vfs_writer.c:176
      NEW:  -> enter spill mode
            mkstemp under brix_vfs_spill_path                  -- AFTER the gate
            brix_vfs_pwrite_full(spill.fd, buf, len, off)
            spill.high_water = max(high_water, off + len)
            spill.written   += len                             -- for the hole check
...
kXR_close
  brix_vfs_staged_commit(st, pre)                              -- vfs_staged.c:369
    require_carried_mutation(policy, proto, MUTATE_PUBLISH)
    spill.written != spill.high_water ?  EINVAL, no publish    -- the hole rule
    reserve(obj, spill.high_water)                             -- C5: pick part size
    drain: for each part-sized chunk in offset order
             driver->staged_write(st, chunk, len, cursor)      -- now sequential
    driver->staged_commit(st, pre)                             -- C6: If-None-Match
    unlink(spill.path)
```

Result codes the client sees: an unfillable hole is `kXR_ArgInvalid`; a spill
that will not fit under `brix_vfs_spill_max` is `kXR_NoSpace` **at spill entry**,
not partway through the object; a reservation the origin refuses is
`kXR_NoSpace` before the first part is uploaded.

The two items compose: the spill is what makes the final size known before the
first part is uploaded, and the final size is what makes the part size legal —
`sd_remote_write.c:66` starts `expected_size = -1` today, which is exactly the
number the spill supplies.

### C.2 `kXR_prepare` with `kXR_stage` against a tape-backed export

```
brix_handle_prepare
  for each resolved path:
    brix_vfs_recall(ctx, reqid)                                -- NEW seam
      require_confined_mutation(ctx, MUTATE_STAGE)             -- EROFS gate (NEW)
      require_unlocked(ctx, MUTATE_STAGE)                      -- C7
      inst = brix_vfs_decorator_source(ctx->sd)                -- walk to the leaf
      brix_sd_caps(inst) & CAP_NEARLINE ? : ENOTSUP
      cred = brix_vfs_cred_resolve(...); COPY into the job     -- lazy slot, A.6
      driver->recall_cred(inst, key, cred, reqid_out[40])
        -> NGX_AGAIN  queued, reqid_out filled                 -- sd.h:435
        -> NGX_OK     already online, no job
    brix_stage_request_add(reqid, requester)                   -- registry:104
  respond with the registry's reqid

kXR_QPrep
  brix_vfs_residency(ctx, &out)                                -- the truth
  brix_stage_request_get(reqid)                                -- the bookkeeping
    QUEUED | ACTIVE | DONE | FAILED | CANCELLED                -- registry:53-60
```

Two orderings matter here. The **policy gate precedes the capability check**, so
a read-only export answers `EROFS` rather than disclosing whether the backend
is nearline at all. And `brix_stage_request_owner_check` (`registry:119`) runs
before cancel and before evict, so one user cannot cancel another's recall — the
`_cred` copy above is the same rule applied to the credential rather than to the
request.

`prepare_command` is reached only when the leaf has no `recall` slot, which the
config advisor reports at `nginx -t` time rather than at first prestage.

### C.3 A recursive DELETE of an S3-backed collection

```
brix_vfs_rmdir(ctx, recursive=1)                               -- vfs_unlink.c:302
  brix_vfs_delete(ctx, recursive)                              -- :250
    require_confined_mutation(ctx, MUTATE_REMOVE)              -- EROFS, then EINVAL
    require_unlocked(ctx, MUTATE_REMOVE)                       -- C7 (NEW)
    brix_vfs_delete_via_driver(ctx, drv)                       -- :124
      leaf = brix_vfs_ns_leaf(ctx->sd)                         -- vfs_cred.c:510
      cred = brix_vfs_cred_resolve(...)
      brix_vfs_driver_rmtree(leaf, drv, logical, cred, depth)  -- :43
        depth > BRIX_FS_TREE_MAX_DEPTH (512) ?  ELOOP          -- fs_walk.h:23
        walk depth-first, filling a window of <= 1000 keys
          leaf caps & CAP_DIRS ?  flush at each directory boundary
                               :  flush whenever the window is full
          leaf caps & CAP_BULK_DELETE
            ?  driver->unlink_many_cred(inst, keys, n, errs, &done, cred)
            :  per-key driver->unlink_cred(...)                -- unchanged
        one metric observation, key count as the value
      brix_sd_cache_evict(ctx->sd, logical)                    -- leaf dispatch
                                                                  skipped the decorator
```

The `CAP_DIRS` branch is the whole correctness content of C4, and it is the
common case rather than the exception: **every driver except `mirage`
advertises `CAP_DIRS`**. Batching across a directory boundary on a backend with
real collections removes a parent before its children. The only place a flat
window is legitimate is `brix_vfs_delete_many()`, where the client itself
supplied a flat key list (S3 `DeleteObjects`) and no tree walk is involved.

### C.4 A locked resource written over `root://`

```
kXR_open(O_WRONLY) on /export/data/run42.root
  brix_vfs_open(ctx, flags)
    require_confined_mutation(ctx, MUTATE_OPEN)     -- EROFS first, always
    require_unlocked(ctx, MUTATE_OPEN)              -- NEW
      webdav_lock_path_ascend equivalent            -- lock_check.c:104
        walk target -> export root, reading WEBDAV_LOCK_XATTR_KEY
      found: live, depth-0, owner = another principal
      ctx->lock_token == NULL                       -- root plane carries none
      -> NGX_ERROR, errno = EBUSY
    brix_kxr_from_errno(EBUSY) -> kXR_FileLocked    -- error_mapping.c:61
```

The same lock refuses the same write over GridFTP (`550`), S3
(`409 OperationAborted`), OCI (`DENIED`) and WebDAV-without-token (`423`, the
one row `brix_http_errno_to_status` is missing today — §5.0). A WebDAV client
presenting the token in an `If:` header proceeds, because that is what holding
a lock means. Note the reverse table already maps `kXR_FileLocked` back to
`EAGAIN` (`error_mapping.c:116`), which is a *client-side* retry hint and is
deliberately not symmetric with `EBUSY`.

### C.5 Durable publish — the flow C3 is fixing

Today, in full, for every staged publish in the tree:

```
brix_staged_commit_excl(log, root_canon, staged, final_path)   -- staged_file.c:335
  staged_commit_internal(..., exclusive=1)                     -- :231
    rootfd    = brix_beneath_open_root(root_canon)             -- beneath.c:79
                open(root_canon, O_PATH|O_DIRECTORY|O_CLOEXEC)
    tmp_rel   = brix_beneath_strip_root(root_canon, tmp)       -- :254
    final_rel = brix_beneath_strip_root(root_canon, final)     -- :255
    fsync(staged->fd)                                          -- :274-281
      failure -> unlink temp, close, NGX_ERROR, DO NOT publish      [CORRECT]
    fchmod / brix_chmod_confined_canon                         -- :291-301
    brix_rename_beneath{,_excl}(rootfd, tmp_rel, final_rel)    -- :306
    (void) fsync(rootfd)                                       -- :317-319  [INERT]
    close(rootfd)
```

The data fsync is right and has been since phase 51 — a failed flush refuses to
publish rather than exposing a torn object. The directory fsync three statements
later is wrong twice over: `fsync` on an `O_PATH` descriptor fails `EBADF`, and
the `(void)` cast discards the failure; and even with a usable descriptor
`rootfd` is the **export root**, while `final_rel` is a path *relative* to it —
the entry the rename created may be many levels below. It is the only
directory-durability attempt anywhere in `src/` (38 `fsync`/`fdatasync` sites,
every other one on a file, a journal or a `brix_sd_obj_t`), and it does nothing.

The replacement, driven from the VFS so all seven call sites get it at once:

```
brix_vfs_staged_commit(ctx, pre)
  require_carried_mutation(policy, proto, MUTATE_PUBLISH)
  ...driver->staged_commit(st, pre) as today, rename included...
  durable_publish on AND leaf caps & CAP_SYNC_PUBLISH ?
    driver->sync_publish(inst, final_rel)
      pfd = openat(rootfd, dirname(final_rel), O_RDONLY|O_DIRECTORY|O_CLOEXEC)
      fsync(pfd); close(pfd)
```

**A failed `sync_publish` is reported, never swallowed** — that is the entire
point of the item — but it does **not** roll the publish back. The rename has
already happened, the name is already visible, and it may have replaced a prior
version; unpublishing would destroy an object this code never owned. So the
contract is: `NGX_ERROR` with `errno` from the `fsync`, an `ERR`-level log
naming the path, and the explicit statement in the header that the object is
**visible but not proven durable**. The caller decides; a TPC pull can retry the
whole transfer, a WebDAV `PUT` can answer `500` and let the client re-`PUT`.
Silently returning `NGX_OK` — which is what `(void) fsync(rootfd)` does today —
is the one option the item exists to remove.

The seven call sites reached through two functions:
`sd_posix_ns.c:497`, `:499` · `vfs_staged.c:370`, `:372` ·
`namespace_ops_copy.c:252` · `webdav/tpc_pull.c:282` ·
`root/write/chkpoint_recover.c:106`.

### C.6 A dedup publish against service storage

```
brix_gcas_publish(cs, key)                                     -- gcas.c:69
  TODAY: cs->store->driver->dedup_publish(cs->store, key, rel)
         no policy gate, no domain assert, WARN-logged on failure

  NEW:   brix_vfs_service_mutation(cs->store, DOMAIN_CACHE, MUTATE_DEDUP)
           inst->domain != DOMAIN_CACHE ?  EINVAL + crit log, refuse
         cs->store->driver->dedup_publish(cs->store, key, rel)

brix_gcas_evict_gc(cs, key)                                    -- gcas.c:91
  TODAY: (void) cs->store->driver->dedup_gc(cs->store, rel)
         the result is discarded outright
  NEW:   same assert; the discarded result becomes a WARN
```

Both functions return `void`, so today a `dedup_gc` failure leaves an
unreferenced alias behind with no trace at all. The assert is **not** an
authorisation check — no endpoint named this storage and the export policy is
the wrong authority (§3.7). It asserts that the instance the CAS store is
pointed at really is a cache store, which is the property a misconfiguration
or a future refactor would break, and it fails with `EINVAL` at `crit` because
reaching it means the configuration was already wrong at `nginx -t` time.

---

## Appendix D — risk register and deliberately rejected alternatives

### D.1 Risks

| risk | item | mitigation |
|---|---|---|
| Strict lock enforcement refuses traffic that worked yesterday | C7 | `advisory` mode for one release; `tools/diag/lock_scan.py` before upgrade; the release note leads with it |
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

Every guard below is in `tools/ci/` and runs in `guards.yml`. The column that
matters is not "does it pass" but **what it will catch in this phase**, because
a guard that cannot catch anything here is not a constraint on the design.

### E.1 Guards that constrain the design

**`check_vfs_mutation_gate.py`** — the phase-105 guard. Every path mutator must
call the confined form of the kernel. The new verbs (`recall`, `evict`,
`delete_many`, `exchange`) become mutators **by the guard's own definition** the
moment they take a path, so it covers them with no change. One extension is
needed, in W8 and not before: once `brix_lock_enforcement` exists, a path
mutator that calls the policy kernel and *not* `brix_vfs_require_unlocked`
should be reported. `tools/ci/vfs_mutation_gate_backlog.txt` is the ratchet
file; the phase adds no entries to it.

**`check_vfs_seam.py`** — the raw-syscall ban. Two distinct obligations:

- The spill temp is the risk. `vfs_writer_spill.c` performs real file I/O
  outside `src/fs/backend/`, so it either carries a `vfs-seam-allow` marker
  naming service storage, or it goes through an existing helper. **Prefer the
  helper**: `brix_vfs_pwrite_full` and the owned-temp path already exist, and
  the spill should not become the tree's newest raw-syscall site in the same
  phase that types the waivers.
- **C9 changes this guard's contract.** Today `_raw_tier3_violation`
  (`check_vfs_seam.py:212`) returns `None` the moment the substring
  `vfs-seam-allow` appears on the line — the prose is unread. After W9 it parses
  a domain constant and checks it against the directory-prefix entitlement table
  in §4/C9. The switch from "any prose" to "an entitled domain" happens in the
  commit that finishes annotating, never before: an enforcing guard over a
  half-annotated tree is a red build carrying no information. Three backlog
  files ratchet this guard (`vfs_seam_backlog.txt`,
  `vfs_seam_backlog_ns.txt`, `vfs_seam_backlog_client.txt`); the phase removes
  entries, adds none.

**`check_sd_driver_conformance.py`** — slot presence and decorator parity.
`_PARITY_BASE` (`:62–66`) is 15 ops today and `PARITY_OPS` (`:67`) doubles it
with the `_cred` twins to 30. Four of the nine new slots join the base:

| slot | parity? | why |
|---|---|---|
| `reserve` | ✅ join | `dec` on both decorators — a slot relayed by one and not the other is the `truncate_path` bug again |
| `unlink_many` | ✅ join | `dec` on both |
| `exchange` | ✅ join | `dec` on both |
| `evict` | ✅ join | implemented by **both** decorators as their own state |
| `sync_publish` | ❌ excluded | leaf-only; a decorator has no dirent to flush, so parity would demand a slot that cannot exist |
| `recall_cred` | ❌ excluded | `walk`, not `dec` — parity is about relaying, and the existing `recall` is already excluded for the same reason |

Joining the base is a two-line change (`_PARITY_BASE` and the `_cred` twins come
free from `:67–69`), and `_decorator_parity` (`:188`) then reports any driver
that gains the slot on `stage` but not `cache`. The script's `_SLOT_RE`
(`.[a-z0-9_]+\s*=`) already tolerates digits and underscores, so no new slot
name needs a regex change — the comment above it records why the digit class
matters (`.preadv2` was invisible to the matrix, the op count and every gate
when the class omitted `[0-9]`).

**`check_vfs_identity_branch.py`** — this one is a **design constraint, not a
review comment**. Its `PATTERN` bans, inside `src/fs/vfs/*.c`, both
`== "s3"`-style string comparisons and direct references to
`sd_(http|s3|remote|ceph)_driver`. Only the config-time factory family
(`vfs_backend_config*.c` / `vfs_backend_registry*.c`) is exempt. So:

- spill entry is `!(brix_sd_caps(inst) & BRIX_SD_CAP_RANDOM_WRITE)`, never
  "is this the http driver";
- bulk-delete batching is `brix_sd_caps(inst) & BRIX_SD_CAP_DIRS`;
- precondition strength is `BRIX_SD_CAP_PRECOND`, which is precisely why C6
  introduces a capability bit rather than letting the protocol layer ask which
  driver it is talking to.

Every "is it capable" question in this phase has to be answerable as a cap bit,
and the guard is what makes that non-negotiable.

**`check_duplication.py`** — absolute, backlog 0. The `_cred` twins are where
this bites, and the Ceph namespace work is the precedent: eight longhand
`_cred` bodies failed the gate and had to become ioctx-explicit `*_io` cores
shared with the plain slots plus **one** tagged acquire/release runner. Every
`_cred` twin here shares an `*_io` core with its plain sibling **from the first
commit**, not after the guard complains — and the release half is the
security-relevant one, so it lives in the shared runner, not in each body.

**`check_complexity.py`** — CCN ≤ 15, **no exemptions, no backlog**. Two
functions in this phase will exceed it if written straight through: the spill
writer's entry/append/drain dispatch and the tree batcher's
walk + window + flush loop. Both split at the design stage (§8's file list
already names `vfs_writer_spill.c` and `vfs_unlink_many.c` as separate units)
rather than after the guard reds.

**`check_file_size.py`** — 600 lines, `.c` **and** `.h` (`CAP = 600`, `:25`).
`sd.h` is the file to watch: nine new members with the doc comments this header
gives every slot is on the order of 60–80 lines. `sd_cred_types.h` was already
split out of it for exactly this reason, and `sd_batch_types.h` (§8) is the
pre-planned second split for the batch structs.

**`check_readme_coverage.py`** — any directory at depth 1–2 under `src/` with
**≥ 2** C sources needs a `README.md` (`:52`). This phase adds no new directory,
so the obligation is the softer one: `src/fs/vfs/README.md` and
`src/fs/backend/README.md` describe the seam and are wrong the moment the
vocabulary grows from 11 to 15 — they are in §8's file lists for that reason.

### E.2 Guards that verify the wiring

- **`check_config_coverage.py`** — every new `src/` `.c` file must appear in the
  repo-root `./config`, and a source-list change means a re-`./configure`, not an
  incremental `make`. §8 lists six new `.c` files.
- **`check_directive_registry.py`** + `directive_registry_allowlist.txt` — the
  four new directives must be rows in the `BRIX_TIER_DIRECTIVES` X-macro
  (`src/core/config/tier_directives.h`), not hand-registered commands.
- **`check_metric_names.py`** and **`check_metric_cardinality.py`** — invariant 8.
  The new labels are `{proto}` (10 values, already used by the phase-105 cube),
  `{kind}` (4 precondition kinds) and `{op}` (now 15). A path, a key, a reqid or
  a user as a label fails the cardinality guard, which is the correct outcome —
  the batch key count belongs in the metric's **value**, never in a label.
- **`tools/diag/sd_slot_matrix.py --check`** — drift over a census that is
  header-derived, and therefore cannot omit a slot the way a hand-maintained
  table could. The matrix goes 54 × 12 = 648 cells to 63 × 12 = 756, and every
  new empty cell needs its verdict (Appendix B) in the same commit.
- **`check_todo_fixme.py`** and **`check_brix_namespace.py`** — no `TODO`s land
  with the phase, and every new symbol is `brix_`/`BRIX_`-prefixed.

### E.3 What no guard can catch — and what compensates

Worth recording explicitly, because W9 is what compensates: a hand-rolled
`open`/`write`/`rename` sequence is **not textually similar enough** to
`staged_file.c` to trip a token-based detector, so structural duplication of a
*contract* is invisible to `check_duplication`. That is how the tree ended up
with three independent staged-publish implementations and three credential
staging roots while the duplication backlog sat at zero.

The census that does see it is the per-domain waiver count (Appendix G). After
W9, a rising count in a domain is the signal `check_duplication` cannot give —
and it is the signal [phase 108](phase-108-vfs-consolidation.md) is measured by.

---

## Appendix F — requirement traceability

| item | §design | wave | tests | metric | guard |
|---|---|---|---|---|---|
| C1 out-of-order writes | §4 C1, A.9 | W2 | §9.1 C1, spill drain, hole refusal | `brix_vfs_spill_bytes_total`, `brix_vfs_spill_active`, `brix_vfs_spill_refused_total` | seam, complexity, file size |
| C2 prestage / evict | §4 C2, A.6, C.2 | W6 | §9.1 C2, ordering, `_cred` copy | `brix_vfs_recall_total{result}`, `brix_vfs_evict_bytes_total{driver}` | mutation gate, identity branch, duplication |
| C3 durable publish | §4 C3, A.7, C.5 | W3 | §9.1 C3, spy fsync counter, the `O_PATH` regression test | `brix_vfs_durable_publish_total{result}` | conformance (parity `dec` exclusion) |
| C4 bulk delete | §4 C4, A.5, C.3 | W5 | §9.1 C4, per-level batching on `CAP_DIRS` | `brix_vfs_bulk_delete_keys_total{driver}` (+ `..._batches_total`) | conformance, duplication, cardinality |
| C5 reserve | §4 C5, A.4, C.1 | W4 | §9.1 C5, MPU part sizing, `EOPNOTSUPP` is advisory | — (a reservation failure surfaces as `ENOSPC`) | conformance, identity branch |
| C6 preconditions / exchange | §4 C6, A.8 | W7 | §9.1 C6, advisory-vs-atomic | `brix_vfs_precond_failed_total{kind}`, `brix_vfs_precond_advisory_total{driver}` | conformance, ABI note, clean rebuild |
| C7 lock enforcement | §4 C7, A.2, C.4 | W8 | §9.1 C7, five-plane cross-protocol proof | `brix_vfs_lock_refused_total{proto}` | mutation gate (extended), directive registry |
| C8 dedup plane | §4 C8, A.3, C.6 | W1 | §9.1 C8 | `brix_vfs_mutation_denied_total{op="dedup"}` | slot matrix (header-derived), metric mirror assert |
| C9 typed domains | §3.7, §4 C9, A.3, App. G | W9 | §9.1 C9, the 108-vs-117 parser proof | domain label on the mutation counter | seam guard (new contract), cardinality |

---

## Appendix G — the storage-domain table

This appendix is **normative** for C9: the entitlement table in
[§4/C9](#c9--the-service-storage-domain-becomes-typed) is a summary of it, and
`check_vfs_seam.py`'s parsed table after W9 is generated from it. Where the two
disagree, this one is right.

### G.1 The seven domains

The last column is consumed by
[phase 108](phase-108-vfs-consolidation.md) §3.3, which is where durability per
domain is enforced.

| domain | covers | entitled path prefixes | durable |
|---|---|---|---|
| `EXPORT` | client-named storage | **none** — an export mutation takes the phase-105 gate, not a waiver | per `brix_durable_publish` |
| `CACHE` | cache store tree, meta sidecars, verify staging, cache-root files reached from a protocol handler | `src/fs/cache/`, `src/fs/backend/cache/`, `src/fs/backend/stage/`, `src/fs/meta/` | no (loss = re-fetch) |
| `STAGE` | upload stage dir, TPC transfer temps, the C1 spill | `src/fs/xfer/`, `src/tpc/`, `src/protocols/webdav/tpc_*`, `src/core/compat/staged_file*` | no (loss = retry) |
| `REGISTRY` | OCI store tree, tag pointers, referrers and store indexes, session state | `src/protocols/oci/` | **yes** |
| `CREDENTIAL` | delegated proxies, minted creds, keytabs, bearer and PEM files | `src/auth/`, `src/net/proxy/`, `src/core/compat/cred_stage.c`, `src/fs/backend/cred_mint*`, `src/fs/vfs/vfs_deleg*`, `src/protocols/webdav/delegation.c` | **yes** |
| `CONFIG` | trust anchors, CA bundles, signing keys, operator files | `src/core/config/`, `src/net/cms/blacklist_file.c` | n/a (read-mostly) |
| `JOURNAL` | FRM and stage journals, request registries | `src/fs/xfer/stage_*`, `src/fs/tier/`, `src/net/cms/` | **yes** |

`src/fs/xfer/` appears under both `STAGE` and `JOURNAL` deliberately: the
transfer temps and the request registry live in the same directory and are not
the same kind of storage. The prefix table resolves longest-prefix-first, so
`src/fs/xfer/stage_request_registry.c` is `JOURNAL` and the rest of
`src/fs/xfer/` is `STAGE`. That is the one place the "directories, not files"
rule bends, and it bends by a *file prefix*, not a full path, so it survives a
shard.

### G.2 The census, re-derived

Measured on the working tree at the head of this document. Two numbers matter
and they are not the same number:

| measure | count |
|---|---|
| lines in `src/**.{c,h}` mentioning `vfs-seam-allow` | **117** |
| …of those, doc-comment lines (leading `*` or `//`) | **9** |
| **real same-line markers** | **108** |

**The nine doc-comment lines are a W9 hazard.** `check_vfs_seam.py` suppresses a
violation on any line where the substring appears (`:213`, `:227`), so a file
header explaining the convention — `oci_store.c:20`, `oci_upload.c:22`,
`oci_upload_seal.c:18`, `oci_meta.c:24`, `delegation.c:49`,
`stage_request_registry.c:120`, `xmeta_path.c:251` and two more — is
indistinguishable from a marker to a substring test. That is harmless today
because those lines contain no syscall. It stops being harmless the moment the
guard demands a domain constant on every matching line: nine perfectly correct
doc comments become nine hard errors. **The W9 parser matches the marker form
`/* vfs-seam-allow: … */` on a line that is not a comment continuation, and the
first thing W9 proves is that the parser finds 108, not 117.**

Markers by area — this is a true partition and sums to 108:

| area | markers |
|---|---|
| `protocols/oci` | 25 |
| `protocols/webdav` | 20 |
| `protocols/root` | 17 |
| `fs/cache` | 15 |
| `tpc/outbound` | 6 |
| `net/cms` | 6 |
| `protocols/cvmfs` | 4 |
| `protocols/shared` | 3 |
| `fs/vfs` | 3 |
| `core/config` | 3 |
| `protocols/s3` | 2 |
| `net/proxy` | 2 |
| `protocols/gridftp` | 1 |
| `core/aio` | 1 |
| **total** | **108** |

### G.3 The reasons already cluster — which is the evidence the domain is real

The most frequent reason strings, verbatim and with exact counts. Nobody
coordinated these; they were written one at a time by whoever added the waiver,
and they still fall into the same seven buckets:

| reason (verbatim) | count | domain |
|---|---|---|
| `staged credential temp, not export storage` | 10 | `CREDENTIAL` |
| `cache-store staging file, svc-owned domain` | 9 | `CACHE` |
| `cred dir is svc-owned config, not an export` | 6 | `CREDENTIAL` |
| `metadata on a VFS-opened confined fd` | 4 | *(already correct — see G.4)* |
| `transient serve scratch (not export storage)` | 3 | `STAGE` |
| `sidecar staging file, not object data` | 3 | `CACHE` |
| `config-domain PASSTHROUGH proxy credential temp (not export storage)` | 3 | `CREDENTIAL` |
| `config-domain delegated proxy credential temp (not export storage)` | 3 | `CREDENTIAL` |
| `svc-owned cache tree` | 2 | `CACHE` |
| `separate upload stage-dir domain` | 2 | `STAGE` |
| `separate svc-owned storage domain (cache/stage), opened as worker` | 2 | `CACHE` |
| `registry store tree, not a VFS export object` | 2 | `REGISTRY` |
| `registry staging area sweep, not a VFS export listing` | 2 | `REGISTRY` |
| `registry's own store index, not a VFS export listing` | 2 | `REGISTRY` |
| `registry's own referrers index, not a VFS export listing` | 2 | `REGISTRY` |
| `config-domain trust-anchor PEM (not export storage)` | 2 | `CONFIG` |
| `config-domain signing-key PEM (not export storage)` | 2 | `CONFIG` |
| `config-domain delegated GSI proxy credential temp (not export storage)` | 2 | `CREDENTIAL` |
| `probe socket, non-export resource` | 2 | *(none — see G.4)* |

Several of these reasons **already contain the word "domain"**. The waiver
convention was reaching for a type and settling for prose; C9 gives it the type.

The long tail — TPC transfer temps, store bookkeeping records, session teardown,
staging idleness probes, `/proc` fd hygiene — is where W9 pass 1 does real work
rather than transcription, and the wave is sized accordingly.

### G.4 Two classifications the seven domains do not cover

Pass 1 must not be forced to lie, so two escape valves are part of the design,
not exceptions to it:

**`NOT_STORAGE` — 6 markers.** Some waived calls are not storage operations at
all: a probe socket (`protocols/cvmfs/origin_probe.c:117`, `:139`), the admin
unix socket (`protocols/root/session/admin_socket.c:543`, `:557`), and `/proc`
fd hygiene before `execv` (`protocols/root/query/prepare_cmd.c:105`, `:117`).
These are syscalls the seam guard sees because it greps for syscall names, not
because a filesystem object is involved. Forcing one of them into `CONFIG` or
`STAGE` would put a false entitlement in the table — precisely the failure mode
§4/C9 names as the wave's whole risk. They get `NOT_STORAGE`, which is entitled
everywhere and grants nothing, and the guard reports the count so it cannot
quietly become the default.

**Already-correct sites — 4 markers.** `metadata on a VFS-opened confined fd`
(all four in `net/cms/recv_forward.c`) marks an `fstat`-class call on a
descriptor the VFS itself opened. These are not domain questions; the call is
already on the right side of the seam and the marker only exists because the
guard greps by syscall name. They are annotated and then left alone — no
migration, no phase-108 follow-up.

---
*End of design record. The implementation and checked execution ledger above
supersede the original plan-only wording. The consolidation half of the original
v2 plan lives in [phase 108](phase-108-vfs-consolidation.md).*
