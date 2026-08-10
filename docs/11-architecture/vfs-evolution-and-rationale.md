# The BriX-Cache VFS — Evolution, Decisions, and Rationale

**Status:** Architecture record (written 2026-08-10, phase-88/89 era)
**Audience:** anyone asking "why does the VFS look this way?", "has this been
tried before?", or "what problem does this solve?" before changing it.
**Companion docs:**
[`vfs-interface-specification.md`](vfs-interface-specification.md) (the
idealized contract this history converged on) ·
[`history-storage-and-caching.md`](../09-developer-guide/history-storage-and-caching.md) ·
[`vfs-shared-architecture.md`](../09-developer-guide/vfs-shared-architecture.md) ·
[`multi-user-backend-credentials-through-the-vfs.md`](../09-developer-guide/multi-user-backend-credentials-through-the-vfs.md) ·
the phase docs under [`docs/refactor/`](../refactor/) cited throughout.

The VFS was not designed once and implemented; it **accreted under pressure**
from real problems — confinement escapes, worker-thread drift, four protocols
re-implementing the same semantics, object stores that refused to look like
POSIX, and origins that needed to see real user identities. This document
records the pressure, the decisions, the alternatives that lost, the bugs
that adversarial review caught, and the lessons — so future work extends the
design instead of unknowingly re-fighting it.

## Contents

1. [The problems that forced a VFS](#1-the-problems-that-forced-a-vfs)
2. [The eras](#2-the-eras)
3. [The pivotal decisions](#3-the-pivotal-decisions)
4. [How the VFS solves BriX-Cache's problems (the map)](#4-how-the-vfs-solves-brix-caches-problems-the-map)
5. [What adversarial review caught (the bug record)](#5-what-adversarial-review-caught-the-bug-record)
6. [Known residuals — the gap to the idealized interface](#6-known-residuals--the-gap-to-the-idealized-interface)
7. [Lessons learned (carried forward as working rules)](#7-lessons-learned-carried-forward-as-working-rules)
8. [Reading list](#8-reading-list)

---

## 1. The problems that forced a VFS

BriX-Cache serves **one namespace over four+ front doors** (XRootD `root://`
stream, WebDAV, S3, CMS data-server I/O — later GridFTP and CVMFS) from
**one nginx worker model** (single-threaded event loops + AIO thread pools),
in front of **storage that stopped being one local filesystem** (POSIX, block
devices, SQLite-cataloged block stripes, Ceph/RADOS, S3 objects, remote
XRootD/HTTP origins, tape). Before the VFS existed as a hard boundary, each
pressure showed up as a class of real or latent bugs:

1. **Confinement.** Every protocol handler open was a potential
   `../`-escape. Path resolution existed, but nothing *structurally*
   prevented a handler from calling `open(2)` on a client-influenced path —
   safety rested on review vigilance across four protocols' worth of call
   sites. The fix had to be kernel-enforced (`openat2(RESOLVE_BENEATH)`)
   and bypass-proof by construction: resolution in one layer, a cheap
   re-check in a second, the kernel refusing the escape in a third.
2. **Protocol drift.** kXR_mv, WebDAV MOVE, and S3 CopyObject are the *same
   storage operation* with different edge-case vocabularies: does a rename
   onto an existing directory replace it (`Overwrite: T`) or fail
   (`kXR_ItExists` — and is the conflict a directory, `kXR_isDirectory`)?
   Is deleting a populated collection recursive (RFC 4918 says yes) or
   `ENOTEMPTY` (POSIX says yes)? Implemented four times, these disagreed
   four ways; every backend added later would have multiplied the matrix.
   The answers had to be decided once and *inherited*.
3. **The TLS/sendfile trap.** nginx serves cleartext fastest with
   file-backed buffers (sendfile) and MUST serve TLS from memory-backed
   buffers; pgread additionally needs every byte in userspace for per-page
   CRC32c. A handler choosing wrongly produced silent corruption on TLS or
   a throughput cliff on cleartext. That decision had to leave the handlers
   entirely (project invariant 2), and later had to generalize to backends
   with *no fd at all*.
4. **Worker-thread duplication.** The event loop had a metered, cache-aware
   VFS; the AIO workers had *their own copies* of the raw
   read/write/readv/pgread loops — outside the funnel. Confinement,
   short-I/O policy, CRC computation, and error behaviour could (and did)
   drift between the two. This was phase-54's entire reason to exist.
5. **Observability gaps.** Per-op metrics and access logs implemented per
   protocol meant every new op or protocol silently under-reported — and
   conversely, resolution-time stats and bulk walks *over*-reported
   (phantom `OP_STAT` per rm/mv, one `OP_DIRLIST` per visited subdir).
6. **The credential wall.** The node authenticated to its origin as one
   static service account. On the wire between node and origin, every
   user's read, write, rename, and delete looked identical; the origin
   could enforce nothing per-user, audit logs named the proxy, and a
   deployment that wanted real identities at the origin simply couldn't
   have it. The identity had to travel the whole storage plane — reads,
   writes, namespace ops, and *detached write-back after a restart*.
7. **Non-POSIX storage.** Object stores have no fd, no atomic rename, no
   random write, sometimes no directories and no mutable metadata. Either
   every handler learns every backend's quirks, or a seam translates
   capability differences exactly once — and refuses honestly what cannot
   be translated (no silent read-modify-write emulation).
8. **Tape.** A read that faults a multi-minute recall cannot look like a
   POSIX read. Residency needed to be a first-class, non-blocking query
   (the WLCG Tape REST API asks without recalling); recall an async driver
   verb; and the recalled bytes needed a defined landing zone.

The answer to all eight is the same shape: **one funnel, policy above,
mechanism below, capabilities in between** — the contract now specified in
[`vfs-interface-specification.md`](vfs-interface-specification.md).

---

## 2. The eras

Dates and phase numbers refer to the docs under `docs/refactor/` and
`docs/superpowers/specs/`; commits named where they are load-bearing.

| Era | When | What changed | Key artifacts |
|---|---|---|---|
| 0. Per-protocol syscalls | pre-2026-06 | handlers called libc directly; path checks by convention | — |
| 1. The unified VFS + identity | early 2026-06 | one `*_vfs_*` surface for all four front ends; `openat2(RESOLVE_BENEATH)` confinement (phase-8); the unified identity model | commits `602872c5`, `a6b22d85`; phase-44 io_uring (`9150802c`) |
| 2. Thread-safe I/O core | planned 2026-06-24 | the worker-tier duplication dissolved into one POD-job executor | phase-54 → `vfs_io_core.{h,c}` |
| 3. The Storage Driver seam | 2026-06-24 → | every raw syscall lifted below a capability-typed vtable; POSIX becomes "just the default driver" | phase-55, `sd.h`, commit `c71b6457` |
| 4. Enforcement | 2026-06-25 → 06-28 | the seam goes from convention to CI-enforced invariant; three guard tiers; backlogs burned 56 → 0 | phase-56 Pillar F, phase-62, zero-exemptions spec 2026-06-28 |
| 5. Composable tiers | 2026-06-29 → | bespoke XCache/FRM machinery dissolved into config-composed `cache`/`stage`/nearline decorators; ONE fill spine; tape as a driver | phase-63, phase-64, commits `4ba3cfdb`, `b74d6ec5` |
| 6. Sharing & topology | 2026-06-27 → 07 | verb core + drivers compile into both the server and the ngx-free client `libxrdproto`; phase-66/67 bucket layout; façade split into `src/fs/vfs/` | layering spec 2026-06-27, `vfs-shared-architecture.md`, commits `2f75a1d4`…`5a5a037f` |
| 7. Identity through the seam | 2026-07 → 08 | per-user backend credentials (phases 1–3), full delegation modes (phase-70), capability uniformity + `cred_accept` (phase-71) | `multi-user-backend-credentials-through-the-vfs.md`, commits `b8b14c1e`, `46977a1b` |
| 8. Backend maturity | 2026-07 → now | pblock to POSIX parity; Ceph completion; S3 forwarding closure; GridFTP writer + gsiftp origin; lab caps + `space`; dedup / packed arena / shared nscache | phases 80–91, `e4b8cf58`, `ef00c15b`; phase-88 W1–W4 (in tree, 2026-08-10) |

### Era 1 — one surface, kernel confinement

The first consolidation created the protocol-agnostic VFS and moved
confinement from "the handler checked the path" to "the kernel refuses the
escape": every open goes through `openat2(RESOLVE_BENEATH)` against a
persistent per-worker `O_PATH` rootfd, and the VFS *re-verifies* the
caller's claim (`is_confined` + non-empty resolved path → else `EINVAL`)
before every syscall. The decision that **`EXDEV` = escape attempt =
kXR_NotAuthorized/403** dates from here and became a reserved errno meaning
for every later driver. Crucially, path *resolution* was kept OUT of the
VFS — `src/fs/path/` owns it and produces the `brix_path_result_t` the ctx
carries — giving an attacker three independent layers to beat (resolver,
façade guard, kernel), each cheap enough to keep.

The same era created `brix_identity_t`: wire-level authentication stayed
protocol-specific, but after verification every schema fills one canonical
principal shape (`BRIX_AUTHN_*` bitmask, DN/subject/issuer, VO lists, scope
verdicts). Without that normalization, era 7 (per-user backend credentials)
would have had nothing schema-neutral to key on.

The open cascade's raw-`open()` tail — reachable only for
server-constructed absolute paths with no export root — was fixed as a
*documented* property with a long in-code comment, because it looks like
tech debt and is not: simplifying it either breaks legacy no-root callers
or silently widens the raw branch to client paths.

### Era 2 — the worker duplication problem (phase-54)

The metered VFS was event-loop-only by necessity: its entry points allocate
from per-request nginx pools, emit Prometheus metrics and access-log lines,
and consult the read-through cache — none of which is thread-safe. So the
AIO workers had grown their own raw `pread`/`pwrite`/`readv`/`pgread`
loops — a **parallel raw-I/O implementation outside every VFS guarantee**.

Phase-54's answer was deliberately NOT "make the VFS thread-safe" (locks on
the hottest loop in the server) but a **two-tier split**:

- a POD job descriptor (`brix_vfs_job_t`: immutable IN fields, executor-owned
  OUT fields) with mandatory zeroing init helpers — nginx thread tasks are
  *reused*, and a stale OUT field leaking into a new run was a real failure
  mode the helpers exist to kill;
- one executor (`brix_vfs_io_execute`) that touches no pool, metric, log, or
  cache, dispatching READ / WRITE / PGREAD / READV / WRITEV / SYNC /
  TRUNCATE / OPENDIR to small per-op helpers that reuse the *same* pure
  bodies the loop uses (`pread_full`, `pwrite_full`, the pgread
  encode-in-place, the readv segment reader);
- the read path builds the *same* buffer chain whether invoked synchronously
  or from an AIO completion — that symmetry is what killed the drift class;
- the dirlist scan moved onto the same core with a confinement upgrade: the
  worker receives an already-confined *fd* (job field `rootfd`), never a
  path to re-open — no TOCTOU between loop-side resolution and worker-side
  scan.

The migration was phased per-opcode with perf gates, and the state/ownership
matrix ("who may touch what, on which thread") written in the plan became
§12 of the spec.

### Era 3 — the Storage Driver seam (phase-55)

With all I/O in one funnel, phase-55 cut underneath it: `brix_sd_driver_t`
(a static vtable + capability bitmap), `brix_sd_instance_t` (one bound
export), `brix_sd_obj_t` (one open object), and the registry. The one-line
goal: *make a block / object backend a first-class — ultimately primary —
storage backend without any protocol handler, metric, cache, or access-log
code changing above the seam.*

Design principles fixed then, still verbatim in the spec: worker-safe raw
ops (no pool/metric/log/lock — they ARE the thread-pool bodies);
**confinement is the driver's job below the seam** (POSIX via `openat2`;
object stores via normalized key-prefix maps that reject `..`); **errno
facts, not wire codes**; the VFS keeps loop policy and buffer building;
**capability absences are honest** — degrade or reject, never emulate.

Phase-55 §5 named **five hard problems** and resolved each *in the design*
before code moved — worth restating because every one is a place a naive
seam would have leaked:

1. **The fd/sendfile leak.** The memory-vs-file buffer choice was
   `is_tls || want_pgcrc`; an object backend has no fd at all. Resolution:
   file-backed/sendfile ONLY when the backend blesses it
   (`CAP_SENDFILE`, later the `read_sendfile_fd` verdict slot); everything
   else serves memory-backed — which was already the TLS path, so the
   "degraded" mode was a proven mode.
2. **Confinement is a filesystem concept.** `RESOLVE_BENEATH` is
   POSIX-only. Resolution: keep the VFS logical-path guard unchanged, make
   *physical* confinement a per-driver duty, preserve `EXDEV`-means-escape
   as a driver-returned fact.
3. **Random write & rename atomicity.** Object stores can't `pwrite` at
   arbitrary offsets and have no atomic rename. Resolution: the
   staged-write lifecycle *already* modeled object PUT exactly
   (`staged_open`→MPU-init, `staged_write`→part upload, `staged_commit`→
   complete = the atomic publish, `staged_abort`→abort). Random-write
   opcodes against a `!RANDOM_WRITE` backend are refused
   (`ENOTSUP`→`kXR_Unsupported`/501, metric-surfaced) — an explicit,
   documented v1 limitation instead of hidden read-modify-write, which is
   expensive, non-atomic, and lies under concurrent writers. A composed
   POSIX *stage* tier lifts the restriction for uploads in progress (the
   random writes land on the stage file; only the finished object is
   promoted).
4. **Server-side copy.** `server_copy` cap: POSIX = `copy_file_range`,
   object = remote CopyObject; absent ⇒ the VFS's own pread→pwrite
   stream-through, which already existed.
5. **Blocking network I/O.** Object-store ops are blocking network calls;
   on the event loop they would stall a worker (cf. the shmtx postmortem).
   Resolution: phase-54's AIO tier already existed — the object driver's
   raw ops simply *are* thread-pool bodies, and the handful of inline
   namespace entry points gain an offload branch. This is the one place
   the upper VFS is allowed backend-*capability*-aware dispatch.

The POSIX driver landed as a **behaviour-preserving wrapper** — every
vtable slot delegating verbatim to the existing confined helper
(`brix_open_beneath`, `pread_full`/`pwrite_full`, `brix_ns_*`,
`*xattr_confined_canon`, `brix_staged_*`) — so the seam shipped at zero
behavioural risk, and the *second* backend proved it later.

### Era 4 — from convention to machine-checked invariant (phases 56, 62)

Phase-56's whole-layer audit found the uncomfortable truth: the funnel
existed but was *bypassed* — handlers still made raw namespace/metadata
syscalls, and a few byte paths went around the seam. Two responses defined
the era:

**The guard + backlog mechanism (F0).** `check_vfs_seam` landed with a
checked-in backlog of 48–56 grandfathered files: any *new* bypass fails CI
immediately; the existing ones burn down monotonically to 0. Regressions
became structurally impossible while the migration proceeded at its own
pace. The cultural rule that `--regen` is for deliberate migrations only —
never to clear red CI — is part of the mechanism, not etiquette.

**Phase-62 extended the invariant beyond bytes** to the entire filesystem
surface — `open`, `stat`/`lstat`, `opendir`/`readdir`,
`unlink`/`rename`/`mkdir`/`rmdir`, `truncate`/`chmod`, and the xattr
family — across every protocol handler, with a third guard tier and its own
backlog (also now 0). The migration went cluster by cluster (the phase doc
records each): the kXR `fattr` dispatcher lifted one ctx to function scope
and routed path-mode through ctx-xattrs and handle-mode through the new
fd-xattr variants; `kXR_open`'s five pre-flight `stat()`s became one
`probe` wrapper; the WebDAV lock sweep, dead properties, S3 tagging, TPC
cleanup, and checksum-on-write reopen each moved onto their VFS primitive.

What made the multi-week closure tractable was a repeated pattern: **when
migration stalls, a primitive is missing.** Each enabler unblocked a whole
cluster at once —

- `brix_vfs_walk` + the pool-free `open_fd`/`unlink_path` primitives → the
  off-thread cluster (checksum scan, S3 multipart assembly, WebDAV copy
  engine);
- `brix_vfs_probe` (non-metered, thread-safe) → every pre-op existence/type
  check without phantom metrics;
- the fd-based xattr variants → confinement traveling with an already-open
  descriptor (fattr handle mode, integrity-info cache);
- the `setattr` vtable slot → before it, `brix_vfs_chmod` silently no-op'd
  on every non-POSIX backend (found by the pblock metadata suite);
- `vfs_scratch` — a capability-gated "materialize to local POSIX scratch"
  for components that fundamentally need a real fd (FRM copy subprocess,
  ZIP member sendfile) even on non-POSIX primary storage; framed VFS↔VFS so
  no raw data escapes the seam.

Phase-62 also wrote down the migration's most important *negative* result —
the impersonation boundary (decision D6 below): some raw calls are correct
and must stay raw, marked.

### Era 5 — decorators, one spine, tape (phases 63–64)

The read cache (XCache-style), the write-back stage, and the FRM/tape
machinery were each bespoke subsystems with their own fill loops, config
grammars, and state. Phase-63/64 rebuilt them as **drivers that wrap
drivers**:

- `sd_cache` and `sd_stage` decorators composed by config over any source
  (posix/pblock/ceph/xroot/http/s3), Ganesha-export-style: `cache_store` =
  where bytes physically live, `cache_root` = the advertised logical root;
- the duplicate origin-fill machinery collapsed onto ONE spine
  (`brix_cache_fill_from_source`) used by the registry backend, per-fill
  `root://`, and S3 alike. Once the in-process `sd_xroot` origin client
  could authenticate all three ways (anonymous, bearer/ztn, X.509/GSI with
  origin-cert verify), the two GSI *subprocess* paths (read fill, 132 LOC;
  write-back flush, 149 LOC) and the duplicate fill loops (~195 LOC) were
  deleted — **~476 LOC of parallel machinery gone**, chaos suite green;
- tape became a `CAP_NEARLINE` driver (`sd_frm`, exec/stub MSS adapters,
  `tape://`/`frm://` tier schemes) with async `recall` returning a stable
  request id the cache tier parks stalled opens on, and a pure `residency`
  probe (which also fixed a real bug: an object *gone* from the MSS used to
  report ONLINE because only a residency marker's absence was checked —
  the driver `stat` now distinguishes ONLINE from LOST);
- `src/frm/` was dissolved; the generic durable-transfer engine
  (`fs/xfer/stage_engine*` + request registry + waiters) took its place,
  driving normal staging, tape stage-out, proxy write-through, and TPC from
  one state machine + ledger;
- phase-64 defined the per-role capability contract (what slots/caps a
  driver needs to serve as backend / cache_store / stage_store / nearline)
  as a **development target** with named gaps — the honest backlog that
  drove era 8.

Cache state unified in the same sweep (one `.cinfo` v3 record for read
cache + write-back + CSI + checksums), and staging itself became a
VFS↔VFS move: the old raw `read`/`write`/`lseek` cross-device copy loop
became `src->driver->pread → dst->driver->pwrite`, generic over both ends.

### Era 6 — sharing the mechanism with the clients

The clients (`xrdcp`, `xrdfs`, `xrootdfs`) had a *second* VFS
(`xrdc_vfs_*`) with its own POSIX/block/S3 backends and its own EINTR
loops. The 2026-06-27 layering design collapsed the stacks onto one shared,
ngx-free core on a single observation: **open is policy (not shared — the
server's confined open vs the client's unconfined URL open must never
merge); everything after open is mechanism (shared).**

Mechanics that made it real: the same `.c` files (`sd_posix.c`,
`sd_block.c`, `sd_s3.c`, `vfs_core.c`) compile into both the module and
`libxrdproto.a` under `-DXRDPROTO_NO_NGX`, with `sd.h` supplying a
*minimal* nginx type surface (typedefs/macros only, no runtime symbols) so
the archive stays at zero `ngx_` symbols — enforced by `check-ngx-free.sh`
inspecting the archive with `nm`. The ngx-coupled slots
(instance/namespace/staged) are compiled out of the client build; the
shared flag vocabulary (`BRIX_SD_O_*` → `O_*`) exists once for both the
server's `openat2` and the client's `open`. The S3 driver's weld to the
client HTTP stack was broken with the injected 4-function transport vtable
(D10) — after which the client S3 shell shrank to URL parsing + cred wiring
and a whole file (`vfs_s3_mpu.c`) was deleted.

Deliberately NOT shared (D11): the handle shells. And the client's io_uring
stays a client-only override *above* the shared verbs.

Phases 66/67 then reorganized the server tree into the 7-bucket topology
and split the VFS façade off the `src/fs/` root into `src/fs/vfs/` with
focused per-op TUs (`vfs_stat.c`, `vfs_rename.c`, …), the backend registry
splitting config parsing from composition. Phase-79 later split the
oversized `vfs.h` into `vfs.h` + `vfs_ops.h` with zero behaviour change
(file-size governance).

### Era 7 — identity through the seam

Three overlapping deliveries turned the single-service-credential node into
a per-user gateway. The full record — including every wiring site and the
proof matrix — is
[`multi-user-backend-credentials-through-the-vfs.md`](../09-developer-guide/multi-user-backend-credentials-through-the-vfs.md);
the shape:

**Phase 1 — SELECT.** A per-export credential directory maps the
authenticated principal to a pre-provisioned `.pem`/`.token`/`.s3`/
`.keyring`. One gate (`vfs_cred.c`) is the sole checkpoint; drivers grow
optional `open_cred`/`staged_open_cred` slots; a NULL cred or absent slot
falls back to the plain slot (service credential) — unless the export is
deny-mode, in which case the request fails closed *before the origin is
touched*.

**Phases 2–3 — surfaces + completion.** The gate extended to namespace ops
via the full `*_cred` twin family — without which a deny-mode request's
*probe stat* still hit the origin as the service account, violating the
invariant. Ceph got per-user librados connections (the one backend where
per-identity connection caching was unavoidable, because librados binds the
CephX user at cluster-connect time — and where the two memory-safety bugs
of §5 consequently lived). Opt-in x509 **minting** gave bearer-only
identities (S3 keys, tokens with no pre-provisioned proxy) a per-user x509
at the origin — with the documented trust shift that the origin must trust
the mint CA, which is why minting is opt-in, data-plane-only, and never
reachable from the stream.

**Phase 1's four hard problems**, each resolved by investigation rather
than machinery:

1. *Session lifecycle*: feared per-identity connection pools; killed by the
   fact that `sd_xroot` sessions were already per-open — the credential
   became a per-open field on the fill task. No pool, no keying.
2. *Async write-back ownership*: the flusher has no request or identity —
   so the owning identity is **persisted in the durable journal record**
   (`brix_stage_cred_t {key, principal, dir, deny}` appended as the LAST
   member, with a size-tolerant decoder so pre-feature journals still
   replay on the service credential).
3. *Credential expiry*: checked **twice** — at request-open by the gate and
   again at flush by re-resolution — so validity is evaluated when bytes
   actually move. A permanently-lapsed deny-mode flush dead-letters loudly
   rather than looping or downgrading.
4. *Plumbing without globals*: the identity was already on the ctx; the
   work was the last hop into the driver. The only global-ish addition is
   the documented per-worker delegation-id store.

**Phase-70 — delegation.** The live-cred bag carries *captured forwardable
bytes* through the resolved mode: PASSTHROUGH (verbatim bearer; a
user-supplied proxy PEM **re-verified against the CA store in-gate** —
see the self-asserted-DN bug in §5), EXCHANGE (RFC-8693 token exchange with
a per-worker minted-token cache; S3 STS AssumeRole/GetSessionToken; krb5
GSSAPI via an async-safe 0600 FILE ccache path, because a live
`gss_cred_id_t` is request-scoped and cannot ride an async fill task), and
the no-captured-bytes injections (SSS identity assertion signed with a
gateway keytab; STS from the node's service keypair). Every degradation
lands on SELECT — never on silent anonymous.

**Phase-71 — capability uniformity.** The closing move: every
`src/fs/vfs/*.c` op branches ONLY on `brix_sd_caps()` bits and vtable-slot
presence, never on backend identity — enforced by a new guard. New bits
split implicit assumptions out of the code (`DIRS_WRITE`, `XATTR_WRITE`,
`MEMFILE`); the `cred_accept` mask let the VFS refuse a credential kind
*before* the origin leg; and the effective per-instance caps (narrowable by
`init`) made per-export capability masks (phase-83's pblock lab) a config
feature instead of a code fork. It also flushed out stale truths — e.g. the
registry comment still calling S3 primaries read-only while the driver
already advertised more.

### Era 8 — backend maturity

With the contract stable, depth arrived — each item validating the seam by
*not* requiring protocol-handler changes:

- **pblock** reached full POSIX-parity caps: 64 MiB-striped block files
  with a persistent block-0 fd (so `CAP_FD|SENDFILE|IOURING` hold), a
  SQLite catalog that the hot byte path never touches, subtree-aware
  rename, quota-aware `space`, native `CAP_CATALOG` enumeration — and the
  reference standalone unit suite (multi-thread, multi-process,
  async-interleave, fsync-durability).
- **Ceph** completed (phase-60 → phase-89): stripe-collapse synthetic
  directory listing (ADR-1 — RADOS has no dirs), copy+delete rename with
  noreplace-`EEXIST` semantics (ADR-5), libradosstriper interop, the
  read-only CephFS-via-RADOS driver decoding CephFS's on-RADOS metadata
  directly, and the standalone security suite for the LFN→object-key map
  (canonicalization, injectivity, `..`-escape rejection).
- **S3 forwarding closed** (phase-80): staged whole-object writes (single
  PUT / MPU) + DELETE as a *primary* backend; coalesced ranged GETs;
  metadata via HEAD / copy-onto-self with the extra `x-amz-*` headers
  folded into SigV4 SignedHeaders; advisory POSIX attrs in
  `x-amz-meta-xrd-unixattr`.
- **GridFTP** (phase-82 inbound gateway) motivated the unified **writer
  session** (`vfs_writer.c`) — one write entry point choosing in-place vs
  staged from caps, tolerating MODE-E out-of-order extents on random-write
  backends, refusing them distinguishably on staged-only ones, with
  commit-time read-back CRC verify. Phase-91 is building the outbound
  `gsiftp` origin driver (wave-A protocol kernels — reply/PASV/EPSV
  parsers with SSRF screening, MLSX fact parsing — landed and unit-tested).
- **The remote-primary relaxation:** making a no-fd backend a `root://`
  *primary* required relaxing the kXR handle path's `fd<0` gates
  additively (gated on `sd_obj.driver` presence) — the one deliberate
  loosening of an old assumption, done at the dispatch layer, not per
  handler.
- **Phase-88 (in tree, 2026-08-10):** commit-time dedup as a driver verb
  (`dedup_publish`/`dedup_gc` — the posix hardlink farm and pblock's
  refcounting folds behind one seam), the packed small-blob arena
  (single-sourced record format with the client packed cache,
  flock-serialised appends for multi-worker safety), the sha256 tier, and
  the cross-process mmap namespace cache (per-entry seqlocks; any arm
  failure silently keeps the heap cache).

---

## 3. The pivotal decisions

Each entry: the problem, the choice, what it beat, and the consequence you
live with today.

**D1 — Cut the seam at open, not around the whole stack.**
Server open (confined, identity-carrying, cache-aware) and client open
(arbitrary URL) are irreconcilable; everything after open is policy-free
byte-pushing over a bound object. Sharing the verbs and *not* the open let
one mechanism serve two worlds without weakening either. The losing
alternative — a single parameterized open — would have put "is confinement
on?" flags on the hottest security decision in the system. Consequence:
confinement lives only in the server's open; the shared verbs assume a
vetted object and must never re-derive policy; never route a client's
unconfined open through the server's confined open or vice versa.

**D2 — Capabilities, not backend identity.**
The alternative — `if (backend == s3)` branches — was actually creeping in
until phase-71 rooted it out. Caps + NULL-able slots mean adding a backend
touches ONLY that driver's `.caps`; the degradation ladders (memory-serve,
staged writer, key-prefix listing, statvfs fallback) are written once. The
guard (`check_vfs_identity_branch.py`) makes the rule permanent, and the
*effective* per-instance bitmap makes capability masking a config feature.
Consequence: capability bits are API; honesty is mandatory (a cap you can't
deliver is a bug the VFS will amplify); implicit assumptions must become
bits (the DIRS_WRITE/XATTR_WRITE/MEMFILE splits are the precedent).

**D3 — Errno facts at the seam; wire codes at the edge.**
Every driver speaks kernel truth (`ENOENT`, `EEXIST`+`was_dir`, `EXDEV`,
`ENOTSUP`); exactly one table per protocol translates. The alternative
(drivers returning protocol statuses) would have coupled every backend to
every front end and made cross-protocol semantic drift *structural*.
Consequence: the reserved meanings (`EXDEV`=escape, `NGX_DECLINED`=
documented fallback, `NGX_AGAIN`=parked recall) are load-bearing and must
never be repurposed; origin drivers must *map* their wire statuses to
errno facts (the §7.5 table) rather than leak them.

**D4 — Two execution tiers instead of a thread-safe VFS.**
Making pools/metrics/cache thread-safe would put locks on the hottest loop
in the server. Splitting metered (loop-only) from raw (POD, any thread)
kept the hot path lock-free while ending worker drift — at the cost of a
discipline: every op author must know their tier, jobs must be
init-zeroed, and quiet/probe variants exist so unmetered resolution doesn't
mean unobservable operations.

**D5 — The confinement cascade, including the raw-`open()` tail.**
Three open strategies (persistent rootfd → per-call canon → raw) encode a
real distinction, not debt: the raw branch is reachable ONLY for
server-constructed paths with *no* export root. The per-call form survives
because the persistent-instance model can't host a per-call rootfd without
leaking it. Consequence: the cascade order is normative; "simplifying" it
is how you silently widen the raw branch to client paths.

**D6 — Separate svc-owned domains stay raw (the impersonation boundary).**
The most counter-intuitive rule in the tree. The confined helpers are
impersonation-aware: under `map` mode they route the syscall to the
privileged broker, which performs it **as the mapped user under the export
rootfd**. For an export path that is exactly right. For a cache root,
upload stage, FRM control dir, S3 multipart staging area, or checkpoint
journal — svc-owned files under a *different* root — it is the **wrong
root under the wrong identity**, and the failure is *silent success on the
wrong file*. So those calls stay raw, as the worker, each marked
`/* vfs-seam-allow: <reason> */`, and the guard's allow-list names the
domains. Consequence: "fixing" a marked call by routing it through
`brix_vfs_*` is a security regression; the marker is the documentation.

**D7 — Enforce with a guard + burn-down backlog, not review.**
The seam only became real when the guard landed with a grandfathered
backlog: new violations fail CI instantly; old ones burn down monotonically
(56 → 0, held at 0 across three tiers). Tier-1 (raw byte ops) is HARD — the
marker deliberately does NOT exempt it. The guard greps markers on the raw
line before comment-stripping and matches syscalls after, so a syscall name
in a comment is never a false hit. Consequence: migrations are cheap to
police and impossible to regress; `--regen` is a deliberate-migration tool,
never a CI-appeasement tool.

**D8 — The A-1 revert: the invariant outranks the inlining win.**
During phase-56, the VFS byte primitives were moved *off* the SD vtable and
inlined with raw pread/pwrite, chasing an indirect-call win. It was
reverted on principle: the driver indirection is exactly what lets
block/S3/pblock slot in unchanged, and a perf win that breaks the seam is a
loss. The episode is the canonical argument for machine-checking
invariants (D7) — a rule that can be quietly optimized away isn't a rule.
Zero-copy fast paths that bypass *buffering* (cleartext/kTLS sendfile, the
`preadv2(RWF_NOWAIT)` warm-cache probe) sit **beside** the core by
documented design — they move bytes without a core buffer, they don't
reimplement the loop.

**D9 — Decorators are drivers.**
Cache, stage, and tape compose as SD instances wrapping SD instances,
selected by config — not as special-cased subsystems threaded through the
VFS. That single choice retired the bespoke XCache/FRM machinery, made
"any backend + cache + stage + tape" a config sentence, let cache verdicts
ride the object model (`cache_outcome`, `cache_evicted_bytes` — stamped by
the decorator, *metered* by the first layer that knows the protocol), and
gave the nearline rule ("no tape without a cache tier") a natural
enforcement point in the composing registry.

**D10 — Transport injection for network drivers.**
`sd_s3` (and the http origin path) perform *protocol logic only* — SigV4,
range math, MPU sequencing, XML/PROPFIND — over an injected transport
vtable (4 functions for S3). A non-2xx is a fact in `resp->status`, never a
transport error. The server injects libcurl *from the cache layer* so
`backend/` stays free of libcurl; the client injects its own HTTP stack.
This is what lets one S3/HTTP implementation serve the module, the
cache-fill worker, and `xrdcp` byte-for-byte. The related boundary
decision: a fully in-process `root://` GSI/token *client* was deliberately
NOT built (that auth logic lives in `libxrdc`, which `src/` cannot link) —
authenticated root:// fills initially delegated to the proven native
client via exec, then moved in-process only when `sd_xroot` earned the
auth matrix.

**D11 — Share the core, keep two shells.**
The server handle (pool/AIO/sendfile chains/metrics/staged commit) and the
client handle (URL routing, io_uring, credential store, temp+rename or
native commit) were deliberately NOT merged: merging would drag nginx into
the client or client concerns into the server. The dual build
(`-DXRDPROTO_NO_NGX`, typedef-only nginx shims, `check-ngx-free.sh` on the
archive) shares the mechanism and nothing else. Consequence: two handle
types is the *correct* end state, not unfinished work — the unification
target was the middle.

**D12 — Atomic staged writes + the unified writer.**
The PUT contract (a failed upload never leaves a partial object at the
final path) became a first-class lifecycle (`staged_open → write →
commit(excl)/abort`, `RENAME_NOREPLACE` for exclusive create), then
generalized by GridFTP into the writer session: one entry point choosing
in-place vs staged from caps, `O_ATOMIC` forcing staged even on
random-write backends, out-of-order extents refused distinguishably
(`expected_off`), and commit-time read-back verification through the
object's own driver — the only end-to-end integrity check that exists for
a backend with no single kernel-file identity. The write-acceptance policy
for `!RANDOM_WRITE` backends (what is refused vs staged) was written as a
table in phase-55 and kept: explicit refusal beats hidden
read-modify-write.

**D13 — One credential gate, kinds not schemas.**
Per-user backend auth could have been threaded through every call site
(and each protocol would have grown its own bugs). Instead exactly one
gate resolves ONE `brix_sd_cred_t` of exactly ONE kind — the gate fills
one kind's fields and NULLs the rest; each driver reads only its own —
with drivers declaring acceptance masks checked *before* the origin leg.
The struct's own history carries a lesson: it started as two fields
(proxy + principal) and had to grow key/dir/deny mid-feature because the
*detached flush* consumer needs to re-resolve — design the struct for the
furthest consumer, not the nearest caller. Fail-closed rules were fought
for individually (expired-pem anti-downgrade; deny-before-origin including
probes; degrade-to-SELECT never to anonymous; re-resolve at flush so
expiry is checked when bytes move; dead-letter over retry-forever) — §5
records the bug that motivated each.

**D14 — Dedup as a driver verb (phase-88).**
Cross-repo dedup of verified CAS objects was a POSIX-only hardlink trick in
the cache layer. Expressing it as `dedup_publish`/`dedup_gc` — with the
**caller** owning content proof and the driver owning the mechanics —
let pblock serve `brix_cache_global_cas` through its refs machinery with no
VFS special case, and left refcounting backends free to ignore `canon`
entirely. The newest confirmation that "add a verb, not a branch" scales.

**D15 — Metering fidelity as a design axis.**
`brix_vfs_probe` and `opendir_quiet` exist because routing pre-op checks
through metered stat/opendir logged phantom operations (one `OP_STAT` per
rm/mkdir/mv; one `OP_DIRLIST` per visited subdir in bulk listings) —
corrupting the operational picture the metrics exist to give. Observability
is part of the interface, so *not emitting* is sometimes the specified
behaviour. The same axis produced the rule that decorators stamp outcomes
and the protocol-aware layer meters them.

**D16 — Caching metadata without lying.**
The negative-stat cache and the open-time `stat_current` fast path both
came with honesty mechanisms: `neg_stat_forget` MUST be called by any
same-worker publish point that materializes a path outside
open/mkdir/rename; and only *read-only* handles trust open-time metadata —
a writable handle always re-stats. Perf caches that can serve stale truth
get an explicit invalidation contract or they don't land. (Phase-88's
cross-process namespace cache follows the same discipline: seqlocks,
generation counters, and silent fallback to the heap cache on any arm
failure.)

**D17 — Origin namespace slots carry a type-probe contract.**
When the origin drivers grew namespace slots, a 37-test three-way sweep
(POSIX ↔ `sd_http` ↔ `sd_xroot`) pinned four rules HTTP semantics do not
give you: `rmdir` probes and refuses a non-collection (`ENOTDIR`) — WebDAV
`DELETE` deletes whatever is at the URL; `rmdir` refuses a populated
collection (`ENOTEMPTY`) — RFC 4918 collection DELETE is recursive, and
recursion is the VFS's decision, never the slot's; deleting an absent path
is `ENOENT`, not success; and `stat` pays one extra RTT (`PROPFIND
Depth: 0`) when `HEAD` cannot tell a collection from an empty object,
because a wrong type corrupts everything above (`mkdir -p` over a regular
file "succeeding"). Correctness bought with an RTT is the accepted trade.

**D18 — The memory sink (streaming origins serve positional reads).**
Origin protocols stream; the SD contract is positional `pread`. The
bridge — a memory sink the streaming reader fills and the driver `pread`s
from — is what let `sd_xroot`/`sd_remote` implement the vtable honestly
instead of forcing a "streaming read" variant through the whole stack.

**D19 — The registry splits choice from instance.**
Backend *choice* is config-time and per-export; the *instance* is
per-worker and lazy — because a SQLite connection cannot cross `fork` and
librados connections are per-process. One `ctx_init` lookup covers ~50
ctx-build sites; reload is idempotent (last write wins per root);
`resolve_for_path` (longest-prefix) exists because staged commits know only
an absolute final path. Consequence: never cache an instance across
workers, and never build one at config time.

---

## 4. How the VFS solves BriX-Cache's problems (the map)

| Problem (§1) | Mechanism | Where |
|---|---|---|
| Confinement escapes | resolve in `path/` → re-check in the façade → `openat2(RESOLVE_BENEATH)` / driver-physical confinement; `EXDEV`=403; three guard tiers ban bypasses | `vfs_open.c`, `path/beneath.h`, `check_vfs_seam.py` |
| Protocol drift | one op catalogue with pinned edge semantics (`overwrite_dirs`, `excl`+`EEXIST`/`was_dir`, recursive vs `ENOTEMPTY`, 404≠success) consumed by all front ends | `vfs_rename.c`/`vfs_unlink.c`/`vfs_copy.c`; spec §5.6 |
| TLS/sendfile trap | single chokepoint: `is_tls`/`want_pgcrc` ⇒ memory-backed; sendfile only via the driver's `read_sendfile_fd` verdict + dup'd fd owned by the pool | `vfs_read.c`, `file_serve.c`; spec §6.2 |
| Worker drift | one POD job executor shared by every dispatch tier; bodies single-sourced in the verb core; same buffer chain sync or async | `vfs_io_core.c`, `core/vfs_core.c` |
| Observability gaps | observers emit exactly one metric + access-log line per metered op; probe/quiet variants keep the picture truthful; cache outcomes metered once at the adopt site | `vfs_internal.h`; spec §11 |
| Static service credential | the credential gate: SELECT / PASSTHROUGH / EXCHANGE / MINT / SSS / STS / krb5 → one cred of one kind → `cred_accept`-checked, leaf-unwrapped dispatch; durable journal identity for detached flushes | `vfs_cred.c`, `vfs_deleg*.c`, `sd_cred_types.h` |
| Non-POSIX storage | capability bitmap + degradation ladders + staged writes + memory-serve + memory sink; decorators for cache/stage; explicit refusal over emulation | `sd.h`, `vfs_writer.c`, `sd_cache`/`sd_stage` |
| Tape | `CAP_NEARLINE` + async `recall`(reqid)/`residency`; residency queryable without recall; parked opens resume on arrival; cache tier mandatory | `brix_vfs_residency`, `sd_frm`, stage engine |

---

## 5. What adversarial review caught (the bug record)

The era-7 security review is the most instructive part of the whole
history, because almost every defect had the same shape: *a credential
silently substituted for the service account somewhere the identity was
supposed to travel*. None was cross-user impersonation (the origin's own
re-authentication was the backstop), but each broke "as the user" on the
allow path or "deny before origin" on the deny path. Kept here in full
because every future auth path should be walked against this list:

- **Critical — path traversal in the credential key.** A token `sub` of
  `..` passed the filesystem-safe charset, building `<cred_dir>/../.pem`.
  Fix: reject a leading `.` in the fs-safe test; unsafe principals fall to
  the `x5h-<sha256>` form. *(Lesson: a "safe charset" must be checked
  against path grammar, not just character classes.)*
- **Critical — decorators dropped the credential on namespace ops.** On a
  stage/cache-composed export, a user's stat/rename/delete reached the
  origin as the service account: the ns dispatch targeted the top
  (decorator) instance, whose plain relay forwards without the cred. The
  initial test masked it because the test's service credential WAS user
  A's proxy. Fix: `brix_vfs_ns_leaf()` unwraps to the leaf for cred-scoped
  dispatch — and the test now uses a *distinct* service DN so the
  difference can never hide again.
- **Important ×5 — ctx built, bind forgotten.** WebDAV MOVE, WebDAV COPY,
  S3 CopyObject, WebDAV LOCK (xattrs), and the remote serve-offload GET
  each built a ctx *with* identity but omitted
  `ctx_bind_backend_cred` — and the offload case ran `driver->open` on a
  worker thread with no gate at all (the largest read-side hole). Fixes:
  bind at each site; MOVE switched from the credential-free
  `rename_path` to the ctx-bound `rename`; the offload runs its deny gate
  on the event loop *before* submitting the task and copies the cred into
  the worker ctx by value. *(This cluster is why the spec's §5.6 warns
  that the raw path twins carry no credential gate.)*
- **Important — delegation trusted a self-asserted DN.** Both delegation
  forms validated a delegated proxy by *string-matching* its self-reported
  subject against the client, with no chain-of-trust proof; an
  authenticated user could store a self-signed proxy for their own slot.
  Fix: `delegation_chain_trusted()` runs the same `brix_gsi_verify_chain`
  as client-cert auth, against the frontend CA store, in both paths —
  rogue-CA tests in both suites.
- **Memory, critical — Ceph connection use-after-free under eviction.**
  A long-lived open's cached per-user RADOS connection could be
  LRU-evicted and freed mid-I/O (>8 concurrent identities). Fix:
  refcount-pin the connection to the open object; eviction skips pinned
  slots (transient uncached connection when all pinned); close unpins with
  deferred destroy. Proven by a test holding a handle through >8 evictions
  doing byte-exact I/O.
- **Memory, critical — Ceph transient connection leak.** The
  all-slots-pinned "transient" connection was never marked doomed, so its
  last unpin never freed it: mon sessions + fds staircased. Fix: doomed at
  birth; a regression test cycles >8 simultaneous transient opens and
  asserts a flat fd count.
- **Liveness — deny-mode flush retried forever.** A write-back whose
  credential permanently lapsed re-drove every scheduler tick and every
  restart. Fix: dead-letter after an attempt/age cap — the write is
  preserved for operator recovery and never flushed under the wrong
  identity.

The review discipline that found these — adversarial verification, a
distinct-service-DN test so the difference cannot hide, reproduction
before acceptance — is what makes the invariant real rather than
aspirational.

Two further non-auth catches worth keeping adjacent: the **false-ONLINE
tape report** (an object gone from the MSS reported ONLINE/DISK over the
Tape REST API because only a residency *marker's absence* was checked —
fixed by verifying via `driver->stat` and adding LOST), and the
**silent chmod no-op** (no `setattr` slot existed, so `brix_vfs_chmod`
succeeded without doing anything on every non-POSIX backend — caught by
the pblock metadata suite, fixed by adding the slot with the
"apply what your namespace can represent" contract).

---

## 6. Known residuals — the gap to the idealized interface

The spec describes the target; these are the acknowledged deviations in the
tree today (verify against `src/` before acting — several have pending
rulings in `phase-90-plan-phase-remainder-register.md`):

- **The handle-table cluster** (`fd_table`, `open_resolved_file`, the
  read/readv/pgread serve paths, `zip_member`, `tpc/launch`) still holds
  raw fds rather than VFS handles — the largest remaining architectural
  wall; it needs the session handle table itself to hold VFS handles.
- **The live synchronous dirlist loop** still runs its own confined
  `fdopendir`/`readdir` beside the core (the core's OPENDIR op backs the
  gated-off worker path). A tracked follow-up, not a second
  implementation.
- **Zero-copy fast paths** (cleartext/kTLS sendfile, the
  `preadv2(RWF_NOWAIT)` warm-cache probe) sit beside the core by design —
  documented in D8, not drift.
- **The 6 PUT files** (`s3/put*`, `webdav/put`, `webdav/tpc`) stay on the
  self-contained, async-safe `staged_file` tier; the open recommendation
  is to reclassify it as an allowed below-seam primitive rather than
  re-plumb it through ctx-holding `vfs_staged` (which would trade away its
  async safety for no accounting gain).
- **Worker-tier namespace mutation is unmetered** (the `_path`/`_at`
  primitives skip metrics by design); unifying it beneath a metered seam
  is the deliberately deferred phase-55 follow-up, waiting on a real need.
- **`vfs/fd_cache.c`** is a reserved placeholder (header + design note, no
  live code) — don't wire callers to it.
- **`brix_vfs_file_fd` retirement** (phase-55 §6.1) is an open
  retire-or-rule decision — the capability-gated accessors exist; the bare
  fd accessor survives for the handle-table wall above.
- **`gsiftp`** as an outbound origin driver is mid-flight (phase-91:
  wave-A protocol kernels landed and unit-tested; the SD driver shell is
  planned). **Origin ns-mutation coverage** still has named gaps
  (gridftp×xroot STOR, S3×xroot PUT/DELETE).
- **`sd_xroot` origin auth** for the *primary-backend* role is anonymous
  login only; authenticated origins ride the staging/native-client path
  until the staged-write phases land (per the writable-remote design
  spec).

Each residual is an invitation to extend the pattern, not to route around
it: when one of these moves, it should move *onto* the interface in
[`vfs-interface-specification.md`](vfs-interface-specification.md), with
the guard updated in the same change.

---

## 7. Lessons learned (carried forward as working rules)

1. **Build the gate before the feature.** Every migration that went
   smoothly had its CI guard first (seam tiers, ngx-free check,
   identity-branch check, directive pins). Every drift bug predated its
   guard.
2. **Burn down through a backlog, never around it.** The monotone-counter
   pattern (grandfather file + hard-fail on new) is how a multi-week
   invariant lands without freezing the tree. `--regen` is for deliberate
   migrations, culturally never for clearing red CI.
3. **When migration stalls, a primitive is missing.** `vfs_walk`, `probe`,
   the fd-xattr variants, `setattr`, `vfs_scratch` — each unblocked a
   whole cluster of call sites that had looked individually hard.
4. **Behaviour-preserving wrappers first.** The POSIX driver wrapped
   existing helpers verbatim before any second backend existed — the seam
   landed at zero risk and the second backend proved it later.
5. **Honest capabilities beat convenient emulation.** Every place the VFS
   "helpfully" assumed (writable dirs, xattr symmetry, fd presence,
   type-blind DELETE) later needed an explicit bit, slot, or probe.
   Absences must be modeled, not papered over — and refusals must be
   truthful errnos with metrics, not silent read-modify-write.
6. **Invariants that matter get machine-checked.** The A-1 revert (D8) is
   the canonical case of a documented rule quietly optimized away until a
   guard made it structural.
7. **The wrong-root/wrong-identity failure mode is silent.** The
   impersonation boundary (D6) produces no error when violated — it opens
   the wrong file as the wrong user *successfully*. Hence the two-way
   marker discipline: no unmarked raw calls, and no "fixing" marked ones.
8. **Fail-closed needs enumerating.** Each credential-gate hole (§5) was
   found and closed individually; new auth paths should walk that list —
   bind at every site, gate before offload, unwrap to the leaf, verify
   chains cryptographically, re-resolve at use, dead-letter over retry.
9. **Design the struct for the furthest consumer.** The two-field cred
   that had to grow key/dir/deny mid-feature (D13); the append-only
   journal record with a size-tolerant decoder is the compatible way to
   do it.
10. **Identity that must survive detachment gets persisted, not
    referenced.** The stage journal carries the credential *key*, not the
    resolved bytes — which is also what makes expiry-at-use real.
11. **Streaming and positional worlds need a declared bridge** (the memory
    sink, D18) — not ad-hoc buffering scattered through drivers.
12. **Semantic parity needs a sweep, not spot checks.** The 37-test
    three-way ns-mutation matrix (D17) is the template: same op, every
    backend, POSIX as the oracle.
13. **Build-system truths are part of the interface**: new `.c` files
    register in `./config` / the client Makefile (guards exist); a new
    shared file must compile under `-DXRDPROTO_NO_NGX`; build-gated
    drivers must leave a no-dependency build byte-identical.

---

## 8. Reading list

Chronological, for the full detail behind each era:

1. `docs/refactor/phase-54-vfs-thread-safe-io-core.md` — the two-tier
   split: job descriptor, executor, migration order, thread-safety
   contract
2. `docs/refactor/phase-55-storage-backend-abstraction.md` — the SD seam
   design: principles, the five hard problems, the write-policy table,
   annotated skeletons
3. `docs/refactor/phase-56-vfs-storage-driver-perf-audit.md` — the bypass
   audit, guard genesis (F0), the A-1 story, the seam-closure backlog
4. `docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md` —
   client/server sharing; `2026-06-28-vfs-seam-closure-zero-exemptions-design.md`
   — the zero-exemptions target
5. `docs/refactor/phase-62-vfs-namespace-metadata-seam-closure.md` — the
   full surface closure: three tiers, the marker, the impersonation
   boundary, the per-cluster migration record
6. `docs/refactor/phase-63-composable-cache-stage-backend-stack.md` /
   `phase-64-fully-tiered-composable-storage.md` — decorators, the one
   fill spine, the FRM dissolution, tape mechanics, the per-role
   capability contract
7. `docs/09-developer-guide/vfs-shared-architecture.md` — the shared core,
   the S3 transport trick, the dual-build mechanism, why two handle types
   remain
8. `docs/09-developer-guide/multi-user-backend-credentials-through-the-vfs.md`
   — identity through the seam: the gate, the four kinds, the four hard
   problems, every bug
9. `docs/refactor/phase-71-vfs-capability-uniformity.md` — caps as the
   only dispatch axis; `cred_accept`
10. `docs/09-developer-guide/storage-backend-drivers-deep-dive.md` +
    `pblock-storage-backend.md` — the drivers in depth; the 17-lesson
    quick index; the origin auth matrix
11. `docs/09-developer-guide/history-storage-and-caching.md` — the era
    synthesis this record draws on
12. `docs/09-developer-guide/lessons-tpc-vfs.md` +
    `lessons-migration-era-2026.md` — field lessons from the same work
13. `docs/refactor/phase-90-plan-phase-remainder-register.md` — the open
    rulings behind §6
