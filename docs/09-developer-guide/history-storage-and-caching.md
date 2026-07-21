# History — Storage Backends, VFS, and Caching

**Date:** 2026-07-15
**Status:** Living historical record — synthesizes the storage/cache/VFS work
from Ceph/RADOS spikes (phase-60) through the S3-forwarding closure plan
(phase-80), as captured in session memory. Point-in-time detail already
covered by a `docs/refactor/phase-NN-*.md` doc or a `docs/09-developer-guide/
*.md` reference doc is not repeated here — this file supplies the narrative,
the decisions and their reasoning, the bugs worth not repeating, and what is
still open.

**Related:** [lessons-migration-era-2026.md](lessons-migration-era-2026.md) ·
[pblock-storage-backend.md](pblock-storage-backend.md) ·
[pblock-metadata-performance.md](pblock-metadata-performance.md) ·
[storage-backend-drivers-deep-dive.md](storage-backend-drivers-deep-dive.md) ·
[vfs-shared-architecture.md](vfs-shared-architecture.md) ·
[multi-user-backend-credentials-through-the-vfs.md](multi-user-backend-credentials-through-the-vfs.md) ·
[../refactor/phase-60-ceph-rados-backend.md](../refactor/phase-60-ceph-rados-backend.md) ·
[../refactor/phase-62-vfs-namespace-metadata-seam-closure.md](../refactor/phase-62-vfs-namespace-metadata-seam-closure.md) ·
[../refactor/phase-63-composable-cache-stage-backend-stack.md](../refactor/phase-63-composable-cache-stage-backend-stack.md) ·
[../refactor/phase-64-fully-tiered-composable-storage.md](../refactor/phase-64-fully-tiered-composable-storage.md) ·
[../refactor/phase-64-generic-slice-fill.md](../refactor/phase-64-generic-slice-fill.md) ·
[../refactor/phase-68-cvmfs-site-cache.md](../refactor/phase-68-cvmfs-site-cache.md) ·
[../refactor/phase-80-s3-backend-forwarding-closure.md](../refactor/phase-80-s3-backend-forwarding-closure.md)

---

## 0. The shape of the era: four overlapping arcs

The storage plane did not evolve as one straight line; four arcs ran
concurrently and kept feeding each other:

| Arc | What it did | Rough window | Landing docs |
|---|---|---|---|
| **VFS seam closure** | Force every data + namespace/metadata syscall on an export path through `xrootd_vfs_*`/the SD driver vtable, enforced by a CI guard with a burn-down backlog | ongoing through phase-62, extended phase-67 | phase-62, phase-67-map.tsv |
| **Composable tiers** | Replace the bespoke, single-purpose XCache/FRM machinery with `cache_store`/`stage`/backend decorators composed by config, Ganesha-export-style | phase-63 → phase-64 | phase-63, phase-64 |
| **Pluggable SD backends** | Grow the storage-driver vtable to cover pblock (SQLite-catalog block store), rados/CephFS, S3, remote root://, http(s), cvmfs, tape | phase-55/56 onward, heaviest June–July 2026 | storage-backend-drivers-deep-dive.md |
| **Unified cache state + observability** | One `.cinfo` v3 record format for read cache + write-back + CSI + checksums; cache storage itself moved onto the SD driver seam; per-backend metrics/logging | phase-63 alongside tiers | pblock-storage-backend.md, metrics-overview.md |

The throughline across all four: **"zero data-plane POSIX outside
`src/fs/backend/`"** (CLAUDE.md invariant #12) started as an aspiration during
phase-55/56, became enforceable machinery in phase-62 (backlog file + guard),
and is now the default assumption every new backend or cache feature is built
against.

---

## 1. VFS seam closure — from convention to enforced invariant

### 1.1 The three-tier guard

The seam closure happened in tiers, each with its own guard behavior
(`tools/ci/check_vfs_seam.sh`):

- **Tier 1 (hard, no exemptions):** raw *positional* data syscalls
  (`pread|pwrite|preadv|pwritev|preadv2|pwritev2|copy_file_range|sendfile`)
  outside `src/fs/backend/`. Comments/strings are stripped before matching so
  a stray mention in a log string or `/* comment */` isn't a false hit. This
  tier strips markers too — a same-line `vfs-seam-allow` comment does **not**
  exempt a tier-1 hit, only tiers 2/3 honor it.
- **Tier 2/3 (namespace/metadata):** `open/stat/opendir/readdir/unlink/
  rename/mkdir/truncate/chmod/xattr` — added in phase-62, with the
  `/* vfs-seam-allow: <reason> */` marker mechanism for legitimate
  exceptions (certs, `/dev/null`, sockets, and separate svc-owned storage
  domains — cache fill, upload staging, S3 multipart — where the VFS's
  confinement root and impersonation identity would be *wrong*).

The mechanism that made the multi-week closure tractable was a **backlog
file** (`vfs_seam_backlog*.txt`): a checked-in enumeration of currently
tolerated violations. Migration became a monotone counter (56 → 0); anything
not in the backlog fails CI immediately, so regressions are structurally
impossible. `--regen` exists but is culturally reserved for deliberate
migrations, never to paper over CI red.

### 1.2 Enablers unblocked whole clusters at once

The backlog repeatedly stalled — not because the remaining call sites were
individually hard, but because a *primitive was missing*. Each enabler, once
built, let a whole cluster of sites migrate trivially:

- `xrootd_vfs_walk` (`src/fs/vfs_walk.c`) — thread-safe, pool-free, non-metered
  confined recursive traversal + copy/copytree + raw thread-safe
  `vfs_open_fd`/`vfs_unlink_path`. Unblocked the off-thread cluster: ckscan,
  S3 multipart assemble, WebDAV copy_engine.
- Threading rule that recurred as a blocker: `xrootd_vfs_open/opendir/
  unlink/stat` allocate on `r->pool` and emit metrics — **not** thread-safe
  off the event loop. `xrootd_vfs_pread_full`/`pwrite_full`/`vfs_probe` *are*
  thread-safe (no pool alloc, non-metered) — the correct choice for
  thread-pool/off-thread code.
- `vfs_scratch.{c,h}` — a capability-gated "materialize to local POSIX
  scratch" pattern for components that fundamentally need a real POSIX fd
  (FRM copycmd subprocess, zip archive fd/sendfile) even when primary
  storage is non-POSIX. Framed as VFS↔VFS (scratch is itself a POSIX SD
  instance), so no raw data ever escapes the seam. Config directives
  (`xrootd_frm_stage_dir`/`_force_scratch`, `xrootd_zip_stage_dir`/
  `_force_scratch`/`_stage_max_bytes`) replaced env-var knobs. The residency
  probe built on top of this distinguishes ONLINE (verified via
  `storage->driver->stat`) from LOST (object gone) rather than assuming
  ONLINE whenever the residency marker is merely absent — fixing a false
  ONLINE/DISK report over the WLCG Tape REST API for an object that no
  longer existed.
- A unified `xrootd_sd_setattr_t` vtable slot — the driver vtable originally
  had no `setattr` slot at all, so `xrootd_vfs_chmod` silently no-op'd for
  every non-POSIX backend (found via the pblock metadata suite; only pblock
  has a mutable namespace, others get a NULL no-op).

### 1.3 Deliberate exemptions and open architectural walls

Not every raw-syscall site was meant to migrate — the seam closure doc
records an explicit boundary decision: raw FS syscalls stay allowed in (a)
`src/fs/` itself, (b) the path/resolution layer, (c) self-contained
alternate-storage/metadata domains with their *own* confinement that is not
the export data plane (`cache_root`, `upload_stage_dir`, FRM control dir).
Routing those through the export-rootfd-impersonation-aware VFS helpers
would open the *wrong* root under impersonation.

Two clusters were deliberately left unmigrated as **net-negative** moves,
not oversights:

- The 6 PUT files (`s3/put*`, `webdav/put`, `webdav/tpc`) — `xrootd_staged_file_t`
  is already async-safe and self-contained; forcing it through ctx-holding
  `vfs_staged` trades that safety away for no accounting gain. Open
  recommendation: reclassify `xrootd_staged_*` as an ALLOW'd below-seam
  primitive instead of re-plumbing it.
- The handle-table cluster (`fd_table`, `open_resolved_file`, `read/readv/
  pgread`, `zip_member`, `tpc/launch`) — the largest remaining architectural
  wall. It needs the session handle table itself to hold VFS handles instead
  of raw fds. Not started as of last check.

### 1.4 The one reverted over-reach: A-1

During phase-56, `vfs_read`/`vfs_write`/`io_core` were moved *off* the SD
driver and inlined with raw pread/pwrite directly in the VFS layer, chasing
an inlining performance win. Rob reverted it: the driver-confinement
invariant ("all data byte I/O routes through the SD driver") outranks the
perf win, because it's what lets a block/S3 driver slot in unchanged. The
routes now go back through `xrootd_sd_posix_driver.pread/pwrite`. This is the
canonical example (§2 of the migration-era lessons doc) of why the invariant
needed to be *machine-checked*, not just documented.

A second consequence of the same invariant: **file staging became a VFS↔VFS
(backend↔backend) move.** `xrootd_commit_staged`'s cross-device path used to
`read`/`write`/`lseek` raw bytes (`stage_copy_fd`); it now loops
`src->driver->pread` → `dst->driver->pwrite` via `stage_move_objects`, using
the generic `obj->driver->op` form (not the concrete POSIX driver), so a
stage/final mount that becomes S3/block only changes how the object is
*opened*, not the copy loop.

### 1.5 Where the raw-syscall audit currently draws the line

As of the last confinement audit, the syscalls left outside `src/fs/backend/`
and judged legitimately excluded ("data, not config" framing) were: FRM's
stage-agent pipe IPC (not seekable), impersonation broker/client socket IPC
(with one flagged special-context `ftruncate` inside the privileged broker),
the staged-file pending-commit marker, cache lock/`.meta` files, the
dashboard config download, a standalone unit-test parser not in the module
build, and the proxy's socket↔pipe splice (pure transport). Anything beyond
that list is either genuinely load-bearing IPC or should be re-examined.

---

## 2. Composable tiers: retiring bespoke machinery for config-composed decorators

### 2.1 The Ganesha-export mental model

Rob's directive reshaped the cache/backend config surface around an NFS
Ganesha analogy: `cache_store` = the physical FSAL (where bytes actually
live), `cache_root` = the advertised, client-facing logical root — both
required together, and `cache_root` drives *both* the client namespace and
redirector advertisement. This let `xrootd_root` be eliminated entirely for a
pure cache node, and let `xrootd_storage_backend posix:<path>`/`pblock://
<path>` become a full PRIMARY export. The whole test suite (~130+ files)
migrated off the legacy `xrootd_root`/`cache_origin`/`write_through` grammar
onto the composable one.

Migration recipe that came out of it: a read-only export can drop
`xrootd_root`; a write-enabled export **must** use `xrootd_storage_backend
posix:<path>` (never bare `xrootd_root`).

Three separate `root_canon == "/"` bugs surfaced and were fixed as part of
this migration — worth remembering as a class, since any future root-anchor
change risks the same trio: (1) the temp reaper `nftw`-walked the *entire
host filesystem* when the anchor was `/`; (2) checkpoint recovery hit EACCES
and treated it as a fatal worker-init failure at `/`; (3) the write-permission
`W_OK` check failed for a write-enabled export anchored at `/`. All three
were fixed by gating `allow_write`/traversal behavior on
`xrootd_storage_backend_is_remote()` — a remote backend's root is a namespace
anchor only, not a real filesystem path to walk or `W_OK`-check.

### 2.2 Phase-63: SD-driver-shaped cache/stage/source

Phase-63 retired the bespoke XCache origin machinery; source, cache, and
stage all became SD-driver-shaped and composed by config (C-1 through C-7 in
the phase doc):

- Read cache fills from the export's own registered source backend — no
  separate `xrootd_cache_origin` needed for the common case (additive,
  byte-identical when unset).
- The registry composes cache/stage as SD-driver *decorators* over a source;
  the old `vfs_staged.c` "Mode-B" collapsed into a new `sd_stage` decorator.
- In-process ztn **and** GSI authentication of a token/X.509-protected
  root:// origin turned out cheap to add because the DH/cipher/
  proof-of-possession crypto is the *same* shared `gsi_core` kernel already
  used by the native client and TPC.
- A read-only `http(s)` source driver was added; cache write-back flush now
  reaches origin only via the `sd_xroot` driver (the inline
  `xrootd_wt_copy_body` helper was deleted).
- A `xrootd_credential <name> { ... }` block (map/geo-style handler pattern)
  plus per-scope `xrootd_storage_credential`/`xrootd_webdav_storage_credential`/
  `xrootd_wt_credential` unified credential handling process-wide, shared
  across stream/webdav/s3.
- **MITM hardening**: GSI origin auth now *requires and verifies* the origin
  server certificate against `ca_dir` before completing the handshake — this
  had previously been unauthenticated on the origin side. Absent/invalid CA
  now returns `kXR_NotAuthorized`; opting out requires explicitly omitting
  `ca_dir`.

Key operational gotcha from this arc: a driver-backed PRIMARY source
(`storage_backend root://O`) makes writes fully transparent (no local copy)
— the write-back/write-through flush path only fires for a *local POSIX*
export with `write_through on` + `wt_origin` set. And: the tier-1 VFS seam
guard is hard — it does **not** honor the `vfs-seam-allow` marker (only
tiers 2/3 do); this caught one pre-existing violation in `vfs_staged.c`.

A related build-out made a node's PRIMARY storage a live remote root://
server (`sd_xroot`) instead of local POSIX, writes routed through the same
generic SD staged-write seam. Rob's explicit auth-boundary rule: true
write-through passthrough with no staging (Mode A) is safe only for an
**anonymous** origin — an authenticated (GSI/token) remote backend *must* go
through a staging directory (Mode B, write-back), enforced as a config
error otherwise. `sd_xroot` was also the first *no-fd*, memory-served
backend to serve as a root:// primary (pblock always kept a real block-0
fd), which required additively relaxing `fd<0` rejections across
`fd_table.c`/`vfs_io_core.c` to accept driver-backed handles.

### 2.3 Phase-64: full tiering and the FRM dissolution

Phase-64 (five sub-projects, SP1–SP5, over `src/fs/tier/`, `src/cache/
cstore.c`, `src/fs/backend/*/sd_*.c`) brought every cache/stage/backend
driver combination (posix/pblock/xroot/rados/http/s3/tape) to parity, wired
config for stream+webdav+s3, landed async nearline recall (202 + kXR_wait) on
both HTTP and root://, made durable staged-write recovery and non-staged
temp-reaping survive restarts, and deleted the legacy `xrootd_cache_origin*`/
`cache_storage_backend` directives in favor of the tier grammar (§14).

The **dissolution of the ~3,900-line standalone `src/frm/`** subsystem into
`fs/xfer/` (durable registry/engine/waiter) + `fs/backend/frm/` (residency/
recall driver) + `core/config/tape_stage_conf.c` + `observability/metrics/
frm_metrics.c` is the single largest structural deletion of the era, and its
execution is the model other dissolutions should follow (see
lessons-migration-era-2026.md §4 for the general shape). The load-bearing
finding that *licensed* deleting rather than porting a third of the
subsystem: a Task-0 spike established that `sd_frm` **already** did the
recall+park work, and `frm/stage.c`'s 647-line double-forked subprocess
driver was the redundant legacy path. External contracts were explicitly
preserved across the dissolution: the reqid wire format survived verbatim,
the `brix_frm_*` directives relocated (not renamed) to `tape_stage_conf.c`,
and the registry journal kept routing through the SD posix seam so the seam
guard stayed green throughout.

FRM/tape MSS staging itself (built earlier, phase-35, ahead of the
dissolution) established the durable-queue architecture the dissolution later
preserved: **file = truth, SHM = cache** — the on-disk queue file is
crash-durable, SHM is process-lifetime only and gets reconciled *from* the
file at master start before workers fork; lock order is always
shmtx→fcntl. Explicit non-goals carried the whole way through: the full
migrate/purge engine (F2/F1) and Category-2 purge were never re-implemented
in-process — delegated to the operator's MSS/CTA/dCache/HPSS backend — and
the purge-watermark monitor only logs, never acts.

Building FRM staging also surfaced a codebase-wide crash class, not scoped
to FRM: nginx's SIGCHLD handler (`ngx_unlock_mutexes`) walks every SHM zone
treating `shm.addr` as an `ngx_slab_pool_t`, but every custom zone
(tpc/session/manager/shm/frm) was `ngx_memzero`-ing over that slab-pool
header with its own struct — any child-process death (e.g. FRM's copycmd
fork) corrupted the mutex and SIGSEGV'd the master. Fixed codebase-wide (12
zones) via `xrootd_shm_table_alloc`, which allocates the zone's table *from*
the slab pool instead of clobbering the header — this is CLAUDE.md invariant
#10 (create SHM tables only via `brix_shm_table_*`, never bare
`ngx_shmtx_create`). FRM's own stage-agent additionally avoids the crash
path entirely by double-forking into a long-lived reparented-to-init agent
process, so nginx itself never reaps the copycmd child; the SHM fix is
defense-in-depth for any other fork path.

### 2.4 XCache fill consolidation — what could and couldn't be deleted

A 2026-06-29 follow-on to phase-63 consolidated the origin-fill code paths in
`src/cache/fetch.c` into one spine, `xrootd_cache_fill_from_source(t,
source)` (open → pread loop → staged sink → commit+verify, with
checksum-on-fill gated to `backend name=="xroot"`). This deleted ~476 lines,
including two entire GSI subprocess helpers (`fetch_origin_exec`,
`xrootd_wt_run_flush_exec`) — replaced by in-process GSI reusing the same
X.509/CA/bearer-token wiring already available in-process.

The investigation also **rejected** two plausible simplifications, worth
recording so they aren't re-attempted without new information:

- **`cache_origin` cannot be fully deleted.** It is conceptually distinct
  from `storage_backend`: a server can have both a `storage_backend pblock`
  PRIMARY and a `cache_origin root://O` fill SOURCE simultaneously
  (`run_cache_pblock_pblock.sh` is the load-bearing test proving this).
  `cache_origin_client` also remains load-bearing on its own — `dirlist/
  handler.c` and `read/stat.c` spawn a separate `xrdfs` subprocess against
  it for dirlist/stat, untouched by the fill consolidation.
- **A `cache_origin` → `cache_source` rename was requested but declined** as
  pure churn: zero code removed, and a full field rename (`cache_origin_host`
  etc., ~30 files) was judged not worth it against the directive-string-only
  alternative (~12 files). Recorded as a deliberate no-op, not an oversight.

`http_transport.c`/`pelican.c`/`pelican_register.c` (~1,167 LOC) were also
explicitly kept: `sd_http` lacks their GSI-mTLS/Digest/Pelican
director-discovery features, so deleting them would have removed real
capability, not just duplication.

### 2.5 Legacy directive removal — the "remove the table entry" technique

Ahead of actually deleting the legacy FRM + stream-proxy + WebDAV
reverse-proxy code, Rob's chosen mechanism (2026-06-30) was to remove the
`ngx_command_t` table entries first, leaving handlers/conf-fields in place
to be deleted later — a config referencing a removed directive now fails
cleanly with nginx's own "unknown directive" error, with zero risk to
in-flight behavior, and the dead code shows up mechanically as
`-Wunused-function` for the follow-up deletion pass.

Three families were removed this way (with a deprecation-comment placeholder
left in the table): `xrootd_frm*` (superseded by phase-64 tier/nearline),
`xrootd_proxy*` (the legacy stream cache-origin proxy — later revived as a
straight rename to `xrootd_tap_proxy*`), and `xrootd_webdav_proxy*` (the
reverse proxy — removed with no replacement; only `_certs`, which is
actually a GSI proxy-*certificate* auth flag despite its name, survived).
`xrootd_cache_origin_proxy` (the phase-64 tier origin) and
`xrootd_http_handoff` (single-port handoff) were retained — not legacy
despite living in the same source region.

**Gotcha that cost real time:** `src/stream/module_core_directives.c` and
`src/stream/module_cache_proxy_directives.c` looked like the natural place to
edit but are **not compiled** — stale reference fragments. The live,
compiled directive tables are the `ngx_command_t` arrays in
`src/stream/module.c` and `src/webdav/module.c`. Any future directive-table
change must land there, not in the `*_directives.c` fragments.

---

## 3. Pluggable backends

### 3.1 pblock — the first full-parity non-POSIX primary

pblock (SQLite catalog of metadata + content-addressed 64 MiB block files,
server-only, gated on `XROOTD_HAVE_SQLITE`) is documented in depth in
[pblock-storage-backend.md](pblock-storage-backend.md) and
[pblock-metadata-performance.md](pblock-metadata-performance.md); the
history worth keeping here is what it *proved* about the SD-driver seam by
being the first non-POSIX, no-real-block-0-fd-required primary to go through
it end to end, root:// and WebDAV both. A key architectural fact not obvious
from the steady-state description: block IDs are content-addressed CSPRNG
values, not path-derived, so rename and staged-commit are catalog-only
`UPDATE`s that copy zero bytes; only `server_copy` actually copies blocks
(minting a new blob ID).

Root:// data-plane bugs found wiring pblock as Layer 3 (all four fixed):

1. The read-open existence pre-check used a raw POSIX `xrootd_stat_beneath`
   against the (empty) physical tree — always NotFound for a driver-backed
   export. Fixed with a driver-aware `xrootd_open_read_probe`.
2. `pblock_make_obj` never populated `obj->snap`, so every open handle
   reported size 0 and reads hit immediate EOF.
3. Root:// reads used `sendfile` on the block-0 fd only — correct for a
   1-block file, silently truncating any multi-block file at 1 MiB. Fixed by
   gating the sendfile fast path on `sd_obj.driver == NULL`; driver-backed
   handles take the buffered io_core path where `preadv` spans blocks.
4. A key-convention mismatch between how WebDAV/stat/dirlist and the driver
   open computed the export-relative key (leading slash required;
   `xrootd_open_logical` dropped it and broke stat/GET).

A fifth, checksum-specific bug: `kXR_Qcksum`/checksum-at-rest originally read
only block 0 of a multi-block file (wrong digest) until `checksum_core`
gained `_obj`-suffixed entry points threaded through `xrootd_integrity_get_fd`
taking an `xrootd_sd_obj_t*` (NULL ⇒ unchanged POSIX-fd path for 5 of 6
callers).

Two more general-purpose bugs the pblock metadata/GSI storm-test suite
surfaced, both fixed **for every non-POSIX driver, not just pblock**:

- A trailing slash in the parent-existence probe (`op_path.c`) that POSIX
  `lstat` tolerates but a catalog key lookup doesn't — non-recursive nested
  `mkdir` failed. Fixed with `plen--`.
- The SD driver vtable originally had **no `setattr` slot at all** —
  `xrootd_vfs_chmod` silently no-op'd on any mutable non-POSIX namespace.
  Fixed by adding a unified `xrootd_sd_setattr_t` slot (§1.2 above); this
  also closed two other confined-helper bypasses of the seam found in the
  same audit (`group_policy` setgid inheritance in mkdir.c/mv.c, and CMS
  cluster node-action replication in `src/cms/recv.c`).

Operational fact worth remembering: `upload_resume` and pblock are
incompatible — resumable-write partials must be plain POSIX files with a
real fd/stat, so pblock exports need an *independent* POSIX staging mount
(`xrootd_stage_dir`) and root:// pblock configs need `xrootd_upload_resume
off` (the Layer-3 driver branch excludes `use_resume`). Performance
characterization: pblock is ~2.5–2.8x slower than POSIX for metadata ops
(~54% of CPU in libsqlite3 per flamegraph) — an architectural WAL-commit
floor, not a bug to chase.

### 3.2 Ceph/RADOS and CephFS — compat contract before code

The Ceph/RADOS work (phase-60) was preceded by a research spike that
*reshaped the plan itself* before any driver code was written — the pattern
the migration-era lessons doc calls out as high-value.

**The stock compatibility contract** (audited from `XrdCephPosix.cc`/
`XrdCephOss*.cc`, required because RAL/Glasgow have Pb+ of existing on-RADOS
data our driver must read byte-for-byte): data plane is libradosstriper
(never raw rados); objects stripe as `<pfn>.%016x`; the first stripe carries
`striper.layout.*` + all user xattrs; `stat` mode is faked (no real
mode/uid/gid); `opendir` only accepts `/` (full pool scan); `Mkdir`/`Remdir`
are no-op-success (a deliberate GFAL2-compat lie); `Chmod`/`Rename`/`Create`
return `ENOTSUP`; one pool per export. Rob's decisions on top of the
contract: namelib (lfn2pfn) support is required but the actual RAL/Glasgow
translation rule was never supplied — this blocks touching production data;
pool is one-per-export; directory listing follows strict stock parity (no
enhancement); setattr/chmod is advisory-only via `user.xrd.unixattr`/
`x-amz-meta-xrd-unixattr` (ignored by stock, so compat is preserved either
way).

**Site landscape** (decisive for scope, worth remembering so it isn't
re-derived): RAL ECHO and Glasgow run XrdCeph/RADOS directly and need the
compat-layer rados driver. Lancaster/Manchester/Brunel run XRootD on top of a
**CephFS POSIX mount** — these sites need *nothing new*; `sd_posix` on the
mount already gives full parity.

**The pre-existing `src/fs/backend/rados/sd_ceph.c`** (raw single-rados-object,
hashed keys) is explicitly **incompatible** with stock XrdCeph and must not
be confused with the striper-based compat driver being built against the
contract above.

**CephFS interop spike go/no-go, from research not implementation:**
zero-copy upgrade of flat/cephns → CephFS is a firm **NO-GO** (the MDS mints
inodes, so there's no way to alias existing RADOS objects into a CephFS
namespace without a real data move). A **read-only `cephfsro` rescue driver
is GO**; write is NO-GO. A bidirectional migration toolchain (redirect/copy/
finalize/rollback) was built on top of this finding, with one safety fact
worth repeating: **RADOS redirect stubs are write-through and delete-through
to the source** — deleting a stub deletes the source object — so redirect
mode is read-only/staging-only until `--finalize` (`tier_promote` +
`unset_manifest`) makes CephFS the owner; a safe rollback must
`unset_manifest` (detach) *before* unlink, never the reverse. Migration is
intra-cluster (`copy_from`/`tier_promote` OSD↔OSD, no external uplink) —
this locality was the reason Rob preferred it over a copy-through-mount
approach. Reverse migration (CephFS→striper) requires CephFS to be
unmounted (the MDS owns live objects); forward migration requires the
filesystem quiesced for a consistent metadata read. Hardlinked files migrate
but are flagged UNVERIFIED by the toolchain; CephFS snapshots are detected
and reported, not migrated. As a result of this
spike, the earlier `cephns` (directory-over-omap) driver was **removed**
(2026-06-30) — the final RADOS lineup is flat `ceph` (block-only reference)
plus read-only `cephfsro`; the reusable `sd_ceph_conn_t`/`sd_ceph_oid_*`
connection layer survived that removal.

**Ceph test infrastructure gotchas** (single-node `quay.io/ceph/demo` in
Docker, `tests/ceph_harness.sh`): this host runs Docker Desktop on Windows
via WSL2, not native Linux Docker — `--network host` binds the Docker-Desktop
VM's own address space, reachable from other `--network host` containers but
**not** from WSL2-host processes (where nginx normally runs). Nginx↔Ceph
testing therefore has to happen *inside* a `--network host` container.
Bind-mounts don't surface WSL2 files into the DD VM — use `docker cp` or a
tar-pipe. Long-lived work containers should be reused (deliver a fresh
source tar into the existing container) rather than recreated, since
recreation loses installed deps. Cleanup must be `pkill -9 nginx`, not
`pkill -f objs/nginx` — workers rename their `cmdline` to "nginx: worker
process" so `-f` misses them, leaving phantom listeners that masquerade as
"hangs."

### 3.3 S3 — write path, metadata parity, and the multi-user credential bug

The S3 backend work spans metadata-parity decisions, credential-forwarding
labs, and — most recently — a production-shaped multi-user bug found by an
exploratory k8s lab.

**Metadata-parity scoping decision (2026-06-29):** two planned phases were
explicitly skipped after tracing actual consumers. Phase 4 (sd_xroot/
sd_remote driver getxattr/listxattr) was skipped because those drivers are
built *only* by `src/cache/fetch.c` as the read-only byte-fill origin — never
a registry-selectable primary backend, so bare vtable slots would be
untestable dead code (forbidden by the "no AI slop" rule). Phase 3 (client
`s3://` mount metadata) was skipped because the client `s3://` VFS is
copy-engine-only, with no mount and no setfattr surface to serve. Instead,
S3 xattr/setattr was folded into the shared `sd_s3` driver, mapping to
`x-amz-meta-*` plus an advisory codec — this serves the real Phase-2
consumer (the registered server S3 export driver). A known transport
limitation was flagged and deferred: `resp_header` reads S3 headers by name
only, with no enumeration API, so a generic `listxattr` over all
`x-amz-meta-*` keys needs a transport extension in both the client and cache
HTTP transports before it can be more than "surface the one known key."

**Credential model:** S3 credentials route through the same
`xrootd_credential`/`xrootd_storage_credential` registry as GSI/token
backends (phase-63 §14), with per-user SigV4 keys resolved from
`<principal>.s3` files under `xrootd_storage_credential_dir`. A recurring
SigV4 gotcha worth keeping: the signed `Host` header must always include
`:port` (`xrootd_format_host_port`), even when it looks redundant — omitting
it produces a silent signature mismatch against MinIO/S3.

**MinIO forwarding suite (2026-07-14):** proved `s3://` as a *primary* export
is genuinely writable via staged PUT, correcting stale comments in
`vfs_backend_config_s3.c`/`sd_remote.c` that say "S3 primary is read-only" —
that statement actually means "no random `pwrite`," not "no writes." WebDAV
PUT through a `brix_storage_backend s3://...` node uploads byte-exact to
MinIO via `sd_remote`'s `.staged_open/write/commit` delegating to `sd_s3`
single-PUT/multipart. The known gap from this suite: staged writes use only
the *static* server credential — `sd_remote` has no `staged_open_cred` yet,
so there's no per-user write attribution on the staged-write path.

**s3gsi multi-user lab (2026-07-14, exploratory, brix source deliberately
untouched during the run) — the killer bug:** on the root:// **stream**
plane specifically (not WebDAV, which has a separate, working credential
path), every S3 request signed with an *empty* access key, producing a
MinIO 403 on every operation. Root cause: worker-process credential replay.
`src/core/config/process_server_init.c`'s
`brix_init_server_backend_credential` — the function that re-populates
`brix_vfs_backend_set_credential` after a worker (re)spawn — maps only
`x509`/`ca_dir`/`sss` fields; it omits `s3_access_key`/`s3_secret_key`/
`s3_region` (and bearer tokens). The config-parse-time version
(`runtime_server.c`) *does* map them correctly, so the credential is present
until the first worker replay, at which point it gets clobbered with empty
strings. This is tracked as phase-80 P80.1 ("single credential mapper") —
the fix is to make replay share the same mapping code as parse-time instead
of maintaining two divergent copies.

Three more findings from the same lab, all still open:

- **Authz/gate path-canonicalization mismatch without an explicit
  `xrootd_export`.** The authorization gate checks `root_canon + wire`
  (yielding a doubled-slash path like `//atlas/...`) while authdb rules are
  canonicalized via `realpath` to a single-slash form (`/atlas/...`) —
  nothing matches, and every operation is denied. Setting `xrootd_export
  /data/xrootd` aligns both sides. This is a config footgun, not a bug in
  either canonicalizer alone, and is worth documenting for operators running
  root://+S3 without an explicit export root.
- **Root:// writes to an S3 backend are not fully wired.** With
  `upload_resume on` (default), the write stages locally and commits via a
  local `rename()` — the bytes never reach S3 and the client gets EIO.
  With `upload_resume off`, the open fails because it needs
  `RANDOM_WRITE`, which `sd_remote` doesn't advertise — `EROFS`/`kXR
  3007` at open time. The VFS staged-write path that *does* work
  (`sd_remote` multipart) is currently driven only by the HTTP/WebDAV plane
  (`brix_webdav_storage_staging`); there is no equivalent stream directive.
  Tracked as phase-80 P80.2/P80.3.
- **`sd_remote`'s vtable coverage gap:** only `open_cred` exists today — no
  `staged_open_cred`/`stat_cred`/`unlink_cred`, and no dirlist/mkdir/rename
  at all. Because `ENOTSUP`/`ENOSYS` fall through the generic error mapper
  to `kXR_IOError`, these read as an opaque I/O error rather than an honest
  "unsupported operation" — tracked as phase-80 P80.4 ("honest
  `kXR_Unsupported`").

A k8s-specific gotcha surfaced by the same lab, worth keeping for any future
secret-backed credential test: Kubernetes secret/configMap mounts are
`..data/`-symlink-based, and an `O_NOFOLLOW` credential open (correct
production hardening) fails against them with "credential missing" — worked
around in test infra with an init container that `cp -rL`s the secret into a
real emptyDir, not a production-code change.

### 3.4 CVMFS — a fourth protocol plane with its own selection/resilience layer

Phase-68 landed `cvmfs://` as a dedicated HTTP module
(`src/protocols/cvmfs/`) with CAS verification, manifest TTL, never-drop
fill, per-worker negative caching, and full metrics/dashboard wiring. Two
points worth keeping beyond what phase-68's own doc covers:

- The live implementation diverged from the original plan in one structural
  way: CVMFS fills through the phase-64 **`sd_cache` tier**, not a
  standalone fetch engine — policy fields thread from `shared_conf` through
  `xrootd_tier_register_stores` into `xrootd_cache_policy_t`. Anyone reading
  the phase-68 plan doc cold should expect this deviation.
- A real production-shaped bug was found and fixed the day after landing:
  `xrootd_cvmfs_upstream_allow` used stock `ngx_conf_set_str_array_slot`,
  which keeps only the *first* argument per directive occurrence — a
  single-line 9-host Stratum-1 allowlist silently allowed only host #1,
  pinning every client to one always-hit-CERN-never-RAL host. Fixed with a
  custom setter that appends every argument. Worth remembering as a class:
  `ngx_conf_set_str_array_slot` is a single-value setter no matter how many
  arguments the directive grammar accepts — any multi-value directive needs
  a custom setter.

Follow-on resilience work (2026-07-03) added stall-detection (vs. wall-clock
timeout) for large catalog fills, force-primary vs. failover retry policy,
RTT-based geo-answer selection, and a `unified_origin` mode that hides
per-endpoint failover from the client so it never marks a healthy proxy
"bad" and falls back to direct. Two operational facts worth keeping:

- `origin_attempt_timeout` is a wall-clock cap — too low a value aborts
  large multi-MB catalog fills mid-download over a WAN, poisoning that
  endpoint's fail-score and cascading to bench *every* origin while small
  objects keep succeeding. Progress-based `origin_stall_timeout`/
  `origin_stall_bytes` (curl low-speed abort) is the correct tool for
  catalog-sized fills.
- `unified_origin on` and `force-primary` fill-retry policy are **mutually
  exclusive by intent** (one wants failover, one wants pinning) — the config
  parser rejects `unified_origin on` without a `storage_backend` configured.

A real crash was fixed in the same arc: a bare `%u` in an `ngx_log_error`
format string (nginx's own printf family requires `%ui`/`%ud` — unlike libc
`snprintf`, which is fine with `%u`) consumed zero varargs and shifted every
subsequent `%s` to dereference the wrong stack slot as a pointer, SIGSEGV'ing
on the first proxied request after a new traffic-log line was added.

Operational logging was added across the whole selection/fill path
(`sd_http.c` per-attempt transport failures + origin-switch reasoning,
`origin_probe.c` per-endpoint RTT ranking, `module.c` startup geo-selection
report, `upstreams.c` proxy-mode registration) specifically so "why did the
cache switch backend server" is answerable from the error log alone. One
config-time logging gotcha applies everywhere in the codebase, not just
CVMFS: **`ngx_conf_log_error(NGX_LOG_NOTICE, ...)` at config parse/merge time
is silently dropped** — `cf->log` is still the prefix log fixed at
`NGX_LOG_ERR` during parsing, so a config-time message that must be seen
(e.g. a geo-selection startup report) needs `NGX_LOG_WARN` or higher.
Runtime `NOTICE` in the worker error log is unaffected and honors `error_log
... info/notice` normally.

A separate mid-fill bug, found while adding client-abort/misbehavior
logging, is a good example of an errno-clobbering bug class: on a mid-fill
source read failure, `sd_cache_stale_serve_ok()`'s own `stat()` of the
(absent) cache entry overwrote `errno` from the real cause (`EIO`, a broken
origin connection) with `ENOENT` — the fill layer then served the client a
definitive 404 for what was really a transient connection break. Fixed by
capturing `errno` immediately after the failing read and restoring it before
returning. **General lesson: any cleanup/diagnostic call between a failing
syscall and its error-handling code is a latent errno-clobber bug — capture
errno immediately, before any further syscalls run.**

> **Caveat on these CVMFS memory notes:** several of the original session
> notes originally concluded that observed timeouts/flakiness during this
> work were "host load, not code." Rob later corrected this
> (2026-07-15): the chronic "overloaded host" during this era was
> substantially self-inflicted — brix was crash-looping (an uninitialized
> reaper timer, fixed in commit `66efecd0`) and `systemd-coredump` was
> capturing a full core on every restart, and retry ladders laundered the
> resulting slowness into apparently-green runs. Treat any "not code, just
> load" verdict from this period with suspicion; re-verify against
> `coredumpctl` before accepting a load-based explanation for a flake.

### 3.5 brixMount cvmfs-rw — a client-side writable overlay

Distinct from the server-side CVMFS protocol plane above: `client/lib/fs/
overlay.{c,h}` is a FUSE/CVMFS-free union filesystem core (O_NOFOLLOW
per-component walk, whiteouts, opaque markers, atomic copy-up via a temp
name + rename) landed 2026-07-05, giving `brixcvmfs --rw` a writable overlay
over an otherwise read-only CVMFS mount. Two gotchas worth keeping for
anyone touching it: `openat(..., O_CREAT, mode)` is umask-filtered, so
copy-up needs an explicit `fchmod` to preserve the lower file's mode bits;
and a directory rename that touches the lower layer returns `EXDEV` by
design (pure-upper/opaque directories rename atomically, cross-layer ones
require the caller's copy+delete fallback, matching standard overlayfs
semantics).

---

## 4. Unified cache state, caching mechanics, and cache-adjacent bugs

### 4.1 One record format: `.cinfo` v3 / xmeta

The cache state format went through two consolidations. First (phase-63), a
unified `.cinfo` v3 (present-bitmap + file-level dirty/write-back fields,
with a frozen v2 reader kept for upgrade) replaced format-specific state,
and cache storage itself was routed through the SD driver seam so cache data
can live on *any* backend, not just POSIX. Rob's explicit call here: unify
cache *state*, but keep cache *storage* POSIX by default; track presence
per-block, dirty per-file; unconditionally remove dirty staging older than 7
days.

Second (2026-07-02, the "xmeta" project, four phases, all landed same day),
the `.cinfo`/`.meta`/CSI-tag/checksum sidecars were folded into one shared
carrier (`src/fs/meta/`, `xmeta_path.c`) with a single RMW flock on the data
file: P1 built the codec+carriers, P2 folded cache `.cinfo` state onto it
(xattr `user.xrd.cinfo` preferred, `<path>.cinfo` sidecar fallback), P3
retired the standalone `.xrdt` CSI tag file in favor of CRC32C-per-block
folded into the same record (writes fold CRCs handle-locally, one merge at
close; reads verify only fully-spanned blocks), and P4 folded `.meta`/`.cks`
sidecars in too while deliberately *keeping* the `user.XrdCks.<alg>` xattr
for stock-XrdCks interop.

A concrete, non-obvious performance bug came out of the CSI/xmeta interplay
after `xrootd_csi` went **default ON fleet-wide** (2026-07-02): brix won
single-stream root://+GSI reads but scaled *worse* than stock xrootd under
concurrency. Root cause: `brix_csi_verify_read` re-loaded the xmeta record
(a `getxattr` + parse + malloc/free) on **every read job** in the thread
pool, because the open path loaded the record once and then discarded it.
Fix: snapshot the record once at open (`brix_csi_t.record`), verify against
the cached snapshot on every subsequent read, and free it at close — the
at-rest record is immutable for a read handle's lifetime, so the open-time
copy is authoritative. A companion directive, `xrootd_csi_trust_fs on`
(default off, meant for ZFS/CephFS/RADOS/Btrfs), lets pure read handles skip
tag verification entirely on filesystems that already checksum end-to-end,
while write-side tagging and strict RMW-verify/pgwrite wire-CRC stay on
regardless — deliberately *not* enforcing `csi_require` while trusting the
filesystem.

Two smaller cache-state facts worth keeping: `xrootd_cache_sink_pwrite`
returns 0=success/-1=fail, **not a byte count** — a `!= n` comparison
silently treats every successful write as a failure; and the reaper's
skip-list originally didn't protect `.cinfo` sidecars, so the proactive
reaper could evict a dirty file's sidecar and leave the data file
unprotected — `.cinfo` was added to `xrootd_cache_skip_name`.

### 4.2 Slice-granular caching — HTTP is N/A by design, not a gap

Phase-26 slice caching (`xrootd_cache_slice`) is stream-plane only, and
that's a *design* fact, not an oversight to revisit: the HTTP cache path
(`cache_root`) is a local read-through with no XRootD origin to fill slices
from, so slice caching simply doesn't apply there. Empirically verified: a
64 KiB read of a 16 MiB file materializes only 2 of 128 slices on disk. Two
guardrails worth remembering if this code is ever touched: `readv` and
`pgread` **reject slice-mode handles** with `kXR_Unsupported` — without that
guard they would `preadv` the handle's parked `/dev/null` fd and silently
return wrong data; and stat on a slice-mode handle must synthesize a
regular-file stat from `cached_size` (a bare `fstat` of `/dev/null` reports
size 0).

The generic-backend follow-up to slice caching (phase-64-generic-slice-fill)
found that **partial-fill sparseness is wired only on the legacy
`xrootd_cache_origin HOST:PORT` + `xrootd_cache_slice <size>` path** — a
composable `storage_backend`-based cache does whole-file COMPLETE fill and
ignores slicing. `xrootd_cache_slice_size` is a *different* field
(`common.cache_slice_size`) that does not trigger the wired partial path —
easy to confuse the two directive names when writing tests or docs.
`xrootd_cache_slice` must be a positive multiple of 1 MiB and in practice
must be *exactly* 1 MiB (larger values exceed the origin's single-read cap).
Also worth remembering when testing offline behavior: a COMPLETE cached file
serves fine with the origin down; a PARTIAL one does not (open re-validates
against origin) — only a warm-hit-with-origin-up scenario is a reliable
partial-fill test.

### 4.3 Cache metrics: a second, hand-rolled pattern

Per-server/per-slot cache Prometheus counters use a genuinely different
wiring pattern than the unified op-metrics recipe in CLAUDE.md — worth
flagging explicitly since it's easy to apply the wrong recipe. Cache
counters are shared-memory atomics on a fixed 16-server slot array
(`ngx_xrootd_metrics_t.servers[]`), exported by hand in
`src/metrics/stream_cache.c` rather than through the generic
`XROOTD_*_METRIC_INC` enum machinery. A metric row only appears in
`/metrics` after a connection has hit that server slot at least once
(`srv->in_use=1`, set in `connection/handler.c`) — the underlying atomic
increments regardless, it just doesn't export until then, which can look
like a missing increment when it's actually a missing connection.

`cache_dirty_reaped_total` is the concrete example: it's a per-reason array
(`abandoned|incomplete|completed`), classified from the `.cinfo`
dirty/flush-generation state at reap time — `DIRTY + aged + flush_gen==0` is
a real loss (abandoned), `DIRTY + aged + flush_gen>0` is a partial loss
(incomplete), `CLEAN + flush_gen>0 + last_flush aged` is a completed
write-back whose staging was reclaimed with no loss at all. The reaper now
also reclaims clean-completed write-back files (a behavior addition beyond
the original bug fix), gated by `cache_dirty_max_age`.

### 4.4 CVMFS-adjacent and general cache correctness bugs worth remembering

- **Multi-MiB chunked-copy offset conflation** (general, not CVMFS-specific,
  surfaced during migration-era hygiene sweeps and already covered in
  lessons-migration-era-2026.md §7): any routine copying bytes between two
  files must take read-offset and write-offset as *separate* parameters —
  a shared-offset bug silently truncated cache fills at 1 MiB chunk
  boundaries for files over 1 MiB, and was only caught because
  checksum-on-fill was left ON in the cache test topology. Keep
  checksum-on-fill on in any cache test topology; it is the last line of
  defense against silently serving corrupt physics data.
- **Symlink stat handling.** `stat`/`statx` originally rejected any
  in-export symlink with EXDEV because the open path used
  `RESOLVE_BENEATH` (which forbids all symlinks). Stock XRootD follows
  in-export symlinks. Fix: split into `do_openat2_resolve(..., resolve)` —
  open/mutate paths keep `RESOLVE_BENEATH`, but `xrootd_stat_beneath`
  (follow) and `xrootd_lstat_beneath` (nofollow) use
  `RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS`, which resolves symlinks
  chroot-style — within the root, never able to escape it. A host-absolute
  symlink target (as opposed to a relative or export-root-absolute one)
  still resolves to ENOENT under `RESOLVE_IN_ROOT`, so a second fallback —
  `realpath()` against `root_canon`, accepted only if the canonical target
  stays inside `root_canon` — handles that case; the TOCTOU window this
  opens is judged benign because stat is read-only. Escapes (`/../../etc/
  passwd`) are still rejected because `realpath` lands outside the root
  either way. `ENOTDIR` on a non-directory path prefix was also corrected
  to match stock's `kXR_FSError` (was `kXR_NotFile`). A genuine security
  regression surfaced mid-migration, worth remembering as its own class:
  after the EXDEV-reject-to-follow fix above, an uncommitted VFS-seam
  refactor routed `xrootd_vfs_statf`/confined `opendir` through
  `xrootd_{l}stat_confined_canon`'s non-impersonation branch, which had
  quietly reverted to a bare `stat()`/`lstat()`/`opendir()` instead of the
  beneath API — a symlink planted under the export could be stat'd or
  listed straight through to a real out-of-export target (e.g.
  `/etc/passwd`), a genuine confinement escape, not just an EXDEV mismatch.
  Fixed by routing that branch through `xrootd_{,l}stat_beneath`/
  `xrootd_opendir_beneath` (openat2 `RESOLVE_IN_ROOT`) via an explicit
  O_PATH rootfd. Fixing the read side also exposed that staged writes never
  `O_NOFOLLOW`'d the final path at open time (only at commit-rename), so a
  symlinked write target could still slip through the exclusive-create
  pre-check — closed with an explicit `S_ISLNK` no-follow guard in
  `open_resolved_file.c`'s write-open path, returning `kXR_NotAuthorized`.
- **Beneath-API path convention.** `xrootd_open_beneath`/`_stat_beneath`/
  `_mkdir_beneath` (the openat2 confinement API, `src/path/beneath.c`)
  resolve relative to `rootfd` and strip leading slashes — they must always
  be called with the *logical* export-relative path (`/file.txt`), never
  the `root_canon`-prefixed absolute filesystem path. Passing the absolute
  path doubles the root prefix and fails with ENOENT. Native TPC's
  destination-open path got this wrong once (it reused the
  authz/logging-oriented absolute path), breaking every native root:// TPC
  destination write; the tell in the access log is a doubled or absolute
  path on an `OPEN ... ERR "No such file or directory"` line.
- **Two root:// staged-write-open bugs**, both in
  `src/read/open_resolved_file.c`: (1) `kXR_new` was rejected whenever the
  *final* file already existed, even when `kXR_delete` was also set —
  stock's actual rule is that delete-intent wins and the open should
  truncate/overwrite; fixed by adding `&& !(options & kXR_delete)` to the
  exclusive-create pre-check. (2) A write-open of an existing *directory*
  staged a bogus `.part` file and returned success instead of
  `kXR_isDirectory` — the `S_ISDIR` reject only existed on the read side;
  fixed by adding a symmetric directory check before staging begins on the
  write side.
- **`upload_resume` needs dedicated on *and* off test coverage, always.**
  It's default-on and stages every writable open into a deterministic
  `*.xrdresume.*.part`, committed on clean close — correct for real
  clients, which only ever read back through the same handle, but invisible
  to any test that inspects on-disk state out-of-band mid-write. Because the
  feature can't be selectively narrowed by open flags (a real `xrdcp -f`
  upload uses the identical flags as some out-of-band test scenarios), the
  resolution was a dedicated resume-OFF conformance server block
  (`xrootd_upload_resume off` on a second port) rather than trying to make
  one endpoint serve both test styles. General principle recorded here:
  **any on/off-toggleable feature needs its own dedicated test coverage per
  setting**, not one test parametrized across both.
- **The `driver->close` vs. shell-ownership contract, and the FRM/cache
  double-free it caught (2026-07-17).** A read of an offline object through
  `frm://exec` (or `frm://stub`) reliably `free(): double free detected in
  tcache 2` on the *serve* — the recall itself succeeded (online buffer +
  cache both correct); only the byte-serve aborted. Root cause was a driver
  contract violation, not an FRM-logic bug: the SD object model splits
  ownership so that `driver->close(o)` releases **only** the fd/state, while
  the malloc'd shell (`heap_shell`) is freed by whoever holds the object *by
  pointer* — `brix_sd_obj_release()` does `close(o); if (o->heap_shell)
  free(o);`, the VFS adopt-fail path does the same, and
  `brix_vfs_adopt_obj()` frees the original after copying it by value (and
  zeroes `heap_shell` on the embedded copy). Every driver obeys this
  (posix/http/remote/pblock close only their state) **except `sd_frm_close`**,
  which also did `if (obj->heap_shell) free(obj);`. So when the cache-fill
  spine released its source object (`brix_sd_obj_release(fs->so)` in
  `cache_fill_pump`, sd_cache_fill.c:209), `sd_frm_close` freed the shell,
  then the release wrapper read `o->heap_shell` (use-after-free) and freed it
  again. The frm object is the one object routinely released *by pointer*
  (as the cache-fill source), never adopted-by-value, which is why only frm
  crashed. Fix: remove the shell-free from `sd_frm_close`. `sd_cache_partial.c`'s
  `sd_cache_close` carried the identical latent violation — harmless on the
  hot path (the partial object is always VFS-adopted, so `heap_shell` is
  already zeroed before close runs) but a double-free on the adopt-fail /
  release-by-pointer paths — and was fixed the same way for contract
  uniformity. **General principle: a `driver->close` implementation must
  never free its own shell; shell lifetime belongs to the by-pointer holder
  or the VFS adopter.** The rewritten `tests/test_frm_scratch.py` (see the
  testing history) now exercises this serve path live on both adapters.

---

## 5. Admin/verification tooling built on top of the backend seam

A handful of client-side and server-side tools were built specifically to
exercise or verify the SD-driver seam and cache-state format, and are worth
knowing about as diagnostic tools rather than re-inventing them:

- **`xrdckverify`** (`client/bin/xrdckverify`) — offline verification of a
  local file's bytes against its already-recorded checksum, reading either
  the storage-side `user.XrdCks.<alg>` xattr / `.cks` sidecar (`--storage`)
  or the cache's `.cinfo`/`.meta` `cks_alg`/`cks_hex` fields (`--cache`).
  As of last check, `--cache` returns "no recorded checksum" (exit 2) for
  any currently-cached file, because the server-side "populate cache
  checksum on fill" wiring (verify-on-fill) hasn't landed yet — the tool
  itself is correct and forward-compatible, only the producer side is
  missing.
- **`xrdcinfo`** (`client/apps/xrdcinfo.c`) — dumps a `.cinfo` present-bitmap
  as JSON with no nginx coupling; built specifically to make partial-cache-fill
  test assertions possible.
- **`xrdstorascan`** (`client/apps/xrdstorascan.c`) + server engine
  `src/scan/scan_engine.c` — backend-aware admin tooling (verify/inspect/
  inventory/drift/bench/health), folded into one design rather than several
  parallel tools. As of last check the server engine walks via raw
  `openat2` (POSIX) rather than the SD-driver seam, so `backend` always
  reports "posix" and `namespace_consistent` is trivially always true —
  real Ceph object-key/cluster-health introspection needs the scan routed
  through the VFS driver first (a shared prerequisite with the deferred
  catalog-enumeration verb, `xrootd_sd_enumerate_fn`), deliberately not
  landed as a placeholder per the project's no-placeholder rule.

---

## 6. Open items and deferred work (storage/cache/VFS scope)

| Item | Class | Status / where tracked |
|---|---|---|
| Worker credential replay omits S3 (and bearer) fields, wiping stream-plane S3 auth after the first worker respawn | correctness bug | phase-80 P80.1; `docs/refactor/phase-80-s3-backend-forwarding-closure.md` |
| Root:// staged writes to object (S3) backends not fully wired (resume-on stages locally & never reaches S3; resume-off needs RANDOM_WRITE that sd_remote lacks) | missing capability | phase-80 P80.2/P80.3 |
| `sd_remote` vtable coverage gap: only `open_cred`; no staged_open_cred/stat_cred/unlink_cred, no dirlist/mkdir/rename; unsupported ops surface as opaque `kXR_IOError` instead of `kXR_Unsupported` | missing capability + honesty | phase-80 P80.4 |
| ~~Generic S3 `listxattr` over all `x-amz-meta-*` keys needs a transport extension~~ **DONE 2026-07-21**: `resp_headers_raw` slot added to `brix_s3_transport_t` (curl + client HTTP transports), `sd_s3_list_meta` + `sd_remote_listxattr` enumerate all `x-amz-meta-*`; live smoke `cmdscripts.metadata_live_ports sd-s3-meta`. Gotcha: the mid-struct vtable insert requires stale-object purges in all three build systems (shared/xrdproto has NO dep tracking) — skew crashed via a shifted `resp_free` slot | ~~missing capability~~ closed | phase-88 §5 loose-end 3 |
| Ceph namelib (lfn2pfn) rule for RAL/Glasgow never supplied — blocks touching production RADOS data | blocked, external dependency | `xrdceph_rados_compat_contract`; rados driver wiring itself also untested without a real Ceph build |
| Handle-table cluster (fd_table, open_resolved_file, read/readv/pgread, zip_member, tpc/launch) still holds raw fds, not VFS handles — largest remaining seam wall | architecture | vfs_phase2_full_seam memory |
| `xrootd_staged_*` (6 PUT files) intentionally not migrated onto ctx-holding `vfs_staged` — recommend reclassifying as an allowed below-seam primitive instead of re-plumbing | architecture decision pending | vfs_phase2_full_seam memory |
| `sd_xroot` (writable remote root:// primary): setattr (chmod/utime) forwarding and directory ops (mkdir/opendir) still follow-ons; staged_commit is non-atomic (no rename); no shared durable-journal/backpressure with the cache WT engine | missing capability | writable_remote_root_staged_write memory |
| Composable `cache_store` has no watermark eviction — watermark tests must stay on the legacy `cache on`+`cache_root`+`cache_origin` grammar | scoped gap | composable_cache_config_ganesha memory |
| Cache checksum-on-fill/producer side for `.cinfo`/`.meta` cks fields not yet populated by the server — `xrdckverify --cache` always reports "no record" today | missing capability | xrdckverify_tool memory; phase26_slice_caching §9 follow-up |
| `xrdstorascan` scan engine walks raw POSIX, not the SD-driver seam — backend/namespace-consistency reporting is meaningless for non-POSIX backends until routed through the VFS | architecture gap | xrdstorascan_backend_tooling memory |
| FRM migrate/purge engine (F1/F2) and Category-2 purge intentionally not reimplemented in-process post-dissolution; purge-watermark monitor logs only, never acts | scoped-out by design | frm_tape_staging_plan memory; comparison docs |
| Ceph phase-5 (server bench + dedicated Ceph CI harness) and phase-4b (catalog enumeration verb + inventory/drift wiring) deferred together, pending a real non-POSIX driver to exercise them meaningfully | deferred | xrdstorascan_backend_tooling memory |
| FRM test modernisation (2026-07-18): three retired subsystems still had tests asserting their old behaviour. **Live surface exists → modernised to green:** on-open nearline recall (`test_frm_staging.py`) moved from posix-export + `user.frm.residency` xattr to `frm://exec` MSS backend + `brix_cache_store` (recall in cache-fill; 8 concurrent opens → 1 exec recall proves the cache tier single-flights). **No live surface → skipped with precise reason (re-arm on reintegration):** the unified `kind=tape` transfer-ledger line (emitted only by the stage_engine RECALL path, not the sync read-fault recall — future integration flagged in `prepare.c`); F5 checksum-verify-on-stage (durable registry records SUBMITTED but the draining/verifying stage-agent is retired); F6 purge-watermark monitor (arming NOTICE removed from source). Key lesson: **when a subsystem is dissolved, its tests split cleanly into "behaviour relocated" (port to the new seam) vs. "behaviour removed/deferred" (skip, don't fake) — the wrong move is forcing a green against a surface that no longer emits the signal.** | test modernisation | `docs/refactor/phase-81-test-server-registry.md` (frm entries); this era |
| **FIXED (2026-07-18) — tape backend advertised zero caps.** The modernised `test_frm_control_locality.py` / `test_tape_rest.py::test_archiveinfo_reports_locality` failed: a tape-only object reported `ONLINE`/`onDisk=true` and a missing object was not `LOST`. Root cause: `brix_sd_frm_create()` (`src/fs/backend/frm/sd_frm.c`) hand-builds the instance instead of going through `brix_sd_instance_create()`, and **never copied `driver->caps` into `inst->caps`** — so `brix_sd_caps()` (which reads the per-instance effective caps, not `driver->caps`) returned 0. The `brix_vfs_residency()` decorator-walk gates on `brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE`, so it never recognised the tape driver, fell through to its default `ONLINE`/`nearline=0`, and every locality probe was wrong. Fix: one line — `inst->caps = brix_sd_frm_driver.caps;` at construction, mirroring `sd_registry.c:141`. This also correctly re-enables the tape driver's `FD`/`RANDOM_WRITE` effective caps for the cache-recall gate. Lesson: **any backend that bypasses the generic instance factory must replicate `inst->caps = driver->caps`, because `brix_sd_caps()` is instance-scoped (Phase-83 cap masking), not driver-scoped.** | correctness fix | this era |

### 6.1 Fault-proxy hardening sweep (2026-07-19, UNCOMMITTED)

Driven by `brix-fault-proxy` (root-free userland TCP fault injector) against the read-through cache, the storage-driver read paths, and every write gateway (WebDAV/S3/GridFTP PUT + native root:// write/pgwrite/writev), to survive the hostile/non-production networks brix must deploy into. Each finding = fault-proxy (or mock-transport / native-wire) repro that proves the break — or, for #11, verifies a path sound and closes the residual integrity gap — then a fail-closed fix / opt-in integrity knob + a 3-test-ritual/unit guard. All UNCOMMITTED.

| Finding | Break (proven) | Fix | Test |
|---|---|---|---|
| **#1 cache truncation → COMPLETE poisoning** | A mid-transfer cut on the origin→cache link could leave a short `.part` that was committed and served as a permanent complete hit. | Fill spine refuses to commit a fill whose staged length is short of the known object size. | `tests/test_cache_truncation_poison.py` (5) |
| **#2 `brix_cache_verify require` was a dead knob** | Three layers: the directive was never *registered* on the root/stream plane; there was no fail-closed enforcement in the fill spine; and — deepest — `brix_cache_origin_query_checksum` gave up on any non-`kXR_ok` status, but a real XRootD origin computes checksums *lazily*, parking the query with `kXR_waitresp` (4006) and delivering the digest later as an unsolicited `kXR_attn`/`kXR_asynresp` (5008) frame. So `require` was unusable against exactly the lazy-checksum origins that are the real-world common case. | (a) register `brix_cache_verify` enum on the plane (`module_enums.{c,h}` + `directives_cache.inc` → `common.cache_verify_mode`); (b) `cache_fill_verify_origin` fails closed on no/unsupported/mismatched digest under `require`, commits-unverified under `best-effort`; (c) rewrite `brix_cache_origin_query_checksum` (`origin_protocol.c`) as a bounded 8-hop `kXR_waitresp`→`kXR_attn(kXR_asynresp)` handshake — also benefits the legacy `fetch.c` path (shared TU). | `tests/test_cache_verify_require.py` (3: success / fail-closed teeth / corruption-neg via FaultProxy) |
| **#3 S3 storage-driver read path had zero in-path integrity** | `sd_s3_pread` (`src/fs/backend/s3/sd_s3.c`) checked HTTP status but never validated **which** bytes came back: (a) a `206` with a shifted `Content-Range` landed the wrong bytes at `off`; (b) a range-ignoring `200` for a request at `off>0` positioned a whole-object body at `off`; (c) a well-formed **empty** body mid-object was treated as EOF → silent truncation. libcurl validates framing/Content-Length but not any of these, and `brix_cache_verify` has no digest source for S3 (brix_s3 `ETag`="mtime-size", not a content hash). | `sd_s3_pread` now fails the read (EIO) on a `Content-Range` that does not start at `off`, on a `200` for `off>0`, and on an empty body at an offset the object provably extends past (EOF distinguished via `obj_size`). Unconditional (not knobbed) — these are pure correctness guards against a non-compliant middlebox. | `tests/unit/test_sd_s3_read.c` (6 mock-transport cases) + `cmdscripts/sd_s3_read_unit.py` + `tests/test_sd_s3_read_unit.py` |
| **DISCOVERED, NOT FIXED — S3-as-cache-origin fill hangs at baseline** | While building the #3 fault harness: a brix-cache node with `brix_storage_backend s3://…` filling from a brix_s3 origin **hangs on a clean local link** (`rc=124`, 0 bytes, no fault injection) — the cache node connects, falls back to the service credential, then never completes the fill. Reproduces the existing `test_cmd_cache_s3_origin.py` xfail ("legacy SigV4 cache-fill failure"). This is a pre-existing *functional* defect (SigV4 cache-fill), **not** a network-actor issue, and it blocks E2E fault-testing of that path — which is why #3 was proven via a deterministic mock transport instead. Fixing the hang is out of the hardening sweep's scope (functional SigV4 debugging). | — (needs its own investigation) | reproduced via `test_cmd_cache_s3_origin.py` (xfail) + a clean-link scratch probe |
| **#4 GridFTP passive data ports were un-firewallable + verify_write over-documented as a wire check** | Two deployment gaps on the gsiftp gateway. (a) `ev_do_pasv` bound the PASV/EPSV data listener to an **ephemeral** port (`sin_port = 0`) — the kernel picks any port, so on a firewalled site the admin cannot know which port to open and every passive transfer through the firewall dies (exactly the "network run by admins who won't admit a device is down" case). (b) `brix_gridftp_verify_write`'s directive comment called it "the trustworthy end-to-end check", which an operator can misread as protection against in-flight corruption — but its CRC is seeded from the **received** bytes, so a byte the network flips is accumulated, written, read back, and *matches*: it is a storage-persistence check, never a wire check. | (a) new `brix_gridftp_pasv_port_range <lo> <hi>` directive (globus `GLOBUS_TCP_PORT_RANGE` / vsftpd `pasv_min_port..max_port` equivalent): `ev_do_pasv` walks the inclusive range and binds the first free port; a fully-occupied range fails **closed** (`425`) rather than falling back to a random un-firewalled port; config-time validation rejects out-of-1..65535 / inverted ranges. Unset = ephemeral (unchanged default). (b) tightened the `verify_write` docs (directive comment + struct field) to say STORAGE-persistence, and point wire integrity at the client's post-transfer `CKSM` (which already exists and works). No `verify_write` behaviour change — it does exactly what a read-back can. | `tests/test_gridftp_pasv_range.py` (3: in-range PASV+EPSV / real STOR+RETR over the pinned channel / range-exhaustion → 425) + config-test matrix; `test_gridftp_verbs.py` (16) regression-clean on the unchanged ephemeral path |
| **#5 client held hostage by a slow-drip read + the `--max-stall` give-up window was a no-op** | Two client-side gaps against a hostile middlebox that dribbles bytes. (a) **Slow-drip (Slowloris) hostage:** the steady-state read loop (`plain_read_full`/`brix_tls_read`) re-arms its poll timeout *per iteration* — an idle timeout — so a firewall that forwards a few bytes just often enough to keep each poll from idling holds a single logical read open for unbounded wall-clock while never tripping the idle timeout; a 1 s download trickles for minutes. Reproduced with `brix-fault-proxy drip <bytes> <ms>`. (b) **Dead give-up knob:** the documented `--max-stall <ms>` / `$XRDC_MAX_STALL_MS` resilience window was parsed into `brix_opts` (the connection opts) but the copy pump's give-up window is read from `brix_copy_opts` (`copt`) via `copy_stall_ms()` — never bridged; worse, `xrdcp` `main()` did a bare `memset`+`verify_host=1` instead of `brix_opts_init()`, so `$XRDC_MAX_STALL_MS` was never even read. Net: an operator who set `--max-stall` to bound a stall silently got the 60 s default, so a tripped-deadline read re-handshook for a full minute. | (a) opt-in **whole-logical-operation** completion deadline: `XRDC_STALL_DEADLINE_MS` (default 0 = off) seeds `brix_io.stall_deadline_ms`; `brix_io_stall_arm()`/`disarm()` (idempotent — only the outermost arm sets it) set an **absolute** `stall_deadline_ns` cutoff **shared across every `read_full` frame** of one logical read (armed around `brix_file_read`/`readv`/`pgread`), so a drip that frame-splits under a per-call deadline can't evade it; a read outrunning the cutoff fails `ETIMEDOUT` (retryable). Because the FUSE/aio path routes through the same `brix_file_*`, it inherits the deadline. (b) `finalize_resilience_posture()` folds `brix_opts`'s `no_retry`/`max_stall_ms` into `copt` (single source of truth — the dead duplicate `--max-stall` handler in `xrdcp_parse_transport_option` removed), and `main()` now calls `brix_opts_init(&conn)` so the env is read. Under a hostile drip the two knobs compose: each read trips the deadline → the pump retries → after `--max-stall`/`$XRDC_MAX_STALL_MS` the copy fails cleanly instead of hanging forever. | `tests/resilience/test_slow_drip_deadline.py` (3: drip w/o deadline → held hostage `TimeoutExpired` / drip w/ deadline → fails fast inside the window / deadline armed + no drip → byte-exact success, no false positive); `FaultProxy.set_drip()` added to `servers.py`; `test_tools_resilience.py`+`run_xrdcp_loss.py` (6) regression-clean on the resilient retry path |
| **#7 S3 PutObject ignored the classic `Content-MD5` ingest digest** | The S3 server front-door (`src/protocols/s3/` — brix speaking S3 as a gateway to the POSIX/backend export) verified the modern AWS `x-amz-checksum-*` header form (`s3_put_checksum_apply`, post-commit read-back + unlink-on-mismatch) but **not** the historically dominant `Content-MD5` (RFC 1864), which the S3 contract says the server MUST verify (answering `400 BadDigest` on mismatch). `Content-MD5` was only in the CORS allow-list. Compounding it, brix's SigV4 canonical request is **hard-coded to `UNSIGNED-PAYLOAD`** (`auth_sigv4_verify_crypto.c` — legitimate, since XrdClS3 always signs UNSIGNED-PAYLOAD), so the body is never folded into the signature either. Net: a `PutObject` from boto3/aws-cli/HEP tooling that asserted an honest `Content-MD5`, with a byte flipped in flight past the TCP checksum, returned `200` and stored the poison silently. Proven with `brix-fault-proxy corrupt <frac> up` in front of an anon S3 PUT server. | New `s3_content_md5_verify` (`checksum.c`) recomputes MD5 over the just-committed object and, on mismatch, removes it and answers `400 BadDigest`; a malformed `Content-MD5` (not base64 / not 16 bytes) removes it and answers `400 InvalidDigest` (`s3_put_finalize_invalid_digest`). Wired into `s3_put_checksum_failed` — the single post-commit funnel all three PUT paths (`put_chunk`/`put_aio`/`put_stream`) already share — so all three inherit the gate from one edit, ahead of the existing `x-amz-checksum-*` verify. Coded bodies (`Content-Encoding`) are skipped (stored plaintext ≠ MD5 over the encoded stream — same limitation as verify-on-write). A real (non-`UNSIGNED`) `x-amz-content-sha256` stays out of scope (brix signs UNSIGNED-PAYLOAD; XrdClS3 never sends a payload hash). Reuses the module's own read-back+unlink model (`s3_cksum_vfs_open`/`s3_cksum_vfs_unlink`) via the VFS — no raw POSIX, seam-clean. | `tests/resilience/test_s3_put_corruption.py` (3: corrupt-up PUT w/ valid Content-MD5 → non-2xx, nothing stored / honest PUT through the proxy → 200 + byte-exact / malformed Content-MD5 → 400 InvalidDigest, nothing stored); `NginxS3Anon` harness + `nginx_resilience_s3_anon.conf` added; `test_s3_checksums.py`+`test_s3_verify_write.py` (18) regression-clean on the unchanged `x-amz-checksum-*` path. **Fix bug caught in test:** the malformed-`Content-MD5` branch first returned `CONFLICT` *without* unlinking, leaving the committed object behind — a header-corruption round exposed it; both malformed returns now unlink first, matching the ambiguous-`x-amz` path. |
| **#8 GridFTP MODE E STOR committed a gapped reassembly as a COMPLETE file** | The gsiftp gateway's MODE E STOR reassembler (`src/protocols/gridftp/ev/ftp_ev_mode_e.c`) fans an object in as offset-addressed extended blocks across ≤`Parallelism` parallel data streams, writing each block at its **absolute** offset into a sparse in-place file. It guarded blocks whose ranges *overlap* (`ftp_eb_range_overlaps` → `550`) but completed the transfer purely on the **EOD tally** the EOF block declares (`eb_eod_seen >= eb_eof_total`) — it never checked the accepted ranges *tile the object gaplessly from 0*. So a set of blocks that leaves a **hole** — an in-path bit-flip of a 17-byte EBLOCK header's OFFSET field past the TCP checksum, or a hostile/short sender that still emits its EOD — committed a file whose gap region was **silently zero-filled**, and the control channel answered `226` (complete) over poison the client never sent. The MODE E analogue of #1 (truncated object served as whole); `verify_write` (§#4) cannot catch it — the read-back hashes exactly the zero-holed bytes on disk. | New `ev_eb_ranges_contiguous` coalesces the accepted ranges (reusing the marker-path sort+merge) and requires exactly one span `[0, high-water)` whose length equals `eb_received`; a gap fails the transfer `550`. Because every EOD is already in, the client *declared* the object complete — this partial is **not** an interrupted transfer awaiting a range-resume, so (unlike a mid-payload network cut, which keeps its clean prefix for the 111-marker resume) the in-place object is **aborted + `brix_vfs_unlink`ed** so nothing is published. Fail-closed, unconditional — a hole in a "complete" transfer is unambiguously wrong. Seam-clean (writer/`brix_vfs_unlink`, no raw POSIX). | `tests/test_gridftp_mode_e_truncation.py` (3: contiguous out-of-order STOR → `226` byte-exact / interior hole → `550`, nothing stored / leading gap → `550`, nothing stored); `test_gridftp_mode_e_event.py`+`test_gridftp_mode_e.py` (11) + `verify_write`/`engine_event`/`pasv_range` (24) regression-clean |
| **#9 GridFTP *stream-mode* STOR silently accepted a truncated upload as complete** | Unlike MODE E (#8), a stream-mode STOR (`ev_stor_read`, `ftp_ev_xfer.c`) has **no length framing** — the object ends when the client closes the data channel, so a bare EOF is the *only* completion signal and is **indistinguishable from a hostile middlebox dropping the connection mid-flight**. The one signal the protocol offers is `ALLO <size>` (RFC 959, the client pre-declaring the file size), and brix answered `200 ALLO ok` then **discarded it** (`ALLO` was a no-op stub in `ftp_ev_dispatch.c`). Net: a truncated upload committed the short prefix and answered `226` complete — a silently short object served as whole (the stream-mode analogue of #1/#8). `verify_write` can't help (it hashes exactly the short bytes on disk). | Capture the `ALLO` size onto the connection (`fc->allo_size`, one-shot, snapshotted into `dc->allo_size` at STOR setup — stream-mode STOR only, since MODE E is validated structurally and RETR/APPE have no ALLO). New opt-in `brix_gridftp_require_allo_size on` holds the transfer to exactly the declared size at EOF: `dc->off != dc->allo_size` → fail `550` instead of commit. The clean prefix is **left in place** (a truncation is a resumable interruption → REST-resume from `dc->off`, unlike MODE E's declared-complete-but-holed poison which is unlinked). **Opt-in (default off)** because RFC 959 permits `ALLO` as an advisory reservation, not a strict size — so strict equality is for deployments whose clients (globus-url-copy/FTS) send the exact file size; a STOR with no preceding `ALLO`, or the knob off, is unaffected (documented inherent stream-mode behaviour). Seam-clean (no VFS change). | `tests/test_gridftp_allo_truncation.py` (3: knob-on ALLO=N + N bytes → `226` byte-exact / knob-on ALLO=N + N−K bytes then close → `550` / knob-off same truncation → `226`, proving it's genuinely opt-in); `nginx_gridftp_allo_ev.conf` (adds `{EXTRA_DIRECTIVES}`); `test_gridftp_verbs.py`+`engine_event`+`mode_e_event`+`mode_e_truncation`+`verify_write`+`pasv_range` (50) regression-clean |
| **#6 WebDAV PUT ingest was never checked against the client's asserted digest** | The WebDAV gateway (front door to the POSIX/S3 export for HTTP/WLCG writers) streamed the PUT body to a staged temp and committed **whatever landed** — a byte flipped past the TCP checksum by a hostile middlebox was published silently, and a client that *told us* what it sent (RFC-3230 `Digest:` — the WLCG/XrdHttp convention — or legacy `Content-MD5:`) got no benefit: the header was ignored on ingest. `webdav_put_persist_checksums` (§8.3) computes digests but runs **post-commit** and only *records*, never *compares*. Proven with `brix-fault-proxy corrupt <frac> up` in front of an anon WebDAV PUT server: a corrupted body carrying a valid `Digest`/`Content-MD5` returned `201` and the poisoned bytes were committed. | New `webdav_put_verify_ingest_digest` runs on **both** commit sites (async `webdav_put_aio_done`, sync `webdav_put_commit`) **before** publish: parse the strongest asserted digest (`Digest:` comma-list, then `Content-MD5:`), recompute it over the fully-staged bytes and **refuse the commit `400`** on mismatch — never publish poisoned bytes. The staged temp is `O_WRONLY` with no final path yet, so it is reopened read-only via `/proc/self/fd/<fd>` (valid for the unlinked/`O_TMPFILE` staged temp; `/* vfs-seam-allow */`-annotated per INVARIANT 12) and hashed over that read handle. Coded bodies (`Content-Encoding`) are skipped (stored plaintext ≠ digest over the encoded stream — same limitation as verify-on-write); a driver-object (S3) target exposes no fd and is verified on its own ingest path. New opt-in `brix_webdav_require_digest on` additionally **refuses `400`** any PUT that carries no usable digest, for deployments that decline writes they cannot verify (default off — a mismatch is always refused; only *absence* is gated). Field added at struct END (ABI, [[struct_field_abi_clean_rebuild]]). Fail-closed: an unparseable digest value, a reopen failure, or a compute failure all reject. | `tests/resilience/test_webdav_put_corruption.py` (3: corrupt-up PUT w/ valid digest → never 2xx, nothing committed / honest PUT w/ digest through the proxy → 2xx + byte-exact stored / `require_digest` + no digest → 4xx, nothing stored); `NginxWebdavAnon` harness + `nginx_resilience_webdav_anon.conf` added; `test_checksum_on_write.py`+`test_webdav_verify_write.py`+`test_webdav_spooled_put.py` regression-clean (the one `gsi-8444` fail is a pre-existing TLS client-cert env condition, pre-body, unrelated) |
| **#11 native cleartext kXR_write / kXR_writev had no wire-integrity option (the truncation surface itself is sound)** | Investigating "can a data-channel cut mid-`kXR_write` commit a short object?" established the native plain-write path is **already sound against truncation** — unlike the gateways (#8/#9), the native protocol has an *explicit in-band completion signal* (`kXR_close`/`kXR_sync`), and brix maps disconnect→abort and close→commit correctly: a staged whole-object handle drops its temp on disconnect (`fd_table_teardown.c`, `brix_vfs_writer_abort`), refuses a gap with `kXR_Unsupported` (sequential-append enforced against the writer cursor, `write_staged.c`), POSC unlinks its temp on non-clean close, and `kXR_posc` is honoured (`open_resolved_file.c`). The residual gap is *integrity*, not truncation: plain `kXR_write` / `kXR_writev` carry **no per-page CRC** (INVARIANT 1 covers only `kXR_pgwrite`), so a byte a hostile middlebox flips past the TCP checksum is committed undetected — and `brix_verify_write` is a storage read-back (it re-reads and matches the corrupt bytes), never a wire check. `kXR_pgwrite` exists precisely to catch this, but nothing let a hostile-network deployment *require* it. | New opt-in `brix_require_pgwrite on` (default off — plain write is the stock upload op): a data-carrying `kXR_write` / `kXR_writev` on a writable handle is refused `kXR_Unsupported`, forcing clients onto the CRC32c-checked pgwrite path. Shared gate `brix_write_require_pgwrite` (`write/write.c`, declared in `write.h`) guards `brix_handle_write`; `brix_handle_writev` applies the same check after framing (the all-zero-length vector already short-circuits). SSI request-accumulation and zero-length no-ops are **exempt** so the knob never breaks control traffic. The native-write analogue of `brix_webdav_require_digest` (#6) / `brix_gridftp_require_allo_size` (#9): fail-closed integrity posture for deployments whose clients already speak pgwrite. Config plumbed through `common.require_pgwrite` (`shared_conf.h` init/merge, `directives_tpc.inc`). | `tests/test_root_require_pgwrite.py` (4, two co-hosted servers over one posix export — knob on `{PORT}` / off `{OFF_PORT}` via `nginx_root_require_pgwrite.conf`, reusing the `test_pgwrite_cse` wire client: knob-on plain write → `kXR_Unsupported`, nothing on disk / knob-on proper pgwrite → clean status + byte-exact [no FP] / knob-on writev → `kXR_Unsupported`, nothing on disk [the sibling non-CRC op can't sneak past] / knob-off same plain write → `kXR_ok` byte-exact [opt-in proof]); `test_pgwrite_cse.py` (21) + `test_pgwrite_staged_sync_gate.py` (3) + `test_open_flags_lifecycle.py` (12) regression-clean — the default-off gate is transparent |
| **#10 native kXR_pgwrite could publish a known-corrupt page as complete on the staged write path (via kXR_sync, and via a misleading clean status)** | The native XRootD write plane (`src/protocols/root/write/`) has a per-handle **Fob** (`pgw_fob.c`) that registers every pgwrite page failing CRC32c (the CSE accept-then-correct machine), and a `kXR_close` gate (`brix_close_pgw_gate`) that refuses to publish while the Fob is non-empty — that gate is what makes INVARIANT 1 (pgread/pgwrite integrity) hold for the committed file. But a WRITE open to a whole-object **staged** backend (`s3://`/`sd_http` — no `BRIX_SD_CAP_RANDOM_WRITE`, no `.pwrite`, so it routes through the phase-70 staged writer, `fh->writer != NULL`) exposed two holes. (a) **Facet A — sync bypass:** `kXR_sync` COMMITS a staged object (single backend PUT) and did so with **no Fob check at all** — a client could pgwrite a corrupt page, then `kXR_sync`, and the poison published as a complete object, sidestepping the close gate entirely. (b) **Facet B — accept-then-correct is a lie on a staged handle:** the staged pgwrite branch registered the bad page in the Fob but then **appended the corrupt bytes** to the sequential append-only staged temp and answered a **clean** `kXR_status` (never the CSE retransmit list) — but a staged handle can never re-receive a page at its already-passed offset, so the "correction" the client is invited to send can never land. The corrupt bytes were already in the object and the close/sync gate would then wedge the handle forever. | Fail-closed on both facets, with a **shared** gate so the two commit points can't drift. New `brix_pgw_fob_commit_blocked()` (`pgw_fob.c/.h`) returns the count of uncorrected pages (or 0 when the Fob was never armed); `brix_close_pgw_gate` (`read/close.c`) now routes through it, and `brix_handle_sync` (`write/sync.c`) consults the *same* helper **before** `brix_staged_commit_handle`, answering `kXR_ChkSumErr` while any page is uncorrected. Facet B: the staged pgwrite branch (`write/pgwrite.c`) now **hard-rejects** any CRC32c failure with `kXR_ChkSumErr` immediately (never appends corrupt bytes behind a clean status) — accept-then-correct stays available *only* on the random-write/POSC paths where a page genuinely can be re-sent to its offset. Seam-clean (no VFS/raw-POSIX change). | `tests/test_pgwrite_staged_sync_gate.py` (3, driven native `root://` → co-hosted `s3://` staged writer via `nginx_root_s3_staged.conf`, reusing the `test_pgwrite_cse` wire client: clean staged pgwrite + sync → `kXR_ok`, one object byte-exact [no FP] / corrupt page → `kXR_ChkSumErr` immediately, nothing appended [facet B] / sync after a corrupt page → `kXR_ChkSumErr`, close likewise, object never published [facet A]); `test_pgwrite_cse.py` (21) + `test_new_opcodes_b.py` (34) regression-clean on the unchanged random-write/POSC CSE path |
| **#13 native TPC pull had NO end-to-end verification (truncation + corruption both commit as complete)** | Native XRootD third-party-copy where **brix is the destination** pulls the source itself: it `kXR_open`s the remote source and streams it in one `kXR_read` window at a time (`src/tpc/outbound/source*.c`, in a thread-pool worker), then fsyncs and commits. The pull's **only** in-band "the whole file arrived" signal is a **zero-byte `kXR_read` reply** — a frame a truncating middlebox can forge (or a source that dies mid-stream naturally produces) — and the destination captured **no source size** and computed **no checksum**. So a **stopped/truncated** pull committed the short prefix as a COMPLETE file (the TPC analogue of #1/#8/#9), and a **byte flipped** on the source→dest hop past the TCP checksum was written verbatim and committed as good (no per-window CRC; plain `kXR_read`, not pgread — cf. INVARIANT 1 / #11). The read loop's own recv-failure path already caught a *raw* mid-frame TCP cut, but not a **well-formed** early-EOF or a length-preserving flip. | Two layers. **(a) Always-on source-size completion gate** (no knob — a size mismatch is unambiguous truncation): a new `tpc_stat_source` issues an explicit `kXR_stat` (distinct streamid tag 4) *before* the stream loop and records the authoritative size; after the loop's EOF, `tpc_stream_to_dst` refuses the copy `kXR_IOError` unless `bytes_written == src_size`. A source that won't declare a size leaves `src_size_known=0` and proceeds — unless opt-in `brix_tpc_require_source_size on` refuses the unverifiable pull `kXR_ServerError`. **(b) Opt-in post-copy checksum** `brix_tpc_verify_checksum on`: after a size-verified pull, `tpc_verify_source_checksum` `kXR_query(kXR_Qcksum)`s the source (tag 5), parses the `<alg> <hex>` reply, recomputes the SAME algorithm (adler32, xrdcp's default) over the written destination via `brix_checksum_hex_name_fd`, and fails closed `kXR_ChkSumErr` on mismatch / absent / unparseable / uncomputable — catching the length-preserving flip the size gate cannot see. On any failure the caller (`done.c`) unlinks the partial destination, so nothing is published. Both knobs default off (a plain pull carries no checksum — stock parity); the size gate is unconditional. Config plumbed like `tpc_max_transfer_secs` (5 files: `srv_conf_fields_net.inc` decl, `server_conf.c` UNSET, `server_conf_merge_cluster.c` merge→0, `directives_tpc.inc` flag directives). The TPC-pull analogue of `brix_webdav_require_digest` (#6) / `brix_gridftp_require_allo_size` (#9) / `brix_require_pgwrite` (#11) / `put_checksum` (#12). **Scope limit:** the single-recv qcksum verify targets brix→brix (small-file) pulls where the source answers the plain query directly with `kXR_ok`; a large-file source that defers the checksum behind a `kXR_wait`/`asynresp` sequence is not handled (documented, out of v1 scope). | `tests/test_tpc_pull_integrity.py` (4, one nginx with two brix_root planes each acting as its own TPC source+dest via `nginx_tpc_harden.conf`, `verify_checksum` on `{PORT}` / off `{PORT_OFF}`, driven by stock `xrdcp --tpc only`). A **kXR-response-aware fault proxy** splices the destination's pull leg: it frames the source→dest stream uniformly (every reply, incl. the handshake, is an 8-byte `ServerResponseHdr`+dlen body) and touches **only** read replies (streamid tag 3) — so the `kXR_stat` (tag 4) and `kXR_Qcksum` (tag 5) replies stay truthful. Two deterministic faults (surgical, non-flaky analogues of `brix-fault-proxy truncate-at`/`corrupt down`): **truncate** shrinks the first data frame to half + forges `dlen=0` EOF; **flip** flips one body byte, length preserved. Contract: clean link knob-on → byte-exact [no FP] / truncated knob-on → `[3007] TPC pull truncated: wrote 4000 of 8000` (size gate), partial unlinked [catch] / one-byte flip knob-on → `[3019] TPC checksum mismatch: source adler32=… destination=…`, unlinked [catch] / same flip knob-off → `kXR_ok`, size-correct-but-corrupt file committed [the exact gap #13 closes]. Because the proxy only ever emits **well-formed** frames, `recv` never fails — so by construction the only rejection path is the new gate (the knob-off flip committing further proves frames are size-correct). **Config gotcha (cf. #12):** the two planes use **distinct** export roots — the storage-backend registry is keyed by canonical root. |
| **#12 the OUTBOUND commit leg (brix → S3/HTTP origin) had no wire integrity** | Findings #1–#11 hardened the paths *into* brix (ingest) and *out to* the client (read). This is the remaining hop: when a brix export is backed by a remote origin (`s3://`/`http://`), a WRITE routes through the phase-70 whole-object staged writer and commits as one PUT to that origin (`brix_vfs_writer_commit → brix_vfs_staged_commit → sd_s3/sd_http staged_commit`). **Truncation** on this leg is defended by `Content-Length` framing, but **corruption** was not: brix's SigV4 canonical request is hard-coded `UNSIGNED-PAYLOAD` (the signature covers only headers, never the body — legitimate, mirrors XrdClS3), and the driver sent no `Content-MD5`. The `ETag` in the PUT response was captured but never compared. Net: a byte a hostile/flaky network flips on the node→origin hop past the TCP checksum is accepted by the origin (signature still verifies), stored, and `200`'d — brix commits the poison as a complete object. The egress analogue of the S3 `Content-MD5` ingest gap (#7): "S3 signs UNSIGNED-PAYLOAD" cuts both ways. | Opt-in, origin-enforced, inline (no extra round trip): `s3://host/bucket?put_checksum=1` makes every commit PUT **and** MPU `UploadPart` carry a **signed** `x-amz-checksum-crc32` (base64 of CRC-32/IEEE over the exact bytes to store, folded into the SigV4 SignedHeaders); `http://…?put_checksum=1` carries `Content-MD5`. A compliant origin recomputes and rejects a mismatch with `400 BadDigest`, so a wire flip fails the commit instead of publishing silent poison. Core signer refactored to `sd_s3_sign_ex(…, ck_name, ck_val, …)` (thin `sd_s3_sign` wrapper unchanged); flag plumbed `?put_checksum=1` → `origin_put_checksum` (registry entry) → `cfg.put_checksum` → `sd_s3_open_params`/`brix_sd_http_cfg_t` → `f->put_checksum`. Backend layer stays ngx-free (OpenSSL `EVP_EncodeBlock`/`EVP_md5`, no ngx pool). The HTTP leg needed **no** transport-signature change: the shared `brix_s3_origin_curl_transport` splits its `headers` block line-by-line into a curl_slist, so `Content-MD5:` is prepended to the existing auth-header block. **Off by default** (UNSIGNED-PAYLOAD parity): an origin that rejects unknown checksum headers keeps working untouched. The outbound analogue of `brix_webdav_require_digest` (#6) / `brix_gridftp_require_allo_size` (#9) / `brix_require_pgwrite` (#11). | `tests/test_backend_put_checksum.py` (3, native `root://` → co-hosted validating brix_s3 origin via `nginx_root_s3_putck.conf`, with a **deterministic marker-targeting body corruptor** interposed on the backend leg — flips one body byte with the SigV4 headers intact, a surgical non-flaky version of `brix-fault-proxy corrupt up`: knob-on clean link → commit byte-exact [no FP] / knob-on one body-byte flip → origin `400 BadDigest`, commit fails, no poison / knob-off same flip → origin `200`, poison silently committed [the exact gap the knob closes]). **Test-config gotcha caught here:** the storage-backend registry is keyed by the export's canonical root, so the knob-on and knob-off servers **must** use distinct `brix_export` roots — sharing one collides on a single entry and the last registration (put_checksum off) silently wins for both. |

---

## 7. Cross-cutting lessons specific to this domain

A few lessons recurred specifically in storage/cache/VFS work, distinct from
(but complementary to) the general migration-era lessons:

1. **A missing primitive, not a hard call site, is usually why a seam
   migration stalls.** Every multi-week stall in the VFS seam backlog
   resolved the moment a genuinely missing thread-safe/pool-free helper
   (`vfs_walk`, thread-safe `vfs_open_fd`/`vfs_rename_path`, the `setattr`
   vtable slot) was built. When a backlog stops moving, look for the
   enabler before grinding individual sites.
2. **Non-POSIX backends need their own bug classes re-audited, not
   assumed-safe by analogy to POSIX.** Trailing-slash existence checks,
   `fstat` of a raw fd instead of driver `fstat`, sendfile fast paths that
   silently assume single-block files, and vtable slots that quietly
   no-op — all four were "the POSIX behavior was accidentally correct, the
   driver behavior wasn't" bugs, found only once a real non-POSIX driver
   (pblock, then S3, then Ceph) exercised the path.
3. **A spike that changes the plan is worth more than the plan.** Both the
   FRM Task-0 spike (delete rather than port a third of the subsystem) and
   the CephFS/RADOS interop spike (read-only rescue is GO, zero-copy
   upgrade is NO-GO) prevented weeks of building the wrong thing. Both were
   done *before* any implementation code, specifically to answer "is this
   viable" rather than "how do I build this."
4. **Config-time vs. runtime logging silently diverges in severity
   requirements** (`NGX_LOG_NOTICE` dropped at parse time, needs `WARN`) —
   this bit CVMFS origin-selection logging and is a trap for any future
   config-time diagnostic.
5. **"Not a byte count" and "errno clobbered by cleanup" are both
   recurring, hard-to-see correctness bug shapes** in this codebase's cache
   and backend code specifically, because so much of it threads return
   codes and errno across pool/fill/verify boundaries. Both classes
   surfaced more than once across this era's memory (`cache_sink_pwrite`
   return convention; the CVMFS mid-fill EIO→ENOENT clobber) — worth an
   explicit check whenever reviewing new fill/flush/verify code.
6. **To verify staged bytes *before* commit you cannot `pread` the writer
   fd or reopen by name.** The staged temp is opened `O_WRONLY`
   (`staged_open_posix`) and has no final path yet, so `brix_vfs_writer_fd()`
   returns a write-only descriptor and `brix_integrity_get_fd` (pread-based)
   fails `NGX_ERROR` on it — which, if used as the verify source, *falsely
   rejects honest PUTs*. Re-open the same open file description read-only via
   `/proc/self/fd/<fd>` (valid for the unlinked/`O_TMPFILE` temp; annotate
   `/* vfs-seam-allow */`). This is the general pattern for any *pre-commit*
   integrity gate over staged bytes, distinct from the *post-commit*
   read-back (`webdav_put_persist_checksums`, S3 checksum-apply) that can
   reopen the published final path. Surfaced building Finding #6 (§6.1).
7. **An out-of-order write path needs a *completeness* invariant, not just an
   *overlap* one — and "declared complete" is the line between resumable
   partial and poison.** A MODE E STOR (Finding #8) reserves an overlap guard
   per block but the reassembly is only whole if the accepted ranges tile
   `[0, high-water)` with no gap; committing on the EOD tally alone published a
   zero-filled hole as a `226`-complete file. The subtlety in the *fix* is that
   an in-place random writer deliberately **keeps** its partial on failure so a
   client can range-resume (the 111 markers) — so you cannot blanket-unlink on
   abort. The safe distinction: the gap is detected only *after every declared
   EOD is in*, i.e. the client asserted completion, so that partial will never
   be resumed and is pure poison → unlink it; a mid-payload network cut (EODs
   *not* all in) keeps its clean prefix untouched. Note also that O_ATOMIC
   staging (WebDAV/S3's poison defence) is **not** available here: the staged
   path demands in-order-from-0 writes, which MODE E's offset-addressed fan-in
   fundamentally is not. Its sibling, stream-mode STOR (#9), has the *opposite*
   problem: **no structural completeness signal at all** — a bare data-channel
   close is indistinguishable from a truncation, so the only lever is the
   client's `ALLO`-declared size, and even that is RFC-advisory (hence an opt-in
   knob, not a fail-closed default). The general shape: for a write gateway, ask
   "what tells me the transfer is *complete*, distinct from *stopped*?" — a
   digest (WebDAV/S3), a gapless tiling (MODE E), or a declared size (stream +
   ALLO); if the answer is "nothing", a stopped transfer will read as complete.
8. **When one commit point is integrity-gated, EVERY commit point must consult
   the *same* gate — and an early-publish opcode is a second commit point.** The
   native pgwrite CSE machine (Finding #10) put its "no known-corrupt page may be
   published" check in the `kXR_close` gate, which was correct but incomplete: a
   whole-object staged writer also publishes on `kXR_sync` (a single backend PUT),
   and that path had no check — so `pgwrite corrupt-page; sync` published the
   poison, sidestepping close entirely. The durable fix wasn't a second copy of
   the check but a *shared* predicate (`brix_pgw_fob_commit_blocked`) both commit
   points call, so they cannot drift as either evolves. Two lessons compound
   here. (a) Enumerate commit points by "what publishes the object", not by opcode
   name — `close` is the obvious one, but `sync`, an idempotent staged-commit, or
   a TPC finalize can each be the real publish. (b) A repair protocol like
   accept-then-correct is only sound where the repair channel actually exists: on
   a sequential append-only staged handle a page can never be re-sent to its
   already-passed offset, so registering it as "correctable" and answering a clean
   status is a lie that both hides the corruption and later wedges the handle —
   the honest answer there is a hard fail-closed reject at ingest, reserving
   accept-then-correct for the random-write/POSC paths where the offset is still
   addressable.
9. **"Sound against truncation" and "sound against corruption" are different
   questions — verify both, and don't fabricate a bug when a path is genuinely
   sound.** The native plain-write sweep (Finding #11) set out to find a
   truncation poison-commit like #1/#8/#9 and found none: the native protocol has
   an *explicit in-band completion signal* (`kXR_close`/`kXR_sync`), so
   disconnect→abort and close→commit map cleanly, and brix already honoured POSC +
   staged-abort + sequential-append. That "verified sound" outcome is itself
   valuable — it's the contrast that shows why the gateways (which lacked an
   explicit completion signal) needed #8/#9 in the first place. But soundness
   against truncation said nothing about *wire integrity*: plain `kXR_write` /
   `kXR_writev` carry no CRC, and `brix_verify_write` is a storage read-back that
   matches whatever landed, so a wire bit-flip commits silently. The knob
   (`brix_require_pgwrite`) closes that as an opt-in, matching the same
   "require-the-integrity-signal" shape as #6/#9. General rule for a write
   gateway: ask *both* "what tells me the transfer is complete?" (truncation) and
   "what proves the bytes are the client's?" (corruption) — a path can pass one
   and fail the other.
10. **Integrity has a direction; audit every hop, and the OUTBOUND commit leg is
    the one most easily forgotten.** The hardening sweep instinctively looks at
    ingress (client → brix: #6/#7/#8/#9/#11) and egress-to-reader (backend → cache
    → client: #1/#2/#3). Finding #12 is the third hop — brix → *its own* remote
    origin on commit — and it inherited the exact blind spot #7 exposed on ingress:
    SigV4 signs `UNSIGNED-PAYLOAD`, so nothing brix sends proves the body to the
    origin unless brix *adds* a checksum header (`x-amz-checksum-crc32` signed into
    the SignedHeaders, or `Content-MD5`). The general rule: for every network hop an
    object crosses, name what proves its bytes at *that* hop — and a proxy/gateway
    has strictly more hops than a single server, so "we verify on ingest" and "we
    verify on read" together still leave the middle leg naked. Two smaller lessons
    rode along. (a) **Prefer the header the *peer* already validates over a new
    round trip.** An origin-enforced checksum header is inline (the origin was going
    to parse the request anyway) and needs no read-back probe — cheaper and simpler
    than a post-commit HEAD-and-compare, and it fails the write atomically. (b) The
    storage-backend **registry is keyed by canonical export root**, so two servers
    that must differ in backend options (here put_checksum on vs off) must not share
    an export root — the last registration silently wins for both. That bit the #12
    *test config* (two co-hosted root nodes), and it is a real deployment footgun,
    not just a test artifact.
11. **A *well-formed forged early-EOF* is a distinct threat from a raw mid-frame
    cut, and only the first one exercises the code you think you're testing.** The
    native TPC destination-side pull (Finding #13) is the reader-side twin of #10:
    its only in-band completion signal is a zero-byte `kXR_read` reply, which a
    truncating middlebox can *forge cleanly* — a valid `ServerResponseHdr` with
    `status=kXR_ok, dlen=0` — so the transfer reads as complete after N bytes
    instead of stopped. This matters twice over. (a) For the *fix*: a pull leg,
    unlike native plain-write (#11), has no `kXR_close`/`kXR_sync` from the writer
    to mark "done", so the only authoritative completion signal is the source's
    own declared size — hence the always-on `kXR_stat` size gate (truncation is
    unambiguous, so it fails closed) plus the opt-in `kXR_query(kXR_Qcksum)`
    checksum compare for length-preserving corruption (the reader-side analogue of
    #12's outbound `put_checksum`). (b) For the *test*: a raw TCP mid-frame cut
    would have hit the pre-existing recv-failure path and passed for the *wrong*
    reason, never touching the new size gate — proving the gate required a
    kXR-response-aware proxy that emits only well-formed frames and forges the EOF
    (or flips a body byte) at the protocol layer. General rule: when the completion
    signal is a specific well-formed message rather than a connection close, the
    adversary you must model produces well-formed messages too, and your repro must
    forge at that same layer or you are testing a different defence than you think.
