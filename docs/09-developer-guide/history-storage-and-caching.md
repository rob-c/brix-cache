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
| Generic S3 `listxattr` over all `x-amz-meta-*` keys needs a transport extension in both client and cache-side S3 transports (header-by-name-only today) | missing capability | `backend_meta_parity_phase4_decision` memory; not yet a tracked phase doc |
| Ceph namelib (lfn2pfn) rule for RAL/Glasgow never supplied — blocks touching production RADOS data | blocked, external dependency | `xrdceph_rados_compat_contract`; rados driver wiring itself also untested without a real Ceph build |
| Handle-table cluster (fd_table, open_resolved_file, read/readv/pgread, zip_member, tpc/launch) still holds raw fds, not VFS handles — largest remaining seam wall | architecture | vfs_phase2_full_seam memory |
| `xrootd_staged_*` (6 PUT files) intentionally not migrated onto ctx-holding `vfs_staged` — recommend reclassifying as an allowed below-seam primitive instead of re-plumbing | architecture decision pending | vfs_phase2_full_seam memory |
| `sd_xroot` (writable remote root:// primary): setattr (chmod/utime) forwarding and directory ops (mkdir/opendir) still follow-ons; staged_commit is non-atomic (no rename); no shared durable-journal/backpressure with the cache WT engine | missing capability | writable_remote_root_staged_write memory |
| Composable `cache_store` has no watermark eviction — watermark tests must stay on the legacy `cache on`+`cache_root`+`cache_origin` grammar | scoped gap | composable_cache_config_ganesha memory |
| Cache checksum-on-fill/producer side for `.cinfo`/`.meta` cks fields not yet populated by the server — `xrdckverify --cache` always reports "no record" today | missing capability | xrdckverify_tool memory; phase26_slice_caching §9 follow-up |
| `xrdstorascan` scan engine walks raw POSIX, not the SD-driver seam — backend/namespace-consistency reporting is meaningless for non-POSIX backends until routed through the VFS | architecture gap | xrdstorascan_backend_tooling memory |
| FRM migrate/purge engine (F1/F2) and Category-2 purge intentionally not reimplemented in-process post-dissolution; purge-watermark monitor logs only, never acts | scoped-out by design | frm_tape_staging_plan memory; comparison docs |
| Ceph phase-5 (server bench + dedicated Ceph CI harness) and phase-4b (catalog enumeration verb + inventory/drift wiring) deferred together, pending a real non-POSIX driver to exercise them meaningfully | deferred | xrdstorascan_backend_tooling memory |

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
