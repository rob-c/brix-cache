# Storage backends, caching, and tape/FRM staging: XRootD vs BriX-Cache

> Part of the [XRootD vs BriX-Cache comparison set](./README.md).

This document compares how **official XRootD** and the **BriX-Cache module** handle
the three layers below the wire protocol:

1. **Storage backend & namespace** — how a logical client path is turned into a
   real byte store (the OSS/filesystem abstraction).
2. **Caching (xcache)** — acting as a read-through / write-through cache node in
   front of a remote origin.
3. **Tape / FRM staging** — disk↔tape residency, recall (stage-in), migration,
   and purge.

Every claim below is grounded in source. Official paths are under
`/tmp/brix-src/src/`; this module's paths are under `src/`. Where a feature is
present but narrower, or absent, that is stated plainly. Maturity claims for the
tape/FRM layer in particular are flagged as **not full parity** because they are
genuinely partial.

This page is consistent with, and does not contradict,
[`../../source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md)
(its "Storage, Cache, Tape, and Backend Ecosystem" section).

---

## Scope

In scope:

- The **storage abstraction**: XRootD `XrdOss`/`XrdOfs` vs this module's
  `src/fs/` (VFS) + `src/fs/path/` (confinement) + `src/core/compat/namespace_ops.c`.
- **POSC** (persist-on-successful-close): `XrdOfs` POSC queue vs `src/protocols/root/read/`
  open/close staging, including the documented disconnect-semantics difference.
- **Caching**: `XrdPfc` (XCache) + `XrdPss` (proxy storage) vs `src/fs/cache/`.
- **Tape / FRM**: `XrdFrm`/`XrdFrc` multi-daemon ecosystem vs the `src/fs/xfer/`
  stage engine + `src/fs/backend/frm/` nearline driver +
  `src/protocols/root/query/prepare.c` + `src/protocols/webdav/tape_rest.c`.
- The **operator view**: directives and what to monitor on each side.

Out of scope (covered elsewhere in the comparison set): the wire protocol, auth,
TPC, HTTP/S3 method coverage, clustering/CMS, and metrics internals. They are
referenced only where storage behaviour depends on them.

---

## In official XRootD

XRootD separates storage into two stacked, **plugin-based** C++ layers, plus a
separate cache plugin family and a separate tape/FRM daemon family:

- **`XrdOss` — the Open Storage System.** An *abstract base class*
  (`/tmp/brix-src/src/XrdOss/XrdOss.hh`, with pure-virtual `Create`, `Mkdir`,
  `Remdir`, `Rename`, `Stat`, `Truncate`, `Unlink`, and `XrdOssDF`-returning
  `newFile`/`newDir`). It is a true **plugin ABI**: alternate backends are loaded
  via `ofs.osslib <path>` (`/tmp/brix-src/src/XrdOfs/XrdOfsConfigPI.cc`, which
  calls the `XrdOssGetStorageSystem2` entry point declared in `XrdOss.hh`). The
  default backend is local POSIX (`XrdOssSys` in
  `/tmp/brix-src/src/XrdOss/XrdOssApi.hh`, default obtained via
  `XrdOssDefaultSS()`). This is the seam that lets sites run **Ceph
  (`XrdCeph`)**, **proxy storage (`XrdPss`)**, checksum-tagstore
  (`XrdOssCsi`), and others under the *same* server.
- **`XrdOfs` — the Open File System frontend.** Implements the `XrdSfsInterface`
  (`/tmp/brix-src/src/XrdOfs/XrdOfs.hh`) on top of whatever OSS is loaded: open
  handle table (`XrdOfsHandle.cc`, a hash table of open handles with locking),
  POSC, TPC, checkpointing, event notification (`XrdOfsEvs.cc`), and the `ofs.*`
  directives (`XrdOfsConfig.cc`).
- **`XrdPfc` — the Proxy File Cache (XCache).** A `XrdOucCache` plugin
  (`/tmp/brix-src/src/XrdPfc/XrdPfc.hh`, entry point `XrdOucGetCache()`) that
  caches blocks of a remote file on local disk, with prefetch, watermark purge,
  per-file `cinfo` sidecars, and pluggable admit/deny decisions.
- **`XrdPss` — the Proxy Storage Service.** An OSS-API plugin
  (`/tmp/brix-src/src/XrdPss/XrdPss.cc`, `XrdPssConfig.cc`) that proxies storage
  ops to a *remote* XRootD origin (`pss.origin`). XCache layers on top of PSS:
  PSS does the remote fetch, PFC caches it locally.
- **`XrdFrm`/`XrdFrc` — the File Residency Manager.** A **multi-daemon** tape
  ecosystem: `frm_xfrd` (transfer daemon), `frm_xfragent` (client-side agent),
  `frm_purged` (purge/GC daemon), and `frm_admin` (interactive admin tool) —
  `XrdFrmXfrMain.cc`, `XrdFrmPurgMain.cc`, `XrdFrmAdminMain.cc`. Requests live in
  a durable fixed-record file (`XrdFrcReqFile.cc`, record =
  `sizeof(XrdFrcRequest)` from `XrdFrcRequest.hh`).

The design point is **pluggability and daemon separation**: storage backend,
cache, and tape are independent, separately deployable, separately configured.

---

## In BriX-Cache

This module collapses the same responsibilities into a single nginx worker
process with a **unified VFS** and **no general plugin ABI** — storage drivers,
cache tiers and FRM adapters are in-tree and selected by configuration, not
dlopened. The two exceptions are deliberate and narrow: `brix_checksum_plugin`
loads a site checksum algorithm (`src/core/compat/checksum_plugin_abi.h`) and
the FRM `lib` MSS adapter loads a tape driver (`sd_frm_lib_abi.h`), both against
plain-C ABIs of this project's own, not upstream's C++ ones:

- **`src/fs/` — the VFS.** One protocol-agnostic API (`brix_vfs_*`) that every
  front end (`root://` stream, WebDAV/HTTP, the S3 subset, CMS data I/O) funnels
  through (`src/fs/README.md`, `src/fs/vfs/vfs.h`). It performs the syscall, records a
  metric + access-log line, and returns a handle or buffer chain. Confinement,
  page-CRC, cache integration, and write-through are implemented **once** here.
- **`src/fs/path/` — confinement and the namespace boundary.** The export root is a
  **single local directory** (`brix_export`). Every client path is confined with
  Linux `openat2(2)` + `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`
  (`src/fs/path/beneath.c`), anchored to a per-worker `O_PATH` "rootfd". This is a
  *kernel-enforced* boundary, not a string prefix (see the next section). Auth/ACL
  gating (`auth_gate.c`, `authdb.c`, `acl.c`) lives in `src/auth/authz/`.
- **`src/core/compat/namespace_ops.c`** — the `brix_ns_*` mutation helpers
  (`mkdir`/`rename`/`unlink`/`link`) that the VFS and HTTP/S3 callers share, each
  confining through the beneath API. (Also `compat/staged_file.c`,
  `compat/shm_slots.c` for SHM-table allocation.)
- **`src/fs/cache/` — XCache-style read-through + write-through.** A caching gateway
  in front of a remote XRootD origin: thread-pool workers speak the XRootD wire
  protocol as a *native client* (`origin_protocol.c`, `origin_connection.c`,
  `io.c`) to fill the local `cache_root` tree on a miss, and mirror local writes
  back to an origin at `kXR_sync`/`kXR_close` (`writethrough_flush.c`).
- **`src/fs/xfer/` + `src/fs/backend/frm/` — durable tape staging.** The former
  standalone `src/frm/` subsystem, dissolved (phase-64) into the composable
  transfer engine: a durable, file-backed request registry with an SHM hot index
  (`stage_request_registry.c`, modeled on `XrdFrcReqFile`) backing
  `kXR_prepare`/`kXR_QPrep`, residency-aware opens via the `sd_frm` nearline
  driver, async recall (`stage_waiter.c`), and the WLCG HTTP Tape REST API
  (`src/protocols/webdav/tape_rest.c`).
  POSC commit logic lives in `src/protocols/root/read/close.c` / `src/protocols/root/connection/fd_table.c`.

The design point is **convergence and operability**: one process, one confinement
model, cross-protocol metrics — at the explicit cost of **no pluggable OSS
backend** and **not the full FRM daemon ecosystem**.

---

## Storage backend & namespace

### Official: pluggable OSS, string-prefix namespace

XRootD's logical-to-physical mapping is a **string transform**, then a plugin
call:

- **`oss.localroot <path>`** prefixes the logical filename with a base path
  (`/tmp/brix-src/src/XrdOss/XrdOssConfig.cc`, stored as `LocalRoot` in
  `XrdOssApi.hh`; applied via `GenLocalPath()` / the N2N plugin in
  `XrdOssApi.cc`). It is **not** a chroot or a kernel confinement: it is a path
  prefix concatenated at the application layer. A symlink inside the tree that
  points outside `localroot` is followed by normal POSIX semantics.
- **`oss.namelib <path> [parms]`** loads a name-to-name (N2N) plugin
  (`XrdOssConfig.cc` `xnml()`), e.g. to map LFN→PFN by rule.
- **`oss.space <name> <path> [...]`** and the deprecated `oss.cache` define
  **named storage spaces / partitions** with independent capacity tracking
  (`XrdOssConfig.cc` `xspace()`; usage in `XrdOssSpace.cc`/`XrdOssCache.cc`,
  `XrdOssCache_Space` carrying Total/Free/Largest/Usage/Quota). A file can be
  assigned to a space; the server tracks per-space usage and reports it.
- **`mkpath`** (auto-create parent dirs) is a *per-`Create()` option*
  (`XRDOSS_mkpath` in `XrdOss.hh`, honoured in `XrdOssCreate.cc`), not a global
  directive.
- The **whole backend is swappable** via `ofs.osslib` — local POSIX, Ceph, PSS,
  CSI-tagstore, etc.

### BriX-Cache: single confined local export, kernel-enforced

This module exposes exactly **one local POSIX export** per server block:

- **`brix_export <dir>`** is the export root. It is canonicalised once at startup
  (`realpath(3)` in `src/fs/path/canonical.c`) and a per-worker `O_PATH` rootfd is
  opened on it.
- Confinement is **kernel-enforced**, not string-based: every client-path syscall
  goes through `brix_open_beneath` / `brix_stat_beneath` /
  `brix_*_beneath` (`src/fs/path/beneath.c`), which use
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` anchored to the rootfd. An
  escape attempt returns `EXDEV`, mapped to `kXR_NotAuthorized`/403. This is
  *stronger* than `oss.localroot`: a symlink that points outside the root is
  refused by the kernel, not followed. (`src/fs/path/README.md` invariants;
  `src/fs/README.md` invariant 1.)
- Mutating ops (`mkdir`/`rename`/`unlink`/`link`) resolve the **parent** under
  `RESOLVE_BENEATH` and act on the final component only, because the bare `*at()`
  syscalls do not themselves honour `RESOLVE_BENEATH`
  (SECURITY note, `src/fs/path/beneath.c`).
- There is **no named-space / partition model** and **no N2N plugin**. The cache
  uses a second directory tree (`brix_cache_export`) but that is a distinct
  feature, not a space-token system.
- Recursive parent creation exists (`src/fs/path/mkdir.c`,
  `brix_mkdir_recursive_beneath`) and is used where the operation calls for it.

**The honest gap:** this module has **no OSS plugin ABI**. There is no
`ofs.osslib` equivalent, no way to load a Ceph/RADOS, PSS, or CSI-tagstore
backend, and no alternate storage system at all — only the confined local
filesystem. Sites that depend on `XrdOss` plugin backends (Ceph, custom MSS OSS,
`XrdOssCsi` page-checksum tagstore) cannot drop this module in for that role. It
is intentionally and only a POSIX-backed data server / gateway. (See the
source-verified comparison's Missing rows for `XrdPss`, `XrdCeph`, `XrdOssCsi`.)

---

## POSC and open semantics

POSC ("persist on successful close") means a file created by a transfer becomes
visible/durable **only** if the client closes it cleanly; an aborted transfer
must not leave a usable partial file.

### Official: a persistence queue with a hold/recovery window

XRootD POSC is configured by **`ofs.persist`**
(`/tmp/brix-src/src/XrdOfs/XrdOfsConfig.cc`, `xpers()`):

```
ofs.persist [auto | manual | off] [hold <sec>] [logdir <dirp>] [sync <snum>]
```

- `auto` = POSC for every create; `manual` (default) = POSC only when requested;
  `off` = disabled.
- **`hold <sec>`** is the load-bearing semantic: when a session drops *without* a
  clean close, the incomplete file is **held for `hold` seconds** (default ~10
  minutes) before removal, so a client that reconnects within the window can
  resume/complete it.
- POSC state lives in a **durable persistence queue** (`XrdOfsPoscq.cc/.hh`): a
  fixed-record file (record = LFN + user + commit time). `Add()` enqueues on
  create, `Commit()` clears it on clean close, and on **restart** the queue is
  read back (`List()`), so unfinished entries can be cleaned up / honoured after a
  server crash.

So official POSC survives both a client disconnect (held for `hold`) and a server
restart (recovered from the poscq file).

### BriX-Cache: stage-temp + atomic rename, immediate disconnect cleanup

This module implements POSC inline in the open/close path, gated on the wire flag
`kXR_posc` on a write open (advertised as `kXR_supposc`):

- On a `kXR_posc` write open, `brix_open_resolved_file()`
  (`src/protocols/root/read/open.h`/`open_request.c`) **stages a temp file** and records its
  intended final name in the handle's `posc_final_path`.
- On a **clean `kXR_close`** (`src/protocols/root/read/close.c`): `fsync(fd)` then
  `rename(temp → final)` atomically publishes the file, and `posc_final_path` is
  cleared so handle-free does not unlink it. A failed rename is reported as an
  error and the partial is removed.
- On **session end / error without a clean close** (`src/protocols/root/connection/fd_table.c`,
  `brix_free_fhandle`): if `posc_final_path` is still set, the staging temp is
  **unlinked immediately** — the partial never becomes visible.
- If write-through caching is on, the final POSC path is what gets mirrored (the
  conformance regression below depended on this ordering).

**The documented semantic difference (from the conformance batch):** on a
disconnect *without* close, this module **removes the un-closed partial
immediately**, whereas stock XRootD **holds** it for the `ofs.persist hold`
window pending a reconnect. The conformance suite records this as a **deliberate
xfail**, not a bug: removing the orphan immediately is a defensible reading of
"persist on *successful* close" intent, and there is no `hold`/resume-window
equivalent here. (`../conformance-findings.md`: "ours removes the un-closed
partial immediately ... stock keeps it pending a reconnect window — a defensible
semantic difference, not a bug.") There is also **no durable poscq file and no
cross-restart POSC recovery**: POSC state is per-handle, in-process; a master
crash mid-transfer leaves the staging temp to be cleaned up by ordinary means,
not replayed from a queue.

Related open-semantics conformance fixes verified against stock `xrdfs` (same
batch, `../conformance-findings.md`): the non-`retstat` `kXR_open` reply is a bare
**4-byte fhandle** (#7); `mkdir` of an existing path returns `kXR_ItExists`
(#11); `kXR_stat` emits full `StatGen` flags including `kXR_writable`/`kXR_xset`
computed against the server's euid/egid (#10); a trailing slash on `mkdir /d/` is
normalised then created (#19).

---

## Caching (xcache)

### Official: XrdPfc block cache over an XrdPss origin

XRootD's cache role is **XCache = `XrdPfc` (cache plugin) + `XrdPss` (remote
origin)**:

- **Fetch granularity.** Block mode (`XrdPfcIOFileBlock.cc`) downloads only the
  requested blocks; full-file mode (`XrdPfcIOFile.cc`) caches the whole file.
  Block size is `pfc.blocksize` (default 128 KB, range 4 KB–512 MB —
  `XrdPfcConfiguration.cc`).
- **Prefetch.** `pfc.prefetch <N>` prefetches up to N blocks ahead (default 10,
  max 4096), driven by a dedicated prefetch thread (`XrdPfc.cc`).
- **Purge.** `pfc.diskusage <lwm> <hwm> ...` runs watermark-based purge between a
  low and high disk-usage mark, on a purge interval (default 300 s), with
  optional cold-file age purge and per-file quotas. Disk/dir accounting is tracked
  hierarchically (`XrdPfcDirState.cc`) and snapshotted
  (`XrdPfcDirStateSnapshot.cc`); the resource monitor
  (`XrdPfcResourceMonitor.cc`) drives it.
- **Metadata.** Each cached file has a binary **`cinfo` sidecar**
  (`XrdPfcInfo.cc`) recording block-present bit vectors, file size, access
  history (open/close, bytes hit/missed/bypassed), and checksum status.
- **Admit/deny is pluggable.** `pfc.decisionlib` loads a `XrdPfc::Decision`
  plugin (`AllowDecision`, `BlacklistDecision`, or custom).
- **Write-through** exists as `pfc.writethrough [on|off]` (default off).
- The remote origin is an `XrdPss` instance: `pss.origin root://host:port`
  (`XrdPssConfig.cc`), with remote checksum support (`XrdPssCks.cc`).

### BriX-Cache: read-through + write-through, native-client origin fill

This module's `src/fs/cache/` is a practical caching gateway with **two halves**
(`src/fs/cache/README.md`):

- **Read-through (XCache).** On a read open of a not-yet-local file, a thread-pool
  worker connects to the export's `brix_storage_backend root://` origin, speaks the XRootD wire protocol as an
  **anonymous native client** (handshake → `kXR_protocol` → `kXR_login` →
  `kXR_open` with `kXR_retstat` to learn the size → `kXR_read` loop honouring
  `kXR_oksofar`), writes into a `.part` file, `fsync`s, and atomically
  `rename`s into the `cache_root` tree; a `.meta` sidecar records origin
  mtime/size/etag for staleness detection (`fetch.c`, `meta.c`,
  `origin_protocol.c`). Subsequent opens hit local disk
  (`brix_cache_open()` in `cache/open.c`, called from `src/fs/vfs/vfs_open.c`).
  - **Two fill granularities:** **whole-file** (`fetch.c`, the historical path)
    and **fixed-size slices** (`slice.c`/`slice_fill.c`, Phase 26 — `read://`
    random reads fetch only the touched ~128 KiB windows; missing slices get a
    `kXR_wait` retry). This is the analogue of PFC's block mode, but it is
    request-driven fetch, **not prefetch** — there is no read-ahead prefetcher.
  - **Serve-while-filling** (`brix_cache_serve_while_filling <time>`, off by
    default) closes the whole-file half of PFC's serve-while-filling. Slice mode
    always served partial content; whole-file mode used to be strictly
    foreground, so every concurrent reader of a cold object serialised behind one
    fill and paid the full transfer before its first byte. With the knob set, a
    second reader FOLLOWS the in-flight fill — it reads the staged bytes below
    the fill frontier and gets `kXR_wait` at it, so it streams at the origin's
    pace. Coordination is a marker file under the cache store (no SHM, no IPC),
    so it holds across workers and processes; the value doubles as a no-progress
    deadline so a filler that dies cannot hang its followers. Bounded on purpose:
    a local `posix:` store only, `brix_cache_verify off` only (staged bytes are
    provisional under any verify mode), and never over sendfile — the file is
    still growing.
  - **GSI-origin fill** is supported (TLS handshake with CA verify + SNI in
    `origin_connection.c`). TLS comes from a `roots://` `brix_storage_backend`
    URL and the CA from `brix_storage_credential`'s `ca_dir` — the
    `brix_cache_origin_tls` / `_cadir` directives named here were retired in
    phase-64 §14. An origin that demands `kXR_authmore` is answered from the
    export's `brix_credential` (bearer over `ztn`, X.509 proxy over `gsi`, SSS,
    or a delegated krb5 TGT); with no credential the login is anonymous and such
    an origin is rejected.
  - **Per-page origin verification** (`verify_pages` on the `root://`
    `brix_storage_backend` line) issues fills and reads as `kXR_pgread` and
    checks each 4 KiB page's CRC32c as it arrives (`cache/origin_pgread.c`).
    This is the read-side analogue of what `XrdOssCsi` provides on the storage
    side, and it covers what `brix_cache_verify` cannot: that check hashes a
    COMPLETED fill against a whole-file digest, so ranged/slice reads and
    digest-less origins go unverified. The bare token fails closed against an
    origin that cannot page-read; `=best-effort` falls back to `kXR_read`.
- **Write-through.** With write-through enabled, locally-written files are mirrored
  back to `brix_wt_origin` (or the cache origin) at `kXR_sync`/`kXR_close`,
  **sync or async** (`brix_wt_mode`). The decision (allow/deny prefixes, size
  limit) is made **once at open** and cached on the handle
  (`writethrough_decision.c`, mirroring the spirit of `XrdPfcDecision`). The flush
  reuses the same native-client origin code in write mode
  (`writethrough_flush.c`).
- **Eviction.** Two-pass LRU (large-file pass, then oldest-first) triggered by a
  `statvfs` occupancy gate (`brix_cache_eviction_threshold`, in ppm), with
  candidate scan, same-device guard, and manager-registry unregister of evicted
  paths in cluster mode (`evict_policy.c`, `evict_candidates.c`).
- **Concurrency.** Per-file fill serialisation via an `O_EXCL` sentinel lock that
  works across worker processes (`lock.c`); eviction has a separate sentinel with
  stale-lock reclaim.

**Modes supported:** read-through (`rt-cache`) whole-file or slice; write-through
(`wt-cache`) sync or async. **What is narrower than PFC:** no prefetch/read-ahead;
no `cinfo`-style per-block presence bitmap (presence is per-file or per-slice
file + `.meta`); no hierarchical dir-state purge policy, snapshots, quota plugin,
or resource-monitor machinery; no pluggable decision-plugin ABI (the
write-through decision *function* is pluggable in-process, but there is no
loadable `.so`). The source-verified comparison rates this **Partial**: "Practical
cache mode exists. Upstream `XrdPfc` has much broader policy, purge, snapshot, and
resource-monitoring machinery."

**A note for cache maintainers (from the conformance batch):** the write-through
origin client (`origin_protocol.c`) once required the origin's `kXR_open` reply to
be ≥ 12 bytes (`sizeof(ServerOpenBody)`). When the conformance work made the
non-`retstat` open reply a bare **4-byte fhandle** (#7 above), the cache rejected
the valid reply and aborted the flush after opening the origin file. The fix was
to require only `XRD_FHANDLE_LEN` and read the fhandle alone. Guarded by
`test_cache_write_through` and the `test_integrity_matrix` write-through
topologies. (`../conformance-findings.md`, "write-through cache flush"
regression.)

---

## Tape & FRM staging

This is the area to be most careful about: official FRM is a large multi-daemon
ecosystem; this module has a **serious durable staging queue + WLCG Tape REST
gateway, but not full FRM parity.**

### Official: a multi-daemon residency ecosystem

The official FRM (`/tmp/brix-src/src/XrdFrm/`, `/tmp/brix-src/src/XrdFrc/`)
is **several separate executables**:

- **`frm_xfrd`** (`XrdFrmXfrMain.cc`) — the transfer daemon: processes stage
  (recall) and migrate requests, runs up to `copymax` concurrent copies, with
  independent `RequestBoss` threads per operation type (Get/Put/Mig/Stg) and
  three priority levels per queue (`XrdFrmReqBoss.cc`, `XrdFrmXfrQueue.cc`).
- **`frm_xfragent`** (`XrdFrmXfrMain.cc` in agent mode) — a light client-side
  agent that submits requests into the queue on a central system
  (`XrdFrmXfrAgent.cc` instantiates Get/Mig/Stg/Put agents).
- **`frm_purged`** (`XrdFrmPurgMain.cc`) — the purge / disk-GC daemon: watermark
  + hold-time based file removal, per-space policy, external policy program
  support, empty-directory expiration (`XrdFrmPurge.cc`).
- **`frm_admin`** (`XrdFrmAdminMain.cc`) — an interactive admin tool (audit,
  find, query, unlink, reloc) talking to the daemons over the admin FIFO.

Migration (disk→tape) is automatic and policy-driven (`XrdFrmMigrate.cc`:
idle-hold defer queue, periodic scan). The **copy to/from the MSS** is an external
command configured by **`copycmd in|out ... <prog> [args]`**
(`XrdFrmConfig.cc` `xcopy()`), with `copymax` concurrency. Requests are durable:
the queue file is a fixed-record linked list (`XrdFrcReqFile.cc`), each record a
`XrdFrcRequest` (LFN, user, ID, notify path, checksum type/value, addTOD,
priority — `XrdFrcRequest.hh`), with four queue types (stg/mig/get/put) and
mutex + file locking. Cluster IDs are tracked (`XrdFrcCID.cc`), and
stage/migrate/purge events stream over **UDP monitoring** (`XrdFrmMonitor.cc`).

### BriX-Cache: one durable queue + Tape REST, in-process

This module's tape staging is a **single-process, durable, crash-safe stage-in
queue**. Since phase-64 it is owned by the composable transfer engine — the
former standalone `src/frm/` subsystem was dissolved into `src/fs/xfer/`
(registry, engine, waiter — see `src/fs/xfer/README.md`) and the `sd_frm`
nearline driver (`src/fs/backend/frm/`), with the directives kept in
`src/core/config/tape_stage_conf.c`. It is enabled by `brix_frm on` and backs
`kXR_prepare`/`kXR_QPrep`, residency-aware opens, and the HTTP Tape REST API. Its
defining invariant is **file = truth, SHM = cache**:

- The queue is a **file-backed fixed-record log** (modeled on the official
  `XrdFrcReqFile`), with a per-record CRC32c and a self-offset so a torn
  write is *detectable*. Every mutation takes the in-process `ngx_shmtx` then an
  `fcntl(F_SETLKW)` whole-file lock (serialising across workers and across hosts
  sharing the filesystem), writes the body + `fdatasync`, then the header +
  `fsync` (the header write is the WAL commit point). nginx SHM is treated as a
  **hot index only**, reconciled from the file at master start before workers fork
  (`stage_request_registry.c` + the engine's startup reconcile).
- **Durable reqids** are `"<seq>.<pid>@<host>"` with the sequence in the file
  header so they stay monotonic across restarts (the registry preserves the
  original FRM reqid format) — replacing the old fire-and-forget stub where
  `reqid` was the literal `"0"` and state died with the connection.
- **Residency model.** The `sd_frm` driver (`src/fs/backend/frm/sd_frm.c`) probes
  a `user.frm.residency` xattr (absent ⇒ ONLINE). A nearline file makes
  `kXR_stat`/`statx` OR in `kXR_offline`; a recall is triggered on open through
  the driver's MSS adapter (the exec adapter runs the operator's copy command via
  the crash-safe, init-reparented agent harness in `xfer_spawn.c` /
  `xfer_mover_agent.c`, so nginx never reaps it), parking the client with
  `kXR_wait`.
- **Prepare / QPrep.** `kXR_prepare(kXR_stage)` enqueues one durable record per
  resolved path and returns the first record's reqid; `kXR_QPrep` is stat-first
  (resident ⇒ `A`) then queue-fallback (`q`/`s`/`f`), unknown ⇒ `M`;
  `kXR_cancel`/`kXR_evict` delete/release the record (`src/protocols/root/query/prepare.c`).
- **Async recall** (`stage_waiter.c`, `brix_frm_async_recall`): a nearline open is
  parked with `kXR_waitresp` and satisfied in place via `kXR_attn(asynresp)` when
  the recall lands — same-worker inline, cross-worker via an SHM waiter table
  delivered by the owning worker's scheduler tick (no IPC).
- **WLCG HTTP Tape REST** (`src/protocols/webdav/tape_rest.c`, `brix_webdav_tape_rest`):
  `/api/v1/{stage, release, unpin, archiveinfo, fileinfo, stage/{id}[/cancel]}`
  over the *same* durable queue, so FTS/gfal2 HTTP tape control and native
  `kXR_prepare` share one queue. This is an **nginx+** feature — not a core
  XRootD daemon surface in the reviewed source.
- **Parity follow-ups (F1–F6), not implemented:** manager registration of a
  now-resident path on stage completion (cmsd "Have"); a residency-oracle
  command; recalled-file checksum verification; a per-DN admission cap. The
  directives once reserved for them left the grammar in 2.0 (ADR-3b) and are
  refused as `unknown directive` — see the
  [2.0 readiness register](../../release-2.0-readiness.md) §(c.1). (The former
  migrate/purge watermark monitor scaffold was removed with the phase-64
  dissolution.)
- **Tape-buffer purge engine** (phase-115 W3.2, 2026-09-05): the online buffer
  of a `tape://` tier is reaped LRU by `src/fs/backend/frm/sd_frm_purge.c` under
  `brix_frm_purge_watermark <hi> <lo>` (filesystem occupancy) and/or
  `brix_frm_purge_max_bytes <size>` (bytes the buffer owns), every
  `brix_frm_purge_interval`. Only copies the MSS adapter confirms `on_tape`, not
  pinned by a live stage request, and older than 30 s are released — the stock
  `frm_purged` analogue, minus the separate daemon.
- **Tape dataset archiver** (phase-115 W3.1, 2026-09-06): `tape://<adapter>/<base>?arc=<depth>`
  (alias `frm://`, same query on `brix_stage_store`/`brix_cache_store` tape
  URLs) wraps the MSS adapter in `src/fs/backend/frm/sd_frm_arc.c`. The first
  `<depth>` path components name a dataset; its members stay online (unmigrated)
  until the `.brix-dataset-complete` marker is written, then reach tape as ONE
  stored ZIP (`<dataset>.brixarc.zip`, readable by `unzip`) with a sidecar
  index (`<base>/.arcidx/<dataset>.idx`) so stat/dirlist need no recall and a
  member read recalls only itself. A sealed dataset is immutable (new member
  → `kXR_NotAuthorized`, marker again → `kXR_ItExists`). The seal itself is
  the `arcAdmin` backup-queue half (2.0 F3): the marker's commit queues an
  `archive` record in the durable stage journal (`brix_frm_queue_path`) and
  the engine composes and ships the archive off the event loop with the
  flush retry / replay / dead-letter discipline; without `brix_frm on` the
  seal runs inline in the commit.
- **Write-path corrections found while building the archiver** (phase-115 W3.1
  burndown, 2026-09-06). The `sd_frm` residency verdict was inverted against
  the adapter's; the recall path built a stage request nothing consumed and
  never delivered the cross-worker async waiter; `kXR_wait` retries duplicated
  the durable record; the driver advertised a `CAP_RANDOM_WRITE` it lacks;
  `brix_stage_store` was inert without `brix_stage on`; the tier and backend
  parsers spelled the `tape://` query differently; the ABSENT publish
  precondition was checked against the writer's own buffer instead of the
  adapter's `on_tape`, so a key that reached tape mid-upload was overwritten;
  and `close`/`sync`/`open` flattened driver errors to `kXR_IOError` rather
  than mapping `errno`. Security: `brix_vfs_staged_abort` never reached the
  driver's `staged_abort`, so a refused or disconnected writer's truncated
  object stayed live on tape. All pinned by
  `tests/test_phase115_tape_recall_gate.py`.
- **Space groups** (phase-115 W3.3, 2026-09-06): `brix_oss_space <group>
  <prefix> [quota=<size>|quota=-1]` gives an export-relative prefix its own
  name, usage figure and quota — longest prefix wins at a component boundary,
  the export root remains the default group (`brix_oss_cgroup`), `quota=-1`
  is accounting-only and exempts the subtree from the export-wide quota, and
  usage is a confined VFS walk cached 5 s per worker with every admitted write
  charged against the cached figure. `kXR_Qspace` reports the owning group or
  the one named by `?oss.cgroup=`; a create-open naming a group that does not
  own its path is `kXR_ArgInvalid` before the file exists. This is the
  `oss.space` name/usage/quota half — not partitions, `alloc` policy, `.anew`
  or relocation.

**The honest maturity statement.** Per `src/fs/xfer/README.md` and the source-verified
comparison: this is **intentionally narrower than the complete upstream
XrdFrm/MSS daemon ecosystem.** Concretely:

- It is **one in-process subsystem**, not the `frm_xfrd` / `frm_xfragent` /
  `frm_purged` / `frm_admin` four-daemon split.
- **Migration (disk→tape) is not implemented in-process.** Migration is
  delegated to the MSS backend / operator policy (the old `migrate_purge.c`
  monitor-only scaffold was deleted in the phase-64 dissolution). There is
  **no automatic disk→tape migration scan**. The purge half of that scaffold
  came back as the phase-115 W3.2 purge engine above (2026-09-05); the
  source-verified comparison rates "Migrate policy engine" as **Missing** and
  flags it as "a serious reviewer item for tape sites requiring disk-to-tape
  migration inside this process."
- **The MSS driver abstraction is a command or a dlopen'd library, configured
  by directive or environment.** Recall runs the program named by
  `brix_frm_stagecmd` (2.0 F1; each invocation bounded by
  `brix_frm_copy_timeout`) or, when the directive is unset, by
  `BRIX_FRM_STAGECMD` (`BRIX_FRM_HPSS_STAGECMD` / `BRIX_FRM_CTA_STAGECMD` per
  dialect), or loads `BRIX_FRM_LIB` / `BRIX_FRM_{HPSS,CTA}_LIB` through the
  `sd_frm` adapter (`src/fs/backend/frm/sd_frm_adapter.c`). There is no
  linked MSS/ARC plugin contract and no `frm_admin`-style tooling.
  Auditable and simple, but **not drop-in for sites depending on upstream MSS
  plugins or FRM operational workflows.**
- Monitoring is **Prometheus**, not UDP stage/migr/purge streams
  (`src/observability/metrics/frm_metrics.c`, `brix_frm_*` counters).

Maturity of the *recall/stage* path (durable queue, prepare/QPrep, async recall,
Tape REST) is **verified** by tests (`test_frm_queue.py` incl. restart durability,
`test_frm_staging.py`, `test_tape_rest.py`, `test_frm_async.py`,
`test_frm_phase4*.py`). Maturity of *migration and in-process purge* is **not
verified as production-grade** — it is explicitly a scaffold and is flagged as
such here.

---

## Admin configuration & operations

### Configuring the export root / storage backend

| Concern | Official XRootD | BriX-Cache |
|---|---|---|
| Export base path | `oss.localroot <path>` (string prefix) | `brix_export <dir>` (kernel-confined export root) |
| Confinement | none from `localroot`; symlinks followed | `openat2(RESOLVE_BENEATH)` per syscall (`src/fs/path/beneath.c`) |
| LFN→PFN mapping | `oss.namelib <lib>` (N2N plugin) | none (lexical path only) |
| Named spaces / partitions | `oss.space <name> <path> ...` | `brix_oss_space <group> <prefix> [quota=<size>\|quota=-1]` — a named group over an export-relative prefix (longest wins), per-group usage/quota/`kXR_overQuota`; no separate partitions (phase-115 W3.3) |
| Alternate backend (Ceph/PSS/CSI) | `ofs.osslib <lib>` (plugin ABI) | **none — POSIX only** |

### Configuring the cache (XCache role)

| Concern | Official XRootD | BriX-Cache |
|---|---|---|
| Cache plugin / enable | `pfc.osslib`, cache plugin load | `brix_cache on` |
| Cache disk tree | OSS data space | `brix_cache_store posix:<dir>` + `brix_cache_export <prefix>` |
| Cache in memory | `pfc.ram <size>` (a RAM block pool in front of the disk tree) | `brix_cache_store ram:<size>` — the store IS memory, per worker, hard cap, self-evicting (no watermark directives apply) |
| Remote origin | `pss.origin root://host:port` | `brix_storage_backend root://host:port` (`roots://` for TLS; `brix_storage_credential` for the origin identity) |
| Fetch granularity | `pfc.blocksize`, block vs full-file | whole-file or `brix_cache_slice_size` (slice mode); a client's `pfc.blocksize=` open hint sets a new object's block size inside `brix_cache_urlcgi blocksize <min> <max>` |
| Prefetch | `pfc.prefetch <N>` | `brix_cache_prefetch <jobs>` + `brix_cache_prefetch_window <size>` (background successor-block fill); per-open `pfc.prefetch=` inside `brix_cache_urlcgi prefetch <min> <max>` |
| Purge / watermark | `pfc.diskusage <lwm> <hwm> ...` | `brix_cache_eviction_threshold` (ppm), two-pass LRU |
| Purge for a memory store | `pfc.ram` is bounded by its own pool | the `ram:` cap is the policy: reserved at fill-open, LRU-evicting, skipping open objects; the filesystem reaper declines (no cache root to lock in) |
| Admission filter | `pfc.decisionlib` (plugin) | `brix_cache_max_file_size`, `brix_cache_include_regex` |
| Write-through | `pfc.writethrough on` | `brix_write_through on`, `brix_wt_mode sync\|async`, `brix_wt_origin`, `brix_wt_{allow,deny}_prefix` |
| Fill lock timeout | (internal) | `brix_cache_lock_timeout` |

### Configuring tape / FRM

| Concern | Official XRootD | BriX-Cache |
|---|---|---|
| Enable | run `frm_xfrd`/`frm_purged` daemons | `brix_frm on` |
| Durable queue file | poscq/req file (internal paths) | `brix_frm_queue_path <dir>` — one `<reqid>.req` record per staged flush/recall, replayed at worker start and by the `brix_frm_fail_backoff` sweep, dead-lettered after `brix_frm_fail_retries` (2.0 F1); the live request registry is shared memory (`brix_frm_max_inflight` slots) |
| MSS copy command | `copycmd in\|out <prog>` | `brix_frm_stagecmd <program>` run as `<program> <verb> <key> <online>` with a `brix_frm_copy_timeout` deadline; `BRIX_FRM_STAGECMD` / `BRIX_FRM_{HPSS,CTA}_STAGECMD` (or `BRIX_FRM_*_LIB`) remain the environment fallback |
| Stage event notification | `oss.stagemsg` / `XRDOFSEVENTS` events file for an external stager | `brix_frm_stagemsg <file>` — one `%`-escaped `<utc> <source> <event> <reqid> <key> [k=v…]` line per engine / prepare-registry / MSS transition (`queued`, `started`, `done`, `failed`, `deadletter`, `recall-begin`, `recall-online`, …), append-only, created `0600`, best-effort (2.0 F2) |
| Concurrency | `copymax`, per-queue boss threads | `brix_frm_copymax` (engine in-flight bound, default 8) over `brix_frm_max_inflight` registry slots; no per-source fairness |
| Migration policy | `migr.idlehold`, `migr.waittime` (auto scan) | **not implemented** — the reserved directive left the grammar in 2.0 |
| Purge policy | `frm_purged`, `purge.policy {*\|sname} ...` | `brix_frm_purge_watermark <hi> <lo>` / `brix_frm_purge_max_bytes <size>` / `brix_frm_purge_interval <time>` — LRU release of on-tape, unpinned, cold online copies (phase-115 W3.2); `brix_frm_purge_policy {*\|<group>} <hi> <lo> [hold <time>] [polprog]` + `brix_frm_purge_polprog <program>` — per-`brix_oss_space` rules (sizes or `%` of the quota, hold) and the external policy program, fail-closed (2.0 F4) |
| Dataset aggregation | `XrdOssArc` (`ossarc.*`, `arcAdmin` backup queue) | `tape://<adapter>/<base>?arc=<depth>` — marker-sealed stored ZIP per dataset + sidecar index (phase-115 W3.1); the seal is an `archive` record in the durable stage journal (2.0 F3) |
| Async recall | (daemon-driven) | `brix_frm_async_recall on` (`kXR_waitresp` + `kXR_attn`) |
| Residency oracle | (OSS/MSS) | **not implemented** — the adapter's `exists` verb is the residency check; the reserved oracle directive left the grammar in 2.0 |
| HTTP tape control | n/a (core) | `brix_webdav_tape_rest on` (WLCG Tape REST) |
| POSC | `ofs.persist [auto\|manual\|off] [hold <sec>]` | `kXR_posc` wire flag (stage-temp + atomic rename; no hold window) |

### What an operator monitors

- **Official:** per-space disk usage / quotas (`XrdOssSpace`); PFC disk usage vs
  watermarks, hit/miss/bypass from `cinfo` access history, purge runs
  (`XrdPfcResourceMonitor`); FRM stage/migrate/purge events over **UDP
  monitoring**; `frm_admin` for queue introspection and audit.
- **BriX-Cache:** Prometheus counters at `/metrics` — cache hit/miss, eviction,
  write-through pending/success/error and bytes; `brix_frm_*` (requests, stage
  success/fail, evict, migrate, async waiters/waitresp/asynresp,
  reject-inflight, dedup hits, cmsd-have); plus the live transfer dashboard
  (`src/observability/dashboard/`, including a cache view). Residency is observable via
  `kXR_offline` on stat, WebDAV PROPFIND `<xrd:locality>`, and S3 HEAD
  `x-amz-storage-class: GLACIER`.

---

## Parity, gaps, and divergences

| Capability | Official XRootD | BriX-Cache | Status | Notes |
|---|---|---|---|---|
| POSIX local serving | `XrdOss`/`XrdOfs` POSIX backend | `src/fs/` VFS + confined `src/fs/path/` | **Parity** | Intentionally strongest as a POSIX data server/gateway. |
| Namespace confinement | `oss.localroot` string prefix (symlinks followed) | `openat2(RESOLVE_BENEATH)` kernel-enforced | **nginx+ (stronger)** | Kernel refuses escape (`EXDEV`); not a chroot vs prefix tradeoff. |
| **Pluggable OSS backend ABI** | `ofs.osslib` loads Ceph/PSS/CSI/custom | **none** | **Missing (honest gap)** | No plugin ABI; POSIX only. Sites needing `XrdCeph`/`XrdPss`/`XrdOssCsi` cannot use this for that role. |
| Named storage spaces / partitions | `oss.space`, per-space usage/quota | `brix_oss_space` prefix-owned groups with per-group usage, quota and `kXR_Qspace` report (phase-115 W3.3) | **Partial** | Groups are prefixes of the one export tree, not partitions; no `alloc` policy, `.anew` or relocation. |
| LFN→PFN mapping (N2N) | `oss.namelib` | none | **Missing** | Lexical path only. |
| POSC clean-close persist | `ofs.persist` + atomic visibility | stage-temp + `fsync`+`rename` | **Parity** | Both atomic on clean close. |
| POSC disconnect handling | **hold `<sec>`** then remove; reconnect window | **remove partial immediately** | **Divergence (documented xfail)** | Defensible "successful-close" reading; no resume window. |
| POSC durable queue + restart recovery | poscq file, replayed on restart | in-process per-handle only | **Missing** | No cross-restart POSC replay. |
| Read-through cache (XCache role) | `XrdPfc` block cache + `XrdPss` origin | `src/fs/cache/` whole-file + slice fill via native client | **Partial** | Practical cache; PFC has far broader policy/snapshot/resource machinery. |
| Cache prefetch / read-ahead | `pfc.prefetch`, per-open `pfc.urlcgi` | `brix_cache_prefetch` / `brix_cache_prefetch_window`, per-open `brix_cache_urlcgi` | **Present** | Background WILLNEED fill of successor blocks; the client's per-open block size / runway hints are clamped into operator bounds (2.0 F5). |
| Per-block presence metadata | `cinfo` block bitmap + access history | `.meta` (mtime/size/etag) per file/slice | **Partial** | Coarser staleness model; no per-block bitmap. |
| Cache purge policy engine | watermark + quota + cold-file + snapshots | LRU on `statvfs` occupancy + owned-bytes cap, per-space rules with hold, external policy program (2.0 F4) | **Full** | Per-space `purge.policy` + polprog landed 2026-09-08; no snapshot-driven policy. |
| Cache admit decision plugin (`.so`) | `pfc.decisionlib` | in-process fn only | **Partial** | Policy fn pluggable in-process; no loadable plugin. |
| Write-through cache | `pfc.writethrough` | `brix_write_through` sync/async + prefix policy | **Parity / nginx+** | Cross-protocol, identity-agnostic edge writes. |
| Proxy storage (remote origin as backend) | `XrdPss` OSS plugin (`pss.origin`, forwarding mode `pss.origin = *` + `pss.permit`) | `brix_storage_backend root://host:port` (fixed origin, read + write-through) and, since 2.0 F5, `brix_storage_backend forward://root[,roots] permit=<host\|.suffix>…` (the client names the origin inside the path; protocol list + mandatory host permit list) | **Present** | `src/fs/backend/xroot/sd_xroot*.c`; persona / reproxy / origin connection pool are not implemented. |
| Tape stage-in (recall) queue | `XrdFrm` durable req file + daemons | `src/fs/xfer/` durable file=truth+SHM queue | **Partial** | Real durable queue; not the daemon ecosystem. |
| `kXR_prepare`/`kXR_QPrep` staging | `do_Prepare` + full FRM | `src/protocols/root/query/prepare.c` + `src/fs/xfer/` durable reqids | **Partial** | Real reqids + restart durability; legacy `"0"` only with FRM off. |
| Async recall delivery | daemon-driven | `kXR_waitresp` + `kXR_attn(asynresp)` (`stage_waiter.c`) | **Parity-ish** | In-process, no IPC; opt-in. |
| Disk→tape migration (auto) | `frm_xfrd`/`XrdFrmMigrate` scan + `copycmd out` | **none in-process** (scaffold removed in phase-64) | **Missing** | No automatic migration scan; delegated to MSS/operator. |
| Disk purge GC daemon | `frm_purged` watermark/hold/policy | `sd_frm_purge.c` worker-0 LRU pass: `brix_frm_purge_watermark` / `_max_bytes` / `_interval` (phase-115 W3.2) | **Partial** | In-process since 2026-09-05; no hold/policy grammar, no separate daemon. |
| Dataset aggregation (OssArc) | `XrdOssArc`: dataset → one archive on tape + `arcAdmin` backup queue | `sd_frm_arc.c` decorator via `tape://…?arc=<depth>`: marker-sealed stored ZIP + sidecar index (phase-115 W3.1) | **Yes** | In-process since 2026-09-06; the seal is queued through the durable stage engine since 2026-09-08 (2.0 F3): retried on `brix_frm_fail_backoff`, replayed after a restart, dead-lettered at `brix_frm_fail_retries`. |
| MSS driver | OSS/MSS plugin + `copycmd` | `stagecmd`/`copycmd`/`residency_cmd` (commands only) | **Partial** | Simpler, auditable; not drop-in for MSS plugins. |
| Admin tooling | `frm_admin` interactive client | Prometheus + dashboard + HTTP Tape REST | **Divergence** | Different operational model. |
| WLCG HTTP Tape REST | not a core daemon surface | `src/protocols/webdav/tape_rest.c` on same queue | **nginx+** | FTS/gfal2-friendly HTTP tape ops. |
| Tape/stage monitoring | UDP stage/migr/purge streams | Prometheus `brix_frm_*` + dashboard | **Divergence** | Modern pull-based metrics instead of UDP. |

**One-line summary:** this module is a **strong, kernel-confined POSIX data
server and caching gateway with a real durable tape stage-in queue and a WLCG
Tape REST gateway** — but it has **no pluggable OSS backend ABI** (no Ceph/PSS/CSI),
**no named storage spaces**, **no cache prefetch or full PFC policy machinery**,
and **no automatic disk→tape migration** (delegated to the MSS / operator;
in-process purge GC landed 2026-09-05 with a narrower grammar than
`frm_purged`). Do not claim full
`XrdOss`-plugin, `XrdPfc`, `XrdPss`, or `XrdFrm` parity.

---

## Source references

**Official XRootD (`/tmp/brix-src/src/`):**

- Storage abstraction: `XrdOss/XrdOss.hh` (abstract base + plugin entry typedefs),
  `XrdOss/XrdOssApi.cc/.hh` (default POSIX `XrdOssSys`),
  `XrdOss/XrdOssConfig.cc` (`oss.localroot`, `oss.namelib`, `oss.space`,
  `oss.cache`, `oss.stagecmd`, `oss.rsscmd`),
  `XrdOss/XrdOssCreate.cc` (`XRDOSS_mkpath`), `XrdOss/XrdOssSpace.cc`,
  `XrdOss/XrdOssCache.cc`, `XrdOss/XrdOssDefaultSS.hh`.
- Filesystem frontend + plugin loader + POSC: `XrdOfs/XrdOfs.hh`,
  `XrdOfs/XrdOfsConfigPI.cc` (`ofs.osslib`), `XrdOfs/XrdOfsConfig.cc`
  (`ofs.persist`/`xpers()`), `XrdOfs/XrdOfsPoscq.cc/.hh` (persistence queue +
  recovery), `XrdOfs/XrdOfsHandle.cc` (handle table/locking).
- Cache + proxy storage: `XrdPfc/XrdPfc.cc/.hh`, `XrdPfc/XrdPfcIOFile.cc`,
  `XrdPfc/XrdPfcIOFileBlock.cc`, `XrdPfc/XrdPfcConfiguration.cc` (`pfc.blocksize`,
  `pfc.prefetch`, `pfc.diskusage`, `pfc.decisionlib`, `pfc.writethrough`, ...),
  `XrdPfc/XrdPfcInfo.cc` (cinfo), `XrdPfc/XrdPfcPurge.cc`,
  `XrdPfc/XrdPfcResourceMonitor.cc`, `XrdPfc/XrdPfcDirState.cc`,
  `XrdPfc/XrdPfcDecision.hh`; `XrdPss/XrdPss.cc`, `XrdPss/XrdPssConfig.cc`
  (`pss.origin`), `XrdPss/XrdPssCks.cc`.
- FRM / tape: `XrdFrm/XrdFrmXfrMain.cc` (frm_xfrd/frm_xfragent),
  `XrdFrm/XrdFrmPurgMain.cc` (frm_purged), `XrdFrm/XrdFrmAdminMain.cc`
  (frm_admin), `XrdFrm/XrdFrmReqBoss.cc`, `XrdFrm/XrdFrmXfrQueue.cc`,
  `XrdFrm/XrdFrmMigrate.cc`, `XrdFrm/XrdFrmPurge.cc`, `XrdFrm/XrdFrmConfig.cc`
  (`copycmd`, `copymax`, `migr.*`, `purge.policy`); `XrdFrc/XrdFrcReqFile.cc`,
  `XrdFrc/XrdFrcRequest.hh` (durable record), `XrdFrc/XrdFrcReqAgent.cc`,
  `XrdFrc/XrdFrcCID.cc`.

**BriX-Cache (`src/`):**

- VFS / storage: `src/fs/README.md`, `src/fs/vfs/vfs.h`, `src/fs/vfs/vfs_open.c`,
  `src/fs/vfs/vfs_read.c`, `src/fs/vfs/vfs_write.c`.
- Confinement / namespace: `src/fs/path/README.md`, `src/fs/path/beneath.c/.h`,
  `src/fs/path/canonical.c`, `src/fs/path/mkdir.c`, `src/core/compat/namespace_ops.c`,
  `src/core/compat/staged_file.c`, `src/core/compat/shm_slots.c`.
- POSC / open semantics: `src/protocols/root/read/open.h`, `src/protocols/root/read/open_request.c`,
  `src/protocols/root/read/close.c`, `src/protocols/root/connection/fd_table.c` (`brix_free_fhandle`).
- Cache: `src/fs/cache/README.md`, `src/fs/cache/open.c`, `src/fs/cache/fetch.c`,
  `src/fs/cache/slice.c`/`slice_fill.c`, `src/fs/cache/origin_protocol.c`,
  `src/fs/cache/origin_connection.c`, `src/fs/cache/io.c`,
  `src/fs/cache/writethrough_decision.c`, `src/fs/cache/writethrough_flush.c`,
  `src/fs/cache/evict_policy.c`, `src/fs/cache/directives.c`.
- FRM / tape (re-homed by the phase-64 dissolution of `src/frm/`):
  `src/fs/xfer/README.md`, `src/fs/xfer/stage_engine.c`,
  `src/fs/xfer/stage_request_registry.c`, `src/fs/xfer/stage_waiter.c`,
  `src/fs/backend/frm/sd_frm.c`, `src/core/config/tape_stage_conf.c`,
  `src/observability/metrics/frm_metrics.c`, `src/protocols/root/query/prepare.c`,
  `src/protocols/webdav/tape_rest.c`.
- Cross-checked against: `docs/10-reference/source-verified-xrootd-comparison.md`
  (Storage/Cache/Tape section) and `docs/10-reference/comparison/conformance-findings.md`
  (POSC-disconnect xfail; 4-byte-fhandle write-through regression).
