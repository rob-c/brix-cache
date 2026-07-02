# Storage backends, caching, and tape/FRM staging: XRootD vs nginx-xrootd

> Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

This document compares how **official XRootD** and the **nginx-xrootd module** handle
the three layers below the wire protocol:

1. **Storage backend & namespace** — how a logical client path is turned into a
   real byte store (the OSS/filesystem abstraction).
2. **Caching (xcache)** — acting as a read-through / write-through cache node in
   front of a remote origin.
3. **Tape / FRM staging** — disk↔tape residency, recall (stage-in), migration,
   and purge.

Every claim below is grounded in source. Official paths are under
`/tmp/xrootd-src/src/`; this module's paths are under `src/`. Where a feature is
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
  `src/fs/` (VFS) + `src/path/` (confinement) + `src/core/compat/namespace_ops.c`.
- **POSC** (persist-on-successful-close): `XrdOfs` POSC queue vs `src/read/`
  open/close staging, including the documented disconnect-semantics difference.
- **Caching**: `XrdPfc` (XCache) + `XrdPss` (proxy storage) vs `src/cache/`.
- **Tape / FRM**: `XrdFrm`/`XrdFrc` multi-daemon ecosystem vs `src/frm/` +
  `src/query/prepare.c` + `src/webdav/tape_rest.c`.
- The **operator view**: directives and what to monitor on each side.

Out of scope (covered elsewhere in the comparison set): the wire protocol, auth,
TPC, HTTP/S3 method coverage, clustering/CMS, and metrics internals. They are
referenced only where storage behaviour depends on them.

---

## In official XRootD

XRootD separates storage into two stacked, **plugin-based** C++ layers, plus a
separate cache plugin family and a separate tape/FRM daemon family:

- **`XrdOss` — the Open Storage System.** An *abstract base class*
  (`/tmp/xrootd-src/src/XrdOss/XrdOss.hh`, with pure-virtual `Create`, `Mkdir`,
  `Remdir`, `Rename`, `Stat`, `Truncate`, `Unlink`, and `XrdOssDF`-returning
  `newFile`/`newDir`). It is a true **plugin ABI**: alternate backends are loaded
  via `ofs.osslib <path>` (`/tmp/xrootd-src/src/XrdOfs/XrdOfsConfigPI.cc`, which
  calls the `XrdOssGetStorageSystem2` entry point declared in `XrdOss.hh`). The
  default backend is local POSIX (`XrdOssSys` in
  `/tmp/xrootd-src/src/XrdOss/XrdOssApi.hh`, default obtained via
  `XrdOssDefaultSS()`). This is the seam that lets sites run **Ceph
  (`XrdCeph`)**, **proxy storage (`XrdPss`)**, checksum-tagstore
  (`XrdOssCsi`), and others under the *same* server.
- **`XrdOfs` — the Open File System frontend.** Implements the `XrdSfsInterface`
  (`/tmp/xrootd-src/src/XrdOfs/XrdOfs.hh`) on top of whatever OSS is loaded: open
  handle table (`XrdOfsHandle.cc`, a hash table of open handles with locking),
  POSC, TPC, checkpointing, event notification (`XrdOfsEvs.cc`), and the `ofs.*`
  directives (`XrdOfsConfig.cc`).
- **`XrdPfc` — the Proxy File Cache (XCache).** A `XrdOucCache` plugin
  (`/tmp/xrootd-src/src/XrdPfc/XrdPfc.hh`, entry point `XrdOucGetCache()`) that
  caches blocks of a remote file on local disk, with prefetch, watermark purge,
  per-file `cinfo` sidecars, and pluggable admit/deny decisions.
- **`XrdPss` — the Proxy Storage Service.** An OSS-API plugin
  (`/tmp/xrootd-src/src/XrdPss/XrdPss.cc`, `XrdPssConfig.cc`) that proxies storage
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

## In nginx-xrootd

This module collapses the same responsibilities into a single nginx worker
process with a **unified VFS** and **no plugin ABI**:

- **`src/fs/` — the VFS.** One protocol-agnostic API (`xrootd_vfs_*`) that every
  front end (`root://` stream, WebDAV/HTTP, the S3 subset, CMS data I/O) funnels
  through (`src/fs/README.md`, `src/fs/vfs.h`). It performs the syscall, records a
  metric + access-log line, and returns a handle or buffer chain. Confinement,
  page-CRC, cache integration, and write-through are implemented **once** here.
- **`src/path/` — confinement and the namespace boundary.** The export root is a
  **single local directory** (`xrootd_root`). Every client path is confined with
  Linux `openat2(2)` + `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`
  (`src/path/beneath.c`), anchored to a per-worker `O_PATH` "rootfd". This is a
  *kernel-enforced* boundary, not a string prefix (see the next section). Auth/ACL
  gating (`auth_gate.c`, `authdb.c`, `acl.c`) lives here too.
- **`src/core/compat/namespace_ops.c`** — the `xrootd_ns_*` mutation helpers
  (`mkdir`/`rename`/`unlink`/`link`) that the VFS and HTTP/S3 callers share, each
  confining through the beneath API. (Also `compat/staged_file.c`,
  `compat/shm_slots.c` for SHM-table allocation.)
- **`src/cache/` — XCache-style read-through + write-through.** A caching gateway
  in front of a remote XRootD origin: thread-pool workers speak the XRootD wire
  protocol as a *native client* (`origin_protocol.c`, `origin_connection.c`,
  `io.c`) to fill the local `cache_root` tree on a miss, and mirror local writes
  back to an origin at `kXR_sync`/`kXR_close` (`writethrough_flush.c`).
- **`src/frm/` — a durable, crash-safe tape stage queue.** A file-backed
  fixed-record log (`frm_format.h`, modeled on `XrdFrcReqFile`) with an SHM hot
  index, backing `kXR_prepare`/`kXR_QPrep`, residency-aware opens, async recall
  (`waiter.c`), and the WLCG HTTP Tape REST API (`src/webdav/tape_rest.c`).
  POSC commit logic lives in `src/read/close.c` / `src/connection/fd_table.c`.

The design point is **convergence and operability**: one process, one confinement
model, cross-protocol metrics — at the explicit cost of **no pluggable OSS
backend** and **not the full FRM daemon ecosystem**.

---

## Storage backend & namespace

### Official: pluggable OSS, string-prefix namespace

XRootD's logical-to-physical mapping is a **string transform**, then a plugin
call:

- **`oss.localroot <path>`** prefixes the logical filename with a base path
  (`/tmp/xrootd-src/src/XrdOss/XrdOssConfig.cc`, stored as `LocalRoot` in
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

### nginx-xrootd: single confined local export, kernel-enforced

This module exposes exactly **one local POSIX export** per server block:

- **`xrootd_root <dir>`** is the export root. It is canonicalised once at startup
  (`realpath(3)` in `src/path/canonical.c`) and a per-worker `O_PATH` rootfd is
  opened on it.
- Confinement is **kernel-enforced**, not string-based: every client-path syscall
  goes through `xrootd_open_beneath` / `xrootd_stat_beneath` /
  `xrootd_*_beneath` (`src/path/beneath.c`), which use
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` anchored to the rootfd. An
  escape attempt returns `EXDEV`, mapped to `kXR_NotAuthorized`/403. This is
  *stronger* than `oss.localroot`: a symlink that points outside the root is
  refused by the kernel, not followed. (`src/path/README.md` invariants;
  `src/fs/README.md` invariant 1.)
- Mutating ops (`mkdir`/`rename`/`unlink`/`link`) resolve the **parent** under
  `RESOLVE_BENEATH` and act on the final component only, because the bare `*at()`
  syscalls do not themselves honour `RESOLVE_BENEATH`
  (SECURITY note, `src/path/beneath.c`).
- There is **no named-space / partition model** and **no N2N plugin**. The cache
  uses a second directory tree (`xrootd_cache_root`) but that is a distinct
  feature, not a space-token system.
- Recursive parent creation exists (`src/path/mkdir.c`,
  `xrootd_mkdir_recursive_beneath`) and is used where the operation calls for it.

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
(`/tmp/xrootd-src/src/XrdOfs/XrdOfsConfig.cc`, `xpers()`):

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

### nginx-xrootd: stage-temp + atomic rename, immediate disconnect cleanup

This module implements POSC inline in the open/close path, gated on the wire flag
`kXR_posc` on a write open (advertised as `kXR_supposc`):

- On a `kXR_posc` write open, `xrootd_open_resolved_file()`
  (`src/read/open.h`/`open_request.c`) **stages a temp file** and records its
  intended final name in the handle's `posc_final_path`.
- On a **clean `kXR_close`** (`src/read/close.c`): `fsync(fd)` then
  `rename(temp → final)` atomically publishes the file, and `posc_final_path` is
  cleared so handle-free does not unlink it. A failed rename is reported as an
  error and the partial is removed.
- On **session end / error without a clean close** (`src/connection/fd_table.c`,
  `xrootd_free_fhandle`): if `posc_final_path` is still set, the staging temp is
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

### nginx-xrootd: read-through + write-through, native-client origin fill

This module's `src/cache/` is a practical caching gateway with **two halves**
(`src/cache/README.md`):

- **Read-through (XCache).** On a read open of a not-yet-local file, a thread-pool
  worker connects to `xrootd_cache_origin`, speaks the XRootD wire protocol as an
  **anonymous native client** (handshake → `kXR_protocol` → `kXR_login` →
  `kXR_open` with `kXR_retstat` to learn the size → `kXR_read` loop honouring
  `kXR_oksofar`), writes into a `.part` file, `fsync`s, and atomically
  `rename`s into the `cache_root` tree; a `.meta` sidecar records origin
  mtime/size/etag for staleness detection (`fetch.c`, `meta.c`,
  `origin_protocol.c`). Subsequent opens hit local disk
  (`xrootd_cache_open()` in `cache/open.c`, called from `src/fs/vfs_open.c`).
  - **Two fill granularities:** **whole-file** (`fetch.c`, the historical path)
    and **fixed-size slices** (`slice.c`/`slice_fill.c`, Phase 26 — `read://`
    random reads fetch only the touched ~128 KiB windows; missing slices get a
    `kXR_wait` retry). This is the analogue of PFC's block mode, but it is
    request-driven fetch, **not prefetch** — there is no read-ahead prefetcher.
  - **GSI-origin fill** is supported (TLS handshake with CA verify + SNI in
    `origin_connection.c`; `xrootd_cache_origin_tls`/`_cadir`). Anonymous login is
    used; an origin that demands `kXR_authmore` is rejected.
- **Write-through.** With write-through enabled, locally-written files are mirrored
  back to `xrootd_wt_origin` (or the cache origin) at `kXR_sync`/`kXR_close`,
  **sync or async** (`xrootd_wt_mode`). The decision (allow/deny prefixes, size
  limit) is made **once at open** and cached on the handle
  (`writethrough_decision.c`, mirroring the spirit of `XrdPfcDecision`). The flush
  reuses the same native-client origin code in write mode
  (`writethrough_flush.c`).
- **Eviction.** Two-pass LRU (large-file pass, then oldest-first) triggered by a
  `statvfs` occupancy gate (`xrootd_cache_eviction_threshold`, in ppm), with
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

The official FRM (`/tmp/xrootd-src/src/XrdFrm/`, `/tmp/xrootd-src/src/XrdFrc/`)
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

### nginx-xrootd: one durable queue + Tape REST, in-process

This module's `src/frm/` is a **single-process, durable, crash-safe stage-in
queue** (`src/frm/README.md`). It is enabled by `xrootd_frm on` and backs
`kXR_prepare`/`kXR_QPrep`, residency-aware opens, and the HTTP Tape REST API. Its
defining invariant is **file = truth, SHM = cache**:

- The queue is a **file-backed fixed-record log** (`frm_format.h`), modeled on the
  official `XrdFrcReqFile`, with a per-record CRC32c and a self-offset so a torn
  write is *detectable*. Every mutation takes the in-process `ngx_shmtx` then an
  `fcntl(F_SETLKW)` whole-file lock (serialising across workers and across hosts
  sharing the filesystem), writes the body + `fdatasync`, then the header +
  `fsync` (the header write is the WAL commit point). nginx SHM is treated as a
  **hot index only**, reconciled from the file at master start before workers fork
  (`reqfile.c`, `index.c`, `reconcile.c`).
- **Durable reqids** are `"<seq>.<pid>@<host>"` with the sequence in the file
  header so they stay monotonic across restarts (`reqid.c`) — replacing the old
  fire-and-forget stub where `reqid` was the literal `"0"` and state died with the
  connection.
- **Residency model.** `residency.c` probes a `user.frm.residency` xattr (absent ⇒
  ONLINE). A nearline file makes `kXR_stat`/`statx` OR in `kXR_offline`; a recall
  is triggered on open via the **stage agent** (`stage.c`, a double-forked,
  init-reparented process so nginx never reaps the copy command), parking the
  client with `kXR_wait`.
- **Prepare / QPrep.** `kXR_prepare(kXR_stage)` enqueues one durable record per
  resolved path and returns the first record's reqid; `kXR_QPrep` is stat-first
  (resident ⇒ `A`) then queue-fallback (`q`/`s`/`f`), unknown ⇒ `M`;
  `kXR_cancel`/`kXR_evict` delete/release the record (`src/query/prepare.c`).
- **Async recall** (`waiter.c`, `xrootd_frm_async_recall`): a nearline open is
  parked with `kXR_waitresp` and satisfied in place via `kXR_attn(asynresp)` when
  the recall lands — same-worker inline, cross-worker via an SHM waiter table
  delivered by the owning worker's scheduler tick (no IPC).
- **WLCG HTTP Tape REST** (`src/webdav/tape_rest.c`, `xrootd_webdav_tape_rest`):
  `/api/v1/{stage, release, unpin, archiveinfo, fileinfo, stage/{id}[/cancel]}`
  over the *same* durable queue, so FTS/gfal2 HTTP tape control and native
  `kXR_prepare` share one queue. This is an **nginx+** feature — not a core
  XRootD daemon surface in the reviewed source.
- **Parity follow-ups (F1–F6):** manager registration of a now-resident path on
  stage completion (cmsd "Have"); a residency-oracle command
  (`xrootd_frm_residency_cmd`) consulted before copying; recalled-file checksum
  verification; per-DN admission cap (`xrootd_frm_max_per_source`); and a
  migrate/purge **watermark monitor scaffold** (`migrate_purge.c`).

**The honest maturity statement.** Per `src/frm/README.md` and the source-verified
comparison: this is **intentionally narrower than the complete upstream
XrdFrm/MSS daemon ecosystem.** Concretely:

- It is **one in-process subsystem**, not the `frm_xfrd` / `frm_xfragent` /
  `frm_purged` / `frm_admin` four-daemon split.
- **Migration (disk→tape) is a scaffold.** `migrate_purge.c` is a worker-0
  watermark *monitor that only logs*; the actual migrate/purge engine is delegated
  to the MSS backend / operator policy. There is **no automatic disk→tape
  migration scan** and **no built-in purge GC** equivalent to `frm_purged`. The
  source-verified comparison rates "Migrate/purge policy engine" as
  **Missing/Partial** and flags it as "a serious reviewer item for tape sites
  requiring disk-to-tape migration or watermark GC inside this process."
- **The MSS driver abstraction is a command, not a library.** Recall runs the
  operator's `xrootd_frm_stagecmd` / `copycmd` (and `xrootd_frm_residency_cmd`
  oracle); there is no linked MSS/ARC plugin and no `frm_admin`-style tooling.
  Auditable and simple, but **not drop-in for sites depending on upstream MSS
  plugins or FRM operational workflows.**
- Monitoring is **Prometheus**, not UDP stage/migr/purge streams (`metrics.c`,
  `xrootd_frm_*` counters).

Maturity of the *recall/stage* path (durable queue, prepare/QPrep, async recall,
Tape REST) is **verified** by tests (`test_frm_queue.py` incl. restart durability,
`test_frm_staging.py`, `test_tape_rest.py`, `test_frm_async.py`,
`test_frm_phase4*.py`). Maturity of *migration and in-process purge* is **not
verified as production-grade** — it is explicitly a scaffold and is flagged as
such here.

---

## Admin configuration & operations

### Configuring the export root / storage backend

| Concern | Official XRootD | nginx-xrootd |
|---|---|---|
| Export base path | `oss.localroot <path>` (string prefix) | `xrootd_root <dir>` (kernel-confined export root) |
| Confinement | none from `localroot`; symlinks followed | `openat2(RESOLVE_BENEATH)` per syscall (`src/path/beneath.c`) |
| LFN→PFN mapping | `oss.namelib <lib>` (N2N plugin) | none (lexical path only) |
| Named spaces / partitions | `oss.space <name> <path> ...` | none |
| Alternate backend (Ceph/PSS/CSI) | `ofs.osslib <lib>` (plugin ABI) | **none — POSIX only** |

### Configuring the cache (XCache role)

| Concern | Official XRootD | nginx-xrootd |
|---|---|---|
| Cache plugin / enable | `pfc.osslib`, cache plugin load | `xrootd_cache on` |
| Cache disk tree | OSS data space | `xrootd_cache_root <dir>` |
| Remote origin | `pss.origin root://host:port` | `xrootd_cache_origin root://host:port` (+ `_tls`, `_cadir`, `_proxy`, `_client`) |
| Fetch granularity | `pfc.blocksize`, block vs full-file | whole-file or `xrootd_cache_slice` (slice mode) |
| Prefetch | `pfc.prefetch <N>` | none (request-driven fill only) |
| Purge / watermark | `pfc.diskusage <lwm> <hwm> ...` | `xrootd_cache_eviction_threshold` (ppm), two-pass LRU |
| Admission filter | `pfc.decisionlib` (plugin) | `xrootd_cache_max_file_size`, `xrootd_cache_include_regex` |
| Write-through | `pfc.writethrough on` | `xrootd_write_through on`, `xrootd_wt_mode sync\|async`, `xrootd_wt_origin`, `xrootd_wt_{allow,deny}_prefix` |
| Fill lock timeout | (internal) | `xrootd_cache_lock_timeout` |

### Configuring tape / FRM

| Concern | Official XRootD | nginx-xrootd |
|---|---|---|
| Enable | run `frm_xfrd`/`frm_purged` daemons | `xrootd_frm on` |
| Durable queue file | poscq/req file (internal paths) | `xrootd_frm_queue_path <abs>` (durable, required) |
| MSS copy command | `copycmd in\|out <prog>` | `xrootd_frm_stagecmd` / `xrootd_frm_copycmd` (falls back to `xrootd_prepare_command`) |
| Concurrency | `copymax`, per-queue boss threads | `xrootd_frm_max_inflight`, `xrootd_frm_copymax`, `xrootd_frm_max_per_source` |
| Migration policy | `migr.idlehold`, `migr.waittime` (auto scan) | `xrootd_frm_migrate_copycmd` + `migrate_purge.c` scaffold (monitor-only) |
| Purge policy | `frm_purged`, `purge.policy {*\|sname} ...` | `xrootd_frm_purge_watermark`, `xrootd_frm_purge_interval` (scaffold) |
| Async recall | (daemon-driven) | `xrootd_frm_async_recall on` (`kXR_waitresp` + `kXR_attn`) |
| Residency oracle | (OSS/MSS) | `xrootd_frm_residency_cmd` |
| HTTP tape control | n/a (core) | `xrootd_webdav_tape_rest on` (WLCG Tape REST) |
| POSC | `ofs.persist [auto\|manual\|off] [hold <sec>]` | `kXR_posc` wire flag (stage-temp + atomic rename; no hold window) |

### What an operator monitors

- **Official:** per-space disk usage / quotas (`XrdOssSpace`); PFC disk usage vs
  watermarks, hit/miss/bypass from `cinfo` access history, purge runs
  (`XrdPfcResourceMonitor`); FRM stage/migrate/purge events over **UDP
  monitoring**; `frm_admin` for queue introspection and audit.
- **nginx-xrootd:** Prometheus counters at `/metrics` — cache hit/miss, eviction,
  write-through pending/success/error and bytes; `xrootd_frm_*` (requests, stage
  success/fail, evict, migrate, async waiters/waitresp/asynresp,
  reject-inflight, dedup hits, cmsd-have); plus the live transfer dashboard
  (`src/dashboard/`, including a cache view). Residency is observable via
  `kXR_offline` on stat, WebDAV PROPFIND `<xrd:locality>`, and S3 HEAD
  `x-amz-storage-class: GLACIER` (`src/frm/README.md`, Phase 1).

---

## Parity, gaps, and divergences

| Capability | Official XRootD | nginx-xrootd | Status | Notes |
|---|---|---|---|---|
| POSIX local serving | `XrdOss`/`XrdOfs` POSIX backend | `src/fs/` VFS + confined `src/path/` | **Parity** | Intentionally strongest as a POSIX data server/gateway. |
| Namespace confinement | `oss.localroot` string prefix (symlinks followed) | `openat2(RESOLVE_BENEATH)` kernel-enforced | **nginx+ (stronger)** | Kernel refuses escape (`EXDEV`); not a chroot vs prefix tradeoff. |
| **Pluggable OSS backend ABI** | `ofs.osslib` loads Ceph/PSS/CSI/custom | **none** | **Missing (honest gap)** | No plugin ABI; POSIX only. Sites needing `XrdCeph`/`XrdPss`/`XrdOssCsi` cannot use this for that role. |
| Named storage spaces / partitions | `oss.space`, per-space usage/quota | none | **Missing** | One export tree; cache tree is separate but not a space-token system. |
| LFN→PFN mapping (N2N) | `oss.namelib` | none | **Missing** | Lexical path only. |
| POSC clean-close persist | `ofs.persist` + atomic visibility | stage-temp + `fsync`+`rename` | **Parity** | Both atomic on clean close. |
| POSC disconnect handling | **hold `<sec>`** then remove; reconnect window | **remove partial immediately** | **Divergence (documented xfail)** | Defensible "successful-close" reading; no resume window. |
| POSC durable queue + restart recovery | poscq file, replayed on restart | in-process per-handle only | **Missing** | No cross-restart POSC replay. |
| Read-through cache (XCache role) | `XrdPfc` block cache + `XrdPss` origin | `src/cache/` whole-file + slice fill via native client | **Partial** | Practical cache; PFC has far broader policy/snapshot/resource machinery. |
| Cache prefetch / read-ahead | `pfc.prefetch` | none | **Missing** | Fill is request-driven only. |
| Per-block presence metadata | `cinfo` block bitmap + access history | `.meta` (mtime/size/etag) per file/slice | **Partial** | Coarser staleness model; no per-block bitmap. |
| Cache purge policy engine | watermark + quota + cold-file + snapshots | two-pass LRU on `statvfs` occupancy | **Partial** | Works; far less policy surface than PFC. |
| Cache admit decision plugin (`.so`) | `pfc.decisionlib` | in-process fn only | **Partial** | Policy fn pluggable in-process; no loadable plugin. |
| Write-through cache | `pfc.writethrough` | `xrootd_write_through` sync/async + prefix policy | **Parity / nginx+** | Cross-protocol, identity-agnostic edge writes. |
| Proxy storage (remote origin as backend) | `XrdPss` OSS plugin | (no PSS-style storage backend; proxy/cache patterns instead) | **Missing** | See proxy/cache comparison pages for the bridge approach. |
| Tape stage-in (recall) queue | `XrdFrm` durable req file + daemons | `src/frm/` durable file=truth+SHM queue | **Partial** | Real durable queue; not the daemon ecosystem. |
| `kXR_prepare`/`kXR_QPrep` staging | `do_Prepare` + full FRM | `src/query/prepare.c` + `src/frm/` durable reqids | **Partial** | Real reqids + restart durability; legacy `"0"` only with FRM off. |
| Async recall delivery | daemon-driven | `kXR_waitresp` + `kXR_attn(asynresp)` (`waiter.c`) | **Parity-ish** | In-process, no IPC; opt-in. |
| Disk→tape migration (auto) | `frm_xfrd`/`XrdFrmMigrate` scan + `copycmd out` | `migrate_purge.c` **monitor-only scaffold** | **Missing / Partial** | No automatic migration scan; delegated to MSS/operator. |
| Disk purge GC daemon | `frm_purged` watermark/hold/policy | watermark monitor scaffold | **Missing / Partial** | No in-process purge engine. |
| MSS driver | OSS/MSS plugin + `copycmd` | `stagecmd`/`copycmd`/`residency_cmd` (commands only) | **Partial** | Simpler, auditable; not drop-in for MSS plugins. |
| Admin tooling | `frm_admin` interactive client | Prometheus + dashboard + HTTP Tape REST | **Divergence** | Different operational model. |
| WLCG HTTP Tape REST | not a core daemon surface | `src/webdav/tape_rest.c` on same queue | **nginx+** | FTS/gfal2-friendly HTTP tape ops. |
| Tape/stage monitoring | UDP stage/migr/purge streams | Prometheus `xrootd_frm_*` + dashboard | **Divergence** | Modern pull-based metrics instead of UDP. |

**One-line summary:** this module is a **strong, kernel-confined POSIX data
server and caching gateway with a real durable tape stage-in queue and a WLCG
Tape REST gateway** — but it has **no pluggable OSS backend ABI** (no Ceph/PSS/CSI),
**no named storage spaces**, **no cache prefetch or full PFC policy machinery**,
and **no automatic disk→tape migration or in-process purge GC** (those are
monitor-only scaffolds delegated to operator commands). Do not claim full
`XrdOss`-plugin, `XrdPfc`, `XrdPss`, or `XrdFrm` parity.

---

## Source references

**Official XRootD (`/tmp/xrootd-src/src/`):**

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

**nginx-xrootd (`src/`):**

- VFS / storage: `src/fs/README.md`, `src/fs/vfs.h`, `src/fs/vfs_open.c`,
  `src/fs/vfs_read.c`, `src/fs/vfs_write.c`.
- Confinement / namespace: `src/path/README.md`, `src/path/beneath.c/.h`,
  `src/path/canonical.c`, `src/path/mkdir.c`, `src/core/compat/namespace_ops.c`,
  `src/core/compat/staged_file.c`, `src/core/compat/shm_slots.c`.
- POSC / open semantics: `src/read/open.h`, `src/read/open_request.c`,
  `src/read/close.c`, `src/connection/fd_table.c` (`xrootd_free_fhandle`).
- Cache: `src/cache/README.md`, `src/cache/open.c`, `src/cache/fetch.c`,
  `src/cache/slice.c`/`slice_fill.c`, `src/cache/origin_protocol.c`,
  `src/cache/origin_connection.c`, `src/cache/io.c`,
  `src/cache/writethrough_decision.c`, `src/cache/writethrough_flush.c`,
  `src/cache/evict_policy.c`, `src/cache/directives.c`.
- FRM / tape: `src/frm/README.md`, `src/frm/frm_format.h`, `src/frm/reqfile.c`,
  `src/frm/reqid.c`, `src/frm/index.c`, `src/frm/reconcile.c`,
  `src/frm/residency.c`, `src/frm/stage.c`, `src/frm/waiter.c`,
  `src/frm/migrate_purge.c`, `src/frm/directives.c`, `src/query/prepare.c`,
  `src/webdav/tape_rest.c`.
- Cross-checked against: `docs/10-reference/source-verified-xrootd-comparison.md`
  (Storage/Cache/Tape section) and `docs/10-reference/comparison/conformance-findings.md`
  (POSC-disconnect xfail; 4-byte-fhandle write-through regression).
