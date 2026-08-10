# The BriX-Cache VFS — Interface Specification

**Status:** Normative reference (reflects the tree as of 2026-08-10, phase-88/89 era)
**Audience:** anyone adding a protocol front end, a storage backend, a VFS
operation, or an authentication schema — and anyone reviewing such a change.
**Companion docs:**
[`src/fs/README.md`](../../src/fs/README.md) (implementation tour) ·
[`src/fs/backend/README.md`](../../src/fs/backend/README.md) (driver layer) ·
[`vfs-shared-architecture.md`](../09-developer-guide/vfs-shared-architecture.md) (client/server sharing) ·
[`storage-backend-drivers-deep-dive.md`](../09-developer-guide/storage-backend-drivers-deep-dive.md) (drivers in depth) ·
[`vfs-evolution-and-rationale.md`](vfs-evolution-and-rationale.md) (why it looks this way)

This document describes the VFS in its **idealized, standardized form**: the
interface every front-end protocol is expected to consume in full, and every
back-end storage driver is expected to implement as completely as its storage
model allows — *regardless of performance* — across every authentication schema
the server supports. Deviations that exist in the tree today are catalogued in
[`vfs-evolution-and-rationale.md` §6](vfs-evolution-and-rationale.md#6-known-residuals--the-gap-to-the-idealized-interface);
this document specifies the target contract.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in the
RFC-2119 sense.

## Contents

0. [How to read this document](#0-how-to-read-this-document)
1. [What the VFS is](#1-what-the-vfs-is)
2. [The layer stack](#2-the-layer-stack)
3. [Design axioms (normative)](#3-design-axioms-normative)
4. [The object model](#4-the-object-model)
5. [The operation catalogue](#5-the-operation-catalogue)
6. [Data-flow contracts](#6-data-flow-contracts)
7. [The Storage Driver contract](#7-the-storage-driver-contract)
8. [Composition: the backend registry and the tier stack](#8-composition-the-backend-registry-and-the-tier-stack)
9. [Authentication schemas through the interface](#9-authentication-schemas-through-the-interface)
10. [Error model](#10-error-model)
11. [Observability model](#11-observability-model)
12. [Threading & memory model](#12-threading--memory-model)
13. [Conformance checklists](#13-conformance-checklists)
14. [Enforcement](#14-enforcement)

---

## 0. How to read this document

- §1–§3 give the mental model and the rules everything else instantiates.
- §4–§5 are the caller-facing API: the request descriptor, the handles, and
  every entry point, grouped by family, with signatures and contracts.
- §6 pins the end-to-end flows a reviewer should recognize on sight.
- §7–§8 are the implementor-facing seam: the driver vtable, capabilities,
  and how per-export stacks are composed.
- §9–§12 are the cross-cutting contracts: authentication, errors,
  observability, threading.
- §13–§14 turn the whole document into checklists and name the CI guards
  that make the checklists structural.

Symbol names are current as of the date above; when a name and this document
disagree, the header comment in `src/fs/vfs/vfs.h` / `vfs_ops.h` /
`src/fs/backend/sd.h` wins and this document should be updated.

---

## 1. What the VFS is

The BriX-Cache **Virtual File System** (`brix_vfs_*`, `src/fs/`) is the single
protocol-agnostic data plane between every protocol front end and every storage
backend. One sentence:

> **Every byte and every namespace/metadata operation that touches an export
> travels through the VFS; the VFS owns policy (confinement, write gating,
> metrics, access logging, page-CRC, cache integration, credential routing) and
> delegates mechanism (the actual byte movement and name mutation) to a
> pluggable Storage Driver selected per export at config time.**

**Front ends that consume it:** XRootD `root://`/`roots://` (stream), WebDAV
`davs://`/`http://`, the S3 REST subset, CMS data-server I/O, the GridFTP
gateway, and the CVMFS proxy — plus the native userland clients (`xrdcp`,
`xrdfs`, `xrootdfs`), which share the lower half of the stack via the ngx-free
`libxrdproto`.

**Back ends that implement it** (the census in `src/core/types/fs_list.h`,
one row per driver, build-gated rows shrink cleanly):

| Kind | Driver | One-liner |
|---|---|---|
| BACKEND | `posix` | the reference store — full capability set, `RESOLVE_BENEATH` confinement |
| BACKEND | `block` | raw block device exported as fixed-size extents `/0../N-1` |
| BACKEND | `pblock` | 64 MiB-striped block files + SQLite catalog; POSIX-parity caps; dedup, packed small-blob arena, shared mmap namespace cache |
| BACKEND | `ceph` / `cephfsro` | librados flat objects / read-only CephFS decoded directly from RADOS |
| ORIGIN | `http` | remote HTTP(S)/WebDAV origin (Stratum-1, DAV server) over injected libcurl |
| ORIGIN | `xroot` | remote `root://` origin via the in-process kXR wire client; read + transparent write-through |
| ORIGIN | `gsiftp` | outbound GridFTP origin (phase-91, in progress) |
| DECORATOR | `cache` | read-through cache tier wrapping any source |
| DECORATOR | `stage` | write-back staging tier wrapping any source |
| DECORATOR | `remote` | S3 remote origin (the shared `sd_s3` kernel over an injected transport) |
| NEARLINE | `frm` (`tape://`) | HSM/MSS adapter: async recall + residency |

The `sd_s3` kernel (SigV4 signing, HEAD, Range GET, single PUT, MPU, XML) is
shared byte-for-byte with the native clients through the transport vtable
(§7.6).

---

## 2. The layer stack

```
 ┌────────────────────────────────────────────────────────────────────────────┐
 │  FRONT ENDS (protocol handlers — src/protocols/*, client apps)             │
 │  root:// stream · WebDAV · S3 · GridFTP · CVMFS · SRR/SSI/Dig · clients    │
 │  own: wire framing, protocol auth, errno→kXR/HTTP/S3 status mapping        │
 └───────────────┬────────────────────────────────────────────────────────────┘
                 │  brix_vfs_ctx_t  +  one brix_vfs_* call
 ┌───────────────▼────────────────────────────────────────────────────────────┐
 │  VFS FAÇADE (policy — src/fs/vfs/)                                         │
 │  confinement re-check · write gate · cache first-refusal · credential gate │
 │  metrics + access log · buffer shaping (TLS vs sendfile) · page-CRC        │
 │  two tiers: METERED (event loop) and WORKER-SAFE RAW (any thread)          │
 └───────────────┬────────────────────────────────────────────────────────────┘
                 │  brix_sd_obj_t  (bound driver object)
 ┌───────────────▼────────────────────────────────────────────────────────────┐
 │  VERB CORE (mechanism — src/fs/core/vfs_core.c, ngx-free, shared)          │
 │  xvfs_pread_full / pread_once / pwrite_full / fsync / ftruncate / fstat    │
 │  owns the EINTR + short-I/O loop policy, single-sourced server & client    │
 └───────────────┬────────────────────────────────────────────────────────────┘
                 │  one raw syscall / one wire request per slot call
 ┌───────────────▼────────────────────────────────────────────────────────────┐
 │  STORAGE DRIVER SEAM (src/fs/backend/sd.h — capability-typed vtable)       │
 │  posix · block · pblock · ceph · cephfsro · xroot · http · remote(S3)      │
 │  gsiftp · cache/stage decorators · frm(tape)                               │
 │  own: physical confinement, raw syscalls / wire protocol to the store      │
 └────────────────────────────────────────────────────────────────────────────┘
```

The dual-build topology — the same `.c` files compiling into both worlds:

```
   src/fs/backend/sd_*.c  ┬─▶ ./config → nginx module   (full drivers: raw + ns ops)
   src/fs/core/vfs_core.c ┘
                          └─▶ shared/xrdproto/Makefile (-DXRDPROTO_NO_NGX)
                              → libxrdproto.a (raw ops only; 0 ngx_ symbols,
                                enforced by check-ngx-free.sh)
                              → linked by xrdcp / xrdfs / xrootdfs
   server:  module ─▶ vfs_server (src/fs/vfs/) ─▶ verb core ─▶ backend
   client:  xrdc_vfs shell (client/lib/) ──────▶ verb core ─▶ backend
```

The client keeps its own handle shell (`xrdc_vfs_file` + per-backend
`commit`/`abort`, URL routing, io_uring, credential store) because those are
client-only concerns; the *mechanism* underneath is shared. See
[`vfs-shared-architecture.md`](../09-developer-guide/vfs-shared-architecture.md) §4/§8.

---

## 3. Design axioms (normative)

These are the load-bearing rules. Every operation in §5 and every driver slot
in §7 is an instance of one or more of them. Each names its enforcement.

- **A1 — Open is policy; the verbs are mechanism.** Path resolution and open
  are where server and client, and export and non-export, genuinely differ
  (confinement, identity, cache, credentials). Everything after open — byte
  movement over an already-bound object — is policy-free mechanism and is
  shared. Confinement MUST NOT be re-derived below the open; it travels with
  the object/fd. *(Enforced by construction: the confined open lives only in
  `vfs_open.c`/`sd_posix.c`; the client's unconfined open lives only in the
  `*_open_unconfined` helpers.)*
- **A2 — Single funnel.** No component above the seam may issue a raw
  filesystem/data syscall against an export path. Raw data syscalls live only
  in `src/fs/backend/`; everything else calls `brix_vfs_*` (or, below the
  façade, the verb core). A raw call to a *non-export* resource or a
  *separate svc-owned domain* is permitted only with a same-line
  `/* vfs-seam-allow: <reason> */` marker (A10, §14). *(Enforced:
  `check_vfs_seam.py`, three tiers, backlogs held at 0.)*
- **A3 — Capability honesty.** A driver advertises exactly what it can do via
  the `BRIX_SD_CAP_*` bitmap and NULL-able optional slots. The VFS shapes
  behaviour ONLY from capabilities and slot presence, never from backend
  identity. Absences are honest: the VFS degrades along the defined ladders
  (§7.4) or rejects with a truthful errno — it never silently emulates a
  primitive a backend does not have (no hidden read-modify-write for a
  non-random-write store, no fake fd for an object store). *(Enforced:
  `check_vfs_identity_branch.py`.)*
- **A4 — Errno facts, not wire codes.** Drivers and the VFS return
  `errno`-style facts (`NGX_OK`/`NGX_ERROR` + `errno`, or byte counts).
  Mapping to `kXR_*`, HTTP, or S3 status codes is exclusively the front end's
  job (§10). One fact has a reserved meaning: **`EXDEV` from a confined
  operation means a confinement-escape attempt** and MUST map to
  kXR_NotAuthorized / HTTP 403.
- **A5 — Two execution tiers.** The **metered tier** (public
  `brix_vfs_open/read/write/stat/...`) allocates from nginx request pools and
  emits metrics/access-log lines; it runs ONLY on the event loop. The
  **worker-safe raw tier** (`brix_vfs_io_execute()`, `brix_vfs_pread_full`,
  `brix_vfs_open_fd`/`_at`, `brix_vfs_*_path`, `brix_vfs_walk`, the SD raw
  slots) mutates only POD descriptors and caller-owned buffers — no pool, no
  metrics, no log, no cache — and may run on any thread. Both tiers share the
  same bodies underneath, so behaviour can never drift between them. *(§12
  has the full placement table.)*
- **A6 — Confinement is re-checked, then kernel-enforced.** Every metered
  entry point calls `brix_vfs_require_confined()` (resolved path non-empty
  AND `resolved.is_confined` set, else `EINVAL`); the actual open then goes
  through `openat2(RESOLVE_BENEATH)` (or the driver's equivalent physical
  confinement — §7.1 rule 2). The VFS never trusts the caller's claim alone:
  resolution (`src/fs/path/`), the façade guard, and the kernel/driver check
  are three independent layers an escape must beat.
- **A7 — Fail-closed writes.** Every mutating entry point checks
  `ctx->allow_write` *after* confinement and before any mutation
  (`brix_vfs_require_write()`, `EACCES`). This is the data-plane backstop
  behind the protocol-layer authorization — both MUST hold independently.
  (One deliberate, documented exception: xattr set/remove, §5.7.)
- **A8 — Observability exactly once.** Every metered entry point wraps its
  result in `brix_vfs_observe_*`, which emits one Prometheus op metric and
  one access-log line (op, bytes, latency, error class) and then restores the
  caller's `errno`. Front ends MUST NOT emit their own per-op data-plane
  metrics, and non-metered variants exist precisely so pre-op resolution
  never logs phantom operations (§11).
- **A9 — Identity travels with the operation; the interface is
  auth-schema-neutral.** Whatever front-door schema authenticated the request
  (GSI/X.509, WLCG bearer, S3 SigV4, Kerberos, sss, unix, host, password —
  the `BRIX_AUTHN_*` bitmask), the front end reduces it to a
  `brix_identity_t` plus (optionally) captured forwardable credential bytes
  bound onto the ctx. The VFS's credential gate — the single checkpoint —
  resolves what the *backend leg* authenticates with (§9). No protocol
  handler ever talks to a backend credential store directly.
- **A10 — Export only; separate domains stay raw.** The VFS confines to ONE
  export root and, under impersonation, routes syscalls to the privileged
  broker which performs them **as the mapped user under the export rootfd**.
  A cache store, upload-stage dir, FRM/journal store, S3 multipart staging
  area, or checkpoint journal is a *different, svc-owned* root written by the
  worker as the service. Opening it through the VFS would, under
  impersonation, resolve the **wrong root as the wrong identity** — silently
  and "successfully". Those domains are therefore opened raw, as the worker,
  behind a `vfs-seam-allow` marker. Routing a marked call through
  `brix_vfs_*` is a security regression, not a cleanup.

---

## 4. The object model

### 4.1 `brix_vfs_ctx_t` — the per-operation request descriptor

Declared in `src/fs/vfs/vfs.h`. The ctx *is* the VFS's view of a request. A
front end fills it (normally via `brix_vfs_ctx_init()` + the `bind` helpers)
and passes it to one entry point.

| Field | Type | Meaning | Who sets it |
|---|---|---|---|
| `pool`, `log` | `ngx_pool_t*`, `ngx_log_t*` | request pool + log for the metered tier | front end |
| `identity` | `brix_identity_t*` | authenticated caller (§4.2) | front end, post-auth |
| `metrics_proto` | `brix_proto_t` | attribution protocol (stream / webdav / s3 / …) | front end |
| `root_canon` | `const char*` | canonical export root (NUL-terminated) | export config |
| `cache_root_canon` | `const char*` | canonical read-through cache root | export config |
| `rootfd` | `int` | persistent per-worker `O_PATH` fd of the export root, or `-1` | export config / worker init |
| `sd` | `brix_sd_instance_t*` | bound storage-driver instance; **`NULL` = default POSIX** (full-featured, sendfile-capable) | resolved via the backend registry in `ctx_init` |
| `cache_writethrough_cfg` | `void*` | write-through decision config | export config |
| `storage_cred_dir` | `const char*` | per-user backend credential dir; `NULL`/`""` = feature off | `ctx_bind_backend_cred` |
| `storage_cred_mint_ca_cert` / `_ca_key` / `_ttl` | `const char*`×2, `ngx_uint_t` | opt-in x509 minting CA + minted-proxy TTL (§9.5) | `ctx_bind_backend_mint` |
| `deleg_live` | `brix_deleg_live_t*` | per-request delegation live-cred bag (§9.4); `NULL` = SELECT path | `brix_vfs_deleg_bind` |
| `resolved` | `brix_path_result_t` | the already-resolved, confined client path (§4.3) | `src/fs/path/` |
| `allow_write` | bit | protocol-layer write verdict (A7 backstop input) | front end |
| `is_tls` | bit | transport is TLS (buffer-shaping input, §6.2) | front end |
| `want_pgcrc` | bit | per-page CRC32c requested (pgread/pgwrite framing) | front end |
| `cache_enabled`, `cache_writethrough` | bits | read-through / write-through cache arming | export config |
| `storage_cred_deny` | bit | 1 = service-credential fallback forbidden (§9.3) | `ctx_bind_backend_cred` |

**Rules.**
- The ctx is a per-request stack/pool object; everything it points at MUST
  outlive the VFS op. (The writer session deep-copies it for exactly this
  reason — §5.9.)
- `brix_vfs_export_relative(ctx, path)` returns the export-root-relative
  ("logical") form of an absolute confined path — the key an instance-keyed
  driver expects; a borrowed pointer into `path`, no allocation.
- Constructor:

```c
void brix_vfs_ctx_init(brix_vfs_ctx_t *vctx, ngx_pool_t *pool,
    ngx_log_t *log, brix_proto_t proto, const char *root_canon,
    const char *cache_root_canon, int allow_write, int is_tls,
    brix_identity_t *identity, const char *resolved_path);
```

  It fills the fields the HTTP front ends set identically and resolves the
  export's backend instance via the registry (§8); callers MAY tweak fields
  afterwards.

### 4.2 `brix_identity_t` — the principal the VFS reasons about

Declared in `src/core/types/identity.h`. Wire-level authentication stays
protocol-specific; after GSI, token, SSS, S3 SigV4, krb5, unix, host, or
password verification the front end fills this one canonical shape:

- `dn` (GSI DN / SSS user), `subject` (JWT `sub` or S3 access key), `issuer`
  (JWT `iss`);
- `vo_list` / `scopes` (structured), plus the policy-hot-path views `vo_csv`,
  `acc_vorg_csv`/`acc_role_csv`/`acc_group_csv` (index-aligned XrdAcc
  attribute triples), `scope_raw`, and the parsed `token_scopes[]`;
- `auth_method` — the `BRIX_AUTHN_{NONE,GSI,TOKEN,SSS,S3KEY,UNIX,KRB5,HOST,
  PWD}` bitmask (this is what `BRIX_CRED_AUTO` dispatches on, §9.4);
- verdict bits `is_authenticated`, `is_admin`, `has_write_scope`,
  `has_read_scope`; and the lazily-resolved grid-mapfile `mapped_user`.

The VFS consumes the identity for three things only: credential-gate key
derivation (§9.3), `CRED_IDENTITY` backends (pblock ownership), and
audit/metric attribution. Authorization itself stays at the protocol layer;
the VFS's `allow_write` bit is the *result* of it.

### 4.3 `brix_path_result_t` — the confined path

Produced exclusively by `src/fs/path/` (`brix_path_resolve(...)`), consumed
by every ctx. Carries the resolved canonical path plus the `is_confined` bit
the façade guard re-checks. Resolution options (`brix_path_opts_t`) express
per-op intent: `allow_missing_tail` (create), `require_directory`,
`allow_missing_parents` (recursive mkdir / HTTP PUT), `is_write_operation`
(audit), `allow_root`. The VFS does not resolve paths — it *re-verifies* and
then lets the kernel/driver enforce.

### 4.4 Handles and result PODs

| Type | What it is | Lifetime rules |
|---|---|---|
| `brix_vfs_file_t` (`brix_vfs_file_s`, private in `vfs_internal.h`) | open-file handle: embedded `brix_sd_obj_t` (driver+instance+fd+state), cached open-time metadata (`size`/`mtime`/`ctime`/`ino`/`mode`), pooled `path` copy, back-pointer to the originating ctx, `from_cache`/`is_tls`/`stat_current` flags | allocated on `ctx->pool`; the fd is closed by `brix_vfs_close()` (idempotent, NULL-safe); the struct is freed with the pool. The pool does NOT own the handle fd — but DOES own the `dup`'d sendfile fd (§6.2) |
| `brix_vfs_dir_t` | directory iterator (driver dir stream + pool + path) | released by `brix_vfs_closedir()` (idempotent) |
| `brix_vfs_staged_t` | atomic staged-write session: POSIX `O_EXCL` temp **or** driver staged object (S3 MPU, pblock staged blob) | consumed by `staged_commit`/`staged_abort` |
| `brix_vfs_writer_t` | unified verified write session (§5.9) | consumed by `writer_commit`/`writer_abort`; deep-copies its ctx |

Result PODs:

```c
typedef struct {                       /* brix_vfs_stat_t */
    off_t      size;
    time_t     mtime, ctime, atime;    /* atime → kXR_Qxattr oss.at            */
    ngx_uint_t mode;
    ino_t      ino;   dev_t dev;       /* together: the kXR stat id            */
    uid_t      uid;   gid_t gid;       /* + mode → readable/writable flags     */
    blkcnt_t   blocks;                 /* statvfs-style size (blocks*512)      */
    unsigned   is_directory:1, is_regular:1;
} brix_vfs_stat_t;

typedef struct {                       /* brix_vfs_io_result_t */
    off_t    offset;  size_t length;
    uint32_t crc32c;                   /* feeds kXR_status(4007) page framing  */
    unsigned from_cache:1, eof:1;
} brix_vfs_io_result_t;
```

### 4.5 The worker-tier job descriptor

`src/fs/vfs/vfs_io_core.h`. The POD that crosses the thread boundary:

```c
typedef enum { BRIX_VFS_IO_READ, BRIX_VFS_IO_WRITE, BRIX_VFS_IO_PGREAD,
               BRIX_VFS_IO_READV, BRIX_VFS_IO_WRITEV, BRIX_VFS_IO_SYNC,
               BRIX_VFS_IO_TRUNCATE, BRIX_VFS_IO_OPENDIR } brix_vfs_io_op_e;

typedef struct {
    /* IN — immutable once posted to a worker */
    brix_vfs_io_op_e op;
    ngx_fd_t         fd;
    brix_sd_obj_t    obj;        /* bound driver object; obj.driver==NULL ⇒
                                    POSIX-wrap the bare fd                   */
    off_t offset;  size_t length;
    u_char *buf;   size_t buf_cap;
    void *segs;    size_t nsegs; /* readv/writev segment arrays              */
    unsigned want_pgcrc:1, do_sync:1, want_stat:1, want_cksum:1;
    void *csi;                   /* CSI page-checksum context or NULL        */
    int rootfd;  u_char streamid[2];
    const char *path, *cksum_algo;
    ngx_log_t *log;  char *err_msg;  size_t err_msg_cap;
    /* OUT — written only by brix_vfs_io_execute() */
    ssize_t  nio;      size_t out_size;
    uint32_t crc32c;   int io_errno;
    unsigned short_io:1, csi_mismatch:1;
} brix_vfs_job_t;
```

**Rules.** Jobs MUST be initialized through the op-specific helpers
(`brix_vfs_job_read_init` / `_write_init` / `_sync_init` / `_truncate_init` /
`_opendir_init`) — nginx thread tasks are reused, and the helpers zero the
descriptor so stale OUT fields never leak into a new run.
`brix_vfs_job_set_obj(job, obj)` binds a non-POSIX handle object so worker
I/O routes through its driver; `brix_vfs_effective_obj()` is the shared
"driver object or POSIX wrap of the bare fd" selector. Segment descriptors
(`brix_vfs_readv_seg_t` / `brix_vfs_writev_seg_t`) carry per-segment
fd/offset/length/payload plus their own `obj` for mixed-backend vectors.

### 4.6 The Storage Driver object model

```
   brix_sd_driver_t            brix_sd_instance_t          brix_sd_obj_t
   ┌───────────────────┐        ┌─────────────────────┐     ┌──────────────────┐
   │ name  "posix"     │◀───────│ driver              │◀────│ driver, inst      │
   │ caps  bitmap      │        │ log / pool / state  │     │ fd (or -1)        │
   │ cred_accept mask  │        │ caps (EFFECTIVE —   │     │ snap (open stat)  │
   │ ~60 slots         │        │  init may narrow)   │     │ state (key, MPU…) │
   └───────────────────┘        └─────────────────────┘     │ heap_shell:1      │
    static const, per driver     one per bound export        │ cache_outcome:2   │
                                 (client: none — wrap)       │ cache_evicted_b.  │
                                                             └──────────────────┘
```

- **Instance** = one bound export: the driver, an instance-lifetime pool/log,
  driver-private state (POSIX: rootfd + root_canon; pblock: SQLite handle;
  ceph: cluster conns), and the **effective** caps bitmap — seeded from
  `driver->caps`, optionally narrowed/extended by `init` per export (the
  pblock lab `caps=` mask). `brix_sd_caps()`/`brix_sd_fd()` read the
  instance bitmap, never `driver->caps`, so a masked capability is honoured
  everywhere.
- **Object** = one open file/object. `heap_shell=1` marks a malloc'd shell
  the adopting caller must free after copying by value
  (`brix_sd_obj_release()` is the pointer-holding caller's release).
  `cache_outcome` (`NONE`/`HIT`/`MISS`) and `cache_evicted_bytes` are
  stamped by the cache decorator for the open orchestrator to translate into
  metrics — the decorator itself never meters (A8 + §7.1 rule 1).
- POD descriptors: `brix_sd_stat_t` (driver-namespace uid/gid; 0 when no
  owner model), `brix_sd_dirent_t` (`name[256]` + `d_type`, `DT_UNKNOWN`
  when the backend cannot classify cheaply — **never** an authorization
  input), `brix_sd_setattr_t` (masked mode/times/owner with
  `UTIME_OMIT`/`UTIME_NOW` semantics), `brix_sd_space_t`,
  `brix_sd_catalog_ent_t`, `brix_sd_residency_t`
  (`ONLINE`/`NEARLINE`/`OFFLINE`/`LOST`), and `brix_sd_cred_t` (§9.6).

---

## 5. The operation catalogue

This is the standard interface. Legend — *Tier*: **M** = metered, event-loop
only; **W** = worker-safe (no pool/metric, any thread); **M(u)** = event-loop
entry that intentionally emits no metric. *Gates*: **C** = requires confined
resolved path (A6); **Wr** = requires `allow_write` (A7).

### 5.1 Context construction & credential binding

```c
void brix_vfs_ctx_init(...);                                    /* §4.1 */
void brix_vfs_ctx_bind_backend_cred(brix_vfs_ctx_t *vctx,
        const ngx_str_t *cred_dir, ngx_uint_t fallback_deny);
void brix_vfs_ctx_bind_backend_mint(brix_vfs_ctx_t *vctx,
        const ngx_str_t *ca_cert, const ngx_str_t *ca_key, ngx_uint_t ttl);
ngx_int_t brix_vfs_deleg_bind(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
        enum brix_cred_mode mode, const ngx_str_t *bearer,
        const ngx_str_t *proxy_pem);
void brix_vfs_deleg_set_exchange(vctx, endpoint, client_id, client_secret,
        audience, tx_cache_slot);          /* RFC-8693 token exchange       */
void brix_vfs_deleg_set_ca_store(vctx, ca_store, verify_depth);
void brix_vfs_deleg_set_sss(vctx, mode, keytab);
void brix_vfs_deleg_set_sts(vctx, mode, sts_conf);
void brix_vfs_deleg_set_krb5(vctx, mode, ccache, origin_princ);
enum brix_cred_mode brix_vfs_backend_mode(vctx);
int  brix_vfs_backend_accepts_proxy(vctx);
void brix_vfs_deleg_snapshot(vctx, &mode, &bearer);
```

Contracts (full detail in §9): `bind_backend_cred` with an empty dir disables
the feature for this ctx. `deleg_bind` is a no-op when the export mode is
`SELECT`; the bearer/proxy byte ranges are **borrowed** and must outlive
every VFS op on the ctx. `set_sss`/`set_sts`/`set_krb5` ALLOCATE the bag when
none is bound (injection is precisely the no-captured-bytes case); on OOM
they degrade to SELECT, never to anonymous. `deleg_snapshot` exposes the
bearer for child-ctx re-binding but deliberately NOT the proxy PEM (a
0600-materialised secret is re-captured, never copied around).
`backend_accepts_proxy` returns 1 only when the leaf driver's `cred_accept`
contains `PROXY_PEM` — so a protocol can arm default-on proxy delegation
without turning it into spurious denials on posix/pblock exports.

**Requirement.** Every front end MUST populate identity, `metrics_proto`,
root/rootfd, the resolved path, and the `allow_write`/`is_tls`/`want_pgcrc`
flags correctly, and MUST bind the export's credential policy at every
data-plane open/staged-open site. Namespace-only ops never need the mint
binding.

### 5.2 Open, close, adopt, and handle accessors

```c
brix_vfs_file_t *brix_vfs_open(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
                               int *err_out);                /* M, C(+Wr) */
ngx_int_t brix_vfs_close(brix_vfs_file_t *fh, ngx_log_t *log);
ngx_int_t brix_vfs_adopt_fd(brix_vfs_ctx_t *ctx, const char *path,
        ngx_fd_t fd, brix_vfs_adopt_attrs_t attrs, brix_vfs_file_t **out);
ngx_int_t brix_vfs_adopt_obj(brix_vfs_ctx_t *ctx, const char *path,
        brix_sd_obj_t *o, unsigned writable, brix_vfs_file_t **out);
```

**Open flags** (`BRIX_VFS_O_*`, mapped internally to `O_*` / `BRIX_SD_O_*`):

| Flag | Semantics |
|---|---|
| `O_READ` / `O_WRITE` | intent; `O_WRITE` requires `allow_write` (rejected `EACCES` up front) |
| `O_CREATE` / `O_EXCL` / `O_TRUNC` / `O_APPEND` | POSIX-equivalent; non-POSIX drivers interpret in their own terms |
| `O_MKDIRPATH` | pre-create the missing parent directory tree |
| `O_NOCACHE` | bypass read-through cache admission for this open |
| `O_ATOMIC` | **writer-session only** (§5.9): force the staged temp+publish path even on a random-write backend, so a failed write never leaves a partial object at the final path. Ignored by `brix_vfs_open` |

**The confinement cascade** (normative order, `vfs_open.c`):
1. read opens: `brix_cache_open()` gets first refusal — a read-through hit
   returns a ready handle (`from_cache=1`, hit metric); `NGX_DECLINED` falls
   through and records a miss;
2. `rootfd >= 0` → the driver's `open` slot under a borrowed-rootfd instance
   → `openat2(RESOLVE_BENEATH)` — the hot path;
3. else `root_canon` → per-call confined open (same semantics, legacy
   callers);
4. else raw `open()` — reachable ONLY for server-constructed absolute paths
   with no export root, never for a client path. Do not "simplify" the
   cascade without preserving this property.

Adoption then `fstat`s the object into the handle. `stat_current` is set
only for **read-only** handles (whose file cannot change through them);
a writable handle always re-stats live (§5.4).

**Accessors** (the only sanctioned reach into a handle; all NULL-safe):

```c
ngx_fd_t    brix_vfs_file_fd(fh);            /* raw fd or NGX_INVALID_FILE */
void        brix_vfs_file_sd_obj(fh, &out);  /* copy of driver object      */
ngx_fd_t    brix_vfs_file_sendfile_fd(fh);   /* fd ONLY when CAP_FD|SENDFILE,
                                                else NGX_INVALID_FILE       */
ngx_uint_t  brix_vfs_file_can_sendfile(fh);  /* predicate form              */
const char *brix_vfs_file_backend_name(fh);  /* census name, for byte attr. */
const char *brix_vfs_file_path(fh);          /* "" never NULL               */
off_t       brix_vfs_file_size(fh);          /* cached; grows with writes   */
time_t      brix_vfs_file_mtime(fh);         /* cached at open              */
ngx_uint_t  brix_vfs_file_from_cache(fh);
ngx_int_t   brix_vfs_file_stat(fh, &st);     /* live fstat (or stat_current)*/
ngx_int_t   brix_vfs_file_read_advise(fh, off, len, advice);
```

Callers that build a sendfile / file-backed response **MUST** gate on
`sendfile_fd`/`can_sendfile` — `NGX_INVALID_FILE` means "this backend cannot
sendfile; serve memory-backed instead" (§6.2). `read_advise` takes
`BRIX_SD_ADV_SEQUENTIAL` (grow whole-fd read-ahead — streaming GET),
`ADV_WILLNEED` (force immediate range read-ahead — windowed prefetch), or
`ADV_RANDOM` (shrink read-ahead); best-effort, never changes contents, silent
no-op success on a backend without the slot.

### 5.3 Byte I/O

| Call | Tier | Semantics |
|---|---|---|
| `ssize_t brix_vfs_file_pread(fh, buf, len, off)` | W | one driver-dispatched positional read (0 = EOF; −1/errno); the backend-neutral read for memory-backed serving |
| `ssize_t brix_vfs_file_pwrite(fh, buf, len, off)` | W | driver-dispatched positional write — unlike the raw-fd `pwrite_full` this routes an object backend's block layout + catalog size bookkeeping; caller loops short writes |
| `ngx_int_t brix_vfs_pread_full(fd, buf, len, off, &nread)` | W | EINTR-safe full-read loop over a raw fd (stack POSIX wrap — no allocation); `NGX_OK` on full read **or clean EOF**; `*nread` always set, even on error |
| `ngx_int_t brix_vfs_pwrite_full(fd, buf, len, off)` | W | EINTR-safe exact-length write; `NGX_OK` only when all `len` bytes landed; a 0-byte pwrite is `EIO` |
| `void brix_vfs_io_execute(job)` | W | the POD job executor (§4.5): dispatches by op to small per-op helpers, reusing the same pure bodies; builds the `kXR_dirlist` payload for `OPENDIR`; computes per-page CRC32c and runs CSI verify when armed; captures errno into `job->io_errno` |
| `ngx_int_t brix_vfs_truncate(fh, len)` | M(u) | ftruncate + cached-size update so later reads see the new length |
| `ngx_int_t brix_vfs_sync(fh)` | M(u) | fsync to stable storage (the enclosing write op records the metric) |

Verb-core kernels underneath (shared, ngx-free, `0/-1 + errno`):
`xvfs_pread_full(obj,buf,len,off,&nread)`, `xvfs_pread_once`,
`xvfs_pwrite_full(obj,buf,len,off,&written,&short_io)`, `xvfs_fsync`,
`xvfs_ftruncate`, `xvfs_fstat`. **The verbs own the loop policy; the backend
owns the syscall** — a driver MUST NOT add its own EINTR/retry loop, and the
VFS MUST NOT bypass the verbs with raw syscalls.

### 5.4 Metadata: stat, probe, residency, space

```c
ngx_int_t brix_vfs_stat (brix_vfs_ctx_t *ctx, brix_vfs_stat_t *out);  /* M OP_STAT, C */
ngx_int_t brix_vfs_statf(brix_vfs_ctx_t *ctx, brix_vfs_stat_t *out);  /* M OP_STAT, C */
ngx_int_t brix_vfs_probe(brix_vfs_ctx_t *ctx, int nofollow,
                         brix_vfs_stat_t *out);                       /* W, C, no metric */
void      brix_vfs_neg_stat_forget(const char *root_canon, const char *path);
ngx_int_t brix_vfs_residency(brix_vfs_ctx_t *ctx, brix_sd_residency_t *out,
                             int *nearline_export);                   /* M, C */
ngx_int_t brix_vfs_space(brix_vfs_ctx_t *ctx, brix_sd_space_t *out);  /* M, C */
```

- `stat` = `lstat` semantics (symlinks reported, not followed); `statf`
  follows a trailing **in-export** symlink chroot-style
  (`RESOLVE_IN_ROOT`) — escapes still impossible.
- `probe` is the **non-metered** existence/type pre-check for op resolution
  and ACL gates: `NGX_OK` present (out filled), `NGX_DECLINED` absent (errno
  kept), `NGX_ERROR` on a guard failure. Routing pre-stats through the
  metered stat would log a phantom `OP_STAT` per rm/mkdir/mv — use probe.
- `neg_stat_forget` is the honesty contract of the per-worker negative-stat
  cache: every same-worker publish point that can materialise a path
  OUTSIDE `open`/`mkdir`/`rename` (a protocol-layer create-open, a
  staged-commit rename) MUST call it on success so a cached `ENOENT` never
  outlives a same-worker create. No-op when the cache is off.
- `residency` classifies tape state WITHOUT forcing a recall, walking
  cache/stage decorators down to the `CAP_NEARLINE` driver; a plain
  disk/object export always reports `ONLINE`. `*nearline_export` lets
  callers speak the WLCG locality vocabulary (`ONLINE_AND_NEARLINE` vs
  plain `ONLINE`). Consumers: the HTTP Tape REST API, S3
  `InvalidObjectState`/`x-amz-storage-class`, the root:// stat nearline flag.
- `space` returns the driver's own quota-aware view (pblock's catalog
  quota); `NGX_DECLINED` = no `space` slot → the caller falls back to
  `statvfs(2)` on the export root. Consumers: `kXR_statvfs`, SRR.

### 5.5 Directory iteration

```c
brix_vfs_dir_t *brix_vfs_opendir      (ctx, &err);   /* M OP_DIRLIST, C   */
brix_vfs_dir_t *brix_vfs_opendir_quiet(ctx, &err);   /* M(u), C           */
ngx_int_t brix_vfs_readdir     (dh, &name, &st_or_NULL);
ngx_int_t brix_vfs_readdir_kind(dh, &name, &kind);   /* no per-entry stat */
ngx_int_t brix_vfs_closedir    (dh, log);
ngx_fd_t  brix_vfs_dir_fd      (dh);
```

- `readdir` yields one pool-allocated NUL-terminated entry name per call
  with an optional child `lstat`; `.`/`..` are filtered; `NGX_DONE` ends the
  stream.
- `readdir_kind` classifies dir/file/other from `d_type` without a stat
  (`brix_vfs_dirent_kind_t`: `UNKNOWN`/`DIR`/`REG`/`OTHER`); `UNKNOWN`
  means the backend could not classify cheaply — the caller SHOULD `probe`
  the child. A spoofed `d_type` may only ever cost a fallback stat, never an
  authorization result.
- `opendir_quiet` exists for bulk recursive traversals (S3 ListObjects,
  WebDAV SEARCH, fattr recursive list): the enclosing protocol op accounts
  for the whole traversal, which would otherwise log one phantom
  `OP_DIRLIST` per visited subdirectory.
- `dir_fd` exposes the open (impersonation-confined) directory fd for
  TOCTOU-safe dirfd-relative `openat` of entries (dirlist checksums);
  `NGX_INVALID_FILE` on fd-less backends.

### 5.6 Namespace mutation

Metered variants — all **C + Wr**, delegating to the confined `brix_ns_*`
family / driver namespace slots, `brix_ns_result_t.status/.sys_errno`
translated back to `NGX_OK`/`NGX_ERROR` + errno:

```c
ngx_int_t brix_vfs_mkdir (ctx, mode_t mode, unsigned parents);       /* OP_MKDIR  */
ngx_int_t brix_vfs_rename(ctx, const brix_path_result_t *dst,
                          unsigned overwrite_dirs);                  /* OP_RENAME */
ngx_int_t brix_vfs_unlink(ctx);                                      /* OP_DELETE */
ngx_int_t brix_vfs_rmdir (ctx, unsigned recursive);                  /* OP_DELETE */
ngx_int_t brix_vfs_chmod (ctx, mode_t mode);
ngx_int_t brix_vfs_setattr(ctx, const brix_sd_setattr_t *attr);
ngx_int_t brix_vfs_truncate_path(ctx, off_t length);                 /* M(u)      */
```

Pinned cross-protocol edge semantics (these ARE the interface — the four
front ends inherited a single answer to each):

| Edge case | Contract |
|---|---|
| rename onto an existing **directory** destination | `overwrite_dirs=1` removes it first (WebDAV MOVE `Overwrite: T` — `rename(2)` alone only replaces an *empty* dir); `overwrite_dirs=0` fails `EEXIST` (kXR_mv semantics), with `was_dir` distinguishing kXR_isDirectory from kXR_ItExists on the thread-safe variant |
| rmdir of a populated directory | `recursive=0` → `ENOTEMPTY`; recursive deletion is the VFS's job, never a driver slot's (WebDAV `DELETE` on a collection is recursive by RFC — the driver slot MUST still refuse, §7.5) |
| delete of an absent path | `ENOENT` — an origin 404 is never mapped to success |
| `setattr` on a backend with no mutable metadata | **no-op success** (so MKCOL/PUT chmod flows pass); a backend applies only what its namespace can represent |
| `truncate_path` | uses a backend path-native truncate when the slot exists (a remote resize needs no write-open and no staging self-collision); else falls back to open(`O_WRITE`)+ftruncate+close; `ENOENT` for a missing path |

Worker-safe path twins (no pool, no metric, impersonation-aware — for
off-loop consumers: native TPC pull, S3 multipart assembly, collection
COPY/MOVE engines):

```c
int brix_vfs_open_fd    (log, root_canon, logical, int O_flags, mode_t);
int brix_vfs_open_fd_at (rootfd, logical, int O_flags, mode_t);
int brix_vfs_unlink_path(log, root_canon, logical);
int brix_vfs_unlink_at  (rootfd, logical, int is_dir);
int brix_vfs_rmdir_path (log, root_canon, logical);
int brix_vfs_mkdir_path (log, root_canon, logical, mode_t);
ngx_int_t brix_vfs_rename_path(sd, log, root_canon, src, dst,
                               unsigned overwrite, int *was_dir_out);
int brix_vfs_backend_mkpath(root_canon, logical, mode_t, log);
int brix_vfs_backend_leaf_isdir(leaf, logical, cred);
```

Two recurring traps, both normative: the `root_canon` forms take the
**absolute** path (they strip the root themselves — the impersonation branch
needs the export-relative form, the local branch the absolute; passing a
pre-stripped path makes the strip fail and the op `ENOENT`s); and these raw
forms carry **no credential gate** — a handler on a per-user-credential
export MUST use the ctx-bound metered variants so namespace ops reach the
origin as the user (this exact bug shipped once; see the evolution doc §5).

### 5.7 Extended attributes

```c
ssize_t   brix_vfs_getxattr   (ctx, name, buf, bufsz);       /* M OP_XATTR, C */
ssize_t   brix_vfs_listxattr  (ctx, buf, bufsz);
ngx_int_t brix_vfs_setxattr   (ctx, name, value, len, flags);
ngx_int_t brix_vfs_removexattr(ctx, name);
/* fd variants: confinement travels with the descriptor; ctx may be NULL
 * (then unobserved) and is used only to attribute the metric.            */
ssize_t   brix_vfs_fgetxattr   (ctx_or_NULL, fd, name, buf, bufsz);
ssize_t   brix_vfs_flistxattr  (ctx_or_NULL, fd, buf, bufsz);
ngx_int_t brix_vfs_fsetxattr   (ctx_or_NULL, fd, name, value, len, flags);
ngx_int_t brix_vfs_fremovexattr(ctx_or_NULL, fd, name);
```

The `user.` namespace carries: S3 object tagging, WebDAV dead properties,
the WebDAV lock database, kXR `fattr`, and checksum-at-rest. get/list return
byte counts (`bufsz==0` asks the required size; `-1`/`ERANGE` when a value
does not fit). **Deliberate exception to A7:** set/remove are NOT
`allow_write`-gated — the lock database writes on otherwise read-only
requests and the protocol layer has already authorized; this matches the
pre-seam behaviour and is part of the contract, not an oversight.

### 5.8 Copy, walk, and bulk traversal

```c
ngx_int_t brix_vfs_copy(ctx, const char *dst_resolved,
                        const brix_vfs_copy_opts_t *opts);  /* M OP_COPY, C+Wr */
ngx_int_t brix_vfs_copyfile(log, root_canon, src, dst, preserve_xattrs,
                            meta_cb, cookie);               /* W */
ngx_int_t brix_vfs_copytree(log, root_canon, src, dst, preserve_xattrs,
                            meta_cb, cookie);               /* W */
ngx_int_t brix_vfs_walk(log, rootfd, logical, const brix_vfs_walk_opts_t *o,
                        brix_vfs_walk_file_cb cb, cookie,
                        brix_vfs_walk_target_t *target_out,
                        char *errmsg, size_t errsz);        /* W */
```

- `copy` (behind WebDAV COPY / S3 CopyObject): single regular-file
  server-side copy via `copy_file_range` with a read/write stream-through
  fallback when `!CAP_SERVER_COPY`; opts
  `{recursive, overwrite, overwrite_dirs, preserve_xattrs, staged_commit}`;
  byte count metered from the post-copy destination size; `EEXIST` when dst
  exists and `!overwrite`.
- `copyfile`/`copytree`: thread-safe confined copies with an optional
  per-entry metadata callback (`meta_cb(cookie, src, dst, is_dir)` — WebDAV
  dead-property propagation); symlinks/specials are skipped and never
  followed out of the export.
- `walk`: the thread-safe, non-allocating, non-metered confined traversal
  for bulk consumers (checksum scan, recursive remove). Opts:
  `max_depth` (0 = target dir only), `max_files`, `open_files` (open each
  regular file `O_RDONLY` and pass the fd to the callback, closing it
  after). Target kinds: `NONE`/`FILE`/`DIR`/`OTHER`. Per-entry failures skip
  that entry (bulk-scan semantics); the callback's non-OK return aborts the
  walk and is returned verbatim.

### 5.9 Write sessions: staged and verified

**Staged (atomic upload lifecycle):**

```c
brix_vfs_staged_t *brix_vfs_staged_open(ctx, mode_t, ngx_uint_t attempts,
                                        int *err_out);        /* C+Wr        */
ngx_fd_t    brix_vfs_staged_fd(st);        /* temp fd, or NGX_INVALID_FILE
                                              for a driver-backed staged obj */
ngx_uint_t  brix_vfs_staged_is_driver(st);
ngx_int_t   brix_vfs_staged_write(st, buf, len, off);  /* backend-neutral   */
const char *brix_vfs_staged_tmp_path(st);
ngx_int_t   brix_vfs_staged_commit(st, unsigned excl); /* M OP_WRITE        */
void        brix_vfs_staged_abort (st, unsigned remove_tmp);
```

Open creates a unique `O_EXCL` temp inside the export (POSIX) or a driver
staged object (S3 multipart, pblock staged blob). Commit atomically
publishes onto the final path — `excl` uses `RENAME_NOREPLACE` and yields
`EEXIST` when the final exists (S3 `If-None-Match` exclusive create). A
failed or aborted upload MUST never leave a partial object at the final
path. Abort is idempotent and NULL-safe.

**Writer — the ONE write entry point for every backend:**

```c
brix_vfs_writer_t *brix_vfs_writer_open(ctx, unsigned flags, int verify,
                                        int *err_out);
ngx_int_t brix_vfs_writer_write   (w, buf, len, off_t off);
ngx_int_t brix_vfs_writer_write_fd(w, int src_fd, off_t src_off,
                                   size_t len, off_t dst_off);
off_t     brix_vfs_writer_expected_off(w);
ngx_int_t brix_vfs_writer_commit  (w);
ngx_int_t brix_vfs_writer_commit_ex(w, unsigned excl);
void      brix_vfs_writer_abort   (w);
ngx_fd_t  brix_vfs_writer_fd      (w);     /* in-place fd or staged temp fd */
brix_vfs_staged_t *brix_vfs_writer_staged(w);  /* staged path only          */
```

The session picks mechanics from the backend's capabilities:

| Backend | Mechanics | Extent rules |
|---|---|---|
| `CAP_RANDOM_WRITE` (posix, pblock, block, xroot, ceph) | in-place `O_WRITE\|O_CREATE` handle, `brix_vfs_file_pwrite` at arbitrary offsets | REST/APPE and out-of-order (GridFTP MODE E) extents supported; `O_TRUNC` honoured |
| staged-only (S3/object; no `CAP_RANDOM_WRITE`) | atomic staged upload (temp → publish; MPU underneath) | extents MUST be sequential from offset 0; a non-sequential write is refused `EINVAL` — `expected_off` lets the caller distinguish an ordering error (its own protocol mapping) from an I/O failure |
| any, with `BRIX_VFS_O_ATOMIC` | forced staged temp+publish | the WebDAV/S3 PUT invariant even on random-write backends |

`verify` asserts a whole-object write from offset 0: every extent is CRC'd
and, on commit, the persisted object is **re-read through its own driver**
and compared (`brix_vfs_wverify_check(w_accum, fresh_read_handle)` is the
underlying seam) — a mismatch, gap, or short/oversize object unlinks the
file and fails the commit. This is the only trustworthy end-to-end check
for an object backend with no single kernel-file identity. An empty object
is a complete `[0,0)` write and verifies trivially. `write_fd` is the
fd-to-fd twin for spooled bodies: a single-fd sendfile-capable random
backend with verify OFF moves kernel-side (`copy_file_range`, zero-copy);
a verifying, staged, or block backend bounces through the write engine so
the CRC accumulator sees every byte and block/staged routing holds. The
writer deep-copies its ctx (and the buffers it points into), so the
caller's per-request frame may die before commit. Commit consumes the
session; the only valid follow-up is `abort` (a no-op once finished).

Write-acceptance policy the writer implements for a `!CAP_RANDOM_WRITE`
backend (the phase-55 §5.3 policy, still normative): create-new via
sequential staged writes = yes; rewriting an offset, punching a hole,
`pgwrite`/`writev` sparse mutation, checkpointed rewrite of an
**already-committed** object = refused (`ENOTSUP`-class fact, surfaced via
metric) — never silently emulated with read-modify-write. A composed POSIX
*stage* tier in front of the backend lifts all of these for uploads **in
progress** (the random writes land on the stage file; only the finished
object is promoted).

### 5.10 Catalog enumeration and dedup

```c
ngx_int_t brix_vfs_enumerate_catalog(brix_sd_instance_t *sd, int want_stat,
                                     brix_sd_catalog_cb cb, void *ctx);
```

Enumerates the backend's OWN physical object catalog (inventory/drift
tooling) — NOT a namespace walk. Fires `cb(ctx, ent)` once per stored
object; `ent->path == NULL` marks an orphan-object candidate; a non-zero cb
return aborts and is returned. `NGX_DECLINED` + `ENOTSUP` when the
namespace *is* the catalog (POSIX) — callers fall back to `brix_vfs_walk`.

Driver dedup verbs (optional; the phase-88 G13 seam):
`dedup_publish(inst, path, canon)` collapses byte-identical stored copies
after the **caller** proved content identity (a verified CAS fill); `canon`
is a stable content-derived alias the driver MAY materialise as a real name
(posix: the cross-repo hardlink farm) or fold into its own refcounting
catalog (pblock refs). `dedup_gc(inst, canon)` releases a last-reference
canonical (NULL on refcounting backends that need no GC). Best-effort
contract: `NGX_OK` = published / folded / benignly skipped — the per-repo
copy is always left correct; `ENOTSUP` = the instance is not armed (config
refuses `brix_cache_global_cas` on such a backend). Both run on cache-fill
worker threads: no pool, `inst->log` only.

---

## 6. Data-flow contracts

The flows a reviewer should recognize on sight. Deviations from these shapes
are bugs or need a documented reason.

### 6.1 Open (read) — cache first-refusal + confinement cascade

```
handler: brix_path_resolve() → fill ctx → brix_vfs_open(ctx, O_READ)
   │ require_confined(ctx)                                      [A6]
   │ credential gate (when armed): resolve backend-leg cred      [§9]
   │ cache first-refusal: brix_cache_open() ── HIT ─▶ handle (from_cache=1)
   │      └─ NGX_DECLINED (miss metric)  ▼
   │ cascade: rootfd  ─▶ driver->open  (openat2 RESOLVE_BENEATH)
   │          root_canon ─▶ per-call confined open
   │          neither ─▶ raw open()      [server-constructed paths ONLY]
   ▼ adopt: driver fstat → handle metadata (stat_current iff read-only)
handle ──▶ caller frames/serves; brix_vfs_close() when done
```

### 6.2 Read serve — the TLS / cleartext fork (invariant 2)

```
                       ┌─ is_tls || want_pgcrc ─▶ MEMORY-backed buf (b->memory=1)
brix_vfs read result ──┤                          bytes via file_pread/io_execute;
                       │                          want_pgcrc ⇒ CRC32c per page →
                       │                          kXR_status(4007) framing
                       └─ cleartext ─▶ driver->read_sendfile_fd(off,len,zerocopy)
                             ├─ real fd:  FILE-backed b->in_file over a dup'd fd;
                             │            ngx_pool_cleanup_file owns the DUP —
                             │            never close the handle out from under
                             │            an in-flight sendfile buf
                             └─ NGX_INVALID_FILE (object/MEMFILE backend):
                                memory-backed serve
```

Never emit a file-backed buffer on a TLS connection; never memory-copy a
large cleartext serve a `CAP_SENDFILE` backend could sendfile. The backend
owns the zero-copy verdict; the VFS passes transport context and consumes
the answer.

### 6.3 Worker-tier read/write (AIO / io_uring / inline fallback)

```
protocol op ─▶ job{op, fd|obj, off, len, buf}  (job_*_init [+ set_obj])
   ─▶ dispatch tier: AIO thread pool │ io_uring inline fallback │ loop inline
   ─▶ brix_vfs_io_execute(job)            [W: no pool/metric/log/cache]
        └─ xvfs_pread_full / pwrite_full(effective_obj)   [shared verb core]
             └─ obj->driver->pread / pwrite               [seam: one syscall]
        └─ optional: per-page CRC32c; CSI verify (read) / retag (write)
   ─▶ OUT: nio / crc32c / io_errno / short_io ─▶ event loop frames the reply
```

Identical bodies on every tier — that identity is the point (drift between
worker and loop was the phase-54 problem class).

### 6.4 Staged PUT (WebDAV / S3 / GridFTP STOR via the writer)

```
writer_open(ctx, flags, verify)
   ├─ CAP_RANDOM_WRITE && !O_ATOMIC ─▶ in-place handle (O_WRITE|O_CREATE[|O_TRUNC])
   └─ else ─▶ staged_open: O_EXCL temp (POSIX) │ driver staged (S3 MPU, pblock)
writer_write / write_fd  (extents; CRC accumulated when verify;
                          staged path enforces sequential-from-0)
writer_commit(excl)
   ├─ staged: fsync → atomic publish (RENAME_NOREPLACE when excl → EEXIST)
   ├─ verify: fresh read handle → re-read through driver → CRC compare
   │          mismatch ⇒ unlink + NGX_ERROR
   ├─ metered OP_WRITE (committed size); neg-stat forget on the final path
   └─ cache write-through consulted (mirror/invalidate per policy)
```

### 6.5 The credential gate (per data-plane open / staged open / cred-scoped ns op)

```
brix_vfs ctx ──▶ gate (vfs_cred.c — THE one checkpoint)
   │
   ├─ deleg_live bag bound? ──────────────── no ─▶ SELECT:
   │        yes ▼                                 key = ucred_key(principal)
   │  mode PASSTHROUGH:                           <key>.pem (expiry-checked!) →
   │    bearer bytes → cred.bearer                <key>.token → <key>.s3 →
   │    proxy PEM → re-verify chain vs            <key>.keyring
   │    ca_store → 0600 materialise →             miss + mint armed ⇒ MINT (§9.5)
   │    cred.x509_proxy                           miss + deny ⇒ EACCES (STOP —
   │  mode EXCHANGE:                              origin never touched)
   │    RFC-8693 tx │ S3 STS │ krb5 ccache        miss + allow ⇒ service cred
   │  no bytes: SSS / STS injection (armed)
   ▼
   cred_accept check: leaf driver accepts this kind?  no ⇒ EACCES (pre-origin)
   ▼
   decorator unwrap (brix_vfs_ns_leaf): cred-scoped dispatch targets the LEAF
   ▼
   driver->open_cred / staged_open_cred / <ns>_cred  (else plain slot when
   cred is NULL — service credential / anonymous)
```

Fail-closed rules (each individually load-bearing; see the evolution doc for
the bugs that motivated them): an expired `.pem` refuses rather than falling
through to `.token`; a deny-mode request never reaches the origin — including
its probe stats; every degradation lands on SELECT, never on silent
anonymous; the deny verdict for an offloaded read runs on the event loop
BEFORE the thread task is submitted.

### 6.6 Composed tiers — cache read-through, write-back, nearline

```
config:  backend=<src>  [+ cache_store=<tier>]  [+ stage=<tier>]  (registry §8)
composed instance (top of stack) = stage( cache( source ) )

READ  open ─▶ sd_cache: admission → local store probe
        HIT  ─▶ obj{cache_outcome=HIT} served from the cache store
        MISS ─▶ driver→driver fill on a worker thread:
                source(sd_xroot│sd_remote│sd_http).pread → memory sink →
                staged write into the cache store → digest verify (when armed;
                staged_path exposes the temp for it) → commit → serve
WRITE open on a stage-composed export ─▶ sd_stage: land on the local spool;
        commit records a durable journal entry {path, size, cred key/dir/deny}
        ─▶ async flush (stage_engine): RE-RESOLVE the credential from key+dir
           (expiry re-checked at use), promote to the source backend, verify,
           retire the record; permanently-denied records dead-letter — never
           flushed under the wrong identity, never looped forever
NEARLINE read (CAP_NEARLINE source) ─▶ residency probe:
        ONLINE   ─▶ normal fill      NEARLINE/OFFLINE ─▶ driver->recall(key,
        reqid) → NGX_AGAIN → open parked on the stage-waiter → recall lands in
        the cache tier → parked open resumes    LOST ─▶ ENOENT-class fact
```

The registry REFUSES to compose a `CAP_NEARLINE` source without a cache tier
(the recall needs a landing zone). Eviction on WRITE/CREATE/TRUNC opens is
accounted via `obj->cache_evicted_bytes` at the adopt site — the decorator
itself never meters.

### 6.7 Dirlist

```
brix_vfs_opendir(ctx) [OP_DIRLIST] ─▶ readdir/readdir_kind loop
  per entry: optional lstat │ d_type classification (probe on DT_UNKNOWN)
  worker path: job{OPENDIR, confined dirfd} ─▶ io_execute builds the
  kXR_dirlist payload (optional per-entry stat + checksum via dir_fd-relative
  TOCTOU-safe opens)
bulk protocol walks (S3 ListObjects, WebDAV SEARCH): opendir_quiet +
  readdir_kind — one metered op for the whole traversal
```

---

## 7. The Storage Driver contract

### 7.1 Contract rules (normative)

1. **Worker-safety.** The raw byte ops (`pread`/`pwrite`/`preadv`/`preadv2`/
   `copy_range`/`ftruncate`/`fsync`/`fstat`/`read_advise`) and
   `staged_write` MUST be worker-safe: no nginx pool, no metrics/log
   emission, no cache state, POD arguments only. They are single verbatim
   operations — the verb core owns the EINTR/short-I/O loop.
2. **Confinement is the driver's job.** Instance-keyed ops take an
   already-confined **logical** path; the driver enforces its own
   **physical** confinement: POSIX via `openat2(RESOLVE_BENEATH)`; block by
   exposing only extent indices (a device export can never be walked into a
   host path); pblock/ceph via canonicalized, injective LFN→object-key maps
   that reject `..` escapes (unit-tested standalone); origins by re-checking
   the logical→physical join locally, never trusting the caller. `EXDEV`
   still means an escape attempt.
3. **Errno facts** (A4). `read_sendfile_fd(obj, off, len, want_zerocopy)` is
   the backend's OWN zero-copy verdict; `NGX_INVALID_FILE` = "serve
   memory-backed"; a NULL slot = "never sendfiles".
4. **Optional slots are NULL, not stubbed.** The VFS applies the §7.4
   ladders on absence. Exactly two slots are specified as tolerant:
   `setattr` (no-op success on immutable-metadata namespaces) and
   `read_advise` (advisory; `NGX_OK` whether or not honoured).
5. **Nearline obligations.** `CAP_NEARLINE` ⇒ implement `recall` (async;
   `NGX_AGAIN` = queued/in-flight with a stable `reqid` ≤39 chars, `NGX_OK`
   = already online, `NGX_ERROR`+errno) and `residency` (pure read of the
   MSS model, never triggers a recall) — and accept that the registry
   refuses to compose without a cache tier.
6. **Borrowed credential strings** are valid only for the duration of the
   vtable call; a driver deferring work (thread-pool fill) MUST copy them
   before returning (§9.6).

### 7.2 The vtable, slot by slot

```c
struct brix_sd_driver_s {
    const char *name;         /* census name: "posix" | "pblock" | …        */
    uint32_t    caps;         /* brix_sd_cap_t bitmap                       */
    uint32_t    cred_accept;  /* OR of brix_sd_cred_kind_t consumed; 0=none */

    /* instance lifecycle (event loop, config/worker init) */
    ngx_int_t (*init)(inst, void *driver_conf);   /* may narrow inst->caps  */
    void      (*cleanup)(inst);

    /* object lifecycle */
    brix_sd_obj_t *(*open)(inst, const char *path, int sd_flags,
                           mode_t mode, int *err_out);
    ngx_int_t (*close)(obj);

    /* worker-safe raw byte I/O (rule 1) */
    ssize_t   (*pread)  (obj, buf, len, off);
    ssize_t   (*pwrite) (obj, buf, len, off);
    ssize_t   (*preadv) (obj, iov, iovcnt, off);
    ssize_t   (*preadv2)(obj, iov, iovcnt, off, flags);  /* RWF_NOWAIT probe */
    ssize_t   (*copy_range)(src, src_off, dst, dst_off, len);
    ngx_fd_t  (*read_sendfile_fd)(obj, off, len, want_zerocopy);
    ngx_int_t (*ftruncate)(obj, len);
    ngx_int_t (*fsync)(obj);              /* durability barrier — a catalog
                                             backend commits its size here  */
    ngx_int_t (*fstat)(obj, brix_sd_stat_t *out);
    ngx_int_t (*read_advise)(obj, off, len, advice);

    /* namespace on logical paths */
    ngx_int_t (*stat)   (inst, path, out);
    ngx_int_t (*unlink) (inst, path, int is_dir);
    ngx_int_t (*mkdir)  (inst, path, mode);
    ngx_int_t (*rename) (inst, src, dst, int noreplace);
    ngx_int_t (*server_copy)(inst, src, dst, off_t *bytes_out);
    ngx_int_t (*setattr)(inst, path, const brix_sd_setattr_t *attr);
    ngx_int_t (*truncate_path)(inst, path, len);

    /* directory iteration */
    brix_sd_dir_t *(*opendir)(inst, path, int *err_out);
    ngx_int_t (*readdir)(dir, brix_sd_dirent_t *out);
    ngx_int_t (*closedir)(dir);

    /* xattr / object metadata */
    ssize_t   (*getxattr)(inst, path, name, buf, cap);
    ssize_t   (*listxattr)(inst, path, buf, cap);
    ngx_int_t (*setxattr)(inst, path, name, val, len, flags);
    ngx_int_t (*removexattr)(inst, path, name);

    /* staged/atomic write (multipart for object stores) */
    brix_sd_staged_t *(*staged_open)(inst, final_path, mode, int *err_out);
    ssize_t   (*staged_write) (st, buf, len, off);
    ngx_int_t (*staged_commit)(st, int noreplace);
    void      (*staged_abort) (st);
    const char *(*staged_path)(st);   /* temp path for digest verify; NULL
                                         when no local file (remote/object) */

    /* commit-time content dedup (optional — §5.10) */
    ngx_int_t (*dedup_publish)(inst, path, canon);
    ngx_int_t (*dedup_gc)(inst, canon);

    /* nearline (rule 5) */
    ngx_int_t (*recall)(inst, key, char reqid_out[40]);
    ngx_int_t (*residency)(inst, key, brix_sd_residency_t *out);

    /* reporting (optional) */
    ngx_int_t (*space)(inst, brix_sd_space_t *out);
    ngx_int_t (*enumerate)(inst, int want_stat, brix_sd_catalog_cb, void*);

    /* credential-scoped twins (§9.6): open_cred · staged_open_cred ·
     * stat_cred · unlink_cred · mkdir_cred · rename_cred · setattr_cred ·
     * truncate_path_cred · getxattr_cred · listxattr_cred · setxattr_cred ·
     * removexattr_cred · server_copy_cred · opendir_cred
     * — each = the plain slot + trailing const brix_sd_cred_t *.
     * NULL ⇒ the brix_sd_<op>_maybe_cred forwarders fall back to the plain
     * slot. stat_cred != NULL is the canonical "supports per-user ns auth"
     * gate.                                                                */
};
```

Registry API (`sd_registry.h`): `brix_sd_instance_create(log, name,
driver_conf, &err)` / `brix_sd_instance_destroy(inst)`;
`brix_sd_driver_count()` / `brix_sd_driver_at(i)` (the census iterator for
tooling/health); `brix_sd_default_driver()` (POSIX);
`brix_sd_posix_borrow_instance(pool, rootfd, root_canon)` (the hot-path
borrowed-rootfd instance the confined open uses). Capability-gated
accessors — **never poke the vtable directly**: `brix_sd_caps(inst)`,
`brix_sd_fd(obj)`, `brix_sd_supports(inst, mask)`,
`brix_sd_backend_name(inst)`, `brix_sd_cred_accept(inst)`,
`brix_sd_obj_release(obj)`.

### 7.3 The capability bitmap and the per-driver matrix

Semantics of each bit and the VFS's behaviour on absence:

| Cap | Grants | Absent ⇒ |
|---|---|---|
| `CAP_FD` | object exposes a real kernel fd | fd accessors return `NGX_INVALID_FILE`; io_uring/sendfile tiers skipped |
| `CAP_SENDFILE` (implies FD) | fd valid as sendfile / `b->in_file` source for any range | memory-backed serve (§6.2) |
| `CAP_RANDOM_WRITE` | pwrite at arbitrary offsets | writer degrades to sequential staged upload; in-place partial writes rejected at the cap layer |
| `CAP_RANGE_READ` | pread at arbitrary offsets | ranged reads rejected (universal in practice) |
| `CAP_TRUNCATE` | ftruncate | truncate rejected |
| `CAP_SERVER_COPY` | native copy (`copy_file_range` / remote COPY) | VFS stream-through pread→pwrite fallback |
| `CAP_XATTR` / `CAP_XATTR_WRITE` | xattr read / write | xattr-backed features degrade per protocol |
| `CAP_HARD_RENAME` | atomic rename | copy+delete rename (documented per driver, e.g. ceph ADR-5) |
| `CAP_DIRS` / `CAP_DIRS_WRITE` | real (mutable) directories | synthetic key-prefix listing / mkdir-family rejected |
| `CAP_APPEND` | `O_APPEND` semantics | append rejected |
| `CAP_IOURING` | fd is ring-submittable | ring tier skipped |
| `CAP_FSCS` | filesystem page checksums (CSI sidecar) | no page-checksum verify/retag |
| `CAP_NEARLINE` | tape/MSS: reads may recall | (marker + rule-5 obligations) |
| `CAP_CATALOG` | native object-catalog enumeration | `enumerate` → `ENOTSUP` → namespace walk |
| `CAP_MEMFILE` | can serve bytes memory-backed without a kernel fd | — (the usual companion of a missing `CAP_FD`) |

Advertised capabilities per driver, verified against the `.caps`
initializers (server build; ¹ = dropped in the ngx-free client build, whose
namespace slots are compiled out):

| Cap | posix | block | pblock | ceph | cephfsro | xroot | http | remote(S3) | cache | stage | frm |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| FD | ✔ | ✔ | ✔ | — | — | — | — | — | — | — | ✔ |
| SENDFILE | ✔ | — | ✔ | — | — | — | — | — | — | — | — |
| RANDOM_WRITE | ✔ | ✔ | ✔ | ✔ | — | ✔ | — | — | ✔ | ✔ | ✔ |
| RANGE_READ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| TRUNCATE | ✔ | — | ✔ | ✔ | — | ✔ | — | — | ✔ | ✔ | — |
| APPEND | ✔ | — | ✔ | — | — | — | — | — | — | — | — |
| IOURING | ✔ | — | ✔ | — | — | — | — | — | — | — | — |
| SERVER_COPY | ✔¹ | — | ✔ | — | — | ✔ | — | — | ✔ | ✔ | — |
| XATTR / XATTR_WRITE | ✔¹/✔¹ | — | ✔/✔ | ✔/✔ | ✔/— | ✔/✔ | — | ✔/✔ | ✔/✔ | ✔/✔ | — |
| HARD_RENAME | ✔¹ | — | ✔ | — | — | ✔ | ✔ | — | ✔ | ✔ | — |
| DIRS / DIRS_WRITE | ✔¹/✔¹ | ✔¹/— | ✔/✔ | ✔/— | ✔/— | ✔/✔ | ✔/✔ | ✔/✔ | ✔/✔ | ✔/✔ | — |
| MEMFILE | — | — | — | ✔ | ✔ | ✔ | ✔ | ✔ | — | — | — |
| CATALOG | — | — | ✔ | ✔ | — | — | — | — | — | — | — |
| NEARLINE | — | — | — | — | — | — | — | — | — | — | ✔ |

The decorator rows (`cache`/`stage`) advertise their own serving surface and
forward the rest to the wrapped source; the per-export **effective** bitmap
(instance `caps`) is what the VFS dispatches on.

### 7.4 Degradation ladders (what the VFS does, once, for every absent cap)

- **Serving:** no `CAP_SENDFILE` → memory-backed chains via
  `file_pread`/`io_execute` (the same path TLS always takes). `CAP_MEMFILE`
  declares this is a supported, first-class serve.
- **Writing:** no `CAP_RANDOM_WRITE` → the writer's sequential staged path
  (§5.9); the composed stage tier restores full random-write PUT semantics
  for uploads in progress.
- **Rename:** no `CAP_HARD_RENAME` → the driver documents copy+delete
  semantics; `noreplace` still yields `EEXIST` correctness.
- **Copy:** no `CAP_SERVER_COPY` → seam-side stream-through.
- **Metadata:** NULL `setattr` → no-op success; NULL `truncate_path` →
  open+ftruncate+close; NULL `space` → `statvfs(2)`; NULL `enumerate` →
  namespace walk.
- **Namespace-on-loop:** a driver whose namespace ops are blocking network
  calls (object/origin backends) runs them via the offload tier rather than
  inline — the one place the upper VFS is allowed backend-*capability*-aware
  dispatch (never identity-aware).

### 7.5 Origin-driver namespace semantics (the type-probe contract)

Remote origins whose wire protocol is type-blind MUST NOT let that blindness
leak: `rmdir` on a non-collection is `ENOTDIR` (WebDAV `DELETE` deletes
whatever is at the URL — probe first); `rmdir` on a populated collection is
`ENOTEMPTY` (RFC 4918 makes collection DELETE recursive — recursion is the
VFS's decision, never the slot's); deleting an absent path is `ENOENT` (an
origin 404 is not success); `stat` MUST probe the real type when the cheap
call cannot distinguish a collection from an empty object (`PROPFIND
Depth: 0` vs `HEAD` — one extra RTT is the accepted price of a correct
answer). HTTP status mapping for origin slots: `207/2xx → ok`,
`404|409 → ENOENT`, `401|403 → EACCES`, `405|501 → ENOTSUP`, else `EIO`.

### 7.6 Transport injection (network drivers)

A network driver implements *protocol logic only* (signing, range math,
multipart sequencing, XML/PROPFIND parsing) over an **injected transport
vtable** — for S3, four functions:

```c
typedef struct brix_s3_transport_s {
    int (*request)(tctx, host, port, tls, method, path_and_query,
                   headers, body, body_len, timeout_ms, resp, errbuf, errcap);
    int (*resp_header)(resp, name, out, outcap);   /* 0 found / -1 absent */
    const void *(*resp_body)(resp, size_t *len);
    void (*resp_free)(resp);
} brix_s3_transport_t;
```

A non-2xx status is a *fact* in `resp->status`, never a transport failure.
The server injects its libcurl transport (from the cache layer, keeping
`backend/` free of libcurl deps); the client injects its own HTTP stack.
This is what makes one S3/HTTP implementation serve the module, the
cache-fill worker, and `xrdcp` byte-for-byte.

### 7.7 Conformance tiers for a backend

The mandate — *fully implemented as far as the storage model allows,
regardless of performance* — concretely:

- **MUST**: `name`; honest `caps` + `cred_accept`; `open`/`close`; `pread`;
  `fstat`; `stat`; errno-fact discipline; physical confinement (rule 2). A
  read-only backend rejects write intent at open with a truthful errno.
- **MUST if the storage model can express it** (absence allowed only when
  the model genuinely cannot): `pwrite`/`ftruncate`/`fsync`; the namespace
  family (`unlink`/`mkdir`/`rename` — synthetic directories count: see the
  ceph stripe-collapse listing); `opendir`/`readdir`/`closedir`; the staged
  family for any writable backend without `CAP_RANDOM_WRITE`; `setattr` for
  any mutable-metadata catalog; the `*_cred` twins for any driver that
  authenticates to a remote origin.
- **SHOULD**: `preadv`/`preadv2`; `read_sendfile_fd` (when `CAP_FD`);
  `truncate_path`; `server_copy`; the xattr family; `space`; `enumerate`
  (when a native catalog exists); `read_advise`.
- **MAY**: `copy_range`; `dedup_publish`/`dedup_gc`; `recall`/`residency`
  (nearline only).

Per-role targets when the driver serves in a composed stack (the tier
contract): a read-only *backend* needs `open`/`pread`/`stat`/`fstat` +
`RANGE_READ`; writable adds the staged family + `RANDOM_WRITE`; a
*cache_store* needs open/pread/stat/staged/unlink/dir-iteration/xattr with
`RANGE_READ|RANDOM_WRITE|DIRS|XATTR`; a *stage_store* needs
staged/open/pread/unlink/xattr with `RANDOM_WRITE|XATTR`; *nearline* adds
`recall` + `NEARLINE`.

Every implemented op ships the standard 3 tests: success + error +
security-negative; drivers additionally ship a standalone vtable-driven unit
suite (function-pointer harness, no server) covering every slot — pblock's
adds multi-thread + multi-process + async-interleave + fsync-durability legs
and is the reference for how thorough "thorough" means.

---

## 8. Composition: the backend registry and the tier stack

`src/fs/vfs/vfs_backend_registry.{h,c}` + `vfs_backend_config*.c` +
`src/fs/tier/`.

**Split lifecycle.** The backend *choice* is config-time; the *instance* is
per-worker and lazy (a SQLite connection cannot cross `fork`; librados
conns are per-process). Config parsing records
`{root_canon, driver, params}` via `brix_vfs_backend_config[_xroot|_http|
_s3|_str]()` (idempotent for reloads; `_str` dispatches `root://…` URLs vs
local driver names — one entry point for both stream and http config);
`brix_vfs_backend_resolve(root_canon, log)` builds/caches the composed
instance on first use in each worker. `NULL` resolve ⇒ default POSIX.
`brix_vfs_backend_resolve_for_path(abs_path, &root, log)` finds the export
for an absolute path by longest-prefix match (staged-commit needs it).

**Credentials & staging on the stack:** `brix_vfs_backend_set_credential`
attaches the export's *upstream service* credential
(`brix_vfs_backend_cred_t`: bearer / x509_proxy(+key)+ca_dir / s3 triple /
sss_keytab — each backend build reads only its scheme's fields; all-unset =
anonymous); `brix_vfs_backend_set_staging` marks write-back promotion vs
Mode-A passthrough. These are the *export's* legs; the *user's* legs come
through §9 and always win where present.

**Tier grammar** (`<scheme>:<location> [credential=<n>] [block_size=<n>]`):
scheme→driver dispatch is the census table (`posix|block|pblock|root[s]|
http[s]|webdav|davs|s3|rados|ceph|tape|frm`), producing a
`{backend, cache_store, stage_store}` stack composed as
`stage(cache(source))` with policy structs (cache: max object, watermarks,
verify mode, include/allow/deny, slice size, dirty age; stage: sync/async
flush + decision fn). Composition rules: nearline source ⇒ cache tier
REQUIRED; a gap between a tier's required slots/caps and the driver's actual
surface is reported as a named development-status gap, not silently
tolerated.

**Observability of the composition:** `brix_vfs_backend_export_count()` /
`_export_info(i)` snapshot every export's `{root, backend, host:port, tls,
staging, has_token, has_proxy}` for the `/metrics` storage-backend info
gauge; `brix_vfs_backend_http_endpoint[_at]()` exposes an http backend's
origin endpoint(s) for protocol-side uncached passthroughs (CVMFS
geo/manifest) that must address the same origin the tier fills from;
`_register_http_upstream()` is the runtime twin for per-upstream proxy-mode
exports.

---

## 9. Authentication schemas through the interface

The VFS is the single place where "who the caller is" meets "how we talk to
storage". Every schema — GSI/X.509, WLCG bearer, S3 SigV4 (incl. STS),
Kerberos/GSSAPI, sss, unix, host, password — flows through the same five
stages.

### 9.1 Stage 1 — front door → identity

Protocol authentication produces the `brix_identity_t` (§4.2) and the
protocol-layer authorization verdict (`allow_write`, token scopes, ACLs,
gridmap). The front end stamps both onto the ctx. The VFS enforces
`allow_write` as the fail-closed backstop (A7) but never re-runs protocol
authorization.

### 9.2 Stage 2 — local enforcement identities

Two backend-side consumers use identity *without* any forwarded secret:
**impersonation** (the confined helpers route syscalls to the privileged
broker, which acts as the grid-mapped local user under the export rootfd —
this is also why separate domains stay raw, A10), and **`CRED_IDENTITY`
backends** (pblock's catalog-internal ownership registry consumes
principal + VO list only — no credential directory needed).

### 9.3 Stage 3 — SELECT: pre-provisioned per-user credentials

When the export configures a credential directory, the gate derives a
filesystem-safe key from the canonical principal (DN preferred over
subject): verbatim for principals matching `[A-Za-z0-9@._-]{1,64}` **with a
rejected leading `.`** (the `..`-traversal fix — unsafe principals fall to
the always-safe `x5h-<sha256>` form), then selects by precedence:
`<key>.pem` (x509 proxy, expiry via `X509_cmp_current_time`) →
`<key>.token` (WLCG bearer) → `<key>.s3` (SigV4 triple) → `<key>.keyring`
(CephX). Anti-downgrade: an **expired** `.pem` hard-declines rather than
falling through — a lapsed strong credential must never silently become a
weaker accepted one. `fallback_deny=1` turns a miss/decline into `EACCES`
with the origin untouched.

### 9.4 Stage 4 — delegation: the live-cred bag (captured forwardable bytes)

When the front door captured forwardable material, `brix_vfs_deleg_bind`
attaches the bag: raw bearer text and/or a user-supplied full x509 proxy
PEM, plus the export's resolved mode:

| `brix_cred_mode` | Meaning |
|---|---|
| `SELECT` (0, default) | §9.3 directory lookup — every zeroed struct keeps its pre-delegation meaning |
| `PASSTHROUGH` | replay the exact user credential: bearer bytes verbatim; a proxy PEM is **re-verified against the export's CA store in-gate** (RFC-3820 chain trust — a self-asserted DN is not proof) and materialised 0600 |
| `EXCHANGE` | trade the inbound credential for a backend-valid one: RFC-8693 token exchange (endpoint/client/audience + per-worker minted-token cache), S3 STS AssumeRole/GetSessionToken (short-lived ak/sk/session scoped to the caller), or krb5 GSSAPI TGT forwarding (async-safe 0600 FILE ccache path + origin service principal; the origin leg re-imports and negotiates AS the caller) |
| `DELEGATE` | obtain a fresh short-lived proxy via the GridSite handshake |
| `MINT` | mint from the local CA (§9.5) |
| `AUTO` | dispatch by `identity->auth_method` |

No-captured-bytes **injection**: `set_sss` (assert the caller's principal via
an XrdSecsss credential signed with the gateway keytab) and `set_sts`
allocate the bag exactly when `deleg_bind` declined (nothing to bind).
Proven bytes always win over injection; every degradation lands on SELECT.

### 9.5 Stage 4b — MINT: bearer-only identities gaining x509

When armed (`ctx_bind_backend_mint`, HTTP data-plane sites only) and no
valid `<key>.pem` exists, the gate mints an EC P-256 keypair + X509 signed
by the operator's mint CA — atomic temp+fsync+rename into
`<cred_dir>/<key>.pem`, reused while it has life left. The origin must
trust the mint CA: minting deliberately shifts a slice of trust-root
authority to the frontend, which is why it is opt-in and never reachable
from the `root://` stream.

### 9.6 Stage 5 — the seam: `brix_sd_cred_t` and `cred_accept`

The gate reduces every schema to ONE record carrying exactly ONE kind:

```c
typedef struct {
    /* exactly one kind's fields set; the rest NULL */
    const char *x509_proxy;                    /* path to per-user proxy PEM */
    const char *bearer;                        /* raw WLCG JWT text          */
    const char *s3_ak, *s3_sk, *s3_region;     /* SigV4 triple               */
    const char *s3_session;                    /* STS X-Amz-Security-Token   */
    const char *ceph_keyring, *ceph_user;      /* CephX                      */
    const char *sss_keytab;                    /* SSS identity injection     */
    const char *krb5_ccache, *krb5_princ;      /* forwarded-TGT FILE ccache  */
    /* audit + async re-resolve */
    const char *key, *principal, *vos, *cred_dir;
    enum brix_cred_mode mode;
    unsigned    fallback_deny:1;
} brix_sd_cred_t;
```

Drivers declare accepted kinds in `cred_accept`
(`BEARER | PROXY_PEM | IDENTITY | SSS | S3 | GSS_KRB5`); the VFS denies
`EACCES` **before touching the origin** when the live kind is not accepted.
Declared masks today: `xroot` = BEARER|PROXY_PEM|SSS|GSS_KRB5;
`http` = BEARER|PROXY_PEM; `remote`(S3) = BEARER|PROXY_PEM|S3;
`pblock` = IDENTITY; posix/block/frm/ceph = none (ceph consumes SELECT-path
keyring creds via `open_cred` without advertising delegation kinds).

Dispatch mechanics: the `brix_sd_<op>_maybe_cred` forwarders route through
the `_cred` slot when a cred is present AND the driver implements it, else
the plain slot; **cred-scoped dispatch unwraps decorators to the leaf**
(`brix_vfs_ns_leaf`) so a stage/cache-composed export authenticates its
origin leg as the user, not the service. The decorators embed the
re-resolvable identity (`key`/`cred_dir`/`fallback_deny` — appended to the
durable journal record, size-tolerant decode for pre-feature journals) so an
async or post-crash flush re-resolves and re-checks expiry **at the moment
bytes move**; a permanently denied flush dead-letters rather than looping or
downgrading.

### 9.7 Requirements

- A front end MUST capture and bind whatever forwardable material its schema
  can produce, at every data-plane site — the enumerated misses (MOVE, COPY,
  CopyObject, LOCK xattrs, offloaded GET) are the §5.6 warning made
  specific.
- A remote-origin driver MUST implement `open_cred`/`staged_open_cred` and
  the `*_cred` namespace twins for every kind it accepts, and MUST copy
  borrowed strings before deferring.
- A new schema plugs in by: mapping to `brix_identity_t` (+ an `AUTHN` bit),
  choosing its forwardable form (bytes → PASSTHROUGH; exchangeable →
  EXCHANGE; nothing → SELECT/injection/MINT), extending `brix_sd_cred_t`
  with its kind's fields, and adding the kind bit — the gate, forwarders,
  deny logic, and audit plumbing are already schema-neutral.

---

## 10. Error model

| Fact | Producer | Meaning / required mapping |
|---|---|---|
| `NGX_OK` / `NGX_ERROR` + `errno` | every entry point | success / failure with the syscall-truth errno |
| `NGX_DECLINED` | `probe` (absent), `space` (no slot), `enumerate` (`ENOTSUP`), `backend_mkpath` (default-POSIX export), cache open (miss) | "not an error — take the documented fallback" |
| `NGX_DONE` | `readdir` family | end of stream |
| `NGX_AGAIN` | `recall` | recall queued/in-flight — park the open |
| byte count / `-1`+`errno` | pread/pwrite/xattr get/list | POSIX-style; `-1`/`ERANGE` = buffer too small (xattr) |
| `EXDEV` from a confined op | path/beneath layer, drivers | **escape attempt** → kXR_NotAuthorized / 403 |
| `EACCES` | write gate, cred gate | fail-closed policy denial |
| `EEXIST` (+`was_dir`) | rename/commit `excl` | kXR_ItExists vs kXR_isDirectory; HTTP 412 |
| `EINVAL` | confinement guard; writer out-of-order extent | guard failure / sequencing error (distinguishable via `expected_off`) |
| `ENOTSUP` | capability-refused op; unarmed dedup; no catalog | map to kXR_Unsupported / 501; surfaced via metric, never silently emulated |
| `ENOENT`, `ENOTEMPTY`, `ENOTDIR`, `ENOSPC`, `EIO`, … | drivers | verbatim facts |

Reference protocol mapping (owned by the front ends; the canonical table
lives in the extended agent guide): `ENOENT → kXR_NotFound / 404`;
`EACCES`/`EPERM → kXR_NotAuthorized / 403`; `EINVAL → kXR_ArgInvalid / 400`;
`EIO → kXR_IOError / 500`; `ENOMEM → kXR_NoMemory / 507`.

The observers restore the caller's `errno` after metric/log emission — rely
on the documented errno, never on globals surviving the observability call.

---

## 11. Observability model

**Vocabulary** (`brix_metric_op_t`): `OP_READ`, `OP_WRITE`, `OP_STAT`,
`OP_DELETE`, `OP_MKDIR`, `OP_RENAME`, `OP_DIRLIST`, `OP_TPC`, `OP_XATTR`,
`OP_COPY` — ten ops, attributed to a `brix_proto_t` and (at serve time, via
`brix_vfs_file_backend_name`) a backend.

**Mechanics.** Every metered entry point brackets its body with a
`brix_vfs_now_ns()` start stamp and one call to:

```c
brix_vfs_observe_ctx_op (ctx, path, op, result, bytes, rc, sys_errno, start_ns);
brix_vfs_observe_file_op(fh,        op, result, bytes, rc, sys_errno, start_ns);
```

which emit `brix_metric_op_done()` + `brix_access_log_emit()` (op, byte
count, latency, an `brix_err_class_t` derived from errno) and restore the
caller's errno.

**Rules.** One metric per metered op, emitted by the VFS, never by the
handler (A8). Non-metered variants (`probe`, `opendir_quiet`, the raw tier,
`truncate`/`sync` under an enclosing write op) exist so the operational
picture stays truthful — a pre-op resolution stat is *not* a client stat,
and a 10 000-directory listing is *one* list operation. Cache outcomes are
translated exactly once, at the open orchestrator, from the object's
`cache_outcome` stamp; eviction bytes at the adopt site from
`cache_evicted_bytes`. Metric labels stay low-cardinality (invariant 8): op,
proto, backend, error class — never paths or principals.

---

## 12. Threading & memory model

| Surface | Thread | Pool | Metrics |
|---|---|---|---|
| metered `brix_vfs_*` (open/stat/dir/ns/xattr/copy/staged/writer open+commit) | event loop ONLY | `ctx->pool` | yes (once) |
| `brix_vfs_io_execute` + job PODs | any (AIO pool / io_uring fallback / inline) | none — POD + caller buffers | no |
| `brix_vfs_pread_full`/`pwrite_full`, `file_pread`/`file_pwrite`, `probe` | any | none | no |
| `brix_vfs_open_fd(_at)`, `*_path`, `walk`, `copyfile`/`copytree` | any | none | no |
| SD raw byte slots + `staged_write` | any | none | no |
| SD instance/namespace slots | per driver contract (loop unless documented worker-safe; origin/object ns ops offloaded) | instance pool / malloc | no |
| dedup verbs, cache-fill bodies | cache-fill worker threads | malloc-owned state | no |

Memory rules: handles live on the request pool; handle fds are closed by
explicit `brix_vfs_close` (the pool does NOT own them) — but the pool DOES
own the `dup`'d sendfile fd via `ngx_pool_cleanup_file`, decoupling handle
close from in-flight sendfile bufs. Driver objects adopted by value free
their `heap_shell`; pointer-held objects release via
`brix_sd_obj_release`. Read/write bound I/O against the handle's cached
`size` — a file grown by another writer is seen on reopen. Instances built
on cache-fill threads are malloc-owned (never `ngx_cycle->pool`, which is
thread-unsafe). Blocking calls MUST NOT run on the event loop on hot paths;
new blocking syscalls in the VFS are AIO-offload candidates by default.

---

## 13. Conformance checklists

**A new front-end protocol** MUST:
1. resolve every client path through `src/fs/path/` before touching the VFS;
2. populate the ctx per §5.1 (identity, proto, roots, flags) and bind
   credential policy at data-plane sites;
3. call only `brix_vfs_*` for export paths (A2) — including probes, xattrs,
   and off-loop bulk work (the `_path`/`walk` tier);
4. serve bytes respecting the TLS/sendfile fork gated on `can_sendfile`
   (§6.2);
5. use `probe`/`opendir_quiet`/`readdir_kind` for resolution and bulk walks
   (§11);
6. map errno facts to its own wire codes (§10) and treat `EXDEV` as 403;
7. never emit its own per-op data-plane metrics;
8. for writes, use the writer/staged sessions and respect the
   out-of-order/`expected_off` contract.
Doing this — and nothing more — buys confinement, caching, observability,
per-user backend auth, tape, dedup, and every current and future backend.

**A new backend driver** MUST: live in `src/fs/backend/<name>/`; implement
§7.7's tiers; advertise honest caps + `cred_accept`; enforce physical
confinement below the seam (rule 2) and keep physical locators there;
register in `fs_list.h`, `sd_registry.c`, and the build lists (top-level
`./config`; `shared/xrdproto/Makefile` if client-shared — then it must
compile under `-DXRDPROTO_NO_NGX`); re-run `./configure`; and ship the
standalone vtable unit suite + 3 tests per op. Build-gated drivers (`ceph`,
`pblock`) MUST leave a no-dependency build byte-for-byte unchanged.

**A new VFS operation** MUST: declare in `vfs.h`/`vfs_ops.h`; implement in a
focused `vfs_<op>.c`; guard with `require_confined`/`require_write` as
appropriate; delegate to `brix_ns_*`/driver slots, never raw syscalls; wrap
in `brix_vfs_observe_*` with the right `BRIX_METRIC_OP_*` (or document why
it is non-metered); register the TU in `./config`; carry 3 tests.

**A new authentication schema** MUST follow §9.7.

---

## 14. Enforcement

The contract is machine-checked; green guards are part of the definition of
done:

| Guard | Enforces |
|---|---|
| `tools/ci/check_vfs_seam.py` **tier-1** | no raw positional byte syscalls (`pread`/`pwrite`/`preadv*`/`pwritev*`/`copy_file_range`/`sendfile`) outside `src/fs/backend/` — HARD, no backlog, markers deliberately ignored; comments/strings stripped before matching |
| **tier-2** | no handler calls the confined-helper layer (`*_confined_canon`/`_beneath`, `brix_ns_*`) or the SD vtable directly instead of `brix_vfs_*` (backlog `vfs_seam_backlog.txt`, held at 0) |
| **tier-3** | no unmarked raw namespace/metadata syscall (`open`/`stat`/`opendir`/`unlink`/`rename`/`mkdir`/`truncate`/`chmod`/xattr) on storage in handler code — the `vfs-seam-allow` marker is grepped on the raw line *before* comment-stripping, the syscall matched *after*, so a name in a comment is never a false hit (backlog `vfs_seam_backlog_ns.txt`, held at 0) |
| `tools/ci/check_vfs_identity_branch.py` | the VFS branches only on caps/slot presence, never backend identity (A3) |
| `shared/xrdproto/check-ngx-free.sh` | `libxrdproto.a` contains zero `ngx_` symbols (`nm` inspection of the archive) |
| `check_config_coverage.py` / `check_client_build_coverage.py` | every new TU is registered in the right build list |

`--regen` on the seam guard re-snapshots backlogs after a **deliberate**
migration only — never to clear red CI. A raw call that is *correct*
(separate svc-owned domain, non-export resource — A10) carries the same-line
`/* vfs-seam-allow: <reason> */` marker; the `TIER3_ALLOW` list
wholesale-excludes the below-seam layers (`fs/`, `path/`, `compat/`,
`impersonate/`) and the separate-domain stores. Do not "fix" a marked raw
call by routing it through `brix_vfs_*` — read A10 for why that is a
regression.
