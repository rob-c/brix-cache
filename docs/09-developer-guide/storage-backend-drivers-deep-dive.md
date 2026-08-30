# Storage Backend Drivers — Deep Dive (`pblock`, `s3`, remote `root://`)

> **Audience:** developers extending the storage layer or the read-through cache.
> **Scope:** the Storage Driver (SD) seam and every concrete driver — local
> (`posix`, `block`, `pblock`, `rados`), object (`s3`), and the two read-only
> *remote-origin* drivers used by the cache (`remote` = S3 origin, `xroot` =
> `root://` origin) — plus how the cache fronts them as one origin-agnostic
> "fold". Captures the architecture **and** the hard-won lessons from building
> them.
> **Companion docs:** [`storage-driver-slot-matrix.md`](storage-driver-slot-matrix.md)
> (the 52-slot × 11-driver matrix with a verdict for every empty cell — read that
> to find out whether a verb is available on a given backend, and this one to find
> out how it works), [`pblock-storage-backend.md`](pblock-storage-backend.md),
> [`vfs-shared-architecture.md`](vfs-shared-architecture.md),
> [`src/fs/backend/README.md`](../../src/fs/backend/README.md),
> [`src/fs/cache/README.md`](../../src/fs/cache/README.md).

---

## 0. TL;DR

Everything above the storage layer — `root://`, WebDAV, S3 REST, the cache — talks
to **one narrow interface** (`brix_sd_driver_t`, the **Storage Driver / SD
seam**). Below it, a driver decides *how* bytes and names physically live:

| Name | Folder | Kind | Bytes live as | Namespace | Caps highlight |
|---|---|---|---|---|---|
| `posix` | `backend/posix/` | registry driver | files on a confined FS | the FS itself | everything |
| `block` | `backend/block/` | registry driver | a raw block device | none (single object) | FD + range |
| `pblock` | `backend/pblock/` | registry driver | **fixed-size block files** | **SQLite catalog** | everything (POSIX-parity) |
| `rados` | `backend/rados/` | registry driver | RADOS objects | flat key map | range/random/trunc |
| `sd_s3` | `backend/s3/` | **protocol library** | S3 objects (HTTP) | bucket/key | range read · multipart write · **object metadata** (get/set + advisory) |
| `remote` | `backend/remote/` | **cache-constructed** | a remote S3 origin (read-only) | bucket/key | **range read only** |
| `xroot` | `backend/xroot/` | cache-constructed **+ selectable primary** | a remote `root://` server | origin namespace | range read **+ write** (transparent write-through) |

Three distinct kinds sit behind the seam:

- **Registry drivers** (`posix`/`block`/`pblock`/`rados`) — selectable as an export
  primary via `brix_storage_backend`; listed in `sd_drivers[]` (`sd_registry.c`).
- **`sd_s3`** — NOT a registered `brix_sd_driver_t`; it is the shared S3 *protocol
  handle library* (`sd_s3_open_read`/`size`/`pread`/`write`/`commit`). The client's
  S3 VFS and the module's `remote` driver both wrap it.
- **Cache-constructed drivers** (`remote`/`xroot`) — built on demand by the cache
  (`brix_sd_remote_create` / `brix_sd_xroot_create`) for read-through fill.
  `remote` (S3) is read-only. `xroot` is **also a registry-selectable primary**
  (`brix_storage_backend root://host:port`) with read **and** write (transparent
  write-through to the remote server) — see §1.1 n.⁵.

One subdirectory per driver; the **shared seam** (`sd.h`), the **registry**
(`sd_registry.c`), and the integrity tagstore (`csi_*`) stay at `backend/` top
level.

```
                          proto handlers (root:// / WebDAV / S3 / cache)
                                          │
                                          ▼
                         VFS  (src/fs/)  — policy: confinement re-check,
                          │               metrics, access log, page-CRC,
                          │               buffer shaping, the CACHE
                          ▼
        ┌──────────────── SD seam  (brix_sd_driver_t, src/fs/backend/sd.h) ───────────────┐
        │  open close pread pwrite preadv fstat | stat unlink mkdir rename opendir readdir   │
        │  getxattr setxattr … | staged_open staged_write staged_commit staged_abort         │
        └───────┬───────────┬──────────┬──────────┬──────────┬──────────┬──────────┬─────────┘
                ▼           ▼          ▼          ▼          ▼          ▼          ▼
             posix       block      pblock      rados        s3       remote      xroot
            (local FS) (blk dev) (blocks+DB) (librados)  (HTTP/S3) (S3 origin) (root:// origin)
```

The golden rule (CLAUDE.md invariant #11): **all data byte I/O lives ONLY below
this seam.** Nothing above a driver issues `pread`/`pwrite`/`sendfile` on export
data — it calls a driver slot. The VFS owns all the EINTR/short-I/O/coalescing
policy; the driver slots are single, verbatim operations.

---

## 1. The SD seam — types & capabilities

Three opaque handles thread through every driver (`src/fs/backend/sd.h`):

```
brix_sd_instance_t   one per export/role   { driver, log, pool, state }
   │                                                              │
   │ driver->open(inst, key, flags, mode, &err)                  (driver-private:
   ▼                                                              POSIX: rootfd+root_canon
brix_sd_obj_t        one per open file      { driver, inst,     pblock: catalog handle
   │   fd      = real kernel fd OR NGX_INVALID_FILE (-1)          s3/remote: endpoint+creds)
   │   snap    = brix_sd_stat_t captured at open
   │   state   = driver-private per-open (object key, S3 handle, origin conn…)
   │   heap_shell = 1 if open() malloc'd THIS shell (caller frees the copy)
   ▼
brix_sd_staged_t     atomic write-then-publish { inst, state }
       staged_open → staged_write(off) … → staged_commit | staged_abort
```

**Capabilities are honest absences**, not lies. A driver advertises only what it
truly has; the VFS degrades or rejects gracefully on the rest:

```
 bit  CAP_…            meaning                              posix block pblock rados s3* remote xroot
  0   FD               exposes a real kernel fd               ✓    ✓    ✓(blk0)  ·   ·    ·     ·
  1   SENDFILE         CAP_FD + zero-copy sendfile-able       ✓    ✓    ✓(blk0)  ·   ·    ·     ·
  2   RANDOM_WRITE     pwrite at arbitrary offset             ✓    ✓     ✓       ✓   ·    ·     ✓
  3   RANGE_READ       pread at arbitrary offset              ✓    ✓     ✓       ✓   ✓    ✓     ✓
  4   TRUNCATE         ftruncate                              ✓    ·     ✓       ✓   ·    ·     ✓
  5   SERVER_COPY      native copy (copy_file_range/COPY)     ✓    ·     ✓       ·   ·    ·     ✓ᵃ
  6   XATTR            user.* xattrs / object metadata        ✓    ·     ✓       ·   ·    ·     ✓ᵃ
  7   HARD_RENAME      atomic rename (else copy+delete)       ✓    ·     ✓       ·   ·    ·     ✓ᵃ
  8   DIRS             real directories (else key-prefix)     ✓    ·     ✓       ·   ·    ·     ·
  9   APPEND           O_APPEND semantics                     ✓    ·     ✓       ·   ·    ·     ·
 10   IOURING          fd is io_uring-submittable             ✓    ✓    ✓(blk0)  ·   ·    ·     ·
 11   FSCS             filesystem page checksums (CSI)        ✓    ·     ·       ·   ·    ·     ·
```

> `ᵃ` — `xroot` (remote `root://` primary) **forwards** these to the origin: xattr
> via `kXR_fattr` (get/set/list/del), rename via `kXR_mv`, server-copy as a gateway
> read+write relay (not a remote zero-copy/TPC), and vectored read via per-segment
> `preadv`. The origin wire helpers live in `src/fs/cache/origin_protocol.c`
> (`brix_cache_origin_{getfattr,setfattr,listfattr,delfattr,rename}`). E2E:
> `tests/run_remote_backend_meta.sh`. **Namespace:** the kXR_fattr handler maps a
> user attr `X` to the on-disk key `user.U.X` *above* the VFS; since the origin
> re-applies the same mapping, `sd_xroot` **strips** one `user.U.` before forwarding
> get/set/del and **re-adds** it on list — so the origin carries a single, standard
> `user.U.X` and a direct-origin client sees the same name (interoperable). Names
> from other consumers (webdav locks/dead-props, s3 tags) carry no `user.U.` prefix
> and pass through unchanged.

> `s3*` — `sd_s3` is a handle library with no caps bitmap of its own; the column
> shows what its read/write API *supports* (range read, plus single-PUT/multipart
> write, **plus object metadata** get/set + advisory POSIX attrs — see §1.1 and
> §3.3). In the cache it is surfaced read-only through the `remote` driver, whose
> advertised caps are `CAP_RANGE_READ`.

> **Lesson — read-only by absence.** As first shipped, the `remote` (S3 origin)
> driver populated ONLY `open/close/pread/fstat/stat` and advertised
> `CAP_RANGE_READ` alone. Because every write/dir/xattr/staged vtable slot was
> `NULL`, it *could not* be selected as a writable export primary — the safety was
> structural, not a runtime check. **This is history, not the current shape:**
> phase-92 finding #4 filled the namespace, staged-write and metadata slots (see
> n.⁴), so the structural read-only property is gone and the caps are now what
> gates the driver. The lesson to keep is the mechanism — an absent slot is a
> hard, unbypassable "no" — not the claim about this particular driver.

### 1.1 Metadata & namespace support — what's supported where

The CAP bits above cover byte I/O and the structural shape. This matrix is the
metadata/namespace **phase-space** every access method can reach through the VFS
(`stat`, directories, `rename`, **xattr**, **setattr** = chmod/utime/owner) — the
key question when picking a backend for a site. `✓` = native; `adv` = *advisory*
(stored in a reserved slot, overlaid on `stat`, **not enforced** by the store);
`—` = unsupported (the VFS rejects or no-ops per the slot contract).

| backend | stat | dirs (mkdir/list) | rename | xattr get/set/list | setattr (mode/utime/owner) | staged write |
|---|---|---|---|---|---|---|
| `posix` | ✓ | ✓ | ✓ atomic | ✓ `user.*` | ✓ | ✓ |
| `block` | ✓ (1 object) | — | — | — | — | — |
| `mirage` (synthetic)⁰ | ✓ (fixed size) | — | — | — | — | — |
| `pblock` | ✓ | ✓ | ✓ atomic | ✓ | ✓ | ✓ |
| `ceph` (librados)¹ | ✓ | synthetic² | copy+delete | ✓ object xattrs | — | ✓ |
| **`sd_s3`** (object store)³ | ✓ HEAD | key-prefix | CopyObject | ✓ `get_meta`/`set_meta` | adv | ✓ multipart |
| `remote` (S3 cache origin)⁴ | ✓ HEAD | markers⁴ | copy+delete | ✓ `user.*`⁴ | adv⁴ | ✓ multipart |
| **`xroot`** (remote root:// primary)⁵ | ✓ | follow-on | ✓⁵ | ✓⁵ | mode only⁶ | ✓⁵ |
| `http` (WebDAV origin)⁷ | ✓ `PROPFIND` | ✓ `MKCOL`/`PROPFIND` | ✓ `MOVE` | ✓ dead props⁷ | — | ✓ `PUT` |

⁰ **`mirage`** (`brix_storage_backend mirage:<size>`, parity audit §3 row 14): the
sizes-only SYNTHETIC backend — stores nothing, makes no syscalls; every path is a
read-only regular file of the configured size whose bytes are the deterministic
offset pattern `(o*131+7)&0xFF`. Protocol/throughput testing with zero storage
behind the export; write-intent opens are `EROFS`. `tests/test_mirage_backend.py`.
¹ Two layers. The **wired** `sd_ceph` driver (gated `BRIX_HAVE_CEPH`) is plain
librados: range read / random write / truncate (`ftruncate` **and** the
path-native `truncate_path` over `rados_trunc`), object xattrs, staged write, a
synthetic directory namespace, copy+delete rename, catalog enumeration and
cluster capacity. `setattr` stays absent — RADOS keeps no mode/owner/times, and
an advisory blob here would report an enforcement the pool does not provide.
**Credential scope:** `open_cred` takes a per-user CephX keyring, and every
namespace slot it can honestly scope has a `_cred` twin (`stat`, `unlink`,
`truncate_path`, the four xattr ops, `opendir`); `rename_cred`,
`staged_open_cred` and `mkdir_cred` are deliberately absent for the reasons in
§4.10. The **stock-XrdCeph libradosstriper path** (the
striper data plane, site `lfn2pfn` translation, stripe helpers, advisory codec, and
the striper xattr wrappers — `sd_ceph_striper.c`, `site_n2n.c`,
`sd_ceph_compat.c`, `meta_advisory.c`, gated `BRIX_HAVE_RADOSSTRIPER`) is **built
and unit-tested but not yet wired into the live vtable**; final integration +
live-pool validation (and the exact site `lfn2pfn` rule) is the open follow-on.
² directories are **synthetic** (phase-89 ADR-1: no marker objects) — a
directory exists iff an object lives under its prefix, so `mkdir` touches
nothing and `opendir` of an empty non-root prefix is `ENOENT`, exactly as on S3.
³ **`sd_s3` object metadata** (`src/fs/backend/s3/sd_s3.c`): `sd_s3_get_meta` reads
an `x-amz-meta-<name>` header (signed HEAD); `sd_s3_set_meta` rewrites the user
metadata via a copy-onto-self with `x-amz-metadata-directive: REPLACE`
(`sd_s3_sign_ext` signs the extra `x-amz-*` headers, so it works against real AWS).
The advisory POSIX-attr blob rides in `x-amz-meta-xrd-unixattr`
(`sd_s3_get/set_unixattr` ↔ `meta_advisory.c`). E2E: `tests/run_sd_s3_meta.sh`.
⁴ the `remote` (S3) driver began as a read-only **byte fill** source; phase-92
finding #4 gave it the namespace and metadata surface an `s3://` *export* needs.
Directories are zero-byte `path/` marker objects (S3 has no directories), rename
is copy+delete (S3 has no atomic move, and a non-empty prefix is `ENOTSUP`), and
the `user.*` xattr surface maps onto `x-amz-meta-*` — every mutation a
read-merge-**rewrite** of the object's whole user-metadata set, since S3 has no
in-place metadata edit. `setattr` (chmod/utime/owner) is *advisory*: it patches
the reserved `x-amz-meta-xrd-unixattr` blob that overlays `stat`, because an
object store enforces none of it. **Credential scope:** every slot has a `_cred`
sibling that signs with the requesting user's SigV4 keys and refuses an unusable
credential (`EACCES`) under `fallback_deny` — including the two metadata READ
slots and the directory listing, whose absence is described in §4.1.1.
⁵ **`xroot` as a writable primary backend** (`brix_storage_backend
root://host:port`): the export's storage IS a remote XRootD server. The byte data
path is done — **stat + read + write** (`pwrite`/`ftruncate`/`fsync` over
kXR_write/_truncate/_sync) — so a write streams straight through to the origin
(**transparent write-through, no local copy**) and a read serves from it. This
required teaching the kXR handle path (and `brix_vfs_file_stat`, the WebDAV lock
pre-check) to accept a **no-fd (memory-served) primary** (additively, gated on
`sd_obj.driver`), since no object/remote backend had ever been a root:// *primary*
before. **Staged-write** (WebDAV PUT / S3 POST) works two ways:
**(a) Mode A — passthrough** (default): `staged_open/write/commit` stream the body
straight to the remote final path (no local copy; non-atomic on the remote).
E2E: `tests/run_remote_backend_write.sh` (root://), `tests/run_remote_backend_webdav.sh`
(WebDAV). **(b) Mode B — write-back** (`brix_webdav_storage_staging on`): the upload
stages to a LOCAL POSIX temp under the export root (fast, random-write, atomic), then
`brix_vfs_staged_promote()` reads it and drives the driver's staged path to the remote
on commit, dropping the local temp. E2E: `tests/run_remote_backend_staging.sh`.
Namespace (mkdir/rename), remote-side atomicity + a durable
journal + backpressure on Mode B are later phases — see
`docs/superpowers/specs/2026-06-29-writable-remote-root-staged-write-design.md`.
**Anonymous** origin only (the in-process wire client's mode); authenticated origins
use Mode B / the native-client path. Recommend a `thread_pool` on the node (the remote
write offloads to AIO).
⁶ `setattr` applies the **mode** group over `kXR_chmod`; `set_times`/`set_owner`
are accepted and ignored (the opcode for those is this project's negotiated vendor
extension, which a stock origin does not implement). Before the slot existed the
VFS reported a `chmod` over a `root://` export as successful without sending
anything — see §4.8.
⁷ the `http` (WebDAV/`davs://`) origin driver. Its xattr surface is RFC 4918 §15
**dead properties**, one per xattr, with the name AND the value hex-encoded so
that remote-chosen bytes can never reach the XML body as markup — total,
reversible, and opaque to a native WebDAV client by design. `PROPPATCH` is an
unconditional upsert, so `XATTR_CREATE`/`XATTR_REPLACE` and the POSIX "removing an
absent attribute is `ENODATA`" contract are each bought with a preceding
size-enquiry read; an origin that keeps no dead properties answers `ENOTSUP`, not
a namespace error. `setattr` has no WebDAV spelling at all and stays absent (an
honest NULL slot, per lesson 1). Every slot has a `_cred` twin. See §4.9.

> **Two ways a remote `root://` filesystem gets full metadata.** (a) The
> **transparent proxy** (`brix_proxy`) relays *every* opcode to the origin by
> raw `requestid` — so a proxied remote `root://` already supports the **whole**
> phase-space (mkdir/stat/chmod/mv/rm/xattr), live, not via the cache drivers.
> Proof: `tests/run_proxy_metadata_phase.sh`. (b) The **cache** drivers
> (`remote`/`xroot`) front an origin for *byte* reads only; they do not forward
> metadata (that would need a metadata-aware cache, a separate concern).

> **The S3 REST endpoint is metadata-capable.** The S3 server
> (`src/protocols/s3/usermeta.c`) persists `x-amz-meta-*` user metadata (one
> `user.s3.usermeta` xattr blob beside the object) on PutObject/CopyObject and
> echoes it on GET/HEAD, honouring `x-amz-metadata-directive: COPY|REPLACE`
> (REPLACE-onto-self = a metadata-only update, no byte rewrite). This is the live
> endpoint `sd_s3`'s get/set-meta validate against. E2E: `tests/run_s3_usermeta.sh`.

### `fd == NGX_INVALID_FILE` is normal

A backend without a kernel fd (S3, remote, pure object store) returns
`obj->fd == -1`. The VFS asks `driver->read_sendfile_fd(off,len,want_zerocopy)`;
a `-1` answer means **"serve memory-backed"** — the VFS `pread`s into a buffer
and emits a memory `ngx_buf_t` instead of a `sendfile()` file buffer. This is the
single switch that lets an object store coexist with the zero-copy POSIX path.

```
   VFS read path
   ┌─────────────────────────────────────────────┐
   │ fd = driver->read_sendfile_fd(off,len,zc)?   │
   │   fd >= 0 ─────────► sendfile(fd)  (zero-copy, cleartext)
   │   fd == -1 ────────► driver->pread → memory ngx_buf_t (TLS / object store)
   └─────────────────────────────────────────────┘
```

---

## 2. `pblock` — block-striped data + a SQLite catalog

`pblock` ("pseudo-block") is a **full POSIX-parity** backend that stores data
nothing like POSIX. It is the proof that an arbitrary physical layout can be a
first-class export.

### 2.1 Physical layout

```
  logical object "/atlas/run42.root"   (size = 150 MiB, block_size = 64 MiB)
        │
        │  catalog: name → blob_id "10fef0…", size, mtime, mode, block_size
        ▼
  <root>/catalog.db          ← SQLite: tables objects(namespace+stat+blob) , xattrs
  <root>/data/10/fe/10fef03de7e134fdb3444f63843cde36/
                              ├── 0   ← bytes [0          , 64 MiB)   (64 MiB file)
                              ├── 1   ← bytes [64 MiB     , 128 MiB)  (64 MiB file)
                              └── 2   ← bytes [128 MiB    , 150 MiB)  (22 MiB file)
       └──┬──┘└┬┘ └──────────────┬───────────────┘ └┬┘
        aa   bb         blob_id (hex)               block index
   (2-level fan-out keeps any one dir small)
```

- **`block_size` is recorded PER FILE at creation** — retuning the export default
  only affects new files; old files keep reading correctly.
- **Block 0 is opened as a persistent real fd** → `pblock` advertises
  `CAP_FD`/`SENDFILE`/`IOURING` and zero-copy-sendfiles offset-0 ranges that fall
  inside the first block. Higher blocks are opened transiently per I/O.

### 2.2 The two planes — and why the hot path never touches SQLite

```
   ┌─────────────────────── DATA plane (hot) ───────────────────────┐
   │ pread/pwrite [off,off+len) → map to (block_idx, in-block off)   │
   │   for each block touched:  pread/pwrite the block file directly │
   │   holes read as zeros; ftruncate drops whole blocks + trims end │
   │   ── NO SQLite here ──                                          │
   └────────────────────────────────────────────────────────────────┘
   ┌─────────────────── METADATA plane (boundaries only) ───────────┐
   │ open (resolve name→blob), fstat, fsync(durability barrier:      │
   │ flush every block + commit catalog size), close, stat, unlink,  │
   │ rename (subtree-aware), mkdir, xattrs   ── SQLite (WAL) ──       │
   └────────────────────────────────────────────────────────────────┘
```

`read [off,off+len)` mapped across 64-MiB blocks:

```
        off=60MiB                    len=10MiB                 (spans blocks 0 and 1)
          │◄───────────────────────────────────────►│
  block 0 ───────────────────────────────────────────────────────────────┐
  [0 ......................................... 64MiB)                       │
                                        ▲ read [60MiB,64MiB) = 4 MiB  ──────┘
  block 1 ───────────────────────────────────────────────────────────────┐
  [64MiB ..................................... 128MiB)                      │
   ▲ read [64MiB,70MiB) = 6 MiB  ───────────────────────────────────────────┘
```

> **Lesson — fsync is a catalog commit, not just a flush.** For write-through
> from a `pblock` primary, the cache flush opens a *fresh read handle* of the
> just-written file. `pblock` records size in the catalog only at `fsync`/`close`
> — so the flush must `fsync` the still-open write handle **before** opening the
> read handle, or the read handle sees catalog size 0 and `pread` clamps to 0
> bytes. (See `writethrough_flush.c` Phase-1 fix.)

> **Lesson — `ngx`-free, dual-built, SQLite-optional.** `pblock` is libc + sqlite
> only (no nginx), so the same `.c` runs in the module and in the standalone unit
> tests, and links into `libxrdproto` for the clients. When `./configure` finds
> no libsqlite3 the file compiles to empty and the registry row is `#if`-compiled
> out, so a no-sqlite build is byte-for-byte unchanged.

### 2.3 How pblock objects get created (tooling — all in-repo)

There is **no separate "make a pblock object" CLI** — objects are created the way
every real write does, through `staged_open → staged_write → staged_commit` (or
`open(O_CREATE)` + `pwrite`). Three repo-resident paths exercise that:

```
  nginx module (runtime) ── client writes (xrdcp PUT) → pblock export → objects
  unit test  src/fs/backend/pblock/sd_pblock_unittest.c  → drives the vtable directly
             (create/write/commit + multi-thread/process concurrency)
  harness    tests/c/run_pblock_tests.sh  → compiles the unittest from repo src
             into an EPHEMERAL /tmp binary (mktemp, rm on EXIT) and runs it
```

The **source** is always in the repo; the compiled unit-test binary is ephemeral
`/tmp` scratch, the same convention every C harness uses (`run_cinfo_tests.sh`,
`run_fs_usage_tests.sh`, …). Nothing a developer needs is left in `/tmp`.

---

## 3. `s3` — protocol logic once, transport injected

`sd_s3` (`backend/s3/sd_s3.c`) holds **all** the S3 *protocol* logic (SigV4
signing, HEAD, Range-GET, single-PUT, multipart upload, XML) and is `ngx`-free in
`libxrdproto`. It performs **no HTTP itself** — it calls an **injected transport
vtable**:

```
  brix_s3_transport_t  (sd_s3_transport.h)
  ┌──────────────────────────────────────────────────────────────────┐
  │ request(tctx, host,port,tls, method, path_and_query, headers,      │
  │         body,body_len, timeout, &resp, errbuf)   → 0 / -1          │
  │ resp_header(resp, name, out) · resp_body(resp,*len) · resp_free()  │
  └──────────────────────────────────────────────────────────────────┘
         ▲                                            ▲
         │ injected by the CLIENT                     │ injected by the SERVER
  client/lib/vfs_s3_transport.c                src/fs/cache/origin/s3_transport.c
  (xrdc_http stack)                            (libcurl)   ◄── NEW for the cache
```

> **Lesson — `sd_s3` was client-only.** Until the cache needed an S3 origin,
> nothing in the *module* injected a transport, so `sd_s3.c` wasn't even in the
> module build. Fronting an S3 origin meant (a) writing the server-side libcurl
> transport and (b) adding `s3/sd_s3.c` to the module's `./config` source list.
> Zero S3 protocol code was duplicated.

### 3.1 SigV4 signing — and the host:port gotcha

```
  HEAD/GET request                          canonical request (signed)
  ┌──────────────────────────┐              ┌─────────────────────────────────────┐
  │ Host: ENDPOINT:PORT       │   must  ===  │ host:ENDPOINT:PORT                   │
  │ x-amz-date: 20260629T…Z   │   match      │ x-amz-content-sha256:UNSIGNED-PAYLOAD│
  │ x-amz-content-sha256: …   │              │ x-amz-date:20260629T…Z              │
  │ Authorization: AWS4-HMAC… │              │ SignedHeaders=host;x-amz-content-…  │
  └──────────────────────────┘              └─────────────────────────────────────┘
```

> **Lesson — `brix_format_host_port` ALWAYS appends the port** (`%s:%u`, even
> 80/443). So `sd_s3` signs the canonical host *with* the port. libcurl, left to
> itself, omits the port on a default port and includes it otherwise — a
> mismatch the moment endpoints differ. **Fix:** the server transport forces
> `Host: host:port` unconditionally, byte-for-byte what was signed. Symptom when
> wrong: server logs `SigV4 auth failed … key_ok=1` (access key recognized,
> signature rejected).

### 3.2 Read = HEAD for size, then Range GETs

```
  sd_s3_open_read(params) ─► handle           sd_s3_pread(buf,n,off):
  sd_s3_size(handle) ─► HEAD ─► Content-Length   Range: bytes=off-(off+n-1)
                                                 GET ─► 206 ─► copy body (short = EOF)
```

`SD_S3_PREAD_MAX` caps a single Range GET; sequential `pread`s become sequential
Range GETs.

### 3.3 Object metadata — get is a HEAD, set is a copy-onto-self

S3 has **no in-place metadata mutation**: you replace an object's user metadata by
*copying it onto itself* with `x-amz-metadata-directive: REPLACE`. `sd_s3` exposes
that as four calls:

```
  sd_s3_get_meta(f, "foo", buf, …)     HEAD ─► read header x-amz-meta-foo
  sd_s3_set_meta(p, {{"foo","bar"}}, 1) PUT key + x-amz-copy-source: key
                                            + x-amz-metadata-directive: REPLACE
                                            + x-amz-meta-foo: bar  (no byte re-upload)
  sd_s3_get_unixattr / set_unixattr     the advisory POSIX-attr blob in
                                            x-amz-meta-xrd-unixattr (meta_advisory.c)
```

**SigV4 over the extra headers.** A copy-with-REPLACE must sign `x-amz-copy-source`,
`x-amz-metadata-directive` and every `x-amz-meta-*` line — AWS rejects them
otherwise. The base `sd_s3_sign` only signs `host;x-amz-content-sha256;x-amz-date`,
so set-meta uses **`sd_s3_sign_ext`**: it merges the extra headers with the fixed
three, **sorts them** (the canonical-headers + `SignedHeaders` list must be
lexicographic), and emits the full signed request — so set-meta works against real
AWS/MinIO, not just an anonymous endpoint.

> **Gotcha — standalone consumers must `brix_crypto_init()` once.** SigV4's HMAC
> goes through a fetched `EVP_MAC` handle (`src/core/compat/crypto.c`); the module and
> client tools fetch it in worker init. A bare `sd_s3` harness that skips it gets
> `s3 … SigV4 sign failed` on **every** request (the HMAC silently returns 0).

> **S3 advisory `set` replaces the whole user-metadata set** (S3 copy semantics) —
> setting the unix-attr blob drops other `x-amz-meta-*`. A read-modify-write that
> preserves siblings needs header *enumeration*, which the transport's by-name
> `resp_header` cannot yet do (a deliberate follow-on).

---

## 4. The remote-origin drivers + the cache "fold"

Two earlier phases made the **local cache storage** an SD instance. The recent
work made the **remote origin** an SD instance too. Once *both* sides of the cache
are SD instances, a read-through fill collapses to a **driver→driver copy**:

```
  READ-THROUGH FILL (origin-agnostic)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  origin_inst->driver->pread(src, buf, len, off)        ── the REMOTE side  │
  │            │                                                               │
  │            ▼                                                               │
  │  brix_cache_sink_pwrite(sink, buf, n, off)  ── staged_write or mem/fd    │
  │            │                                                               │
  │            ▼                                                               │
  │  cache_inst->driver->staged_commit()  → commit-then-verify-then-publish    │
  └──────────────────────────────────────────────────────────────────────────┘
```

### 4.1 `remote` (S3 origin) — delegation, transport injected by the cache

```
  fetch.c::brix_cache_fetch_origin_s3
        │ build brix_sd_remote_cfg_t { host,port,tls,bucket,ak,sk,region,
        │                                transport = &server libcurl xport }
        ▼
  brix_sd_remote_create(cfg) ─► sd_remote instance (CAP_RANGE_READ)
        │ open("/sub/file")
        ▼
  sd_remote_open → builds sd_s3_open_params("/bucket/sub/file") → sd_s3_open_read
        obj->state = sd_s3_file*   obj->fd = -1
        │ pread → sd_s3_pread (Range GET)   stat/fstat → HEAD size
        ▼
  sd_s3  (SigV4)  ──►  s3_transport.c (libcurl)  ──►  S3 origin
```

> **Lesson — keep the backend layer free of the cache.** `sd_remote` is
> transport-**agnostic**: the cache *injects* `&brix_s3_origin_curl_transport`.
> No `cache/` or libcurl dependency leaks into `backend/` — exactly the same trick
> `sd_s3` already used for the client.

#### 4.1.1 Reads that signed as the export — metadata, then the listing

A driver slot and its `_cred` sibling are not "the same operation, optionally
scoped" — they are **who the request is authorised as**. `sd_remote` grew a full
`_cred` set with the phase-92 namespace work: `open`, `staged_open`, `stat`,
`unlink`, `mkdir`, `rename`, `setxattr`, `removexattr`, `setattr`. `getxattr` and
`listxattr` did not get one, and the gap is easy to miss because nothing
*visibly* fails: `brix_sd_getxattr_maybe_cred` finds `getxattr_cred == NULL` and
falls through to the plain slot, which signs with the instance's static service
key. A user presenting perfectly good S3 keys therefore had their metadata read
**authorised as the export**, returning `x-amz-meta-*` their own keys would have
been denied — a confused deputy in the one direction the caps matrix does not
show, because the slot *was* implemented; only its identity was wrong.

Note what was *not* the hole, since it is the part that looks like the bug: the
forwarder's `fallback_deny` arm already refused a credential it had no `_cred`
slot to route to. Deny mode was safe. It was the **permitted** path — the
successful read for a user who had keys — that ran as the wrong principal. A
deny-mode-only audit of this surface would have passed.

The fix is the shape every other slot on this driver already had: one `_impl`
taking `ak/sk/region/session`, a plain wrapper passing `NULL` (the service
credential, unchanged), and a `_cred` wrapper over `sd_remote_cred_gate` —
sign as the user (gate > 0), refuse `EACCES` (gate < 0), or fall back (gate 0).

`tests/c/test_sd_remote_xattr_cred.c` pins it by the **signing key**, not by the
returned bytes: the fake transport lifts the access key id out of the SigV4
`Credential=<AK>/…` scope on every request, so "the user's key signed this read"
is a direct assertion rather than an inference. That is the only way to test this
class of defect — a read authorised as the wrong principal returns *correct-looking
data*, so any assertion about the value is green either way.

**`opendir` had the same hole, with a twist.** `sd_remote_opendir` also had no
`_cred` sibling, so a per-user directory listing ran `ListObjectsV2` **as the
export**: a user whose own keys are scoped to one prefix saw every sibling prefix
in the bucket, and the entries looked entirely normal. Closing it is not the same
edit as a read slot, because **`opendir` performs no I/O at all** — it derives
the S3 key prefix and returns; the first LIST is issued lazily from `readdir`,
and continuation pages later still. `brix_sd_cred_t` is documented as *borrowed
for the duration of the vtable call*, so the credential must be **copied onto the
handle** (`sd_remote_dir_state`) and wiped with `OPENSSL_cleanse` in `closedir`.

> **Lesson — a lazy slot changes the credential's lifetime, not just its scope.**
> Whenever the `_cred` sibling of a *deferred* operation is added, the borrowed
> credential outlives nothing: copy it. The test has to pin that too, and the
> only convincing way is to destroy the caller's credential in the window a
> borrowed pointer would still be dereferenced —
> `tests/c/test_sd_remote_opendir_cred.c` `free()`s the credential strings and
> scribbles `0xAA` over the struct **between `opendir` and the first `readdir`**,
> then asserts both pages still signed as the user.

The one bound that is not a copy is the STS session token: `s3_ak`/`s3_sk`/
`s3_region` have ucred-store limits to mirror, but `s3_session` has none, so the
handle sizes it at 4 KiB and **refuses (`E2BIG`) rather than truncates**. A
clipped session token is not a smaller token — it signs a request the store
rejects with an opaque `SignatureDoesNotMatch`, pages into a listing, far from
the `opendir` that caused it.

`server_copy` was the last slot in the family and the widest — one request that
reads one key and writes another; it is covered in §4.7. With it, every slot
`sd_remote` implements has a `_cred` sibling: the driver's `_cred` column is
complete, which is the only state in which "this export enforces per-user S3
identity" is a true statement rather than a mostly-true one.

### 4.2 `xroot` (`root://` origin) — wrapping the in-process wire client

The `root://` origin client (`cache/origin_*.c`) does handshake + anonymous login
+ open + `kXR_read`. It is *almost* a driver already; the key discovery is that it
needs only a **server conf + a logical path** (no connection object, no log):

```
  sd_xroot_open(path):
    t = calloc(fill_task)         ← SYNTHETIC: only t->conf + t->clean_path used
    origin_connect(t,&oc) → origin_bootstrap(t,&oc) → origin_open(t,&oc,fhandle)
    obj->state = { oc, fhandle, t }   obj->snap.size = t->file_size

  sd_xroot_pread(buf,len,off):
    sink = { mem = buf, mem_cap = len }            ◄── the MEMORY sink (new)
    origin_read_chunk(t,&oc,fhandle,&sink, off, 0, len, &got)   (kXR_read ranges)
    return got
```

> **Lesson — a memory sink unifies streaming and pread.** The origin reader was
> built to stream into a *sink* (fd or staged handle). To serve a driver `pread`
> into the caller's buffer, `brix_cache_sink_t` grew a `mem`/`mem_cap` mode; the
> driver points `mem` at the caller buffer and `dst_off = 0`.

> **Lesson — `brix_cache_sink_pwrite` returns `0`/`-1`, NOT a byte count.** The
> first S3/root fill loops wrote `if (sink_pwrite(...) != n) fail;` — and since a
> success returns `0`, *every* successful write looked like a failure (S3 read was
> fine; the cache write "failed"). The correct check is `!= 0`.

> **Lesson — layering exception, made explicit.** Unlike `sd_remote`, `sd_xroot`
> *does* depend on `cache/origin_*.c` — it exists precisely to expose that client
> as an SD backend, so the dependency is inherent and documented in the header,
> not a slip.

### 4.3 The fill dispatch + the origin auth matrix

```
  brix_cache_fetch_origin(t)  — by cache_origin_scheme + creds
  ┌───────────────────────────────────────────────────────────────────────────┐
  │ http:// https:// davs://  → http_transport.c (libcurl, whole-file)          │
  │ s3://                     → fetch_origin_s3   → sd_remote → sd_s3 → libcurl  │
  │ pelican://                → pelican director  → http_transport.c            │
  │ root:// + proxy OR token  → fetch_origin_exec → native client (xrdcp)       │
  │ root:// (anonymous)       → fetch_origin_xroot → sd_xroot (in-process)       │
  └───────────────────────────────────────────────────────────────────────────┘

  AUTH PARITY (token AND GSI on both protocols)
  ┌──────────────┬────────────────────────────┬───────────────────────────────┐
  │              │ bearer TOKEN               │ GSI / X.509 proxy              │
  ├──────────────┼────────────────────────────┼───────────────────────────────┤
  │ http(s)://   │ Authorization: Bearer       │ CURLOPT_SSLCERT/SSLKEY = proxy │
  │ (libcurl)    │ (configured + forwarded)    │ PEM (cert+chain+key)  ◄── NEW  │
  ├──────────────┼────────────────────────────┼───────────────────────────────┤
  │ root://      │ exec: BEARER_TOKEN_FILE ◄NEW│ exec: X509_USER_PROXY +        │
  │ (native cli) │ (xrdc_token_discover)       │       X509_CERT_DIR            │
  │  anonymous   │ in-process sd_xroot driver  │ —                              │
  └──────────────┴────────────────────────────┴───────────────────────────────┘
```

> **Scope note.** A *fully in-process* `root://` token/GSI client is deliberately
> NOT built — that auth logic lives in `libxrdc`, which `src/` cannot link.
> Authenticated `root://` origins use the proven native-client (`xrdcp`)
> delegation; the in-process `sd_xroot` driver covers the anonymous case.

---

### 4.4 Namespace mutation on the origin drivers — the type-probe contract

The origin drivers (`sd_http` over WebDAV, `sd_xroot` over kXR) also carry the
`mkdir`/`rmdir`/`unlink`/`stat` slots, and those slots are what a client's
`mkdir`/`rm`/`rmdir`/`stat` reaches when the export's storage IS the origin. The
combinatorial sweep behind `tests/test_ns_mutation_gateways.py` (37 tests, three-way
POSIX ↔ `sd_http` ↔ `sd_xroot` comparison) pinned four rules that HTTP semantics do
**not** give you for free:

- **`rmdir` must refuse a non-collection.** WebDAV `DELETE` deletes whatever is at
  the URL, so an unguarded `rmdir` slot destroyed a *regular file*. The driver now
  runs a type probe first and returns `ENOTDIR`.
- **`rmdir` must refuse a populated collection.** RFC 4918 §9.6 makes `DELETE` on a
  collection **recursive** — an unguarded slot silently wiped a whole subtree where
  POSIX would have said `ENOTEMPTY`. Recursive deletes are the VFS's job
  (`brix_vfs_driver_rmtree`), never the slot's.
- **Deleting something absent must fail.** A 404 from the origin is `ENOENT`, not
  success; the earlier mapping reported a delete of a missing path as done.
- **`stat` must probe the type.** A `HEAD` cannot tell a collection from a
  zero-length object, so every path came back a regular file (and `mkdir -p` over a
  regular file then reported success). Only `PROPFIND Depth: 0` +
  `<resourcetype><collection/>` answers it — **cost: one extra RTT per stat of a
  zero-sized entry**, which is the deliberate trade for a correct type.

The probe path is shared: `sd_http_propfind_issue()` / `sd_http_propfind_errno()`
in `sd_http_dir.c` issue both the listing PROPFIND (`Depth: 1`) and the type probe
(`Depth: 0`). Status mapping is `207 → ok`, `404|409 → ENOENT`, `401|403 → EACCES`,
`405|501 → ENOTSUP`, anything else `EIO`.

Still open (no coverage yet): `gridftp × xroot` STOR, and `S3 × xroot` PUT/DELETE.

### 4.5 Checksum offload on the origin drivers — ask, never re-read

A checksum request against an origin-backed export used to have exactly one
answer: `pread` the whole object across the network and hash it locally. All
three origin drivers now implement the optional `query_checksum` slot
(`sd.h`), which asks the backend for a digest it already holds **without reading
the object's bytes**, and the byte-reading compute in
`core/compat/integrity_info.c` becomes the fallback rather than the only path:

| driver | how it asks | how it answers |
|---|---|---|
| `xroot` | `kXR_Qcksum` (`brix_sd_xroot_query_checksum`) | the origin's own digest, in the origin's algorithm |
| `http` | one `HEAD` carrying RFC-3230 `Want-Digest: <token>` (`sd_http_digest.c`) | the `Digest:` reply header, parsed for exactly the requested algorithm |
| `remote` (s3://) | one **signed** `HEAD` carrying `x-amz-checksum-mode: ENABLED` (`sd_remote_checksum.c` → `sd_s3_get_checksum`) | the `x-amz-checksum-<algo>` header (base64), or the `ETag` for `md5` |

Three rules the slot's contract makes non-negotiable, and which the units pin
(`sd_http_digest`, `sd_remote_checksum`, `digest_header` in the C-regression
suite):

- **Never relabel.** The reply is parsed asking for *exactly* the canonical
  algorithm that was requested. An origin that answers `md5` when we asked for
  `sha256` declines to the compute fallback — a digest in the wrong function
  presented as the right one is worse than no digest at all. Same reason
  `sd_xroot` declines on an algorithm mismatch.
- **Never guess a wire spelling.** The canonical brix names and the RFC-3230
  registered tokens differ exactly where RFC 3230 hyphenates the SHA family
  (`sha256` → `sha-256`). `brix_digest_wire_token()` maps them; an algorithm with
  no registered token (`crc64nvme`, `zcrc32`) declines *before any I/O*.
- **A decline is not a failure.** `NGX_DECLINED` and `NGX_ERROR` are treated
  identically by callers — fall back to hashing the bytes. An origin that ignores
  `Want-Digest`, speaks RFC 9530's `Repr-Digest:` instead, or holds no digest at
  all costs one `HEAD`, never a wrong answer.

The RFC-3230 grammar itself is **shared, in one place**
(`src/core/compat/digest_header.c`): the same parser reads a client's asserted
`Digest:` on a WebDAV PUT (`put_body_digest.c`) and an origin's `Digest:` reply
here, because a client and an origin must not be understood by two different
parsers. Extracting it widened PUT verification to `sha-1`/`sha-512`, which the
WebDAV side had silently read as "no digest asserted". Two traps it now pins:

- **Size a base64 decode buffer by `ngx_base64_decoded_length()`, not the digest
  width.** That bound is `((len+3)/4)*3` — 66 for a padded 64-byte sha-512 — so a
  buffer sized at the digest's own 64 bytes makes *every* sha-512 fail the
  pre-decode check and read as unusable. The true width is still enforced
  downstream by the hex output not fitting `BRIX_DIGEST_HEX_MAX`.
- **Validate a whole hex value before writing any of it.** Rejecting at the first
  non-hex byte after copying the prefix leaves the caller's buffer holding a
  shorter string that still looks like a digest.

Origins trim leading zeros off an adler32; `brix_digest_hex_pad()` re-pads to the
algorithm width, because a digest handed on as authoritative is compared
literally against a zero-padded local compute.

S3 adds two traps of its own, both pinned by `sd_remote_checksum`:

- **An `ETag` is the object's md5 only for a single-part upload.** A *multipart*
  ETag is spelled `<hex>-<nparts>` and is an md5 **of the concatenated part
  digests** — it matches nothing a client can compute over the object — and an
  SSE-KMS/SSE-C ETag is not an md5 at all. The driver requires a bare 32-char hex
  run after stripping the quotes, which refuses every one of those shapes without
  a special case per shape, and declines to the compute fallback.
- **HeadObject omits the stored checksums unless you ask**, and AWS requires the
  `x-amz-checksum-mode: ENABLED` header that asks to be in the **signed** header
  set. That is why the probe goes through `sd_s3_sign_ext()` (arbitrary signed
  `x-amz-*` extras) rather than the plain `sd_s3_sign()` the other `HEAD`s use — a
  request that carries the header unsigned is rejected by the origin, and one
  that omits it succeeds while silently reporting "no checksum stored".

The digest grammar lives on the `sd_remote` side, never in `sd_s3`: `sd_s3` is
deliberately ngx-free (it is shared with the userland clients in
`libxrdproto`) while `digest_header.h` pulls in `ngx_core.h`. `sd_s3` therefore
returns the header value **raw** and the base64/hex normalisation happens one
layer up.

#### 4.5.1 The tier that already knew the answer — seeding the cache

`query_checksum` fixes the question for an origin-backed export. Put a **cache**
in front of that export and the offload silently stops applying, for a reason
worth understanding because it generalises to every obj-keyed slot:

`integrity_driver_query()` dispatches on `obj->driver` — **the object's** driver,
not the export's. On a cache HIT the served object comes from
`brix_cstore_serve_open()` → `cs->store->driver->open(...)`, so its driver is the
cache **store's** (`posix`/`pblock`). The origin driver is not in the picture at
all, and adding `.query_checksum` to the cache *decorator's* vtable would be dead
code: the decorator is never the served object's driver either.

Which is doubly wasteful, because the cache is the one tier that **already
computed the answer and threw it away**. Checksum-on-fill (`§ verify`) hashes the
whole `.part` and compares it to the origin's advertised digest before publishing
— and then recorded that digest only in the `.cinfo`, which describes the cache's
own bookkeeping and which no client-facing checksum path ever reads. So the first
`kXR_Qcksum` on a freshly cached 10 GB file re-read all 10 GB to re-derive a
value proven minutes earlier.

`cache_fill_commit()` now hands it over instead, through
`brix_cstore_seed_checksum()` → `brix_integrity_seed_fd()`: the digest lands in
`user.XrdCks.<alg>` on the committed store object — **exactly where a recompute
would have written it**, so a seeded entry and a computed one are
indistinguishable to every reader, and the existing staleness policy (the record
carries the file's mtime+size and is rejected when they no longer match) applies
unchanged. No new lookup layer, no `brix_sd_obj_t` ABI change.

Three properties the unit (`integrity_seed`) pins, each for a concrete failure:

- **Canonicalise the algorithm NAME, not just the value.** A fill reporting
  `crc64xz` and a client asking for `crc64` must meet on one key, or the seed buys
  nothing for precisely the algorithms whose names have two spellings.
  `brix_checksum_parse()` does it for both sides.
- **Refuse, never truncate.** This API records an *assertion about file content*,
  so the whole value is validated before any of it is stored. A validate-as-you-
  copy loop leaves a 64-hex prefix of an over-long value behind — a perfectly
  well-formed sha256 digest **of nothing**, which every later reader serves as
  authoritative. (The same defect shipped once in the RFC-3230 hex copier above;
  it is one bug class, not two.)
- **The test's compute kernels `abort()`.** "The digest was answered without
  reading the object" cannot be asserted by comparing hex strings — the right
  answer arrives either way. Linking a checksum kernel that aborts on entry is
  the assertion.

Not done, deliberately: the built-in fill in `fs/cache/fetch.c`
(`brix_cache_commit_staged`) verifies the same way but publishes a *driver-backed*
entry that frequently has no local fd to hang an xattr on — and those entries are
served through the driver, where the origin's own `query_checksum` already
answers. The seam that needed this is the local store the decorator serves by fd.

---

### 4.6 Capacity reporting — the backend's space, not the gateway's spool

"How much room is there?" has the same shape of wrong answer the checksum
question had. A gateway fronting a remote origin holds an export *directory* that
is empty by construction — every byte lives on the origin — so answering
`kXR_statvfs` / `kXR_Qspace` / `kXR_QFSinfo` / SRR from a `statvfs(2)` of that
directory tells a client sizing a transfer about the gateway's spool rather than
the storage it is about to write to.

The optional `space` slot (`brix_sd_space_t`: `total`/`used`/`free`) is the
backend's own answer. `brix_query_backend_usage()` consults it for the space
verbs, and falls back to the local `statvfs` when the slot is absent or reports
`NGX_ERROR`:

| driver | how it asks | how it answers |
|---|---|---|
| `pblock` | the SQLite catalog | quota-aware *logical* space, not the filesystem under the blocks |
| `xroot` | `kXR_Qspace` on the origin (`sd_xroot_ns.c`) | the origin's own oss space report |
| `http` | one `Depth: 0` **named-prop** `PROPFIND` on the export root (`sd_http_space.c`) | RFC 4331 `DAV:quota-available-bytes` + `DAV:quota-used-bytes` |
| `ceph` / `cephfs_ro` | one `rados_cluster_stat` on the export's own connection (`sd_ceph_cluster_space`, `sd_ceph_io.c`) | the RAW cluster-wide figures `ceph df` reports |

`s3` has no slot and none is coming: the S3 API has no capacity call at all, and
a bucket's "size" is a billing aggregate computed hours late.

Five things this cost, in the order they bite:

- **`space` is instance-keyed, so the decorators hide it.** Unlike
  `query_checksum` (object-keyed), the slot is reached through the *instance*, so
  a `stage` or `cache` decorator wrapping a leaf driver answers from its own
  table — and a table with no `.space` reports nothing even though the leaf under
  it can answer. Both decorators now forward. Adding any instance-keyed slot to a
  leaf driver means auditing every decorator that can sit above it.
- **RFC 4331 has no `total` property.** `used + available` is the only defined
  derivation and the one every WebDAV client makes; the addition is overflow-
  checked, and a missing *half* is a refusal — there is nothing to derive a total
  from, and a fabricated one is worse than falling back.
- **An empty PROPFIND is not enough.** The quota pair are live properties outside
  RFC 4918, so "allprop" is not obliged to return either. The request carries an
  explicit `<D:prop>` body naming both — which is why `sd_http_req_t` grew an
  optional request entity, and why `sd_http_pf_t` + `sd_http_propfind_issue()`
  moved out of `sd_http_dir.c` into the shared internal header rather than a
  second PROPFIND sender being written.
- **"The tag is present" is not "there is a value".** RFC 4918 lists an
  unsupported property as an *empty* element inside a `404` propstat, so
  `<D:quota-available-bytes/>` must never read as a zero — a zero total looks
  exactly like a full backend. The reader refuses the self-closing form, refuses a
  value that is not one bare non-negative integer (`1024junk` is rejected whole,
  never read as `1024`), and finds the property only as a real element — the
  namespace-agnostic tag scanner the listing parser uses, so a *file named*
  `quota-available-bytes` cannot spoof a capacity. Pinned by the `sd_http_space`
  unit.
- **Raw cluster bytes are the only triple RADOS will hand a C caller.** librados'
  C API exposes `rados_cluster_stat` (`kb`/`kb_used`/`kb_avail`, pre-replication
  and cluster-wide) and nothing pool-scoped: a pool's MAX AVAIL needs the
  replication factor, which is reachable only through a mon command. Mixing a
  pool's *logical* bytes into a raw total would produce a `used + free` that does
  not add up, so both Ceph drivers report the raw triple and say so. The
  read-only `cephfs_ro` driver reports it too — read-only does not mean
  capacity-blind, and it reads through its **data**-pool connection so a later
  pool-scoped refinement lands on the right handle. Both live tests check the
  triple for self-consistency rather than for a value, and both pin `NULL out →
  EINVAL`; the flat driver additionally pins `space` after `cleanup()` as
  `ENOTCONN`, never a call into a shut-down cluster handle.

---

### 4.7 Server-side copy — the bytes never come to the gateway

The third question with the same shape. `brix_vfs_copy_driver` dispatches an
object-store copy to the leaf driver's `server_copy` slot and returns `ENOTSUP`
when it is absent — and an absent slot means the caller reads the whole object
down to this host and pushes it straight back up. For an intra-origin copy (an
`xrdcp` clone, a WebDAV `COPY` arriving at the gateway, a TPC whose two legs
resolve to the same origin) that is the entire transfer, twice, for bytes that
never needed to leave the store.

| driver | how it copies |
|---|---|
| `posix` | `copy_file_range(2)`, with a `pread`/`pwrite` fallback |
| `pblock` | a catalog-level block reference — no data movement at all |
| `xroot` | the origin's own server-side copy |
| `remote` (s3://) | `CopyObject` (`x-amz-copy-source`), one signed PUT |
| `http` | WebDAV `COPY` (RFC 4918 §9.8) — `sd_http_mutate.c` |

The Ceph drivers have no slot and cannot get one: `copy_from` is a **C++-only**
`ObjectWriteOperation` method — `librados.h` (checked against the 3.0 header the
ceph-build image ships) exposes no C spelling of it, so `sd_ceph_rename` keeps its
chunked read/write copy through the gateway. Do not re-derive this from the C++
docs; check the C header.

`COPY` and `MOVE` differ on the wire in exactly one token, so both go through one
`sd_http_dest_verb()` helper: composing the absolute `Destination:` URI, folding
in the resolved credential and mapping the status are identical, and two copies
of that would drift — the Destination-composition bug class (a relative URI, a
dropped port) is one an origin reports as a flat `400` with no hint which leg was
malformed. Four things the slot's contract settles:

- **`Overwrite: T`, always.** The no-clobber decision belongs to the VFS, which
  has already pre-stat'ed the destination and refused `EEXIST` when the caller
  withheld overwrite. A second `Overwrite: F` here would turn an explicitly
  authorized replace into a `412`.
- **`207 Multistatus` is not success.** That is how a *collection* `COPY` reports
  that some members failed. Read as OK, a caller implementing a move would go on
  to delete the source of a half-copied tree. The success set is `201`/`204` and
  nothing else.
- **`bytes_out` is a follow-up stat, and a failed one is not a failed copy.**
  `COPY` reports no byte count, so the slot HEADs the destination — exactly as the
  POSIX and s3:// slots do. When that probe fails the copy still returns `NGX_OK`
  with `bytes_out = 0`: an accounting gap in the `OP_COPY` metric, never a reason
  to make the caller copy the object again.
- **A namespace path becomes a header *value* here, and nowhere else in the
  driver.** A raw CR or LF in `src` or `dst` would close the `Destination:` line
  and let what follows be read as a header of the caller's choosing — a second
  `Destination` pointing off this origin, or an `Authorization` replacing ours.
  Paths reaching a driver are resolved, but this is the layer where the injection
  would land, so `sd_http_dest_verb()` refuses `\r`/`\n` with `EINVAL` before any
  wire op. The guard covers `MOVE` for free, which had the same exposure.

**Whose copy is it?** This is the widest slot on any driver: one signed request
*reads* one key and *writes* another, so the identity it presents governs both
halves at once. `sd_http` carried `server_copy_cred` from the start; `sd_remote`
did not, and the forwarder therefore fell through to the plain slot — a per-user
`COPY` over an `s3://` export ran as the **export**, able to duplicate an object
the caller's own keys could not read into a prefix they could not write, and
report success (§4.1.1 is the same defect on the metadata reads). The size
follow-up is part of the same rule: the HEAD signs with the identity that
copied, because a probe signed by anyone else answers about visibility the
copying identity may not have — the noreplace-commit rule from the staged path.
`server_copy` moved to `sd_remote_write.c` when the `_cred` sibling landed: it is
a mutation, and `sd_remote_meta.c` was at the 600-line cap.

Registering the slot also means registering the **cap**: `BRIX_SD_CAP_SERVER_COPY`
is what introspection and the config advisor report, and it must not disagree with
the vtable. `sd_remote` had implemented `server_copy` since the S3 `CopyObject`
wave while its `.caps` still said otherwise; both now advertise it. Pinned by the
`sd_http_copy` unit, which also asserts that a mutation never fails over to a
secondary endpoint — a namespace mutation applied to a non-primary origin
split-brains the store.

### 4.8 Metadata mutation on `xroot` — an absent slot that *reported success*

The other three gaps in this chapter cost a round trip or a whole transfer. This
one lost the operation entirely. `brix_vfs_chmod()` and `brix_vfs_setattr()` treat
a NULL `driver->setattr` as "this backend has no mutable metadata" and return
`NGX_OK` **without contacting the backend** — the right answer for a data-only
object namespace (a `MKCOL`/`PUT` flow that chmods should not fail against a block
store), and exactly the wrong one for a `root://` export, whose origin is a real
POSIX-backed server. A `chmod` over such an export returned success and changed
nothing, with no log line and no error to correlate.

`sd_xroot` now carries `setattr` + `setattr_cred`, over `kXR_chmod` (3002) — the
one metadata mutation the base XRootD protocol defines. The chain is
`sd_xroot_setattr` (plain slot) → `sd_xroot_setattr_cred` (the single
implementation, like every other path-based xroot ns op) →
`brix_cache_origin_chmod()` in `origin_ns.c`, alongside the existing
`_rm`/`_rmdir`/`_mkdir`/`_rename` primitives and sharing their body packer and
status→errno mapping.

- **Only the mode group travels; times and owner are accepted and ignored.** The
  union slot also carries `set_times`/`set_owner`, but the opcode for those
  (`kXR_setattr`, 3500) is *this project's* capability-negotiated vendor
  extension, which a stock origin does not implement and the driver has no
  negotiation to lean on. Failing a `cp -p` outright would be worse than the
  documented `sd.h` contract — "a driver applies what its namespace can
  represent" — which `sd_pblock` reads the same way for `atime`.
- **A times-only or owner-only request must send nothing at all.** This is the
  security-negative the unit exists for. The mode field of an unset request is
  zero, so a slot that applied it unconditionally would turn a `touch -d` into a
  `chmod 000` — every permission bit stripped off an object the caller never
  meant to touch. `set_mode == 0` returns success before the session is even
  opened; the origin sees no frame.
- **Only the low nine bits reach the wire.** The XRootD mode bits
  (`kXR_ur`..`kXR_ox`) are numerically the POSIX `0777` layout, and the protocol
  has no encoding for setuid/setgid/sticky. Masking `& 0777` on send is exactly
  symmetric with the server half (`exec_chmod` masks the same way), and keeps a
  caller's file-type bits (`S_IFDIR` is `0040000`, which truncates into the
  16-bit field as `0x4000`) from ever being read as a mode.
- **A chmod of 0 is *not* defaulted.** The server half substitutes `0644` for a
  zero mode; the client half must not, because inventing a mode here would hide a
  caller's mistake rather than report it.

Pinned by the `sd_xroot_setattr` unit, which links the real chain down to
`wire_codec_ns.o` and stubs only the socket — so it asserts on the bytes that
would really be sent (opcode, the reserved(14)+mode(2) body, the path payload)
as well as the errno mapping, the credential the session authenticates with, and
the deny gate that must stop a resolved-to-nothing credential from quietly
chmod'ing as the gateway's service identity.

### 4.9 Extended attributes on `http` — dead properties, hex on both halves

`http` was the last namespace-capable driver with **no** xattr surface at all, and
the loss was not one feature: an xattr is the storage-neutral spelling every
per-object key/value feature in the tree already uses, so behind an `http` origin
the WebDAV `LOCK` token store, WebDAV `PROPPATCH` dead properties, S3 object
tagging, S3 user metadata and `root://` `kXR_fattr` all went dark at once. Closing
the four slots (`getxattr`/`listxattr`/`setxattr`/`removexattr`, each with its
`_cred` twin) re-lights all of them, rather than teaching five features about HTTP.

RFC 4918 §15 **dead properties** are exactly the primitive wanted: arbitrary
server-preserved name/value pairs on a resource, read with `PROPFIND` and written
with `PROPPATCH`. One xattr becomes one element in a BriX namespace
(`https://brix.dev/ns/xattr`), local name `bxa` + lowercase hex of the xattr name,
with the value hex too. Reads live in `sd_http_xattr.c`, writes in
`sd_http_xattr_write.c` (the split is the 600-line cap, not two mappings); the
wire spelling itself is in `sd_http_xattr_internal.h` so the two halves cannot
drift.

- **Hex on BOTH halves is a security property, not a style.** An xattr name and
  an xattr value are arbitrary bytes chosen by a remote client, and interpolating
  those into an XML request body is how markup injection happens. Hex has no XML
  metacharacter and no NUL problem, so a value of `]]></D:prop></D:set>` is just
  more hex digits on the wire. It also makes the mapping total and reversible,
  which "translate to the natural dead property" cannot be: a key like
  `user.s3.tagging` has no namespace/local pair to translate *into*, and the
  webdav dead-prop codec that owns the other direction is `ngx_pool_t`-based, so
  calling it from ngx-free backend code would invert the layering. The cost —
  these properties are opaque to a *native* WebDAV client — is deliberate, and is
  why the element carries a BriX namespace instead of squatting `DAV:`.
- **A named-prop `PROPFIND` for an ABSENT property still returns the element**,
  empty, inside a **404 propstat**. Reading the element without reading the
  propstat status is how "no such attribute" becomes "an attribute whose value is
  empty" — a difference `XATTR_REPLACE`, `removexattr` and every caller that
  branches on `ENODATA` depends on. RFC 4918 orders `propstat = prop, status`, so
  the first `<status>` after the element is the one that judges it.
- **`PROPPATCH` is an unconditional upsert, so two POSIX contracts have to be
  bought with a preceding read.** `XATTR_CREATE`/`XATTR_REPLACE` have no native
  conditional form, and RFC 4918 §9.2 makes removing an *absent* property a
  **success** where POSIX demands `ENODATA`. Both are gated by one size-enquiry
  `getxattr` before the patch — racy against a concurrent writer on the same
  origin exactly as the flags are on any network filesystem, and far better than
  offering flags that are silently not enforced.
- **`405`/`409` map to `ENOTSUP`, not to `EEXIST`/`ENOENT`.** An origin that keeps
  no dead properties at that path must read to the VFS as "this backend cannot",
  so the tier above can fall back; the shared mutation status map would have
  called it a namespace conflict.
- **A `207` is not a success until its propstat says so.** The transport status
  and the per-property status are two different verdicts, and reading only the
  outer one reports a write that never landed.
- Mutations go through the driver's **no-failover** namespace sender
  (`sd_http_ns_send`, generalised to a request struct here so it can carry a
  request entity): replaying a property write against a second endpoint could
  apply it twice. Reads pin `force_primary` for the matching reason — a property
  read must see the replica the write acts on.

Pinned by the `sd_http_xattr` unit over the scripted fake transport: the round
trip and the exact bytes on the wire, the absent/short-buffer/oversize refusals
(`ENODATA`, `ERANGE` **with nothing written**, `E2BIG` before any request), and
the security-negative pair — a `fallback_deny` proxy-only credential refused on
all four ops *before* anything reaches the transport, and a name and value full of
XML metacharacters that cannot escape the hex in either direction.

### 4.10 `ceph` — the ioctx *is* the identity, and truncate needs no handle

The flat RADOS driver published `open_cred` — a per-user CephX keyring, cached in
a bounded per-export LRU of connections — and nothing else. Every namespace slot
(`stat`, `unlink`, `getxattr`, `listxattr`, `setxattr`, `removexattr`,
`opendir`) reached back to `st->ioctx`, the export's own service connection.

> **Lesson — the identity a RADOS op asserts at the OSDs is the ioctx it runs
> on, and nothing else.** There is no per-op principal to pass and no header to
> get wrong: an op that touches `st->ioctx` executed as the export, whatever
> credential the request carried. That makes the audit mechanical — grep the
> namespace slots for `st->ioctx` — and it makes the fix mechanical too.

This is the same confused deputy as §4.1.1 on `sd_remote`, with the same
asymmetry: `brix_sd_<op>_maybe_cred` refuses `EACCES` when a `fallback_deny`
credential meets a driver that has the plain slot and no `_cred` twin, so **deny
mode was always safe and the permitted path was the hole** — a user with a valid
keyring got their reads and writes checked by CephX and their metadata served on
the export's authority.

The shape of the fix is worth copying because it is not the `_impl`/wrapper shape
`sd_remote` uses. Each namespace op was split into an **ioctx-explicit core**
(`sd_ceph_stat_io(st, io, …)`) that the plain slot calls with `st->ioctx`; the
`_cred` twins live in their own TU (`sd_ceph_ns_cred.c`) and call the same core
with the caller's ioctx. There is exactly one implementation of each operation
and the credential decides nothing except *which connection it runs on* — the
property that makes "did this run as the user?" answerable by reading one line.

The acquire/release pair (`sd_ceph_cred_ioctx_get` / `_put`) also lives once, in
a tagged dispatcher, rather than eight times: the release is the security-
relevant half, and eight copies is eight chances for an early return to skip it.
Two lifetime facts justify how short it is:

- **No pin is taken.** `open_cred` must pin its connection because the object it
  returns keeps reading through it; a namespace op leaves no handle behind, so
  the connection can be released the moment the core returns. `opendir_cred` is
  safe for the same reason **only because `sd_ceph_opendir` is eager** — it
  snapshots the entire listing into the handle before returning, so no later
  `readdir` touches the cluster. The `sd_remote` twin of this slot is lazy and
  therefore had to *copy* the credential onto the handle (§4.1.1). Same slot
  name, opposite lifetime rule; the driver's own laziness decides which.
- **`_put` destroys a transient connection only.** A cached one belongs to the
  LRU and must be left to it.

`truncate_path` came along with them, and is a plain win: `rados_trunc` is a
path-native object op, so the VFS's open + `ftruncate` + close fallback was three
round trips and a write handle to shorten a file. Its `_cred` twin matters more
than most — truncation destroys bytes without ever opening the object, so it is
exactly the op that must not run on the export's authority.

Three `_cred` twins are deliberately **absent**, and the reasons are the useful
part:

| slot | why not |
|---|---|
| `rename_cred` | `sd_ceph_rename` is copy+delete through `st->striper`, which is bound to the **export's** connection. A cred-shaped wrapper would look right at the call site and assert the wrong identity for the copy. |
| `staged_open_cred` | `sd_ceph_staged_t` carries only the final oid; a cred-scoped stage would have to hold the ioctx and keep the connection pinned across **both** commit and abort. |
| `mkdir_cred` | Directories are synthetic (ADR-1) — `mkdir` touches no object, so there is no cluster-side authority to scope. |

Pinned by leg (f) of `tests/ceph/sd_ceph_cred_live_test.c` against the live demo
cluster: `bob` (`allow rwx`) drives the whole lifecycle through the `_cred`
slots; `readonly` (`allow r`) is refused **by the cluster** on `setxattr_cred`,
`truncate_path_cred` and `unlink_cred`, with a service-credential `stat` proving
the object survived byte-for-byte and a `listxattr` proving the denied attribute
never landed; and a wrong-kind credential in `fallback_deny` mode is refused on
`stat_cred`/`unlink_cred`/`opendir_cred` **on an object that exists** — the only
arrangement in which a silent fallthrough to the service account would show up as
a success rather than as an indistinguishable `ENOENT`.

---

### 4.11 Nearline on `http` and `remote` — the cap is a declaration, never an inference

`residency` and `recall` are the pair every protocol plane advertises tape state
from: *are these bytes readable right now*, and *start bringing them back*, with
the first paying nothing and the second never blocking. Both origin drivers
carried neither slot until this wave, which meant `brix_vfs_residency` answered
`ONLINE` for every key (its answer for a driver with no residency model) and the
first read of an archived object came back as an opaque `403 InvalidObjectState`
or a `425` — a hard error, with no way to say "it is on tape, ask again later"
and no way at all to start the recall.

| | `http` | `remote` (s3) |
|---|---|---|
| residency wire | `POST {base}/archiveinfo` `{"paths":["/k"]}` → `[{"locality":…}]` (WLCG Tape REST API) | one signed `HEAD` → `x-amz-storage-class` / `x-amz-restore` / `x-amz-archive-status` |
| recall wire | `POST {base}/stage` `{"files":[{"path":"/k"}]}` → `201 {"requestId":…}` | `POST ?restore` (RestoreObject) |
| request id | the API's `requestId`, carried back to the caller | none — S3 issues no id, so `reqid_out` stays empty, which the slot contract already defines as "queued, poll the state" |
| unknown token | **`EIO`** | **`ONLINE`** |

That last row is the one deliberate asymmetry, and it is worth stating plainly
because a later "make these consistent" change would break one of them. The Tape
REST API's localities are a **closed vocabulary** (`DISK` / `TAPE` /
`DISK_AND_TAPE` / `LOST` / `NONE` / `UNAVAILABLE`), so a token this build has not
seen means we are not talking to that API at all — answering `ONLINE` there would
hand a caller a file that is still on tape. S3 storage classes are an **open**
one: AWS adds them routinely and every class it has ever added outside
`GLACIER` / `DEEP_ARCHIVE` serves a `GET` directly, so guessing "archived" for a
new name would park every open on a restore that was never needed. Both units
pin their own direction (`tests/unit/test_sd_{http,remote}_nearline.c`).

Three more verdicts that are invisible from a passing build, and so are asserted
rather than merely commented:

- `x-amz-archive-status` **overrides** an online-looking storage class.
  `INTELLIGENT_TIERING` keeps its class name when it demotes an object into an
  archive tier and reports the demotion only in that header.
- `ongoing-request="false"` is `ONLINE`, not `NEARLINE`. A completed restore
  leaves a readable temporary copy; calling it `NEARLINE` makes the cache pay for
  the same archive retrieval a second time.
- A residency call that **failed** must never fall through to a recall. A denied
  `HEAD` becoming a billable `RestoreObject` is the one outcome neither slot may
  produce, so `recall` runs residency first and returns `NGX_ERROR` on it.

#### The operator surface, and why it cannot be inferred

`BRIX_SD_CAP_NEARLINE` is a **contract**, not a hint: `tier_build` refuses to
compose a nearline backend without a cache tier in front of it (§9.4) — the cache
*is* the recall target. So the cap can only ever come from an explicit operator
declaration. Inferring it from a storage class seen on one object would turn
every working `s3://` export into a **startup failure** the first time somebody
tiered a single key to GLACIER.

Both spellings are query options on the origin spec, alongside the existing
`?put_checksum=1`:

```nginx
brix_storage_backend https://tape.example.org/data?tape_api=/api/v1;
brix_storage_backend s3://s3.example.org/bucket?nearline=1&restore_days=7;
```

| option | driver | effect |
|---|---|---|
| `?tape_api=<abs path>` | `http` | the origin fronts an HSM and speaks the WLCG Tape REST API at that base. Non-empty is the whole arming condition. |
| `?nearline=1` | `remote` | the bucket is archive-backed: residency reads the storage class, recall issues RestoreObject |
| `?restore_days=N` | `remote` | how long a restored copy stays readable; `0` leaves the driver's default |

`http` needs a **value** where `remote` needs only a flag, which is why neither is
spelled as a scheme the way `xroot` does it (`root+tape://`) — an API base path
is not derivable from the data URL, and a bare scheme cannot carry it.

Three details in that surface are load-bearing:

1. **The value terminator is `&` *or* `|`.** T11 made origin specs
   pipe-separated for failover, so a reader that stopped only at `&` would
   silently swallow the next origin's URL into the option. Both readers
   (`brix_vfs_origin_opt_str` / `_int`, one copy, in `vfs_backend_config.c`)
   stop at either.
2. **Both are stamped on *every* registration, not only when present.** A reload
   that DROPS the declaration must leave a plain origin, not a stale nearline cap
   from the previous cycle — which would be a startup failure nobody asked for.
3. **The API base is an allowlist, not a sanitiser.** It is concatenated into a
   request line, so `sd_http_tape_init` accepts only RFC 3986 unreserved bytes
   plus `/`. A stray CR/LF would split the request and a `?` or `#` would make
   `/archiveinfo` part of a query or fragment. A base with anything else leaves
   the instance **un-armed** (the export keeps working as plain http) rather than
   being cleaned up into a base the operator never wrote and cannot see in their
   config.

Neither driver gives either slot a `_cred` twin, and that is correct rather than
convenient: a recall is the gateway's own housekeeping, driven by the cache tier
on a miss, and the restored copy is charged to and owned by the export — not by
whichever user's read happened to trigger it.

---

## 5. The unified caching layer around the drivers

The drivers are the bottom of a four-part caching machine:

```
                         client read /write
                               │
   ┌───────────────────────────┼────────────────────────────────────────────┐
   │ READ  : ready? ─yes► serve from cache_storage (driver)                   │
   │         ─no► fill: origin_inst->pread → cache_storage->staged_write      │
   │                     → staged_commit → commit-then-verify                 │
   │ WRITE : client → PRIMARY (driver)  → stage copy (driver) → origin (FRM)  │
   │                                                                          │
   │ REAPER timer ─► watermark_purge(cache_root) oldest-first to LOW          │ [B]
   │ WRITE-open ──► stage_admit(stage_root): <low ALLOW / band WAIT / ≥high REJECT │ [C]
   └───────────────────────────┬──────────────────────────────────────────────┘
                                ▼
   SD seam:  posix | pblock | remote(s3) | xroot(root) | … (read & write roles)
                                ▲
            shared statvfs+TTL sampler (cache_fs_sampler) feeds [B] and [C]
```

- **Read cache, sidecar/state, write-back staging** are each an independent SD
  role (POSIX by default, or a configured backend) — a node can run pblock for its
  primary, a pblock read-cache, and a POSIX state tree, all at once.
- The `.cinfo` v3 record is the single write-back/present-bitmap state.

> **Lesson — the write-back spool is a private namespace the tier must build.**
> `sd_stage` advertises `BRIX_SD_CAP_RANDOM_WRITE`, so `brix_vfs_writer_open` takes
> the *random* branch — `brix_vfs_open(WRITE|CREATE|TRUNC)` **without**
> `BRIX_VFS_O_MKDIRPATH`. The client's `kXR_mkpath` builds the parent chain in the
> **export** and the flush builds it on the **origin**; nobody built it in the
> **spool**, so with a stage tier configured a create of *any* nested key failed
> `kXR_NotFound` (3011). `sd_stage_store_mkparents()` now walks the key's parents
> through the store driver's `mkdir` slot on every create-open. The whole-object
> *staged* leg never hit this — the POSIX store's `staged_open` mkpaths its own
> parents. Consequence, accepted: with a stage tier a nested create **without**
> `kXR_mkpath` now succeeds, matching every other driver-backed export (the flush
> materialises the remote parents itself; a source-parent pre-check would break
> nested uploads through a stage gateway to a remote origin). The stock-parity
> "no mkpath ⇒ NotFound" tests run against plain POSIX exports and are unaffected.
> Regression: `tests/test_stage_hydration.py` (nested lands byte-exact / unwritable
> spool refuses the open / traversal key materialises nothing).

> **Lesson — `.cinfo` is state, never a candidate.** The watermark reaper
> enumerates the cache tree and evicts oldest-first. The eviction skip-list
> covered `*.part`/`*.lock`/`.meta` but **not** `.cinfo`. Evicting a dirty file's
> `.cinfo` orphaned its write-back-dirty protection → on the next tick the (now
> "clean"-looking) data file could be reaped. `.cinfo` joined the skip-list.

### 5.1 The decorators and the credential — an instance-keyed forwarder

`sd_cache` and `sd_stage` are **decorators**: instances whose vtable forwards
most path ops to a `source` instance (the origin driver) while keeping the data
ops for themselves. Everything in §4 about honest capability absence applies to
them one tier further out, and one rule governs the whole file:

> `brix_sd_<op>_maybe_cred()` decides cred-slot vs plain-slot vs deny-refusal by
> looking at **the instance it is called on**. A decorator that publishes
> `.mkdir` and no `.mkdir_cred` therefore reads, one tier up, exactly like a
> driver with no per-user support — whatever the source can actually do.

Both decorators shipped every plain namespace/xattr/dir slot and **none** of the
`_cred` twins. The VFS namespace sites worked around that: `vfs_ns_cap_ok()`
probes, and every site dispatches against, `brix_vfs_ns_leaf(ctx->sd)` — which
walks past `sd_stage`/`sd_cache` (`brix_sd_stage_source_instance` /
`brix_sd_cache_source_instance`) to the leaf origin instance. So the credential
did reach the origin's `_cred` slot; there was no live confused deputy on that
path. **The bypass is the cost.** Dispatching on the leaf skips the decorator's
own work — `sd_cache_stat`'s answer-from-a-COMPLETE-`.cinfo` shortcut, and, the
part that bites, its automatic `brix_cstore_evict` after a mutation.

Both halves are now closed:

- **The twins exist.** Each op on both decorators is *one* `_common` body taking
  a possibly-NULL credential, with a plain wrapper passing `NULL` (so the plain
  path is provably the path it always took) and a `_cred` wrapper that
  re-dispatches through `brix_sd_<op>_maybe_cred` against the **source**. The
  decorator adds no policy of its own; it only stops erasing the credential, and
  a caller that dispatches on the decorator *directly* now carries it correctly.
  Two pre-existing contracts survive the refactor and are pinned by tests: the
  xattr ops report **`ENOTSUP`** (via a `*_src_no_xattr()` pre-check) where the
  shared forwarder would say the vaguer `ENOSYS`, because callers read `ENOTSUP`
  as "this filesystem has no extended attributes"; and a `setattr` with no
  source slot stays **`NGX_OK`**, an advisory no-op.
- **The bypassing sites compensate.** Only `vfs_unlink.c` and `vfs_rename.c`
  had re-added the eviction by hand. Four more mutate origin state and did not:
  `vfs_copy.c` (the COPY **destination** — a read of it kept serving the
  pre-copy object), `vfs_sync.c` (`brix_vfs_truncate_path` — the store held the
  old full-length copy), `vfs_mkdir.c` (**both** the chmod and the setattr site —
  the `.cinfo` `sd_cache_stat` answers from still carried the old mode), and
  `vfs_xattr.c` (set/remove — including the checksum record a fill seeds,
  §4.5.1). Each now calls `brix_metric_cache_evicted(brix_vfs_metrics_proto(ctx),
  brix_sd_cache_evict(ctx->sd, key))` on success — a no-op when `ctx->sd` is not
  a cache, so the POSIX and stage-only paths are untouched.

> **Lesson — an absent `_cred` twin on a *decorator* is not a confused deputy;
> it is why the layer above stopped calling you.** The VFS routed around the
> gap rather than signing as the export, so the symptom was never an auth
> failure — it was **stale cached bytes and stale cached metadata** at every
> bypassing site that forgot to re-add the invalidation the decorator would have
> done for free. Look for the workaround before you look for the leak.

The regression gate is structural rather than behavioural, because the defect
class is "a slot nobody added": `tests/c/test_decorator_cred_forward.c` links the
real `sd_cache_forward.o` and `sd_stage.o` over a fake source driver and asserts
`drv->op == NULL || drv->op_cred != NULL` for all twelve ops, then routes every
cred slot and checks the source saw the *same* credential, that a successful
`unlink_cred` evicted (and a failed one did not), and that deny-mode refuses all
22 ops with `EACCES` **without ever reaching the source**. Run it with
`PYTHONPATH=. python3 -m cmdscripts.c_regression_units decorator_cred_forward`.

Now that the twins exist, the VFS namespace sites *could* dispatch on `ctx->sd`
and drop the hand-maintained evictions entirely. That is a larger change across
six files and is deliberately left for its own pass.

### 5.2 Decorator parity — a slot on one tier and not the other

The two decorators wrap the *same* source and compose in **either order**
(`cache` over `stage`, `stage` over `cache`), so a namespace slot published by
one and not the other does not merely lose a capability — it makes the export's
capability set depend on which tier happened to end up on top. `truncate_path`
was exactly that: relayed by `sd_stage`, absent from `sd_cache`.

The user-visible half of the bug was one tier up. `brix_vfs_truncate_path`
**gated on the top driver and dispatched on the leaf** — it asked
`ctx->sd->driver` whether a path-native truncate existed, then called
`brix_sd_truncate_path_maybe_cred()` against `brix_vfs_ns_leaf(ctx->sd)`. Over a
cache-fronted `root://` export the gate said no, and the whole path-native
branch was skipped in favour of the open + `ftruncate` + close staging round
trip the slot exists to avoid.

The fix is *not* symmetric with §5.1's, and getting it backwards would have made
things worse:

- **The gate moved to the leaf, not the slot to the gate.** Adding
  `.truncate_path` to `sd_cache` alone would have let the gate pass over
  cache→`http`/`s3`/`posix` — backends with no path-native truncate at all —
  and `brix_sd_truncate_path_maybe_cred()` returns **`ENOSYS`** when the leaf
  has neither slot. A working fallback would have become an error. The gate now
  reads the leaf's driver, which is the instance that will actually be called.
- **The decorator answers `ENOTSUP`, never the relay's `ENOSYS`.** Same contract
  as the xattr ops: a pre-check on the source's two slots, so a caller reads
  "this backend cannot resize by path" and takes its fallback.
- **Success evicts.** `truncate_path`, `server_copy` (the **destination** key —
  the source object is unchanged), `setattr`, `setxattr` and `removexattr` now
  invalidate the cstore entry the way `unlink`/`rename` always did. The xattr
  pair matters more than it looks: the store copy carries the object's
  attributes, **including the digest a fill seeds as `user.XrdCks.<alg>`**
  (§4.5.1). Eviction is conditioned on the source returning `NGX_OK`, so a
  transient origin error cannot throw away a valid entry on every retry.

Why the VFS still dispatches namespace ops on the **leaf** rather than on
`ctx->sd`, now that the twins and the parity both exist: only the VFS can label
the eviction metric with the protocol that caused it
(`brix_metric_cache_evicted(brix_vfs_metrics_proto(ctx), …)`, INVARIANT #8), and
a driver has no ctx. Moving the dispatch up would silence that metric at every
site or make it report zero behind a decorator that had already evicted. The
decorator's own eviction is therefore for callers that dispatch on it
**directly**; the six VFS sites keep their explicit `brix_sd_cache_evict` call,
and the conversion stays deferred with a concrete reason rather than as a
loose end.

The gate is structural and lives in the Python guard, not the C unit, because
`brix_sd_cache_driver` is `static` and `sd_cache.o` is deliberately not linked
into `test_decorator_cred_forward` — the unit can only see `sd_stage`'s struct.
`tools/ci/check_sd_driver_conformance.py` parses both decorator initializers and
fails on the symmetric difference of their slot sets ∩ `PARITY_OPS`. The **byte**
plane is excluded on purpose: the cache serves reads from its store
(`read_advise`, `read_sendfile_fd`) and the stage tier owns writes (`fsync`,
`ftruncate`, `pwrite`), so those slots differ by design.

---

## 6. Per-driver subdirectories — the layout & its mechanics

```
  src/fs/backend/
    sd.h            ← the seam (vtable, caps, handles, accessors, registry API)
    sd_registry.c   ← driver table + per-worker instance creation
    csi_*.{c,h}     ← filesystem page-checksum integrity (not a storage driver)
    README.md
    posix/   block/   pblock/   rados/   s3/   remote/   xroot/    ← one per driver
```

Moving a driver into `<name>/` deepens its relative includes by one level:

```
   before (backend/sd_posix.c)        after (backend/posix/sd_posix.c)
   #include "sd.h"            ──►      #include "../sd.h"
   #include "../vfs_internal.h" ─►     #include "../../vfs_internal.h"
   #include "../../compat/x.h"  ─►     #include "../../../compat/x.h"
   #include "sd_pblock_catalog.h"      (same driver dir — UNCHANGED)
```

> **Lesson — a `.` in a `sed` pattern is a wildcard.** Rewriting `./config` paths
> with `s|sd_pblock.c|pblock/sd_pblock.c|` silently mangled `sd_pblock_catalog.c`
> → `sd_pblock.catalog.c`, because `sd_pblock.c` matched `sd_pblock_c` inside the
> longer name (the `.` matched `_`). Escape the dot or anchor the match.

> **Lesson — three places know a driver's path.** Adding/moving a driver touches:
> (1) the top-level `./config` `NGX_ADDON_SRCS`, (2) `sd_registry.c` (its header
> include + table row), and (3) `shared/xrdproto/Makefile` if the client links it
> (`posix`, `block`, `s3`). A new `.c` always needs `rm -rf objs && ./configure &&
> make` — `configure` over stale objects yields mixed-ABI garbage (thread_pool =
> 0x1 SIGSEGV / EBADF).

---

## 7. Lessons index (quick reference)

| # | Lesson | Where it bit |
|---|---|---|
| 1 | Caps are honest absences; read-only = NULL write slots (structural safety) | `remote`/`xroot` |
| 2 | `fd == -1` ⇒ memory-served; `read_sendfile_fd` is the switch | object stores |
| 3 | pblock `fsync` commits catalog size — fsync before re-opening for read | write-through |
| 4 | `sd_s3` signs `host:port` for EVERY port → force `Host: host:port` | S3 SigV4 |
| 5 | `sd_s3` was client-only — add `s3/sd_s3.c` to the module `./config` | S3 origin |
| 6 | Keep `backend/` free of `cache/`: inject the transport (`sd_remote`) | layering |
| 7 | A **memory sink** lets a streaming origin reader serve driver `pread` | `sd_xroot` |
| 8 | `brix_cache_sink_pwrite` returns `0`/`-1`, not a byte count | fill loops |
| 9 | `.cinfo` must be in the eviction skip-list (dirty-protection durability) | watermark reaper |
| 10 | `brix_format_host_port` always appends the port | S3 SigV4 |
| 11 | A `*/` inside a `/* … X509_*​/BEARER_* … */` comment closes it early | exec env edit |
| 12 | `sed` `.` is a regex wildcard — it mangled `sd_pblock_catalog` | reorg |
| 13 | New `.c` ⇒ `rm -rf objs && ./configure && make` (no incremental over stale objs) | build governance |
| 14 | In-process `root://` GSI/token client lives in libxrdc — delegate via exec | auth parity |
| 15 | WebDAV `DELETE` is type-blind and recursive — probe before `rmdir`/`unlink` | `sd_http` §4.4 |
| 16 | `HEAD` cannot tell a collection from an empty object — `PROPFIND Depth: 0` can | `sd_http` stat |
| 17 | The write-back spool is private: the tier builds the key's parents, not the client | `sd_stage` §5 |
| 18 | A missing `_cred` sibling is a **confused deputy**, not a missing feature — the plain slot signs as the export. Assert on the signing key, never the bytes | `sd_remote` §4.1.1 |
| 19 | A *lazy* slot's credential outlives the call that borrowed it — copy it onto the handle, wipe it in `close`, and refuse (never truncate) an unbounded token | `sd_remote` `opendir_cred` |
| 20 | An obj-keyed slot dispatches on **the object's** driver — a cache HIT is served by the STORE's driver, so it never reaches the origin's slot and a decorator vtable entry would be dead code. Hand the value to the tier that serves the fd | `§4.5.1` seed |
| 21 | An instance-keyed forwarder (`brix_sd_*_maybe_cred`) decides on **the instance it is called on** — a decorator missing a `_cred` twin reads as a driver with no per-user support, whatever its source can do | `sd_cache`/`sd_stage` §5.1 |
| 22 | Routing *around* a decorator to reach the leaf skips the decorator's own work — the four VFS sites that bypassed it for the credential also lost its cache invalidation, and served stale bytes/mode until each re-added `brix_sd_cache_evict` by hand | `vfs_copy`/`_sync`/`_mkdir`/`_xattr` §5.1 |
| 23 | Remote-chosen bytes in an XML body are an injection surface — hex-encode **both** the name and the value; the encoding doubles as a total, reversible mapping no "natural property" scheme can be | `sd_http` §4.9 |
| 24 | A named-prop `PROPFIND` returns the element for an **absent** property too, inside a 404 propstat — read the status, or "no such attribute" becomes "an empty one" | `sd_http` §4.9 |
| 25 | Two decorators wrapping the same source compose in either order, so a slot on one and not the other makes the export's capabilities depend on **composition order** — publish a namespace slot on both or on neither | `sd_cache`/`sd_stage` §5.2 |
| 26 | Gate on the same instance you dispatch on. `brix_vfs_truncate_path` asked the **top** driver and called the **leaf**, so a cache-fronted origin lost a capability its leaf had | `vfs_sync` §5.2 |

---

## 8. Adding the next driver (recipe)

1. `mkdir src/fs/backend/<name>/`; write `<name>/sd_<name>.c` defining a
   `const brix_sd_driver_t` (include the seam as `../sd.h`). Set **only** the
   caps the backend truly has.
2. `extern` it in `sd.h`; add a row to `sd_drivers[]` in `sd_registry.c`
   (`#include "<name>/sd_<name>.h"` for any header).
3. Register `src/fs/backend/<name>/sd_<name>.c` in the top-level `./config`.
4. For a **remote/origin** driver: keep it transport-agnostic and let the cache
   inject the transport (S3 model), or — if it must wrap an existing in-process
   client — depend on it explicitly and document the layering (xroot model).
5. `rm -rf objs && ./configure && make`. Add a unit test (`tests/c/`) for pure
   logic and an e2e (`tests/run_*.sh`) for the wired path. 3 tests minimum:
   success + error + security-negative.
