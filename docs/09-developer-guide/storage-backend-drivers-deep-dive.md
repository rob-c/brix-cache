# Storage Backend Drivers — Deep Dive (`pblock`, `s3`, remote `root://`)

> **Audience:** developers extending the storage layer or the read-through cache.
> **Scope:** the Storage Driver (SD) seam and every concrete driver — local
> (`posix`, `block`, `pblock`, `rados`), object (`s3`), and the two read-only
> *remote-origin* drivers used by the cache (`remote` = S3 origin, `xroot` =
> `root://` origin) — plus how the cache fronts them as one origin-agnostic
> "fold". Captures the architecture **and** the hard-won lessons from building
> them.
> **Companion docs:** [`pblock-storage-backend.md`](pblock-storage-backend.md),
> [`vfs-shared-architecture.md`](vfs-shared-architecture.md),
> [`src/fs/backend/README.md`](../../src/fs/backend/README.md),
> [`src/fs/cache/README.md`](../../src/fs/cache/README.md).

---

## 0. TL;DR

Everything above the storage layer — `root://`, WebDAV, S3 REST, the cache — talks
to **one narrow interface** (`xrootd_sd_driver_t`, the **Storage Driver / SD
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
  primary via `xrootd_storage_backend`; listed in `sd_drivers[]` (`sd_registry.c`).
- **`sd_s3`** — NOT a registered `xrootd_sd_driver_t`; it is the shared S3 *protocol
  handle library* (`sd_s3_open_read`/`size`/`pread`/`write`/`commit`). The client's
  S3 VFS and the module's `remote` driver both wrap it.
- **Cache-constructed drivers** (`remote`/`xroot`) — built on demand by the cache
  (`xrootd_sd_remote_create` / `xrootd_sd_xroot_create`) for read-through fill.
  `remote` (S3) is read-only. `xroot` is **also a registry-selectable primary**
  (`xrootd_storage_backend root://host:port`) with read **and** write (transparent
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
        ┌──────────────── SD seam  (xrootd_sd_driver_t, src/fs/backend/sd.h) ───────────────┐
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
xrootd_sd_instance_t   one per export/role   { driver, log, pool, state }
   │                                                              │
   │ driver->open(inst, key, flags, mode, &err)                  (driver-private:
   ▼                                                              POSIX: rootfd+root_canon
xrootd_sd_obj_t        one per open file      { driver, inst,     pblock: catalog handle
   │   fd      = real kernel fd OR NGX_INVALID_FILE (-1)          s3/remote: endpoint+creds)
   │   snap    = xrootd_sd_stat_t captured at open
   │   state   = driver-private per-open (object key, S3 handle, origin conn…)
   │   heap_shell = 1 if open() malloc'd THIS shell (caller frees the copy)
   ▼
xrootd_sd_staged_t     atomic write-then-publish { inst, state }
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
> (`xrootd_cache_origin_{getfattr,setfattr,listfattr,delfattr,rename}`). E2E:
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

> **Lesson — read-only by absence.** The `remote` (S3 origin) driver populates
> ONLY `open/close/pread/fstat/stat` and advertises `CAP_RANGE_READ` alone. Because
> every write/dir/xattr/staged vtable slot is `NULL`, it *cannot* be selected as a
> writable export primary — the safety is structural,
> not a runtime check.

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
| `pblock` | ✓ | ✓ | ✓ atomic | ✓ | ✓ | ✓ |
| `rados` (XrdCeph)¹ | ✓ | root-only² | opt-in copy | striper¹ | adv¹ | follow-on |
| **`sd_s3`** (object store)³ | ✓ HEAD | key-prefix | CopyObject | ✓ `get_meta`/`set_meta` | adv | ✓ multipart |
| `remote` (S3 cache origin)⁴ | ✓ (read) | — | — | — | — | — |
| **`xroot`** (remote root:// primary)⁵ | ✓ | follow-on | ✓⁵ | ✓⁵ | follow-on | ✓⁵ |

¹ Two layers. The **wired** `sd_ceph` driver (phase-60, gated `XROOTD_HAVE_CEPH`)
is basic librados: range read / random write / truncate only — **no** dirs /
rename / xattr / setattr yet. The **stock-XrdCeph libradosstriper path** (the
striper data plane, site `lfn2pfn` translation, stripe helpers, advisory codec, and
the striper xattr wrappers — `sd_ceph_striper.c`, `site_n2n.c`,
`sd_ceph_compat.c`, `meta_advisory.c`, gated `XROOTD_HAVE_RADOSSTRIPER`) is **built
and unit-tested but not yet wired into the live vtable**; final integration +
live-pool validation (and the exact site `lfn2pfn` rule) is the open follow-on.
² target (stock-XrdCeph parity): flat object namespace, `opendir` only on `/`.
³ **`sd_s3` object metadata** (`src/fs/backend/s3/sd_s3.c`): `sd_s3_get_meta` reads
an `x-amz-meta-<name>` header (signed HEAD); `sd_s3_set_meta` rewrites the user
metadata via a copy-onto-self with `x-amz-metadata-directive: REPLACE`
(`sd_s3_sign_ext` signs the extra `x-amz-*` headers, so it works against real AWS).
The advisory POSIX-attr blob rides in `x-amz-meta-xrd-unixattr`
(`sd_s3_get/set_unixattr` ↔ `meta_advisory.c`). E2E: `tests/run_sd_s3_meta.sh`.
⁴ the `remote` (S3) driver is a read-only **byte fill** source; it exposes no write
or metadata slots (see "read-only by absence" above).
⁵ **`xroot` as a writable primary backend** (`xrootd_storage_backend
root://host:port`): the export's storage IS a remote XRootD server. The byte data
path is done — **stat + read + write** (`pwrite`/`ftruncate`/`fsync` over
kXR_write/_truncate/_sync) — so a write streams straight through to the origin
(**transparent write-through, no local copy**) and a read serves from it. This
required teaching the kXR handle path (and `xrootd_vfs_file_stat`, the WebDAV lock
pre-check) to accept a **no-fd (memory-served) primary** (additively, gated on
`sd_obj.driver`), since no object/remote backend had ever been a root:// *primary*
before. **Staged-write** (WebDAV PUT / S3 POST) works two ways:
**(a) Mode A — passthrough** (default): `staged_open/write/commit` stream the body
straight to the remote final path (no local copy; non-atomic on the remote).
E2E: `tests/run_remote_backend_write.sh` (root://), `tests/run_remote_backend_webdav.sh`
(WebDAV). **(b) Mode B — write-back** (`xrootd_webdav_storage_staging on`): the upload
stages to a LOCAL POSIX temp under the export root (fast, random-write, atomic), then
`xrootd_vfs_staged_promote()` reads it and drives the driver's staged path to the remote
on commit, dropping the local temp. E2E: `tests/run_remote_backend_staging.sh`.
Namespace (mkdir/rename), xattr/setattr forwarding, remote-side atomicity + a durable
journal + backpressure on Mode B are later phases — see
`docs/superpowers/specs/2026-06-29-writable-remote-root-staged-write-design.md`.
**Anonymous** origin only (the in-process wire client's mode); authenticated origins
use Mode B / the native-client path. Recommend a `thread_pool` on the node (the remote
write offloads to AIO).

> **Two ways a remote `root://` filesystem gets full metadata.** (a) The
> **transparent proxy** (`xrootd_proxy`) relays *every* opcode to the origin by
> raw `requestid` — so a proxied remote `root://` already supports the **whole**
> phase-space (mkdir/stat/chmod/mv/rm/xattr), live, not via the cache drivers.
> Proof: `tests/run_proxy_metadata_phase.sh`. (b) The **cache** drivers
> (`remote`/`xroot`) front an origin for *byte* reads only; they do not forward
> metadata (that would need a metadata-aware cache, a separate concern).

> **The S3 REST endpoint is metadata-capable.** The S3 server
> (`src/s3/usermeta.c`) persists `x-amz-meta-*` user metadata (one
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
  xrootd_s3_transport_t  (sd_s3_transport.h)
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

> **Lesson — `xrootd_format_host_port` ALWAYS appends the port** (`%s:%u`, even
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

> **Gotcha — standalone consumers must `xrootd_crypto_init()` once.** SigV4's HMAC
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
  │  xrootd_cache_sink_pwrite(sink, buf, n, off)  ── staged_write or mem/fd    │
  │            │                                                               │
  │            ▼                                                               │
  │  cache_inst->driver->staged_commit()  → commit-then-verify-then-publish    │
  └──────────────────────────────────────────────────────────────────────────┘
```

### 4.1 `remote` (S3 origin) — delegation, transport injected by the cache

```
  fetch.c::xrootd_cache_fetch_origin_s3
        │ build xrootd_sd_remote_cfg_t { host,port,tls,bucket,ak,sk,region,
        │                                transport = &server libcurl xport }
        ▼
  xrootd_sd_remote_create(cfg) ─► sd_remote instance (CAP_RANGE_READ)
        │ open("/sub/file")
        ▼
  sd_remote_open → builds sd_s3_open_params("/bucket/sub/file") → sd_s3_open_read
        obj->state = sd_s3_file*   obj->fd = -1
        │ pread → sd_s3_pread (Range GET)   stat/fstat → HEAD size
        ▼
  sd_s3  (SigV4)  ──►  s3_transport.c (libcurl)  ──►  S3 origin
```

> **Lesson — keep the backend layer free of the cache.** `sd_remote` is
> transport-**agnostic**: the cache *injects* `&xrootd_s3_origin_curl_transport`.
> No `cache/` or libcurl dependency leaks into `backend/` — exactly the same trick
> `sd_s3` already used for the client.

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
> into the caller's buffer, `xrootd_cache_sink_t` grew a `mem`/`mem_cap` mode; the
> driver points `mem` at the caller buffer and `dst_off = 0`.

> **Lesson — `xrootd_cache_sink_pwrite` returns `0`/`-1`, NOT a byte count.** The
> first S3/root fill loops wrote `if (sink_pwrite(...) != n) fail;` — and since a
> success returns `0`, *every* successful write looked like a failure (S3 read was
> fine; the cache write "failed"). The correct check is `!= 0`.

> **Lesson — layering exception, made explicit.** Unlike `sd_remote`, `sd_xroot`
> *does* depend on `cache/origin_*.c` — it exists precisely to expose that client
> as an SD backend, so the dependency is inherent and documented in the header,
> not a slip.

### 4.3 The fill dispatch + the origin auth matrix

```
  xrootd_cache_fetch_origin(t)  — by cache_origin_scheme + creds
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

> **Lesson — `.cinfo` is state, never a candidate.** The watermark reaper
> enumerates the cache tree and evicts oldest-first. The eviction skip-list
> covered `*.part`/`*.lock`/`.meta` but **not** `.cinfo`. Evicting a dirty file's
> `.cinfo` orphaned its write-back-dirty protection → on the next tick the (now
> "clean"-looking) data file could be reaped. `.cinfo` joined the skip-list.

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
| 8 | `xrootd_cache_sink_pwrite` returns `0`/`-1`, not a byte count | fill loops |
| 9 | `.cinfo` must be in the eviction skip-list (dirty-protection durability) | watermark reaper |
| 10 | `xrootd_format_host_port` always appends the port | S3 SigV4 |
| 11 | A `*/` inside a `/* … X509_*​/BEARER_* … */` comment closes it early | exec env edit |
| 12 | `sed` `.` is a regex wildcard — it mangled `sd_pblock_catalog` | reorg |
| 13 | New `.c` ⇒ `rm -rf objs && ./configure && make` (no incremental over stale objs) | build governance |
| 14 | In-process `root://` GSI/token client lives in libxrdc — delegate via exec | auth parity |

---

## 8. Adding the next driver (recipe)

1. `mkdir src/fs/backend/<name>/`; write `<name>/sd_<name>.c` defining a
   `const xrootd_sd_driver_t` (include the seam as `../sd.h`). Set **only** the
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
