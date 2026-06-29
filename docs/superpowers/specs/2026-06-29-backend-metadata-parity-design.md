# Backend Metadata & Namespace Parity — Design Spec

**Date:** 2026-06-29
**Status:** Approved for planning
**Goal:** Bring every storage backend (`rados`, `s3`, the client S3/WebDAV VFS, and
the read-only cache-origin drivers) up to the metadata/namespace phase-space that
`posix`/`pblock` already provide — xattr, setattr (advisory), directories, rename,
and atomic staged publish — so the full set of storage commands works over
`root://`, WebDAV, and S3-REST regardless of which backend is mounted.

## Context — the gap is at the driver vtable, not the protocol

A complete end-to-end audit shows the **protocol, VFS, and native-client layers
already implement the whole metadata phase-space**:

```
  CLIENT                 WIRE / PROTOCOL                 VFS                 DRIVER (SD seam)
  xrdc_fattr      ──►  kXR_fattr (src/fattr/)     ──► xrootd_vfs_*xattr  ──►  getxattr/setxattr/…
  xrdc_chmod      ──►  kXR_chmod (write/chmod.c)  ──► xrootd_vfs_chmod   ──►  setattr  (or POSIX fallback)
  xrdc_setattr    ──►  kXR_setattr (write/ext_ops)──► xrootd_vfs_setattr ──►  setattr
  WebDAV PROPPATCH──►  dead_props.c               ──► xrootd_vfs_setxattr──►  setxattr
  S3   ?tagging   ──►  s3/tagging.c               ──► xrootd_vfs_setxattr──►  setxattr
  xrdfs mkdir/mv  ──►  kXR_mkdir/mv/truncate      ──► xrootd_vfs_mkdir/… ──►  mkdir/rename/…
```

`xrootd_vfs_chmod` already routes to the driver `setattr` slot when present and
otherwise falls back to a confined POSIX `chmod`. So **no new wire commands or
client commands are required for the common ops** — the work is implementing the
driver vtable slots and defining each backend's metadata semantics.

### Driver vtable gap matrix (what this spec closes)

Status legend: ✓ shipped · **add** planned · *built* = done by this work
(2026-06-29).

| slot | posix | pblock | rados | s3 | remote/xroot |
|---|---|---|---|---|---|
| `getxattr/setxattr/listxattr/removexattr` | ✓ | ✓ | **add** | *built*³ | read-side only |
| `setattr` (mode/mtime/uid/gid, advisory) | ✓¹ | ✓ | **add** | *built*³ | — |
| `mkdir/opendir/readdir/closedir` | ✓ | ✓ | **add** | n/a⁴ | — |
| `rename` | ✓ | ✓ | **add** | CopyObject⁴ | — |
| `staged_open/write/commit/abort` | ✓ | ✓ | **add** | ✓² | — |

¹ via the VFS confined-POSIX fallback. ² `sd_s3` already has multipart write.
³ **shipped:** the S3 server persists/echoes `x-amz-meta-*` user metadata
(`src/s3/usermeta.c`, PUT/GET/HEAD + CopyObject COPY/REPLACE), and the shared
`sd_s3` driver gained `get_meta`/`set_meta` + advisory `get/set_unixattr` with a
SigV4-over-extra-headers signer (`sd_s3_sign_ext`). Live-tested:
`tests/run_s3_usermeta.sh`, `tests/run_sd_s3_meta.sh`. Decision context: a remote
`root://` filesystem already supports the **full** metadata phase-space via the
transparent proxy (`tests/run_proxy_metadata_phase.sh`), so the cache-origin
read-side `remote`/`xroot` xattr slots were de-scoped (no live consumer).
⁴ S3 has no directories (key-prefix namespace); "rename" is CopyObject at the REST
layer (`src/s3/copy.c`), now metadata-directive aware.

## Global constraints (from the repo rules)

- **No `goto`** in `src/`/`shared/`/`client/`; early-return + helper decomposition.
- **Functional/modular**; one job per function; table/descriptor dispatch.
- **All data byte I/O stays below the SD seam**; metadata ops are driver slots.
- **3 tests per change** (success + error + security-negative). Where a real
  cluster/endpoint is unavailable in CI, unit-test the pure logic and gate the
  integration test on availability (skip otherwise) — the existing `sd_ceph`
  pattern.
- New `.c` files register in `./config`, then `rm -rf objs && ./configure && make`.
- New concepts ship with docs + tests in the same change. **Operator drives git.**

## Cross-cutting: the advisory "unix-metadata" convention

Object stores have no native POSIX mode/mtime/uid/gid. Per the approved
**advisory** model, every backend that lacks them stores them in a **reserved
metadata slot** and returns them on `stat`, so `chmod`/`utime` round-trip:

```
  reserved name:  user.xrd.unixattr           (rados xattr / S3 x-amz-meta-xrd-unixattr)
  encoding (fixed, parseable, libc-only):
      "v1 mode=0644 uid=1000 gid=1000 mtime=1782726000 mtime_ns=0"
```

A single shared codec (`src/fs/backend/meta_advisory.{c,h}`, ngx-free) encodes/
decodes this string and merges it into an `xrootd_sd_stat_t`. `rados` and `s3`
(and the client S3/WebDAV VFS) all reuse it, so semantics are identical and a
file's mode set over one access method reads back over another.

```
  setattr(mode=0640):  read user.xrd.unixattr → patch mode → write back
  stat():              striper->stat / S3 HEAD → base size+mtime → overlay user.xrd.unixattr
```

> The data-store's own mtime (set on write) is the fallback when no advisory
> mtime is present; an explicit `utime` overrides it advisorily.

---

## Phase 1 — `rados` (sd_ceph): **100% XrdCeph-compatible**, via libradosstriper

> **REVISED after auditing the stock XrdCeph plugin (`/tmp/xrootd-src/src/XrdCeph`).**
> Sites hold Pb+ of data and >1M objects in the stock on-RADOS layout, so the
> driver MUST read/write that exact format. The earlier "omap namespace" idea and
> the **current `sd_ceph.c` (raw single-object, hashed keys, no striper) are both
> INCOMPATIBLE** with it. The current driver's own header already flags
> libradosstriper interop as the deferred follow-on — this phase is that work.

### 1.0 The compatibility contract (reverse-engineered, must be matched byte-for-byte)

Stock XrdCeph (`XrdCephPosix.cc` / `XrdCephOss.cc`) stores every file through
**`libradosstriper`** — there is no separate namespace; the object names ARE the
paths, and "directories" are implicit slash-prefixes in a flat pool.

```
  logical file  "/atlas/run42.root"   in RADOS pool  "<pool>"  (default "default")
        │  (optional ceph.namelib lfn2pfn translation)
        ▼
  libradosstriper object  named  "/atlas/run42.root"
        │  striped across RADOS objects, stripe index = ".%016x":
        ▼
   /atlas/run42.root.0000000000000000   ◄── FIRST stripe; carries:
   /atlas/run42.root.0000000000000001        • xattr striper.layout.stripe_unit
   /atlas/run42.root.0000000000000002        • xattr striper.layout.object_size
                  …                            • the striper-managed size (striper->stat)
                                               • ALL user xattrs (striper->setxattr)
   default layout: object_size = 4 MiB, plus stripe_unit / stripe_count
```

| op | stock XrdCeph behavior (the baseline we must not break) |
|---|---|
| read/write/trunc/remove | `rados_striper_*` on the path-named striper object |
| `stat` | `striper->stat(name,&size,&atime)`; **mode is faked**, no real uid/gid |
| xattr get/set/list/rm | `striper->{get,set,rm,get}xattr[s](name,…)` (lands on the first stripe) |
| `opendir` | **only `/` is accepted**; anything else → `ENOENT` |
| `readdir` | **full pool scan**, keep only oids ending `.0000000000000000`, return the oid with that 17-char suffix stripped (= the logical file name) |
| `Mkdir` / `Remdir` | **`return 0`** — a deliberate no-op "lie" so GFAL2 doesn't choke |
| `Chmod` | **`-ENOTSUP`** |
| `Rename` | **`-ENOTSUP`** |
| `Create` | **`-ENOTSUP`** |
| name translation | `ceph.namelib` plugin → `XrdOucName2Name::lfn2pfn` (default identity) |

### 1.0a GridPP Ceph landscape — TWO architectures (researched)

There is **no single "Ceph backend"** across the sites; there are two, and the
`ceph.namelib`/`oss.namelib` means different things in each:

| Site | Architecture | Backend we use | namelib maps LFN → | mode/dirs/rename |
|---|---|---|---|---|
| **RAL ECHO** (T1) | **XrdCeph / RADOS** (libradosstriper) | the `rados` driver (Phase 1) | a RADOS object name: `<pool>:<spacetoken>/<file>` (pool = `:`-prefix, one pool per VO, 8+3 EC) | faked / no-op / ENOTSUP |
| **Glasgow** (ScotGrid) | **XrdCeph / RADOS**, "following RAL, T2 bias" | the `rados` driver | RAL-style `<pool>:…/<file>` (site-tuned) | as RAL |
| **Lancaster** | **XRootD-on-CephFS** (POSIX, kernel/fuse mount; migrated Q1-2022) | **`sd_posix` on the CephFS mount** | a POSIX path (localroot + LFN / deterministic Rucio path) | **native (MDS): real mode, dirs, rename, xattr** |
| **Manchester** | **XRootD/CephFS** (POSIX; migrated Q1-2024, 6.8 PB ex-DPM) | `sd_posix` on CephFS | a POSIX path | native |
| **Brunel** | XRootD-on-CephFS | `sd_posix` on CephFS | a POSIX path | native |

**Decisive implication:**

- **CephFS sites (Lancaster, Manchester, Brunel, …) need NO new backend work.**
  CephFS *is* a POSIX filesystem; `sd_posix` on the mount already gives full
  xattr/setattr/dirs/rename parity via the MDS. Their "namelib" is an LFN→path
  mapping handled at the path layer (an `oss.namelib`/`localroot` equivalent), not
  an object-name scheme. *(An optional `libcephfs` OSS driver — à la
  `cern-eos/xrootd-cephfs`, no kernel mount — is a possible future add, but not
  required for parity.)*
- **The Phase-1 `rados` (libradosstriper) work targets the XrdCeph/RADOS sites
  (RAL, Glasgow)**, where mode is faked and chmod/rename are ENOTSUP — exactly
  where the advisory-metadata model (Phase 0) earns its keep.

### 1.0b namelib & pool — pluggable, per the chosen architecture

- **namelib: pluggable `lfn2pfn`/`pfn2lfn`** (`src/fs/backend/rados/sd_ceph_n2n.{c,h}`).
  For RADOS sites the rule produces the object name (RAL: `<pool>:<spacetoken>/<file>`);
  it must match the site's `ceph.namelib` exactly. **OPEN ITEM — supply the exact
  rule per target site before touching production data**; verified by translating a
  known LFN and matching a real object in the pool.
- **Pool: one pool per export, from config** (`xrootd_rados_pool`); the `ioctx` is
  bound once at instance init. *(RAL encodes the pool as a `:`-prefix in the name
  instead — supported by the namelib emitting the prefix + the driver's
  `extractPool` split, kept faithful to stock `XrdCephOss::extractPool`.)*

### 1.1 Adopt the libradosstriper data plane (replaces the current raw-rados)

Rework `sd_ceph.c` to use the **libradosstriper C API** (`rados_striper_create`,
`rados_striper_write`/`read`/`trunc`/`remove`/`stat`, `rados_striper_*xattr`) so
our open/pread/pwrite/ftruncate/fstat/unlink are **byte-exact with stock XrdCeph
and existing data**. The striper object name is **`lfn2pfn(export-relative path)`**
(§1.0a). Compiled only under `XROOTD_HAVE_CEPH` + the new `XROOTD_HAVE_RADOSSTRIPER`
probe; otherwise the file keeps contributing only its pure helpers (a no-Ceph build
stays unchanged).

### 1.2 xattr — native, via the striper (fully compatible)

`getxattr/setxattr/listxattr/removexattr` → `rados_striper_{get,set,rm,get}xattr[s]`
on the file. Same storage stock uses (first stripe) ⇒ xattrs set by us are visible
to stock XrdCeph and vice-versa. Advertise `CAP_XATTR`.

### 1.3 advisory setattr / chmod — **additive, non-breaking**

Stock returns `ENOTSUP` for chmod; we ADD advisory mode/mtime/uid/gid stored as a
single reserved **user xattr** (`user.xrd.unixattr`, shared codec) on the file via
the striper. Stock ignores the unknown xattr ⇒ **100% compat preserved**; our
`stat`/`fstat` overlay it on the striper's size+atime. (No on-format change.)

### 1.4 directory listing — **strict stock parity** (confirmed)

Match stock exactly, no enhancement: `opendir` accepts **only `/`** (anything else
→ `ENOENT`); the root listing is the full-pool scan filtered to `*.0000000000000000`
with the 17-char suffix stripped (then `pfn2lfn`-reversed through the namelib if one
is configured, so the listing shows logical names). `Mkdir`/`Remdir` stay no-op
`return 0`; `CAP_DIRS` is **not** advertised (stock's model is root-only). The
implicit per-prefix "folders" remain as they are in the flat object names — not
separately browsable, exactly as stock leaves them. *(A prefix/indexed enhancement
was explicitly de-scoped in favor of pure interop; it can return as a compatible
add-on later without a format change.)*

### 1.5 rename — stays `ENOTSUP` by default (compat); opt-in copy for small files

A true rename would have to copy/relocate every stripe of a (possibly Pb) file —
impractical and not what stock does. **Default: `ENOTSUP`** (byte-compat). An
**opt-in** `xrootd_rados_allow_rename` may enable a `striper read→write→remove`
copy-rename, size-capped, for tooling that needs it. (Decision flagged.)

### 1.6 Files / tests

- `src/fs/backend/rados/sd_ceph_n2n.{c,h}` — the pluggable `lfn2pfn`/`pfn2lfn`
  namelib translation (the site rule; **prerequisite input**). Pure, unit-tested
  against known LFN↔PFN pairs.
- `src/fs/backend/rados/sd_ceph_striper.{c,h}` — the libradosstriper data-plane +
  xattr wrappers (the compat core), and `sd_ceph_compat.{c,h}` — the PURE helpers:
  stripe-suffix (`.%016x`) derivation and the `.0000000000000000` readdir filter
  (all libc-only, unit-tested cluster-free).
- Extend the `sd_ceph.c` vtable: striper open/IO/fstat/ftruncate/unlink, xattr,
  advisory setattr + stat-overlay, root-only opendir/readdir/closedir; widen `caps`
  (`+CAP_XATTR` only). Config: `xrootd_rados_pool` (per export).
- `sd_ceph_unittest.c` adds the pure helpers (namelib translation, stripe naming,
  readdir filter, advisory codec). `tests/run_rados_parity.sh` — integration test
  gated on `XROOTD_TEST_RADOS_POOL` (skip without a cluster): write via OUR driver →
  **assert the on-RADOS object names (post-lfn2pfn), `.%016x` stripes, and
  `striper.layout.*` xattrs match stock XrdCeph's layout exactly**; where the
  `rados`/`rados-striper` CLI is present, assert stock can read our object and we
  can read a stock-written one; then drive xattr/chmod(advisory)/root-ls/stat over
  `root://` + a rados export.

---

## Phase 2 — `s3` as a registered server export backend

Promote `sd_s3` (handle library) to a registered `xrootd_sd_driver_t`
(`xrootd_sd_s3_driver`) so `xrootd_storage_backend s3` selects it for an export,
using the server libcurl transport (`s3_transport.c`).

```
  xrootd_storage_backend s3;  xrootd_s3_endpoint …;  xrootd_s3_bucket …;  creds…
            │
            ▼
  xrootd_sd_s3_driver  (NEW vtable, src/fs/backend/s3/sd_s3_driver.c)
     open  → sd_s3_open_read/_write          pread/pwrite → sd_s3_pread/_pwrite
     stat  → HEAD (size+mtime) ⊕ advisory metadata
     xattr → x-amz-meta-<name>  (arbitrary names; tagging stays user.s3.tagging)
     setattr → advisory x-amz-meta-xrd-unixattr  (CopyObject metadata-replace)
     mkdir → zero-byte "<dir>/" marker     opendir/readdir → ListObjects delimiter=/
     rename → CopyObject + DeleteObject     staged_* → multipart upload (existing)
```

**Feasibility honesty (advisory model):** S3 metadata is immutable after PUT, so
`setattr`/`setxattr` on an existing object issue a `CopyObject` onto itself with
`x-amz-metadata-directive=REPLACE`. mtime is the store's PUT time unless an
advisory mtime is set. No empty directories without marker objects.

### Files / tests
- `src/fs/backend/s3/sd_s3_driver.{c,h}` (vtable) + register in `sd_registry.c` +
  `./config`; config directives for endpoint/bucket/creds (reuse the S3 patterns).
- `tests/run_s3_export_parity.sh` — stand up the module's **own** S3 server as the
  *backend target* of a second instance whose export is `xrootd_storage_backend
  s3`; drive xattr/setattr/dirs/rename/stat over `root://` + WebDAV, byte- and
  metadata-exact. (Self-contained, like `run_cache_s3_origin.sh`.)

---

## Phase 3 — client S3/WebDAV VFS metadata

The native client's `s3://` and `http(s)://` VFS backends gain xattr/setattr so
`xrootdfs` mounts and the CLI expose `getfattr`/`setfattr`/`chmod`:

- `client/lib/vfs_s3*`: `getxattr/setxattr/listxattr/removexattr` → S3
  tagging/metadata; `setattr` → advisory metadata copy. Reuse the shared codec.
- WebDAV client VFS: xattr → dead properties (PROPPATCH/PROPFIND); setattr →
  properties. (Mirrors the server `dead_props.c` mapping.)
- FUSE (`client/lib/fuse_ops.c`): route `getxattr/setxattr/setattr` to the above.

### Tests
- Extend the client-conformance suite (`tests/clientconf` / `test_clientconf_*`):
  `setfattr` then `getfattr` round-trip over a mounted `s3://` and `davs://`,
  differential vs. the POSIX VFS.

---

## Phase 4 — remote cache-origin drivers (read-side only)

`sd_remote` (S3 origin) and `sd_xroot` (root:// origin) are read-only, but gain
**read-side** `getxattr`/`listxattr` so the cache can surface origin metadata
(e.g. an origin checksum exposed as an xattr):

- `sd_remote`: `getxattr` → S3 `x-amz-meta-*` / tagging on the origin object.
- `sd_xroot`: `getxattr/listxattr` → `kXR_fattr` to the origin (the wire client
  already speaks it). Write-side xattr/setattr remain `NULL` (read-only by design).

### Tests
- Extend `run_cache_s3_origin.sh` / `run_cache_xroot_origin.sh`: a `getfattr` on a
  cached object returns the origin's metadata.

---

## Capability flags updated

```
  rados:  + CAP_XATTR  (NO CAP_DIRS — strict stock root-only listing; NO CAP_HARD_RENAME
          — rename stays ENOTSUP/opt-in; keeps RANGE/RANDOM/TRUNC; data plane =
          libradosstriper + the site lfn2pfn, byte-compatible with stock XrdCeph)
  s3:     + CAP_RANGE_READ + CAP_XATTR + CAP_DIRS             (no FD/SENDFILE; no HARD_RENAME)
  remote/xroot: unchanged caps (read-side xattr needs no cap bit; it is a slot)
```

## Testing strategy summary

| backend | pure-logic unit test (CI) | integration test |
|---|---|---|
| rados | stripe-suffix derivation, readdir `.0…0` filter, prefix→component, advisory codec (cluster-free) | `run_rados_parity.sh` gated on a real pool: assert OUR on-RADOS layout == stock XrdCeph's |
| s3 export | advisory codec (shared) | `run_s3_export_parity.sh` vs the module's own S3 server (always runs) |
| client S3/WebDAV | codec | `test_clientconf_*` setfattr/getfattr round-trip |
| remote/xroot | — | extend the existing origin e2e |

## Sequencing & feasibility

**Phase 1 (rados) → Phase 2 (s3 export) → Phase 3 (client) → Phase 4 (remote).**
Phase 1 is the highest-value, fully-feasible win (native librados support) and
establishes the shared advisory-metadata codec the others reuse. Phase 2 is
self-testable against our own S3 server. Phase 3/4 are incremental. Each phase is
independently shippable and independently tested. The **advisory** caveats (no
enforced mode on S3, no empty dirs without markers, rename = copy+delete on S3)
are inherent to the stores and documented at each surface.

## Non-goals

- Enforced POSIX permissions/ownership on object stores (advisory only).
- libradosstriper / stock-XrdCeph interop (separate ADR-3 follow-on).
- Write/setattr on the read-only cache-origin drivers.
- Hardlinks on rados (v1 namespace is 1 name : 1 blob).
