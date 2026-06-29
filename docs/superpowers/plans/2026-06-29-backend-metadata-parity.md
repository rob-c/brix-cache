# Backend Metadata & Namespace Parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use `- [ ]` checkboxes.

**Goal:** Implement the driver-vtable metadata/namespace ops (xattr, advisory
setattr, directories, rename, staged publish) on `rados` and `s3`, on the client
`s3://`/WebDAV VFS, and read-side xattr on the remote cache-origin drivers — so the
full storage-command phase-space works over `root://`/WebDAV/S3-REST on every
backend. **The protocol, VFS, and client command layers are already wired**; this
is concentrated below the SD seam.

**Architecture:** Per [the design spec](../specs/2026-06-29-backend-metadata-parity-design.md):
a shared **advisory unix-metadata codec** is reused by every backend that lacks
native POSIX attrs; **rados adopts the stock-XrdCeph `libradosstriper` layout
byte-for-byte** (Pb+ of existing data must round-trip) and layers xattr +
advisory-metadata + prefix-directory listing *additively* on top without changing
the on-RADOS format; s3 becomes a registered export driver with metadata via
`x-amz-meta-*` + CopyObject.

**Tech stack:** C (ngx-free driver code), `librados` + **`libradosstriper` C API
(`rados_striper_*`)**, libcurl + the existing `sd_s3` handle library +
`s3_transport.c`, the SD seam (`sd.h`).

## Global Constraints

- No `goto`; functional/modular; table/descriptor dispatch.
- All data byte I/O stays below the SD seam; metadata ops are driver slots.
- Advisory model: object stores persist mode/mtime/uid/gid in a reserved metadata
  slot and return them on `stat` (they do not enforce them).
- 3 tests/change (success+error+security-neg). Cluster/endpoint-dependent paths:
  unit-test pure logic in CI; gate the integration test on availability (skip).
- New `.c` ⇒ register in `./config`, then `rm -rf objs && ./configure && make`.
- Operator drives all git commits.

---

# Phase 0 — Shared advisory-metadata codec (prerequisite)

### Task 0.1: `meta_advisory` codec (pure, libc-only)

**Files:**
- Create: `src/fs/backend/meta_advisory.c`, `src/fs/backend/meta_advisory.h`
- Register: `./config`
- Test: `tests/c/test_meta_advisory.c`, `tests/c/run_meta_advisory_tests.sh`

**Interfaces (produced — reused by rados/s3/client):**
```c
/* Reserved slot name on object stores. */
#define XROOTD_META_ADVISORY_XATTR "user.xrd.unixattr"
typedef struct { mode_t mode; uid_t uid; gid_t gid; time_t mtime; long mtime_ns;
                 unsigned have_mode:1, have_owner:1, have_mtime:1; } xrootd_meta_advisory_t;
/* "v1 mode=0644 uid=1000 gid=1000 mtime=1782726000 mtime_ns=0" */
int  xrootd_meta_advisory_encode(const xrootd_meta_advisory_t*, char*, size_t);   /* len or -1 */
int  xrootd_meta_advisory_decode(const char*, size_t, xrootd_meta_advisory_t*);   /* 0/-1 */
/* Overlay decoded advisory fields onto a base sd_stat (size/mtime from the store). */
void xrootd_meta_advisory_overlay(const xrootd_meta_advisory_t*, struct xrootd_sd_stat_s*);
/* Patch an advisory blob from a setattr request (read-modify-write helper). */
int  xrootd_meta_advisory_patch(char *blob, size_t cap, const xrootd_meta_advisory_t *delta);
```

- [ ] **Step 1:** failing unit test — encode→decode round-trips mode/uid/gid/mtime;
  decode tolerates missing fields + an unknown `vN` (forward-compat: ignore extras);
  `overlay` sets only present fields; truncation returns -1.
- [ ] **Step 2:** run `tests/c/run_meta_advisory_tests.sh` → FAIL.
- [ ] **Step 3:** implement with `snprintf`/`strtoul` only (no nginx, no alloc).
- [ ] **Step 4:** PASS. `./configure` (new `.c`) + `make`.

---

# Phase 1 — `rados` (sd_ceph): 100% XrdCeph-compatible (libradosstriper)

> **REVISED** after auditing `/tmp/xrootd-src/src/XrdCeph`. Sites hold Pb+ of data
> in the stock libradosstriper layout; the driver MUST match it byte-for-byte. The
> current `sd_ceph.c` (raw single-object, hashed keys) is **incompatible** and is
> reworked here. See the design spec §1.0 for the exact contract.

**Prereq:** a `./configure` probe `XROOTD_HAVE_RADOSSTRIPER` (libradosstriper C API,
`rados_striper_*`), gating the data-plane code like `XROOTD_HAVE_CEPH` gates the
rest. No-Ceph / no-striper builds stay byte-for-byte unchanged.

### Task 1.0a: namelib `lfn2pfn`/`pfn2lfn` (PREREQUISITE — needs the site rule)

**Files:** Create `src/fs/backend/rados/sd_ceph_n2n.{c,h}`; `./config`. Test:
`sd_ceph_unittest.c`.

> **BLOCKING INPUT:** sites run a `ceph.namelib`, so the object name is
> `lfn2pfn(logical)`, not the raw path. The **exact rule must be supplied** before
> this can target production data. Implement the confirmed rule as a pure function
> (and a reverse `pfn2lfn` for the root listing). Identity is the fallback only when
> a site genuinely runs no namelib.

```c
int sd_ceph_lfn2pfn(const char *lfn, char *pfn, size_t);   /* the site rule */
int sd_ceph_pfn2lfn(const char *pfn, char *lfn, size_t);   /* reverse (for ls /) */
```

- [ ] Failing unit test: known LFN↔PFN pairs (from the supplied rule) round-trip;
  `..`/escape rejected. → FAIL → implement → PASS. *(Until the rule is supplied, the
  test pins identity + the escape guard.)*

### Task 1.1: pure compat helpers (cluster-free)

**Files:** Create `src/fs/backend/rados/sd_ceph_compat.{c,h}`; `./config`. Test:
extend `sd_ceph_unittest.c` (via `tests/test_sd_ceph.py`).

**Interfaces:**
```c
/* first-stripe oid for a striper object name: name + ".0000000000000000". */
int  sd_ceph_first_stripe(const char *name, char *oid, size_t);
/* readdir filter: is this oid a first stripe? if so, strip the 17-char suffix → pfn. */
int  sd_ceph_oid_is_first_stripe(const char *oid);                 /* 0/1 */
int  sd_ceph_oid_to_pfn(const char *oid, char *pfn, size_t);       /* strips .0..0 */
```

- [ ] Failing unit test: first-stripe suffix is exactly `.%016x` of 0;
  `oid_to_pfn` round-trips; a non-first-stripe oid is rejected. → FAIL → implement
  (libc-only) → PASS.

### Task 1.2: striper data plane (replaces raw rados)

**Files:** Create `src/fs/backend/rados/sd_ceph_striper.{c,h}` (the libradosstriper
C-API wrappers: create/open/read/write/trunc/remove/stat); rewire `sd_ceph.c`
`open/close/pread/pwrite/preadv/fstat/ftruncate/fsync/unlink/stat` onto it. Object
name = **`sd_ceph_lfn2pfn(export-relative path)`** (Task 1.0a). The pool is bound
once at instance init from the per-export `xrootd_rados_pool` directive.

- [ ] **Step 1:** integration assertion in `tests/run_rados_parity.sh` (gated on
  `XROOTD_TEST_RADOS_POOL`): a PUT via OUR driver creates objects named
  `<path>.0000000000000000…` with `striper.layout.*` xattrs — i.e. the stock layout;
  GET is byte-exact. → (skips without a pool).
- [ ] **Step 2:** implement the striper wrappers + rewire; keep everything under
  `XROOTD_HAVE_RADOSSTRIPER`.
- [ ] **Step 3:** build; run the gated test on a pool; where the `rados`/striper CLI
  exists, assert stock can read our object and vice-versa.

### Task 1.3: rados xattr via the striper (native, compatible)

**Files:** `sd_ceph.c` — `getxattr/setxattr/listxattr/removexattr` →
`rados_striper_{get,set,rm,get}xattr[s]` on the file; add `CAP_XATTR`.

- [ ] Gated test: `xrdfs fattr set/get/list/rm` round-trips AND the xattr is stored
  on the first stripe (stock-visible). → implement → verify.

### Task 1.4: rados advisory setattr/chmod + stat overlay (additive)

**Files:** `sd_ceph.c` — `setattr` reads/patches/writes `user.xrd.unixattr`
(shared codec, Phase 0) via the striper; `stat`/`fstat` overlay it on
`rados_striper_stat`'s size+atime. No format change; stock ignores the xattr.

- [ ] Gated test: `xrdfs chmod 0640` then `stat` shows `0640`; a stock client still
  reads the file unchanged. → implement → verify.

### Task 1.5: rados directory listing — **strict stock parity** (root-only)

**Files:** `sd_ceph.c` — `opendir` accepts **only `/`** (else `ENOENT`, exactly
stock); root `readdir` = full pool scan (`rados_nobjects_list_*`) filtered via
`sd_ceph_oid_is_first_stripe`, `oid_to_pfn`, then `sd_ceph_pfn2lfn` so logical names
show. `Mkdir`/`Remdir` stay no-op `return 0`. **Do NOT advertise `CAP_DIRS`** (the
prefix/indexed enhancement was de-scoped for pure interop).

- [ ] Gated test: `ls /` returns logical file names byte-identical to stock; `ls
  /atlas` → ENOENT (matches stock). → implement → verify.

### Task 1.6: rename policy (compat default) + docs

**Files:** `sd_ceph.c` — `rename` returns `ENOTSUP` by default (byte-compat); behind
an opt-in `xrootd_rados_allow_rename` (size-capped), a `striper read→write→remove`
copy-rename. Update the rados header + `docs/.../storage-backend-drivers-deep-dive.md`
(the XrdCeph compat contract + the striper diagram + the advisory/prefix-dir notes).

- [ ] Gated test: default `mv` → ENOTSUP; with the opt-in, a small-file `mv` copies+
  deletes (new object stripes appear, old gone). → implement → verify. CI green:
  `test_sd_ceph.py` (compat helpers), no-Ceph build unchanged, seam guard.

---

# Phase 2 — `s3` registered export backend

### Task 2.1: the `xrootd_sd_s3_driver` vtable + registration

**Files:** Create `src/fs/backend/s3/sd_s3_driver.{c,h}` wrapping the `sd_s3`
handle API; `extern` in `sd.h`; row in `sd_registry.c`; `./config`; config
directives `xrootd_s3_endpoint/_bucket/_access_key/_secret_key/_region` for an
export (reuse the cache-origin parsing patterns). `open/close/pread/pwrite/fstat`
delegate to `sd_s3_*`; `caps = RANGE_READ | XATTR | DIRS`.

- [ ] Failing e2e `tests/run_s3_export_parity.sh`: a stream/WebDAV server whose
  export is `xrootd_storage_backend s3` (pointed at the module's OWN S3 server as
  the object store) serves a PUT/GET byte-exact. → FAIL → implement open/IO/stat →
  PASS.

### Task 2.2: s3 xattr via object metadata

**Files:** `sd_s3_driver.c` + `sd_s3.c` helpers: `getxattr/setxattr/listxattr/
removexattr` map an arbitrary name `N` ↔ `x-amz-meta-<N>` (set via CopyObject
metadata-REPLACE; list via HEAD response headers; the existing `user.s3.tagging`
remains the tagging blob). 

- [ ] e2e: `setfattr user.foo=bar` then `getfattr` over `root://`+s3-export → `bar`;
  `listxattr` includes it. → implement → verify.

### Task 2.3: s3 advisory setattr

**Files:** `sd_s3_driver.c` — `setattr` writes `x-amz-meta-xrd-unixattr` (shared
codec) via CopyObject-REPLACE; `stat` overlays it on the HEAD size+mtime.

- [ ] e2e: `chmod 0600` then `stat` shows `0600` (advisory). Document that S3 does
  not enforce it. → implement → verify.

### Task 2.4: s3 dirs + rename

**Files:** `sd_s3_driver.c` — `opendir/readdir` = ListObjects(prefix, delimiter=/)
→ CommonPrefixes (dirs) + Contents (files); `mkdir` = zero-byte `<dir>/` marker;
`rename` = CopyObject + DeleteObject.

- [ ] e2e: `ls` a prefix lists children; `mkdir /d` then `ls` shows `d/`; `mv a b`
  copies+deletes. Security-neg: key escape (`../`) rejected by `s3_resolve_key`.
  → implement → verify.

### Task 2.5: Phase-2 docs + gate

- [ ] Backend README + deep-dive: `s3` is now a registered export driver (was a
  handle library); the advisory/limited-model caveats. Full e2e + seam guard green.

---

# Phase 3 — client `s3://` / WebDAV VFS metadata

### Task 3.1: client S3 VFS xattr/setattr

**Files:** `client/lib/vfs_s3*.c` (+ `vfs_s3_internal.h`): implement the client VFS
xattr/setattr ops by mapping to S3 tagging/metadata (the same `x-amz-meta-*` and
advisory codec). `client/lib/cred_s3.c` unaffected.

- [ ] Failing client-conformance test (`tests/test_clientconf_*`): mount/op an
  `s3://` target, `setfattr`→`getfattr` round-trips; `chmod`→`stat` advisory. → FAIL
  → implement → PASS.

### Task 3.2: client WebDAV VFS xattr/setattr

**Files:** the client WebDAV VFS: xattr ↔ dead properties (PROPPATCH/PROPFIND, the
client mirror of `dead_props.c`); setattr → properties.

- [ ] Conformance: `setfattr`/`getfattr` over `davs://` round-trips. → implement →
  PASS.

### Task 3.3: FUSE wiring + gate

**Files:** `client/lib/fuse_ops.c` — route `getxattr/setxattr/setattr` to the new
VFS ops for s3/webdav mounts.

- [ ] `test_xrootdfs`-style: `setfattr`/`getfattr`/`chmod` on a mounted s3/davs
  path. Client build + the full client-conformance suite green.

---

# Phase 4 — remote cache-origin drivers (read-side xattr)

### Task 4.1: `sd_remote` (S3 origin) read-side getxattr/listxattr

**Files:** `src/fs/backend/remote/sd_remote.c` — add `getxattr/listxattr` (read the
origin object's `x-amz-meta-*`); write slots stay NULL (read-only).

- [ ] Extend `tests/run_cache_s3_origin.sh`: a `getfattr` on a cached object
  surfaces the origin metadata. → implement → verify.

### Task 4.2: `sd_xroot` (root:// origin) read-side getxattr/listxattr

**Files:** `src/fs/backend/xroot/sd_xroot.c` — add `getxattr/listxattr` via
`kXR_fattr` to the origin (the wire client already speaks it; add a small
origin-fattr helper alongside `query_checksum`).

- [ ] Extend `tests/run_cache_xroot_origin.sh`: `getfattr` returns origin xattr.
  → implement → verify.

---

## Self-review notes

- **Spec coverage:** all four scopes + the shared codec (Phase 0) + caps + tests
  are mapped. Each phase independently shippable.
- **Type consistency:** the advisory codec (`xrootd_meta_advisory_t`) and reserved
  name are defined once (Phase 0) and reused in 1.4 / 2.3 / 3.1. The rados omap
  entry codec is defined in 1.1 and consumed by 1.2/1.5/1.6.
- **Feasibility caveats** (documented at each surface): S3 enforces nothing
  (advisory), no empty dirs without markers, rename = copy+delete; rados needs a
  cluster for the integration tests (pure logic is CI-tested); remote drivers stay
  read-only. These are inherent, not gaps.
- **Build governance:** new `.c` files (`meta_advisory.c`, `sd_ceph_ns.c`,
  `sd_s3_driver.c`) each require `rm -rf objs && ./configure && make`.
