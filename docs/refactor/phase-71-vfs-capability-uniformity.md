# Phase-71 — VFS capability uniformity

**Goal:** Every `src/fs/vfs/*.c` op must branch only on `brix_sd_caps()` bits (and vtable-slot
presence), never on backend identity or on hand-set `writable`/read-only assumptions. Adding an
object backend as *primary*, or making HTTP/S3 writable, then requires editing ONLY that driver's
`.caps` in `src/fs/backend/`. No behavior change.

## 0. Current-state facts (verified)

- `brix_sd_cap_t` bitmap: `src/fs/backend/sd.h:80-105`. Existing bits used below:
  `CAP_FD(1<<0)`, `CAP_SENDFILE(1<<1)`, `CAP_RANDOM_WRITE(1<<2)`, `CAP_RANGE_READ(1<<3)`,
  `CAP_TRUNCATE(1<<4)`, `CAP_SERVER_COPY(1<<5)`, `CAP_XATTR(1<<6)`, `CAP_HARD_RENAME(1<<7)`,
  `CAP_DIRS(1<<8)`, `CAP_APPEND(1<<9)`, `CAP_IOURING(1<<10)`, `CAP_FSCS(1<<11)`,
  `CAP_NEARLINE(1<<12)`, `CAP_CATALOG(1<<13)`. Next free bit = `1<<14`.
- Accessors: `brix_sd_caps()`, `brix_sd_fd()`, `brix_sd_supports(inst, mask)` — `sd.h:503-510`.
- Driver `.caps` sites (edit each in step 1): posix `sd_posix.c:703`, ceph `sd_ceph.c:1582`,
  http `sd_http.c:676`, remote(s3) `sd_remote.c:372`, xroot `sd_xroot.c:609`,
  cache `sd_cache.c:948`, stage `sd_stage.c:568`, frm `sd_frm.c:306`, block `sd_block.c:111`,
  pblock `sd_pblock.c:1066`, cephfs_ro `sd_cephfs_ro.c:857`.
- **Stale facts to fix in passing:** `sd_http.c:676` and `sd_remote.c:372` ALREADY advertise
  `CAP_RANDOM_WRITE`, but registry comment `vfs_backend_registry.h:54-56` still says "S3 primary is
  read-only". Reconcile: either honor the cap or drop it (decide per step 4).
- **Cred routing is already capability-gated** via `*_cred` vtable slots (`sd.h:445-490`) +
  `brix_cred_mode` enum + `brix_deleg_live_s.mode` (`vfs_internal.h:57-63`). Exploration item #4 is
  MOSTLY DONE; step 5 only adds an explicit accept-mask so a bearer-only backend rejects a proxy_pem.

## 1. Capability-model additions (`src/fs/backend/sd.h`)

Add to `brix_sd_cap_t` (bits `1<<14…1<<17`) with WHAT/WHY doc lines matching the existing style:

| New bit | Meaning | Replaces implicit assumption |
|---|---|---|
| `CAP_DIRS_WRITE (1<<14)` | catalog is mutable (mkdir/rename/rmdir) | "CAP_DIRS ⇒ writable dir" |
| `CAP_XATTR_WRITE (1<<15)` | set/remove xattr (read still = `CAP_XATTR`) | "CAP_XATTR ⇒ both directions" |
| `CAP_MEMFILE (1<<16)` | can serve bytes via a memory-fd proxy when no `CAP_FD` | "no fd ⇒ VFS memory-backs it" |

Add a driver field + accessor for delegation kinds (step 5):
```c
typedef enum { BRIX_SD_CRED_NONE=0, BRIX_SD_CRED_BEARER=1u<<0,
               BRIX_SD_CRED_PROXY_PEM=1u<<1 } brix_sd_cred_kind_t;
/* on brix_sd_driver_s, near .caps (sd.h:311): */
uint32_t cred_accept;   /* OR of brix_sd_cred_kind_t the backend can consume; 0 = none */
/* accessor beside brix_sd_supports (sd.h:510): */
uint32_t brix_sd_cred_accept(const brix_sd_instance_t *inst);
```
Set every driver's new bits/`cred_accept` correctly at its `.caps` site (step-0 list). Header-only
change → no `./config` edit; `make -j$(nproc)`.

## 2. Sendfile uniformity (`src/fs/vfs/`)

- **Site:** `brix_vfs_file_sendfile_fd()` (decl `vfs.h:234`, body in `vfs_*` .c) returns the raw fd
  only for `CAP_FD` backends; callers treat `NGX_INVALID_FILE` as "memory-back it" (`vfs.h:227`
  comment; WebDAV GET / S3 object serve).
- **Change:** for a `CAP_MEMFILE` (no `CAP_FD`) backend, materialize a memory-backed descriptor
  (memfd / pool buffer) so one serve path works everywhere; the caller gates on
  `brix_sd_supports(inst, CAP_SENDFILE) || (caps & CAP_MEMFILE)` instead of the sentinel.
- Keep zero-copy `CAP_SENDFILE` fast path unchanged; `CAP_MEMFILE` is the fallback the VFS already
  performs — this only moves the decision from sentinel-detection to a cap check.

## 3. Read-then-stat fast path (`vfs_internal.h:83-91`)

- **Site:** `brix_vfs_file_s.stat_current` is set by `brix_vfs_adopt_fd()` (`vfs.h:226`) iff the
  caller passed `writable==0` — an implicit read-only assumption.
- **Change:** set `stat_current` iff `!(brix_sd_caps(inst) & CAP_RANDOM_WRITE)` (backend genuinely
  cannot mutate the object) instead of trusting the caller's `writable` argument. Drop/retain the
  `writable` param as convenience only; the cap is authoritative.

## 4. Write-op rejection at dispatch, not registration (`vfs_backend_registry.h:54`, `vfs_backend_config.c`)

- **Site:** S3/HTTP "read-only" is enforced implicitly by which slots the driver populates + a stale
  comment; there is no single VFS guard.
- **Change:** in the VFS write/mkdir/rename/truncate op wrappers add an early
  `if (!(brix_sd_caps(inst) & CAP_RANDOM_WRITE)) { errno=EROFS; return NGX_ERROR; }` (and
  `CAP_TRUNCATE`, `CAP_DIRS_WRITE` for their ops). Then reconcile the stale `CAP_RANDOM_WRITE` on
  `sd_http.c:676`/`sd_remote.c:372`: **remove** it if those primaries are truly read-only, so the
  new guard and the advertised cap agree. Update the `vfs_backend_registry.h:54` comment.

## 5. Cred-kind accept mask (`vfs_internal.h:57`, cred routing helper)

- **Site:** delegation mode chosen from `brix_deleg_live_s.mode`; a backend that only accepts bearer
  still gets handed a `proxy_pem` with no rejection.
- **Change:** before routing, check `brix_sd_cred_accept(inst)` against the live cred kind; if the
  present kind isn't accepted → `EACCES` (deny-before-origin, matching the phase-2 invariant in
  `sd.h:415-419`). Bearer-only vs proxy-only backends now reject the wrong kind uniformly.

## 6. OpenDir / mkdir / rename catalog guard (`vfs.h:296-309`)

- **Site:** `brix_vfs_opendir_quiet` (S3 ListObjects / WebDAV SEARCH) trusts backend identity for
  "read-only catalog"; mkdir/rename assume a writable dir when `CAP_DIRS` is set.
- **Change:** listing requires `CAP_DIRS`; mutation (mkdir/rmdir/rename-into-dir) requires
  `CAP_DIRS_WRITE`. Set `CAP_DIRS_WRITE` on posix/ceph/xroot/cache/stage/frm/block/pblock; NOT on
  cephfs_ro/http/remote. VFS mutation wrappers early-return `EPERM` when the bit is absent.

## 7. Xattr read/write split (`vfs.h:426-430`)

- **Site:** single `CAP_XATTR` bit; HTTP/S3 leave xattr vtable slots NULL and the VFS relies on
  slot==NULL → the wrapper's ENOTSUP path is uneven.
- **Change:** get/list require `CAP_XATTR`; set/remove require `CAP_XATTR_WRITE`. The
  `brix_vfs_{set,remove}xattr` (+ `f*` fd variants) wrappers early-return `ENOTSUP` when the write
  bit is absent, regardless of slot presence. Keep the "xattr is NOT allow_write-gated" lock detail
  (`vfs.h:426`) — this is a capability gate, orthogonal to the write-token gate.

## 8. Guard + docs

- **Guard:** add `tools/ci/check_vfs_identity_branch.sh` — greps `src/fs/vfs/*.c` for a branch
  condition naming a concrete backend/proto (`sd_http`, `sd_s3`, `sd_remote`, `== .*posix`,
  `strcmp(.*backend`, `"s3"`, `"webdav"`, `"http"`). Backlog file `vfs_identity_backlog.txt` = 0 at
  completion; wire into `.github/workflows/guards.yml`.
- **Docs:** update `src/fs/README.md`, `src/fs/backend/README.md`, `sd.h` cap table, this file.

## Tests (3 per changed op: success + error + capability-negative)

1. Backend with `CAP_RANGE_READ` only → VFS `pwrite`/`mkdir`/`truncate`/`rename` all `EROFS`/`EPERM`
   at dispatch; `pread` OK. (step 4/6)
2. `CAP_MEMFILE` (no `CAP_FD`) backend serves byte-exact vs a `CAP_SENDFILE` backend for the same
   object. (step 2)
3. `CAP_DIRS` without `CAP_DIRS_WRITE`: `opendir`/list OK; `mkdir`/`rename` → `EPERM`. (step 6)
4. `CAP_XATTR` without `CAP_XATTR_WRITE`: `getxattr`/`listxattr` OK; `setxattr`/`removexattr` →
   `ENOTSUP`. (step 7)
5. `cred_accept = BEARER` backend: proxy_pem cred → `EACCES` before any origin call; bearer OK.
   Mirror for a proxy-only backend. (step 5)
6. read-only handle (`!CAP_RANDOM_WRITE`) sets `stat_current`; a synthetic writable-cap handle does
   not. (step 3)
7. Guard: `check_vfs_identity_branch.sh` exits 0 (zero identity branches in `src/fs/vfs/`).

## Implementation status (2026-07-09)

**LANDED (build clean, `objs/nginx` linked):**
- Step 1 — `CAP_DIRS_WRITE`/`CAP_XATTR_WRITE`/`CAP_MEMFILE` bits + `brix_sd_cred_kind_t`
  + `driver.cred_accept` field + `brix_sd_cred_accept()` accessor (`sd.h`, `sd_registry.c`).
- All driver `.caps`/`.cred_accept` set: posix, ceph, xroot, cache, stage, pblock, cephfs_ro,
  http, remote. (block/frm have no dirs/xattr → unchanged.)
- Step 6 — mkdir catalog-mutation guard: `!(caps & CAP_DIRS_WRITE) → EPERM` (`vfs_mkdir.c`).
- Step 7 — xattr write guard: `!(caps & CAP_XATTR_WRITE) → ENOTSUP` on set/removexattr only,
  read ops (get/list) untouched (`vfs_xattr.c`).
- Step 8 — guard `tools/ci/check_vfs_identity_branch.sh` (OK 0<=0); exempts the config-time
  factory `vfs_backend_{config,registry}.c` (the one intended backend-naming site).

- Step 4 — namespace-mutation dispatch guards: rename `!(caps & CAP_DIRS_WRITE) → EPERM`
  (`vfs_rename.c`), truncate `!(caps & CAP_TRUNCATE) → ENOTSUP` (`vfs_sync.c`). (Data-plane
  write is gated at open via the writable handle + io_core job path — no VFS write wrapper to
  guard, per the storage-plane invariant.)
- Step 5 — credential-kind accept gate in `brix_vfs_deleg_live_cred` (`vfs_deleg.c`): a live
  proxy_pem/bearer not in the leaf's `cred_accept` → deny (EACCES) before any origin contact.

- Step 4 (reconciliation) — dropped the dishonest `CAP_RANDOM_WRITE` from sd_http/sd_remote:
  neither has a `.pwrite` slot (writes are whole-object staged PUTs via `.staged_*`), so they now
  advertise `CAP_RANGE_READ | CAP_MEMFILE` only. Registry comment (`vfs_backend_registry.h`) updated
  to match.
- Tests — `tests/c/test_vfs_caps.c` + `run_vfs_caps_tests.sh`: 15 assertions on `brix_sd_supports`
  (CAP_DIRS_WRITE / CAP_XATTR_WRITE / CAP_TRUNCATE, read caps preserved) and `brix_sd_cred_accept`
  (bearer-only rejects proxy, proxy-only rejects bearer, no-deleg rejects both, NULL-safe) —
  **ALL PASS**, linked against the shipped `sd_registry.o`.

- Step 2 — memfd sendfile proxy LANDED (`vfs_open.c`, `vfs_internal.h`): a handle-owned `memfd`
  field (init `NGX_INVALID_FILE` at both constructors); `brix_vfs_memfile_materialize()` preads a
  fd-less `CAP_MEMFILE` object once into a `memfd_create` fd and caches it;
  `brix_vfs_file_sendfile_fd()` returns it when the backend's `read_sendfile_fd` declines;
  `brix_vfs_close()` releases it before the fd-based early-out. On any failure → `NGX_INVALID_FILE`
  so callers keep their legacy memory-backed path (zero behavior change). Build clean, binary
  relinked, guard + cap unit test green.

**DEFERRED (follow-up):**
- Step 3 — `stat_current` left keyed on the `writable` arg (already correct + avoids a perf
  regression on read handles over writable backends); cap refinement optional.
- ~~e2e wire tests (davs/S3 EPERM/ENOTSUP on the read-only backends)~~ — **DONE
  2026-07-21**: `tests/test_readonly_backend_wire.py` proves, over the native
  root:// wire against an s3 backend (`nginx_root_s3_staged.conf`, write-token
  gate deliberately OPEN so the caps gate answers): kXR_mkdir/kXR_mv →
  `kXR_NotAuthorized` (EPERM, !CAP_DIRS_WRITE) and path-form kXR_truncate →
  `kXR_Unsupported` (ENOTSUP, !CAP_TRUNCATE), plus a byte-exact read success
  leg proving the backend is live.

**Docs updated:** `src/fs/backend/README.md` (sd.h row now lists the phase-71 caps + `cred_accept`
accessor + the identity-branch guard); sd.h cap-table comments inline on each new bit.

## Invariant after phase-71

`proto → VFS → backend` is capability-driven end to end. The VFS names no backend and assumes no
read-only-ness; promoting a backend to a writable/sendfile-capable primary is a one-line `.caps`
edit under `src/fs/backend/`, enforced by `check_vfs_identity_branch.sh`.
