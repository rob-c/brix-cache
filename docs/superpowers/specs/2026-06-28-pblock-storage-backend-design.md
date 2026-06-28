# pblock — full-parity, block-based drop-in storage backend (design)

**Status:** approved design — Phase 1 (driver + standalone tests)
**Date:** 2026-06-28
**Seam:** `xrootd_sd_driver_t` (`src/fs/backend/sd.h`); registry `src/fs/backend/sd_registry.c`

---

## 1. Purpose

`xrootd_sd_pblock_driver` (backend name `"pblock"`) is a **complete** storage
driver that splits the two planes a POSIX directory tree conflates:

- **Metadata plane** → a SQLite catalog holding the entire logical namespace
  (paths, directory tree, stat fields, xattrs) and the path→blob mapping.
- **Data plane** → opaque **blob files** that are *real POSIX files* (real
  kernel fds), named by a server-generated id under a fanned-out data folder.

Because blobs are real files, pblock exposes a real fd and therefore supports
the **full** capability set — including `CAP_FD | CAP_SENDFILE` (zero-copy),
random I/O, `copy_file_range`, atomic rename, directories, xattrs, and staged
atomic publish. It advertises **the same capabilities as the POSIX driver** and
implements **every vtable slot**, so it is a genuine drop-in replacement.

### Why it exists

1. **Keep the VFS data pathways honest.** Today every data callsite reconstructs
   a POSIX object from a bare fd (`xrootd_sd_posix_wrap()` / `xrootd_sd_posix_driver.*`)
   instead of dispatching through the bound `fh->obj.driver` / `ctx->sd`. A
   *second complete backend* is the forcing function that exposes and ultimately
   closes that gap (see the seam audit). This driver is the test vehicle.
2. **A potentially perf-viable POSIX alternative** for proxy and data-storage
   nodes, where separating bulk content (blobs) from namespace/metadata (catalog)
   can be operationally and performance-advantageous.

---

## 2. The performance-defining invariant

**The data plane never touches SQLite.** SQLite is consulted only on:

- `open` — resolve or create the object row + blob;
- extending `pwrite`, `ftruncate`, `staged_commit`, `close` — write back
  `size` + `mtime`;
- namespace ops (`stat`, `unlink`, `mkdir`, `rename`, `server_copy`, `opendir`/
  `readdir`, xattr CRUD).

The hot byte ops — `pread` / `pwrite` / `preadv` / `preadv2` /
`read_sendfile_fd` — operate **purely on the blob fd**, issuing the identical
syscalls the POSIX driver does. Bulk transfer therefore runs at raw-POSIX speed,
including kernel zero-copy `sendfile(2)`. Only metadata operations pay the
catalog cost.

---

## 3. On-disk layout

```
<pblock_root>/
  data/<aa>/<bb>/<blob_id>     opaque content blobs (real files)
  catalog.db                   SQLite: namespace + stat + xattrs + path→blob map (WAL)
```

- `blob_id` is a server-generated 128-bit CSPRNG hex token. `<aa>/<bb>` is a
  two-level fan-out (first two hex byte-pairs) so no single directory grows
  unbounded.
- User-supplied logical paths are **only ever TEXT keys in SQLite**; the physical
  blob path is composed solely from the server-generated `blob_id`. User input
  never reaches a physical path, so path traversal is impossible by construction.
  The driver still asserts the VFS-supplied logical path is canonical, per the
  seam contract ("inst-keyed ops take an already-confined logical path").

---

## 4. Catalog schema

```sql
CREATE TABLE IF NOT EXISTS objects(
  path    TEXT PRIMARY KEY,    -- confined logical path
  parent  TEXT NOT NULL,       -- parent dir path; indexed for opendir/readdir
  is_dir  INTEGER NOT NULL,    -- 1 = directory, 0 = regular file
  blob_id TEXT,                -- NULL for dirs; data/<fanout>/<blob_id> for files
  size    INTEGER NOT NULL,
  mtime   INTEGER NOT NULL,
  ctime   INTEGER NOT NULL,
  mode    INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS objects_parent ON objects(parent);

CREATE TABLE IF NOT EXISTS xattrs(
  path  TEXT NOT NULL,
  name  TEXT NOT NULL,
  value BLOB NOT NULL,
  PRIMARY KEY(path, name));
```

**Stat authority:** the catalog is authoritative for stat. `size` and `mtime`
are written back transactionally on extending `pwrite`, `ftruncate`,
`staged_commit`, and `close` — never by `fstat`-ing the blob on the read path —
so `stat`-by-path (PROPFIND, dirlist) costs zero blob opens.

---

## 5. Capabilities

Match the POSIX driver **exactly**, including `CAP_IOURING` (blob fds are real
kernel fds, so io_uring submission is honest):

```
caps = CAP_FD | CAP_SENDFILE | CAP_RANDOM_WRITE | CAP_RANGE_READ
     | CAP_TRUNCATE | CAP_APPEND | CAP_IOURING | CAP_SERVER_COPY
     | CAP_XATTR | CAP_HARD_RENAME | CAP_DIRS
```

---

## 6. Vtable slot mapping (full POSIX parity — every slot implemented)

| Group | Slots | Implementation |
|---|---|---|
| I/O (blob fd, **no SQLite**) | `pread` `pwrite` `preadv` `preadv2` `copy_range` `read_sendfile_fd` `ftruncate` `fsync` `fstat` | direct syscalls on the blob fd; `read_sendfile_fd` returns the blob fd for the range; extending `pwrite`/`ftruncate` flag a deferred catalog size/mtime write-back |
| lifecycle | `open` `close` | `open`: one txn to look up or create the row + blob, return the real fd in `obj->fd`; private blob fd is the object's fd. `close`: flush pending size/mtime, close blob fd |
| namespace (catalog txns) | `stat` `unlink` `mkdir` `rename` `server_copy` | `unlink`: row + blob removal (dir-emptiness check first). `rename`: atomic `UPDATE objects SET path=…,parent=…` + child reparent in one txn (honest `CAP_HARD_RENAME`). `server_copy`: `copy_file_range` the blob + insert row (`CAP_SERVER_COPY`) |
| dirs (`CAP_DIRS`) | `opendir` `readdir` `closedir` | `SELECT … WHERE parent=?`; cursor state in the dir handle |
| xattr (`CAP_XATTR`) | `getxattr` `listxattr` `setxattr` `removexattr` | rows in `xattrs` keyed by `(path, name)` |
| staged atomic publish | `staged_open` `staged_write` `staged_commit` `staged_abort` | `staged_open`: temp blob. `staged_commit`: one txn finalizing the blob + insert/replace row (atomic publish). `staged_abort`: drop temp blob |

`obj->fd` = the real blob fd for regular files; `obj->state` carries the catalog
handle reference + the blob id + pending-writeback flags. Directories carry no
blob fd.

---

## 7. Concurrency

nginx workers are separate processes, so the catalog is a cross-process shared
resource. Each instance opens its own SQLite handle in `init()` with:

```
PRAGMA journal_mode = WAL;      -- concurrent readers + single writer
PRAGMA busy_timeout = N;        -- retry on writer lock instead of erroring
PRAGMA synchronous  = NORMAL;   -- WAL-safe, faster than FULL
```

Prepared statements are cached per-instance; metadata transactions are kept
minimal. WAL concurrency only gates **metadata** throughput — never bulk data,
which never touches SQLite. Measuring this contention is the core of the
"is the performance good enough?" question that gates Phase 2.

---

## 8. Module layout (coding-standards: small, focused files)

- **New** `src/fs/backend/sd_pblock.c` — driver vtable + object/I/O ops
- **New** `src/fs/backend/sd_pblock_catalog.c` + `.h` — isolated SQLite layer
  (schema bootstrap, prepared statements, object/xattr/dir CRUD); independently
  unit-testable, keeps all `sqlite3.h` usage in one translation unit
- **Edit** `src/fs/backend/sd.h` — `extern const xrootd_sd_driver_t xrootd_sd_pblock_driver;`
- **Edit** `src/fs/backend/sd_registry.c` — one `#if XROOTD_HAVE_SQLITE` row in `sd_drivers[]`
- **Edit** `./config` — `XROOTD_HAVE_SQLITE` probe (Ceph pattern), add the two new
  `.c` files to `NGX_ADDON_SRCS`, append `-lsqlite3` to `ngx_module_libs`
- **Edit** `src/fs/backend/README.md` — document the backend

---

## 9. Build gating

Header-gated `XROOTD_HAVE_SQLITE`, mirroring the Ceph/librados gate in `./config`:

- probe compiles a tiny `#include <sqlite3.h>` + `sqlite3_open`/`sqlite3_libversion`
  program against `-lsqlite3`;
- present → `-DXROOTD_HAVE_SQLITE=1`, compile both `.c` files, register the row,
  append `-lsqlite3` to `ngx_module_libs` (NOT only `CORE_LIBS`, or dynamic-module
  dlopen fails — see rpm_packaging_three_packages);
- absent → `sd_pblock*.c` contribute nothing, the registry row is `#if`-compiled
  out → a no-SQLite build is byte-for-byte unchanged.
- `XROOTD_WITHOUT_SQLITE=1` force-disables even when present.

(Enabled on the dev box: sqlite3 3.34.1, header present.)

---

## 10. Verification — Phase 1 (this work)

Standalone C unit tests following the existing convention
(`sd_ceph_unittest.c`, `csi_unittest.c`, `tests/c/run_cinfo_tests.sh`),
compiled directly against `-lsqlite3` over a temp root + temp catalog — no nginx,
no real S3/Ceph:

- **`src/fs/backend/sd_pblock_catalog_unittest.c`** — the SQLite layer in
  isolation: schema bootstrap, object CRUD, parent-indexed listing, xattr CRUD,
  rename/reparent, size/mtime write-back.
- **`src/fs/backend/sd_pblock_unittest.c`** — the driver through the vtable,
  every slot with POSIX-parity assertions:
  - create → `pwrite` → extend → `fstat` (catalog size) → `pread` / `preadv`
    round-trip → `ftruncate` → `fsync`
  - `read_sendfile_fd` returns a **valid** blob fd (proves the zero-copy path)
  - `mkdir` → `opendir` / `readdir` enumeration → nested children
  - `rename` of a file and of a directory subtree (children reparented)
  - `server_copy` (independent blob, shared bytes verified)
  - xattr set/get/list/remove round-trip
  - staged atomic publish: `staged_open` → `staged_write` → `staged_commit`
    (visible only after commit) and `staged_abort` (never visible)
  - `unlink` removes row + blob; `stat`-by-path consistent after every mutation
- **Concurrency / parallel + async tests** (explicit requirement):
  - **Multi-thread**: N pthreads issuing parallel blob reads/writes to distinct
    and shared objects, asserting data integrity and no catalog corruption under
    WAL + `busy_timeout`.
  - **Multi-process**: `fork()` several children, each its own instance/handle,
    concurrently creating/renaming/statting + reading/writing blobs against one
    shared catalog — validates cross-process WAL locking, the `busy_timeout`
    retry path, and that bulk blob I/O is unaffected by metadata contention.
  - **Async-style interleave**: out-of-order open/write/stat/close sequences to
    confirm pending size/mtime write-back is flushed correctly regardless of
    operation ordering.
  - **`tests/c/run_pblock_tests.sh`** compiles and runs all of the above with a
    non-zero exit on any failure.

---

## 11. Phase 2 — deferred (named follow-on, NOT this work)

Per the agreed steer (*implementation first, VFS-correctness later*), this work
does **not**:

- add a per-export config directive to **select** `pblock` for live traffic, nor
- fix the data-plane POSIX-pinning (the VFS audit gap) so protocol handlers
  dispatch through `obj->driver` instead of `xrootd_sd_posix_wrap()`.

Those are the immediate Phase-2 follow-on this driver unlocks: once `pblock`
exists and is proven in isolation, wiring selection + making the VFS dispatch
through the bound driver lets the full pytest protocol suites
(`root://`, WebDAV, S3) run end-to-end against a `pblock` export — the real
"keep the VFS data access pathways 100% correct" payoff, and the harness for the
"is the performance good enough to drop in for POSIX?" evaluation.
