# The `pblock` storage backend — a block-striped, full-parity drop-in for POSIX

> **Audience:** developers extending the storage layer.
> **Scope:** the `pblock` ("pseudo-block") Storage Driver (`src/fs/backend/sd_pblock.c`
> + `sd_pblock_catalog.c`), and the VFS↔backend wiring (`src/fs/vfs_backend_registry.c`,
> `vfs_open.c`, `vfs_*.c`) that lets one VFS serve many backends and keeps the
> nginx server *and* the native clients reaching storage correctly.
> **Companion docs:** [`pblock-metadata-performance.md`](pblock-metadata-performance.md)
> (metadata throughput vs POSIX, flame-graph analysis, and the lookup-cache /
> single-statement-mutation / existence-gate optimizations),
> [`vfs-shared-architecture.md`](vfs-shared-architecture.md)
> (the cross-tree SD/VFS sharing), [`src/fs/backend/README.md`](../../src/fs/backend/README.md)
> (the driver index), [`phase-55-storage-backend-abstraction.md`](../refactor/phase-55-storage-backend-abstraction.md)
> (the seam), [`phase-62-vfs-namespace-metadata-seam-closure.md`](../refactor/phase-62-vfs-namespace-metadata-seam-closure.md)
> (the full VFS seam).

---

## 0. TL;DR

`pblock` is a complete storage backend that behaves like POSIX to everything above
it, but stores data very differently:

- **Bulk content** is striped across **fixed-size block files** (default **64 MiB**)
  on a real filesystem — `<root>/data/<aa>/<bb>/<blob_id>/<block_index>`.
- **The entire logical namespace + metadata** (path → blob mapping, size, mtime,
  mode, directory tree, xattrs) lives in **one SQLite catalog** —
  `<root>/catalog.db`.
- The **hot byte path never touches SQLite**. Block 0 is held open as a real
  kernel fd (so small files keep zero-copy `sendfile`); the catalog is consulted
  only at metadata boundaries (`open`, `fsync`, `close`, namespace ops).

It advertises **the same capability bitmap as POSIX** and implements **every**
vtable slot, so it is a true drop-in: `root://`, WebDAV, and S3 all run unchanged
on top of it. It is **server-only** and **build-gated** on `libsqlite3`
(`XROOTD_HAVE_SQLITE`); a no-sqlite build is byte-for-byte unchanged.

```
                    pblock in one picture
   ┌──────────────────────────────────────────────────────────────┐
   │  logical view (what every protocol sees)                       │
   │      /atlas/run42/AOD.root   →   a normal 9.7 GB file          │
   └──────────────────────────────────────────────────────────────┘
                 │                              │
        metadata │                              │ bytes
                 ▼                              ▼
   ┌───────────────────────┐      ┌──────────────────────────────────┐
   │  catalog.db (SQLite)  │      │  data/3f/a9/3fa9…e1/              │
   │  path → blob_id,size, │      │     0   1   2   …   154           │
   │  mode, mtime, dirtree │      │   (64 MiB block files; 0 = open)  │
   └───────────────────────┘      └──────────────────────────────────┘
       cold: open/fsync/ns           hot: pread/pwrite/sendfile
```

---

## 1. Where pblock sits in the stack

pblock is one **Storage Driver** below the VFS seam. Everything above the seam —
confinement re-check, metrics, access log, cache, page-CRC, buffer shaping — is
written once in the VFS and is *identical* regardless of which driver is bound.

```
   root://        WebDAV/davs://      S3 REST          (protocol handlers)
      │                │                 │
      └────────────────┼─────────────────┘
                       ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  VFS  (src/fs/)   xrootd_vfs_open / read / write / stat /       │
   │                   opendir / unlink / rename / mkdir / xattr …   │
   │   • re-checks confinement        • metrics + access log         │
   │   • read-through / write cache    • page-CRC (pgread/pgwrite)   │
   │   • builds nginx buffer chains    • EINTR / short-I/O loops     │
   └───────────────────────────────────────────────────────────────┘
                       │  the SD seam (sd.h): a flat vtable + caps
        ┌──────────────┼───────────────┬─────────────┬─────────────┐
        ▼              ▼               ▼             ▼             ▼
   ┌─────────┐   ┌──────────┐    ┌──────────┐  ┌─────────┐  ┌──────────┐
   │ posix   │   │ pblock   │    │ block    │  │  s3     │  │  ceph    │
   │(default)│   │(this doc)│    │ (device) │  │(object) │  │ (rados)  │
   └─────────┘   └──────────┘    └──────────┘  └─────────┘  └──────────┘
        │              │
        │              ├── catalog.db  (SQLite: namespace + metadata)
        │              └── data/…/<blob>/<idx>  (fixed-size block files)
        └── openat2(RESOLVE_BENEATH) on the export tree (1 file == 1 inode)
```

**Key consequence:** because pblock implements every slot and advertises every
POSIX capability, no protocol handler, metric, cache, or access-log call site
changes when an export switches from POSIX to pblock. The switch is one config
directive (`xrootd_storage_backend pblock`).

---

## 2. The defining idea — split metadata from bulk content

POSIX couples three concerns in the inode + directory entry: the **name**, the
**metadata** (size/mtime/mode), and the **bytes**. pblock deliberately *splits*
them:

```
        POSIX                              pblock
   ┌───────────────┐            ┌─────────────────┐   ┌──────────────────┐
   │  dir entry +  │            │  catalog row    │   │  block files     │
   │  inode +      │            │  (name+meta+    │──▶│  (opaque bytes,   │
   │  data extents │            │   blob pointer) │   │   id-addressed)   │
   │  (all one fs  │            └─────────────────┘   └──────────────────┘
   │   object)     │             namespace/metadata     content
   └───────────────┘             — SQLite —             — filesystem —
```

Why split?

1. **The hot path stays database-free.** A `pread`/`pwrite`/`sendfile` needs only
   the blob id + cached size, both captured at `open`. No row lookup per I/O.
2. **Rename/commit become metadata-only.** Blocks are addressed by a random
   `blob_id`, not by their logical path, so moving a file (or publishing a staged
   upload) is a *catalog edit* — **zero bytes are copied or moved**.
3. **The catalog is independently testable.** `sd_pblock_catalog.c` is pure
   libc + sqlite3 (no nginx types), unit-tested standalone, and reusable.
4. **Content is just opaque blocks.** A future backend could keep the same
   catalog and put blocks on object storage, a raw device, etc.

---

## 3. On-disk layout

```
  <export root>/                     ← conf->common.root_canon
  ├── catalog.db                     ← SQLite: the whole namespace + metadata
  ├── catalog.db-wal                 ← WAL journal (journal_mode=WAL)
  ├── catalog.db-shm
  └── data/                          ← all object content, id-addressed
      ├── 3f/                        ← fan-out: blob_id[0:2]
      │   └── a9/                    ← fan-out: blob_id[2:4]
      │       └── 3fa9c1…e1/         ← per-object dir = full 32-hex blob_id
      │           ├── 0              ← block 0 (held open as obj->fd)
      │           ├── 1              ← block 1 (opened transiently per I/O)
      │           ├── 2
      │           └── …
      └── b7/
          └── 02/
              └── b702…9c/
                  └── 0              ← a small file: a single block-0 file
```

- The two-level **fan-out** (`<aa>/<bb>`) keeps any one directory from holding
  millions of object dirs — the same trick git uses for loose objects.
- A `blob_id` is **16 CSPRNG bytes → 32 lowercase hex** (`getrandom`), so it is
  unguessable and collision-free in practice. It is *not* derived from the path,
  which is exactly what makes rename free (§9).
- Block files are sparse-friendly: an unwritten block is simply **absent**, and a
  partially written block can be **short** — both read back as zeros (§6, holes).

### The catalog schema

```sql
CREATE TABLE objects(
  path       TEXT PRIMARY KEY,   -- logical path, e.g. "/atlas/run42/AOD.root"
  parent     TEXT NOT NULL,      -- parent dir path (for O(1) readdir)
  is_dir     INTEGER NOT NULL,   -- 1 = directory, 0 = file
  blob_id    TEXT NOT NULL DEFAULT '',   -- 32-hex content id ('' for dirs)
  size       INTEGER NOT NULL DEFAULT 0,
  block_size INTEGER NOT NULL DEFAULT 0, -- per-file stripe size (0 for dirs)
  mtime      INTEGER NOT NULL DEFAULT 0,
  ctime      INTEGER NOT NULL DEFAULT 0,
  mode       INTEGER NOT NULL DEFAULT 0);
CREATE INDEX objects_parent ON objects(parent);   -- readdir = WHERE parent=?

CREATE TABLE xattrs(
  path  TEXT NOT NULL,
  name  TEXT NOT NULL,
  value BLOB NOT NULL,
  PRIMARY KEY(path, name));
```

Two structural facts worth internalizing:

- **`parent` is denormalized** so a directory listing is one indexed
  `SELECT … WHERE parent = ?` instead of a path-prefix scan.
- **`block_size` is stored per file.** Re-tuning the export default only affects
  files created *afterwards*; existing files keep the stripe size they were born
  with (so their block math never changes underneath them).

The root `/` is inserted as a directory at instance init, so `stat("/")`,
`opendir("/")`, and PROPFIND on the export root work before anything is written —
exactly like a freshly mounted POSIX filesystem.

---

## 4. The block-striping model

A logical file of `size` bytes with stripe `bs` occupies blocks
`0 .. (size-1)/bs`. Block 0 always exists (a 0-byte file still has block 0).

```
  logical file  (size = 150 MiB, block_size = 64 MiB)
  ┌──────────────────────────┬──────────────────────────┬───────────────┐
  │  block 0  [0 .. 64MiB)    │  block 1  [64 .. 128MiB)  │ block 2 [128…) │
  └──────────────────────────┴──────────────────────────┴───────────────┘
        │                            │                          │
        ▼                            ▼                          ▼
   data/…/<blob>/0              data/…/<blob>/1            data/…/<blob>/2
   (full 64 MiB,                (full 64 MiB,              (22 MiB,
    held OPEN as obj->fd)        transient open)            transient open)
```

For any byte offset `off`, the mapping is:

```
   block index   idx  = off / bs
   in-block off  boff = off % bs
   room in block room = bs - boff
```

A read or write of `len` bytes walks block-by-block, clamping each step to the
room left in the current block (`pblock_read_blocks` / `pblock_write_blocks`):

```
   pwrite(off=60MiB, len=8MiB), bs=64MiB
   ┌─ step 1 ─────────────┐┌─ step 2 ──────────────────────────┐
   │ idx0  boff=60M room=4M││ idx1  boff=0   room=64M            │
   │ write 4 MiB to blk 0  ││ write 4 MiB to blk 1               │
   └──────────────────────┘└───────────────────────────────────┘
        (a single client write straddles two block files)
```

**Block 0 is special.** It is opened persistently at `open` time and stored in
`obj->fd`. Higher blocks are opened `O_RDWR|O_CREAT` *transiently* for the
duration of one I/O and closed immediately. This keeps the common case (small
files, and the start of large ones) on a real, already-open kernel fd — which is
what makes zero-copy `sendfile` possible (§11) — without holding hundreds of fds
open for a multi-GB file.

---

## 5. Object lifecycle (`open` / `close`)

`sd_pblock_open` is the single decision point. It first does **one** catalog
lookup, then branches:

```
                 sd_pblock_open(path, sd_flags)
                          │
              catalog_lookup(path) ──► rc<0 ─► error (errno)
                          │
          ┌───────────────┼───────────────────────────┐
        present dir     present file                 absent
          │               │                            │
   O_WRITE? EISDIR    O_CREATE|O_EXCL? EEXIST     O_CREATE? ── no ─► ENOENT
   else: make_obj      else:                           │ yes
   (fd = INVALID,      open_existing:                pblock_open_create:
    dir handle)        • open blk0 (O_RDWR/RDONLY)   • gen blob_id (CSPRNG)
                       • O_TRUNC? block-aware        • mkdir fan-out + obj dir
                         ftruncate(0)                • create blk0 O_EXCL
                                                     • INSERT catalog row
                          │                            │
                          └──────────► pblock_make_obj(fd, meta) ◄──┘
                                       (heap obj + per-open state,
                                        obj->heap_shell = 1)
```

The returned `xrootd_sd_obj_t` carries:

```
  obj.fd        = block-0 kernel fd  (or NGX_INVALID_FILE for a directory)
  obj.heap_shell= 1   (malloc'd shell — the VFS adopter frees it after copy)
  obj.state ──► pblock_obj_t {
                  st          → instance state (root, data_dir, catalog)
                  path        → logical path (the catalog key)
                  blob_id     → 32-hex content id
                  block_size  → THIS file's stripe size
                  meta        → cached {size, mtime, mode, …}  ← hot path reads
                  dirty:1     → size/mtime changed, needs catalog write-back
                }
```

`close` flushes the cached `size`/`mtime` to the catalog **iff `dirty`**
(`catalog_touch`), closes the block-0 fd, and frees the per-open state — but
**not** the `obj` shell (the VFS copies the object *by value* into its handle, so
the shell's owner frees it; see §15).

---

## 6. The hot read path (`pread`)

```
   sd_pblock_pread(buf, len, off)
      │  meta.size cached at open — NO catalog touch
      ├─ off >= size?            → return 0   (EOF)
      ├─ clamp len to size-off   (never read past logical EOF)
      └─ pblock_read_blocks(blob_id, bs, blk0_fd, buf, len, off)
              walk block-by-block:
              ┌─────────────────────────────────────────────┐
              │ idx==0 && blk0_fd>=0 ? reuse obj->fd         │
              │ else open(block_path(idx), O_RDONLY)         │
              │   └─ ENOENT  → memset(zeros)   (whole hole)  │
              │ pread(fd, …, boff)                           │
              │   └─ short read → memset tail zeros (hole)   │
              └─────────────────────────────────────────────┘
```

Holes are first-class: a block file that was never written is **absent**
(`ENOENT` → zero-fill), and a block written only partway is **short** (the
unread tail zero-fills). This is what lets a random `pwrite` at a high offset
create a logically large, physically sparse file.

`preadv` is a loop over `pread` (stops at the first short/EOF segment);
`preadv2` ignores `RWF_*` and delegates to `preadv` (the warm-cache `RWF_NOWAIT`
probe in `read/read.c` simply gets a normal read).

> **Client short reads are normal.** A single `kXR_read` of a multi-block range
> comes back as a *short read* (the server frames up to roughly one block per
> response); a correct client loops until it has the bytes it asked for. This is
> XRootD wire behaviour, not a pblock limit — the object's full length is always
> available across iterations.

### 6.1 `stat` of an OPEN handle must ask the driver, not the bare fd

A handle's `obj.fd` is **only block 0**, so a plain `fstat(obj.fd)` reports the
block size, not the logical object size (for a >1-block file it would under-report
to one `block_size`). The handle-based `kXR_stat` path (`read/stat.c`) therefore
has a **driver-backed branch**: when the handle carries a non-default storage
driver (`files[idx].sd_obj.driver`), it calls that driver's worker-safe `fstat`
slot (pblock returns the catalog-backed `meta`) instead of `fstat`ing the bare fd.

```
   kXR_stat on an open handle (read/stat.c):
     zip_mode?    → archive fstat, size = cached_size (member length)
     slice_mode?  → synthesize from cached_size (/dev/null fd)
     sd_obj.driver != default ?  → driver->fstat(&sd_obj)   ← pblock: real size
     else          → fstat(bare fd)                          ← POSIX export
```

Path-based `kXR_stat` was always correct (it routes through `driver->stat` →
catalog). The driver-backed handle branch makes the *handle* path agree. The
branch is gated on `sd_obj.driver`, which is `NULL` for POSIX handles, so POSIX
stat is untouched.

---

## 7. The hot write path (`pwrite`) + durability

```
   sd_pblock_pwrite(buf, len, off)
      └─ pblock_write_blocks(blob_id, bs, blk0_fd, buf, len, off)
              walk block-by-block:
                idx==0 && blk0_fd>=0 ? reuse obj->fd
                else open(block_path(idx), O_RDWR|O_CREAT) transiently
                pwrite(fd, …, boff)
      └─ on success, update the CACHED row (in memory only):
                meta.mtime = now
                meta.size  = max(size, off+len)     ← grow high-water mark
                dirty = 1                            ← deferred catalog write
```

The catalog row's `size`/`mtime` are **not** written on every `pwrite` — they are
cached in `obj.meta` and the `dirty` bit is set. They are flushed to SQLite only
at a **durability boundary**:

```
   fsync(obj):                          close(obj):
   ┌─────────────────────────────┐      ┌──────────────────────────────┐
   │ fsync(block 0)              │      │ if dirty: catalog_touch(      │
   │ for blk 1..last_block:      │      │     path, size, mtime)        │
   │     open, fsync, close      │      │ close(block-0 fd)             │
   │ if dirty: catalog_touch(…)  │      │ free per-open state           │
   │     dirty = 0               │      │ (shell freed by VFS adopter)  │
   └─────────────────────────────┘      └──────────────────────────────┘
```

`fsync` is the real durability barrier: it fsyncs **every** block file backing
the object (block 0 via the open fd, higher blocks opened read-only just to
fsync), then persists the metadata. This mirrors POSIX `fsync` semantics across
the striped representation.

---

## 8. `ftruncate` — block trim + drop

Truncation is block-aware: trim the boundary block to its surviving bytes, then
unlink whole blocks past the new end.

```
   ftruncate(file, len)         bs = 64 MiB,  old size = 150 MiB → new len = 70 MiB

   keep     = (len-1)/bs   = 1          (block 1 survives, partly)
   boundary = len - keep*bs= 6 MiB      (bytes kept inside block 1)
   old_last = (150M-1)/bs  = 2

   before:   [ blk0 64M ][ blk1 64M ][ blk2 22M ]
                                ▼ truncate blk1 to 6 MiB,  unlink blk2
   after:    [ blk0 64M ][ blk1 6M ]
                  meta.size = 70M, dirty = 1
```

`open … O_TRUNC` on a write reuses this exact path with `len = 0`.

---

## 9. Namespace operations (catalog-only) — and why rename is free

`stat`, `mkdir`, `unlink`, `rename`, `opendir`/`readdir`, and xattr CRUD are
**pure catalog operations** — they never open a block file (except `unlink` of a
*file*, which also removes its blocks).

The standout is **rename**, which moves *no bytes at all* because blocks are
addressed by `blob_id`, not by the logical path:

```
   rename("/a/old", "/a/new")           rename("/dir", "/dir2")  (a subtree)

   objects                              objects (one IMMEDIATE transaction)
   ┌──────────┬─────────┐               BEGIN IMMEDIATE
   │ path     │ blob_id │               1. collect:  SELECT path WHERE
   │ /a/old   │ 3fa9…   │                   path='/dir' OR substr(path,1,
   └──────────┴─────────┘                   len+1)='/dir/'    ← prefix, not LIKE
        │  UPDATE path='/a/new'         2. for each row: rename_one()
        ▼  (blob_id untouched)             UPDATE path, parent  (objects)
   ┌──────────┬─────────┐                  UPDATE path          (xattrs)
   │ /a/new   │ 3fa9…   │               COMMIT  (or ROLLBACK on any failure)
   └──────────┴─────────┘
   bytes moved: 0                       bytes moved: 0   (atomic subtree move)
```

The subtree collect uses a **`substr()` prefix test, not `LIKE`** — deliberately,
to avoid `LIKE` wildcard (`%`/`_`) escaping on user-controlled paths. The whole
subtree reparent runs in one `BEGIN IMMEDIATE … COMMIT`, so it is atomic and
isolated from other workers.

By contrast, `server_copy` (kXR_clone / WebDAV COPY / S3 CopyObject) **does** copy
blocks — the destination needs its own `blob_id`, so each source block file is
copied to a fresh destination block (`pblock_copy_one_block`), then a new catalog
row is inserted.

```
   operation        bytes touched     catalog
   ───────────────  ───────────────   ──────────────────────────────
   rename / move    none              UPDATE path(s)          (atomic)
   staged commit    none              INSERT row → staged blob (atomic)
   server_copy      copy all blocks   INSERT row → new blob
   unlink (file)    unlink all blocks DELETE row (+ xattrs)
   unlink (dir)     none              DELETE row (must be empty: ENOTEMPTY)
```

`unlink`/`rmdir` enforce POSIX semantics from the catalog: removing a directory
checks `child_count(path) == 0` (else `ENOTEMPTY`); `unlink` of a directory is
`EISDIR`, `rmdir` of a file is `ENOTDIR`.

---

## 10. Staged atomic publish — commit without a copy or a rename

Crash-safe uploads (S3 PutObject, WebDAV PUT) use the staged family. pblock's
implementation is the cleanest expression of the blob-id idea: the staged blocks
**become** the final object — commit is a single catalog `INSERT`.

```
   staged_open(final="/x/big.root")          (no catalog row yet)
        gen blob_id  b=7c1f…           ┌── data/7c/1f/7c1f…/0,1,2,…  (writing)
        mkdir obj dir                  │
                                       │
   staged_write(off,len)  ────────────┘   (block-striped, high-water `size`)
        … many writes, possibly out of order, possibly multi-GB …

   staged_commit(noreplace?):
        if final exists: noreplace?EEXIST : drop_dst(final)  (free old blocks)
        INSERT objects(path="/x/big.root", blob_id=7c1f…, size, …)
        ── the staged blocks ARE now the file.  0 bytes moved. ──

   staged_abort():
        remove the staged blocks (no catalog row was ever inserted)
```

Compare with the POSIX backend, where staging is a temp file that must be
`rename()`d into place. Here there is **no temp-to-final move** — publishing is
the catalog insert, and aborting is just deleting orphan blocks.

### 10.1 `upload_resume on` with a pblock export — stage on an independent POSIX mount

`xrootd_upload_resume on` (the `root://` write path) stays **on** with a pblock
export. The key is that the **resume partial is NOT a pblock object** — it is a
plain POSIX file on an **independent POSIX staging mount** (`xrootd_stage_dir`),
and only the *committed* result lands in the pblock namespace.

Why the partial must be POSIX:

- A resume partial takes **random-offset writes** and survives reconnects; that
  wants a real kernel fd and a real `stat()` for the deterministic resume-offset
  probe. A POSIX staging mount gives exactly that.
- Reconnect detection (`xrootd_open_probe` of the partial) and the partial open
  both run **as the worker on the POSIX stage dir** — never through the pblock
  driver — so they are not confused by pblock's catalog namespace.

The publish is then a **cross-filesystem atomic commit** done by the staged-write
state machine on a clean `kXR_close` — it does **not** `rename(2)` (which cannot
cross from the POSIX stage mount into the driver-owned pblock namespace). Instead
`xrootd_commit_staged` resolves the final export's backend and, finding pblock,
streams the partial **into** the backend via the driver's `staged_*` state
machine (§10), then drops the POSIX partial:

```
   upload (resume on, pblock export)               independent POSIX
   ┌───────────────────────────────┐               staging mount
   │ kXR_open(write)                │            /stage/<id>.xrdresume.part
   │   resume partial opens on the  │  ────────▶  (real POSIX fd; random-offset
   │   POSIX stage dir (as worker)  │              writes; survives reconnect)
   │ kXR_write × N → pwrite(partial)│
   └───────────────────────────────┘
                 │ clean kXR_close
                 ▼
   xrootd_commit_staged(fd, stage_path, final_path)
     ├─ fsync(partial)                       ← durability
     ├─ xrootd_vfs_backend_resolve_for_path(final_path) → pblock  (non-POSIX:
     │     longest-prefix match of the absolute final path to a registered export)
     └─ commit_staged_to_backend():          ← CROSS-FS atomic publish
          st = pblock.staged_open("/run42/AOD.root")
          loop: pread(partial) → pblock.staged_write(st)   (stripes into blocks)
          pblock.staged_commit(st)           ← one catalog INSERT = published
          unlink(partial)                    ← POSIX partial consumed
                 │ (on failure: staged_abort + KEEP the partial → resume retry)
                 ▼
   the object now exists in the pblock catalog + data/ blocks
```

So `rename(2)` is the same-filesystem fast path for POSIX exports; a pblock final
takes the driver `staged_*` publish; a POSIX-to-POSIX cross-device commit takes
the copy-then-rename path — all three behind the one `xrootd_commit_staged`
chokepoint shared by `root://` close and WebDAV PUT.

**Operational requirement:** with a pblock export and `upload_resume on`, point
`xrootd_stage_dir` at an **independent POSIX mount**. (Without a stage dir the
deterministic partial would be derived under the export root — a namespace the
pblock driver, not the kernel, owns — so reconnect detection and the partial open
would be inconsistent. The independent POSIX mount is the supported, intended
layout.)

> **Verified (2026-06-28).** A live `root://` upload to a pblock export
> (`block_size=1m`, `upload_resume on`, an independent POSIX `xrootd_stage_dir`):
> a 3.2 MB write staged on the POSIX mount and committed into pblock byte-exact —
> the catalog recorded `size=3200000`, the data striped across 4 block files
> (0,1,2 = 1 MiB, 3 = 54 272 B), the **stage dir was empty** afterwards (the POSIX
> partial consumed), and the md5 read-back matched. Overwrite (delete+new) and
> `rm` likewise behaved exactly as on a POSIX export. The single commit chokepoint
> (`xrootd_commit_staged`) keeps POSIX exports on the original rename / cross-device
> path, so non-pblock exports are unaffected.

---

## 11. Zero-copy `sendfile` — block-0 only

The VFS read path asks the driver, per range, whether it can serve zero-copy
(`read_sendfile_fd`). pblock says yes **only** for an offset-0 range that fits
inside block 0 (the persistently-open `obj->fd`):

```
   read_sendfile_fd(off, len, want_zerocopy)
      ├─ !want_zerocopy (TLS / page-CRC wanted) → INVALID  (serve memory-backed)
      ├─ obj->fd == INVALID (a directory)        → INVALID
      ├─ off == 0 && len <= block_size           → return obj->fd   ✅ sendfile
      └─ otherwise (multi-block / mid-file range) → INVALID  (memory-backed)
```

So a small file, or the first `block_size` bytes of a large file over cleartext,
is sent with `sendfile(2)` straight from block 0. Ranges that span block
boundaries fall back to the VFS's memory-backed chain (a normal `pread` through
the driver) — correct, just not zero-copy. (Making the VFS read path
block-boundary-aware so every range can sendfile from the right block is a
documented follow-on; the capability is advertised, the fast path is offset-0.)

This is exactly the contract the seam was designed for: **the backend owns the
zero-copy decision; the VFS only consumes the answer.**

---

## 12. Capability bitmap — full POSIX parity

```
   cap                    posix   pblock   meaning
   ─────────────────────  ─────   ──────   ───────────────────────────────
   CAP_FD                   ✓       ✓       exposes a real kernel fd (block 0)
   CAP_SENDFILE             ✓       ✓       zero-copy (offset-0 / block-0)
   CAP_RANGE_READ           ✓       ✓       pread at any offset
   CAP_RANDOM_WRITE         ✓       ✓       pwrite at any offset
   CAP_TRUNCATE             ✓       ✓       block-aware ftruncate
   CAP_APPEND               ✓       ✓       O_APPEND semantics
   CAP_IOURING              ✓       ✓       block-0 fd is io_uring-submittable
   CAP_SERVER_COPY          ✓       ✓       server_copy (copies blocks)
   CAP_XATTR                ✓       ✓       xattrs in the catalog
   CAP_HARD_RENAME          ✓       ✓       atomic rename (catalog UPDATE)
   CAP_DIRS                 ✓       ✓       real directories (catalog rows)
   CAP_FSCS                 ✓        ✗      page checksums (CSI) — not yet
```

Every slot in the vtable is implemented. The one absent capability is `CAP_FSCS`
(filesystem page checksums / CSI) — pblock does not yet integrate the CSI
tagstore.

---

## 13. Concurrency model

Two axes of concurrency, handled differently:

```
   ┌── one worker PROCESS ──────────────────────────────────────────┐
   │   event loop                AIO thread pool                     │
   │      │  open/close/ns          │  pread/pwrite/fsync (hot path) │
   │      ▼                         ▼                                │
   │   ┌──────────────────────────────────────────┐                 │
   │   │  ONE pblock instance per export           │                 │
   │   │  • ONE sqlite3 conn (SQLITE_OPEN_FULLMUTEX │                │
   │   │    = SERIALIZED → safe across threads)     │                │
   │   │  • block fds are per-open, thread-local    │                │
   │   └──────────────────────────────────────────┘                 │
   └────────────────────────────────────────────────────────────────┘
        worker A                         worker B (separate process)
        ┌─────────────┐                  ┌─────────────┐
        │ conn → WAL  │ ◀── busy_timeout ──▶ │ conn → WAL  │
        └─────────────┘   (retry, don't fail)└─────────────┘
                     shared catalog.db (+ -wal, -shm)
```

- **Across threads (one worker):** the single SQLite connection is opened
  `SQLITE_OPEN_FULLMUTEX` (serialized), and statements are **prepared per call and
  finalized immediately** — no cached cursors that could race between threads. The
  raw byte ops touch only per-open block fds and the cached `meta`, never SQLite.
- **Across processes (many workers):** `journal_mode=WAL` + `synchronous=NORMAL` +
  a **busy timeout** so a writer blocked by another worker **retries** rather than
  failing with `SQLITE_BUSY`. `BEGIN IMMEDIATE` on rename takes the write lock
  up-front so the subtree move is isolated.
- **Per-worker instance.** A SQLite connection **must not be shared across
  `fork()`**, so the instance is built **lazily, per worker** (§15) — never in the
  master.

---

## 14. Design philosophies & concerns

| Principle | How pblock embodies it | The concern it answers |
|---|---|---|
| **Metadata ≠ content** | catalog (SQLite) vs blocks (files) | keep the hot path DB-free; make rename/commit O(metadata) |
| **Hot path is sacred** | size/mtime cached in `obj.meta`; `dirty` bit; catalog only on `fsync`/`close` | a per-I/O DB round-trip would dominate latency |
| **Content is id-addressed** | random `blob_id`, never the path | rename/move/commit copy **zero bytes** |
| **Blocks are independent files** | fixed-size stripes, holes = absent/short | sparse files; bounded per-block fd lifetime; trivial truncate |
| **Per-file block size** | recorded at create, never retuned | changing the export default can't corrupt existing files' math |
| **Block 0 stays open** | persistent `obj->fd`; higher blocks transient | zero-copy sendfile for small files without fd exhaustion on big ones |
| **Bounded directories** | two-level `<aa>/<bb>` fan-out | millions of objects without a giant directory |
| **Pure, testable metadata** | catalog is libc + sqlite3, no nginx | standalone unit tests; reusable; no data-plane cost |
| **ngx-free, malloc-owned** | all state `malloc`'d, no nginx pool | identical in the module and the standalone test binary |
| **Build-gated, fail-closed** | whole file under `#if XROOTD_HAVE_SQLITE` | no-sqlite build byte-for-byte unchanged; registry row `#if`'d out |
| **Confinement is the catalog** | logical paths are catalog keys; no `..` escape possible because there is no real path traversal | a non-POSIX namespace can't be tricked by symlinks |

**Known limits / follow-ons** (honest about the edges):

- **`sendfile` is offset-0 only** (§11) — multi-block ranges serve memory-backed.
- **No CSI page checksums** (`CAP_FSCS` absent).
- **Catalog is the single point of metadata truth** — back it up with the blocks;
  a lost `catalog.db` orphans the blocks (they are id-addressed, not
  self-describing). `fsync` syncs blocks + metadata, but a catalog-level backup
  strategy is an operator concern.
- **`getrandom` blob ids** assume a seeded CSPRNG (always true post-boot).

---

## 15. How the VFS serves *many* backends — the sharing changes

The whole point of the seam is that the VFS body is backend-agnostic. Three
pieces make that real for pblock (and any non-POSIX driver).

### 15.1 Per-export registration (config time) → lazy per-worker instance

```
   CONFIG TIME (master process, parsing nginx.conf)
   ┌────────────────────────────────────────────────────────────────┐
   │  location /  {                                                  │
   │     xrootd_webdav_storage_backend     pblock;                   │
   │     xrootd_webdav_pblock_block_size   128m;                     │
   │  }                                                              │
   │  (stream: xrootd_storage_backend / xrootd_pblock_block_size)    │
   └────────────────────────────────────────────────────────────────┘
        │ merge-time hook (webdav/config.c, config/runtime_server.c)
        ▼
   xrootd_vfs_backend_config(root_canon, "pblock", block_size)
        └─ records {root_canon, "pblock", block_size} in a small fixed
           table (deduped on root_canon → reload-idempotent).  NO instance
           is built here (the master must not hold a SQLite conn across fork).

   FIRST USE (per worker process, after fork)
   xrootd_vfs_backend_resolve(root_canon, log)
        ├─ entry.inst != NULL ? return it          (already built this worker)
        └─ else xrootd_sd_instance_create("pblock", {root, busy=5s, block})
                 → sd_pblock_init: mkdir root+data, open catalog.db, ensure "/"
                 → cache entry.inst (on ngx_cycle->pool)  → return
```

Because the loc-conf table is copy-on-write across workers, each worker writes its
**own** `entry.inst` pointer and therefore gets its **own** SQLite connection —
never shared across `fork()`.

### 15.2 `ctx_init` resolves the backend for *every* op, automatically

The crucial wiring: `xrootd_vfs_ctx_init()` calls `xrootd_vfs_backend_resolve()`
once, so **every** VFS context — from any protocol, for any op — carries the right
bound instance without each of the ~50 ctx-build sites threading it by hand.

```
   handler (root:// / WebDAV / S3)
        │  build ctx for "/atlas/run42/AOD.root"
        ▼
   xrootd_vfs_ctx_init(ctx, …, root_canon, …)
        └─ ctx->sd = xrootd_vfs_backend_resolve(root_canon)   ← pblock or NULL
        ▼
   xrootd_vfs_open(ctx, …)
        ├─ ctx->sd != default-driver ?  → ctx->sd->driver->open(logical,…)
        │                                  + adopt_obj (carry per-open state)
        └─ else (POSIX) → borrow rootfd instance → driver->open → adopt_fd
```

`NULL` (no registered backend, or a no-sqlite build) means "default POSIX" — the
existing confinement cascade runs unchanged. So the pblock path is purely
*additive*: nothing about the POSIX path changed.

### 15.3 The logical-path contract (`export_relative`)

An instance-keyed driver op (`stat`/`open`/`xattr`/…) expects the
**export-root-relative logical path**, because that is the pblock catalog key.
The VFS supplies it via `xrootd_vfs_export_relative()`:

```
   ctx->root_canon = "/srv/exports/atlas"
   resolved path   = "/srv/exports/atlas/run42/AOD.root"
        │  xrootd_vfs_export_relative()  strips root_canon
        ▼
   logical path    = "/run42/AOD.root"   ← the catalog key pblock stores
```

(POSIX, by contrast, uses the absolute resolved path + `RESOLVE_BENEATH`; the
helper returns the path unchanged when it is not under `root_canon`.)

### 15.4 Driver dispatch is the same shape in every VFS op

Each VFS entry point uses the identical pattern: *if a non-default driver is
bound, route to it on the logical path; else take the POSIX confined-helper
path.* The op stays metered + access-logged + confinement-checked above the seam
regardless.

```
   xrootd_vfs_<op>(ctx, …):
       require_confined(ctx)                       ← always (above the seam)
       drv = xrootd_vfs_ctx_driver(ctx)            ← bound driver or NULL
       if (drv != NULL && drv-><op> != NULL)
           rc = drv-><op>(ctx->sd, export_relative(ctx, path), …)   ← pblock
       else
           rc = xrootd_<op>_confined_canon(root_canon, path, …)     ← POSIX
       observe(ctx, OP_<X>, …)                     ← always (metric + log)
```

This is live today for `stat`/`open`/`unlink`/`copy`/the xattr family; the byte
ops (`pread`/`pwrite`/`preadv`/`copy_range`/`fstat`/`sendfile`) dispatch on the
handle's `obj.driver`.

**Two resolvers, one registry.** Most call sites carry the export `root_canon`
(from the request ctx) and use `xrootd_vfs_backend_resolve(root_canon)`. The
staged-commit path (§10.1) instead has only the absolute *final path* of a partial
it must publish, so it uses `xrootd_vfs_backend_resolve_for_path(abs_path)`, which
longest-prefix-matches the path against the registered export roots. Both share
the same per-worker lazy-build helper, so they return the *same* cached instance.

---

## 16. Server vs. client — what is shared, what is not

The SD seam is shared between two build worlds: the **nginx server** (`src/`) and
the **native clients** (`client/lib`, via the ngx-free `libxrdproto`). pblock sits
on the server-only side.

```
   ┌───────────────────────── shared (compiles into BOTH) ─────────────────┐
   │  sd.h            the seam: caps, vtable, obj model, xrootd_sd_posix_wrap│
   │  sd_posix.c      POSIX raw byte ops (pread/pwrite/…) — touch only fd    │
   │  sd_block.c      block-device driver (raw fd I/O + BLKGETSIZE64 fstat)  │
   │  sd_s3.c         object/S3 driver (SigV4/HEAD/GET/PUT/MPU) + transport  │
   │  fs/core/        the xvfs_* verb core: the EINTR / short-I/O loop policy │
   └───────────────────────────────────────────────────────────────────────┘
        ▲                                              ▲
        │ nginx server (src/)                          │ native clients (client/lib)
   ┌────┴───────────────────────────┐        ┌─────────┴───────────────────────┐
   │ vfs_server (nginx-coupled):     │        │ client VFS shell (ngx-free):     │
   │  • confined open (RESOLVE_      │        │  • UNconfined open (arbitrary    │
   │    BENEATH / impersonation)     │        │    user URL/path)                │
   │  • metrics, access log, cache   │        │  • io_uring override, temp+rename│
   │  • pool/threadpool/sendfile     │        │    commit                        │
   │  • pblock  ← SERVER-ONLY        │        │  • per-handle capability flags   │
   │    (sqlite + malloc, module     │        └──────────────────────────────────┘
   │     build only)                 │
   └─────────────────────────────────┘
```

**Why pblock is server-only:**

- It needs **SQLite** (a server/operator dependency), and it manages a
  **per-export, per-worker** catalog + block tree — a server-side storage role.
  The clients address *remote* endpoints (`root://…`, `s3://…`, a local file,
  a block device); they never own a pblock catalog.
- The seam is still shared: pblock is *just another `xrootd_sd_driver_t`*. The
  parts the client needs — the vtable shape, the POSIX raw-fd ops, the verb core —
  are exactly the ngx-free pieces in `libxrdproto`. pblock simply isn't compiled
  into that archive.

**How the client reaches storage correctly:** the client builds its own
`xrootd_sd_obj_t`/handle over the shared driver (e.g. `xrootd_sd_posix_wrap` for a
local fd, `sd_s3` for an object endpoint) and runs the **same** `fs/core` verb
loops the server runs. So the EINTR/short-I/O/CRC behaviour can never drift
between server and client — there is one implementation. The split is only in
*open policy* (confined vs unconfined) and the nginx runtime, which is correct:
the server's confinement must never leak onto the client's arbitrary paths. See
[`vfs-shared-architecture.md`](vfs-shared-architecture.md) for the full cross-tree
treatment.

---

## 17. End-to-end flows on a pblock export

### 17.1 `root://` write of a 9.7 GB file

```
   xrdcp big.root root://gw//atlas/run42/AOD.root
     │
     ▼ kXR_open (write)         handler → ctx_init → ctx->sd = pblock instance
        xrootd_vfs_open(WRITE|CREATE) → driver->open("/run42/AOD.root")
           sd_pblock_open → open_create: blob_id, mkdir fan-out, blk0 O_EXCL,
                            INSERT catalog row, return heap obj (fd=blk0)
        adopt_obj → VFS handle carries obj by value (frees the heap shell)
     │
     ▼ kXR_write × N           (AIO thread pool)
        xrootd_vfs_io_execute(WRITE) → obj.driver->pwrite(buf,len,off)
           pblock_write_blocks: stripe across blocks 0..154 (blk0 reused,
           higher blocks transient); meta.size grows; dirty=1   (NO sqlite)
     │
     ▼ kXR_sync / kXR_close
        driver->fsync: fsync every block + catalog_touch(size,mtime); dirty=0
        driver->close: (already clean) close blk0; free state
```

This is the **direct** write path (resume/POSC off): the driver opens the final
object and the client writes straight into pblock. With **`upload_resume on`** the
client instead writes to a POSIX partial on the staging mount and the close-time
state machine publishes it into pblock — see §10.1.

### 17.2 S3 GET of a small object (zero-copy)

```
   GET /bucket/key   (cleartext)
     │ ctx_init → ctx->sd = pblock; xrootd_vfs_open(READ) → driver->open
     │ size = 2 MiB (≤ block_size) → block 0 holds it all
     ▼ VFS read path asks driver->read_sendfile_fd(off=0, len=2MiB, zc=1)
        pblock returns obj->fd  → nginx sendfile(2) straight from block 0
        (a TLS GET, or a >block_size / mid-file range, returns INVALID →
         the VFS serves a memory-backed chain via driver->pread instead)
```

---

## 18. Testing

pblock is exercised entirely **outside** the nginx build, because both halves are
ngx-free:

```
   sd_pblock_catalog_unittest.c   the catalog API in isolation (CRUD, rename,
                                  readdir, xattr, child-count)
   sd_pblock_unittest.c           the full driver vtable through its function
                                  pointers — every slot, plus:
                                    • multi-thread  (FULLMUTEX correctness)
                                    • multi-process (WAL + busy-timeout)
                                    • async interleave
                                    • fsync durability
```

Run them via `tests/c/run_pblock_tests.sh`. Because the driver is pure libc +
sqlite3, the test binary links it directly — no nginx, no server, no fixture
export.

**Live end-to-end (manual, 2026-06-28):** a dedicated stream instance with
`xrootd_storage_backend pblock`, `xrootd_pblock_block_size 1m`,
`xrootd_upload_resume on`, and an independent POSIX `xrootd_stage_dir` — a
multi-block `root://` upload committed into pblock byte-exact, with correct
path- *and* handle-`stat`, overwrite, and `rm` (see §10.1 and §6.1). A POSIX
export's handle-`stat` was re-checked to confirm the driver-backed branch left it
unchanged.

---

## 19. Invariants & gotchas (carry these forward)

1. **Never share a SQLite connection across `fork()`.** The instance is built
   lazily per worker for exactly this reason; do not move instance creation into
   the master or a config-time path.
2. **The hot path must stay SQLite-free.** `pread`/`pwrite`/`preadv`/`copy_range`
   read `obj.meta` (cached at open) and touch only block files. If you need fresh
   metadata mid-I/O, you are doing it wrong — flush on `fsync`/`close`.
3. **`block_size` is immutable per file.** It is read from the catalog row at
   open and drives all block math. Never recompute it from the current export
   default.
4. **Block 0 is the only persistent fd.** Higher blocks are opened transiently;
   don't assume an fd for block N>0 outside the small helper that opens it.
5. **`blob_id` is the content identity, not the path.** This is what makes rename
   and staged-commit byte-free — preserve it. `server_copy` is the *only* op that
   mints a new blob_id and copies bytes.
6. **The obj shell is freed by the adopter, not by `close`.** The VFS copies the
   object by value into its handle; `close` frees the per-open *state* but leaves
   the malloc'd shell to its owner (`obj.heap_shell` tells the adopter to free it).
7. **Paths are bound parameters, never formatted into SQL.** The subtree rename
   uses a `substr()` prefix test, not `LIKE`, to avoid wildcard escaping on
   user-controlled paths. Keep it that way.
8. **Build-gated.** All of `sd_pblock.c` is under `#if XROOTD_HAVE_SQLITE`; the
   registry row and the `xrootd_sd_pblock_conf_t` type are too. A no-sqlite build
   must remain byte-for-byte unchanged.
9. **Never `fstat` the bare fd to size a driver-backed handle.** The fd is block 0
   only — use the driver's `fstat` (§6.1). Any new code that reports an open
   handle's size/metadata must take the `sd_obj.driver`-backed branch, not a raw
   `fstat(fd)`.
10. **`upload_resume on` needs an independent POSIX `xrootd_stage_dir`.** The
   resume partial is a POSIX file there; the close-time commit publishes it into
   pblock cross-filesystem via the driver `staged_*` machine (§10.1). Do not route
   the partial itself through the pblock driver — it must stay a real POSIX file so
   random-offset writes and reconnect detection work.

---

## 20. File index

| File | Role |
|---|---|
| `src/fs/backend/sd_pblock.c` | the driver: block-striped byte I/O, object lifecycle, namespace/dir/xattr/staged ops, the `xrootd_sd_pblock_driver` descriptor |
| `src/fs/backend/sd_pblock_catalog.c` / `.h` | the SQLite metadata catalog: schema, typed CRUD, subtree rename, WAL/FULLMUTEX concurrency |
| `src/fs/backend/sd_pblock_unittest.c` | standalone driver-vtable suite (incl. multi-thread / multi-process / fsync) |
| `src/fs/backend/sd_pblock_catalog_unittest.c` | standalone catalog API suite |
| `src/fs/backend/sd.h` | the SD seam: caps, vtable, object model, `xrootd_sd_pblock_conf_t` |
| `src/fs/vfs_backend_registry.c` / `.h` | per-export backend choice (config time) → lazy per-worker instance; `xrootd_vfs_backend_resolve` (by root_canon) + `xrootd_vfs_backend_resolve_for_path` (by absolute path, longest-prefix — used by the staged commit) |
| `src/fs/vfs_open.c` | `ctx_init` backend resolve; the non-POSIX `driver->open` + `adopt_obj` path; `export_relative` |
| `src/fs/vfs_xattr.c`, `vfs_unlink.c`, `vfs_copy.c`, `vfs_stat.c` | the per-op `driver-><op>` vs POSIX dispatch |
| `src/core/compat/staged_file.c` | `xrootd_commit_staged` — backend-aware staged commit: POSIX rename / cross-device copy, **or** `commit_staged_to_backend` (driver `staged_*` upload) when the final export is non-POSIX (§10.1) |
| `src/protocols/root/read/open_resolved_file.c` | `kXR_open`: keeps resume/POSC partials on the POSIX-fd path; opens the final through the driver otherwise (Layer 3) |
| `src/protocols/root/read/stat.c` | `kXR_stat` — path stat via `driver->stat`; handle stat via the driver-backed `fstat` branch (§6.1) |
| `src/protocols/root/read/close.c` | `kXR_close`: POSC/resume commit via `xrootd_commit_staged` |
| `src/protocols/root/stream/module.c`, `src/protocols/webdav/module.c` | the `xrootd_storage_backend` / `xrootd_pblock_block_size` directives |
| `config` | build-gates `sd_pblock*.c` on `libsqlite3` (`-DXROOTD_HAVE_SQLITE=1`) |

## See also

- [`vfs-shared-architecture.md`](vfs-shared-architecture.md) — the shared SD/VFS
  core across server and client, the capability matrix, the S3 transport-vtable
  trick, and the dual (`ngx`-free) build.
- [`../../src/fs/backend/README.md`](../../src/fs/backend/README.md) — the driver
  index (posix/block/s3/ceph/pblock + the CSI tagstore).
- [`../../src/fs/README.md`](../../src/fs/README.md) — the VFS layer the driver
  sits beneath.
- [`../refactor/phase-55-storage-backend-abstraction.md`](../refactor/phase-55-storage-backend-abstraction.md),
  [`../refactor/phase-60-ceph-rados-backend.md`](../refactor/phase-60-ceph-rados-backend.md)
  — the seam and a second non-POSIX driver for comparison.
