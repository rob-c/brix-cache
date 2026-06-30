# cephns — directory-aware RADOS driver over the flat sd_ceph backend

**Status:** design / spec — approved 2026-06-30
**Owner:** Rob Currie
**Scope:** A second librados storage driver, `sd_ceph_ns` (backend name
**`cephns`**), that adds a real POSIX-like directory namespace (mkdir / ls / mv /
stat / xattr) on top of the flat `sd_ceph` data plane, plus a zero-copy offline
migration from the existing flat layout. **No protocol changes; no RADOS symbol
above `src/fs/backend/`.**

---

## 1. Why

The flat `sd_ceph` driver maps a logical path directly to one RADOS object id
(`key_prefix + normalized_LFN`). It serves `xrdcp` in/out + stat + xattr, but is a
**flat key space**: no directories, so `xrdfs ls / mkdir / mv` are unsupported.
`cephns` adds a directory tree while reusing the flat driver's connection and
byte/xattr plane, and lets a site migrate existing flat data **without copying a
byte**.

---

## 2. Namespace model (omap dir-tree, stable IDs)

Every entry — file or directory — is identified by a **stable id**, so rename is
always a pure omap move (even for a populated directory), and migration can adopt
existing objects in place.

- **Directory object** — one RADOS object per directory, keyed by a stable
  `dir_id` (a uuid; the root is the well-known id `"ROOT"`). Its **OMAP** holds
  one key per child: `child-name → record`. The record is a fixed-size packed
  struct: `{ uint8 type (1=file,2=dir); int64 size; int64 mtime; int64 ctime;
  uint32 mode; char id[40] }` where `id` is the child's `blob_id` (file) or
  `dir_id` (subdir).
- **File data object** — keyed by `blob_id` in the same pool; the file's bytes
  **and** xattrs live here (reusing the flat data plane). `blob_id` = a fresh
  uuid for new files, or **the legacy flat object key for migrated files**
  (zero-copy adoption).
- **Collision-free single namespace:** dir_ids/blob_ids are uuids (+ the literal
  `"ROOT"`); legacy keys are `key_prefix`-prefixed human paths. None collide, so
  one RADOS namespace suffices (no `rados_ioctx_set_namespace` juggling).

**Operation map**

| op | mechanism |
|---|---|
| `stat(path)` | read `parent_dir` omap entry for `basename` (single-key omap get); `/` synthesizes a dir |
| `opendir/readdir` | `omap_get_vals` over the dir object → one dirent per omap key |
| `mkdir(path)` | create child dir object (empty) + add `type=dir` entry to parent omap; ENOENT if parent missing, EEXIST if name taken |
| `open(create)` | alloc `blob_id` (uuid), add `type=file` entry to parent omap, data ops on the blob object |
| `rename(src,dst)` | read src entry from src-parent omap, write to dst-parent omap, remove from src-parent — **id unchanged**, no data/descendant movement |
| `unlink(path)` | remove parent omap entry; for a file also remove the blob object; rmdir requires the dir omap be empty |
| `setattr` | rewrite the parent omap entry's mode/mtime fields |

Per-dir-object omap updates are atomic (one `rados_write_op`). A cross-directory
rename touches two dir objects and is **not** atomic across both — acceptable for
v1 (documented; a crash mid-rename can duplicate or drop one entry, never corrupt
data).

---

## 3. Reuse of the flat driver

`sd_ceph.c` is refactored to expose an **oid-level layer** (in `sd_ceph.h`, under
`#if XROOTD_HAVE_CEPH`), and its existing path-keyed vtable becomes a thin caller
of it. `cephns` builds on the same layer:

```c
typedef struct sd_ceph_conn_s sd_ceph_conn_t;            /* cluster + ioctx + pool */
sd_ceph_conn_t *sd_ceph_conn_create(const xrootd_sd_ceph_conf_t*, ngx_pool_t*, int *err);
void            sd_ceph_conn_destroy(sd_ceph_conn_t*);
rados_ioctx_t   sd_ceph_conn_ioctx(sd_ceph_conn_t*);     /* cephns drives omap with this */
/* data, keyed by an explicit oid */
ssize_t sd_ceph_oid_read (sd_ceph_conn_t*, const char *oid, void*, size_t, off_t);
ssize_t sd_ceph_oid_write(sd_ceph_conn_t*, const char *oid, const void*, size_t, off_t);
int     sd_ceph_oid_stat (sd_ceph_conn_t*, const char *oid, uint64_t *size, time_t *mtime);
int     sd_ceph_oid_trunc(sd_ceph_conn_t*, const char *oid, uint64_t);
int     sd_ceph_oid_remove(sd_ceph_conn_t*, const char *oid);
/* xattr, keyed by an explicit oid */
ssize_t sd_ceph_oid_getxattr (sd_ceph_conn_t*, const char *oid, const char *name, void*, size_t);
ssize_t sd_ceph_oid_listxattr(sd_ceph_conn_t*, const char *oid, void*, size_t);
int     sd_ceph_oid_setxattr (sd_ceph_conn_t*, const char *oid, const char *name, const void*, size_t);
int     sd_ceph_oid_rmxattr  (sd_ceph_conn_t*, const char *oid, const char *name);
```

The flat driver: `path → sd_ceph_key() → oid → sd_ceph_oid_*`. `cephns`:
`path → namespace lookup → blob_id → sd_ceph_oid_*` for data/xattr, and
`sd_ceph_conn_ioctx()` for the omap directory operations. The flat driver's wire
behaviour is byte-for-byte unchanged (verified by its existing live test).

---

## 4. Components (files)

```
src/fs/backend/rados/
  sd_ceph.{c,h}        REFACTORED: expose the sd_ceph_conn_t + oid-level API; flat
                       vtable now calls it. Behaviour-identical.
  sd_ceph_omap.{c,h}   NEW: the dir-record codec (pack/unpack, pure → unit-tested)
                       + dir-object omap helpers (get-entry / put-entry / del-entry
                       / list / create-dir / empty?) over a rados_ioctx_t.
  sd_ceph_ns.{c,h}     NEW: the cephns driver vtable (open/pread/pwrite/fstat/
                       stat/mkdir/rename/unlink/opendir/readdir/closedir/setattr/
                       xattr/staged) + xrootd_sd_ceph_ns_migrate().
src/fs/backend/sd_registry.c   register xrootd_sd_ceph_ns_driver (#if XROOTD_HAVE_CEPH)
src/fs/vfs_backend_registry.c  parse "cephns:<pool>[@conf][?key_prefix]" → instance
config (./config)              add sd_ceph_omap.c + sd_ceph_ns.c to NGX_ADDON_SRCS
tests/ceph/
  sd_ceph_omap_unittest.c   NEW: standalone record-codec checks (no cluster)
  sd_ceph_ns_live_test.c    NEW: live driver test (mkdir/ls/stat/rename/xattr/data)
  sd_ceph_migrate.c         NEW: offline migration tool (librados) over a pool
  ceph_ns_smoke.sh          NEW: end-to-end xrdfs mkdir/ls/mv + xrdcp + xattr
```

---

## 5. Migration (offline, zero-copy, idempotent)

`xrootd_sd_ceph_ns_migrate(conn, key_prefix, flags, &stats)` and the
`sd_ceph_migrate` CLI walk the flat pool (`rados_nobjects_list`) and build the
omap tree:

1. Ensure the root dir object (`dir_id="ROOT"`) exists.
2. For each flat object whose key starts with `key_prefix`: derive the LFN
   (strip prefix), split into path components, **create any missing intermediate
   directories** (new dir objects + parent omap links), then add a **file entry**
   in the leaf directory with `blob_id = the existing object key` (no data copy)
   and `size/mtime` from `rados_stat` of that object.
3. Skip entries that already exist (idempotent — safe to re-run / resume).
4. Skip the driver's own metadata objects (dir objects, by id shape) so a second
   pass doesn't re-ingest them.

Run once before switching the export's `xrootd_storage_backend` from `ceph:` to
`cephns:`. The adopted data objects keep their xattrs (incl. `user.XrdCks.*`), so
checksums-at-rest survive migration.

---

## 6. Error handling

`rados` negative-errno → errno via the existing `sd_ceph_set_errno`. Namespace
semantics: `mkdir` → EEXIST / ENOENT(parent) / ENOTDIR(parent is a file);
`rename` honours `noreplace` (EEXIST) and rejects a dir onto a non-empty dir /
onto itself; `unlink` of a non-empty dir → ENOTEMPTY; `open` of a missing file
without create → ENOENT. Path normalization reuses `sd_ceph_normalize` (slash
collapse, `.`/`..`, escape rejection).

---

## 7. Testing (3-per-change: success + error + security-neg)

- **Unit (no cluster):** `sd_ceph_omap_unittest.c` — record pack/unpack round-trip,
  field bounds, id truncation, type discrimination.
- **Live driver (container, pool xrdtest):** mkdir tree, create+write+read a file
  (byte-exact), stat sizes, opendir/readdir lists children, rename file + rename
  populated dir (id stable, children intact), xattr set/get/list on a file,
  unlink + rmdir (ENOTEMPTY on non-empty), negatives (mkdir missing parent,
  duplicate, open missing).
- **Migration:** seed flat objects via `sd_ceph`, run migrate, then via `cephns`:
  `ls` shows the reconstructed tree, `stat` sizes match, data round-trips
  byte-exact (proving zero-copy — same data objects), re-run migrate is a no-op.
- **Export smoke (`ceph_ns_smoke.sh`):** nginx with a `cephns` export (auth off):
  `xrdfs mkdir /d`, `xrdcp` into `/d/f`, `xrdfs ls /` and `/d`, `xrdfs mv`,
  `xrdfs stat`, `xrdfs xattr`, `xrdcp` out byte-exact; objects present in pool.

---

## 8. Scope boundaries (YAGNI)

- **No hardlinks / symlinks** (object stores have neither).
- **Cross-dir rename not crash-atomic** (single-dir ops are); documented.
- **No quota / per-dir accounting** in v1.
- **libradosstriper interop with stock XrdCeph** stays out of scope (flat driver's
  follow-on); cephns data objects are plain `rados_write` blobs like flat `sd_ceph`.
- Migration is **offline + zero-copy adopt-in-place** only (no lazy online import).
