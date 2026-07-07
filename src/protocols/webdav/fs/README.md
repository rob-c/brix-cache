# webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE

## Overview

This subsystem implements the **byte-and-metadata copy primitives** used by the WebDAV
`COPY` (and `MOVE`-via-copy-fallback) handler when both the source and the destination
live under the same local export root. It is deliberately *not* a remote transfer engine:
cross-server transfers are HTTP-TPC (`../tpc.c` / native `../../tpc/`). This code only
duplicates a file or a directory tree **within one filesystem namespace**, doing so with
kernel-side zero-copy when the filesystem supports it and a portable `pread`/`pwrite`
fallback when it does not.

It exists because RFC 4918 `COPY` requires an atomic, metadata-preserving duplication of a
resource, and a naive "open + loop + write" loses two things HEP/grid clients care about:
(1) kernel zero-copy performance on large physics files, and (2) the XRootD extended
attributes (`user.xrd.*`) and WebDAV dead-properties that carry checksums and custom
metadata across protocol boundaries. Both functions here preserve those xattrs on every
successful copy.

In the request lifecycle this subsystem sits **below** the WebDAV method router. The HTTP
`COPY` handler (`../copy.c`) does all the protocol work — parses the `Destination`,
`Overwrite`, and `Depth` headers, resolves and confines both paths via `resolve_path()`,
runs `webdav_check_locks()` and the `If-Match`/`If-None-Match` conditionals, and stages a
temp path for atomic commit. It then calls into this subsystem to move the actual bytes:
`webdav_copy_file()` for a single resource (`Depth: 0`) and `webdav_copy_dir_recursive()`
for a collection (`Depth: infinity`). The result is committed back to the destination by
`../copy.c` via a confined `rename`.

Only the WebDAV protocol uses this code. The S3 `CopyObject` path and XRootD
`kXR_clone`/`kXR_chkpoint` share the lower-level `brix_copy_range()` engine in
`../../compat/copy_range.c` directly but do not enter this subsystem.

## Files

| File | Responsibility |
|------|----------------|
| `copy_engine.c` | The two confined copy orchestrators. `webdav_copy_file()` stat's the source for size/mode, opens both ends with confined `openat2`, drives the shared `brix_copy_range()` engine, then preserves XRootD fattr + WebDAV dead-props. `webdav_copy_dir_recursive()` walks a directory with `opendir`/`readdir` (skipping `.`/`..`), `lstat`-classifies each entry, recreates subdirectories with `brix_mkdir_confined_canon()` (tolerating `EEXIST`), copies regular files via `webdav_copy_file()`, and recurses — propagating xattrs on directories too. |
| `copy_engine.h` | Public prototypes: `webdav_copy_file()` and `webdav_copy_dir_recursive()`, both `(log, root_canon, src, dst) -> ngx_int_t`. Pulls in `../webdav.h` for shared types and the confined-helper declarations. |

## Key types & data structures

This subsystem defines **no structs of its own** — it is pure procedural glue over already
canonicalized C-string paths. The relevant types it operates on are:

- `root_canon` (`const char *`) — the canonical, NUL-terminated export-root path used as the
  confinement anchor for every `openat2`/`mkdir`/`rename`. Supplied by the caller
  (`webdav_copy_collection_task_t.root_canon` in `../copy.c`).
- `src` / `dst` (`const char *`) — already-resolved, confined absolute paths produced by the
  WebDAV `resolve_path()` helper before this subsystem is reached.
- `WEBDAV_MAX_PATH` (== `BRIX_PATH_MAX`, `../webdav.h:77`) — the size of the on-stack
  `src_child` / `dst_child` buffers in the recursive walk; child-path composition is bounds-
  checked against it with `snprintf` truncation detection.
- `struct stat` / `struct dirent` — POSIX classification primitives; `S_ISDIR`/`S_ISREG`
  gate the recursion vs. file-copy branch.

## Control & data flow

**Entry.** Called only from `../copy.c`:
- `webdav_copy_file()` — file copies and the per-file leaf of a recursive copy.
- `webdav_copy_dir_recursive()` — invoked once `../copy.c` has created the staged temp
  directory, when `Depth: infinity`.

**Calls out to (siblings):**
- `../../compat/copy_range.c` (`brix_copy_range()`) — the actual byte mover:
  `copy_file_range(2)` with a `pread`/`pwrite` fallback on `ENOSYS`/`EOPNOTSUPP`/`EXDEV`.
  See [../../compat/README.md](../../../core/compat/README.md).
- `../../compat/namespace_ops.c` — confinement + metadata: `brix_open_confined_canon()` /
  `brix_mkdir_confined_canon()` (`openat2 RESOLVE_BENEATH` against the export root),
  `brix_ns_copy_fattrs()` (copies the `user.xrd.*` xattr prefix), and `brix_log_safe_path()`
  for sanitized error logging.
- `../webdav.h` → `webdav_dead_props_copy()` — copies the WebDAV dead-property xattr prefix;
  a thin wrapper over the same `brix_xattr_copy_by_prefix()` helper as the fattr copy.

**Returns** `NGX_OK` / `NGX_ERROR` to `../copy.c`, which translates failures into HTTP status
(typically `500`, or the staged temp tree is cleaned up before a retryable status). This
subsystem itself runs synchronously; see the blocking-I/O note below.

Related upstream context: WebDAV method routing lives in [../README.md](../README.md);
path canonicalization/confinement in [../../path/README.md](../../../fs/path/README.md); the
async data plane for *reads/writes* (not used here) in [../../aio/README.md](../../../core/aio/README.md).

## Invariants, security & gotchas

1. **Kernel confinement is mandatory and never bypassed for opens.** Every `open` and
   `mkdir` of a client-influenced path goes through `brix_open_confined_canon` /
   `brix_mkdir_confined_canon`, which use `openat2` with `RESOLVE_BENEATH` anchored to the
   per-worker export root. A `..`/symlink escape is refused with `EXDEV` rather than falling
   through to a raw syscall (`../../compat/namespace_ops.c:67`, `:88`). Do **not** add a raw
   `open`/`mkdir` on a wire path here.

2. **The bare `stat(src)` / `lstat(src_child)` calls are read-only probes, not the trust
   boundary.** `webdav_copy_file()` opens with `stat()` for size+mode and the recursive walk
   uses `lstat()` for classification (`copy_engine.c:49`, `:117`). These are not confined
   syscalls — confinement is enforced at the subsequent `openat2`/`mkdir`. They are safe only
   because `../copy.c` has already resolved both paths through `resolve_path()` and rejected
   self-copy by inode/dev comparison *before* this subsystem is entered. Never call these
   functions with an unresolved client path.

3. **This is pure file I/O — no TLS/cleartext buffer concerns, but it is BLOCKING.**
   `brix_copy_range()` is explicitly documented as a blocking call that must not run on the
   nginx event-loop thread (`../../compat/copy_range.h`). The collection copy in `../copy.c`
   is therefore dispatched as a thread-pool task (`webdav_copy_collection_task_t`); any new
   caller of these functions must likewise keep them off the event loop.

4. **Zero-copy with graceful degradation.** `copy_file_range(2)` gives kernel-side zero-copy
   on supporting filesystems; the fallback path makes the same call portable across NFS/CIFS/
   cross-device targets. Callers get identical semantics regardless — the degradation is
   invisible above this layer.

5. **Metadata preservation happens on success only, for both files and directories.** xattr
   copy (`brix_ns_copy_fattrs` + `webdav_dead_props_copy`) runs after a successful byte copy
   in `webdav_copy_file()` (`copy_engine.c:74-77`) and immediately after each `mkdir` in the
   recursive walk (`:131-132`). A failed body copy preserves nothing — the temp tree is
   discarded by the caller.

6. **Child-path overflow is fatal, not silent.** The recursive walk bounds-checks every
   composed child path against `WEBDAV_MAX_PATH` and aborts the whole copy with `NGX_ERROR`
   on truncation (`copy_engine.c:108-115`) rather than copying to a wrong/truncated path.

7. **`EEXIST` on subdirectory `mkdir` is tolerated; any other error aborts.** This makes the
   recursive copy idempotent over a partially pre-existing destination tree
   (`copy_engine.c:124-128`). Non-`EEXIST` mkdir failures stop the walk.

8. **Special files are skipped, not errored.** Only `S_ISDIR` and `S_ISREG` entries are acted
   on; symlinks, devices, sockets, and FIFOs are silently ignored by the walk. A failed
   `lstat` on a child is also skipped (`continue`), not fatal.

## Entry points / extending

- **To add a new local copy variant** (e.g. preserving timestamps, or sparse-aware copy):
  add the function to `copy_engine.c`, declare it in `copy_engine.h`, keep the
  `(log, root_canon, src, dst)` signature shape, and route confined opens exclusively
  through the `*_confined_canon` helpers. Register the byte mover via `brix_copy_range()`
  rather than reimplementing `copy_file_range`.
- **To preserve an additional xattr namespace**, do not hand-roll `getxattr`/`setxattr` —
  add a thin wrapper over `brix_xattr_copy_by_prefix()` (`../../compat/namespace_ops.h`)
  alongside the existing `brix_ns_copy_fattrs` / `webdav_dead_props_copy` calls.
- **Build registration:** both files are already listed in the top-level `config`
  (`$ngx_addon_dir/src/protocols/webdav/fs/copy_engine.{c,h}`). A new `.c` in this directory must be
  added to that list and `./configure` re-run; an incremental edit needs only `make`.
- **Testing:** every change needs the standard three tests — success (file + recursive),
  error (e.g. mkdir failure, copy_range failure), and a security-negative (a `..`/symlink
  destination that must be refused with `EXDEV` and never written outside the export root).

## See also

- [../README.md](../README.md) — WebDAV method router and `COPY`/`MOVE` handlers (`../copy.c`).
- [../../compat/README.md](../../../core/compat/README.md) — `brix_copy_range`, `namespace_ops`
  confined helpers, and xattr-prefix copy.
- [../../path/README.md](../../../fs/path/README.md) — path canonicalization and `RESOLVE_BENEATH`
  confinement model.
- `../../tpc/` (native SHM-key TPC) and `../tpc.c` (WebDAV curl COPY) — the *remote*
  third-party-copy paths this subsystem deliberately does not implement.
- [../../README.md](../../README.md) — master subsystem index.
