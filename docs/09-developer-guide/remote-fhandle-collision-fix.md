# Remote File-Handle Collision: concurrent driver-backed opens crushed onto handle 0

This is the durable decision record for four BriX bugs that surfaced when a
pure-python `xrd` client + uproot read/write an MNIST `.root` file **through
BriX → an official xrootd origin** (local, no-auth). Three were correctness bugs
in BriX's remote (driver-backed) path; the fourth was a missing explicit-mkdir
verb over a remote backend. Agent memory about this work must point here rather
than restate it, so the rationale cannot drift from the code.

This record is a companion to
[pass-through-gap-closure.md](pass-through-gap-closure.md), which covers the
metadata-op parity gaps (statx / isdir / locate / rename / truncate / checksum)
over the same `root://` backend. That doc closes *what BriX could not describe*;
this one closes *how BriX corrupted concurrent file handles and large reads*.

## Context

BriX is an nginx stream module speaking the XRootD wire protocol. A `root://`
origin is fronted by the `sd_xroot` driver, over which BriX auto-composes a posix
write-stage tier (`sd_stage`). A remote/object open is **memory-served**: the
handle slot has `obj->fd = -1` and `obj->sd_obj.driver = sd_xroot` — there is no
local file descriptor. uproot legitimately holds several `File` objects on one
connection at once, which is what exposed the handle bookkeeping.

## Root cause — the fd-only allocation predicate

The file-handle allocator `brix_alloc_fhandle`
(`src/protocols/root/connection/fd_table.c`) returned "the first slot where
`fd < 0`". For a local file that is correct: an open sets `fd >= 0`, so the slot
reads as occupied. But a remote open leaves `fd = -1` and marks liveness only via
`sd_obj.driver != NULL`. So after a remote open the slot's `fd` stayed `-1`, and
the allocator re-handed the **same slot (0)** to the next open. Every concurrent
remote open collapsed onto handle 0.

The bug was an **asymmetry between allocation and liveness**: the liveness
predicate `brix_validate_file_handle` (same file) already treated a slot as live
iff `fd >= 0 || sd_obj.driver != NULL || writer != NULL`, but the allocator only
checked `fd`. When uproot closed one `File`, it tore down the shared slot 0, so a
later read/readv on "another" file got `kXR_FileNotOpen` (errcode 3004).

## The fix

Allocation and liveness now share one predicate. Added
`static ngx_inline int brix_fhandle_slot_live(const brix_ctx_t *ctx, int handle_index)`
in `src/protocols/root/connection/fd_table.c`; both `brix_alloc_fhandle` and
`brix_ctx_has_open_file` are rewritten to use it, so a slot is "free" only when it
is live by the *same* rule validation uses (`fd >= 0 || sd_obj.driver != NULL ||
writer != NULL`). Concurrent remote opens now get distinct slot indices.

## Related fixes (same uncommitted change)

**Subdir staged-commit ENOENT** —
`sd_posix_staged_open` (`src/fs/backend/posix/sd_posix_ns.c`) now creates the
target's parent-directory chain in the store root via
`brix_mkdir_recursive_confined_canon` before opening the `O_EXCL` temp, so a
staged write to a subdirectory no longer fails with ENOENT on commit.

**`>1 MiB` remote read** —
`sd_xroot_pread` (`src/fs/backend/xroot/sd_xroot_io.c`) loops the origin read in
`≤ BRIX_CACHE_FETCH_CHUNK` (1 MiB) sub-reads, because `read_response` rejects wire
frames larger than 1 MiB — a single `>1 MiB` origin read previously failed.
Additionally, the read handlers gate off the thread-pool offload when
`sd_obj.driver != NULL` (see `src/protocols/root/read/read_buffered.c` and the
sibling read paths): the offload uses a local fd, which is invalid for a
memory-served remote handle.

**Explicit remote mkdir (was a gap)** —
`kXR_mkdir` over a remote xroot backend used to return EAGAIN: xroot had no
`.mkdir` vtable slot, so `sd_stage_mkdir` forwarded to it and got `NGX_ERROR`.
Now:

| Layer | Addition |
|:---|:---|
| Origin verb (`src/fs/cache/origin_ns.c`) | `brix_cache_origin_mkdir` — wire `kXR_mkdir` with the `kXR_mkdirpath` option; mode big-endian in `body[14..15]` |
| xroot driver (`src/fs/backend/xroot/sd_xroot_ns.c`) | `sd_xroot_mkdir`, same session pattern as unlink/rename, wired into the xroot vtable's `.mkdir` slot |

Both a client `MKDIR` and the mkpath prefix-walk
(`brix_vfs_backend_mkpath`, `src/fs/vfs/vfs_walk.c`) now resolve against
`root://`.

## Testing and bench

The full unmodified `bench.py` suite — including its `fs.mkdir` preamble — runs
through BriX end-to-end. All four fixes were shipped, the 1.3.0 RPMs
(`nginx-mod-brix-cache` et al.) rebuilt and reinstalled, and verified from the
packaged (stripped) module.

Bench baseline (256 MiB loopback, best-of-3, MiB/s) — origin direct / through
BriX:

| Workload | origin | BriX |
|:---|---:|---:|
| write | 80 | 33 (stage double-write) |
| read-whole | 326 | 249 |
| stream 8 MiB windows | 819 | 344 |
| readv 16 × 512 K | 584 | 331 |
