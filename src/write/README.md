# write — XRootD write-path handlers

Implements all mutating XRootD operations.  Each opcode has its own file;
shared helpers live in `common.c` and `aio.c`.

| File | XRootD opcode | Operation |
|------|--------------|-----------|
| `write.c` | `kXR_write` | Raw write at offset (v3/v4 clients) |
| `pgwrite.c` | `kXR_pgwrite` | Paged write with CRC32c integrity (xrdcp v5+) |
| `writev.c` | `kXR_writev` | Scatter-gather write from a vector of (offset, data) segments |
| `mkdir.c` | `kXR_mkdir` | Create directory; handles `kXR_mkdirpath` for recursive creation |
| `rm.c` | `kXR_rm` | Remove a file |
| `rmdir.c` | `kXR_rmdir` | Remove an empty directory |
| `mv.c` | `kXR_mv` | Rename or move a file or directory |
| `chmod.c` | `kXR_chmod` | Change permission bits |
| `sync.c` | `kXR_sync` | fsync an open file handle |
| `truncate.c` | `kXR_truncate` | Truncate by path or open handle |
| `aio.c` | — | Thread-pool AIO helpers for write and pgwrite |
| `chkpoint.c` | `kXR_chkpoint` | Checkpoint lifecycle: begin (snapshot), commit (discard), rollback (restore), query |
| `chkpoint_xeq.c` | — | `ckpXeq` sub-dispatcher: executes write/pgwrite/truncate/writev under an active checkpoint |
| `common.c` | — | Shared path resolution for mutating requests and write AIO posting |

All handlers require `xrootd_allow_write on` in the server block; the
dispatcher rejects mutating requests with `kXR_NotAuthorized` if writes are
disabled.

`pgwrite.c` verifies the per-page CRC32c checksums supplied by the client
before writing; a mismatch returns `kXR_ChkSumErr`.

## Data flow

All write opcodes share the same guard sequence in
`handshake/dispatch_write.c`: require_auth → require_write → handler.
The AIO fork in `write.c` and `pgwrite.c` mirrors the read path.

```
handshake/dispatch_write.c: xrootd_dispatch_write_opcode()
    │   [every case calls require_auth + require_write first]
    │
    ├─ kXR_write   →  write/write.c: xrootd_handle_write()
    │       write/common.c: xrootd_write_resolve_handle()
    │       [thread pool] → aio/write.c: xrootd_try_post_write_aio()
    │                             worker thread: pwrite(2)
    │                             main loop: xrootd_write_aio_done()
    │       [no thread pool] → pwrite(2) inline
    │
    ├─ kXR_pgwrite →  write/pgwrite.c: xrootd_handle_pgwrite()
    │       per-page CRC32c verify (client-supplied vs. computed)
    │       same AIO fork as kXR_write on success
    │
    ├─ kXR_writev  →  write/writev.c: xrootd_handle_writev()
    │       parses iov-style segment list, issues sequential pwrite(2)s
    │
    ├─ kXR_sync    →  write/sync.c: xrootd_handle_sync()
    │       fdatasync(2) on the open handle
    │
    ├─ kXR_truncate → write/truncate.c: xrootd_handle_truncate()
    │       path or handle based ftruncate(2)
    │
    ├─ kXR_mkdir   →  write/mkdir.c: xrootd_handle_mkdir()
    │       mkdir(2); recursive when kXR_mkdirpath flag set
    │
    ├─ kXR_rm / kXR_rmdir / kXR_mv / kXR_chmod
    │       → write/{rm,rmdir,mv,chmod}.c — thin wrappers over the matching syscall
    │
    └─ kXR_chkpoint → write/chkpoint.c: xrootd_handle_chkpoint()
            dispatches on req->opcode subcode:
            kXR_ckpBegin    → copy original → .ckp sibling file
            kXR_ckpCommit   → delete .ckp
            kXR_ckpRollback → restore from .ckp, delete .ckp
            kXR_ckpQuery    → stat .ckp, return max/current size
            kXR_ckpXeq      → parse inner 24-byte sub-header, execute
                               sub-write synchronously (no AIO)
```
