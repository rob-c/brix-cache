# read — read-side XRootD operations and file-handle lifecycle

| File | Responsibility |
|---|---|
| `close.c` | Close open handles and log transfer totals |
| `locate.c` | `kXR_locate` local endpoint and manager/upstream redirects |
| `open.c` | `kXR_open`, write-mode detection, TPC detection, retstat, path resolution |
| `open_cache.c` | Cache-aware read-open: ACL check against auth root, cache-hit open, cache-miss fill trigger |
| `pgread.c` | `kXR_pgread` page reads plus shared page/CRC trailer encoding |
| `prefetch.c` | Best-effort `posix_fadvise()` helpers |
| `read.c` | Single-handle `kXR_read` and sendfile/chunked response choice |
| `readv.c` | Multi-segment `kXR_readv` validation and response assembly |
| `stat.c` | Path and handle based `kXR_stat` |
| `statx.c` | Batched `kXR_statx` |

## Data flow

The common read path goes through `open.c` to get a file handle and then
`read.c` or `pgread.c` to transfer data.  The AIO fork branches at
`xrootd_try_post_read_aio()` — if a thread pool is configured the pread is
offloaded; otherwise the read is synchronous inline.

```
handshake/dispatch_read.c: xrootd_dispatch_read_opcode()
    │
    ├─ kXR_open  →  read/open.c: xrootd_handle_open()
    │       path/resolve.c: xrootd_resolve_path()       [path sanitization]
    │       path/acl.c: xrootd_check_vo_acl()           [VO access gate]
    │       [cache miss?] → cache/: xrootd_cache_open_or_fill()
    │       open(2), connection/fd_table.c: xrootd_alloc_fhandle()
    │       response/basic.c: xrootd_send_ok() with retstat body
    │
    ├─ kXR_read  →  read/read.c: xrootd_handle_read()
    │       connection/fd_table.c: xrootd_get_read_fhandle()
    │       [thread pool] → aio/read.c: xrootd_try_post_read_aio()
    │                             worker thread: pread(2)
    │                             main loop: xrootd_read_aio_done()
    │       [no thread pool] → pread(2) inline
    │       connection/write_helpers.c: xrootd_queue_response_chain()
    │
    ├─ kXR_pgread →  read/pgread.c: xrootd_handle_pgread()
    │       same AIO fork as kXR_read; response includes per-page CRC32c
    │
    ├─ kXR_readv  →  read/readv.c: xrootd_handle_readv()
    │       validates segment list, assembles interleaved response
    │       [thread pool] → aio/readv.c
    │
    ├─ kXR_stat   →  read/stat.c: xrootd_handle_stat()
    │       stat(2) or fstat(2), encodes id/size/flags/mtime
    │
    └─ kXR_close  →  read/close.c: xrootd_handle_close()
            close(2), logs cumulative bytes and duration
```
