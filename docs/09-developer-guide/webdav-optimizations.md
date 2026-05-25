# WebDAV path optimizations

How WebDAV GET/PUT/COPY achieve near-syscall efficiency: `copy_file_range`, per-connection fd cache, spooled PUT fast-path, and x509 verification reuse.

[← Overview](optimizations.md)

## 18. WebDAV Pre-Resolves The Export Root

### What Changed

The WebDAV module resolves `xrootd_webdav_root` to a canonical absolute path at
configuration time and stores it in `root_canon`.

### Before

Each request could need a `realpath()`-style walk of the export root.

### After

The root is canonical once, and request-time path handling starts from that
trusted canonical prefix.

### Why It Helps

`realpath()` is not a single cheap string operation. It can perform repeated
metadata checks for path components. Eliminating it from every request removes
avoidable VFS work.

Expected benefits:

- fewer path-resolution syscalls
- cheaper `GET`, `HEAD`, `PUT`, `DELETE`, `MKCOL`, and `PROPFIND`
- simpler request-time confinement checks

Relevant code:

- `src/webdav/config.c`
- `src/webdav/path.c`

---

## 19. WebDAV GET Keeps A Per-Connection FD Cache

### What Changed

The WebDAV path keeps a small fd cache on the HTTP connection, sized by
`WEBDAV_FD_TABLE_SIZE` (currently 16 entries).

Each cached entry records:

- open fd
- canonical path
- URI hash
- inode/device
- open time

### Why It Helps

HTTP keepalive clients frequently issue repeated `GET`, `HEAD`, or range
requests for the same file. Reusing the open fd avoids repeating the full path
resolution and open sequence.

On a cache hit, the request can use one `fstat()` on an existing fd instead of
another pathname walk and `open()`.

Expected benefits:

- fewer `open()` and path walk syscalls
- less duplicate VFS work
- faster keepalive range traffic
- fewer race windows from resolving the same path repeatedly

### Correctness

The cache validates entries and is evicted on writes and deletes so stale
content is not served after mutation.

Relevant code:

- `src/webdav/fd_cache.c`
- `src/webdav/get.c`

---

## 20. WebDAV Miss Path Uses `open()+fstat()`

### What Changed

When the fd cache misses, WebDAV `GET` opens the file first and then uses
`fstat()` on that fd. It avoids doing a separate pathname `stat()` before
`open()`.

### Why It Helps

`stat(path)` followed by `open(path)` repeats pathname lookup work and creates
a race window between checking the path and opening it. `open()+fstat()` gives
metadata for the object that was actually opened.

Expected benefits:

- one fewer pathname-based syscall on cache misses
- less duplicate VFS work
- better correctness under concurrent path mutation

Relevant code:

- `src/webdav/get.c`
- `src/webdav/fd_cache.c`

---

## 21. WebDAV GET Uses File-Backed Output Buffers

### What Changed

The WebDAV download path builds file-backed nginx buffers and hands them to the
normal HTTP output filter chain, including range responses.

### Why It Helps

This keeps the data path streaming-oriented. The module does not assemble an
entire large HTTP response in user memory.

Expected benefits:

- lower memory use for large downloads
- fewer userspace copies where nginx can use file-output optimizations
- better behavior for large Range responses
- compatibility with nginx's normal HTTP output filters

### TLS Caveat

As with native stream TLS, HTTPS still pays encryption costs. File-backed
buffers avoid unnecessary module-level copying, but TLS can still force data
through the SSL stack.

Relevant code:

- `src/webdav/get.c`
- `src/webdav/fd_cache.c`

---

## 22. WebDAV PUT Uses A Kernel-Side Spooled-File Fast Path

### What Changed

Large HTTPS uploads often arrive in nginx as spooled temp files under
`client_body_temp_path`. The optimized WebDAV `PUT` path detects those file
buffers and copies them to the destination with:

- `copy_file_range()` on Linux when available
- a 1 MiB buffered fallback when the kernel fast path is unavailable

### Why It Helps

If nginx has already written the request body to a temp file, reading it back
into small userspace buffers and writing it out again is wasteful.
`copy_file_range()` lets the kernel copy file data between fds without a large
userspace bounce buffer.

Expected benefits:

- fewer read/write loop syscalls for large uploads
- less userspace memory copying
- lower CPU per GiB uploaded
- better large WebDAV PUT throughput

Relevant code:

- `src/webdav/put.c`
- `src/webdav/io.c`

---

## 23. WebDAV PUT Can Offload In-Memory Bodies

### What Changed

When nginx already has the full request body in memory, the WebDAV module can
coalesce it once and hand the blocking write to a thread pool.

### Why It Helps

Small and medium request bodies may never be spooled to disk by nginx. The
spooled-file fast path does not apply there, but the worker still should not
sit in a blocking write loop.

Expected benefits:

- worker stays responsive during upload writes
- mixed read/write workloads remain smoother
- small and medium uploads avoid penalizing unrelated keepalive connections

Relevant code:

- `src/webdav/put.c`
- `src/webdav/io.c`

---

## 24. WebDAV X509 Auth Reuses Verification Work

### What Changed

The WebDAV TLS/x509 path has several fast paths:

1. The CA/CRL store is built once at config load.
2. If nginx already verified the client certificate with matching trust inputs,
   the module can reuse that result.
3. Verified subject information is cached on the live TLS connection.
4. Verified subject information can also be stored on the `SSL_SESSION`.
5. Cache-reuse INFO logging is emitted once per cached auth entry instead of on
   every keepalive request.

### Why It Helps

Certificate verification is expensive relative to steady-state bulk I/O.
Repeatedly rebuilding trust state or reverifying the same client certificate on
keepalive requests wastes CPU.

Expected benefits:

- fewer `X509_verify_cert()` calls
- cheaper keepalive HTTPS requests
- cheaper resumed TLS sessions
- lower auth CPU in multi-request clients
- less error-log I/O when `error_log` is configured at `info`

Relevant tests:

- `tests/test_gsi_tls.py`
- `tests/test_webdav_auth_cache.py`

Relevant code:

- `src/webdav/auth_cert.c`
- `src/webdav/pki.c`
- `src/crypto/pki_load.c`
- `src/crypto/pki_check.c`
