# Optimizations in nginx-xrootd

Code-level optimizations that matter at scale: what changed, what cost was removed, why it matters, and which workloads
benefit. It is intentionally about implementation choices inside
`nginx-xrootd`, not just generic nginx tuning.

The short version: the module tries to keep the event loop free, avoid
unnecessary path walks and metadata syscalls, use file-backed output whenever it
is correct, batch small operations into larger kernel calls, and reuse hot-path
scratch objects instead of growing nginx pools for every transfer chunk.

---

## Optimization Goals

The project has two performance profiles that pull in different directions:

1. **High-concurrency transfers**
   - Many clients are active at once.
   - Scheduler overhead, event-loop blocking, and memory growth matter most.
   - nginx's event-driven model helps strongly here.

2. **Single-stream or low-concurrency transfers**
   - One or a few clients try to move data as fast as possible.
   - Per-request syscall count, sendfile boundaries, corking behavior,
     allocation overhead, and read-ahead behavior matter more.
   - The module must avoid being "efficient only at scale".

The current optimizations target both profiles. A few are primarily about
scale-out fairness, but many were added specifically because low-thread
benchmarks exposed avoidable overhead in the read path.

### Readability bar for optimizations

Optimization work must still be easy to audit. Prefer the simple implementation
when it is within roughly 90 percent of the performance of a more complex
version, especially outside the tight read/send/auth paths. Use the complex
version only when it removes a clear syscall, allocation, copy, event wakeup, or
protocol round trip, or when benchmark data shows the simpler version is a real
bottleneck.

When an optimization is worth keeping, make the fast path legible:

- isolate pointer-heavy or stateful logic in a small helper
- use parameter names that state ownership and units, such as `owned_base`,
  `bytes_remaining`, `range_start`, or `segment_count`
- document the invariant that prevents a future edit from breaking protocol
  framing, buffer lifetime, or nginx event-loop safety
- avoid macro-driven control flow for parsing, allocation, and error returns

The goal is not merely fast code. The goal is code that stays fast because the
next maintainer can safely understand and modify it.

---

## Quick Map

| Area | Optimization | Main Cost Removed | Most Helpful For |
|------|--------------|-------------------|------------------|
| Workers | Event-driven nginx stream/HTTP handling | One thread per connection | Many clients |
| File I/O | nginx thread-pool offload | Blocking event-loop disk I/O | Mixed and slow-storage workloads |
| Native read | File-backed buffers and sendfile path | Userspace file-data copy | Cleartext `root://` reads |
| Native read | Larger 16 MiB response chunks | Extra header/file chain links and send boundaries | Single and low-thread reads |
| Native read | Reusable one-chunk chains | Per-read chain/buf/file allocations | xrdcp default read shape |
| Native read | Cached open-file metadata | Per-read `fstat()` for read-only handles | All repeated reads |
| Native read | Stateful sequential read-ahead | One `posix_fadvise()` per read request | Single-stream sequential reads |
| Native TLS read | Reusable read AIO task | Thread-task allocation per encrypted read | `roots://` single-stream reads |
| Native TLS read | Stateful prefetch hints | Cold memory-backed TLS reads | `roots://` sequential reads |
| `readv` | Direct final-layout packing | Extra response copy pass | Vector reads |
| `readv` | Adjacent range batching with `preadv()` | One `pread()` per segment | Clustered vector reads |
| Send path | Posted write continuation | Extra poll wakeups after partial sends | Large responses |
| Send path | Pending-byte tracking | Repeated full chain scans | Large/chunked responses |
| `pgread` | Direct `kXR_status` response | Wrong chunked wrapper and extra framing | Protocol conformance and CRC reads |
| `pgwrite` | CRC verify and flatten once | Many tiny writes or unverified data | Modern XRootD uploads |
| WebDAV GET | Per-connection fd cache | Repeated path resolve/open/stat | Keepalive GET/HEAD |
| WebDAV GET | `open()+fstat()` miss path | Duplicate pathname metadata syscall | Cache misses |
| WebDAV PUT | `copy_file_range()` spooled-body path | Userspace copy loop | Large HTTPS uploads |
| Auth | Cached x509/JWKS state | Repeated expensive auth setup | Authenticated workloads |
| Auth | Cached GSI certificate PEM | PEM serialization per GSI login | Native GSI session startup |
| Auth | Cached GSI sigver HMAC state | OpenSSL provider lookup/context allocation per signed request | Native GSI `root://` sessions |
| Auth | Rate-limited DAVS x509 cache logs | Repeated INFO log writes on keepalive reuse | HTTPS/GSI low-thread transfers |

---

## Visual Model Of The Hot Paths

The most important optimizations remove work from the tight transfer loop. The
diagrams below are intentionally simplified, but they show where the big wins
come from.

```text
naive sequential native read
    kXR_read
       |
       v
    fstat(fd) every time
       |
       v
    posix_fadvise() every time
       |
       v
    pread() into module buffer
       |
       v
    copy/build response buffer
       |
       v
    write socket

optimized cleartext native read
    kXR_open
       |
       v
    cache fd + size + sequential hint state
       |
       v
    kXR_read loop
       |
       +--> reuse cached size
       +--> refresh readahead only when hint window moves
       +--> build small header buffer
       +--> attach file-backed buffer slice
       |
       v
    nginx send chain / possible sendfile path
```

```text
WebDAV keepalive download before fd cache
    GET /path
       |
       v
    resolve path -> stat path -> open path -> stream -> close
       |
       v
    next GET repeats the same path/open work

WebDAV keepalive download after fd cache
    first GET /path
       |
       v
    resolve path -> open -> fstat -> cache fd on HTTP connection
       |
       v
    next GET/HEAD on same connection
       |
       v
    cache hit -> fstat(fd) -> file-backed output buffer
```

```text
readv without range batching
    segment 1 -> pread()
    segment 2 -> pread()
    segment 3 -> pread()
    ...
    pack all segments for the wire

readv with adjacent-range batching
    normalize segments
       |
       v
    coalesce adjacent runs
       |
       v
    preadv() / fewer pread() calls
       |
       v
    pack directly into final wire layout
```

---

## Optimization detail pages

- [Native read path](native-read.md) — items 1–13: event model, thread pool, read chains, readv, send path
- [pgread and write](pgread-write.md) — items 14–17: pgread response shape, CRC encoding, pgwrite, write scratch
- [WebDAV](webdav-optimizations.md) — items 18–24: root pre-resolve, fd cache, GET/PUT paths, x509 auth cache
- [Auth and cross-cutting](auth-optimizations.md) — items 25–28: GSI HMAC reuse, token-local auth, handle reuse, atomic metrics

---

## Performance Expectations By Workload

### Single Cleartext `root://` Read

Most relevant optimizations:

- file-backed sendfile chains
- 16 MiB response chunks
- reusable one-chunk chains
- cached read-only file size
- stateful sequential read-ahead
- pending-byte tracking in send resumes

Expected result:

- fewer syscalls per GiB
- less allocation churn
- less page-cache hint overhead
- less CPU spent describing the same response shape repeatedly

### Low Parallelism, 2-8 Transfers

Most relevant optimizations:

- all single-stream read optimizations
- posted send continuation
- thread-pool offload for paths that cannot use sendfile
- access-log guards when logs are disabled

Expected result:

- better per-stream throughput
- fewer stalls from one connection's slow disk operation
- less worker time spent on bookkeeping

### High Parallelism

Most relevant optimizations:

- event-driven workers
- thread-pool offload
- bounded send spinning
- fd/path reuse
- local auth
- low-overhead metrics

Expected result:

- fewer runnable threads
- less scheduler churn
- better fairness across many clients
- stable memory behavior over long runs

### TLS Native Reads

Most relevant optimizations:

- thread-pool memory-backed read path
- reusable read scratch buffers
- reusable read AIO task
- stateful prefetch hints
- larger response chunks
- send continuation and pending-byte tracking
- cached GSI certificate PEM
- cached GSI request-signing HMAC state

Expected result:

- no sendfile win, because TLS changes the transport path
- still avoids avoidable allocation and send bookkeeping overhead

### WebDAV Downloads

Most relevant optimizations:

- canonical root cached at config time
- per-connection fd cache
- `open()+fstat()` miss path
- file-backed output buffers
- WebDAV read-ahead
- x509 verification caches
- rate-limited x509 cache-reuse logging

Expected result:

- fewer path syscalls on keepalive/range workloads
- lower auth overhead on repeated requests
- flatter memory use for large downloads

### WebDAV Uploads

Most relevant optimizations:

- spooled temp-file detection
- `copy_file_range()` fast path
- larger fallback copy buffer
- thread-pool offload for memory bodies

Expected result:

- fewer syscalls on large spooled uploads
- lower CPU spent copying request bodies in userspace
- less event-loop blocking during writes

---

## What Still Costs Real Time

Some costs are intrinsic or intentionally preserved:

- TLS encryption and decryption still cost CPU.
- HTTPS still carries HTTP parsing and response-filter overhead.
- `readv` still needs response packing because of the XRootD wire format.
- `pgread` must compute CRC32c because the protocol requires per-page
  integrity fields.
- x509 auth still costs CPU when a new certificate chain actually needs to be
  verified.
- Access logs still cost I/O when enabled.
- The module serializes responses per connection, matching the current state
  machine and avoiding multiple simultaneous writes on the same stream.

The goal is not to make every protocol mode equally cheap. The goal is to
remove avoidable syscalls, copies, allocations, and event-loop blocking so the
remaining cost is the cost of the feature being used.

---

## How To Verify The Optimizations

Useful tools:

```bash
strace -f -c -p <nginx-worker-pid>
perf stat -p <nginx-worker-pid>
perf top -p <nginx-worker-pid>
```

Things to look for:

- `posix_fadvise()` should not appear once per sequential read request.
- Large cleartext reads should show fewer send-side calls after larger chunks.
- Single-stream reads should show less allocator-related CPU.
- `readv` clustered ranges should use fewer file-read syscalls.
- WebDAV fd-cache hits should avoid repeated `open()` calls.
- Access-log writes should disappear from read-heavy traces when the access log
  is disabled.

Suggested benchmarks:

```bash
# One native stream: good for low-concurrency regressions.
xrdcp root://127.0.0.1:1094//path/to/large-file /dev/null

# Several native streams: good for fairness and worker behavior.
seq 1 8 | xargs -n1 -P8 -I{} xrdcp root://127.0.0.1:1094//path/to/large-file /dev/null

# WebDAV download.
curl -k -o /dev/null https://127.0.0.1:8443/path/to/large-file
```

For repeatable numbers, pin the same nginx config, file size, storage device,
TLS mode, access-log setting, and client request size.

---

## Where To Look In The Tree

Start here when tracing a performance change:

- `src/core/types/tunables.h` - size limits and hot-path constants
- `src/core/types/context.h` - per-connection reusable buffers and pending sends
- `src/core/types/file.h` - per-handle cached state
- `src/connection/*.c` - receive/send event flow and response draining
- `src/core/aio/*.c` - response builders and thread-pool completion paths
- `src/read/*.c` - native read/readv/pgread implementations
- `src/write/*.c` - native write/pgwrite implementations
- `src/webdav/*.c` - WebDAV GET/PUT/auth/path optimizations
- `src/token/*.c` - local token verification
- `src/metrics/*.c` - shared-memory counters

Useful tests:

- `tests/test_aio.py`
- `tests/test_readv.py`
- `tests/test_new_opcodes.py`
- `tests/test_webdav.py`
- `tests/test_webdav_auth_cache.py`
- `tests/test_webdav_spooled_put.py`
- `tests/test_gsi_tls.py`

The benchmark-oriented config and notes in [benchmarks.md](../05-operations/performance-benchmarks.md) are a
good companion to this page.
