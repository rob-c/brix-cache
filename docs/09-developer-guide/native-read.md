# Native XRootD read path optimizations

How the read path gets from `kXR_read` to bytes on the wire without blocking nginx workers: sendfile, AIO thread pools, readahead, and the buffer reuse tricks that matter at scale.

[← Overview](optimizations.md)

## 1. Event-Driven Workers

### What Changed

The module is built around nginx stream and HTTP handlers instead of a
thread-per-connection server model. Connections live in nginx workers and
become active only when socket or posted events are ready.

### Why It Helps

In a classic thread-per-connection design, thousands of mostly idle transfers
still create thousands of kernel threads or user-level blocking contexts. That
causes scheduler churn, stack memory pressure, and wake/sleep overhead.

With nginx:

- idle sockets are cheap
- a worker only runs code for ready connections
- one worker can multiplex many transfers
- a blocked socket does not consume a dedicated thread

This is the architectural reason the module tends to look good at 32, 64, or
128 parallel transfers. The scheduler has less housekeeping to do, so more CPU
time is spent moving bytes.

### Trade-Off

The event-loop model only wins if handlers do not block. Any synchronous slow
disk call in the worker can still stall unrelated connections. That is why the
thread-pool I/O paths below matter.

Relevant code:

- `src/connection/*.c`
- `src/handshake/*.c`
- `src/webdav/*.c`

---

## 2. Thread-Pool Offload For Blocking File I/O

### What Changed

The stream module and WebDAV module can offload blocking disk operations to
nginx thread pools.

Native XRootD paths:

- async `pread()` for memory-backed `kXR_read`
- async `preadv()`/`pread()` work for `kXR_readv`
- async `pwrite()` for `kXR_write`
- async flattened writes for `kXR_pgwrite`

WebDAV paths:

- async `PUT` writes when the body is already resident in memory

Relevant directives:

- `xrootd_thread_pool`
- `xrootd_webdav_thread_pool`

### Why It Helps

nginx workers should mostly do request parsing, response construction, and
nonblocking socket I/O. If a worker blocks on disk, every unrelated connection
assigned to that worker is delayed.

Moving large or potentially slow storage operations to a thread pool:

- keeps the event loop responsive
- prevents one slow disk operation from pausing other clients
- improves fairness under mixed read/write workloads
- gives uploads and TLS memory-backed reads somewhere safe to block

### Trade-Off

Thread-pool dispatch has overhead. It is not automatically faster for every
small operation. It is most useful when disk latency or write size is large
enough that avoiding event-loop blocking is worth the handoff.

Relevant code:

- `src/aio/resume.c`
- `src/aio/reads.c`
- `src/aio/readv.c`
- `src/aio/write.c`
- `src/write/*.c`
- `src/webdav/put.c`

---

## 3. Native `kXR_read` Uses File-Backed Chains

### What Changed

For regular files on non-TLS stream connections, `kXR_read` avoids reading file
data into a large userspace response buffer. Instead, the module builds a chain
with:

- a small in-memory XRootD response header
- a file-backed nginx buffer pointing at the requested byte range

nginx can then use its platform sendfile chain implementation where available.

### Before

A naive implementation would do:

```text
pread(fd, userspace_buffer, len, offset)
build_response_header()
copy/append data into response buffer
send(response_buffer)
```

That pulls file bytes from the page cache into userspace only to send them back
to the kernel.

### After

The cleartext regular-file path does:

```text
build_response_header()
attach file-backed ngx_buf_t with file_pos/file_last
send_chain(header + file slice)
```

### Why It Helps

This removes a whole userspace copy of the file data on the common native
cleartext read path. It also keeps memory usage flatter because large reads are
described as file ranges instead of large allocated buffers.

```text
  BEFORE: data crosses into userspace and back

     page cache            userspace               socket
   ┌────────────┐  pread  ┌────────────┐  send   ┌────────────┐
   │ file bytes │ ──────▶ │ resp buf   │ ──────▶ │  NIC TX    │
   └────────────┘  copy 1 └────────────┘ copy 2  └────────────┘
                     (2 copies, large allocation held for the read)

  AFTER (cleartext): kernel sends the file range directly

     page cache                              socket
   ┌────────────┐         sendfile         ┌────────────┐
   │ file bytes │ ───────────────────────▶ │  NIC TX    │
   └────────────┘   header in memory,      └────────────┘
                    body = file-backed ngx_buf_t (file_pos..file_last)
                            0 userspace copies of file data

  ── fork by transport ──────────────────────────────────────────
     root://  (cleartext) ──▶ file-backed chain ──▶ sendfile
     roots:// (TLS)       ──▶ memory-backed read ──▶ OpenSSL encrypt
                              (no kernel sendfile for SSL → see caveat)
```

Expected benefits:

- lower CPU per GiB transferred
- less memory bandwidth pressure
- fewer large temporary allocations
- better single-stream throughput when the network path is fast enough

### TLS Caveat

The stream TLS path intentionally falls back to memory-backed reads. Without a
kernel TLS sendfile path available through nginx's SSL machinery, handing a file
buffer to the SSL send path is not safe or portable. The code prefers correct
encrypted output over pretending sendfile still applies.

Relevant code:

- `src/read/read.c`
- `src/aio/buffers.c`

---

## 4. Larger Native Read Response Chunks

### What Changed

Large `kXR_read` responses are still split into XRootD response frames, but the
per-frame data chunk was raised to 16 MiB for outbound response construction.
The overall contiguous read cap remains separate at 64 MiB.

Current sizing:

```c
#define XROOTD_READ_MAX          (4 * 1024 * 1024)
#define XROOTD_READ_CHUNK_MAX    (16 * 1024 * 1024)
#define XROOTD_READ_REQUEST_MAX  (64 * 1024 * 1024)
```

`XROOTD_READ_MAX` remains the per-vector element cap used for `readv`
normalization. `XROOTD_READ_CHUNK_MAX` controls outgoing response chunking.

### Before

A 64 MiB read response could be split into:

```text
16 chunks x (8-byte response header + file buffer)
```

That meant more chain links, more response headers, and more send-chain
boundaries.

### After

The same 64 MiB response is split into:

```text
4 chunks x (8-byte response header + file buffer)
```

### Why It Helps

For sendfile-style output, every header/file pair can turn into additional
`writev()`/`sendfile()` boundaries inside nginx's send chain. Fewer chunks do
not change the number of bytes sent, but they reduce the number of objects and
state transitions needed to describe those bytes.

This is especially visible in low-concurrency tests because there are fewer
other transfers to hide per-request overhead. A single `xrdcp` stream spends a
larger fraction of total time in request-response cadence and send bookkeeping.

Expected benefits:

- fewer response header buffers
- fewer file-buffer chain links
- fewer send-chain boundaries
- less chain traversal and bookkeeping
- better large sequential read throughput

Relevant code:

- `src/types/tunables.h`
- `src/aio/buffers.c`
- `src/read/read.c`
- `src/read/pgread.c`

---

## 5. Reusable One-Chunk Read Chains

### What Changed

Most client reads, including xrdcp's default read shape, fit in one outbound
response chunk. The module now has a fast path for that case.

Instead of allocating fresh nginx objects for every one-chunk read, the
connection context owns reusable objects:

- one header chain link
- one body chain link
- one header buffer
- one body buffer
- one `ngx_file_t` for file-backed sendfile responses

These are rewritten for each read response.

### Before

Every read response allocated chain links and buffers from the connection pool.
nginx pools are cheap, but pool allocations are not free, and they are not
normally returned one-by-one. A long transfer could therefore grow the
connection pool just by repeatedly describing the same two-link response shape.

### After

For `data_total <= XROOTD_READ_CHUNK_MAX`, `xrootd_build_chunked_chain()` and
`xrootd_build_sendfile_chain()` use the reusable context-owned chain objects.
Multi-chunk responses still allocate chain links because they need a variable
number of headers and buffers.

### Why It Helps

This optimization targets low-concurrency throughput. When only one or a few
streams are active, allocator overhead and cache locality become visible.

Expected benefits:

- less pool growth during sustained reads
- fewer per-request allocations
- less pointer chasing in the allocator
- better cache locality for the common read response shape

### Correctness Constraints

The reusable chain is safe because the stream state machine has only one
response in flight per connection. If a response stalls, the connection state
stays in `XRD_ST_SENDING` until the chain drains. The next request does not
reuse the chain objects until the previous response is complete.

Relevant code:

- `src/types/context.h`
- `src/aio/buffers.c`
- `src/connection/write_helpers.c`

---

## 6. Cached File Metadata For Read Handles

### What Changed

At open time, the module records whether the handle points to a regular file
and caches the file size for read-only handles.

For read-only handles:

- `kXR_read` can use `cached_size`
- no per-read `fstat()` is needed to determine EOF and clamp the response

For writable handles:

- the module still refreshes size with `fstat()`
- this preserves read-after-write behavior on the same handle

### Why It Helps

Sequential clients often issue many read requests on the same handle. Calling
`fstat()` on every chunk repeats metadata work that is usually stable for a
read-only transfer.

Expected benefits:

- one fewer syscall per read request on read-only handles
- less VFS metadata work
- lower latency in small and medium read loops
- better single-stream behavior where every syscall is visible

Relevant code:

- `src/types/file.h`
- `src/read/open.c`
- `src/read/read.c`
- `src/connection/fd_table.c`

---

## 7. Stateful Sequential Readahead

### What Changed

The module uses `posix_fadvise(..., POSIX_FADV_WILLNEED)` for large reads, but
plain sequential `kXR_read` no longer sends a hint on every request. Instead,
each open file tracks:

- the end offset of the previous read
- the farthest offset already covered by a read-ahead hint

The read path now maintains a 32 MiB hint window and refreshes it only when the
transfer is within 8 MiB of the current hinted range.

### Before

For a sequential transfer using 4 MiB requests, the module could issue roughly:

```text
1 posix_fadvise() per 4 MiB read request
```

That is a syscall per chunk, even though the kernel can use a larger hint.

### After

For the same transfer, the module issues a larger hint and reuses that window
for several requests:

```text
hint [current offset, current offset + 32 MiB]
skip more hints until the stream nears the end of that window
refresh the next window
```

### Why It Helps

`posix_fadvise()` is only a hint, but the call still crosses into the kernel.
On low-thread transfers, extra syscalls in the tight read loop matter. The
stateful window keeps the useful read-ahead behavior while avoiding a hint per
request.

Expected benefits:

- fewer `posix_fadvise()` syscalls
- page cache is still warmed ahead of sendfile
- less per-request overhead on single sequential reads
- random or nonsequential reads still get local hints without poisoning the
  sequential state

### Trade-Off

The window size is deliberately conservative. A very large hint could evict
useful cache under mixed workloads; a tiny hint becomes syscall noise. The
current 32 MiB window with an 8 MiB low-water mark is meant to be a practical
middle ground.

Relevant code:

- `src/read/prefetch.h`
- `src/read/prefetch.c`
- `src/read/read.c`
- `src/types/file.h`

### Native TLS Extension

Encrypted native reads cannot use the cleartext sendfile path. They read file
data into memory and then let nginx/OpenSSL encrypt that buffer. The
memory-backed `kXR_read` path now reuses one nginx thread-pool task per
connection instead of allocating a fresh task for every read. It also uses this
same stateful prefetch helper, so `roots://` transfers can warm the next window
before the worker thread reaches `pread()`.

Expected benefits:

- less connection-pool growth during long `roots://` transfers
- fewer per-read allocations before thread-pool dispatch
- better single-stream behavior when file data is not already hot in cache

---

## 8. `kXR_readv` Packs Directly Into The Final Wire Layout

### What Changed

`kXR_readv` responses are awkward because each segment needs a descriptor and
then that segment's data. The module now builds the response workspace in the
final wire layout:

```text
[segment descriptor][segment bytes][segment descriptor][segment bytes]...
```

Each `pread()` or `preadv()` target points directly into the final output slice.

```text
  ONE workspace, laid out in final wire order:

  ┌──────┬───────────────┬──────┬───────────────┬──────┬─────────┐
  │ desc │   data slice  │ desc │   data slice  │ desc │  data   │
  │  0   │   (seg 0)     │  1   │   (seg 1)     │  2   │ (seg 2) │
  └──────┴───────▲───────┴──────┴───────▲───────┴──────┴────▲────┘
                 │                      │                   │
            pread(fd, ─┘           pread(fd, ─┘        pread(fd, ─┘
            into slice)            into slice)         into slice)
                 ▲ reads land directly in their final position —
                 │ no temp buffers, no second packing pass
   adjacent segments (§9) collapse into a single preadv() over these slices
```

### Before

A simpler implementation would read every segment into temporary buffers, then
make another pass to pack descriptors and data into the response.

### After

The response buffer is laid out once, and read calls fill the data portions
directly.

### Why It Helps

This removes a copy pass and reduces temporary allocation. It also makes the
response chain simpler because the already-packed buffer can be wrapped by the
same chunked response builder used by regular reads.

Expected benefits:

- fewer userspace copies
- less allocation churn
- better cache locality for vector responses
- less CPU per returned byte for multi-segment reads

Relevant code:

- `src/read/readv.c`
- `src/aio/readv.c`
- `src/aio/buffers.c`

---

## 9. `kXR_readv` Batches Adjacent Ranges With `preadv()`

### What Changed

When `readv` segments are adjacent, same-file, and contiguous in the output
workspace, the module batches them with `preadv()`.

### Before

A client sending 64 small clustered ranges could force roughly:

```text
64 separate pread() calls
```

### After

Adjacent segments can be grouped into one `preadv()` call, up to a bounded
number of iovecs.

### Why It Helps

`readv` clients often request clustered ranges. This happens in columnar data
access patterns and metadata-heavy reads where the client knows it needs
several nearby byte ranges.

Batching reduces filesystem read syscalls while preserving the exact XRootD
wire layout.

Expected benefits:

- fewer `pread()` syscalls
- less syscall overhead for clustered vector reads
- better storage scheduler visibility into adjacent reads
- less worker or thread-pool task overhead

Relevant code:

- `src/read/readv.c`
- `src/aio/readv.c`
- `src/aio/aio.h`

---

## 10. Coalesced `readv` Readahead

### What Changed

`readv` readahead no longer blindly hints every segment. The module walks the
segment list and coalesces nearby ranges when:

- the fd is the same
- the next range is close enough to the previous range
- the coalesced range stays under a configured maximum

### Why It Helps

Without coalescing, a vector read with many small ranges can spend too much
time issuing hint syscalls. Coalescing gives the kernel a small number of
larger ranges instead.

Expected benefits:

- fewer `posix_fadvise()` calls
- less kernel hint overhead
- better page-cache preparation for clustered vector reads

Relevant code:

- `src/read/prefetch.c`
- `src/read/readv.c`

---

## 11. Send Path Posted Continuation

### What Changed

When `send_chain()` makes partial progress, the module does not always wait for
another full poll cycle. It spins a bounded number of times, then posts the
write event through nginx's posted-event queue if more data remains.

The bound is:

```c
#define XROOTD_SEND_CHAIN_SPIN_MAX  16
```

```text
                 ┌──────────────────────┐
        ┌───────▶│  send_chain(chain)    │
        │        └───────────┬──────────┘
        │                    │
        │         ┌──────────┴───────────┐
        │      drained?                stalled (partial)
        │         │                      │
        │         ▼            spins < 16 │  ┌── spins == 16 ──┐
        │   response done      & socket   │  │                 │
        │   reuse chain        writable   ▼  ▼                 ▼
        └──── (next req)      └─ retry ─┘  post write event   wait for
                               immediately  (yield worker)    epoll-out
                                                  │              │
                                                  └──────┬───────┘
                                                         ▼
                                                  resume later, no
                                                  monopolizing the worker
```

### Why It Helps

Large responses often drain in pieces even when the socket remains writable.
Immediately making bounded additional progress can improve throughput and
reduce wakeup latency. The bound prevents one large transfer from monopolizing
the worker.

Expected benefits:

- fewer unnecessary epoll waits
- better large-response drain behavior
- less wake/sleep churn on busy workers
- fairer behavior than an unbounded send loop

Relevant code:

- `src/connection/write_helpers.c`
- `src/connection/event_sched.c`

---

## 12. Send Path Pending-Byte Tracking

### What Changed

The send resume path tracks how many bytes remain in a stalled chain. When
possible, it uses nginx's connection byte counter to infer progress. It falls
back to walking the chain only when necessary.

### Before

After each partial `send_chain()`, the code repeatedly walked the remaining
chain to calculate pending bytes for metrics and progress detection.

### After

The connection context stores `wchain_pending`, and the send helper updates it
as data drains.

### Why It Helps

Chain walks are CPU work, not syscalls, but they happen on the same hot path as
large read responses. They also get more expensive when a response has many
chain links.

This change became more important while tuning chunk sizes and sendfile
responses because it keeps send-side bookkeeping from becoming the next
visible bottleneck.

Expected benefits:

- less CPU per partial send
- fewer full-chain scans
- cheaper metrics accounting
- smoother progress on large responses that stall and resume

Relevant code:

- `src/types/context.h`
- `src/connection/write_helpers.c`
- `src/connection/chain_helpers.c`

---

## 13. Access Logging Is Guarded On Hot Read Paths

### What Changed

Read paths check whether the access log fd is valid before formatting read
detail strings and writing log records.

### Why It Helps

Access logging is useful for operations, but it is expensive in a bulk transfer
benchmark:

- formatting strings costs CPU
- `write()` to the log fd is another syscall
- log I/O can add contention or storage noise

When the access log is disabled, the hot read path avoids that work entirely.

Expected benefits:

- less per-request CPU when access logs are off
- fewer log-write syscalls
- cleaner performance measurements

Relevant code:

- `src/read/read.c`
- `src/read/readv.c`
- `src/read/pgread.c`
- `src/path/access_log.c`
