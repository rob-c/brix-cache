# pgread and write optimizations

`kXR_pgread` and `kXR_pgwrite` have a different response shape and per-page CRC32c constraints. Here's what makes the implementation fast and where the sharp edges are.

[← Overview](optimizations.md)

## 14. `kXR_pgread` Uses The Correct Direct Response Shape

### What Changed

`kXR_pgread` is not the same as ordinary `kXR_read`. It must return:

- response code `kXR_status` (`4007`)
- raw encoded pages with per-page CRC32c

The module now builds a direct header/data chain for pgread instead of using
the normal chunked read response builder.

```text
  kXR_read  response                    kXR_pgread response
  ─────────────────                     ────────────────────
  ┌────────────────────┐                ┌────────────────────┐
  │ kXR_ok / oksofar   │  status=0      │ kXR_status (4007)   │  status=4007
  │ dlen = N           │                │ + status payload    │
  ├────────────────────┤                ├──────────┬─────────┤
  │ data … (N bytes)   │  raw bytes,    │ page 0    │ crc32c  │ ← 4 KiB page
  │                    │  no checksums  ├──────────┼─────────┤   + 4-byte CRC
  └────────────────────┘                │ page 1    │ crc32c  │
                                        ├──────────┼─────────┤
        wrong builder for pgread →      │ page 2    │ crc32c  │
        emits kXR_ok, drops CRCs        └──────────┴─────────┘
                                          client re-verifies every page
```

Using the `kXR_read` builder for `kXR_pgread` would emit the wrong status code
and discard the per-page CRCs the client expects — hence the dedicated path.

### Why It Helps

This is primarily a correctness and conformance fix, but it also removes the
wrong abstraction from the path. The ordinary chunked read builder emits
`kXR_ok`/`kXR_oksofar` frames. That is correct for `kXR_read`, but wrong for
`kXR_pgread`.

Expected benefits:

- correct wire status code
- client CRC validation works as intended
- less accidental framing work
- easier comparison with reference xrootd

Relevant code:

- `src/read/pgread.c`
- `src/aio/pgread.c`
- `src/response/crc32c.c`

---

## 15. `pgread` CRC Encoding Copies Once

### What Changed

The pgread encoder computes the CRC32c while copying page data into the encoded
output buffer.

### Why It Helps

The encoded pgread response format is:

```text
[page data][CRC32c][page data][CRC32c]...
```

The module must produce a new encoded buffer because the checksum bytes are
interleaved with page data. Combining checksum calculation with the data copy
reduces memory passes over the same bytes.

```text
  NAIVE: two passes over the data          OPTIMIZED: one fused pass
  ──────────────────────────────          ─────────────────────────
  pass 1   crc = crc32c(page) ──┐          for each page:
           (reads page)         │            copy page → out, and
  pass 2   memcpy(page → out) ──┘            crc32c() the same bytes
           (reads page again)                in the same loop
                                              └─ write crc after page
  page in memory read 2×                     page in memory read 1×

  ┌─page─┐         ┌─page─┐┌crc┐┌─page─┐┌crc┐
  │ src  │  ──▶    │ out  ││   ││ out  ││   │   crc computed while
  └──────┘         └──────┘└───┘└──────┘└───┘   the byte is in cache
```

Expected benefits:

- less memory bandwidth for pgread
- fewer passes over page data
- cleaner shared encoder for sync and AIO paths

Relevant code:

- `src/read/pgread.c`
- `src/response/crc32c.c`

---

## 16. `kXR_pgwrite` Verifies, Flattens, Then Writes Once

### What Changed

Modern XRootD clients prefer `kXR_pgwrite`, where each page arrives as:

```text
[CRC32c][page data][CRC32c][page data]...
```

The module verifies each per-page CRC field, strips the CRC fields into one
flat data buffer, and then writes that flattened payload through the normal
single-write path.

### Before

The tempting implementation is to process each page fragment independently.
That creates many tiny writes or pushes protocol framing into the storage path.

### After

Protocol validation and storage I/O are separated:

```text
  wire payload (CRC-interleaved)        reusable write scratch
  ┌crc┐┌──page 0──┐┌crc┐┌──page 1──┐
  │ a ││  data    ││ b ││  data    │ …
  └─┬─┘└────┬─────┘└─┬─┘└────┬─────┘
    │       │        │       │
    │ ① verify each per-page CRC
    │  crc32c(page 0)==a ?   crc32c(page 1)==b ?
    ▼                ▼               ▼
   any mismatch ──▶ reply kXR_ChkSumErr, write nothing
    │
    │ ② strip CRCs, flatten data only
    ▼
  ┌──page 0──┬──page 1──┬──page 2──┐   contiguous buffer
  │  data    │  data    │  data    │
  └──────────┴──────────┴──────────┘
    │
    │ ③ single contiguous write
    ▼
  pwrite(flattened, len, offset)      one syscall, kernel coalesces
```

Corruption is caught in step ① — before any byte reaches storage in step ③.

### Why It Helps

Storage wants contiguous byte ranges. Protocol framing is useful on the wire,
but it should not leak into many tiny disk writes.

Expected benefits:

- one storage write path for the whole pgwrite payload
- fewer write syscalls
- better kernel write coalescing
- corruption detected before data is committed
- conformance with clients that expect `kXR_ChkSumErr`

Relevant code:

- `src/write/pgwrite.c`
- `src/write/chkpoint_xeq.c`
- `src/write/write.h`
- `src/response/crc32c.c`

---

## 17. Reusable Write Scratch For Paged Writes

### What Changed

The connection context keeps reusable write scratch space for pgwrite decode
and flattening work.

### Why It Helps

Large uploads can otherwise allocate repeatedly from the connection pool or
heap. Reusing scratch memory keeps the working set stable over a long upload
session.

Expected benefits:

- fewer allocations
- less allocator churn
- lower memory growth during long uploads

Relevant code:

- `src/types/context.h`
- `src/aio/buffers.c`
- `src/write/pgwrite.c`
