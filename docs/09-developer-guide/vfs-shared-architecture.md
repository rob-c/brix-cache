# The shared VFS: one storage core under `src/` and `client/`

**Status:** Reference (reflects the tree as of 2026-06-28)
**Scope:** how file/object byte I/O is layered and *shared* between the nginx
server (`src/`) and the native userland clients (`client/`), after the
storage-driver unification (phases 54–59).
**Companion docs:** [`src/fs/README.md`](../../src/fs/README.md) ·
[`src/fs/backend/README.md`](../../src/fs/backend/README.md) ·
[`src/fs/core/README.md`](../../src/fs/core/README.md) ·
design spec [`docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md`](../superpowers/specs/2026-06-27-unified-vfs-layering-design.md)

---

## 0. TL;DR

There used to be **two** parallel VFS stacks — one nginx-coupled
(`src/fs/xrootd_vfs_*`) and one in the clients (`client/lib/xrdc_vfs_*`) — each
with its own copy of the read/write loop and its own POSIX / block / S3 backend.
They have been collapsed onto **one set of storage drivers and one set of I/O
verbs that physically compile into both binaries**:

```
                         ┌─────────────────────────────────────────┐
                         │   src/fs/backend/  +  src/fs/core/        │
                         │   (the SHARED, ngx-free storage core)     │
                         └─────────────────────────────────────────┘
                            ▲                                 ▲
        compiled into       │                                 │   compiled into
        the nginx module    │                                 │   libxrdproto.a
        via ./config        │                                 │   (-DXRDPROTO_NO_NGX)
                            │                                 │
   ┌────────────────────────┴───────────┐     ┌───────────────┴───────────────────┐
   │  nginx server data plane (src/fs/)  │     │  native clients (client/lib/)      │
   │  module ─▶ vfs_server ─▶ vfs ─▶ be  │     │  client ───────────▶ vfs ─▶ be     │
   └─────────────────────────────────────┘     └────────────────────────────────────┘
```

The **same `.c` files** (`sd_posix.c`, `sd_block.c`, `sd_s3.c`, `vfs_core.c`)
build twice: once into the nginx `.so`, once into the client's `libxrdproto.a`.
A guard (`check-ngx-free.sh`) keeps the client side free of any `ngx_` symbol.

The four layers, top to bottom:

| Layer | Server home | Client home | Shared? |
|---|---|---|---|
| **module / app** | proto handlers (`src/protocols/root/read/`, `src/protocols/webdav/`, `src/protocols/s3/`) | `xrdcp`, `xrootdfs`, `copy.c` | no (protocol/UX) |
| **vfs_server** (confined open + nginx lifecycle) | `src/fs/vfs/vfs_open.c`, `vfs_io_core.c`, … | *(n/a — the client adapter is its peer)* | no (policy) |
| **vfs** (storage-neutral I/O verbs) | `src/fs/core/vfs_core.c` | `client/lib/vfs_posix.c`, `vfs_block.c`, `vfs_s3*.c` | **YES** (`vfs_core.c`) |
| **backend** (Storage Driver: raw syscalls / S3 protocol) | `src/fs/backend/sd_*.c` | same files via `libxrdproto` | **YES** |

---

## 1. The mental model: *open is policy, the verbs are mechanism*

The whole unification rests on one observation about the old code:

- **`open`** is where the two worlds genuinely differ. The server must resolve
  every path **under an export root** with `openat2(RESOLVE_BENEATH)` so a client
  can never escape its confinement. The client opens **arbitrary user paths /
  URLs** with no export root at all. These cannot and must not share code.
- **Everything *after* open** — `pread` / `pwrite` / `fstat` / `ftruncate` /
  `fsync`, the EINTR retry loop, the short-I/O accounting — touches only an
  already-open handle. It is byte-pushing mechanism with **no policy in it**.

So the seam is drawn exactly there:

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  OPEN  (policy — NOT shared)                                       │
   │                                                                    │
   │   server:  xrootd_open_beneath(rootfd, path, …)   RESOLVE_BENEATH  │
   │   client:  xrootd_sd_posix_open_unconfined(path, …)   plain open() │
   └──────────────────────────────────────────────────────────────────┘
                                   │ produces a bound object (fd or driver state)
                                   ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  VERBS  (mechanism — SHARED, src/fs/core/vfs_core.c)              │
   │                                                                    │
   │   xvfs_pread_full / xvfs_pread_once / xvfs_pwrite_full            │
   │   xvfs_fsync / xvfs_ftruncate / xvfs_fstat                         │
   │   (own the EINTR + short-I/O loop; call obj->driver->pread/…)      │
   └──────────────────────────────────────────────────────────────────┘
                                   │ one raw syscall per call
                                   ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  BACKEND  (Storage Driver — SHARED, src/fs/backend/sd_*.c)        │
   │   pread()/pwrite()/preadv()/fsync()/fstat()  →  the kernel / S3   │
   └──────────────────────────────────────────────────────────────────┘
```

> **Invariant:** confinement lives *only* in the server's open. The shared verbs
> never re-derive or re-check it — by the time they run, the fd is already proven
> safe (server) or intentionally unconfined (client). Never route a client's
> unconfined open through the server's confined open, or vice versa.

---

## 2. The Storage Driver (SD) — the bottom layer

**File:** `src/fs/backend/sd.h` (interface) · `sd_posix.c`, `sd_block.c`,
`sd_s3.c` (drivers) · `sd_registry.c` (name → instance).

A driver is a `static const xrootd_sd_driver_t` — a capability bitmap plus a flat
table of function pointers. The flatness matters: the **raw byte ops are
worker-safe** (no nginx pool, no log, no metrics, no locks), so they can run on an
AIO thread pool.

### 2.1 The object model

```
   xrootd_sd_driver_t          xrootd_sd_instance_t        xrootd_sd_obj_t
   ┌─────────────────┐         ┌──────────────────┐        ┌────────────────┐
   │ name  "posix"   │◀────────│ driver           │◀───────│ driver         │
   │ caps  0x…       │         │ log / pool       │        │ inst           │
   │ pread  ───────▶ │         │ state (rootfd,   │        │ fd  (or -1)    │
   │ pwrite ───────▶ │         │        root_canon)│       │ snap (stat)    │
   │ fstat  ───────▶ │         └──────────────────┘        │ state (S3 key, │
   │ open/stat/…     │          per-export, server-only      │   upload id…) │
   └─────────────────┘          (NULL on the client)         └────────────────┘
```

- **`instance`** = one bound export (server). It holds the persistent
  `RESOLVE_BENEATH` rootfd and `root_canon`. The client never builds an
  instance — it opens unconfined and wraps the bare fd (see §2.4).
- **`obj`** = one open file/object. For CAP_FD backends `obj->fd` is a real
  kernel fd; for S3 it is `-1` and `obj->state` carries the object key + upload
  state.

### 2.2 Capability bitmap (`xrootd_sd_cap_t`)

The VFS shapes its behaviour from caps rather than from the driver name. Absences
are honest — the VFS degrades or rejects, it never emulates a missing primitive.

| Cap | Meaning | posix | block | s3 |
|---|---|:--:|:--:|:--:|
| `CAP_FD` | exposes a real kernel fd | ✔ | ✔ | — |
| `CAP_SENDFILE` | fd is sendfile/`b->in_file` source (implies FD) | ✔ | — | — |
| `CAP_RANDOM_WRITE` | pwrite at arbitrary offset | ✔ | ✔ | — |
| `CAP_RANGE_READ` | pread at arbitrary offset | ✔ | ✔ | ✔ (HTTP Range) |
| `CAP_TRUNCATE` | ftruncate | ✔ | — | — |
| `CAP_SERVER_COPY` | native copy (`copy_file_range`/COPY) | ✔¹ | — | — |
| `CAP_XATTR` | `user.*` xattr / object metadata | ✔¹ | — | — |
| `CAP_HARD_RENAME` | atomic rename | ✔¹ | — | — |
| `CAP_DIRS` | real directories (else key-prefix) | ✔¹ | — | — |
| `CAP_APPEND` | `O_APPEND` semantics | ✔ | — | — |
| `CAP_IOURING` | fd is io_uring-submittable | ✔ | — | — |
| `CAP_FSCS` | filesystem page checksums (CSI) | (server) | — | — |

¹ *Server-only caps:* the POSIX driver drops `SERVER_COPY`/`XATTR`/`HARD_RENAME`/
`DIRS` in the ngx-free client build (those slots are `#ifndef XRDPROTO_NO_NGX`),
because they need the confined-namespace helpers that only exist in the module.
See the `caps` initializer at the bottom of `sd_posix.c`.

### 2.3 The vtable, grouped by who calls it

```
   ┌── worker-safe raw byte I/O (SHARED — run on AIO threads, ngx-free) ──┐
   │  pread  pwrite  preadv  preadv2  copy_range  read_sendfile_fd        │
   │  ftruncate  fsync  fstat                                             │
   └─────────────────────────────────────────────────────────────────────┘
   ┌── instance lifecycle (server-only, #ifndef XRDPROTO_NO_NGX) ─────────┐
   │  init  cleanup  open  close                                          │
   └─────────────────────────────────────────────────────────────────────┘
   ┌── namespace on logical paths (server-only) ─────────────────────────┐
   │  stat  unlink  mkdir  rename  server_copy                           │
   │  opendir  readdir  closedir                                          │
   │  getxattr  listxattr  setxattr  removexattr                         │
   │  staged_open  staged_write  staged_commit  staged_abort             │
   └─────────────────────────────────────────────────────────────────────┘
```

The dividing line is exactly the `#ifndef XRDPROTO_NO_NGX` blocks in
`sd_posix.c`: the raw byte ops are compiled in *both* builds; the
namespace/instance ops are compiled *only* in the module.

### 2.4 `xrootd_sd_posix_wrap` — the client/server bridge for raw fds

Both sides need to push bytes through the driver without allocating an instance.
The hot path uses a **stack** object:

```c
xrootd_sd_obj_t obj;
xrootd_sd_posix_wrap(&obj, fd);          /* zero-init; obj.driver=posix; obj.fd=fd */
xvfs_pwrite_full(&obj, buf, len, off, &written, &short_io);
```

This is how the *server* routes its AIO write/sync/truncate through the seam
(`src/fs/vfs/vfs_io_core.c: xrootd_vfs_io_write_counted`, `_execute_sync`,
`_execute_truncate`) **and** how the *client's* plain (non-io_uring) POSIX/block
paths run (`client/lib/vfs_posix.c: posix_pread/pwrite/fstat/…`). One wrap helper,
one driver, two callers.

### 2.5 The unconfined open helpers (client side)

The client can't use `sd_posix_open` (it needs a rootfd). Instead the driver
exposes single-sourced **unconfined** opens that share the SD-flag → `O_*`
mapping (`sd_posix_flags`) with the confined path:

- `xrootd_sd_posix_open_unconfined(path, sd_flags, mode)` → `open(2)`.
- `xrootd_sd_block_open_unconfined(path, sd_flags, mode)` → same, minus
  `O_CREATE`/`O_TRUNC` (a block device is opened *in place*, never recreated or
  zeroed).

So the flag vocabulary (`XROOTD_SD_O_READ|WRITE|CREATE|EXCL|TRUNC|APPEND|DIR|
NOFOLLOW`) and its `O_*` translation exist exactly once, used by both the
server's `openat2` and the client's `open`.

---

## 3. The shared `vfs` verb core

**File:** `src/fs/core/vfs_core.{c,h}` — ngx-free, in `libxrdproto` *and* the
module. This is the only "middle" code that is byte-for-byte shared.

| Verb | Returns | Semantics |
|---|---|---|
| `xvfs_pread_full(obj,buf,len,off,*nread)` | 0 / −1 | loop (EINTR) until `len` or EOF; short read at EOF = success |
| `xvfs_pread_once(obj,buf,len,off)` | bytes / −1 | single EINTR-retried read (caller owns its own loop) |
| `xvfs_pwrite_full(obj,buf,len,off,*written,*short_io)` | 0 / −1 | loop until all written; reports partial + short-I/O fact |
| `xvfs_fsync(obj)` | 0 / −1 | one backend `fsync` |
| `xvfs_ftruncate(obj,len)` | 0 / −1 | one backend `ftruncate` |
| `xvfs_fstat(obj,*out)` | 0 / −1 | one backend `fstat` → `xrootd_sd_stat_t` |

Convention: `0/-1` with `errno` set — value-compatible with the server's
`NGX_OK`/`NGX_ERROR`. **The verbs own the loop policy; the backend owns the
syscall.** Every op dispatches through `obj->driver->…`, so a non-POSIX backend
works unchanged.

**Who calls it:**

- **Server:** `src/fs/vfs/vfs_read.c` (the `xrootd_vfs_pread_full` wrapper) and
  `src/fs/vfs/vfs_io_core.c` (write-counted / sync / truncate executors) — see the
  `xrootd_sd_posix_wrap` calls in §2.4.
- **Client:** `client/lib/vfs_posix.c` and `vfs_block.c`, plain paths.

> io_uring stays a **client-only fast-path override**: when a ring is attached
> (`vfs_posix.c: posix_pread/pwrite`), the client uses it; otherwise it falls
> through to the shared `xvfs_*` verbs. The server never takes the ring path here.

---

## 4. The client VFS shell

**Files:** `client/lib/vfs.h` (contract) · `vfs.c` (façade + registry) ·
`vfs_posix.c` · `vfs_block.c` · `vfs_s3*.c`.

The client keeps its *own* handle abstraction (`xrdc_vfs_file` + `xrdc_vfs_ops`)
because it carries client-only concerns the server has no use for: URL/scheme
routing, credential stores, io_uring, and a `commit`/`abort` lifecycle (the
server commits differently — via its staged-file machinery). But underneath, the
**byte I/O and the open both delegate to the shared core**.

### 4.1 Façade + registry (`vfs.c`)

```
   xrdc_vfs_open(url,…)
        │  pthread_once → register posix, block, s3 backends (weak accessors)
        │  vfs_url_to_scheme(url)  →  "file" | "block" | "s3" | "s3s" | NULL
        │  vfs_find_backend(scheme)
        ▼
   be->open(be, path, flags, opts, &handle, st)   ── per-backend
        ▼
   handle->ops->{pread,pwrite,fstat,truncate,sync,commit,abort,close}
```

URL grammar (`vfs_url_to_scheme`): `s3://`/`s3s://` → s3 (backend parses the full
URL); `block://` or `/dev/…` → block; `file://` or a bare path → file; a non-S3
web URL (`http`/`dav`) → `NULL` (no VFS backend, caller errors out).

### 4.2 Per-handle capability flags (distinct from SD caps)

The client exposes a *transfer-oriented* cap set (`xrdc_vfs_caps`) that the copy
engine reads to choose its strategy:

| Client cap | posix | block | s3 | drives |
|---|:--:|:--:|:--:|---|
| `RANDOM_WRITE` | ✔ | ✔ | — | random-write vs append/stream pump |
| `TRUNCATE` | ✔ | — | — | whether truncate is offered |
| `ATOMIC_TEMP` | ✔ | — | — | commit = temp+rename vs native commit |
| `FADVISE` | ✔ | ✔ | — | readahead hints |

`commit()` is the keystone that differs per backend:

```
   posix.commit  =  ring-flush → fsync(tmp) → rename(tmp → final)     (atomic temp)
   block.commit  =  fsync                                             (in place)
   s3.commit     =  single PUT  OR  flush-last-part + CompleteMPU     (native)
```

### 4.3 POSIX backend (`vfs_posix.c`)

- **open READ:** `xrootd_sd_posix_open_unconfined(path, O_READ)`.
- **open WRITE:** FORCE-check the final path, then open a sibling temp
  `"<dst>.xrdvfs-tmp.<pid>.<seq>"` with `O_WRITE|O_CREATE|O_TRUNC|O_EXCL|
  O_NOFOLLOW` (the atomic-rename + symlink-safety guard).
- **I/O:** ring path if attached, else the shared `xvfs_*` verbs.
- **commit:** fsync + `rename(tmp,final)`; **abort:** `unlink(tmp)`.

### 4.4 Block backend (`vfs_block.c`)

- **open:** `xrootd_sd_block_open_unconfined` (no create/truncate).
- **fstat:** dispatches through `xrootd_sd_block_driver.fstat` → `BLKGETSIZE64`
  for the true device capacity (a block device's `st_size` is 0).
- caps: `RANDOM_WRITE | FADVISE` only — **no** `TRUNCATE`, **no** `ATOMIC_TEMP`
  (you can't rename onto a raw device).

---

## 5. The S3 driver and the transport-vtable trick

This is the most intricate part of the unification, because S3 was *welded* to
the client's hand-rolled HTTP/1.1 stack (`xrdc_http_*`) and `src/` cannot depend
on `client/lib`, nor does the server own an HTTP client.

### 5.1 The problem and the seam

```
   BEFORE (client-only):                AFTER (shared):

   vfs_s3*.c  ── SigV4, HEAD,           sd_s3.c (src/fs/backend/)  ── SigV4, HEAD,
              ── Range GET, PUT,            Range GET, single-PUT, MPU, XML
              ── MPU, XML  ──┐                       │ calls
              ── xrdc_http ◀─┘             xrootd_s3_transport_t  (vtable, sd_s3_transport.h)
                                                     ▲ implemented by
                                          ┌──────────┴───────────┐
                                          │ client:              │ (future) server:
                                          │ xrdc_s3_http_transport│  its own HTTP client
                                          │ (vfs_s3_transport.c)  │
                                          └───────────────────────┘
```

The **S3 protocol logic** (request building, SigV4 signing via the shared
kernels, range math, multipart sequencing, XML extraction) now lives once in
`src/fs/backend/sd_s3.c`. The **HTTP transport is injected** through a narrow
4-function vtable:

```c
typedef struct xrootd_s3_transport_s {
    int (*request)(tctx, host,port,tls, method, path_and_query,
                   headers, body,body_len, timeout_ms, resp, errbuf,errcap);
    int (*resp_header)(resp, name, out, outcap);          /* 0 found / -1 absent */
    const void *(*resp_body)(resp, *len);
    void (*resp_free)(resp);
} xrootd_s3_transport_t;
```

A non-2xx HTTP status is **not** a transport failure — it's reported via
`resp->status` for the driver to map. The response carries a transport-private
`opaque` handle the driver only ever touches through the accessors.

### 5.2 The client's transport (`vfs_s3_transport.c`)

`const xrootd_s3_transport_t xrdc_s3_http_transport` wires the vtable onto the
client's `xrdc_http_req` / `xrdc_http_header` / `xrdc_http_resp_free`, mapping the
client's `1/0` returns to the vtable's `0/-1` and copying error text into the
caller's `errbuf`. This is the *only* S3 code still in the client.

### 5.3 The client S3 shell after cleanup (`vfs_s3*.c`)

What survives in `client/lib` is a thin shell — everything else was deleted when
`sd_s3` took ownership:

| File | Keeps | (deleted) |
|---|---|---|
| `vfs_s3.c` | URL parse, cred wiring, `s3_be_open`/`s3_be_stat`, single-vs-MPU param build | `s3_open_write_single/_mpu` |
| `vfs_s3_io.c` | the `xrdc_vfs` vtable, each delegating to `sd_s3_*` | `s3_pwrite_*`, `s3_commit_single/_mpu` |
| `vfs_s3_http.c` | `s3_creds_load` only | `s3_sign`, `s3_http_err`, `xml_extract_tag`, `s3_etag_ensure_cap` |
| `vfs_s3_internal.h` | endpoint fields + `sd_s3_file *sd` + live decls | the `s3_part_etag` typedef + 13 dead write-state fields |
| `vfs_s3_mpu.c` | — | **whole file removed** |

The client handle `vfs_s3_file` now holds only the parsed endpoint
(`host/port/tls/key_path/ak/sk/region`), a cached `obj_size`, an `is_write` flag,
and the shared driver handle `sd_s3_file *sd`. All buffers/upload state live
inside `sd_s3.c`.

### 5.4 Single-PUT vs multipart decision (`sd_s3_open_write`)

```
   expected_size >= 0  AND  expected_size <= part_size
        ├── yes →  single buffered PUT (malloc put_buf, flush on commit)
        └── no  →  CreateMultipartUpload immediately; pwrite flushes ≥part_size
                   chunks as parts; commit = CompleteMultipartUpload
```

`part_size` defaults to 64 MiB; the client exposes `S3_PART_MAX_OVERRIDE` (env)
to force small parts for testing. `expected_size` comes from the copy engine's
`xrdc_vfs_open_opts.expected_size` hint (`<0` = unknown → MPU).

> **`<time.h>` gotcha (S3):** the module build adds `-I src/core/compat`, so
> `#include <time.h>` resolves to `src/core/compat/time.h` (module-only,
> self-recursive). `sd_s3.c` therefore computes UTC with `gettimeofday` + a
> Howard-Hinnant civil-from-days calc instead of `gmtime_r`. Don't "fix" it back
> to `<time.h>`.

---

## 6. End-to-end data flows

### 6.1 Server `root://` read (AIO worker)

```
  kXR_read handler (src/protocols/root/read/)
     │ xrootd_vfs_open → vfs_open.c → sd_posix_open(inst, path)   [RESOLVE_BENEATH]
     │ submit job{op=READ, fd, off, len} to AIO thread pool
     ▼  (worker thread)
  xrootd_vfs_io_execute (vfs_io_core.c)
     │ → xrootd_vfs_io_execute_read → xrootd_vfs_pread_full
     │      → xvfs_pread_full(obj=wrap(fd))        [SHARED vfs core]
     │           → obj->driver->pread = sd_posix_pread → pread(2)   [SHARED backend]
     │ (optional) per-page CRC32c + CSI verify
     ▼
  done callback builds the kXR wire response on the event loop
```

### 6.2 Server write / sync / truncate (AIO worker)

```
  xrootd_vfs_io_execute_write
     → xrootd_vfs_io_write_counted(fd)
        → xvfs_pwrite_full(wrap(fd))               [SHARED vfs core: EINTR+short-io]
           → sd_posix_pwrite → pwrite(2)           [SHARED backend]
     → (phase-59) xrootd_csi_update_aligned  (per-page CRC retag, fail-open)

  _execute_sync     → xvfs_fsync(wrap(fd))     → sd_posix_fsync → fsync(2)
  _execute_truncate → xvfs_ftruncate(wrap(fd)) → sd_posix_ftruncate → ftruncate(2)
```

### 6.3 Client local copy `file → file` (`xrdcp /a /b`)

```
  copy.c
   ├─ xrdc_vfs_open("/a", READ)  ─▶ posix_be_open ─▶ open_unconfined(O_READ)
   └─ xrdc_vfs_open("/b", WRITE) ─▶ posix_be_open ─▶ open_unconfined(tmp, O_EXCL|O_NOFOLLOW)
        loop:
          xrdc_vfs_pread(src)  ─▶ posix_pread  ─▶ [ring] OR xvfs_pread_once ─▶ pread(2)
          xrdc_vfs_pwrite(dst) ─▶ posix_pwrite ─▶ [ring] OR xvfs_pwrite_full ─▶ pwrite(2)
        xrdc_vfs_commit(dst)   ─▶ posix_commit ─▶ fsync + rename(tmp → /b)
        xrdc_vfs_close(both)
```

### 6.4 Client S3 read (`xrdcp s3://… /local`)

```
  s3_be_open(READ)
     → s3_open_read: build sd_s3_open_params{host,port,tls,key,ak,sk,region,
                       transport=&xrdc_s3_http_transport}
     → sd_s3_open_read  (src/fs/backend/sd_s3.c)
  xrdc_vfs_fstat → s3_fstat → (lazy) s3_load_size → sd_s3_size
     → sd_s3_sign(HEAD) → transport->request → resp_header("Content-Length")
  xrdc_vfs_pread → s3_pread → sd_s3_pread
     → sd_s3_sign(GET, "Range: bytes=off-…") → transport->request → resp_body → memcpy
```

### 6.5 Client S3 write (single-PUT and MPU)

```
  s3_be_open(WRITE)  → sd_s3_open_write(expected_size, part_size)
                       ├─ small → buffer in put_buf
                       └─ large → sd_s3_mpu_create (CreateMultipartUpload)
  xrdc_vfs_pwrite → s3_pwrite → sd_s3_pwrite
                       ├─ single → append to put_buf
                       └─ MPU → buffer to part_buf; flush ≥part_size as UploadPart
  xrdc_vfs_commit → s3_commit → sd_s3_commit
                       ├─ single → one PUT of put_buf
                       └─ MPU → flush last part + CompleteMultipartUpload
  xrdc_vfs_abort  → s3_abort → sd_s3_abort  (AbortMultipartUpload / drop buffer)
```

---

## 7. The dual-build mechanism (how one file compiles into two worlds)

```
   src/fs/backend/sd_posix.c ─┬─▶  ./config  ── nginx ./configure ──▶  ngx_xrootd_module.so
   src/fs/backend/sd_block.c ─┤        (real ngx_core.h)               (full driver: raw + ns ops)
   src/fs/backend/sd_s3.c  ───┤
   src/fs/core/vfs_core.c  ───┘
                              └─▶  shared/xrdproto/Makefile  ──▶  libxrdproto.a
                                       (-DXRDPROTO_NO_NGX)          (raw ops only; ns ops #ifdef'd out)
                                                                    │
                                                          client/Makefile links it
                                                                    ▼
                                                     xrdcp, xrootdfs, … (0 ngx_ symbols)
```

`sd.h` makes this work. Under `-DXRDPROTO_NO_NGX` it supplies the *minimal* nginx
surface the header merely **names** — all typedefs/macros, no runtime symbols:

```c
typedef intptr_t          ngx_int_t;
typedef int               ngx_fd_t;
typedef struct ngx_log_s  ngx_log_t;    /* opaque; only ever a pointer */
typedef struct ngx_pool_s ngx_pool_t;   /* opaque; only ever a pointer */
#define NGX_OK 0 / NGX_ERROR -1 / NGX_INVALID_FILE -1 / ngx_memzero …
```

Because these are types/macros (not functions), the built archive has **zero**
`ngx_*` symbols, which `shared/xrdproto/check-ngx-free.sh` enforces by inspecting
the archive (`nm`). The ngx-coupled driver slots (instance/namespace/staged) are
simply `NULL` in the client build via `#ifndef XRDPROTO_NO_NGX`.

### 7.1 Build-list facts (easy to get wrong)

- New `.c` files register in the **top-level `./config`** (the `$ngx_addon_dir/
  src/…` lists), *not* `src/core/config/config.h`.
- The module build (`./config`) compiles `sd_posix.c`, `sd_block.c`,
  `sd_registry.c`, `vfs_io_core.c`, `vfs_core.c`.
- **`sd_s3.c` is `libxrdproto`-only** — it is in `shared/xrdproto/Makefile`'s
  `BACKEND_OBJS` but **not** in `./config`, because the module has no S3
  transport consumer yet. (When an S3 cache-origin lands server-side, add it to
  `./config` and supply a server transport.)
- `shared/xrdproto/Makefile`: `BACKEND_OBJS = sd_posix.o sd_block.o sd_s3.o`,
  `FSCORE_OBJS = vfs_core.o`.
- `client/Makefile`: the VFS shell is `vfs.c vfs_posix.c vfs_block.c vfs_s3.c
  vfs_s3_io.c vfs_s3_http.c vfs_s3_transport.c` (note: `vfs_s3_mpu.c` is gone).

---

## 8. Why two handle types remain (and that's correct)

The server (`xrootd_vfs_*` / `xrootd_sd_obj_t`) and client (`xrdc_vfs_file`)
handle types were **not** merged. This is deliberate, not unfinished work:

| Concern | Server handle | Client handle |
|---|---|---|
| runtime | nginx pool/log, AIO jobs, sendfile chains, Prometheus | `malloc`, `xrdc_status`, io_uring |
| reach | export-confined (`RESOLVE_BENEATH`) | arbitrary URL/path |
| finalize | staged-file commit (server semantics) | `commit`/`abort` (temp+rename / MPU) |
| extras | metrics, access log, slice cache, CSI | credential store, URL routing |

Merging the *shells* would drag nginx into the client or client concerns into the
server. The unification target was the **mechanism in the middle** (verbs +
drivers), which is now genuinely shared. The shells are thin adapters over that
shared core.

---

## 9. Invariants & gotchas (carry these forward)

1. **Confinement stays in the server's open.** Never route an unconfined client
   open through `sd_posix_open`, and never drop `RESOLVE_BENEATH` from the server
   path. The shared verbs assume the fd is already vetted.
2. **`libxrdproto` must stay ngx-free.** Any new shared file under `src/fs/`
   compiled into the client must build under `-DXRDPROTO_NO_NGX`; gate
   nginx-coupled code with `#ifndef XRDPROTO_NO_NGX`. `check-ngx-free.sh` fails
   the build otherwise; client binaries must show `nm … | grep -c ngx_ == 0`.
3. **Verbs own the loop, drivers own the syscall.** Don't add an EINTR loop in a
   driver, and don't call a raw syscall outside `src/fs/backend/`. (Project
   invariant: all data-plane byte I/O routes through `src/fs/backend/` via the
   SD seam — tier-1, a hard rule.)
3a. **Namespace & metadata, not just bytes (phase-62).** The seam invariant now
   covers the *whole* filesystem surface: a protocol handler reaches
   `open`/`stat`/`opendir`/`unlink`/`rename`/`mkdir`/`truncate`/`chmod`/**xattr**
   on an export path through `xrootd_vfs_*` (incl. `xrootd_vfs_probe`, the
   `xrootd_vfs_open_fd`/`_at` raw-fd primitives, the path *and* fd xattr variants,
   and `xrootd_vfs_unlink_path`/`mkdir_path`/`rename_path`/`walk`), never a raw
   libc call. The only raw FS allowed in handler code is a **separate svc-owned
   storage domain** (cache / upload-stage / FRM-control / S3-multipart-staging /
   checkpoint journal) or a **non-export resource** (config/cert/token, `/tmp`,
   `/dev/null`, `/proc`, sockets), each marked with a same-line
   `/* vfs-seam-allow: <reason> */` comment. **Why those stay raw:** the VFS
   confines to ONE export root and, under impersonation, routes to the broker as
   the mapped user — the wrong root and identity for a different svc-owned store.
   See [`../refactor/phase-62-vfs-namespace-metadata-seam-closure.md`](../refactor/phase-62-vfs-namespace-metadata-seam-closure.md).
4. **S3 = `sd_s3.c` only.** New S3 protocol behaviour goes in the shared driver,
   reached via the transport vtable. Don't re-add SigV4/XML/MPU logic to the
   client shell.
5. **`<time.h>` is shadowed in the module build** — see §5.4.
6. **block:// is opened in place** — no create/truncate, no atomic-temp, no
   truncate cap.
7. **io_uring is a client-only override** layered *above* the shared verbs, not a
   driver capability the server uses on this path.

---

## 10. File index

### Shared core (compiles into both)
| File | Role |
|---|---|
| `src/fs/backend/sd.h` | SD interface: caps, vtable, accessors, ngx-free fallback, `wrap`, unconfined opens |
| `src/fs/backend/sd_posix.c` | POSIX driver (raw ops shared; instance/namespace ops module-only) |
| `src/fs/backend/sd_block.c` | block driver (raw ops delegate to POSIX; `BLKGETSIZE64` fstat) |
| `src/fs/backend/sd_s3.c` / `sd_s3.h` | S3 driver: SigV4, HEAD, Range GET, single-PUT, MPU, XML (libxrdproto-only) |
| `src/fs/backend/sd_s3_transport.h` | injected HTTP transport vtable for the S3 driver |
| `src/fs/backend/sd_registry.c` | name → bound instance (`posix`/`block`) |
| `src/fs/core/vfs_core.c` / `.h` | the shared `vfs` I/O verbs (`xvfs_*`) |
| `src/fs/core/vfs_core_unittest.c` | standalone gcc round-trip of every verb |

### Server-only `vfs_server` (nginx-coupled)
| File | Role |
|---|---|
| `src/fs/vfs/vfs_open.c` | confined open cascade (produces the fd) |
| `src/fs/vfs/vfs_io_core.c` / `.h` | worker-safe job executor (read/write/readv/pgread/sync/truncate/opendir) over the shared verbs |
| `src/fs/vfs/vfs_read.c` … `vfs_xattr.c` | per-op data-plane handlers, staged commit, dir/stat/rename/xattr |
| `src/fs/vfs/vfs_walk.c` | thread-safe pool-free confined primitives (`xrootd_vfs_open_fd`/`_at`, `unlink_path`/`_at`, `mkdir_path`, `rename_path`, `walk`, `copyfile`/`copytree`) for off-loop/bulk consumers |
| `src/fs/backend/sd_ceph.c` (`+_unittest`) | module-only Ceph/RADOS driver (gated on `XROOTD_HAVE_CEPH`); **not** compiled into the client `libxrdproto` |
| `src/fs/backend/sd_pblock.c`, `sd_pblock_catalog.c` (`+ unittests`) | module-only striped-block driver over a SQLite catalog (gated on `XROOTD_HAVE_SQLITE`); ngx-free + standalone-testable but not in the client build. **Deep-dive (block-striping, the catalog, the VFS↔backend wiring, with ASCII diagrams):** [`pblock-storage-backend.md`](pblock-storage-backend.md) |
| `src/fs/backend/csi_tagstore.c`, `csi_verify.c` (`+_unittest`) | module-only `XrdOssCsi`-parity per-page CRC32C tagstore; tag-file I/O stays below the seam (in `backend/`) |

### Client-only shell (ngx-free)
| File | Role |
|---|---|
| `client/lib/vfs.h` / `vfs.c` | `xrdc_vfs` contract + façade/registry + URL routing |
| `client/lib/vfs_posix.c` | POSIX backend: unconfined open, io_uring/shared-verb I/O, temp+rename commit |
| `client/lib/vfs_block.c` | block backend over `xrootd_sd_block_driver` |
| `client/lib/vfs_s3.c`, `vfs_s3_io.c`, `vfs_s3_http.c`, `vfs_s3_internal.h` | S3 shell: URL parse, creds, vtable→`sd_s3` adapter |
| `client/lib/vfs_s3_transport.c` | `xrdc_s3_http_transport` — the client's S3 transport impl |

### Build & guards
| File | Role |
|---|---|
| `./config` | module source list (sd_posix/block/registry, vfs_io_core, vfs_core) |
| `shared/xrdproto/Makefile` | `libxrdproto.a` (BACKEND_OBJS incl. sd_s3, FSCORE_OBJS) |
| `client/Makefile` | links the client shell + `libxrdproto.a` |
| `shared/xrdproto/check-ngx-free.sh` | fails the build if the archive references `ngx_*` |
| `tools/ci/check_vfs_seam.sh` | enforces "VFS = sole storage truth" in 3 tiers — tier-1 raw byte ops (HARD), tier-2/1.5 confined-helper/SD-vtable (`vfs_seam_backlog.txt`, 0), tier-3 raw namespace/metadata syscalls (`vfs_seam_backlog_ns.txt`, 0). Skips lines marked `/* vfs-seam-allow: … */`. `--regen` re-snapshots after a deliberate migration. |
| `tools/ci/vfs_seam_backlog.txt` / `…_ns.txt` | grandfather allowlists for tier-2 and tier-3 respectively; both empty (seam closed) |
