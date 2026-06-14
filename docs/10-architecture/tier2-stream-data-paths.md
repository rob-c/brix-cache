# Tier 2: Stream Data Paths — Wire Protocol Through nginx-xrootd

## Overview

This document maps every XRootD wire protocol operation to its implementation in the nginx-xrootd module, showing how the native `stream` module translates binary opcodes into file operations.

**Reference:** `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` — full wire spec  
**Entry point:** `src/connection/handler.c` → `src/handshake/dispatch.c` → opcode handlers in `src/read/`, `src/write/`, etc.

---

## Stream Module Architecture

```
Client (xrdcp/xrdfs) ──TCP──> nginx-xrootd stream server
                                    │
                                    ├── XRootD protocol handler (stream module)
                                    │   ├── Handshake: kXR_protocol, kXR_ableTLS
                                    │   ├── Auth: GSI / token / SSS
                                    │   ├── Session bind + login
                                    │   └── Opcode dispatch → read/write/stat/tpc handlers
                                    │
                                    └── Local POSIX filesystem (or proxy upstream)
```

### Key Files

| File | Role |
|---|---|
| `src/connection/handler.c` | Stream module entry — receives raw TCP, routes to XRootD protocol handler |
| `src/handshake/dispatch.c` | Dispatches post-login opcodes by opcode number |
| `src/session/protocol.c` | Protocol state machine (XRD_ST_* states) |
| `src/session/bind.c` | kXR_bind — session-to-fd mapping |
| `src/session/login.c` | kXR_login, kXR_auth handlers |
| `src/handshake/policy.c` | Policy enforcement (allow_write, TLS requirements) |

---

## Wire Protocol Basics

### Frame Format

All XRootD wire messages follow a consistent framing:

```
+------------------+--------+
| ServerResponseHdr  | Body   |
| status (2 bytes)   | N bytes|
| dlen   (4 bytes)   |        |
+------------------+--------+
```

- `status`: uint16, network byte order — result code (kXR_ok = 0, kXR_Error = 3000+)
- `dlen`: uint32, network byte order — body length in bytes
- Body: opaque payload, format depends on opcode

### Response Header Struct

```c
typedef struct {
    uint16_t status;  // kXR result code (network byte order)
    uint32_t dlen;     // data length (network byte order)
} ServerResponseHdr;
```

**Helper:** `xrootd_build_resp_hdr(streamid, status, dlen, buf)` — builds header from components  
**Helper:** `xrootd_queue_response(ctx, c, buf, total)` — queues response on connection

### Client Request Header

All client requests carry a 4-byte stream ID prefix:

```c
typedef struct {
    uint32_t streamid[2]; // magic + session identifier
} ClientRequestHdr;
```

**Helper:** `xrootd_parse_req_hdr(c, buf)` — parses and validates header  
**Helper:** `xrootd_aio_restore_request(ctx, streamid)` — restores AIO state from stream ID

---

## Opcode Dispatch Flow

### Entry: `src/handshake/dispatch.c`

```c
// Post-login dispatch by opcode number
static ngx_int_t xrootd_dispatch_opcode(xrootd_ctx_t *ctx, ...) {
    switch (opcode) {
        case kXR_open:      return xrootd_handle_open(ctx, c, conf, body);
        case kXR_read:      return xrootd_handle_read(ctx, c, conf, body);
        case kXR_pgread:    return xrootd_handle_pgread(ctx, c, conf, body);
        case kXR_write:     return xrootd_handle_write(ctx, c, conf, body);
        case kXR_pgwrite:   return xrootd_handle_pgwrite(ctx, c, conf, body);
        // ... all other opcodes
    }
}
```

### Pre-login Dispatch (`src/handshake/dispatch_session.c`)

Handles pre-authentication opcodes: `kXR_protocol`, `kXR_ableTLS`, `kXR_wantTLS`, `kXR_login`, `kXR_auth`.

---

## Data Path 1: Read Operations

### kXR_read — Variable-Length Block Read

**File:** `src/read/read.c`  
**Opcode:** `kXR_read` (3013)  
**Wire format:** `ClientReadBody { offset (8B), length (4B) }` → `ServerReadBody { data_len (4B), data (N bytes) }`

```
Client                          Server
  |                               |
  |--kXR_read(offset, length)----->|
  |<-kXR_ok + data_len + data-----|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Parse `offset` (uint64) and `length` (uint32) from wire body
2. Validate file handle index against open files table
3. Check read-ahead cache (`file->read_ahead_end`) — if hit, serve from cache
4. If not cached: issue async read via thread pool (`ngx_thread_task_post`)
5. On completion: build response with `ServerReadBody` containing data_len + raw bytes
6. Update file's `bytes_read` counter and `cached_size`

**Key fields:**
- `file->read_last_end`: tracks last read position for sequential optimization
- `file->read_ahead_end`: end of pre-fetched range (read-ahead window)
- `file->bytes_read`: total bytes served via kXR_read

**Error handling:**
- ENOENT → kXR_NotFound
- EACCES → kXR_NotAuthorized  
- EINVAL → kXR_ArgInvalid (bad offset/length)
- EIO → kXR_IOError

### kXR_pgread — Page Read with CRC32c Integrity

**File:** `src/read/pgread.c`  
**Opcode:** `kXR_pgread` (3030)  
**Wire format:** `ClientPgReadBody { offset (8B), length (4B), pagesize (4B) }` → `ServerPgReadBody { status (2B), dlen (4B), page1_crc32c(4B), page2_crc32c(4B), ... }`

```
Client                          Server
  |                               |
  |--kXR_pgread(offset, length)-->|
  |<-kXR_ok + per-page CRC32c-----|
  |<-kXR_Error if any page fails--|
```

**Implementation:**
1. Parse `offset`, `length`, and `pagesize` from wire body
2. For each page: read data into buffer, compute CRC32c checksum
3. Build response with per-page CRC values (not raw data)
4. Each page's CRC is 4 bytes (uint32, network byte order)

**Key invariant:** pgread requires kXR_status(4007) framing + per-page CRC32c — no exceptions

**Error handling:**
- Any page with mismatched CRC → return error status for that page
- All pages must be read successfully or return partial results with errors

### kXR_readv — Scatter/Gather Read

**File:** `src/read/readv.c`  
**Opcode:** `kXR_readv` (3025)  
**Wire format:** `ClientReadvBody { offset (8B), length (4B), iovec_count (4B), iovecs[N] }` → `ServerReadvBody { status (2B), lengths[N], data[N] }`

```
Client                          Server
  |                               |
  |--kXR_readv(offset, [iovec])-->|
  |<-kXR_ok + per-segment results-|
```

**Implementation:**
1. Parse array of iovec structures (offset + length pairs)
2. For each segment: read from file at specified offset into separate buffer
3. Build response with per-segment lengths and data
4. Each segment's result is independent — partial success allowed

---

## Data Path 2: Write Operations

### kXR_write — Variable-Length Block Write

**File:** `src/write/write.c`  
**Opcode:** `kXR_write` (3019)  
**Wire format:** `ClientWriteBody { offset (8B), length (4B), data (N bytes) }` → `ServerWriteBody { status (2B), dlen (4B) }`

```
Client                          Server
  |                               |
  |--kXR_write(offset, data)----->|
  |<-kXR_ok-----------------------|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Parse `offset`, `length`, and raw data from wire body
2. Write to file at specified offset (supports random access writes)
3. Update file's `bytes_written` counter and `cached_size`
4. Return success status or errno-derived kXR error code

**Key fields:**
- `file->writable`: must be 1 for write operations
- `file->readable`: typically 0 after write (invalidates read cache)
- `file->bytes_written`: total bytes written via kXR_write

### kXR_pgwrite — Page Write with CRC32c Integrity

**File:** `src/write/pgwrite.c`  
**Opcode:** `kXR_pgwrite` (3026)  
**Wire format:** `ClientPgWriteBody { offset (8B), length (4B), pagesize (4B), page1_crc32c(4B), ... }` → `ServerPgWriteBody { status (2B), dlen (4B) }`

```
Client                          Server
  |                               |
  |--kXR_pgwrite(offset, [pages])->|
  |<-kXR_ok-----------------------|
  |<-kXR_Error if any page fails--|
```

**Implementation:**
1. Parse `offset`, `length`, `pagesize` and per-page CRC values
2. For each page: write data at offset + pagesize*i, verify CRC32c matches
3. Return success status or error for specific page indices

**Key invariant:** pgwrite requires kXR_status(4007) framing + per-page CRC32c — no exceptions

### kXR_sync — Flush/Sync File to Disk

**File:** `src/write/sync.c`  
**Opcode:** `kXR_sync` (3016)  
**Wire format:** `ClientSyncBody { fhandle (1B) }` → `ServerSyncBody { status (2B), dlen (4B) }`

```
Client                          Server
  |                               |
  |--kXR_sync(fhandle)----------->|
  |<-kXR_ok-----------------------|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Parse file handle index from wire body
2. Call `fsync()` or equivalent on the underlying file descriptor
3. Update file's `cached_size` and `bytes_written` after sync
4. Return success or errno-derived kXR error code

---

## Data Path 3: Third-Party Copy (TPC) — Native Stream

### Overview

Native TPC enables a client to copy files between two XRootD servers through nginx-xrootd acting as the destination server. The protocol uses `kXR_open` with opaque parameters (`tpc.src=`, `tpc.key=`) and relies on shared-memory key registry for cross-process rendezvous.

**Key file:** `src/tpc/key_registry.c` — SHM-based key registry (256 slots, 60s TTL)  
**Entry point:** `src/handshake/dispatch.c` → `xrootd_handle_open()` with TPC params

### Wire Protocol Sequence

```
Client                 nginx-xrootd (dest)          Remote root:// origin
  |                         |                              |
  |--kXR_open dst?tpc.src=->|                              |
  |                        |--connect + handshake---------->|
  |                        |--kXR_login + kXR_open--------->|
  |                        |--kXR_read (loop)-------------->|
  |                        |<-file data--------------------|
  |                        |--kXR_close------------------->|
  |<-kXR_ok (open response)--|                              |
```

### Key Registry (SHM Rendezvous)

**File:** `src/tpc/key_registry.c`  
**Header:** `src/tpc/key_registry.h`

The key registry is a shared-memory table with:
- **256 slots** for concurrent TPC operations
- **60-second TTL** (configurable via `xrootd_tpc_key_ttl`)
- Per-process counter + PID for uniqueness
- Lazy expiration on lookup

**API:**
```c
void xrootd_tpc_generate_key(char *buf, size_t buf_sz);  // Generate unique key
void xrootd_tpc_key_register(const char *key, ngx_msec_t ttl_ms);  // Register with TTL
int  xrootd_tpc_key_validate(const char *key);  // Check if valid and unexpired
int  xrootd_tpc_key_consume(const char *key);   // Consume (remove) key
void xrootd_tpc_key_remove(const char *key);    // Remove key from registry
```

### Pull Path Implementation

**Files:** `src/tpc/launch.c`, `thread.c`, `io.c`, `done.c`

#### launch.c — Event Thread Entry

```c
// Validates TPC params, allocates fhandle, posts thread task
xrootd_tpc_prepare_pull(ctx, c, conf, tpc, dst_path, options, mode_bits);
xrootd_tpc_start_pull(ctx, c, conf, fhandle_idx);  // Start async pull
```

**Key logic:**
1. Check `conf->thread_pool` — required for TPC pull
2. Validate source host/path from `tpc.src=` parameter
3. Apply source policy (local/private network checks)
4. Allocate file handle index via `xrootd_alloc_fhandle()`
5. Open destination file with appropriate flags (`O_CREAT | O_TRUNC`)
6. Generate/register TPC key for rendezvous
7. Post thread task to nginx thread pool

#### thread.c — Thread Pool Worker

```c
// Orchestrates: connect → bootstrap → pull_from_source
xrootd_tpc_pull_thread(data, log);
```

**Key logic:**
1. Connect to remote XRootD server via `tpc_connect()`
2. Bootstrap anonymous session (handshake + login)
3. Pull data from source via `tpc_pull_from_source()`
4. Close file descriptor on completion

#### io.c — Low-Level Socket I/O

```c
int tpc_send_all(int fd, const void *buf, size_t len);  // Send all bytes
int tpc_recv_exact(int fd, void *buf, size_t len);      // Receive exact count
int tpc_recv_response(int fd, uint16_t *status, u_char **body, uint32_t *dlen);
```

**Key logic:**
- `tpc_send_all`: retry on EINTR, returns -1 on any other error
- `tpc_recv_exact`: reads exactly `len` bytes (may span multiple recv calls)
- `tpc_recv_response`: parses ServerResponseHdr + body, validates dlen ≤ TPC_RESP_MAX_BODY

#### done.c — Event Thread Completion Callback

```c
void xrootd_tpc_pull_done(ngx_event_t *ev);  // Sends kXR_open response or error
```

**Key logic:**
1. Restore AIO state from stream ID (`xrootd_aio_restore_request`)
2. If result != NGX_OK: close fd, unlink temp file, send error response
3. If success: update file metadata (size, inode, device), send kXR_ok response with stat info

### Push Path Implementation

**File:** `src/tpc/source.c` — Remote source open + read loop  
**File:** `src/tpc/bootstrap.c` — Anonymous XRootD session setup on remote side

The push path is the inverse of pull: nginx-xrootd acts as a client to a remote origin, reading data and writing locally.

---

## Data Path 4: File Operations (Open/Close/Stat)

### kXR_open — Open File for Read or Write

**File:** `src/read/open.c`  
**Opcode:** `kXR_open` (3010)  
**Wire format:** `ClientOpenBody { path (N bytes), options (2B) }` → `ServerOpenBody { fhandle (1B), statbuf? }`

```
Client                          Server
  |                               |
  |--kXR_open(path, options)----->|
  |<-kXR_ok + fhandle------------|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Resolve path (canonical + confined under root)
2. Check policy (`conf->allow_write` for write mode)
3. Open file with appropriate flags:
   - Read: `O_RDONLY`
   - Write: `O_RDWR | O_CREAT | O_TRUNC`
   - New file: `O_EXCL`
4. Allocate file handle index (0–255, from fd_table)
5. If `kXR_retstat` option: include stat info in response

**Key fields:**
- `file->writable`: set based on options (`kXR_new`, `kXR_delete`)
- `file->readable`: set for read mode opens
- `file->tpc_destination`: set when TPC params present
- `file->tpc_armed`: flag for pending TPC pull

**Error handling:**
- ENOENT → kXR_NotFound  
- EACCES → kXR_NotAuthorized
- EEXIST → kXR_FileExists (for new file mode)
- ENOSPC → kXR_NoMemory

### kXR_close — Close File Handle

**File:** `src/close.c`  
**Opcode:** `kXR_close` (3003)  
**Wire format:** `ClientCloseBody { fhandle (1B) }` → `ServerCloseBody { status (2B), dlen (4B) }`

```
Client                          Server
  |                               |
  |--kXR_close(fhandle)----------|
  |<-kXR_ok-----------------------|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Parse file handle index from wire body
2. Validate against open files table
3. Close underlying file descriptor
4. Free file handle slot in registry
5. Return success or errno-derived kXR error code

### kXR_stat — Get File Metadata

**File:** `src/stat.c`  
**Opcode:** `kXR_stat` (3017)  
**Wire format:** `ClientStatBody { fhandle (1B) }` → `ServerStatBody { ino, size, flags, mtime }`

```
Client                          Server
  |                               |
  |--kXR_stat(fhandle)----------->|
  |<-kXR_ok + stat info-----------|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Parse file handle index from wire body
2. Call `fstat()` on underlying file descriptor
3. Build response with inode, size, flags (readable/writable), mtime
4. Return success or errno-derived kXR error code

### kXR_statx — Extended File Metadata

**File:** `src/statx.c`  
**Opcode:** `kXR_statx` (3022)  
**Wire format:** `ClientStatxBody { fhandle (1B), mask (4B) }` → `ServerStatxBody { extended attributes }`

Extended version of stat supporting additional metadata fields.

---

## Data Path 5: Directory Operations

### kXR_dirlist — List Directory Contents

**File:** `src/dirlist/handler.c`  
**Opcode:** `kXR_dirlist` (3004)  
**Wire format:** `ClientDirListBody { path (N bytes), options (2B) }` → `ServerDirListBody { count (4B), entries[N] }`

```
Client                          Server
  |                               |
  |--kXR_dirlist(path)----------->|
  |<-kXR_ok + [entry1, entry2...]--|
  |<-kXR_Error if error-----------|
```

**Implementation:**
1. Resolve and canonicalize path
2. Open directory with `opendir()`
3. Read entries with `readdir()`, filter hidden files
4. Build response with count + array of entry names
5. Return success or errno-derived kXR error code

### kXR_locate — Get Server Location for Path

**File:** `src/read/locate.c`  
**Opcode:** `kXR_locate` (3027)  
**Wire format:** `ClientLocateBody { path (N bytes), options (2B) }` → `ServerLocateBody { server_addr, port }`

Returns the address of the server responsible for a given path (used in distributed XRootD setups).

### kXR_clone — Clone File Handle

**File:** `src/clone.c`  
**Opcode:** `kXR_clone` (3032)  
**Wire format:** `ClientCloneBody { src_fhandle (1B), dst_path (N bytes) }` → `ServerCloneBody { status (2B), dlen (4B) }`

Creates a copy of an already-open file handle at a new path.

---

## Data Path 6: Extended Attributes & Sync

### kXR_fattr — File Attributes

**File:** `src/fattr/`  
**Opcode:** `kXR_fattr` (3020)  
**Wire format:** `ClientFattrBody { fhandle (1B), mask (4B) }` → `ServerFattrBody { attributes }`

Reads or writes extended file attributes (permissions, ownership, custom metadata).

### kXR_prepare — Prepare File for Write

**File:** `src/read/open.c`  
**Opcode:** `kXR_prepare` (3021)  
**Wire format:** `ClientPrepareBody { path (N bytes), options (2B) }` → `ServerPrepareBody { status (2B), dlen (4B) }`

Pre-allocates file space and sets up for sequential writes.

### kXR_sync — Sync File to Disk

**File:** `src/write/sync.c`  
**Opcode:** `kXR_sync` (3016)  
**Wire format:** `ClientSyncBody { fhandle (1B) }` → `ServerSyncBody { status (2B), dlen (4B) }`

Flushes file data and metadata to persistent storage. See Data Path 2 above for details.

---

## Data Path 7: Authentication & Session Management

### kXR_bind — Bind File Handle to Session

**File:** `src/session/bind.c`  
**Opcode:** `kXR_bind` (3024)  
**Wire format:** `ClientBindBody { fhandle (1B), session_id (8B) }` → `ServerBindBody { status (2B), dlen (4B) }`

Associates a file handle with a specific session identifier for multi-session support.

### kXR_login — Authenticate Session

**File:** `src/session/login.c`  
**Opcode:** `kXR_login` (3007)  
**Wire format:** `ClientLoginBody { username (N bytes), password (N bytes) }` → `ServerLoginBody { status (2B), dlen (4B) }`

Initial session authentication. Sets up context for subsequent operations.

### kXR_auth — Verify Authentication Token

**File:** `src/session/login.c`  
**Opcode:** `kXR_auth` (3000)  
**Wire format:** `ClientAuthBody { token (N bytes), type (2B) }` → `ServerAuthBody { status (2B), dlen (4B) }`

Verifies authentication tokens (GSI, bearer token, SSS).

### kXR_sigver — Signature Verification

**File:** `src/session/login.c`  
**Opcode:** `kXR_sigver` (3029)  
**Wire format:** `ClientSigVerBody { request_hash (N bytes), signature (N bytes) }` → `ServerSigVerBody { status (2B), dlen (4B) }`

HMAC-SHA256 request signing for GSI sessions — verifies integrity of all subsequent requests.

---

## Data Path 8: Protocol Lifecycle

### kXR_protocol — Version Negotiation

**File:** `src/handshake/dispatch.c`  
**Opcode:** `kXR_protocol` (3006)  
**Wire format:** `ClientProtocolBody { version (4B) }` → `ServerProtocolBody { status (2B), dlen (4B) }`

Initial handshake: client sends supported protocol version, server responds with compatible version.

### kXR_ableTLS — TLS Capability Exchange

**File:** `src/handshake/dispatch.c`  
**Opcode:** `kXR_ableTLS` (3013)  
**Wire format:** `ClientAbleTlsBody { }` → `ServerAbleTlsBody { status (2B), dlen (4B) }`

Client declares TLS capability; server responds with its own capability.

### kXR_wantTLS — Request TLS Upgrade

**File:** `src/handshake/dispatch.c`  
**Opcode:** `kXR_wantTLS` (3014)  
**Wire format:** `ClientWantTlsBody { }` → `ServerWantTlsBody { status (2B), dlen (4B) }`

Client requests TLS upgrade; server responds with success/failure.

---

## Data Path 9: Manager/Cluster Operations

### kXR_redirect — Get Redirect Server Address

**File:** `src/handshake/dispatch.c`  
**Opcode:** `kXR_redirect` (4004)  
**Wire format:** `ClientRedirectBody { path (N bytes), options (2B) }` → `ServerRedirectBody { server_addr, port }`

Returns the address of the server that should handle a given path (used in distributed setups).

### CMS Heartbeat / Dynamic Registry

**File:** `src/manager/registry.c`, `src/cms/send.c`

Manages cluster membership: servers register themselves, heartbeat monitoring, dynamic server discovery.

---

## Data Path 10: Async I/O Pattern

All blocking operations (read, pgread, readv, write, pgwrite) follow the same async pattern:

```
Event Thread                    Thread Pool
    |                                |
    |--post task to thread pool------|
    |<-return NGX_OK (AIO state)-----|
    |                                |--execute blocking I/O
    |<--callback restores AIO--------|
    |<-send response to client-------|
```

**Key files:** `src/aio/` — async I/O helpers  
**Pattern:** `ngx_thread_task_alloc()` → `ngx_thread_task_post()` → callback in `done.c`

---

## Error Mapping Reference

| errno | kXR code | HTTP equivalent | Description |
|---|---|---|---|
| ENOENT | kXR_NotFound (3011) | 404 | File not found |
| EACCES/EPERM | kXR_NotAuthorized (3010) | 403 | Permission denied |
| EINVAL | kXR_ArgInvalid (3000) | 400 | Invalid argument |
| EIO | kXR_IOError (3007) | 500 | I/O error |
| ENOMEM | kXR_NoMemory (3008) | 507 | Out of memory |
| EEXIST | kXR_FileExists (3014) | — | File already exists |

---

## TLS Buffer Layout

**Invariant:** TLS connections use `b->memory=1` only; cleartext uses file-backed buffers with sendfile. Never mix modes.

```c
// TLS: memory-backed buffer
ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(*b));
b->pos = b->start = data;
b->last = b->end = data + len;
b->memory = 1;
b->last_buf = 1;

// Cleartext: file-backed buffer for sendfile
ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(*b));
b->file = ...;  // file pointer from open()
```

---

## File Handle Management

**File:** `src/connection/fd_table.c`  
**Range:** 0–255 (fixed-size array)

| Field | Purpose |
|---|---|
| `xrootd_file_t::fd` | Underlying file descriptor |
| `xrootd_file_t::writable` | Can write to this handle |
| `xrootd_file_t::readable` | Can read from this handle |
| `xrootd_file_t::cached_size` | Cached file size (from fstat) |
| `xrootd_file_t::bytes_read` | Total bytes served via kXR_read |
| `xrootd_file_t::bytes_written` | Total bytes written via kXR_write |
| `xrootd_file_t::tpc_destination` | Is this a TPC destination file |
| `xrootd_file_t::tpc_armed` | Pending TPC pull flag |

**Key functions:**
- `xrootd_alloc_fhandle(ctx)` — allocate next available slot
- `xrootd_free_fhandle(ctx, idx)` — free slot and close fd
- `xrootd_set_fhandle_path(ctx, c, idx, path)` — associate path with handle

---

## Access Logging

All operations log to structured access logs:

```c
xrootd_log_access(ctx, c, "OPCODE", path, "detail", status, kxr_code, msg, bytes);
XROOTD_OP_OK(ctx, opcode) / XROOTD_OP_ERR(ctx, opcode)  // increment metrics
```

**Log format:** structured text with opcode, path, detail level, status code, kXR error code, message, byte count.

---

## Prometheus Metrics

All operations increment counters via helpers:

```c
XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_WR)  // Increment request counter for open/write
XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC)    // Increment error counter for sync
```

**Metric categories:** opcodes (open, read, write, stat, dirlist, etc.), status (ok, err), protocol (root, dav, s3).

---

## Configuration Invariants

1. `conf->allow_write` checked globally before any write operation
2. All wire paths → `resolve_path()` before `open()` — no exceptions
3. pgread/pgwrite require per-page CRC32c integrity checks
4. TLS: memory-backed buffers only; cleartext: file-backed + sendfile

---

## Thread Safety Notes

- Event thread: handles all parsing, dispatching, response building (`ngx_palloc` OK)
- Thread pool: handles blocking I/O (`malloc`/`free` for allocations in `thread.c`, `io.c`)
- Shared memory: TPC key registry protected by `ngx_shmtx_sh_t` lock

---

## Summary Table

| Opcode | Wire Name | File | Success Response | Error Mapping |
|---|---|---|---|---|
| 3006 | kXR_protocol | dispatch.c | ServerResponseHdr { status, dlen } | — |
| 3010 | kXR_open | read/open.c | ServerOpenBody + statbuf? | errno → kXR_* |
| 3013 | kXR_read | read/read.c | ServerReadBody { data_len, data } | errno → kXR_* |
| 3019 | kXR_write | write/write.c | ServerWriteBody { status, dlen } | errno → kXR_* |
| 3003 | kXR_close | close.c | ServerCloseBody { status, dlen } | errno → kXR_* |
| 3007 | kXR_login | session/login.c | ServerLoginBody { status, dlen } | errno → kXR_* |
| 3025 | kXR_readv | read/readv.c | ServerReadvBody { per-segment results } | errno → kXR_* |
| 3016 | kXR_sync | write/sync.c | ServerSyncBody { status, dlen } | errno → kXR_* |
| 3017 | kXR_stat | stat.c | ServerStatBody { ino, size, flags, mtime } | errno → kXR_* |
| 3004 | kXR_dirlist | dirlist/handler.c | ServerDirListBody { count, entries[] } | errno → kXR_* |
| 3030 | kXR_pgread | pgread.c | ServerPgReadBody { per-page CRC32c } | errno → kXR_* |
| 3026 | kXR_pgwrite | pgwrite.c | ServerPgWriteBody { status, dlen } | errno → kXR_* |

---

## References

- **Wire spec:** `/tmp/xrootd-src/src/XProtocol/XProtocol.hh`
- **Client request structs:** `src/XProtocol/wire_core_requests.h`
- **Helper functions:** HELPERS section in AGENTS.md
- **Tests:** `tests/test_X.py`, cross-backend conformance suite
