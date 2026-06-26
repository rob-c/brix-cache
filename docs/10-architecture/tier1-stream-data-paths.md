# Tier 1 XRootD Wire Protocol Operations — nginx-xrootd Module

Comprehensive documentation of all Tier 1 XRootD wire protocol operations through the nginx-xrootd module. This covers the stream-layer operations that handle the XRootD binary wire protocol, as defined in `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` and implemented via `src/protocol/wire_core_requests.h`.

## Operations Covered (8 total)

| Opcode | Name | Hex | Description |
|--------|------|-----|-------------|
| 3013 | kXR_read | 0x0BC5 | Read data from file |
| 3019 | kXR_write | 0x0BCB | Write data to file |
| 3017 | kXR_stat | 0x0BC9 | Get file status |
| 3003 | kXR_close | 0x0BBB | Close file handle |
| 3011 | kXR_ping | 0x0BC3 | Keep-alive ping |
| 3004 | kXR_dirlist | 0x0BBC | List directory contents |
| 3010 | kXR_open | 0x0BC2 | Open file (boundary case) |
| 3022 | kXR_statx | 0x0BCE | Batch stat multiple files (boundary case) |

## Shared Infrastructure

### File Handle Management (`src/connection/fd_table.c`)

The `fd_table` manages file handles using a slot-based system:

```c
typedef struct {
    int fd;                    // OS file descriptor
    char path[XROOTD_MAX_PATH]; // Resolved canonical path
    uint8_t handle;            // Wire protocol handle (0-255)
    time_t last_access;        // Last access timestamp
} xrootd_file_t;

// Allocation helpers:
xrootd_file_t* fd_alloc(int os_fd, const char *path);  // Allocates new slot
void fd_set(xrootd_file_t *file, int os_fd, const char *path);  // Updates existing
xrootd_file_t* fd_get(uint8_t handle);                  // Retrieves by wire handle
```

- Single-byte wire format for handle values (0–255)
- Slots are allocated via `fd_alloc()` and retrieved via `fd_get()`
- Last access time is tracked for cleanup purposes

### ACL Enforcement (`src/path/acl.c`)

Path-based ACL rules with VO-specific attribute validation:

```c
// Key functions:
int acl_check_read(xrootd_file_t *file, const char *path);  // Check read permission
int acl_check_write(xrootd_file_t *file, const char *path); // Check write permission
void acl_update_vo_attrs(xrootd_file_t *file, const char *path); // Update VO attributes
```

- ACL rules are evaluated per-path with VO-specific attribute checks
- Read/write gates check `conf->allow_write` globally before token scope validation
- Path resolution (`resolve_path()`) is performed before any open operation

### Metrics (`src/metrics/stream.c`, `src/metrics/writer.c`)

Prometheus counters for stream operations:

```c
// Metric types tracked:
XROOTD_METRIC_READ_BYTES      // Bytes read via kXR_read
XROOTD_METRIC_WRITE_BYTES     // Bytes written via kXR_write  
XROOTD_METRIC_STAT_CALLS      // Stat operation count
XROOTD_METRIC_OPEN_CALLS      // Open operation count
XROOTD_METRIC_CLOSE_CALLS     // Close operation count
XROOTD_METRIC_PING_CALLS      // Ping keep-alive count
XROOTD_METRIC_DIRLIST_CALLS   // Directory listing calls
```

- Low-cardinality labels only (no paths/bucket-names/UUIDs)
- Incremented via `XROOTD_PROXY_METRIC_INC(op, status)` macro at callsites

## Invariants Applied to Tier 1 Operations

1. **pgread/pgwrite → kXR_status(4007) framing + per-page CRC32c required** — All page-granular operations use kXR_status response type with CRC32c checksums
2. **TLS: `b->memory=1` only; cleartext: file-backed+sendfile; never mix** — TLS buffers are memory-backed, cleartext uses file-backed buffers with sendfile
3. **`conf->allow_write` checked globally before token scope** — Write permission gate is checked before any write operation
4. **All wire paths → `resolve_path()` before `open()` — no exceptions** — Path resolution happens before every open/statx call

## Operation Details

### 1. kXR_read (3013)

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for read operations. The switch case for `kXR_read` calls the read handler with parsed parameters.

#### Request Parsing
From `wire_core_requests.h`, the ClientReadRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)
    uint32_t offset;          // Byte offset in file
    uint32_t count;           // Number of bytes to read
} __attribute__((packed)) ClientReadRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_read = 3013)
- Byte 2: Handle (single byte, 0-255)
- Bytes 3-6: Offset (uint32_t big-endian)
- Bytes 7-10: Count (uint32_t big-endian)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. `fd_get(handle)` retrieves file handle from fd_table
3. ACL check via `acl_check_read(file, path)` for path-based permissions

#### Core Logic
1. Validate handle exists in fd_table
2. Check read permission against ACL rules
3. Read data via the VFS I/O core (`xrootd_vfs_io_execute()`, `src/fs/vfs_io_core.c`), which issues the raw `pread`/`preadv` through the POSIX storage driver (`src/fs/backend/`) — the handler never calls `pread` directly
4. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_status (4007) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful reads, the data payload follows:
- Bytes 0-1: Opcode (kXR_read = 3013)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: File data content

#### Error Handling
- ENOENT → kXR_NotFound (3011) → HTTP 404
- EACCES/EPERM → kXR_NotAuthorized (3010) → HTTP 403  
- EINVAL → kXR_ArgInvalid (3000) → HTTP 400
- EIO → kXR_IOError (3007) → HTTP 500
- ENOMEM → kXR_NoMemory (3008) → HTTP 507

#### Wire Struct Details
```c
// ClientReadRequest - from wire_core_requests.h
typedef struct {
    uint8_t handle;           // File handle (0-255)
    uint32_t offset;          // Byte offset in file  
    uint32_t count;           // Number of bytes to read
} __attribute__((packed)) ClientReadRequest;

// XRootDResponse - from wire_core_requests.h  
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 2. kXR_write (3019)

#### Entry Point
`xrootd_dispatch_write_opcode()` in `src/handshake/dispatch_write.c` handles opcode dispatch for write operations, called from the switch case for `kXR_write`.

#### Request Parsing
From `wire_core_requests.h`, the ClientWriteRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)
    uint32_t offset;          // Byte offset in file
    uint32_t count;           // Number of bytes to write
} __attribute__((packed)) ClientWriteRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_write = 3019)
- Byte 2: Handle (single byte, 0-255)
- Bytes 3-6: Offset (uint32_t big-endian)
- Bytes 7-10: Count (uint32_t big-endian)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. `require_write(ctx, conf)` — stricter gate requiring BOTH authentication AND explicit write permission (conf->allow_write)
3. `fd_get(handle)` retrieves file handle from fd_table
4. ACL check via `acl_check_write(file, path)` for path-based permissions

#### Core Logic
1. Validate handle exists in fd_table
2. Check write permission against ACL rules and conf->allow_write gate
3. Write data via the VFS I/O core (`xrootd_vfs_io_execute()`, `src/fs/vfs_io_core.c`), which issues the raw `pwrite`/`pwritev` through the POSIX storage driver (`src/fs/backend/`) — the handler never calls `pwrite` directly
4. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_status (4007) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code
    char msg[1];              // Null-terminated message string  
} __attribute__((packed)) XRootDResponse;
```

For successful writes, the response includes:
- Bytes 0-1: Opcode (kXR_write = 3019)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: Written data confirmation

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Write-specific errors include:
- ENOSPC → kXR_NoSpace (3009) → HTTP 507
- EROFS → kXR_IOError (3007) → HTTP 500

#### Wire Struct Details
```c
// ClientWriteRequest - from wire_core_requests.h
typedef struct {
    uint8_t handle;           // File handle (0-255)
    uint32_t offset;          // Byte offset in file
    uint32_t count;           // Number of bytes to write  
} __attribute__((packed)) ClientWriteRequest;

// XRootDResponse - from wire_core_requests.h
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 3. kXR_stat (3017)

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for stat operations via the switch case for `kXR_stat`.

#### Request Parsing
From `wire_core_requests.h`, the ClientStatRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)  
} __attribute__((packed)) ClientStatRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_stat = 3017)
- Byte 2: Handle (single byte, 0-255)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. `fd_get(handle)` retrieves file handle from fd_table
3. ACL check via `acl_check_read(file, path)` for path-based permissions

#### Core Logic
1. Validate handle exists in fd_table
2. Check read permission against ACL rules
3. Use handle metadata (stat cache) — no extra path syscalls per stat call
4. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_stat (3017) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful stat, the response includes file metadata:
- Bytes 0-1: Opcode (kXR_stat = 3017)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: File metadata (size, permissions, timestamps)

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Stat-specific errors include:
- ENOENT → kXR_NotFound (3011) → HTTP 404
- EACCES/EPERM → kXR_NotAuthorized (3010) → HTTP 403

#### Wire Struct Details
```c
// ClientStatRequest - from wire_core_requests.h  
typedef struct {
    uint8_t handle;           // File handle (0-255)
} __attribute__((packed)) ClientStatRequest;

// XRootDResponse - from wire_core_requests.h
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 4. kXR_close (3003)

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for close operations via the switch case for `kXR_close`.

#### Request Parsing
From `wire_core_requests.h`, the ClientCloseRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)  
} __attribute__((packed)) ClientCloseRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_close = 3003)
- Byte 2: Handle (single byte, 0-255)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. `fd_get(handle)` retrieves file handle from fd_table

#### Core Logic
1. Validate handle exists in fd_table
2. Close OS file descriptor using close() or shutdown()
3. Remove slot from fd_table via fd_free()
4. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_status (4007) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful close, the response includes:
- Bytes 0-1: Opcode (kXR_close = 3003)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: Close confirmation

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Close-specific errors include:
- EBADF → kXR_ArgInvalid (3000) → HTTP 400
- EIO → kXR_IOError (3007) → HTTP 500

#### Wire Struct Details
```c
// ClientCloseRequest - from wire_core_requests.h  
typedef struct {
    uint8_t handle;           // File handle (0-255)
} __attribute__((packed)) ClientCloseRequest;

// XRootDResponse - from wire_core_requests.h
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 5. kXR_ping (3011)

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for ping operations via the switch case for `kXR_ping`.

#### Request Parsing
From `wire_core_requests.h`, the ClientPingRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)  
} __attribute__((packed)) ClientPingRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_ping = 3011)
- Byte 2: Handle (single byte, 0-255)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. `fd_get(handle)` retrieves file handle from fd_table

#### Core Logic
1. Validate handle exists in fd_table
2. Check if connection is still alive via keep-alive mechanism
3. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_status (4007) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful ping, the response includes:
- Bytes 0-1: Opcode (kXR_ping = 3011)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: Ping confirmation

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Ping-specific errors include:
- ECONNRESET → kXR_IOError (3007) → HTTP 500
- ETIMEDOUT → kXR_IOError (3007) → HTTP 500

#### Wire Struct Details
```c
// ClientPingRequest - from wire_core_requests.h  
typedef struct {
    uint8_t handle;           // File handle (0-255)
} __attribute__((packed)) ClientPingRequest;

// XRootDResponse - from wire_core_requests.h
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 6. kXR_dirlist (3004)

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for directory listing operations via the switch case for `kXR_dirlist`.

#### Request Parsing
From `wire_core_requests.h`, the ClientDirListRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)  
} __attribute__((packed)) ClientDirListRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_dirlist = 3004)
- Byte 2: Handle (single byte, 0-255)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. `fd_get(handle)` retrieves file handle from fd_table
3. ACL check via `acl_check_read(file, path)` for path-based permissions

#### Core Logic
1. Validate handle exists in fd_table
2. Check read permission against ACL rules
3. List directory contents using readdir() or getdents64()
4. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_dirlist (3004) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful dirlist, the response includes:
- Bytes 0-1: Opcode (kXR_dirlist = 3004)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: Directory entries (names, sizes, permissions)

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Dirlist-specific errors include:
- ENOENT → kXR_NotFound (3011) → HTTP 404
- EACCES/EPERM → kXR_NotAuthorized (3010) → HTTP 403

#### Wire Struct Details
```c
// ClientDirListRequest - from wire_core_requests.h  
typedef struct {
    uint8_t handle;           // File handle (0-255)
} __attribute__((packed)) ClientDirListRequest;

// XRootDResponse - from wire_core_requests.h
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 7. kXR_open (3010) — Boundary Case

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for open operations via the switch case for `kXR_open`. The handler is implemented in `src/read/open_request.c`.

#### Request Parsing
From `wire_core_requests.h`, the ClientOpenRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)  
    uint32_t flags;           // Open flags (O_RDONLY, O_WRONLY, etc.)
} __attribute__((packed)) ClientOpenRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_open = 3010)
- Byte 2: Handle (single byte, 0-255)
- Bytes 3-6: Flags (uint32_t big-endian)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. Path resolution via `resolve_path()` before open() call
3. ACL check via `acl_check_read(file, path)` for path-based permissions
4. Write permission gate checks conf->allow_write globally before token scope

#### Core Logic
1. Validate handle exists in fd_table
2. Resolve path using resolve_path() — no exceptions
3. Open file using open() or fopen() with resolved path
4. Allocate new slot in fd_table via fd_alloc()
5. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_status (4007) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful open, the response includes:
- Bytes 0-1: Opcode (kXR_open = 3010)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: Open confirmation with new handle

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Open-specific errors include:
- ENOENT → kXR_NotFound (3011) → HTTP 404
- EACCES/EPERM → kXR_NotAuthorized (3010) → HTTP 403
- EINVAL → kXR_ArgInvalid (3000) → HTTP 400

#### Wire Struct Details
```c
// ClientOpenRequest - from wire_core_requests.h  
typedef struct {
    uint8_t handle;           // File handle (0-255)
    uint32_t flags;           // Open flags (O_RDONLY, O_WRONLY, etc.)
} __attribute__((packed)) ClientOpenRequest;

// XRootDResponse - from wire_core_requests.h  
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

### 8. kXR_statx (3022) — Boundary Case

#### Entry Point
`xrootd_dispatch_read_opcode()` in `src/handshake/dispatch_read.c` handles opcode dispatch for batch stat operations via the switch case for `kXR_statx`. The handler is implemented in `src/read/statx.c`.

#### Request Parsing
From `wire_core_requests.h`, the ClientStatxRequest struct:

```c
typedef struct {
    uint8_t handle;           // File handle (0-255)  
} __attribute__((packed)) ClientStatxRequest;
```

Wire layout (big-endian):
- Bytes 0-1: Opcode (kXR_statx = 3022)
- Byte 2: Handle (single byte, 0-255)

#### Security Checks
1. `require_auth(ctx)` — checks ctx->logged_in flag
2. Path resolution via `resolve_path()` before stat() call
3. ACL check via `acl_check_read(file, path)` for path-based permissions

#### Core Logic
1. Validate handle exists in fd_table
2. Resolve path using resolve_path() — no exceptions  
3. Get file status using statx() or fstat() with handle metadata
4. Build response chain with ngx_buf_t buffers

#### Response Building
Response type is kXR_status (4007) for success/failure:

```c
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

For successful statx, the response includes:
- Bytes 0-1: Opcode (kXR_statx = 3022)
- Bytes 2-3: Status code (uint16_t big-endian)
- Byte 4: Data length indicator
- Remaining bytes: Batched file metadata

#### Error Handling
Same errno → kXR → HTTP mapping as read operations. Statx-specific errors include:
- ENOENT → kXR_NotFound (3011) → HTTP 404
- EACCES/EPERM → kXR_NotAuthorized (3010) → HTTP 403

#### Wire Struct Details
```c
// ClientStatxRequest - from wire_core_requests.h  
typedef struct {
    uint8_t handle;           // File handle (0-255)
} __attribute__((packed)) ClientStatxRequest;

// XRootDResponse - from wire_core_requests.h
typedef struct {
    uint16_t status;          // kXR_ok (2000) or error code  
    char msg[1];              // Null-terminated message string
} __attribute__((packed)) XRootDResponse;
```

## errno → kXR → HTTP Mapping Reference Table

| errno | kXR Error Code | HTTP Status | Description |
|-------|----------------|-------------|-------------|
| ENOENT | kXR_NotFound (3011) | 404 Not Found | File/directory not found |
| EACCES/EPERM | kXR_NotAuthorized (3010) | 403 Forbidden | Permission denied |
| EINVAL | kXR_ArgInvalid (3000) | 400 Bad Request | Invalid argument |
| EIO | kXR_IOError (3007) | 500 Internal Server Error | I/O error |
| ENOMEM | kXR_NoMemory (3008) | 507 Insufficient Storage | Out of memory |
| ENOSPC | kXR_NoSpace (3009) | 507 Insufficient Storage | No space left on device |
| EROFS | kXR_IOError (3007) | 500 Internal Server Error | Read-only file system |
| EBADF | kXR_ArgInvalid (3000) | 400 Bad Request | Bad file descriptor |

## Reference Files

- `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` — wire protocol definitions (source of truth for wire details)
- `src/protocol/wire_core_requests.h` — Client*Request struct definitions used by nginx-xrootd
- `.sisyphus/plans/tier1-kxr-read.md`, `.sisyphus/plans/tier1-kxr-stat.md` — format reference for section structure
- `src/handshake/dispatch_read.c` — opcode dispatch switch cases for Tier 1 operations (xrootd_dispatch_read_opcode, xrootd_dispatch_write_opcode)
- `src/read/open.c` — kXR_open handler implementation (boundary case)
- `src/read/statx.c` — kXR_statx handler implementation (boundary case, batched stat)
- `src/connection/fd_table.c` — file handle management, xrootd_file_t struct
- `src/path/acl.c` — ACL enforcement for path-based operations

## Notes on Implementation Patterns

1. **All wire paths → resolve_path() before open()** — No exceptions in the codebase
2. **TLS buffer layout**: `b->memory=1` only; cleartext: file-backed+sendfile; never mix
3. **Write permission gate**: `conf->allow_write` checked globally before token scope validation
4. **Stat optimization**: Uses handle metadata — no extra path syscalls per stat call
5. **fd_table management**: Single-byte wire format for handle values (0-255), slots allocated via fd_alloc() and retrieved via fd_get()
6. **Metrics tracking**: Low-cardinality labels only, incremented via XROOTD_PROXY_METRIC_INC(op, status) macro at callsites

## Summary

This documentation covers all 8 Tier 1 XRootD wire protocol operations through the nginx-xrootd module:
- 6 core operations (read, write, stat, close, ping, dirlist)
- 2 boundary cases (open, statx)
- Each operation documented with Entry Point, Request Parsing, Security Checks, Core Logic, Response Building, Error Handling, and Wire Struct Details sections
- Shared infrastructure documented: fd_table.c, path/acl.c, metrics/stream.c
- Invariants applied to Tier 1 ops (#2 TLS buffer, #3 allow_write gate, #4 resolve_path before open, #7 stat uses handle metadata)
- errno → kXR → HTTP mapping reference table included at end of file

All operations follow the wire protocol format defined in `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` and use the Client*Request struct definitions from `src/protocol/wire_core_requests.h`.