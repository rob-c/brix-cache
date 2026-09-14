# Windows HANDLE/fd Abstraction Layer

**Status**: ✅ Implementation Complete  
**Date**: 2025-12-12  
**Location**: `src/platform/windows/handle_abstraction.*`

---

## Overview

The HANDLE/fd abstraction layer provides thread-safe mapping between POSIX file descriptors and Windows HANDLEs, enabling BriX-Cache to use POSIX-style file descriptor operations on Windows.

### Problem Statement

**POSIX/Unix**:
- Uses small integer file descriptors (0, 1, 2, ...)
- Uniform interface: read(), write(), close()
- Managed by kernel in per-process fd table

**Windows**:
- Uses opaque HANDLE pointers
- Different APIs for different handle types:
  - Files: ReadFile(), WriteFile(), CloseHandle()
  - Sockets: recv(), send(), closesocket()
  - Pipes: ReadFile(), WriteFile(), CloseHandle()
- No unified fd concept

**Solution**: Maintain a registry that maps integer fds to HANDLEs with type information for proper cleanup.

---

## Architecture

### Data Structures

#### 1. Handle Entry (`brix_win32_handle_entry_t`)

```c
typedef struct {
    int fd;                      /* File descriptor (index in registry) */
    union {
        HANDLE handle;           /* Generic handle */
        SOCKET socket;           /* Socket handle (Winsock) */
    };
    brix_win32_fd_type_t type;   /* Handle type for proper cleanup */
    int refcount;                /* Reference count for shared handles */
    const char *name;            /* Optional debug name */
} brix_win32_handle_entry_t;
```

**Fields**:
- `fd`: File descriptor number (also serves as array index)
- `handle/socket`: Union for different handle types
- `type`: Enum indicating handle type (FD_FILE, FD_SOCKET, FD_PIPE, FD_EVENT)
- `refcount`: Reference count for shared handles (e.g., dup'd fds)
- `name`: Optional debug name for diagnostics

#### 2. Handle Registry (`brix_win32_handle_registry_t`)

```c
typedef struct {
    brix_win32_handle_entry_t *entries;  /* Array of handle entries */
    size_t capacity;                     /* Total capacity */
    size_t next_fd;                      /* Next available fd (round-robin) */
    size_t used_count;                   /* Number of active handles */
    SRWLOCK lock;                        /* Thread-safe access lock */
    int initialized;                     /* Initialization flag */
} brix_win32_handle_registry_t;
```

**Configuration**:
- `BRIX_WIN32_MAX_FDS`: 4096 (maximum concurrent fds)
- `BRIX_WIN32_INITIAL_SIZE`: 256 (initial registry size)
- Dynamic growth: Doubles when capacity reached

### Handle Types

```c
typedef enum {
    FD_UNUSED = 0,
    FD_FILE,      /* Regular files - CloseHandle() */
    FD_SOCKET,    /* Winsock sockets - closesocket() */
    FD_PIPE,      /* Named/anonymous pipes - CloseHandle() */
    FD_EVENT      /* Events, semaphores, etc. - CloseHandle() */
} brix_win32_fd_type_t;
```

---

## Thread Safety

### SRW Lock (Slim Reader-Writer Lock)

The registry uses Windows SRW locks for thread-safe access:

- **Read Lock** (`AcquireSRWLockShared`): For fd→HANDLE conversion (fast path)
  - Multiple readers can hold lock simultaneously
  - Used by `brix_win32_fd_to_handle()`, `brix_win32_get_fd_type()`

- **Write Lock** (`AcquireSRWLockExclusive`): For registration/cleanup (slow path)
  - Exclusive access
  - Used by `brix_win32_register_handle()`, `brix_win32_close_handle()`

### Why SRW Locks?

1. **Performance**: Faster than critical sections for read-heavy workloads
2. **Scalability**: Multiple concurrent readers
3. **Low Overhead**: Implemented using atomic operations when uncontended
4. **Windows Native**: Available since Windows Vista

---

## API Reference

### Handle Registration

#### `brix_win32_register_handle()`

```c
int brix_win32_register_handle(HANDLE handle, brix_win32_fd_type_t type, const char *name);
```

**Parameters**:
- `handle`: Windows HANDLE to register
- `type`: Handle type (FD_FILE, FD_SOCKET, etc.)
- `name`: Optional debug name (for diagnostics)

**Returns**: File descriptor (>= 0) on success, -1 on error

**Example**:
```c
HANDLE h = CreateFileA("test.txt", ...);
int fd = brix_win32_register_handle(h, FD_FILE, "test.txt");
if (fd < 0) {
    CloseHandle(h);
    // Handle error
}
```

#### `brix_win32_register_socket()`

```c
int brix_win32_register_socket(SOCKET socket);
```

**Convenience wrapper for sockets**.

### Handle Conversion

#### `brix_win32_fd_to_handle()`

```c
HANDLE brix_win32_fd_to_handle(int fd);
```

**Returns**: HANDLE on success, NULL on error (errno set to EBADF)

**Note**: Does NOT transfer ownership - caller should not close the returned HANDLE.

#### `brix_win32_fd_to_socket()`

```c
SOCKET brix_win32_fd_to_socket(int fd);
```

**Returns**: SOCKET on success, INVALID_SOCKET on error (errno set to ENOTSOCK)

**Note**: Only valid for FD_SOCKET type handles.

### Handle Cleanup

#### `brix_win32_close_handle()`

```c
int brix_win32_close_handle(int fd);
```

**Closes handle based on type**:
- FD_SOCKET: `closesocket()`
- FD_FILE/FD_PIPE/FD_EVENT: `CloseHandle()`

**Returns**: 0 on success, -1 on error

#### `brix_win32_dup_fd()`

```c
int brix_win32_dup_fd(int fd);
```

**Increments refcount** - handle is not actually closed until refcount reaches 0.

---

## Integration Approach

### 1. Include in Windows PAL Files

```c
#include "win32_compat.h"
#include "handle_abstraction.h"
```

### 2. Register Handles on Creation

**Example: `brix_plat_anon_fd()`**

```c
HANDLE handle = CreateFileA(
    filename,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_DELETE_ON_CLOSE,
    NULL
);

int fd = brix_win32_register_handle(handle, FD_FILE, "anon_fd");
if (fd < 0) {
    CloseHandle(handle);
    return -1;
}
return fd;
```

### 3. Convert fd to HANDLE for Win32 API Calls

**Example: `brix_plat_fsync_data()`**

```c
int brix_plat_fsync_data(int fd)
{
    HANDLE handle = brix_win32_fd_to_handle(fd);
    if (handle == NULL) {
        return -1;  /* errno already set */
    }
    
    if (FlushFileBuffers(handle)) {
        return 0;
    }
    
    brix_win32_set_errno(GetLastError());
    return -1;
}
```

### 4. Close Handles on Cleanup

**Example: `brix_plat_pipe2()` error path**

```c
pipefd[0] = brix_win32_register_handle(read_handle, FD_PIPE, "pipe_read");
if (pipefd[0] < 0) {
    CloseHandle(read_handle);
    CloseHandle(write_handle);
    return -1;
}
```

---

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Register handle | O(n) | May need to grow registry |
| fd→HANDLE conversion | O(1) | Array lookup with lock |
| Close handle | O(1) | Array lookup with lock |
| Dup fd | O(1) | Increment refcount |

### Space Complexity

- **Base**: 256 entries × 48 bytes = 12 KB
- **Maximum**: 4096 entries × 48 bytes = 192 KB
- **Growth**: Doubles when full (256 → 512 → 1024 → ...)

### Lock Contention

- **Read-heavy workloads**: SRW lock allows concurrent readers
- **Write-heavy workloads**: May become bottleneck
- **Mitigation**: Keep critical sections short

---

## Debugging & Diagnostics

### Registry Statistics

```c
size_t capacity, used, next_fd;
brix_win32_get_registry_stats(&capacity, &used, &next_fd);
printf("Handle registry: %zu/%zu used, next_fd=%zu\n", used, capacity, next_fd);
```

### Debug Names

```c
const char *name = brix_win32_get_fd_name(fd);
if (name) {
    printf("fd %d is \"%s\"\n", fd, name);
}
```

### Handle Type Checking

```c
brix_win32_fd_type_t type = brix_win32_get_fd_type(fd);
switch (type) {
    case FD_FILE:   printf("Regular file\n"); break;
    case FD_SOCKET: printf("Socket\n"); break;
    case FD_PIPE:   printf("Pipe\n"); break;
    case FD_EVENT:  printf("Event\n"); break;
    default:        printf("Invalid fd\n"); break;
}
```

---

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| EBADF | Invalid fd | Check fd range, ensure handle not already closed |
| EMFILE | Too many open fds | Increase BRIX_WIN32_MAX_FDS, check for leaks |
| ENOMEM | Out of memory | System memory pressure |
| ENOTSOCK | Not a socket | Use brix_win32_fd_to_handle() for non-socket fds |

### Error Reporting

All functions set `errno` on error:

```c
HANDLE h = brix_win32_fd_to_handle(fd);
if (h == NULL) {
    switch (errno) {
        case EBADF: /* Invalid fd */ break;
        case ENOMEM: /* Out of memory */ break;
        default: /* Unknown error */ break;
    }
}
```

---

## Limitations & Future Enhancements

### Current Limitations

1. **No fd inheritance**: Child processes don't inherit fds
2. **No fd flags**: O_RDONLY/O_WRONLY/O_RDWR not tracked
3. **No fd flags**: O_NONBLOCK, O_CLOEXEC not implemented
4. **Single-threaded cleanup**: `brix_win32_cleanup_registry()` not thread-safe

### Future Enhancements

1. **fd flags support**: Track and enforce read/write modes
2. **fd inheritance**: Support for CreateProcess with inherited handles
3. **Handle tracing**: Log all handle operations for debugging
4. **Per-thread registries**: Reduce lock contention
5. **Handle leak detection**: Report unclosed handles at shutdown

---

## Testing

### Unit Tests

```c
void test_handle_registration(void)
{
    HANDLE h = CreateFileA(...);
    int fd = brix_win32_register_handle(h, FD_FILE, "test");
    assert(fd >= 0);
    
    HANDLE h2 = brix_win32_fd_to_handle(fd);
    assert(h2 == h);
    
    assert(brix_win32_close_handle(fd) == 0);
}

void test_socket_registration(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    int fd = brix_win32_register_socket(s);
    assert(fd >= 0);
    
    SOCKET s2 = brix_win32_fd_to_socket(fd);
    assert(s2 == s);
    
    assert(brix_win32_close_handle(fd) == 0);
}

void test_thread_safety(void)
{
    /* Multiple threads registering/closing handles concurrently */
}
```

### Integration Tests

- Test with nginx worker processes
- Test with high fd counts (stress test)
- Test handle leak detection
- Test with Winsock sockets

---

## References

- [Windows HANDLE Documentation](https://docs.microsoft.com/en-us/windows/win32/sysinfo/handles)
- [SRW Lock Documentation](https://docs.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks)
- [Winsock closesocket()](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-closesocket)
- [POSIX fd concept](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_258)

---

**End of Document**
