# Platform Abstraction Layer (PAL) API Reference
**Generated**: 2026-09-12 17:24:48
**Source**: `/Users/rcurrie/src/brix-cache/src/platform/platform_api.h`
**Version**: 1.0

---
## Table of Contents
1. [Overview](#overview)
2. [Platform Support Matrix](#platform-support-matrix)
3. [API Reference](#api-reference)
   - [Platform Detection](#platform-detection--information)
   - [File Descriptor Operations](#file-descriptor-operations)
   - [Zero-Copy Transfers](#zero-copy-transfers)
   - [Event & Notification](#event--notification)
   - [Security & Confinement](#security--confinement)
   - [Random Number Generation](#random-number-generation)
   - [Extended Attributes](#extended-attributes)
   - [Process Execution](#process-execution)
   - [Byte Order Operations](#byte-order-operations)
   - [Initialization](#initialization)
4. [Data Structures](#data-structures)
5. [Constants & Macros](#constants--macros)
6. [Documentation Coverage](#documentation-coverage)
7. [Implementation Guide](#implementation-guide)

---
## Overview
The Platform Abstraction Layer (PAL) provides a unified interface for platform-specific operations.
All platform detection and `#ifdef` logic is isolated in platform-specific implementation files.

**Design Goals**:
- Zero `#ifdef` in business logic code
- Clean, consistent API across all platforms
- Easy to add new platforms (Windows, BSD, etc.)
- Architecture-aware (x86_64, arm64, etc.)

---
## Platform Support Matrix

| Platform | Status | Build | Runtime | Notes |
|----------|--------|-------|---------|-------|
| Linux x86_64 | ✅ Complete | ✅ | ✅ | Production ready |
| Linux ARM64 | 🚧 Planned | 🔲 | 🔲 | CRC32/NEON optimizations |
| macOS x86_64 | ✅ Complete | ✅ | ✅ | Production ready |
| macOS ARM64 | ✅ Supported | ✅ | ✅ | Optimization planned |
| Windows x86_64 | 🚧 Planned | 🔲 | 🔲 | Skeleton implementation |
| Windows ARM64 | 🔲 Future | 🔲 | 🔲 | After x86_64 Windows |

**Legend**: ✅ Complete, 🚧 In Progress, 🔲 Planned, ❌ Not Supported

---
## API Reference

### Unknown

#### `brix_plat_anon_fd`

Create an anonymous file descriptor (memfd on Linux, tmpfile on macOS/HANDLE on Windows).

```c
int brix_plat_anon_fd(
    const char * name,
    const char * dir
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `name` | `const char *` | Name hint for the resource (may be NULL) |
| `dir` | `const char *` | Directory path (may be NULL for default) |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_available_memory`

Get available system memory in bytes.

```c
uint64_t brix_plat_available_memory();
```

**Returns**: `uint64_t` - 0 on success, -1 on error (errno set)


#### `brix_plat_cleanup`

Clean up the platform abstraction layer.

```c
void brix_plat_cleanup();
```


#### `brix_plat_cpu_count`

Get the number of online CPUs.

```c
int brix_plat_cpu_count();
```

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_eventfd`

Create an event notification file descriptor.

```c
int brix_plat_eventfd(
    unsigned int initial_value,
    int flags
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `initial_value` | `unsigned int` | Initial counter value |
| `flags` | `int` | Operation flags |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_execvpe`

Execute a program with PATH search and environment.

```c
int brix_plat_execvpe(
    const char * file,
    char *const argv[] unnamed,
    char *const envp[] unnamed
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `file` | `const char *` | Program filename |
| `unnamed` | `char *const argv[]` | Parameter |
| `unnamed` | `char *const envp[]` | Parameter |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_fadvise`

Provide file access hints (e.g., sequential, random, willneed).

```c
int brix_plat_fadvise(
    int fd,
    off_t offset,
    off_t len,
    int advice
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `fd` | `int` | File descriptor |
| `offset` | `off_t` | File offset |
| `len` | `off_t` | Length in bytes |
| `advice` | `int` | Access advice hint |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_flistxattr`

List all extended attribute names (file descriptor version).

```c
ssize_t brix_plat_flistxattr(
    int fd,
    char * list,
    size_t size
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `fd` | `int` | File descriptor |
| `list` | `char *` | Parameter |
| `size` | `size_t` | Buffer size in bytes |

**Returns**: `ssize_t` - 0 on success, -1 on error (errno set)


#### `brix_plat_fremovexattr`

Remove an extended attribute (file descriptor version).

```c
int brix_plat_fremovexattr(
    int fd,
    const char * name
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `fd` | `int` | File descriptor |
| `name` | `const char *` | Name hint for the resource (may be NULL) |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_fs_watcher_destroy`

Destroy a filesystem watcher.

```c
void brix_plat_fs_watcher_destroy(
    brix_plat_fs_watcher_t * watcher
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `watcher` | `brix_plat_fs_watcher_t *` | Filesystem watcher context |


#### `brix_plat_fs_watcher_init`

Initialize a filesystem watcher.

```c
int brix_plat_fs_watcher_init(
    brix_plat_fs_watcher_t * watcher
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `watcher` | `brix_plat_fs_watcher_t *` | Filesystem watcher context |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_fs_watcher_rm`

Remove a watch from the filesystem watcher.

```c
int brix_plat_fs_watcher_rm(
    brix_plat_fs_watcher_t * watcher,
    int wd
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `watcher` | `brix_plat_fs_watcher_t *` | Filesystem watcher context |
| `wd` | `int` | Watch descriptor |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_fsync_data`

Flush file data to stable storage (metadata may also be flushed).

```c
int brix_plat_fsync_data(
    int fd
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `fd` | `int` | File descriptor |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_init`

Initialize the platform abstraction layer.

```c
int brix_plat_init();
```

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_is_root`

Check if the current process is running as root.

```c
int brix_plat_is_root();
```

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_listxattr`

List all extended attribute names.

```c
ssize_t brix_plat_listxattr(
    const char * path,
    char * list,
    size_t size
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `path` | `const char *` | File or directory path |
| `list` | `char *` | Parameter |
| `size` | `size_t` | Buffer size in bytes |

**Returns**: `ssize_t` - 0 on success, -1 on error (errno set)


#### `brix_plat_pipe2`

Create a pipe with flags (CLOEXEC, NONBLOCK).

```c
int brix_plat_pipe2(
    int[2] pipefd,
    int flags
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `pipefd` | `int[2]` | Pipe file descriptors [2] |
| `flags` | `int` | Operation flags |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_random`

Generate cryptographically secure random bytes.

```c
int brix_plat_random(
    void * buf,
    size_t len
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `buf` | `void *` | Buffer for random data |
| `len` | `size_t` | Length in bytes |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_removexattr`

Remove an extended attribute.

```c
int brix_plat_removexattr(
    const char * path,
    const char * name
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `path` | `const char *` | File or directory path |
| `name` | `const char *` | Name hint for the resource (may be NULL) |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_security_enter`

Enter security confinement mode.

```c
int brix_plat_security_enter(
    const char * profile
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `profile` | `const char *` | Security profile name |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_security_init`

Initialize security context (seccomp on Linux).

```c
int brix_plat_security_init(
    const char * profile
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `profile` | `const char *` | Security profile name |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_sendfile`

Zero-copy transfer from file to socket/file.

```c
ssize_t brix_plat_sendfile(
    int out_fd,
    int in_fd,
    off_t * offset,
    size_t count
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `out_fd` | `int` | Output file descriptor |
| `in_fd` | `int` | Input file descriptor |
| `offset` | `off_t *` | File offset |
| `count` | `size_t` | Parameter |

**Returns**: `ssize_t` - 0 on success, -1 on error (errno set)


#### `brix_plat_setfsgid`

Set filesystem group ID (Linux only, stub on others).

```c
int brix_plat_setfsgid(
    gid_t gid
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `gid` | `gid_t` | Group ID |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_setfsuid`

Set filesystem user ID (Linux only, stub on others).

```c
int brix_plat_setfsuid(
    uid_t uid
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `uid` | `uid_t` | User ID |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_splice`

Zero-copy splice between file descriptors (Linux only).

```c
ssize_t brix_plat_splice(
    int in_fd,
    int out_fd,
    size_t nbytes,
    unsigned int flags
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `in_fd` | `int` | Input file descriptor |
| `out_fd` | `int` | Output file descriptor |
| `nbytes` | `size_t` | Number of bytes |
| `flags` | `unsigned int` | Operation flags |

**Returns**: `ssize_t` - 0 on success, -1 on error (errno set)


#### `brix_plat_sync`

Flush all filesystem buffers to stable storage.

```c
void brix_plat_sync();
```


#### `brix_plat_sync_tree`

Flush a specific filesystem tree to stable storage.

```c
int brix_plat_sync_tree(
    int dirfd
);
```

**Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `dirfd` | `int` | Parameter |

**Returns**: `int` - 0 on success, -1 on error (errno set)


#### `brix_plat_total_memory`

Get total system memory in bytes.

```c
uint64_t brix_plat_total_memory();
```

**Returns**: `uint64_t` - 0 on success, -1 on error (errno set)


---
## Data Structures

### `brix_plat_fs_watcher_t`

*Forward declaration - see platform-specific implementation for details.*


### `brix_plat_fs_event_t`

```c
struct brix_plat_fs_event_t {
    uint64_t timestamp;
    char[4096] path;
    uint32_t events;
};
```

**Members**:

| Name | Type | Description |
|------|------|-------------|
| `timestamp` | `uint64_t` | Event timestamp (platform-specific) |
| `path` | `char[4096]` | Path where the event occurred |
| `events` | `uint32_t` | Event type mask (BRIX_FS_EVENT_*) |


---
## Constants & Macros

### Unknown

```c
#define BRIX_COPY_F_MOVE 1  /**< Move data (not copy) */
#define BRIX_COPY_F_REFLINK 4  /**< Use reflink if possible */
#define BRIX_COPY_F_SAME_MOUNT 8  /**< Require same mount point */
#define BRIX_COPY_F_SPLICE 2  /**< Use splice semantics */
#define BRIX_EVENTFD_CLOEXEC 02000  /**< Set FD_CLOEXEC */
#define BRIX_EVENTFD_NONBLOCK 04000  /**< Set O_NONBLOCK */
#define BRIX_FADV_DONTNEED 4  /**< Don't need access */
#define BRIX_FADV_NOREUSE 5  /**< Access once only */
#define BRIX_FADV_NORMAL 0  /**< No special treatment */
#define BRIX_FADV_RANDOM 1  /**< Expect random access */
#define BRIX_FADV_SEQUENTIAL 2  /**< Expect sequential access */
#define BRIX_FADV_WILLNEED 3  /**< Will access soon */
#define BRIX_FS_EVENT_ATTRIB 0x010  /**< Metadata changed */
#define BRIX_FS_EVENT_CREATE 0x004  /**< File/directory created */
#define BRIX_FS_EVENT_DELETE 0x001  /**< File/directory deleted */
#define BRIX_FS_EVENT_RENAME 0x008  /**< File/directory renamed */
#define BRIX_FS_EVENT_WRITE 0x002  /**< File modified */
#define BRIX_PIPE_CLOEXEC 02000  /**< Set FD_CLOEXEC on both ends */
#define BRIX_PIPE_NONBLOCK 04000  /**< Set O_NONBLOCK on both ends */
#define BRIX_SPLICE_F_GIFT 8  /**< Pages are a gift */
#define BRIX_SPLICE_F_MORE 4  /**< More data coming */
#define BRIX_SPLICE_F_MOVE 1  /**< Move pages (not copy) */
#define BRIX_SPLICE_F_NONBLOCK 2  /**< Don't block */
#define BRIX_XATTR_CREATE 0x0002  /**< Fail if attr exists */
#define BRIX_XATTR_NOFOLLOW 0x0001  /**< Don't follow symlinks */
#define BRIX_XATTR_REPLACE 0x0004  /**< Fail if attr doesn't exist */
```

---
## Documentation Coverage

**Functions**: 28/28 (100.0%)
**Structs**: 1/2 (50.0%)
**Macros**: 26/26 (100%)
**Platform-Specific Functions**: 0

**By Section**:

| Section | Functions | Coverage |
|---------|-----------|----------|
| Unknown | 28 | - |

---
## Implementation Guide

### Adding a New Platform

1. Create platform directory: `src/platform/<platform>/`
2. Implement all PAL functions in `<platform>/posix_wrapper.c`
3. Add platform detection to `config` script
4. Update platform support matrix above
5. Add tests to `tests/platform/`

### Platform-Specific Implementation Notes

#### Linux
- Use native syscalls (memfd_create, sendfile, splice, etc.)
- Leverage io_uring for async I/O where available
- Use inotify for filesystem watching
- Implement seccomp for security confinement

#### macOS
- Use mkstemp+unlink for anonymous files
- Use sendfile with different signature
- Use kqueue for event monitoring
- Use FSEvents/kqueue for filesystem watching
- Link with `-framework Security` for SecRandomCopyBytes

#### Windows (Planned)
- Use CreateFile+FILE_FLAG_DELETE_ON_CLOSE for anonymous files
- Use TransmitFile for zero-copy transfers
- Use IOCP or select() for event handling
- Use ReadDirectoryChangesW for filesystem watching
- Use BCryptGenRandom for secure random
- Handle HANDLE vs file descriptor abstraction

---
## See Also

- [PAL Architecture](../../src/platform/ARCHITECTURE.md)
- [Platform Expansion Plan](PLATFORM_EXPANSION_PLAN.md)
- [macOS Support Guide](../refactor/macos-support-v3.0.md)

---

*Generated by `gen_pal_docs.py` on 2026-09-12*
