# Platform Abstraction Layer (PAL) Architecture

## Overview

The Platform Abstraction Layer (PAL) provides a clean, #ifdef-free interface for all platform-specific operations. Similar to the VFS layer, PAL uses runtime function pointers or compile-time selected implementations to abstract away platform differences.

## Design Goals

1. **Zero #ifdef in business logic** - All platform detection happens in PAL implementation files
2. **Clean API** - Source code calls `brix_plat_*()` functions, never platform-specific APIs
3. **Extensible** - Easy to add new platforms (Windows, BSD, etc.)
4. **Architecture-aware** - Supports x86_64, arm64, and future architectures
5. **Performance** - Zero runtime overhead where possible (compile-time selection)

## Directory Structure

```
src/platform/
├── README.md                    # Usage guide
├── platform.h                   # Core types and platform detection
├── platform_api.h               # Public API (what source code includes)
├── platform.c                   # Platform detection & initialization
├── platform_endian_compat.h     # Byte-order compatibility (temporary)
│
├── generic/                     # Platform-agnostic helpers
│   ├── endian.c                 # Byte-order operations
│   └── atomic.c                 # Atomic operations
│
├── linux/                       # Linux implementation
│   ├── posix_wrapper.c          # POSIX syscalls (openat2, etc.)
│   ├── event_wrapper.c          # epoll/eventfd
│   ├── fs_watcher.c             # inotify
│   ├── security_wrapper.c       # seccomp/capabilities
│   ├── copy_range.c             # copy_file_range
│   └── aio_wrapper.c            # io_uring
│
├── darwin/                      # macOS implementation
│   ├── posix_wrapper.c          # POSIX syscalls (mkstemp, etc.)
│   ├── event_wrapper.c          # kqueue
│   ├── fs_watcher.c             # FSEvents/kqueue
│   ├── security_wrapper.c       # sandbox_exec (stub)
│   ├── copy_range.c             # clonefile/copyfile
│   └── aio_wrapper.c            # Thread pool
│
└── windows/                     # Windows implementation (future)
    ├── posix_wrapper.c
    ├── event_wrapper.c
    ├── fs_watcher.c
    ├── security_wrapper.c
    ├── copy_range.c
    └── aio_wrapper.c
```

The associated documentation is now under `docs/`: [ARCHITECTURE.md](ARCHITECTURE.md).

## API Categories

### 1. File I/O Operations
```c
// Anonymous file descriptors (memfd on Linux, O_TMPFILE/mkstemp on macOS)
int brix_plat_anon_fd(const char *name, const char *dir);

// File access hints
int brix_plat_fadvise(int fd, off_t offset, off_t len, int advice);

// Data synchronization
int brix_plat_fsync_data(int fd);
int brix_plat_sync_tree(int dirfd);

// Zero-copy operations
ssize_t brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
ssize_t brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags);
ssize_t brix_plat_copy_range(int in_fd, off_t in_off, int out_fd, off_t out_off, size_t len, unsigned int flags);
```

### 2. Event & Notification
```c
// Event loop initialization
int brix_plat_event_init(void);
int brix_plat_event_wait(int efd, int timeout_ms);

// File system watching
int brix_plat_fs_watcher_init(brix_plat_fs_watcher_t *watcher);
int brix_plat_fs_watcher_add(brix_plat_fs_watcher_t *watcher, const char *path, uint32_t events);
int brix_plat_fs_watcher_next(brix_plat_fs_watcher_t *watcher, brix_plat_fs_event_t *event, int timeout_ms);
```

### 3. Security & Confinement
```c
// Security context
int brix_plat_security_init(const char *profile);
int brix_plat_security_enter(const char *profile);

// Credential manipulation
int brix_plat_setfsuid(uid_t uid);
int brix_plat_setfsgid(gid_t gid);
```

### 4. Random & Cryptography
```c
// Secure random
int brix_plat_random(void *buf, size_t len);
```

### 5. Extended Attributes
```c
// Xattr operations (unified signature across platforms)
ssize_t brix_plat_getxattr(const char *path, const char *name, void *value, size_t size);
int brix_plat_setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
int brix_plat_removexattr(const char *path, const char *name);
ssize_t brix_plat_listxattr(const char *path, char *list, size_t size);
```

### 6. Process & Execution
```c
// Process execution
int brix_plat_execvpe(const char *file, char *const argv[], char *const envp[]);

// Pipe creation
int brix_plat_pipe2(int pipefd[2], int flags);
```

### 7. Platform Information
```c
const char *brix_plat_name(void);
const char *brix_plat_version(void);
const char *brix_plat_arch(void);
int brix_plat_cpu_count(void);
uint64_t brix_plat_total_memory(void);
uint64_t brix_plat_available_memory(void);
```

## Implementation Strategy

### Compile-Time Selection (Preferred)
For performance-critical paths, use compile-time platform detection:

```c
// platform_internal.h - included by implementation files only
#if BRIX_PLATFORM_LINUX
    // Linux implementation
#elif BRIX_PLATFORM_DARWIN
    // macOS implementation
#endif
```

Source code NEVER includes `platform_internal.h` - only `platform_api.h`.

### Runtime Dispatch (When Needed)
For features that vary within a platform (kernel versions, feature flags):

```c
typedef struct {
    int (*anon_fd)(const char *name, const char *dir);
    ssize_t (*sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);
    // ...
} brix_plat_ops_t;

static brix_plat_ops_t plat_ops;

// CURRENT: Minimal stub implementation
// FUTURE: May detect capabilities and set function pointers
void brix_plat_init(void) {
    // Currently returns 0 (stub)
    // Future enhancement: plat_ops.anon_fd = has_memfd ? linux_memfd_anon_fd : linux_tmpfile_anon_fd;
}
```

## Migration Plan

### Phase 1: Consolidate Existing Wrappers ✅
- Move all `#ifdef` logic into platform-specific implementation files
- Create clean `brix_plat_*()` API
- Update all callers to use PAL API

### Phase 2: Add Missing Wrappers
- Identify remaining platform-specific code
- Add PAL wrappers for each
- Migrate callers

### Phase 3: Architecture Support
- Add architecture detection (x86_64 vs arm64)
- Optimize for each architecture (SIMD, cache lines, etc.)
- Add architecture-specific wrappers where needed

### Phase 4: Windows Support (Future)
- Implement Windows versions of all PAL APIs
- Use Win32 APIs, POSIX compatibility layer, or WSL

## Usage Example

### Before (❌ #ifdef clutter)
```c
#include <sys/xattr.h>

#if defined(__APPLE__) && defined(__MACH__)
    n = getxattr(path, name, value, size, 0, 0);
#else
    n = getxattr(path, name, value, size);
#endif
```

### After (✅ Clean PAL API)
```c
#include "platform/platform_api.h"

n = brix_plat_getxattr(path, name, value, size);
```

## Build Integration

The `config` script selects platform-specific source files:

```bash
if [ "$BRIX_PLATFORM" = "linux" ]; then
    PAL_SRCS="$ngx_addon_dir/src/platform/linux/*.c"
elif [ "$BRIX_PLATFORM" = "darwin" ]; then
    PAL_SRCS="$ngx_addon_dir/src/platform/darwin/*.c"
fi
```

## Testing

Each PAL function should have:
1. Unit tests in `tests/platform/`
2. Integration tests verifying behavior matches native API
3. Cross-platform consistency tests

## Platform Support Matrix

| Feature | Linux | macOS | Windows | Notes |
|---------|-------|-------|---------|-------|
| `anon_fd` | ✅ memfd | ✅ mkstemp | 🔲 HANDLE | |
| `sendfile` | ✅ sendfile | ✅ sendfile | 🔲 TransmitFile | |
| `splice` | ✅ splice | ❌ stub | 🔲 | macOS uses buffered copy |
| `copy_range` | ✅ copy_file_range | ✅ clonefile | 🔲 | |
| `event_init` | ✅ epoll | ✅ kqueue | 🔲 IOCP | |
| `fs_watcher` | ✅ inotify | ✅ FSEvents | 🔲 ReadDirectoryChanges | |
| `security` | ✅ seccomp | ❓ sandbox_exec | 🔲 Job Objects | |
| `getxattr` | ✅ getxattr | ✅ getxattr | 🔲 GetFileSecurity | macOS has 6-param signature |
| `random` | ✅ getrandom | ✅ SecRandom | 🔲 BCryptGenRandom | |
| `execvpe` | ✅ execvpe | ✅ posix_spawn | 🔲 CreateProcess | |

Legend: ✅ Implemented, ❌ Not available (stubbed), 🔲 Future, ❓ Needs investigation
