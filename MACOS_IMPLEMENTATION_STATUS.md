# macOS Support Implementation Status

**Last Updated:** Current Session  
**Phase:** 2 (Filesystem Monitoring)  
**Target:** v3.0.0

## ✅ Completed This Session

### 1. Platform Detection Headers

**Files Created:**
- `src/platform/platform.h` - Master platform detection and feature gating
- `src/platform/platform_api.h` - Unified API for platform-specific operations
- `src/platform/platform.c` - Common platform utilities (CPU count, memory info, etc.)
- `src/platform/README.md` - Documentation for the PAL

**Key Features:**
- Automatic platform detection via `uname -s`
- Compile-time feature gating (`BRIX_HAS_IO_URING`, `BRIX_HAS_SECCOMP`, etc.)
- Platform-specific compiler attributes
- Compile-time assertions to prevent invalid configurations

### 2. Platform Wrappers (Phase 1 & 2)

**Phase 1 - File I/O & Event Monitoring:**

Linux Wrappers:
- `src/platform/linux/posix_wrapper.c` - File I/O (fadvise, fsync, sendfile, splice, clonefile)
- `src/platform/linux/event_wrapper.c` - Event monitoring (epoll)

macOS Wrappers:
- `src/platform/darwin/posix_wrapper.c` - File I/O (fadvise stub, F_FULLFSYNC, sendfile translation, buffered splice, clonefile)
- `src/platform/darwin/event_wrapper.c` - Event monitoring (kqueue)

**Phase 2 - Filesystem Monitoring:**

Linux Wrappers:
- `src/platform/linux/fs_watcher.c` - inotify-based filesystem monitoring

macOS Wrappers:
- `src/platform/darwin/fs_watcher.c` - kqueue EVFILT_VNODE-based file monitoring

### 3. Build System Integration

**Modified Files:**
- `config` - Added platform detection and conditional feature gating

**Changes:**
1. Platform detection block (lines 7-60)
   - Auto-detects Linux/macOS via `uname -s`
   - Sets `BRIX_PLATFORM_LINUX` and `BRIX_PLATFORM_DARWIN` macros
   - Removes Linux-specific compiler flags on macOS
   - Detects Homebrew prefix on macOS
   - Validates macOS version (minimum 12.0)

2. Conditional feature detection
   - io_uring: Linux-only (skipped on macOS)
   - seccomp: Linux-only (skipped on macOS)
   - Ceph/RADOS: Linux-only (skipped on macOS with helpful message)

3. Platform-specific source files
   - Adds `platform.c` to all builds
   - Adds Linux wrappers on Linux
   - Adds macOS wrappers on Darwin
   - Links Security/CoreFoundation frameworks on macOS

## 📋 Build System Changes Detail

### Platform Detection (config:7-60)

```bash
case "$BRIX_PLATFORM" in
    Linux|linux)
        BRIX_CFLAGS="-DBRIX_PLATFORM_LINUX=1 -DBRIX_PLATFORM_DARWIN=0"
        BRIX_LIBS=""
        ;;
    
    Darwin|darwin)
        BRIX_CFLAGS="-DBRIX_PLATFORM_LINUX=0 -DBRIX_PLATFORM_DARWIN=1 -D_DARWIN_C_SOURCE"
        BRIX_LIBS="-framework Security -framework CoreFoundation"
        # Remove Linux-specific flags
        CFLAGS=$(echo "$CFLAGS" | sed 's/-fcf-protection=full//g')
        CFLAGS=$(echo "$CFLAGS" | sed 's/-fstack-clash-protection//g')
        ;;
esac
```

### Feature Gating (config:265-320)

```bash
# io_uring - Linux only
if [ "$BRIX_PLATFORM" = "linux" ] && [ -n "$BRIX_ENABLE_IO_URING" ] \
   && pkg-config --exists liburing; then
    # Enable io_uring
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: io_uring disabled (not available on macOS)"
    fi
fi

# seccomp - Linux only
if [ "$BRIX_PLATFORM" = "linux" ]; then
    # Enable seccomp
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: seccomp disabled (not available on macOS)"
    fi
fi

# Ceph - Linux only
if [ "$BRIX_PLATFORM" = "linux" ] && [ "${BRIX_WITHOUT_CEPH:-}" != "1" ]; then
    # Enable Ceph
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd storage backend: ceph/rados disabled (no macOS Ceph support)"
    fi
fi
```

## 🔧 Platform API Summary

### File I/O APIs

| Function | Linux | macOS | Status |
|----------|-------|-------|--------|
| `brix_platform_fadvise()` | `posix_fadvise()` | No-op (returns 0) | ✅ Implemented |
| `brix_platform_fsync_data()` | `fdatasync()` | `fcntl(F_FULLFSYNC)` + `fsync()` fallback | ✅ Implemented |
| `brix_platform_sync_tree()` | `syncfs()` | `sync()` | ✅ Implemented |
| `brix_platform_sendfile()` | `sendfile()` | `sendfile()` with signature translation | ✅ Implemented |
| `brix_platform_splice()` | `splice()` | Buffered copy (1MB ring buffer) | ✅ Implemented |
| `brix_platform_clonefile()` | Stub (ENOSYS) | `clonefile()` (APFS) | ✅ Implemented |

### Event Monitoring APIs

| Function | Linux | macOS | Status |
|----------|-------|-------|--------|
| `brix_platform_event_init()` | `epoll_create1()` | `kqueue()` | ✅ Implemented |
| `brix_platform_event_close()` | `close()` | `close()` | ✅ Implemented |
| `brix_platform_event_watch()` | `epoll_ctl()` | `kevent()` | ✅ Implemented |
| `brix_platform_event_wait()` | `epoll_wait()` | `kevent()` | ✅ Implemented |

### Utility APIs

| Function | Implementation | Status |
|----------|----------------|--------|
| `brix_platform_name()` | Returns "linux" or "darwin" | ✅ Implemented |
| `brix_platform_version()` | `uname()` | ✅ Implemented |
| `brix_platform_is_root()` | `geteuid()` | ✅ Implemented |
| `brix_platform_cpu_count()` | `sysconf()` / `sysctl(hw.ncpu)` | ✅ Implemented |
| `brix_platform_total_memory()` | `sysinfo()` / `sysctl(hw.memsize)` | ✅ Implemented |
| `brix_platform_available_memory()` | `sysinfo()` / `vm_statistics` | ✅ Implemented |

## 🚧 Remaining Work (Phase 2+)

### Phase 2: Filesystem Monitoring (Weeks 3-4)

**Missing Implementations:**
- `brix_fs_watcher_create()` - inotify (Linux) / FSEvents (macOS)
- `brix_fs_watcher_add()` - inotify_add_watch (Linux) / FSEvents stream (macOS)
- `brix_fs_watcher_remove()` - inotify_rm_watch (Linux) / FSEvents cancel (macOS)
- `brix_fs_watcher_next()` - inotify event read (Linux) / FSEvents callback (macOS)

**Files to Create:**
- `src/platform/linux/inotify_wrapper.c`
- `src/platform/darwin/fsevents_wrapper.c`

### Phase 3: Security Wrappers (Weeks 5-6)

**Missing Implementations:**
- `brix_security_init()` - seccomp_init/load (Linux) / sandbox_exec stub (macOS)
- `brix_security_enable_audit()` - seccomp audit mode (Linux) / stub (macOS)
- `brix_security_load_profile()` - JSON profile (Linux) / .sb profile (macOS)

**Files to Create:**
- `src/platform/linux/seccomp_wrapper.c` (refactor existing `src/core/seccomp/`)
- `src/platform/darwin/sandbox_wrapper.c`

### Phase 4: Async I/O (Weeks 7-8)

**Missing Implementations:**
- `brix_aio_create()` - io_uring_setup (Linux) / thread pool (macOS)
- `brix_aio_read()` - io_uring_prep_readv (Linux) / thread task (macOS)
- `brix_aio_write()` - io_uring_prep_writev (Linux) / thread task (macOS)
- `brix_aio_wait()` - io_uring_enter (Linux) / thread completion (macOS)

**Files to Create:**
- `src/platform/linux/io_uring_wrapper.c` (refactor existing Phase 44 code)
- `src/platform/darwin/aio_wrapper.c`

### Phase 5: Integration & Testing (Weeks 9-12)

**Integration Tasks:**
- Update existing code to use platform API instead of direct syscalls
- Audit all `#if __linux__` and `#if __APPLE__` occurrences
- Migrate to platform wrappers

**Testing Tasks:**
- macOS build verification
- Unit tests for all platform wrappers
- Integration tests on macOS
- Performance benchmarking (Linux vs macOS)

## 📊 Code Coverage

### Files Modified: 1
- `config` - Platform detection and conditional builds

### Files Created: 13
- `src/platform/platform.h`
- `src/platform/platform_api.h`
- `src/platform/platform.c`
- `src/platform/README.md`
- `src/platform/linux/posix_wrapper.c`
- `src/platform/linux/event_wrapper.c`
- `src/platform/linux/fs_watcher.c`
- `src/platform/darwin/posix_wrapper.c`
- `src/platform/darwin/event_wrapper.c`
- `src/platform/darwin/fs_watcher.c`
- `MACOS_IMPLEMENTATION_STATUS.md` (this file)
- `docs/01-getting-started/macos-quickstart.md`
- `verify_macos_support.sh`

### Total Lines Added: ~2,400
- Headers: ~600 lines
- Implementations: ~1,400 lines
- Documentation: ~400 lines

## 🎯 Next Steps

### Immediate (This Week)

1. **Test Linux Build (Regression)**
   ```bash
   ./configure --with-stream --with-threads --add-module=$(pwd)
   make -j$(nproc)
   objs/nginx -t
   ```

2. **Test macOS Build (First Pass)**
   ```bash
   ./configure --with-stream --with-threads --add-module=$(pwd)
   make -j$(sysctl -n hw.ncpu)
   objs/nginx -V 2>&1 | grep -i brix
   ```

3. **Fix Compilation Errors**
   - Address any macOS-specific warnings
   - Ensure platform.h is included everywhere needed

### Short-Term (Next 2 Weeks)

4. **Implement Filesystem Monitoring**
   - inotify wrapper (Linux)
   - FSEvents wrapper (macOS)

5. **Refactor Existing Code**
   - Update cache invalidation to use `brix_fs_watcher_*`
   - Update event loops to use `brix_platform_event_*`

### Medium-Term (Next Month)

6. **Security Wrapper Implementation**
   - Full seccomp integration (Linux)
   - sandbox_exec stub (macOS, Phase 2)
   - Full sandbox_exec (macOS, Phase 4)

7. **Async I/O Integration**
   - io_uring backend (Linux, Phase 44)
   - Thread pool backend (macOS)

## 📝 Known Issues

### None Yet

Build hasn't been tested on either platform after these changes.

## 📚 References

- Full specification: `docs/refactor/macos-support-v3.0.md` (2585 lines)
- Platform API: `src/platform/platform_api.h`
- Build configuration: `config` (lines 7-60, 265-320, 1810-1830)
- CVMFS platform shim: `shared/cvmfs/platform/` (pre-existing minimal implementation)

---

**Status:** Phase 1 Complete (Platform Detection & Build System)  
**Next Phase:** Phase 2 (Filesystem Monitoring & Event Integration)  
**Estimated Completion:** 8-12 weeks for full feature parity
