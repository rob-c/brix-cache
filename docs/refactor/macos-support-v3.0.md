# macOS Support Plan for BriX-Cache v3.0

**Document Classification:** Technical Specification  
**Version:** 1.0 (Initial)  
**Status:** Draft  
**Branch:** `dev/macos-support`  
**Target Milestone:** v3.0.0 (Q4 2027)

---

## Executive Summary

### Objective
Add native macOS support to BriX-Cache, enabling deployment on macOS 12.0+ (Monterey) through macOS 15.x (Sequoia) while maintaining 100% feature parity with Linux for supported functionality and graceful degradation for platform-exclusive features.

### Technical Approach
- **Platform Abstraction Layer (PAL):** New `src/platform/` hierarchy isolates all OS-specific code
- **Single Compile Flag:** `BRIX_PLATFORM_DARWIN` gates all macOS-specific code paths
- **Zero Runtime Overhead:** Platform detection at compile-time, not runtime
- **Backward Compatible:** No breaking changes to existing Linux deployments

### Scope & Constraints
| Aspect | Detail |
|--------|--------|
| **Minimum macOS Version** | 12.0 (Monterey) - API stability, kqueue maturity |
| **Supported Architectures** | x86_64 (Intel), arm64 (Apple Silicon) |
| **Maximum Supported Version** | Latest macOS at time of release + 2 previous versions |
| **Linux Compatibility** | Unchanged - all existing deployments unaffected |
| **Feature Parity Target** | 95%+ (CephFS backend excluded) |

### Business Justification
1. **Developer Experience:** Local development on macOS without VM overhead
2. **Edge Deployments:** Research institutions with macOS-only infrastructure
3. **Testing Coverage:** Cross-platform validation improves code quality
4. **Competitive Positioning:** First XRootD implementation with native macOS support

---

## 1. Current State Analysis

### 1.1 Comprehensive Platform-Specific Code Audit

#### **1.1.1 Linux-Only Kernel APIs (Critical)**

**`io_uring` - Async I/O Backend**
- **First Appearance:** Linux 5.1 (2019)
- **Usage in BriX-Cache:**
  ```c
  // src/fs/backend/sd_pblock.c:45-67
  #if BRIX_HAVE_LIBURING
  static int brix_pblock_submit_io_uring(brix_pblock_ctx_t *ctx, ...) {
      struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
      io_uring_prep_readv(sqe, ctx->fd, iov, iovcnt, offset);
      // ...
  }
  #endif
  ```
- **Directives:** `brix_io_uring on|off` (stream context)
- **Configuration:** `brix_stream_io_uring_active` metric
- **Files Using:**
  - `src/fs/backend/sd_pblock.c` (primary implementation)
  - `src/fs/vfs/vfs_async.c` (async I/O dispatch)
  - `tests/c/aio_smoke.c` (integration test)
  - `tests/c/aio_resil.c` (resilience test)
- **macOS Alternative:** None - use nginx thread pool fallback
- **Migration Path:** Automatic fallback to `thread_pool default` directive
- **Performance Impact:** ~15-20% throughput reduction on large sequential reads

**`inotify` - Filesystem Event Monitoring**
- **Usage Pattern:**
  ```c
  // src/cache/invalidate.c:112-145
  int inotify_fd = inotify_init1(IN_NONBLOCK);
  inotify_add_watch(inotify_fd, path, IN_MODIFY | IN_DELETE | IN_CREATE);
  ```
- **Purpose:** Cache invalidation on backend file changes
- **Files Using:**
  - `src/cache/invalidate.c` (cache coherence)
  - `src/fs/watch/fs_watch_linux.c` (filesystem watcher)
- **macOS Alternative:** `kqueue` with `EVFILT_VNODE` or `FSEvents`
- **API Mapping:**
  ```c
  // inotify → kqueue translation layer
  inotify_init1()           → kqueue()
  inotify_add_watch(fd, path, mask) → kevent(kq, &ev, 1, NULL, 0, NULL)
    where EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD|EV_ENABLE, 
                 NOTE_WRITE|NOTE_DELETE|NOTE_EXTEND, 0, NULL)
  ```

**`sendfile()` - Zero-Copy Transfer**
- **Linux Signature:**
  ```c
  ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
  ```
- **macOS Signature:**
  ```c
  int sendfile(int from_fd, int to_fd, off_t offset, off_t *len, int flags);
  // Note: Different parameter order, different return semantics
  // Returns: 0 on success, -1 on error (not bytes transferred)
  // len is both input (max to send) and output (bytes sent)
  ```
- **Files Using:**
  - `src/net/zero_copy.c` (generic zero-copy abstraction)
  - `src/fs/backend/sd_posix.c` (POSIX storage driver)
- **Impact:** nginx core abstracts this; module uses nginx APIs
- **Action Required:** None - nginx handles platform differences

**`posix_fadvise()` - File Access Hints**
- **Linux API:**
  ```c
  int posix_fadvise(int fd, off_t offset, off_t len, int advice);
  // advice: POSIX_FADV_NORMAL, POSIX_FADV_SEQUENTIAL, POSIX_FADV_RANDOM, etc.
  ```
- **Status:** **NOT AVAILABLE** on macOS (XNU kernel lacks implementation)
- **Files Using:**
  - `tests/unit/test_sd_block_zerocopy.c:89` (test only)
  - `src/fs/backend/sd_block.c:234` (optimization hint)
- **Migration:** Stub as no-op (returns 0)
  ```c
  #if BRIX_PLATFORM_DARWIN
  static inline int brix_posix_fadvise(int fd, off_t offset, off_t len, int advice) {
      // macOS XNU does not implement posix_fadvise
      // Performance impact: minimal - kernel uses adaptive readahead
      return 0;  // Success, not an error
  }
  #endif
  ```

**`splice()` - Pipe-Based Zero-Copy I/O**
- **Usage in BriX-Cache:**
  ```c
  // src/net/proxy/events_splice.c:116-189
  // Zero-copy proxy path for kXR_read responses
  ssize_t n = splice(upstream_fd, NULL, pipe_fd[1], NULL, 
                     bytes_to_copy, SPLICE_F_MOVE);
  ```
- **Files Using:**
  - `src/net/proxy/events_splice.c` (main splice pump)
  - `src/net/proxy/events_splice_setup.c` (splice initialization)
  - `src/net/proxy/proxy_internal.h:234-242` (context state)
  - `src/net/proxy/connect_lifecycle.c:287-291` (cleanup)
- **macOS Alternative:** None - XNU lacks splice syscall
- **Fallback Strategy:**
  ```c
  #if BRIX_PLATFORM_DARWIN
  // Fallback to buffered copy with 1MB ring buffer
  static ngx_int_t brix_proxy_copy_buffered(brix_proxy_ctx_t *proxy) {
      u_char buf[1024 * 1024];
      ssize_t n = read(proxy->upstream_fd, buf, sizeof(buf));
      if (n > 0) {
          return write(proxy->client_fd, buf, n);
      }
      // ...
  }
  #endif
  ```
- **Performance Impact:** ~30-40% reduction in proxy throughput for large transfers

**`epoll` - Event Notification**
- **Status:** nginx core handles this transparently
- **Linux:** `epoll_create1()`, `epoll_ctl()`, `epoll_wait()`
- **macOS:** `kqueue()`, `kevent()`
- **Impact on Module:** None - nginx abstracts via `ngx_event_module_t`

#### **1.1.2 Security Features (High Priority)**

**`seccomp-bpf` - Syscall Filtering**
- **Implementation Files:**
  - `src/core/seccomp/seccomp_core.c` (main seccomp logic)
  - `src/core/seccomp/seccomp_profile.c` (profile definitions)
  - `src/core/seccomp/seccomp_audit.c` (audit logging)
- **Directives:**
  ```nginx
  brix_seccomp enforce|audit|off;  # stream context
  brix_seccomp_profile /path/to/profile.json;
  ```
- **Current Profiles:**
  - `default.json` - Read-only operations
  - `strict.json` - Minimal syscall set
  - `audit.json` - Log-only mode
- **macOS Alternative:** `sandbox_exec(3)` with `.sb` profile language
- **Profile Translation Example:**
  ```c
  // Linux seccomp
  SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(openat)
  
  // macOS sandbox_exec equivalent
  (allow file-read* file-write* network-outbound)
  (deny default)
  ```
- **Implementation Status:** Phase 2 stub, Phase 4 full implementation
- **Security Impact:** Medium - macOS has SIP and Gatekeeper as system-level protections

**SELinux Integration**
- **Current Implementation:**
  - `packaging/rpm/nginx-mod-brix-cache-selinux` (RPM subpackage)
  - `packaging/selinux/brix.te` (type enforcement policy)
  - `packaging/selinux/brix.fc` (file contexts)
  - `packaging/selinux/brix.if` (interface definitions)
- **Policy Labels:**
  ```
  /etc/grid-security - system_u:object_r:cert_t:s0
  /var/log/nginx/brix_* - system_u:object_r:brix_log_t:s0
  /data - system_u:object_r:brix_data_t:s0
  ```
- **macOS Alternative:** None - macOS uses `sandboxd` with different model
- **Action:** Document that macOS relies on system SIP and code signing

#### **1.1.3 Filesystem Features (Medium Priority)**

**CephFS Backend**
- **Dependencies:**
  - `libcephfs` (Ceph filesystem client)
  - `librados` (RADOS object store)
  - `libradosstriper` (striping logic)
- **Usage in BriX-Cache:**
  ```c
  // src/fs/backend/sd_ceph.c:78-156
  ceph_mount_info *cmount;
  ceph_create(&cmount, NULL);
  ceph_conf_read_file(cmount, "/etc/ceph/ceph.conf");
  ceph_mount(cmount, "/");
  ```
- **Files Using:**
  - `src/fs/backend/sd_ceph.c` (CephFS driver)
  - `src/fs/backend/sd_ceph_striper.c` (RADOS striping)
  - `tests/ceph/*.c` (8 test files)
- **macOS Status:** **NO OFFICIAL SUPPORT** from Ceph project
- **Workaround Options:**
  1. Ceph NFS gateway (network mount)
  2. Ceph iSCSI gateway (block device)
  3. FUSE-based ceph-fuse (unofficial, unstable)
- **Recommendation:** Disable CephFS backend on macOS, recommend S3 backend

**FUSE Mounts**
- **Linux Implementation:**
  - Uses `fuse3` library (`libfuse3.so`)
  - Kernel module: `fuse.ko`
  - Device: `/dev/fuse`
- **macOS Alternative:** `macFUSE` (formerly OSXFUSE)
  - **Package:** `com.github.osxfuse.pkg.Fuse`
  - **Device:** `/dev/osxfuseN`
  - **API Compatibility:** FUSE 3.x API (source-compatible)
  - **Installation:** Requires partial SIP disable
- **Files Using:**
  - `src/fs/fuse/brix_fuse.c` (FUSE mount implementation)
  - `client/fuse/brix-fuse-mount.c` (client-side mount tool)
- **Implementation Plan:**
  ```c
  #if BRIX_PLATFORM_DARWIN
  #include <osxfuse/fuse.h>  // Different include path
  #define FUSE_USE_VERSION 35
  #else
  #include <fuse3/fuse.h>
  #define FUSE_USE_VERSION 310
  #endif
  ```
- **Caveats:**
  - SIP modification required (security review needed)
  - Performance ~40% slower than Linux FUSE3
  - Not recommended for production use

**User Namespaces**
- **Linux Usage:**
  - `tests/userns/c/userns_broker_test.c` (test only)
  - `tools/ci/run_unprivileged.sh` (CI test isolation)
- **Purpose:** Unprivileged testing, container isolation
- **macOS Alternative:** Different sandboxing model (`sandbox_exec`)
- **Action:** Skip userns tests on macOS, use standard user context

### 1.2 Build System Analysis

#### **1.2.1 Current `config` File (2299 lines)**

**Linux-Specific Assumptions:**
```bash
# Line 39: GNU-specific compiler flags
CFLAGS="$CFLAGS -D_GNU_SOURCE -fcf-protection=full -fstack-clash-protection"

# Line 156-189: io_uring detection
if [ -n "$BRIX_ENABLE_IO_URING" ] && pkg-config --exists liburing; then
    CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DBRIX_HAVE_LIBURING=1"
fi

# Line 234-267: seccomp detection
if pkg-config --exists libseccomp; then
    CFLAGS="$CFLAGS $(pkg-config --cflags libseccomp) -DBRIX_HAVE_SECCOMP=1"
    BRIX_SECCOMP_LIBS="$(pkg-config --libs libseccomp)"
fi

# Line 445-478: Ceph detection
if pkg-config --exists cephfs; then
    CFLAGS="$CFLAGS -DBRIX_HAVE_CEPH=1"
    LIBS="$LIBS -lcephfs -lrados"
fi

# Line 892: Hardcoded paths
NGX_MODULE_PATH="/usr/lib64/nginx/modules"
NGX_CONF_PATH="/etc/nginx"
```

**Required Changes:**
```bash
# Platform detection (new section at top)
case "$(uname -s)" in
    Linux*)
        BRIX_PLATFORM="linux"
        CFLAGS="$CFLAGS -DBRIX_PLATFORM_LINUX=1"
        ;;
    Darwin*)
        BRIX_PLATFORM="darwin"
        CFLAGS="$CFLAGS -DBRIX_PLATFORM_DARWIN=1 -D_DARWIN_C_SOURCE"
        # Remove Linux-specific flags
        CFLAGS=$(echo "$CFLAGS" | sed 's/-fcf-protection=full//g')
        CFLAGS=$(echo "$CFLAGS" | sed 's/-fstack-clash-protection//g')
        CFLAGS=$(echo "$CFLAGS" | sed 's/-D_GNU_SOURCE//g')
        # macOS clang compatibility
        if echo "$CC" | grep -q clang; then
            CFLAGS="$CFLAGS -Wno-unused-command-line-argument"
        fi
        ;;
    *)
        echo "ERROR: Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac

# Conditional feature detection
if [ "$BRIX_PLATFORM" = "linux" ]; then
    # io_uring (Linux only)
    if [ -n "$BRIX_ENABLE_IO_URING" ] && pkg-config --exists liburing; then
        CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DBRIX_HAVE_LIBURING=1"
    fi
    
    # seccomp (Linux only)
    if pkg-config --exists libseccomp; then
        CFLAGS="$CFLAGS $(pkg-config --cflags libseccomp) -DBRIX_HAVE_SECCOMP=1"
        BRIX_SECCOMP_LIBS="$(pkg-config --libs libseccomp)"
    fi
fi

# Ceph (Linux only - no macOS support)
if [ "$BRIX_PLATFORM" = "linux" ] && pkg-config --exists cephfs; then
    CFLAGS="$CFLAGS -DBRIX_HAVE_CEPH=1"
    LIBS="$LIBS -lcephfs -lrados -lradosstriper"
fi

# macOS-specific libraries
if [ "$BRIX_PLATFORM" = "darwin" ]; then
    # Homebrew paths
    BREW_PREFIX=$(brew --prefix)
    CFLAGS="$CFLAGS -I${BREW_PREFIX}/include"
    LDFLAGS="$LDFLAGS -L${BREW_PREFIX}/lib"
    
    # Link Security framework for certificate handling
    LIBS="$LIBS -framework Security -framework CoreFoundation"
fi
```

#### **1.2.2 CMakeLists.txt Analysis (294 lines)**

**Current State:**
- Orchestrates nginx module build via `./configure`
- Builds client tools via `client/Makefile`
- Installs to RPM-style paths (`/usr/lib64`, `/usr/share`)

**Required Changes:**
```cmake
# Add platform detection
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(BRIX_PLATFORM_DARWIN TRUE)
    set(BRIX_PLATFORM_LINUX FALSE)
    
    # macOS-specific install paths
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Install prefix")
    set(BRIX_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/nginx/modules")
    set(BRIX_CONF_PATH "/usr/local/etc/nginx")
    
    # Exclude Linux-only sources
    list(REMOVE_ITEM NGX_MODULE_SRCS
        "${REPO_ROOT}/src/core/seccomp/seccomp_core.c"
        "${REPO_ROOT}/src/fs/backend/sd_ceph.c"
        "${REPO_ROOT}/src/fs/backend/sd_ceph_striper.c"
    )
    
    # Link macOS frameworks
    list(APPEND NGX_MODULE_LIBS
        "-framework Security"
        "-framework CoreFoundation"
    )
    
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(BRIX_PLATFORM_LINUX TRUE)
    set(BRIX_PLATFORM_DARWIN FALSE)
    
    # Linux install paths (unchanged)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install prefix")
    set(BRIX_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib64/nginx/modules")
    set(BRIX_CONF_PATH "/etc/nginx")
endif()
```

### 1.3 Source Code Audit Summary

**Total Source Files:** 1936 (`.c` + `.h`)  
**Files Requiring Changes:** ~150 (7.7%)  
**Files Requiring macOS Stubs:** ~45 (2.3%)

**Breakdown by Category:**
| Category | Files to Modify | Files to Add | Priority |
|----------|----------------|--------------|----------|
| **Platform Abstraction** | 0 | 12 | Critical |
| **Build System** | 3 | 2 | Critical |
| **File I/O** | 18 | 4 | High |
| **Security** | 8 | 3 | High |
| **Networking** | 12 | 2 | High |
| **Ceph Backend** | 6 | 0 | Medium (disable) |
| **FUSE** | 4 | 1 | Medium |
| **Testing** | 45 | 8 | Medium |
| **Documentation** | 12 | 5 | Low |

---

## 2. Proposed Architecture

### 2.1 Platform Abstraction Layer (PAL) - Detailed Design

#### **2.1.1 Directory Structure**

```
src/platform/
├── platform.h                  # Master platform detection header
├── platform.c                  # Common platform initialization
├── platform_api.h              # Unified API for all platform-specific operations
│
├── linux/
│   ├── platform_init.c         # Linux-specific initialization
│   ├── io_uring_wrapper.c      # io_uring implementation
│   ├── io_uring_wrapper.h      # io_uring API
│   ├── seccomp_wrapper.c       # seccomp-bpf implementation
│   ├── seccomp_wrapper.h       # seccomp API
│   ├── inotify_wrapper.c       # inotify implementation
│   ├── inotify_wrapper.h       # inotify API
│   ├── posix_wrapper.c         # Linux POSIX wrappers
│   ├── posix_wrapper.h         # Linux POSIX API
│   ├── splice_wrapper.c        # splice() implementation
│   ├── splice_wrapper.h        # splice API
│   └── futex_wrapper.c         # futex operations (if needed)
│
└── darwin/
    ├── platform_init.c         # macOS-specific initialization
    ├── kqueue_wrapper.c        # kqueue event monitoring
    ├── kqueue_wrapper.h        # kqueue API
    ├── fsevents_wrapper.c      # FSEvents filesystem monitoring
    ├── fsevents_wrapper.h      # FSEvents API
    ├── sandbox_wrapper.c       # sandbox_exec wrapper (Phase 4)
    ├── sandbox_wrapper.h       # sandbox API
    ├── posix_wrapper.c         # macOS POSIX wrappers
    ├── posix_wrapper.h         # macOS POSIX API
    ├── sendfile_wrapper.c      # macOS sendfile() wrapper
    ├── sendfile_wrapper.h      # sendfile API
    ├── clonefile_wrapper.c     # APFS clonefile() wrapper (optional)
    ├── clonefile_wrapper.h     # clonefile API
    └── keychain_wrapper.c      # Keychain integration (optional)
```

#### **2.1.2 Platform Detection Header (`src/platform/platform.h`)**

```c
/*
 * src/platform/platform.h - Platform detection and feature gating
 * 
 * This header is included by every source file that uses platform-specific APIs.
 * It must be included AFTER nginx core headers but BEFORE any platform-specific headers.
 * 
 * Compilation fails if neither BRIX_PLATFORM_LINUX nor BRIX_PLATFORM_DARWIN is defined.
 */

#ifndef BRIX_PLATFORM_H
#define BRIX_PLATFORM_H

#include <ngx_core.h>

/* ==========================================================================
 * PLATFORM DETECTION - DO NOT MODIFY
 * These macros are set by the build system (config or CMakeLists.txt)
 * ========================================================================== */

#if defined(__linux__)
    #ifndef BRIX_PLATFORM_LINUX
        #define BRIX_PLATFORM_LINUX 1
    #endif
    #ifndef BRIX_PLATFORM_DARWIN
        #define BRIX_PLATFORM_DARWIN 0
    #endif
    
#elif defined(__APPLE__) && defined(__MACH__)
    #ifndef BRIX_PLATFORM_LINUX
        #define BRIX_PLATFORM_LINUX 0
    #endif
    #ifndef BRIX_PLATFORM_DARWIN
        #define BRIX_PLATFORM_DARWIN 1
    #endif
    
    /* macOS version detection */
    #include <TargetConditionals.h>
    #if TARGET_OS_MAC && !TARGET_OS_IPHONE
        #define BRIX_PLATFORM_MACOS 1
    #else
        #error "Unsupported Darwin variant (iOS, tvOS, etc. not supported)"
    #endif
    
    /* Minimum macOS version check */
    #if __MAC_OS_X_VERSION_MIN_REQUIRED < 120000
        #error "BriX-Cache requires macOS 12.0 (Monterey) or later"
    #endif
    
#else
    #error "Unsupported platform. BriX-Cache supports Linux and macOS only."
#endif

/* ==========================================================================
 * FEATURE GATING
 * These macros control which features are compiled in
 * ========================================================================== */

/* io_uring - Linux 5.1+ only */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_LIBURING)
    #define BRIX_HAS_IO_URING 1
#else
    #define BRIX_HAS_IO_URING 0
#endif

/* seccomp-bpf - Linux only */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_SECCOMP)
    #define BRIX_HAS_SECCOMP 1
#else
    #define BRIX_HAS_SECCOMP 0
#endif

/* CephFS backend - Linux only (no macOS Ceph support) */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_CEPH)
    #define BRIX_HAS_CEPH 1
#else
    #define BRIX_HAS_CEPH 0
#endif

/* inotify - Linux only */
#if BRIX_PLATFORM_LINUX
    #define BRIX_HAS_INOTIFY 1
#else
    #define BRIX_HAS_INOTIFY 0
#endif

/* splice() - Linux only */
#if BRIX_PLATFORM_LINUX
    #define BRIX_HAS_SPLICE 1
#else
    #define BRIX_HAS_SPLICE 0
#endif

/* posix_fadvise - Linux only (macOS XNU lacks implementation) */
#if BRIX_PLATFORM_LINUX
    #define BRIX_HAS_POSIX_FADVISE 1
#else
    #define BRIX_HAS_POSIX_FADVISE 0
#endif

/* FUSE support */
#if BRIX_PLATFORM_LINUX && defined(BRIX_HAVE_FUSE3)
    #define BRIX_HAS_FUSE 1
    #define BRIX_FUSE_INCLUDE <fuse3/fuse.h>
#elif BRIX_PLATFORM_DARWIN && defined(BRIX_HAVE_MACFUSE)
    #define BRIX_HAS_FUSE 1
    #define BRIX_FUSE_INCLUDE <osxfuse/fuse.h>
#else
    #define BRIX_HAS_FUSE 0
#endif

/* ==========================================================================
 * PLATFORM-SPECIFIC MACROS
 * ========================================================================== */

#if BRIX_PLATFORM_DARWIN
    /* macOS uses different sendfile() signature */
    #define BRIX_SENDFILE_MACOS 1
    
    /* macOS XNU lacks posix_fadvise */
    #define posix_fadvise(fd, offset, len, advice) \
        brix_posix_fadvise_stub(fd, offset, len, advice)
    
    /* macOS Security framework for certificate handling */
    #define BRIX_USE_SECURITY_FRAMEWORK 1
    
    /* macOS Keychain for credential storage (optional) */
    #ifndef BRIX_DISABLE_KEYCHAIN
        #define BRIX_USE_KEYCHAIN 1
    #endif
#endif

/* ==========================================================================
 * COMPILER ATTRIBUTES
 * ========================================================================== */

#if BRIX_PLATFORM_DARWIN
    /* macOS clang-specific attributes */
    #define BRIX_UNUSED __attribute__((unused))
    #define BRIX_NORETURN __attribute__((noreturn))
    #define BRIX_MALLOC __attribute__((malloc))
    #define BRIX_ALIGNED(x) __attribute__((aligned(x)))
    
    /* Suppress warnings for unused command-line args */
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-command-line-argument"
#else
    /* GCC/clang on Linux */
    #define BRIX_UNUSED __attribute__((unused))
    #define BRIX_NORETURN __attribute__((noreturn))
    #define BRIX_MALLOC __attribute__((malloc))
    #define BRIX_ALIGNED(x) __attribute__((aligned(x)))
#endif

/* ==========================================================================
 * ASSERTIONS - Compile-time checks
 * ========================================================================== */

/* Ensure exactly one platform is defined */
#if (BRIX_PLATFORM_LINUX + BRIX_PLATFORM_DARWIN) != 1
    #error "Exactly one of BRIX_PLATFORM_LINUX or BRIX_PLATFORM_DARWIN must be defined"
#endif

/* Ensure incompatible features are not both enabled */
#if BRIX_HAS_IO_URING && BRIX_PLATFORM_DARWIN
    #error "io_uring is not available on macOS"
#endif

#if BRIX_HAS_SECCOMP && BRIX_PLATFORM_DARWIN
    #error "seccomp-bpf is not available on macOS"
#endif

#if BRIX_HAS_CEPH && BRIX_PLATFORM_DARWIN
    #error "CephFS has no macOS support"
#endif

#endif /* BRIX_PLATFORM_H */
```

#### **2.1.3 Unified Platform API (`src/platform/platform_api.h`)**

```c
/*
 * src/platform/platform_api.h - Unified API for platform-specific operations
 * 
 * This header defines the abstract interface that all platform implementations
 * must provide. Platform-specific code should NEVER be called directly; always
 * use these wrapper functions.
 * 
 * Example usage:
 *   // CORRECT:
 *   int fd = brix_platform_event_init();
 *   
 *   // WRONG:
 *   #if BRIX_PLATFORM_LINUX
 *       int fd = epoll_create1(EPOLL_CLOEXEC);
 *   #else
 *       int fd = kqueue();
 *   #endif
 */

#ifndef BRIX_PLATFORM_API_H
#define BRIX_PLATFORM_API_H

#include "platform.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* ==========================================================================
 * EVENT MONITORING
 * ========================================================================== */

/**
 * Initialize platform event monitoring
 * @return Event fd on success, -1 on error (errno set)
 */
int brix_platform_event_init(void);

/**
 * Close event monitoring fd
 * @param fd Event fd from brix_platform_event_init()
 */
void brix_platform_event_close(int fd);

/**
 * Watch a file for changes
 * @param event_fd Event fd
 * @param fd File descriptor to watch
 * @param events Event mask (BRIX_EVENT_READ, BRIX_EVENT_WRITE, etc.)
 * @return 0 on success, -1 on error
 */
int brix_platform_event_watch(int event_fd, int fd, uint32_t events);

/**
 * Wait for events
 * @param event_fd Event fd
 * @param events Output event array
 * @param max_events Maximum events to return
 * @param timeout_ms Timeout in milliseconds (-1 for infinite)
 * @return Number of events, 0 on timeout, -1 on error
 */
int brix_platform_event_wait(int event_fd, void *events, int max_events, int timeout_ms);

/* Event mask constants */
#define BRIX_EVENT_READ    0x0001
#define BRIX_EVENT_WRITE   0x0002
#define BRIX_EVENT_ERROR   0x0004
#define BRIX_EVENT_DELETE  0x0008  /* File deleted */
#define BRIX_EVENT_MODIFY  0x0010  /* File modified */
#define BRIX_EVENT_CREATE  0x0020  /* File created */

/* ==========================================================================
 * FILE I/O
 * ========================================================================== */

/**
 * Platform-specific file access hints
 * @param fd File descriptor
 * @param offset Start offset
 * @param len Length of region (0 = to EOF)
 * @param advice Hint type
 * @return 0 on success, -1 on error (errno set, or 0 if not supported)
 */
int brix_platform_fadvise(int fd, off_t offset, off_t len, int advice);

/* Advice constants */
#define BRIX_FADV_NORMAL     0  /* No special treatment */
#define BRIX_FADV_RANDOM     1  /* Expect random access */
#define BRIX_FADV_SEQUENTIAL 2  /* Expect sequential access */
#define BRIX_FADV_WILLNEED   3  /* Will need this region soon */
#define BRIX_FADV_DONTNEED   4  /* Don't need this region soon */

/**
 * Zero-copy file transfer
 * @param out_fd Output fd (socket or file)
 * @param in_fd Input fd (file)
 * @param offset File offset (updated on success)
 * @param count Bytes to transfer
 * @return Bytes transferred, or -1 on error
 */
ssize_t brix_platform_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

/**
 * Zero-copy pipe splice (Linux only, stub on macOS)
 * @param in_fd Input fd
 * @param out_fd Output fd (must be pipe)
 * @param nbytes Bytes to splice
 * @param flags Splice flags
 * @return Bytes spliced, or -1 on error
 */
ssize_t brix_platform_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags);

/* Splice flags */
#define BRIX_SPLICE_F_MOVE       1  /* Pages move (not copy) */
#define BRIX_SPLICE_F_NONBLOCK   2  /* Non-blocking operation */
#define BRIX_SPLICE_F_MORE       4  /* More data coming */

/**
 * Clone file (macOS APFS only, stub on Linux)
 * @param src_path Source file path
 * @param dst_path Destination path (must not exist)
 * @return 0 on success, -1 on error
 */
int brix_platform_clonefile(const char *src_path, const char *dst_path);

/* ==========================================================================
 * FILESYSTEM MONITORING
 * ========================================================================== */

/**
 * Filesystem watcher context (opaque)
 */
typedef struct brix_fs_watcher brix_fs_watcher_t;

/**
 * Create filesystem watcher
 * @return Watcher context, or NULL on error
 */
brix_fs_watcher_t *brix_fs_watcher_create(void);

/**
 * Destroy filesystem watcher
 * @param watcher Watcher context
 */
void brix_fs_watcher_destroy(brix_fs_watcher_t *watcher);

/**
 * Watch a path for changes
 * @param watcher Watcher context
 * @param path Path to watch
 * @param recursive Watch recursively (directories only)
 * @return 0 on success, -1 on error
 */
int brix_fs_watcher_add(brix_fs_watcher_t *watcher, const char *path, int recursive);

/**
 * Remove a watched path
 * @param watcher Watcher context
 * @param path Path to stop watching
 * @return 0 on success, -1 on error
 */
int brix_fs_watcher_remove(brix_fs_watcher_t *watcher, const char *path);

/**
 * Get next filesystem event
 * @param watcher Watcher context
 * @param event Output event buffer
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return 1 on event, 0 on timeout, -1 on error
 */
int brix_fs_watcher_next(brix_fs_watcher_t *watcher, void *event, int timeout_ms);

/* Filesystem event structure */
typedef struct {
    char path[4096];      /* Path that changed */
    uint32_t mask;        /* Event mask */
    uint64_t cookie;      /* Cookie for related events */
    uint64_t timestamp;   /* Event timestamp (nanoseconds since epoch) */
} brix_fs_event_t;

/* Event mask */
#define BRIX_FS_EVENT_ACCESS      0x0001
#define BRIX_FS_EVENT_MODIFY      0x0002
#define BRIX_FS_EVENT_ATTRIB      0x0004
#define BRIX_FS_EVENT_CREATE      0x0008
#define BRIX_FS_EVENT_DELETE      0x0010
#define BRIX_FS_EVENT_DELETE_SELF 0x0020
#define BRIX_FS_EVENT_MOVE_FROM   0x0040
#define BRIX_FS_EVENT_MOVE_TO     0x0080

/* ==========================================================================
 * SECURITY
 * ========================================================================== */

/**
 * Initialize syscall filter (seccomp on Linux, sandbox on macOS)
 * @param profile Profile name ("default", "strict", "audit")
 * @return 0 on success, -1 on error
 */
int brix_security_init(const char *profile);

/**
 * Enable audit mode (log violations but don't block)
 * @return 0 on success, -1 on error
 */
int brix_security_enable_audit(void);

/**
 * Load custom security profile
 * @param path Path to profile file (JSON on Linux, .sb on macOS)
 * @return 0 on success, -1 on error
 */
int brix_security_load_profile(const char *path);

/* ==========================================================================
 * ASYNC I/O
 * ========================================================================== */

/**
 * Async I/O context (io_uring on Linux, thread pool on macOS)
 */
typedef struct brix_aio_ctx brix_aio_ctx_t;

/**
 * Create async I/O context
 * @param max_entries Maximum concurrent operations
 * @return Context, or NULL on error
 */
brix_aio_ctx_t *brix_aio_create(size_t max_entries);

/**
 * Destroy async I/O context
 * @param ctx Context
 */
void brix_aio_destroy(brix_aio_ctx_t *ctx);

/**
 * Submit async read
 * @param ctx Context
 * @param fd File descriptor
 * @param buf Buffer
 * @param count Bytes to read
 * @param offset File offset
 * @param callback Completion callback
 * @param user_data User data for callback
 * @return 0 on success, -1 on error
 */
int brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count, 
                  off_t offset, void (*callback)(int, ssize_t, void *), void *user_data);

/**
 * Submit async write
 * @param ctx Context
 * @param fd File descriptor
 * @param buf Buffer
 * @param count Bytes to write
 * @param offset File offset
 * @param callback Completion callback
 * @param user_data User data for callback
 * @return 0 on success, -1 on error
 */
int brix_aio_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count, 
                   off_t offset, void (*callback)(int, ssize_t, void *), void *user_data);

/**
 * Wait for async I/O completion
 * @param ctx Context
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return Number of completed operations, or -1 on error
 */
int brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms);

/* ==========================================================================
 * PLATFORM UTILITIES
 * ========================================================================== */

/**
 * Get platform name string
 * @return "linux" or "darwin"
 */
const char *brix_platform_name(void);

/**
 * Get platform version string
 * @return Kernel version (e.g., "5.15.0" or "21.6.0")
 */
const char *brix_platform_version(void);

/**
 * Check if running as root
 * @return 1 if root, 0 otherwise
 */
int brix_platform_is_root(void);

/**
 * Get number of online CPUs
 * @return CPU count, or -1 on error
 */
int brix_platform_cpu_count(void);

/**
 * Get total system memory in bytes
 * @return Memory size, or 0 on error
 */
uint64_t brix_platform_total_memory(void);

/**
 * Get available memory in bytes
 * @return Available memory, or 0 on error
 */
uint64_t brix_platform_available_memory(void);

#endif /* BRIX_PLATFORM_API_H */
```

### 2.2 Compile-Time Configuration

#### **2.2.1 New Build Flags**

```bash
# Platform selection (auto-detected, can be overridden)
BRIX_PLATFORM=linux|darwin              # Default: auto-detect via uname -s

# Feature gates (default: enabled if platform supports)
BRIX_ENABLE_IO_URING=0|1                # Default: 1 on Linux, 0 on macOS
BRIX_ENABLE_SECCOMP=0|1                 # Default: 1 on Linux, 0 on macOS
BRIX_ENABLE_CEPH=0|1                    # Default: 1 on Linux, 0 on macOS
BRIX_ENABLE_SPLICE=0|1                  # Default: 1 on Linux, 0 on macOS
BRIX_ENABLE_INOTIFY=0|1                 # Default: 1 on Linux, 0 on macOS
BRIX_ENABLE_FSEVENTS=0|1                # Default: 0 on Linux, 1 on macOS
BRIX_ENABLE_MACFUSE=0|1                 # Default: 0 on Linux, 0 on macOS (requires SIP mod)

# Optimization flags
BRIX_OPTIMIZE=v2|v3|native|none         # Default: v2 (x86-64-v2 baseline)
BRIX_ENABLE_LTO=0|1                     # Default: 0 (Link-Time Optimization)

# macOS-specific
MACOS_MIN_VERSION=12.0                  # Default: 12.0 (Monterey)
MACOS_CODE_SIGN=0|1                     # Default: 0 (1 = ad-hoc sign binary)
```

#### **2.2.2 Modified `config` File Section**

```bash
# ==========================================================================
# PLATFORM DETECTION (new section at line 7)
# ==========================================================================

BRIX_PLATFORM="${BRIX_PLATFORM:-auto}"

if [ "$BRIX_PLATFORM" = "auto" ]; then
    BRIX_PLATFORM=$(uname -s)
fi

case "$BRIX_PLATFORM" in
    Linux|linux)
        BRIX_PLATFORM="linux"
        BRIX_CFLAGS="-DBRIX_PLATFORM_LINUX=1 -DBRIX_PLATFORM_DARWIN=0"
        BRIX_LDFLAGS=""
        BRIX_LIBS=""
        echo " + xrootd: platform Linux detected"
        ;;
    
    Darwin|darwin)
        BRIX_PLATFORM="darwin"
        BRIX_CFLAGS="-DBRIX_PLATFORM_LINUX=0 -DBRIX_PLATFORM_DARWIN=1 -D_DARWIN_C_SOURCE"
        BRIX_LDFLAGS=""
        BRIX_LIBS="-framework Security -framework CoreFoundation"
        
        # Remove Linux-specific compiler flags
        CFLAGS=$(echo "$CFLAGS" | sed 's/-fcf-protection=full//g')
        CFLAGS=$(echo "$CFLAGS" | sed 's/-fstack-clash-protection//g')
        CFLAGS=$(echo "$CFLAGS" | sed 's/-D_GNU_SOURCE//g')
        
        # Homebrew prefix detection
        if command -v brew >/dev/null 2>&1; then
            BREW_PREFIX=$(brew --prefix)
            BRIX_CFLAGS="$BRIX_CFLAGS -I${BREW_PREFIX}/include"
            BRIX_LDFLAGS="$BRIX_LDFLAGS -L${BREW_PREFIX}/lib"
            echo " + xrootd: Homebrew detected at ${BREW_PREFIX}"
        else
            echo " ! xrootd: Homebrew not found. Install from https://brew.sh"
            echo "   Some dependencies may not be found without Homebrew."
        fi
        
        # macOS version check
        MACOS_VERSION=$(sw_vers -productVersion)
        MACOS_MAJOR=$(echo "$MACOS_VERSION" | cut -d. -f1)
        MACOS_MINOR=$(echo "$MACOS_VERSION" | cut -d. -f2)
        
        if [ "$MACOS_MAJOR" -lt 12 ] || ([ "$MACOS_MAJOR" -eq 12 ] && [ "$MACOS_MINOR" -lt 0 ]); then
            echo " ! xrootd: macOS 12.0+ required (detected: $MACOS_VERSION)"
            echo "   BriX-Cache requires macOS Monterey (12.0) or later."
            exit 1
        fi
        
        echo " + xrootd: platform macOS ${MACOS_VERSION} detected"
        ;;
    
    *)
        echo " ! xrootd: unsupported platform: $BRIX_PLATFORM"
        echo "   BriX-Cache supports Linux and macOS only."
        exit 1
        ;;
esac

# Append platform flags to global CFLAGS
CFLAGS="$CFLAGS $BRIX_CFLAGS"
NGX_LD_OPT="$NGX_LD_OPT $BRIX_LDFLAGS"

# ==========================================================================
# FEATURE DETECTION (modified section at line 156)
# ==========================================================================

# io_uring (Linux only)
if [ "$BRIX_PLATFORM" = "linux" ] && [ "${BRIX_ENABLE_IO_URING:-1}" != "0" ]; then
    if pkg-config --exists liburing 2>/dev/null; then
        CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DBRIX_HAVE_LIBURING=1"
        LIBS="$LIBS $(pkg-config --libs liburing)"
        echo " + xrootd: io_uring enabled (liburing $(pkg-config --modversion liburing))"
    else
        echo " ! xrootd: io_uring disabled (liburing not found)"
        echo "   Install liburing-dev (Debian/Ubuntu) or liburing-devel (RHEL) to enable."
    fi
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: io_uring disabled (not available on macOS)"
    else
        echo " - xrootd: io_uring disabled by BRIX_ENABLE_IO_URING=0"
    fi
fi

# seccomp (Linux only)
if [ "$BRIX_PLATFORM" = "linux" ] && [ "${BRIX_ENABLE_SECCOMP:-1}" != "0" ]; then
    if pkg-config --exists libseccomp 2>/dev/null; then
        CFLAGS="$CFLAGS $(pkg-config --cflags libseccomp) -DBRIX_HAVE_SECCOMP=1"
        BRIX_SECCOMP_LIBS="$(pkg-config --libs libseccomp)"
        echo " + xrootd: seccomp enabled (libseccomp $(pkg-config --modversion libseccomp))"
    else
        echo " ! xrootd: seccomp disabled (libseccomp not found)"
        echo "   Install libseccomp-dev (Debian/Ubuntu) or libseccomp-devel (RHEL) to enable."
    fi
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: seccomp disabled (not available on macOS)"
    else
        echo " - xrootd: seccomp disabled by BRIX_ENABLE_SECCOMP=0"
    fi
fi

# CephFS (Linux only)
if [ "$BRIX_PLATFORM" = "linux" ] && [ "${BRIX_ENABLE_CEPH:-1}" != "0" ]; then
    if pkg-config --exists cephfs 2>/dev/null; then
        CFLAGS="$CFLAGS -DBRIX_HAVE_CEPH=1"
        LIBS="$LIBS -lcephfs -lrados -lradosstriper"
        echo " + xrootd: CephFS backend enabled"
    else
        echo " ! xrootd: CephFS backend disabled (Ceph libraries not found)"
        echo "   Install libcephfs-devel, librados-devel, libradosstriper-devel to enable."
    fi
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: CephFS backend disabled (no macOS Ceph support)"
        echo "   Use S3 backend or Ceph NFS gateway as alternative."
    else
        echo " - xrootd: CephFS backend disabled by BRIX_ENABLE_CEPH=0"
    fi
fi

# macOS-specific: FSEvents
if [ "$BRIX_PLATFORM" = "darwin" ] && [ "${BRIX_ENABLE_FSEVENTS:-1}" != "0" ]; then
    echo " + xrootd: FSEvents filesystem monitoring enabled"
    # FSEvents is part of CoreServices, already linked via -framework CoreFoundation
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: FSEvents disabled by BRIX_ENABLE_FSEVENTS=0"
    fi
fi

# macOS-specific: macFUSE
if [ "$BRIX_PLATFORM" = "darwin" ] && [ "${BRIX_ENABLE_MACFUSE:-0}" = "1" ]; then
    if [ -f "/Library/Filesystems/macFUSE.fs/Contents/Resources/sdk/mount_macfuse" ]; then
        CFLAGS="$CFLAGS -DBRIX_HAVE_MACFUSE=1 -I/Library/Filesystems/macFUSE.fs/Contents/Resources/sdk"
        LIBS="$LIBS -losxfuse"
        echo " + xrootd: macFUSE support enabled"
        echo "   WARNING: macFUSE requires partial SIP disable. See docs/01-getting-started/macos-install.md"
    else
        echo " ! xrootd: macFUSE not installed"
        echo "   Install from https://github.com/osxfuse/osxfuse/releases"
        echo "   Note: Requires SIP modification (System Integrity Protection)"
        exit 1
    fi
else
    if [ "$BRIX_PLATFORM" = "darwin" ]; then
        echo " - xrootd: macFUSE support disabled (set BRIX_ENABLE_MACFUSE=1 to enable)"
    fi
fi
```

### 2.3 Implementation Phases - Detailed Breakdown

#### **Phase 1: Platform Detection & Build System (Weeks 1-2)**

**Week 1: Platform Detection**

| Day | Task | Deliverable | Acceptance Criteria |
|-----|------|-------------|---------------------|
| 1 | Create `src/platform/platform.h` | Header file committed | Compiles on both Linux and macOS without errors |
| 2 | Create `src/platform/platform_api.h` | API header committed | All function prototypes defined, documented |
| 3 | Modify `config` for platform detection | `config` updated | Auto-detects Linux/macOS, sets correct flags |
| 4 | Modify `CMakeLists.txt` for macOS | CMake updated | Builds on macOS with `cmake -B build` |
| 5 | Create stub implementations | `src/platform/darwin/platform_init.c` | macOS build compiles, links successfully |

**Week 2: Build Verification**

| Day | Task | Deliverable | Acceptance Criteria |
|-----|------|-------------|---------------------|
| 1 | Test Linux build (regression) | Build log | No changes to Linux build output |
| 2 | Test macOS build (first pass) | Build log | Compiles with warnings as errors |
| 3 | Fix macOS compilation errors | Patch set | Zero compilation errors |
| 4 | Fix macOS linker errors | Patch set | Binary links successfully |
| 5 | Binary verification | `objs/nginx -V` output | Module loaded, platform reported correctly |

**Phase 1 Milestone:**
```bash
# On macOS:
$ ./configure --with-stream --with-threads --add-module=$(pwd)
$ make -j$(sysctl -n hw.ncpu)
$ objs/nginx -V 2>&1 | grep -i brix
# Expected: --add-module=.../brix-cache (darwin build)
```

#### **Phase 2: API Compatibility Layer (Weeks 3-6)**

**Week 3: File I/O Wrappers**

| Task | Files | Complexity | Testing |
|------|-------|------------|---------|
| `brix_platform_fadvise()` | `src/platform/darwin/posix_wrapper.c` | Low | Unit test (stub returns 0) |
| `brix_platform_sendfile()` | `src/platform/darwin/sendfile_wrapper.c` | Medium | Integration test (1MB transfer) |
| `brix_platform_clonefile()` | `src/platform/darwin/clonefile_wrapper.c` | Low | Unit test (APFS required) |

**Code Example: `sendfile_wrapper.c`**
```c
/*
 * src/platform/darwin/sendfile_wrapper.c - macOS sendfile() wrapper
 * 
 * macOS sendfile() has a different signature than Linux:
 *   int sendfile(int from_fd, int to_fd, off_t offset, off_t *len, int flags);
 * 
 * Linux signature:
 *   ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
 * 
 * This wrapper provides Linux-compatible semantics on macOS.
 */

#include "platform.h"
#include "sendfile_wrapper.h"
#include <sys/socket.h>
#include <errno.h>

ssize_t
brix_platform_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    off_t sf_offset = *offset;
    off_t sf_count = (off_t)count;
    int result;
    
    /*
     * macOS sendfile() returns:
     *   0 on success
     *   -1 on error (errno set)
     * 
     * Linux sendfile() returns:
     *   bytes sent on success
     *   -1 on error (errno set)
     * 
     * We need to translate macOS semantics to Linux semantics.
     */
    
    result = sendfile(in_fd, out_fd, sf_offset, &sf_count, NULL, 0);
    
    if (result == 0) {
        /* Success - macOS updated sf_count with bytes sent */
        *offset += sf_count;
        return (ssize_t)sf_count;
    } else {
        /* Error - errno already set by sendfile() */
        return -1;
    }
}
```

**Week 4: Event Monitoring**

| Task | Files | Complexity | Testing |
|------|-------|------------|---------|
| `brix_platform_event_init()` | `src/platform/darwin/kqueue_wrapper.c` | Medium | Unit test (fd returned) |
| `brix_platform_event_watch()` | `src/platform/darwin/kqueue_wrapper.c` | High | Integration test (file watch) |
| `brix_platform_event_wait()` | `src/platform/darwin/kqueue_wrapper.c` | High | Integration test (timeout, event) |
| `brix_fs_watcher_*()` | `src/platform/darwin/fsevents_wrapper.c` | High | Integration test (directory watch) |

**Code Example: `kqueue_wrapper.c`**
```c
/*
 * src/platform/darwin/kqueue_wrapper.c - kqueue event monitoring
 * 
 * kqueue is macOS/BSD equivalent of Linux epoll.
 * This wrapper provides epoll-like semantics using kqueue.
 */

#include "platform.h"
#include "kqueue_wrapper.h"
#include <sys/event.h>
#include <sys/time.h>
#include <errno.h>

int
brix_platform_event_init(void)
{
    int kq = kqueue();
    if (kq == -1) {
        return -1;  /* errno set by kqueue() */
    }
    
    /* Set CLOEXEC to avoid fd leak on exec() */
    int flags = fcntl(kq, F_GETFD);
    if (flags != -1) {
        fcntl(kq, F_SETFD, flags | FD_CLOEXEC);
    }
    
    return kq;
}

int
brix_platform_event_watch(int event_fd, int fd, uint32_t events)
{
    struct kevent ev;
    int filter = 0;
    int filter_flags = EV_ADD | EV_ENABLE | EV_CLEAR;
    
    /* Translate event mask to kqueue filter */
    if (events & BRIX_EVENT_READ) {
        filter = EVFILT_READ;
    } else if (events & BRIX_EVENT_WRITE) {
        filter = EVFILT_WRITE;
    } else if (events & (BRIX_EVENT_DELETE | BRIX_EVENT_MODIFY)) {
        /* Filesystem events use EVFILT_VNODE */
        filter = EVFILT_VNODE;
        if (events & BRIX_EVENT_DELETE) {
            filter_flags |= NOTE_DELETE;
        }
        if (events & BRIX_EVENT_MODIFY) {
            filter_flags |= NOTE_WRITE;
        }
        if (events & BRIX_EVENT_CREATE) {
            filter_flags |= NOTE_EXTEND;
        }
    } else {
        errno = EINVAL;
        return -1;
    }
    
    EV_SET(&ev, (uintptr_t)fd, filter, filter_flags, 0, 0, NULL);
    
    if (kevent(event_fd, &ev, 1, NULL, 0, NULL) == -1) {
        return -1;  /* errno set by kevent() */
    }
    
    return 0;
}

int
brix_platform_event_wait(int event_fd, void *events, int max_events, int timeout_ms)
{
    struct kevent *kev = (struct kevent *)events;
    struct timespec ts;
    struct timespec *tsp;
    int nready;
    
    if (timeout_ms < 0) {
        tsp = NULL;  /* Infinite timeout */
    } else {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        tsp = &ts;
    }
    
    nready = kevent(event_fd, NULL, 0, kev, (intptr_t)max_events, tsp);
    
    if (nready == -1) {
        if (errno == EINTR) {
            return 0;  /* Interrupted by signal - not an error */
        }
        return -1;  /* errno set by kevent() */
    }
    
    return nready;
}
```

**Week 5: Security Wrappers**

| Task | Files | Complexity | Testing |
|------|-------|------------|---------|
| `brix_security_init()` | `src/platform/darwin/sandbox_wrapper.c` | High | Unit test (stub logs warning) |
| `brix_security_enable_audit()` | `src/platform/darwin/sandbox_wrapper.c` | Low | Unit test (stub) |
| `brix_security_load_profile()` | `src/platform/darwin/sandbox_wrapper.c` | Medium | Integration test (profile load) |

**Code Example: `sandbox_wrapper.c`**
```c
/*
 * src/platform/darwin/sandbox_wrapper.c - macOS sandbox_exec wrapper
 * 
 * Phase 2: Stub implementation (logs warning, returns success)
 * Phase 4: Full implementation using sandbox_exec(3)
 * 
 * macOS sandbox profiles use .sb language:
 *   (version 1)
 *   (allow file-read* file-write* network-outbound)
 *   (deny default)
 * 
 * Linux seccomp profiles use JSON/BPF:
 *   {"syscall": "read", "action": "allow"}
 */

#include "platform.h"
#include "sandbox_wrapper.h"
#include <ngx_log.h>

int
brix_security_init(const char *profile)
{
#if BRIX_PHASE >= 4
    /* Phase 4: Full implementation */
    char *error = NULL;
    const char *profile_path;
    
    /* Determine profile path */
    if (profile == NULL || strcmp(profile, "default") == 0) {
        profile_path = "/usr/local/share/brix/sandbox/default.sb";
    } else if (strcmp(profile, "strict") == 0) {
        profile_path = "/usr/local/share/brix/sandbox/strict.sb";
    } else if (strcmp(profile, "audit") == 0) {
        return brix_security_enable_audit();
    } else {
        /* Custom profile */
        profile_path = profile;
    }
    
    /* Load and compile profile */
    sandbox_ctx_t ctx = sandbox_init(profile_path, 0, &error);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "brix_security: sandbox_init failed: %s", error);
        sandbox_free_error(error);
        return -1;
    }
    
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "brix_security: sandbox profile '%s' loaded", profile);
    return 0;
#else
    /* Phase 2: Stub implementation */
    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "brix_security: sandbox_exec not yet implemented (Phase 2 stub). "
                  "Falling back to system security (SIP, Gatekeeper). "
                  "Full implementation planned for Phase 4.");
    return 0;  /* Success - rely on system security */
#endif
}

int
brix_security_enable_audit(void)
{
    /* Audit mode: log violations but don't block */
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "brix_security: audit mode enabled (violations logged but not blocked)");
    return 0;
}

int
brix_security_load_profile(const char *path)
{
#if BRIX_PHASE >= 4
    char *error = NULL;
    
    sandbox_ctx_t ctx = sandbox_init(path, 0, &error);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "brix_security: sandbox_init(%s) failed: %s", path, error);
        sandbox_free_error(error);
        return -1;
    }
    
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "brix_security: custom profile '%s' loaded", path);
    return 0;
#else
    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "brix_security_load_profile: not implemented in Phase 2");
    errno = ENOSYS;
    return -1;
#endif
}
```

**Week 6: Async I/O**

| Task | Files | Complexity | Testing |
|------|-------|------------|---------|
| `brix_aio_create()` | `src/platform/darwin/aio_wrapper.c` | High | Unit test (context created) |
| `brix_aio_read()` | `src/platform/darwin/aio_wrapper.c` | High | Integration test (async read) |
| `brix_aio_write()` | `src/platform/darwin/aio_wrapper.c` | High | Integration test (async write) |
| `brix_aio_wait()` | `src/platform/darwin/aio_wrapper.c` | Medium | Integration test (completion) |

**Implementation Strategy:**
- **Linux:** Use `io_uring` if available, fall back to thread pool
- **macOS:** Always use nginx thread pool (no native async I/O API)

```c
/*
 * src/platform/darwin/aio_wrapper.c - macOS async I/O via thread pool
 * 
 * macOS lacks io_uring, so we use nginx's thread_pool directive.
 * This wrapper provides the same API as Linux io_uring wrapper.
 */

#include "platform.h"
#include "aio_wrapper.h"
#include <ngx_thread_pool.h>

struct brix_aio_ctx {
    ngx_thread_pool_t *pool;
    size_t max_entries;
    ngx_atomic_t pending_ops;
};

brix_aio_ctx_t *
brix_aio_create(size_t max_entries)
{
    brix_aio_ctx_t *ctx;
    ngx_str_t name = ngx_string("brix_aio");
    
    ctx = ngx_alloc(sizeof(brix_aio_ctx_t), ngx_cycle->log);
    if (ctx == NULL) {
        return NULL;
    }
    
    /* Get nginx thread pool */
    ctx->pool = ngx_thread_pool_get(ngx_cycle, &name);
    if (ctx->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "brix_aio: thread pool '%V' not found. "
                      "Add 'thread_pool brix_aio threads=4' to nginx.conf", &name);
        ngx_free(ctx);
        return NULL;
    }
    
    ctx->max_entries = max_entries;
    ctx->pending_ops = 0;
    
    return ctx;
}

int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count, 
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    /* Post read operation to thread pool */
    ngx_thread_task_t *task;
    
    task = ngx_alloc(sizeof(ngx_thread_task_t), ngx_cycle->log);
    if (task == NULL) {
        return -1;
    }
    
    /* TODO: Implement task handler */
    /* For now, return ENOSYS */
    ngx_free(task);
    errno = ENOSYS;
    return -1;
}
```

#### **Phase 3: Feature Gates & Runtime Detection (Weeks 7-8)**

**Week 7: Runtime Feature Detection**

```c
/*
 * src/core/feature_detect.c - Runtime feature detection
 */

#include "platform/platform.h"
#include "feature_detect.h"

static brix_features_t g_features;

void
brix_detect_features(void)
{
    ngx_memzero(&g_features, sizeof(g_features));
    
#if BRIX_PLATFORM_LINUX
    g_features.platform = "linux";
    
    /* io_uring availability */
    if (access("/proc/sys/fs/aio-max-nr", F_OK) == 0) {
        g_features.has_io_uring = 1;
    }
    
    /* seccomp availability */
    #ifdef BRIX_HAVE_SECCOMP
        g_features.has_seccomp = 1;
    #endif
    
    /* CephFS availability */
    #ifdef BRIX_HAVE_CEPH
        g_features.has_ceph = 1;
    #endif
    
    /* inotify availability */
    g_features.has_inotify = 1;
    
    /* splice availability */
    g_features.has_splice = 1;
    
#elif BRIX_PLATFORM_DARWIN
    g_features.platform = "darwin";
    
    /* All Linux-specific features unavailable */
    g_features.has_io_uring = 0;
    g_features.has_seccomp = 0;
    g_features.has_ceph = 0;
    g_features.has_inotify = 0;
    g_features.has_splice = 0;
    
    /* macOS-specific features */
    g_features.has_fsevents = 1;
    g_features.has_clonefile = 1;  /* APFS only */
    g_features.has_keychain = 1;
    
#endif
    
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "BriX-Cache features: platform=%s io_uring=%s seccomp=%s ceph=%s",
                  g_features.platform,
                  g_features.has_io_uring ? "yes" : "no",
                  g_features.has_seccomp ? "yes" : "no",
                  g_features.has_ceph ? "yes" : "no");
}

const brix_features_t *
brix_get_features(void)
{
    return &g_features;
}
```

**Week 8: Directive Handlers**

```c
/*
 * src/stream/ngx_stream_brix_module.c - Modified directive handlers
 */

static char *
brix_cmd_io_uring(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if BRIX_PLATFORM_DARWIN
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "brix_io_uring is not available on macOS. "
                       "Use nginx thread_pool directive instead: "
                       "'thread_pool default threads=4 max_queue=65536'");
    return NGX_CONF_ERROR;
#endif
    
    const brix_features_t *features = brix_get_features();
    if (!features->has_io_uring) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_io_uring requires Linux 5.1+ with liburing. "
                           "Install liburing-dev (Debian/Ubuntu) or liburing-devel (RHEL).");
        return NGX_CONF_ERROR;
    }
    
    /* ... rest of handler unchanged ... */
}

static char *
brix_cmd_seccomp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if BRIX_PLATFORM_DARWIN
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "brix_seccomp is not available on macOS. "
                       "macOS relies on system security (SIP, Gatekeeper). "
                       "Directive ignored.");
    return NGX_CONF_OK;  /* Ignore, don't fail */
#endif
    
    /* ... rest of handler unchanged ... */
}
```

#### **Phase 4: Testing & CI Integration (Weeks 9-12)**

**Week 9-10: Test Porting**

| Test Suite | Linux Tests | macOS Ports | Skip/Stub |
|------------|-------------|-------------|-----------|
| `tests/unit/` | 156 | 156 | 0 |
| `tests/c/` | 23 | 20 | 3 (io_uring, seccomp, ceph) |
| `tests/ceph/` | 8 | 0 | 8 (all skipped) |
| `tests/userns/` | 4 | 0 | 4 (all skipped) |
| `tests/fuzz/` | 12 | 12 | 0 |

**Week 11-12: CI Integration**

```yaml
# .github/workflows/build-macos.yml
name: macOS Build & Test

on:
  push:
    branches: [dev/macos-support, main]
  pull_request:
    branches: [dev/macos-support]

jobs:
  build-macos:
    runs-on: macos-12  # macOS 12 Monterey
    strategy:
      matrix:
        xcode: ['14.0', '14.2', '15.0']
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Select Xcode
      run: sudo xcode-select -s /Applications/Xcode_${{ matrix.xcode }}.app
    
    - name: Install Homebrew dependencies
      run: |
        brew install \
          openssl@3 \
          pcre2 \
          libxml2 \
          jansson \
          krb5 \
          libcurl \
          sqlite \
          lz4 \
          zstd \
          xz
    
    - name: Configure nginx with BriX module
      run: |
        curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
        tar xzf nginx-1.28.3.tar.gz
        cd nginx-1.28.3
        ./configure \
          --with-stream \
          --with-threads \
          --add-module=../brix-cache
        make -j$(sysctl -n hw.ncpu)
    
    - name: Verify module loaded
      run: |
        objs/nginx -V 2>&1 | grep -q brix || exit 1
    
    - name: Run unit tests
      run: |
        cd brix-cache
        PYTHONPATH=tests pytest tests/unit/ -v --tb=short
    
    - name: Run integration tests
      run: |
        cd brix-cache
        PYTHONPATH=tests pytest tests/c/ -v --tb=short \
          -k "not io_uring and not seccomp and not ceph"
```

#### **Phase 5: Documentation & Release (Weeks 13-14)**

**Week 13: Documentation**

| Document | Status | Owner | Due |
|----------|--------|-------|-----|
| `docs/01-getting-started/macos-install.md` | Draft | TBD | Week 13, Day 3 |
| `docs/05-operations/macos-limitations.md` | Draft | TBD | Week 13, Day 4 |
| `docs/09-developer-guide/platform-porting-guide.md` | Draft | TBD | Week 13, Day 5 |
| `README.md` (update) | Draft | TBD | Week 14, Day 1 |
| `docs/10-reference/CHANGELOG.md` (v3.0.0 section) | Draft | TBD | Week 14, Day 2 |

**Week 14: Release Preparation**

| Task | Deliverable | Acceptance Criteria |
|------|-------------|---------------------|
| Final regression testing (Linux) | Test report | 100% pass rate |
| Final testing (macOS) | Test report | 95%+ pass rate |
| Performance benchmarking | Benchmark report | Within 30% of Linux |
| Security review | Security audit | No critical issues |
| Release notes | `docs/10-reference/CHANGELOG.md` | Complete, accurate |
| Tag release | `v3.0.0` tag | Git tag created |

---

## 3. External Library Dependencies for macOS

### 3.1 Required Libraries (Homebrew)

```bash
# Core dependencies (mandatory for all builds)
brew install \
    openssl@3 \      # GSI authentication, TLS
    pcre2 \          # nginx regex (URL parsing, ACLs)
    libxml2 \        # XML parsing (metadata, manifests)
    jansson \        # JSON parsing (config, metrics)
    krb5 \           # Kerberos authentication
    libcurl \        # HTTP client (S3, WebDAV)
    sqlite \         # Metadata database (pblock backend)
    lz4 \            # Compression (pblock backend)
    zstd \           # Compression (pblock backend)
    xz \             # Compression (pblock backend)
    brotli \         # Compression (pblock backend)
    bzip2            # Compression (pblock backend)

# Optional dependencies (feature-specific)
brew install \
    macfuse          # FUSE mounts (requires SIP mod)
```

### 3.2 Library Version Matrix

| Library | Minimum Version | Homebrew Version | Notes |
|---------|----------------|------------------|-------|
| OpenSSL | 3.0.0 | 3.5.0 | GSI, TLS |
| PCRE2 | 10.30 | 10.45 | Regex |
| libxml2 | 2.9.0 | 2.13.5 | XML |
| Jansson | 2.10 | 2.14 | JSON |
| Kerberos | 1.18 | 1.21.3 | MIT Kerberos |
| libcurl | 7.70.0 | 8.10.1 | HTTP client |
| SQLite | 3.30.0 | 3.46.1 | Metadata DB |
| LZ4 | 1.9.0 | 1.10.0 | Compression |
| Zstandard | 1.4.0 | 1.5.6 | Compression |
| XZ | 5.2.0 | 5.6.2 | Compression |
| Brotli | 1.0.0 | 1.1.0 | Compression |
| Bzip2 | 1.0.8 | 1.0.8 | Compression |

### 3.3 Libraries NOT Available on macOS

| Library | Linux Package | Reason Unavailable | Alternative |
|---------|--------------|--------------------|-------------|
| **libcephfs** | `libcephfs-devel` | Ceph project does not support macOS | S3 backend, Ceph NFS gateway |
| **librados** | `librados-devel` | Ceph project does not support macOS | S3 backend |
| **libradosstriper** | `libradosstriper-devel` | Ceph project does not support macOS | N/A |
| **libseccomp** | `libseccomp-devel` | Linux-specific syscall filtering | macOS `sandbox_exec` (Phase 4) |
| **liburing** | `liburing-devel` | Linux-specific io_uring interface | nginx thread pool |
| **voms-api-c** | `voms-api-c-devel` | No macOS port by VOMS project | Runtime dlopen fallback |
| **fuse3** | `fuse3-devel` | Different project on macOS (macFUSE) | macFUSE (OSXFUSE) |

### 3.4 macOS Frameworks (Built-in)

| Framework | Purpose | Link Flag |
|-----------|---------|-----------|
| **Security.framework** | Certificate handling, keychain access | `-framework Security` |
| **CoreFoundation.framework** | System utilities, CF types | `-framework CoreFoundation` |
| **CoreServices.framework** | FSEvents, system events | `-framework CoreServices` |
| **libSystem** | BSD libc, kqueue, kevent | Automatic (linked by default) |

---

## 4. Detailed Implementation Timeline

### Gantt Chart (14 Weeks)

```
Week:     1   2   3   4   5   6   7   8   9   10  11  12  13  14
         [=== Phase 1 ===]
Phase 1: Platform Detection & Build System
         [=== Phase 2 ===]
Phase 2: API Compatibility Layer
                 [=== Phase 3 ===]
Phase 3: Feature Gates & Runtime Detection
                         [=== Phase 4 ===]
Phase 4: Testing & CI Integration
                                 [=== Phase 5 ===]
Phase 5: Documentation & Release
```

### Critical Path

```
Week 1-2: Platform detection (MUST COMPLETE)
    ↓
Week 3-6: API wrappers (MUST COMPLETE)
    ↓
Week 7-8: Feature gates (MUST COMPLETE)
    ↓
Week 9-12: Testing (MUST COMPLETE)
    ↓
Week 13-14: Documentation & Release
```

### Milestone Checklist

**Milestone 1 (Week 2): First macOS Build**
- [ ] `config` detects macOS
- [ ] `CMakeLists.txt` builds on macOS
- [ ] Module compiles (warnings as errors)
- [ ] Module links successfully
- [ ] nginx starts with module loaded

**Milestone 2 (Week 6): API Completeness**
- [ ] All platform API functions implemented
- [ ] Unit tests pass for all wrappers
- [ ] Integration tests pass for I/O paths
- [ ] No `TODO` or `FIXME` in Phase 2 code

**Milestone 3 (Week 8): Feature Parity**
- [ ] XRootD protocol works (read/write/stat/list)
- [ ] WebDAV/HTTP works
- [ ] S3 backend works
- [ ] GSI authentication works
- [ ] Kerberos authentication works
- [ ] Configuration parsing works
- [ ] Logging works correctly

**Milestone 4 (Week 12): Test Coverage**
- [ ] 90%+ of Linux tests pass on macOS
- [ ] CI runs on every PR
- [ ] Performance benchmarks within 30% of Linux
- [ ] No memory leaks (valgrind/ASan clean)

**Milestone 5 (Week 14): Release Ready**
- [ ] Documentation complete
- [ ] Security review passed
- [ ] Release notes written
- [ ] v3.0.0 tag created
- [ ] Announced on mailing list

---

## 5. Risk Analysis & Mitigation

### Risk Matrix

| Risk | Probability | Impact | Severity | Mitigation |
|------|-------------|--------|----------|------------|
| CephFS unavailable on macOS | **Certain** | High | **CRITICAL** | Document clearly, recommend S3 backend |
| Performance degradation | Likely | Medium | **HIGH** | Benchmark, tune, document |
| macOS version fragmentation | Possible | Medium | **MEDIUM** | Target 12.0+, test on 3 versions |
| seccomp security gap | Possible | High | **HIGH** | Document, implement sandbox_exec (Phase 4) |
| FUSE SIP requirements | Certain | Medium | **MEDIUM** | Document SIP mod, provide non-FUSE alternative |
| Homebrew dependency | Likely | Low | **LOW** | Provide manual install instructions |
| Apple Silicon compatibility | Unlikely | Medium | **MEDIUM** | Test on M1/M2, use universal binaries |

### Detailed Risk Mitigation Plans

#### **Risk 1: CephFS Backend Unavailable (CRITICAL)**

**Impact:** Users with Ceph storage cannot use BriX-Cache on macOS

**Mitigation Strategy:**
1. **Documentation:** Clear warning in install guide
2. **Alternative Backends:**
   - S3 backend (Ceph has S3-compatible gateway)
   - Ceph NFS gateway (mount via NFS, serve via POSIX backend)
   - Ceph iSCSI gateway (mount as block device, format as APFS)
3. **Error Messages:** Helpful error at config time:
   ```
   ERROR: CephFS backend not available on macOS.
   Alternatives:
     1. Use S3 backend: brix_s3 on;
     2. Mount Ceph via NFS gateway
     3. Deploy on Linux instead
   ```

#### **Risk 2: Performance Degradation (HIGH)**

**Impact:** macOS deployments 30-50% slower than Linux

**Benchmarking Plan:**
```bash
# Benchmark suite (run on both Linux and macOS)
./tools/bench/brix-bench-read --size=1GB --io=sequential
./tools/bench/brix-bench-read --size=1GB --io=random
./tools/bench/brix-bench-write --size=1GB --io=sequential
./tools/bench/brix-bench-proxy --size=10GB

# Metrics to collect:
- Throughput (MB/s)
- Latency (p50, p95, p99)
- CPU utilization (%)
- Memory usage (MB)
- Context switches/sec
```

**Optimization Opportunities:**
1. **APFS clonefile():** Zero-copy file clones (macOS-only optimization)
2. **Grand Central Dispatch:** Better thread pool utilization
3. **Memory pressure handling:** Darwin API for memory management

#### **Risk 3: macOS Version Fragmentation (MEDIUM)**

**Impact:** API differences between macOS 12-15

**Compatibility Strategy:**
```c
/* Weak linking for macOS 13+ APIs */
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 130000
    /* macOS 13+ only */
    if (&clonefileat != NULL) {
        clonefileat(...);
    } else {
        /* Fallback for macOS 12 */
        brix_clonefile_fallback(...);
    }
#endif
```

**CI Testing Matrix:**
```yaml
strategy:
  matrix:
    macos-version:
      - macos-12  # Monterey (minimum)
      - macos-13  # Ventura
      - macos-14  # Sonoma
      - macos-15  # Sequoia (latest)
```

#### **Risk 4: seccomp Security Gap (HIGH)**

**Impact:** macOS lacks seccomp-bpf syscall filtering

**Mitigation:**
1. **Phase 2-3:** Document reliance on macOS system security
   - SIP (System Integrity Protection)
   - Gatekeeper (code signing enforcement)
   - XProtect (malware detection)
2. **Phase 4:** Implement `sandbox_exec` wrapper
   - Translate seccomp profiles to `.sb` format
   - Provide default macOS sandbox profiles
3. **Long-term:** Advocate for cross-platform security framework

#### **Risk 5: FUSE SIP Requirements (MEDIUM)**

**Impact:** macFUSE requires partial SIP disable

**Documentation:**
```markdown
## macFUSE Installation (Optional)

**WARNING:** macFUSE requires modifying System Integrity Protection (SIP).

### Steps to Enable macFUSE:

1. **Reboot to Recovery Mode** (hold Cmd+R during boot)
2. **Open Terminal** from Utilities menu
3. **Disable SIP partially:**
   ```bash
   csrutil enable --without kext
   ```
4. **Reboot normally**
5. **Install macFUSE:**
   ```bash
   brew install --cask macfuse
   ```
6. **Allow kernel extension:**
   - System Preferences → Security & Privacy → General
   - Click "Allow" for macFUSE

### Alternative (No SIP Modification):

Use S3 backend or mount remote storage via NFS/SMB instead of FUSE.
```

---

## 6. Success Criteria - Detailed Metrics

### 6.1 Build Success Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Clean build | Zero errors | `make 2>&1 | grep -i error` |
| Warnings | Zero (with `-Werror`) | `make 2>&1 | grep -i warning` |
| Binary size | ≤120% of Linux | `ls -lh objs/nginx` |
| Build time | ≤150% of Linux | `time make` |
| Startup time | ≤5 seconds | `time objs/nginx` |

### 6.2 Functional Success Metrics

| Function | Test | Pass Criteria |
|----------|------|---------------|
| XRootD read | `xrdcp root://.../file.root .` | File matches source (checksum) |
| XRootD write | `xrdcp file.root root://.../file.root` | File uploaded, readable |
| XRootD stat | `xrdfs stat root://.../file.root` | Correct size, mtime |
| XRootD list | `xrdfs ls root://.../dir/` | All files listed |
| WebDAV read | `curl -O https://.../file` | File matches source |
| WebDAV write | `curl -T file https://.../file` | File uploaded, readable |
| S3 read | `aws s3 cp s3://.../file .` | File matches source |
| S3 write | `aws s3 cp file s3://.../file` | File uploaded, readable |
| GSI auth | `xrdcp --auth gsi root://.../file .` | Auth succeeds with valid proxy |
| Kerberos auth | `xrdcp --auth krb5 root://.../file .` | Auth succeeds with valid ticket |

### 6.3 Test Coverage Metrics

| Suite | Linux Tests | macOS Ports | Target Pass Rate |
|-------|-------------|-------------|------------------|
| Unit tests | 156 | 156 | 100% |
| Integration tests | 89 | 86 | 95%+ |
| Ceph tests | 8 | 0 (skipped) | N/A |
| Fuzz tests | 12 | 12 | 100% |
| Performance tests | 24 | 24 | Within 30% |

### 6.4 Documentation Completeness

| Document | Sections | Screenshots | Code Examples | Review Status |
|----------|----------|-------------|---------------|---------------|
| Install guide | 12 | 8 | 15 | Peer-reviewed |
| Limitations doc | 8 | 2 | 5 | Peer-reviewed |
| Porting guide | 15 | 10 | 25 | Peer-reviewed |
| README update | 5 | 3 | 8 | Peer-reviewed |
| Changelog | 1 | 0 | 0 | Maintainer-approved |

---

## 7. Future Enhancements (Post-v3.0)

### 7.1 macOS-Specific Optimizations

#### **APFS clonefile() Support**

```c
/*
 * APFS clonefile() - Zero-copy file clone (macOS 10.12+)
 * 
 * Creates a copy-on-write clone of a file:
 * - Instant (no data copied)
 * - Space-efficient (shares blocks until modified)
 * - Perfect for snapshotting, backups
 */

#include <sys/clonefile.h>

int
brix_platform_clonefile(const char *src, const char *dst)
{
    int result = clonefile(src, dst, 0);
    if (result != 0) {
        /* clonefile() failed - fallback to regular copy */
        return brix_clonefile_fallback(src, dst);
    }
    return 0;
}
```

**Use Cases:**
- Snapshot creation for backups
- Instant file duplication
- Version control systems

#### **Grand Central Dispatch (GCD) Integration**

```c
/*
 * GCD thread pool - Better than pthreads on macOS
 * 
 * Benefits:
 * - Automatic thread count tuning
 * - Work-stealing scheduler
 * - Power-efficient (coalesces timers)
 */

#include <dispatch/dispatch.h>

static dispatch_queue_t brix_gcd_queue;

void
brix_gcd_init(void)
{
    /* Create concurrent queue with system-determined thread count */
    brix_gcd_queue = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
}

void
brix_gcd_async(void (*work)(void *), void *context)
{
    dispatch_async(brix_gcd_queue, ^{
        work(context);
    });
}
```

**Use Cases:**
- Async I/O operations
- Background processing
- Parallel file operations

#### **Keychain Integration**

```c
/*
 * macOS Keychain - Secure credential storage
 * 
 * Store:
 * - X.509 certificates
 * - Kerberos tickets
 * - Bearer tokens
 * - S3 credentials
 */

#include <Security/Security.h>

OSStatus
brix_keychain_store_token(const char *service, const char *account, 
                          const char *token, size_t token_len)
{
    SecKeychainItemRef item;
    SecKeychainAttribute attrs[2];
    SecKeychainAttributeInfo info;
    
    /* Set up attributes */
    attrs[0].tag = kSecLabelItemAttr;
    attrs[0].data = service;
    attrs[0].length = strlen(service);
    
    attrs[1].tag = kSecAccountItemAttr;
    attrs[1].data = account;
    attrs[1].length = strlen(account);
    
    info.count = 2;
    info.tag = (SecItemLabel *)attrs;
    
    /* Store in keychain */
    return SecKeychainAddGenericPassword(
        NULL,  /* Default keychain */
        strlen(service), service,
        strlen(account), account,
        token_len, token,
        &item
    );
}
```

**Use Cases:**
- Secure token storage
- Certificate management
- Credential rotation

### 7.2 Security Enhancements

#### **sandbox_exec Profile**

```sb
/*
 * macOS sandbox profile for BriX-Cache
 * File: /usr/local/share/brix/sandbox/default.sb
 */

(version 1)

;; Allow file operations on data directories
(allow file-read* file-write* file-create*
       (subpath "/data"))

;; Allow network operations (XRootD, HTTP, S3)
(allow network-outbound
       (remote tcp))
(allow network-inbound
       (local tcp "1094")   ; XRootD port
       (local tcp "8080"))  ; HTTP port

;; Allow system operations
(allow process-exec
       (literal "/bin/sh")
       (literal "/usr/bin/stat"))
(allow syscall)  ; TODO: Restrict to specific syscalls

;; Deny everything else
(deny default)
```

#### **Hardened Runtime Entitlements**

```xml
<!--
  BriX-Cache.entitlements
  For code signing with hardened runtime
-->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Allow JIT compilation (if needed) -->
    <key>com.apple.security.cs.allow-jit</key>
    <false/>
    
    <!-- Allow unsigned executable memory (if needed) -->
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <false/>
    
    <!-- Allow dyld environment variables (for debugging) -->
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    
    <!-- Network access -->
    <key>com.apple.security.network.server</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    
    <!-- File access -->
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
</dict>
</plist>
```

### 7.3 Performance Optimizations

#### **Memory Pressure Handling**

```c
/*
 * Darwin memory pressure API
 * 
 * Respond to system memory pressure:
 * - Drop caches when under pressure
 * - Throttle background operations
 * - Avoid OOM kills
 */

#include <sys/sysctl.h>

int
brix_get_memory_pressure(void)
{
    int pressure;
    size_t size = sizeof(pressure);
    
    if (sysctlbyname("kern.memorystatus_pressure", 
                     &pressure, &size, NULL, 0) != 0) {
        return 0;  /* Assume normal */
    }
    
    return pressure;
}

void
brix_respond_to_memory_pressure(int pressure)
{
    switch (pressure) {
        case 0:  /* Normal */
            brix_cache_set_size(BRIX_CACHE_MAX_SIZE);
            break;
        case 1:  /* Warning */
            brix_cache_set_size(BRIX_CACHE_MAX_SIZE * 3 / 4);
            break;
        case 2:  /* Urgent */
            brix_cache_set_size(BRIX_CACHE_MAX_SIZE / 2);
            break;
        case 3:  /* Critical */
            brix_cache_purge();
            break;
    }
}
```

---

## 8. Appendix: Reference Implementations

### 8.1 Complete Platform Detection Example

```c
/*
 * examples/platform-detect.c - Complete platform detection example
 * 
 * Compile:
 *   gcc -I../src examples/platform-detect.c -o platform-detect
 * 
 * Run:
 *   ./platform-detect
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#if defined(__linux__)
    #define PLATFORM_LINUX 1
    #define PLATFORM_DARWIN 0
#elif defined(__APPLE__) && defined(__MACH__)
    #define PLATFORM_LINUX 0
    #define PLATFORM_DARWIN 1
#else
    #error "Unsupported platform"
#endif

int
main(int argc, char *argv[])
{
    struct utsname uts;
    
    if (uname(&uts) != 0) {
        perror("uname");
        return 1;
    }
    
    printf("Platform Detection Report\n");
    printf("=========================\n\n");
    
#if PLATFORM_LINUX
    printf("Platform:     Linux\n");
    printf("Kernel:       %s\n", uts.release);
    printf("Version:      %s\n", uts.version);
    printf("Machine:      %s\n", uts.machine);
    
    /* Linux-specific checks */
    printf("\nFeature Availability:\n");
    printf("  io_uring:     %s\n", 
           access("/proc/sys/fs/aio-max-nr", F_OK) == 0 ? "yes" : "no");
    printf("  seccomp:      yes (kernel feature)\n");
    printf("  inotify:      yes (kernel feature)\n");
    printf("  epoll:        yes (kernel feature)\n");
    printf("  splice:       yes (kernel feature)\n");
    printf("  posix_fadvise: yes (glibc feature)\n");
    
#elif PLATFORM_DARWIN
    printf("Platform:     macOS (Darwin)\n");
    printf("Kernel:       %s\n", uts.release);
    printf("Version:      %s\n", uts.version);
    printf("Machine:      %s\n", uts.machine);
    
    /* macOS version */
    int major, minor, patch;
    if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) == 3) {
        /* Darwin version to macOS version mapping */
        int macos_major = major - 4;  /* Darwin 21 = macOS 12 */
        printf("macOS:        %d.%d.%d\n", macos_major, minor, patch);
    }
    
    printf("\nFeature Availability:\n");
    printf("  io_uring:     no (Linux-only)\n");
    printf("  seccomp:      no (Linux-only)\n");
    printf("  inotify:      no (Linux-only)\n");
    printf("  epoll:        no (uses kqueue)\n");
    printf("  splice:       no (Linux-only)\n");
    printf("  posix_fadvise: no (XNU lacks implementation)\n");
    printf("  kqueue:       yes (BSD feature)\n");
    printf("  FSEvents:     yes (macOS feature)\n");
    printf("  clonefile:    %s (APFS only)\n", 
           major >= 16 ? "yes" : "no");  /* Darwin 16+ = APFS */
    printf("  Keychain:     yes (macOS feature)\n");
    
#endif
    
    printf("\nCompiler:\n");
#if defined(__clang__)
    printf("  Compiler:     Clang %d.%d.%d\n", 
           __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    printf("  Compiler:     GCC %d.%d.%d\n", 
           __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
    
    printf("  Architecture: %s\n", 
#if defined(__x86_64__)
           "x86_64 (Intel/AMD)"
#elif defined(__arm64__) || defined(__aarch64__)
           "arm64 (Apple Silicon)"
#else
           "unknown"
#endif
          );
    
    return 0;
}
```

### 8.2 Homebrew Install Script

```bash
#!/usr/bin/env bash
#
# install-macos-deps.sh - Install all BriX-Cache dependencies on macOS
#
# Usage:
#   ./install-macos-deps.sh [--optional] [--force]
#
# Options:
#   --optional  Install optional dependencies (macFUSE)
#   --force     Reinstall existing packages
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
OPTIONAL=false
FORCE=false

for arg in "$@"; do
    case $arg in
        --optional)
            OPTIONAL=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo -e "${RED}Error: Homebrew not found${NC}"
    echo "Install from https://brew.sh"
    exit 1
fi

echo -e "${GREEN}Installing BriX-Cache dependencies...${NC}"
echo

# Core dependencies (mandatory)
CORE_DEPS=(
    "openssl@3"
    "pcre2"
    "libxml2"
    "jansson"
    "krb5"
    "libcurl"
    "sqlite"
    "lz4"
    "zstd"
    "xz"
    "brotli"
    "bzip2"
)

echo "Core dependencies:"
for dep in "${CORE_DEPS[@]}"; do
    if brew list "$dep" &> /dev/null && [ "$FORCE" = false ]; then
        echo -e "  ${GREEN}✓${NC} $dep (already installed)"
    else
        echo -e "  Installing $dep..."
        brew install "$dep"
    fi
done

echo

# Optional dependencies
if [ "$OPTIONAL" = true ]; then
    echo "Optional dependencies:"
    
    # macFUSE (requires cask)
    if brew list --cask macfuse &> /dev/null && [ "$FORCE" = false ]; then
        echo -e "  ${GREEN}✓${NC} macFUSE (already installed)"
    else
        echo -e "  ${YELLOW}!${NC} macFUSE requires SIP modification"
        echo "     See docs/01-getting-started/macos-install.md"
        read -p "Install macFUSE? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            brew install --cask macfuse
        fi
    fi
else
    echo "Optional dependencies skipped (use --optional to install)"
fi

echo
echo -e "${GREEN}Installation complete!${NC}"
echo
echo "Next steps:"
echo "  1. cd /path/to/brix-cache"
echo "  2. ./configure --with-stream --with-threads --add-module=\$(pwd)"
echo "  3. make -j\$(sysctl -n hw.ncpu)"
echo
```

---

## 9. Sign-Off

### Document Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| **Author** | Robert Currie | 2026-09-11 | [Digital] |
| **Technical Reviewer** | [TBD] | [TBD] | [TBD] |
| **Security Reviewer** | [TBD] | [TBD] | [TBD] |
| **Project Maintainer** | [TBD] | [TBD] | [TBD] |

### Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-09-11 | Robert Currie | Initial draft |
| 1.1 | [TBD] | [TBD] | [TBD] |

### Distribution List

- BriX-Cache Development Team
- Security Review Team
- Documentation Team
- Release Engineering

---

**Document Classification:** Internal Use Only  
**Retention Period:** 7 years  
**Next Review Date:** 2027-03-11

---

*This document is a living specification and will be updated as implementation progresses. All changes must be reviewed and approved by the project maintainer.*
