# macOS Support Plan for BriX-Cache v3.0

## Executive Summary

This document outlines the roadmap for adding macOS support to BriX-Cache, enabling the module to run on macOS hosts while maintaining full functionality on Linux. The goal is to gate Linux-exclusive features behind a single `BRIX_LINUX_ONLY` compile flag and identify all external library dependencies required for macOS builds.

**Target Release:** Version 3.0  
**Priority:** Medium-High  
**Estimated Effort:** 3-4 months  
**Risk Level:** Medium (requires careful testing of platform-specific code paths)

---

## 1. Current State Analysis

### 1.1 Platform-Specific Code Identified

The following Linux-specific dependencies and APIs are currently used without platform guards:

#### **1.1.1 Linux-Only Kernel APIs**
- **`io_uring`** - Async I/O backend (Linux 5.1+)
  - Files: `src/fs/backend/sd_pblock.c`, `tests/c/aio_smoke.c`
  - Directive: `brix_io_uring on|off`
  - Status: **NO macOS equivalent** - must be disabled on macOS

- **`inotify`** - Filesystem event monitoring
  - Used for: File change detection, cache invalidation
  - Status: macOS uses **`kqueue`** with `EVFILT_VNODE`

- **`epoll`** - Event notification (nginx core handles this)
  - Status: nginx abstracts this; macOS uses `kqueue` transparently

- **`sendfile()`** - Zero-copy file transfer
  - macOS signature differs from Linux
  - Status: nginx abstracts this

- **`posix_fadvise()`** - File access hints
  - Used in: `tests/unit/test_sd_block_zerocopy.c`
  - Status: **Not available on macOS** - must be stubbed

- **`splice()`** - Pipe-based zero-copy I/O
  - Status: **Linux-only** - no macOS equivalent

#### **1.1.2 Security Features**
- **`seccomp-bpf`** - Syscall filtering
  - Files: `src/core/seccomp/seccomp_core.c`
  - Directive: `brix_seccomp audit|enforce`
  - Status: **Linux-only** - macOS uses **`sandbox_exec`** with different policy language

- **SELinux integration** - Mandatory access control
  - Files: `packaging/rpm/nginx-mod-brix-cache-selinux`
  - Status: **Linux-only** - macOS uses **`sandboxd`** / AppArmor-like mechanisms

#### **1.1.3 Filesystem Features**
- **CephFS backend** - Distributed filesystem
  - Dependencies: `libcephfs`, `librados`, `libradosstriper`
  - Status: **No official macOS support** from Ceph project

- **FUSE mounts** - Userspace filesystem
  - Dependencies: `fuse3`
  - Status: macOS has **`macFUSE`** (OSXFUSE fork) - API compatible but different package

- **User namespaces** - Container isolation
  - Files: `tests/userns/c/userns_broker_test.c`
  - Status: **Linux-only** - macOS has different sandboxing model

### 1.2 Current Build System

The `config` file and `CMakeLists.txt` assume Linux:
- Hardcoded paths: `/usr/lib`, `/usr/share`, `/etc`
- RPM/deb packaging only
- Systemd service files
- Linux-specific compiler flags (`-fcf-protection=full` may not work on macOS clang)

---

## 2. Proposed Architecture

### 2.1 Platform Abstraction Layer

Introduce a new platform abstraction layer in `src/platform/`:

```
src/platform/
├── platform.h              # Platform detection macros
├── platform.c              # Common platform code
├── linux/
│   ├── io_uring_wrapper.c  # io_uring implementation
│   ├── seccomp_wrapper.c   # seccomp implementation
│   ├── inotify_wrapper.c   # inotify implementation
│   └── posix_wrapper.c     # Linux-specific POSIX wrappers
└── darwin/
    ├── kqueue_wrapper.c    # kqueue-based event monitoring
    ├── sandbox_wrapper.c   # macOS sandbox_exec wrapper
    ├── fsevents_wrapper.c  # FSEvents for file monitoring
    └── posix_wrapper.c     # macOS-specific POSIX wrappers
```

### 2.2 New Compile-Time Flag

**`BRIX_LINUX_ONLY`** (default: `0` on Linux, `1` on macOS)

When set to `1`:
- Disables all Linux-only features at compile time
- Excludes Linux-specific object files from build
- Provides stub implementations for platform-specific APIs

When set to `0` (or undefined):
- Enables platform detection at runtime
- Compiles all platform-specific code with appropriate `#if` guards

**Usage:**
```bash
# Linux build (default)
./configure --add-module=/path/to/brix-cache

# macOS build
BRIX_LINUX_ONLY=0 ./configure --add-module=/path/to/brix-cache
# OR explicitly:
CFLAGS="-DBRIX_PLATFORM_DARWIN=1" ./configure --add-module=/path/to/brix-cache
```

### 2.3 Feature Matrix

| Feature | Linux | macOS | Notes |
|---------|-------|-------|-------|
| **XRootD protocol** | ✅ Full | ✅ Full | Pure C, no platform deps |
| **WebDAV/HTTP** | ✅ Full | ✅ Full | nginx core handles this |
| **S3 backend** | ✅ Full | ✅ Full | Pure C, HTTP-based |
| **CephFS backend** | ✅ Full | ❌ Disabled | No macOS Ceph support |
| **io_uring async I/O** | ✅ Opt-in | ❌ Disabled | Use nginx thread pool on macOS |
| **seccomp filtering** | ✅ Opt-in | ❌ Disabled | Use macOS sandbox_exec (future) |
| **SELinux labels** | ✅ RPM auto | ❌ N/A | macOS has no SELinux |
| **inotify/FSEvents** | ✅ inotify | ⚠️ kqueue/FSEvents | Different API, same purpose |
| **FUSE mounts** | ✅ fuse3 | ⚠️ macFUSE | API-compatible, different install |
| **User namespaces** | ✅ Linux | ❌ Disabled | Different security model |
| **sendfile()** | ✅ Linux | ✅ macOS | nginx abstracts differences |
| **posix_fadvise()** | ✅ Linux | ❌ Stubbed | No-op on macOS |
| **GSI authentication** | ✅ Full | ✅ Full | OpenSSL-based, cross-platform |
| **Kerberos** | ✅ Full | ✅ Full | macOS has native Kerberos |
| **CVMFS client** | ✅ Full | ⚠️ Needs port | CVMFS has macOS support upstream |

---

## 3. External Library Dependencies for macOS

### 3.1 Required Libraries (Install via Homebrew)

```bash
# Core dependencies (same as Linux, available via Homebrew)
brew install \
    openssl@3 \
    pcre2 \
    zlib \
    libxml2 \
    jansson \
    krb5 \
    libcurl \
    sqlite \
    lz4 \
    zstd \
    xz \
    brotli \
    bzip2

# FUSE support (optional, for FUSE mounts)
brew install --cask macfuse
# Note: Requires disabling System Integrity Protection (SIP) partially
# See: https://github.com/osxfuse/osxfuse/wiki
```

### 3.2 Libraries NOT Available on macOS

| Library | Linux Package | macOS Alternative | Action |
|---------|--------------|-------------------|--------|
| **libcephfs** | `libcephfs-devel` | None | Disable Ceph backend on macOS |
| **librados** | `librados-devel` | None | Disable RADOS backend on macOS |
| **libradosstriper** | `libradosstriper-devel` | None | Disable striper backend on macOS |
| **libseccomp** | `libseccomp-devel` | None (sandbox_exec exists) | Disable seccomp, add macOS sandbox later |
| **liburing** | `liburing-devel` | None | Disable io_uring, use thread pool |
| **voms-api** | `voms-api-c-devel` | None | Runtime dlopen fallback to disabled |
| **fuse3** | `fuse3-devel` | macFUSE (OSXFUSE) | Use macFUSE, API-compatible |

### 3.3 macOS-Specific Frameworks

These are built into macOS and require no installation:

- **`Security.framework`** - Certificate handling, keychain access
- **`CoreFoundation.framework`** - System-level utilities
- **`libSystem`** - BSD libc (includes `kqueue`, `kevent`)

---

## 4. Implementation Plan

### Phase 1: Platform Detection & Build System (Weeks 1-2)

**Goal:** Enable compilation on macOS with stub implementations for missing features.

#### Tasks:
1. **Add platform detection to `config` file:**
   ```bash
   case "$(uname -s)" in
       Linux*)
           PLATFORM=linux
           CFLAGS="$CFLAGS -DBRIX_PLATFORM_LINUX=1"
           ;;
       Darwin*)
           PLATFORM=darwin
           CFLAGS="$CFLAGS -DBRIX_PLATFORM_DARWIN=1 -DBRIX_LINUX_ONLY=0"
           # Remove Linux-specific flags
           CFLAGS=$(echo "$CFLAGS" | sed 's/-fcf-protection=full//')
           CFLAGS=$(echo "$CFLAGS" | sed 's/-fstack-clash-protection//')
           ;;
   esac
   ```

2. **Update `CMakeLists.txt` for macOS:**
   - Add platform detection
   - Conditionally exclude Linux-only source files
   - Link macOS frameworks where needed

3. **Create platform detection header:**
   ```c
   // src/platform/platform.h
   #ifndef BRIX_PLATFORM_H
   #define BRIX_PLATFORM_H

   #if defined(__linux__)
   #define BRIX_PLATFORM_LINUX 1
   #define BRIX_PLATFORM_DARWIN 0
   #elif defined(__APPLE__) && defined(__MACH__)
   #define BRIX_PLATFORM_LINUX 0
   #define BRIX_PLATFORM_DARWIN 1
   #else
   #error "Unsupported platform"
   #endif

   #ifndef BRIX_LINUX_ONLY
   #define BRIX_LINUX_ONLY BRIX_PLATFORM_LINUX
   #endif

   #endif
   ```

4. **Guard Linux-specific source files in `config`:**
   ```bash
   if [ "$PLATFORM" = "linux" ]; then
       NGX_ADDON_SRCS="$NGX_ADDON_DIR/src/core/seccomp/seccomp_core.c ..."
   fi
   ```

### Phase 2: API Compatibility Layer (Weeks 3-6)

**Goal:** Provide working implementations or stubs for all platform-specific APIs.

#### Tasks:

1. **File I/O wrappers (`src/platform/posix_wrapper.c`):**
   ```c
   #if BRIX_PLATFORM_DARWIN
   // posix_fadvise() not available on macOS
   static inline int brix_posix_fadvise(int fd, off_t offset, off_t len, int advice) {
       return 0; // No-op, not an error
   }

   // sendfile() has different signature on macOS
   static inline ssize_t brix_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
       off_t sf_offset = *offset;
       int sf_count = count;
       int result = sendfile(in_fd, out_fd, sf_offset, &sf_count, NULL, 0);
       *offset += sf_count;
       return (result == 0) ? sf_count : -1;
   }
   #endif
   ```

2. **Event monitoring (`src/platform/darwin/kqueue_wrapper.c`):**
   ```c
   #if BRIX_PLATFORM_DARWIN
   #include <sys/event.h>

   typedef struct {
       int kq_fd;
       struct kevent events[64];
   } brix_kqueue_ctx_t;

   int brix_kqueue_init(brix_kqueue_ctx_t *ctx) {
       ctx->kq_fd = kqueue();
       return (ctx->kq_fd >= 0) ? 0 : -1;
   }

   int brix_kqueue_watch_file(brix_kqueue_ctx_t *ctx, int fd, uint32_t filter) {
       struct kevent ev;
       EV_SET(&ev, fd, EVFILT_VNODE,
              EV_ADD | EV_ENABLE | EV_CLEAR,
              filter, 0, NULL);
       return kevent(ctx->kq_fd, &ev, 1, NULL, 0, NULL);
   }
   #endif
   ```

3. **Security wrappers (`src/platform/darwin/sandbox_wrapper.c`):**
   ```c
   #if BRIX_PLATFORM_DARWIN
   // Stub for seccomp equivalent - future work
   int brix_sandbox_init(const char *profile) {
       // TODO: Use sandbox_exec(3) with macOS profile
       // For now, return success but log warning
       ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                     "brix_sandbox: macOS sandbox not yet implemented");
       return 0;
   }
   #endif
   ```

4. **Async I/O fallback:**
   ```c
   // In nginx config, force thread pool on macOS
   #if BRIX_PLATFORM_DARWIN
   // io_uring not available - always use thread pool
   #define brix_aio_submit brix_aio_submit_thread_pool
   #endif
   ```

### Phase 3: Feature Gates & Runtime Detection (Weeks 7-8)

**Goal:** Ensure all Linux-only features are properly gated and provide clear error messages.

#### Tasks:

1. **Add runtime feature detection:**
   ```c
   // src/core/feature_detect.c
   typedef struct {
       int has_io_uring;
       int has_seccomp;
       int has_inotify;
       int has_cephfs;
   } brix_features_t;

   static brix_features_t g_features;

   void brix_detect_features(void) {
   #if BRIX_PLATFORM_LINUX
       g_features.has_io_uring = (access("/proc/sys/fs/aio-max-nr", F_OK) == 0);
       g_features.has_seccomp = 1; // Compiled in
       g_features.has_inotify = 1;
       g_features.has_cephfs = BRIX_HAVE_CEPH;
   #elif BRIX_PLATFORM_DARWIN
       g_features.has_io_uring = 0;
       g_features.has_seccomp = 0;
       g_features.has_inotify = 0;
       g_features.has_cephfs = 0;
   #endif
   }
   ```

2. **Update directives to check platform:**
   ```c
   // In directive handlers
   static char *
   brix_cmd_io_uring(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
   {
   #if BRIX_PLATFORM_DARWIN
       return NGX_CONF_ERROR;
       "io_uring is not available on macOS";
   #endif
       if (!g_features.has_io_uring) {
           ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "io_uring not available on this system");
           return NGX_CONF_ERROR;
       }
       // ... rest of handler
   }
   ```

3. **Add startup warning for missing features:**
   ```c
   void brix_log_feature_status(void) {
       ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                     "BriX-Cache features: io_uring=%s seccomp=%s cephfs=%s",
                     g_features.has_io_uring ? "yes" : "no",
                     g_features.has_seccomp ? "yes" : "no",
                     g_features.has_cephfs ? "yes" : "no");
   }
   ```

### Phase 4: Testing & CI Integration (Weeks 9-12)

**Goal:** Ensure macOS builds are tested automatically and all features work as expected.

#### Tasks:

1. **Add macOS to GitHub Actions CI:**
   ```yaml
   # .github/workflows/build.yml
   jobs:
     build:
       strategy:
         matrix:
           os: [ubuntu-latest, macos-latest]
       runs-on: ${{ matrix.os }}
       steps:
         - uses: actions/checkout@v4
         - name: Install dependencies (macOS)
           if: runner.os == 'macOS'
           run: |
             brew install openssl@3 pcre2 libxml2 jansson krb5 libcurl sqlite
         - name: Configure
           run: |
             ./configure --with-stream --with-threads --add-module=$PWD
         - name: Build
           run: make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc)
   ```

2. **Create macOS-specific test suite:**
   - Port existing unit tests to macOS
   - Skip tests that require Linux-only features
   - Add tests for macOS-specific code paths

3. **Document known limitations:**
   - Create `docs/01-getting-started/macos-install.md`
   - List unsupported features clearly
   - Provide workarounds where possible

### Phase 5: Documentation & Release (Weeks 13-14)

**Goal:** Complete documentation and prepare for v3.0 release.

#### Tasks:

1. **Update installation guides:**
   - Add macOS-specific installation steps
   - Document Homebrew dependencies
   - Explain feature limitations

2. **Update API documentation:**
   - Mark Linux-only directives clearly
   - Document macOS equivalents where they exist

3. **Create migration guide:**
   - For users moving from Linux to macOS deployments
   - Configuration differences to be aware of

---

## 5. Modified Files List

### 5.1 Build System Files
- `config` - Add platform detection, conditional compilation
- `CMakeLists.txt` - Add macOS support, platform-specific source lists
- `packaging/rpm/build-rpm.sh` - Note: RPM only, no changes needed
- `BUILD.md` - Add macOS build section
- `BUILD_INSTALL.md` - Add macOS installation section

### 5.2 Source Files (New)
- `src/platform/platform.h` - Platform detection macros
- `src/platform/platform.c` - Common platform code
- `src/platform/linux/io_uring_wrapper.c` - Linux io_uring implementation
- `src/platform/linux/seccomp_wrapper.c` - Linux seccomp implementation
- `src/platform/linux/inotify_wrapper.c` - Linux inotify implementation
- `src/platform/darwin/kqueue_wrapper.c` - macOS kqueue implementation
- `src/platform/darwin/sandbox_wrapper.c` - macOS sandbox stub
- `src/platform/darwin/fsevents_wrapper.c` - macOS FSEvents implementation
- `src/platform/darwin/posix_wrapper.c` - macOS POSIX wrappers

### 5.3 Source Files (Modified)
- `src/core/feature_detect.c` - Add runtime feature detection
- `src/fs/backend/sd_pblock.c` - Guard io_uring usage
- `src/core/seccomp/seccomp_core.c` - Guard with `BRIX_PLATFORM_LINUX`
- All files using `inotify`, `sendfile`, `posix_fadvise` - Add platform guards
- `config` - Add platform detection logic

### 5.4 Test Files
- `tests/unit/*.c` - Add platform guards where needed
- `.github/workflows/build.yml` - Add macOS CI job
- `tests/c/aio_smoke.c` - Skip on macOS or use thread pool fallback

### 5.5 Documentation Files (New)
- `docs/01-getting-started/macos-install.md` - macOS installation guide
- `docs/05-operations/macos-limitations.md` - Feature limitations on macOS
- `docs/09-developer-guide/platform-porting-guide.md` - Guide for future platform ports

### 5.6 Documentation Files (Modified)
- `README.md` - Add macOS support badge
- `CHANGELOG.md` - Document macOS support addition
- `docs/index.md` - Update platform support matrix

---

## 6. Risks & Mitigations

### Risk 1: CephFS Backend Unavailable
**Impact:** High for users relying on Ceph storage  
**Mitigation:** 
- Document clearly that CephFS is Linux-only
- Recommend S3 backend as alternative on macOS
- Consider Ceph NFS gateway as workaround

### Risk 2: Performance Differences
**Impact:** Medium - kqueue vs epoll, different I/O paths  
**Mitigation:**
- Benchmark both platforms thoroughly
- Document expected performance characteristics
- Tune defaults for each platform

### Risk 3: macOS Version Fragmentation
**Impact:** Medium - different macOS versions have different APIs  
**Mitigation:**
- Target macOS 12.0+ (Monterey) as minimum
- Use weak linking for newer APIs
- Test on multiple macOS versions in CI

### Risk 4: Security Feature Parity
**Impact:** High - seccomp provides strong security guarantees  
**Mitigation:**
- Document security differences clearly
- Implement macOS sandbox_exec as future enhancement
- Rely on macOS system security (SIP, Gatekeeper) in interim

### Risk 5: FUSE Compatibility
**Impact:** Medium - macFUSE requires SIP modification  
**Mitigation:**
- Document SIP requirements clearly
- Provide alternative (non-FUSE) deployment modes
- Consider using native macOS filesystem APIs instead

---

## 7. Success Criteria

### 7.1 Build Success
- [ ] Clean build on macOS 12+ with Xcode 14+
- [ ] All compiler warnings treated as errors
- [ ] No runtime crashes on startup
- [ ] Binary size within 20% of Linux build

### 7.2 Functional Success
- [ ] XRootD protocol works (read/write/stat/list)
- [ ] WebDAV/HTTP works
- [ ] S3 backend works
- [ ] GSI authentication works
- [ ] Kerberos authentication works
- [ ] All non-Ceph backends work
- [ ] Configuration file parsing works
- [ ] Logging works correctly

### 7.3 Test Coverage
- [ ] 90%+ of Linux test suite passes on macOS
- [ ] Platform-specific tests added for macOS code
- [ ] CI runs on every PR for macOS
- [ ] Performance benchmarks within 30% of Linux

### 7.4 Documentation
- [ ] Installation guide complete
- [ ] Feature limitations documented
- [ ] Troubleshooting guide for common macOS issues
- [ ] API differences documented

---

## 8. Future Enhancements (Post-v3.0)

### 8.1 macOS-Specific Features
- **Touch Bar support** for monitoring (niche, but unique)
- **Keychain integration** for certificate storage
- **launchd** service management instead of systemd
- **Notarization** for distribution outside Homebrew

### 8.2 Security Enhancements
- **sandbox_exec** profile for BriX-Cache
- **Hardened Runtime** entitlements
- **System Integrity Protection** compatibility testing

### 8.3 Performance Optimizations
- **APFS** clone file support (`clonefile()`)
- **Grand Central Dispatch** for async operations
- **Memory pressure** handling via Darwin APIs

---

## 9. Appendix: Quick Reference

### 9.1 macOS Build Command
```bash
# Prerequisites
brew install nginx openssl@3 pcre2 libxml2 jansson krb5 libcurl sqlite

# Build
export CFLAGS="-I$(brew --prefix openssl)/include"
export LDFLAGS="-L$(brew --prefix openssl)/lib"
./configure --with-stream --with-threads --add-module=$(pwd)
make -j$(sysctl -n hw.ncpu)
```

### 9.2 Feature Availability Quick Reference

| Feature | Linux | macOS | Notes |
|---------|-------|-------|-------|
| XRootD | ✅ | ✅ | Full support |
| WebDAV | ✅ | ✅ | Full support |
| S3 | ✅ | ✅ | Full support |
| CephFS | ✅ | ❌ | No macOS Ceph |
| io_uring | ✅ | ❌ | Use thread pool |
| seccomp | ✅ | ❌ | Future: sandbox_exec |
| FUSE | ✅ | ⚠️ | macFUSE (SIP req.) |
| GSI | ✅ | ✅ | OpenSSL-based |
| Kerberos | ✅ | ✅ | Native on macOS |
| CVMFS | ✅ | ⚠️ | Needs porting |

### 9.3 Homebrew Dependencies Command
```bash
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
    xz \
    brotli \
    bzip2
```

---

## 10. Sign-Off

**Author:** [Your Name]  
**Date:** 2026-09-11  
**Reviewers:** [TBD]  
**Approved:** [TBD]  
**Target Milestone:** v3.0.0  
**JIRA/Ticket:** [TBD]

---

*This document is a living specification and should be updated as implementation progresses.*
