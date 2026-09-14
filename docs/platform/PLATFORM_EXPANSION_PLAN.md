# Platform Expansion Plan: Windows & ARM64 Support

**Document Status**: Draft Plan  
**Version**: 1.0  
**Date**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Author**: Platform Abstraction Layer Team

---

## Executive Summary

This document outlines the strategic plan for expanding the BriX-Cache Platform Abstraction Layer (PAL) to support:

1. **Windows (Win32/Win64)** - Full nginx/Windows compatibility
2. **ARM64 Linux** - Native ARM64 servers (AWS Graviton, Ampere, etc.)
3. **ARM64 macOS** - Apple Silicon optimization (already supported, needs optimization)

The PAL architecture enables this expansion without modifying business logic code.

---

## 1. Windows Support

### 1.1 nginx/Windows Status Assessment

**Current nginx/Windows Limitations** (per nginx.org):
- ⚠️ **Beta status** - Production use not recommended by nginx upstream
- ⚠️ Uses **Win32 API** (not Cygwin)
- ⚠️ Only `select()` and `poll()` connection processing (no epoll/kqueue equivalent)
- ⚠️ **Lower performance and scalability** expected
- ✅ Provides **almost all UNIX functionality**
- ❌ Missing: XSLT filter, image filter, GeoIP module, embedded Perl

**Decision Point**: Given nginx/Windows limitations, BriX-Cache Windows support should target:
- **Development/testing environments** on Windows
- **Production deployments** via WSL2 (Windows Subsystem for Linux)
- **Native Windows production** only for specific use cases where nginx limitations are acceptable

### 1.2 Windows PAL Implementation Plan

#### Phase 1: Core Infrastructure (Weeks 1-2)

**Directory Structure**:
```
src/platform/windows/
├── posix_wrapper.c      # Win32 file/pipe operations
├── event_wrapper.c      # IOCP/select emulation
├── fs_watcher.c         # ReadDirectoryChangesW
├── security_wrapper.c   # Windows security tokens
├── copy_range.c         # CopyFile2/FSCTL_COPY_FILE
├── aio_wrapper.c        # IOCP-based async I/O
└── win32_compat.h       # Windows-specific type definitions
```

**Build Integration**:
```bash
# config script additions
if [ "$BRIX_PLATFORM" = "windows" ]; then
    BRIX_PLATFORM_WINDOWS=1
    CFLAGS="$CFLAGS -DBRIX_PLATFORM_WINDOWS=1"
    CFLAGS="$CFLAGS -D_WIN32_WINNT=0x0602"  # Windows 8 minimum
    CFLAGS="$CFLAGS -DWIN32_LEAN_AND_MEAN"
    CFLAGS="$CFLAGS -D_CRT_SECURE_NO_WARNINGS"
    
    # Link against Windows libraries
    CORE_LIBS="$CORE_LIBS -lws2_32 -ladvapi32 -lkernel32"
    
    PAL_SRCS="$ngx_addon_dir/src/platform/windows/*.c"
fi
```

**Key Win32 API Mappings**:

| PAL Function | Win32 Implementation | Notes |
|--------------|---------------------|-------|
| `brix_plat_anon_fd()` | `CreateFile()` + `FILE_FLAG_DELETE_ON_CLOSE` | Returns HANDLE cast to fd |
| `brix_plat_sendfile()` | `TransmitFile()` | Win32 equivalent |
| `brix_plat_eventfd()` | `WSAEventSelect()` or pipe emulation | No native eventfd |
| `brix_plat_pipe2()` | `CreatePipe()` + `SetHandleInformation()` | |
| `brix_plat_random()` | `BCryptGenRandom()` | Cryptographic RNG |
| `brix_plat_getxattr()` | `GetNamedSecurityInfo()` | NTFS alternate data streams |
| `brix_plat_execvpe()` | `CreateProcessW()` | PATH search via `SearchPathW()` |
| `brix_plat_fs_watcher_*()` | `ReadDirectoryChangesW()` | Directory monitoring |

#### Phase 2: File Descriptor Abstraction (Weeks 3-4)

**Challenge**: Windows uses HANDLE, not file descriptors

**Solution**: fd-to-HANDLE wrapper layer
```c
// src/platform/windows/win32_compat.h
typedef struct {
    union {
        int fd;
        HANDLE handle;
    };
    int type;  // FD_FILE, FD_SOCKET, FD_PIPE
} brix_win32_handle_t;

// Conversion functions
static inline HANDLE brix_win32_fd_to_handle(int fd);
static inline int brix_win32_handle_to_fd(HANDLE handle, int type);
```

**Implementation Priority**:
1. ✅ File I/O operations (highest priority)
2. ✅ Socket operations (WSA2 compatibility)
3. ⚠️ Pipe operations (limited functionality)
4. ❌ Event operations (select-only fallback)

#### Phase 3: Event Loop Adaptation (Weeks 5-6)

**Challenge**: nginx/Windows uses `select()`, not epoll/kqueue

**Options**:
1. **IOCP-based event loop** (best performance, most complex)
2. **select() emulation** (compatible with nginx, lower performance)
3. **WSAPoll()** (Windows Vista+, middle ground)

**Recommended**: Option 2 for compatibility, Option 1 for future optimization

```c
// src/platform/windows/event_wrapper.c
int brix_plat_event_init(void)
{
    // Option 2: select()-based
    return 0;  // No-op, nginx handles select()
}

// Option 1: IOCP-based (future)
int brix_plat_event_init(void)
{
    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    return (iocp != NULL) ? 0 : -1;
}
```

#### Phase 4: Security & Permissions (Week 7)

**Windows Security Model Differences**:
- No UID/GID (uses SIDs and security tokens)
- No POSIX permissions (uses ACLs)
- No capabilities (uses privileges)

**Stub Implementation**:
```c
int brix_plat_setfsuid(uid_t uid)
{
    // Windows doesn't support setfsuid
    // Stub: return success for compatibility
    (void)uid;
    return 0;
}

int brix_plat_security_init(const char *profile)
{
    // Windows: could use Job Objects or AppContainer
    // For now, stub for compatibility
    (void)profile;
    return 0;
}
```

#### Phase 5: Testing & Validation (Week 8)

**Test Matrix**:
- Windows Server 2019/2022
- Windows 10/11
- WSL2 (Ubuntu on Windows)
- Cross-compilation from Linux (mingw-w64)

---

## 2. ARM64 Linux Support

### 2.1 Target Platforms

**Server Platforms**:
- AWS Graviton2/Graviton3
- Ampere Altra/Altra Max
- Marvell ThunderX
- Huawei Kunpeng

**Edge/Embedded**:
- Raspberry Pi 4/5 (64-bit)
- NVIDIA Jetson
- Qualcomm Snapdragon

### 2.2 ARM64 Linux Implementation Plan

#### Phase 1: Build Configuration (Week 1)

**config script additions**:
```bash
# ARM64 detection
case "$CC_ARCH" in
    aarch64|arm64)
        BRIX_ARCH_ARM64=1
        CFLAGS="$CFLAGS -DBRIX_ARCH_ARM64=1"
        
        # ARM64-specific optimizations
        if [ "$BRIX_OPTIMIZE" = "auto" ] || [ "$BRIX_OPTIMIZE" = "arm64" ]; then
            CFLAGS="$CFLAGS -march=armv8-a"
            
            # Detect crypto extensions
            if echo "" | $CC -march=armv8-a+crc -xc - -o /dev/null 2>/dev/null; then
                CFLAGS="$CFLAGS -march=armv8-a+crc"
            fi
            
            # Detect SVE (Scalable Vector Extension)
            if echo "" | $CC -march=armv8.2-a+sve -xc - -o /dev/null 2>/dev/null; then
                CFLAGS="$CFLAGS -march=armv8.2-a+sve"
            fi
        fi
        ;;
esac
```

#### Phase 2: ARM64 Optimizations (Week 2)

**CRC32 Hardware Acceleration**:
```c
// src/platform/linux/crc32c_arm64.c
#if BRIX_ARCH_ARM64 && defined(__ARM_FEATURE_CRC32)

#include <arm_acle.h>

uint32_t brix_crc32c_hw(const uint8_t *buf, size_t len, uint32_t crc)
{
    return __crc32cb(crc, buf, len);  // Single instruction
}

#endif
```

**NEON SIMD for Checksums**:
```c
// src/platform/linux/checksum_neon.c
#if BRIX_ARCH_ARM64
#include <arm_neon.h>

uint64_t brix_checksum_neon(const void *buf, size_t len)
{
    uint64x2_t sum = vdupq_n_u64(0);
    const uint64_t *data = (const uint64_t *)buf;
    
    // Process 16 bytes per iteration
    for (size_t i = 0; i < len / 16; i++) {
        uint64x2_t v = vld1q_u64(data + i * 2);
        sum = vaddq_u64(sum, v);
    }
    
    return vaddvq_u64(sum);
}

#endif
```

**Atomic Operations** (already optimal on ARM64):
```c
// ARM64 has native load-linked/store-conditional
// No changes needed - compiler generates optimal code
```

#### Phase 3: PAL Enhancements (Week 3)

**ARM64-Specific syscalls**:
```c
// src/platform/linux/posix_wrapper.c
#if BRIX_ARCH_ARM64

// ARM64 has different syscall numbers
// Most are handled by glibc, but some need explicit handling

int brix_plat_anon_fd(const char *name, const char *dir)
{
    // ARM64: use memfd_create syscall directly
    return syscall(__NR_memfd_create, name, MFD_CLOEXEC);
}

#endif
```

**Cache Line Alignment** (ARM64 typically 64-byte):
```c
// src/platform/platform.h
#if BRIX_ARCH_ARM64
#define BRIX_CACHE_LINE_SIZE 64
#else
#define BRIX_CACHE_LINE_SIZE 64  // x86_64 is also 64
#endif

#define BRIX_CACHE_ALIGNED __attribute__((aligned(BRIX_CACHE_LINE_SIZE)))
```

#### Phase 4: Testing (Week 4)

**Test Environments**:
- AWS EC2 Graviton instances (m6g, c6g, r6g)
- Ampere Altra developer platform
- Raspberry Pi 4/5 (edge cases)

**Validation**:
- Endianness (ARM64 is little-endian, same as x86_64)
- Alignment requirements (stricter than x86)
- Atomic operation correctness
- SIMD instruction availability

---

## 3. ARM64 macOS (Apple Silicon) Support

### 3.1 Current Status

✅ **Already supported** - PAL compiles and runs on Apple Silicon  
⚠️ **Not optimized** - Generic ARM64 flags, no Apple-specific tuning

### 3.2 Optimization Plan

#### Phase 1: Build Configuration (Week 1)

**config script additions**:
```bash
# Detect Apple Silicon
if [ "$BRIX_PLATFORM" = "darwin" ]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "arm64" ]; then
        BRIX_ARCH_ARM64=1
        CFLAGS="$CFLAGS -DBRIX_ARCH_ARM64=1"
        
        if [ "$BRIX_OPTIMIZE" = "auto" ] || [ "$BRIX_OPTIMIZE" = "apple_silicon" ]; then
            # Apple Silicon specific flags
            CFLAGS="$CFLAGS -march=armv8.5-a"
            CFLAGS="$CFLAGS -mtune=apple-m1"  # or apple-m2, apple-m3
            
            # Enable Apple-specific extensions
            CFLAGS="$CFLAGS -mcpu=apple-m1"
            
            # LTO for production builds
            if [ "$BRIX_ENABLE_LTO" = "yes" ]; then
                CFLAGS="$CFLAGS -flto=thin"
                LDFLAGS="$LDFLAGS -flto=thin"
            fi
        fi
    fi
fi
```

#### Phase 2: Apple Silicon Optimizations (Week 2)

**Firestorm/Icestall Big.LITTLE Awareness**:
```c
// src/platform/darwin/cpu_topology.c
#if BRIX_ARCH_ARM64 && BRIX_PLATFORM_DARWIN

int brix_plat_cpu_count_performance(void)
{
    // Return number of "firestorm" (performance) cores
    size_t len = 2;
    int count = 0;
    sysctlbyname("hw.perflevel0.physicalcpu", &count, &len, NULL, 0);
    return count;
}

int brix_plat_cpu_count_efficiency(void)
{
    // Return number of "icestorm" (efficiency) cores
    size_t len = 2;
    int count = 0;
    sysctlbyname("hw.perflevel1.physicalcpu", &count, &len, NULL, 0);
    return count;
}

#endif
```

**Accelerate Framework Integration**:
```c
// src/platform/darwin/checksum_accelerate.c
#if BRIX_PLATFORM_DARWIN && BRIX_ARCH_ARM64
#include <Accelerate/Accelerate.h>

uint64_t brix_checksum_accelerate(const void *buf, size_t len)
{
    // Use vDSP for vectorized operations
    uint64_t sum;
    vDSP_sve( (const uint64_t *)buf, 1, &sum, len / 8 );
    return sum;
}

#endif
```

**APFS Clonefile for Zero-Copy**:
```c
// src/platform/darwin/copy_range.c
#if BRIX_PLATFORM_DARWIN && BRIX_ARCH_ARM64

ssize_t brix_plat_copy_range(int in_fd, off_t *in_off,
                             int out_fd, off_t *out_off,
                             size_t len, unsigned int flags)
{
    struct clonefile_args args = {
        .src = in_fd,
        .dst = out_fd,
        .flags = 0,
    };
    
    // APFS clonefile is extremely fast on Apple Silicon
    if (syscall(SYS_clonefile, &args) == 0) {
        return len;
    }
    
    // Fallback to buffered copy
    return -1;
}

#endif
```

#### Phase 3: Testing (Week 3)

**Test Devices**:
- M1 MacBook Pro/Air
- M1/M2/M3 Mac mini
- M1/M2/M3 MacBook Pro
- M1/M2 Ultra Mac Studio

**Validation**:
- Rosetta 2 compatibility (x86_64 binaries on ARM64)
- Universal binary builds (fat binaries)
- Performance comparison (x86_64 vs ARM64)

---

## 4. Implementation Timeline

### Phase 1: Foundation (Weeks 1-4)
- [x] PAL architecture complete
- [ ] ARM64 Linux build configuration
- [ ] ARM64 macOS optimization flags
- [ ] Windows build infrastructure (mingw-w64)

### Phase 2: Platform Implementations (Weeks 5-12)
- [ ] ARM64 Linux optimizations (CRC32, NEON)
- [ ] ARM64 macOS optimizations (Accelerate, clonefile)
- [ ] Windows PAL core (posix_wrapper, event_wrapper)
- [ ] Windows fd-to-HANDLE abstraction

### Phase 3: Advanced Features (Weeks 13-20)
- [ ] Windows IOCP event loop (optional)
- [ ] Windows security model integration
- [ ] ARM64 SVE/SVE2 support (Linux)
- [ ] Apple Silicon big.LITTLE awareness

### Phase 4: Testing & Validation (Weeks 21-24)
- [ ] ARM64 Linux testing (Graviton, Ampere)
- [ ] ARM64 macOS testing (M1/M2/M3)
- [ ] Windows testing (Server 2019/2022, WSL2)
- [ ] Cross-platform regression testing

---

## 5. Technical Challenges & Solutions

### 5.1 Windows Challenges

| Challenge | Solution | Priority |
|-----------|----------|----------|
| HANDLE vs fd abstraction | Wrapper layer with type tagging | High |
| No epoll/kqueue | select() fallback, IOCP future | High |
| Different security model | Stub implementation, Job Objects future | Medium |
| Path separators (`\` vs `/`) | Normalize in PAL layer | High |
| Case-insensitive filesystem | Handle in VFS layer | Medium |

### 5.2 ARM64 Challenges

| Challenge | Solution | Priority |
|-----------|----------|----------|
| Stricter alignment | Use `BRIX_CACHE_ALIGNED` macros | High |
| Endianness (big-endian ARM) | PAL byte-order ops already handle | Low |
| SIMD availability varies | Runtime detection + fallback | Medium |
| Different syscall numbers | glibc abstraction (handled) | Low |

---

## 6. Build System Changes

### 6.1 Platform Detection

```bash
# config script
case "$(uname -s)" in
    Linux)
        BRIX_PLATFORM=linux
        BRIX_PLATFORM_LINUX=1
        ;;
    Darwin)
        BRIX_PLATFORM=darwin
        BRIX_PLATFORM_DARWIN=1
        ;;
    MINGW*|MSYS*|CYGWIN*)
        BRIX_PLATFORM=windows
        BRIX_PLATFORM_WINDOWS=1
        ;;
esac

case "$(uname -m)" in
    x86_64|amd64)
        BRIX_ARCH=x86_64
        ;;
    aarch64|arm64|ARM64)
        BRIX_ARCH=arm64
        ;;
esac
```

### 6.2 Optimization Profiles

```bash
# BRIX_OPTIMIZE options
# - auto: Detect platform and apply optimal flags
# - generic: Minimal flags, maximum compatibility
# - native: Optimize for build machine
# - arm64: ARM64-specific optimizations
# - apple_silicon: Apple Silicon optimizations
# - graviton: AWS Graviton optimizations
```

---

## 7. Testing Strategy

### 7.1 CI/CD Integration

**GitHub Actions Matrix**:
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-12, macos-14, windows-2022]
    arch: [x86_64, arm64]
    exclude:
      - os: ubuntu-latest
        arch: arm64  # Use ARM runner
      - os: windows-2022
        arch: arm64  # Not available
```

### 7.2 Platform-Specific Tests

```python
# tests/platform/test_pal_api.py
def test_brix_plat_anon_fd():
    fd = brix_plat_anon_fd("test", None)
    assert fd >= 0
    os.close(fd)

def test_brix_plat_random():
    buf = bytearray(32)
    assert brix_plat_random(buf, len(buf)) == 0
    assert buf != bytearray(32)  # Changed from zero

def test_brix_plat_byte_order():
    val = 0x123456789ABCDEF0
    be = brix_plat_htobe64(val)
    assert brix_plat_be64toh(be) == val
```

---

## 8. Documentation Updates

### 8.1 New Documentation Files

- `docs/platform/windows-support.md` - Windows installation and limitations
- `docs/platform/arm64-linux.md` - ARM64 Linux optimization guide
- `docs/platform/apple-silicon.md` - macOS ARM64 optimization guide
- `docs/platform/pal-api-reference.md` - Complete PAL API documentation

### 8.2 Updated Documentation

- `docs/platform/macos/reports/MACOS_BUILD_PROGRESS.md` → `PLATFORM_SUPPORT_MATRIX.md`
- `docs/01-getting-started/` - Add platform-specific quickstarts
- `docs/03-configuration/BUILD.md` - Multi-platform build instructions

---

## 9. Success Criteria

### 9.1 Windows Support
- [ ] nginx with BriX-Cache builds on Windows
- [ ] All PAL functions implemented or stubbed
- [ ] Basic functionality tests pass
- [ ] WSL2 support verified

### 9.2 ARM64 Linux
- [ ] Native ARM64 build succeeds
- [ ] CRC32 hardware acceleration active
- [ ] Performance within 5% of x86_64 (same clock)
- [ ] Graviton2/Graviton3 tested

### 9.3 ARM64 macOS
- [ ] Apple Silicon optimizations active
- [ ] Accelerate framework integration
- [ ] Performance 2x vs x86_64 (same generation)
- [ ] M1/M2/M3 all tested

---

## 10. Future Considerations

### 10.1 Additional Platforms

**BSD Support** (FreeBSD, OpenBSD):
- kqueue already implemented (shared with macOS)
- Different xattr signatures
- Different security model (capabilities vs seccomp)

**RISC-V Support**:
- Growing server market presence
- Vector extension (RVV) optimization opportunities
- Similar to ARM64 in many ways

### 10.2 Performance Optimization

**Profile-Guided Optimization (PGO)**:
```bash
# Generate profiling data
CFLAGS="$CFLAGS -fprofile-generate"
# Run representative workload
# Recompile with profiling data
CFLAGS="$CFLAGS -fprofile-use"
```

**Link-Time Optimization (LTO)**:
```bash
# Thin LTO for faster builds
CFLAGS="$CFLAGS -flto=thin"

# Full LTO for maximum optimization
CFLAGS="$CFLAGS -flto"
```

---

## Appendix A: PAL Function Completeness Matrix

| Function | Linux x86_64 | Linux ARM64 | macOS x86_64 | macOS ARM64 | Windows |
|----------|--------------|-------------|--------------|-------------|---------|
| `brix_plat_anon_fd` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_sendfile` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_splice` | ✅ | ✅ | ❌ | ❌ | ❌ |
| `brix_plat_copy_range` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_eventfd` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_pipe2` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_random` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_getxattr` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_setxattr` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_execvpe` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_fs_watcher_*` | ✅ | ✅ | ✅ | ✅ | 🔲 |
| `brix_plat_setfsuid` | ✅ | ✅ | ✅ | ✅ | ❌ |
| `brix_plat_security_*` | ✅ | ✅ | ❌ | ❌ | ❌ |

**Legend**: ✅ Implemented, ❌ Not available (stubbed), 🔲 TODO

---

## Appendix B: References

- [nginx/Windows Documentation](https://nginx.org/en/docs/windows.html)
- [AWS Graviton Processor](https://aws.amazon.com/ec2/graviton/)
- [Apple Silicon Documentation](https://developer.apple.com/documentation/apple_silicon)
- [Win32 API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)

---

**End of Document**
