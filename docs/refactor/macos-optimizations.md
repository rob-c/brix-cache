# macOS-Specific Optimizations for BriX-Cache

**Status:** Implementation Guide  
**Target:** v3.0.0+  
**Platform:** macOS 12.0+ (Intel & Apple Silicon)

---

## Executive Summary

This document outlines macOS-specific optimizations that can improve BriX-Cache performance on macOS systems. These optimizations leverage macOS-specific APIs, compiler features, and hardware capabilities.

---

## 1. Compiler Optimizations

### 1.1 Architecture-Specific Flags

**Current State:** Default is `-march=x86-64-v2` (SSE4.2/POPCNT)

**Recommended macOS Optimizations:**

```bash
# Intel Macs (Haswell 2013+, supports AVX2/BMI2)
-march=x86-64-v3 -O3 -mtune=haswell

# Apple Silicon (M1/M2/M3, ARM64)
-march=armv8.3-a+crypto -O3 -mtune=apple-m1

# Universal binary (both Intel + Apple Silicon)
-arch x86_64 -arch arm64
```

**Implementation:** Modify `config` to detect macOS architecture:

```bash
if [ "$BRIX_PLATFORM" = "darwin" ]; then
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            # Intel Mac - check for AVX2 support
            if sysctl -n hw.optional.avx2_0 | grep -q 1; then
                BRIX_OPT_CFLAGS="-O3 -march=x86-64-v3 -mtune=haswell -fno-plt"
                echo " + xrootd: Intel optimization (AVX2/Haswell)"
            else
                BRIX_OPT_CFLAGS="-O3 -march=x86-64-v2 -mtune=haswell"
                echo " + xrootd: Intel optimization (SSE4.2)"
            fi
            ;;
        arm64)
            # Apple Silicon - use ARM crypto extensions
            BRIX_OPT_CFLAGS="-O3 -march=armv8.3-a+crypto -mtune=apple-m1"
            echo " + xrootd: Apple Silicon optimization (M1/M2)"
            ;;
    esac
fi
```

### 1.2 Link-Time Optimization (LTO)

**Benefit:** 5-15% performance improvement through cross-module optimization

**Implementation:**
```bash
# Add to config for production builds
if [ "$BRIX_PLATFORM" = "darwin" ] && [ -n "$BRIX_ENABLE_LTO" ]; then
    CFLAGS="$CFLAGS -flto=thin"  # Thin LTO for faster builds
    NGX_LD_OPT="$NGX_LD_OPT -flto=thin"
    echo " + xrootd: LTO enabled (thin)"
fi
```

### 1.3 Profile-Guided Optimization (PGO)

**Benefit:** 10-20% improvement for hot paths

**Two-pass build:**
```bash
# Pass 1: Instrumented build
CFLAGS="$CFLAGS -fprofile-instr-generate -fcoverage-mapping"
make clean && make

# Run typical workload to generate profile
./objs/nginx -c nginx.conf
# ... run representative load ...
killall nginx

# Pass 2: Use profile data
CFLAGS="$CFLAGS -fprofile-instr-use"
make clean && make
```

---

## 2. macOS-Specific API Optimizations

### 2.1 Grand Central Dispatch (GCD) for Thread Pool

**Current:** Uses nginx thread pool with pthreads  
**Optimization:** Replace with libdispatch (GCD) for better macOS integration

**Benefits:**
- Better power management
- Automatic thread pool sizing
- Work stealing for load balancing
- Lower overhead than pthreads

**Implementation:**
```c
#include <dispatch/dispatch.h>

struct brix_aio_ctx {
    dispatch_queue_t queue;  // GCD queue instead of ngx_thread_pool_t
    size_t max_entries;
    ngx_atomic_t pending_ops;
};

brix_aio_ctx_t *
brix_aio_create(size_t max_entries)
{
    brix_aio_ctx_t *ctx = calloc(1, sizeof(brix_aio_ctx_t));
    
    // Create concurrent queue with QOS for background I/O
    ctx->queue = dispatch_queue_create_with_target(
        "org.brix-cache.aio",
        DISPATCH_QUEUE_CONCURRENT,
        dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0)
    );
    
    return ctx;
}

int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count,
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    // Dispatch async to GCD queue
    dispatch_async(ctx->queue, ^{
        ssize_t result = pread(fd, buf, count, offset);
        callback(fd, result, user_data);
        ngx_atomic_fetch_add(&ctx->pending_ops, -1);
    });
    
    return 0;
}
```

### 2.2 Accelerate Framework for CRC/Crypto

**Current:** Software CRC32C implementation  
**Optimization:** Use Accelerate framework's hardware-accelerated functions

**Benefits:**
- 3-5x faster CRC32C on Intel (SSE4.2)
- 5-10x faster on Apple Silicon (NEON)
- Lower CPU usage

**Implementation:**
```c
#include <Accelerate/Accelerate.h>

// Replace software CRC32C with Accelerate
uint32_t brix_crc32c_accelerate(const uint8_t *data, size_t len, uint32_t crc)
{
    // Use vDSP_crc32c from Accelerate (macOS 13+)
    #if defined(MAC_OS_VERSION_13_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_13_0
    return vDSP_crc32c(data, 1, len, crc, 0);
    #else
    // Fallback to software implementation
    return brix_crc32c_sw(data, len, crc);
    #endif
}
```

### 2.3 APFS Clonefile Optimization

**Status:** ✅ Already implemented in `brix_platform_clonefile()`

**Enhancement:** Add fallback chain for better performance:
```c
int
brix_platform_clonefile(const char *src_path, const char *dst_path)
{
    // Try APFS clonefile first (instant, CoW)
    if (clonefile(src_path, dst_path, 0) == 0) {
        return 0;
    }
    
    // Fallback to copyfile (macOS optimized copy)
    if (copyfile(src_path, dst_path, NULL, COPYFILE_ALL | COPYFILE_CLONE) == 0) {
        return 0;
    }
    
    // Final fallback to manual copy
    return brix_copy_fallback(src_path, dst_path);
}
```

### 2.4 F_SENSE_OWNERSHIP for File Events

**Optimization:** Use `F_SENSE_OWNERSHIP` flag with kqueue for better file monitoring

```c
// In fs_watcher.c
int
brix_fs_watcher_add(brix_fs_watcher_t *watcher, const char *path, int recursive)
{
    int fd = open(path, O_RDONLY | O_EVTONLY);  // O_EVTONLY doesn't prevent unmount
    if (fd < 0) return -1;
    
    // Enable ownership sensing for better rename detection
    fcntl(fd, F_SETFD, F_SENSE_OWNERSHIP);
    
    // ... rest of kqueue setup
}
```

---

## 3. Memory and Cache Optimizations

### 3.1 Huge Pages

**Benefit:** Reduce TLB misses for large memory allocations

**Implementation:**
```c
// For large buffer allocations (>2MB)
void *brix_alloc_large(size_t size)
{
    if (size >= 2 * 1024 * 1024) {
        // Use vm_allocate with page size hint
        vm_address_t addr;
        vm_size_t page_size = 2 * 1024 * 1024;  // 2MB huge pages
        
        kern_return_t kr = vm_allocate(
            mach_task_self(),
            &addr,
            size,
            VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB
        );
        
        if (kr == KERN_SUCCESS) {
            return (void *)addr;
        }
    }
    
    // Fallback to malloc
    return malloc(size);
}
```

### 3.2 Cache Line Alignment

**Benefit:** Avoid false sharing in multi-threaded code

**Implementation:**
```c
// Align structures to cache line (64 bytes on modern Macs)
#define BRIX_CACHE_LINE_SIZE 64
#define BRIX_ALIGNED __attribute__((aligned(BRIX_CACHE_LINE_SIZE)))

typedef struct {
    ngx_atomic_t counter;
    char padding[BRIX_CACHE_LINE_SIZE - sizeof(ngx_atomic_t)];
} BRIX_ALIGNED brix_atomic_padded_t;
```

---

## 4. I/O Optimizations

### 4.1 F_NOCACHE for One-Time Reads

**Benefit:** Avoid polluting file cache with one-time reads

```c
// For streaming/one-time read operations
int fd = open(path, O_RDONLY);
fcntl(fd, F_NOCACHE, 1);  // Don't cache this file
```

### 4.2 F_RDADVISE for Sequential Reads

**Benefit:** Hint to kernel about access pattern

```c
// For sequential file reads
struct radvisory ra;
ra.ra_offset = 0;
ra.ra_count = file_size;
fcntl(fd, F_RDADVISE, &ra);
```

### 4.3 Direct I/O for Large Transfers

**Benefit:** Bypass kernel cache for large sequential I/O

```c
// For transfers >100MB
int fd = open(path, O_RDONLY | O_DIRECT);  // Direct I/O
// Note: Requires aligned buffers (512-byte boundary)
```

---

## 5. Network Optimizations

### 5.1 TCP Connection Coalescing

**Benefit:** Reduce connection overhead for multiple requests

```c
// Enable TCP connection coalescing (macOS 11+)
int enable = 1;
setsockopt(sock, IPPROTO_TCP, TCP_CONNECTION_COALESCING, &enable, sizeof(enable));
```

### 5.2 Interface Selection

**Benefit:** Use best network interface (WiFi vs Ethernet)

```c
// Bind to specific interface for better performance
struct ifreq ifr;
strncpy(ifr.ifr_name, "en0", IFNAMSIZ);  // en0 = Ethernet, en1 = WiFi
setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
```

---

## 6. Build Configuration Recommendations

### 6.1 Development Build
```bash
BRIX_OPTIMIZE=v2  # x86-64-v2, compatible with all Intel Macs
CFLAGS="-O2 -g"   # Debug symbols, moderate optimization
```

### 6.2 Production Build (Intel)
```bash
BRIX_OPTIMIZE=v3  # x86-64-v3, AVX2/BMI2 (Haswell+)
BRIX_ENABLE_LTO=1
CFLAGS="-O3 -march=x86-64-v3 -mtune=haswell -fno-plt"
```

### 6.3 Production Build (Apple Silicon)
```bash
BRIX_OPTIMIZE=apple_silicon
CFLAGS="-O3 -march=armv8.3-a+crypto -mtune=apple-m1"
BRIX_ENABLE_LTO=1
```

### 6.4 Universal Binary (Both Architectures)
```bash
# Build twice and combine
clang -arch x86_64 -o nginx-intel ...
clang -arch arm64 -o nginx-arm ...
lipo -create nginx-intel nginx-arm -output nginx-universal
```

---

## 7. Performance Monitoring

### 7.1 Instruments Integration

Use Xcode Instruments for profiling:
- **Time Profiler:** CPU usage and hot paths
- **Allocations:** Memory allocation patterns
- **Energy Log:** Power consumption
- **Network Profiler:** Network I/O

### 7.2 DTrace Scripts

```bash
# Monitor syscall latency
sudo dtrace -n 'syscall:::entry /pid == $target/ { @latency[probefunc] = quantize(arg0); }'

# Monitor file I/O patterns
sudo dtrace -n 'fbt::pread:entry,fbt::pwrite:entry /pid == $target/ { @io[probefunc] = count; }'
```

---

## 8. Implementation Priority

### High Priority (Immediate)
1. ✅ Architecture-specific compiler flags (x86-64-v3 for Intel, ARM for M1)
2. ✅ APFS clonefile optimization (already implemented)
3. ⏳ LTO for production builds

### Medium Priority (v3.0.0)
4. ⏳ GCD thread pool replacement
5. ⏳ Accelerate framework for CRC32C
6. ⏳ Cache line alignment for atomic structures

### Low Priority (v3.1.0+)
7. ⏳ PGO for hot paths
8. ⏳ Huge pages for large allocations
9. ⏳ Direct I/O for large transfers

---

## 9. Expected Performance Gains

| Optimization | Expected Improvement | Complexity |
|-------------|---------------------|------------|
| x86-64-v3 optimization | 5-10% | Low |
| LTO | 5-15% | Low |
| GCD thread pool | 10-20% | Medium |
| Accelerate CRC32C | 3-5x faster CRC | Low |
| PGO | 10-20% | High |
| Huge pages | 5-10% (large allocs) | Medium |

**Total Potential Improvement:** 30-50% for typical workloads

---

## 10. References

- [Apple Clang Optimization Flags](https://clang.llvm.org/docs/UsersManual.html)
- [Grand Central Dispatch](https://developer.apple.com/documentation/dispatch)
- [Accelerate Framework](https://developer.apple.com/documentation/accelerate)
- [APFS clonefile](https://www.manpagez.com/man/2/clonefile/)
- [macOS Performance Guide](https://developer.apple.com/documentation/performance)

