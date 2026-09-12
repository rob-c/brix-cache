# Getting Started with macOS Support

**Phase 1: Platform Detection & Build System**

This document provides quick-start instructions for building BriX-Cache on macOS after the Phase 1 implementation.

## Prerequisites

### macOS Requirements

- **Minimum Version:** macOS 12.0 (Monterey)
- **Architecture:** x86_64 (Intel) or arm64 (Apple Silicon)
- **Disk Space:** ~500MB for build dependencies

### Install Homebrew

Homebrew is the recommended package manager for macOS:

```bash
/bin/bash -c "$(curl -fsSL https://brew.sh)"
```

### Install Dependencies

```bash
# Core dependencies
brew install openssl@3 libxml2 jansson curl krb5

# Optional dependencies (for additional features)
brew install zstd xz brotli lz4  # Compression codecs
brew install sqlite               # pblock storage backend
```

## Build Instructions

### Standard Build

```bash
cd /path/to/brix-cache

# Configure with stream module support
./configure --with-stream --with-threads --add-module=$(pwd)

# Build (use all available CPU cores)
make -j$(sysctl -n hw.ncpu)

# Test configuration
objs/nginx -t
```

### Custom Build Options

```bash
# Disable optional features for minimal build
BRIX_ENABLE_IO_URING=0 \
BRIX_ENABLE_SECCOMP=0 \
BRIX_ENABLE_CEPH=0 \
./configure --with-stream --with-threads --add-module=$(pwd)

# Enable all compression codecs
BRIX_LZ4_CFLAGS="-I$(brew --prefix)/include" \
BRIX_LZ4_LIBS="-L$(brew --prefix)/lib -llz4" \
./configure --with-stream --with-threads --add-module=$(pwd)
```

### Build Output

Expected output during configure:

```
 + xrootd: platform macOS 13.6 detected
 + xrootd: Homebrew detected at /opt/homebrew  # or /usr/local
 + xrootd: io_uring disabled (not available on macOS)
 + xrootd: seccomp disabled (not available on macOS)
 + xrootd storage backend: ceph/rados disabled (no macOS Ceph support)
 + xrootd WebDAV: native MKCOL/DELETE handlers enabled
 + xrootd compression: zstd enabled
 + xrootd compression: xz/lzma enabled
 + xrootd auth: Kerberos 5 plugin enabled (pkg-config)
```

## Verification

### Check Platform Detection

```bash
objs/nginx -V 2>&1 | grep -i "brix"
```

Expected output should include platform information.

### Run Verification Script

```bash
./verify_macos_support.sh
```

This checks that all platform files are present and correctly configured.

### Test Module Load

```bash
objs/nginx -t
```

Expected output:
```
nginx: configuration file test successful
```

## Known Limitations

### Feature Differences from Linux

| Feature | Linux | macOS | Impact |
|---------|-------|-------|--------|
| io_uring async I/O | ✅ Full support | ❌ Thread pool fallback | ~15-20% throughput reduction on large reads |
| seccomp-bpf | ✅ Full support | ❌ Phase 4 (sandbox_exec) | Relies on macOS SIP/Gatekeeper |
| CephFS backend | ✅ Full support | ❌ Not available | Use S3 backend or Ceph NFS gateway |
| splice() zero-copy | ✅ Full support | ⚠️ Buffered copy | ~30-40% reduction for large proxy transfers |
| posix_fadvise | ✅ Full support | ⚠️ No-op (XNU lacks API) | Minimal - kernel uses adaptive readahead |
| sendfile() | ✅ Standard | ✅ With translation | Equivalent performance (wrapper handles signature differences) |
| clonefile() | ❌ Not available | ✅ APFS fast clone | Faster than copy when available |

### Performance Considerations

1. **Async I/O**: macOS uses nginx thread pool instead of io_uring
   - Impact: ~15-20% reduction in throughput for large sequential reads
   - Mitigation: Increase thread pool size in nginx.conf

2. **Zero-Copy Proxy**: macOS uses buffered copy instead of splice()
   - Impact: ~30-40% reduction for large transfers (>100MB)
   - Mitigation: Use sendfile() for file-to-socket transfers (handled by nginx core)

3. **File Access Hints**: posix_fadvise() is a no-op
   - Impact: Minimal - macOS XNU kernel uses adaptive readahead
   - No action needed

## Configuration Example

### nginx.conf for macOS

```nginx
worker_processes auto;
worker_rlimit_nofile 65536;

events {
    worker_connections 4096;
    use kqueue;  # nginx auto-detects kqueue on macOS
}

thread_pool brix_aio threads=8 max_queue=65536;

stream {
    server {
        listen 10999;
        
        # Enable BriX cache
        brix_export /data;
        brix_storage_backend posix:/data/storage;
        
        # Cache configuration
        brix_cache_path /data/cache max_size=100g;
        brix_cache_enable on;
        
        # Thread pool for async I/O (macOS uses this instead of io_uring)
        brix_thread_pool brix_aio;
    }
}
```

## Troubleshooting

### Build Fails with "Unsupported platform"

**Symptom:**
```
! xrootd: unsupported platform: Darwin
BriX-Cache supports Linux and macOS only.
```

**Cause:** Platform detection failed or macOS version < 12.0

**Solution:**
```bash
# Check macOS version
sw_vers -productVersion

# Must be 12.0 or later
# If older, upgrade macOS
```

### Build Fails with "Homebrew not found"

**Symptom:**
```
! xrootd: Homebrew not found. Install from https://brew.sh
Some dependencies may not be found without Homebrew.
ERROR: libxml2 is required for WebDAV PROPFIND XML parsing.
```

**Cause:** Homebrew not installed or not in PATH

**Solution:**
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://brew.sh)"

# Add to PATH if needed
export PATH="/opt/homebrew/bin:$PATH"  # Apple Silicon
export PATH="/usr/local/bin:$PATH"     # Intel
```

### Missing Dependencies

**Symptom:**
```
ERROR: jansson library is required but was not found.
Install jansson-devel (RHEL/CentOS) or libjansson-dev (Debian/Ubuntu).
```

**Solution:**
```bash
# Install all dependencies
brew install openssl@3 libxml2 jansson curl krb5
```

### Module Fails to Load

**Symptom:**
```
nginx: [emerg] dlopen("/usr/local/lib/nginx/modules/ngx_stream_brix_module.so") failed
  Library not loaded: @rpath/libssl.3.dylib
```

**Cause:** Dynamic library paths not resolved

**Solution:**
```bash
# Rebuild with explicit library paths
export LDFLAGS="-L$(brew --prefix)/lib"
export CPPFLAGS="-I$(brew --prefix)/include"

./configure --with-stream --with-threads --add-module=$(pwd)
make clean
make -j$(sysctl -n hw.ncpu)
```

### Performance Issues

**Symptom:** Lower throughput than expected on macOS

**Solutions:**

1. **Increase thread pool size:**
   ```nginx
   thread_pool brix_aio threads=16 max_queue=65536;
   ```

2. **Enable sendfile in nginx:**
   ```nginx
   http {
       sendfile on;
       tcp_nopush on;
   }
   ```

3. **Use APFS for storage:**
   - APFS supports fast clone operations
   - Better performance for copy operations

## Next Steps

### Phase 2 Implementation (Coming Soon)

- Filesystem monitoring (FSEvents integration)
- Improved async I/O handling
- Security wrapper (sandbox_exec stub)

### Testing

Once Phase 2 is complete, run:

```bash
# Run integration tests
PYTHONPATH=tests pytest tests/test_macos_platform.py -v

# Performance benchmarks
./tools/benchmark/macos_perf_test.sh
```

## References

- Full specification: `docs/refactor/macos-support-v3.0.md`
- Platform API documentation: `src/platform/README.md`
- Implementation status: `MACOS_IMPLEMENTATION_STATUS.md`
- Build configuration: `config` (lines 7-60)

## Support

For issues or questions:

1. Check `docs/09-developer-guide/agent-guide-extended.md`
2. Review `MACOS_IMPLEMENTATION_STATUS.md` for known issues
3. Run `./verify_macos_support.sh` for diagnostics
