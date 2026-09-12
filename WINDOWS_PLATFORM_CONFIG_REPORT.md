# Windows Platform Configuration Report

**Date**: 2025-12-12  
**Task**: Implement Windows platform detection in config script  
**Status**: ✅ Complete

---

## Summary

Windows platform detection has been successfully implemented in the BriX-Cache `config` script. The implementation supports MinGW, MSYS, Cygwin, and native Windows builds with proper compiler flags, library linking, and source file selection.

---

## Changes Made

### 1. Platform Detection (Lines 78-106)

**Location**: `config` script, case statement

```bash
MINGW*|MSYS*|CYGWIN*|Windows*|windows*)
    BRIX_PLATFORM="windows"
    BRIX_CFLAGS="-DBRIX_PLATFORM_LINUX=0 -DBRIX_PLATFORM_DARWIN=0 -DBRIX_PLATFORM_WINDOWS=1"
    BRIX_CFLAGS="$BRIX_CFLAGS -D_WIN32_WINNT=0x0602 -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS"
    BRIX_LDFLAGS=""
    BRIX_LIBS="-lws2_32 -ladvapi32 -lkernel32 -lbcrypt"
```

**Features**:
- ✅ Detects MINGW, MSYS, CYGWIN, and Windows environments
- ✅ Sets `BRIX_PLATFORM_WINDOWS=1` macro
- ✅ Defines Windows API version (Windows 8 / Server 2012 minimum)
- ✅ Links required Windows libraries

### 2. Compiler Flag Cleanup

**Removed Unix-specific flags**:
```bash
# Compiler hardening flags (not supported by Windows compilers)
-fcf-protection=full
-fstack-clash-protection
-fzero-call-used-regs=*
-ftrivial-auto-var-init=*
-D_GNU_SOURCE

# Linker security flags (not supported by Windows)
-Wl,-z,relro
-Wl,-z,now
-Wl,-z,noexecstack
```

### 3. Windows Libraries

**Linked libraries**:
- `-lws2_32` - Winsock 2 (networking)
- `-ladvapi32` - Advanced Windows API (security, registry)
- `-lkernel32` - Core Windows API (file I/O, processes)
- `-lbcrypt` - Cryptographic API (secure random)

**Added to**:
- `BRIX_LIBS` (platform-specific)
- `CORE_LIBS` (core module linking)

### 4. Source File Selection (Lines 2130-2141)

```bash
if [ "$BRIX_PLATFORM" = "windows" ]; then
    ngx_module_srcs="$ngx_module_srcs \
        $ngx_addon_dir/src/platform/windows/posix_wrapper.c \
        $ngx_addon_dir/src/platform/windows/event_wrapper.c \
        $ngx_addon_dir/src/platform/windows/fs_watcher.c \
        $ngx_addon_dir/src/platform/windows/security_wrapper.c \
        $ngx_addon_dir/src/platform/windows/copy_range.c \
        $ngx_addon_dir/src/platform/windows/aio_wrapper.c"
    ngx_module_libs="$ngx_module_libs $BRIX_LIBS"
fi
```

**Source files**:
- ✅ `posix_wrapper.c` - File descriptor and syscall wrappers
- ✅ `event_wrapper.c` - IOCP/select event handling
- ✅ `fs_watcher.c` - ReadDirectoryChangesW implementation
- ✅ `security_wrapper.c` - Windows security stubs
- ✅ `copy_range.c` - CopyFile2/TransmitFile wrappers
- ✅ `aio_wrapper.c` - IOCP-based async I/O

### 5. Optimization Profile (Lines 292-301)

```bash
windows)
    if [ "$BRIX_PLATFORM" = "windows" ]; then
        CFLAGS="$CFLAGS -O2"
        echo " + xrootd: performance profile = Windows (generic)"
    else
        echo "WARNING: windows profile only valid on Windows" >&2
        CFLAGS="$CFLAGS -O3 -march=x86-64-v2 -fno-plt"
    fi
    ;;
```

**Usage**: `BRIX_OPTIMIZE=windows ./configure ...`

---

## Platform Macros

The following preprocessor macros are defined for Windows builds:

| Macro | Value | Purpose |
|-------|-------|---------|
| `BRIX_PLATFORM_WINDOWS` | 1 | Platform detection |
| `BRIX_PLATFORM_LINUX` | 0 | Disable Linux code |
| `BRIX_PLATFORM_DARWIN` | 0 | Disable macOS code |
| `_WIN32_WINNT` | 0x0602 | Windows 8 minimum |
| `WIN32_LEAN_AND_MEAN` | defined | Exclude rare APIs |
| `_CRT_SECURE_NO_WARNINGS` | defined | Suppress CRT warnings |

---

## Build Integration

### Configure Command

```bash
# MinGW/MSYS/Cygwin
./configure --add-module=/path/to/brix-cache

# Explicit Windows platform
BRIX_PLATFORM=windows ./configure --add-module=/path/to/brix-cache

# With Windows optimization
BRIX_OPTIMIZE=windows ./configure --add-module=/path/to/brix-cache
```

### Detected Output

```
+ xrootd: platform Windows (MinGW/MSYS/Cygwin) detected
+ xrootd: performance profile = Windows (generic)
```

---

## Compatibility Notes

### ⚠️ nginx/Windows Limitations

Per [nginx.org](https://nginx.org/en/docs/windows.html):

- **Beta Status**: nginx/Windows is considered beta by upstream
- **Performance**: Only `select()` and `poll()` connection processing
- **Scalability**: Lower performance and scalability expected
- **Missing Features**: XSLT filter, image filter, GeoIP module, embedded Perl

**Recommendation**: Use WSL2 (Windows Subsystem for Linux) for production deployments.

### 📋 Windows Version Support

- **Minimum**: Windows 8 / Windows Server 2012 (`_WIN32_WINNT=0x0602`)
- **Recommended**: Windows 10 / Windows Server 2019 or later
- **Architecture**: x86_64, ARM64 (future optimization)

---

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Platform Detection | ✅ Complete | MinGW/MSYS/Cygwin/Windows |
| Compiler Flags | ✅ Complete | Win32 API flags defined |
| Library Linking | ✅ Complete | ws2_32, advapi32, kernel32, bcrypt |
| Source Selection | ✅ Complete | 6 PAL wrapper files |
| Optimization Profile | ✅ Complete | Generic Windows (-O2) |
| PAL Implementation | 🚧 In Progress | Skeleton in `src/platform/windows/` |

---

## Next Steps

1. ✅ **Config Script**: Complete
2. 🚧 **PAL Implementation**: Implement Windows wrapper functions
3. 🔲 **Testing**: Test on MinGW, MSYS2, Cygwin
4. 🔲 **Documentation**: Update build guides for Windows
5. 🔲 **CI/CD**: Add Windows build matrix to GitHub Actions

---

## Files Modified

- `/Users/rcurrie/src/brix-cache/config` - Platform detection and build configuration

## Files Created

- `/Users/rcurrie/src/brix-cache/WINDOWS_PLATFORM_CONFIG_REPORT.md` - This report

## Related Files

- `/Users/rcurrie/src/brix-cache/src/platform/windows/` - PAL implementation directory
- `/Users/rcurrie/src/brix-cache/docs/platform/PLATFORM_EXPANSION_PLAN.md` - Full expansion roadmap

---

## Testing

To test the configuration:

```bash
# Simulate Windows detection (on Unix)
BRIX_PLATFORM=windows ./configure --add-module=/Users/rcurrie/src/brix-cache --dry-run

# Check platform macros
grep "BRIX_PLATFORM_WINDOWS" objs/Makefile
```

---

**End of Report**
