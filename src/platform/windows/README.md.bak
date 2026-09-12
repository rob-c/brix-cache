# Windows Platform Abstraction Layer

**Status**: 🚧 In Development (Draft)

This directory contains the Windows implementation of the Platform Abstraction Layer (PAL) for BriX-Cache.

## Overview

The Windows PAL provides Win32 API implementations of all `brix_plat_*()` functions, enabling BriX-Cache to run on Windows with minimal changes to business logic code.

## Important Limitations

⚠️ **nginx/Windows is Beta**: Per [nginx.org](https://nginx.org/en/docs/windows.html):
- Uses Win32 API (not Cygwin)
- Only `select()` and `poll()` connection processing
- Lower performance and scalability expected
- Missing: XSLT filter, image filter, GeoIP module, embedded Perl

**Recommendation**: Use WSL2 (Windows Subsystem for Linux) for production deployments where possible.

## Build Requirements

- Windows 8 / Windows Server 2012 or later
- Visual Studio 2019 or later (or MinGW-w64)
- nginx source with Windows support
- BriX-Cache module

## File Structure

```
src/platform/windows/
├── README.md              # This file
├── win32_compat.h         # Windows compatibility types and macros
├── posix_wrapper.c        # File descriptor and syscall wrappers
├── event_wrapper.c        # IOCP/select event handling
├── fs_watcher.c           # ReadDirectoryChangesW implementation
├── security_wrapper.c     # Windows security model stubs
├── copy_range.c           # CopyFile2/TransmitFile wrappers
└── aio_wrapper.c          # IOCP-based async I/O
```

## Implementation Status

| Category | Status | Notes |
|----------|--------|-------|
| File Descriptors | ✅ Implemented | HANDLE/fd abstraction layer |
| Zero-Copy Transfers | 🔲 Planned | TransmitFile, CopyFile2 |
| Event Handling | 🔲 Planned | select() fallback, IOCP future |
| File System Watcher | 🔲 Planned | ReadDirectoryChangesW |
| Security | 🔲 Planned | Stub implementation |
| Random | ✅ Implemented | BCryptGenRandom |
| Extended Attributes | ✅ Implemented | NTFS ADS (see ADS_IMPLEMENTATION.md) |
| Process Execution | 🔲 Planned | CreateProcessW |

## Key Design Decisions

### 1. HANDLE vs File Descriptor Abstraction

Windows uses HANDLE, not POSIX file descriptors. The PAL provides:

```c
typedef struct {
    union {
        int fd;
        HANDLE handle;
    };
    int type;  // FD_FILE, FD_SOCKET, FD_PIPE
} brix_win32_handle_t;
```

### 2. Event Loop Strategy

**Phase 1**: select() compatibility with nginx/Windows  
**Phase 2**: IOCP-based event loop for better performance

### 3. Security Model

Windows security model (ACLs, SIDs, tokens) differs significantly from POSIX (UID/GID, capabilities). The PAL provides stub implementations for compatibility.

## Testing

Run tests on:
- Windows Server 2019/2022
- Windows 10/11
- WSL2 (Ubuntu on Windows)

## Future Enhancements

- [ ] IOCP-based event loop
- [ ] Full ACL/xattr mapping
- [ ] Job Objects for security confinement
- [ ] RISC-V support (future platform)

## References

- [Win32 API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [nginx/Windows](https://nginx.org/en/docs/windows.html)
- [IOCP Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports)
- [ReadDirectoryChangesW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)
