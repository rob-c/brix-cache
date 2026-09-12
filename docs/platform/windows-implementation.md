# Windows Implementation Guide

**Status**: 🚧 In Development (Skeleton Complete)  
**Minimum Version**: Windows 8 / Server 2012  
**nginx Status**: Beta (production use not recommended)

---

## Overview

This document provides detailed implementation guidance for the Windows PAL layer. The Windows implementation enables BriX-Cache to run on Windows with minimal changes to business logic.

### Important Limitations

⚠️ **nginx/Windows is Beta** (per nginx.org):
- Uses Win32 API (not Cygwin)
- Only `select()` and `poll()` connection processing
- Lower performance and scalability expected
- Missing: XSLT filter, image filter, GeoIP module, embedded Perl

**Recommendation**: Use WSL2 for production deployments where possible.

---

## Architecture

### HANDLE vs File Descriptor Abstraction

Windows uses HANDLE, not POSIX file descriptors. The PAL provides a unified abstraction:

```c
typedef union {
    int fd;
    HANDLE handle;
    SOCKET socket;
} brix_win32_handle_t;
```

**Conversion Functions**:
```c
/* Convert fd to HANDLE */
HANDLE brix_win32_fd_to_handle(int fd);

/* Convert HANDLE to fd */
int brix_win32_handle_to_fd(HANDLE handle, int type);

/* Close handle properly based on type */
int brix_win32_close_handle(int fd, int type);
```

**Handle Types**:
- `BRIX_WIN32_HANDLE_FILE` - Regular file
- `BRIX_WIN32_HANDLE_SOCKET` - Winsock socket
- `BRIX_WIN32_HANDLE_PIPE` - Named or anonymous pipe
- `BRIX_WIN32_HANDLE_EVENT` - Event object

---

## Implementation Details

### 1. Anonymous File Descriptors

**Function**: `brix_plat_anon_fd()`

**Implementation**:
```c
int brix_plat_anon_fd(const char *name, const char *dir)
{
    char temp_path[MAX_PATH];
    char filename[MAX_PATH];
    HANDLE handle;
    
    /* Get temp directory */
    GetTempPathA(sizeof(temp_path), temp_path);
    
    /* Generate unique filename */
    GetTempFileNameA(temp_path, "brix", 0, filename);
    
    /* Open with DELETE_ON_CLOSE */
    handle = CreateFileA(
        filename,
        GENERIC_READ | GENERIC_WRITE,
        0,  /* No sharing */
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_RANDOM_ACCESS,
        NULL
    );
    
    /* Convert HANDLE to fd */
    int fd = _open_osfhandle((intptr_t)handle, 0);
    return fd;
}
```

**Key Points**:
- Uses `CreateFile()` with `FILE_FLAG_DELETE_ON_CLOSE`
- File automatically deleted when closed
- Similar to `memfd_create()` on Linux

---

### 2. Sendfile

**Function**: `brix_plat_sendfile()`

**Implementation**:
```c
ssize_t brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    HANDLE socket_handle = (HANDLE)_get_osfhandle(out_fd);
    HANDLE file_handle = (HANDLE)_get_osfhandle(in_fd);
    LARGE_INTEGER offset_val;
    
    offset_val.QuadPart = *offset;
    
    TransmitFile(
        socket_handle,
        file_handle,
        (DWORD)count,
        0,
        &offset_val,
        NULL,
        TF_USE_KERNEL_APC | TF_WRITE_BEHIND
    );
    
    *offset += count;
    return (ssize_t)count;
}
```

**Key Points**:
- Uses `TransmitFile()` Win32 API
- Socket must be Winsock2 socket
- Kernel-mode copy for performance

---

### 3. Pipe Creation

**Function**: `brix_plat_pipe2()`

**Implementation**:
```c
int brix_plat_pipe2(int pipefd[2], int flags)
{
    HANDLE read_handle, write_handle;
    SECURITY_ATTRIBUTES sa;
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = (flags & BRIX_PIPE_CLOEXEC) ? FALSE : TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    /* Create pipe */
    CreatePipe(&read_handle, &write_handle, &sa, 0);
    
    /* Set non-blocking if requested */
    if (flags & BRIX_PIPE_NONBLOCK) {
        DWORD mode = PIPE_NOWAIT;
        SetNamedPipeHandleState(write_handle, &mode, NULL, NULL);
    }
    
    /* Convert to fds */
    pipefd[0] = _open_osfhandle((intptr_t)read_handle, _O_RDONLY);
    pipefd[1] = _open_osfhandle((intptr_t)write_handle, _O_WRONLY);
    
    return 0;
}
```

**Key Points**:
- Uses `CreatePipe()` Win32 API
- `SetHandleInformation()` for CLOEXEC
- `SetNamedPipeHandleState()` for NONBLOCK

---

### 4. Random Number Generation

**Function**: `brix_plat_random()`

**Implementation**:
```c
int brix_plat_random(void *buf, size_t len)
{
    static BCRYPT_ALG_HANDLE alg_handle = NULL;
    
    if (alg_handle == NULL) {
        BCryptOpenAlgorithmProvider(
            &alg_handle,
            BCRYPT_RNG_ALGORITHM,
            NULL,
            0
        );
    }
    
    BCryptGenRandom(alg_handle, (PUCHAR)buf, (ULONG)len, 0);
    
    return 0;  /* Success */
}
```

**Key Points**:
- Uses `BCryptGenRandom()` (CNG API)
- Cryptographically secure
- Algorithm provider cached for performance

---

### 5. Event File Descriptors

**Function**: `brix_plat_eventfd()`

**Implementation** (Phase 1 - Pipe-based):
```c
int brix_plat_eventfd(unsigned int initial_value, int flags)
{
    int pipefd[2];
    
    if (brix_plat_pipe2(pipefd, flags) < 0) {
        return -1;
    }
    
    /* Write initial value if non-zero */
    if (initial_value != 0) {
        uint64_t val = initial_value;
        write(pipefd[1], &val, sizeof(val));
    }
    
    /* Return read end */
    return pipefd[0];
}
```

**Future** (Phase 2 - IOCP-based):
```c
int brix_plat_eventfd(unsigned int initial_value, int flags)
{
    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    return _open_osfhandle((intptr_t)iocp, 0);
}
```

---

### 6. Extended Attributes

**Function**: `brix_plat_getxattr()`

**Status**: 🔲 Not Implemented (stub returns ENOSYS)

**Future Implementation** (NTFS Alternate Data Streams):
```c
ssize_t brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    char ads_path[MAX_PATH];
    snprintf(ads_path, sizeof(ads_path), "%s:%s:$DATA", path, name);
    
    HANDLE handle = CreateFileA(
        ads_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    DWORD bytes_read;
    ReadFile(handle, value, (DWORD)size, &bytes_read, NULL);
    CloseHandle(handle);
    
    return (ssize_t)bytes_read;
}
```

**Key Points**:
- NTFS supports Alternate Data Streams (ADS)
- Path format: `file.txt:streamname:$DATA`
- Limited to NTFS filesystem

---

### 7. Process Execution

**Function**: `brix_plat_execvpe()`

**Implementation**:
```c
int brix_plat_execvpe(const char *file, char *const argv[], char *const envp[])
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR file_path[MAX_PATH];
    
    /* Search for file in PATH */
    SearchPathW(NULL, file, L".exe", MAX_PATH, file_path, NULL);
    
    /* Build command line */
    wcscpy(cmd_line, L"\"");
    wcscat(cmd_line, file_path);
    wcscat(cmd_line, L"\"");
    
    /* Create process */
    CreateProcessW(file_path, cmd_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    
    /* Wait for child */
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    /* Exit with same code */
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    _exit(exit_code);
}
```

**Key Points**:
- Uses `CreateProcessW()` (Unicode version)
- PATH search via `SearchPathW()`
- Mimics execvpe behavior (doesn't return on success)

---

## Build Configuration

### config Script Additions

```bash
# Windows detection
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        BRIX_PLATFORM=windows
        BRIX_PLATFORM_WINDOWS=1
        CFLAGS="$CFLAGS -DBRIX_PLATFORM_WINDOWS=1"
        CFLAGS="$CFLAGS -D_WIN32_WINNT=0x0602"  # Windows 8
        CFLAGS="$CFLAGS -DWIN32_LEAN_AND_MEAN"
        CFLAGS="$CFLAGS -D_CRT_SECURE_NO_WARNINGS"
        
        # Link Windows libraries
        CORE_LIBS="$CORE_LIBS -lws2_32 -ladvapi32 -lkernel32 -lbcrypt"
        
        PAL_SRCS="$ngx_addon_dir/src/platform/windows/*.c"
        ;;
esac
```

### Required Libraries

- `ws2_32` - Winsock2 (networking)
- `advapi32` - Advanced Windows API (security, registry)
- `kernel32` - Core Windows API
- `bcrypt` - Cryptographic API (random generation)

---

## Testing

### Unit Tests

```python
# tests/platform/test_windows.py

import pytest
import os

def test_brix_plat_anon_fd_windows():
    """Test anonymous fd on Windows"""
    fd = brix_plat_anon_fd("test", None)
    assert fd >= 0
    
    # Verify it's a valid handle
    handle = _get_osfhandle(fd)
    assert handle != INVALID_HANDLE_VALUE
    
    os.close(fd)

def test_brix_plat_random_windows():
    """Test random generation on Windows"""
    buf = bytearray(32)
    ret = brix_plat_random(buf, len(buf))
    assert ret == 0
    assert buf != bytearray(32)
```

### Integration Tests

```bash
# Build on Windows (MinGW)
make clean
./configure --add-module=/path/to/brix-cache
make

# Run tests
pytest tests/platform/ -v
```

---

## Performance Considerations

### 1. HANDLE/fd Conversion Overhead

**Issue**: Converting between HANDLE and fd has overhead

**Solution**: Cache conversions where possible:
```c
/* Cache handle in struct */
struct my_struct {
    int fd;
    HANDLE cached_handle;  /* Cache to avoid repeated conversion */
};

/* Use cached handle */
HANDLE handle = (obj->cached_handle != NULL) 
    ? obj->cached_handle 
    : brix_win32_fd_to_handle(obj->fd);
```

### 2. select() Limitations

**Issue**: nginx/Windows uses `select()` (max 64 sockets by default)

**Workaround**: Increase FD_SETSIZE:
```c
#define FD_SETSIZE 1024  /* Before including winsock2.h */
#include <winsock2.h>
```

**Future**: IOCP-based event loop for better scalability

### 3. Path Normalization

**Issue**: Windows uses backslashes, POSIX uses forward slashes

**Solution**: Normalize paths in PAL:
```c
void brix_win32_normalize_path(char *path)
{
    while (*path) {
        if (*path == '/') {
            *path = '\\';
        }
        path++;
    }
}
```

---

## Known Issues

### Issue 1: Symlinks

**Problem**: Windows symlinks work differently than POSIX

**Status**: 🔲 Not supported in PAL

**Workaround**: Use junction points or document limitation

---

### Issue 2: File Locking

**Problem**: Windows file locking is mandatory, not advisory

**Status**: ⚠️ Partial support

**Workaround**: Use `LockFile()`/`UnlockFile()` explicitly

---

### Issue 3: Case Sensitivity

**Problem**: Windows filesystem is case-insensitive

**Status**: ⚠️ Documented limitation

**Workaround**: Avoid case-sensitive operations

---

## Future Enhancements

### Phase 2: IOCP Event Loop

Replace select()-based event loop with IOCP:

```c
int brix_plat_event_init(void)
{
    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    return (iocp != NULL) ? 0 : -1;
}

int brix_plat_event_wait(int efd, int timeout_ms)
{
    DWORD bytes_transferred;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;
    
    GetQueuedCompletionStatus(
        (HANDLE)_get_osfhandle(efd),
        &bytes_transferred,
        &key,
        &overlapped,
        timeout_ms
    );
    
    return 0;
}
```

### Phase 3: Full xattr Support

Implement NTFS ADS for extended attributes:
- `brix_plat_getxattr()` - Read ADS
- `brix_plat_setxattr()` - Write ADS
- `brix_plat_removexattr()` - Delete ADS
- `brix_plat_listxattr()` - Enumerate ADS

### Phase 4: Security Integration

Use Windows security features:
- Job Objects for resource limits
- AppContainer for sandboxing
- Security tokens for impersonation

---

## References

- [Win32 API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [IOCP Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports)
- [NTFS Alternate Data Streams](https://docs.microsoft.com/en-us/windows/win32/fileio/alternate-data-streams)
- [nginx/Windows](https://nginx.org/en/docs/windows.html)
- [WSL2 Documentation](https://docs.microsoft.com/en-us/windows/wsl/)

---

**End of Windows Implementation Guide**
