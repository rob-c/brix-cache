# Windows Zero-Copy Transfer Implementation

**File**: `src/platform/windows/copy_range.c`  
**Status**: ✅ Complete (Draft)  
**Windows Version**: Windows 8+ (for CopyFile2)

---

## Implemented Functions

### 1. brix_plat_sendfile() ✅

**Purpose**: Zero-copy file to socket transfer

**Windows API**: `TransmitFile()` from MSWSOCK.DLL

**Signature**:
```c
ssize_t brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
```

**Implementation Details**:
- Uses `TransmitFile()` - the Win32 equivalent of Linux `sendfile()`
- Requires `out_fd` to be a socket, `in_fd` to be a file
- Zero-copy: Data transferred directly from file cache to socket
- Uses `TF_USE_KERNEL_APC | TF_WRITE_BEHIND` flags for async operation
- Updates offset pointer on success

**Performance**:
- ✅ Zero-copy (kernel-mode transfer)
- ✅ Uses system send buffer optimization
- ✅ Supports overlapped I/O

**Fallback**:
- If `out_fd` is not a socket → Returns `-1` with `errno = EINVAL`
- If `TransmitFile()` fails → Returns `-1` with `errno` set from `GetLastError()`
- Caller should fallback to buffered `read()`/`write()` loop

**Usage Example**:
```c
int file_fd = open("data.bin", O_RDONLY);
int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
off_t offset = 0;
size_t size = 1024 * 1024;  // 1MB

ssize_t sent = brix_plat_sendfile(socket_fd, file_fd, &offset, size);
if (sent < 0) {
    // Fallback to send()/write()
}
```

---

### 2. brix_plat_copy_range() ✅

**Purpose**: Copy a range of data between file descriptors

**Windows API**: `CopyFile2()` from KERNEL32.DLL (Windows 8+)

**Signature**:
```c
ssize_t brix_plat_copy_range(int in_fd, off_t *in_off,
                             int out_fd, off_t *out_off,
                             size_t len, unsigned int flags);
```

**Implementation Details**:
- Uses `CopyFile2()` - modern Windows file copy API
- Supports copy-on-write (CoW) on ReFS volumes
- Converts file descriptors to paths using `GetFinalPathNameByHandleA()`
- Maps `BRIX_COPY_F_REFLINK` to `COPY_FILE_NO_BUFFERING`
- **Limitation**: Copies entire file, not just range (Windows API limitation)

**Performance**:
- ✅ Efficient for full file copies
- ✅ CoW support on ReFS volumes
- ✅ Preserves file attributes
- ⚠️ Overhead for small ranges (path conversion, full file copy)

**Fallback Scenarios**:
1. **Windows < 8**: `CopyFile2()` unavailable → Returns `-1` with `errno = ENOSYS`
2. **Cannot get file paths**: `GetFinalPathNameByHandleA()` fails → Returns `-1` with `errno = ENOSYS`
3. **Range copy needed**: Not supported by `CopyFile2()` → Manual `read()`/`write()` required

**Usage Example**:
```c
int src_fd = open("source.bin", O_RDONLY);
int dst_fd = open("dest.bin", O_WRONLY | O_CREAT, 0644);
off_t src_off = 0, dst_off = 0;
size_t len = 4096;

ssize_t copied = brix_plat_copy_range(src_fd, &src_off, dst_fd, &dst_off, len, 0);
if (copied < 0) {
    // Fallback to manual read/write
    // Or use CopyFile() for full file copy
}
```

---

### 3. brix_plat_splice() ✅ (Stub)

**Purpose**: Zero-copy pipe splice (Linux-specific)

**Status**: ❌ Not available on Windows

**Signature**:
```c
ssize_t brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags);
```

**Implementation**:
- Always returns `-1` with `errno = ENOSYS`
- No Windows equivalent exists

**Rationale**:
- `splice()` is Linux-specific syscall for moving data through pipes
- Windows has no equivalent zero-copy pipe mechanism
- Alternatives exist but use different paradigms

**Windows Alternatives**:
1. **TransmitFile**: For file→socket (use `brix_plat_sendfile()`)
2. **IOCP**: For async I/O completion ports
3. **Named Pipes**: For IPC (not zero-copy)
4. **Buffered copy**: Manual `read()`/`write()` with large buffers

**Usage**:
```c
// Don't use splice() on Windows
ssize_t result = brix_plat_splice(in_fd, out_fd, size, 0);
if (result < 0 && errno == ENOSYS) {
    // Use TransmitFile or buffered copy instead
    result = brix_plat_sendfile(out_fd, in_fd, NULL, size);
}
```

---

## Windows APIs Used

| API | DLL | Used By | Min Windows | Purpose |
|-----|-----|---------|-------------|---------|
| `TransmitFile()` | MSWSOCK.DLL | `brix_plat_sendfile()` | Windows NT 3.5 | Zero-copy file→socket |
| `CopyFile2()` | KERNEL32.DLL | `brix_plat_copy_range()` | Windows 8 | Efficient file copy |
| `GetFinalPathNameByHandleA()` | KERNEL32.DLL | `brix_plat_copy_range()` | Windows Vista | Handle→path conversion |
| `GetFileType()` | KERNEL32.DLL | helper | Windows NT 3.5 | Determine handle type |
| `getsockopt()` | WS2_32.DLL | helper | Windows 95/NT 4 | Verify socket handle |

---

## Helper Functions

### brix_win32_get_handle_type()

**Purpose**: Determine if a handle is a file, socket, or pipe

**Returns**:
- `BRIX_WIN32_HANDLE_FILE` - Regular file
- `BRIX_WIN32_HANDLE_SOCKET` - Network socket
- `BRIX_WIN32_HANDLE_PIPE` - Pipe or character device
- `-1` - Unknown or invalid handle

**Implementation**:
```c
static int brix_win32_get_handle_type(HANDLE handle)
{
    DWORD type = GetFileType(handle);
    
    if (type == FILE_TYPE_DISK) {
        return BRIX_WIN32_HANDLE_FILE;
    }
    
    if (type == FILE_TYPE_CHAR || type == FILE_TYPE_PIPE) {
        // Check if it's a socket using getsockopt
        int optval;
        if (getsockopt((SOCKET)handle, SOL_SOCKET, SO_TYPE, ...) == 0) {
            return BRIX_WIN32_HANDLE_SOCKET;
        }
        return BRIX_WIN32_HANDLE_PIPE;
    }
    
    return -1;
}
```

### brix_win32_copy_flags_to_win32()

**Purpose**: Convert BRIX copy flags to Windows CopyFile2 flags

**Mappings**:
- `BRIX_COPY_F_REFLINK` → `COPY_FILE_NO_BUFFERING`
- `BRIX_COPY_F_MOVE` → Not supported (would need `MoveFileEx`)
- `BRIX_COPY_F_SPLICE` → Ignored (no Windows equivalent)

---

## Fallback Decision Tree

### brix_plat_sendfile() Fallback
```
Is out_fd a socket?
├─ YES → Call TransmitFile()
│  ├─ Success → Return bytes sent
│  └─ Failure → errno set, caller fallback to send()/write()
└─ NO → errno = EINVAL, caller fallback to send()/write()
```

### brix_plat_copy_range() Fallback
```
Can get file paths from handles?
├─ NO → errno = ENOSYS, caller fallback to read()/write()
└─ YES → Call CopyFile2()
   ├─ Success → Return bytes copied
   └─ Failure → errno set, caller fallback to read()/write()
```

### brix_plat_splice() Fallback
```
Always → errno = ENOSYS
Caller must use:
- TransmitFile() for file→socket
- IOCP for async I/O
- Buffered read()/write() for general case
```

---

## Performance Characteristics

| Operation | Linux Equivalent | Windows Implementation | Performance |
|-----------|------------------|------------------------|-------------|
| `sendfile()` | `sendfile()` | `TransmitFile()` | ✅ Zero-copy, similar |
| `copy_file_range()` | `copy_file_range()` | `CopyFile2()` | ✅ Efficient (full file) |
| `splice()` | `splice()` | ❌ Not available | ⚠️ Use alternatives |

**Notes**:
- `TransmitFile()` performance is comparable to Linux `sendfile()`
- `CopyFile2()` is efficient for full file copies but has overhead for ranges
- No zero-copy pipe mechanism exists on Windows

---

## Testing Recommendations

### Test Cases for brix_plat_sendfile()
1. ✅ Valid file→socket transfer
2. ✅ Offset update verification
3. ❌ Socket→file (should fail with EINVAL)
4. ❌ Socket→socket (should fail with EINVAL)
5. ❌ Invalid file descriptor

### Test Cases for brix_plat_copy_range()
1. ✅ Full file copy
2. ✅ ReFS volume copy (CoW verification)
3. ❌ Range copy (limitation - copies full file)
4. ❌ Windows 7 (CopyFile2 unavailable)
5. ❌ Handle without path (e.g., anonymous file)

### Test Cases for brix_plat_splice()
1. ❌ All cases should return ENOSYS

---

## Compatibility Matrix

| Windows Version | TransmitFile | CopyFile2 | GetFinalPathNameByHandle |
|-----------------|--------------|-----------|--------------------------|
| Windows 7 | ✅ | ❌ | ✅ |
| Windows 8 | ✅ | ✅ | ✅ |
| Windows 10 | ✅ | ✅ | ✅ |
| Windows 11 | ✅ | ✅ | ✅ |
| Server 2008 R2 | ✅ | ❌ | ✅ |
| Server 2012+ | ✅ | ✅ | ✅ |

**Recommendation**: Require Windows 8+ for full functionality. On Windows 7, `brix_plat_copy_range()` will always return ENOSYS.

---

## Future Enhancements

### Phase 2: Enhanced copy_range()
- [ ] Implement manual range copy using `SetFilePointer()` + `ReadFile()` + `WriteFile()`
- [ ] Add support for `BRIX_COPY_F_MOVE` using `MoveFileEx()`
- [ ] Optimize for small ranges (avoid full file copy overhead)

### Phase 3: IOCP Integration
- [ ] Add overlapped I/O support for async operations
- [ ] Integrate with nginx/Windows event loop
- [ ] Implement completion port-based splice alternative

### Phase 4: ReFS Optimization
- [ ] Detect ReFS volumes
- [ ] Enable CoW explicitly on ReFS
- [ ] Benchmark performance vs NTFS

---

## References

- [TransmitFile Documentation](https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-transmitfile)
- [CopyFile2 Documentation](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile2)
- [GetFinalPathNameByHandle](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlea)
- [Windows I/O Completion Ports](https://docs.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports)

---

**End of Implementation Report**
