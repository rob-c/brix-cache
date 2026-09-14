# Windows Extended Attributes via NTFS Alternate Data Streams

**Status**: 🚧 Implementation Complete (Draft)  
**File**: `src/platform/windows/xattr.c`

---

## Overview

This document describes the implementation of POSIX-style extended attributes (xattr) on Windows using NTFS Alternate Data Streams (ADS).

### What are Alternate Data Streams?

NTFS Alternate Data Streams allow a single file to have multiple data streams associated with it. This is conceptually similar to extended attributes in POSIX systems.

**Example**:
```
myfile.txt           → Main data stream
myfile.txt:attr1     → Alternate data stream "attr1"
myfile.txt:attr2     → Alternate data stream "attr2"
```

---

## Implementation Approach

### Name Mapping

POSIX xattr names are mapped directly to ADS stream names:

| POSIX | Windows ADS |
|-------|-------------|
| `user.myattr` | `filepath:user.myattr` |
| `security.selinux` | `filepath:security.selinux` |
| `trusted.foo` | `filepath:trusted.foo` |

The namespace prefix (`user.`, `security.`, `trusted.`) is preserved as-is.

### API Mapping

| POSIX Function | Windows Implementation |
|----------------|----------------------|
| `getxattr(path, name, value, size)` | `CreateFileW("path:name")` → `ReadFile()` |
| `setxattr(path, name, value, size, flags)` | `CreateFileW("path:name")` → `WriteFile()` |
| `removexattr(path, name)` | `DeleteFileW("path:name")` |
| `listxattr(path, list, size)` | `FindFirstStreamW()` / `FindNextStreamW()` |

### File Descriptor Variants

For `f*` variants (e.g., `fgetxattr`), we:
1. Convert fd → HANDLE using `_get_osfhandle()`
2. Get file path using `GetFinalPathNameByHandleW()`
3. Proceed with path-based implementation

---

## Code Examples

### Setting an Extended Attribute

```c
#include "platform/platform_api.h"

const char *path = "C:\\data\\myfile.txt";
const char *value = "Hello, World!";
int ret;

ret = brix_plat_setxattr(path, "user.comment", value, strlen(value), 0);
if (ret < 0) {
    perror("setxattr failed");
}
```

This creates an ADS named `C:\data\myfile.txt:user.comment` containing "Hello, World!".

### Getting an Extended Attribute

```c
char buffer[256];
ssize_t size;

size = brix_plat_getxattr("C:\\data\\myfile.txt", "user.comment", 
                          buffer, sizeof(buffer));
if (size > 0) {
    printf("Attribute value: %.*s\n", (int)size, buffer);
} else if (errno == ENODATA) {
    printf("Attribute does not exist\n");
}
```

### Listing All Attributes

```c
char list[1024];
ssize_t size;
char *p;

size = brix_plat_listxattr("C:\\data\\myfile.txt", list, sizeof(list));
if (size > 0) {
    for (p = list; p < list + size; p += strlen(p) + 1) {
        printf("Attribute: %s\n", p);
    }
}
```

---

## NTFS-Only Limitations

### ⚠️ Critical: NTFS Filesystem Required

**ADS is an NTFS-specific feature.** It does not work on:

- ❌ **FAT32** - Common on USB drives, SD cards
- ❌ **exFAT** - Common on external drives
- ❌ **ReFS** - Windows Resilient File System (some support, but limited)
- ❌ **Network shares** - SMB may not preserve ADS
- ❌ **Compressed/encrypted files** - ADS may be inaccessible

### Detection

Use `brix_win32_is_ntfs_path()` to check if a path is on NTFS:

```c
if (!brix_win32_is_ntfs_path("C:\\data\\myfile.txt")) {
    fprintf(stderr, "Error: ADS not supported on this filesystem\n");
    return -1;
}
```

### Stream Name Limitations

ADS names cannot contain these characters:
```
:  \  /  *  ?  "  <  >  |
```

Maximum stream name length: **255 characters**

### Size Limitations

- Maximum ADS size: Limited by volume size (theoretically up to 16 TB)
- Practical limit: Performance degrades with very large streams (>100 MB)

---

## Security Considerations

### 1. Antivirus Flags

Some antivirus software monitors ADS usage because malware can use ADS to hide data.

**Mitigation**: Document ADS usage clearly, consider signing executables.

### 2. Security Descriptors

ADS inherit security descriptors from the parent file, but can also have independent ACLs.

**Current Implementation**: Uses default inheritance (same as parent file).

**Future Enhancement**: Could use `SetNamedSecurityInfo()` to set explicit ACLs on streams.

### 3. Backup/Restore

Some backup tools do not preserve ADS by default.

**Mitigation**: Use backup tools that explicitly support ADS:
- ✅ robocopy (with `/COPYALL` flag)
- ✅ Windows Server Backup
- ❌ Some third-party tools

---

## Compatibility Matrix

| Operation | Windows NTFS | Windows FAT32 | Linux xattr | macOS xattr |
|-----------|--------------|---------------|-------------|-------------|
| `setxattr` | ✅ Supported | ❌ Not supported | ✅ Supported | ✅ Supported |
| `getxattr` | ✅ Supported | ❌ Not supported | ✅ Supported | ✅ Supported |
| `removexattr` | ✅ Supported | ❌ Not supported | ✅ Supported | ✅ Supported |
| `listxattr` | ✅ Supported | ❌ Not supported | ✅ Supported | ✅ Supported |
| Max value size | ~16 TB | N/A | ~64 KB | ~128 KB |
| Atomic operations | ✅ Yes | N/A | ✅ Yes | ✅ Yes |

---

## Error Handling

### Error Code Mapping

| Windows Error | POSIX errno | Meaning |
|---------------|-------------|---------|
| `ERROR_FILE_NOT_FOUND` | `ENODATA` | Stream doesn't exist |
| `ERROR_HANDLE_EOF` | `ENODATA` | Stream is empty |
| `ERROR_FILE_EXISTS` | `EEXIST` | Stream exists (XATTR_CREATE) |
| `ERROR_ACCESS_DENIED` | `EACCES` | Permission denied |
| `ERROR_INVALID_NAME` | `EINVAL` | Invalid stream name |
| `ERROR_BUFFER_OVERFLOW` | `ERANGE` | Buffer too small |

### Example Error Handling

```c
ssize_t size = brix_plat_getxattr(path, "user.comment", buf, sizeof(buf));
if (size < 0) {
    switch (errno) {
        case ENODATA:
            fprintf(stderr, "Attribute does not exist\n");
            break;
        case ERANGE:
            fprintf(stderr, "Buffer too small, need %zd bytes\n", 
                    brix_plat_getxattr(path, "user.comment", NULL, 0));
            break;
        case EACCES:
            fprintf(stderr, "Permission denied\n");
            break;
        default:
            perror("getxattr failed");
            break;
    }
}
```

---

## Performance Characteristics

### Operation Costs

| Operation | Relative Cost | Notes |
|-----------|---------------|-------|
| `setxattr` (small) | Low | Similar to small file write |
| `getxattr` (small) | Low | Similar to small file read |
| `removexattr` | Low | Metadata operation |
| `listxattr` | Medium | Enumerates all streams |
| `setxattr` (large) | High | Full file I/O |

### Optimization Tips

1. **Keep attributes small** (< 4 KB) for best performance
2. **Batch operations** when possible
3. **Avoid listing** in hot paths (expensive)
4. **Cache attribute values** if read frequently

---

## Testing

### Manual Testing

```cmd
# Create a file with ADS
echo Hello > C:\test\file.txt
echo World > C:\test\file.txt:myattr

# List streams (PowerShell)
Get-Item C:\test\file.txt -Stream *

# Read ADS
Get-Content C:\test\file.txt:myattr

# Delete ADS
Remove-Item C:\test\file.txt:myattr
```

### Automated Testing

```c
// tests/platform/test_windows_xattr.c

void test_set_get_xattr(void) {
    const char *path = "test_file.txt";
    const char *value = "test value";
    char buf[64];
    
    assert(brix_plat_setxattr(path, "user.test", value, strlen(value), 0) == 0);
    assert(brix_plat_getxattr(path, "user.test", buf, sizeof(buf)) == strlen(value));
    assert(strcmp(buf, value) == 0);
}

void test_list_xattr(void) {
    char list[256];
    ssize_t size;
    
    size = brix_plat_listxattr("test_file.txt", list, sizeof(list));
    assert(size > 0);
    assert(memmem(list, size, "user.test", 10) != NULL);
}

void test_remove_xattr(void) {
    assert(brix_plat_removexattr("test_file.txt", "user.test") == 0);
    assert(brix_plat_getxattr("test_file.txt", "user.test", NULL, 0) < 0);
    assert(errno == ENODATA);
}
```

---

## Future Enhancements

### 1. Namespace Support

Currently all namespaces (`user.`, `security.`, `trusted.`, `system.`) are mapped directly.

**Future**: Could map to different ADS prefixes:
```
user.foo    → :user.foo
security.bar → :$security_bar  (hidden stream)
```

### 2. Security Descriptor Integration

```c
// Future API
int brix_plat_setxattr_with_security(
    const char *path, 
    const char *name,
    const void *value, 
    size_t size,
    const SECURITY_DESCRIPTOR *sd  // Custom ACL
);
```

### 3. Transaction Support

```c
// Future API - atomic multi-attribute operations
int brix_plat_xattr_begin_transaction(const char *path);
int brix_plat_xattr_commit_transaction(void);
int brix_plat_xattr_rollback_transaction(void);
```

### 4. Volume Quota Support

```c
// Future API - check ADS space usage
ssize_t brix_win32_get_ads_quota(const char *path);
ssize_t brix_win32_get_ads_usage(const char *path);
```

---

## References

- [Microsoft Docs: Alternate Data Streams](https://docs.microsoft.com/en-us/windows/win32/fileio/alternate-data-streams)
- [The Old New Thing: ADS Overview](https://blogs.msdn.microsoft.com/oldnewthing/20151229-00/?p=92111)
- [NTFS.com: Alternate Data Streams](https://www.ntfs.com/alternate-data-streams.htm)
- [POSIX xattr Specification](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getxattr.html)

---

## Summary

**Advantages**:
- ✅ Native Windows implementation (no compatibility layer)
- ✅ Supports all xattr operations (get/set/remove/list)
- ✅ Large attribute sizes (up to volume size)
- ✅ Atomic operations
- ✅ Security descriptor inheritance

**Limitations**:
- ⚠️ NTFS-only (not FAT32/exFAT/ReFS)
- ⚠️ Stream name character restrictions
- ⚠️ Antivirus sensitivity
- ⚠️ Backup tool compatibility varies

**Recommendation**: 
- Use for Windows-native deployments on NTFS volumes
- Detect non-NTFS volumes and fallback gracefully
- Document ADS usage for users and backup administrators

---

**End of Document**
