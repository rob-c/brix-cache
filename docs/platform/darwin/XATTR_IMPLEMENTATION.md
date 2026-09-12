# macOS Extended Attributes (xattr) Implementation - COMPLETE ✅

**Status**: ✅ **COMPLETE**  
**Date**: 2025-12-18  
**Platform**: macOS (x86_64, ARM64/Apple Silicon)  
**Implementation**: 8/8 functions (100%)  
**Test Coverage**: Verified via PAL integration tests  

---

## 📊 Implementation Summary

All 8 POSIX-style extended attribute functions are fully implemented for macOS using native `getxattr(2)`, `setxattr(2)`, `removexattr(2)`, and `listxattr(2)` system calls:

| Function | Status | Lines | Description |
|----------|--------|-------|-------------|
| `brix_plat_getxattr` | ✅ Complete | 8 | Get xattr from path |
| `brix_plat_fgetxattr` | ✅ Complete | 8 | Get xattr from fd |
| `brix_plat_setxattr` | ✅ Complete | 9 | Set xattr on path |
| `brix_plat_fsetxattr` | ✅ Complete | 9 | Set xattr on fd |
| `brix_plat_removexattr` | ✅ Complete | 8 | Remove xattr from path |
| `brix_plat_fremovexattr` | ✅ Complete | 8 | Remove xattr from fd |
| `brix_plat_listxattr` | ✅ Complete | 8 | List all xattrs (path) |
| `brix_plat_flistxattr` | ✅ Complete | 8 | List xattrs (fd) |
| **TOTAL** | ✅ **8/8** | **66** | **100% Complete** |

**Implementation File**: `src/platform/darwin/posix_wrapper.c` (lines 229-284)

---

## 🏗️ Architecture

### Native macOS xattr Support

macOS provides native extended attribute support through BSD-style system calls, compatible with POSIX xattr semantics:

```
POSIX xattr          →  macOS Implementation
─────────────────────────────────────────────────────
getxattr()           →  getxattr(2) syscall
fgetxattr()          →  fgetxattr(2) syscall
setxattr()           →  setxattr(2) syscall
fsetxattr()          →  fsetxattr(2) syscall
removexattr()        →  removexattr(2) syscall
fremovexattr()       →  fremovexattr(2) syscall
listxattr()          →  listxattr(2) syscall
flistxattr()         →  flistxattr(2) syscall
```

### Filesystem Support

| Filesystem | xattr Support | Notes |
|------------|---------------|-------|
| **APFS** | ✅ Full | Default on macOS 10.13+ |
| **HFS+** | ✅ Full | Legacy macOS filesystem |
| **NFS** | ⚠️ Limited | Server must support xattrs |
| **SMB/CIFS** | ⚠️ Limited | Depends on server |
| **FAT32/exFAT** | ❌ None | No xattr support |
| **NTFS (read-only)** | ❌ None | macOS NTFS driver doesn't support xattrs |

### APFS Enhanced Features

APFS (Apple File System) provides enhanced xattr capabilities:

| Feature | Description |
|---------|-------------|
| **Inline xattrs** | Small xattrs stored directly in inode (fast) |
| **Extended xattrs** | Large xattrs stored in separate extents |
| **Resource forks** | Legacy Mac resource fork support via xattr |
| **File clones** | Cloned files share xattrs until modified |
| **Snapshots** | Xattrs preserved in APFS snapshots |

### xattr Namespaces

macOS supports xattr namespaces with some differences from Linux:

| Namespace | Prefix | Access | Use Case |
|-----------|--------|--------|----------|
| **user** | `user.` | Any user | User-defined metadata |
| **system** | `system.` | Root only | System metadata |
| **security** | `security.` | Root/capability | Security labels |
| **com.apple** | `com.apple.` | Mixed | Apple-specific metadata |

**Common Apple xattrs**:
- `com.apple.FinderInfo` - Finder metadata
- `com.apple.ResourceFork` - Legacy resource fork
- `com.apple.metadata:kMDItem*` - Spotlight metadata
- `com.apple.quarantine` - Gatekeeper quarantine flag

**Default Usage**: BriX-Cache uses `user.*` namespace for portability.

---

## 🔧 Key Features

### ✅ Complete Functionality

- **Path-based operations**: `getxattr`, `setxattr`, `removexattr`, `listxattr`
- **FD-based operations**: `fgetxattr`, `fsetxattr`, `fremovexattr`, `flistxattr`
- **Flag support**: `BRIX_XATTR_CREATE`, `BRIX_XATTR_REPLACE`, `XATTR_NOFOLLOW`
- **Binary data**: Full binary data support (no null-termination required)
- **Size queries**: Get required buffer size by passing NULL value

### ✅ Zero Overhead

macOS implementation is a **thin wrapper** with zero overhead:

```c
// Direct passthrough - no additional processing
ssize_t
brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    return getxattr(path, name, value, size, 0, 0);
}
```

**Note**: macOS `getxattr(2)` takes 6 parameters (vs 4 on Linux):
- Position 5: `uint32_t position` - Resource fork position (0 for xattrs)
- Position 6: `int options` - Flags like `XATTR_NOFOLLOW`

### ✅ Full Error Mapping

All macOS xattr errors are properly propagated:

| Error | Condition | Meaning |
|-------|-----------|---------|
| `ENODATA` | Attribute doesn't exist | No data for this name |
| `ENOATTR` | Attribute doesn't exist | Alias for ENODATA (BSD) |
| `EEXIST` | XATTR_CREATE on existing | Attribute already exists |
| `ERANGE` | Buffer too small | Need larger buffer |
| `EINVAL` | Invalid name, NULL params | Invalid argument |
| `EBADF` | Invalid file descriptor | Bad file descriptor |
| `ENAMETOOLONG` | Path or name too long | Path name too long |
| `EACCES` | Permission denied | No read/write permission |
| `EPERM` | Wrong namespace access | Operation not permitted |
| `ENOTSUP` | Filesystem doesn't support | Operation not supported |
| `EIO` | I/O error | Hardware or network error |
| `EROFS` | Read-only filesystem | Cannot modify read-only FS |
| `ENOSPC` | No space left | Filesystem full |

---

## 📝 Usage Examples

### Basic Set/Get/Remove

```c
#include "src/platform/platform_api.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(void) {
    const char *file = "example.txt";
    const char *attr = "user.comment";
    const char *value = "This is a test";
    char buffer[256];
    ssize_t result;

    /* Set attribute */
    result = brix_plat_setxattr(file, attr, value, strlen(value) + 1, 0);
    if (result < 0) {
        perror("setxattr failed");
        return 1;
    }
    printf("Set attribute: %zd bytes\n", result);

    /* Get attribute */
    result = brix_plat_getxattr(file, attr, buffer, sizeof(buffer));
    if (result > 0) {
        printf("Attribute value: %s\n", buffer);
    } else if (result < 0) {
        perror("getxattr failed");
    }

    /* Remove attribute */
    result = brix_plat_removexattr(file, attr);
    if (result < 0) {
        perror("removexattr failed");
    }

    return 0;
}
```

### Using Flags (macOS-specific)

```c
#include "src/platform/platform_api.h"
#include <sys/xattr.h>
#include <errno.h>

/* Create new attribute (fail if exists) */
ssize_t result = brix_plat_setxattr(file, attr, value, size, BRIX_XATTR_CREATE);
if (result < 0) {
    if (errno == EEXIST) {
        printf("Attribute already exists\n");
    }
}

/* Don't follow symlinks (macOS-specific) */
result = brix_plat_setxattr(file, attr, value, size, XATTR_NOFOLLOW);
if (result < 0 && errno == EINVAL) {
    printf("Cannot set xattr on symlink without following\n");
}
```

### File Descriptor Operations

```c
#include "src/platform/platform_api.h"
#include <fcntl.h>
#include <unistd.h>

int fd = open("example.txt", O_RDWR);
if (fd < 0) {
    perror("open failed");
    return 1;
}

/* Set using fd */
ssize_t result = brix_plat_fsetxattr(fd, "user.myattr", value, size, 0);
if (result < 0) {
    perror("fsetxattr failed");
}

/* Get using fd */
result = brix_plat_fgetxattr(fd, "user.myattr", buffer, sizeof(buffer));
if (result > 0) {
    printf("Value: %.*s\n", (int)result, buffer);
}

/* Remove using fd */
result = brix_plat_fremovexattr(fd, "user.myattr");
if (result < 0) {
    perror("fremovexattr failed");
}

close(fd);
```

### Size Query Pattern

```c
/* First call: get required size */
ssize_t size = brix_plat_getxattr(path, "user.myattr", NULL, 0);
if (size < 0) {
    perror("getxattr size query failed");
    return 1;
}

/* Allocate buffer */
char *buffer = malloc(size + 1);  /* +1 for null terminator */
if (!buffer) {
    perror("malloc failed");
    return 1;
}

/* Second call: get actual value */
ssize_t result = brix_plat_getxattr(path, "user.myattr", buffer, size);
if (result < 0) {
    perror("getxattr failed");
    free(buffer);
    return 1;
}

/* Null-terminate for string safety */
buffer[result] = '\0';
printf("Value: %s\n", buffer);

free(buffer);
```

### Listing All Attributes

```c
/* First call: get required size */
ssize_t size = brix_plat_listxattr(path, NULL, 0);
if (size < 0) {
    perror("listxattr size query failed");
    return 1;
}

/* Allocate buffer */
char *list = malloc(size);
if (!list) {
    perror("malloc failed");
    return 1;
}

/* Second call: get attribute list */
ssize_t result = brix_plat_listxattr(path, list, size);
if (result < 0) {
    perror("listxattr failed");
    free(list);
    return 1;
}

/* Iterate through null-separated list */
char *attr = list;
char *end = list + result;
while (attr < end) {
    printf("Attribute: %s\n", attr);
    attr += strlen(attr) + 1;  /* Skip to next null-terminated string */
}

free(list);
```

### Apple-Specific: Check Quarantine Flag

```c
#include "src/platform/platform_api.h"

int is_quarantined(const char *path) {
    char buffer[256];
    ssize_t result = brix_plat_getxattr(path, "com.apple.quarantine", 
                                        buffer, sizeof(buffer));
    if (result < 0) {
        return 0;  /* No quarantine attribute */
    }
    return 1;  /* File is quarantined */
}
```

---

## 📋 Function Reference

### brix_plat_getxattr()

```c
ssize_t brix_plat_getxattr(const char *path, const char *name, 
                           void *value, size_t size);
```

**Description**: Retrieve extended attribute value from a file.

**Parameters**:
- `path`: Path to the file
- `name`: Attribute name (e.g., "user.myattr")
- `value`: Buffer to store value (can be NULL for size query)
- `size`: Size of value buffer

**Returns**:
- `>0`: Number of bytes read
- `-1`: Error (errno set)

**Errors**: `ENODATA`, `ERANGE`, `EINVAL`, `EACCES`, `ENOENT`, `ENOTSUP`

**macOS Notes**: Calls `getxattr(path, name, value, size, 0, 0)` internally.

---

### brix_plat_fgetxattr()

```c
ssize_t brix_plat_fgetxattr(int fd, const char *name, 
                            void *value, size_t size);
```

**Description**: Retrieve extended attribute value from an open file descriptor.

**Parameters**:
- `fd`: Open file descriptor
- `name`: Attribute name
- `value`: Buffer to store value
- `size`: Size of value buffer

**Returns**:
- `>0`: Number of bytes read
- `-1`: Error (errno set)

**Errors**: `ENODATA`, `ERANGE`, `EINVAL`, `EBADF`, `ENOTSUP`

---

### brix_plat_setxattr()

```c
int brix_plat_setxattr(const char *path, const char *name,
                       const void *value, size_t size, int flags);
```

**Description**: Set extended attribute on a file.

**Parameters**:
- `path`: Path to the file
- `name`: Attribute name
- `value`: Value to set
- `size`: Size of value
- `flags`: 0, `BRIX_XATTR_CREATE`, `BRIX_XATTR_REPLACE`, or `XATTR_NOFOLLOW`

**Returns**:
- `0`: Success
- `-1`: Error (errno set)

**Errors**: `EEXIST`, `ENODATA`, `EINVAL`, `EACCES`, `ENOSPC`, `ENOTSUP`, `EROFS`

**macOS Flags**:
- `0`: Create or replace
- `BRIX_XATTR_CREATE`: Fail if attribute exists
- `BRIX_XATTR_REPLACE`: Fail if attribute doesn't exist
- `XATTR_NOFOLLOW`: Don't follow symlinks

---

### brix_plat_fsetxattr()

```c
int brix_plat_fsetxattr(int fd, const char *name,
                        const void *value, size_t size, int flags);
```

**Description**: Set extended attribute on an open file descriptor.

**Parameters**: Same as `brix_plat_setxattr()` but with `fd` instead of `path`.

**Returns**: `0` on success, `-1` on error.

**Errors**: `EEXIST`, `ENODATA`, `EINVAL`, `EBADF`, `ENOSPC`, `ENOTSUP`, `EROFS`

---

### brix_plat_removexattr()

```c
int brix_plat_removexattr(const char *path, const char *name);
```

**Description**: Remove extended attribute from a file.

**Parameters**:
- `path`: Path to the file
- `name`: Attribute name to remove

**Returns**:
- `0`: Success
- `-1`: Error (errno set)

**Errors**: `ENODATA`, `EINVAL`, `EACCES`, `ENOENT`, `ENOTSUP`, `EROFS`

---

### brix_plat_fremovexattr()

```c
int brix_plat_fremovexattr(int fd, const char *name);
```

**Description**: Remove extended attribute from an open file descriptor.

**Parameters**:
- `fd`: Open file descriptor
- `name`: Attribute name to remove

**Returns**: `0` on success, `-1` on error.

**Errors**: `ENODATA`, `EINVAL`, `EBADF`, `ENOTSUP`, `EROFS`

---

### brix_plat_listxattr()

```c
ssize_t brix_plat_listxattr(const char *path, char *list, size_t size);
```

**Description**: List all extended attribute names on a file.

**Parameters**:
- `path`: Path to the file
- `list`: Buffer to store attribute names (can be NULL for size query)
- `size`: Size of list buffer

**Returns**:
- `>0`: Number of bytes in the list
- `-1`: Error (errno set)

**Notes**: Attribute names are null-separated in the buffer.

**Errors**: `ERANGE`, `EINVAL`, `EACCES`, `ENOENT`, `ENOTSUP`

---

### brix_plat_flistxattr()

```c
ssize_t brix_plat_flistxattr(int fd, char *list, size_t size);
```

**Description**: List all extended attribute names on an open file descriptor.

**Parameters**:
- `fd`: Open file descriptor
- `list`: Buffer to store attribute names
- `size`: Size of list buffer

**Returns**: `>0` on success (bytes in list), `-1` on error.

**Errors**: `ERANGE`, `EINVAL`, `EBADF`, `ENOTSUP`

---

## ⚠️ Limitations and Considerations

### Filesystem Limitations

1. **APFS**: Full xattr support with inline and extended storage
2. **HFS+**: Full xattr support (legacy)
3. **FAT32/exFAT**: No xattr support - operations return `ENOTSUP`
4. **NTFS (read-only)**: macOS NTFS driver doesn't support xattrs
5. **NFS/SMB**: Depends on server configuration

### Permission Considerations

1. **user.* namespace**: Any user with file access
2. **system.* namespace**: Requires root
3. **security.* namespace**: Requires root or appropriate entitlement
4. **com.apple.* namespace**: Varies by specific attribute

### Size Limitations

| Filesystem | Max xattr Size | Notes |
|------------|----------------|-------|
| APFS (inline) | ~3.5KB | Stored in inode |
| APFS (extended) | ~8MB | Separate extents |
| HFS+ | ~128KB | Attribute fork |

### Performance Characteristics

| Operation | Latency | Notes |
|-----------|---------|-------|
| getxattr (cached) | <1μs | Inode cache hit |
| getxattr (APFS) | 5-50μs | Flash storage typical |
| getxattr (HDD) | 5-15ms | Mechanical disk |
| setxattr (small) | 10-50μs | Inode update |
| setxattr (large) | 50-200μs | Extent allocation |
| listxattr | 5-20μs | Usually cached |

### APFS-Specific Features

| Feature | Benefit |
|---------|---------|
| **Clones** | Copy-on-write preserves xattrs |
| **Snapshots** | Xattrs preserved in snapshots |
| **Encryption** | Xattrs encrypted with file data |
| **Space sharing** | Efficient xattr storage |

---

## 🔍 Error Handling Best Practices

### Check for ENODATA vs ENOATTR

```c
ssize_t result = brix_plat_getxattr(path, "user.myattr", buffer, size);
if (result < 0) {
    if (errno == ENODATA || errno == ENOATTR) {
        /* Attribute doesn't exist - this is normal */
        printf("Attribute not found\n");
    } else {
        /* Real error */
        perror("getxattr failed");
    }
}
```

**Note**: `ENOATTR` is the BSD alias for `ENODATA` - both are valid on macOS.

### Handle XATTR_NOFOLLOW for Symlinks

```c
/* Don't follow symlinks */
int result = brix_plat_setxattr(symlink_path, "user.myattr", value, size, XATTR_NOFOLLOW);
if (result < 0 && errno == EINVAL) {
    /* Cannot set xattr on symlink without following */
    printf("Cannot set xattr on symlink\n");
}

/* Follow symlinks (default) */
result = brix_plat_setxattr(symlink_path, "user.myattr", value, size, 0);
```

### Handle Quarantine Attribute

```c
/* Check if file is quarantined by Gatekeeper */
ssize_t result = brix_plat_getxattr(path, "com.apple.quarantine", NULL, 0);
if (result > 0) {
    printf("File is quarantined by Gatekeeper\n");
    /* May need to remove quarantine flag for certain operations */
}
```

---

## 🧪 Testing

### Manual Testing

```bash
# Set an attribute
xattr -w user.comment "Test value" file.txt

# Get an attribute
xattr -p user.comment file.txt

# List all attributes
xattr -l file.txt

# Remove an attribute
xattr -d user.comment file.txt

# Edit attribute in editor
xattr -e user.comment file.txt
```

### Programmatic Testing

```c
#include "src/platform/platform_api.h"
#include <assert.h>
#include <errno.h>
#include <unistd.h>

void test_xattr_basic(void) {
    const char *file = "test_xattr.txt";
    const char *attr = "user.test";
    const char *value = "test_value";
    char buffer[256];
    ssize_t result;

    /* Create test file */
    int fd = open(file, O_CREAT | O_RDWR, 0644);
    close(fd);

    /* Set attribute */
    result = brix_plat_setxattr(file, attr, value, strlen(value) + 1, 0);
    assert(result >= 0);

    /* Get attribute */
    result = brix_plat_getxattr(file, attr, buffer, sizeof(buffer));
    assert(result > 0);
    assert(strcmp(buffer, value) == 0);

    /* Remove attribute */
    result = brix_plat_removexattr(file, attr);
    assert(result == 0);

    /* Verify removal */
    result = brix_plat_getxattr(file, attr, buffer, sizeof(buffer));
    assert(result < 0 && (errno == ENODATA || errno == ENOATTR));

    /* Cleanup */
    unlink(file);
    printf("✓ Basic xattr test passed\n");
}
```

### Test with Symlinks

```c
void test_xattr_symlink(void) {
    const char *file = "test_target.txt";
    const char *link = "test_link.txt";
    const char *attr = "user.test";
    
    /* Create target and symlink */
    int fd = open(file, O_CREAT | O_RDWR, 0644);
    close(fd);
    symlink(file, link);
    
    /* Set on symlink (don't follow) */
    int result = brix_plat_setxattr(link, attr, "value", 6, XATTR_NOFOLLOW);
    if (result < 0) {
        printf("Expected: cannot set xattr on symlink without following\n");
    }
    
    /* Set on symlink (follow) */
    result = brix_plat_setxattr(link, attr, "value", 6, 0);
    assert(result >= 0);  /* Sets on target */
    
    /* Cleanup */
    unlink(link);
    unlink(file);
    printf("✓ Symlink xattr test passed\n");
}
```

---

## 📚 References

- `xattr(2)` - macOS man page for extended attributes
- `getxattr(2)`, `setxattr(2)`, `removexattr(2)`, `listxattr(2)` - System call documentation
- `xattr(1)` - Command-line utility
- https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html
- https://developer.apple.com/documentation/foundation/nsfileattributekey

---

## 🔍 macOS vs Linux Differences

| Feature | Linux | macOS |
|---------|-------|-------|
| **System calls** | 4 parameters | 6 parameters |
| **Symlink handling** | `lgetxattr()` separate | `XATTR_NOFOLLOW` flag |
| **Resource forks** | Not supported | Supported via xattr |
| **Finder metadata** | N/A | `com.apple.FinderInfo` |
| **Quarantine** | N/A | `com.apple.quarantine` |
| **Spotlight** | N/A | `com.apple.metadata:kMDItem*` |
| **Max inline size** | ~4KB (ext4) | ~3.5KB (APFS) |
| **Max extended size** | ~64KB | ~8MB |

---

## ✅ Verification Checklist

- [x] All 8 functions implemented
- [x] Direct syscall passthrough (zero overhead)
- [x] Full error propagation
- [x] Flag support (CREATE, REPLACE, NOFOLLOW)
- [x] Path-based and FD-based variants
- [x] Size query pattern supported
- [x] Binary data support
- [x] Namespace documentation (user, system, security, com.apple)
- [x] Filesystem compatibility documented
- [x] APFS-specific features documented
- [x] Performance characteristics documented
- [x] Usage examples provided
- [x] Error handling best practices documented
- [x] macOS vs Linux differences documented
- [x] Apple-specific xattrs documented

---

**Implementation Status**: ✅ **COMPLETE**  
**Documentation Status**: ✅ **COMPLETE**  
**Production Ready**: ✅ **YES**  
