# Linux Extended Attributes (xattr) Implementation - COMPLETE ✅

**Status**: ✅ **COMPLETE**  
**Date**: 2025-12-18  
**Platform**: Linux (x86_64, ARM64)  
**Implementation**: 8/8 functions (100%)  
**Test Coverage**: Verified via PAL integration tests  

---

## 📊 Implementation Summary

All 8 POSIX-style extended attribute functions are fully implemented for Linux using native `getxattr(2)`, `setxattr(2)`, `removexattr(2)`, and `listxattr(2)` syscalls:

| Function | Status | Lines | Description |
|----------|--------|-------|-------------|
| `brix_plat_getxattr` | ✅ Complete | 3 | Get xattr from path |
| `brix_plat_fgetxattr` | ✅ Complete | 3 | Get xattr from fd |
| `brix_plat_setxattr` | ✅ Complete | 4 | Set xattr on path |
| `brix_plat_fsetxattr` | ✅ Complete | 4 | Set xattr on fd |
| `brix_plat_removexattr` | ✅ Complete | 3 | Remove xattr from path |
| `brix_plat_fremovexattr` | ✅ Complete | 3 | Remove xattr from fd |
| `brix_plat_listxattr` | ✅ Complete | 3 | List all xattrs (path) |
| `brix_plat_flistxattr` | ✅ Complete | 3 | List xattrs (fd) |
| **TOTAL** | ✅ **8/8** | **26** | **100% Complete** |

**Implementation File**: `src/platform/linux/posix_wrapper.c` (lines 129-177)

---

## 🏗️ Architecture

### Native Linux xattr Support

Linux provides native extended attribute support through the `attr(5)` filesystem feature:

```
POSIX xattr          →  Linux Implementation
─────────────────────────────────────────────────────
getxattr()           →  syscall(__NR_getxattr)
fgetxattr()          →  syscall(__NR_fgetxattr)
setxattr()           →  syscall(__NR_setxattr)
fsetxattr()          →  syscall(__NR_fsetxattr)
removexattr()        →  syscall(__NR_removexattr)
fremovexattr()       →  syscall(__NR_fremovexattr)
listxattr()          →  syscall(__NR_listxattr)
flistxattr()         →  syscall(__NR_flistxattr)
```

### Filesystem Support

| Filesystem | xattr Support | Notes |
|------------|---------------|-------|
| **ext4** | ✅ Full | Default on most Linux systems |
| **ext3** | ✅ Full | With `user_xattr` mount option |
| **XFS** | ✅ Full | Enabled by default |
| **Btrfs** | ✅ Full | Native support |
| **NFS** | ⚠️ Limited | Server must support NFSv4 xattrs |
| **CIFS/SMB** | ⚠️ Limited | Depends on server configuration |
| **FAT32/exFAT** | ❌ None | No xattr support |
| **tmpfs** | ✅ Full | In-memory, size-limited |

### xattr Namespaces

Linux supports four xattr namespaces:

| Namespace | Prefix | Access | Use Case |
|-----------|--------|--------|----------|
| **user** | `user.` | Any user | User-defined metadata |
| **system** | `system.` | Root only | System metadata (ACLs, capabilities) |
| **security** | `security.` | Root/capability | Security labels (SELinux, AppArmor) |
| **trusted** | `trusted.` | Root only | Trusted programs only |

**Default Usage**: BriX-Cache uses `user.*` namespace for portability.

---

## 🔧 Key Features

### ✅ Complete Functionality

- **Path-based operations**: `getxattr`, `setxattr`, `removexattr`, `listxattr`
- **FD-based operations**: `fgetxattr`, `fsetxattr`, `fremovexattr`, `flistxattr`
- **Flag support**: `BRIX_XATTR_CREATE`, `BRIX_XATTR_REPLACE`
- **Binary data**: Full binary data support (no null-termination required)
- **Size queries**: Get required buffer size by passing NULL value

### ✅ Zero Overhead

Linux implementation is a **thin wrapper** with zero overhead:

```c
// Direct passthrough - no additional processing
ssize_t
brix_plat_getxattr(const char *path, const char *name, void *value, size_t size)
{
    return getxattr(path, name, value, size);
}
```

### ✅ Full Error Mapping

All Linux xattr errors are properly propagated:

| Error | Condition | Meaning |
|-------|-----------|---------|
| `ENODATA` | Attribute doesn't exist | No data for this name |
| `EEXIST` | XATTR_CREATE on existing | Attribute already exists |
| `ENOATTR` | Attribute doesn't exist | Alias for ENODATA |
| `ERANGE` | Buffer too small | Need larger buffer |
| `EINVAL` | Invalid name, NULL params | Invalid argument |
| `EBADF` | Invalid file descriptor | Bad file descriptor |
| `ENAMETOOLONG` | Path or name too long | Path name too long |
| `EACCES` | Permission denied | No read/write permission |
| `EPERM` | Wrong namespace access | Namespace permission error |
| `ENOTSUP` | Filesystem doesn't support xattr | Operation not supported |
| `EIO` | I/O error | Hardware or network error |
| `EROFS` | Read-only filesystem | Cannot modify read-only FS |

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

### Using Flags

```c
#include "src/platform/platform_api.h"
#include <errno.h>

/* Create new attribute (fail if exists) */
ssize_t result = brix_plat_setxattr(file, attr, value, size, BRIX_XATTR_CREATE);
if (result < 0) {
    if (errno == EEXIST) {
        printf("Attribute already exists\n");
    } else if (errno == ENODATA) {
        printf("Attribute does not exist\n");
    } else {
        perror("setxattr failed");
    }
}

/* Replace existing attribute (fail if not exists) */
result = brix_plat_setxattr(file, attr, value, size, BRIX_XATTR_REPLACE);
if (result < 0 && errno == ENODATA) {
    printf("Attribute does not exist, cannot replace\n");
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
- `flags`: 0, `BRIX_XATTR_CREATE`, or `BRIX_XATTR_REPLACE`

**Returns**:
- `0`: Success
- `-1`: Error (errno set)

**Errors**: `EEXIST`, `ENODATA`, `EINVAL`, `EACCES`, `ENOSPC`, `ENOTSUP`, `EROFS`

**Flags**:
- `0`: Create or replace
- `BRIX_XATTR_CREATE`: Fail if attribute exists
- `BRIX_XATTR_REPLACE`: Fail if attribute doesn't exist

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

1. **FAT32/exFAT**: No xattr support - operations return `ENOTSUP`
2. **NFS/CIFS**: Depends on server configuration - may return `ENOTSUP` or `EIO`
3. **tmpfs**: Size-limited - may return `ENOSPC` if xattr storage exhausted

### Permission Considerations

1. **user.* namespace**: Any user with file access
2. **security.* namespace**: Requires `CAP_SECURITY` or root
3. **trusted.* namespace**: Requires root
4. **system.* namespace**: Requires root

### Size Limitations

| Filesystem | Max xattr Size | Notes |
|------------|----------------|-------|
| ext4 | ~4KB | Inline in inode |
| ext4 (large) | ~64KB | With `large_dir` feature |
| XFS | ~64KB | Block-based storage |
| Btrfs | ~16KB | Inline or extent-based |
| tmpfs | ~64KB | Memory-limited |

### Performance Characteristics

| Operation | Latency | Notes |
|-----------|---------|-------|
| getxattr (cached) | <1μs | Inode cache hit |
| getxattr (disk) | 10-100μs | Disk read required |
| setxattr (small) | 10-50μs | Inode update |
| setxattr (large) | 100-500μs | Block allocation |
| listxattr | 5-20μs | Usually cached |

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

### Handle ERANGE for Buffer Too Small

```c
/* Query size first */
ssize_t size = brix_plat_getxattr(path, "user.myattr", NULL, 0);
if (size < 0) {
    perror("size query failed");
    return 1;
}

/* Allocate and retry */
char *buffer = malloc(size);
if (!buffer) {
    perror("malloc failed");
    return 1;
}

ssize_t result = brix_plat_getxattr(path, "user.myattr", buffer, size);
if (result < 0) {
    if (errno == ERANGE) {
        /* Buffer still too small - race condition? */
        fprintf(stderr, "Buffer too small after size query\n");
    } else {
        perror("getxattr failed");
    }
    free(buffer);
    return 1;
}
```

### Handle EEXIST/ENODATA for Flags

```c
/* XATTR_CREATE: fail if exists */
int result = brix_plat_setxattr(path, "user.myattr", value, size, BRIX_XATTR_CREATE);
if (result < 0 && errno == EEXIST) {
    printf("Attribute already exists, not overwriting\n");
}

/* XATTR_REPLACE: fail if doesn't exist */
result = brix_plat_setxattr(path, "user.myattr", value, size, BRIX_XATTR_REPLACE);
if (result < 0 && errno == ENODATA) {
    printf("Attribute doesn't exist, cannot replace\n");
}
```

---

## 🧪 Testing

### Manual Testing

```bash
# Set an attribute
setfattr -n user.comment -v "Test value" file.txt

# Get an attribute
getfattr -n user.comment file.txt

# List all attributes
getfattr -d file.txt

# Remove an attribute
setfattr -x user.comment file.txt
```

### Programmatic Testing

```c
#include "src/platform/platform_api.h"
#include <assert.h>
#include <errno.h>

void test_xattr_basic(void) {
    const char *file = "test_xattr.txt";
    const char *attr = "user.test";
    const char *value = "test_value";
    char buffer[256];
    ssize_t result;

    /* Create test file */
    FILE *f = fopen(file, "w");
    fclose(f);

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
    assert(result < 0 && errno == ENODATA);

    /* Cleanup */
    unlink(file);
    printf("✓ Basic xattr test passed\n");
}
```

---

## 📚 References

- `xattr(7)` - Linux man page for extended attributes
- `getxattr(2)`, `setxattr(2)`, `removexattr(2)`, `listxattr(2)` - System call documentation
- `attr(5)` - Filesystem attributes documentation
- https://www.kernel.org/doc/html/latest/filesystems/ext4/attributes.html
- https://wiki.archlinux.org/title/Xattr

---

## ✅ Verification Checklist

- [x] All 8 functions implemented
- [x] Direct syscall passthrough (zero overhead)
- [x] Full error propagation
- [x] Flag support (CREATE, REPLACE)
- [x] Path-based and FD-based variants
- [x] Size query pattern supported
- [x] Binary data support
- [x] Namespace documentation (user, security, trusted, system)
- [x] Filesystem compatibility documented
- [x] Performance characteristics documented
- [x] Usage examples provided
- [x] Error handling best practices documented

---

**Implementation Status**: ✅ **COMPLETE**  
**Documentation Status**: ✅ **COMPLETE**  
**Production Ready**: ✅ **YES**  
