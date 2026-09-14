# Migration Guide: #ifdef to Platform Abstraction Layer (PAL)

**Document Status**: ✅ Complete  
**Version**: 1.0  
**Date**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Audience**: Developers migrating existing code to use PAL

---

## Overview

This guide provides step-by-step instructions for migrating platform-specific `#ifdef` code to use the Platform Abstraction Layer (PAL) API. The PAL eliminates platform detection logic from business code, moving it to dedicated implementation files.

### Benefits of Migration

✅ **Cleaner code** - No `#ifdef` blocks in business logic  
✅ **Easier testing** - Platform logic isolated and testable  
✅ **Faster onboarding** - New developers don't need platform expertise  
✅ **Reduced bugs** - Platform differences handled consistently  
✅ **Future-proof** - Easy to add new platforms (Windows, BSD, etc.)

---

## Migration Patterns

### Pattern 1: Byte-Order Operations

**Before** (❌):
```c
#if defined(__APPLE__) && defined(__MACH__)
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

uint64_t val = htobe64(offset);
```

**After** (✅):
```c
#include "platform/platform_api.h"

uint64_t val = brix_plat_htobe64(offset);
```

**Migration Steps**:
1. Replace `#include <endian.h>` or `#include <libkern/OSByteOrder.h>` with `#include "platform/platform_api.h"`
2. Replace `htobe64` → `brix_plat_htobe64`
3. Replace `be64toh` → `brix_plat_be64toh`
4. Replace `htobe32` → `brix_plat_htobe32`
5. Replace `be32toh` → `brix_plat_be32toh`
6. Replace `htobe16` → `brix_plat_htobe16`
7. Replace `be16toh` → `brix_plat_be16toh`
8. Remove local `#define` macros for byte-order functions

---

### Pattern 2: Anonymous File Descriptors

**Before** (❌):
```c
#if defined(__linux__)
    int fd = memfd_create("temp", MFD_CLOEXEC);
#elif defined(__APPLE__)
    char template[] = "/tmp/brix_XXXXXX";
    int fd = mkstemp(template);
    unlink(template);
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

int fd = brix_plat_anon_fd("temp", NULL);
```

**Migration Steps**:
1. Identify all `memfd_create()`, `mkstemp()+unlink()`, or `O_TMPFILE` usage
2. Replace with `brix_plat_anon_fd(name, dir)`
3. Pass `NULL` for `dir` parameter to use default temp directory
4. Remove platform-specific `#ifdef` blocks

---

### Pattern 3: Extended Attributes

**Before** (❌):
```c
#if defined(__APPLE__) && defined(__MACH__)
    ssize_t n = getxattr(path, name, value, size, 0, 0);
#else
    ssize_t n = getxattr(path, name, value, size);
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

ssize_t n = brix_plat_getxattr(path, name, value, size);
```

**Migration Steps**:
1. Replace `getxattr()` → `brix_plat_getxattr()`
2. Replace `setxattr()` → `brix_plat_setxattr()`
3. Replace `removexattr()` → `brix_plat_removexattr()`
4. Replace `listxattr()` → `brix_plat_listxattr()`
5. Replace `fgetxattr()` → `brix_plat_fgetxattr()`
6. Replace `fsetxattr()` → `brix_plat_fsetxattr()`
7. Replace `fremovexattr()` → `brix_plat_fremovexattr()`
8. Replace `flistxattr()` → `brix_plat_flistxattr()`
9. Remove extra parameters (macOS 6-param signature handled by PAL)

---

### Pattern 4: Random Number Generation

**Before** (❌):
```c
#if defined(__linux__)
    ssize_t n = getrandom(buf, len, 0);
#elif defined(__APPLE__)
    SecRandomCopyBytes(kSecRandomDefault, len, (uint8_t *)buf);
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

int ret = brix_plat_random(buf, len);
if (ret < 0) {
    /* Handle error */
}
```

**Migration Steps**:
1. Replace `getrandom()` or `SecRandomCopyBytes()` with `brix_plat_random()`
2. Note: PAL returns `0` on success, `-1` on error (check return value!)
3. Remove platform-specific includes (`<sys/random.h>`, `<Security/Security.h>`)

---

### Pattern 5: File System Watching

**Before** (❌):
```c
#if defined(__linux__)
    int fd = inotify_init1(IN_CLOEXEC);
    inotify_add_watch(fd, path, IN_MODIFY | IN_DELETE);
#elif defined(__APPLE__)
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD, NOTE_DELETE | NOTE_WRITE, 0, NULL);
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

brix_plat_fs_watcher_t watcher;
brix_plat_fs_watcher_init(&watcher);
brix_plat_fs_watcher_add(&watcher, path, BRIX_FS_EVENT_DELETE | BRIX_FS_EVENT_WRITE);

brix_plat_fs_event_t event;
if (brix_plat_fs_watcher_next(&watcher, &event, 1000) == 0) {
    /* Handle event */
}
```

**Migration Steps**:
1. Replace `inotify_init1()` with `brix_plat_fs_watcher_init()`
2. Replace `inotify_add_watch()` with `brix_plat_fs_watcher_add()`
3. Replace `inotify_rm_watch()` with `brix_plat_fs_watcher_rm()`
4. Replace manual event reading with `brix_plat_fs_watcher_next()`
5. Replace `inotify_close()` with `brix_plat_fs_watcher_destroy()`
6. Update event constants: `IN_MODIFY` → `BRIX_FS_EVENT_WRITE`, etc.

---

### Pattern 6: Pipe Creation with Flags

**Before** (❌):
```c
#if defined(__linux__)
    pipe2(pipefd, O_CLOEXEC | O_NONBLOCK);
#elif defined(__APPLE__)
    pipe(pipefd);
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

brix_plat_pipe2(pipefd, BRIX_PIPE_CLOEXEC | BRIX_PIPE_NONBLOCK);
```

**Migration Steps**:
1. Replace `pipe2()` or `pipe()+fcntl()` with `brix_plat_pipe2()`
2. Replace `O_CLOEXEC` → `BRIX_PIPE_CLOEXEC`
3. Replace `O_NONBLOCK` → `BRIX_PIPE_NONBLOCK`

---

### Pattern 7: Event File Descriptors

**Before** (❌):
```c
#if defined(__linux__)
    int efd = eventfd(0, EFD_CLOEXEC);
#elif defined(__APPLE__)
    int pipefd[2];
    pipe(pipefd);
    int efd = pipefd[0];  /* Read end */
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

int efd = brix_plat_eventfd(0, BRIX_EVENTFD_CLOEXEC);
```

**Migration Steps**:
1. Replace `eventfd()` or pipe-based emulation with `brix_plat_eventfd()`
2. Replace `EFD_CLOEXEC` → `BRIX_EVENTFD_CLOEXEC`
3. Replace `EFD_NONBLOCK` → `BRIX_EVENTFD_NONBLOCK`

---

### Pattern 8: Sendfile

**Before** (❌):
```c
#if defined(__linux__)
    ssize_t n = sendfile(out_fd, in_fd, &offset, count);
#elif defined(__APPLE__)
    off_t sbytes = offset;
    int ret = sendfile(in_fd, out_fd, sbytes, &sbytes, NULL, 0);
    offset += sbytes;
    ssize_t n = (ret == 0) ? sbytes : -1;
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

ssize_t n = brix_plat_sendfile(out_fd, in_fd, &offset, count);
```

**Migration Steps**:
1. Replace `sendfile()` calls with `brix_plat_sendfile()`
2. PAL handles signature differences (Linux vs macOS parameter order)
3. Offset update handled automatically

---

### Pattern 9: Process Execution

**Before** (❌):
```c
#if defined(__linux__)
    execvpe(file, argv, envp);
#elif defined(__APPLE__)
    posix_spawn(&pid, file, NULL, NULL, argv, envp);
    waitpid(pid, &status, 0);
    _exit(WEXITSTATUS(status));
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

brix_plat_execvpe(file, argv, envp);
```

**Migration Steps**:
1. Replace `execvpe()` or `posix_spawn()+waitpid()` with `brix_plat_execvpe()`
2. PAL handles PATH search and environment inheritance

---

### Pattern 10: Security/Confinement

**Before** (❌):
```c
#if defined(__linux__)
    setfsuid(uid);
    setfsgid(gid);
    /* seccomp profile loading */
#elif defined(__APPLE__)
    seteuid(uid);  /* Affects both real and effective */
    setegid(gid);
    /* No seccomp equivalent */
#endif
```

**After** (✅):
```c
#include "platform/platform_api.h"

brix_plat_setfsuid(uid);
brix_plat_setfsgid(gid);
brix_plat_security_init("default");
```

**Migration Steps**:
1. Replace `setfsuid()` → `brix_plat_setfsuid()`
2. Replace `setfsgid()` → `brix_plat_setfsgid()`
3. Replace seccomp/sandbox code with `brix_plat_security_init()` and `brix_plat_security_enter()`

---

## Testing Strategy

### Unit Tests

Create tests in `tests/platform/` for each PAL function:

```python
# tests/platform/test_pal_api.py

import pytest
import os
import tempfile

def test_brix_plat_anon_fd():
    """Test anonymous file descriptor creation"""
    fd = brix_plat_anon_fd("test", None)
    assert fd >= 0
    
    # Verify file is anonymous (deleted on close)
    stat_before = os.fstat(fd)
    os.close(fd)
    
    # File should be gone
    with pytest.raises(OSError):
        os.fstat(fd)

def test_brix_plat_random():
    """Test cryptographically secure random generation"""
    buf = bytearray(32)
    ret = brix_plat_random(buf, len(buf))
    assert ret == 0
    
    # Verify buffer changed from zero
    assert buf != bytearray(32)
    
    # Verify uniqueness
    buf2 = bytearray(32)
    brix_plat_random(buf2, len(buf2))
    assert buf != buf2

def test_brix_plat_byte_order():
    """Test byte-order conversion"""
    val = 0x123456789ABCDEF0
    
    be = brix_plat_htobe64(val)
    assert brix_plat_be64toh(be) == val
    
    # Test round-trip
    assert brix_plat_be64toh(brix_plat_htobe64(val)) == val

def test_brix_plat_getxattr():
    """Test extended attribute operations"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    
    try:
        # Set attribute
        ret = brix_plat_setxattr(path, "user.test", b"hello", 5, 0)
        assert ret == 0
        
        # Get attribute
        buf = bytearray(100)
        n = brix_plat_getxattr(path, "user.test", buf, len(buf))
        assert n == 5
        assert buf[:5] == b"hello"
        
        # Remove attribute
        ret = brix_plat_removexattr(path, "user.test")
        assert ret == 0
    finally:
        os.unlink(path)
```

### Integration Tests

Test PAL functions in real scenarios:

```python
# tests/platform/test_integration.py

def test_origin_protocol_with_pal():
    """Test origin protocol uses PAL correctly"""
    # This tests that origin_protocol.c uses brix_plat_htobe64
    # instead of direct htobe64 calls
    pass

def test_cache_fill_with_pal():
    """Test cache fill path uses PAL for xattr"""
    # Verify xattr operations use brix_plat_getxattr
    pass
```

### Platform-Specific Tests

Run tests on each platform:

```bash
# Linux
cd /tmp/nginx-1.28.3
PYTHONPATH=tests pytest tests/platform/ -v

# macOS
cd /tmp/nginx-1.28.3
PYTHONPATH=tests pytest tests/platform/ -v

# Windows (future)
pytest tests/platform/ -v
```

### Automated Grep Tests

Verify no `#ifdef` remains in business code:

```bash
# tests/platform/check_no_ifdef.sh
#!/bin/bash

# Check for forbidden patterns in src/ (excluding src/platform/)
if grep -r "#if defined(__linux__)" src/ --include="*.c" --include="*.h" \
    --exclude-dir=platform; then
    echo "ERROR: Found platform-specific #ifdef in business code"
    exit 1
fi

if grep -r "#if defined(__APPLE__)" src/ --include="*.c" --include="*.h" \
    --exclude-dir=platform; then
    echo "ERROR: Found platform-specific #ifdef in business code"
    exit 1
fi

echo "✓ No platform-specific #ifdef found in business code"
exit 0
```

---

## Rollback Procedure

If migration causes issues, follow this rollback procedure:

### Step 1: Identify Problematic Files

```bash
# Check git status for modified files
git status

# View diff for specific file
git diff src/fs/cache/origin_protocol.c
```

### Step 2: Revert Individual Files

```bash
# Revert single file
git checkout HEAD -- src/fs/cache/origin_protocol.c

# Revert all migration changes
git checkout HEAD -- src/
```

### Step 3: Restore Build

```bash
# Clean build artifacts
cd /tmp/nginx-1.28.3
make clean

# Reconfigure
./configure --add-module=/Users/rcurrie/src/brix-cache

# Rebuild
make
```

### Step 4: Test Rollback

```bash
# Verify binary works
objs/nginx -t

# Run tests
PYTHONPATH=tests pytest tests/ -v
```

### Step 5: Document Issue

Create incident report in `docs/incidents/`:

```markdown
# Incident: PAL Migration Issue

**Date**: YYYY-MM-DD  
**Files Affected**: src/fs/cache/origin_protocol.c  
**Issue**: brix_plat_htobe64 not declared  
**Root Cause**: Missing #include "platform/platform_api.h"  
**Resolution**: Added include, updated migration guide
```

---

## Common Pitfalls

### Pitfall 1: Missing Include

**Symptom**: `error: call to undeclared function 'brix_plat_htobe64'`

**Cause**: Forgot to add `#include "platform/platform_api.h"`

**Fix**:
```c
/* Add at top of file */
#include "platform/platform_api.h"
```

**Prevention**: Always add include before using PAL functions

---

### Pitfall 2: Partial Migration

**Symptom**: Mix of `htobe64` and `brix_plat_htobe64` in same file

**Cause**: Incomplete search-and-replace

**Fix**:
```bash
# Find all occurrences
grep -n "htobe64\|be64toh" src/file.c

# Replace all
sed -i.bak 's/\bhtobe64\b/brix_plat_htobe64/g' src/file.c
sed -i.bak 's/\bbe64toh\b/brix_plat_be64toh/g' src/file.c
```

**Prevention**: Use comprehensive grep before committing

---

### Pitfall 3: Old Macro Definitions Remain

**Symptom**: `warning: "htobe64" redefined`

**Cause**: Old `#define htobe64` macros not removed

**Fix**:
```bash
# Remove old macros
sed -i.bak '/#define htobe64/d' src/file.c
sed -i.bak '/#define be64toh/d' src/file.c
sed -i.bak '/#include <endian.h>/d' src/file.c
sed -i.bak '/#include <libkern\/OSByteOrder.h>/d' src/file.c
```

**Prevention**: Automated cleanup script

---

### Pitfall 4: Incorrect Return Value Handling

**Symptom**: Random data not working, or always zero

**Cause**: PAL `brix_plat_random()` returns `0` on success (unlike `getrandom()`)

**Fix**:
```c
/* WRONG */
ssize_t n = brix_plat_random(buf, len);
if (n < 0) { /* ... */ }

/* CORRECT */
int ret = brix_plat_random(buf, len);
if (ret != 0) { /* ... */ }
```

**Prevention**: Read function documentation carefully

---

### Pitfall 5: File Descriptor Leaks

**Symptom**: "Too many open files" error

**Cause**: `brix_plat_anon_fd()` returns fd that must be closed

**Fix**:
```c
int fd = brix_plat_anon_fd("temp", NULL);
if (fd < 0) {
    /* Handle error */
}

/* Use fd... */

close(fd);  /* Don't forget! */
```

**Prevention**: Use RAII patterns or goto cleanup

---

### Pitfall 6: Event Constants Confusion

**Symptom**: Wrong events triggered in file watcher

**Cause**: Mixing `IN_MODIFY` (inotify) with `BRIX_FS_EVENT_WRITE` (PAL)

**Fix**:
```c
/* WRONG */
brix_plat_fs_watcher_add(&watcher, path, IN_MODIFY);

/* CORRECT */
brix_plat_fs_watcher_add(&watcher, path, BRIX_FS_EVENT_WRITE);
```

**PAL Event Constants**:
- `BRIX_FS_EVENT_DELETE` - File deleted
- `BRIX_FS_EVENT_WRITE` - File modified (was `IN_MODIFY`)
- `BRIX_FS_EVENT_CREATE` - File created
- `BRIX_FS_EVENT_RENAME` - File renamed (was `IN_MOVED_FROM` + `IN_MOVED_TO`)
- `BRIX_FS_EVENT_ATTRIB` - Metadata changed

---

### Pitfall 7: Build Configuration Not Updated

**Symptom**: Linker errors for PAL functions

**Cause**: Platform wrapper files not added to build

**Fix**: Update `config` script:

```bash
# Add to config script
PAL_SRCS="$ngx_addon_dir/src/platform/linux/posix_wrapper.c \
          $ngx_addon_dir/src/platform/linux/event_wrapper.c \
          ..."
```

**Prevention**: Follow platform file structure

---

## Automated Migration Script

Use this script to automate common migrations:

```bash
#!/bin/bash
# migrate_to_pal.sh - Automated #ifdef to PAL migration

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <file.c> [file2.c ...]"
    exit 1
fi

for file in "$@"; do
    echo "Migrating $file..."
    
    # Backup original
    cp "$file" "$file.bak"
    
    # Add include if not present
    if ! grep -q "platform_api.h" "$file"; then
        sed -i.bak '1i #include "platform/platform_api.h"' "$file"
    fi
    
    # Replace byte-order functions
    sed -i.bak 's/\bhtobe64\b/brix_plat_htobe64/g' "$file"
    sed -i.bak 's/\bbe64toh\b/brix_plat_be64toh/g' "$file"
    sed -i.bak 's/\bhtobe32\b/brix_plat_htobe32/g' "$file"
    sed -i.bak 's/\bbe32toh\b/brix_plat_be32toh/g' "$file"
    sed -i.bak 's/\bhtobe16\b/brix_plat_htobe16/g' "$file"
    sed -i.bak 's/\bbe16toh\b/brix_plat_be16toh/g' "$file"
    
    # Remove old includes
    sed -i.bak '/#include <endian.h>/d' "$file"
    sed -i.bak '/#include <libkern\/OSByteOrder.h>/d' "$file"
    
    # Remove old macros
    sed -i.bak '/#define htobe64/d' "$file"
    sed -i.bak '/#define be64toh/d' "$file"
    
    # Replace xattr functions
    sed -i.bak 's/\bgetxattr(\([^,]*\), \([^,]*\), \([^,]*\), \([^)]*\), 0, 0)/brix_plat_getxattr(\1, \2, \3, \4)/g' "$file"
    
    echo "  ✓ Migrated $file"
    
    # Remove backup if successful
    rm -f "$file.bak"
done

echo "Migration complete!"
```

---

## Checklist

Before committing migration changes:

- [ ] All `#ifdef __linux__` blocks removed from business code
- [ ] All `#ifdef __APPLE__` blocks removed from business code
- [ ] `#include "platform/platform_api.h"` added to all migrated files
- [ ] All byte-order functions replaced with `brix_plat_*` variants
- [ ] Old `#define htobe64` macros removed
- [ ] Old `<endian.h>` and `<libkern/OSByteOrder.h>` includes removed
- [ ] Return value handling updated (especially for `brix_plat_random()`)
- [ ] File descriptor cleanup verified (no leaks)
- [ ] Event constants updated to `BRIX_FS_EVENT_*`
- [ ] Code compiles without warnings
- [ ] Tests pass on target platform
- [ ] No regression on other platforms

---

## Resources

- **PAL API Reference**: `src/platform/platform_api.h`
- **Architecture Guide**: `docs/platform/pal/ARCHITECTURE.md`
- **Platform Expansion Plan**: `docs/platform/PLATFORM_EXPANSION_PLAN.md`
- **Migration Issues**: `docs/incidents/`

---

**End of Migration Guide**
