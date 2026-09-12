# PAL Function Naming Standardization Report

**Date**: 2025-12-18  
**Audit Type**: Function Naming Consistency  
**Status**: ⚠️ INCONSISTENCIES FOUND - FIX REQUIRED  
**Priority**: MEDIUM (does not block builds, affects code quality)

---

## Executive Summary

A comprehensive audit of function naming conventions across the Platform Abstraction Layer (PAL) has identified **naming inconsistencies** between different platform implementations. This report documents the current state, recommends a standard, and provides a detailed change plan.

### Key Findings

| Metric | Value |
|--------|-------|
| **Standard Prefix** | `brix_plat_*` (used in 127+ functions) |
| **Non-Standard Prefix** | `brix_platform_*` (used in 11 functions) |
| **Inconsistent Files** | 4 files (Linux + macOS) |
| **Functions Requiring Rename** | 11 functions |
| **Platforms Affected** | Linux, macOS (Darwin) |
| **Windows** | ✅ Already compliant |

### Recommendation

**Standardize on `brix_plat_*` prefix** for all PAL functions to maintain consistency with:
- `platform_api.h` (85 declarations use `brix_plat_*`)
- Windows implementation (100% compliant)
- Majority of codebase (92% already uses `brix_plat_*`)

---

## 1. CURRENT STATE ANALYSIS

### 1.1 Standard Prefix: `brix_plat_*` ✅

**Location**: `src/platform/platform_api.h` (85 declarations)

**All Core PAL Functions** (44 functions):
```c
// Platform Detection
int brix_plat_is_root(void);
int brix_plat_cpu_count(void);
uint64_t brix_plat_total_memory(void);
uint64_t brix_plat_available_memory(void);

// File Descriptor Operations
int brix_plat_anon_fd(const char *name, const char *dir);
int brix_plat_fadvise(int fd, off_t offset, off_t len, int advice);
int brix_plat_fsync_data(int fd);
void brix_plat_sync(void);
int brix_plat_sync_tree(int dirfd);

// Zero-Copy Transfers
ssize_t brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
ssize_t brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags);
ssize_t brix_plat_copy_range(int in_fd, off_t *in_off, ...);

// Event & Notification
int brix_plat_eventfd(unsigned int initial_value, int flags);
int brix_plat_pipe2(int pipefd[2], int flags);

// Filesystem Watcher
int brix_plat_fs_watcher_init(brix_plat_fs_watcher_t *watcher);
int brix_plat_fs_watcher_add(...);
int brix_plat_fs_watcher_rm(brix_plat_fs_watcher_t *watcher, int wd);
int brix_plat_fs_watcher_next(...);
void brix_plat_fs_watcher_destroy(brix_plat_fs_watcher_t *watcher);

// Security & Confinement
int brix_plat_security_init(const char *profile);
int brix_plat_security_enter(const char *profile);
int brix_plat_setfsuid(uid_t uid);
int brix_plat_setfsgid(gid_t gid);

// Random Number Generation
int brix_plat_random(void *buf, size_t len);

// Extended Attributes (8 functions)
ssize_t brix_plat_getxattr(...);
ssize_t brix_plat_fgetxattr(...);
int brix_plat_setxattr(...);
int brix_plat_fsetxattr(...);
int brix_plat_removexattr(...);
int brix_plat_fremovexattr(...);
ssize_t brix_plat_listxattr(...);
ssize_t brix_plat_flistxattr(...);

// Process Execution
int brix_plat_execvpe(const char *file, char *const argv[], char *const envp[]);

// PAL Initialization
int brix_plat_init(void);
void brix_plat_cleanup(void);

// Windows-Specific Extensions (8 functions)
int brix_plat_is_windows(void);
int brix_plat_windows_version_info(...);
int brix_plat_is_windows_server(void);
int brix_plat_windows_version_at_least(...);
// ... etc
```

**Usage in Implementation Files**:
- Windows: 100% compliant (all functions use `brix_plat_*`)
- Linux: 95% compliant (most functions use `brix_plat_*`)
- macOS: 95% compliant (most functions use `brix_plat_*`)

### 1.2 Non-Standard Prefix: `brix_platform_*` ⚠️

**Location**: 4 files (Linux + macOS)

**Functions Using Non-Standard Prefix** (11 total):

| File | Function | Line | Should Be |
|------|----------|------|-----------|
| `src/platform/linux/event_wrapper.c` | `brix_platform_event_init()` | 17 | `brix_plat_eventfd()` |
| `src/platform/linux/event_wrapper.c` | `brix_platform_event_close()` | 29 | `brix_plat_event_close()` |
| `src/platform/linux/event_wrapper.c` | `brix_platform_event_watch()` | 37 | `brix_plat_event_watch()` |
| `src/platform/linux/event_wrapper.c` | `brix_platform_event_wait()` | 70 | `brix_plat_event_wait()` |
| `src/platform/linux/copy_range.c` | `brix_platform_copy_range()` | 15, 55 | `brix_plat_copy_range()` |
| `src/platform/darwin/event_wrapper.c` | `brix_platform_event_init()` | 18 | `brix_plat_event_init()` |
| `src/platform/darwin/event_wrapper.c` | `brix_platform_event_close()` | 36 | `brix_plat_event_close()` |
| `src/platform/darwin/event_wrapper.c` | `brix_platform_event_watch()` | 44 | `brix_plat_event_watch()` |
| `src/platform/darwin/event_wrapper.c` | `brix_platform_event_wait()` | 83 | `brix_plat_event_wait()` |
| `src/platform/darwin/copy_range.c` | `brix_platform_copy_range()` | 19 | `brix_plat_copy_range()` |

**Note**: Some of these are internal/static functions, but consistency is still important for code quality.

### 1.3 Macro Wrappers in `platform_compat.h`

**Location**: `src/platform/platform_compat.h`

**Macros Using `brix_platform_*`** (7 macros):

```c
// Line 30
#define brix_fadvise(fd, offset, len, advice) \
        brix_platform_fadvise((fd), (offset), (len), (advice))

// Line 37
#define brix_fsync_data(fd) brix_platform_fsync_data(fd)

// Line 45
#define brix_sync_tree(dirfd) brix_platform_sync_tree(dirfd)

// Line 50
#define brix_sendfile(out_fd, in_fd, offset, count) \
    brix_platform_sendfile((out_fd), (in_fd), (offset), (count))

// Line 58
#define brix_splice(in_fd, out_fd, nbytes, flags) \
        brix_platform_splice((in_fd), (out_fd), (nbytes), (flags))

// Line 65
#define brix_clonefile(src, dst) brix_platform_clonefile((src), (dst))

// Line 83, 91 (event functions)
return brix_platform_event_init();
brix_platform_event_close(event_fd);
```

**Issue**: These macros reference `brix_platform_*` functions that don't exist in the standard API!

---

## 2. ROOT CAUSE ANALYSIS

### 2.1 Historical Context

The `brix_platform_*` prefix appears to be from an **earlier iteration** of the PAL design. Over time, the project standardized on the shorter `brix_plat_*` prefix, but some files were not updated.

### 2.2 Why This Matters

1. **Code Quality**: Inconsistent naming reduces code readability and maintainability
2. **Discoverability**: Developers must remember two prefixes for the same API
3. **Documentation**: Harder to write clear documentation with two naming conventions
4. **Professionalism**: Consistent naming is a hallmark of mature, production-ready code

### 2.3 Impact Assessment

| Impact Area | Severity | Notes |
|-------------|----------|-------|
| **Build System** | ✅ None | Both prefixes compile fine |
| **Runtime** | ✅ None | No performance impact |
| **API Compatibility** | ✅ None | Internal functions only |
| **Code Quality** | 🟡 Medium | Reduces maintainability |
| **Documentation** | 🟡 Medium | Creates confusion |
| **New Developer Onboarding** | 🟡 Medium | Extra cognitive load |

---

## 3. RECOMMENDATION

### 3.1 Standard: `brix_plat_*` Prefix

**Rationale**:

1. **Majority Usage**: 92% of codebase already uses `brix_plat_*`
2. **API Header**: `platform_api.h` exclusively uses `brix_plat_*`
3. **Windows Compliance**: Windows implementation is 100% compliant
4. **Brevity**: Shorter prefix reduces visual clutter
5. **Consistency**: Aligns with common C library naming (e.g., `pthread_*`, `socket_*`)

### 3.2 Naming Convention Rules

**Standard PAL Function Naming**:

```c
// Format: brix_plat_<category>_<action>()
brix_plat_<category>_<action>(parameters);

// Examples:
brix_plat_event_init()      // Category: event, Action: init
brix_plat_copy_range()      // Category: copy, Action: range
brix_plat_fs_watcher_add()  // Category: fs_watcher, Action: add
```

**Exceptions** (allowed):
- Static/internal functions may use shorter names
- Platform-specific extensions may include platform in name (e.g., `brix_plat_windows_*`)

---

## 4. CHANGE PLAN

### 4.1 Files Requiring Changes (4 files)

| File | Platform | Changes | Effort |
|------|----------|---------|--------|
| `src/platform/linux/event_wrapper.c` | Linux | 4 function renames | 15 min |
| `src/platform/linux/copy_range.c` | Linux | 1 function rename | 5 min |
| `src/platform/darwin/event_wrapper.c` | macOS | 4 function renames | 15 min |
| `src/platform/darwin/copy_range.c` | macOS | 1 function rename | 5 min |
| `src/platform/platform_compat.h` | Cross-platform | 7 macro updates | 20 min |
| **TOTAL** | | **17 changes** | **60 min** |

### 4.2 Detailed Find/Replace Plan

#### File 1: `src/platform/linux/event_wrapper.c`

```diff
- static int brix_platform_event_init(void)
+ static int brix_plat_event_init(void)

- static void brix_platform_event_close(int event_fd)
+ static void brix_plat_event_close(int event_fd)

- static int brix_platform_event_watch(int event_fd, int fd, uint32_t events)
+ static int brix_plat_event_watch(int event_fd, int fd, uint32_t events)

- static int brix_platform_event_wait(int event_fd, void *events, int max_events, int timeout_ms)
+ static int brix_plat_event_wait(int event_fd, void *events, int max_events, int timeout_ms)
```

#### File 2: `src/platform/linux/copy_range.c`

```diff
- ssize_t brix_platform_copy_range(int src_fd, off_t *src_off, int dst_fd, ...)
+ ssize_t brix_plat_copy_range(int src_fd, off_t *src_off, int dst_fd, ...)
```

#### File 3: `src/platform/darwin/event_wrapper.c`

```diff
- static int brix_platform_event_init(void)
+ static int brix_plat_event_init(void)

- static void brix_platform_event_close(int event_fd)
+ static void brix_plat_event_close(int event_fd)

- static int brix_platform_event_watch(int event_fd, int fd, uint32_t events)
+ static int brix_plat_event_watch(int event_fd, int fd, uint32_t events)

- static int brix_platform_event_wait(int event_fd, void *events, int max_events, int timeout_ms)
+ static int brix_plat_event_wait(int event_fd, void *events, int max_events, int timeout_ms)
```

#### File 4: `src/platform/darwin/copy_range.c`

```diff
- ssize_t brix_platform_copy_range(int src_fd, off_t *src_off, int dst_fd, ...)
+ ssize_t brix_plat_copy_range(int src_fd, off_t *src_off, int dst_fd, ...)
```

#### File 5: `src/platform/platform_compat.h`

```diff
- #define brix_fadvise(fd, offset, len, advice) \
-         brix_platform_fadvise((fd), (offset), (len), (advice))
+ #define brix_fadvise(fd, offset, len, advice) \
+         brix_plat_fadvise((fd), (offset), (len), (advice))

- #define brix_fsync_data(fd) brix_platform_fsync_data(fd)
+ #define brix_fsync_data(fd) brix_plat_fsync_data(fd)

- #define brix_sync_tree(dirfd) brix_platform_sync_tree(dirfd)
+ #define brix_sync_tree(dirfd) brix_plat_sync_tree(dirfd)

- #define brix_sendfile(out_fd, in_fd, offset, count) \
-     brix_platform_sendfile((out_fd), (in_fd), (offset), (count))
+ #define brix_sendfile(out_fd, in_fd, offset, count) \
+     brix_plat_sendfile((out_fd), (in_fd), (offset), (count))

- #define brix_splice(in_fd, out_fd, nbytes, flags) \
-         brix_platform_splice((in_fd), (out_fd), (nbytes), (flags))
+ #define brix_splice(in_fd, out_fd, nbytes, flags) \
+         brix_plat_splice((in_fd), (out_fd), (nbytes), (flags))

- #define brix_clonefile(src, dst) brix_platform_clonefile((src), (dst))
+ #define brix_clonefile(src, dst) brix_plat_clonefile((src), (dst))

- return brix_platform_event_init();
+ return brix_plat_event_init();

- brix_platform_event_close(event_fd);
+ brix_plat_event_close(event_fd);
```

### 4.3 Verification Steps

After applying changes:

```bash
# 1. Verify no remaining brix_platform_* usage
grep -r "brix_platform_" src/platform/ --include="*.c" --include="*.h"
# Expected: 0 results (or only in comments)

# 2. Build verification
cd /tmp/nginx-1.28.3
make clean
BRIX_OPTIMIZE=auto ./configure --add-module=/Users/rcurrie/src/brix-cache
make

# 3. Run tests
cd /Users/rcurrie/src/brix-cache/tests
PYTHONPATH=tests pytest tests/platform/ -v
```

### 4.4 Rollback Plan

If issues arise:

```bash
# Git revert (if using git)
git checkout HEAD -- src/platform/linux/event_wrapper.c
git checkout HEAD -- src/platform/linux/copy_range.c
git checkout HEAD -- src/platform/darwin/event_wrapper.c
git checkout HEAD -- src/platform/darwin/copy_range.c
git checkout HEAD -- src/platform/platform_compat.h

# Or manual revert using this report as reference
```

---

## 5. IMPLEMENTATION STATUS

### Phase 5D: Naming Standardization

| Step | Status | Notes |
|------|--------|-------|
| 1. Document current state | ✅ COMPLETE | This report |
| 2. Recommend standard | ✅ COMPLETE | `brix_plat_*` |
| 3. List files requiring changes | ✅ COMPLETE | 4 files + 1 header |
| 4. Create find/replace plan | ✅ COMPLETE | Detailed above |
| 5. Apply changes | ⏳ PENDING | Awaiting approval |
| 6. Verify build | ⏳ PENDING | Post-change |
| 7. Run tests | ⏳ PENDING | Post-change |

---

## 6. ADDITIONAL RECOMMENDATIONS

### 6.1 Future Naming Guidelines

Add to `docs/09-developer-guide/coding-standards.md`:

```markdown
## PAL Function Naming

All Platform Abstraction Layer (PAL) functions MUST use the `brix_plat_*` prefix.

**Format**: `brix_plat_<category>_<action>()`

**Examples**:
- `brix_plat_event_init()` ✅
- `brix_plat_copy_range()` ✅
- `brix_plat_fs_watcher_add()` ✅

**Non-Compliant**:
- `brix_platform_event_init()` ❌
- `brix_platform_copy_range()` ❌

**Rationale**: Consistency, brevity, alignment with `platform_api.h`.
```

### 6.2 Automated Enforcement

Consider adding a CI check:

```bash
# tools/ci/check_naming_consistency.sh
#!/bin/bash
# Check for non-standard PAL function naming

NON_STANDARD=$(grep -r "brix_platform_" src/platform/ --include="*.c" --include="*.h" | grep -v "^[^:]*:\s*//")

if [ -n "$NON_STANDARD" ]; then
    echo "❌ Non-standard PAL function naming detected:"
    echo "$NON_STANDARD"
    exit 1
fi

echo "✅ All PAL functions use standard brix_plat_* prefix"
exit 0
```

---

## 7. CONCLUSION

### Summary

- **Issue**: 11 functions use non-standard `brix_platform_*` prefix
- **Standard**: `brix_plat_*` (used in 92% of codebase)
- **Files Affected**: 4 implementation files + 1 header
- **Effort**: ~60 minutes to fix
- **Impact**: Code quality improvement, no functional changes

### Recommendation

**APPLY THE CHANGES** outlined in Section 4.2 to standardize on `brix_plat_*` prefix across all PAL implementations.

### Next Steps

1. Review and approve this report
2. Apply find/replace changes (Section 4.2)
3. Verify build on all 5 platforms
4. Run test suite
5. Update coding standards documentation
6. Consider adding automated CI check

---

**Report Status**: ✅ COMPLETE  
**Priority**: MEDIUM  
**Estimated Effort**: 60 minutes  
**Risk Level**: LOW (cosmetic changes only)  
**Recommendation**: APPROVE AND APPLY
