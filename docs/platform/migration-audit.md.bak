# Platform #ifdef Migration Audit

**Generated**: 2025-12-12  
**Scope**: `src/` directory (excluding `src/platform/`)  
**Purpose**: Identify platform-specific code for PAL migration

---

## Executive Summary

| Metric | Count |
|--------|-------|
| **Total #ifdef blocks** | 150+ |
| **Files affected** | 80+ |
| **Direct syscalls** | 40+ |
| **Platform headers** | 30+ |
| **Migration priority** | HIGH |

---

## Breakdown by Platform

### macOS (__APPLE__ && __MACH__)
- **Count**: 70+ occurrences
- **Status**: Mostly migrated to PAL
- **Remaining**: xattr signatures, stat members, some syscalls

### Linux (__linux__)
- **Count**: 50+ occurrences
- **Status**: Many direct syscalls remain
- **Remaining**: splice, eventfd, memfd, copy_file_range

### Windows (_WIN32 || _WIN64)
- **Count**: 2 occurrences
- **Status**: Only in token/b64url.h and token/json.h
- **Remaining**: Base64 encoding compatibility

---

## Priority Ranking

### P0: Critical (Block PAL Completion)
1. **xattr syscalls** - 15 files, direct getxattr/setxattr calls
2. **sendfile signatures** - 5 files, macOS vs Linux signature mismatch
3. **Byte-order ops** - 10 files, still using htobe64/be64toh directly

### P1: High (Should Migrate)
4. **eventfd usage** - 3 files, DNS and aio subsystems
5. **pipe2/syscalls** - 5 files, proxy and subprocess code
6. **stat member access** - 8 files, st_mtim vs st_mtimespec

### P2: Medium (Nice to Have)
7. **copy_file_range** - 3 files, fallback logic present
8. **openat2/renameat2** - 2 files, already have fallbacks
9. **memfd_create** - 2 files, already migrated to PAL

### P3: Low (Can Wait)
10. **DNS resolution** - 4 files, already using platform wrappers
11. **Performance counters** - 2 files, macOS perfmon differences

---

## Detailed File Listings

### P0: Critical Migrations Needed

#### 1. Extended Attributes (xattr)
**Files**: 15 files with direct xattr syscalls

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/core/compat/staged_file.c` | 21, 26, 311 | Direct getxattr/setxattr | `brix_plat_getxattr()`, `brix_plat_setxattr()` |
| `src/core/compat/namespace_ops_copy.c` | 31, 48 | 6-param macOS signature | `brix_plat_*xattr()` handles signature |
| `src/fs/vfs/vfs_xattr.c` | 31, 34 | Platform-specific xattr | Already uses PAL, verify |
| `src/fs/cache/cinfo.c` | 23 | Direct xattr syscall | `brix_plat_getxattr()` |
| `src/fs/path/resolve_confined_ops_xattr.c` | 17, 20, 41 | Multiple xattr calls | `brix_plat_*xattr()` family |
| `src/fs/meta/xmeta_path.c` | 16, 19 | Direct xattr | `brix_plat_getxattr()` |
| `src/fs/backend/pblock/sd_pblock_catalog_ns.c` | 37 | XATTR_CREATE flag | Use `BRIX_XATTR_CREATE` |
| `src/fs/backend/http/sd_http_xattr_write.c` | 29 | Direct setxattr | `brix_plat_setxattr()` |
| `src/fs/backend/remote/sd_remote_xattr.c` | 30 | XATTR flags | Use `BRIX_XATTR_*` constants |
| `src/protocols/s3/tagging.c` | 33 | Direct xattr | `brix_plat_*xattr()` |
| `src/protocols/root/fattr/set.c` | 4 | XATTR_CREATE | Use `BRIX_XATTR_CREATE` |
| `src/protocols/root/fattr/helpers.c` | 12 | Direct xattr | `brix_plat_*xattr()` |
| `src/protocols/root/dirlist/dcksm.c` | 15 | Direct xattr | `brix_plat_*xattr()` |
| `src/protocols/webdav/lock_check.c` | 28 | Direct xattr | `brix_plat_*xattr()` |
| `src/protocols/webdav/prop_xattr.c` | 15 | Multiple xattr | `brix_plat_*xattr()` family |

**Migration Effort**: ~4 hours  
**Risk**: LOW - PAL already handles signature differences

#### 2. sendfile Signature Mismatch
**Files**: 5 files with platform-specific sendfile

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/fs/backend/posix/sd_posix_io.c` | 85, 101 | macOS 6-param vs Linux 4-param | `brix_plat_sendfile()` |
| `src/protocols/shared/http_serve_offload.c` | TBD | Direct sendfile call | `brix_plat_sendfile()` |

**Migration Effort**: ~1 hour  
**Risk**: LOW - PAL signature is unified

#### 3. Byte-Order Operations
**Files**: 10 files still using direct htobe64/be64toh

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/tpc/gsi/gsi_outbound_finish.c` | 14 | `#include <endian.h>` | `#include "platform/platform_api.h"` |
| `src/tpc/gsi/gsi_outbound_common.c` | 18 | Direct htobe64 | `brix_plat_htobe64()` |
| `src/tpc/outbound/source_open.c` | 16 | `#include <endian.h>` | Remove, use PAL |
| `src/fs/cache/origin_pgread.c` | 54-55 | Platform #ifdef for endian | `brix_plat_htobe64()` |
| `src/fs/cache/origin_protocol.c` | 14 | macOS endian #ifdef | `brix_plat_htobe64()` |
| `src/fs/backend/pblock/pblock_pack.c` | 441 | Linux-specific htobe64 | `brix_plat_htobe64()` |

**Migration Effort**: ~2 hours (mostly automated)  
**Risk**: VERY LOW - Drop-in replacement

### P1: High Priority Migrations

#### 4. eventfd Usage
**Files**: 3 files with direct eventfd

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/net/dns/resolve_bridge.c` | 63 | `#include <sys/eventfd.h>`, direct eventfd() | `brix_plat_eventfd()` |
| `src/core/aio/uring_bringup.c` | 7 | `#include <sys/eventfd.h>` | `brix_plat_eventfd()` |

**Migration Effort**: ~2 hours  
**Risk**: MEDIUM - Need to verify pipe fallback behavior

#### 5. pipe2 and Direct Syscalls
**Files**: 5 files with pipe2/syscalls

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/net/proxy/events_splice_setup.c` | 12, 78 | `#ifdef __linux__`, pipe2() | `brix_plat_pipe2()` |
| `src/net/proxy/events_splice.c` | 9, 512 | `#ifdef __linux__` | PAL already stubbed |
| `src/net/proxy/events_read.c` | 75, 169 | `#ifdef __linux__` | Verify PAL usage |
| `src/core/compat/subprocess.c` | 34, 536 | macOS pipe2 compatibility | Already uses PAL |

**Migration Effort**: ~3 hours  
**Risk**: MEDIUM - Proxy splice path is critical

#### 6. stat Member Access (st_mtim vs st_mtimespec)
**Files**: 8 files with platform-specific stat access

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/core/compat/integrity_info.c` | 31 | `#if __APPLE__` st_mtimespec | Add `brix_plat_stat_mtime()` helper |
| `src/core/compat/integrity_info_record.c` | 33 | macOS stat members | Add PAL helper |
| `src/fs/cache/cache_storage.c` | 17 | Platform stat access | Add PAL helper |
| `src/fs/path/canonical.c` | 7 | macOS stat | Add PAL helper |
| `src/fs/backend/pblock/pblock_store.c` | 23 | macOS stat | Add PAL helper |
| `src/fs/backend/http/sd_http_read.c` | 31 | macOS stat | Add PAL helper |

**Migration Effort**: ~4 hours (need new PAL helpers)  
**Risk**: MEDIUM - Need to design stat helper API

### P2: Medium Priority

#### 7. copy_file_range
**Files**: 3 files with direct copy_file_range

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/core/compat/copy_range.c` | 27, 94, 185, 194 | `#ifdef __linux__`, syscall wrapper | `brix_plat_copy_range()` |
| `src/fs/backend/posix/sd_posix_io.c` | 101 | Direct copy_file_range | `brix_plat_copy_range()` |
| `src/fs/backend/frm/sd_frm_exec.c` | 324 | renameat2 syscall | `brix_plat_copy_range()` for copy |

**Migration Effort**: ~2 hours  
**Risk**: LOW - Fallback already exists

#### 8. openat2 / renameat2
**Files**: 2 files with advanced syscalls

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/fs/path/resolve_confined_helpers.c` | 69, 71 | `#ifdef __linux__`, openat2 | `brix_plat_openat()` (already stubbed) |
| `src/fs/backend/frm/sd_frm_exec.c` | 324 | renameat2 syscall | `brix_plat_rename()` (already stubbed) |

**Migration Effort**: ~1 hour  
**Risk**: LOW - Fallbacks already in place

#### 9. memfd_create
**Files**: 2 files (already migrated!)

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/fs/vfs/vfs_open_handle.c` | Already migrated | Was using memfd_create | ✅ `brix_plat_anon_fd()` |
| `src/fs/backend/pblock/pblock_pack.c` | Already migrated | Was using memfd_create | ✅ `brix_plat_anon_fd()` |

**Migration Effort**: ✅ COMPLETE  
**Risk**: NONE

### P3: Low Priority

#### 10. DNS Resolution
**Files**: 4 files with platform DNS code

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/net/dns/resolve_bridge.c` | 39, 89, 222, 236, 248, 299 | `#ifdef __APPLE__` | Already uses PAL |
| `src/net/cms/altds.c` | 31 | macOS perfmon | Can wait |
| `src/net/cms/perf_pgm.c` | 33 | macOS perfmon | Can wait |

**Migration Effort**: ~2 hours  
**Risk**: LOW - Already working

#### 11. splice() Zero-Copy
**Files**: 3 files in proxy subsystem

| File | Line | Issue | PAL Replacement |
|------|------|-------|-----------------|
| `src/net/proxy/events_splice_setup.c` | 5-193 | `#ifdef __linux__`, splice | `brix_plat_splice()` (stubbed on macOS) |
| `src/net/proxy/events_splice.c` | 5-512 | `#ifdef __linux__` | `brix_plat_splice()` |
| `src/net/proxy/proxy_internal.h` | 233-242 | splice state | Already abstracted |

**Migration Effort**: ~2 hours  
**Risk**: MEDIUM - Performance-critical path

---

## Additional Platform-Specific Code

### Authentication & Impersonation
| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `src/auth/krb5/capture.c` | 20 | macOS Kerberos | P3 |
| `src/auth/authz/acc/groups.c` | 177 | macOS getgrouplist | P2 |
| `src/auth/impersonate/broker.c` | 8 | macOS credential handling | P2 |
| `src/auth/impersonate/broker_ops.c` | 18, 85, 240, 274 | Multiple macOS blocks | P2 |
| `src/auth/impersonate/lifecycle.c` | 29, 51 | macOS lifecycle | P2 |
| `src/auth/impersonate/lifecycle_broker.c` | 29, 51, 75 | macOS broker | P2 |
| `src/auth/impersonate/lifecycle_worker.c` | 30, 52 | macOS worker | P2 |
| `src/auth/impersonate/client.c` | 35 | macOS client | P2 |
| `src/auth/impersonate/broker_creds.c` | 11 | macOS creds | P2 |
| `src/auth/impersonate/idmap_denylist.c` | 27 | macOS denylist | P3 |

### TPC (Third-Party Copy)
| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `src/tpc/gsi/gsi_outbound_finish.c` | 13 | Linux GSI | P3 |
| `src/tpc/gsi/gsi_outbound_common.c` | 17 | Linux GSI | P3 |
| `src/tpc/outbound/source_stream.c` | 12, 23 | Platform endian | P0 |
| `src/tpc/outbound/push_stream.c` | 14 | Platform endian | P0 |
| `src/tpc/outbound/tpc_token.c` | 33 | macOS token | P3 |
| `src/tpc/outbound/source_stream_multi.c` | 31, 37 | Platform-specific | P1 |

### File System Backend
| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `src/fs/backend/posix/sd_posix_io.c` | 38, 85, 101, 140 | Multiple platform blocks | P1 |
| `src/fs/backend/block/sd_block.c` | 36 | Linux-only block device | P3 |
| `src/fs/backend/block/sd_block_ns.c` | 29 | Linux-only | P3 |
| `src/fs/xfer/xfer_spawn.c` | 29 | macOS spawn | P2 |

### Path Resolution
| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `src/fs/path/resolve_confined_helpers.c` | 51, 69, 71 | openat2, platform checks | P2 |
| `src/fs/path/resolve_confined_ops.c` | 21 | macOS ops | P2 |
| `src/fs/path/resolve_confined_ops_meta.c` | 21 | macOS meta ops | P2 |
| `src/fs/path/beneath.c` | 39, 169, 430, 507 | Multiple macOS blocks | P2 |

### Protocols
| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `src/protocols/cvmfs/origin_probe.c` | 30 | macOS probe | P3 |
| `src/protocols/root/query/prepare_cmd.c` | 103 | Linux command prep | P3 |
| `src/protocols/root/stream/*.c` | Various | Platform stream code | P2 |

### Observability
| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `src/observability/dashboard/dashboard_auth_creds.c` | 10 | macOS creds | P3 |
| `src/observability/pmark/flowlabel.c` | 30, 198 | Linux flowlabel | P3 |
| `src/observability/pmark/sockstats.c` | 34, 52 | Linux sockstats | P3 |

---

## Migration Strategy

### Phase 1: Quick Wins (Week 1)
1. ✅ **Byte-order operations** - Automated search/replace
   - Replace all `htobe64` → `brix_plat_htobe64`
   - Replace all `be64toh` → `brix_plat_be64toh`
   - Remove `#include <endian.h>` and `<libkern/OSByteOrder.h>`
   - Add `#include "platform/platform_api.h"`

2. ✅ **xattr syscalls** - Direct migration
   - Replace `getxattr()` → `brix_plat_getxattr()`
   - Replace `setxattr()` → `brix_plat_setxattr()`
   - Replace `XATTR_CREATE` → `BRIX_XATTR_CREATE`
   - Remove platform #ifdef blocks

### Phase 2: Core Syscalls (Week 2)
3. **sendfile unification**
   - Migrate to `brix_plat_sendfile()`
   - Remove signature #ifdef blocks

4. **eventfd/pipe2**
   - Migrate to `brix_plat_eventfd()`, `brix_plat_pipe2()`
   - Verify fallback behavior

5. **stat member access**
   - Design `brix_plat_stat_*()` helpers
   - Migrate st_mtim/st_mtimespec access

### Phase 3: Advanced Features (Week 3)
6. **splice/copy_file_range**
   - Migrate to `brix_plat_splice()`, `brix_plat_copy_range()`
   - Verify stub behavior on macOS

7. **openat2/renameat2**
   - Verify PAL stubs are sufficient
   - Remove direct syscall code

### Phase 4: Cleanup (Week 4)
8. **Remove platform headers**
   - Audit all `#include` statements
   - Remove platform-specific headers
   - Ensure only `platform_api.h` is included

9. **Documentation**
   - Update PAL API docs
   - Document migration decisions
   - Create before/after examples

---

## Automated Migration Scripts

### Script 1: Byte-Order Migration
```bash
#!/bin/bash
# migrate_endian.sh - Automated byte-order migration

find src/ -name "*.c" -o -name "*.h" | while read file; do
    # Skip platform directory
    if [[ "$file" == src/platform/* ]]; then
        continue
    fi
    
    # Replace byte-order functions
    sed -i.bak 's/\bhtobe64\b/brix_plat_htobe64/g' "$file"
    sed -i.bak 's/\bbe64toh\b/brix_plat_be64toh/g' "$file"
    sed -i.bak 's/\bhtobe32\b/brix_plat_htobe32/g' "$file"
    sed -i.bak 's/\bbe32toh\b/brix_plat_be32toh/g' "$file"
    
    # Remove old headers
    sed -i.bak '/#include <endian.h>/d' "$file"
    sed -i.bak '/#include <libkern\/OSByteOrder.h>/d' "$file"
    
    # Add PAL header if byte-order functions were found
    if grep -q "brix_plat_htobe\|brix_plat_be64" "$file"; then
        if ! grep -q "platform_api.h" "$file"; then
            sed -i.bak '1i #include "platform/platform_api.h"' "$file"
        fi
    fi
    
    rm -f "$file.bak"
done
```

### Script 2: xattr Migration
```bash
#!/bin/bash
# migrate_xattr.sh - Extended attribute migration

find src/ -name "*.c" -o -name "*.h" | while read file; do
    if [[ "$file" == src/platform/* ]]; then
        continue
    fi
    
    # Replace xattr functions
    sed -i.bak 's/\bgetxattr\b/brix_plat_getxattr/g' "$file"
    sed -i.bak 's/\bsetxattr\b/brix_plat_setxattr/g' "$file"
    sed -i.bak 's/\bsyz_getxattr\b/brix_plat_getxattr/g' "$file"
    
    # Replace flags
    sed -i.bak 's/\bXATTR_CREATE\b/BRIX_XATTR_CREATE/g' "$file"
    sed -i.bak 's/\bXATTR_REPLACE\b/BRIX_XATTR_REPLACE/g' "$file"
    
    # Remove platform-specific xattr headers
    sed -i.bak '/#include <sys\/xattr.h>/d' "$file"
    
    # Add PAL header
    if grep -q "brix_plat_.*xattr" "$file"; then
        if ! grep -q "platform_api.h" "$file"; then
            sed -i.bak '1i #include "platform/platform_api.h"' "$file"
        fi
    fi
    
    rm -f "$file.bak"
done
```

---

## Testing Strategy

### Unit Tests
- Test each PAL function on Linux and macOS
- Verify byte-order operations are correct
- Test xattr with various file systems

### Integration Tests
- Run full test suite on both platforms
- Verify no regression in functionality
- Performance benchmarks (ensure no overhead)

### Manual Testing
- Test on Intel macOS
- Test on Apple Silicon macOS
- Test on x86_64 Linux
- Test on ARM64 Linux (Graviton)

---

## Success Criteria

✅ **Phase 1 Complete**:
- Zero direct `htobe64`/`be64toh` calls outside PAL
- Zero `#include <endian.h>` outside PAL
- All xattr calls go through PAL

✅ **Phase 2 Complete**:
- Zero direct `sendfile()` calls
- Zero direct `eventfd()`/`pipe2()` calls
- All stat access through PAL helpers

✅ **Phase 3 Complete**:
- Zero direct `splice()`/`copy_file_range()` calls
- Zero direct `openat2()`/`renameat2()` calls
- All advanced syscalls abstracted

✅ **Phase 4 Complete**:
- Zero platform `#ifdef` in business logic
- All platform code in `src/platform/*/`
- Documentation complete

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Performance regression | HIGH | Benchmark before/after, optimize PAL |
| Broken fallback paths | MEDIUM | Test on both platforms thoroughly |
| Missing edge cases | MEDIUM | Code review, integration testing |
| Build breaks on one platform | HIGH | CI/CD with both Linux and macOS |

---

## Appendix: Complete File List

### Files with Platform #ifdef (80+ files)
[See detailed listings above]

### Files Already Migrated to PAL
- `src/fs/vfs/vfs_open_handle.c` ✅
- `src/fs/backend/pblock/pblock_pack.c` ✅
- `src/core/compat/subprocess.c` ✅
- Most files in `src/net/` ✅

### Files Needing Migration
[See priority rankings above]

---

**End of Audit Report**
