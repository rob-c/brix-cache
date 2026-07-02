# Phase 1: Resolver Consolidation - Implementation Plan

**Status:** PLANNING  
**Phase:** 1 of 3 (Protocol Unification)  
**Estimated Effort:** 8-12 hours  
**Risk Level:** HIGH (affects path security)  
**Target:** Unified path resolver for XRootD/WebDAV/S3  

---

## Executive Summary

Phase 1 consolidates two separate path resolution implementations into a single, unified resolver. Currently:

- **Stream Path Resolver** (`src/path/resolve_path_variants.c`) - XRootD protocol
- **HTTP Path Resolver** (`src/core/compat/path.c`) - WebDAV/S3 protocols

This creates security inconsistencies and maintenance overhead. A unified resolver will:
- ✅ Guarantee identical path validation across all protocols
- ✅ Reduce attack surface by centralizing security checks
- ✅ Simplify future feature additions (erasure coding, tiered storage)
- ✅ Enable cross-protocol consistency tests

---

## Current State Analysis

### Stream Resolver (`src/path/resolve_path_variants.c`)

**Characteristics:**
- Uses `ngx_str_t` for memory management
- Integrated with stream context logging
- Supports `mkdirpath` flag for automatic directory creation
- Handles `..` and `\0` detection
- Maintains path depth tracking

**Key Functions:**
```c
ngx_str_t *xrootd_resolve_path(ngx_str_t *path, 
                                const ngx_str_t *root, 
                                ngx_log_t *log, 
                                xrootd_resolve_opts_t *opts);
```

**Modes:**
- Standard resolution
- With mkdirpath (automatic intermediate directories)
- Skip cache checks
- Require directory type

---

### HTTP Path Resolver (`src/core/compat/path.c`)

**Characteristics:**
- Pure C (no nginx-specific memory)
- Numeric return codes
- Parent walking for PUT/COPY operations
- Handles missing intermediate paths

**Key Functions:**
```c
int ngx_http_xrootd_webdav_resolve_path(const char *root_canon,
                                        const char *req_path,
                                        char *resolved_out,
                                        size_t outsz);
```

**Modes:**
- Standard resolution
- Missing parent handling (for PUT/COPY)

---

## Unification Architecture

### New Unified Resolver: `src/path/unified.c`

#### Header File: `src/path/unified.h`

```c
#ifndef XROOTD_PATH_UNIFIED_H
#define XROOTD_PATH_UNIFIED_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Path resolution options flag structure.
 * Used by both stream and HTTP protocols to configure resolver behavior.
 */
typedef struct {
    unsigned int allow_missing_tail:1;      /* PUT/MKDIR: allow missing final component */
    unsigned int require_directory:1;       /* DIRLIST/MKCOL: resolve must be directory */
    unsigned int allow_missing_parents:1;   /* PUT/COPY: create intermediate dirs if missing */
    unsigned int skip_cache_check:1;        /* Direct origin access, bypass cache */
    unsigned int is_write_operation:1;      /* Write semantics for audit logging */
    unsigned int reject_symlinks:1;         /* Security: reject symlink traversal */
} xrootd_path_opts_t;

/*
 * Result structure from path resolution.
 * Contains resolved path and metadata useful for error reporting.
 */
typedef struct {
    ngx_str_t   resolved;                   /* Canonical absolute path */
    ngx_int_t   type;                       /* S_IFREG, S_IFDIR, NGX_FILE_NOT_FOUND */
    ngx_uint_t  depth;                      /* Component count for audit */
    unsigned int is_confined:1;             /* Path is within root boundary */
} xrootd_path_result_t;

/*
 * Unified path resolver entry point.
 * 
 * Resolves a request path within a root boundary using options flags.
 * Guarantees identical security semantics across all protocols.
 * 
 * Args:
 *   cf           - nginx config context (for pool allocation)
 *   root_canon   - Canonical absolute root path (must be pre-validated)
 *   req_path     - Request path (relative or absolute)
 *   opts         - Resolution options bitmask
 *   result       - Output: resolved path and metadata
 *   log          - Logger for errors/audit
 * 
 * Returns:
 *   NGX_OK              - Resolution successful, result is valid
 *   NGX_ERROR           - Allocation failure
 *   NGX_INVALID_FILE    - Path validation failed (traversal attempt, etc.)
 *   NGX_FILE_NOT_FOUND  - Path doesn't exist and allow_missing_* not set
 */
ngx_int_t xrootd_path_resolve(
    ngx_conf_t *cf,
    const ngx_str_t *root_canon,
    const ngx_str_t *req_path,
    xrootd_path_opts_t opts,
    xrootd_path_result_t *result,
    ngx_log_t *log
);

/*
 * Fast path for validation-only (no file type check).
 * Used in ACL checking where we only need to know if path is confined.
 * 
 * Returns:
 *   NGX_OK              - Path is valid and confined
 *   NGX_INVALID_FILE    - Path escapes root or contains invalid sequences
 */
ngx_int_t xrootd_path_validate(
    const ngx_str_t *root_canon,
    const ngx_str_t *req_path,
    ngx_log_t *log
);

/*
 * Helper: get file type without full resolution.
 * Used when we already have resolved path, just need to determine type.
 */
ngx_int_t xrootd_path_get_type(const ngx_str_t *resolved_path);

#endif /* XROOTD_PATH_UNIFIED_H */
```

#### Implementation: `src/path/unified.c`

```c
#include <ngx_config.h>
#include <ngx_core.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "unified.h"
#include "path.h"
#include "path_internal.h"

/*
 * Security Constants
 * These define the upper bounds on path operations to prevent DoS attacks.
 */
#define XROOTD_MAX_PATH_DEPTH       256     /* Prevent symlink exhaustion */
#define XROOTD_MAX_PATH_LENGTH      4096    /* Standard POSIX PATH_MAX */
#define XROOTD_MAX_MKDIR_DEPTH      20      /* Limit mkdirpath intermediate dirs */

/*
 * === Internal Functions ===
 */

/*
 * WHAT: Validate request path for malicious sequences.
 * WHY: Prevent "../", embedded nulls, and other traversal attempts BEFORE
 *      any filesystem operations. This reduces attack surface.
 * HOW: Character-by-character scan for forbidden patterns:
 *      - Null bytes (\0)
 *      - ".." components
 *      - Control characters (< 0x20, > 0x7E except '/') 
 *      Early rejection avoids expensive syscalls.
 * 
 * Returns: NGX_OK if valid, NGX_INVALID_FILE if contains forbidden sequence
 */
static ngx_int_t
xrootd_path_component_validate(const ngx_str_t *req_path)
{
    u_char *p, *last;
    size_t component_len;
    
    if (req_path->len == 0 || req_path->len > XROOTD_MAX_PATH_LENGTH) {
        return NGX_INVALID_FILE;  /* Empty or too long */
    }
    
    p = req_path->data;
    last = req_path->data + req_path->len;
    
    /* Scan each component */
    while (p < last) {
        /* Skip leading slash */
        if (*p == '/') {
            p++;
            if (p >= last) break;
        }
        
        /* Find component length */
        component_len = 0;
        while (p + component_len < last && p[component_len] != '/') {
            component_len++;
        }
        
        /* Validate component */
        if (component_len == 0) {
            /* Empty component (e.g., "//" or trailing "/") — OK, normalize */
            continue;
        }
        
        if (component_len == 2 && p[0] == '.' && p[1] == '.') {
            /* ".." component — FORBIDDEN traversal attempt */
            return NGX_INVALID_FILE;
        }
        
        if (component_len == 1 && p[0] == '.') {
            /* "." component — OK, can normalize */
            p += 1;
            continue;
        }
        
        /* Check for null bytes or control chars */
        for (size_t i = 0; i < component_len; i++) {
            u_char c = p[i];
            if (c == '\0' || c < 0x20 || (c > 0x7E && c != '/')) {
                return NGX_INVALID_FILE;
            }
        }
        
        p += component_len;
    }
    
    return NGX_OK;
}

/*
 * WHAT: Count path depth to detect symlink exhaustion.
 * WHY: Malicious symlinks can form loops (A → B → A). A deep chain
 *      causes excessive CPU during path traversal. Depth counting limits this.
 * HOW: Count "/" separators + 1 = number of components.
 *      Compare against XROOTD_MAX_PATH_DEPTH (256 components).
 * 
 * Returns: Component count, or 0 if path is empty/root
 */
static ngx_uint_t
xrootd_count_path_components(const ngx_str_t *path)
{
    u_char *p;
    ngx_uint_t count = 0;
    
    if (path->len == 0) return 0;
    if (path->len == 1 && path->data[0] == '/') return 1;  /* Root */
    
    for (p = path->data; p < path->data + path->len; p++) {
        if (*p == '/') count++;
    }
    
    return count + 1;  /* Count separators + 1 */
}

/*
 * WHAT: Normalize path by removing "." and redundant "/" separators.
 * WHY: "//foo" and "/foo" and "/./foo" all mean the same thing.
 *      Normalization ensures canonical comparison works.
 * HOW: Build new path by skipping "." components and collapsing "//".
 *      Allocate from pool to ensure cleanup.
 * 
 * Returns: Normalized ngx_str_t allocated from pool, or null on failure
 */
static ngx_str_t *
xrootd_normalize_path(ngx_conf_t *cf, const ngx_str_t *req_path)
{
    u_char *src, *dst, *last;
    ngx_str_t *normalized;
    size_t alloc_len;
    
    alloc_len = req_path->len + 1;  /* Extra byte for null-term if needed */
    
    normalized = ngx_palloc(cf->pool, sizeof(ngx_str_t) + alloc_len);
    if (normalized == NULL) return NULL;
    
    normalized->data = (u_char *)(normalized + 1);
    normalized->len = 0;
    
    src = req_path->data;
    last = req_path->data + req_path->len;
    dst = normalized->data;
    
    while (src < last) {
        if (*src == '/') {
            /* Skip multiple slashes */
            while (src < last && *src == '/') src++;
            if (src < last) {
                *dst++ = '/';
                normalized->len++;
            }
        } else {
            *dst++ = *src++;
            normalized->len++;
        }
    }
    
    return normalized;
}

/*
 * WHAT: Check if resolved path is within root boundary.
 * WHY: Path traversal attacks try to escape root (e.g., symlink to /etc/passwd).
 *      Double-check: (1) realpath() results, (2) string comparison.
 * HOW: After realpath(), do strncmp() between root and resolved.
 *      Ensure resolved starts with root + "/" (or is exactly root).
 * 
 * Returns: NGX_OK if confined, NGX_INVALID_FILE if escapes
 */
static ngx_int_t
xrootd_check_confinement(const ngx_str_t *root_canon,
                         const ngx_str_t *resolved)
{
    /* Exact match: root == resolved (e.g., both are "/data") */
    if (root_canon->len == resolved->len && 
        ngx_memcmp(root_canon->data, resolved->data, root_canon->len) == 0) {
        return NGX_OK;
    }
    
    /* Prefix match: resolved starts with root + "/" */
    if (resolved->len > root_canon->len &&
        ngx_memcmp(root_canon->data, resolved->data, root_canon->len) == 0 &&
        resolved->data[root_canon->len] == '/') {
        return NGX_OK;
    }
    
    /* Path escapes root → DENY */
    return NGX_INVALID_FILE;
}

/*
 * WHAT: Perform actual filesystem stat on resolved path.
 * WHY: Determine if path is file, directory, doesn't exist, etc.
 *      This is the only filesystem operation (after validation).
 * HOW: Call stat(), interpret mode via S_ISREG(), S_ISDIR(), etc.
 * 
 * Returns: S_IFREG, S_IFDIR, NGX_FILE_NOT_FOUND, or NGX_ERROR
 */
static ngx_int_t
xrootd_stat_resolved(const ngx_str_t *resolved_path)
{
    struct stat st;
    char path_buf[XROOTD_MAX_PATH_LENGTH + 1];
    
    /* Null-terminate for stat() */
    if (resolved_path->len >= sizeof(path_buf)) {
        return NGX_INVALID_FILE;
    }
    ngx_memcpy(path_buf, resolved_path->data, resolved_path->len);
    path_buf[resolved_path->len] = '\0';
    
    if (stat(path_buf, &st) == -1) {
        if (errno == ENOENT) return NGX_FILE_NOT_FOUND;
        if (errno == EACCES) return NGX_ERROR;  /* Permission denied */
        return NGX_ERROR;
    }
    
    if (S_ISREG(st.st_mode))  return S_IFREG;
    if (S_ISDIR(st.st_mode))  return S_IFDIR;
    
    return NGX_ERROR;  /* Symlink, socket, fifo, etc. */
}

/*
 * === Public Functions ===
 */

ngx_int_t
xrootd_path_resolve(ngx_conf_t *cf,
                    const ngx_str_t *root_canon,
                    const ngx_str_t *req_path,
                    xrootd_path_opts_t opts,
                    xrootd_path_result_t *result,
                    ngx_log_t *log)
{
    ngx_str_t *normalized;
    char combined_path[XROOTD_MAX_PATH_LENGTH * 2];
    char resolved_path[XROOTD_MAX_PATH_LENGTH + 1];
    size_t combined_len;
    ngx_uint_t depth;
    ngx_int_t type;
    char *real_result;
    
    /* Initialize result */
    ngx_str_null(&result->resolved);
    result->type = NGX_FILE_NOT_FOUND;
    result->depth = 0;
    result->is_confined = 0;
    
    /* STEP 1: Validate component sequences (before any FS ops) */
    if (xrootd_path_component_validate(req_path) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: path contains invalid sequences: \"%V\"", req_path);
        return NGX_INVALID_FILE;
    }
    
    /* STEP 2: Count components for DoS protection */
    depth = xrootd_count_path_components(req_path);
    if (depth > XROOTD_MAX_PATH_DEPTH) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: path depth %d exceeds limit %d",
            depth, XROOTD_MAX_PATH_DEPTH);
        return NGX_INVALID_FILE;
    }
    
    /* STEP 3: Normalize path */
    normalized = xrootd_normalize_path(cf, req_path);
    if (normalized == NULL) {
        return NGX_ERROR;  /* Allocation failure */
    }
    
    /* STEP 4: Build combined path (root + request) */
    combined_len = root_canon->len + 1 + normalized->len;
    if (combined_len >= sizeof(combined_path)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: combined path exceeds maximum length");
        return NGX_INVALID_FILE;
    }
    
    /* Construct: root + "/" + normalized */
    ngx_memcpy(combined_path, root_canon->data, root_canon->len);
    combined_path[root_canon->len] = '/';
    ngx_memcpy(combined_path + root_canon->len + 1, 
               normalized->data, normalized->len);
    combined_path[combined_len] = '\0';
    
    /* STEP 5: Call realpath() to resolve symlinks */
    real_result = realpath(combined_path, resolved_path);
    if (real_result == NULL) {
        if (errno == ENOENT) {
            /* Path doesn't exist. Check if caller allows this. */
            if (opts.allow_missing_tail || opts.allow_missing_parents) {
                /* Use combined_path as resolved (unresolved symlinks are OK for write) */
                result->resolved.data = ngx_palloc(cf->pool, combined_len + 1);
                if (result->resolved.data == NULL) return NGX_ERROR;
                ngx_memcpy(result->resolved.data, combined_path, combined_len);
                result->resolved.len = combined_len;
                result->type = NGX_FILE_NOT_FOUND;
                result->is_confined = 1;  /* Combined path is confined by construction */
                return NGX_OK;
            } else {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd: path not found: %s", combined_path);
                return NGX_FILE_NOT_FOUND;
            }
        }
        /* Other realpath() errors (EACCES, ELOOP, etc.) */
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: realpath() failed: %s", strerror(errno));
        return NGX_ERROR;
    }
    
    /* STEP 6: Verify confinement (path doesn't escape root) */
    ngx_str_t resolved_str;
    resolved_str.data = (u_char *)resolved_path;
    resolved_str.len = strlen(resolved_path);
    
    if (xrootd_check_confinement(root_canon, &resolved_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: path escapes root: %s not under %V",
            resolved_path, root_canon);
        return NGX_INVALID_FILE;
    }
    
    /* STEP 7: Get file type via stat() */
    type = xrootd_stat_resolved(&resolved_str);
    if (type == NGX_ERROR) {
        /* Stat failed (permission, not regular file, etc.) */
        if (opts.allow_missing_tail) {
            /* For write operations, allow non-existent files */
            type = NGX_FILE_NOT_FOUND;
        } else {
            return NGX_INVALID_FILE;
        }
    }
    
    /* STEP 8: Validate type requirements */
    if (opts.require_directory && type != S_IFDIR) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd: path is not a directory: %s", resolved_path);
        return NGX_INVALID_FILE;
    }
    
    /* STEP 9: Populate result */
    result->resolved.data = ngx_palloc(cf->pool, resolved_str.len + 1);
    if (result->resolved.data == NULL) return NGX_ERROR;
    ngx_memcpy(result->resolved.data, resolved_str.data, resolved_str.len);
    result->resolved.len = resolved_str.len;
    result->type = type;
    result->depth = depth;
    result->is_confined = 1;
    
    ngx_log_debug4(NGX_LOG_DEBUG, log, 0,
        "xrootd: resolved \"%V\" → \"%V\" (depth=%d, type=%d)",
        req_path, &result->resolved, depth, type);
    
    return NGX_OK;
}

ngx_int_t
xrootd_path_validate(const ngx_str_t *root_canon,
                     const ngx_str_t *req_path,
                     ngx_log_t *log)
{
    /* Quick validation: check for forbidden sequences and confinement */
    if (xrootd_path_component_validate(req_path) != NGX_OK) {
        return NGX_INVALID_FILE;
    }
    
    ngx_uint_t depth = xrootd_count_path_components(req_path);
    if (depth > XROOTD_MAX_PATH_DEPTH) {
        return NGX_INVALID_FILE;
    }
    
    return NGX_OK;
}

ngx_int_t
xrootd_path_get_type(const ngx_str_t *resolved_path)
{
    return xrootd_stat_resolved(resolved_path);
}
```

---

## Migration Path

### Step 1: Deploy Unified Resolver
1. Create `src/path/unified.h` and `src/path/unified.c`
2. Add to `src/core/config/config.h` build list
3. Compile and run unit tests
4. Target: No behavior changes, identical output to old resolvers

### Step 2: Update Stream Code
1. Update `src/read/open.c` to use new resolver
2. Update `src/write/open.c` to use new resolver
3. Update `src/dirlist/handler.c` to use new resolver
4. Run existing stream tests, verify no regressions

### Step 3: Update HTTP/WebDAV Code
1. Update `src/webdav/dispatch.c` to use new resolver
2. Update `src/s3/handler.c` to use new resolver
3. Run existing WebDAV/S3 tests, verify no regressions

### Step 4: Cross-Protocol Tests
1. Run same operations through both protocols
2. Verify identical security behavior
3. Create test cases for known traversal attacks

---

## Testing Strategy

### Unit Tests: `tests/test_unified_path_resolver.c`

```c
static void test_reject_dotdot(void) {
    /* Verify ".." is rejected */
}

static void test_reject_nullbyte(void) {
    /* Verify embedded \0 is rejected */
}

static void test_normalize_slashes(void) {
    /* Verify "//" becomes "/" */
}

static void test_symlink_confinement(void) {
    /* Verify symlink escapes are rejected */
}

static void test_allow_missing_tail(void) {
    /* Verify PUT operations can target non-existent files */
}

static void test_require_directory(void) {
    /* Verify MKCOL on files is rejected */
}

static void test_depth_limit(void) {
    /* Verify deep paths are rejected */
}
```

### Integration Tests

Cross-protocol tests that verify:
- Stream read via `kXR_read` returns same data as WebDAV GET
- Stream write via `kXR_write` stores in same location as WebDAV PUT
- ACL enforcement is identical across protocols
- Error conditions produce same response codes

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| **Security Regression** | Create "Golden Test Set" of known attacks (symlink loops, traversal, null bytes) that MUST pass before merge |
| **Performance Degradation** | Profile old vs new resolver, ensure <5% overhead |
| **Behavioral Incompatibility** | Create cross-protocol test suite comparing byte-for-byte results |
| **Rollback Difficulty** | Keep old resolvers until new one is proven, then remove |

---

## Success Criteria

- ✅ 0 security test failures
- ✅ All existing tests pass (2,073+ tests)
- ✅ Cross-protocol consistency verified
- ✅ Performance within 5% of original
- ✅ Code review approved by 2+ maintainers
- ✅ Documentation complete

---

## Timeline

- **Day 1-2:** Implement unified resolver + unit tests
- **Day 3:** Integrate stream code, run stream tests
- **Day 4:** Integrate HTTP/WebDAV, run WebDAV tests
- **Day 5:** Cross-protocol testing, bug fixes
- **Day 6:** Performance testing, profiling
- **Day 7:** Code review, documentation, release

---

**Estimated Effort:** 40-50 hours (1 week)  
**Risk Level:** HIGH (path security) — Proceed with caution and extensive testing  
**Next Phase:** Phase 2 - Identity Abstraction (Week 2)
