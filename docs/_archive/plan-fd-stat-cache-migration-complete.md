# Design Plan: FD/Stat Cache Migration to Nginx Core (COMPLETED)

This migration was successfully executed on 2026-05-20. The custom `src/webdav/fd_cache.c` was removed and replaced with core `ngx_open_file_cache` integration.

## 1. Objectives
- **Code Reduction**: Eliminate ~15KB of custom C code in `src/webdav/fd_cache.c` and associated logic.
- **Reliability**: Use the battle-tested, high-performance open file cache provided by Nginx core.
- **Consistency**: Align the module's resource management with standard Nginx behavior (e.g., proper handling of `inactive`, `valid`, and `min_uses` parameters).
- **Correctness**: Leverage core Nginx logic for detecting stale file handles after disk mutations.

## 2. Components for Removal
The following files and logic will be removed or substantially pruned:
- `src/webdav/fd_cache.c`: Entire file.
- `webdav_fd_table_t` and `webdav_fd_entry_t` structures in `src/webdav/webdav.h`.
- Custom WebDAV metrics for FD cache hits/misses/evictions.
- `webdav_get_fd_table()`, `webdav_fd_table_get()`, `webdav_fd_table_put()`, and `webdav_fd_table_evict()` functions.

## 3. Core Integration Strategy

### A. Configuration
We will introduce a new set of directives (or reuse core ones if possible via configuration merging) to control the cache.
Proposed directive:
```nginx
xrootd_open_file_cache max=1000 inactive=20s;
xrootd_open_file_cache_valid 30s;
xrootd_open_file_cache_min_uses 2;
xrootd_open_file_cache_errors on;
```
These will map to `ngx_open_file_cache_t` fields in the `ngx_http_xrootd_webdav_loc_conf_t` structure.

### B. Implementation Steps
1.  **Header Updates**: Include `ngx_open_file_cache.h` in `src/webdav/webdav.h`.
2.  **Configuration Structure**: Add `ngx_open_file_cache_t *open_file_cache` and related settings to the WebDAV location configuration.
3.  **Directive Registration**: Add command handlers in `src/webdav/postconfig.c` or a new directive file that uses standard Nginx parsing for open file caches.
4.  **Handler Refactoring**:
    - Update `src/webdav/get.c`: Replace `webdav_fd_table_get()` with `ngx_open_cached_file()`.
    - Update `src/webdav/namespace.c` (DELETE), `src/webdav/move.c`, and `src/webdav/copy.c`: Remove explicit `webdav_fd_table_evict()` calls. The core cache handles invalidation via the `valid` timer and re-stating files.
5.  **Metrics Integration**: Map standard Nginx cache events to the module's Prometheus metrics if necessary, or rely on core Nginx status modules.

## 4. Migration Risks & Mitigations
- **Risk**: Protocol-specific behavior. Some XRootD handlers might expect specific FD state.
  - **Mitigation**: Ensure `ngx_open_file_info_t` is properly populated before being passed to I/O routines.
- **Risk**: Performance regressions in high-keepalive scenarios.
  - **Mitigation**: Standard Nginx caching is highly optimized for these scenarios; benchmark against the existing custom implementation using `tests/load_test.py`.

## 5. Verification Plan
1.  **Functional**: Run `tests/test_a_webdav_clients.py` and `tests/test_http_webdav.py` to ensure GET/PUT/DELETE operations remain correct.
2.  **Concurrency**: Run `tests/test_concurrent.py` to verify thread-safe access to the core cache.
3.  **Stability**: Execute a 10-minute run of `tests/run_load_test.sh` to monitor for leaks or crashes.
