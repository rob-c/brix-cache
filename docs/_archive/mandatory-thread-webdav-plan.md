# Mandatory Thread Pool & WebDAV Plan [2026-05-22]

**Goal:** Remove all `#if (NGX_THREADS)` and `#if defined(XROOTD_WEBDAV_DAV_DELEGATION)` / `#if defined(XROOTD_HAVE_LIBXML2)` conditionals from the module so that nginx thread pool support and WebDAV components are required at build time. No ifdef checks for these modules remain anywhere in source or headers.

---

## 1. Current State Map

### Compile-time conditionals (`#if (NGX_THREADS)`)

#### Headers (3 files, 4 blocks)
| File | Line(s) | What is guarded | Action |
|------|---------|-----------------|--------|
| `src/core/aio/aio.h` | 68–end of file | AIO struct definitions (`xrootd_aio_ctx_t`) and all function declarations | Remove — always compile |
| `src/core/config/config.h` | 315–319 | `thread_pool` + `thread_pool_name` fields in `ngx_stream_xrootd_srv_conf_t` | Remove ifdef wrapper, keep fields |
| `src/webdav/webdav.h` | 8 | `#include <ngx_thread_pool.h>` | Remove ifdef wrapper, always include |
| `src/webdav/webdav.h` | 125–130 | `thread_pool` + `thread_pool_name` in `ngx_http_xrootd_webdav_loc_conf_t` | Remove ifdef wrapper, keep fields |
| `src/webdav/webdav.h` | 304–318 | Thread pool function declarations (`webdav_*_aio_thread`, `_done`) | Remove ifdef wrapper, always declare |

#### Source files (22 blocks across 17 files)
| File | Line(s) | What is guarded | Action |
|------|---------|-----------------|--------|
| `src/core/aio/config.c` | 3–72 | Entire file — thread pool resolution | Remove ifdef wrapper, always compile |
| `src/connection/fd_table.c` | 295–end | AIO-related cleanup code | Remove ifdef, keep code |
| `src/stream/module_cache_proxy_directives.c` | 170–end | Thread pool directive parsing | Remove ifdef, keep code |
| `src/stream/module.c` | 541–end | Postconfiguration thread pool setup | Remove ifdef, always call |
| `src/webdav/postconfig.c` | 70–100 | WebDAV thread pool resolution loop | Remove ifdef, always run |
| `src/webdav/tpc_thread.c` | 17–209 | Thread functions for HTTP-TPC | Remove ifdef wrapper, keep code |
| `src/webdav/tpc.c` | 203–408 | TPC thread pool usage in pull handler | Remove ifdef, always use threads |
| `src/webdav/tpc.c` | 409–end | Second thread block (TPC async dispatch) | Remove ifdef, keep code |
| `src/webdav/put.c` | 14–182 | AIO PUT path | Remove ifdef, always use aio |
| `src/webdav/put.c` | 183–end | Second thread block in PUT handler | Remove ifdef, keep code |
| `src/s3/put.c` | 61–347 | S3 PUT with thread pool async write | Remove ifdef, always use aio |
| `src/s3/put.c` | 348–end | Second thread block in S3 PUT | Remove ifdef, keep code |
| `src/s3/module.c` | 42–44 | Postconfiguration forward declaration | Remove ifdef |
| `src/s3/module.c` | 106–143 | Postconfiguration function body | Remove ifdef, always compile |
| `src/s3/module.c` | 147–151 | Module context postconfig slot (NGX_THREADS/else) | Collapse to single entry: `ngx_http_s3_postconfiguration` |
| `src/write/pgwrite.c` | 237–255 | pgwrite thread pool path | Remove ifdef, always use aio |
| `src/write/common.c` | 106–163 | Common write with thread pool | Remove ifdef, keep code |
| `src/core/aio/pgread.c` | 14–183 | AIO pgread thread/callback | Remove ifdef wrapper, keep code |
| `src/core/aio/readv.c` | 15–134 | AIO readv thread/callback | Remove ifdef wrapper, keep code |
| `src/core/aio/resume.c` | 3–139 | AIO resume callback plumbing | Remove ifdef wrapper, keep code |
| `src/write/writev.c` | 110–175 | writev with thread pool | Remove ifdef, always use aio |
| `src/write/sync.c` | 73–end | Sync with async fallback via thread pool | Remove ifdef, always compile |
| `src/core/aio/dirlist.c` | 63–end | Dirlist async via thread pool | Remove ifdef wrapper, keep code |

### Runtime NULL checks (instead of compile-time conditionals)

These `.c` files check `conf->thread_pool == NULL` at runtime — after making threads mandatory, these become either no-ops or can be tightened to assertions:

| File | Location | Pattern | Action |
|------|----------|---------|--------|
| `src/write/common.c` | ~line 106–163 | `if (conf->thread_pool == NULL) { /* sync fallback */ }` | Convert to assert or remove — pool always exists |
| `src/cache/open_or_fill.c` | ~line X | `if (conf->thread_pool == NULL)` | Convert to assert |
| `src/webdav/postconfig.c` | lines 88–92 | `if (wdcf->thread_pool == NULL) { NGX_LOG_NOTICE }` | Remove — pool always resolved, change log level if needed |
| `src/s3/module.c` | lines 133–137 | `if (scf->thread_pool == NULL) { NGX_LOG_NOTICE }` | Remove |
| `src/core/aio/config.c` | lines 49–61 | Cache-required pool check + fallback notice | Keep cache-required check; remove fallback notice path |

### Other conditionals related to WebDAV

| Conditional | Files | Lines | What is guarded | Action |
|-------------|-------|-------|-----------------|--------|
| `#if defined(XROOTD_WEBDAV_DAV_DELEGATION)` | `src/webdav/access.c` | 197, 225 | MKCOL/DELETE delegation to nginx dav module | Remove ifdef — always include DAV delegation path |
| `#if defined(XROOTD_WEBDAV_DAV_DELEGATION)` | `src/webdav/dispatch.c` | 81, 93 | Method routing for MKCOL/DELETE | Remove ifdef — always route MKCOL/DELETE |
| `#if defined(XROOTD_HAVE_LIBXML2)` | `src/webdav/propfind.c` | 24, 153, 159 | XML parsing for PROPFIND Multi-Status responses | Remove ifdef — always compile XML path; provide stub fallback if libxml2 absent (or make mandatory) |

### Current configure script dependency status

| Dependency | Status | How checked | Where in `config` |
|------------|--------|-------------|-------------------|
| `--with-stream` | **Required** | Comment: "Requires: --with-stream" | Line 2 |
| `--with-http_ssl_module` | Recommended (checked via `$HTTP_DAV`) | nginx core variable set by configure | Line 26 |
| `--with-threads` | Strongly recommended (no check) | Uses `NGX_THREADS` from nginx headers | No explicit check in config script |
| libxml2 | **Optional** | pkg-config check; sets `-DXROOTD_HAVE_LIBXML2=1` only if found | Lines 18–21 |
| HTTP DAV delegation | Optional | Only when `$HTTP_DAV = YES` (built with `--with-http_dav_module`) | Lines 26–29 |
| jansson | **Required** | pkg-config check; exits on missing | Lines 31–38 |
| voms-libs | Runtime-only | dlopen at startup, no compile-time link | No config script entry |

### RPM spec file
`packaging/rpm/nginx-mod-xrootd.spec` line 41: `--with-threads` already present — **no change needed**.

---

## 2. Removal Plan by Category

### Phase A: Configure Script Changes (single edit)

**File:** `config`

Changes to make at lines 16–38:
```bash
# Before:
CFLAGS="$CFLAGS -D_GNU_SOURCE ..."

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libxml-2.0; then
    CFLAGS="$CFLAGS $(pkg-config --cflags libxml-2.0) -DXROOTD_HAVE_LIBXML2=1"
    CORE_LIBS="$CORE_LIBS $(pkg-config --libs libxml-2.0)"
fi

if [ "$HTTP_DAV" = YES ]; then
    CFLAGS="$CFLAGS -DXROOTD_WEBDAV_DAV_DELEGATION=1"
    echo " + xrootd WebDAV: nginx DAV delegation enabled ..."
fi

# After:
CFLAGS="$CFLAGS -D_GNU_SOURCE ..."

# Threads is now required — verify NGX_THREADS is defined by nginx headers
if [ "$NGX_THREADS" != YES ]; then
    echo "ERROR: --with-threads is required. Re-run configure with --with-threads." >&2
    exit 1
fi

# libxml2 is now required for WebDAV PROPFIND XML parsing
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libxml-2.0; then
    CFLAGS="$CFLAGS $(pkg-config --cflags libxml-2.0) -DXROOTD_HAVE_LIBXML2=1"
    CORE_LIBS="$CORE_LIBS $(pkg-config --libs libxml-2.0)"
else
    echo "ERROR: libxml2 is required for WebDAV PROPFIND XML parsing." \
         "Install libxml2-devel (RHEL/CentOS) or libxml2-dev (Debian/Ubuntu)." >&2
    exit 1
fi

# DAV delegation always enabled when HTTP module is present
CFLAGS="$CFLAGS -DXROOTD_WEBDAV_DAV_DELEGATION=1"
echo " + xrootd WebDAV: nginx DAV delegation enabled (MKCOL+DELETE → ngx_http_dav_module)"
```

**Result:** 3 compile-time conditionals eliminated from configure script. `--with-threads` and libxml2 become hard requirements with explicit exit-on-missing.

### Phase B: Header File Cleanups (5 blocks across 3 files)

#### `src/core/aio/aio.h` — Remove `#if (NGX_THREADS)` at line 68
- Delete the `#if (NGX_THREADS)` guard and corresponding `#endif`
- AIO struct (`xrootd_aio_ctx_t`) and all function declarations always compile
- Update file header comment: "All code in this directory is compiled unconditionally."

#### `src/core/config/config.h` — Remove `#if (NGX_THREADS)` at lines 315–319
- Keep the `thread_pool` and `thread_pool_name` fields, remove ifdef wrapper
- Update field comments to drop "(NGX_THREADS only)" qualifier
- This is the most impactful header change: every .c file that accesses these fields now has them unconditionally

#### `src/webdav/webdav.h` — Remove 3 blocks (lines 8, 125–130, 304–318)
- Line 8: always include `<ngx_thread_pool.h>`
- Lines 125–130: keep `thread_pool` + `thread_pool_name` fields in loc_conf_t unconditionally
- Lines 304–318: always declare thread pool function prototypes

### Phase C: Source File Cleanups (22 blocks across 17 files)

For each .c file, remove the `#if (NGX_THREADS)` / `#endif` pair and keep all code. Specific notes per file:

**Files with entire-file guards (remove outermost ifdef):**
- `src/core/aio/config.c` — lines 3–72: remove outer `#if (NGX_THREADS)`, function always compiles
- `src/webdav/tpc_thread.c` — lines 17–209: remove outer guard, thread functions always compile

**Files with module context conditional slots:**
- `src/s3/module.c` — lines 42–44, 106–143, 147–151: 
  - Remove forward-declaration ifdef (line 42)
  - Remove function-body ifdef (line 106)
  - Collapse module context slot from `#if/else/#endif` pattern to single entry: `ngx_http_s3_postconfiguration, /* postconfiguration */`

**Files with runtime NULL checks that become no-ops:**
- `src/write/common.c`, `src/cache/open_or_fill.c`: convert `conf->thread_pool == NULL` fallback paths to either assertions or remove entirely (pool always exists)
- `src/webdav/postconfig.c` lines 88–92: change "NOT found" notice to never-executed path, or remove the else branch
- `src/s3/module.c` lines 133–137: same — pool always resolved

**Files with inline thread blocks (remove ifdef pair only):**
- `src/webdav/tpc.c`, `src/webdav/put.c`, `src/s3/put.c`, `src/write/pgwrite.c`, `src/write/common.c`, `src/core/aio/pgread.c`, `src/core/aio/readv.c`, `src/core/aio/resume.c`, `src/write/writev.c`, `src/write/sync.c`, `src/core/aio/dirlist.c`: each has a single `#if (NGX_THREADS)` / `#endif` pair wrapping a function or code block — remove the pair, keep the content

### Phase D: WebDAV-specific conditionals (3 files)

#### `src/webdav/access.c` — Remove `#if defined(XROOTD_WEBDAV_DAV_DELEGATION)` at lines 197, 225
- Lines 197–224: MKCOL delegation to nginx dav module — always compile this path
- Line 225: DELETE delegation — always compile

#### `src/webdav/dispatch.c` — Remove `#if defined(XROOTD_WEBDAV_DAV_DELEGATION)` at lines 81, 93
- Lines 81–92: MKCOL method routing — always include
- Line 93: DELETE method routing — always include

#### `src/webdav/propfind.c` — Remove `#if defined(XROOTD_HAVE_LIBXML2)` at lines 24, 153, 159
- Line 24: XML header includes and forward declarations — always compile
- Lines 153–159: XML parsing functions for PROPFIND Multi-Status body — always compile

### Phase E: Documentation Updates (6 files)

| File | Section to Update | What Changes |
|------|-------------------|--------------|
| `docs/03-configuration/build-guide.md` | Lines 85–101 (configure flags table) | Change `--with-threads` from "Strongly recommended" → **Required**; add libxml2 as required package; remove HTTP DAV delegation note |
| `README.md` | Line 95 (quick install config), line 87 (flag explanation) | Remove "--with-threads" optional qualifier; add libxml2 to prerequisites table |
| `docs/01-getting-started/getting-started-full.md` | Lines 79, 87, 447, 471 | Change thread_pool from "strongly recommended" → required; update build examples |
| `docs/05-operations/operation-status.md` | Line 202 | Remove "is built with --with-threads and a working xrootd_thread_pool is configured" qualifier |
| `docs/04-protocols/webdav-directives.md` | Line 171 (thread_pool directive) | Remove "(NGX_THREADS only)" note |
| `src/stream/README.md` | Line 50 | Remove "NGX_THREADS only" from thread_pool directive description |
| `src/core/aio/README.md` | Last paragraph ("All code in this directory is compiled only when nginx is built with thread support") | Change to: "All code in this directory is compiled unconditionally." |

### Phase F: Dockerfile Updates (4 files)

Check and update if needed:
- `packaging/rpm/Dockerfile.alma8` — verify `--with-threads` present
- `packaging/rpm/Dockerfile.alma9` — verify `--with-threads` present + add libxml2-devel
- `packaging/rpm/Dockerfile.alma10` — same
- `packaging/rpm/Dockerfile.alma11` — same

---

## 3. Migration Impact Summary

### What breaks for existing builds

| Scenario | Before | After | Fix |
|----------|--------|-------|-----|
| Build without `--with-threads` | Works, async I/O falls back to sync | Configure exits with error | Add `--with-threads` to configure line |
| Build without libxml2 | Works, PROPFIND returns XML-free responses or stub | Configure exits with error | Install libxml2-devel/libxml2-dev |
| RPM build (alma9) | Already has `--with-threads` | No change needed | None |
| Dockerfile builds | Have `--with-threads` | Need libxml2-devel added to RUN install line | Add libxml2-devel to package list |

### What improves

1. **Fewer code paths:** Every opcode that used async I/O now always uses it — no sync fallback branches, smaller binary decision trees
2. **Compile-time certainty:** `conf->thread_pool` is never NULL at runtime in enabled servers — NULL checks become assertions or disappear
3. **PROPFIND consistency:** XML parsing always available — no conditional Multi-Status response generation
4. **MKCOL/DELETE always delegated to nginx dav module** — single code path instead of two (delegated vs self-handled)

### What stays the same

1. `xrootd_thread_pool` directive still allows operators to choose pool name or use "default"
2. Cache-required thread pool check in `aio/config.c` remains (cache needs threads even if threads is always compiled)
3. VOMS runtime dlopen behavior unchanged
4. jansson requirement unchanged

---

## 4. Execution Order & Dependencies

```
Phase A (config script) → Phase B (headers) → Phase C (.c files) → Phase D (webdav conditionals) → Phase E (docs) → Phase F (Dockerfiles)
```

**Dependencies:**
- Phase B must precede Phase C: header fields become unconditional before .c files that reference them are edited
- Phase A must precede everything else: configure script changes validate the build environment for all subsequent code changes
- Phase D can run parallel with Phase C (no dependency on headers or config)

### Estimated effort per phase

| Phase | Files affected | Edits per file | Total edits | Effort |
|-------|---------------|----------------|-------------|--------|
| A: config script | 1 | 3 blocks | 3 | ~5 min |
| B: headers | 3 | 4–6 each | 14 | ~10 min |
| C: source files | 17 | 2–3 each (ifdef remove + NULL check cleanup) | ~45 | ~30 min |
| D: webdav conditionals | 3 | 2–3 each | ~8 | ~10 min |
| E: documentation | 7 | 1–2 each | ~12 | ~15 min |
| F: Dockerfiles | 4 | 1 each (add libxml2-devel) | ~4 | ~5 min |

**Total estimated effort: ~75 minutes** — all phases can be parallelized where dependencies allow.

---

## 5. Verification Checklist

After all phases complete:
- [ ] `grep -r '#if.*NGX_THREADS' src/` returns zero matches (headers + source)
- [ ] `grep -r 'defined(XROOTD_WEBDAV_DAV_DELEGATION)' src/` returns zero matches
- [ ] `grep -r 'defined(XROOTD_HAVE_LIBXML2)' src/` returns zero matches
- [ ] `./configure --with-stream --with-http_ssl_module --with-threads --add-module=...` succeeds (libxml2 installed)
- [ ] `./configure --without-threads --add-module=...` exits with error message
- [ ] `make -j$(nproc)` compiles cleanly — no warnings about unused conditional code
- [ ] `lsp_diagnostics` clean on all changed files
- [ ] Full test suite passes (`pytest -v`)
- [ ] Cross-backend tests pass (`TEST_CROSS_BACKEND=nginx pytest tests/ -v --tb=short`)
- [ ] RPM build succeeds with spec file unchanged

---

## 6. Notes & Edge Cases

### `#if (NGX_SSL)` conditionals — NOT in scope

These are separate from the thread/WebDAV plan:
- `src/core/config/config.h` lines 180–182, 328–330: guards `upstream_tls_ctx` and `proxy_tls_ctx` fields
- These remain as-is (SSL is already required via `--with-http_ssl_module` / `--with-stream_ssl_module`)

### `__linux__` conditionals — NOT in scope

POSIX_FADV_WILLNEED and other Linux-specific optimizations scattered across source files. Not part of this mandatory-dependency plan.

### Cache fallback when thread pool not found

After making threads mandatory, the cache-required check in `aio/config.c` (lines 50–55) remains valid: if `cache=on` but no thread pool is configured in nginx.conf, configure still fails with `emerg`. This is a config-level error, not a build-time conditional.

### libxml2 stub fallback option

If libxml2 should remain optional rather than mandatory, add a minimal XML-free PROPFIND stub in `propfind.c` that returns basic property responses without full XML formatting. However, the plan assumes mandatory for cleaner code paths — if libxml2 becomes optional again, Phase D needs to restore conditionals with stub fallback.
