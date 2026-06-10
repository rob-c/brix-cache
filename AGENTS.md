# nginx-xrootd AGENT GUIDE v3.5 [2026-05-16]

**Quick lookup:** OP→FILE → HELPERS → INVARIANTS → BUILD/TEST → FAQ
**Wire spec:** `/tmp/xrootd-src/src/XProtocol/XProtocol.hh`
**Core rules:** (1) Use HELPERS — never reimplement path/auth/metrics/framing (2) 3 tests per change: success + error + security-neg

---

## SMALL-MODEL USAGE (IMPORTANT)

This file is a **lookup reference**, not memorization material. If your context window is limited:

1. **Search by section header** — use `grep` or `read_file` with line ranges to pull only what you need
2. **OP→FILE tables are the fastest entry point** — search keywords, get file paths immediately
3. **HELPERS section is mandatory** — never reimplement functions listed here
4. **INVARIANTS + HARD BLOCKS are critical** — read these before writing code
5. **FAQ for nginx-specific patterns** — alloc, ngx_str_t, async I/O, response building

**Token-efficient shorthand:**
- `ngx_palloc` / `ngx_alloc` → HTTP/Stream allocation (never raw malloc)
- `.len` + `ngx_memcpy` → ngx_str_t operations (no strlen/strcpy)
- `ngx_chain_t` of `ngx_buf_t` → response building (never raw write/send)
- `NGX_OK/NGX_ERROR/NGX_DONE` → error codes

---

## ROUTING
| Proto | Layer | Entry | Test Port |
|---|---|---|---|
| `root://` / `roots://` | stream | `src/connection/handler.c`→`src/handshake/dispatch.c` | anon=11094 GSI=11095 TLS=11096 Token=11097 |
| `davs://` (GSI+TLS) | http | `src/webdav/dispatch.c`→method handler | 8444 |
| `davs://` / `http://` (no GSI) | http | `src/webdav/dispatch.c`→method handler | 8443 |
| S3 REST | http | `src/s3/handler.c`→method handler | 9001 |
| `/metrics` | http | `src/metrics/stream.c`/`writer.c` | 9100 |

---

## OP→FILE (search keywords → get files)

### STREAM (`src/` prefix)
| Keyword | Files |
|---|---|
| handshake / dispatch | `handshake/dispatch.c`, `dispatch_session.c` |
| auth (GSI/token/SSS) | `session/login.c`, `gsi/parse.c`, `token/validate.c`, `sss/` |
| protocol lifecycle | `session/protocol.c`, `lifecycle.c` |
| bind / session | `session/bind.c`, `registry.c` |
| acl / policy / voms | `handshake/policy.c`, `path/acl.c`, `authdb.c`, `voms/` |
| open / close / stat | `read/open.c`, `open_cache.c`, `close.c`, `stat.c`, `statx.c` |
| read / readv / pgread | `read/read.c`, `readv.c`, `pgread.c`, `aio/` |
| write / pgwrite / sync | `write/write.c`, `pgwrite.c`, `sync.c` |
| rename / mkdir / rm | `write/mv.c`, `mkdir.c`, `rm.c`, `fattr/` |
| dirlist / locate / clone | `dirlist/handler.c`, `read/locate.c`, `clone.c` |
| native tpc | `tpc/key_registry.c`, `launch.c`, `thread.c`, `io.c`, `done.c` |
| cms / manager / cluster | `manager/registry.c`, `cms/send.c`, `upstream/` |

### HTTP (`src/webdav/` prefix unless noted)
| Keyword | Files |
|---|---|
| routing / proxy | `dispatch.c`, `proxy.c`, `postconfig.c` |
| methods (GET/PUT/etc) | `get.c`, `put.c`, `namespace.c`, `move.c`, `copy.c`, `propfind.c`, `lock.c` |
| auth / tpc | `auth_cert.c`, `auth_token.c`, `tpc.c`, `tpc_curl.c`, `tpc_cred.c`, `tpc_headers.c` |
| helpers | `path.c`, `resource.c`, `io.c`, `fd_cache.c`, `headers.c` |
| s3 dispatch | `src/s3/handler.c`, `auth.c`, `util.c` |
| s3 ops | `src/s3/get.c`, `put.c`, `list.c`, `multipart.c` |

---

## HELPERS (MUST USE — NEVER REIMPLEMENT)
| Function | Purpose |
|---|---|
| `ngx_http_xrootd_webdav_resolve_path(path)` | Canonical+confined path |
| `xrootd_open_confined_canon(fd, path)` | Confined fd open |
| `webdav_verify_proxy_cert(cert_path)` | Valid GSI cert → NGX_OK |
| `webdav_verify_bearer_token(token_str)` | Valid JWT → NGX_OK |
| `xrootd_token_check_scope(scope, path)` | Scope grants access → NGX_OK |
| `webdav_tpc_find_header(headers, name)` | Find header in linked list |
| `webdav_add_cors_headers(r)` | Add Access-Control-* headers |
| `webdav_metrics_return(status_bytes, proto)` | Increment bytes_sent metric |
| `XROOTD_PROXY_METRIC_INC(op, status)` | Increment request counter |
| `webdav_check_locks(path)` | NGX_OK or 423 |
| `webdav_copy_fds(src_fd, dst_fd)` | copy_file_range for TPC |

---

## INVARIANTS (read before writing code)

**CRITICAL:**
1. pgread/pgwrite → kXR_status(4007) framing + per-page CRC32c required
2. TLS: `b->memory=1` only; cleartext: file-backed+sendfile; never mix
3. `conf->allow_write` checked globally before token scope
4. All wire paths → `resolve_path()` before `open()` — no exceptions

**Subtle bugs:**
5. DEL/MOVE/COPY on collections: recursively check child locks
6. S3 SigV4 ≠ WLCG token — never share auth logic
7. Stat: use handle metadata; no extra path syscalls per read
8. Metric labels: low-cardinality only (no paths/bucket-names/UUIDs)

**Architecture:**
9. Native TPC = SHM key registry (`src/tpc/key_registry.c`) — cross-process, zero-copy
10. WebDAV TPC = curl COPY with Source/Credential headers (`src/webdav/tpc.c`)

---

## HARD BLOCKS (non-negotiable)
- **NEVER run any git command (stash, reset, checkout, clean, rebase, etc.) without explicit OP instruction** — these destroy uncommitted work and cannot always be recovered
- **NEVER use `git show HEAD:path` or any other git command to restore linter-corrupted files** — the working tree has uncommitted changes that would be lost; use the Edit tool to surgically remove the corrupted lines instead
- Never reimplement helpers listed in HELPERS section
- Sequential single-file edits for dependent files; parallel only for independent work
- No blind edit retry loops on "oldString not found" — verify exact match, stop after 2 failures
- No RALPH/ULW loops unless OP explicitly requests
- Stop on failure: 2 identical tool failures OR 3 identical error patterns

---

## ERROR RECOVERY
1. Single failure → retry with adjusted approach
2. Two failures → consult Oracle or ask OP
3. Three failures → revert to working state, document attempts
4. Never leave code broken after failed attempt

---

## errno → kXR → HTTP (quick reference)
| errno | kXR | HTTP |
|---|---|---|
| ENOENT | kXR_NotFound | 404 |
| EACCES/EPERM | kXR_NotAuthorized | 403 |
| EINVAL | kXR_ArgInvalid | 400 |
| EIO | kXR_IOError | 500 |
| ENOMEM | kXR_NoMemory | 507 |

---

## BUILD & TEST
```bash
# Build (full when config/source list changes)
./configure --with-stream --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)
make -j$(nproc) # incremental
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf # validate
```

```bash
# Test (single → keyword → full suite)
PYTHONPATH=tests pytest tests/test_X.py::Class::test_name -v
PYTHONPATH=tests pytest tests/ -k "keyword" -v
PYTHONPATH=tests pytest tests/ -v --tb=short
TEST_CROSS_BACKEND=nginx  pytest tests/test_X.py -v # cross-backend (nginx vs xrootd)
tests/manage_test_servers.sh start|restart|stop
```

**Logs:** `/tmp/xrd-test/logs/` — `error.log`, `xrootd_access*.log`, `http_webdav_access.log`, `s3_access.log`

## BUILD GOVERNANCE (read before editing)

**The build is governed by two things — and only two:**

1. **`src/config/config.h`** — the module's source list, config fields, and command declarations.
   Every new source file or header you add must be registered in `config.h` (`NGX_ADDON_SRCS`).
   If your change introduces a new `.c` file, `./configure` will not compile it unless it appears here.
2. **nginx's `./configure`** — the top-level configure script from nginx.org source that picks up
   this module via `--add-module=$REPO`. It generates Makefiles and object files in the nginx build tree.

**What agents should NOT do:**
- **Do NOT edit generated Makefiles.** They live in `/tmp/nginx-1.28.3/objs/Makefile` (or similar) and are
   fully regenerated by `./configure`. Editing them is a no-op — the next configure run overwrites everything.
- **Do NOT patch nginx's own source files** (`src/core/`, `src/event/`, `src/http/`, etc.). All module changes stay
   inside this repository (`src/` directory). If you need to change how nginx behaves, do it through the
   module's hooks and callbacks — not by modifying nginx's internals.
- **Do NOT run `./configure` unless** you added a new source file (not in `config.h`), a new top-level config block,
   or changed `--with-*` options. Incremental builds use `make -j$(nproc)` alone.

---

## RECIPES (step-by-step implementation patterns)
**New WebDAV method:** `src/webdav/op.c` → declare `webdav.h` → register `dispatch.c` → update Allow header test → `make` → 3 tests
**New XRootD opcode:** `src/<sub>/op.c` → register `handshake/dispatch_<type>.c` → constants `protocol/opcodes.h`/`wire.h` → `./configure`+`make` → 3 tests
**New metric:** enum `metrics.h` → field `metrics_internal.h` → export `src/metrics/<sub>.c` → `XROOTD_<TYPE>_METRIC_INC(slot)` at callsite
**New config directive:** field `src/config/config.h` (`NGX_CONF_UNSET`) → `ngx_command_t` `src/config/directives.c` → merge in `merge_*_conf()` — no `./configure` unless new top-level block

---

## FAQ (nginx-specific patterns)

| Question | Answer |
|---|---|
| Alloc? | HTTP: `ngx_palloc(r->pool,sz)` · Stream: `ngx_alloc(sz,log)` · Zero: `ngx_pcalloc` — never raw malloc. Free: `ngx_pool_cleanup_add(pool,size)` |
| ngx_str_t? | NOT null-terminated; use `.len`. No strcpy/strlen. Null-term: `char z[s.len+1]; ngx_memcpy(z,s.data,s.len); z[s.len]=0;` |
| Async I/O? | Event-loop only. No wait/sleep/read. Use `ngx_thread_pool_run` (`src/aio/`) or timers |
| Send response? | Build `ngx_chain_t` of `ngx_buf_t`; never raw write/send. HTTP: `r->headers_out.status=X; r->headers_out.content_length_n=n; ngx_http_send_header(r); return ngx_http_output_filter(r,&chain);` |
| Stream ctx? | `xrootd_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module)` |
| HTTP loc conf? | `ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module)` |
| Conf merge? | main→srv→loc. Check `NGX_CONF_UNSET` in merge |
| File handles? | 0–255 → `xrootd_file_t` in `src/connection/fd_table.c` |
| Log strings from wire? | `xrootd_sanitize_log_string()` — escapes control bytes, quotes, backslashes, non-ASCII to `\xNN` |

---

## TLS buffer layout (quick copy)
```c
ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(*b));
b->pos = b->start = data; b->last = b->end = data + len;
b->memory = 1; b->last_buf = 1;  // TLS: memory-backed
// Cleartext: set b->file for sendfile instead
```

---

## DEBUG
```bash
XRD_LOGLEVEL=Debug xrdcp root://localhost:11094//file /tmp/out # wire trace
error_log /tmp/xrd-test/logs/debug.log debug; # nginx debug (server block)
```

| Symptom | Check | Command |
|---|---|---|
| Connection refused | Port listening? | `ss -tlnp \| grep 1094` |
| Auth failure | Cert/token valid? | `openssl x509 -in cert.pem -noout -dates` |
| Permission denied | ACL logic | `src/path/acl.c` |

---

## CODE STYLE
Smaller well-documented files with focused responsibilities. Use existing helpers and patterns. New concepts require docs+tests in same PR. Code must compile and pass tests — no placeholders or stubs. Add comments explaining intent; section-level WHAT/WHY/HOW blocks preferred over minimal documentation. Consistent formatting and naming conventions. Avoid clever tricks; prefer clarity.

---

## CLARIFICATION PROTOCOL
Only ask if critically underspecified or blocked. ONE question per turn. Different questions each time. Proceed with defaults during execution — don't wait for user input unless blocking.
