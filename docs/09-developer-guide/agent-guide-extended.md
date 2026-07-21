# Agent Guide — Extended Prose (moved out of CLAUDE.md v3.6)

Verbatim long-form text moved out of the root `CLAUDE.md` (2026-07-15) to keep the
per-call context cost down. The root file keeps the compressed, load-bearing form;
this file preserves the full original wording so no detail is lost.

---

## SMALL-MODEL USAGE

CLAUDE.md is a **lookup reference**, not memorization material. If your context window is limited:

1. **Search by section header** — use `grep` or `read_file` with line ranges to pull only what you need
2. **OP→FILE tables are the fastest entry point** — search keywords, get file paths immediately
3. **HELPERS section is mandatory** — never reimplement functions listed there
4. **INVARIANTS + HARD BLOCKS are critical** — read these before writing code
5. **FAQ for nginx-specific patterns** — alloc, ngx_str_t, async I/O, response building

**Token-efficient shorthand:**
- `ngx_palloc` / `ngx_alloc` → HTTP/Stream allocation (never raw malloc)
- `.len` + `ngx_memcpy` → ngx_str_t operations (no strlen/strcpy)
- `ngx_chain_t` of `ngx_buf_t` → response building (never raw write/send)
- `NGX_OK/NGX_ERROR/NGX_DONE` → error codes

---

## INVARIANT 10 — SHM mutexes (full text)

**SHM mutexes = spin+yield, NEVER the POSIX-semaphore mode.** Every module shared-memory table mutex MUST be created via `brix_shm_table_alloc()` / `brix_shm_table_mutex_create()` (`src/core/compat/shm_slots.c`), which clears `mtx->semaphore` after `ngx_shmtx_create()`. Stock `ngx_shmtx_create(…, NULL)` silently enables a POSIX semaphore whose wakeup path is **lost-wakeup-prone under high cross-worker contention**: a worker blocks in `sem_wait` forever with the lock already free (`*lock==0, *wait==0`), freezing the whole worker (it stops running its event loop) and stalling every connection pinned to it. This hit the hot `kXR_open` path (`brix_handle_mutex`) and caused 60–450s multi-worker connection stalls. Our critical sections are µs-held fixed-slot scans, so spin+yield is correct and cheaper. See [postmortem-shmtx-semaphore-stall.md](postmortem-shmtx-semaphore-stall.md).

---

## INVARIANT 11 — VFS storage plane (full text)

**Storage plane ≈ `proto → VFS → backend`. The VFS is the SOLE source of storage truth — bytes AND namespace AND metadata.** (a) **Byte data**: proto handler → VFS (`src/fs/`) → storage driver (`src/fs/backend/`, POSIX default); raw `pread`/`pwrite`/`preadv`/`copy_file_range`/`fstat`/`sendfile` on file data live ONLY in `src/fs/backend/` (tier-1, HARD rule). `root://` read/write/readv/pgread/pgwrite/sync/truncate → `brix_vfs_io_execute()` (`vfs_io_core.c`); WebDAV/S3 GET → `brix_vfs_open()`+`brix_vfs_file_sendfile_fd()`+`brix_vfs_close()`. (b) **Namespace + metadata (phase-62)**: every handler reaches `open`/`stat`/`opendir`/`unlink`/`rename`/`mkdir`/`truncate`/`chmod`/**xattr** on an export path through `brix_vfs_*` — `brix_vfs_probe` (non-metered existence/type), `brix_vfs_stat`/`statf`, `brix_vfs_open_fd`/`_at`, `brix_vfs_{get,set,list,remove}xattr` + fd variants `brix_vfs_f{get,set,list,remove}xattr`, `brix_vfs_unlink_path`/`_at`/`mkdir_path`/`rename_path`/`walk` — never a raw libc call. **Only raw FS left in handlers:** (i) non-export resources (config/cert/token, `/tmp` creds, `/dev/null`, `/proc`, sockets) and (ii) SEPARATE svc-owned storage domains (read-through cache, upload stage dir, FRM control/journal, S3 multipart staging, checkpoint journal) which MUST stay raw-as-worker — the VFS confines to ONE export root + routes to the impersonation broker as the mapped user, the wrong root/identity for those. Each such raw call carries a same-line `/* vfs-seam-allow: <reason> */` marker. `*_confined_canon` primitives take the ABSOLUTE path (they strip root_canon themselves — never pre-strip). **Guard `tools/ci/check_vfs_seam.py`** (3 tiers; tier-2 backlog `vfs_seam_backlog.txt`=0, tier-3 ns backlog `vfs_seam_backlog_ns.txt`=0; `--regen` only after a deliberate migration). Driver = capability-typed pluggable seam (`brix_sd_driver_t`, `src/fs/backend/sd.h`): an object/S3 backend can become primary without changing anything above it. See [src/fs/README.md](../../src/fs/README.md), [src/fs/backend/README.md](../../src/fs/backend/README.md), [phase-62 closure doc](../refactor/phase-62-vfs-namespace-metadata-seam-closure.md).

---

## BUILD GOVERNANCE (full text)

**The build is governed by two things — and only two:**

1. **the repo-root `./config`** — the module's source lists (`ngx_module_srcs`), header dep
   lists, and feature gates. Every new `.c` file must be added to the appropriate
   `$ngx_addon_dir/src/…` list here or `./configure` will not compile it.
   (`src/core/config/config.h` holds the module's config STRUCT fields + command
   declarations — it is NOT the source list.)
2. **nginx's `./configure`** — the top-level configure script from nginx.org source (the build
   tree at `/tmp/nginx-1.28.3`) that picks up this module via `--add-module=$REPO`. It
   generates Makefiles and object files in the nginx build tree.

**What agents should NOT do:**
- **Do NOT edit generated Makefiles.** They live in `/tmp/nginx-1.28.3/objs/Makefile` (or similar) and are
   fully regenerated by `./configure`. Editing them is a no-op — the next configure run overwrites everything.
- **Do NOT patch nginx's own source files** (the NGINX BUILD TREE's `/tmp/nginx-1.28.3/src/core/`,
   `/tmp/nginx-1.28.3/src/event/`, `/tmp/nginx-1.28.3/src/http/` — not to be confused with this repo's `src/core/`).
   All module changes stay inside this repository. If you need to change how nginx behaves,
   do it through the module's hooks and callbacks — not by modifying nginx's internals.
- **Do NOT run `./configure` unless** you added a new source file (not in `./config`), a new top-level config block,
   or changed `--with-*` options. Incremental builds use `make -j$(nproc)` alone.

---

## CODE STYLE headlines (full text)

Smaller well-documented files with focused responsibilities. **No `goto`** — early-return + helper decomposition. **Functional + modular** — one job per function, explicit data flow (pass `ctx`, no new globals), pure helpers with side effects at the edges, table/descriptor-driven dispatch over branch ladders. Use existing helpers and patterns — never reimplement path/auth/metrics/framing. New concepts require docs+tests in same PR. Code must compile and pass tests — no placeholders or stubs. Section-level WHAT/WHY/HOW doc blocks on every function. Consistent formatting and naming. Avoid clever tricks; prefer clarity.

(`src/`, `shared/`, and `client/` are all `goto`-free as of 2026-06-26 — the former `client/`
OpenSSL/socket cleanup-ladder backlog has been fully burned down; keep it that way.)

---

## ERROR RECOVERY (full text)

1. Single failure → retry with adjusted approach
2. Two failures → consult Oracle or ask OP
3. Three failures → revert to working state, document attempts
4. Never leave code broken after failed attempt

## CLARIFICATION PROTOCOL (full text)

Only ask if critically underspecified or blocked. ONE question per turn. Different questions each time. Proceed with defaults during execution — don't wait for user input unless blocking.

---

# Sections moved verbatim from CLAUDE.md v3.7 → v3.8 compaction (2026-07-15)

The following sections were removed from the root `CLAUDE.md` to cut per-call context
cost. They are preserved here in full — grep by section header exactly as before.

## SRC TOPOLOGY (phase-66, 2026-07-02 — seven concept buckets) — full block
```
src/core/           platform primitives: compat/ types/ config/ shm/ aio/ + ngx_brix_module.h
                    + http/ (shared HTTP semantics: headers/body/conditionals/etag/query/
                    xml/file-response — security-load-bearing)
src/protocols/      one subdir per wire protocol: root/ (connection/ session/ protocol/
                    handshake/ read/ write/ zip/ stream/ handoff/ relay/ response/ path/)
                    webdav/ s3/ cvmfs/ ssi/ srr/ dig/ shared/
src/fs/             storage plane (VFS = sole storage truth): vfs/ core/ backend/ tier/
                    xfer/ path/ cache/ scan/
src/auth/           identity + authz: gsi/ token/ sss/ krb5/ pwd/ unix/ host/ voms/
                    crypto/ authz/ (acl + acc engine) impersonate/
src/net/            clustering/proxying/shadowing: cms/ manager/ upstream/ proxy/
                    ratelimit/ tap/ mirror/ guard/ httpguard/
src/observability/  metrics/ pmark/ dashboard/ accesslog/
src/tpc/            third-party-copy: engine/ (parse/launch/done/key registry)
                    outbound/ (source-session client) gsi/ common/
```
Cross-dir includes are **src-rooted** (`#include "auth/gsi/parse.h"`); same-dir stay bare.
Full mapping: [phase-66-map.tsv](../refactor/phase-66-map.tsv).

## ROUTING
| Proto | Layer | Entry | Test Port |
|---|---|---|---|
| `root://` / `roots://` | stream | `src/protocols/root/connection/handler.c`→`src/protocols/root/handshake/dispatch.c` | anon=11094 GSI=11095 TLS=11096 Token=11097 |
| `davs://` (GSI+TLS) | http | `src/protocols/webdav/dispatch.c`→method handler | 8444 |
| `davs://` / `http://` (no GSI) | http | `src/protocols/webdav/dispatch.c`→method handler | 8443 |
| `cvmfs://` (HTTP) / `scvmfs://` (TLS, experimental) | http | `src/protocols/cvmfs/handler.c` | site-config (e.g. 3128 / 8443); tests 12831–12902 |
| S3 REST | http | `src/protocols/s3/handler.c`→method handler | 9001 |
| `/metrics` | http | `src/observability/metrics/stream.c`/`writer.c` | 9100 |

## OP→FILE (search keywords → get files)

### STREAM (`src/protocols/root/` prefix unless a full `src/…` path is given)
| Keyword | Files |
|---|---|
| handshake / dispatch | `handshake/dispatch.c`, `dispatch_session.c` |
| auth (GSI/token/SSS) | `session/login.c`, `src/auth/gsi/parse_x509.c`, `src/auth/token/validate.c`, `src/auth/sss/` |
| protocol lifecycle | `session/protocol.c`, `lifecycle.c` |
| bind / session | `session/bind.c`, `registry.c` |
| acl / policy / voms | `handshake/policy.c`, `src/auth/authz/acl.c`, `authdb.c`, `src/auth/voms/` |
| open / close / stat | `read/open_cache.c`, `close.c`, `stat.c`, `statx.c` |
| read / readv / pgread | `read/read.c`, `readv.c`, `pgread.c`, `src/core/aio/` |
| write / pgwrite / sync | `write/write.c`, `pgwrite.c`, `sync.c` |
| rename / mkdir / rm | `write/mv.c`, `mkdir.c`, `rm.c`, `fattr/` |
| dirlist / locate / clone | `dirlist/handler.c`, `read/locate.c`, `clone.c` |
| native tpc | `src/tpc/engine/` (`key_registry.c`, `launch.c`, `parse.c`, `done.c`), `src/tpc/outbound/` (`thread.c`, `io.c`, `source.c`), `src/tpc/gsi/` |
| cms / manager / cluster | `src/net/manager/registry.c`, `src/net/cms/send.c`, `src/net/upstream/` |

### HTTP (`src/protocols/webdav/` prefix unless noted)
| Keyword | Files |
|---|---|
| unified config / storage directives | `src/core/config/http_common.c` (bare `brix_export`/`brix_storage_backend`/`brix_cache_store`/`brix_cache_evict_*`/`brix_cache_verify` — shared by webdav/s3/cvmfs), `src/protocols/shared/proto_exclusive.c` (one brix protocol per location+port) |
| routing / proxy | `dispatch.c`, `proxy.c`, `postconfig.c` |
| methods (GET/PUT/etc) | `get.c`, `put.c`, `namespace.c`, `move.c`, `copy.c`, `propfind.c`, `lock.c` |
| auth / tpc | `auth_cert.c`, `auth_token.c`, `tpc.c`, `tpc_curl.c`, `tpc_cred.c`, `tpc_headers.c` |
| helpers | `path.c`, `resource.c`, `io.c`, `fd_cache.c`, `headers.c` |
| s3 dispatch | `src/protocols/s3/handler.c`, `auth.c`, `util.c` |
| s3 ops | `src/protocols/s3/object.c` (GET/PUT), `list_objects_v1.c`/`list_objects_v2.c`, `multipart_initiate.c`+`multipart_complete_*.c`, `operation_table.c` |
| guard / bad-actor / fail2ban | `src/net/httpguard/*`, `src/net/guard/*` (pure-C core), `src/protocols/root/relay/relay_guard.c`, `deploy/fail2ban/` |
| cvmfs:// site cache (+ scvmfs://) | `src/protocols/cvmfs/module.c`, `handler.c`, `gate.c`, `classify.c`, `geo.c`, `request.c`, `upstreams.c`, `origin_geo.c`, `origin_probe.c`, `secure.c`, `src/fs/cache/verify.c` (cvmfs-cas), `fill_retry.c`, `src/protocols/shared/http_cache_fill.c` (coalescing+hold) |

## HELPERS (MUST USE — NEVER REIMPLEMENT)
| Function | Purpose |
|---|---|
| `ngx_http_brix_webdav_resolve_path(path)` | Canonical+confined path |
| `brix_open_confined_canon(fd, path)` | Confined fd open |
| `webdav_verify_proxy_cert(cert_path)` | Valid GSI cert → NGX_OK |
| `webdav_verify_bearer_token(token_str)` | Valid JWT → NGX_OK |
| `brix_token_check_scope(scope, path)` | Scope grants access → NGX_OK |
| `webdav_tpc_find_header(headers, name)` | Find header in linked list |
| `webdav_add_cors_headers(r)` | Add Access-Control-* headers |
| `webdav_metrics_return(status_bytes, proto)` | Increment bytes_sent metric |
| `BRIX_PROXY_METRIC_INC(op, status)` | Increment request counter |
| `webdav_check_locks(path)` | NGX_OK or 423 |
| `webdav_copy_fds(src_fd, dst_fd)` | copy_file_range for TPC |

## INVARIANTS 1–9 + 11 (full text; 10 and 12 have their own sections above)

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
9. CRC64: `crc64`=CRC-64/XZ, `crc64nvme`=CRC-64/NVME — DIFFERENT polys. Engine `src/core/compat/crc64.c`; root://+WebDAV emit 16-hex, S3 emits base64-of-8-BE-bytes (encode at the edge, never in the kernel). See [crc64-checksums.md](../10-reference/crc64-checksums.md)

**Architecture:**
11. Native TPC = SHM key registry (`src/tpc/engine/key_registry.c`) — cross-process, zero-copy; WebDAV TPC = curl COPY with Source/Credential headers (`src/protocols/webdav/tpc.c`)

## HARD BLOCKS (full text)
- **NO `goto`** anywhere in `src/`, `shared/`, or `client/` (`.c`/`.h`) — early-return + helper decomposition ([coding-standards §4](coding-standards.md#no-goto--forbidden-no-exceptions)). New `goto` rejected; refactor existing `goto` out of any function you touch (all three trees are `goto`-free since 2026-06-26 — keep it that way).
- **Functional + modular code** — one responsibility per function, pass state explicitly (no new globals), pure helpers with side effects at the edges ([coding-standards §8](coding-standards.md#8-functional--modular-design)).
- **NEVER run ANY git write command (commit, add, mv, rm, stash, reset, checkout, clean, rebase, push, merge, etc.) without explicit OP approval IN THE CURRENT CONVERSATION** — a skill saying "commit", a /goal directive, or a memory note does NOT count as approval. Read-only git (status/log/diff/show/grep/ls-files) is fine. Enforced by `ask` rules in `.claude/settings.json`; bypassing or weakening them is itself a violation. These commands destroy uncommitted work — yours AND concurrent sessions' (2026-07-07: two concurrent sessions cross-contaminated each other's commits via unasked `git add`/`git commit`).
- **NEVER use `git show HEAD:path` or any git command to restore linter-corrupted files** — the working tree has uncommitted changes that would be lost; use Edit to surgically remove the corrupted lines instead
- Never reimplement helpers listed in HELPERS section
- Sequential single-file edits for dependent files; parallel only for independent work
- No blind edit retry loops on "oldString not found" — verify exact match, stop after 2 failures
- No RALPH/ULW loops unless OP explicitly requests
- Stop on failure: 2 identical tool failures OR 3 identical error patterns

## errno → kXR → HTTP
| errno | kXR | HTTP |
|---|---|---|
| ENOENT | kXR_NotFound | 404 |
| EACCES/EPERM | kXR_NotAuthorized | 403 |
| EINVAL | kXR_ArgInvalid | 400 |
| EIO | kXR_IOError | 500 |
| ENOMEM | kXR_NoMemory | 507 |

## BUILD & TEST (full command block)
```bash
# Build (full only when config/source list changes)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)
make -j$(nproc) # incremental
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf # validate

# Test (single → keyword → full suite)
PYTHONPATH=tests pytest tests/<test-file>.py::Class::test_name -v
PYTHONPATH=tests pytest tests/ -k "keyword" -v
PYTHONPATH=tests pytest tests/ -v --tb=short
TEST_CROSS_BACKEND=nginx pytest tests/<test-file>.py -v # cross-backend (nginx vs xrootd)
(cd tests && python3 -m cmdscripts.manage_test_servers start-all|restart|stop-all|status)
```
**Logs:** `/tmp/xrd-test/logs/` — `error.log`, `brix_access*.log`, `http_webdav_access.log`, `s3_access.log`

## RECIPES
**New WebDAV method:** `src/protocols/webdav/<op>.c` → declare `webdav.h` → register `dispatch.c` → update Allow header test → `make` → 3 tests
**New XRootD opcode:** `src/protocols/root/<sub>/op.c` → register `protocols/root/handshake/dispatch_<type>.c` → constants `protocols/root/protocol/opcodes.h`/`wire.h` → add to `./config` → `./configure`+`make` → 3 tests
**New metric:** enum `metrics.h` → field `metrics_internal.h` → export `src/observability/metrics/<sub>.c` → `BRIX_<TYPE>_METRIC_INC(slot)` at callsite
**New protocol:** ONE row in `src/core/types/proto_list.h` (append-only!) → enum+labels/dashboard/JSON buckets all generate; then follow the checklist in that header
**New config directive:** field `src/core/config/config.h` (`NGX_CONF_UNSET`) → `ngx_command_t` in owning module's table (`src/protocols/root/stream/module_definition.c` stream / `src/protocols/webdav/module_directives.c` WebDAV) → merge in `merge_*_conf()` — no `./configure` unless new top-level block. Unified storage names (`brix_export`/`brix_storage_backend`/`brix_cache_*`) are owned ONCE in `src/core/config/http_common.c` (field on `common.*`) — add shared names there, not per-protocol.

## FAQ (nginx-specific patterns)
| Question | Answer |
|---|---|
| Alloc? | HTTP: `ngx_palloc(r->pool,sz)` · Stream: `ngx_alloc(sz,log)` · Zero: `ngx_pcalloc` — never raw malloc. Free: `ngx_pool_cleanup_add(pool,size)` |
| ngx_str_t? | NOT null-terminated; use `.len`. No strcpy/strlen. Null-term: `char z[s.len+1]; ngx_memcpy(z,s.data,s.len); z[s.len]=0;` |
| Async I/O? | Event-loop only. No wait/sleep/read. Use `ngx_thread_pool_run` (`src/core/aio/`) or timers |
| Send response? | Build `ngx_chain_t` of `ngx_buf_t`; never raw write/send. HTTP: `r->headers_out.status=X; r->headers_out.content_length_n=n; ngx_http_send_header(r); return ngx_http_output_filter(r,&chain);` |
| TLS buffer? | `b->pos=b->start=data; b->last=b->end=data+len; b->memory=1; b->last_buf=1;` (cleartext: set `b->file` for sendfile instead) |
| Stream ctx? | `brix_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_brix_module)` |
| HTTP loc conf? | `ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module)` |
| Conf merge? | main→srv→loc. Check `NGX_CONF_UNSET` in merge |
| File handles? | 0–255 → `brix_file_t` in `src/protocols/root/connection/fd_table.c` |
| Log strings from wire? | `brix_sanitize_log_string()` — escapes control bytes, quotes, backslashes, non-ASCII to `\xNN` |
| Config reload? | Standard nginx drain. `config_generation`/`config_version` in `/healthz` + `brix_config_generation` gauge confirm. Certs/keys/keytabs rotate **on reload**; slot-count changes reset the SHM table (WARN). Matrix: [reload-semantics.md](reload-semantics.md) |

## DEBUG
```bash
XRD_LOGLEVEL=Debug xrdcp root://localhost:11094//file /tmp/out # wire trace
error_log /tmp/xrd-test/logs/debug.log debug; # nginx debug (server block)
```
| Symptom | Command |
|---|---|
| Connection refused | `ss -tlnp \| grep 1094` |
| Auth failure | `openssl x509 -in cert.pem -noout -dates` |
| Permission denied | ACL logic: `src/auth/authz/acl.c` |
| Conn stalls under concurrency (multi-worker) | `ss -tn 'sport = :PORT'` (Recv-Q>0=read-side); `cat /proc/PID/wchan` (`do_epoll_wait`=idle/lost-notify vs `futex_do_wait`=blocked on a lock) |
| Worker frozen / armed timer never fires | `gdb -p WORKER -batch -ex "thread apply all bt"`; stuck `ngx_shmtx`: print `*lock`/`*wait` — 0/0 + thread in `sem_wait` = lost semaphore wakeup → see postmortem |

**Full symptom-indexed runbook:** [troubleshooting-runbook.md](../05-operations/troubleshooting-runbook.md) — every previously-diagnosed failure mode (orphaned-worker lock poisoning, dead FUSE mounts, fleet desync after rebuild, xdist crashes, bare-nginx configure, port lookup). Test ports: [test-fleet-ports.md](../10-reference/test-fleet-ports.md).
