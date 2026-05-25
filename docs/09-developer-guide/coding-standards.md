# Coding Standards for nginx-xrootd

**Location:** `docs/09-developer-guide/coding-standards.md`
**Applies to:** All `.c` and `.h` files under `src/`, plus test files under `tests/`.
**Reference:** See also [`code-style.md`](code-style.md) for the detailed style rules; this document is the authoritative summary.

---

## 1. File Structure

### Size and Focus

- **Smaller files are preferred.** Each file should have a single, focused responsibility.
- Files split by job (e.g., `src/cache/fetch.c`, `src/cache/evict.c`) over monolithic modules.
- If a file exceeds ~500 lines, consider whether it owns more than one concept and split accordingly.

### Directory Organization

```text
src/
  protocol/   — wire-format constants and structs (read this first)
  types/      — core type definitions (one typedef per file)
  connection/ — TCP state machine and event wiring
  handshake/  — request dispatch
  session/    — login, auth, bind, lifecycle
  read/       — open, stat, read, pgread, close, dirlist
  write/      — write, sync, mkdir, rm, truncate, chmod, mv
  path/       — path resolution, ACL enforcement
  aio/        — thread-pool async I/O helpers
  gsi/        — GSI x509 authentication
  token/      — JWT/WLCG bearer-token authentication
  sss/        — shared-secret authentication
  tpc/        — third-party copy
  cache/      — read-through origin cache
  metrics/    — Prometheus counter exporter
  stream/     — nginx module glue (directive table, lifecycle hooks)
  webdav/     — WebDAV HTTP handlers
  s3/         — S3-compatible REST handlers
```

Each directory has a `README.md` explaining its purpose and key files. New subdirectories must include one.

### Header Files

- Use `#pragma once` (not traditional include guards).
- Each `.h` file defines exactly **one concept** — one struct, one enum, or one set of related constants.
- Include prerequisites explicitly in the doc block at the top: "Requires: X, Y, Z before inclusion."
- Do not forward-declare unrelated types; only declare what this file needs.

---

## 2. Naming Conventions

### Function Prefixes (MANDATORY)

| Pattern | Where it applies | Example |
|---|---|---|
| `xrootd_handle_*` | Top-level opcode handlers called from dispatch | `xrootd_handle_open()`, `xrootd_handle_read()` |
| `xrootd_send_*` | Response formatting functions | `xrootd_send_error()`, `xrootd_send_ok()` |
| `xrootd_dispatch_*` | Dispatch plumbing (handshake/) | `xrootd_dispatch_login()` |
| `xrootd_on_*` | nginx event callbacks (connection/) | `xrootd_on_recv()`, `xrootd_on_disconnect()` |
| `xrootd_try_post_*` | Functions that may post to the AIO thread pool | `xrootd_try_post_read()` |
| `XROOTD_OP_*` | Per-opcode metric slot constants (metrics/) | `XROOTD_OP_READ`, `XROOTD_OP_ERR` |
| `kXR_*` | XRootD wire-protocol constants | `kXR_open`, `kXR_ok` |
| `ngx_stream_xrootd_*` | nginx module public symbols | `ngx_stream_xrootd_module` |

### Type Naming

- Structs: `xrootd_ctx_t`, `xrootd_file_t`, `xrootd_state_t` — descriptive name + `_t`.
- Enums: `xrootd_state_t` (typedef'd enum) — same naming pattern.
- Config structs: `ngx_stream_xrootd_srv_conf_t` — nginx module prefix + role suffix.

### Variable Naming

- **Descriptive names with units or role:** `body_bytes`, `range_start`, `response_cursor`, `owned_base`, `handle_index`.
- Avoid generic single-letter names (`p`, `q`, `n`, `idx`) outside very small loops.
- Cursor/walker variables: explicit `cursor`, `start`, `end`, and `length` — never implicit pointer arithmetic without named bounds.

### Test Naming

- Files: `test_<feature>.py` (e.g., `test_file_api.py`, `test_webdav.py`).
- Classes: `Test<Feature>` (e.g., `TestFileCreate`, `TestDirList`).
- Methods: `test_<scenario>` (e.g., `test_create_new_file`, `test_dirlist_nonexistent_fails`).

---

## 3. Documentation

### Section-Level Doc Blocks (MANDATORY)

Every function — public and static — must have a section-level doc block before its definition with three explicit sections:

```c
/* ---- Function purpose summary line ----
 *
 * WHAT: What the function does, in one or two sentences. Includes return values.
 *
 * WHY: Why this function exists — the problem it solves or the invariant it maintains.
 *
 * HOW: Step-by-step description of the algorithm (numbered list).
 */
static ngx_int_t
xrootd_handle_open(...)
```

**Rules:**

- **WHAT** includes return values and success/failure conditions.
- **WHY** explains the design rationale, not just a restatement of WHAT.
- **HOW** is a numbered step list describing the algorithm flow.
- The summary line (before `*`) describes the function in one sentence — copyable for quick reference.

### Inline Comments

- Write comments about **why**, not what. A reader can see what the code does; they cannot see the wire-format quirk, the subtle invariant, or the past bug that makes the code look the way it does.
- Good: `/* XRootD clients send dlen == 0 for kXR_ping; skip payload accumulation. */`
- Bad: `/* Check if dlen is zero */`
- Keep comments concise and local to the rule they explain.

### Doc Blocks for Files

- Every source file starts with a doc block describing what the file owns, why it exists separately, and its relationship to sibling files.
- Directory-level `README.md` files must list each file's responsibility in a table.

---

## 4. Error Handling

### Return Early (MANDATORY)

```c
/* Good */
rc = xrootd_resolve_path(ctx, c, conf, path, resolved, sizeof(resolved));
if (rc != NGX_OK) {
    return rc;
}

/* Bad — swallowed */
xrootd_resolve_path(ctx, c, conf, path, resolved, sizeof(resolved));
```

### Error Access Log Triplet

Every error path must call these three in order before returning:

1. `xrootd_log_access()` — structured access log line with operation name and status
2. `XROOTD_OP_ERR()` — increment the per-opcode error metric counter
3. `xrootd_send_error()` — wire or HTTP response with appropriate kXR/HTTP code

The three always travel together. No exception.

### Error Code Mapping

| errno | kXR code | HTTP status |
|---|---|---|
| ENOENT | `kXR_NotFound` (3011) | 404 |
| EACCES/EPERM | `kXR_NotAuthorized` (3010) | 403 |
| EINVAL | `kXR_ArgInvalid` (3006) | 400 |
| EIO | `kXR_IOError` (3012) | 500 |
| ENOMEM | `kXR_NoMemory` (3013) | 507 |

### Goto Usage

The code-style guide states "do not use goto." In practice, goto is used in **two allowed contexts**:

1. **Cleanup at function exit** — when multiple resources must be freed on failure and early returns would duplicate cleanup code (e.g., `src/cache/writethrough_flush.c`, `src/tpc/gsi_outbound_exchange.c`). Label: `failed` or `done`.
2. **Loop control in parser state machines** — jumping to the next parsing step within a single function (e.g., `src/s3/auth_sigv4_canonical.c` → `next_param`, `src/compat/range_vector.c` → `next`).

**Forbidden:** goto across functions, goto into the middle of a block from outside, goto that bypasses meaningful state changes.

**Total current usage: 89 goto statements across 16 files.** All are in tpc/, gsi/, token/, cache/, s3/, proxy/, and compat/ subdirectories — modules with complex multi-resource lifetimes or parser loops. Core handler files (read.c, write.c, stat.c) use early-return exclusively.

---

## 5. Allocation

### Pool Allocation (HTTP requests)

`ngx_palloc(r->pool, sz)` — freed when the connection/request closes. Use for any allocation that lasts the lifetime of a single request but does not need to outlive the connection.

### Raw Allocation

`ngx_alloc(size, log)` — raw malloc; you own it. Use only when:
- The allocation must outlive the pool (reusable buffers across requests)
- The allocation needs explicit free before connection closes (e.g., checkpoint paths)

**Rule:** Never call `ngx_alloc` from inside an AIO `_thread` function — that runs in a worker thread and `c->log` is not thread-safe. Allocate from the main event loop before posting the task.

### Zero-Fill

`ngx_pcalloc(r->pool, sz)` — allocated + zero-filled. Use when struct fields need clean initialization.

### AIO Completion Guard

In AIO completion callbacks (`_done`), always check `ctx->destroyed` before touching any connection-owned memory. The connection may have been torn down while the thread was running.

---

## 6. ngx_str_t Operations

- **NOT null-terminated.** Use `.len`. No strcpy/strlen.
- For null-term conversion: `char z[s.len+1]; ngx_memcpy(z, s.data, s.len); z[s.len] = 0;`
- Comparison: `ngx_strncmp()` or `ngx_strcmp()` — never raw memcmp with guessed length.

---

## 7. Response Building

### HTTP Responses

Build `ngx_chain_t` of `ngx_buf_t`; never raw write/send.

```c
r->headers_out.status = NGX_HTTP_OK;
r->headers_out.content_length_n = body_len;
ngx_http_send_header(r);
return ngx_http_output_filter(r, &chain);
```

### TLS Buffers

`b->memory = 1` only — memory-backed buffers.

```c
ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(*b));
b->pos = b->start = data;
b->last = b->end = data + len;
b->memory = 1;
b->last_buf = 1;
```

### Cleartext Buffers

File-backed buffers with sendfile. Never mix memory-backed and file-backed in the same chain for a single response.

**Invariant:** TLS: `b->memory=1` only; cleartext: file-backed+sendfile; never mix.

---

## 8. Modular Design

### Helper Functions (MUST USE — NEVER REIMPLEMENT)

The following helpers are shared across modules and must be used instead of reimplementing:

| Function | Purpose |
|---|---|
| `ngx_http_xrootd_webdav_resolve_path(path)` | Canonical+confined path resolution |
| `xrootd_open_confined_canon(fd, path)` | Confined fd open with canonical check |
| `webdav_verify_proxy_cert(cert_path)` | Valid GSI cert → NGX_OK |
| `webdav_verify_bearer_token(token_str)` | Valid JWT → NGX_OK |
| `xrootd_token_check_scope(scope, path)` | Scope grants access → NGX_OK |
| `webdav_tpc_find_header(headers, name)` | Find header in linked list |
| `webdav_add_cors_headers(r)` | Add Access-Control-* headers |
| `webdav_metrics_return(status_bytes, proto)` | Increment bytes_sent metric |
| `XROOTD_PROXY_METRIC_INC(op, status)` | Increment request counter |
| `webdav_check_locks(path)` | NGX_OK or 423 |
| `webdav_copy_fds(src_fd, dst_fd)` | copy_file_range for TPC |

**Rule:** Never reimplement path resolution, auth verification, metrics incrementing, or wire framing. Use the helpers listed above.

### Cross-Protocol Shared Code

WebDAV and S3 share helper functions (path.c, resource.c, io.c). New protocol handlers should use shared helpers rather than duplicating logic.

---

## 9. Anti-Patterns (BLOCKING)

The following patterns are common sources of mistakes and must be avoided:

- One-line `if`/`while` bodies that hide returns, cleanup, or state changes
- Generic names like `p`, `q`, `n`, `len`, `buf`, `idx` outside very small loops
- Macros that parse input, allocate memory, or return from the caller when a normal helper function would be clearer
- Pointer-walking parsers without explicit `cursor`, `start`, `end`, and `length` variables
- Response or AIO buffer ownership that is implied rather than named
- Micro-optimized algorithms that make future protocol/security review harder

**Performance rule:** Prefer the simplest implementation within roughly 90% of a clever alternative. Use complex versions only when benefit is measured, easy to reason about from syscall/allocation counts, or required by protocol correctness. If a hot path needs cleverness, hide it behind a small helper with a descriptive name and document the invariant that keeps it safe.

---

## 10. Test Requirements

### Every PR Must Pass Three Checks

```bash
# 1. Build must be clean (no errors, no new warnings)
cd /tmp/nginx-1.28.3 && make -j$(nproc) 2>&1 | grep -E "error:|warning:"

# 2. Full test suite must be green
pytest tests/ -x -q

# 3. xrdcp round-trip smoke test
xrdcp /etc/hostname root://localhost:1094//tmp/test-smoke.txt
xrdcp root://localhost:1094//tmp/test-smoke.txt /tmp/out.txt
diff /etc/hostname /tmp/out.txt
```

Documentation-only changes (no `.c` or `.h` edits) require only check 1.

### Deterministic Output (HARD REQUIREMENT)

All tests should be deterministic — **one output from the server, ever**. No xfails. Every new feature or major rewrite must have passing tests with one expected output and no `xfail`.

### Test Coverage Requirements

- All new features must be accompanied by new tests.
- New tests should cover full integration of all features with the rest of the module where possible.
- For new opcodes: at least one test for the success path + one test for an expected error path (e.g., path not found, handle not open, write on read-only connection).
- For config directives: one test with directive present + one test testing default behaviour when absent.

### Test Structure Pattern

```python
"""
Module-level docstring describing what the file covers and how to run it.
"""

import pytest
from XRootD import client

# Configuration constants
# Helper functions (private, prefixed with _)
# Fixtures (scope="module" for shared env, autouse=True for cleanup)

class Test<Feature>:
    def test_<scenario>(self):
        """One-sentence docstring describing the scenario."""
        # Setup → action → assert with descriptive message
```

- **Docstrings** on module level and every test method.
- **Assertions** include descriptive messages: `assert status.ok, f"open NEW failed: {status.message}"`.
- **Fixtures** handle setup/cleanup (prefix-based file cleanup before/after each test).
- **Class grouping** by feature area (e.g., `TestFileCreate`, `TestDirList`).

---

## 11. Wire Protocol Invariants

These are non-negotiable correctness requirements:

1. **pgread/pgwrite → kXR_status(4007) framing + per-page CRC32c required.** Every page-mode read and write must include status framing and CRC32c integrity checks.
2. **TLS: `b->memory=1` only; cleartext: file-backed+sendfile; never mix.** Buffer type must match transport layer.
3. **`conf->allow_write` checked globally before token scope.** Write permission gate is first, then scope enforcement.
4. **All wire paths → resolve_path() before open() — no exceptions.** Path resolution and confinement check precedes every file open.

---

## 12. Async I/O

- Event-loop only. No wait/sleep/read in handler functions.
- Use `ngx_thread_pool_run` (`src/aio/`) or timers for blocking operations.
- AIO handlers run in worker threads; allocate before posting, check `ctx->destroyed` on completion.

---

## 13. Metrics

- Labels are **low-cardinality only** — no paths, bucket-names, or UUIDs as labels.
- Metric slot constants: `XROOTD_OP_*` enum in `metrics/metrics.h`.
- Increment at callsite via generated macro: `XROOTD_<TYPE>_METRIC_INC(slot)`.

---

## 14. Code Format

- Brace style: K&R / Allman (open brace on same line for functions, separate line for control flow — follow existing file pattern).
- Indentation: 4 spaces (matching nginx convention).
- Line length: reasonable; wrap long expressions at logical boundaries rather than arbitrary column.
- Trailing commas in struct initializers and array lists where consistent with surrounding code.

---

## Quick Reference

| Concept | Pattern | Source |
|---|---|---|
| Alloc HTTP | `ngx_palloc(r->pool, sz)` | AGENTS.md FAQ |
| Alloc Stream | `ngx_alloc(sz, log)` | AGENTS.md FAQ |
| ngx_str_t | `.len` + `ngx_memcpy`, no strlen/strcpy | AGENTS.md FAQ |
| Response | `ngx_chain_t` of `ngx_buf_t` | AGENTS.md FAQ |
| Error triplet | `log_access()` → `XROOTD_OP_ERR()` → `send_error()` | code-style.md §4 |
| Goto allowed | cleanup at exit, parser loop control | code-style.md §4 + grep evidence |
| Helpers | never reimplement path/auth/metrics/framing | AGENTS.md HELPERS section |
| Doc blocks | WHAT/WHY/HOW sections mandatory | this document §3 |
| Tests | deterministic output, no xfail | this document §10 |
