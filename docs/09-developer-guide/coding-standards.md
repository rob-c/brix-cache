# Coding Standards for nginx-xrootd

**Status:** AUTHORITATIVE and MANDATORY — this is *the* coding standard for the
project. Every agent or contributor making changes under `src/` or `client/`
must follow it; it is referenced from [`AGENTS.md`](../../AGENTS.md) (auto-loaded
as `CLAUDE.md`) so it is picked up on every session. Where this document and any
older note disagree, this document and the code in `src/` / `client/` win.
(`code-style.md` is now a short pointer here.)
**Applies to:** All `.c` and `.h` files under `src/` and `client/`, plus test
files under `tests/`.

**Two project-wide mandates, called out up front:**
1. **No `goto`** anywhere in `src/` or `client/` — use early-return and helper decomposition (§4).
2. **Functional and modular by design** — small single-purpose functions, explicit
   data flow, pure helpers with side effects at the edges, composition over large
   stateful procedures (§8).

---

## 1. File Structure

### Size and Focus

- **Smaller files are preferred.** Each file should have a single, focused responsibility.
- Files split by job (e.g., `src/fs/cache/fetch.c`, `src/fs/cache/evict.c`) over monolithic modules.
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
| EINVAL | `kXR_ArgInvalid` (3000) | 400 |
| EIO | `kXR_IOError` (3007) | 500 |
| ENOMEM | `kXR_NoMemory` (3008) | 507 |

### No `goto` — FORBIDDEN (no exceptions)

**`goto` must not appear in any `.c` or `.h` file under `src/` or `client/`.**
This is a [HARD BLOCK](../../AGENTS.md#hard-blocks-non-negotiable): new code that
introduces `goto` will not be accepted, and existing `goto` is to be refactored
out as files are touched. `goto` defeats the functional, modular design this project targets —
it hides control flow, couples cleanup to call sites, and makes a function
impossible to reason about (or test) in isolation. Every `goto` idiom has a
functional replacement; the three that cover essentially all real cases are below.

> **Migration status:** `src/` is now `goto`-free (verified). The standard now
> also covers `client/` (the clean-room native client + `libxrdc`), which still
> carries ~70 `goto` sites — OpenSSL/socket single-exit cleanup ladders —
> concentrated in `client/lib/copy.c`, `proxy.c`, `sec/sec_gsi.c`, `http.c`,
> `sec/sec_krb5.c`, `aio.c`, and `ops_file.c`. These are a **refactor-on-touch**
> backlog: when you edit one of those functions, convert it to early-return +
> helper decomposition per Recipe 1/2 (the OpenSSL-cleanup-without-`goto` pattern
> lives in `src/auth/crypto/scoped.h`). Do not add new `goto` anywhere under `src/` or
> `client/`.

#### Recipe 1 — single-resource cleanup (`goto done` / `goto cleanup`)

Acquire one resource, do work, free on every exit. Replace the cleanup label by
**confining the resource to the smallest scope that owns it** — usually a helper
that acquires, uses, and releases linearly, returning the computed value:

```c
/* BEFORE: goto done */                  /* AFTER: linear, single owner */
ctx = EVP_MD_CTX_new();                  rc = digest_into(out, in, len);   /* helper owns ctx */
if (!ctx) { rc = NGX_ERROR; goto done; } return rc;
if (EVP_DigestInit(ctx,...)!=1) goto done;
...                                      /* helper body: acquire -> use -> free -> return,
done:                                       with one cleanup before each early return, or a
    EVP_MD_CTX_free(ctx);                    single owned resource freed once at the end. */
    return rc;
```

When a helper genuinely owns exactly one resource and frees it once before
returning, that is **not** `goto` and is fine — the point is that control flow is
linear and the resource never escapes the function that frees it.

#### Recipe 2 — multi-resource / multi-step cleanup (`goto round_fail`, two-tier)

A long function that acquires many resources and jumps to a shared cleanup on any
error (e.g. `client/lib/copy.c`'s 25 `goto close_remote`/`done`/`finish` sites) is
the signal to **decompose into sequential single-purpose helpers**. Each helper owns its
resources, frees them on its own error paths, and returns `NGX_OK`/`NGX_ERROR`;
the orchestrator is a flat early-return sequence:

```c
/* AFTER: one function per step; each is independently testable */
rc = gsi_round1_derive_secret(t, body, dlen, &secret, &secret_len);
if (rc != NGX_OK) return rc;                       /* round1 freed its own temporaries */

rc = gsi_round1_encrypt_inner(secret, secret_len, chain, &enc, &enc_len);
if (rc != NGX_OK) { ngx_free(secret); return rc; }

rc = gsi_round2_build_and_send(t, fd, client_kp, enc, enc_len);
ngx_free(secret); ngx_free(enc);
return rc;
```

If a chain of owned buffers makes the caller messy, bundle them in a small
context struct with one `*_cleanup(ctx)` function and call it once on the single
return — but prefer decomposition first. For pool-tracked allocations, register
`ngx_pool_cleanup_add()` so the pool frees them and no manual cleanup is needed.

#### Recipe 3 — parser loop control (`goto next` / `goto next_param`)

Jumping to the next iteration of a parse is just a loop. Use `continue` in a
`for`/`while`, or extract the per-item body into a helper called in the loop:

```c
/* BEFORE: goto next */            /* AFTER: continue */
for (;;) {                         for (i = 0; i < n; i++) {
    if (skip_this) goto next;          if (skip_this(item[i])) continue;
    ... handle ...                     handle_one(item[i]);   /* or inline */
 next: advance();                  }
}
```

There is no allowed `goto` case. If you believe a function cannot be expressed
without `goto`, that function is too large — split it (Recipe 2).

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

### Shared-Memory Zones (MANDATORY)

nginx initialises **every** `shared_memory` zone as an `ngx_slab_pool_t`, and its SIGCHLD handler runs `ngx_unlock_mutexes()` on **every child death** — that routine walks `ngx_cycle->shared_memory` *unconditionally* and dereferences `((ngx_slab_pool_t *) zone.shm.addr)->mutex` for each zone. A zone whose `init` callback lays its own struct directly over `shm.addr` clobbers that slab header, so the **master SIGSEGVs the instant any worker exits** (this was a real codebase-wide bug).

- **Never** cast `shm_zone->shm.addr` to anything but `ngx_slab_pool_t`, and **never** `ngx_memzero(shm.addr, …)`. The slab header lives there and must survive.
- Allocate the table **from** the slab pool via `xrootd_shm_table_alloc()` (`src/core/compat/shm_slots.h`), and size the zone with `xrootd_shm_zone_size()`. The helper handles fresh-alloc / reload / re-attach, builds the process-local mutex from the table's first member (an `ngx_shmtx_sh_t lock`; pass `NULL` for lock-less atomic-only tables), and publishes the table via `shm_zone->data`. Initialise non-lock fields only when `*fresh` is set.
- The reference pattern is `src/ratelimit/ratelimit_zone.c` (view the slab pool, then `ngx_slab_alloc`).

This contract is enforced two ways: `tests/test_shm_slab_safety_lint.py` (static — fails CI if any zone clobbers `shm.addr` or skips the slab-safe allocator) and `tests/test_shm_fork_safety.py` (runtime — SIGKILLs workers across every protocol's zones and asserts the master survives).

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

## 8. Functional & Modular Design

This project is written in C but is designed to be **as functional and modular as
possible**. Code is built from small, single-purpose functions with explicit
inputs and outputs and linear control flow — not large stateful procedures.
These principles are the reason `goto` is banned (§4) and small focused files are
required (§1); they are the primary lens for code review.

### Core principles (MANDATORY)

1. **One responsibility per function.** A function does one nameable thing. If you
   cannot describe it in the summary doc-line without "and", split it. A function
   that needs `goto` to manage its own complexity is too big — decompose it
   (§4 Recipe 2).
2. **Explicit data flow — pass state, don't reach for it.** Take what you need as
   parameters (`ctx`, `c`, `conf`, the buffer, the length) and return the result
   or an `ngx_int_t` status. Do not introduce new mutable file-scope/global state;
   the per-connection `xrootd_ctx_t` is the one shared state object and it is
   passed explicitly. Never communicate between functions through hidden globals.
3. **Prefer pure helpers; isolate side effects.** Computation (parse, encode,
   validate, map errno→kXR) should be in helpers that take inputs and return
   outputs with no I/O. Keep the side effects (socket send, file I/O, metric
   increment, logging) at the edges, in the handler/orchestrator. Pure helpers are
   trivially unit-testable and reusable across protocols.
4. **Return values over out-of-band control.** Functions return `NGX_OK`/
   `NGX_ERROR`/`NGX_AGAIN` (or a typed result); callers branch with early-return
   (§4). No `goto`, no `longjmp`, no error flags smuggled through shared state.
5. **Compose small functions; orchestrators stay flat.** A handler reads as a
   short, linear sequence of `rc = step(...); if (rc != NGX_OK) return ...;`. The
   complexity lives in the named steps, each independently reviewable and testable.
6. **Table/descriptor-driven over branch ladders.** Express variation as data, not
   `if/else` chains: the opcode dispatch table, the `op_table` namespace-op
   descriptors (`src/path/`), the table-driven metric exporter (`src/metrics/`),
   and the directive tables (`src/stream/module.c`) are the models. New families of
   similar operations should add a descriptor row, not a new branch.
7. **Reuse shared helpers; never reimplement.** Path resolution, auth gating,
   error mapping, response framing, and metrics each have ONE implementation
   (see the helper table below and the AGENTS.md HELPERS list). Calling the shared
   helper — not copying its logic — is what keeps the codebase uniform.
8. **Idempotent, side-effect-honest naming.** A function's name says what it does
   and whether it mutates: `xrootd_resolve_*`/`*_parse_*`/`*_map_*` compute;
   `xrootd_send_*`/`*_on_*`/`*_handle_*` act. Don't hide a send or a free inside a
   function named like a pure query.

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
- Use `ngx_thread_pool_run` (`src/core/aio/`) or timers for blocking operations.
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
| Error triplet | `log_access()` → `XROOTD_OP_ERR()` → `send_error()` | §4 |
| `goto` | **FORBIDDEN** — early-return + helper decomposition | §4 (3 recipes) |
| Functional/modular | one job per function, explicit data flow, pure helpers | §8 |
| Helpers | never reimplement path/auth/metrics/framing | AGENTS.md HELPERS section |
| Doc blocks | WHAT/WHY/HOW sections mandatory | this document §3 |
| Tests | deterministic output, no xfail | this document §10 |
