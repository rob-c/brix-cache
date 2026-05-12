[← Contributing overview](index.md)

## 3. Code style guide

### Readability is a correctness requirement

Write C that is easy to read, review, and mechanically parse. This matters for
humans and for coding tools: ambiguous pointer movement, hidden ownership
transfer, clever macros, and over-compressed branches are common sources of
mistakes.

Prefer the simplest implementation that is within roughly 90 percent of the
performance of a clever alternative. Use the more complex version only when the
benefit is measured, easy to reason about from syscall/allocation counts, or
required by protocol correctness. If a hot path needs cleverness, hide it behind
a small helper with a descriptive name and document the invariant that keeps it
safe.

Avoid mistakable anti-patterns:

- one-line `if`/`while` bodies that hide returns, cleanup, or state changes
- generic names like `p`, `q`, `n`, `len`, `buf`, and `idx` outside very small
  loops
- macros that parse input, allocate memory, or return from the caller when a
  normal helper function would be clearer
- pointer-walking parsers without explicit `cursor`, `start`, `end`, and
  `length` variables
- response or AIO buffer ownership that is implied rather than named
- micro-optimized algorithms that make future protocol/security review harder

Use descriptive names that carry units or role: `body_bytes`, `range_start`,
`response_cursor`, `owned_base`, `method_slot`, `status_class`, and
`handle_index` are better than `n`, `p`, or `idx` when the value lives beyond a
tiny loop.

### Comment philosophy

Write comments about **why**, not what.  A reader can see what the code does;
they cannot see the wire-format quirk, the subtle invariant, or the past bug
that makes the code look the way it does.

Good:
```c
/* XRootD clients send dlen == 0 for kXR_ping; skip payload accumulation. */
```

Bad:
```c
/* Check if dlen is zero */
if (ctx->cur_dlen == 0) {
```

Keep comments concise and local to the rule they explain. Short multi-line
comments are fine for protocol invariants, ownership/lifetime rules, or a
performance trade-off; avoid decorative banners and comments that repeat the
syntax.

### Naming conventions

| Pattern | Where it applies |
|---|---|
| `xrootd_handle_*` | Top-level opcode handlers called from dispatch |
| `xrootd_send_*` | Response formatting functions (response/) |
| `xrootd_dispatch_*` | Dispatch plumbing (handshake/) |
| `xrootd_on_*` | nginx event callbacks (connection/) |
| `xrootd_try_post_*` | Functions that may post to the AIO thread pool |
| `XROOTD_OP_*` | Per-opcode metric slot constants (metrics/metrics.h) |
| `kXR_*` | XRootD wire-protocol constants (protocol/opcodes.h, flags.h) |
| `ngx_stream_xrootd_*` | nginx module public symbols (prefixed for nginx naming) |

### Error-return discipline

Return early on error; do not use `goto`; do not silently swallow errors.

```c
/* Good */
rc = xrootd_resolve_path(ctx, c, conf, path, resolved, sizeof(resolved));
if (rc != NGX_OK) {
    return rc;
}

/* Bad — swallowed */
xrootd_resolve_path(ctx, c, conf, path, resolved, sizeof(resolved));
```

Every error path must call `xrootd_log_access` and `XROOTD_OP_ERR` before
returning `xrootd_send_error()`.  The three always travel together.

### Pool allocation lifetimes

`ngx_palloc(c->pool, ...)` — freed when the connection closes.  Use this for
any allocation that should last the lifetime of a single request but does not
need to outlive the connection.

`ngx_alloc(size, log)` — raw `malloc`; you own it.  Use this only when the
allocation must outlive the pool or be freed before the connection closes
(example: `payload_buf` is reused across many requests; `ckp_path` is freed
explicitly at checkpoint commit/rollback).

Never call `ngx_alloc` from inside an AIO `_thread` function — that runs in
a worker thread and `c->log` is not thread-safe.  Allocate from the main
event loop before posting the task.

In AIO completion callbacks (`_done`), always check `ctx->destroyed` before
touching any connection-owned memory.  The connection may have been torn down
while the thread was running.

---

## 4. Test requirements for a pull request

Every PR must pass all three checks:

```bash
# 1. Build must be clean (no errors, no new warnings)
cd /tmp/nginx-1.28.3
make -j$(nproc) 2>&1 | grep -E "error:|warning:"

# 2. Full test suite must be green
cd /path/to/nginx-xrootd
pytest tests/ -x -q

# 3. xrdcp round-trip smoke test
xrdcp /etc/hostname root://localhost:1094//tmp/test-smoke.txt
xrdcp root://localhost:1094//tmp/test-smoke.txt /tmp/out.txt
diff /etc/hostname /tmp/out.txt
```

**Important Test Requirements:**
- **Deterministic output**: ALL tests should be deterministic (one output from the server, EVER).
- **Test coverage**: All new features should be accompanied by new tests.
- **Integration**: New tests should cover the full integration of all features with the rest of the module where possible.

Documentation-only changes (no `.c` or `.h` edits) require only check 1.

For new opcodes: add at least one test to `tests/test_conformance.py` that
exercises the success path and one test that exercises the expected error path
(e.g., path not found, handle not open, write on read-only connection).

For config directives: add a test that starts nginx with the directive
present and one that tests the default behaviour when it is absent.

---
