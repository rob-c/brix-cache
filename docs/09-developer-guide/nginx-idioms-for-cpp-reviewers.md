# nginx idioms for C++ reviewers

A one-page Rosetta Stone for engineers fluent in C++ reading this C codebase. The
language is C, but most of the "what am I looking at?" friction is **nginx**, not
C. This page maps the nginx idioms (and this module's own conventions) to their
C++ equivalents so you can review at speed. Pairs with the authoritative
[coding-standards.md](coding-standards.md); browse the API with
[Doxygen](#browsing-the-code-with-doxygen).

---

## 1. Mental model

This is an **nginx module**, not a standalone server. nginx owns `main()`, the
listening sockets, the epoll **event loop**, and the worker-process model; our
code is a set of **callbacks** nginx invokes (on connect, on readable, on
timer). Think of it as writing handlers for a single-threaded async framework
(closer to Node/asio than to a thread-per-connection server):

- **One worker = one thread = one event loop.** Protocol handlers must **never
  block** (no `sleep`, no blocking `read`, no long CPU). Blocking I/O is offloaded
  to a thread pool (`ngx_thread_pool_run`, see `src/core/aio/`); everything else is
  driven by readiness callbacks and timers. A blocked handler freezes every
  connection on that worker.
- **Per-connection state lives in a context struct**, fetched at the top of each
  handler — this is the module's `this`:
  ```c
  brix_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_brix_module);
  ```
- **Memory is arena-allocated per request/connection** (see §4). There is no
  RAII; lifetimes are tied to nginx pools, which are freed wholesale.

```text
  ONE worker process = ONE thread = ONE epoll loop, driving MANY connections
  ───────────────────────────────────────────────────────────────────────────
        ┌──────────────── nginx event loop (owns main/epoll) ───────────────┐
        │   epoll_wait() ──▶ readable? timer? ──▶ invoke OUR callback        │
        └───────┬─────────────────────────────────────────────▲─────────────┘
                │ calls                                        │ returns
                ▼                                              │
        xrootd handler(ctx, c)   ◀── ctx = get_module_ctx() = our `this`
                │
        ┌───────┼───────────────────────────────────────────┐
        ▼       ▼                       ▼                     ▼
     NGX_OK   NGX_AGAIN            NGX_DONE              blocking I/O?
     done,    "consumed what's     reply already        ngx_thread_pool_run()
     reply    available — call     sent, stop           → runs on a POOL thread,
     sent     me again later"                             loop stays free
                │  ↑                                       │
                └──┘ hand-rolled coroutine suspend/resume  └─▶ completion callback
                     (returns to loop, no thread blocked)      posted back to loop

   ✗ NEVER block here (sleep / blocking read / long CPU) — it freezes EVERY
     connection pinned to this worker. That is the whole game.
```

Entry points to start reading (full map in [AGENTS.md / CLAUDE.md OP→FILE table]):
| Protocol | Entry |
|---|---|
| `root://` (binary, stream) | `src/protocols/root/connection/handler.c` → `src/protocols/root/handshake/dispatch.c` |
| `davs://` / WebDAV (HTTP) | `src/protocols/webdav/dispatch.c` |
| S3 (HTTP) | `src/protocols/s3/handler.c` |

---

## 2. Type cheat-sheet

| nginx / module type | What it is | Closest C++ |
|---|---|---|
| `ngx_str_t` | `{ size_t len; u_char *data; }` — **NOT NUL-terminated** | `std::string_view` (non-owning) |
| `u_char` | `unsigned char` | `uint8_t` |
| `ngx_int_t` / `ngx_uint_t` | platform-word signed/unsigned int | `intptr_t` / `uintptr_t` |
| `ngx_pool_t *` | arena allocator (bump + free-list) | a region/arena; "allocate, never individually free" |
| `ngx_connection_t *` | one TCP connection (fd, log, pool, read/write events) | a `Connection` object |
| `ngx_log_t *` | logger handle threaded through almost every call | `spdlog::logger&` |
| `ngx_buf_t` | one buffer span (memory- or file-backed) | `span<byte>` + a file-region variant |
| `ngx_chain_t` | singly-linked list of `ngx_buf_t` — the output unit | `std::list<span>` / iovec chain |
| `brix_ctx_t *` | **our** per-connection protocol state | the request handler's `this` |
| `ngx_command_t` | one config directive descriptor (name → setter) | a config-binding table row |

`ngx_` = nginx core. `brix_` / `BRIX_` = this module.

---

## 3. Return codes — the status "enum"

nginx functions return a small set of sentinels instead of throwing. Treat them
as a status enum (`std::expected`-style, error-as-value — there are **no
exceptions**):

| Code | Meaning |
|---|---|
| `NGX_OK` (0) | success |
| `NGX_ERROR` (-1) | hard failure |
| `NGX_AGAIN` (-2) | would block / not finished — yield to the event loop, resume later |
| `NGX_DONE` (-4) | finished, response already sent — stop processing |
| `NGX_DECLINED` (-5) | "not mine / not found" — try the next handler |

`NGX_AGAIN` is the one with no C++ analog: it's how a handler says *"I've consumed
what's available; call me again when there's more"* and returns to the loop. A
function that returns `NGX_AGAIN` has **suspended a coroutine by hand**.

The wire protocol has its own error space (`kXR_*` codes in
`src/protocols/root/protocol/opcodes.h`); the boundary maps `errno → kXR → HTTP`
(`src/core/compat/error_mapping.c`, table in the coding standard).

---

## 4. Memory — pools, not RAII

There is no destructor; you allocate from a **pool** whose lifetime nginx owns,
and the whole pool is released at once (request end / connection close).

| Call | Use |
|---|---|
| `ngx_palloc(pool, n)` | allocate `n` bytes (HTTP path: `r->pool`) |
| `ngx_pcalloc(pool, n)` | zeroed allocate |
| `ngx_alloc(n, log)` / `ngx_free(p)` | raw malloc/free (stream path, when not pool-scoped) |
| `ngx_pool_cleanup_add(pool, sz)` | register a destructor-like callback run at pool free |

Rules of thumb for a C++ reader:
- **Never `malloc`/`free` directly** in module code — use the pool calls. (`ngx_alloc`
  is the sanctioned raw path for stream allocations with explicit lifetime.)
- A pointer from `ngx_palloc(r->pool, …)` is valid for the **whole request** and
  needs no free — the pool is the owner. Mentally: every pool alloc is a
  `unique_ptr` owned by the pool, all reset together.
- For OpenSSL / fd / temp-file cleanup that must run deterministically, use
  `ngx_pool_cleanup_add` (the manual equivalent of a destructor) — see
  `src/auth/crypto/scoped.h`.

---

## 5. Strings — `ngx_str_t` is a view, not owned

`ngx_str_t` carries an explicit length and is **not** NUL-terminated. Do not pass
`.data` to `strlen`/`strcpy`/`printf("%s")`.

```c
ngx_str_t s = ...;
/* compare: */            if (s.len == 4 && ngx_strncmp(s.data, "root", 4) == 0)
/* copy n bytes: */       ngx_memcpy(dst, s.data, s.len);
/* need a C string? copy + terminate on the stack: */
char z[s.len + 1]; ngx_memcpy(z, s.data, s.len); z[s.len] = '\0';
```

`ngx_memcpy`/`ngx_memzero`/`ngx_cpystrn` are thin wrappers over libc with nginx
bounds conventions; prefer them for consistency.

---

## 6. This module's own conventions

**Helpers first (mandatory).** Path confinement, auth, metrics, and wire framing
have canonical helpers — never re-implement them. The authoritative list is in
[CLAUDE.md / AGENTS.md "HELPERS"]. The ones you'll see most:

| Helper / family | Role (C++ intuition) |
|---|---|
| `brix_*_beneath(rootfd, rel, …)` | confined filesystem ops via `openat2(RESOLVE_BENEATH)` — **all** path I/O goes through these so nothing escapes the export root (think: a chroot-checked `std::filesystem` wrapper) |
| `brix_resolve_op_path(...)` / `brix_path_resolve_beneath(...)` | extract + validate + confine a wire path before use |
| `brix_extract_path(...)` | pull a path out of a wire payload (strips CGI, rejects embedded NUL) |
| `brix_make_stat_body(...)` / `src/protocols/root/protocol/stat_flags.h` | encode the `kXR_stat` line + flags (single source of truth, shared with the client decoder) |
| `brix_auth_gate(...)` | the access-control choke point |

**Control flow:** **no `goto`** anywhere in `src/`/`client/` (hard rule). Errors
use **early-return**; deep cleanup is decomposed into helpers. Status is returned,
not thrown; "out" results come back via pointer parameters.

**The error/response macros** (legend — these are the few macros worth learning,
expansions in `src/protocols/root/protocol/` and the op headers):

| Macro | Conceptually does |
|---|---|
| `BRIX_RETURN_ERR(ctx, c, op, "OP", path, detail, kXR_code, msg)` | log + bump the op's error metric + send a `kXR_error` reply + `return` |
| `BRIX_RETURN_OK(...)` / `BRIX_OP_OK(ctx, op)` | success-path logging + metric, send OK |
| `BRIX_OP_ERR(ctx, op)` | bump the error metric without sending (caller sends) |
| `BRIX_<TYPE>_METRIC_INC(slot)` | increment a low-cardinality counter |

They exist to make every handler's success/error/metric/log path uniform and
one-line. When reviewing a handler, read them as `return Error(...)` /
`return Ok(...)`.

**Naming:** `snake_case` throughout (as in the C++ standard library). `ngx_`
prefix = nginx core; `brix_` = module functions; `BRIX_` = macros/constants;
`kXR_*` = on-the-wire protocol constants (from the XRootD spec, kept verbatim).

---

## 7. Things that look wrong to a C++ reviewer but aren't

- **No exceptions, no RAII** — by design (nginx is C; errors are values, cleanup
  is pool- or `cleanup_add`-driven).
- **Functions threading `ngx_log_t *log` / `ngx_connection_t *c` everywhere** —
  there's no ambient context object; these are passed explicitly (no globals is a
  hard rule).
- **`ngx_str_t` string compares by length + `ngx_strncmp`** rather than `==` —
  because it's a view, not an owning string.
- **Manual buffer/chain assembly for responses** instead of a stream `<<` — see
  the TLS vs cleartext buffer rules in the coding standard (TLS must be
  memory-backed; cleartext uses file-backed sendfile).
- **Big section-banner doc comments** — being trimmed to concise Doxygen headers;
  treat the first sentence of each as the brief.

---

## Browsing the code with Doxygen

A `Doxyfile` is checked in at the repo root, tuned for C (static functions
included, macro expansion on, include/dir graphs via graphviz). Generate the
browsable HTML (output is git-ignored under `docs/doxygen/html/`):

```bash
doxygen Doxyfile          # or: tools/gen-docs.sh
xdg-open docs/doxygen/html/index.html
```

The landing page is this primer; from there use **Files** (per-directory source
tree), **Data Structures** (the `*_t` structs — start with `brix_ctx_t`), and
the include-dependency graphs to navigate. `EXTRACT_ALL` is on, so every function
appears even before it has a Doxygen comment.
