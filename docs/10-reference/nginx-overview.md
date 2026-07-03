# nginx programming concepts for this module

> ⚠️ **Reference tier — contributor-focused.** nginx architecture decisions that shape how the module is structured. Useful when adding features or debugging; not needed to operate a server.
>
> Prerequisites: [XRootD Basics](../02-concepts/brix-basics.md), basic understanding of C programming.

The nginx architecture decisions that shape how this module is structured — and, critically, what nginx provides for free that any standalone server (including the official XRootD daemon) must implement from scratch.

The two most common questions from new contributors are:

- **Why is `root://` support in the `ngx_stream_*` subsystem?**
- **Why is `davs://` support in the `ngx_http_*` subsystem?**

The answer to both requires understanding nginx's internal architecture first.

---

## Sub-pages

- [Stream module: why root:// lives here](nginx-stream-module.md)
- [HTTP module: why davs:// lives here](nginx-http-module.md)
- [nginx internals: event loop, buffers, TLS, shared memory, config, hot reload](nginx-internals.md)

---

## 1. The nginx process model

nginx runs as a small cluster of OS processes:

```
master process  (root)
    │
    ├── worker process 0  (nginx user, event loop)
    ├── worker process 1  (nginx user, event loop)
    ├── worker process N  (nginx user, event loop)
    │
    └── cache manager process  (nginx user, background)
```

**What the master process does:**
- Reads and validates the config file at startup
- Binds privileged ports (< 1024) before dropping to the nginx user
- Forks worker processes and keeps them alive (restarts on crash)
- Receives OS signals (`SIGHUP` = reload config, `SIGQUIT` = graceful stop)
- Coordinates hot-reload: starts new workers before draining the old ones so
  no connections are ever dropped during a config change

**What each worker process does:**
- Runs a single-threaded event loop (epoll on Linux)
- Accepts connections from the shared listening socket
- Processes all I/O without blocking — ever
- Never calls `fork()` or creates threads (except for the configured thread pool)

**What this means for this module:**
The module's C code runs entirely inside the worker process. Privileged port
binding, signal handling, process supervision, config file watching — none of
these need to be written. nginx handles them all.

For comparison: the official XRootD daemon has its own process manager
(`XrdSupervisor`), its own signal handling, its own config reload logic, and
its own privilege-dropping code. That is thousands of lines of infrastructure
code that BriX-Cache simply does not need.

---

## 2. The two subsystems: stream and HTTP

nginx has two completely separate subsystems for handling TCP connections:

| Subsystem | nginx.conf block | nginx type constant | What it understands |
|---|---|---|---|
| **Stream** | `stream { server { … } }` | `NGX_STREAM_MODULE` | Raw TCP bytes; optional TLS |
| **HTTP** | `http { server { … } }` | `NGX_HTTP_MODULE` | HTTP/1.1 framing, methods, headers, status codes, body |

They are compiled as separate modules and cannot be mixed in one `server {}`
block. A connection is either a raw stream or an HTTP request — never both at
the same time on the same port.

---

## 15. Summary: nginx vs implementing from scratch

| What is needed | Implementing from scratch | Using nginx |
|---|---|---|
| Event-driven I/O | Write epoll/kqueue loop | `epoll` event loop is nginx core |
| TLS | Wire OpenSSL state machine | `ngx_ssl_handshake()` — 1 function |
| HTTP framing (WebDAV) | Parse request line, headers, body | `ngx_http_request_t` — pre-parsed |
| Config file system | Parser, inheritance, types | `ngx_command_t` + merge callbacks |
| Memory management | Custom allocator or malloc/free | `ngx_pool_t` — pool-based, zero leaks |
| Cross-process metrics | mmap + atomic + shmget | `ngx_shared_memory_add()` |
| Thread pool for blocking I/O | pthreads, work queue, sync | `ngx_thread_task_post()` |
| Process lifecycle | fork, exec, signal, setuid | nginx master process |
| Hot reload | Connection draining + re-exec | nginx `SIGHUP` — built-in |
| Access logging | Log format, rotation, buffering | `access_log` directive |
| Connection limits | Per-IP counting, shared state | `limit_conn_zone` directive |
| Virtual hosting | SNI parsing, Host matching | `server_name` directive |
| Upstream proxying | TCP client, connection pool | `proxy_pass` directive |
| Sendfile zero-copy | `sendfile(2)` + scatter/gather | File-backed `ngx_buf_t` |
| **Total LOC for above** | **~50,000–100,000 C lines** | **~0 C lines** |

That 0 is not an exaggeration. Every item in the table is configuration or a
single API call in the module code. The module's ~97,000 lines of C are
exclusively protocol logic (XRootD wire format, GSI handshake, JWT validation,
VO ACL matching, TPC rendezvous, S3 SigV4) and storage logic (path confinement,
`pread`/`pwrite` dispatch, cache management).

---

## Related docs

- [architecture.md](../10-architecture/overview.md) — end-to-end request lifecycle for both modules
- [types.md](types.md) — `brix_ctx_t` and config struct field reference
- [development.md](../09-developer-guide/dev-workflow.md) — AIO pattern, build workflow, configure vs make
- [contributing.md](../09-developer-guide/contributing.md) — step-by-step guides for adding opcodes and WebDAV methods
- [comparison-with-xrootd.md](../10-reference/design-rationale.md) — developer-hours comparison and deployment decision matrix
- [optimizations.md](../09-developer-guide/optimizations.md) — sendfile, zero-copy, and buffer chain design decisions
