# Contributing to nginx-xrootd

nginx-xrootd is an nginx stream module that speaks the XRootD `root://` wire
protocol and serves files over WebDAV (`davs://`). It is used in production
at CERN and other HEP computing sites as a drop-in replacement for the native
xrootd daemon. See [`docs/02-concepts/xrootd-basics.md`](docs/02-concepts/xrootd-basics.md) for an XRootD
protocol primer if this is your first encounter with the project.

---

## Read these first

Work through these five documents in order before writing any code. Each one
builds on the previous.

1. [`docs/10-reference/design-rationale.md`](docs/10-reference/design-rationale.md) — request lifecycle, state
   machine, and entry points. Start here to understand how a TCP byte becomes a
   file operation.
2. [`docs/10-reference/types.md`](docs/10-reference/types.md) — the three core types (`xrootd_ctx_t`,
   `xrootd_file_t`, `ngx_stream_xrootd_srv_conf_t`) and their field-by-field
   semantics. You will reference this constantly.
3. [`docs/09-developer-guide/contributing.md`](docs/09-developer-guide/contributing.md) — step-by-step mechanics for
   the two most common contribution tasks: adding an opcode and adding a
   directive. Also contains the code style guide and test requirements.
4. [`docs/10-reference/protocol-notes.md`](docs/10-reference/protocol-notes.md) — wire-format quirks,
   XRootD version differences, and client compatibility notes.
5. [`docs/03-configuration/build-guide.md`](docs/03-configuration/build-guide.md) — how to compile, what flags do, and
   how to run the test suite.

---

## Quick task guide

| What you want to do | Where to start |
|---|---|
| Add a new XRootD opcode | [`docs/09-developer-guide/contributing.md`](docs/09-developer-guide/contributing.md) §1 |
| Add a new nginx directive | [`docs/09-developer-guide/contributing.md`](docs/09-developer-guide/contributing.md) §2 |
| Add or change auth | [`docs/06-authentication/auth-overview.md`](docs/06-authentication/auth-overview.md) |
| Write a handler (response API, AIO) | [`docs/10-reference/handler-reference.md`](docs/10-reference/handler-reference.md) |
| Run tests / set up test PKI | [`docs/09-developer-guide/dev-workflow.md`](docs/09-developer-guide/dev-workflow.md) |
| Understand the metrics exporter | [`docs/08-metrics-monitoring/monitoring-guide.md`](docs/08-metrics-monitoring/monitoring-guide.md) |
| Understand the WebDAV / S3 surface | [`docs/04-protocols/webdav-overview.md`](docs/04-protocols/webdav-overview.md) |
| Understand the CMS manager mode | [`docs/05-operations/manager-mode.md`](docs/05-operations/manager-mode.md) |

---

## Quick orientation

```
src/
  protocol/   — wire-format constants and structs (read this first)
  types/      — core type definitions (xrootd_ctx_t etc.)
  connection/ — TCP state machine and event wiring
  handshake/  — request dispatch (dispatch.c and four dispatch_*.c files)
  session/    — login, auth, bind, lifecycle
  read/       — open, stat, read, readv, pgread, close, dirlist, locate
  write/      — write, sync, mkdir, rm, truncate, chmod, mv, fattr, set
  path/       — path resolution, ACL enforcement, access logging
  aio/        — thread-pool async I/O helpers
  gsi/        — GSI x509 authentication
  token/      — JWT/WLCG bearer-token authentication
  sss/        — simple shared-secret (Blowfish) authentication
  tpc/        — third-party copy (WebDAV COPY with Source: header)
  cache/      — read-through origin cache
  metrics/    — Prometheus counter exporter
  stream/     — nginx module glue (directive table, lifecycle hooks)
```

Each directory has a `README.md` explaining its purpose and key files.
