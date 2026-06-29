# Architecture — Visual Overview

This document has been consolidated into a single **visual architecture guide** with Mermaid diagrams showing how all components relate.

- **[Architecture Overview (Visual)](../10-architecture/overview.md)** — High-level diagram, deployment modes, request flows, and file reference index

---

## What's Here?

The new overview includes:
- **Mermaid.js architecture diagram** — shows clients → nginx layers → VFS → storage driver (POSIX by default) → filesystem in one visual (every protocol's file I/O takes the same `proto → VFS → backend` path)
- **Protocol comparison table** — XRootD vs WebDAV vs S3 side-by-side
- **Deployment mode diagrams** — standalone, proxy, and perimeter proxy modes
- **Sequence diagram** — native XRootD download request flow (connect → handshake → read → close)

---

## Deep Dive

For code-level details (state machines, file handles, backpressure), see the original architecture docs:
- [Native XRootD stream layer](../10-architecture/stream.md)
- [WebDAV request lifecycle](../10-architecture/webdav.md)
- [S3 request lifecycle](../10-architecture/s3.md)
- [Shared VFS architecture](vfs-shared-architecture.md) — how the storage drivers and I/O verbs are shared between the nginx server (`src/`) and the native clients (`client/`): object model, capability matrix, every data flow, the S3 transport-vtable trick, and the dual-build (`ngx`-free) mechanism
