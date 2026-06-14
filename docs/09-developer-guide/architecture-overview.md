# Architecture — Visual Overview

This document has been consolidated into a single **visual architecture guide** with Mermaid diagrams showing how all components relate.

- **[Architecture Overview (Visual)](../10-architecture/overview.md)** — High-level diagram, deployment modes, request flows, and file reference index

---

## What's Here?

The new overview includes:
- **Mermaid.js architecture diagram** — shows clients → nginx layers → filesystem in one visual
- **Protocol comparison table** — XRootD vs WebDAV vs S3 side-by-side
- **Deployment mode diagrams** — standalone, proxy, and perimeter proxy modes
- **Sequence diagram** — native XRootD download request flow (connect → handshake → read → close)

---

## Deep Dive

For code-level details (state machines, file handles, backpressure), see the original architecture docs:
- [Native XRootD stream layer](../10-architecture/stream.md)
- [WebDAV request lifecycle](../10-architecture/webdav.md)
- [S3 request lifecycle](../10-architecture/s3.md)
