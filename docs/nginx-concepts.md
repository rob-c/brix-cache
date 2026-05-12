# nginx concepts

This document has been split into focused sub-pages. All content is preserved.

- [Overview: process model and the two subsystems](nginx/index.md)
- [Stream module: why `root://` lives here](nginx/stream-module.md) — wire protocol, what nginx provides, comparison table
- [HTTP module: why `davs://` lives here](nginx/http-module.md) — WebDAV framing, what nginx provides, comparison table
- [nginx internals](nginx/internals.md) — event loop, buffer chains, TLS, shared memory, config system, hot reload, source layout
