# Architecture

This document has been split into focused sub-pages. All content is preserved.

- [Overview and mental models](architecture/index.md) — new-nginx and XRootD developer perspectives, code-path routing
- [Native XRootD stream](architecture/stream.md) — state machine, file handles, handlers, backpressure, AIO, auth flow
- [WebDAV request lifecycle](architecture/webdav.md) — HTTP dispatch path, TPC routing, GET/PUT detail
- [S3 request lifecycle](architecture/s3.md) — SigV4 auth, method routing, multipart staging layout
