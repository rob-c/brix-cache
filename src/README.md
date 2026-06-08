# src — nginx-xrootd Source Tree

Core implementation of the nginx-xrootd module, supporting XRootD (`root://`),
WebDAV (`davs://`), and S3 protocols.

## Directory Structure

| Directory | Purpose |
|-----------|---------|
| `aio` | Thread-pool async I/O for read and write handlers |
| `cache` | Read-through cache and write-through origin mirroring |
| `cms` | CMS manager heartbeat client and cluster registration |
| `compat` | Nginx and protocol compatibility layers (CRC32, XML, headers) |
| `config` | Nginx directive parsing, configuration merging, and validation |
| `connection` | TCP connection lifecycle and XRootD state machine |
| `crypto` | Shared cryptographic helpers (HMAC, SHA256) |
| `dashboard` | HTTPS monitoring dashboard implementation |
| `dirlist` | XRootD directory listing and stat collection |
| `fattr` | Extended attribute (`fattr`) support |
| `gsi` | GSI/x509 proxy certificate authentication |
| `handshake` | Initial XRootD connection handshake and request dispatch |
| `manager` | Cluster/Redirector mode and server registry |
| `metrics` | Prometheus metrics exporter and shared counters |
| `path` | Path resolution, sanitization, and ACL enforcement |
| `protocol` | XRootD wire-protocol constants and structures |
| `proxy` | Transparent XRootD proxy logic |
| `query` | `kXR_query` sub-protocol handlers (checksum, space, config) |
| `read` | Read-side XRootD operations (`open`, `read`, `pgread`, `stat`) |
| `response` | XRootD response framing and error helpers |
| `s3` | S3-compatible REST endpoint implementation |
| `session` | XRootD session lifecycle, login, and binding |
| `sss` | Simple Shared Secrets (SSS) authentication |
| `stream` | Main XRootD stream module entry point and configuration |
| `token` | WLCG/JWT bearer token validation |
| `tpc` | Native XRootD Third-Party Copy (pull) |
| `types` | Shared internal type definitions |
| `upstream` | Upstream connection management for proxying |
| `voms` | VOMS attribute parsing and validation |
| `webdav` | WebDAV over HTTPS module implementation |
| `write` | Write-side XRootD operations (`write`, `pgwrite`, `mkdir`, `rm`) |

## Module Architecture

The project is structured as a collection of focused submodules, each with its own
`README.md` explaining its responsibility and file map. The two main entry
points are the **Stream module** (for native XRootD) and the **HTTP module** (for
WebDAV and S3).

- **Stream:** `connection/handler.c` → `handshake/dispatch.c` → `read/`, `write/`, etc.
- **HTTP:** `webdav/dispatch.c` → `webdav/methods/` OR `s3/handler.c` → `s3/`

Shared services like `metrics`, `cache`, and `path` are used by both layers where
applicable.
