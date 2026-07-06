# Architecture: request lifecycle

Traces a single XRootD request from TCP connection arrival to the last response byte leaving the socket. Read it alongside the source code — file names link to the corresponding directories.

---

## Mental Model For New nginx Developers

nginx has a few ideas that show up everywhere in this module:

| nginx concept | How to think about it in this project |
|---|---|
| Master process | Starts workers, owns config reloads, does not handle client I/O directly |
| Worker process | Single-threaded event loop that accepts sockets and runs handlers |
| `stream {}` | Raw TCP layer; used for native XRootD `root://` and `roots://` |
| `http {}` | HTTP request layer; used for WebDAV `davs://`, S3-compatible HTTP, and metrics |
| `ngx_connection_t` | The live socket plus read/write events and send functions |
| `ngx_stream_session_t` | nginx's per-connection stream session wrapper |
| `ngx_http_request_t` | nginx's per-HTTP-request object for WebDAV, S3, and metrics |
| Pool allocation | Memory tied to a connection/request lifetime; cheap, but not free |
| Module context | Our per-connection or per-request state attached to nginx objects |
| Thread pool | Optional worker threads for blocking disk I/O, not protocol parsing |

The key rule: nginx workers must not block for long. A worker may be handling
thousands of sockets, so a slow disk read in the event loop delays unrelated
clients. This module therefore tries to keep protocol parsing and response
construction on the worker, while large or potentially slow file I/O can move
through nginx thread pools.

nginx module code also tends to split configuration by lifecycle:

| Phase | What happens |
|---|---|
| Config parsing | Directives are read and stored in `ngx_stream_brix_srv_conf_t` or the relevant HTTP location conf |
| Postconfiguration | SSL contexts, module hooks, and shared settings are finalized |
| Worker init | Per-worker timers or runtime objects can be started |
| Connection/request runtime | `brix_ctx_t` or WebDAV request context carries live state |

If you are new to nginx, this explains why the code does not look like a
single blocking server loop. There is no `while (accept()) { read(); write(); }`
in the module. nginx owns accept, event polling, timers, memory pools, and most
socket details; the module supplies handlers.

---

## Mental Model For ROOT/XRootD Developers

From the client side, native XRootD feels like a stateful file protocol:

```
connect → handshake → protocol → login → auth → open → read/readv/pgread → close
```

The server does not receive "read `/store/a.root`" on every read. It receives an
open request first, returns a small file-handle byte, and later reads reference
that handle. The module stores those handles in `ctx->files[]`.

ROOT users usually see this through higher-level APIs:

```cpp
TFile::Open("root://host//store/a.root");
```

or through `xrdcp`. In both cases the XRootD client library emits the same
wire-level operations: `kXR_open`, `kXR_read`, `kXR_stat`, `kXR_close`, and
occasionally `kXR_readv` or paged-read/write operations. BriX-Cache implements
the storage protocol; it does not inspect the ROOT object model.

WebDAV is different. `davs://` clients use HTTP methods:

```
GET /store/a.root
PUT /store/new.root
HEAD /store/a.root
PROPFIND /store/
```

That means the code path is different too: native XRootD requests enter under
`src/protocols/root/connection/`, `src/protocols/root/handshake/`, `src/protocols/root/read/`, and `src/protocols/root/write/`; WebDAV
requests enter through nginx HTTP and land under `src/protocols/webdav/`.

---

## Which Code Path Handles My URL?

| URL | nginx block | Main state object | Main source directories |
|---|---|---|---|
| `root://host//path` | `stream { server { brix_root on; } }` | `brix_ctx_t` | `connection/`, `handshake/`, `session/`, `read/`, `write/` |
| `roots://host//path` | `stream { listen ... ssl; brix_root on; }` or native TLS upgrade | `brix_ctx_t` plus `c->ssl` | same native path, with TLS in `connection/tls.c` |
| `http://host/path` | `http { location { brix_webdav on; } }` | `ngx_http_brix_webdav_req_ctx_t` | `webdav/` |
| `https://host/path` | `http { listen ... ssl; location { brix_webdav on; } }` | `ngx_http_brix_webdav_req_ctx_t` plus `r->connection->ssl` | `webdav/`, plus nginx HTTP SSL |
| `davs://host/path` | XRootD client WebDAV mode over HTTPS; same nginx block as `https://` WebDAV | `ngx_http_brix_webdav_req_ctx_t` plus `r->connection->ssl` | `webdav/`, plus nginx HTTP SSL |
| `s3://host/bucket/key` in clients, or `https://host/bucket/key` on the wire | `http { location { brix_s3 on; } }` | `ngx_http_request_t` plus `ngx_http_s3_loc_conf_t` | `s3/` |
| `/metrics` | `http { location { brix_metrics on; } }` | HTTP request | `metrics/` |

When debugging, start by identifying both the URL scheme and the configured
nginx location. A `davs://` URL is WebDAV over HTTPS from nginx's point of
view. S3 clients also use HTTP(S) on the wire, but a location with
`brix_s3 on;` dispatches to `src/protocols/s3/` instead of `src/protocols/webdav/`. A
`root://` bug and an HTTPS/WebDAV/S3 bug may touch the same filesystem, CA
bundle, and user credential, but they travel through different nginx modules
and different code.

```text
                         accepted socket
                               |
                +--------------+--------------+
                |                             |
            stream{}                        http{}
                |                             |
      +---------+---------+        +----------+----------+
      |                   |        |          |          |
   root://             roots://   WebDAV      S3      metrics
      |                   |        |          |          |
 raw XRootD        TLS, then raw   HTTP       HTTP       HTTP
 request frames    XRootD frames   methods    S3 API     GET
      |                   |        |          |          |
      +---------+---------+        |          |          |
                |                  |          |          |
          brix_ctx_t       WebDAV req   S3 loc    counters
                |              ctx         conf
                |                  |          |
                +------------------+----------+
                                   |
                       VFS data plane (src/fs/)
                 confinement · metrics · cache · CRC
                                   |
                  POSIX storage driver (src/fs/backend/)
                    pread / pwrite / sendfile / fstat
                                   |
                           filesystem and logs
```

All four file-serving protocols converge on **one** data plane: the protocol
handler populates an `brix_vfs_ctx_t` and calls the VFS (`src/fs/`), which applies
confinement, metrics, caching and page-CRC once, then calls the storage driver
(`src/fs/backend/`, POSIX by default) for the raw syscall — so the data path is
`proto → VFS → backend` for `root://`, WebDAV, and S3 alike. See the [data-plane section of the architecture
overview](overview.md#the-data-plane-one-path-for-every-byte-proto--vfs--posix) and
[`src/fs/README.md`](../../src/fs/README.md).

---

## Protocol-specific lifecycle docs

- [**Request-lifecycle sequence diagrams**](request-lifecycle-sequences.md) — call-ladder diagrams for all four protocols (root/davs/S3/CMS), each step annotated with the real `function() (file.c:line)`
- [Native XRootD stream](stream.md) — state machine, file handles, handlers, backpressure, AIO, auth flow, key source files
- [WebDAV request lifecycle](webdav.md) — HTTP dispatch, auth gate, GET/PUT paths
- [S3 request lifecycle](s3.md) — SigV4 auth gate, method routing, multipart staging

---

## Design rationale

- [**Reliability under load**](reliability-under-load.md) — load-induced failure modes observed in the official XRootD stack (XrdCl sync-call deadlock, dirlist framing corruption, CMS-heartbeat-drop false NotFound, per-request token-crypto stalls) and the module's event-loop / caching / availability-biased-selection mitigations for each

---
