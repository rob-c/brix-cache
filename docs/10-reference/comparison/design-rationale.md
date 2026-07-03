[← Comparison overview](../design-rationale.md)

## Current upstream XRootD state

Upstream XRootD remains active and is the reference implementation. The official
site describes XRootD as a high-performance, scalable, fault-tolerant framework
for file-based repositories, with a plugin ecosystem and cluster deployments of
very large size.

As of this document's check:

- The XRootD website lists **6.0.1** and **5.9.3** release announcements dated
  2026-05-05.
- The GitHub releases page marks **v6.0.1** as the latest release and also lists
  **v5.9.3**.
- The public documentation set includes a **Release 6.0 and above** Xrd/XRootD
  configuration reference, 6.0 CMS docs, 6.0 Proxy Storage Services docs, 6.x
  monitoring docs, and the XRootD protocol reference.
- The 6.0 configuration reference describes `xrd` as a framework that can load
  multiple application protocols, including `xrootd`, `http`, and `cmsd`, and
  documents many component namespaces such as `acc`, `cms`, `frm`, `ofs`,
  `oss`, `pfc`, `pss`, `sec`, `xrd`, `xrootd`, and `http`.

That breadth is impressive. It is also the reason `nginx-xrootd` can present a
more attractive design for a narrower deployment class: if the site wants a
fast POSIX-backed data service behind nginx, most of XRootD's generality becomes
configuration surface and process inventory rather than direct value.

```text
official XRootD shape

    xrd framework
        |
        +-- xrootd protocol
        +-- http protocol / XrdHttp
        +-- cmsd clustering
        +-- security plugins
        +-- OFS / OSS storage layers
        +-- PSS proxy storage
        +-- PFC cache
        +-- FRM residency tools
        +-- XrdMon monitoring
        +-- site-specific plugins and policy

nginx-xrootd shape

    nginx
      |
      +-- stream{} -> native XRootD module
      +-- http{}   -> WebDAV module
      +-- http{}   -> S3-compatible module
      +-- http{}   -> Prometheus metrics
      |
      +-- local POSIX filesystem
```

The design difference is not "one is good, the other is bad." It is "one is a
general storage framework, while the other is a purpose-built nginx data plane."

---

## Why the nginx-based design is favourable

### 1. nginx is already the edge-service operating model

Many sites already operate nginx for TLS policy, HTTP routing, connection
limits, access logs, reloads, systemd units, rate limiting, IP allow/deny rules,
Prometheus scraping, and reverse-proxy style deployment.

`nginx-xrootd` uses that existing machinery instead of asking operators to run
an additional storage daemon with a separate configuration model.

```text
traditional mixed stack

    clients
      |
      +-- HTTPS/WebDAV ---> nginx or xrootd XrdHttp
      +-- root:// -------> xrootd daemon
      +-- metrics -------> exporter / XrdMon collector / custom tooling
      |
    separate configs, logs, reload semantics, TLS policy, monitoring paths

nginx-xrootd stack

    clients
      |
      +-- HTTPS/WebDAV ---> nginx http{} location
      +-- root:// -------> nginx stream{} server
      +-- S3 HTTP -------> nginx http{} location
      +-- metrics -------> nginx /metrics
      |
    one nginx process model, one TLS/logging/metrics surface
```

That makes the module especially compelling as an edge gateway: the service can
look like the rest of the site's production infrastructure instead of being a
special island.

### 2. The event loop keeps idle and slow clients cheap

The official XRootD scheduler is mature, but it is its own server runtime.
`nginx-xrootd` inherits nginx's core strength: event-driven socket handling.
Connections become active when sockets or posted events are ready; blocking disk
operations can be moved to nginx thread pools.

This is favourable for HEP sites because transfer nodes often see mixed
behavior:

- fast local clients
- slow WAN clients
- TLS clients
- metadata probes
- large sequential reads
- bursty multi-client copies

The design goal is not "never use threads." The design goal is more precise:
use the event loop for protocol and socket readiness, and use worker threads
only for operations that would otherwise block the event loop.

```text
nginx-xrootd hot path

    ready socket event
        |
        v
    parse request in nginx worker
        |
        +-- cheap metadata/syscall path -> respond
        |
        +-- potentially blocking I/O
                |
                v
          nginx thread pool
                |
                v
          posted completion back to worker
                |
                v
          response chain / socket write readiness
```

### 3. The protocol families are separated cleanly

In upstream XRootD, native XRootD, HTTP, security, storage, monitoring, and
cluster behavior live inside a broad plugin-capable framework. That is powerful,
but it can be harder for a new maintainer to see which path owns a request.

In this module the separation is blunt:

| Request | nginx object | Main state | Main code path |
|---|---|---|---|
| native `root://` | `ngx_connection_t` / stream session | `xrootd_ctx_t` | `src/protocols/root/connection/`, `src/protocols/root/handshake/`, `src/protocols/root/read/`, `src/protocols/root/write/` |
| WebDAV `davs://` | `ngx_http_request_t` | WebDAV request ctx | `src/protocols/webdav/` |
| S3-style HTTP | `ngx_http_request_t` | S3 location config/request ctx | `src/protocols/s3/` |
| metrics | `ngx_http_request_t` | shared counters | `src/observability/metrics/` |

That clarity is a design advantage for security review and performance work.
When a regression appears in WebDAV auth-cache reuse, it does not require
understanding native `kXR_auth`. When native `kXR_readv` batching changes, it
does not touch WebDAV `GET`.

### 4. It avoids generality on the hot data path

XRootD's strongest feature is the same thing that can make it heavy for simple
data servers: it can talk to many storage services through OFS/OSS/PSS/PFC
layers and plugins.

`nginx-xrootd` deliberately optimizes the common local-file case:

- cached open-file metadata for native handles
- file-backed nginx buffers for cleartext regular-file reads
- larger native response chunks
- stateful sequential readahead
- direct final-layout packing for `readv`
- `preadv()` batching for adjacent vector ranges
- WebDAV fd cache on keepalive connections
- WebDAV `open()+fstat()` miss path
- WebDAV file-backed output buffers
- spooled-body fast path for WebDAV uploads

```text
focused local-file data path

    open once
      |
      v
    handle stores fd + canonical path + safe cached metadata
      |
      v
    repeated reads avoid rediscovering the file
      |
      v
    response chain points at file slices where transport permits
```

This is the core bet of the project: for a POSIX-backed data server, the fastest
architecture is often the one that removes abstraction from the critical path.

### 5. Observability is modern by default

XRootD's `xrd.monitor` UDP stream will never be implemented here. It is a
fire-and-forget UDP protocol with no delivery guarantees, an undocumented
binary wire format, and a fragile collector ecosystem. Modern operations teams
use Prometheus.

`nginx-xrootd` makes Prometheus a first-class output:

```text
request path
    |
    +-- native op counters
    +-- WebDAV method/status/auth counters
    +-- S3 method/status/auth/range/list counters
    +-- bytes and range counters
    +-- fd-cache counters
    +-- TPC counters
    |
    v
http{} /metrics
    |
    v
Prometheus scrape
```

The exported protocol-specific counters cover native XRootD, WebDAV, and the
S3-compatible endpoint with fixed low-cardinality labels. That is favourable
for teams already using Grafana/Prometheus for the rest of their infrastructure.
The exported protocol-specific counters are the only monitoring output the
module needs to produce.

### 6. nginx gives WebDAV and TLS a better home

Upstream XRootD has `XrdHttp`, and recent release notes show ongoing work in
`XrdHttp`, `XrdHttpTpc`, SciTokens, Macaroons, and XrdClS3. That means HTTP is
alive upstream, but it also means HTTP is one protocol plugin inside the broader
XRootD framework.

In `nginx-xrootd`, HTTP is handled by nginx's native HTTP stack:

- TLS termination is nginx HTTP SSL
- client body buffering/spooling is nginx machinery
- response filters and file buffers are nginx-native
- CORS and HTTP preflight live in the HTTP module
- WebDAV request lifetime uses `ngx_http_request_t`

For a WebDAV-heavy site, this is a natural fit. HTTP does not need to be
translated into a storage-server worldview before being served.

---

## Performance comparison from this repository

The benchmark numbers in this repository compare nginx 1.28.3 plus this module
against **xrootd v5.9.2** on the same host, using 1 GiB local reads and
GSI/x509 authentication. They are not a universal claim about every XRootD
release or every storage device; they are a repeatable local comparison of the
current implementation and the official daemon in a controlled setup.

| Workload | Pattern visible in current results |
|---|---|
| single native `root://` stream | official xrootd is faster in the measured v5.9.2 run; it has less framing and module overhead at the lowest concurrency |
| low-to-mid parallel `davs://` | BriX-Cache is very competitive and wins several measured concurrency points |
| high parallel native `root://` | BriX-Cache overtakes in the measured table as concurrency rises |
| high parallel WebDAV | BriX-Cache wins the measured 32/64 concurrency points and keeps p95 lower in the README table |

The design lesson is favourable to this module: when the workload stops being a
single ideal transfer and starts looking like a real service with many clients,
nginx's event-driven runtime and hot-path reductions become visible.

```text
single transfer
    fixed protocol overhead dominates
    official xrootd may be very strong

many transfers
    scheduler overhead + idle sockets + partial sends matter
    nginx event loop becomes a structural advantage

HTTP/WebDAV transfers
    nginx's native HTTP/TLS machinery becomes a structural advantage
```

See `docs/benchmarks.md` for exact reproduction commands, hardware/software
details, and caveats.

---
