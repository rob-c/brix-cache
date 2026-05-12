# nginx-xrootd

An nginx module that gives any nginx server native XRootD (`root://`) and
WebDAV (`davs://`) endpoints — the two primary data-transfer paths used across
High Energy Physics at CERN, SLAC, and Fermilab. It also exposes an
S3-compatible HTTP endpoint for XrdClS3-style workloads. One binary, three
protocols, all of nginx's operations tooling behind it.

```text
                         +-----------------+
  xrdcp root://host/...  |                 |  /data/atlas/...  (POSIX)
  ─────────────────────> |                 | ─────────────────>
                         |  nginx-xrootd   |
  xrdcp davs://host/...  |                 |  root://backend:1094
  ─────────────────────> |    (nginx +     | ─────────────────>  (proxy mode)
                         |     module)     |
  aws s3 cp s3://host/.. |                 |  http://dav-backend/  (WebDAV proxy)
  ─────────────────────> |                 | ─────────────────>
                         +-----------------+
                                 |
                         Prometheus /metrics
```

New to XRootD or grid security? Start with
[Background](docs/background.md) and [Architecture](docs/architecture.md).

---

## Three deployment modes

```text
  MODE 1 — Standalone server
  ──────────────────────────
  xrdcp client ──> nginx-xrootd ──> local POSIX filesystem
                       |
                  auth/TLS/metrics handled here

  MODE 2 — XRootD transparent proxy
  ──────────────────────────────────
  xrdcp client ──> nginx-xrootd ──> root://backend (xrdceph, HDFS, tape, ...)
                       |                  ^
                  terminates auth    file-handle translation,
                  & TLS, emits       lazy connect, opaque relay
                  metrics

  MODE 3 — WebDAV perimeter proxy
  ────────────────────────────────
  HTTP client  ──> nginx-xrootd ──> http://internal-dav-server/
  (xrdcp,            |
   browser,     terminates HTTPS,
   rucio)       WLCG token auth,
                metrics
```

Pick the mode that fits your site:

| Situation | Mode |
|---|---|
| Replacing or augmenting an `xrootd` daemon on a storage node | Standalone |
| Adding TLS, auth, or metrics in front of an existing XRootD service | XRootD proxy |
| Exposing xrootd WebDAV through an HTTPS perimeter (WLCG token auth) | WebDAV proxy |

All three modes can run in the same nginx instance. The `stream {}` block
handles native `root://` / `roots://` traffic; the `http {}` block handles
WebDAV, S3, and Prometheus.

---

## Quick start

```bash
# 1. Download nginx source
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz && cd nginx-1.28.3

# 2. Configure with the module
./configure --with-stream --with-http_ssl_module --with-threads \
            --add-module=/path/to/nginx-xrootd

# 3. Build and install
make -j$(nproc) && sudo make install

# 4. Write an nginx.conf (see examples below) and start
nginx -p /prefix -c nginx.conf
```

For a detailed walkthrough with PKI setup, test tokens, and running the test
suite, see [docs/getting-started.md](docs/getting-started.md) and
[docs/building.md](docs/building.md).

---

## Minimal configurations

### Standalone server — native XRootD + WebDAV

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;
events { worker_connections 1024; }

# Native XRootD protocol (xrdcp root://localhost:1094//data/file.root)
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_allow_write on;
    }
}

# WebDAV over HTTPS (xrdcp davs://localhost:8443//data/file.root)
http {
    server {
        listen 8443 ssl;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
        ssl_verify_client   optional_no_ca;
        xrootd_webdav_proxy_certs on;
        location / {
            xrootd_webdav      on;
            xrootd_webdav_root /data;
            xrootd_webdav_cadir /etc/grid-security/certificates;
        }
    }
    server {
        listen 9100;
        location /metrics { xrootd_metrics on; }
    }
}
```

```bash
# Test it
xrdcp /local/file.root root://localhost:1094//data/test.root
xrdcp --allow-http /local/file.root davs://localhost:8443//data/test.root
```

### Transparent XRootD proxy

Place nginx-xrootd in front of an existing XRootD server to add
TLS termination, auth enforcement, and Prometheus metrics without touching
either the client or the backend:

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_proxy on;
        xrootd_proxy_upstream ceph-xrootd.site.example:1094;
    }
}
```

```bash
# Clients connect to nginx — the backend is invisible to them
xrdcp root://nginx.site.example//data/file.root /local/file.root
```

The proxy: authenticates the client locally, lazily connects to the upstream
on the first post-login opcode, translates file handles in both directions,
relays all responses byte-for-byte, and emits per-request metrics and access
logs. See [docs/proxy-mode.md](docs/proxy-mode.md).

### WebDAV perimeter proxy

Terminate HTTPS and WLCG token auth at nginx, forward plain HTTP to an
internal WebDAV server:

```nginx
http {
    server {
        listen 8443 ssl;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;

        location / {
            xrootd_webdav_proxy on;
            xrootd_webdav_proxy_upstream http://internal-dav.site.example:8080;
        }
    }
}
```

---

## Same data, three views

```text
Path on disk:  /data/atlas/run3/AOD.pool.root
                       |
          +------------+------------+
          |            |            |
   root://host/        davs://host/ s3://host/
   /data/atlas/        /data/atlas/ atlas/
   run3/AOD.pool.root  run3/...     run3/AOD.pool.root
          |            |            |
        xrdcp        xrdcp        aws s3 cp
        xrdfs        curl         XrdClS3
        Python        rucio
        XRootD        browser
        client
```

The same POSIX file tree is served over all three protocols simultaneously.
Permissions, checksums, and metadata are consistent across all views. XRootD
`fattr` extended attributes are preserved across all access paths.

---

## Protocol support

| Protocol | Default port | Transport | Use |
|---|---|---|---|
| `root://` (native XRootD) | 1094 | raw TCP | `xrdcp`, `xrdfs`, Python XRootD client |
| `roots://` (TLS-from-first-byte) | 1095 | TLS | `xrdcp` with strict TLS |
| `davs://` (WebDAV over HTTPS) | 8443 | HTTPS | `xrdcp --allow-http`, rucio, browsers |
| S3-compatible HTTP | site-defined | HTTP/HTTPS | XrdClS3, `aws s3` CLI |

---

## Authentication

| Method | Native `root://` | WebDAV `davs://` | S3 |
|---|---|---|---|
| Anonymous | Yes | Yes | Yes |
| GSI / x509 proxy certificates | Yes | Yes | — |
| WLCG / JWT bearer tokens | Yes | Yes | — |
| SSS (shared secret) | Yes | — | — |

`kXR_sigver` HMAC-SHA256 request signing is verified for all GSI sessions.
WLCG token scope enforcement is configurable per location. See
[docs/authentication.md](docs/authentication.md) and [docs/pki.md](docs/pki.md).

---

## XRootD operations

All 32 active opcodes from the XRootD 5.2 wire protocol are implemented.
See [docs/status.md](docs/status.md) for the full table.

**File I/O**
- `open`, `close`, `stat`, `statx`
- `read`, `readv`, `pgread` (with CRC32c verification)
- `write`, `writev`, `pgwrite`, `truncate`, `sync`

**Filesystem**
- `mkdir`, `rmdir`, `rm`, `mv`, `chmod`
- `locate`, `prepare`, `chkpoint`, `clone`

**Metadata**
- `fattr` — get, set, del, list
- checksum, space, stats, config, filesystem queries

**WebDAV operations:** OPTIONS, GET (with Range), HEAD, PUT, DELETE, MKCOL,
PROPFIND, COPY, MOVE, LOCK, UNLOCK, HTTP-TPC COPY pull from `https://` sources.

**S3-compatible operations:** GET, HEAD, PUT, DELETE, ListObjectsV2,
CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
AbortMultipartUpload. Path-style addressing.

---

## Manager / cluster mode

```text
  CMS cluster layout

  Manager node (nginx-xrootd)
       |
       |-- kXR_redirect / kXR_locate
       |
  +----+----+
  |         |
  Sub-mgr   Sub-mgr
  |         |
  Storage   Storage   <-- self-register via CMS heartbeat
  node 1    node 2
```

- CMS heartbeat client: storage nodes self-register with the manager
- Dynamic server registry with health-check and deregistration
- `kXR_redirect` and `kXR_locate` for path-to-server routing
- Static path-to-backend mapping via `xrootd_manager_map`
- `kXR_clone` and `kXR_chkpoint` forwarded through manager
- S3 gateway for inter-service transfers

See [docs/cluster-mode.md](docs/cluster-mode.md).

---

## Performance

1 GiB reads, localhost, nginx 1.28.3 + module vs xrootd v5.9.2, all transfers
GSI/x509 authenticated. See [docs/benchmarks.md](docs/benchmarks.md) to
reproduce.

| Protocol | Connections | nginx-xrootd | xrootd native | nginx p95 | xrootd p95 |
|---|---:|---:|---:|---:|---:|
| `root://` + GSI | 1 | 1,302 MiB/s | 1,790 MiB/s | 0.8 s | 0.6 s |
| `root://` + GSI | 8 | 4,305 MiB/s | 5,303 MiB/s | 1.9 s | 1.5 s |
| `root://` + GSI | 16 | 4,478 MiB/s | 5,329 MiB/s | 3.6 s | 3.1 s |
| `root://` + GSI | 32 | 5,349 MiB/s | 4,674 MiB/s | 6.1 s | 6.9 s |
| `root://` + GSI | 64 | 4,977 MiB/s | 4,421 MiB/s | 13.0 s | 14.7 s |
| `davs://` + x509 | 1 | 1,593 MiB/s | 1,940 MiB/s | 0.6 s | 0.5 s |
| `davs://` + x509 | 8 | 7,134 MiB/s | 5,392 MiB/s | 1.1 s | 1.5 s |
| `davs://` + x509 | 16 | 5,703 MiB/s | 5,845 MiB/s | 2.9 s | 2.8 s |
| `davs://` + x509 | 32 | 6,495 MiB/s | 5,797 MiB/s | 4.9 s | 5.6 s |
| `davs://` + x509 | 64 | 5,919 MiB/s | 5,538 MiB/s | 10.7 s | 11.7 s |

At single connection, native xrootd has lower latency (less per-request
framing overhead). At 32+ simultaneous connections, nginx-xrootd's event-driven
workers outperform native xrootd's thread-per-connection model on both
protocols. At 128 concurrent connections, nginx-xrootd sustains 4.6x higher
aggregate `root://` throughput; native xrootd p95 latency climbs 5-57x under
the same load.

---

## Feature summary

- **Three deployment modes:** standalone server, transparent XRootD proxy,
  WebDAV perimeter proxy — all supported in a single nginx binary
- **32 XRootD 5.2 opcodes** fully implemented; see [docs/status.md](docs/status.md)
- **WebDAV:** OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE,
  LOCK, UNLOCK, HTTP-TPC COPY pull
- **S3-compatible:** GET, HEAD, PUT, DELETE, ListObjectsV2, multipart upload
- **Auth:** anonymous, GSI/x509 proxy certs with `kXR_sigver` signing,
  WLCG/JWT bearer tokens (scope enforcement), SSS shared secret
- **TLS:** in-protocol `root://` upgrade (`kXR_wantTLS`/`kXR_ableTLS`),
  `roots://` TLS-from-byte-one, HTTPS for WebDAV and S3
- **Transparent XRootD proxy:** lazy upstream connect, file-handle translation,
  opaque opcode relay, full metrics and audit logging, backend invisible to client
- **WebDAV proxy:** terminate HTTPS + WLCG auth at nginx, forward to HTTP/HTTPS backend
- **Manager/cluster:** CMS heartbeat, dynamic server registry, `kXR_redirect`,
  `kXR_locate`, S3 gateway
- **Read-through cache:** XCache-style direct-mode fills from anonymous
  `root://`/`roots://` origin with per-file worker locks
- **Async I/O:** nginx thread pool for all blocking paths (`read`, `pgread`,
  `readv`, `write`, `pgwrite`, WebDAV PUT); cleartext reads use nginx
  file-backed sendfile paths
- **Prometheus metrics:** per-request counters for XRootD ops, WebDAV, S3,
  auth events, fd cache, TPC — all from a shared low-cardinality metrics zone
- **Config validation:** missing certs, JWKS files, CRLs, or required
  directories cause `nginx -t` to fail with explicit `emerg` errors before any
  traffic is accepted
- **License:** AGPL-3.0-only

---

## Observability

```text
  Prometheus scrape

  GET http://nginx:9100/metrics
          |
  xrootd_requests_total{proto="root",op="read",status="ok"} 14302
  xrootd_requests_total{proto="dav",op="GET",status="ok"}   8871
  xrootd_bytes_sent_total{proto="root"}                      9.2e11
  xrootd_auth_total{method="gsi",result="ok"}               4201
  xrootd_auth_total{method="token",result="invalid"}        3
  xrootd_fd_cache_hits_total                                 29441
  ...
```

Every request — XRootD, WebDAV, or S3 — writes a structured access log line
and increments protocol-specific Prometheus counters. Labels are fixed and
low-cardinality so dashboards stay fast at scale. See
[docs/metrics-and-logging.md](docs/metrics-and-logging.md).

---

## Request lifecycle

```text
  Native root:// download
  ───────────────────────
  TCP connect -> handshake/login -> kXR_auth (GSI or token)
      -> kXR_open(path) -> kXR_read / kXR_pgread loop
      -> kXR_close -> access log + Prometheus counter

  WebDAV davs:// download
  ───────────────────────
  TLS handshake -> HTTP GET / Range header
      -> cert or bearer-token auth -> file read
      -> response body -> access log + counter

  Proxy mode (XRootD transparent)
  ────────────────────────────────
  Client connect -> nginx authenticates client
      -> first post-login opcode -> lazy upstream connect
      -> handle translation -> relay response verbatim
      -> access log + counter (backend never sees client identity)
```

---

## Testing

The Python test suite covers `xrdcp` / XRootD Python client behavior, WebDAV,
HTTP-TPC interop, auth, ACLs, proxy mode, manager mode, and hardening paths.

```bash
# Start test nginx + reference xrootd
tests/manage_test_servers.sh start

# Run the full suite
pytest -v

# Run cross-compatible tests against both nginx-xrootd and reference xrootd
tests/run_cross_compatible_tests.sh

# Target an already-running server
export TEST_NGINX_URL=https://ci-nginx.example:8443
pytest -v
```

Cross-compatible test modules (run against both backends automatically):
- `tests/test_file_api.py`
- `tests/test_query.py`
- `tests/test_protocol_edge_cases.py`
- `tests/test_privilege_escalation.py`

Set `TEST_CROSS_BACKEND=nginx` or `TEST_CROSS_BACKEND=xrootd` to target one
backend directly. Extra `pytest` arguments are forwarded to both runs.

---

## Documentation index

| Document | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | Build, install, first working server |
| [Background](docs/background.md) | XRootD, ROOT files, `root://`, and why this module exists |
| [Architecture](docs/architecture.md) | Request lifecycle, nginx concepts for module developers |
| [Building from scratch](docs/building.md) | Detailed build with all dependencies |
| [Configuration reference](docs/configuration.md) | All directives with defaults |
| [Authentication](docs/authentication.md) | Anonymous, GSI/x509, WLCG/JWT setup |
| [PKI, proxy certificates, VOMS](docs/pki.md) | Grid/WLCG/OSG security model |
| [TLS implementation](docs/tls.md) | `root://` upgrade, `roots://`, HTTPS |
| [Proxy mode](docs/proxy-mode.md) | Transparent XRootD MITM proxy design and config |
| [WebDAV](docs/webdav.md) | WebDAV ops, LOCK/UNLOCK, x509 and bearer token setup |
| [Cluster mode](docs/cluster-mode.md) | CMS heartbeat, dynamic registry, redirect semantics |
| [Operations](docs/operations.md) | All 32 XRootD opcodes, status, edge cases |
| [Status](docs/status.md) | Per-opcode implementation status table |
| [Metrics & logging](docs/metrics-and-logging.md) | Prometheus metrics, access log format |
| [Benchmarks](docs/benchmarks.md) | How to reproduce the performance numbers above |
| [Development](docs/development.md) | Source layout, utilities, workflow |
| [Protocol notes](docs/protocol-notes.md) | Wire-protocol details for developers |
| [xrdcp interactions](docs/xrdcp-interactions.md) | Detailed client/server flows |
| [Quirks & compromises](docs/quirks.md) | Design mismatches, trade-offs, gotchas |
| [Operations guide](docs/operations.md) | Production deployment, tuning |
| [Test PKI setup](docs/pki.md) | Generate test CA, certs, proxies, VOMS |
| [Test tokens](docs/test-tokens.md) | Generate local WLCG/JWT signing keys and tokens |
| [TLS](docs/tls.md) | TLS configuration for all protocols |

---

## License

nginx-xrootd is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`). See [LICENSE](LICENSE).
