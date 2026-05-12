# Background: what XRootD is and why this module exists

## What is XRootD?

XRootD is a file transfer protocol designed for High Energy Physics. It is the primary way physicists at CERN, SLAC, and Fermilab move data between storage systems and analysis jobs — files like ROOT ntuples and HEP datasets that can be tens of gigabytes each.

The protocol is similar in concept to FTP or HTTP, but optimised for physics workflows:

- **Addresses** look like `root://server//path/to/file.root` (note the double slash before the path)
- **Port 1094** is the default (also 1095 for authenticated access)
- **Tools** include `xrdcp` (like `scp`), `xrdfs` (like an FTP shell), and the XRootD Python and C++ client libraries
- **Authentication** commonly uses x509/GSI proxy certificates, and modern WLCG deployments are also moving toward JWT bearer tokens

A typical use looks like:

```bash
# Copy a file from an XRootD server
xrdcp root://server.cern.ch//store/mc/Run3/sample.root /tmp/local.root

# List a directory
xrdfs server.cern.ch ls /store/mc/Run3

# Or directly from Python / ROOT:
import XRootD.client as xrd
f = xrd.File()
f.open("root://server.cern.ch//store/mc/Run3/sample.root")
```

### XRootD vs ROOT

The naming is easy to trip over:

| Term | What it means |
|---|---|
| ROOT | The C++ analysis framework and file format used by HEP experiments |
| `.root` file | A ROOT data file, often containing TTrees, histograms, or RNTuples |
| XRootD | The network protocol and client/server ecosystem for moving files |
| `root://` | A URL scheme handled by XRootD clients; it is not the Unix `root` user |

This module serves bytes. It does not parse ROOT files, inspect TTrees, or know
about event data. A ROOT application can still read through it because ROOT's
I/O layer knows how to open `root://` URLs through the XRootD client library.

That separation matters when debugging:

- If `xrdcp root://host//file.root /tmp/file.root` fails, debug the transfer
  protocol, auth, path mapping, and server logs.
- If `TFile::Open("root://host//file.root")` succeeds but reading a tree fails,
  the transfer layer may be fine and the issue may be in the ROOT file or the
  analysis code.
- If a plain text file copies correctly but a `.root` file does not, first check
  file size, permissions, checksum, and client-side ROOT/XRootD errors before
  assuming the server understands ROOT-specific structure.

### Several Transfer Views To The Same Storage

nginx-xrootd exposes the same backing filesystem through native XRootD and
WebDAV, with an optional S3-compatible HTTP view for clients that speak the
XrdClS3-style subset:

| Client URL | nginx subsystem | Module path | Typical client |
|---|---|---|---|
| `root://host:1094//store/a.root` | `stream {}` raw TCP | native XRootD handlers | `xrdcp`, `xrdfs`, ROOT, XRootD Python |
| `roots://host:1094//store/a.root` | `stream {}` raw TCP + TLS from byte 0 | native XRootD handlers after TLS decrypt | `xrdcp`, ROOT, XRootD Python |
| `davs://host:8443/store/a.root` | `http {}` HTTPS | WebDAV content handler | `xrdcp --allow-http`, curl, HTTP/WebDAV tools |
| `https://host/bucket/store/a.root` | `http {}` HTTP(S) | S3-compatible content handler | XrdClS3-style clients |

```text
                         client chooses a URL
                                  |
        +-------------------------+-------------------------+
        |                         |                         |
 root:// or roots://             davs://                S3 path URL
        |                         |                         |
 nginx stream module        nginx HTTP module       nginx HTTP module
        |                         |                         |
 native XRootD handlers       WebDAV handler         S3 handler
        |                         |                         |
        +-------------------------+-------------------------+
                                  |
                         configured export root
                                  |
                         /data/store/a.root
```

The native XRootD path is session-oriented: one TCP connection logs in, opens a
file handle, reads or writes by handle, and closes it. The WebDAV path is
HTTP-oriented: each `GET`, `PUT`, `HEAD`, or `PROPFIND` is an HTTP request with
headers, status codes, and optional TLS client authentication. The S3-compatible
path is also HTTP-oriented, but it dispatches to `src/s3/` and maps
`GET`, `HEAD`, `PUT`, `DELETE`, and `ListObjectsV2` requests onto filesystem
objects under the configured bucket root.

These views can serve the same files, but they do not share exactly the same
wire semantics. For example, native `kXR_read` returns XRootD response frames,
WebDAV `GET` returns HTTP headers and a response body, and S3-compatible
`GET` returns S3-style headers and errors. This is why the source tree has
separate `src/read/`, `src/webdav/`, and `src/s3/` implementations.

## What is an nginx stream module?

nginx is primarily an HTTP server, but its `stream {}` block handles raw TCP connections — any protocol, not just HTTP. A stream module intercepts the TCP connection right after nginx accepts it and drives a custom protocol.

This module is an nginx stream module: nginx accepts a TCP connection on port 1094, hands it to this module, and the module speaks XRootD directly — handshake, login, file operations, everything. nginx never sees HTTP; the whole connection is XRootD.

```
XRootD client (xrdcp, ROOT, Python)
        │  root://nginx-host//store/mc/sample.root
        │  TCP port 1094
        ▼
┌──────────────────────────────────────────┐
│ nginx                                    │
│  stream { xrootd on; xrootd_root /data; }│
│  (this module drives the XRootD protocol)│
└──────────────────┬───────────────────────┘
                   │  POSIX open/read/write/stat/readdir
                   ▼
             /data/store/mc/sample.root
```

## Three ways to deploy

nginx-xrootd supports three deployment modes, and you can combine them in a single nginx instance:

```text
  MODE 1 — Standalone server
  ──────────────────────────
  xrdcp client ──> nginx-xrootd ──> local POSIX filesystem
                       |
                  auth / TLS / metrics all here

  MODE 2 — Transparent XRootD proxy
  ───────────────────────────────────
  xrdcp client ──> nginx-xrootd ──> root://backend (xrdceph, HDFS, tape…)
                       |
                  terminates auth & TLS, translates file handles,
                  relays opcodes, emits metrics

  MODE 3 — WebDAV perimeter proxy
  ────────────────────────────────
  HTTP / davs:// ──> nginx-xrootd ──> http://internal-dav-server/
  client               |
                  terminates HTTPS + WLCG token auth,
                  forwards plain HTTP inside the perimeter
```

| Mode | Good for |
|---|---|
| Standalone | Replacing or augmenting an `xrootd` daemon on a storage node |
| XRootD proxy | Adding TLS, auth, or metrics in front of an existing XRootD service without changing clients or backends |
| WebDAV proxy | Exposing a plain internal WebDAV server through an HTTPS perimeter with WLCG token enforcement |

## Why run XRootD inside nginx?

The standard XRootD server (`xrootd` daemon) is purpose-built and very capable, but it is a separate process with its own configuration, its own authentication infrastructure, and its own operational tooling.

If you already operate nginx, you get several things for free by using this module instead:

- **TLS policy and termination** — nginx's SSL stack provides the HTTPS and `roots://` transport layer, and the native stream module can also trigger the XRootD in-protocol TLS upgrade
- **IP-based access control** — use `allow`/`deny` in nginx config
- **Connection/request limiting** — nginx HTTP `limit_req` plus HTTP/stream
  connection limiting when the relevant nginx modules are built
- **Load balancing** — put multiple nginx-xrootd backends behind an nginx upstream
- **Unified access logging** — same log format and log rotation as your other services
- **Prometheus metrics** — built-in `/metrics` endpoint, no extra exporters needed
- **Single binary** — one nginx process, one config file, one set of ops runbooks

The trade-off: this is an nginx module, not the full xrootd daemon. It
implements the current XRootD data-server opcode set and explicitly rejects the
legacy `kXR_gpfile` opcode. It targets local POSIX storage and supports XRootD
cluster federation (redirector, manager, sub-manager, cache node roles) via the
built-in CMS protocol and dynamic server registry — see
[cluster-mode.md](cluster-mode.md). It does not implement remote storage
backends (HDFS, EOS, Ceph) or XrdMon UDP monitoring.

## What this module does and does not support

**Supported:**

- Full read and write access to local POSIX filesystems
- All standard file operations: open, read, write, stat, dirlist, rename, delete, chmod, mkdir, rmdir, truncate, sync
- Paged reads and writes with per-page CRC32c integrity (`kXR_pgread`, `kXR_pgwrite`) — the default mode used by xrdcp v5
- Scatter-gather vector reads and writes (`kXR_readv`, `kXR_writev`)
- Extended file attributes (`kXR_fattr`: get / set / del / list)
- Checksum queries: adler32, md5, sha1, sha256 (`kXR_query` `kXR_Qcksum`)
- File location with static manager-map redirect (`kXR_locate`)
- Parallel data streams via `kXR_bind` (secondary connections, pathid assignment)
- Request signing envelope (`kXR_sigver`, HMAC-SHA256)
- Server-side range copy (`kXR_clone`)
- Checkpointed writes (`kXR_chkpoint`)
- Staging hints (`kXR_prepare` with path validation)
- Anonymous access, GSI/x509 proxy certificate authentication, SSS, and JWT/WLCG bearer-token authentication
- VO-style path ACLs from VOMS proxy attributes or token `wlcg.groups`
- In-protocol TLS upgrade (`kXR_wantTLS`) and `roots://` stream-SSL
- Transparent XRootD proxy: lazy upstream connect, file-handle translation, opaque opcode relay, optional upstream TLS (`xrootd_proxy_upstream_tls`), bearer-token auth bridging (`xrootd_proxy_auth forward`), per-handle JSON audit log (`xrootd_proxy_audit_log`), and Prometheus proxy counters
- WebDAV over HTTPS (`davs://`) including HTTP TPC and WebDAV upstream proxy mode
- S3-compatible HTTP endpoint for GET, HEAD, PUT, DELETE, and ListObjectsV2
- CMS manager heartbeat (registration, ping/pong, space and load reporting)
- Thread-pool offload for blocking read/write paths
- Prometheus metrics

**Not supported (gaps vs full xrootd daemon):**

- XrdMon UDP monitoring — required for WLCG accounting and site dashboards
- Legacy `kXR_gpfile`
- krb5 / host / pwd authentication
- Remote storage backends (HDFS, EOS, Ceph, etc.)

For a complete opcode-by-opcode breakdown see [status.md](status.md).
