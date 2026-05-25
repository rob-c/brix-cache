# XRootD Concepts (deep dive)

> ⚠️ **Reference tier — advanced.** Assumes familiarity with:
> - [XRootD Basics](../02-concepts/xrootd-basics.md) *(read first, 10 min)*
> - Basic understanding of TCP sessions and file I/O
>
> If you just want to set up a server, stop reading after [Configuration Reference](../03-configuration/config-reference.md).

The core ideas that underpin XRootD's design — protocol model, data-transfer patterns, security architecture, and cluster topology — at the level needed to implement or operate an XRootD-compatible server.

For wire-level behavior discovered by reverse-engineering real clients, see
[protocol-notes.md](protocol-notes.md). For this module's specific implementation
trade-offs, see [quirks.md](quirks.md).

---

## 1. What XRootD Is For

XRootD was designed for High Energy Physics data access. Its constraints follow
directly from HEP workloads:

- **Files are large.** ROOT ntuples and HEP datasets are frequently tens of
  gigabytes and occasionally several terabytes. The protocol is optimized for
  bulk sequential transfer, not small object access.
- **Data lives in storage elements across institutions.** CERN, SLAC,
  Fermilab, and national grids each own storage. Moving data between them is
  routine, not exceptional.
- **Clients are batch jobs on compute farms.** Thousands of concurrent jobs may
  open different files on the same server or the same file from different
  offsets. Throughput per job matters, but so does aggregate concurrency.
- **Authentication is Grid-oriented.** The credential ecosystem is X.509 proxy
  certificates, VOMS virtual-organization attributes, and increasingly WLCG JWT
  bearer tokens. These are not username/password systems.
- **Transfers span institutions.** "Third-party copy" — where a server pulls or
  pushes data on behalf of a client without routing all bytes through the
  client — is a first-class use case, not an afterthought.

The protocol design choices — session handles, vector reads, paged I/O with
checksums, manager/data-server separation, and both native and HTTP transport —
all follow from these constraints.

---

## 2. URL Scheme and Address Format

XRootD URLs use a scheme invented specifically for the protocol:

```
root://server.example.org:1094//store/data/run3/sample.root
       |___________________|    |___________________________|
          host and port               server-side path
                              ^
                              double slash is the path separator
```

The double slash after the authority component is mandatory and not a typo.
It comes from the convention that the first part of the path after the host
identifies the cluster or redirector, and the remainder identifies the file
on the eventual storage element. In simple single-server deployments the first
component is empty, producing `root://host//path`.

Default port is **1094** for unauthenticated access and **1095** is historically
used for authenticated access, though in practice both modes run on the same
port and the port number is not the authentication signal.

The authenticated-TLS variant uses `roots://` (note the `s`) and behaves
identically to `root://` at the application layer except that TLS is established
before any XRootD bytes are exchanged.

---

## 3. Session Model

Unlike HTTP, XRootD is fundamentally stateful. A client establishes a session
that lasts for the duration of the connection, not for a single request.

The session lifecycle is:

```
1. TCP connect
2. Client hello (20-byte handshake frame)
3. kXR_protocol — version negotiation, capability advertisement
4. kXR_login    — client announces username, PID, capabilities
5. kXR_auth     — one or more round-trips to prove identity (optional)
6. kXR_sigver   — request signing setup (optional, with GSI)
7. [kXR_open, kXR_read, kXR_write, kXR_close, kXR_stat, ...] — file operations
8. kXR_endsess or TCP close
```

After step 6, the client holds an authenticated session with the server. File
handles opened during that session persist until explicitly closed or until the
connection drops.

**File handles are small integers.** `kXR_open` returns a 1-byte file handle.
Subsequent `kXR_read`, `kXR_write`, and `kXR_close` reference that handle, not
the full path. This means the server can store open file state (fd, position
hints, permissions) per handle and the client can issue multiple operations on
the same handle in parallel without repeating the path.

**Stream IDs multiplex concurrent requests.** The 2-byte `streamid` field in
every request header allows multiple in-flight operations on one connection.
The client matches responses to requests by streamid. A client using XRootD's
parallel stream mode (`kXR_bind`) can open multiple TCP connections tied to
the same logical session to maximize throughput.

---

## 4. Request Framing

Every XRootD request and response uses the same fixed-length header structure:

```c
struct ClientRequestHdr {
    uint8_t  streamid[2];   /* client-chosen request identifier */
    uint16_t requestid;     /* opcode, e.g. kXR_open = 3010 */
    uint8_t  body[16];      /* opcode-specific fixed fields */
    uint32_t dlen;          /* length of following variable-length data */
};
```

The body after the header is `dlen` bytes. For a `kXR_open` that body contains
the path; for a `kXR_read` it contains the byte offset and length to read.

Server responses use a similar 8-byte header:

```c
struct ServerResponseHdr {
    uint8_t  streamid[2];   /* echoed from the request */
    uint16_t status;        /* kXR_ok, kXR_error, kXR_wait, kXR_redirect, ... */
    uint32_t dlen;          /* length of following body */
};
```

Response status codes are not HTTP codes. Notable ones:

| Status | Value | Meaning |
|---|---|---|
| `kXR_ok` | 0 | Success |
| `kXR_oksofar` | 4003 | Partial response, more to follow on the same streamid |
| `kXR_attn` | 4004 | Server attention — redirect, wait, or async notification |
| `kXR_authmore` | 4005 | More auth data needed (multi-step auth exchange) |
| `kXR_error` | 4006 | Fatal request error; body contains error code + message |
| `kXR_status` | 4007 | Used for `kXR_pgread` paged-read responses |
| `kXR_redirect` | embedded in attn body | Redirect to another host:port |

The fixed-header + variable-body framing means the server can always parse a
request without knowing the opcode in advance: read 24 bytes, inspect
`requestid` and `dlen`, then read `dlen` more bytes.

---

## 5. File Access Opcodes

The core read-side opcodes form a progression from simple to sophisticated:

### kXR_read — simple sequential read

```
client: kXR_read { handle, offset, rlen }
server: response body = rlen bytes of file data
```

The server returns exactly `rlen` bytes starting at `offset`. If the file is
shorter, the response body is truncated (no padding). The response header's
`dlen` tells the client how many bytes arrived.

### kXR_readv — vector read

```
client: kXR_readv { handle, list of (offset, length) pairs }
server: series of (offset, length, data) chunks in one or more responses
```

A single client request can retrieve non-contiguous byte ranges in one round
trip. The server responds with the ranges in the order requested, each prefixed
with its own offset and length header. Clients use this heavily for ROOT's
branch-by-branch access pattern where a TTree stores many branches as separate
byte ranges in the file.

### kXR_pgread — paged read with per-page checksums

```
client: kXR_pgread { handle, offset, rlen }
server: response with data in 4096-byte pages,
        each page followed by its CRC32c checksum
```

The paged read protocol provides end-to-end integrity verification at the page
level. The response uses `kXR_status` framing (status 4007) rather than plain
`kXR_ok`. Each page is 4096 bytes with a 4-byte CRC32c appended, allowing the
client to verify data integrity without waiting for the full transfer to
complete.

### kXR_pgwrite — paged write with checksum verification

```
client: kXR_pgwrite { handle, offset, data with per-page CRC32c }
server: kXR_ok or kXR_error with which pages failed checksum
```

The inverse of `kXR_pgread`. The server strips the per-page CRC32c fields,
verifies them, and writes the raw data bytes to disk. A response can indicate
which specific pages failed verification, allowing the client to retry just the
bad pages rather than the whole request.

The write-side namespace opcodes (`kXR_mkdir`, `kXR_rm`, `kXR_mv`,
`kXR_chmod`, `kXR_truncate`, `kXR_rmdir`) follow the same request/response
pattern with path arguments in the variable body.

---

## 6. The kXR_query System

`kXR_query` is a general-purpose inquiry opcode. It dispatches to different
sub-handlers depending on the 2-byte `infotype` field in the request:

| infotype | What it retrieves |
|---|---|
| `kXR_Qchecksum` | Checksum of a file at a path |
| `kXR_Qconfig` | Server configuration values (key/value pairs) |
| `kXR_Qspace` | Storage space statistics |
| `kXR_Qstats` | Server-wide statistics (XML) |
| `kXR_QPrep` | Staging/prepare a file from tape |

The query system is how clients discover what the server supports, check data
integrity without transferring file content, and integrate with tape-storage
systems that require explicit stage-in requests.

---

## 7. Authentication Architecture

XRootD's authentication is layered and pluggable. The protocol defines the
exchange pattern; the specific credential type is negotiated.

### The Exchange Pattern

After `kXR_login` the server includes a challenge string in the response body.
The client picks an authentication protocol it supports from that string and
sends a `kXR_auth` request. The server may respond with `kXR_authmore` (status
4005) to request additional data. This continues for as many round trips as the
chosen protocol needs.

The two most common protocols in HEP are:

**GSI (Grid Security Infrastructure)** — X.509 proxy certificates using a
Diffie-Hellman key exchange to establish a session cipher, then mutual
certificate presentation. The `&P=gsi` tag in the login challenge identifies
it. The exchange takes two `kXR_auth` round trips: one for DH parameters and
one for the proxy certificate chain.

**ZTN (Zero-Trust Native)** — JWT bearer tokens. The `&P=ztn` tag in the login
challenge identifies it. The client sends its JWT in a single `kXR_auth` round
trip. The server verifies the signature locally using a JWKS key set.

### Authentication Is Not Transport Security

This is the most important distinction in XRootD's security model:

- **GSI proves identity.** It authenticates the client and establishes a shared
  session state for signing. It does not automatically encrypt data bytes.
- **TLS encrypts the wire.** Transport TLS (`roots://`, `xrootd_tls on`, or
  `davs://`) protects bytes in transit. It does not by itself grant access to
  files.

A typical HEP deployment uses GSI for identity and either adds TLS transport
separately or relies on institutional network controls. Both are valid choices
with different trade-offs.

### Identity → Authorization

Authentication establishes identity facts:
- **DN** (Distinguished Name) — from the X.509 subject field
- **VOMS FQANs** — Virtual Organization Membership Service attributes
  embedded in the proxy certificate extension
- **Token sub and wlcg.groups** — from WLCG JWT claims

Authorization then checks those facts against:
- Token `storage.read`, `storage.write`, `storage.create` scopes
- Configured VO requirements (`xrootd_require_vo`)
- Server-wide write gate (`xrootd_allow_write`)
- Filesystem permissions from the OS

These are separate steps. A credential can be valid without having access to a
specific path, and a credential can have write scope without the server
permitting writes at all.

---

## 8. Proxy Certificates and VOMS

Standard X.509 certificates bind an identity to a public key and are signed by
a Certificate Authority. HEP adds two layers on top:

**Proxy certificates** (RFC 3820) are short-lived credentials derived from a
user's long-term certificate. A user signs their own proxy certificate using
their private key, then hands the proxy to a batch job. The job presents the
proxy to storage services, avoiding the need to expose the user's private key
to the job environment. Proxy certificates are typically valid for 12–96 hours
and can be re-delegated to create further proxies with reduced lifetimes.

**VOMS attributes** (Virtual Organization Membership Service) encode group
membership and role information in a signed extension attached to the proxy.
A VOMS attribute certificate from the VO's VOMS server attests that the user
belongs to a VO or subgroup (an FQAN: `/atlas/Role=production`, for example).
Storage servers can enforce VO membership as an access policy condition.

The server-side trust stack for proxy certificates requires:
1. A CA bundle of trusted grid CAs (typically IGTF-accredited)
2. CRL (Certificate Revocation List) enforcement for revoked credentials
3. `X509_V_FLAG_ALLOW_PROXY_CERTS` in OpenSSL — not set by default
4. VOMS attribute verification using VO-specific signing certificates

WLCG JWT tokens carry similar information in a simpler format: `sub` for
identity, `wlcg.groups` for VO membership, and storage scopes for path-level
access claims. JWTs are self-contained and can be verified locally using a
cached JWKS without contacting the issuer per request.

---

## 9. Manager / Redirector / Data Server Topology

XRootD was designed from the beginning for federated storage. A single cluster
has multiple roles:

```
Clients
   │
   ▼
Redirector (Manager)              knows about all data servers
   │                              answers kXR_locate, kXR_open with
   │ kXR_redirect                 kXR_redirect → client, go there
   ▼
Data Servers                      actually hold the files
   │
   │ CMS heartbeat to redirector
   ▼
CMS listener on redirector        learns which servers have which paths
```

**Redirectors** answer `kXR_locate` and `kXR_open` requests with `kXR_redirect`
responses. The redirect body contains the host and port the client should try
next. The client then opens a fresh connection to that data server and re-issues
the request. The redirector never touches file data.

**Data servers** register with the redirector using the Cluster Management
Service (CMS) protocol on port 1213. A CMS heartbeat carries the server's host,
port, exported path prefixes, free disk space, and current utilization. The
redirector uses this to build a dynamic registry of which server has which data
and how loaded each server is.

**Path selection** is longest-prefix matching on the path against each server's
exported prefix list, then load selection: lowest utilization for reads, most
free space for writes.

**Hierarchical topologies** are possible: a meta-manager redirects to
sub-managers, which redirect to data servers. The sub-manager appears as a
data-server from the meta-manager's perspective and as a redirector from the
data server's perspective.

---

## 10. Third-Party Copy (TPC)

In physics data management, moving a file from one storage element to another
without routing all bytes through the initiating client is a fundamental
operation. XRootD provides two separate TPC mechanisms:

### Native root:// TPC

A client sends a `kXR_open` with a source URL embedded in the `opaque` query
string to the destination server. The destination opens a new `root://`
connection to the source, reads the file, and writes locally. The client polls
for completion.

The key is that the destination server acts as a client to the source server.
This requires the destination to be able to authenticate to the source, which
usually means either anonymous access to the source, or a shared TPC key
in the query string.

### HTTP-TPC (WLCG HTTP Transfer Protocol)

WebDAV COPY requests with a `Source:` header (pull mode) or a `Destination:`
plus `Credential:` header (push mode) trigger HTTP-TPC. The server issues an
HTTP GET or PUT on behalf of the client to the specified remote URL.

The HTTP-TPC mechanism is defined by WLCG standards and is used heavily in
the Rucio and FTS data management systems. It allows transfers between any two
HTTP(S)-capable storage endpoints, not just XRootD-native servers.

---

## 11. kXR_fattr — Extended Attributes

`kXR_fattr` provides get/set/delete operations on per-file extended attributes.
Attribute names and values are arbitrary byte strings. Use cases include storing
checksums (separate from the `kXR_query` checksum path), provenance metadata,
and tape staging state.

The opcode uses a sub-command field to dispatch between get, set, delete, and
list operations.

---

## 12. kXR_sigver — Request Signing

`kXR_sigver` is a request signing protocol activated after a GSI session
establishes a shared session key. Once signing is in effect, each write-path
request must be preceded by a `kXR_sigver` request carrying an HMAC signature
over the request header and key fields. Sequence numbers must strictly increase.

The purpose is to prevent replay attacks on write operations when the transport
is not encrypted. An attacker who can observe the wire cannot replay a signed
write request for a different path or at a different sequence position.

---

## 13. kXR_bind — Parallel Streams

A single XRootD session can have multiple TCP connections. After a primary
connection completes login/auth, additional connections can bind to the session
with `kXR_bind`. Bound secondary connections may only send read requests; all
write-path and namespace opcodes must go through the primary (control) channel.
The primary is the only channel that can `kXR_close` a file handle.

This design lets clients saturate high-bandwidth links using multiple parallel
streams without repeating the authentication handshake for each connection.

---

## 14. WebDAV as an XRootD-Compatible Access Layer

WebDAV (RFC 4918) over HTTPS provides a second access path to the same data
that XRootD serves natively. It maps naturally:

| XRootD operation | WebDAV equivalent |
|---|---|
| `kXR_open` + `kXR_read` | `GET` (with optional `Range:` header) |
| `kXR_open` + `kXR_write` | `PUT` |
| `kXR_stat` | `HEAD` or `PROPFIND` |
| `kXR_dirlist` | `PROPFIND` with `Depth: 1` |
| `kXR_mkdir` | `MKCOL` |
| `kXR_rm` | `DELETE` |
| `kXR_mv` | `MOVE` |
| server-side copy | `COPY` (RFC 4918 §9.8) |
| HTTP-TPC pull | `COPY` with `Source:` header |

WebDAV differs fundamentally from native XRootD in its execution model:

- Each HTTP request is stateless at the application layer. There are no
  persistent file handles; the server opens and closes the file within the
  request handler.
- Authentication is re-evaluated per request (though TLS sessions persist).
- Byte-range access is expressed via HTTP `Range:` headers, not a separate
  read opcode.

The same filesystem can be exported via both native XRootD and WebDAV, giving
clients a choice of protocol based on their capabilities.

---

## 15. S3-Compatible HTTP Layer

The S3-compatible endpoint exposes the same filesystem using the AWS S3 REST
API subset (path-style URLs). This allows clients written for S3-compatible
object storage — Rucio, MinIO clients, boto3 — to access data without
modification.

The mapping between S3 and filesystem semantics:
- S3 bucket → configured filesystem root directory
- S3 object key → filename relative to root
- `ListObjectsV2` → directory listing, formatted as S3 XML
- `GetObject` → file read, with optional `Range:`
- `PutObject` → file write
- `CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload` → staged
  writes assembled from parts stored as hidden files, then atomically renamed

S3 auth (`Authorization: AWS4-HMAC-SHA256 ...`) is independent of GSI and JWT:
it uses HMAC-SHA256 over a canonical request string (SigV4). The three auth
systems — GSI, JWT, and SigV4 — do not mix.

---

## 16. Checksums and Data Integrity

XRootD provides two layers of checksum support:

**Transfer-level checksums** via `kXR_query kXR_Qchecksum` return a named
checksum for a file. The server computes or retrieves a checksum (adler32, md5,
or crc32c depending on configuration) and the client can verify it after
transfer. This is an end-to-end integrity check but requires a complete transfer
before verification.

**Page-level checksums** via `kXR_pgread` and `kXR_pgwrite` provide integrity
verification at the 4096-byte granularity during transfer. The server appends a
CRC32c to each page in `kXR_pgread` responses; clients verify each page as it
arrives and can report individual page failures. For `kXR_pgwrite` the client
attaches CRC32c values and the server verifies before committing to disk.

Page-level checksums are the preferred mechanism for large transfers where
detecting corruption early (rather than after the full transfer) matters.

---

## 17. The Prometheus Metrics Layer

The module exports server counters in Prometheus text format at a configurable
`/metrics` HTTP endpoint. Counters are maintained in shared memory so all nginx
worker processes update the same values atomically.

Key metric categories:
- Per-opcode request counts and error counts (native XRootD)
- Active connections and total connection counts
- Bytes received and transmitted
- WebDAV method counts per HTTP status bucket
- S3 operation counts
- Cache hit/miss/fill counts (when read-through cache is enabled)

This provides operational observability without requiring the external XRootD
monitoring infrastructure (xrd.mon protocol).
