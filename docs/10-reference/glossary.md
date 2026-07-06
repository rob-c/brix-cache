# Glossary

> Every term you'll encounter in this project's documentation, tests, and configuration. No physics background required.

---

## Quick Lookup — Alphabetical

Stuck on a single term? Find it below by letter:

| A | B | C | F | G | H | J | K | M | P | R | S | T | V | W | X |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| — | [Bearer Token](#bearer-token) | [CRL](#crl-certificate-revocation-list), [Cluster Mode](#cluster-mode), [Content Handler](#content-handler) | [File Handle / kXR_open](#file-handle--kxr_open) | [GSI (Grid Security Infrastructure)](#gsi-grid-security-infrastructure) | [HTTP-TPC](#http-tpc) | [JWKS](#jwks-json-web-key-set) | — | [Macaroon Token](#macaroon-token), [Manager Mode](#manager-mode) | [Proxy Certificate](#proxy-certificate), [Proxy Mode (Transparent XRootD)](#proxy-mode-transparent-xrootd) | [ROOT file (.root)](#root-file-root), [ROOT (Framework)](#root-framework), [Request Phase / Session](#request-phase--session), [Response Phase](#response-phase) | — | [TPC (Third-Party Copy)](#tpc-third-party-copy) | [VOMS (Virtual Organization Membership Service)](#voms-virtual-organization-membership-service), [VO (Virtual Organization)](#vo-virtual-organization), [VOSAN (Fully Qualified Attribute Name)](#vosan-fully-qualified-attribute-name) | — | [XRootD](#xrootd) |

---

## A-Z Glossary Entries

### Bearer Token

A security credential that proves identity without requiring a password. Instead of "proving who you are" via a certificate, you simply *present* your token — whoever holds it is trusted ("bearer"). In BriX-Cache, bearer tokens are JWTs issued by WLCG Identity Providers (IdPs).

**Where you'll encounter it:** `Authorization: Bearer <token>` HTTP header in WebDAV requests; `brix_auth token` directive.

See also: [JWT](#jwt), [WLCG Token](#wlcg-token)

---

### CRL (Certificate Revocation List)

A list of X.509 certificates that have been **revoked before their natural expiration date**. When BriX-Cache verifies a proxy certificate, it checks the CRL to ensure the issuing CA hasn't revoked any intermediate certificates in the chain. A revoked cert means "this certificate is no longer trustworthy" — common reasons include private key compromise or administrative policy changes.

**Where you'll encounter it:** `brix_crl` directive for native XRootD layer; `brix_webdav_cadir` with CRL files for WebDAV layer. See [PKI Configuration](../06-authentication/pki-config.md) for setup details.

See also: [X.509 Certificate](#x509-certificate), [GSI](#gsi-grid-security-infrastructure)

---

### Cluster Mode

A deployment configuration where multiple BriX-Cache servers are managed together by a single **manager** node. The manager tracks which servers have which data and redirects clients to the right server using `kXR_redirect`. Used in large HEP experiments with thousands of storage nodes.

See also: [Manager Mode](#manager-mode), [Hierarchical Cluster](../05-operations/hierarchical-cluster.md)

---

### Content Handler

In nginx terminology, a "content handler" is the module code that processes HTTP requests in the `http {}` block. The WebDAV and S3 modules are both content handlers — they receive an HTTP request and return an HTTP response with appropriate status codes and body content.

See also: [stream {} block](#stream--block), [http {} block](#http--block)

---

### File Handle / kXR_open

After authentication, clients must **open a file** (`kXR_open`) to receive a numeric file handle. All subsequent read/write operations use this handle rather than the full path — this is more efficient and allows file-level locking.

```
xrdcp flow:
  connect → login → open("/data/file.root") → read(handle) → close(handle)
```

In BriX-Cache: The proxy mode translates handles between client and backend servers so each sees consistent handle numbers even though the underlying files may differ.

See also: [kXR_open](#kxr_opcodes-opcodes), [Proxy Mode](#proxy-mode-transparent-xrootd)

---

### GSI (Grid Security Infrastructure)

The security framework standard in the global computing grid ecosystem. Provides certificate-based authentication using **x509 proxy certificates** — short-lived credentials derived from a user's long-term certificate that prove identity and permissions.

**How it works:**
1. User has a long-term x509 certificate (valid ~1 year)
2. Before accessing XRootD, the user creates a **proxy certificate** (valid ~12-24 hours) with VO/FQAN attributes
3. The proxy is presented during TLS handshake to the nginx server
4. BriX-Cache verifies the proxy chain and extracts identity/permissions

```bash
# Create a GSI proxy certificate (on the client side)
voms-proxy-init --voms atlas --valid 12:00
```

**In BriX-Cache:** Handled by `src/auth/gsi/` module files. Requires `brix_auth gsi` directive and valid host certificate at `/etc/grid-security/hostcert.pem`.

See also: [Proxy Certificate](#proxy-certificate), [WLCG Token](#wlcg-token)

---

### HTTP-TPC (HTTP Third-Party Copy)

A way to copy files between two remote servers without the data passing through your local machine. Instead of downloading then uploading, the source server sends data directly to the destination. BriX-Cache supports HTTP-TPC via `COPY` requests with a `Credential:` header in WebDAV mode.

**Why it matters:** Saves bandwidth and time when moving large datasets between sites.

See also: [Native XRootD TPC](#native-xrootd-tpc), [HTTP TPC Reference](../04-protocols/http-tpc-reference.md)

---

### JWKS (JSON Web Key Set)

A standard format for publishing public keys that can verify JWT signatures. In BriX-Cache, a JWKS endpoint serves the public keys needed to validate WLCG bearer tokens — this is checked locally against cached keys, not on every request.

**In BriX-Cache:** Configured via token authentication directives. Keys are loaded once at startup and periodically refreshed from the JWKS endpoint. This avoids per-request network latency to an Identity Provider.

See also: [JWT](#jwt), [WLCG Token](#wlcg-token)

---

### kXR_opcode (XRootD Opcode)

A numerical command code sent over the XRootD wire protocol. Each opcode tells the server what operation to perform — `kXR_open` (open a file), `kXR_read` (read data), `kXR_write` (write data), etc. There are 32+ active opcodes in the XRootD 5.2 protocol that BriX-Cache implements.

**Common opcodes:**

| Opcode | Number | Description |
|---|---|---|
| kXR_protocol | 3006 | Version negotiation (first command) |
| kXR_login | 3007 | Session authentication |
| kXR_open | 3010 | Open a file for reading/writing |
| kXR_read | 3013 | Read data from an open file |
| kXR_write | 3019 | Write data to a file |
| kXR_close | 3003 | Close an open file |
| kXR_stat / statx | 3017/3022 | Get file metadata (like `ls -l`) |
| kXR_dirlist | 3004 | List directory contents (like `ls`) |
| kXR_clone | 3032 | Native TPC: copy between servers |
| kXR_bind | 3024 | Bind secondary connection for parallel I/O |
| kXR_sigver | 3029 | Request signing for GSI sessions |

**Where you'll encounter it:** AGENTS.md operation-to-file index; `src/protocols/root/protocol/opcodes.h`; test coverage files.

See also: [XRootD Wire Protocol](#xrootd-wire-protocol)

---

### Manager Mode

A deployment pattern where one BriX-Cache instance acts as a **manager** — coordinating multiple backend storage servers. The manager maintains a registry of available backends, handles redirects (`kXR_redirect`), and can serve as an S3 gateway for the entire cluster.

See also: [Cluster Mode](#cluster-mode), [Hierarchical Cluster](#hierarchical-cluster)

---

### Macaroon Token

A cryptographic capability token used for delegation and fine-grained authorization. Unlike JWT bearer tokens (which prove identity via signature), macaroons encode **specific capabilities** — what operations are allowed, on which resources, under what conditions. In BriX-Cache, macaroon authentication is an alternative to WLCG JWT tokens for WebDAV access control.

**Key difference from JWT:** A JWT says "this user is X"; a macaroon says "the bearer of this token can read /path/to/data but not write it." Macaroons are harder to forge because they include **context-bound caveats**.

**Where you'll encounter it:** `webdav_auth_token macaroon` directive; `src/auth/token/macaroon.c`.

See also: [Bearer Token](#bearer-token), [JWT](#jwks-json-web-key-set)

---

### Manager Mode

A deployment pattern where one BriX-Cache instance acts as a **manager** — coordinating multiple backend storage servers. The manager maintains a registry of available backends, handles redirects (`kXR_redirect`), and can serve as an S3 gateway for the entire cluster.

See also: [Cluster Mode](#cluster-mode), [Hierarchical Cluster](#hierarchical-cluster)

---

### Native XRootD TPC

Third-party copy using XRootD's native `kXR_clone` opcode. Unlike HTTP-TPC (which uses WebDAV COPY requests), this is a protocol-level feature where the manager node coordinates data transfer between two remote XRootD servers without carrying the payload itself.

**How it differs from HTTP-TPC:**
| Aspect | Native TPC | HTTP-TPC |
|---|---|---|
| Protocol | XRootD wire (`kXR_clone`) | WebDAV COPY + HTTP |
| Coordination | Manager node | Client-side curl |
| Auth | GSI via manager | Token delegation |

See also: [HTTP-TPC](#http-tpc), [Third-Party Copy](#tpc-third-party-copy)

---

### Proxy Certificate (GSI)

A temporary X.509 certificate that delegates the identity of a long-term host or user certificate. In grid computing, your **host certificate** proves *who you are* (the server/organization), while your **proxy certificate** proves *which person is acting on behalf of that organization*. Proxy certificates typically expire after 12–24 hours and can be renewed without re-authenticating to the CA.

**Why it matters:** BriX-Cache validates proxy certificates using either GSI (native XRootD layer) or WebDAV (HTTP layer). The validation checks: certificate chain, expiration, revocation status (CRL), and VOMS attributes for authorization.

See also: [GSI](#gsi), [x509 Certificate](#x509-certificate)

---

### Proxy Mode (Transparent XRootD)

BriX-Cache can act as a **man-in-the-middle proxy** between clients and backend XRootD servers. Clients think they're talking directly to the backend, but nginx:
- Terminates client TLS/auth locally
- Lazily connects to upstream on first request
- Translates file handles bidirectionally
- Relays all opcodes byte-for-byte

```
client ──> nginx-xrootd (proxy) ──> root://backend:1094 (upstream)
         authenticates client    translates handles, relays ops
```

See also: [Proxy Mode Guide](../05-operations/proxy-mode-guide.md), [Deployment Modes](../02-concepts/deployment-modes.md)

---

### ROOT (Framework)

A C++ analysis framework used in High Energy Physics for data analysis, visualization, and storage. **Important distinction:** ROOT is the *analysis tool*; XRootD is the *transfer protocol*. BriX-Cache serves raw bytes — it does not understand or manipulate ROOT file structure internally.

**Why newcomers confuse them:** The `.root` file extension comes from ROOT (the framework), but the `root://` URL scheme comes from XRootD (the protocol). They're related but completely different things.

See also: [XRootD](#xrootd)

---

### ROOT file (.root)

A binary data file format used by the **ROOT analysis framework** (not to be confused with XRootD). Contains TTrees, histograms, RNTuples, and other physics data structures. Often tens of gigabytes in size.

**Important distinction:** BriX-Cache serves raw bytes — it does not parse or understand ROOT file structure. Any ROOT application can still read through it because ROOT's I/O layer knows how to open `root://` URLs via the XRootD client library.

---

### Request Phase / Session

An XRootD connection has two phases:
1. **Session phase** — TCP connection, handshake (`kXR_protocol`), login/authentication, optional parallel stream binding (`kXR_bind`)
2. **Request phase** — file operations on the session's primary or secondary connections

A session can have one primary connection and multiple "secondary" connections for parallel data transfers (via `kXR_bind`).

See also: [kXR_bind](#kxr_opcode-xrootd-opcode)

---

### Response Phase

After reading or writing, clients receive either a success response (`kXR_ok`) or an error status. For reads, the response includes `kXR_rdres` with the actual data payload. The exact wire format differs between standard read (`kXR_read`) and page-based read (`kXR_pgread`).

**Note:** `kXR_pgread` uses `kXR_status` (opcode 4007) as its response, **not** `kXR_ok`. Data pages include per-page CRC32c in a specific wire layout.

See also: [pgread](#xrootd-wire-protocol), [Response Builder](#response-builder)

---

### S3-Compatible Endpoint

An HTTP API that mimics Amazon S3's REST interface, allowing tools like `aws s3 cp` to work with BriX-Cache without modification. Uses path-style URLs like `http://host/atlas/data/file.root`. Implemented in `src/protocols/s3/`.

See also: [S3 Path-Style URL](#s3-path-style-url), [XrdClS3](#xrdcls3)

---

### SSS (Shared Secret System)

An authentication method using a shared password instead of certificates or tokens. Simpler than GSI but less secure — typically used for testing or internal services where certificate management is impractical.

**Where you'll encounter it:** `brix_auth sss` directive; `src/auth/sss/` source directory.

See also: [Authentication Overview](../06-authentication/auth-overview.md)

---

### TPC (Third-Party Copy)

Copying data between two storage locations without the client acting as an intermediary. In BriX-Cache, there are two types:
1. **Native XRootD TPC** (`src/tpc/`) — uses `kXR_clone` opcode for root:// transfers
2. **HTTP-TPC** (WebDAV) — uses COPY requests with Credential headers

**Why it matters:** Essential for moving large datasets between HEP sites efficiently without consuming client bandwidth.

See also: [HTTP-TPC](#http-tpc), [Native XRootD TPC](#native-xrootd-tpc)

---

### VO (Virtual Organization) / FQAN (Fully Qualified Attribute Name)

In grid computing, a **VO** is a logical group of people and resources working together on a physics experiment. Each VO has **FQANs** — attributes like `/atlas/acl/role=production` that define what members are allowed to do. BriX-Cache can enforce VO-based access controls via `brix_require_vo`.

**Common VOs:** ATLAS, CMS, LHCb, ALICE (the four main experiments at CERN's Large Hadron Collider).

See also: [Authorization](#authorization), [ACL](#access-control-list)

---

### WebDAV (Web Distributed Authoring and Versioning)

An HTTP extension that allows clients to manage files on remote servers — essentially "HTTP-based FTP". BriX-Cache exposes the same POSIX filesystem over both XRootD (`root://`) and WebDAV (`davs://`), enabling browser access, `xrdcp --allow-http`, and tools like rucio.

**Methods supported:** GET (read), PUT (write), DELETE, MKCOL (create directory), COPY, MOVE, PROPFIND (metadata query), LOCK/UNLOCK.

See also: [WebDAV Overview](../04-protocols/webdav-overview.md)

---

### WLCG (Worldwide LHC Computing Grid)

The global computing infrastructure that supports the Large Hadron Collider experiments at CERN. It spans hundreds of sites across 42 countries and processes petabytes of data daily. BriX-Cache is designed to integrate with WLCG standards: authentication via **WLCG tokens**, authorization via **FQAN attributes**, and data transfer via both XRootD and HTTP-TPC.

**Key components:**
- **Identity Providers (IdPs):** Issue JWT tokens for user authentication
- **Token Service:** Validates tokens against JWKS endpoints
- **VO/FQAN system:** Provides role-based authorization

See also: [WLCG Token](#wlcg-token), [JWKS](#jwks)

---

### WLCG Token

A JWT issued according to the Worldwide LHC Computing Grid specification. Contains claims about the bearer's identity (`sub`), groups (`wlcg.groups`), and authorization scopes. BriX-Cache validates these tokens locally using a **JWKS** (JSON Web Key Set) endpoint — no per-request network call to an IdP is needed.

**Common scopes:**
- `storage.read` — allowed to read files
- `storage.write` — allowed to write files  
- `storage.create` — allowed to create new files/directories

See also: [JWT](#jwt), [Bearer Token](#bearer-token), [WLCG](#wlcg)

---

### X.509 Certificate

A standard format for digital certificates used in public key infrastructure (PKI). Contains a public key, identity information, and a signature from a trusted Certificate Authority (CA). In grid computing, X.509 certificates serve as "digital passports" — your host certificate proves the server's identity, while your proxy certificate proves which user is operating on behalf of that server.

**Structure:**
1. **Subject** — who owns this certificate
2. **Public Key** — used for encryption/verification
3. **Issuer** — who signed (trusted CA)
4. **Validity Period** — start and end dates
5. **Extensions** — additional constraints (e.g., VOMS attributes)

See also: [GSI](#gsi), [Proxy Certificate](#proxy-certificate)

---

### XRootD

A high-performance file transfer protocol designed for High Energy Physics (HEP). It's the primary way physicists at CERN, SLAC, and Fermilab move data — files like ROOT ntuples that can be tens of gigabytes each.

**URL format:** `root://server:1094//path/to/file.root` (note the double slash before the path)

**Main tools:**
- **xrdcp** — copy files (like `scp`)
- **xrdfs** — interactive filesystem shell (like an FTP client)

> **Not to be confused with ROOT:** ROOT is a C++ analysis framework for HEP data. XRootD is the *transfer protocol*. They're related but different things. This module serves raw bytes — it doesn't understand ROOT file structure.

See also: [XRootD Proxy Mode](#xrootd-proxy-mode), [kXR_opcode](#kxr-opcode)

---

### XRootD Proxy Mode

A deployment pattern where BriX-Cache sits in front of an existing XRootD server, acting as a **transparent proxy**. The client connects to nginx (not the backend), and nginx:
1. Authenticates the client locally
2. Lazily connects to the upstream on first use
3. Translates file handles between client and backend
4. Relays all responses byte-for-byte
5. Emits metrics and access logs

**Benefit:** Adds TLS termination, authentication enforcement, and observability without modifying either the client or the backend server.

See also: [Proxy Mode Guide](../05-operations/proxy-mode-guide.md)

---

### XRootD Wire Protocol

The binary communication format between XRootD clients and servers. It uses **opcodes** (numerical commands), variable-length framing, and a request/response pattern. BriX-Cache implements 32+ opcodes from the XRootD 5.2 protocol specification.

**Key characteristics:**
- Binary wire format (not text-based)
- Session-oriented: handshake → login → operations → disconnect
- Supports parallel secondary connections via `kXR_bind`
- Optional in-protocol TLS upgrade (`kXR_wantTLS`)
- `roots://` transport from byte zero (stream-level TLS, not in-protocol)

See also: [Wire Protocol Notes](../10-reference/protocol-notes.md), [kXR_opcode](#kxr-opcode)

---

## nginx Concepts

### stream {} block

An nginx configuration section that handles **raw TCP connections** (any protocol, not just HTTP). This is where BriX-Cache lives — the module intercepts TCP connections on port 1094 and drives the XRootD protocol.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;              # enable our module
        brix_export /data;      # serve files from this directory
    }
}
```

See also: [http {} block](#http--block)

---

### http {} block

An nginx configuration section for **HTTP traffic**. This is where WebDAV and S3 endpoints live — each request is a standard HTTP GET/PUT/DELETE with headers, status codes, and optional TLS client authentication.

---

### thread_pool

nginx's async I/O mechanism. Without threading, slow disk operations block the entire worker process (all connections stall). A thread pool offloads blocking paths to background threads.

```nginx
thread_pool default threads=4 max_queue=65536;
```

**Critical:** This is required for BriX-Cache to function properly under load. Without it, a slow disk read blocks all concurrent connections.

---

### worker_processes / worker_connections

- **worker_processes auto** — number of nginx master workers (typically = CPU cores)
- **worker_connections 1024** — max simultaneous connections per worker

These control nginx's concurrency model: how many clients it can handle at once without queuing.

---

## Physics Organizations

### CERN

The **European Organization for Nuclear Research**. Located near Geneva, Switzerland, CERN operates the Large Hadron Collider (LHC) and generates petabytes of physics data annually. XRootD was originally developed at CERN to solve their file transfer challenges.

**In BriX-Cache:** Many deployment patterns (CMS cluster mode, WLCG token auth) originate from CERN use cases. The `hierarchical-cms-cluster.md` document describes a CMS experiment deployment pattern.

---

### SLAC / Fermilab / NERSC

Other major US physics laboratories that use XRootD:
- **SLAC** — Stanford Linear Accelerator Center (Belle II, LHCb)
- **Fermilab** — Fermi National Accelerator Laboratory (DUNE, MINOS)
- **NERSC** — National Energy Research Scientific Computing Center

---

### OSG (Open Science Grid)

A distributed computing resource that connects regional and institutional computing clusters. Often used for physics analysis jobs that need to access data via XRootD from multiple locations.

---

## Quick Reference Table

| Term | Category | Where to Learn More |
|---|---|---|
| XRootD | Protocol | [Background](../02-concepts/xrootd-basics.md), [Getting started](../01-getting-started/getting-started-full.md) |
| xrdcp / xrdfs | Tools | [Getting started](../01-getting-started/getting-started-full.md#step-5-test-with-xrdcp) |
| kXR_opcodes | Protocol | AGENTS.md §4, [Operations status](../05-operations/operation-status.md) |
| GSI | Authentication | [Auth Overview](../06-authentication/auth-overview.md), [PKI Config](../06-authentication/pki-config.md) |
| WLCG token | Authentication | [Auth Overview](../06-authentication/auth-overview.md#token--jwt-wlcg-bearer-token-authentication) |
| VOMS / FQAN | Authorization | [PKI Config](../06-authentication/pki-config.md), [VO ACLs](../../tests/test_vo_acl.py) (tests) |
| stream {} block | nginx | [Architecture Overview](../10-architecture/overview.md), [XRootD Basics](../02-concepts/xrootd-basics.md) |
| thread_pool | Performance | [Getting started](../01-getting-started/getting-started-full.md#step-3-write-a-minimal-nginxconf), [Optimizations](../09-developer-guide/optimizations.md) |
| WebDAV (davs://) | Protocol | [WebDAV Overview](../04-protocols/webdav-overview.md) |
| HTTP-TPC / Native TPC | Transfer | [HTTP TPC Reference](../04-protocols/http-tpc-reference.md), [Native TPC tests](../../tests/test_root_tpc.py) |
| S3 endpoint | Protocol | [S3 handler](../../src/protocols/s3/handler.c), [S3 tests](../../tests/) |

---

## Contributing to the Glossary

If you encounter a term not listed here, add an entry following this format:
1. **Term name** as heading (H2 or H3 depending on hierarchy level)
2. **Category tag** — one of: Protocol, Authentication, nginx, File Format, Physics Organization, Performance
3. **Definition** — clear explanation in plain English
4. **Context note** — where/how the term appears in *this* project specifically
5. **Cross-references** — links to related terms

Place entries alphabetically under their section heading. Update the Quick Lookup table at the top if adding a new letter range.
