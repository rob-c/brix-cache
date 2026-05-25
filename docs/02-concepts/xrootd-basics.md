# XRootD Basics

XRootD is the data highway of High Energy Physics — the protocol that ships collision events from storage to analysis farms, one multi-gigabyte file at a time. This page maps the key concepts, translates the jargon, and shows where nginx-xrootd fits in.

---

## Core Concept: "What am I looking at?"

XRootD is a **network protocol** — like HTTP or FTP — designed for moving large files between computers. The key differences from HTTP/FTP:

| Feature | HTTP/FTP | XRootD |
|---|---|---|
| Designed for | Web pages, small downloads | 10–100 GB physics datasets |
| Connection model | Request/response per file | Persistent session with handles |
| Parallel transfers | One download at a time (per connection) | Multiple streams on one connection |
| Checksums | Optional (TLS provides some) | Built-in CRC32c per page |

---

## Terminology Translation Guide

### "root://" — The URL Scheme *(skip if you know XRootD)*

```
root://server.example.com//store/data/Run3/sample.root
     │              │    │           │        │
     │              │    │           │        └─ filename
     │              │    │           └────────── dataset name
     │              │    └────────────────────── directory path on server
     │              └─────────────────────────── host:port (double slash = root)
     └────────────────────────────────────────── protocol scheme
```

**Key things to know:**
- The **double slash** (`//`) before the path is intentional — it means "root directory" in XRootD
- Port 1094 is the default; port 1095 is for authenticated access
- This is *not* related to Unix `/root` or the `root` user

See also: [Glossary → XRootD](../10-reference/glossary.md#xrootd)

### "xrdcp" — The Copy Tool *(skip if you know XRootD)*

```bash
# Upload a file (like scp, but over XRootD)
xrdcp local-file.root root://server//remote/path/file.root

# Download a file (reverse order)
xrdcp root://server//remote/path/file.root /local/destination/
```

**How it works:** xrdcp opens a session, negotiates transfer parameters, then streams data in chunks with integrity verification. For large files, it can use parallel connections for speed.

### "xrdfs" — The Shell

```bash
# List directory contents (like ls)
xrdfs server.example.com ls /store/data/Run3/

# Create a directory (like mkdir)
xrdfs server.example.com mkdir /new/directory

# Get file info (like stat or ls -l)
xrdfs server.example.com stat /store/data/Run3/sample.root
```

### ".root" — The File Format *(skip if you know ROOT)*

`.root` files contain **TTrees**, **histograms**, and other physics analysis data. They are binary containers managed by the ROOT framework (a C++ analysis toolkit).

**Important:** nginx-xrootd does *not* understand `.root` files internally. It serves raw bytes. A ROOT application reads them because ROOT knows how to open `root://` URLs through its own XRootD client library.

See also: [Glossary → ROOT (Framework)](../10-reference/glossary.md#root-framework)

---

## Session Model — How Clients Talk to the Server

Unlike HTTP where each request is independent, XRootD uses a **session model**:

```
1. CONNECT ──────── TCP connection established
2. HANDSHAKE ────── Protocol version negotiation (kXR_protocol)
3. LOGIN ────────── Client identity verification (kXR_login)
4. AUTH ─────────── Authentication (GSI cert, token, or anonymous)
5. OPEN ─────────── Get a file handle for reading/writing (kXR_open)
6. READ/WRITE ───── Transfer data using the handle (kXR_read / kXR_write)
7. CLOSE ────────── Release the handle (kXR_close)
8. ENDSESSION ───── Graceful disconnect (kXR_endsess)
```

**Why this matters:** The server maintains state about which client has open files. This enables:
- Parallel reads/writes from multiple streams on one connection
- Efficient caching of file metadata
- Better performance for sequential access patterns

---

## Authentication Methods — How Clients Prove Who They Are *(skip if you know auth)*

| Method | What it is | When to use | Complexity |
|---|---|---|---|
| **Anonymous** | No authentication at all | Public data, development | Lowest |
| **GSI/x509 proxy cert** | X.509 certificate chain with VOMS extensions | HEP experiments, grid computing | Medium-High |
| **JWT bearer token** | JSON Web Token from WLCG identity provider | Modern deployments, cloud-friendly | Medium |
| **SSS (shared secret)** | Pre-shared cryptographic key | Internal/private setups | Low-Medium |

See also: [Authentication Overview](../../06-authentication/auth-overview.md)

### GSI Certificate — The "Physics Standard"

This is the traditional way physicists authenticate. It involves:
1. A certificate authority (CA) that issues proxy certificates
2. VOMS (Virtual Organization Membership Service) that encodes permissions in the cert
3. Proxy certs that expire after 7–84 hours (short-lived for security)

**Analogy:** Think of it like an airline boarding pass — issued by a trusted authority, contains your identity and access rights, and expires quickly.

### JWT Token — The "Modern Alternative"

JWTs are web-standard tokens (like OAuth2). WLCG has defined a standard format that maps to GSI concepts:
- `sub` claim → user identity
- `wlcg.groups` claim → VO/FQAN membership
- Scope claims → read/write permissions

**Analogy:** Like a digital access card — self-contained, easy to verify, works across systems.

---

## File Operations — What Clients Can Do

### Read Operations

| Operation | Description | Typical use |
|---|---|---|
| `kXR_open` + `kXR_read` | Sequential read with file handle | Streaming large files |
| `kXR_open` + `kXR_readv` | Scatter-gather read (multiple ranges) | Random access, prefetching |
| `kXR_pgread` | Paged read with per-page CRC32c | Default mode for xrdcp v5+ |
| `kXR_stat` / `kXR_statx` | Get file metadata (size, permissions) | Client-side caching |
| `kXR_dirlist` | List directory contents | Browsing remote filesystems |

### Write Operations

| Operation | Description | Typical use |
|---|---|---|
| `kXR_write` / `kXR_writev` | Sequential/vec write with file handle | Uploading files |
| `kXR_pgwrite` | Paged write with CRC32c verification | Default mode for xrdcp v5+ |
| `kXR_truncate` | Resize a file to specific length | Pre-allocating space |
| `kXR_sync` | Flush writes to disk | Ensuring durability |

### Filesystem Operations

| Operation | Description |
|---|---|
| `mkdir`, `rmdir` | Create/remove directories |
| `rm` | Delete files |
| `mv` | Rename/move files |
| `chmod` | Change file permissions |
| `locate` / `clone` | File location and server-side copy |

---

## Architecture — How nginx-xrootd Fits Together

```
                    Client Request (XRootD protocol)
                              │
                    ┌─────────┴─────────┐
                    │  nginx stream {}  │ ← TCP accept, read loop
                    │    + module       │ ← XRootD protocol handling
                    └─────────┬─────────┘
                              │
                    ┌─────────┴─────────┐
                    │   Protocol Layer  │ ← Handshake, auth, session mgmt
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
     ┌────────┴────────┐ ┌────┴────┐   ┌──────┴──────┐
     │  Read Handlers  │ │Write    │   │ Query/Stat  │
     │ (src/read/)     │ │Handlers │   │ Handlers    │
     └────────┬────────┘ │(src/write│   └─────────────┘
              │          │ /)       │
              └──────────┼──────────┘
                         │
                    POSIX Filesystem
                   (your actual files)
```

---

## What You Need to Know as a Beginner

You don't need to understand every opcode or wire protocol detail. Focus on:

1. **URL format:** `root://host:port//path/to/file` — that's all clients need to connect
2. **Basic commands:** `xrdcp` for copying, `xrdfs` for browsing
3. **Authentication choice:** Start anonymous for testing, add GSI or JWT for production
4. **Session behavior:** Clients maintain persistent connections with handles (not HTTP-style request/response)

The rest is configuration detail you'll encounter when you need it.

---

## Related Reading

- [What Is This Project](../01-getting-started/what-is-this.md) — Why nginx-xrootd exists *(5 min)*
- [Deployment Modes](deployment-modes.md) — Three ways to run this software *(10 min, or skip if you know modes)*
- [Authentication Overview](../../06-authentication/auth-overview.md) — Setting up access control *(20 min)*
- **[Security Hardening Guide](../../07-security/hardening-guide.md)** — Verify your deployment is secure *(30 min)*
- [XRootD Concepts (Deep)](../10-reference/xrootd-concepts-deep.md) — Protocol-level details for advanced understanding *(reference, read as needed)*

---

### In this section

| Document | Purpose |
|---|---|
| [XRootD Basics](xrootd-basics.md) ← You are here | Core concepts explained simply, terminology translation guide |
| [Deployment Modes](deployment-modes.md) | When to use each of the three deployment approaches |
| [How It Works](how-it-works.md) | Request lifecycle from connection to response with debugging tips |

> **Quick reference:** For terms you encounter but don't understand, see the **[Glossary](../10-reference/glossary.md)** — no need to read it sequentially.

