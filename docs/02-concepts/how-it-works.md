# How It Works

Tracing a request from TCP connect to access-log entry is the fastest way to become confident with nginx-xrootd. Read this once and debugging becomes much less mysterious.

---

## The Big Picture

Every request goes through these stages:

```
Client ──┬── Connect ──> 1. TCP Accept (nginx stream module)
         │               2. Protocol Handshake (version negotiation)
         │               3. Authentication (prove who you are)
         │               4. Authorization (check what you can do)
         │               5. Operation (read/write/browse)
         │               6. Response (send data back or error)
         └── Disconnect ─> Cleanup + Metrics
```

---

## XRootD Request Lifecycle (root://)

### Step 1: TCP Connection

```
Client                          nginx-xrootd
  │                                  │
  │──── Connect to port 1094 ──────→│  (TCP handshake)
  │←─── Accept connection ──────────│
  │                                  │
  ▼                                  ▼
[Waiting for first XRootD message]
```

**What happens:** nginx accepts the TCP connection and hands it to the module. No protocol data yet — just a raw TCP stream waiting for commands.

### Step 2: Protocol Handshake

The client sends `kXR_protocol` (opcode 3006) with its version number. The server responds with its supported versions. This is like saying "hello, I speak XRootD v5" and the server answering "I support v4 through v6".

### Step 3: Login and Authentication

```
Client                          nginx-xrootd
  │                                  │
  │─── kXR_login ─────────────────→│  Send username/identity
  │←── kXR_login response ─────────│  Accept or reject
  │                                  │
  │─── kXR_auth (GSI/token) ──────→│  Present credentials
  │←── kXR_auth response ──────────│  Verify and respond
```

**Authentication types:**
- **Anonymous:** No credentials needed, immediate access
- **GSI/x509:** Client presents a certificate chain; server validates against trusted CAs
- **JWT token:** Client sends `Authorization: Bearer <token>` header; server verifies signature and checks scopes

### Step 4: Authorization (Scope Check)

After authentication, the server checks what operations the client is allowed to perform based on their **scopes**:

| Scope | Permission |
|---|---|
| `storage.read` | Read files, list directories, stat metadata |
| `storage.write` | Create new files, overwrite existing ones |
| `storage.create` | Create new files and directories |

**Important:** Even with valid authentication, a client without `storage.write` scope will get "permission denied" for write operations.

### Step 5: File Operations (The Actual Work)

#### Reading a File

```
Client                     Protocol handler → VFS        POSIX driver (kernel)
  │                                  │                            │
  │─── kXR_open (read mode) ──────→│ open (confined, cache-aware)│
  │                                  │─ openat2 RESOLVE_BENEATH + fstat ─→│
  │←── handle + metadata ──────────│←──────────── fd + stat ─────│
  │                                  │                            │
  │─── kXR_read (handle, offset) ─→│ xrootd_vfs_io_execute()     │
  │                                  │─ driver->pread / preadv ───→│
  │←── data chunk ─────────────────│←──────────── read bytes ────│
  │                                  │                            │
  │─── kXR_close (handle) ────────→│ close handle                │
  │                                  │─ close(fd) ────────────────→│
```

**Every byte takes the same path, whatever the protocol.** The opcode handler never
touches the disk itself: it calls the **VFS** (`xrootd_vfs_*`, `src/fs/`), which
re-checks confinement, records the metric and access-log line, and consults the
cache — then the VFS calls the **storage driver** (`src/fs/backend/`, POSIX by
default; block / S3 / Ceph / pblock drivers register the same way) for the raw
`open`/`pread`/`pwrite`/`fsync`. WebDAV and S3 reuse these exact two layers, so
the path is `proto → VFS → backend` for all of them.

**Key concepts:**
- **File handle:** A numeric ID that represents an open file. Multiple reads/writes use the same handle — no need to re-open every time.
- **Paged read (kXR_pgread):** Data is split into pages with per-page CRC32c checksums for integrity verification. This is what `xrdcp` v5+ uses by default.

#### Writing a File

A fresh upload is **never written directly to its final path**. The server opens
a **staging file** (a temp/partial file in the same directory, or under
`xrootd_stage_dir`), streams the writes there, and only **moves it into place
with an atomic `rename(2)` on a successful `kXR_close`**. If the client
disconnects mid-transfer, the final path never appears as a half-written file —
readers see either the old file or the new one, never a torn one.

```
Client                  Protocol handler → VFS         POSIX driver (kernel)
  │                               │                            │
  │─ kXR_open (write/new) ──────→│ open STAGING file           │
  │                               │  (.part / temp, O_EXCL) ──→│ fd on temp, not
  │←─ handle + metadata ─────────│←─────────── fd + stat ──────│ the final path
  │                               │                            │
  │─ kXR_write (handle, data) ──→│ xrootd_vfs_io_execute()     │
  │                               │─ driver->pwrite (→ temp) ──→│
  │←─ status OK ─────────────────│←─────────── bytes written ──│
  │                               │                            │
  │─ kXR_sync (handle) ─────────→│ driver->fsync (temp) ──────→│  durability
  │←─ status OK ─────────────────│←─────────── sync complete ──│
  │                               │                            │
  │─ kXR_close (handle) ────────→│ COMMIT: rename(temp → final)│  atomic move
  │←─ status OK ─────────────────│←──── final path now visible ┘  into place
```

**Staging applies to fresh uploads** (`root://` new/overwrite opens with
`xrootd_upload_resume` on — the default — or POSC; **all** WebDAV `PUT` and S3
`PUT`, via `xrootd_staged_open()`/`xrootd_staged_commit()`). A *pure in-place
update* (`kXR_open_updt` with no create, modifying an existing file at an offset)
writes directly to the file, because staging through an empty temp would lose the
unwritten bytes. On a non-clean close the staged partial is preserved (resume),
not published. See [`src/core/compat/staged_file.c`](../../src/core/compat/staged_file.c)
and `src/read/open_resolved_file.c`.

### Step 6: Response and Cleanup

After every operation, the server:
1. Sends an XRootD response frame back to the client
2. Increments a Prometheus counter (e.g., `xrootd_requests_total{op="read",status="ok"}`)
3. Writes an access log line

```bash
# Example access log entry
2025/12/01 14:32:15 [info] client=192.168.1.100 proto=root op=read status=ok bytes_read=1048576 duration_ms=12 auth_method=gsi user=/O=Grid/C=US/O=CERN/OU=Ganglia/CN=test

# Example Prometheus metric
xrootd_requests_total{proto="root",op="read",status="ok"} 14302
```

---

## WebDAV Request Lifecycle (davs://)

WebDAV is simpler — it's HTTP-based, so each request is independent:

```
Client                     WebDAV handler → VFS          POSIX driver (kernel)
  │                                  │                            │
  │─── GET /path/to/file ─────────→│                            │
  │     Host: server.example.com     │ Authenticate (cert/token)  │
  │     Range: bytes=0-1023          │                            │
  │                                  │ xrootd_vfs_open()          │
  │                                  │─ driver->open + fstat ─────→│
  │←── HTTP/1.1 200 OK ─────────────│←──────────── fd + stat ─────│
  │     Content-Type: application/   │ xrootd_vfs_file_sendfile_fd│
  │     Content-Length: 1024         │─ driver->read_sendfile_fd ─→│
  │     [response body follows...]    │←──────────── data (sendfile) ─│
```

WebDAV (and S3) take the **same** `proto → VFS → backend` data path as `root://` —
only the front-end framing differs. Auth runs in the handler; once a file is
touched, the VFS and the storage driver (POSIX by default) do the rest.

**Key differences from XRootD:**
- No persistent session — each request is independent
- Uses HTTP headers for range requests (partial file downloads)
- Authentication happens per-request (cached in nginx connection pool)
- Returns standard HTTP status codes (200, 403, 404, etc.)

---

## Common Debugging Scenarios

### "Connection refused" — Client can't reach the server

```bash
# Check if nginx is listening on the right port
sudo ss -tlnp | grep 1094

# If nothing shows up:
sudo /usr/local/nginx/sbin/nginx -t    # Verify config syntax
sudo /usr/local/nginx/sbin/nginx       # Start nginx
```

### "Permission denied" — Authenticated but can't access file

This means authentication succeeded but authorization failed. Check:
1. Does the user have the right scope? (`storage.read` for reads, `storage.write` for writes)
2. Are there any VO/FQAN restrictions configured?
3. Is the filesystem permission correct for the nginx process user?

### "File not found" — Valid auth but missing file

1. Check that the path doesn't have typos (XRootD uses double slash `//` before the path)
2. Verify the file exists in the configured `xrootd_root` directory
3. Check for path traversal protections (nginx-xrootd won't serve files outside the root)

### "Slow transfers" — Performance issues

1. Check if you're using paged reads (`kXR_pgread`) — this is the default and most efficient mode
2. Verify AIO thread pool configuration: `thread_pool default threads=4 max_queue=65536;`
3. For large files, check if parallel connections are being used

---

## Metrics You Can Watch

```bash
# All XRootD request counters
curl http://localhost:9100/metrics | grep xrootd_requests_total

# Only read operations
curl http://localhost:9100/metrics | grep "xrootd_requests_total.*op=\"read\""

# Authentication events (helps detect failed auth attempts)
curl http://localhost:9100/metrics | grep xrootd_auth_total
```

---

## Summary

| Stage | What to check if something fails |
|---|---|
| TCP Connection | nginx listening on correct port, firewall rules |
| Protocol Handshake | Client and server XRootD version compatibility |
| Authentication | Valid certificates/tokens, correct auth method configured |
| Authorization | User has required scopes, no VO/FQAN restrictions blocking access |
| File Operation | File exists, permissions allow operation, path is within root directory |
| Response | Network stability, disk I/O performance |

---

## Related Reading

- [XRootD Basics](xrootd-basics.md) — Understanding the protocol concepts
- [Deployment Modes](deployment-modes.md) — Choosing your setup
- [Metrics & Monitoring](../08-metrics-monitoring/) — Observability and alerting
