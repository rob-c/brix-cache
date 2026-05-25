# Cross-Protocol Unification

How three protocols — native XRootD (stream), WebDAV (HTTP), and S3 (HTTP) — share common
infrastructure, what they still duplicate, and the roadmap for closing the gap.

[← Architecture overview](index.md)

---

## Mental model: layers not silos

The module is **not** three independent servers that happen to live in one binary. There is
already a significant shared layer: path confinement, JWT/WLCG token validation, PKI/OCSP,
Prometheus shared-memory layout, and cross-worker TPC rendezvous are all protocol-agnostic
code that every handler reaches for. The remaining duplication is now mostly policy- or
protocol-shape specific; common mechanics such as range responses, query parsing, token-file
loading, XML chain building, request-body transfer, checksum calculation, conditional headers,
temporary-file staging, recursive filesystem cleanup, and filesystem-capacity arithmetic live in
shared helpers.

```
┌────────────────────────────────────────────────────────────────────┐
│                   Protocol handler layer                           │
│                                                                    │
│  stream/   ──────────────────────────────────  src/connection/    │
│  (native XRootD)           WebDAV          S3  src/handshake/     │
│  src/session/          src/webdav/      src/s3/                   │
│  src/read/             src/webdav/tpc.c    src/s3/multipart*.c    │
│  src/write/                                                        │
│  src/tpc/                                                          │
└────────────────────────────┬───────────────────────────────────────┘
                             │  calls into
┌────────────────────────────▼───────────────────────────────────────┐
│                    Shared infrastructure layer                      │
│                                                                    │
│  src/compat/path.c      xrootd_http_resolve_path()  [HTTP+S3]     │
│  src/path/              xrootd_resolve_path_*()     [stream]      │
│  src/token/             JWT validate + scope check  [all]         │
│  src/crypto/            OCSP + PKI load             [all]         │
│  src/metrics/metrics.h  shared-memory layout        [all]         │
│  src/metrics/tracking.c VO/user activity accounting [all]         │
│  src/tpc/key_registry.c SHM TPC key table           [stream+webdav]│
│  src/session/registry.h bind session table          [stream]       │
│  src/compat/crc32c.c    CRC32c for pgread/pgwrite   [stream]      │
│  src/compat/checksum.c  file checksums/digests      [stream+HTTP] │
│  src/compat/range.c     HTTP Range header parse     [webdav+s3]   │
│  src/compat/uri.c       percent-decode              [webdav+s3]   │
│  src/compat/etag.c      ETag generation             [webdav+s3]   │
│  src/compat/http_*.c    headers/body/conditions     [webdav+s3]   │
│  src/compat/fs_walk.c   dot-entry/remove-tree       [webdav+s3+query] │
│  src/compat/staged_file temp open/commit/abort      [webdav+s3]   │
│  src/cms/frame_io.c     CMS send-all + frame build  [cms paths]   │
│  src/compat/xml.c       minimal XML scanner         [webdav]      │
└────────────────────────────────────────────────────────────────────┘
```

---

## What is already shared

### Path resolution (`src/compat/path.c`)

`xrootd_http_resolve_path()` is a pure-C function (no nginx headers) that is the single
path-resolution implementation for both WebDAV and S3:

```
WebDAV PUT /atlas/reco/file.root
    │
    ▼
ngx_http_xrootd_webdav_resolve_path()      src/webdav/path.c
    │  percent-decodes URI (compat/uri.c)
    │  strips trailing slashes
    ▼
xrootd_http_resolve_path(root_canon, decoded, out, outsz)
    │                                        src/compat/path.c
    │  1. reject "." / ".." components
    │  2. snprintf(root_canon + decoded_path) → candidate
    │  3. realpath(candidate) → resolved
    │      ENOENT: walk ancestor chain, resolve deepest existing
    │              prefix, append non-existent suffix literally
    │  4. check resolved has root_canon as prefix → 403 if not
    ▼
  filesystem path confined to root_canon
```

The same `xrootd_http_resolve_path()` is called from `src/s3/handler.c` via a thin wrapper
that maps the return codes to S3 XML error responses instead of HTTP status codes.

Return codes from `xrootd_http_resolve_path()`:

| Return | Meaning | WebDAV maps to | S3 maps to |
|--------|---------|----------------|------------|
| 0 | Success | — | — |
| 403 | Path traversal / outside root | 403 Forbidden | AccessDenied |
| 404 | Parent dir does not exist | 409 Conflict (COPY/MOVE dest) | NoSuchKey |
| 414 | Path too long | 414 URI Too Long | InvalidURI |
| 500 | `realpath(3)` unexpected error | 500 | InternalError |

### Token/WLCG JWT validation (`src/token/`)

All three protocols consume the same JWT validation stack:

```
src/token/
    validate.c    xrootd_token_validate()       — split header.payload.sig, verify sig
    keys.c        xrootd_token_jwks_lookup()    — JWKS key rotation + fetch
    jwks.c        xrootd_token_refresh_jwks()   — background JWKS refresh
    scopes.c      xrootd_token_check_read/write() — WLCG scope prefix match
    macaroon.c    xrootd_token_check_macaroon()  — Macaroon discharge chain
    b64url.c      base64url decode               — shared by all parsers
    json.c        minimal JSON scanner           — claims extraction
```

Stream path (kXR_auth with credtype="ztn"):
```
xrootd_handle_auth()    src/gsi/auth.c
    └─ xrootd_handle_token_auth()   src/gsi/token.c
           └─ xrootd_token_validate()   src/token/validate.c
```

WebDAV path (Authorization: Bearer):
```
webdav_verify_bearer_token()   src/webdav/auth_token.c
    └─ xrootd_token_validate()    src/token/validate.c
    └─ xrootd_token_check_write() src/token/scopes.c   (for PUT/DELETE/MKCOL/MOVE)
```

S3 path (when SigV4 is not configured, falls back to token):
```
s3_verify_signature()   src/s3/auth_sigv4_verify.c  (SigV4 branch)
    OR
xrootd_token_validate() src/token/validate.c        (bearer-token branch)
```

The scope check function `xrootd_token_check_write()` enforces WLCG storage.write / storage.create /
storage.modify prefix matching for all mutating operations regardless of protocol. The path passed
to it is the raw decoded URI path (not the filesystem path) so that token scope granularity
matches the namespace visible to the client.

### PKI / OCSP (`src/crypto/`)

```
src/crypto/
    pki_load.c    load CA store, CRL list, proxy cert settings at startup
    pki_check.c   xrootd_pki_check_cert()  — verify one x509 chain (stream use)
    ocsp.c        online stapling + cache  — both GSI and WebDAV TLS paths use this
```

`pki_check.c` exports `xrootd_pki_check_cert()` which wraps `X509_STORE_CTX` setup with
`X509_V_FLAG_ALLOW_PROXY_CERTS`. The stream GSI path (`src/gsi/auth.c`) calls this after
the two-round DH exchange; `src/crypto/ocsp.c` is referenced by both `src/gsi/` and the
nginx TLS handshake hook registered by `src/webdav/pki.c`.

### Prometheus shared-memory layout (`src/metrics/`)

All counters live in `ngx_xrootd_metrics_t` (defined in `src/metrics/metrics.h`), a single
shared-memory zone visible to all nginx worker processes:

```
metrics.h
    ngx_xrootd_metrics_t
    ├── srv[XROOTD_METRICS_MAX_SERVERS]   — per-port stream counters
    │     ├── connections_active / total
    │     ├── bytes_rx / bytes_tx
    │     ├── op_ok[XROOTD_NOPS]
    │     └── op_err[XROOTD_NOPS]
    ├── webdav                            — HTTP WebDAV counters
    │     ├── requests_total[METHOD][STATUS_CLASS]
    │     ├── auth_total[AUTH_RESULT]
    │     ├── range_total[RANGE_RESULT]
    │     ├── tpc_events[TPC_EVENT]
    │     └── cors_events[CORS_EVENT]
    ├── s3                                — S3 counters
    │     ├── requests_total[METHOD][STATUS_CLASS]
    │     ├── auth_total[AUTH_RESULT]
    │     └── multipart_events[…]
    ├── vo_global                         — VO activity slots (FNV-1a hashed)
    └── user_global                       — unique user identity slots
```

The stream module writes counters with `XROOTD_STREAM_METRIC_INC(op, status)` (increments
atomic counters by slot index). The HTTP metrics handler (`src/metrics/handler.c`) reads the
same zone and serialises all counter families to Prometheus text format via `metrics_writer_t`
from `src/metrics/writer.c`.

`src/metrics/tracking.c` provides `xrootd_track_vo_activity()` and `xrootd_track_unique_user()`
which are called from stream, WebDAV, and S3 paths alike after successful authentication.

### TPC key registry (`src/tpc/key_registry.c`)

Native XRootD TPC uses a shared-memory key table (`xrootd_tpc_key_table_t`) protected by a
spinlock so that a pull-transfer key generated by worker A can be validated by a different
worker B when the remote server connects:

```
Source client sends kXR_open (TPC pull)
    │
    ▼
Worker A: xrootd_tpc_key_register()    src/tpc/key_registry.c
    creates key entry in SHM with a 128-bit random key

Remote server connects to Worker B
    │
    ▼
Worker B: xrootd_tpc_key_lookup()      src/tpc/key_registry.c
    scans SHM table — same physical memory, no IPC needed
    validates key, marks entry consumed
```

WebDAV TPC (`src/webdav/tpc.c` + `tpc_curl.c`) is an entirely separate implementation using
libcurl rather than the key registry — the two TPC mechanisms are not currently unified.

### Compat utilities (`src/compat/`)

| File | Exports | Used by |
|------|---------|---------|
| `crc32c.c` | `xrootd_crc32c()` | `src/read/pgread.c`, `src/write/pgwrite.c` |
| `checksum.c` | `xrootd_checksum_parse()`, `xrootd_checksum_hex_fd()` | `kXR_Qcksum`, `kXR_Qckscan`, dirlist checksums, XrdHttp Digest |
| `etag.c` | `xrootd_http_etag_str()` | `src/webdav/get.c`, `src/s3/object.c` |
| `range.c` | `xrootd_http_parse_range()` | `src/webdav/get.c`, `src/s3/object.c` |
| `uri.c` | `xrootd_http_urldecode()` | `src/webdav/path.c`, `src/s3/handler.c` |
| `xml.c` | minimal XML scanner | `src/webdav/propfind.c`, `src/webdav/lock.c` |
| `copy_range.c` | `xrootd_copy_range()` | stream clone/checkpoint, WebDAV COPY, S3 CopyObject |
| `http_file_response.c` | file-backed sendfile response + range/ETag headers | WebDAV GET/HEAD path, S3 GET |
| `http_headers.c` | request-header lookup, value comparison, response header set | WebDAV TPC/CORS, S3 SigV4/CopyObject |
| `http_body.c` | body summary, spooled/memory write, bounded body flattening | WebDAV PUT/PROPFIND, S3 PUT/DeleteObjects |
| `http_conditionals.c` | ETag preconditions, If-Modified-Since, Overwrite:F | WebDAV GET/PUT/COPY/MOVE |
| `http_query.c` | bounded query parameter scan/decode | XrdHttp query params, S3 list/multipart params |
| `http_xml.c` | XML chain append/send helpers | WebDAV PROPFIND/LOCK XML, S3 XML errors |
| `fs_walk.c` | dot-entry test, path join, dir-empty, confined remove-tree | WebDAV DELETE, S3 MPU cleanup, Qckscan/PROPFIND loops |
| `fs_usage.c` | `statvfs` arithmetic | kXR_Qspace/QFSinfo, cache metrics, WebDAV quota props |
| `staged_file.c` | temp-file open/commit/abort lifecycle | S3 PUT/CopyObject, WebDAV COPY/TPC pull |
| `shm_slots.h` | expiry/free-slot helpers | TPC keys, pending locate, WebDAV lock table |
| `src/cms/frame_io.c` | send-all loop + CMS frame assembly | CMS client and server send paths |

---

### Temp-file staging (`src/compat/staged_file.c`)

Every write operation that produces a file atomically (a write-then-rename pattern) goes through
the shared staged-file lifecycle.  This consolidation exists primarily for security: each of the
four callers previously had its own ad-hoc temp-path construction, open flags, cleanup logic, and
— in some cases — vulnerable pre-`unlink()` races (see
[code-audit-findings-3.md](../07-security/code-audit-findings-3.md)).

**API:**

```c
xrootd_staged_file_t staged;

/* Open: random name, O_CREAT|O_EXCL|O_NOFOLLOW, confined to root_canon.
 * Retries up to `attempts` times on EEXIST (collision is astronomically rare
 * but handled correctly). */
if (xrootd_staged_open(log, root_canon, final_path,
                        O_WRONLY | O_CLOEXEC, 0644,
                        /*attempts=*/ 16, &staged) != NGX_OK) {
    /* handle error */
}

/* Write to staged.fd — any amount of data via normal I/O */

/* Commit: confined rename tmp_path → final_path (atomic on same filesystem) */
if (xrootd_staged_commit(log, root_canon, &staged, final_path) != NGX_OK) {
    xrootd_staged_abort(log, root_canon, &staged, 1);
    /* handle error */
}

/* On any error path before commit: */
xrootd_staged_abort(log, root_canon, &staged, /*remove_tmp=*/ 1);
```

**Security properties enforced at every call site:**

| Property | Mechanism |
|---|---|
| No clobber on open | `O_CREAT\|O_EXCL` — fails if a file already exists at the temp path |
| No symlink follow on create | `xrootd_open_confined_canon` passes `O_NOFOLLOW` — returns `ELOOP` instead of following |
| Unpredictable name | `xrootd_make_tmp_path()` → `<base>.xrd-tmp.<pid>.<ngx_random()>` — attacker cannot pre-stage a symlink at a known path |
| No path escape | `xrootd_open_confined_canon`, `xrootd_rename_confined_canon`, `xrootd_unlink_confined_canon` all verify paths stay within `root_canon` |
| Uniform stale-file cleanup | `*.xrd-tmp.*` — one glob pattern cleans orphans from every caller (e.g. after a crash mid-write) |

**Callers:**

| File | Final path | Lifecycle |
|---|---|---|
| `webdav/copy.c` | WebDAV COPY destination | `staged_open` → `xrootd_copy_range` → `staged_commit` |
| `webdav/tpc.c` | TPC pull destination | `staged_open` → curl download → `staged_commit` |
| `s3/put.c` | S3 object path | `staged_open` → `xrootd_http_body_write_to_fd` → `staged_commit` |
| `s3/copy.c` | S3 CopyObject destination | `staged_open` → `xrootd_copy_range` → `staged_commit` |

**Three sites that cannot use the staged API — and why:**

| Site | Reason | Security posture |
|---|---|---|
| `read/open_resolved_file.c` (POSC writes) | Session-scoped: temp opened on `kXR_open`, renamed on `kXR_close` across multiple protocol messages — `staged_file` lifetime fits a single function call | `xrootd_make_tmp_path()` random name; `xrootd_open_confined()` for path escape prevention; `O_EXCL` on first open attempt ✅ |
| `cache/fetch.c` (`.part` file) | Fixed `.part` suffix required — `cache/lock.c` uses this predictable path for fill-lock coordination (only one worker fetches a given entry at a time). Operates on `cache_root`, a separate confinement domain from the export root. | `O_CREAT\|O_TRUNC\|O_NOFOLLOW` — no preceding `unlink()` (TOCTOU fix); `O_NOFOLLOW` prevents symlink swap ✅ |
| `write/chkpoint.c` (`.ckp` snapshot) | Not a temporary file — an XRootD protocol-defined persistent snapshot. Predictable path required so clients can locate their checkpoint on reconnect. Commit semantics are delete-on-rollback, not rename-on-commit. | `O_CREAT\|O_TRUNC\|O_NOFOLLOW` — defense-in-depth on an already-confined path ✅ |

---

## Completed unification work

The current tree includes the originally planned Phase 1-3 work plus a second pass over
HTTP and token-adjacent helpers.

| Area | Shared helper | Callers now using it |
|------|---------------|----------------------|
| Blocking writes | `src/compat/io.c` | WebDAV PUT/COPY spooled writes, S3 PUT body writes |
| HTTP status classes | `src/metrics/http_common.h` | WebDAV metrics, S3 metrics |
| GSI verification core | `src/crypto/gsi_verify.c` | stream GSI auth, WebDAV client-cert auth |
| Server-side local copy | `src/compat/copy_range.c` | stream clone/checkpoint, WebDAV COPY, S3 CopyObject |
| HTTP file/range response | `src/compat/http_file_response.c` | WebDAV GET, S3 GET |
| HTTP query params | `src/compat/http_query.c` | XrdHttp, S3 list/multipart helpers |
| XML chain/send helpers | `src/compat/http_xml.c` | WebDAV PROPFIND wrapper, S3 XML errors |
| HTTP request/response headers | `src/compat/http_headers.c` | WebDAV TPC/CORS, S3 SigV4/CopyObject/util headers |
| HTTP request bodies | `src/compat/http_body.c` | WebDAV PUT/PROPFIND, S3 PUT/DeleteObjects |
| HTTP conditionals | `src/compat/http_conditionals.c` | WebDAV GET/PUT/COPY/MOVE |
| File checksum algorithms | `src/compat/checksum.c` | native Qcksum/Qckscan, dirlist dcksm, XrdHttp Digest |
| Recursive filesystem mechanics | `src/compat/fs_walk.c` | WebDAV DELETE/access checks, S3 multipart cleanup, Qckscan/PROPFIND dot filtering |
| Staged temp-file lifecycle | `src/compat/staged_file.c` | S3 PUT/CopyObject, WebDAV file COPY, WebDAV TPC pull |
| CMS frame sending | `src/cms/frame_io.c` | CMS client send path, CMS server send path |
| Base64url | `src/token/b64url.c` | JWT/macaroons, S3 continuation tokens |
| Token files | `src/token/file.c` | upstream redirector auth, native TPC outbound auth |
| OAuth2 token JSON | `src/token/oauth2.c` | native TPC token fetch, WebDAV TPC credential parsing |
| Filesystem usage | `src/compat/fs_usage.c` | native query, cache metrics, WebDAV quota props |
| SHM slot bookkeeping | `src/compat/shm_slots.h` | pending locate, TPC key registry, WebDAV locks |

The main deliberate non-goals are still protocol-policy boundaries: S3 SigV4 stays separate
from WLCG bearer-token validation, native TPC stays separate from curl-based WebDAV TPC, and
stream path resolution stays separate from HTTP path resolution.

---

## Remaining candidates

The largest remaining shared-code opportunity is a generic helper-subprocess runner for token
delegation and curl-style child processes. Native TPC token fetching and WebDAV TPC credential
fetching now share JSON parsing, but they still own separate `fork`/`pipe`/`waitpid` loops.

A second candidate is a generic fixed-slot shared-memory table iterator. The current
`shm_slots.h` helper intentionally covers only expiry and first-free-slot bookkeeping; a deeper
iterator abstraction would need careful review because each registry has different key matching,
conflict rules, and side effects while locked.

A third candidate is AIO completion boilerplate. The blocking work itself is operation-specific,
but destroyed-connection checks, errno-to-response mapping, byte counters, and resume logic still
repeat across several `src/aio/` handlers.

---

## Why the path engines stay separate

`src/compat/path.c` (HTTP) and `src/path/` (stream) look similar but serve fundamentally
different callers:

| Dimension | `src/compat/path.c` | `src/path/` |
|-----------|---------------------|-------------|
| Input | Decoded URI string | Wire reqpath + open fd handle |
| ENOENT strategy | Walk ancestor, append suffix | Segment-by-segment with depth counter |
| Non-existent parent | Return 404 | Return 0 (used for `kXR_mkdir --makepath`) |
| Open handle tracking | None | `xrootd_file_t` in `fd_table.c` |
| Symlink confinement | `realpath(3)` + prefix check | `realpath(3)` + `xrootd_path_within_root()` per segment |
| Caller type | HTTP handler (thread/event) | Stream dispatch (event loop) |

Merging them would add branching complexity that exceeds the benefit. The correct abstraction
is the one already in place: `src/compat/path.c` is the shared HTTP engine; `src/path/` is
the stream engine. Both enforce the same invariant (confined to root, no `..`) by different
mechanisms appropriate to their callers.

---

## Security consistency property

The important security property after the GSI, token, query, XML, and path-helper
consolidations is that security-sensitive mechanics now have one implementation per concern:

- A CA store misconfiguration is caught in one place (`src/crypto/gsi_verify.c`).
- A proxy-cert depth limit change applies to both stream and HTTP simultaneously.
- A CRL-check bypass would have to exist in `xrootd_gsi_verify_chain()` to affect either protocol.
- Malformed OAuth2 JSON is parsed by Jansson-backed `src/token/oauth2.c`, not by ad-hoc
  quote scanners in each protocol.
- NUL and percent-decoding behavior for HTTP query values is controlled by
  `src/compat/http_query.c` flags at each call site.
- Symlink and TOCTOU defenses for atomic file creation are enforced once in
  `src/compat/staged_file.c`; all four write-then-rename callers inherit them
  automatically (see [code-audit-findings-3.md](../07-security/code-audit-findings-3.md)).

---

## Further reading

- [Stream architecture](stream.md) — state machine, dispatch, read/write paths
- [WebDAV architecture](webdav.md) — method routing, TPC, GSI auth cache
- [S3 architecture](s3.md) — SigV4, multipart staging
- `src/metrics/metrics.h` — shared-memory counter layout
- `src/compat/path.h` — path resolver API contract
- `src/token/token.h` — JWT validation public API
