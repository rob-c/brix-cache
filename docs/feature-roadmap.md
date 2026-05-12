# Feature roadmap

These are the next meaningful protocol features. Each one closes a gap between
this module and a full drop-in replacement for `xrootd` at a WLCG Tier-2
disk-only site. Items are ordered by implementation difficulty, not priority —
pick the one that unblocks your site first.

---

## 1. HTTP-TPC push ✓ IMPLEMENTED

**Status:** Complete. COPY with a `Destination:` header is fully implemented as
of 2026-05-09. All 10 integration tests pass.

**What was done:** Added `webdav_tpc_handle_push()` in `src/webdav/tpc.c`,
`webdav_tpc_run_curl_push()` in `src/webdav/tpc_curl.c`, two new Prometheus
metric slots (`push_started`, `push_success`), and 10 tests in
`tests/test_webdav_tpc.py::TestHTTPTPCPush`. The main `handle_copy` dispatcher
now routes on which header is present (`Source:` → pull, `Destination:` → push,
both or neither → 400).

**Why it matters:** FTS3 / FTS4 channel configuration can place transfers in
either pull or push mode. Sites where the source server initiates the transfer
(common when the destination is being written by a site with strict egress
policy) use push mode. Without push support those transfers fail with 501.

**What push means:** The server receives a COPY request whose URI is the local
source path and whose `Destination:` header is a remote HTTPS URL. The server
fetches nothing; it reads the local file and streams it out via an outbound
HTTP PUT to the destination URL, forwarding the `Authorization:` /
`TransferHeaderAuthorization:` headers from the original request.

**Implementation sketch:**

```c
/* in src/webdav/tpc.c, in ngx_http_xrootd_webdav_tpc_handle_copy() */

if (source_hdr == NULL && dest_hdr != NULL) {
    /* push mode */
    return webdav_tpc_run_curl_push(r, conf, dest_url, local_path,
                                    transfer_headers);
}
```

`webdav_tpc_run_curl_push()` mirrors `webdav_tpc_run_curl_pull()` but inverts
the direction: `curl --upload-file <local_path> <destination_url>` with the
same header forwarding, cert/key, and CA configuration. The local path is
resolved with `webdav_resolve_stat` before curl is invoked to confirm the
source file exists and is readable.

**Response:** `201 Created` if curl exits 0; `502 Bad Gateway` if curl reports
a remote error; `500` for local I/O failure. The `Performance-Marker` streaming
response (chunked 202 with periodic position updates) is optional for
interoperability with standard FTS but makes large transfers observable.

**Files to change:**
- `src/webdav/tpc.c` — add `webdav_tpc_run_curl_push()` and wire into the
  dispatch at the top of `ngx_http_xrootd_webdav_tpc_handle_copy()`
- `src/webdav/webdav.h` — declare `webdav_tpc_run_curl_push()`
- `src/metrics/webdav.c` — add `XROOTD_WEBDAV_TPC_PUSH_OK` /
  `XROOTD_WEBDAV_TPC_PUSH_FAIL` event slots
- `src/webdav/dispatch.c` — OPTIONS Allow header already advertises COPY; no
  change needed
- Tests: `tests/test_webdav_tpc.py` — add push-mode tests against a local
  HTTPS server fixture

**Estimated effort:** 2–3 days. The curl subprocess infrastructure is already
in place; push is structurally identical to pull with source and destination
swapped.

---

## 2. Native root:// TPC full rendezvous ✓ IMPLEMENTED

**Status:** Complete for the wire rendezvous used by `xrdcp --tpc` and
manager redirect. Integration tests in `tests/test_root_tpc.py` cover
nginx↔nginx and nginx↔reference xrootd transfers.

**What was done:**
- Shared-memory TPC key registry (`src/tpc/key_registry.c`) with register,
  consume, and TTL eviction.
- Source role in `src/read/open.c`: read-open with `tpc.dst` + `tpc.key`
  registers the key; read-open with `tpc.org` + `tpc.key` consumes it before
  serving data (destination’s outbound pull presents `tpc.org` from
  `tpc_build_origin_id()` in `src/tpc/launch.c`).
- Destination role: write-open with `tpc.src=` defers to the thread-pool pull
  (`src/tpc/thread.c`, `source.c`, …) which opens the remote file with
  `?tpc.key=` / `&tpc.org=` as needed.
- Manager mode: `kXR_redirect` with `?tpc.key=` (`src/response/control.c`).
- Configurable TTL: `xrootd_tpc_key_ttl` (default 60s), merged in
  `src/config/server_conf.c`.

**Remaining gap (parity, not protocol):** The outbound pull client still uses
anonymous `kXR_login` to the source (`src/tpc/bootstrap.c`), the same class of
limitation as read-through cache fill. Sites that require GSI or token on the
source for every session may need source-side policy compatible with that or
HTTP-TPC. See `docs/status.md` (soft gap: native TPC outbound auth).

**Protocol sketch (reference):**

```text
xrdcp / FTS (initiator)
    │
    ├─► manager: kXR_open dest-path (options=kXR_new|kXR_posc, tpc.dst=...)
    │       manager responds: kXR_redirect → dest server, tpc.key=<K>
    │
    ├─► dest server: kXR_open (tpc.src=root://src/path, tpc.key=<K>)
    │       dest opens staging temp, stores key K in handle context
    │
    ├─► src server: kXR_open src-path (tpc.dst=root://dest, tpc.key=<K>)
    │       src verifies key K exists in session, returns handle
    │
    └─► dest server: kXR_read(s) on src handle (delegated via dest)
            dest server opens outbound connection to src, authenticates
            with key K, reads data, writes to staging temp, renames on close
```

---

## 3. kXR_bind parallel streams with cross-handle sharing ✓ IMPLEMENTED

**Status:** Complete. Secondary connections established via
`kXR_bind` inherit auth from the primary session registry and may read
primary-published file handles. They are deliberately not independent file
sessions: after bind, non-read file operations such as `kXR_open`, `kXR_close`,
`kXR_write`, `kXR_stat`, `kXR_dirlist`, `kXR_query`, `kXR_fattr`, and mutation
opcodes are rejected. The primary connection remains the control channel that
decides which handles exist.

**Why it matters:** `xrdcp -S N` is the standard way to saturate a high-bandwidth
link with a single large file. Without cross-handle sharing the per-file
throughput ceiling is the throughput of a single TCP connection.

**How the implementation works:** The module uses a second shared-memory zone
named `xrootd_session_handles`. Primary connections publish readable handles as
`{sessid, handle_index, path, dev, ino, size, readable, writable, from_cache}`
entries after `kXR_open`, and remove them on `kXR_close` or session teardown.
Bound secondaries look up `{bound_sessid, handle_index}` in
`xrootd_ensure_read_handle()` before serving `kXR_read`, `kXR_readv`, or
`kXR_pgread`.

The shared table intentionally does **not** share raw file descriptors. nginx
workers are separate processes, so an fd opened by one worker is not a valid fd
in another worker. Instead, the secondary reopens the primary's canonical path
inside its own worker and validates `st_dev/st_ino` against the published entry.
If the primary closes or reuses the handle, the shared entry disappears or
changes; the bound stream closes any stale local fd and the read fails with
`kXR_FileNotOpen`.

**Key files:**
- `src/session/registry.c` / `.h` — session registry plus shared readable-handle
  table.
- `src/read/open.c` — publishes primary readable handles after successful open.
- `src/connection/fd_table.c` — lazy bound-handle materialization and revocation.
- `src/handshake/dispatch_read.c` and `src/handshake/policy.c` — reject
  non-read file operations from bound streams.
- `tests/test_session_bind.py` — bind, shared-handle read, invalid sessid, and
  secondary-open rejection coverage.

---

## 4. Macaroon tokens ✓ IMPLEMENTED
 
 **Status:** Complete. Basic HMAC-SHA256 signature chaining and caveat validation using a static secret is fully implemented as of 2026-05-09.
 
 **What was done:**
 - Implemented `xrootd_macaroon_validate()` in `src/token/macaroon.c` with support for parsing ISO8601 timestamps and WLCG activity caveats.
 - Updated `xrootd_token_validate()` to dispatch Macaroon validation transparently.
 - Added `xrootd_macaroon_secret` directive in the stream module and `xrootd_webdav_macaroon_secret` in the WebDAV module for static secret configuration.
 - Integrated secret parsing into `src/gsi/token.c` and `src/webdav/auth_token.c`.
 - Created Macaroon generation helper and test cases in `tests/test_token_macaroon.py`.

**Why it matters:** Some WLCG sites (particularly those running dCache and
sites with Rucio transfer rules that issue Macaroons) still present Macaroons
as bearer credentials. Without Macaroon support those clients cannot
authenticate.

---

## 5. WebDAV LOCK / UNLOCK ✓ IMPLEMENTED
 
 **Status:** Complete. Exclusive write locks with in-memory storage, Depth header support (0/infinity), and XML owner parsing are fully implemented as of 2026-05-09.
 
 **What was done:**
 - Added `src/webdav/lock.c` and `src/webdav/lock.h` with a shared-memory lock table.
 - Integrated LOCK/UNLOCK handlers in `src/webdav/dispatch.c` with client request body parsing.
 - Implemented XML body parsing in `lock.c` for custom `<D:owner>` metadata using safety-first `webdav_strnstr`.
 - Supported `Depth: 0` (shallow) and `Depth: infinity` (recursive) lock scope.
 - Updated OPTIONS advertisement in `src/webdav/methods_basic.c`.
 - Added `lockdiscovery` and `supportedlock` properties in `src/webdav/propfind.c`.
 - Added `xrootd_webdav_lock_timeout` directive for site-specific policy.
 - Enforced lock checks in `PUT`, `DELETE`, `MKCOL`, `MOVE`, and `COPY`.
 - Added 9 integration tests in `tests/test_http_webdav_lock.py` covering timeout, conflict, depth, and owner parsing.

---

## 6. WebDAV server-side COPY ✓ IMPLEMENTED

**Status:** Complete. RFC 4918 §9.8 server-side copy is fully implemented in `src/webdav/copy.c`.

**What was done:**
- Implemented `webdav_handle_copy()` with `copy_file_range(2)` support and fallback to pread/write.
- Supports atomic rename-into-place for destination.
- Supports recursive collection copies (Depth: infinity) and shallow copies (Depth: 0).
- Integrated with path confinement and recursive lock enforcement for destination collections.
- Preserves XRootD-mapped extended attributes (`user.U.*`) during copy.
 
 ---
 
 ## 7. kXR_prepare / kXR_stage (Tape Dispatch)
 
 **Status:** Not implemented (path validation and existence check only).
 
 **Why it matters:** Sites with tape backends (CASTOR, EOS tape, dCache tape) rely on FTS or physics frameworks issuing stage requests before data access. Without dispatching these requests to the tape backend, this module cannot be used as a full replacement at tape-backed deployments.
 
 ---
 
## 8. S3 Multipart Upload ✓ IMPLEMENTED

**Status:** Complete. The S3 endpoint supports the full multipart upload lifecycle:

| S3 API | HTTP Method | Handler |
|---|---|---|
| `CreateMultipartUpload` | `POST /bucket/key?uploads` | `s3_handle_multipart_initiate()` |
| `UploadPart` | `PUT /bucket/key?partNumber=N&uploadId=ID` | inline in `ngx_http_s3_handler()` → `s3_put_body_handler()` |
| `CompleteMultipartUpload` | `POST /bucket/key?uploadId=ID` | `s3_multipart_complete_body_handler()` |
| `AbortMultipartUpload` | `DELETE /bucket/key?uploadId=ID` | `s3_handle_multipart_abort()` |

Parts are staged as `part.<N>` files inside a hidden directory
`.<key>.mpu-<id>/` alongside the target object.  `CompleteMultipartUpload`
streams parts in ascending part-number order into a temp file then atomically
renames it to the final path.  `AbortMultipartUpload` removes the staging
directory via a safe `opendir/unlinkat` recursive helper.

Security: part numbers are range-checked (1–10 000) and validated as decimal
integers before appearing in any path.  All filesystem paths go through the
confined-open helpers to prevent path traversal.

**Tests:** 13 integration tests in `tests/test_s3_multipart.py` covering the
full lifecycle, abort, negative cases, and security invariants.

**Files:**
- `src/s3/multipart.c` — initiate, abort, complete handlers + query helpers
- `src/s3/handler.c` — PUT UploadPart routing + POST Complete dispatch
- `tests/test_s3_multipart.py` — full integration test suite

---
 
 ## 9. Native root:// TPC outbound auth polish
 
 **Status:** Partially implemented (basic auth works).
 
 **Why it matters:** While the pull client can complete basic **ztn** or **GSI** exchanges after `kXR_authmore`, multi-hop delegation and TLS-upgraded origins (`kXR_gotoTLS`) beyond the initial exchange are not yet supported. This limits complex delegation scenarios.
 
 ---
 
## 10. HTTP-TPC OAuth2/OIDC delegation endpoints ✓ IMPLEMENTED

**Status:** Complete. OAuth2/OIDC credential delegation for HTTP-TPC COPY
pull and push is fully implemented as of 2026-05-10.

**What was done:**
- Wired up existing `tpc_cred.c` implementation into the WebDAV COPY handler
  (`src/webdav/tpc.c`). The `Credential:` header is now parsed in both pull
  and push modes, and delegated tokens are injected into the curl subprocess
  as `Authorization: Bearer` headers.
- Added nginx directives:
  - `xrootd_webdav_tpc_token_endpoint` — OAuth2 token endpoint URL
  - `xrootd_webdav_tpc_token_client_id` — OAuth2 client ID (optional)
  - `xrootd_webdav_tpc_token_client_secret` — OAuth2 client secret (optional)
  - `xrootd_webdav_tpc_token_scope` — scope string (default: `storage.read`)
- Added Prometheus counter `xrootd_webdav_tpc_cred_total` with events:
  `started`, `success`, `error`, `unknown_mode`, `parse_error`.
- Two delegation modes are supported:
  - `oidc-agent` — UNIX-socket JSON IPC to a local `oidc-agent` daemon
  - `token-exchange` — RFC 8693 token-exchange request to an external OAuth2
    token endpoint (uses `curl` subprocess)

**Why it matters:** The current TPC curl subprocess forwarded standard
`Authorization: Bearer` headers but did not implement RFC 8693 token exchange
or `oidc-agent` delegation. Newer FTS flows relying on full OIDC delegation
chains now work end-to-end: the server can obtain a delegated access token
from a local `oidc-agent` or via RFC 8693 token exchange, then use it to
authenticate to the remote source (pull) or destination (push).

**Configuration example:**

```nginx
location / {
    xrootd_webdav              on;
    xrootd_webdav_root         /data;
    xrootd_webdav_allow_write  on;
    xrootd_webdav_tpc          on;

    # OAuth2/OIDC token delegation for TPC
    xrootd_webdav_tpc_token_endpoint https://idp.example.com/oauth2/token;
    xrootd_webdav_tpc_token_client_id  nginx-xrootd;
    xrootd_webdav_tpc_token_client_secret abc123secret;
    xrootd_webdav_tpc_token_scope      storage.read;
}
```

**Client usage:**

```bash
# Pull with oidc-agent delegation
curl -X COPY https://server:8443//local/path \
     -H "Source: https://remote-server//remote/path" \
     -H "Credential: oidc-agent"

# Pull with RFC 8693 token-exchange delegation
curl -X COPY https://server:8443//local/path \
     -H "Source: https://remote-server//remote/path" \
     -H "Credential: token-exchange" \
     -H "Authorization: Bearer <session-jwt>"

# Push with token-exchange delegation
curl -X COPY https://server:8443//local/path \
     -H "Destination: https://remote-server//remote/path" \
     -H "Credential: token-exchange" \
     -H "Authorization: Bearer <session-jwt>"
```

**Files changed:**
- `src/webdav/tpc.c` — wire up credential delegation in pull and push handlers
- `src/webdav/tpc_cred.c` — add `webdav_tpc_cred_metric_increment` helper
- `src/webdav/tpc_cred.h` — declare metric increment function
- `src/webdav/tpc_config.c` — merge OAuth2/OIDC config fields
- `src/webdav/webdav.h` — add `tpc_cred` config field and declarations
- `src/webdav/module.c` — add nginx directives for token endpoint, client ID/secret, scope
- `src/metrics/metrics.h` — add TPC cred metrics enum and shared memory field
- `src/metrics/webdav.c` — add TPC cred metrics export
 
 ---
 
 ## 11. Full hierarchical CMS cluster
 
 **Status:** Not implemented (simple two-tier works).
 
 **Why it matters:** `kYR_select`, `kYR_try`, and `kYR_redirect` are missing, meaning the module cannot perform sub-manager-directed redirects. It works fine for a two-tier (redirector → leaf) setup, but multi-tier sub-manager topologies are not supported.
 
 ---
 
## 12. VO Authorization Database (authdb) rules ✓ IMPLEMENTED

**Status:** Core implementation complete. Minor coverage gaps documented below.

**What is implemented** (`src/path/authdb.c`, `src/config/policy.c`):

- `xrootd_authdb <path>` directive — registered as `NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1`, requires `xrootd_auth gsi`, `token`, or both
- Full authdb file parser: `[u|g|p|a] <id> <path> <privs>` line format, comments (`#`), blank lines
- Identity types enforced: `u` (user DN matched against `ctx->dn`), `g` (VO group matched against `ctx->vo_list`), `a` (all/anonymous); wildcard `*` id accepted for `u` and `g`
- Privilege flags: `r` (read + lookup), `l` (lookup only), `w`/`a` (update/append), `d` (delete), `m` (mkdir), `k` (admin)
- Longest-prefix matching on resolved (absolute) paths — ties go to the later rule in file order
- Opt-in model: no authdb configured → all paths pass; authdb configured → deny unless an explicit allow rule matches
- Path resolution via `xrootd_finalize_authdb_rules()` — normalizes rule paths relative to `xrootd_root` at config time
- Enforced in all core operation handlers before `xrootd_check_vo_acl()`:

| Handler | Priv checked |
|---|---|
| `kXR_stat` | `LOOKUP` |
| `kXR_open` (read) | `READ` |
| `kXR_open` (write) | `UPDATE` |
| `kXR_open` (TPC destination) | `UPDATE` |
| `kXR_write`, `kXR_rm`, `kXR_rmdir` | `DELETE` |
| `kXR_mkdir` | `MKDIR` |
| `kXR_truncate` | `UPDATE` |
| `kXR_mv` (source) | `DELETE` |
| `kXR_mv` (destination) | `UPDATE` |

**Test coverage** (`tests/test_authdb.py`): 6 integration tests covering public read, public write denied, CMS VO read, ATLAS VO denied for CMS path, user DN private write, and unlisted-path deny.

**Known limitations / not yet implemented:**

- `HOST` type (`p` rules) — parsed but silently never matches; peer IP is not exposed in `ctx`. Host-based rules in an authdb file are ignored.
- `kXR_dirlist` — only enforces `xrootd_require_vo` ACL, not authdb `LOOKUP`. Directory listings bypass authdb.
- `query/` handlers (`kXR_query checksum`, `kXR_query config`, `kXR_prepare`) — use `check_vo_acl` only; authdb is not consulted.
- `fattr/` handlers (`kXR_getattr`, `kXR_setattr`, `kXR_delattr`) — use `check_vo_acl` only.
- `kXR_chmod` — uses `XROOTD_AUTH_UPDATE` (not `ADMIN`); full authdb enforcement is present via `xrootd_write_resolve_existing_path()`.
- Authdb file is read once at `nginx -s reload` / startup (max 4096 bytes); runtime reload requires `nginx -s reload`. Files larger than 4096 bytes are silently truncated.

---

## Sequencing recommendation

If the goal is maximum deployment coverage fastest:

```text
1. [DONE] WebDAV server-side COPY
2. [DONE] HTTP-TPC push              2–3 days    unblocks FTS push-mode sites
3. [DONE] WebDAV LOCK/UNLOCK
4. [DONE] Macaroon tokens            3–5 days    enables dCache/Rucio Macaroon sites
5. [DONE] kXR_bind parallel streams  1–2 weeks   full xrdcp -S N performance
6. [DONE] Native TPC full rendezvous
7. kXR_prepare / kXR_stage           2–3 weeks   critical for tape-backed sites
8. [DONE] S3 Multipart Upload         1–2 weeks   required for >5GiB S3 uploads
9. Native TPC outbound auth polish   1–2 weeks   for complex delegation scenarios
10. [DONE] HTTP-TPC OAuth2/OIDC delegation  1–2 weeks  for modern FTS OIDC flows
11. Full hierarchical CMS cluster    2–3 weeks   for multi-tier manager topologies
12. [DONE] VO authdb rules           u/g/a identity + all core ops covered
```


Items 1–4 are self-contained and have no shared dependencies. Native TPC and
`kXR_bind` handle sharing each use a shared-memory zone; the TPC key table is
already implemented (`xrootd_tpc_keys`).

---

## Known gaps and further work

This section catalogs sub-feature gaps found by code inspection across every
implemented feature. Each entry names the relevant source file and describes
what is missing. Items are grouped by feature area.

### HTTP-TPC push and pull (items 1, 10)

- **No Performance-Marker streaming (chunked 202):** `tpc.c` / `tpc_curl.c`
  wait for the curl subprocess to exit before sending the final response.
  FTS optionally expects periodic `Performance-Marker:` lines in a chunked
  `202 Accepted` body for large-file observability. Not implemented; FTS falls
  back to polling but loses transfer-rate visibility.

- **No automatic credential-mode fallback:** `tpc_cred.c` — if `oidc-agent`
  mode is requested but the daemon is unavailable, the request fails rather
  than falling back to bearer passthrough. Retries must be initiated by the
  client.

- **Token refresh not implemented:** Delegated tokens fetched at request time
  are used as-is. If the oidc-agent returns a short-lived token that expires
  during a multi-hour transfer, the downstream curl PUT will fail with 401 and
  the transfer is aborted with no retry.

- **curl subprocess is blocking:** `tpc_curl.c` forks and waits via
  `waitpid(2)`. While the thread pool keeps the nginx worker responsive, each
  in-flight TPC transfer consumes one thread-pool thread. The pool can be
  exhausted under heavy concurrency; `xrootd_webdav_thread_pool` sizing must
  account for this.

### Native root:// TPC rendezvous (item 2) and upstream connections

- **Outbound `kXR_gotoTLS` not implemented:** `src/upstream/bootstrap.c:100` —
  if the source server's `kXR_protocol` response has the `kXR_gotoTLS` flag
  set, the connection is aborted with `"upstream requires TLS (not supported
  on outbound)"`. Affects cache-fill paths and native TPC source connections
  to any server that mandates in-protocol TLS upgrade.

- **Upstream `kXR_authmore` not implemented:** `src/upstream/bootstrap.c:115`
  — if the upstream server requires authentication after `kXR_login`, the
  connection is aborted. Both the TPC outbound pull and the read-through cache
  fill share this limitation. Only servers that accept anonymous `kXR_login`
  are usable as upstream sources.

- **No multi-hop GSI delegation for TPC:** `src/tpc/bootstrap.c` — when the
  source server requires GSI (completes `kXR_authmore` successfully), the
  client presents a delegated token or the module certificate/key, but does
  not perform a second delegation step. Multi-hop proxy-delegation chains
  (common in WLCG) are not supported.

### kXR_bind parallel streams (item 3)

- **Write handle sharing not implemented:** `src/connection/fd_table.c:149,251`
  — bound secondary connections always receive `writable = 0`. Parallel write
  streams (e.g. for parallel upload) require the primary to be the sole writer.
  This matches `xrdcp` behavior (`-S` is read-only) but blocks any future
  parallel-write protocol extension.

### Macaroon tokens (item 4)

- ~~**`path:` caveat not enforced**~~ ✓ **DONE:** `src/token/macaroon.c` now
  enforces `path:` caveats. Each caveat narrows the allowed scope paths by
  intersection: if the caveat path is a sub-path of the scope it is narrowed;
  if the paths are disjoint all permission bits for that scope are revoked.
  Multiple `path:` caveats are applied in sequence (up to 8 per token).

- **Third-party / discharge macaroons not implemented:** `vid` packets (third-
  party caveat discharge) are not parsed. Macaroons that require a third-party
  discharge from a separate service cannot be validated.

- ~~**Static secret only — no key rotation**~~ ✓ **DONE:** `xrootd_macaroon_secret_old`
  grace-period directive added to both stream (`src/stream/module.c`) and WebDAV
  (`src/webdav/module.c`) modules. `src/gsi/token.c` and `src/webdav/auth_token.c`
  now fall back to the old secret when primary validation fails, allowing zero-
  downtime key rotation without reloading nginx.

### WebDAV LOCK / UNLOCK (item 5)

- ~~**Shared locks always treated as exclusive**~~ ✓ **DONE:** `src/webdav/lock.c`
  now parses `<D:lockscope>` in the request body and sets `e->exclusive`
  accordingly. Conflict detection treats shared+exclusive and exclusive+any as
  conflicting; shared+shared is permitted. `lockdiscovery` in PROPFIND and the
  LOCK response XML both reflect the actual scope. `supportedlock` now
  advertises both exclusive and shared scopes.

- **Lock table lost on nginx reload:** The lock shared-memory zone is
  reinitialised on `nginx -s reload`. Any in-flight LOCK held by a long-lived
  client is silently lost. A client that then issues the matching UNLOCK
  receives 412 Precondition Failed. Persisting lock tokens across reload
  (e.g. by flushing to a file) is not implemented.

- **Fixed-size lock table:** The number of concurrent locks is bounded at
  compile time by `WEBDAV_LOCK_TABLE_SIZE`. Sites with many concurrent long-
  lived locks (e.g. recursive collection locks during bulk ingest) may exhaust
  the table; attempts to acquire additional locks return 503.

### WebDAV PROPFIND (items 5, 6)

- **Limited property set:** `src/webdav/propfind.c` now returns
  `resourcetype`, `getcontentlength`, `getlastmodified`, `getetag`,
  `creationdate`, and `displayname`. Still missing:
  - `quota-available-bytes` / `quota-used-bytes` (RFC 4331) — used by rucio
    and some monitoring scripts
  - `supported-report-set` — needed for clients that probe for CalDAV/CardDAV
    collision

- ~~**PROPPATCH not implemented**~~ ✓ **DONE:** `src/webdav/methods_basic.c` now
  implements `webdav_handle_proppatch()` per RFC 4918 §9.2: drains the request
  body and returns 207 Multi-Status with `200 OK` per property. Dead properties
  are not stored (acceptable per the RFC). Unblocks Cyberduck and rucio upload
  scripts that treat 501 as a hard error.

### WebDAV server-side COPY (item 6)

- ~~**No ETag enforcement on `Overwrite: F`**~~ ✓ **DONE:** `src/webdav/copy.c`
  now implements `webdav_check_copy_conditionals()` (called from
  `webdav_handle_copy()`). `If-Match: "*"` requires the destination to exist;
  `If-Match: "<etag>"` requires an exact ETag match. `If-None-Match: "*"` fails
  if the destination already exists. Handles the `W/"mtime-size"` weak ETag
  format used elsewhere in the WebDAV module.

### S3 multipart upload (item 8)

- ~~**`ListParts` not implemented**~~ ✓ **DONE:** `GET /<bucket>/<key>?uploadId=<id>`
  is now handled by `s3_handle_list_parts()` in `src/s3/multipart.c`. Scans the
  MPU staging directory for `part.<N>` files, sorts by part number, and emits a
  valid `ListPartsResult` XML response.

- ~~**`UploadPartCopy` not implemented**~~ ✓ **DONE:** `src/s3/multipart.c` now
  implements `s3_handle_upload_part_copy()`. When `PUT /<bucket>/<key>?partNumber=N&uploadId=<id>`
  carries an `x-amz-copy-source:` header, `src/s3/handler.c` dispatches to this
  handler instead of starting the body reader. Validates the copy-source path
  against `root_canon` to prevent traversal, copies via a 64 KiB read/write loop,
  and returns `<CopyPartResult>` XML with ETag and LastModified.

- ~~**`ListMultipartUploads` not implemented**~~ ✓ **DONE:** `GET /<bucket>/?uploads`
  is now handled by `s3_handle_list_multipart_uploads()` in `src/s3/multipart.c`.
  Scans the bucket root for `.*.mpu-*` hidden directories, parses key and
  upload-id from each name, and emits a `ListMultipartUploadsResult` XML response
  (capped at 1000 entries per page, matching the AWS S3 default).

- **Presigned URL authentication not implemented:** `src/s3/auth.c` — only
  header-based `Authorization: AWS4-HMAC-SHA256 …` SigV4 is supported.
  Presigned URL authentication (`X-Amz-Signature` query parameter, AWS
  Signature Version 4 query-string form) is not validated. Requests using
  presigned URLs will fail signature verification.

- **STS session token not supported:** `X-Amz-Security-Token` header (for
  temporary credentials issued by STS `AssumeRole`) is not parsed. Only static
  access-key / secret-key pairs configured via `xrootd_s3_access_key` /
  `xrootd_s3_secret_key` are accepted.

### Token / JWT validation (items 4, 10)

- ~~**RS256 only**~~ ✓ **ES256 added:** `src/token/validate.c` now accepts both
  `RS256` and `ES256`. EC P-256 public keys are loaded from JWKS files
  (`kty:"EC"`, `crv:"P-256"`) in `src/token/jwks.c`; the IEEE P1363 raw
  signature is converted to DER before OpenSSL verification in
  `src/token/signature.c`. PS256, RS384/RS512, and `alg:"none"` remain refused.

- **Single JWKS file, no hot refresh:** `xrootd_token_jwks` is loaded at
  config time and reloaded only on `nginx -s reload`. Key rotation at the
  issuer without a coordinated nginx reload causes all new tokens to fail
  signature verification. A background periodic JWKS refresh (polling the
  JWKS URI) is not implemented.

- ~~**`storage.stage:` not enforced**~~ ✓ **DONE:** `src/token/scopes.c` now maps
  `storage.stage:` to `read = 1`, matching the WLCG token profile intent that
  stage is a read-like capability for tape-recall workflows. `openid` / `profile`
  scopes are still parsed but grant no storage privileges (correct behavior).

### kXR_prepare / kXR_stage (item 7 — not yet implemented)

- **No tape backend dispatch:** `src/query/prepare.c` validates path existence
  and authorization, but does not dispatch to any tape backend. `kXR_stage`
  flag is recognized in the opcode but treated identically to a regular
  `kXR_prepare`; no recall is triggered. Sites with CASTOR, EOS tape, or
  dCache tape cannot use this module as a full replacement until tape dispatch
  is wired in.

- **No async status polling:** The XRootD `kXR_QPrep` query subtype returns
  per-path staging status. The current implementation always returns `A <path>`
  (on disk) or `M <path>` (missing), which is correct for disk-only sites but
  wrong for tape recalls in progress.

### Full hierarchical CMS cluster (item 11 — not yet implemented)

- **`kYR_select` / `kYR_try` / `kYR_redirect` missing:** Multi-tier manager
  topologies where a sub-manager redirects a client to a leaf data server are
  not supported. `kXR_redirect` is sent correctly in two-tier mode; the
  sub-manager CMS messages that produce it in a three-tier topology have not
  been implemented.

### Cross-cutting gaps

- ~~**`kXR_chmod` has no access control check**~~ ✓ **CLARIFIED:** `src/write/common.c`
  calls both `xrootd_check_authdb()` (with `XROOTD_AUTH_UPDATE`) and
  `xrootd_check_vo_acl()` via `xrootd_write_resolve_existing_path()` before
  dispatching to `chmod(2)`. The roadmap entry was stale.

- ~~**POSC not implemented**~~ ✓ **DONE:** `kXR_open` with `kXR_posc` now opens a
  temp file (`.posc.<pid>.<rand>` in the same directory) and stores the final
  target in `xrootd_file_t.posc_final_path`. On `kXR_close` the temp is
  `fsync`d then atomically renamed to the final path. On disconnect or error the
  temp is unlinked by `xrootd_free_fhandle()`. See `src/read/open.c`,
  `src/read/close.c`, `src/connection/fd_table.c`.

- **CRL delta updates not supported:** `src/crypto/pki_load.c` — only full CRL
  files are loaded; delta CRLs (RFC 5280 §5.2.4) are not processed. Sites that
  publish only delta CRLs between full refreshes will have a stale revocation
  state until the next full CRL is published.

- **No OCSP support:** Certificate revocation is checked against loaded CRL
  files only. OCSP stapling and OCSP responder queries are not implemented.

- ~~**WebDAV `PROPPATCH` returns 501**~~ ✓ **DONE:** See WebDAV PROPFIND section above.

- ~~**Authdb `kXR_dirlist` bypass**~~ ✓ **DONE:** `src/dirlist/handler.c` now
  calls `xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_LOOKUP)` before
  `xrootd_check_vo_acl()`.

- ~~**Authdb not applied to `query/` or `fattr/` handlers**~~ ✓ **DONE:**
  `src/query/checksum.c`, `src/query/metadata.c`, `src/query/prepare.c`, and
  `src/fattr/dispatch.c` all now call `xrootd_check_authdb()` with the
  appropriate privilege (`XROOTD_AUTH_READ` for queries; `XROOTD_AUTH_READ` or
  `XROOTD_AUTH_UPDATE` depending on fattr subcode) before the vo_acl check.

- ~~**Authdb file size limit**~~ ✓ **DONE:** `src/path/authdb.c` now uses
  `ngx_fd_info()` to determine the exact file size at config time and allocates
  accordingly, with a hard 1 MiB cap (logs `NGX_LOG_EMERG` and aborts startup
  if exceeded). Silent truncation at 4096 bytes is gone.

- ~~**S3 `ListObjectsV2` `fetch-owner` and `encoding-type` not handled**~~ ✓ **DONE:**
  `src/s3/list.c` now parses both query parameters. `fetch-owner=true` adds an
  `<Owner>` element (using the configured `access_key` as both ID and display name)
  to each `<Contents>` entry. `encoding-type=url` percent-encodes key characters
---

## Test Coverage Requirements for Implemented Features

This section outlines the requirements for developing automated tests for features marked as DONE in the roadmap but currently lacking validation in the `tests/` directory.

### WebDAV PROPPATCH
- **Requirement:** Verify that `PROPPATCH` returns `207 Multi-Status` with `200 OK` for property updates, ensuring compatibility with Rucio and Cyberduck. Test should drain the request body and verify the response XML.
- **Target File:** `tests/test_http_webdav_status_codes.py` or `tests/test_http_webdav.py`.

### S3 Multipart Upload Extras
- **Requirement:** Implement integration tests for `ListParts`, `UploadPartCopy`, and `ListMultipartUploads`. Verify XML response structure, part sorting (for `ListParts`), and correct handling of the `x-amz-copy-source` header.
- **Target File:** `tests/test_s3_multipart.py`.

### ES256 Signature Verification
- **Requirement:** Add a success case using a valid ES256-signed JWT and corresponding EC public key in the test JWKS. Verify that the server correctly converts IEEE P1363 raw signatures to DER for OpenSSL.
- **Target File:** `tests/test_token_auth.py` or `tests/test_token_security.py`.

### Token `storage.stage:` Scope
- **Requirement:** Confirm that the `storage.stage:` scope correctly maps to read privileges. Test should verify that a token with only this scope can read files but is denied write access.
- **Target File:** `tests/test_token_auth.py`.

### WebDAV Shared Locks
- **Requirement:** Verify support for `<D:shared/>` locks. Test should confirm that multiple shared locks can be held concurrently on the same path, and that an exclusive lock correctly conflicts with an existing shared lock.
- **Target File:** `tests/test_http_webdav_lock.py`.

### WebDAV COPY ETag Conditionals
- **Requirement:** Test `If-Match` and `If-None-Match` headers specifically on `COPY` requests. Verify that `If-None-Match: "*"` prevents overwriting existing files and that `If-Match: "<etag>"` enforces exact matches.
- **Target File:** `tests/test_http_webdav_status_codes.py`.

### S3 ListObjectsV2 Extras
- **Requirement:** Verify `fetch-owner=true` (adding `<Owner>` elements) and `encoding-type=url` (percent-encoding keys) query parameter handling in the S3 listing response.
- **Target File:** `tests/test_s3.py`.

### Authdb Enforcement on Query/Fattr
- **Requirement:** Expand authdb testing to cover `kXR_query` (checksum, metadata) and `kXR_fattr` (get/set/del) opcodes. Verify that rules for `XROOTD_AUTH_READ` and `XROOTD_AUTH_UPDATE` are respected.
- **Target File:** `tests/test_authdb.py`.
