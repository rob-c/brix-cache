# Feature roadmap

The next meaningful protocol features — ordered by implementation difficulty, not priority. Each one closes a gap between this module and a full drop-in replacement for `xrootd` at a WLCG Tier-2 disk-only site.
pick the one that unblocks your site first.

---

## 1. HTTP-TPC push ✓ IMPLEMENTED

**Status:** Complete. COPY with a `Destination:` header is fully implemented as
of 2026-05-09. All 10 integration tests pass.

**What was done:** Added `webdav_tpc_handle_push()` in `src/protocols/webdav/tpc.c`,
`webdav_tpc_run_curl_push()` in `src/protocols/webdav/tpc_curl.c`, two new Prometheus
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
/* in src/protocols/webdav/tpc.c, in ngx_http_xrootd_webdav_tpc_handle_copy() */

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
- `src/protocols/webdav/tpc.c` — add `webdav_tpc_run_curl_push()` and wire into the
  dispatch at the top of `ngx_http_xrootd_webdav_tpc_handle_copy()`
- `src/protocols/webdav/webdav.h` — declare `webdav_tpc_run_curl_push()`
- `src/observability/metrics/webdav.c` — add `XROOTD_WEBDAV_TPC_PUSH_OK` /
  `XROOTD_WEBDAV_TPC_PUSH_FAIL` event slots
- `src/protocols/webdav/dispatch.c` — OPTIONS Allow header already advertises COPY; no
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
- Source role in `src/protocols/root/read/open.c`: read-open with `tpc.dst` + `tpc.key`
  registers the key; read-open with `tpc.org` + `tpc.key` consumes it before
  serving data (destination’s outbound pull presents `tpc.org` from
  `tpc_build_origin_id()` in `src/tpc/launch.c`).
- Destination role: write-open with `tpc.src=` defers to the thread-pool pull
  (`src/tpc/thread.c`, `source.c`, …) which opens the remote file with
  `?tpc.key=` / `&tpc.org=` as needed.
- Manager mode: `kXR_redirect` with `?tpc.key=` (`src/protocols/root/response/control.c`).
- Configurable TTL: `xrootd_tpc_key_ttl` (default 60s), merged in
  `src/core/config/server_conf.c`.

**Remaining gap (parity, not protocol):** The outbound pull client can complete
ztn or GSI after `kXR_authmore` when configured, but TLS-upgraded origins and
multihop delegation remain narrower than upstream. Sites with strict source-side
credential requirements should test native TPC with their production auth flow or
use HTTP-TPC. See `docs/05-operations/operation-status.md` (native TPC outbound
auth caveat).

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
- `src/protocols/root/session/registry.c` / `.h` — session registry plus shared readable-handle
  table.
- `src/protocols/root/read/open.c` — publishes primary readable handles after successful open.
- `src/protocols/root/connection/fd_table.c` — lazy bound-handle materialization and revocation.
- `src/protocols/root/handshake/dispatch_read.c` and `src/protocols/root/handshake/policy.c` — reject
  non-read file operations from bound streams.
- `tests/test_session_bind.py` — bind, shared-handle read, invalid sessid, and
  secondary-open rejection coverage.

---

## 4. Macaroon tokens ✓ IMPLEMENTED
 
 **Status:** Complete. Basic HMAC-SHA256 signature chaining and caveat validation using a static secret is fully implemented as of 2026-05-09.
 
 **What was done:**
 - Implemented `xrootd_macaroon_validate()` in `src/auth/token/macaroon.c` with support for parsing ISO8601 timestamps and WLCG activity caveats.
 - Updated `xrootd_token_validate()` to dispatch Macaroon validation transparently.
 - Added `xrootd_macaroon_secret` directive in the stream module and `xrootd_webdav_macaroon_secret` in the WebDAV module for static secret configuration.
 - Integrated secret parsing into `src/auth/gsi/token.c` and `src/protocols/webdav/auth_token.c`.
 - Created Macaroon generation helper and test cases in `tests/test_token_macaroon.py`.

**Why it matters:** Some WLCG sites (particularly those running dCache and
sites with Rucio transfer rules that issue Macaroons) still present Macaroons
as bearer credentials. Without Macaroon support those clients cannot
authenticate.

---

## 5. WebDAV LOCK / UNLOCK ✓ IMPLEMENTED
 
 **Status:** Complete. Exclusive write locks with xattr-based storage, Depth header support (0/infinity), and XML owner parsing are fully implemented (originally SHM-backed as of 2026-05-09; migrated to the unified xattr prop store).

 **What was done:**
 - Added `src/protocols/webdav/lock.c` (lock lifecycle) with lock state persisted as the `user.nginx_xrootd.lock` xattr via `src/protocols/webdav/prop_xattr.c`; request parsing lives in `src/protocols/webdav/locks/request.c`.
 - Integrated LOCK/UNLOCK handlers in `src/protocols/webdav/dispatch.c` with client request body parsing.
 - Implemented XML body parsing in `lock.c` for custom `<D:owner>` metadata using safety-first `webdav_strnstr`.
 - Supported `Depth: 0` (shallow) and `Depth: infinity` (recursive) lock scope.
 - Updated OPTIONS advertisement in `src/protocols/webdav/methods_basic.c`.
 - Added `lockdiscovery` and `supportedlock` properties in `src/protocols/webdav/propfind.c`.
 - Added `xrootd_webdav_lock_timeout` directive for site-specific policy.
 - Enforced lock checks in `PUT`, `DELETE`, `MKCOL`, `MOVE`, and `COPY`.
 - Added 9 integration tests in `tests/test_http_webdav_lock.py` covering timeout, conflict, depth, and owner parsing.

---

## 6. WebDAV server-side COPY ✓ IMPLEMENTED

**Status:** Complete. RFC 4918 §9.8 server-side copy is fully implemented in `src/protocols/webdav/copy.c`.

**What was done:**
- Implemented `webdav_handle_copy()` with `copy_file_range(2)` support and fallback to pread/write.
- Supports atomic rename-into-place for destination.
- Supports recursive collection copies (Depth: infinity) and shallow copies (Depth: 0).
- Integrated with path confinement and recursive lock enforcement for destination collections.
- Preserves XRootD-mapped extended attributes (`user.U.*`) during copy.
 
 ---
 
## 7. kXR_prepare / kXR_stage (Tape Dispatch) ✓ PARTIAL

**Status:** Implemented for local staging hints, durable FRM queueing, `kXR_QPrep`
state, cancel, async open wait/attention, and the WLCG HTTP Tape REST gateway
when `xrootd_frm on` is configured. FRM-off mode intentionally keeps the legacy
disk-only behavior: path validation/existence checks, optional
`xrootd_prepare_command`, and request id `"0"`.

**Why it matters:** Sites with tape backends (CASTOR, EOS tape, dCache tape)
rely on FTS or physics frameworks issuing stage requests before data access. The
module now has a functional FRM/Tape REST control-plane bridge, but it is still
not a complete clone of the upstream XrdFrm/MSS daemon and policy ecosystem.
 
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
- `src/protocols/s3/multipart.c` — initiate, abort, complete handlers + query helpers
- `src/protocols/s3/handler.c` — PUT UploadPart routing + POST Complete dispatch
- `tests/test_s3_multipart.py` — full integration test suite

---
 
## 9. Native root:// TPC outbound auth polish
 
**Status:** Partially implemented. Direct native TPC pull can complete ztn
(WLCG/JWT) or GSI after `kXR_authmore` when configured. Multi-hop delegation and
native TPC source-side `kXR_gotoTLS` remain open.
 
 **Why it matters:** While the pull client can complete basic **ztn** or **GSI** exchanges after `kXR_authmore`, multi-hop delegation and TLS-upgraded origins (`kXR_gotoTLS`) beyond the initial exchange are not yet supported. This limits complex delegation scenarios.
 
 ---
 
## 10. HTTP-TPC OAuth2/OIDC delegation endpoints ✓ IMPLEMENTED

**Status:** Complete. OAuth2/OIDC credential delegation for HTTP-TPC COPY
pull and push is fully implemented as of 2026-05-10.

**What was done:**
- Wired up existing `tpc_cred.c` implementation into the WebDAV COPY handler
  (`src/protocols/webdav/tpc.c`). The `Credential:` header is now parsed in both pull
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
- `src/protocols/webdav/tpc.c` — wire up credential delegation in pull and push handlers
- `src/protocols/webdav/tpc_cred.c` — add `webdav_tpc_cred_metric_increment` helper
- `src/protocols/webdav/tpc_cred.h` — declare metric increment function
- `src/protocols/webdav/tpc_config.c` — merge OAuth2/OIDC config fields
- `src/protocols/webdav/webdav.h` — add `tpc_cred` config field and declarations
- `src/protocols/webdav/module.c` — add nginx directives for token endpoint, client ID/secret, scope
- `src/observability/metrics/metrics.h` — add TPC cred metrics enum and shared memory field
- `src/observability/metrics/webdav.c` — add TPC cred metrics export
 
 ---
 
## 11. Full hierarchical CMS cluster

**Status:** Native redirect implementation complete; `kYR_try` and true
three-tier escalation tests are in place. A select-then-proxy gateway mode
remains a possible extension. See
[hierarchical-cluster.md](../05-operations/hierarchical-cluster.md) for the
full M6 plan and per-step status.

**What is implemented (M6 steps 1–6):**

- `kYR_gone` CMS opcode — data-server path deregistration (`src/net/cms/server_recv.c`)
- Configurable registry slots (`xrootd_registry_slots`; `src/net/manager/registry.c`)
- Per-worker CMS connections — each nginx worker holds its own upstream CMS channel
- Pending-locate table (`src/net/manager/pending.c`) — shared-memory bridge between a suspended XRootD session and an in-flight CMS query
- `ngx_xrootd_cms_send_locate()` — builds and sends `kYR_locate` frames to the parent manager
- `XRD_ST_WAITING_CMS` state — XRootD session suspension while awaiting `kYR_select`; `xrootd_cms_locate_timeout` fires `kXR_wait` to the client on expiry
- `kYR_select` and `kYR_try` handling in `src/net/cms/recv.c` — wakes the suspended session and issues `kXR_redirect`

**Validation status and remaining extension:**

- `kYR_try` multi-alternative selection is covered by `TestCmsKyrTry` in
  `tests/test_manager_mode.py`.
- True CMS escalation (sub-manager miss → parent `kYR_locate` → `kYR_select` →
  suspended client wakeup) is covered by `TestCmsEscalation` in
  `tests/test_manager_mode.py`.
- Proxy/gateway integration remains an extension: using the CMS infrastructure
  to select a backend and proxy on the client's behalf instead of redirecting
  the client (see hierarchical-cluster.md §Proxy/gateway integration).

---
 
## 12. VO Authorization Database (authdb) rules ✓ IMPLEMENTED

**Status:** Core implementation complete for user, group, host, and all-identity
rules. Operational caveats are documented below.

**What is implemented** (`src/auth/authz/authdb.c`, `src/core/config/policy.c`):

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

Directory listings, query/prepare/checksum handlers, and fattr handlers are
also guarded by authdb before VO ACL/token scope. Host (`p`) rules match the
peer IP captured in `ctx->peer_ip`, including exact IPs, CIDR, and `*`.

**Test coverage** (`tests/test_authdb.py`): integration coverage for public
read, public write denied, CMS VO read, ATLAS VO denied for CMS path, user DN
private write, and unlisted-path deny; additional coverage is spread across
dirlist/query/fattr tests.

**Known limitations / operational notes:**

- Authdb is loaded at startup/reload. Runtime policy refresh requires
  `nginx -s reload`; files larger than 1 MiB are rejected at config time.
- `kXR_chmod` uses `XROOTD_AUTH_UPDATE`, not `ADMIN`, via the op-descriptor
  dispatcher (`src/protocols/root/write/op_table.c` → `xrootd_auth_gate()`).
- Empty rule arrays mean allow-all; once rules are loaded, no matching grant
  means deny.

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
7. [DONE/PARTIAL] kXR_prepare / kXR_stage FRM queue + Tape REST; full MSS parity still site-specific
8. [DONE] S3 Multipart Upload         1–2 weeks   required for >5GiB S3 uploads
9. Native TPC outbound auth polish   1–2 weeks   for complex delegation scenarios
10. [DONE] HTTP-TPC OAuth2/OIDC delegation  1–2 weeks  for modern FTS OIDC flows
11. [DONE native redirects] Hierarchical CMS cluster  proxy/gateway extension remaining
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

- ~~**No Performance-Marker streaming (chunked 202)**~~ ✓ **DONE:**
  `src/protocols/webdav/tpc_marker.c` streams WLCG `Performance-Marker:` blocks in a
  chunked `202 Accepted` body when `xrootd_webdav_tpc_marker_interval` is set.

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

### Native root:// TPC rendezvous (item 2), cache origin, and upstream connections

- **Transparent upstream `kXR_gotoTLS` implemented; native TPC source TLS still
  open:** `src/net/upstream/bootstrap.c` / `src/net/upstream/tls.c` handle protocol-time
  TLS upgrade for transparent upstream connections. Native TPC source
  connections still do not upgrade after `kXR_gotoTLS`, and cache/write-through
  origins require their own cache-origin TLS setting.

- **Read-through cache upstream `kXR_authmore` not implemented:** the cache
  origin client still uses anonymous upstream login. If the origin requires
  authentication after `kXR_login`, cache fill is limited to origins that accept
  anonymous or compatible policy. Native TPC has separate ztn/GSI handling after
  `kXR_authmore` when configured.

- **No multi-hop GSI delegation for TPC:** `src/tpc/bootstrap.c` — when the
  source server requires GSI (completes `kXR_authmore` successfully), the
  client presents a delegated token or the module certificate/key, but does
  not perform a second delegation step. Multi-hop proxy-delegation chains
  (common in WLCG) are not supported.

### kXR_bind parallel streams (item 3)

- **Write handle sharing not implemented:** `src/protocols/root/connection/fd_table.c:149,251`
  — bound secondary connections always receive `writable = 0`. Parallel write
  streams (e.g. for parallel upload) require the primary to be the sole writer.
  This matches `xrdcp` behavior (`-S` is read-only) but blocks any future
  parallel-write protocol extension.

### Macaroon tokens (item 4)

- ~~**`path:` caveat not enforced**~~ ✓ **DONE:** `src/auth/token/macaroon.c` now
  enforces `path:` caveats. Each caveat narrows the allowed scope paths by
  intersection: if the caveat path is a sub-path of the scope it is narrowed;
  if the paths are disjoint all permission bits for that scope are revoked.
  Multiple `path:` caveats are applied in sequence (up to 8 per token).

- **Former third-party / discharge macaroon gap** ✓ **DONE:**
  `src/auth/token/macaroon.c` validates space-separated root/discharge bundles,
  decrypts `vid` with AES-256-CBC, and intersects discharge caveats with the
  root token constraints. See `tests/test_macaroon_discharge.py`.

- ~~**Static secret only — no key rotation**~~ ✓ **DONE:** `xrootd_macaroon_secret_old`
  grace-period directive added to both stream (`src/protocols/root/stream/module.c`) and WebDAV
  (`src/protocols/webdav/module.c`) modules. `src/auth/gsi/token.c` and `src/protocols/webdav/auth_token.c`
  now fall back to the old secret when primary validation fails, allowing zero-
  downtime key rotation without reloading nginx.

### WebDAV LOCK / UNLOCK (item 5)

- ~~**Shared locks always treated as exclusive**~~ ✓ **DONE:** `src/protocols/webdav/lock.c`
  now parses `<D:lockscope>` in the request body and sets `e->exclusive`
  accordingly. Conflict detection treats shared+exclusive and exclusive+any as
  conflicting; shared+shared is permitted. `lockdiscovery` in PROPFIND and the
  LOCK response XML both reflect the actual scope. `supportedlock` now
  advertises both exclusive and shared scopes.

- **Locks persist across nginx reload/restart:** As of the unified prop-store
  migration, lock state is stored as an xattr on each resource rather than in a
  shared-memory zone, so locks now **survive** `nginx -s reload` and full
  restarts. This diverges from RFC 4918 §10.1's ephemeral model; enable
  `xrootd_webdav_lock_startup_sweep` to clear persisted locks at startup if
  ephemeral semantics are required.

- **No fixed lock-table capacity:** Lock count is bounded only by filesystem
  capacity (one xattr per locked resource), so the former compile-time
  `WEBDAV_LOCK_TABLE_SIZE` limit and its capacity-exhaustion failures no longer
  apply.

### WebDAV PROPFIND (items 5, 6)

- **Limited property set:** `src/protocols/webdav/propfind.c` now returns
  `resourcetype`, `getcontentlength`, `getlastmodified`, `getetag`,
  `creationdate`, and `displayname`. Still missing:
  - `quota-available-bytes` / `quota-used-bytes` (RFC 4331) — used by rucio
    and some monitoring scripts
  - `supported-report-set` — needed for clients that probe for CalDAV/CardDAV
    collision

- **Former PROPPATCH gap** ✓ **DONE:** `src/protocols/webdav/methods_basic.c` now
  implements `webdav_handle_proppatch()` per RFC 4918 §9.2: drains the request
  body and returns 207 Multi-Status with `200 OK` per property. Dead properties
  are not stored (acceptable per the RFC). Unblocks Cyberduck and rucio upload
  scripts that treat 501 as a hard error.

### WebDAV server-side COPY (item 6)

- ~~**No ETag enforcement on `Overwrite: F`**~~ ✓ **DONE:** `src/protocols/webdav/copy.c`
  now implements `webdav_check_copy_conditionals()` (called from
  `webdav_handle_copy()`). `If-Match: "*"` requires the destination to exist;
  `If-Match: "<etag>"` requires an exact ETag match. `If-None-Match: "*"` fails
  if the destination already exists. Handles the `W/"mtime-size"` weak ETag
  format used elsewhere in the WebDAV module.

### S3 multipart upload (item 8)

- **Former `ListParts` gap** ✓ **DONE:** `GET /<bucket>/<key>?uploadId=<id>`
  is now handled by `s3_handle_list_parts()` in `src/protocols/s3/multipart.c`. Scans the
  MPU staging directory for `part.<N>` files, sorts by part number, and emits a
  valid `ListPartsResult` XML response.

- **Former `UploadPartCopy` gap** ✓ **DONE:** `src/protocols/s3/multipart.c` now
  implements `s3_handle_upload_part_copy()`. When `PUT /<bucket>/<key>?partNumber=N&uploadId=<id>`
  carries an `x-amz-copy-source:` header, `src/protocols/s3/handler.c` dispatches to this
  handler instead of starting the body reader. Validates the copy-source path
  against `root_canon` to prevent traversal, copies via a 64 KiB read/write loop,
  and returns `<CopyPartResult>` XML with ETag and LastModified.

- **Former `ListMultipartUploads` gap** ✓ **DONE:** `GET /<bucket>/?uploads`
  is now handled by `s3_handle_list_multipart_uploads()` in `src/protocols/s3/multipart.c`.
  Scans the bucket root for `.*.mpu-*` hidden directories, parses key and
  upload-id from each name, and emits a `ListMultipartUploadsResult` XML response
  (capped at 1000 entries per page, matching the AWS S3 default).

- **Former presigned URL authentication gap** ✓ **DONE:**
  `src/protocols/s3/auth_sigv4_parse.c`, `src/protocols/s3/auth_sigv4_canonical.c`, and
  `src/protocols/s3/auth_sigv4_verify.c` now accept SigV4 query-string authentication
  (`X-Amz-Signature`) and enforce `X-Amz-Expires`.

- **Former STS-shaped session-token compatibility gap** ✓ **STATIC-SECRET COMPAT ADDED:**
  `xrootd_s3_allow_unsigned_session_token on` accepts signed
  `X-Amz-Security-Token` header/query forms while still verifying SigV4 with
  the configured static `xrootd_s3_secret_key`. A dynamic temporary-credential
  store is still out of scope.

### Token / JWT validation (items 4, 10)

- ~~**RS256 only**~~ ✓ **ES256 added:** `src/auth/token/validate.c` now accepts both
  `RS256` and `ES256`. EC P-256 public keys are loaded from JWKS files
  (`kty:"EC"`, `crv:"P-256"`) in `src/auth/token/jwks.c`; the IEEE P1363 raw
  signature is converted to DER before OpenSSL verification in
  `src/auth/token/signature.c`. PS256, RS384/RS512, and `alg:"none"` remain refused.

- ~~**Single JWKS file, no hot refresh**~~ ✓ **DONE:**
  `xrootd_token_jwks_refresh_interval` mtime-polls file-based JWKS material and
  keeps the old key set if a refresh parse fails.

- ~~**`storage.stage:` not enforced**~~ ✓ **DONE:** `src/auth/token/scopes.c` now maps
  `storage.stage:` to `read = 1`, matching the WLCG token profile intent that
  stage is a read-like capability for tape-recall workflows. `openid` / `profile`
  scopes are still parsed but grant no storage privileges (correct behavior).

### kXR_prepare / kXR_stage (item 7 — FRM/Tape REST implemented; full MSS parity partial)

- ~~**Former tape-dispatch gap**~~ ✓ **UPDATED:** `src/frm/` now provides a
  durable FRM-style stage queue, host-qualified request ids, cancel handling,
  and queue-backed `kXR_QPrep` states when `xrootd_frm on` is configured.
  WebDAV Tape REST gateway support also exists. This is still narrower than the
  full upstream XrdFrm/MSS ecosystem, so tape-backed sites must validate their
  actual stage, cancel, evict, purge, and recall workflows.

- ~~**Former tape-recall state gap**~~ ✓ **UPDATED:** FRM-enabled operation can
  report queued/staging/failed/available state from durable records. FRM-off mode
  intentionally keeps the legacy disk-only `A <path>` / `M <path>` behavior and
  request id `"0"`.

### Full hierarchical CMS cluster (item 11 — core done; tests + gateway plan remaining)

`kYR_select`, `kYR_try`, and the `XRD_ST_WAITING_CMS` session-suspension
mechanism are all implemented (M6 steps 1–6). Remaining gaps:

- **Former `kYR_try` integration-test gap** ✓ **DONE:** `TestCmsKyrTry` in
  `tests/test_manager_mode.py` exercises a parent CMS `kYR_try` response with
  multiple alternatives and verifies nginx redirects to the first entry.

- **Former true CMS-escalation three-tier test gap** ✓ **DONE:**
  `TestCmsEscalation` in `tests/test_manager_mode.py` covers a sub-manager
  registry miss, parent `kYR_locate`, parent `kYR_select`, client wakeup, and
  leaf open.

- **Proxy/gateway integration plan:** The pending-locate infrastructure can
  power a "select-then-proxy" gateway where, instead of redirecting the client
  to a CMS-selected backend, nginx proxies the request on the client's behalf.
  This is documented in `docs/05-operations/hierarchical-cluster.md`
  §Proxy/gateway integration.

### Cross-cutting gaps

- ~~**`kXR_chmod` has no access control check**~~ ✓ **CLARIFIED:**
  `src/protocols/root/write/op_table.c`'s `xrootd_dispatch_op()` runs `xrootd_auth_gate()`
  (authdb `XROOTD_AUTH_UPDATE` + VO ACL + token scope) before dispatching to
  `chmod(2)` via the `exec_chmod` descriptor. The roadmap entry was stale.

- **Former POSC gap** ✓ **DONE:** `kXR_open` with `kXR_posc` now opens a
  temp file (`.posc.<pid>.<rand>` in the same directory) and stores the final
  target in `xrootd_file_t.posc_final_path`. On `kXR_close` the temp is
  `fsync`d then atomically renamed to the final path. On disconnect or error the
  temp is unlinked by `xrootd_free_fhandle()`. See `src/protocols/root/read/open.c`,
  `src/protocols/root/read/close.c`, `src/protocols/root/connection/fd_table.c`.

- **Former CRL delta-update gap** ✓ **DONE:**
  stream GSI and WebDAV X.509 stores enable `X509_V_FLAG_USE_DELTAS` alongside
  full-chain CRL checking when CRLs are configured.

- **Former OCSP gap** ✓ **DONE:** `src/auth/crypto/ocsp.c` implements client-cert
  OCSP responder queries and server-cert staple fetching; `src/protocols/root/session/tls_config.c`
  attaches cached staples during TLS handshakes. See `tests/test_ocsp.py`.

- **Former WebDAV `PROPPATCH` 501 gap** ✓ **DONE:** See WebDAV PROPFIND section above.

- **Former authdb `kXR_dirlist` bypass** ✓ **DONE:** `src/protocols/root/dirlist/handler.c` now
  calls `xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_LOOKUP)` before
  `xrootd_check_vo_acl()`.

- ~~**Authdb not applied to `query/` or `fattr/` handlers**~~ ✓ **DONE:**
  `src/protocols/root/query/checksum_qcksum.c`, `src/protocols/root/query/checksum_ckscan_dispatch.c`,
  `src/protocols/root/query/metadata.c`, `src/protocols/root/query/prepare.c`, and `src/protocols/root/fattr/dispatch.c`
  all now call `xrootd_check_authdb()` with the
  appropriate privilege (`XROOTD_AUTH_READ` for queries; `XROOTD_AUTH_READ` or
  `XROOTD_AUTH_UPDATE` depending on fattr subcode) before the vo_acl check.

- ~~**Authdb file size limit**~~ ✓ **DONE:** `src/auth/authz/authdb.c` now uses
  `ngx_fd_info()` to determine the exact file size at config time and allocates
  accordingly, with a hard 1 MiB cap (logs `NGX_LOG_EMERG` and aborts startup
  if exceeded). Silent truncation at 4096 bytes is gone.

- ~~**S3 `ListObjectsV2` `fetch-owner` and `encoding-type` not handled**~~ ✓ **DONE:**
  `src/protocols/s3/list.c` now parses both query parameters. `fetch-owner=true` adds an
  `<Owner>` element (using the configured `access_key` as both ID and display name)
  to each `<Contents>` entry. `encoding-type=url` percent-encodes key characters
---

## 13. Write-through PFC cache mode

**Status:** Implemented as close/sync whole-file origin mirroring. [Implementation note](./pfc-write-through-plan.md).

**What is it:** Write-through mode allows a client to open a file for writing,
commit local writes normally, and mirror dirty data to an origin XRootD data
server when the client issues `kXR_sync` or `kXR_close`.

**Why it matters:** Enables "active cache" deployments where the cache node
is used as a gateway for both reads and writes. This is common in federated
storage systems where regional caches need to handle data ingest from local
instruments or jobs.

**Implemented in:**
- `src/fs/cache/writethrough_decision.c` — WT policy evaluation.
- `src/fs/cache/writethrough_flush.c` — local-to-origin mirror worker.
- `src/fs/cache/origin_protocol.c` — origin write, truncate, sync, and close helpers.
- `src/protocols/root/read/open_resolved_file.c`, `src/protocols/root/write/*.c`, `src/core/aio/write.c`,
  `src/protocols/root/read/close.c`, `src/protocols/root/write/sync.c` — handle state, dirty tracking, and
  flush integration.

**Caveat:** This is whole-file replacement at sync/close, not a persistent
per-write dual-dispatch path. Origin authentication follows the cache-origin
client, not the native TPC client: cache/write-through origins may use configured
origin TLS, but login is still anonymous and `kXR_authmore` is not completed.

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
