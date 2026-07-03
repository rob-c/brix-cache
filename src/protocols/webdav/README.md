# webdav — HTTP/WebDAV/HTTPS gateway (`davs://`, `http://`) over the export root

## Overview

This subsystem is the **HTTP face** of `nginx-xrootd`. It registers an nginx
HTTP **content handler** plus a chain of access/precontent/log-phase handlers in
a `location` marked `brix_webdav on`, and projects the same on-disk export
root that the `root://` stream side and the S3 side serve. It speaks standard
WebDAV (curl, rclone, davix, Cyberduck, Microsoft Office), the WLCG HTTP-TPC
third-party-copy dialect (FTS, RUCIO), and the XRootD-aware **XrdHttp**
extension (`xrdcp --prefer-xrdhttp`, ROOT `TFile`) — all over the same handler.
It replaces both nginx's built-in `ngx_http_dav_module` and the XRootD reference
`XrdHttp` plugin so that one daemon serves every HEP grid transfer protocol.

Where it sits in the request lifecycle: an HTTP request to a WebDAV location is
processed in nginx phases. The **access phase** (`access.c`,
`introspect.c`, plus the shared rate-limit handler) does CORS, request metrics,
authentication (GSI proxy cert then bearer token), the global write gate, and
token-scope checks — so the content handler always sees a pre-authenticated
request. The **precontent phase** fires traffic-mirror shadow subrequests
(`../mirror/`). The **content phase** (`dispatch.c`) routes by HTTP method to
the per-method handler, which confines the URI to the export root via
`../path/` and performs the filesystem operation through `../fs/` (VFS) and
`../aio/` (thread-pool offload). The **log phase** charges bandwidth and stamps
mirror-divergence status.

The module covers the full WebDAV method set (GET/HEAD/OPTIONS/PUT/DELETE/
MKCOL/MOVE/COPY/PROPFIND/PROPPATCH/LOCK/UNLOCK/SEARCH/ACL), three TPC variants
(local server-side COPY, curl-based pull/push HTTP-TPC with WLCG Performance
Markers, and OAuth2/OIDC credential delegation), a macaroon token-issuance
endpoint, an OIDC-introspection revocation path, and a transparent upstream
HTTP(S) **proxy mode** with static and dynamic (SHM) backend pools. A large
shared infrastructure lives one directory up (`../compat/`, `../crypto/`,
`../token/`, `../metrics/`, `../mirror/`, `../ratelimit/`, `../shm/`); this
subsystem is the HTTP-specific glue plus the WebDAV/XrdHttp protocol logic.

## Files

### Module wiring & configuration

| File | Responsibility |
|------|----------------|
| `module.c` | The `ngx_module_t` object + `ngx_http_module_t` ctx + the full `ngx_command_t` directive table (declarative data — kept here, watch tier per §2.6). *(Phase 38: logic extracted.)* |
| `module_directives.c` | The custom directive setters (`webdav_conf_*`: CORS origins, dig export, proxy-auth/upstream, open-file-cache). *(Phase 38 split of `module.c`.)* |
| `module_init.c` | Phase handlers + per-worker `init_process`/`exit_process` (`curl_global_init`) + the protocol-variable wiring. *(Phase 38 split of `module.c`.)* |
| `webdav_module_internal.h` | Private split contract shared by `module*.c`. |
| `config.c` | Location config `create_loc_conf`/`merge_loc_conf`; startup validation: canonicalize export root, build cached `X509_STORE`, load JWKS, validate TPC/CA/CRL paths, parse upstream URLs. |
| `postconfig.c` | Registers handlers into ACCESS/PRECONTENT/CONTENT/LOG phases; sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on SSL contexts when `proxy_certs on`; resolves the async thread pool. |
| `webdav.h` | Umbrella header: `ngx_http_brix_webdav_loc_conf_t`, per-request `ngx_http_brix_webdav_req_ctx_t`, lock structs, auth enums, every cross-file prototype, and inline helpers (`webdav_send_no_body`, TPC header macros). Includes `xrdhttp.h`. |
| `pki.c` | `webdav_check_pki_consistency` — fail `nginx -t` if CA/CRL paths are missing/invalid (delegates to `../crypto/pki_check.h`). |

### Dispatch & generic helpers

| File | Responsibility |
|------|----------------|
| `dispatch.c` | Content-handler entry `ngx_http_brix_webdav_handler`: routes by `r->method`/`r->method_name`; pre-body lock check for PUT/MOVE; COPY → distinguishes TPC pull (`Source:`), TPC push (`Credential:`), local server-side copy; emits `Allow:` for unknown methods (405). |
| `access.c` | `ngx_http_brix_webdav_access_handler`: CORS, request metrics, IP-rate-limit shed, auth gate (cert→token), XrdHttp parse, global `allow_write` write-method gate, token write-scope check; skips re-auth for mirror subrequests. |
| `operation_table.c` | `brix_webdav_operations[]` descriptor table — one row per method with metric slot + capability flags (`BRIX_PROTO_OP_READ/WRITE/LIST/LOCK/TPC`); drives Allow/CORS strings and write-method detection. |
| `path.c` | `ngx_http_brix_webdav_resolve_path` / `webdav_resolve_destination_path`: urldecode + strip trailing slashes + confine via `brix_http_resolve_path`; maps resolver codes to HTTP (404→409 Conflict for COPY/MOVE parents). |
| `resource.c` | `webdav_resolve_stat` — resolve-then-VFS-stat in one call for GET/HEAD/PROPFIND; maps ENOENT→404. |
| `io.c` | Blocking write helpers shared by PUT: `webdav_write_full`, `webdav_copy_spooled_file` (delegates to `copy_file_range` body writer), `webdav_fadvise_willneed`. |
| `metrics.c` | Maps method→metric slot and unified op; `webdav_metrics_request/response/return/finalize_request` — request and per-method/status-class counters. |
| `cors.c` | `webdav_add_cors_headers` — single CORS entry point; origin allowlist match (incl. `*`), credentials, max-age, preflight Allow-Methods. |

### HTTP method handlers

| File | Responsibility |
|------|----------------|
| `get.c` | GET via VFS open (read-through cache aware) → `brix_http_serve_file_ranged` (shared ranged sendfile); routes multi-range to XrdHttp multipart; If-Modified-Since; checksum/XrdHttp headers; range + byte-transfer metrics. |
| `put.c` | PUT body callback: thread-pool async write (memory body), synchronous spooled-file copy, or in-memory `pwrite`; ETag preconditions; gzip/deflate `Content-Encoding` inflate; 201/204; missing parent → 409. |
| `methods_basic.c` | OPTIONS (DAV/DASL/Allow/MS-Author-Via), HEAD (`webdav_resolve_stat`, Content-Type, ETag, Want-Digest), and PROPPATCH (dead-property set/remove via xattr, 207 Multi-Status). |
| `namespace.c` | DELETE (recursive collection delete via `../compat/fs_walk`, tree lock check) and MKCOL (delegates to `brix_ns_mkdir`). |
| `copy.c` | RFC 4918 COPY (local, same-root): Destination/Overwrite/Depth parse, staged temp-path + atomic rename, recursive dir copy (thread-pool offloaded), xattr/dead-prop preservation, self-copy → 403. |
| `move.c` | RFC 4918 MOVE: confined `rename(2)` via `brix_ns_rename`; collection moves offloaded to thread pool; Overwrite:F → 412, self-move → 403, non-empty dest dir → 409. |
| `propfind.c` | RFC 4918 PROPFIND entry/dispatch: request + Depth parse, prop-name→bit, body assembly. *(Phase 38: split.)* |
| `propfind_props.c` | The per-resource property emitter `propfind_entry` + RFC 3744 ACL property append. *(Phase 38 split of `propfind.c`.)* |
| `propfind_walk.c` | Depth traversal `propfind_walk` + the `propfind_do` Multi-Status orchestration. *(Phase 38 split of `propfind.c`.)* |
| `propfind_internal.h` | Private split contract shared by `propfind*.c`. |
| `lock.c` | RFC 4918 LOCK/UNLOCK; `webdav_check_locks` (ancestor walk) and `webdav_check_locks_tree` (+descendant scan); lock token UUID; lockdiscovery/supportedlock XML; `webdav_lock_startup_sweep`. |
| `search.c` | RFC 5323 DAV:basicsearch — conservative subset: scope walk + optional `DAV:contains`/`literal` displayname substring filter. |
| `acl.c` | RFC 3744 ACL method — write is protected; always returns 403 `cannot-modify-protected-property` (ACL is read-only via PROPFIND). |
| `dead_props.c` | Dead (client-owned) WebDAV properties persisted as `user.nginx_xrootd.webdav.*` xattrs; set/remove/append/copy; protects live DAV: props. |
| `prop_xattr.c` | xattr encode/decode/read/write/delete for the lock record (`user.nginx_xrootd.lock`); `XATTR_CREATE` gives atomic cross-worker lock creation. |

### Authentication

| File | Responsibility |
|------|----------------|
| `auth_cert.c` | `webdav_verify_proxy_cert` — GSI/x509 proxy chain verification with a two-tier per-TLS-connection + per-SSL_SESSION auth cache (OpenSSL ex_data); optional VOMS VO extraction; populates `brix_identity_t`. |
| `auth_token.c` | `webdav_verify_bearer_token` (WLCG JWT via JWKS + macaroon secret, grace-period old-secret fallback, cross-worker token cache) and `webdav_check_token_write_scope` (path-prefix write-scope on the raw URI). |
| `auth_store.c` | `webdav_build_ca_store` — build the `X509_STORE` from `cadir`/`cafile`/`crl` (no proxy certs in the plain trust store). |
| `introspect.c` | OIDC RFC 7662 token-introspection revocation as a second access-phase handler: SHM revoke-cache fast path, non-blocking `ngx_http_subrequest` to the IdP, fail-open/closed policy. |
| `macaroon_endpoint.c` | `POST /.oauth2/token` (issue scoped WLCG macaroon) + `GET /.well-known/oauth-authorization-server` discovery; maps `storage.*` scopes → macaroon activity/path caveats. |

### HTTP-TPC (third-party copy)

| File | Responsibility |
|------|----------------|
| `tpc.c` | HTTP-TPC COPY orchestrator (pull & push): authz, path resolution, transfer-registry registration, dashboard tracking; chooses sync, thread, or 202-marker path. |
| `tpc_curl.c` | The libcurl transfer driver `webdav_tpc_run_curl_core` + pull/push/multi entry points (HTTPS-only). *(Phase 38: split.)* |
| `tpc_curl_setup.c` | Curl handle setup: `tpc_curl_secure` (SSRF-validated `CURLOPT_RESOLVE`, `SSL_VERIFYPEER/HOST`), conf + stall-bound application, HEAD size probe. *(Phase 38 split of `tpc_curl.c`.)* |
| `tpc_curl_pmark.c` | SciTags packet-marking socket hooks + the curl progress/finish/write callbacks. *(Phase 38 split of `tpc_curl.c`.)* |
| `tpc_curl_internal.h` | Private split contract shared by `tpc_curl*.c`. |
| `tpc_thread.c` | Thread-pool wrapper that moves the blocking curl transfer off the event loop; falls back to sync when no pool. |
| `tpc_marker.c` | `202 Accepted` + chunked WLCG Performance-Marker streaming while curl runs; single- and multi-stream (`X-Number-Of-Streams`) pull with per-stripe byte counters and a poll timer. |
| `tpc_headers.c` | `webdav_tpc_collect_transfer_headers` — collect `TransferHeader*` request headers into curl headers; reject control chars (400). |
| `tpc_config.c` | TPC location defaults + parent→child inheritance (curl path, timeout, SSRF policy, cert/key fallback to WebDAV CA, OAuth2 scope). |
| `tpc_cred.c` | OAuth2/OIDC credential delegation for pull: `oidc-agent` UNIX-socket IPC or RFC 8693 token-exchange; metric helpers. |
| `tpc_cred_parse.c` | Parse the OAuth2 token JSON response (`access_token`) into an `r->pool` string (bounded). |
| `tpc_config.h`, `tpc_cred.h`, `tpc_cred_internal.h` | TPC config struct, credential-mode enum/API, and internal-only constants. |

### Upstream proxy mode

| File | Responsibility |
|------|----------------|
| `proxy.c` | `webdav_proxy_handler` — entry point; creates the nginx upstream, wires lifecycle callbacks, selects a backend (static array or dynamic SHM pool). |
| `proxy_request.c` | Build the backend request: rewrite `Destination:` public→internal URL, strip hop-by-hop headers, apply auth policy (anonymous/forward/static-token). |
| `proxy_response.c` | Upstream response callbacks: parse status line then header loop, relay to client. |
| `proxy_config.c` | Parse the proxy-URL list into resolved `brix_webdav_backend_t[]` (multi-backend, round-robin + passive health); legacy single-backend aliased to `backend[0]`. |
| `proxy_pool.c` / `proxy_pool.h` | Phase 23 dynamic SHM backend pool: runtime add/remove/drain/undrain via the REST admin API, weighted round-robin skipping DRAINING/DEAD, atomic `in_flight` for safe draining. |
| `proxy_internal.h` | Proxy-mode-only header: `webdav_proxy_ctx_t`, `brix_webdav_backend_t`, and the six upstream lifecycle prototypes. |

### XrdHttp protocol extension

| File | Responsibility |
|------|----------------|
| `xrdhttp.h` / `xrdhttp.c` | XrdHttp parity: detect `X-Xrootd-Proto`, parse `?xrd.*`/`?tpc.*` params, echo `X-Xrootd-Requuid`, emit `X-Xrootd-Status` (kXR codes), Wait/Retry, redirect dialect, on-demand `Digest:`, HTTP→kXR status map. |
| `xrdhttp_filter.c` | Separate `HTTP_AUX_FILTER` module that chains the XrdHttp header + Digest body filters *after* the core header filter (so direct call-site injection plus error-page paths both get `X-Xrootd-Status`). |
| `xrdhttp_multipart.c` | `multipart/byteranges` GET (RFC 7233) = kXR_readv-over-HTTP vector read; file-backed data bufs + memory boundary bufs, sendfile-eligible. |
| `xrdhttp_stats.c` | `?xrd.stats` XML endpoint in XRootD 5.x format from the SHM metrics zone — observable by `xrd_mon`/`xrdfs query stats`; aggregate counters only. |

## Key types & data structures

- **`ngx_http_brix_webdav_loc_conf_t`** (`webdav.h`) — the per-location
  configuration. Embeds the shared `ngx_http_brix_shared_conf_t common`
  (enable, root, `root_canon`, `allow_write`, thread pool) and adds GSI/CA
  fields + cached `ca_store`, bearer-token (JWKS/issuer/audience/macaroon
  secret + grace key), CORS, LOCK policy, optional read-through `cache_root`,
  HTTP-TPC + SSRF policy + OAuth2 delegation, upstream proxy (static and dynamic
  pool), token-cache/rate-limit SHM handles, OIDC introspection, traffic mirror,
  and advanced rate-limit rules.
- **`ngx_http_brix_webdav_req_ctx_t`** (`webdav.h`) — per-request context
  (`r->pool`). **Its first member is `xrdhttp_req_ctx_t xrdhttp`** so a pointer
  to this struct can be cast to `xrdhttp_req_ctx_t *` (C11 §6.7.2.1p15). Carries
  the auth result (`verified`, `auth_source`, `dn`, canonical `identity`,
  token scopes), LOCK metadata, OIDC-introspection state, mirror state, and
  rate-limit charge targets.
- **`brix_webdav_operations[]` / `brix_http_operation_t`**
  (`operation_table.c`) — the method descriptor table (name, nginx method,
  metric slot, capability flags). The single source of truth for which methods
  are writes, the Allow/CORS method strings, and metric classification.
- **`webdav_lock_xattr_t`** (`webdav.h`, encoded by `prop_xattr.c`) — a WebDAV
  lock stored as one xattr: token, owner, absolute expiry (msec), exclusive,
  depth-infinity. No shared memory or lock table.
- **`xrdhttp_req_ctx_t`** (`xrdhttp.h`) — XrdHttp signals: proto version, client
  UUID/app, want-cksum, opaque blob, tpc.src/dst/key/token, request UUID echo,
  wait/retry, streaming-Digest adler32 accumulator.
- **`brix_webdav_backend_t` / `brix_proxy_be_table_t` / `webdav_proxy_ctx_t`**
  (`proxy_internal.h`, `proxy_pool.h`) — static resolved backend (with passive
  health counters), the SHM dynamic-pool table + entries, and the per-request
  proxy state.
- **`tpc_ms_progress_t`** (`webdav.h`) — atomic per-stream byte counters shared
  between the curl thread and the marker poll timer during 202-streaming TPC.

## Control & data flow

Entry is via nginx HTTP phase handlers registered in `postconfig.c`:

1. **Access phase** (`access.c`): if `!conf->common.enable` → `NGX_DECLINED`
   (not our location). Otherwise CORS + request metric, optional per-IP rate
   shed, then the auth gate — `webdav_verify_proxy_cert` (`auth_cert.c`) then
   `webdav_verify_bearer_token` (`auth_token.c`); `auth=required` rejects
   anonymous with 403. Then `xrdhttp_parse_request`, the global write gate
   (`allow_write`), and `webdav_check_token_write_scope`. `introspect.c` runs as
   a second access handler; `../ratelimit/` as a third.
2. **Precontent phase**: `../mirror/` (`brix_http_mirror_precontent_handler`)
   fires shadow subrequests and takes over mirror subrequests.
3. **Content phase** (`dispatch.c`): routes to the per-method handler. Each
   handler calls `ngx_http_brix_webdav_resolve_path` (`path.c`) to confine the
   URI under `root_canon`, `webdav_check_locks[_tree]` (`lock.c`) where mutation
   is involved, then performs the operation through `../fs/` (VFS open/stat),
   `../shared/file_serve.h` (ranged sendfile for GET), `../compat/namespace_ops.h`
   (DELETE/MKCOL/MOVE/local COPY), and `../aio/` (PUT/large-copy thread offload).
4. **Log phase**: bandwidth charge (`../ratelimit/`) + mirror-divergence status.

Outbound calls into sibling subsystems:
[`../path/`](../path/README.md) (confinement),
[`../fs/`](../fs/README.md) (VFS),
[`../aio/`](../aio/README.md) (thread-pool I/O),
[`../cache/`](../cache/README.md) (read-through cache, via VFS),
[`../shared/`](../shared/README.md) (`file_serve`),
[`../compat/`](../compat/README.md) (path resolver, http body/headers/xml, ETag,
namespace ops, fs_walk, net_target/SSRF, staged_file),
[`../crypto/`](../crypto/README.md) (GSI verify, PKI build),
[`../token/`](../token/README.md) (JWT/macaroon/OAuth2, token cache),
[`../gsi/`](../gsi/README.md) & [`../voms/`](../voms/README.md) (cert identity),
[`../metrics/`](../metrics/README.md) (counters),
[`../mirror/`](../mirror/README.md) (shadow replay),
[`../ratelimit/`](../ratelimit/README.md) (advanced limits),
[`../tpc/`](../tpc/README.md) (transfer registry, authz, credential common),
[`../dashboard/`](../dashboard/README.md) (live transfer tracking),
[`../shm/`](../shm/README.md) (KV/rate-limit zones).
The S3 face ([`../s3/`](../s3/README.md)) is a sibling HTTP handler that shares
the same export root and the same `../compat`/`../fs` core but never shares auth
logic (SigV4 ≠ WLCG token).

## Invariants, security & gotchas

- **Kernel confinement is mandatory.** Every client URI and `Destination:` is
  resolved through `brix_http_resolve_path` / the `../path/` `RESOLVE_BENEATH`
  confinement before any syscall (`path.c`). In `get.c`, VFS errors `EXDEV`/
  `ELOOP` (escape attempts) and `EACCES`/`EPERM` map to **403, never 500**.
  Never call a raw `open`/`stat` on a client path.
- **Fail-closed auth, two-domain isolation.** Auth proceeds only on explicit
  `NGX_OK`; `auth=required` rejects anonymous (`access.c:138`). The global
  `allow_write` write gate (`access.c:170`) is checked **before** token scope
  (invariant: write gate before scope). WLCG tokens and S3 SigV4 never share
  logic. Token write-scope is checked against the **raw decoded URI**, not the
  filesystem path (`auth_token.c`), with exact-prefix matching in `../token/`.
- **TLS vs cleartext buffers never mix.** GET ranged serving and XrdHttp
  multipart use file-backed data bufs (sendfile-eligible) + memory boundary
  bufs; nginx's sendfile filter handles the mixed chain (`xrdhttp_multipart.c`).
  The shared `file_serve` honors the TLS-memory vs cleartext-sendfile rule.
- **Event loop, no blocking in handlers.** PUT writes, collection COPY/MOVE, and
  the curl TPC transfer are offloaded to the thread pool; the request is kept
  alive with `r->main->count++` and finalized in the `_done` event on the loop
  (`put.c`, `copy.c`, `move.c`, `tpc_thread.c`). When no thread pool is
  configured these fall back to the synchronous path.
- **Locks are xattr-based, not SHM.** A lock is one xattr on the resource
  (`prop_xattr.c`), written through the VFS xattr seam
  (`brix_vfs_setxattr` with `XATTR_CREATE`) — kernel-atomic cross-worker
  creation (EEXIST → 423), confined and impersonation-aware. Expiry cleanup is
  lazy on next access. Lock checks walk path→root in O(depth); collection
  mutations also scan descendants (`webdav_check_locks_tree`). Locks **survive
  restart** unless `brix_webdav_lock_startup_sweep on` clears them (the sweep
  removes each persisted lock xattr via `brix_vfs_removexattr`; RFC 4918 §10.1
  ephemeral semantics). (Note: an earlier SHM lock table with a 1024-lock cap no longer
  exists — the xattr design is the current, correct implementation.)
- **Recursive lock checks on collections** (`lock.c`): DELETE/COPY/MOVE on a
  directory must check ancestor *and* descendant locks, not just the target.
- **SSRF hardening for TPC** (`tpc_curl.c`): HTTPS-only, `SSL_VERIFYPEER/HOST`
  forced on, and the SSRF-validated IP is pinned via `CURLOPT_RESOLVE` to close
  the DNS-rebind TOCTOU window; loopback denied, RFC-1918 allowed by default
  (HEP federation nodes are commonly on private nets), both configurable.
- **PROPPATCH compatibility hack** (`methods_basic.c`): Cyberduck/rucio treat a
  501 after PUT as fatal, so dead-prop set/remove always returns a 207 with
  per-property status rather than refusing.
- **XrdHttp header filter ordering** (`xrdhttp_filter.c`): the header filter
  *must* live in a separate `HTTP_AUX_FILTER` module, because the core header
  filter installs itself by direct assignment and would clobber a filter
  registered from this module's postconfiguration. The filter is idempotent with
  the direct call-site injections (guarded by `headers_injected`).
- **Metric labels stay low-cardinality** — method/status-class only; no
  paths/DNs/buckets/UUIDs (`metrics.c`, `xrdhttp_stats.c`). `?xrd.stats` exposes
  aggregate counters only; restrict access via nginx location directives.
- **`ngx_str_t` is not NUL-terminated** and all request-pool allocation uses
  `ngx_palloc(r->pool, …)` (see `webdav.h` inline helpers and `../../CLAUDE.md`).

## Entry points / extending

- **Add a WebDAV method:** implement `webdav_handle_<m>` in a `.c` here, declare
  it in `webdav.h`, route it in `dispatch.c` (by `r->method` or `r->method_name`
  length+`ngx_strncmp`), add a row to `brix_webdav_operations[]` in
  `operation_table.c` (name, method, metric slot, capability flags — this drives
  the Allow header, write gate, and CORS), and add a metric slot if needed. Three
  tests per the project rule: success + error + security-negative.
- **Add a config directive:** add the field to
  `ngx_http_brix_webdav_loc_conf_t` (`webdav.h`, sentinel `NGX_CONF_UNSET*`),
  the `ngx_command_t` row in `module.c`, and the `ngx_conf_merge_*` line in
  `config.c` (or `tpc_config.c` for TPC, `proxy_config.c` for proxy). No
  `./configure` unless you add a new `.c` file (register it in the top-level
  `config` script — the module's `ngx_module_srcs` / `NGX_ADDON_SRCS` list).
- **Add an XrdHttp signal:** extend `xrdhttp_req_ctx_t` (`xrdhttp.h`), parse it
  in `xrdhttp_parse_request` and emit it in `xrdhttp_add_response_headers`
  (`xrdhttp.c`); fixed-size fields only (bound untrusted client input).
- **Add a metric:** follow `../metrics/README.md` (enum + field + export) then
  `BRIX_WEBDAV_METRIC_INC(slot)` at the call site.

## See also

- [`../README.md`](../README.md) — master subsystem index
- [`../s3/README.md`](../s3/README.md) — sibling HTTP face (S3 REST), same root, distinct auth
- [`../path/README.md`](../path/README.md) — RESOLVE_BENEATH confinement
- [`../fs/README.md`](../fs/README.md) / [`../aio/README.md`](../aio/README.md) — VFS + thread-pool I/O
- [`../cache/README.md`](../cache/README.md) — read-through / write-through cache
- [`../tpc/README.md`](../tpc/README.md) — TPC transfer registry & native (stream) TPC
- [`../token/README.md`](../token/README.md) / [`../gsi/README.md`](../gsi/README.md) / [`../crypto/README.md`](../crypto/README.md) — auth building blocks
- [`../mirror/README.md`](../mirror/README.md) / [`../ratelimit/README.md`](../ratelimit/README.md) / [`../metrics/README.md`](../metrics/README.md) / [`../dashboard/README.md`](../dashboard/README.md) — cross-cutting
- [`../compat/README.md`](../compat/README.md) — shared HTTP/path/XML/namespace helpers
