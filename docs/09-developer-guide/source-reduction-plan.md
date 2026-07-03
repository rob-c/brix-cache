# Source Reduction Plan: External Libraries and Nginx Built-ins

This guide evaluates where BriX-Cache can reduce local C source by using
external libraries and existing nginx modules more aggressively, without
weakening the project-specific guarantees around XRootD wire compatibility,
path confinement, auth policy, metrics, and WLCG interoperability.

The goal is not to remove code at any cost. The goal is to delete code that is
expensive to maintain because it implements generic parsing, cryptography, or
serialization better handled by mature libraries.

## Baseline

Measured from the current tree on 2026-05-20:

| Area | Approx. local C/header LOC | Notes |
|---|---:|---|
| `src/protocols/webdav` | 12,176 | Largest single area; includes DAV methods, TPC, locks, proxy mode, XrdHttp compatibility. |
| `src/protocols/s3` | 4,923 | SigV4, XML responses, object/multipart operations. |
| `src/net/proxy` | 3,897 | Native XRootD transparent proxy state machine. |
| `src/tpc` | 3,796 | Native XRootD third-party copy and outbound GSI helpers. |
| `src/fs/cache` | 3,709 | Cache origin client, fills, eviction, write-through. |
| `src/protocols/root/query` | 2,765 | Query subtypes, checksum scans, prepare/stage. |
| `src/auth/token` | 2,658 | JWT/JWKS/scopes/macaroons/base64/json. |
| `src/path` | 2,885 | Path confinement, ACL/authdb; keep mostly local. |
| `src/core/aio` | 2,131 | nginx thread-pool file I/O; keep mostly local. |
| `src/auth/gsi` + `src/auth/sss` + `src/auth/crypto` | 4,315 | Security protocol glue and PKI/OCSP helpers. |
| Whole `src/` tree | 68,893 | All C/header files. |

The most promising reduction targets are therefore:

1. WebDAV method implementation.
2. Token, macaroon, JSON, XML, and checksum helpers.
3. HTTP proxy/TPC orchestration where nginx already has upstream machinery.
4. Repeated local buffer builders that can share small commodity adapters.

## Executive Estimate

These are net estimates: gross local code deleted minus wrapper/adaptor code
that would be added.

| Strategy | Net source reduction | Percent of `src/` | Confidence | Main tradeoff |
|---|---:|---:|---|---|
| Conservative: libxml2 + JWT/JWK library + checksum adapter + small DAV delegation | 2,500-4,500 LOC | 4-7% | High | Few build/deployment shocks, moderate payoff. |
| Balanced: conservative + broader nginx DAV/static delegation + WebDAV proxy simplification | 4,500-7,000 LOC | 7-10% | Medium | More behavior migration, still no new C++ client dependency. |
| Aggressive: balanced + patched/vendored nginx DAV core | 6,000-9,000 LOC | 9-13% | Medium-low | Larger DAV semantic migration; needs heavy conformance testing. |
| Extreme: replace broad S3 surface with an external S3 gateway/library | Not recommended | N/A | Low | Likely increases dependency and ops complexity more than it removes code. |

The best near-term target is the conservative plan. XrdCl is intentionally no
longer part of this roadmap because BriX-Cache is moving toward replacing the
XRootD server role outright rather than embedding the upstream client as a
large outbound dependency.

**Additional items from the second-pass analysis (Candidates 9-11, 2026-05-20):**

| Item | Net LOC change | Correctness benefit | Priority | Status |
|---|---:|---|---|---|
| TPC thread-pool wrapping (Design A) | ~0 | Fixes worker event-loop blocking on every TPC | Immediate | **Done 2026-05-20** |
| Config-time upstream DNS pre-resolution | ~+30 | Eliminates per-request getaddrinfo() on hot path | Immediate | **Done 2026-05-20** |
| TPC → libcurl CURLM (Design B) | −100 to −250 | Same fix + removes external binary dependency | Medium-term | Planned |
| date.c → ngx_http_time() | −70 | None (correctness is already fine) | Any time | **Done 2026-05-20** |
| Jansson fallback deletion (Jansson now required) | −345 | None | Any time | **Done 2026-05-20** |
| lock.c owner XML escaping fix | ~0 | Fixes XML injection via GSI DN in LOCK response | Any time | **Done 2026-05-20** |

**Additional items from the third-pass analysis (Candidates 13-18, 2026-05-20) — internal consolidation:**

| Item | Net LOC change | Area | Priority |
|---|---:|---|---|
| TPC curl pull/push deduplication (Candidate 14) | −60 to −120 | src/protocols/webdav/tpc_curl.c | Medium (pairs with Design B) |
| AIO dispatch pattern consolidation (Candidate 13) | −80 to −160 | src/core/aio/*.c | Medium |
| Pool alloc null-check macro (Candidate 15) | −150 to −200 | All of src/ | Low (mechanical) |
| Dead code audit (Candidate 18) | −50 to −200 | All of src/ | Medium (audit first) |
| Shared-memory registry template (Candidate 16) | −10 to −60 | src/tpc/, src/protocols/root/session/ | Low |
| GSI X.509 OpenSSL delegation (Candidate 17) | −30 to −70 | src/auth/gsi/ | Low (security-critical) |

The correctness items (blocking event loop) are independent of the LOC
reduction roadmap but should be addressed first because they affect production
reliability.

**Completed internal sharing pass (2026-05-21):**

| Item | Primary helper | Areas migrated | Source impact |
|---|---|---|---:|
| Request-header lookup/set and value checks | `src/core/http/http_headers.c` | WebDAV TPC/CORS, S3 SigV4/CopyObject/util headers | moderate deletion, fewer private scans |
| Request-body chain handling | `src/core/http/http_body.c` | WebDAV PUT/PROPFIND, S3 PUT/DeleteObjects | removes duplicate spooled/memory loops |
| HTTP conditional headers | `src/core/http/http_conditionals.c` | WebDAV GET/PUT/COPY/MOVE | centralizes ETag list and `Overwrite:F` handling |
| Checksum algorithms | `src/core/compat/checksum.c` | `kXR_Qcksum`, `kXR_Qckscan`, dirlist `dcksm`, XrdHttp Digest | removes parallel adler/crc/digest dispatch |
| Recursive filesystem mechanics | `src/core/compat/fs_walk.c` | WebDAV DELETE/access checks, S3 MPU cleanup, Qckscan/PROPFIND dot filtering | removes repeated dot-entry/remove-tree code |
| Staged temp-file lifecycle | `src/core/compat/staged_file.c` | S3 PUT/CopyObject, WebDAV COPY, WebDAV TPC pull | centralizes temp open/commit/abort |
| CMS frame send boilerplate | `src/net/cms/frame_io.c` | CMS client/server send paths | removes duplicate send-all frame assembly |

Guardrail coverage is in `tests/test_cross_protocol_shared_helpers.py`; the
full nginx build with `--with-http_dav_module` also compiles these helpers with
`-Werror`.

## Principles

Keep local code where it is the product:

- XRootD server-side request dispatch, response framing, and handle table.
- Path confinement helpers and authdb/VO/token scope policy.
- Low-cardinality metrics and access logging.
- nginx module configuration and phase integration.
- Protocol-specific compatibility decisions documented in `docs/10-reference/`.

Replace local code where it is commodity:

- XML parsing/building and escaping.
- JSON/JWK parsing and JOSE signature verification.
- Macaroon cryptographic chain verification.
- Checksum implementations where a stable library exists.
- Generic HTTP proxying where nginx `proxy_pass` can own the transport.

## Candidate 1: Use nginx `http_dav_module`

### What nginx already provides

The built-in module at `nginx/src/http/modules/ngx_http_dav_module.c` handles:

- `PUT`
- `DELETE`
- `MKCOL`
- `COPY`
- `MOVE`
- `create_full_put_path`
- `min_delete_depth`
- `dav_access`
- `Depth` and `Overwrite` header handling for the methods above
- recursive directory copy/delete through nginx tree walkers
- temp-file-based PUT using nginx request-body buffering

It does not handle:

- `GET` / `HEAD` (normally `ngx_http_static_module` handles these)
- `OPTIONS`
- `PROPFIND`
- `PROPPATCH`
- `LOCK` / `UNLOCK`
- HTTP-TPC
- WLCG token/GSI auth
- project lock registry semantics
- XrdHttp compatibility headers, checksums, or stats
- custom Prometheus labels/counters
- project path confinement semantics beyond nginx URI mapping

### Why this can help

Current local WebDAV method code that overlaps with nginx DAV includes:

| Current file(s) | Approx. LOC | Possible fate |
|---|---:|---|
| `src/protocols/webdav/put.c` + `src/protocols/webdav/io.c` | 564 | Delegate `PUT` to nginx DAV, keep auth/scope checks in an earlier phase. |
| `src/protocols/webdav/namespace.c` | 210 | Replace DELETE/MKCOL with nginx DAV where semantics match. |
| `src/protocols/webdav/move.c` | 188 | Delegate to nginx DAV after destination/scope/lock precheck. |
| `src/protocols/webdav/copy.c`, `fs/copy_engine.c`, `methods/copy_conditionals.c` | 686 | Delegate same-host local COPY to nginx DAV. |
| `src/protocols/webdav/get.c`, parts of `fd_cache.c` | 350-850 | Potentially delegate GET/HEAD to `ngx_http_static_module` plus filters. |

Gross overlap is roughly 1,600-2,500 LOC for write methods, or 2,200-3,300
LOC if GET/HEAD are also moved toward nginx static file serving. The required
adapter layer is likely 700-1,400 LOC, so net reduction is probably
1,000-2,000 LOC for unmodified nginx DAV delegation.

### Design A: Use unmodified `http_dav_module`

This is the least invasive design.

1. Enable `--with-http_dav_module` in supported builds.
2. Configure locations with nginx's native `dav_methods`.
3. Move BriX-Cache WebDAV auth and write-policy gates out of the content
   handler and into `NGX_HTTP_ACCESS_PHASE` or `NGX_HTTP_PREACCESS_PHASE`.
4. For methods delegated to nginx DAV, return `NGX_DECLINED` from the
   BriX-Cache content handler after auth, scope, CORS, destination, and lock
   checks have already run.
5. Keep BriX-Cache content handlers for `OPTIONS`, `PROPFIND`, `PROPPATCH`,
   `LOCK`, `UNLOCK`, HTTP-TPC, XrdHttp stats, and S3.
6. Add a header filter for CORS, XrdHttp headers, checksum headers, and metrics
   that need to observe nginx DAV/static responses.

Required prechecks before delegation:

- `allow_write` and token-scope enforcement for source path.
- Destination path scope enforcement for `COPY` and `MOVE`.
- `Overwrite` / destination lock checks.
- recursive child-lock checks for collection `DELETE`, `MOVE`, and `COPY`.
- authdb/VO policy if the WebDAV path currently depends on the native helpers.

Risks:

- The current `webdav_resolve_path()` confinement behavior is stricter and more
  project-specific than raw `ngx_http_map_uri_to_path()`.
- Built-in DAV uses request body temp files for PUT. That may be acceptable,
  but it differs from current async PUT behavior and needs performance tests.
- Built-in DAV status codes may differ from XrdHttp/reference xrootd behavior.
- nginx DAV's internal functions are static; an external module cannot call or
  override individual handlers.

Expected deletion:

- Net 1,000-2,000 LOC.
- Highest payoff files: local PUT/COPY/MOVE/MKCOL/DELETE helpers.

### Design B: Patch nginx `http_dav_module` with hooks

Because nginx is already built from source for this module, a small nginx patch
is possible. The patch would keep `ngx_http_dav_module.c` upstream-owned but
add extension hooks such as:

```c
typedef ngx_int_t (*ngx_http_dav_preflight_pt)(ngx_http_request_t *r,
    ngx_uint_t method);

typedef ngx_int_t (*ngx_http_dav_destination_pt)(ngx_http_request_t *r,
    ngx_str_t *destination_uri);
```

The BriX-Cache module would register hooks during postconfiguration. Native
DAV would then call those hooks before file mutation. That lets nginx DAV own
the method machinery while BriX-Cache owns auth, locks, destination scope,
and metrics.

Benefits:

- Better semantic control than unmodified delegation.
- Less duplicated filesystem method code.
- Keeps the source delta smaller than vendoring all of DAV.

Costs:

- Requires maintaining an nginx patch across nginx upgrades.
- CI must build both patched and unpatched modes or make the patch mandatory.
- This is harder for downstream packagers than a normal dynamic module.

Expected deletion:

- Net 1,500-2,500 LOC.
- Better confidence than unmodified delegation for lock and auth behavior.

### Design C: Vendor and rename nginx DAV core

Copy `ngx_http_dav_module.c` into this repo, rename symbols, and add project
hooks directly. This avoids patching nginx itself, but it means the DAV source
still lives in this project.

Benefits:

- Full control over behavior.
- No external nginx patch.
- Easier to call existing nginx helper functions and add xrootd hooks.

Costs:

- Project source size may not shrink much because the vendored DAV module is
  about 1,200 LOC.
- You now own a fork of nginx DAV and must merge security/bug fixes.

Expected deletion:

- Gross delete 2,000-3,000 LOC, add about 1,200-1,600 LOC vendored DAV core,
  net 500-1,500 LOC.
- Use only if Design A cannot match required behavior and Design B is too hard
  for packaging.

### Recommended DAV path

Start with Design A for a narrow method subset:

1. Delegate `MKCOL` and simple file `DELETE`.
2. Then delegate file `MOVE`.
3. Then delegate file `COPY`.
4. Only after conformance is stable, evaluate collection recursive operations
   and PUT.

Do not move `PROPFIND`, `LOCK`, `UNLOCK`, HTTP-TPC, or XrdHttp stats to
`http_dav_module`; nginx does not provide those features.

## Candidate 2: Use `ngx_http_static_module` for WebDAV GET/HEAD

nginx already has mature static-file handling:

- sendfile
- range requests
- conditional requests
- content length and mtime headers
- open file cache integration

Potential design:

1. Move WebDAV auth/scope checks to access/preaccess phase.
2. Let BriX-Cache content handler return `NGX_DECLINED` for plain GET/HEAD.
3. Keep a header/body filter for:
   - `Digest:` checksum headers
   - XrdHttp `X-Xrootd-*` headers
   - access-log/metrics accounting
   - directory behavior if it must differ from nginx static/autoindex

Risks:

- Current WebDAV GET has project-specific fd cache and checksum behavior.
- XrdHttp compatibility may require headers nginx static does not know about.
- Directory GET behavior must stay compatible with current tests.

Expected deletion:

- Net 500-900 LOC if the fd-cache and GET path can be simplified.

## Candidate 3: Use nginx `proxy_pass` for WebDAV perimeter proxy mode

Current files:

- `src/protocols/webdav/proxy.c`
- `src/protocols/webdav/proxy_config.c`
- `src/protocols/webdav/proxy_request.c`
- `src/protocols/webdav/proxy_response.c`
- `src/protocols/webdav/proxy_internal.h`

These exist because the module can terminate auth and forward WebDAV to an
internal HTTP/HTTPS server.

Potential design:

1. Keep BriX-Cache as an auth/access module for the location.
2. Use standard nginx `proxy_pass` for the backend.
3. Use nginx directives for buffering, timeouts, TLS to backend, and header
   forwarding.
4. Keep only small helpers for project-specific credential/header rewriting.

Expected deletion:

- Gross 600-800 LOC.
- Net 300-600 LOC after adding config migration and any header-filter glue.

Risks:

- Existing config directives would need compatibility aliases or deprecation.
- TPC credential headers and WLCG-specific behavior must be preserved.

## Candidate 4: Use libxml2 for WebDAV and XrdHttp XML

Local XML code is small in helpers but spread across WebDAV response builders.
The larger benefit is correctness and less hand-built string assembly.

Targets:

- `src/protocols/webdav/propfind.c`
- `src/protocols/webdav/lock.c`
- `src/protocols/webdav/methods_basic.c` (`PROPPATCH`)
- `src/protocols/webdav/xrdhttp_stats.c`
- S3 XML response builders if a minimal common XML writer is introduced

Use:

- `xmlTextWriter` for response generation.
- `xmlReadMemory` with entity/network disabled for LOCK/PROPPATCH request body
  parsing.

Security requirements:

- Disable network access and external entity expansion.
- Set size limits before parsing.
- Preserve exact DAV namespace output expected by tests.

Expected deletion:

- Net 700-1,500 LOC across WebDAV/S3 XML assembly.
- Higher security confidence, moderate source reduction.

Current status:

- `src/core/compat/xml.c` centralizes XML escaping for WebDAV and S3.
- When `libxml2` is available, `src/core/compat/xml.c` parses WebDAV `LOCK`
  request bodies with `XML_PARSE_NONET` and without entity expansion.
- `src/protocols/webdav/locks/request.c`, `src/protocols/webdav/util/xml.c`, and `src/protocols/s3/util.c`
  now use the shared adapter.
- Unit coverage lives in `tests/unit/test_xml_compat.c` and includes success,
  short-buffer error, and external-entity security-negative cases.

## Candidate 5: Use a JOSE/JWT/JWK library

Current token code includes local base64url, JSON, JWKS, signature, and claim
handling. Scope and path authorization should remain local, but parsing and
cryptographic verification can move to a library.

Candidate libraries:

- `cjose`
- `libjwt`
- `jansson` plus OpenSSL/JWK helper code

Keep local:

- WLCG scope semantics.
- token-to-path authorization.
- issuer/audience policy.
- nginx config and refresh timers.

Replace:

- base64url decode/encode helpers
- JSON scanner
- JWKS key parsing
- JOSE header and signature verification

Expected deletion:

- Gross 1,000-1,600 LOC.
- Adapter/config code 300-700 LOC.
- Net 500-1,200 LOC.

Risk:

- Library API behavior around claim validation may not match WLCG expectations.
- Keep conformance tests for bad alg, bad kid, expired token, wrong issuer,
  wrong audience, and path-scope negative cases.

## Candidate 6: Use libmacaroons

If macaroons remain supported, libmacaroons can own signature chaining,
third-party caveats, discharge verification, and serialization.

Keep local:

- binding macaroon caveats to BriX-Cache path/scope semantics
- configured secret rotation
- HTTP/native token extraction

Replace:

- macaroon parser
- caveat packet handling
- signature chain verification
- discharge-chain verification

Expected deletion:

- Net 500-800 LOC.

Risk:

- Requires packaging a new dependency.
- Must preserve current accepted token format and tests.

## Candidate 7: Use checksum libraries

Candidates:

- `google-crc32c` for CRC32C.
- ISA-L if the deployment already carries it.
- OpenSSL EVP remains fine for SHA/MD5.

Expected deletion:

- Net 150-400 LOC.

Risk:

- Low, provided byte order and hex formatting stay identical.

Current status:

- `src/core/compat/crc32c.c` now owns CRC32C value, copy, and incremental update
  helpers.
- `src/protocols/root/response/crc32c.c` keeps the public wire-facing API but delegates to
  the shared adapter.
- Unit coverage lives in `tests/unit/test_crc32c.c` and checks the standard
  `123456789` vector, fused copy, and incremental chunking.

## Candidate 8: Use nginx event/upstream primitives more

This is more about deleting custom failure modes than huge LOC reduction.

Targets:

- raw socket connect/poll loops in outbound clients
- custom DNS resolution
- timer retry paths
- HTTP subprocess/curl orchestration where nginx upstream can stream the body

Expected deletion:

- Net 500-1,500 LOC in the long run.

Risk:

- Medium. nginx upstream internals are powerful but not always pleasant to use
  outside normal HTTP proxying.

---

## Candidate 9: Fix blocking event-loop violations in the WebDAV TPC subsystem

**This is a correctness issue, not only a code-reduction opportunity.**

### The problem

`src/protocols/webdav/tpc_curl.c` and `src/protocols/webdav/tpc_cred.c` both use `fork()` +
`waitpid()` to run external processes synchronously:

- `tpc_curl.c` (296 LOC) forks the `curl` binary for each HTTP-TPC pull and
  push transfer and calls `waitpid()` until the transfer completes.
- `tpc_cred.c` (475 LOC) forks an `oidc-agent` helper or a `curl` subprocess
  for RFC 8693 token exchange and calls `waitpid()` until the token arrives.

Both paths run inside the nginx worker event loop.  While `waitpid()` blocks,
the worker cannot serve any other connection.  A slow remote server or a large
file transfer therefore stalls all connections on that worker for its duration.

### Design A: Wrap subprocesses in `ngx_thread_pool`

The lowest-change fix is to run the existing `fork/exec/waitpid` logic inside
an `ngx_thread_task_t` so the block happens on a thread-pool thread, not on the
event loop.  The event loop resumes the request via the completion handler when
the thread task returns.

- Keeps existing subprocess machinery and `curl` CLI arguments unchanged.
- Requires moving per-request state into a heap-allocated task context.
- Adds about 100-150 LOC of thread-task plumbing per blocking path.
- Does not reduce LOC but fixes the correctness problem without a new
  compile-time dependency.

### Design B: Replace curl subprocess with libcurl CURLM API

Replace `tpc_curl.c` entirely with the libcurl multi-socket API
(`curl_multi_socket_action`).  libcurl drives I/O via callbacks registered
with `ngx_add_event()`, so transfer progress is event-driven with no blocking.
CURLOPT_SSLCERT / CURLOPT_SSLKEY replace the `--cert` / `--key` CLI flags.

For `tpc_cred.c`:

- The oidc-agent path uses a UNIX-socket JSON exchange.  This can be rewritten
  as a short non-blocking ngx_event connect + read, deleting the
  fork/exec path entirely.
- The RFC 8693 token exchange path is a plain HTTPS POST and can use the same
  CURLM handle as the TPC transfer or a separate single-use handle.

Expected deletion:

- `tpc_curl.c` entirely (296 LOC).
- subprocess plumbing in `tpc_cred.c` (~250 LOC of fork/exec/waitpid).
- New CURLM adapter: approximately 300-400 LOC.
- Net: 100-250 LOC reduction; primary benefit is event-loop correctness.

Risk:

- libcurl is a new compile-time dependency (though it is already an implicit
  runtime dependency because the `curl` binary is assumed to be installed).
- CURLM integration with nginx events requires careful fd lifetime management.
- ngx_thread_pool (Design A) is lower risk but does not eliminate the
  dependency on the external `curl` binary.

### Recommended path

Design A is the correct first step: thread-pool wrapping fixes the blocking
problem immediately without changing the external interface or adding a new
build dependency.  Design B is the right long-term target: it removes the
external binary dependency, reduces LOC, and enables connection reuse and
progress reporting inside the nginx worker.

---

## Candidate 10: Fix blocking DNS in outbound connections

`src/net/upstream/start.c` calls `getaddrinfo()` synchronously before
`ngx_event_connect_peer()`.  `getaddrinfo()` can block for seconds when the
nameserver is slow or unreachable.  `src/net/cms/connect.c` uses the same
pattern for cluster manager connections.

nginx provides an async resolver (`ngx_resolve_name()`) that integrates with
the event loop.  When the resolve completes, a callback receives the address
and the connection proceeds normally.

```c
/* Async DNS — replace the synchronous getaddrinfo block in start.c */
ngx_resolve_ctx_t *rctx = ngx_resolve_start(conf->resolver, NULL);
rctx->name   = conf->upstream_host;
rctx->port   = conf->upstream_port;
rctx->handler = brix_upstream_dns_handler;
rctx->data   = up;
ngx_resolve_name(rctx);
```

Affected files:

| File | LOC | Issue |
|------|----:|-------|
| `src/net/upstream/start.c` | 187 | `getaddrinfo()` at line 67 |
| `src/net/cms/connect.c` | 267 | same pattern for CMS manager address |

Expected deletion:

- Replace 30-50 LOC of `getaddrinfo`/`freeaddrinfo` loop with 20-30 LOC of
  resolver context setup plus a small callback handler.
- Net change is near-zero LOC but fixes the blocking DNS hazard.

Risk:

- Low.  nginx's resolver is stable and used by many modules.
- Requires a `resolver` directive in the server block if the operator does not
  already have one.  Add a `resolver` directive to the recommended
  configuration.

---

## Candidate 11: Use `ngx_http_time()` to eliminate `src/protocols/webdav/date.c`

`src/protocols/webdav/date.c` (70 LOC) implements two functions:

- `webdav_http_date(t, buf, sz)` — RFC 1123 format (`Mon, 01 Jan 2025 …`)
- `webdav_iso8601_date(t, buf, sz)` — ISO 8601 format (`2025-01-01T00:00:00Z`)

nginx provides `ngx_http_time(buf, time_t)` which writes RFC 1123 directly
into a caller-supplied buffer.  The ISO 8601 formatter is a 3-line
`gmtime_r` + `snprintf` that can be inlined at its two call sites rather than
living in a separate file.

Expected deletion:

- `src/protocols/webdav/date.c` entirely (70 LOC).
- Two forward declarations removed from `src/protocols/webdav/webdav.h`.
- Two call sites updated to call `ngx_http_time()` or a short inline snippet.
- Net: 55-65 LOC deleted.

Risk:

- None.  `ngx_http_time()` is part of nginx's stable HTTP API and is already
  transitively available in the WebDAV module.
- The RFC 1123 output format is identical to the local implementation.

---

## Candidate 12: Avoid re-implementing already-available S3 / VOMS primitives

Two areas were evaluated and confirmed **not worth replacing**:

### S3 SigV4 authentication (src/protocols/s3/auth_sigv4*.c — 1,043 LOC)

The SigV4 code is server-side HMAC-SHA256 verification, not signing.  No
small C library exists for server-side verification; the AWS C SDK
(`aws-c-auth`) is far larger than the local implementation and ties to a
heavy dependency tree.  The current code is lean and specification-correct.
**Keep local.**

### VOMS attribute certificate extraction (src/auth/voms/ — 415 LOC)

The module already delegates to `libvomsapi` at runtime via `dlopen()`.  The
local code builds VO lists from the VOMS API result structs; replacing this
with direct OpenSSL X.509v3 extension parsing would require implementing ASN.1
VOMS-AC-Targets decoding and would not reduce source size.  **Keep local.**

---

## Part 2: Internal Consolidation Opportunities

The candidates below are not about replacing local code with external libraries;
they reduce duplication and boilerplate **within** this module.  They were
identified in a third-pass analysis (2026-05-20) and are not already covered by
Candidates 1-12.

---

## Candidate 13: Consolidate AIO dispatch patterns

`src/core/aio/read.c`, `write.c`, `readv.c`, and `pgread.c` (772 LOC total) all
implement an identical two-phase pattern:

- A `*_thread()` function runs the blocking I/O call on a thread-pool thread.
- A `*_done()` callback fires on the event loop, guards against a destroyed
  connection, maps `io_errno` to kXR_IOError, updates byte counters, and builds
  and sends the XRootD response.

The destroyed-connection guard, error-to-kXR mapping, byte-counter update, and
pool-cleanup idioms are copy-pasted across all four files.

**Potential design:**

A small set of shared helpers (perhaps 80-120 LOC) could own:

- Destroyed-connection guard check.
- errno → kXR error code mapping.
- Byte-counter update.
- Response-send boilerplate.

Each file's `_done()` callback would shrink to: call the guard, call the
response builder helper with a direction-specific argument, return.

**Expected deletion:**
- Gross deletable: 200-280 LOC.
- New shared helper: 80-120 LOC.
- Net: **−80 to −160 LOC**.

**Risk:** Low.  Changes are internal to the AIO subsystem, which is
well-covered by the existing read/write test suites.

---

## Candidate 14: Deduplicate TPC curl pull and push functions

`src/protocols/webdav/tpc_curl.c` contains `webdav_tpc_run_curl_pull()` and
`webdav_tpc_run_curl_push()`, approximately 140 LOC each, with 70-80% textual
similarity.

Identical in both:
- `WEBDAV_TPC_ARG()` macro and argv-building loop.
- `--fail`, `--silent`, `--show-error`, `--proto =https` flags.
- `--max-time`, `--cert`, `--key`, `--cacert`, `--capath` flag insertion.
- Transfer-header `-H` loop.
- `fork()` + child fd-cleanup + `execv/execvp`.
- `waitpid()` loop and `WIFEXITED/WEXITSTATUS` mapping.
- Metric increments and log messages.

Different only in the final argv elements:
- Pull: `--output <tmp_path> <source_url>`
- Push: `--upload-file <local_path> <dest_url>`

**Note:** Both functions already take `ngx_log_t *log` (changed as part of
Phase 0.5 to make them thread-safe), which makes parameterization
straightforward.

**Potential design:**

```c
typedef enum { TPC_DIR_PULL, TPC_DIR_PUSH } webdav_tpc_dir_e;

static ngx_int_t
webdav_tpc_run_curl(ngx_log_t *log,
                    ngx_http_brix_webdav_loc_conf_t *conf,
                    webdav_tpc_dir_e dir,
                    const char *url, const char *path,
                    ngx_array_t *transfer_headers);
```

The public pull/push functions become one-line wrappers.

**Expected deletion:**
- Gross deletable: 120-160 LOC (shared argv/fork/exec/waitpid boilerplate).
- New parameterized wrapper: 40-60 LOC.
- Net: **−60 to −120 LOC**.

**Priority:** Best done in parallel with Candidate 9 Design B (libcurl CURLM),
which will refactor this code anyway.  If Design B is executed, this candidate
is subsumed by it.

---

## Candidate 15: Pool allocation null-check macro

The pattern:

```c
ptr = ngx_pnalloc(pool, size);
if (ptr == NULL) {
    return NGX_ERROR;   /* or NGX_CONF_ERROR, or an HTTP status */
}
```

appears at over 100 call sites across `src/`.  The error return value varies
(NGX_ERROR, NGX_CONF_ERROR, NGX_HTTP_INTERNAL_SERVER_ERROR) but the guard
structure is identical.

**Potential design:**

```c
/* in src/core/config/config.h or a shared util header */
#define XALLOC_OR_RETURN(ptr, pool, size, err) \
    do { (ptr) = ngx_pnalloc((pool), (size)); \
         if ((ptr) == NULL) { return (err); } } while (0)

#define XCALLOC_OR_RETURN(ptr, pool, size, err) \
    do { (ptr) = ngx_pcalloc((pool), (size)); \
         if ((ptr) == NULL) { return (err); } } while (0)
```

**Expected deletion:**
- Each replaced site removes 2-3 LOC and replaces with 1.
- Net: **−150 to −200 LOC** across `src/`.

**Risk:** Very low — the macro is a pure syntactic transformation.
Apply incrementally; the biggest wins are in webdav and proxy modules.

---

## Candidate 16: Shared-memory registry pattern consolidation

**Status:** Partially implemented.  `src/core/compat/shm_slots.h` now owns the
lowest-risk common pieces: expiration comparison and first-free-slot selection.
It is used by the TPC key registry, pending locate registry, and WebDAV lock
table.  The deeper macro-generated-table design below remains a future option,
but has not been applied because each registry still has distinct key matching,
conflict, and cleanup semantics while holding its lock.

`src/tpc/engine/key_registry.c` (178 LOC) and `src/protocols/root/session/registry.c` (463 LOC)
both implement fixed-size shared-memory lookup tables:

- Both use `ngx_shm_zone_t` + `ngx_shmtx_t` with a spinlock.
- Both scan a fixed-size array looking for a free slot or a matching entry.
- Both follow the same lock / mutate / unlock pattern.
- Both handle zone init, lookup, insert, and delete operations.

**Potential design:**

A macro-generated table (`BRIX_SHM_TABLE_DEFINE(name, entry_type, size)`)
that expands to the standard functions for a given entry type and table size.
This pattern is common in the Linux kernel and nginx's own code.

**Expected deletion:**
- Gross deletable: 100-150 LOC.
- New macro template: 60-90 LOC.
- Net: **−10 to −60 LOC**.

**Risk:** Medium.  Shared-memory manipulation is the most latency-sensitive
and crash-sensitive code in the module.  Template expansion must be
audited carefully.  Only attempt after comprehensive integration tests for
both TPC key exchange and session handling.

---

## Candidate 17: Delegate more X.509 parsing to OpenSSL

`src/auth/gsi/parse_x509.c` (294 LOC) includes manual DER field extraction that
OpenSSL already provides:

- Subject DN extraction: `X509_get_subject_name()` + `X509_NAME_oneline()`.
- Extension lookup: `X509_get_ext_d2i()` for NID-based access.
- Validity period checking: `X509_get0_notBefore()` / `X509_get0_notAfter()`.

**Keep local (not replaceable):**
- RFC 3820 proxy delegation chain validation.
- VOMS attribute certificate issuer/target scope matching.
- Project-specific DN normalization and logging.

**Expected deletion:**
- Net: **−30 to −70 LOC**.

**Risk:** Medium.  Certificate parsing is security-critical.  Any change
here requires the full GSI auth negative test suite to pass and should be
reviewed independently.  The OpenSSL API surface for X.509 has changed across
versions; confirm behavior against OpenSSL 1.1.x and 3.x.

---

## Candidate 18: Dead code audit

No static analysis has been run on the module to identify functions that are
defined but never called.  Short files like `src/auth/gsi/pki.c` (31 LOC) suggest
some stub or transitional code may remain.

**Recommended approach:**
1. Build with `-ffunction-sections` and link with `--gc-sections --print-gc-sections`.
2. Review any section discarded for function-level reachability.
3. Or use `cflow` / `callgrind` to map the call graph.

**Expected deletion:** 50-200 LOC (unknown until audited).

**Risk:** Low.  Unreachable code cannot affect behavior.

---

## Not Recommended

### Replacing S3 with AWS SDK C/C++

The AWS SDK is much larger than this module's S3 surface. It would not remove
the need to implement a server-side S3-compatible API, and it would add a large
dependency footprint.

Prefer targeted cleanup:

- keep SigV4 local unless a small verification library is selected
- use shared XML writers
- keep filesystem object/multipart semantics local

### Replacing inbound XRootD dispatch

The inbound XRootD server implementation is core product behavior. There is no
nginx built-in or small external library that can own it while preserving the
module's auth, metrics, and proxy modes.

## Migration Roadmap

### Phase 0: Guardrails

Status: implemented.

Phase 0 is now enforced by `tests/test_phase0_guardrails.py`.  That test is a
lightweight inventory contract: it does not replace the protocol suites, but it
prevents source-reduction work from silently removing the guardrails that make
later deletion safe.

Before deleting source, keep these behavioral suites green:

| Guardrail | Primary tests |
|---|---|
| WebDAV method parity against reference XrdHttp | `tests/test_http_webdav_status_codes.py`, `tests/test_webdav.py`, `tests/test_xrdhttp_webdav.py` |
| Token auth success and negatives: bad signature, bad issuer/audience, expired token, bad scope, and missing/rotated key | `tests/test_token_auth.py`, `tests/test_token_security.py`, `tests/test_token_jwks_refresh.py` |
| Lock and child-lock negatives for DELETE/MOVE/COPY | `tests/test_http_webdav_lock_recursive.py`, `tests/test_http_webdav_lock.py` |
| XrdHttp checksum and metadata headers | `tests/test_xrdhttp.py`, `tests/test_xrdhttp_conformance.py`, `tests/test_query_extended.py` |
| Cache fill and write-through against direct origin | `tests/test_cache_write_through.py` |
| TPC success, credential handling, auth negatives, and SSRF policy | `tests/test_webdav_tpc.py`, `tests/test_webdav_tpc_cred.py`, `tests/test_tpc_ssrf_policy.py`, `tests/test_tpc_token_mode.py` |

Build matrix guardrails:

- Minimal dependency builds keep fallback XML and checksum paths compiled.
- External XML builds are detected with `pkg-config --exists libxml-2.0` and
  compile `src/core/compat/xml.c` with `BRIX_HAVE_LIBXML2=1`.
- Shared checksum code is compiled through `src/core/compat/crc32c.c`.
- Unit coverage for the build hooks lives in `tests/unit/run_tests.sh`,
  `tests/unit/test_xml_compat.c`, and `tests/unit/test_crc32c.c`.

Recommended Phase 0 verification:

```bash
PYTHONPATH=tests pytest tests/test_phase0_guardrails.py -q
tests/unit/run_tests.sh
PYTHONPATH=tests pytest tests/test_http_webdav_status_codes.py tests/test_http_webdav_lock_recursive.py -q
PYTHONPATH=tests pytest tests/test_token_auth.py tests/test_token_security.py tests/test_token_jwks_refresh.py -q
PYTHONPATH=tests pytest tests/test_xrdhttp.py tests/test_xrdhttp_conformance.py tests/test_query_extended.py -q
PYTHONPATH=tests pytest tests/test_webdav_tpc.py tests/test_webdav_tpc_cred.py tests/test_tpc_ssrf_policy.py tests/test_tpc_token_mode.py -q
```

### Phase 0.5: Event-loop correctness (do before code deletion)

Status: **partially implemented (2026-05-20).**

These are not source-reduction items; they fix correctness bugs where nginx
worker event loops block on synchronous I/O.  They should be resolved before
or in parallel with Phase 1 because later phases (nginx DAV delegation, proxy
delegation) assume correct event-loop behavior.

1. **TPC subprocess blocking (Candidate 9, Design A)** — **DONE.** The
   `fork/waitpid` call paths in `tpc_curl.c` are now wrapped by
   `src/protocols/webdav/tpc_thread.c` (`webdav_tpc_post_thread_task`).  The thread
   worker runs the entire blocking path (curl fork + waitpid + file commit) and
   fires a completion callback on the event loop.  Both pull and push paths try
   the thread-pool first and fall back to synchronous execution when
   `conf->thread_pool == NULL`.  The function signatures of
   `webdav_tpc_run_curl_pull` and `webdav_tpc_run_curl_push` were changed from
   `ngx_http_request_t *r` to `ngx_log_t *log` to make them thread-safe.
   Design B (libcurl CURLM) is the long-term target.
2. **Upstream DNS blocking (Candidate 10)** — **DONE (pre-resolution
   approach).** `src/net/upstream/directives.c` now calls `ngx_parse_url()` at
   configuration time (the same approach the CMS module already uses) and
   stores the resolved `ngx_addr_t *` in `conf->upstream_addr`.
   `src/net/upstream/start.c` uses the pre-resolved address directly; the
   `getaddrinfo()` block now only runs as a defensive fallback when config-time
   resolution fails (which emits a WARN log at startup).  Remaining work: a
   full async `ngx_resolve_name()` path for deployments where the upstream
   hostname changes after startup.

Neither item required external libraries; both use nginx primitives already
available in the build.

### Phase 1: Commodity libraries

Status: **complete (cleanup done 2026-05-20).**

- Implemented: shared XML escape adapter in `src/core/compat/xml.c`.
- Implemented: libxml2-backed WebDAV `LOCK` body parsing when libxml2 is
  available, with fallback parsing for minimal builds.
- Implemented: shared CRC32C adapter in `src/core/compat/crc32c.c`.
- Implemented: shared XML text-element helpers in `src/core/compat/xml.c`.
- Implemented: S3 XML response builders now use shared text-element helpers
  for ListObjectsV2, ListParts, ListMultipartUploads, and XML error bodies.
- Implemented + cleaned up: Jansson is now a **required** build dependency
  (config fails with a clear error if not found).  The 345-LOC local JSON/JWKS
  fallback parser (`json.c` helpers + `jwks.c` fallback path) has been deleted.
  `src/auth/token/json.c` is now 150 LOC (was 495); `src/auth/token/jwks.c` is 171 LOC
  (was 281).
- Implemented + cleaned up: `src/protocols/webdav/date.c` (70 LOC) deleted; callers in
  `propfind.c` now use `ngx_http_time()` for RFC 1123 and `strftime()` for
  ISO 8601.
- Correctness fix: `D:owner` in LOCK responses (`webdav_lock_xml_response`,
  `webdav_lock_append_discovery`) was interpolated into XML without escaping.
  GSI distinguished names containing `<`, `>`, or `&` would produce malformed
  XML.  Both sites now call `webdav_escape_xml_text()` before interpolation.
- Note on XML response generation (`xmlTextWriter` for propfind.c/lock.c):
  `propfind_entry()` and the lock XML helpers share the same `ngx_chain_t *`
  for streaming output; `xmlTextWriter` writes to a separate buffer, so the
  two models do not compose without an extra copy layer.  The existing
  `webdav_propfind_append()` + `webdav_escape_xml_text()` pattern is correct
  and appropriate for nginx's chain model.  `xmlTextWriter` was not applied to
  response generation.
- Implemented: libmacaroons compatibility decision.  Keep the current WLCG
  macaroon packet parser for now because it owns dCache/WLCG-specific
  activity/path caveat mapping, third-party discharge VID decryption, secret
  rotation behavior, and scope narrowing.  `libmacaroons` can be reconsidered
  only as a standard-macaroon compatibility path, not as a drop-in replacement
  for the current parser.

Phase 1 guardrails:

```bash
PYTHONPATH=tests pytest tests/test_phase1_commodity_libraries.py -q
tests/unit/run_tests.sh
```

The Phase 1 inventory is enforced by
`tests/test_phase1_commodity_libraries.py`; behavioral coverage remains in the
token, WebDAV, S3, and unit suites listed under Phase 0.

The 500-1,200 LOC remaining deletion estimate has now been delivered: net
~415 LOC removed (date.c 70 + json.c/jwks.c fallback 345).  The larger
reductions now come from Phase 2/3 delegation rather than additional
commodity parser swaps.

### Phase 2: nginx DAV/static delegation

1. Move WebDAV auth/scope/lock checks to access/preaccess phase.
2. Delegate MKCOL and simple DELETE to nginx DAV.
3. Delegate file MOVE and file COPY.
4. Evaluate PUT delegation after performance and status-code tests.
5. Evaluate static module delegation for plain GET/HEAD.

Expected net deletion: 1,000-2,500 LOC.

### Phase 3: nginx proxy delegation for WebDAV perimeter mode

1. Keep auth and header rewriting local.
2. Move transport to `proxy_pass`.
3. Preserve legacy directives as wrappers or document migration.

Expected net deletion: 300-600 LOC.

## Decision Matrix

| Candidate | Delete payoff | Correctness benefit | Compatibility risk | Build risk | Recommended priority |
|---|---:|---:|---:|---:|---|
| **TPC blocking fix (Design A: thread pool)** | None | **HIGH — fixes event-loop stall** | Low | None | **Done 2026-05-20** |
| **Config-time upstream DNS pre-resolution** | None | **HIGH — eliminates per-request getaddrinfo()** | Low | None | **Done 2026-05-20** |
| libxml2 | Medium | Low | Low-medium | Low | 1 |
| JOSE/JWT/JWK library | Medium | Low | Medium | Medium | 2 |
| checksum library | Low | Low | Low | Low | 3 |
| libmacaroons | Low-medium | Low | Medium | Medium | 4 |
| **date.c → ngx_http_time()** | Low | Low | None | None | **Done 2026-05-20** |
| **Jansson fallback deletion** | Medium | None | None | None | **Done 2026-05-20** |
| **lock.c owner XML escaping** | ~0 | Medium — correctness fix | None | None | **Done 2026-05-20** |
| **AIO dispatch consolidation (Cand. 13)** | Medium | None | Low | Low | 4 |
| unmodified nginx DAV delegation | Medium | Low | Medium-high | Low | 5 |
| **TPC curl deduplication (Cand. 14)** | Low-medium | None | Low | None | 5 — pairs with Design B |
| **Dead code audit (Cand. 18)** | Unknown | None | None | None | 5 — do first (free win) |
| nginx static GET/HEAD delegation | Low-medium | Low | Medium | Low | 6 |
| nginx proxy_pass for WebDAV proxy | Low | Low | Medium | Low | 7 |
| **TPC blocking fix (Design B: libcurl CURLM)** | Medium | HIGH | Medium | Medium | 8 — after Design A |
| **Pool alloc macro (Cand. 15)** | Medium | None | None | None | 8 — mechanical, any time |
| **Shared-mem registry template (Cand. 16)** | Low | None | Medium | Medium | 9 |
| **GSI X.509 OpenSSL delegation (Cand. 17)** | Low | None | Medium | Medium | 9 — security audit needed |
| patched nginx DAV hooks | Medium | Low | Medium | Medium-high | Only if unmodified delegation fails |
| vendored nginx DAV core | Low-medium net | Low | Low-medium | Medium | Last resort |

## Success Criteria

The reduction is successful only if:

- source size drops by at least 2,500 net LOC in the conservative track or
  5,000 net LOC in the balanced track
- all existing conformance tests still pass
- all security-negative tests still pass
- default builds remain possible without heavyweight optional dependencies
- dependency-enabled builds are documented and covered in CI
- operators can keep existing configuration or get a clear migration path

## Recommended Next Step

**Completed (Phase 0.5, 2026-05-20):**
- TPC `fork/waitpid` wrapped in `ngx_thread_pool` via `src/protocols/webdav/tpc_thread.c`.
- Upstream DNS blocking eliminated by config-time `ngx_parse_url()` pre-resolution in `src/net/upstream/directives.c`; `src/net/upstream/start.c` uses the cached `ngx_addr_t *`.
- `webdav_tpc_run_curl_pull/push` signatures changed to `ngx_log_t *log` for thread safety.

**Completed (Phase 1, cleanup done 2026-05-20):**
- Commodity-library wiring in place for libxml2, CRC32C, S3 XML helpers, Jansson token parsing.
- Jansson is now a required dependency; local fallback parser deleted (−345 LOC: json.c 495→150, jwks.c 281→171).
- `src/protocols/webdav/date.c` deleted (−70 LOC); `propfind.c` uses `ngx_http_time()` + `strftime()`.
- LOCK response `D:owner` XML-escaped via `webdav_escape_xml_text()` (correctness fix).
- Phase 1 guardrails updated to reflect Jansson as required dependency.

**Completed (internal sharing pass, 2026-05-21):**
- Added shared helpers for HTTP headers, HTTP request bodies, HTTP conditionals,
  file checksums, confined filesystem walking/removal, staged temp files, and
  CMS frame sending.
- Migrated WebDAV, S3, native query/checksum, dirlist checksum, XrdHttp Digest,
  and CMS send call sites to those helpers.
- Added static guardrails in `tests/test_cross_protocol_shared_helpers.py`.
- Verified with `bash -n config`, the focused static test, and a full nginx
  `./configure --with-stream --with-http_ssl_module --with-http_dav_module --with-threads --add-module=... && make -j$(nproc)` build.

**Low-hanging fruit (any time):**
1. Run the dead code audit (Candidate 18) — one build with `--gc-sections` to find free deletions.
2. Consolidate `tpc_curl.c` pull/push (Candidate 14) — pairs naturally with any future Design B work.

**Next source-reduction step (Phase 2):** Start unmodified nginx DAV delegation
for `MKCOL` and simple `DELETE`.  That pair has a good payoff-to-risk ratio and
will quickly expose whether nginx phase restructuring can safely protect
built-in content handlers with BriX-Cache auth, scope, locks, CORS, and
metrics.

**Medium-term internal consolidation:** AIO dispatch consolidation (Candidate 13)
and pool-alloc macro (Candidate 15) are independent of Phase 2 and can be
tackled in parallel.  Both are low risk.  Shared-memory registry template
(Candidate 16) and GSI X.509 delegation (Candidate 17) require more care and
should wait until integration tests are comprehensive for those paths.

## External References

- nginx `ngx_http_dav_module` documentation:
  <https://nginx.org/en/docs/http/ngx_http_dav_module.html>
- libxml2 API documentation:
  <https://gnome.pages.gitlab.gnome.org/libxml2/html/>
- XRootD documentation index, including client API references:
  <https://brix.org/docs>
- libmacaroons upstream package/source reference:
  <https://github.com/rescrv/libmacaroons>
- libcurl multi-socket API (CURLM — event-driven TPC replacement target):
  <https://curl.se/libcurl/c/curl_multi_socket_action.html>
- nginx async resolver (`ngx_resolve_name`) — search nginx source for
  `ngx_resolve_name` in `src/core/ngx_resolver.h` for the API contract.
