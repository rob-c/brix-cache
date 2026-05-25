# Test Coverage Map

This document answers the question every new contributor asks: *"I just touched X — which tests should I run, and what do they actually prove?"*

It maps each part of the codebase to the tests that exercise it, and for each test file explains *what it proves* (not just what it runs). Read the section for the code you're changing, then use the quick-run command to check your work before pushing.

---

## Quick orientation

The test suite lives in `tests/`. Run a single file, a keyword, or everything:

```bash
# One file
PYTHONPATH=tests pytest tests/test_proxy_mode.py -v

# Keyword across all files
PYTHONPATH=tests pytest tests/ -k "gsi" -v --tb=short

# Everything
PYTHONPATH=tests pytest tests/ -v --tb=short
```

Tests need a running server. Start it with `tests/manage_test_servers.sh start`. Logs land in `/tmp/xrd-test/logs/`.

---

## At a glance

| Area | Key test files |
|---|---|
| Wire protocol & handshake | `test_wire_protocol_security`, `test_protocol_edge_cases`, `test_a_robustness` |
| GSI authentication | `test_gsi_security`, `test_gsi_tls`, `test_gsi_bridge`, `test_crl`, `test_ocsp` |
| Token (JWT/WLCG) auth | `test_token_auth`, `test_token_security`, `test_token_jwks_refresh` |
| Macaroon auth | `test_token_macaroon`, `test_macaroon_discharge` |
| VO / VOMS ACL | `test_vo_acl`, `test_authdb` |
| Authorization boundaries | `test_privilege_escalation`, `test_security_hardening`, `test_security_level` |
| File I/O (read/write) | `test_file_api`, `test_io_edge_cases`, `test_readv`, `test_write` |
| AIO thread pool | `test_aio` |
| pgread / pgwrite checksums | `test_new_opcodes`, `test_pgwrite_checksum`, `test_io_edge_cases` |
| New opcodes (v5.2+) | `test_new_opcodes` |
| Filesystem namespace ops | `test_fs_ops`, `test_file_api` |
| Path security | `test_path_depth_guards`, `test_privilege_escalation` |
| kXR_query variants | `test_query`, `test_query_extended`, `test_fattr_query` |
| kXR_fattr / kXR_statx | `test_fattr_query`, `test_new_opcodes`, `test_interop_namespace` |
| kXR_prepare / staging | `test_prepare_staging`, `test_interop_query` |
| kXR_bind (data channels) | `test_session_bind` |
| kXR_sigver signing | `test_sigver_verify`, `test_new_opcodes`, `test_security_level` |
| CMS heartbeat | `test_cms` |
| Manager / cluster / redirector | `test_manager_mode` |
| Native TPC (root://) | `test_root_tpc` |
| WebDAV methods | `test_webdav`, `test_http_webdav_status_codes`, `test_https_webdav_status_codes` |
| WebDAV locking | `test_http_webdav_lock`, `test_http_webdav_lock_recursive` |
| WebDAV PROPFIND | `test_webdav`, `test_propfind_infinity`, `test_webdav_http_security` |
| WebDAV TPC | `test_webdav_tpc`, `test_webdav_tpc_cred`, `test_tpc_ssrf_policy`, `test_tpc_token_mode` |
| WebDAV auth cache | `test_webdav_auth_cache` |
| S3 | `test_s3`, `test_s3_status_codes`, `test_s3_multipart`, `test_s3_presigned` |
| Metrics (Prometheus) | `test_metrics` |
| Proxy mode | `test_proxy_mode`, `test_a_upstream_redirect` |
| Cache write-through | `test_cache_write_through` |
| nginx ↔ xrootd conformance | `test_conformance`, `test_interop_io`, `test_interop_namespace`, `test_interop_query` |
| xrdhttp interop | `test_xrdhttp*` |
| Concurrency / throughput | `test_concurrent`, `test_throughput` |
| Structural guardrails | `test_phase0_guardrails`, `test_phase1_commodity_libraries`, `test_plan6_guardrails` |

---

## Protocol and wire layer

**Source:** `src/handshake/`, `src/connection/`, `src/session/protocol.c`, `src/stream/`

### `test_wire_protocol_security.py`

The most rigorous low-level test file. It speaks raw TCP and verifies:

- **Stream ID echo** (`TestStreamIDEchoCorrectness`) — every response byte-for-bytes echoes the request's 2-byte stream ID regardless of opcode. Catches any response-framing bug.
- **dlen guards** (`TestMalformedDlen`) — the `recv.c` allocation guards reject oversized dlen values (UINT32_MAX, signed-negative-as-large) that would otherwise cause heap overflow.
- **Invalid request IDs** (`TestInvalidRequestID`) — opcodes below 3001 or above the known range return `kXR_Unsupported`, never a crash. Also verifies the lowest valid opcode is 3001.
- **Pre-auth rejection** (`TestPreAuthRequestRejection`) — sync, fattr, writev, pgwrite, locate, statx, chmod, rm, rmdir, mv all refused before login. Extends `test_privilege_escalation.py` to opcodes not tested there.
- **Handshake variants** (`TestProtocolHandshakeVariants`) — partial handshakes (10 / 19 bytes), non-zero first field, login before protocol frame, byte-by-byte delivery.
- **Fast-path attacks** (`TestFastPathAttacks`) — 100 sequential pings, 10 open/close cycles, 100 stats, 50 new connections: verifies no handle leaks or worker stalls.

### `test_a_robustness.py`

Adversarial suite. Uses hand-crafted TCP to probe:

- **Lockup prevention** (`TestLockup`) — partial handshakes, silence after handshake, giant dlen with no body: server must stay responsive to legitimate clients.
- **Auth bypass** (`TestAuthBypass`) — stat/open/read/dirlist/mkdir/rm/write/auth all before login: all must be rejected.
- **Protocol fuzzing** (`TestProtocolFuzzing`) — unknown opcodes 0, 0xffff, 9999; embedded nulls in paths; max/over-max path lengths; all-zero and all-0xFF request frames; bad handshake fields.
- **Resource exhaustion** (`TestResourceExhaustion`) — 50 simultaneous connections, rapid connect/disconnect, 1000 pings, handle limit enforcement.
- **State machine attacks** (`TestStateMachineAttacks`) — read from closed handle, endsess with open handles, auth after anon login, read without open.
- **Path traversal** (`TestPathTraversal`) — batch of `..` variants rejected.
- **Concurrency safety** (`TestConcurrencySafety`) — 16 concurrent sessions + concurrent stat/ping.

### `test_protocol_edge_cases.py`

Functional edge cases on a live connection:

- Handshake field validation, sequential requests on one connection, `kXR_endsess`, handle-based stat, readv edge cases (zero-length segment, past EOF, many segments), `kXR_open` with `kXR_retstat`, connection resilience after non-fatal errors, query edge cases (unsupported infotype, checksum via API).

### `test_conformance.py`

Runs the same operations against both the nginx-xrootd endpoint and a reference xrootd server side-by-side, asserting identical results. Covers: ping, stat (file/dir/non-existent/large), read (small/offset/beyond-EOF/5MB MD5), dirlist, checksum, write+readback, open, and `..` rejection.

---

## Authentication

**Source:** `src/session/login.c`, `src/gsi/`, `src/token/`, `src/sss/`

### `test_gsi_security.py`

The most thorough GSI test. Covers:

- **Pre-auth rejection on GSI port** (`TestGSIPreAuthRejection`) — 12 opcodes including writev, truncate, chmod, sync all rejected before login. Ping is the exception (allowed).
- **Protocol edge cases** (`TestGSIProtocolEdges`) — unknown credtype, 4-byte-too-short auth body, invalid request ID after login, stat while unauthenticated after login, partial handshake survivability.
- **Authenticated ops** (`TestGSIClientStat`, `TestGSIClientRead`, `TestGSIClientWrite`) — stat, dirlist, qconfig, qspace, read, adler32, write, cross-endpoint visibility.
- **GSI+TLS port** (`TestGSITLSPort`) — full functional suite on the `roots://` port.

### `test_gsi_tls.py`

Focused functional tests for `roots://` (GSI + in-protocol TLS):

- Connection/metadata ops, reads (small/large/partial/spanning EOF), readv, CopyProcess, cross-endpoint data match, auth failure on wrong CA, write round-trips.

### `test_gsi_bridge.py`

Cross-server bridge: proves GSI auth works end-to-end when copying between the nginx-xrootd endpoint and the reference xrootd. Small/large files, checksum preservation, directory listing after bridge transfer, rejection of missing proxy.

### `test_crl.py`

CRL revocation checking:

- CRL file content (revoked serial present), stream rejection of revoked cert, WebDAV rejection of revoked cert, config directive acceptance, directory-mode CRL (`xrootd_crl` pointing at a directory), **hot reload** (`TestCRLReload`) — initially accepts a cert, then after reload rejects it without nginx restart.

### `test_ocsp.py`

OCSP config directives accepted by `nginx -t`, mock OCSP response builder produces parseable DER, mock OCSP server start/serve/stop, soft-fail behaviour (unreachable responder doesn't block connections), stapling directive with/without TLS.

### `test_token_auth.py`

JWT bearer token authentication end-to-end:

- Token generation (valid, with groups, expired, bad sig, wrong issuer/audience), protocol advertising `ztn`, login/stat/dirlist/ping after token auth, **negative suite** (expired/bad-sig/wrong-issuer/wrong-audience/empty/garbage/no-scope tokens all rejected), WebDAV `Authorization: Bearer`, scope enforcement (read/write/path boundaries), wlcg.groups extraction.

### `test_token_security.py`

Security hardening for the JWT path (`src/token/validate.c`):

- **Algorithm confusion** (`TestAlgorithmConfusion`) — `none`, HS256, RS384, RS512, ES256, missing alg, empty, uppercase NONE, mixed-case, null byte, very long string, control chars: all rejected.
- **nbf future token** — 1s / 1h future rejected; zero / now / 1s ago accepted.
- **Malformed structure** — no dots, one dot, three dots, empty header part, non-base64 header, oversized token, zero-length, binary garbage.
- **Scope path boundary** — `/data` scope does not match `/database` or `/datastore`. Thorough prefix boundary tests for read and write scopes across both XRootD and WebDAV.
- **WebDAV token security** — read-only token blocks write, wrong-path scope blocks write, log injection in `kid`/`sub` fields rejected.

### `test_token_jwks_refresh.py`

JWKS hot refresh: original key accepted before rotation, new key accepted after rotation (without restart), parse errors keep old keys, old key rejected after rotation.

### `test_token_macaroon.py` / `test_macaroon_discharge.py`

Macaroon token authentication. `test_macaroon_discharge.py` specifically validates the discharge bundle format: root macaroon structure (identifier, cid, vid, signature, location, activity caveat), discharge macaroon structure, bundle format (space-separated, independently decodable), crypto correctness (VID decrypts to discharge key, tampered identifiers change signatures), path narrowing HMAC chain, expiry caveat participation, security negatives (tampered discharge, wrong discharge key).

### `test_sigver_verify.py`

`kXR_sigver` request-signing verification (`src/session/`): expectrid mismatch rejected, replay attacks (same / decreasing sequence number), body-too-short, anonymous and token sessions accept sigver without HMAC check, RSA-signed envelopes accepted.

---

## Authorization

**Source:** `src/path/acl.c`, `src/handshake/policy.c`, `src/voms/`, `src/authdb.c`

### `test_vo_acl.py`

VOMS VO-based path ACL. CMS proxy admitted to `/cms/`, denied `/atlas/`. Atlas proxy admitted to `/atlas/`, denied `/cms/`. Plain GSI proxy (no VOMS) denied all VO-restricted paths. Any authenticated client can access public paths.

### `test_privilege_escalation.py`

Authorization boundary tests:

- **Read-only server** (`TestReadOnlyServer`) — `xrootd_allow_write off` blocks all mutating opcodes while reads continue.
- **Symlink escape** (`TestReadSideSymlinkEscape`) — stat/open/dirlist reject symlinks pointing outside `xrootd_root`.
- **Pre-auth rejection** (`TestPreAuthRejection`) — nine opcodes rejected before login; ping and protocol allowed.
- **Unknown opcodes** — `kXR_Unsupported` before and after login.
- **Handle misuse** — truncate on read-only handle, write to read-only handle, operations on invalid handles, use-after-close.
- **Oversized paths** — stat/open with path > buffer limit rejected cleanly.
- **Empty payloads** — rm/mkdir/stat with missing path payload.
- **Path traversal** — stat/open/dirlist/mv with `..` components.
- **kXR_set** — advisory modifier values accepted after login; rejected before.

### `test_security_level.py`

Security-level negotiation: default `none` allows unsigned reads, `standard` protocol advertises security level, `pedantic` advertises payload signing.

### `test_security_hardening.py`

Security hardening regression inventory. Run this whenever touching auth or path resolution.

---

## File I/O

**Source:** `src/read/`, `src/write/`, `src/aio/`

### `test_file_api.py`

The most comprehensive file API test. Covers the full lifecycle end-to-end:

- **Create** (`TestFileCreate`) — new file, GSI, `kXR_new` flag fails if exists, delete/force/makepath flags.
- **Read/Write** (`TestFileWrite`) — write-at-offset, overwrite middle, multiple chunks, large file MD5, partial read, read beyond EOF, handle permission enforcement.
- **Sync** (`TestFileSync`) — sync flushes to disk, sync on read-only handle.
- **Truncate** (`TestFileTruncate`) — shrink/extend/to-zero via handle, path-based truncate, nonexistent.
- **Stat** (`TestStat`) — file/directory/nonexistent/root, size after write, modtime, handle stat.
- **Dirlist** (`TestDirList`) — root/subdir/empty/nonexistent/with-stat/distinguish files+dirs.
- **Mkdir/Rmdir/Rm/Mv/Chmod** — full suites including GSI variants and error conditions.
- **Path security** — `..` traversal rejected for open/stat/rm/mkdir.

### `test_io_edge_cases.py`

Wire-level edge cases for every read/write variant:

- **Read** — at/past/zero-length/rlen-larger-than-file/page-boundary/first-last-byte/exact-size/two-non-overlapping/same-offset-twice/negative-offset-as-unsigned/far-beyond-EOF.
- **pgread** — single page CRC correct, empty file, single byte, exactly two pages, partial last page, at page boundary offset, sequential calls, all page CRCs correct.
- **readv** — single/zero-length/two/at-EOF/wraps-EOF/one-byte/overlapping/descending/many-small/response-after-request.
- **Write** — at offset 0 and nonzero, zero bytes, invalid handle, read-only handle, 1KiB chunk, beyond-EOF hole, offset overflow.
- **writev** — single/zero/two-non-overlapping/do-sync/invalid-handle/read-only/zero-length.
- **sync** — write handle, data durable, invalid handle, read-only handle, double sync.

### `test_readv.py`

`kXR_readv` correctness: single segment, three non-overlapping, many small, matches scalar read, unordered segments, EOF error, large response, max segments, invalid handle. Plus GSI variant.

### `test_aio.py`

AIO thread pool path (`src/aio/`):

- Large reads: integrity, at offset, multiple chunks, MD5 hash.
- Large writes: integrity, at offset, multiple chunks.
- readv via AIO: multiple/max segments.
- pgread via AIO: integrity.
- **Destroyed guard** (`TestAioDestroyedGuard`) — disconnect during large read does not crash via stale callback.

### `test_pgwrite_checksum.py`

`kXR_pgwrite` CRC32c enforcement (`xrootd_pgwrite_decode_payload`):

Good checksum accepted, bad checksum rejected, multi-page (first/second/middle page bad), good write reaches disk, bad write does not corrupt existing content. Unaligned offsets, page boundary offset, full 4096-byte page, sequential writes same handle, overwrite partial content.

---

## Advanced opcodes

**Source:** `src/read/`, `src/write/`, `src/clone.c`, `src/fattr/`, `src/session/`

### `test_new_opcodes.py`

Functional tests for opcodes added beyond the original feature set:

- **pgread** — small file, exactly one page, multiple pages, mid-file offset, GSI endpoint, MD5 integrity.
- **writev** — two non-overlapping segments, contiguous, integrity, GSI endpoint.
- **locate** — existing file, server type in response, missing file error, GSI endpoint, read-only server access type.
- **sigver** — accepted, session continues after accept.
- **statx** — single path, multiple paths, missing returns sentinel, mixed, directory.
- **kXR_chkpoint** — begin/commit, begin/rollback, query, ckpXeq write, double-begin rejected, rollback-without-begin rejected.
- **kXR_clone** — full file, partial range, rejected on read-only handle.
- **ckpXeq sub-operations** (`TestChkpointXeq`, `TestChkpointExtended`) — pgwrite good/bad CRC, pgwrite+rollback, multi-page, truncate reduce/extend+rollback, writev segments+rollback, unknown subop rejected, commit persists all, rollback restores all, xeq without checkpoint fails.

### `test_fattr_query.py`

Extended attributes and query sub-operations:

- **kXR_fattr** — set+get, del, list, list with values, nonexistent, multiple attrs, Linux xattr visible on disk, GSI endpoint, recursive flag (extension bit 0x20).
- **kXR_QStats** — XML blob, contains port and link section, via Python client.
- **kXR_Qxattr** — responds, returns set attribute, empty for no attrs.
- **kXR_QFinfo** — ok response, indicates no compression.
- **kXR_QFSinfo** — ok, format, sane values, space via Python client.

---

## Query system

**Source:** `src/query/`

### `test_query.py`

`kXR_Qcksum` (checksum) and `kXR_Qspace` via anonymous and GSI endpoints. Algorithms: adler32, MD5, SHA1, SHA256. Verifies response format, matches after upload, invalid algorithm handling, space query keys.

### `test_query_extended.py`

Less-tested query infotypes:

- **Qconfig** — `chksum`→adler32, `readv`→1, unknown→zero, multiple keys, empty payload, key without newline, response ends with newline, consecutive requests.
- **Qvisa** — no path no crash, with path returns error, consecutive requests, then-ping.
- **Qopaque** — plain path, with opaque string, large payload, then-ping.
- **Dirlist edge cases** — empty dir, dstat flag, file path error, dstat sizes correct, newline delimited, trailing slash, root contents, multiple files, no cross-dir contamination.
- **Checksum variants** — crc32 and crc32c response shape, known file values.
- **Qckscan** — single file, directory tree, nonexistent errors, symlink escape not followed.
- **Consistency** — adler32 of empty file is 1, checksum changes after overwrite, qspace/qfsinfo/qconfig consistent, unknown infotype returns unsupported.

---

## Filesystem namespace

**Source:** `src/write/mv.c`, `src/write/mkdir.c`, `src/write/rm.c`, `src/stat.c`, `src/statx.c`

### `test_fs_ops.py`

Focused namespace operations: mkdir (simple/with-parents/idempotent/GSI), rmdir (empty/nonempty-fails/nonexistent-fails/GSI), rm (file/nonexistent-fails/empty-directory/GSI), mv (file/directory/nonexistent-source/GSI), chmod (file/directory/nonexistent-fails/GSI).

### `test_path_depth_guards.py`

Recursive walk guards: verifies that deeply nested paths cannot cause CPU exhaustion via unbounded recursion.

### `test_interop_namespace.py`

Side-by-side conformance with reference xrootd for all namespace ops: mkdir/rmdir/rm/mv/chmod visible on both, matching error codes for nonexistent sources, truncate by path and by handle, statx multiple paths, fattr set/get/list/del/visible-from-ref.

---

## CMS, manager, and cluster

**Source:** `src/manager/`, `src/cms/`

### `test_cms.py`

CMS heartbeat client:

- Login frame received and contains paths.
- Periodic load sent (`TestCmsPingPong`).
- Avail frames carry correct space fields.
- CMS connection maintained across pings, server survives manager disconnect.
- Wire format: 8-byte frame header, short-tag encoding, int-tag encoding.

### `test_manager_mode.py`

Redirector functionality:

- Protocol flags include `kXR_isManager`.
- `kXR_locate` → `kXR_redirect` to registered data server; host is loopback.
- `kXR_open` → `kXR_redirect`.
- After data server disconnects, redirector stops redirecting.
- **Multi-path** (`TestClusterMultiPath`) — colon-delimited path lists: first/second token redirect, exact token redirect, unregistered path no redirect, partial match not redirected.
- **Multi-server** (`TestClusterMultiServer`) — two servers: locate returns valid server, repeated locates valid, open redirects.
- **Per-worker CMS** (`TestPerWorkerCMS`) — each nginx worker opens independent CMS connection.
- **Three-tier topology** (`TestThreeTierTopology`) — client → meta → sub → leaf two-hop chain.
- **CMS select wake** (`TestCmsSelectWake`) — nginx suspends locate, forwards kYR_locate to CMS, wakes on kYR_select response.
- **Registry full counter** — increments when slot limit exceeded.
- **kYR_gone** — removes path without disconnecting server, other paths unaffected.
- **kYR_try** — redirects to first entry in list, second entry ignored.
- **CMS escalation** — registry miss → kYR_locate to parent → kYR_select → kXR_redirect.

---

## Native TPC

**Source:** `src/tpc/`

### `test_root_tpc.py`

Native root:// third-party copy (SHM key registry):

- `QConfig` reports TPC supported.
- TPC between two nginx-xrootd endpoints (nginx→nginx).
- TPC between reference xrootd and nginx-xrootd (both directions).
- `tpc=only` and `tpc=first` modes.

---

## Session bind (data channels)

**Source:** `src/session/bind.c`, `src/registry.c`

### `test_session_bind.py`

`kXR_bind` secondary data channel:

- Valid bind assigns path ID, bound read uses primary handle, bound stream cannot open files.
- Path ID increments sequentially and cycles at 253.
- Bind with random session ID fails.
- Bind without completing handshake rejected.
- Secondary can read a primary handle after path ID assignment.
- Multiple secondaries on the same primary.

---

## WebDAV

**Source:** `src/webdav/`

### `test_webdav.py`

Functional WebDAV over HTTPS. OPTIONS, PUT, HEAD, GET (range, suffix, from-offset, beyond-EOF), DELETE, MKCOL (including nested-parent 409), path hardening (double-encoded NUL, double-encoded traversal), PROPFIND (depth 0/1, content-length, lastmodified, XML-escaped hrefs), PROPFIND body parsing (allprop, propname, prop, unknown property → 404 propstat), auth (anonymous get, proxy cert PUT), round-trip tests, traversal (dotdot, symlink via GET and PROPFIND), method restrictions (POST/PATCH → 405).

### `test_http_webdav_status_codes.py`

Exhaustive HTTP status code coverage for the **plain HTTP** WebDAV port:

OPTIONS (Allow header, CORS preflight), GET (200/404/403/206/304/412 with all conditional variants), HEAD (ETag stability), PUT (201/204/412/409/ETag rotation), DELETE (204/404/409), MKCOL (201/405/409), PROPFIND (207/404, valid XML, depth 0 vs 1, content-length), MOVE (201/204/412, Overwrite header, no-Destination 400, directory overwrite), COPY (201/204/412/404, directory recursive, depth-0, overwrite), LOCK (201/200/423/204/conflict/expiration).

### `test_https_webdav_status_codes.py`

Same coverage for the **HTTPS** port, plus `TestAuthentication` (proxy cert accepted, optional auth behaviour).

### `test_http_webdav_lock.py` / `test_http_webdav_lock_recursive.py`

WebDAV locking: lock new file (201), refresh (200), enforcement (423 on PUT/DELETE), unlock (204), conflict (423), expiration, depth-zero lock, lock owner from body.

### `test_propfind_infinity.py`

`PROPFIND Depth: infinity` — returns all descendants, finds deep entries, on a file returns one entry. Depth-0 and Depth-1 regressions. Security: response cap prevents exhaustion, response is still valid XML, missing Depth header defaults to zero.

### `test_webdav_http_security.py`

HTTP-level correctness:

- **Range requests** — first/last byte, exact span, middle, suffix > file, beyond-end 416, invalid syntax no crash, reversed start>end, 206 includes Content-Range, total correct, zero-to-zero empty file, body bytes correct.
- **Conditional requests** — If-Match (correct/wrong/star), If-None-Match (304/200), If-Modified-Since, If-Unmodified-Since, PUT If-None-Match-star (new/existing), ETag rotation after PUT, stable across two GETs.
- **Error status codes** — 404/409/207/200/204/201/412 correctness.
- **PROPFIND depth variants** — 0/1/file/no-header/valid-XML/includes-getcontentlength/empty-dir.
- **Content-Range PUT** — partial/full overwrite, first segment accepted, invalid value no crash.

### `test_webdav_auth_cache.py`

x509 certificate authentication caching (`src/webdav/auth_cert.c`).

### `test_webdav_spooled_put.py`

Regression test for PUT bodies that nginx spools to a temp file (large bodies that exceed the in-memory buffer threshold).

---

## WebDAV TPC

**Source:** `src/webdav/tpc.c`, `src/webdav/tpc_curl.c`, `src/webdav/tpc_cred.c`, `src/webdav/tpc_headers.c`

### `test_webdav_tpc.py`

HTTP third-party copy:

- **Plugin-to-plugin pull** (`TestNginxPluginToPluginTPC`) — required cert source, cadir destination, overwrite-false, TPC disabled destination rejects, read-only destination rejects, missing service credential fails.
- **xrootd-http interop** (`TestXrootdHttpInteropTPC`) — xrootd-http source → nginx destination, nginx source → xrootd-http destination.
- **Push mode** (`TestHTTPTPCPush`) — basic push creates file, required source with auth, cadir destination, nonexistent source 404, directory source 409, TPC disabled on source 405, missing service cert destination 502, non-HTTPS destination rejected 400, Transfer header forwarded, Overwrite-false forwarded, both Source+Destination rejected 400.

### `test_webdav_tpc_cred.py`

`Credential:` header parsing:

- none (default), oidc-agent accepted, token-exchange accepted, invalid mode → 400, empty mode → 400, case sensitive, `Credentials:` variant.
- Push credential delegation: none, invalid mode, oidc-agent accepted.
- TPC cred metrics exported at Prometheus endpoint.

### `test_tpc_ssrf_policy.py`

SSRF protection for TPC destinations (`src/webdav/tpc.c`):

- **Default policy** — loopback IPv4 rejected, `localhost` rejected, link-local rejected, RFC-1918 10/192.168/172 allowed.
- **`tpc_allow_local on`** — loopback and link-local not SSRF-blocked, private still allowed.
- **`tpc_allow_private off`** — RFC-1918 all three ranges rejected, loopback still rejected, public IP not blocked.

### `test_tpc_token_mode.py`

`tpc.token_mode` opaque parameter parsing: none, oidc-agent, token-exchange, without-src, no-token-mode, case sensitivity, with other params, empty value, long value.

---

## S3

**Source:** `src/s3/`

### `test_s3.py` / `test_s3_status_codes.py`

S3-compatible API. `test_s3_status_codes.py` provides exhaustive status code coverage:

- **PUT** — 200 new/overwrite/zero-byte/large, ETag present and changes on overwrite, binary roundtrip.
- **GET** — 200/404, XML error body on 404 (NoSuchKey), range 206/416/content-range, content-length, ETag stable.
- **HEAD** — 200/404/ETag/no-body.
- **DELETE** — 204 existing/idempotent, then 404 on GET/HEAD/list.
- **ListObjectsV2** — 200, valid XML, prefix filter, max-keys pagination (collects all), delimiter common-prefixes, sentinel not included.
- **Error responses** — XML error element/code/message, HEAD 404 has no body, POST 405, list bad bucket 404.
- **Path traversal** — `..` rejected with 403 for GET/PUT/DELETE.
- **Symlink confinement** — symlink outside bucket root blocked.

### `test_s3_multipart.py`

Multipart upload lifecycle: basic two-part, single-part, overwrite existing, large part ordering. Abort cleans staging dir, abort idempotent → 404. Negative: part number 0 / too-large / non-numeric rejected, invalid upload ID rejected on abort/complete, complete-nonexistent 404, initiate returns XML with correct namespace.

### `test_s3_presigned.py`

SigV4 authentication for presigned URLs (`src/s3/auth.c`).

---

## Prometheus metrics

**Source:** `src/metrics/`

### `test_metrics.py`

- Endpoint returns 200, correct content-type, HELP+TYPE headers for all ops.
- **Anon counters** — write increments connections and bytes_rx, read increments bytes_tx, open-wr/rd/login counters, connections_active does not leak across close.
- **GSI counters** — GSI server slot appears after transfer, connections_total increments, login counter.

---

## Proxy mode

**Source:** `src/proxy/`

### `test_proxy_mode.py`

Transparent proxy (`xrootd_proxy on`): the module connects to an upstream xrootd server and translates handles between client and upstream.

- **Bootstrap** (`TestProxyBootstrap`) — lazy connect: ping handled before upstream touch, first FS op triggers connect, endsess clean, multiple independent proxy connections.
- **Stat / Dirlist / Read / Write** — forwarding for all basic ops, error propagation.
- **Handle translation** (`TestProxyHandleTranslation`) — two files simultaneously, three interleaved, handle reuse after close, many simultaneous, read from closed handle.
- **readv** (`TestProxyReadV`) — single segment, two same handle, two different handles, many segments.
- **Filesystem mutations** (`TestProxyFsOps`) — mkdir+stat, nested mkdir, rm, rmdir, mv, truncate via path, create+write+stat+rm lifecycle.
- **Error propagation** (`TestProxyErrorPropagation`) — multiple errors in sequence don't break connection.
- **Sequential / Large / Multi-client** — 50 stats in sequence, alternating stat+ping, open+read+close repeated, 512KB reads, 4 clients concurrent access.
- **Backend unavailable** (`TestProxyBackendUnavailable`) — FS op returns error when upstream down, session still clean after failure.

### `test_a_upstream_redirect.py`

Upstream redirect handling (`kXR_redirect`, `kXR_wait`, `kXR_waitresp`):

- Locate redirected, locate with wait-then-redirect, locate waitresp-then-redirect, upstream error forwarded.
- Phase 1 & 2: kXR_authmore bearer-token auth, kXR_gotoTLS (no TLS configured aborts).

---

## Cache write-through

**Source:** `src/cache/`

### `test_cache_write_through.py`

- **Read-through** — cache fill from origin, cache hit local serve, large file admission rejection, eviction threshold.
- **WT decision layer** — allow/deny by prefix, size admission filter, deny precedence over allow.
- **Sync flush** (`WT_MODE_SYNC`) — success before close, no dirty state, origin unreachable fail-open.
- **Async flush** (`WT_MODE_ASYNC`) — task posting, completion callback, failure no propagation.
- **Security negatives** — denied path no flush, origin TLS required, flush permission denied.
- **Close handler integration** — WT-sync flush, WT-async post, eviction excludes WT-enabled files.

---

## Conformance and interop

### `test_interop_io.py`

readv, pgread, pgwrite, writev, sync, locate, clone — all verified to produce identical results on both nginx-xrootd and reference xrootd.

### `test_interop_query.py`

QStats, QSpace, QConfig, Qvisa, checksum format, prepare, open flags, error code families, protocol negotiation, dirlist flags — all compared between both servers.

### `test_xrdhttp*.py`

Interoperability tests using an actual `xrdhttp` (built-in xrootd HTTP module) as the comparison server or counterparty. Covers auth, conformance, TPC, and WebDAV method behaviour.

### `test_xrdcp_*.py`

Functional tests using the `xrdcp` command-line client: client option flags, anonymous access vs GSI comparison.

### `test_concurrent.py`

Concurrency matrix: 1/2/4/8 concurrent transfers over anonymous and GSI, mixed anon+GSI, aggregate throughput scales with connections. Repeated over `roots://`.

### `test_throughput.py`

200 MB streaming: chunked reads anon+GSI, CopyProcess anon+GSI, anon vs GSI throughput within 20%.

---

## Structural guardrails

These tests verify code-level invariants rather than runtime behaviour. They fail when the source tree diverges from architectural contracts — for example, if a helper gets reimplemented, a planned library gets added, or a source layer boundary gets crossed.

| File | What it guards |
|---|---|
| `test_phase0_guardrails.py` | Source-reduction contracts from phase 0 |
| `test_phase1_commodity_libraries.py` | Commodity-library inventory from phase 1 |
| `test_plan6_guardrails.py` | Plan 6 source-layer boundaries |
| `test_cross_protocol_shared_helpers.py` | Shared helpers used across protocols |
| `test_opcode_coverage.py` | Opcode dispatch table completeness |
| `test_opcode_flag_coverage.py` | Option flags with no other test coverage |

---

## Adding coverage

The suite follows one rule: **three tests per change — success, error, and security-negative**. When you add a new test file, register it here in the relevant section so the next contributor knows it exists.

For a deeper dive into *writing* tests see [`writing-tests.md`](writing-tests.md) and the infrastructure overview in [`testing-runbook.md`](testing-runbook.md).
