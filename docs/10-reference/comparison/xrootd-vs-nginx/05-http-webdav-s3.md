# HTTP Family — XrdHttp / WebDAV / HTTP-TPC / S3: Official XRootD vs. gnuBall

> Part of the [XRootD vs gnuBall comparison set](./README.md).

This document compares the **official XRootD C++** server with the **gnuBall**
module on the *HTTP family* of protocols: XrdHttp and WebDAV (RFC 4918 class 1 and
class 2), HTTP third-party-copy (HTTP-TPC, the WebDAV `COPY` push/pull dialect used
by FTS/gfal2), and the S3 REST gateway.

Every claim below is grounded in source. The official side cites the upstream tree
under `/tmp/xrootd-src/src/` (`XrdHttp/`, `XrdHttpTpc/`, `XrdHttpCors/`, and the
*client-side* `XrdClS3/` plugin). The gnuBall side cites this repository's
`src/protocols/webdav/` and `src/protocols/s3/` trees. Where a fact was already established by the
companion comparison documents, this doc reuses it rather than re-deriving it:

- [`../../source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md) — the master source-anchored matrix (HTTP/WebDAV/S3 section).
- [`02-rootd-protocol.md`](./02-rootd-protocol.md) — the `root://` binary wire protocol.

The companion `root://` document covers **native** XRootD third-party-copy (the SHM
key-registry TPC in `src/tpc/` and `src/protocols/root/read/clone.c`). That is a *different*
mechanism from the HTTP-TPC described here and is cross-referenced where the two
meet — see [HTTP third-party-copy](#http-third-party-copy) below.

---

## Scope

In scope:

- **XrdHttp vs. our WebDAV**: every HTTP/WebDAV method — `GET` (ranges, conditional,
  content-encoding, checksum digest), `PUT`, `HEAD`, `DELETE`, `MKCOL`, `OPTIONS`/CORS,
  `PROPFIND`/`PROPPATCH`, `MOVE`, `COPY`, `LOCK`/`UNLOCK` (class-2 locking), `SEARCH`,
  `ACL` — each mapped to its handler file.
- **HTTP-TPC**: the WebDAV `COPY` push/pull dialect with `Source`/`Destination` and
  `Credential` headers, multistream, performance markers, and credential delegation.
- **S3 gateway**: SigV4 (header + presigned + `aws-chunked`), bucket/object operations,
  ListObjects V1/V2 with an LRU cache, multipart upload, `CopyObject`, batch
  `DeleteObjects`, conditional requests, tagging, checksums, `HeadBucket`.
- **TLS, certificates, and tokens** on the HTTP side (GSI/VOMS over HTTPS, bearer
  tokens, grid-mapfile).
- **Admin configuration and end-user examples** for `davs://` and S3 clients.

Out of scope (covered elsewhere): native `root://` TPC and clustering/redirection
([`02-rootd-protocol.md`](./02-rootd-protocol.md) and the clustering comparison),
the metrics/dashboard plane, and FRM/tape internals (Tape REST is touched here only
where it shares the HTTP surface).

---

## In official XRootD

XrdHttp is XRootD's HTTP/WebDAV protocol plugin. Its request model is in
`XrdHttp/XrdHttpReq.hh` / `XrdHttpReq.cc`; the protocol/TLS plumbing and config keyword
parsing live in `XrdHttp/XrdHttpProtocol.cc`; range handling is in
`XrdHttpReadRangeHandler.{hh,cc}`; checksum/digest in `XrdHttpChecksum*.{cc,hh}`;
security extraction in `XrdHttpSecurity.cc` / `XrdHttpSecXtractor.hh`. CORS is an
optional loadable plugin under `XrdHttpCors/`. HTTP-TPC is a separate plugin under
`XrdHttpTpc/` (`XrdHttpTpcTPC.cc`, `XrdHttpTpcState.cc`, `XrdHttpTpcMultistream.cc`,
`XrdHttpTpcConfigure.cc`, `XrdHttpTpcPMarkManager.{hh,cc}`).

The HTTP method set XrdHttp implements is fixed by an enum in `XrdHttpReq.hh`:

```cpp
enum ReqType : int {
  rtUnset = -1, rtUnknown = 0, rtMalformed,
  rtGET, rtHEAD, rtPUT, rtOPTIONS, rtPATCH, rtDELETE,
  rtPROPFIND, rtMKCOL, rtMOVE, rtPOST, rtCOPY,
  rtCount
};
```

So upstream covers `GET`, `HEAD`, `PUT`, `OPTIONS`, `PATCH`, `DELETE`, `POST`, plus the
WebDAV verbs `PROPFIND`, `MKCOL`, `MOVE`, and `COPY`. There is **no** server-side
`LOCK`, `UNLOCK`, `PROPPATCH`, `SEARCH`, or `ACL` method enum in the reviewed source
(grep over `XrdHttpReq.{hh,cc}` returns zero matches for `rtLOCK`/`rtUNLOCK`/
`rtPROPPATCH`/`rtSEARCH`/`rtACL`). This means upstream XrdHttp is effectively WebDAV
**class 1** plus the WLCG extensions (TPC, digests), not WebDAV class 2.

On the S3 side, upstream ships **`XrdClS3`**, which is a **client** plugin: an
`XrdCl::PlugInFactory` (`XrdClS3Factory.hh`) that creates file/filesystem plugins so an
XRootD *client* can read/write objects on a remote S3-compatible store
(`XrdClS3Filesystem.cc`, `XrdClS3File.cc`, with `GenerateV4Signature()` to sign outbound
requests). There is **no server-side S3 REST endpoint** in the reviewed upstream tree —
the `XrdS3/` directory exists but is empty, and there is no `XrdS3Server`/`S3Endpoint`
symbol in `XrdHttp`.

---

## In gnuBall

The WebDAV/XrdHttp plane is an nginx HTTP module under `src/protocols/webdav/`. The master
request router is `ngx_http_xrootd_webdav_handler()` in `src/protocols/webdav/dispatch.c`, which
switches on the HTTP method and delegates to per-method handler files; the
advertised method set and per-method metric slots/flags are described by the
`xrootd_webdav_operations[]` descriptor array in `src/protocols/webdav/operation_table.c`. The
handler is installed in `NGX_HTTP_CONTENT_PHASE` by
`src/protocols/webdav/postconfig.c`. The XrdHttp dialect (the `X-Xrootd-*` headers, `?xrd.stats`,
`Want-Digest`, HTTP↔`kXR_*` status mapping) is layered on top in `src/protocols/webdav/xrdhttp.c`,
`xrdhttp_filter.c`, `xrdhttp_stats.c`, and `xrdhttp_multipart.c`.

The module implements WebDAV **class 1 and class 2** — its `OPTIONS` response sends
`DAV: "1, 2"` (`src/protocols/webdav/methods_basic.c`), and it ships real `LOCK`/`UNLOCK`
handlers (`src/protocols/webdav/lock.c`), `PROPPATCH` and dead properties
(`src/protocols/webdav/methods_basic.c`, `dead_props.c`, `prop_xattr.c`), plus `SEARCH`
(`src/protocols/webdav/search.c`, advertised via `DASL: <DAV:basicsearch>`) and a read-only
`ACL` discovery method (`src/protocols/webdav/acl.c`). All of these are beyond the upstream
XrdHttp method enum.

The S3 gateway is a **second, independent** nginx HTTP module under `src/protocols/s3/`, with its
own dispatcher (`ngx_http_s3_handler` in `src/protocols/s3/handler.c`), operation descriptor
table (`src/protocols/s3/operation_table.c`), and SigV4 verification stack
(`auth_sigv4_parse.c`, `auth_sigv4_canonical.c`, `auth_sigv4_verify.c`). This is a
**server-side** S3 REST endpoint — it has no upstream counterpart and is therefore
described throughout this document as **nginx-forward** (a feature the module *adds*,
not one it ports). See [S3 gateway](#s3-gateway-nginx-forward).

A shared discipline applies to both modules: every wire path is resolved and confined
before any syscall via `ngx_http_xrootd_webdav_resolve_path()` /
`xrootd_open_confined_canon()` (and the S3 `s3_resolve_key()` equivalent), per the
project's path-confinement invariant.

---

## WebDAV methods

Per-method comparison. "RFC class" indicates whether the method is WebDAV class 1
(RFC 4918 core, no locking) or class 2 (locking), or a related RFC. "Official" is the
upstream XrdHttp behaviour from the `ReqType` enum and handlers; "Our handler" is the
gnuBall file and entry function.

| Method | RFC class | Official XrdHttp | Our handler | Notes |
|---|---|---|---|---|
| `GET` | class 1 | `rtGET`; ranges via `XrdHttpReadRangeHandler`; ETag (`addETagHeader`, `inode-dev`); chunked TE; no compression | `src/protocols/webdav/get.c` → `webdav_handle_get()` | Single + multi-range (`multipart/byteranges`); `If-Modified-Since` → 304; optional response compression via `xrootd_webdav_compress`; TLS=memory-backed buffers, cleartext=sendfile |
| `HEAD` | class 1 | `rtHEAD` | `src/protocols/webdav/methods_basic.c` → `webdav_handle_head()` | Stat via `webdav_resolve_stat()`; `Content-Length`, `Last-Modified`, optional `ETag`; `Content-Type` `httpd/unix-directory` for dirs |
| `PUT` | class 1 | `rtPUT` | `src/protocols/webdav/put.c` → `webdav_handle_put_body()` | Async body read; lock check **before** body read; staged temp file + atomic rename; thread-pool offload |
| `DELETE` | class 1 | `rtDELETE` | `src/protocols/webdav/namespace.c` → `webdav_handle_delete()` | Recursive delete; on collections checks child locks via `webdav_check_locks_tree()` |
| `MKCOL` | class 1 | `rtMKCOL` | `src/protocols/webdav/namespace.c` → `webdav_handle_mkcol()` | Collection create (mkdir, confined) |
| `OPTIONS` | class 1/2 | `rtOPTIONS`; `Allow` header | `src/protocols/webdav/methods_basic.c` → `webdav_handle_options()` | Emits `DAV: "1, 2"`, `DASL: <DAV:basicsearch>`, `MS-Author-Via: DAV`; `Allow` built from `allow_write` (read-only vs. full set) |
| `PROPFIND` | class 1 | `rtPROPFIND` | `src/protocols/webdav/propfind.c` → `webdav_handle_propfind()` | `Depth: 0/1/infinity`; live + dead properties; libxml2 hardened (`NONET`, no-XXE, no `HUGE`); `infinity` capped at `XROOTD_WEBDAV_PROPFIND_MAX_ENTRIES` (DoS ceiling) |
| `PROPPATCH` | class 1 | **not present** (no `rtPROPPATCH`) | `src/protocols/webdav/methods_basic.c` → `webdav_handle_proppatch()` (dead-prop storage in `dead_props.c`/`prop_xattr.c`) | Returns 207 Multi-Status; dead props stored as hex-encoded xattrs — needed by clients that treat `501` as fatal |
| `MOVE` | class 1 | `rtMOVE` | `src/protocols/webdav/move.c` → `webdav_handle_move()` | Lock check on **both** source and destination; thread-pool offload; rename within confined root |
| `COPY` | class 1 | `rtCOPY` (also the HTTP-TPC verb) | `src/protocols/webdav/copy.c` → `webdav_handle_copy()`; TPC path → `src/protocols/webdav/tpc.c` | Local server-side copy (recursive tree → temp → rename); when `Source`/`Credential` header present, dispatched to HTTP-TPC instead (see below) |
| `LOCK` | **class 2** | **not present** | `src/protocols/webdav/lock.c` → `webdav_handle_lock()` | xattr-backed; exclusive + shared; `Depth: 0`/`infinity`; locks persist across restart unless `xrootd_webdav_lock_startup_sweep on` |
| `UNLOCK` | **class 2** | **not present** | `src/protocols/webdav/lock.c` → `webdav_handle_unlock()` | Removes lock xattr; `If:`/lock-token matching |
| `SEARCH` | RFC 5323 (DASL) | **not present** | `src/protocols/webdav/search.c` → `webdav_handle_search()` | Basic `<DAV:basicsearch>` over the confined namespace; `Depth: 0/1/infinity` |
| `ACL` | RFC 3744 | **not present** | `src/protocols/webdav/acl.c` → `webdav_handle_acl()` | Read-only discovery; refuses client-side ACL mutation (403) |
| `POST` | — | `rtPOST` | `src/protocols/webdav/macaroon_endpoint.c` → `webdav_handle_macaroon_token()` (also S3 browser-form POST in `src/protocols/s3/`) | Our WebDAV `POST` is the macaroon/token issuance endpoint (`/.oauth2/token`) |
| `PATCH` | — | `rtPATCH` | not implemented (returns method-not-allowed) | Upstream parses `rtPATCH`; our module does not expose a `PATCH` handler |

### Locking detail (class 2)

Our locks are stored as a single xattr per resource, encoded
`token=…|owner=…|expires=…|scope=exclusive\|shared|depth=infinity\|0`
(`src/protocols/webdav/prop_xattr.c`), created with `XATTR_CREATE` so the kernel serialises lock
creation (race losers get `EEXIST` → 423 Locked). `webdav_check_locks()`
(`src/protocols/webdav/lock.c`) walks from the target path up to the export root checking each
ancestor; `webdav_check_locks_tree()` adds recursive descent so that `DELETE`/`MOVE`/
`COPY` on a collection also honour locks on children. This satisfies INVARIANT #5 of
the project (recursive child-lock checks on collection mutations) and is the principal
WebDAV-class-2 advantage over upstream XrdHttp, which has no server-side lock handler.

### XrdHttp dialect parity

Both sides speak the WLCG XrdHttp dialect on top of WebDAV:

- **Checksum / digest.** Upstream `XrdHttpChecksumHandler` answers `Want-Digest` (RFC 3230)
  and `Want-Repr-Digest` (RFC 8941) with `md5`, `adler32`, `sha`, `sha-256`, `sha-512`,
  `UNIXcksum`, `crc32c` (per `XrdHttp/README-CKSUM.md`). Our `src/protocols/webdav/xrdhttp.c`
  answers `Want-Digest` / `?xrd.want.cksum` by computing the digest from the fd (or the
  xattr integrity cache) and emitting a `Digest:` header; `adler32` can be folded
  through the body filter, others computed from a full read. Algorithms include the
  project's CRC-64/XZ and CRC-64/NVME (per the CRC64 invariant; engine in
  `src/core/compat/crc64.c`).
- **`X-Xrootd-*` headers and `?xrd.stats`.** `src/protocols/webdav/xrdhttp.c` parses `X-Xrootd-Proto`,
  echoes `X-Xrootd-Requuid`, captures `X-Xrootd-Tpc-Token`, and maps HTTP status → `kXR_*`
  opcode in the response filter (`xrdhttp_filter.c`); `?xrd.stats` is served by
  `xrdhttp_stats.c`.
- **CORS.** Upstream CORS is the optional `XrdHttpCors` plugin (`cors.origin` config,
  echoes `Access-Control-Allow-Origin`). Ours is built in: `webdav_add_cors_headers()`
  in `src/protocols/webdav/cors.c`, driven by `xrootd_webdav_cors_origin` (allowlist, repeatable)
  and `xrootd_webdav_cors_credentials`, and emits `Vary: Origin` to avoid origin leakage.

---

## HTTP third-party-copy

HTTP-TPC is the WebDAV `COPY` dialect used by FTS3/gfal2 to move bytes directly between
two storage endpoints. The active endpoint receives a `COPY` with either a `Source:`
header (it **pulls** from the remote) or a `Destination:` header (it **pushes** to the
remote), plus an optional `Credential:` header describing how to authenticate the
remote leg. **Note:** this is distinct from *native* `root://` TPC (the SHM key-registry
mechanism in `src/tpc/`), which is covered in the `root://` / clustering comparison.

| Aspect | Official `XrdHttpTpc` | gnuBall `src/protocols/webdav/tpc*.c` |
|---|---|---|
| Dispatch | `rtCOPY` handler in `XrdHttpTpcTPC.cc`; `Source`/`Destination` headers select pull/push | `ngx_http_xrootd_webdav_tpc_handle_copy()` in `src/protocols/webdav/tpc.c`; detects `Source`/`Destination` (rejects both-or-neither with 400) |
| Outbound client | libcurl (`#include <curl/curl.h>`, `curl_multi` for concurrency) | libcurl via `src/protocols/webdav/tpc_curl.c` (`curl_multi`); curl path configurable (`xrootd_webdav_tpc_curl`, default `/usr/bin/curl`) |
| Multistream | `RunCurlWithStreams()`; `X-Number-Of-Streams` header | `X-Number-Of-Streams` parsed, capped by `xrootd_webdav_tpc_max_streams` (default 1); parallel Range-GET via per-stream `pwrite()` |
| Performance markers | `XrdHttpTpc::PMarkManager`; periodic chunked `Perf Marker` blocks | `src/protocols/webdav/tpc_marker.c`; same `Perf Marker` wire block (`Timestamp:`/`Stripe Index:`/`Stripe Bytes Transferred:`/`Total Stripe Count:`/`End`), 202 + chunked body, 200 ms poll, interval set by `xrootd_webdav_tpc_marker_interval` (default 0 = off) |
| Credential / delegation | `Credential:` header (`none` only in reviewed source); `TransferHeaderN` forwarding (e.g. `TransferHeaderAuthorization`); `tpcForwardCreds` for redirects | `Credential:` modes `none`, `oidc-agent`, `token-exchange` (`src/protocols/webdav/tpc_cred.c`, `tpc_cred_parse.c`); injects `Authorization: Bearer <tok>` into the transfer |
| OAuth2 token exchange | not in reviewed source | RFC 8693 exchange against `xrootd_webdav_tpc_token_endpoint` using the request's bearer as subject token (`src/protocols/webdav/tpc_cred.c`) |
| SSRF / DNS-pinning | not in reviewed source | `tpc_curl_secure()` forces `SSL_VERIFYPEER=1`/`VERIFYHOST=2`, resolves+pins the target IP via `CURLOPT_RESOLVE` (`xrootd_net_target_check_dns_pin()`) to close the TOCTOU window; policy gated by `xrootd_webdav_tpc_allow_local`/`_allow_private` |
| Stall protection | curl timeouts | 30 s connect timeout, TCP keepalive, low-speed detector (`xrootd_webdav_tpc_low_speed_bytes`/`_secs`, default 1024 B/s for 60 s) |

So the two are at parity on the core HTTP-TPC mechanics (pull/push, libcurl, multistream,
performance markers), and gnuBall **adds** operational hardening: OAuth2 token
exchange and `oidc-agent` delegation, SSRF/DNS-pinning, low-speed stall detection, and
dashboard/metric visibility. Upstream's `Credential:` handling in the reviewed source
accepts only `none` (with `TransferHeaderN`-style header forwarding for the actual auth),
whereas our module performs the credential acquisition itself.

The full HTTP-TPC tuning surface is in `src/protocols/webdav/tpc_config.c`:

| Directive | Default | Purpose |
|---|---|---|
| `xrootd_webdav_tpc` | off | Enable HTTP-TPC |
| `xrootd_webdav_tpc_max_streams` | 1 | Max parallel Range-GET streams |
| `xrootd_webdav_tpc_marker_interval` | 0 (off) | Performance-marker poll interval (ms) |
| `xrootd_webdav_tpc_timeout` | 0 (no limit) | Overall transfer timeout (s) |
| `xrootd_webdav_tpc_low_speed_bytes` / `_secs` | 1024 / 60 | Stall detector floor / window |
| `xrootd_webdav_tpc_allow_local` / `_allow_private` | 0 / 1 | SSRF policy for loopback / RFC 1918 targets |
| `xrootd_webdav_tpc_cert` / `_key` / `_cafile` / `_cadir` | inherit | Client X.509 material for the remote leg |
| `xrootd_webdav_tpc_token_endpoint` / `_client_id` / `_client_secret` / `_token_scope` | "" / "" / "" / `storage.read` | RFC 8693 token-exchange parameters |

A related HTTP tape surface, the WLCG **Tape REST** API
(`src/protocols/webdav/tape_rest.c`, gated by `xrootd_webdav_tape_rest`), is an nginx-forward
feature with no upstream daemon equivalent; it shares the FRM stage queue and is
detailed in the FRM/tape documentation.

---

## S3 gateway (nginx-forward)

This is the clearest divergence in the HTTP family: upstream `XrdClS3` is a **client**
plugin for talking *to* S3 stores, whereas gnuBall ships a **server-side S3 REST
endpoint** under `src/protocols/s3/`. There is no upstream feature to compare it against, so every
row below is an nginx-forward capability. The endpoint is **path-style** (`/<bucket>/<key>`);
virtual-hosted bucket addressing and a dynamic STS credential store are explicitly out
of scope.

**Dispatch** (`src/protocols/s3/handler.c`, `src/protocols/s3/operation_table.c`): `s3_parse_uri()` splits
`/<bucket>/<key>`, the request is authorized through the XrdAcc tier (`s3_acc_check()`),
and then routed by method + query string:

| S3 operation | HTTP + selector | Handler file |
|---|---|---|
| GetObject | `GET /<bucket>/<key>` | `src/protocols/s3/object.c` |
| HeadObject | `HEAD /<bucket>/<key>` | `src/protocols/s3/object.c` |
| HeadBucket | `HEAD /<bucket>` | `src/protocols/s3/handler.c` |
| PutObject | `PUT /<bucket>/<key>` | `src/protocols/s3/put.c` |
| CopyObject | `PUT /<bucket>/<key>` + `x-amz-copy-source` | `src/protocols/s3/copy.c` |
| DeleteObject | `DELETE /<bucket>/<key>` | `src/protocols/s3/object.c` |
| DeleteObjects (batch) | `POST /<bucket>/?delete` | `src/protocols/s3/delete_objects.c` |
| ListObjectsV2 | `GET /<bucket>/?list-type=2` | `src/protocols/s3/list_objects_v2.c` |
| ListObjectsV1 | `GET /<bucket>/` (no `list-type`) | `src/protocols/s3/list_objects_v1.c` |
| InitiateMultipartUpload | `POST /<bucket>/<key>?uploads` | `src/protocols/s3/multipart_initiate.c` |
| UploadPart | `PUT …?uploadId=&partNumber=` | `src/protocols/s3/multipart_*.c` |
| UploadPartCopy | `PUT …?uploadId=&partNumber=` + copy-source | `src/protocols/s3/multipart_complete_upload_part_copy.c` |
| CompleteMultipartUpload | `POST …?uploadId=` | `src/protocols/s3/multipart_complete.c` |
| AbortMultipartUpload | `DELETE …?uploadId=` | `src/protocols/s3/multipart_abort.c` |
| ListParts | `GET …?uploadId=` | `src/protocols/s3/multipart_complete_list_parts.c` |
| Get/Put/DeleteObjectTagging | `…?tagging` | `src/protocols/s3/tagging.c` |
| POST Object (browser form) | `POST /<bucket>/` multipart/form-data | `src/protocols/s3/post_object.c` |
| GetBucketVersioning / ACL / CORS | `GET …?versioning` / `?acl` / `?cors` | `src/protocols/s3/handler.c` (canned/disabled responses; unsupported mutations return `501 NotImplemented`) |

### SigV4 authentication

`src/protocols/s3/auth_sigv4_*` verifies **AWS Signature Version 4** server-side in three forms:

- **Header form** — `Authorization: AWS4-HMAC-SHA256 Credential=…,SignedHeaders=…,Signature=…`
  (`auth_sigv4_parse.c`).
- **Presigned query form** — `X-Amz-Algorithm`/`X-Amz-Credential`/`X-Amz-Date`/
  `X-Amz-Expires`/`X-Amz-SignedHeaders`/`X-Amz-Signature` (same parser).
- **Streaming `aws-chunked`** — `src/protocols/s3/aws_chunked.c` runs a chunk-framing state machine
  and verifies the per-chunk `AWS4-HMAC-SHA256-PAYLOAD` signature with a constant-time
  compare; gated by `xrootd_s3_verify_chunk_signatures`.

Canonicalisation (`auth_sigv4_canonical.c`) sorts and percent-encodes query parameters
per the SigV4 rules. SigV4 is kept strictly separate from WLCG-token auth per the
project invariant (S3 SigV4 ≠ WLCG token — never shared).

### Object, list, multipart, conditional, checksum behaviour

- **ListObjects** supports both V1 (`list_objects_v1.c`) and V2 (`list_objects_v2.c`),
  sharing the filesystem walk in `list_walk.c`. V2 parses `prefix`, `delimiter`,
  `continuation-token` (base64url), `max-keys` (capped by `xrootd_s3_max_keys`,
  default 1000), `fetch-owner`, and `encoding-type=url`. A **per-worker LRU cache**
  (`src/protocols/s3/list_cache.c`/`.h`, enabled by `xrootd_s3_list_cache`, TTL
  `xrootd_s3_list_cache_ttl`, default 10 s) memoises sorted `(root, prefix, delimiter)`
  listings keyed on the bucket-root mtime — bounded-eventual consistency, not SHM-shared.
- **Multipart upload** is complete: initiate (with a generated upload-ID and a confined
  `0700` staging dir), upload part (`part.<N>` staging files), upload-part-copy, complete
  (XML part list validated against staged parts, sorted, assembled), abort (recursive
  staging cleanup), list-parts, and list-uploads. Abandoned uploads older than
  `xrootd_s3_mpu_max_age` can be reaped.
- **Conditional requests** (`src/protocols/s3/conditional.c`) implement RFC 9110 §13.2.2 precedence:
  `If-Match` → 412, `If-Unmodified-Since` → 412, `If-None-Match` → 304/412 (incl. `"*"`
  for atomic create-if-absent), `If-Modified-Since` → 304. ETags are synthetic
  `"mtime-size"` validators.
- **Checksums** (`src/protocols/s3/checksum.c`) cover `crc32`, `crc32c`, `crc64nvme`, `sha1`,
  `sha256`, emitted as `x-amz-checksum-*`. Per the CRC64 invariant, `crc64nvme` is the
  S3 default and is wire-encoded as **base64 of the 8 big-endian raw bytes** (encoded at
  the edge, never in the kernel) — distinct from the 16-hex form used on `root://`/WebDAV.
- **CopyObject** (`copy.c`) reads `x-amz-copy-source`, resolves both keys under
  confinement, and commits via the staged-file pattern; **batch DeleteObjects**
  (`delete_objects.c`) parses up to 1000 `<Object><Key>` entries (libxml2 with network
  disabled), treats `ENOENT` as success (S3 idempotency), and returns per-key
  `<Deleted>`/`<Error>`. **Tagging** (`tagging.c`) stores tags in the `user.s3.tagging`
  xattr; **POST Object** (`post_object.c`) handles browser multipart-form uploads with
  policy + SigV4 verification.

---

## TLS, certs, and tokens on HTTP

Both stacks support GSI/VOMS X.509 over HTTPS and bearer tokens, but the plumbing differs
because gnuBall reuses nginx's TLS engine and certificate model rather than XrdTls.

| Concern | Official XrdHttp | gnuBall |
|---|---|---|
| TLS termination | XrdTls; `http.cert`/`http.key`/`http.cadir`/`http.httpsmode {off\|manual\|auto}` (`XrdHttpProtocol.cc`) | nginx `listen … ssl;` + `ssl_certificate`/`ssl_certificate_key`, plus module client-cert directives |
| X.509 / GSI client cert | chain extraction in `XrdHttpSecurity.cc` (`EECname()`/`EEChash()` → `SecEntity`) | `src/protocols/webdav/auth_cert.c`, `pki.c`; `xrootd_webdav_cadir`/`cafile`/`crl`/`verify_depth` |
| VOMS proxy | `http.secxtractor libXrdHttpVOMS.so` plugin (`XrdHttpSecXtractor.hh`) | proxy-cert support enabled by `xrootd_webdav_proxy_certs` (sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on the SSL ctx in `postconfig.c`); verified by `webdav_verify_proxy_cert()` |
| Grid-mapfile | `http.gridmap` → `dn2user()` (`XrdHttpSecurity.cc`) | DN/issuer mapping through the auth/ACC stack |
| Bearer / token | `http.secretkey` token-hash check; HTTPS→HTTP+token redirect (`http.selfhttps2http`) | `webdav_verify_bearer_token()` + `xrootd_token_check_scope()` (HELPERS); macaroon issuance at `/.oauth2/token` (`macaroon_endpoint.c`) |
| Auth requirement | per-protocol/path config | `xrootd_webdav_auth {none\|optional\|required}` |

A subtle but important policy invariant on our side: access is gated on the **completed**
auth verdict (`allow_write` is checked globally *before* token scope), never on an
intermediate "logged-in" state — this is what prevents proxy fail-open.

---

## Admin configuration & end-user examples

### Listen ports (this module's routing table)

| Plane | Port | Notes |
|---|---|---|
| `davs://` / `http://` (no GSI) | **8443** | plain TLS / cleartext WebDAV |
| `davs://` (GSI + TLS) | **8444** | GSI/VOMS proxy-cert WebDAV |
| S3 REST | **9001** | path-style buckets |

(Ports are the module's documented test/routing convention; nginx `listen` is freely
configurable per deployment.)

### Enabling WebDAV

```nginx
server {
    listen 8444 ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;

    location / {
        xrootd_webdav              on;
        xrootd_webdav_root         /data/export;
        xrootd_webdav_allow_write  on;          # PUT/DELETE/MKCOL/MOVE/COPY/LOCK
        xrootd_webdav_auth         required;
        xrootd_webdav_cadir        /etc/grid-security/certificates;
        xrootd_webdav_proxy_certs  on;          # accept VOMS/GSI proxy chains
        xrootd_webdav_tpc          on;          # HTTP third-party-copy
        xrootd_webdav_tpc_max_streams       4;
        xrootd_webdav_tpc_marker_interval   5000;
        xrootd_webdav_cors_origin  https://portal.example.org;
    }
}
```

End-user WebDAV access:

```bash
# Listing / download / upload with gfal2 over davs://
gfal-ls    davs://host.example.org:8444/data/export/dir/
gfal-copy  davs://host.example.org:8444/data/export/file  file:///tmp/file
gfal-copy  file:///tmp/file  davs://host.example.org:8444/data/export/file

# Third-party copy (FTS-style): pull on the destination endpoint
curl -X COPY \
  -H 'Source: https://src.example.org:8444/data/file' \
  -H 'Credential: none' \
  -H 'X-Number-Of-Streams: 4' \
  https://dst.example.org:8444/data/file
```

### Enabling S3

```nginx
server {
    listen 9001 ssl;
    ssl_certificate     /etc/pki/tls/certs/s3.crt;
    ssl_certificate_key /etc/pki/tls/private/s3.key;

    location / {
        xrootd_s3             on;
        xrootd_s3_root        /data/export;
        xrootd_s3_bucket      mybucket;
        xrootd_s3_access_key  AKIAEXAMPLE;
        xrootd_s3_secret_key  <secret>;
        xrootd_s3_region      us-east-1;
        xrootd_s3_allow_write on;
        xrootd_s3_list_cache  on;
        xrootd_s3_max_keys    1000;
    }
}
```

End-user S3 access (path-style):

```bash
aws --endpoint-url https://host.example.org:9001 --no-verify-ssl \
    s3 cp ./file.dat s3://mybucket/path/file.dat
aws --endpoint-url https://host.example.org:9001 --no-verify-ssl \
    s3 ls s3://mybucket/path/
```

---

## Parity, divergences, and extensions

| Area | Official XrdHttp | gnuBall | Verdict |
|---|---|---|---|
| Core WebDAV class 1 (`GET`/`HEAD`/`PUT`/`DELETE`/`MKCOL`/`OPTIONS`/`PROPFIND`/`MOVE`/`COPY`) | yes | yes | Parity |
| Range GET (single + multipart byteranges) | yes | yes | Parity |
| Conditional GET (`If-Modified-Since`) | ETag emitted; `If-Modified-Since`/`If-None-Match` not verified in reviewed source | `If-Modified-Since` → 304; ETag | nginx ≥ / Parity |
| Want-Digest / checksum | yes (md5/adler32/sha*/crc32c) | yes (+ CRC-64/XZ, CRC-64/NVME) | Parity / nginx+ |
| CORS | optional `XrdHttpCors` plugin | built-in helper + directives | Parity |
| WebDAV class 2 `LOCK`/`UNLOCK` | **no** | **yes** (xattr, recursive child checks) | nginx+ |
| `PROPPATCH` / dead properties | **no** | **yes** | nginx+ |
| `SEARCH` (DASL) | **no** | **yes** | nginx+ |
| `ACL` method | **no** | **yes** (read-only discovery) | nginx+ |
| `PATCH` | parsed (`rtPATCH`) | not implemented | upstream+ (minor) |
| HTTP-TPC pull/push + libcurl | yes | yes | Parity |
| HTTP-TPC multistream + perf markers | yes | yes | Parity |
| HTTP-TPC credential delegation | `Credential: none` + `TransferHeaderN` forwarding | `none`/`oidc-agent`/`token-exchange` (RFC 8693) | nginx+ |
| HTTP-TPC SSRF / DNS-pinning / stall detection | not in reviewed source | yes | nginx+ |
| Server-side S3 REST endpoint | **no** (only `XrdClS3` client plugin) | **yes** (`src/protocols/s3/`) | nginx-only |
| S3 SigV4 (header + presigned + aws-chunked) | client-side signing only | server-side verification | nginx-only |
| S3 multipart / CopyObject / batch delete / tagging / conditional / checksums | n/a (no server) | yes | nginx-only |
| GSI/VOMS over HTTPS | yes (secxtractor + gridmap) | yes (proxy-cert + ACC) | Parity |
| HTTPS→HTTP+token redirect (`selfhttps2http`) | yes | not applicable (nginx TLS model) | upstream-specific |
| Native `root://` TPC | yes | yes | covered in `02-rootd-protocol.md` / clustering |

Net: on **WebDAV class 1 + XrdHttp WLCG extensions + HTTP-TPC**, the two are at parity,
with gnuBall adding full **WebDAV class 2** (locking, dead props, SEARCH, ACL) and
hardened TPC credential/SSRF handling. The **S3 gateway is nginx-only** — upstream has no
server-side S3 in the reviewed tree. The single small thing upstream parses that we do
not handle is `PATCH`.

---

## Source references

**Official XRootD** (`/tmp/xrootd-src/src/`):

- `XrdHttp/XrdHttpReq.hh` — `ReqType` method enum (`rtGET`…`rtCOPY`); `XrdHttpReq.cc` —
  `addETagHeader()`, range/multipart byteranges, digest handling.
- `XrdHttp/XrdHttpReadRangeHandler.{hh,cc}` — range parsing.
- `XrdHttp/XrdHttpChecksum*.{cc,hh}`, `README-CKSUM.md` — `Want-Digest`/`Repr-Digest`.
- `XrdHttp/XrdHttpProtocol.cc` — `http.cert`/`key`/`cadir`/`gridmap`/`secretkey`/
  `secxtractor`/`httpsmode`/`selfhttps2http` config keywords.
- `XrdHttp/XrdHttpSecurity.cc`, `XrdHttpSecXtractor.hh` — X.509 chain extraction, VOMS
  secxtractor, gridmap.
- `XrdHttpCors/` — CORS plugin (`cors.origin`).
- `XrdHttpTpc/XrdHttpTpcTPC.cc`, `XrdHttpTpcState.cc`, `XrdHttpTpcMultistream.cc`,
  `XrdHttpTpcConfigure.cc`, `XrdHttpTpcPMarkManager.{hh,cc}` — HTTP-TPC (libcurl,
  multistream, `TransferHeaderN`, perf markers, `Credential: none`).
- `XrdClS3/XrdClS3Factory.hh`, `XrdClS3Filesystem.cc`, `XrdClS3File.cc` — **client** S3
  plugin (`GenerateV4Signature()`); confirms no server-side S3 (`XrdS3/` empty).

**gnuBall** (`src/`):

- WebDAV dispatch / methods: `webdav/dispatch.c`, `operation_table.c`, `postconfig.c`,
  `get.c`, `put.c`, `namespace.c` (DELETE/MKCOL), `move.c`, `copy.c`, `propfind.c`,
  `methods_basic.c` (OPTIONS/HEAD/PROPPATCH), `lock.c` (LOCK/UNLOCK), `search.c`,
  `acl.c`, `dead_props.c`, `prop_xattr.c`, `cors.c`, `macaroon_endpoint.c`.
- XrdHttp dialect: `webdav/xrdhttp.c`, `xrdhttp_filter.c`, `xrdhttp_stats.c`,
  `xrdhttp_multipart.c`.
- TLS/cert/token: `webdav/auth_cert.c`, `pki.c`, `auth_token.c`, `postconfig.c`.
- HTTP-TPC: `webdav/tpc.c`, `tpc_curl.c`, `tpc_cred.c`, `tpc_cred_parse.c`,
  `tpc_headers.c`, `tpc_marker.c`, `tpc_thread.c`, `tpc_config.c`.
- S3: `s3/handler.c`, `operation_table.c`, `auth_sigv4_parse.c`,
  `auth_sigv4_canonical.c`, `auth_sigv4_verify.c`, `aws_chunked.c`, `object.c`,
  `put.c`, `copy.c`, `delete_objects.c`, `list_objects_v1.c`, `list_objects_v2.c`,
  `list_walk.c`, `list_cache.c`/`.h`, `multipart_*.c`, `conditional.c`, `checksum.c`,
  `tagging.c`, `post_object.c`, `module.c`.
- Config keywords cited from `webdav/module.c`, `webdav/config.c`, `webdav/tpc_config.c`,
  `s3/module.c`; port routing from the project routing table.

Companion documents:
[`../../source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md),
[`02-rootd-protocol.md`](./02-rootd-protocol.md).
