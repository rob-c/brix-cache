# Request-lifecycle sequence diagrams

These call-ladder diagrams trace each protocol from the wire to the filesystem and back, naming the real function and `file:line` at every step so a reviewer can jump straight to the code. They complement the prose walk-throughs in [`overview.md`](overview.md), [`stream.md`](stream.md), [`webdav.md`](webdav.md) and [`s3.md`](s3.md), and the per-subsystem tables in [`../../src/README.md`](../../src/README.md).

> Generated and verified against the source by an adversarial documentation audit (every cited symbol was confirmed to exist). If a line number drifts as code moves, trust the **function name** over the number and re-anchor with `grep`.

## Contents

- [root:// — XRootD stream session lifecycle](#root--xrootd-stream-session-lifecycle)
- [davs:// — WebDAV / HTTPS request lifecycle](#davs--webdav--https-request-lifecycle)
- [S3 REST request lifecycle](#s3-rest-request-lifecycle)
- [CMS cluster registration and redirect lifecycle](#cms-cluster-registration-and-redirect-lifecycle)

## root:// — XRootD stream session lifecycle

```text
TCP Accept → TCP Connection Ready
     |
     v
ngx_stream_xrootd_handler (handler.c:26)
 [ctx allocation, HANDSHAKE state]
     |
     v
ngx_stream_xrootd_recv (recv.c:98)
 [state machine: HANDSHAKE → REQ_HEADER → REQ_PAYLOAD]
 [reads 20-byte ClientInitHandShake]
     |
     v
Dispatch kXR_protocol
     |
xrootd_dispatch_session_opcode (dispatch_session.c:123)
     ├─→ xrootd_handle_protocol (protocol_hdr)
     |    └─→ xrootd_queue_response (basic.c via response/)
     |         └─→ Send ServerResponseHdr + caps
     |
     v (next request)
Dispatch kXR_login
     |
xrootd_handle_login (login.c:61)
 [parse username, set logged_in=1]
 [session_start = ngx_current_msec]
     |
     ├─→ XROOTD_AUTH_NONE?
     |    └─→ xrootd_session_register (registry.h)
     |         └─→ xrootd_queue_response (sessid only)
     |              └─→ auth_done = 1 (skip auth round)
     |
     └─→ XROOTD_AUTH_GSI/TOKEN/SSS?
          └─→ xrootd_queue_response (sessid + param block)
              └─→ auth_done = 0 (await kXR_auth)
     |
     v (if auth required)
Dispatch kXR_auth
     |
xrootd_handle_auth (gsi/auth.c:80 inner)
 [extract credtype, route: gsi/token/sss]
     |
     ├─→ GSI path:
     |    ├─→ kXGC_certreq: xrootd_gsi_send_cert()
     |    └─→ kXGC_cert: xrootd_gsi_parse_x509()
     |         ├─→ verify cert chain (X509_V_FLAG_ALLOW_PROXY_CERTS)
     |         ├─→ extract DN from leaf
     |         └─→ optional VOMS extraction
     |              └─→ auth_done = 1
     |                   └─→ xrootd_session_register (dn, vo_list)
     |
     ├─→ TOKEN path:
     |    └─→ xrootd_handle_token_auth()
     |         └─→ validate JWT vs JWKS
     |              └─→ auth_done = 1
     |
     └─→ SSS path:
          └─→ xrootd_handle_sss_auth()
               └─→ verify shared secret
                    └─→ auth_done = 1
     |
     v (after auth_done=1)
Dispatch kXR_open (read-mode)
     |
xrootd_dispatch_read_opcode (dispatch_read.c)
     |
xrootd_handle_open (open_request.c:39)
     |
     ├─→ TPC detection: xrootd_tpc_parse_opaque()
     |    ├─→ is_write && tpc.src? → xrootd_tpc_prepare_pull()
     |    └─→ is_read && tpc.key? → xrootd_tpc_register_key()
     |
     └─→ Normal read-open:
          ├─→ strip CGI query (strip_cgi.c)
          ├─→ Auth gates:
          |    ├─→ Manager mode redirect check
          |    ├─→ Static map prefix check
          |    └─→ authdb ACL check (auth_gate.c)
          |
          ├─→ Path resolution (op_path.c):
          |    └─→ xrootd_beneath_full_path() [canonical path]
          |
          ├─→ Path confinement gate:
          |    └─→ xrootd_open_confined_canon()
          |         └─→ xrootd_openat2_confined() [RESOLVE_BENEATH]
          |
          └─→ xrootd_open_resolved_file (open_resolved_file.c)
               ├─→ POSC staging temp file (if O_CREAT)?
               ├─→ xrootd_alloc_fhandle() [slot 0-255]
               ├─→ xrootd_set_fhandle_path() [heap alloc]
               ├─→ File metadata: fstat() → inode/size/flags/mtime
               └─→ Return fhandle in kXR_ok body
                    └─→ xrootd_queue_response()
     |
     v (kXR_open succeeds)
Dispatch kXR_read/pgread/readv
     |
xrootd_dispatch_read_opcode (dispatch_read.c)
     |
xrootd_handle_read (read.c:78)
     |
     ├─→ xrootd_validate_read_handle() [idx validation]
     |
     ├─→ Parse offset (be64toh) + rlen (ntohl)
     |
     ├─→ Cap rlen at XROOTD_READ_REQUEST_MAX
     |
     ├─→ sendfile fast-path?
     |    ├─→ !c->ssl OR xrootd_ktls_send_active()?
     |    └─→ pread(fd, offset, rlen)
     |         └─→ xrootd_build_chunked_chain()
     |              └─→ xrootd_queue_response_chain()
     |
     └─→ fallback (TLS or irregular file):
          ├─→ [NGX_THREADS]: AIO pread via thread pool
          |    └─→ completion callback frees payload_buf
          |
          └─→ sync pread on main event loop
               └─→ xrootd_queue_response()
     |
     v (parallel: multiple read requests)
Recv loop defers non-pipelinable ops
     |
     [ctx->recv_deferred flag holds dispatch until output drained]
     |
     v
Dispatch kXR_write/pgwrite
     |
xrootd_dispatch_write_opcode (dispatch_write.c)
     |
xrootd_handle_write (write.c:68)
     |
     ├─→ xrootd_validate_write_handle() [idx validation]
     |
     ├─→ Parse offset (be64toh)
     |
     ├─→ [NGX_THREADS]: AIO pwrite via thread pool
     |    ├─→ xrootd_ensure_payload_buffer() [detach buffer]
     |    └─→ completion callback sends kXR_ok + frees buffer
     |
     └─→ fallback: sync pwrite on main event loop
          └─→ Track: wt_bytes_written, wt_dirty_offset [PFC]
               └─→ xrootd_queue_response() (kXR_ok)
     |
     v
Dispatch kXR_close
     |
xrootd_handle_close (close.c:40)
     |
     ├─→ xrootd_validate_file_handle() [idx validation]
     |
     ├─→ Log access entry:
     |    └─→ path = posc_final_path OR ctx->files[idx].path
     |         └─→ throughput = bytes_read/bytes_written ÷ duration
     |
     ├─→ POSC commit (if staging):
     |    ├─→ fsync(fd)
     |    └─→ rename(temp_path, final_path)
     |         └─→ on failure: return kXR_IOError
     |
     ├─→ Write-through flush (if enabled):
     |    └─→ xrootd_wt_flush_on_close()
     |         └─→ propagate dirty bytes to origin
     |
     ├─→ Write-recovery journal flush:
     |    └─→ xrootd_wrts_flush() [post-reconnect tracking]
     |
     └─→ xrootd_free_fhandle():
          ├─→ close(fd)
          ├─→ ngx_free(ctx->files[idx].path)
          ├─→ fd = -1 [sentinel clear]
          └─→ xrootd_queue_response() (kXR_ok empty body)
     |
     v (session cleanup)
Dispatch kXR_endsess
     |
xrootd_handle_endsess (session/lifecycle.c:97)
     |
     ├─→ xrootd_close_all_files() [release all fhandles]
     |
     └─→ xrootd_session_unregister()
          └─→ Free shared sessid slot
               └─→ xrootd_queue_response() (kXR_ok)
                    └─→ TCP connection closes
                         └─→ xrootd_on_disconnect()
                              ├─→ ngx_free(payload_buf)
                              └─→ xrootd_log_access() [final]
```

**Key**

PARTICIPANTS: Client = XRootD root:// user; recv loop = TCP state machine in recv.c; dispatch = central router in dispatch.c switching on opcode; handlers = protocol opcode implementations (login/open/read/write/close); fs/path layer = confinement gates via openat2(RESOLVE_BENEATH) in beneath.c and op_path.c; response queue = xrootd_queue_response() in response/ handling partial writes and EAGAIN retries.

KEY FILES: src/connection/handler.c (entry point), src/connection/recv.c (framing state machine), src/handshake/dispatch.c (opcode router), src/handshake/dispatch_session.c (login/auth), src/gsi/auth.c (GSI certificate verification), src/session/login.c (kXR_login), src/read/open_request.c (kXR_open), src/read/read.c (kXR_read), src/write/write.c (kXR_write), src/read/close.c (kXR_close), src/path/op_path.c (path resolution), src/path/beneath.c (openat2 RESOLVE_BENEATH confinement), src/connection/fd_table.c (file handle table).

CRITICAL INVARIANTS: (1) Path confinement: all client paths → xrootd_resolve_path() (canonical) THEN xrootd_open_confined_canon() (kernel RESOLVE_BENEATH gate). Escape attempts return EXDEV/ELOOP → kXR_NotAuthorized. (2) Auth ordering: login MUST precede auth; auth_done gates file operations. (3) Handle lifecycle: fd slot = -1 (free) | >= 0 (open); allocation bounded by XROOTD_MAX_FILES <= 256 (wire format one byte). (4) Response format: [streamid:2B][status:2B BE][dlen:4B BE][body:dlen bytes]. (5) POSC durability: write temp, fsync+rename on close before fd release. (6) Write-through PFC: wt_dirty_offset tracks unflushed origin bytes for cache-origin propagation. (7) TLS vs sendfile: !c->ssl OR xrootd_ktls_send_active() gates zero-copy; else memory-backed buffers. (8) Rate-limiting and signing: sigver()/kXR_sigver envelope wraps costly operations; fail-closed on verification failure.

**Jump-to anchors:** `src/connection/handler.c:ngx_stream_xrootd_handler` · `src/connection/recv.c:ngx_stream_xrootd_recv` · `src/handshake/dispatch.c:xrootd_dispatch` · `src/handshake/dispatch_session.c:xrootd_dispatch_session_opcode` · `src/read/open_request.c:xrootd_handle_open` · `src/path/beneath.c:xrootd_open_beneath`

## davs:// — WebDAV / HTTPS request lifecycle

```text

  Client HTTPS → nginx    Access Phase      Content Handler      Method Handler      Response
  ──────────────────────────────────────────────────────────────────────────────────────────────
                                                              
  1. TLS Handshake       
  ├─ TLS negotiation                                         
  └─ Peer cert presented
                        
  2. HTTP Request        
  ├─ HTTPS/1.1           
  ├─ Verb (GET, PUT, etc)
  └─ URI, headers         
                        
                        → ngx_http_xrootd_webdav_access_handler() (access.c:58)
                          ├─ Rate limit check
                          ├─ CORS headers added
                          │                              
                          ├─ Auth gate:                 
                          │  ├─ webdav_verify_proxy_cert() (auth_cert.c:418)
                          │  │  ├─ Check cached TLS auth (ex_data)
                          │  │  ├─ SSL_get_peer_certificate()
                          │  │  ├─ Try nginx-compatible verify
                          │  │  └─ Fallback: xrootd_gsi_verify_chain()
                          │  │     → [auth success: dn → req ctx]
                          │  │
                          │  └─ webdav_verify_bearer_token() (auth_token.c:77)
                          │     ├─ Extract "Authorization: Bearer"
                          │     ├─ xrootd_token_validate() [JWKS/macaroon]
                          │     └─ Store claims in req ctx
                          │                              
                          ├─ Write permission gate (allow_write check)
                          ├─ Token scope check (mutating methods only)
                          └─ Return NGX_OK → content handler proceeds
                        
                                                          
                                                          → ngx_http_xrootd_webdav_handler() (dispatch.c:24)
                                                            ├─ Conf check: xrootd_webdav enabled?
                                                            │
                                                            ├─ OPTIONS → webdav_handle_options()
                                                            │
                                                            ├─ Macaroon endpoints (.oauth2/token)
                                                            │
                                                            ├─ Proxy mode → webdav_proxy_handler()
                                                            │
                                                            ├─ GET → webdav_handle_get() (get.c:87)
                                                            │  ├─ Resolve path (confine)
                                                            │  ├─ Check locks (webdav_check_locks)
                                                            │  ├─ Stat file (vfs or fd-cache)
                                                            │  ├─ Parse Range header
                                                            │  ├─ Open/sendfile (with fd-cache)
                                                            │  └─ ngx_http_send_header() + body
                                                            │
                                                            ├─ PUT → xrootd_http_read_body()
                                                            │     → webdav_handle_put_body() (put.c:200+)
                                                            │  ├─ Resolve path + lock check
                                                            │  ├─ Create/open file
                                                            │  ├─ Write body (thread pool or sync)
                                                            │  └─ Respond 201 Created / 204 No Content
                                                            │
                                                            ├─ HEAD → webdav_handle_head()
                                                            │
                                                            ├─ DELETE → webdav_handle_delete()
                                                            │
                                                            ├─ MKCOL → webdav_handle_mkcol() (namespace.c:81)
                                                            │
                                                            ├─ COPY → Check headers for TPC signal
                                                            │  ├─ Source: header (TPC pull)
                                                            │  │  └─ ngx_http_xrootd_webdav_tpc_handle_copy() (tpc.c:405)
                                                            │  │     ├─ Extract auth (bearer or cert identity)
                                                            │  │     ├─ webdav_tpc_authorize() scope check
                                                            │  │     ├─ xrootd_tpc_cred_from_request() [delegation]
                                                            │  │     ├─ Launch in tpc_thread_pool:
                                                            │  │     │  └─ tpc_transfer_pull_curl_thread()
                                                            │  │     │     ├─ tpc_curl_secure() DNS pin + TLS verify
                                                            │  │     │     ├─ curl GET /Source → local fd
                                                            │  │     │     └─ Update registry + metrics
                                                            │  │     └─ Return 202 Accepted
                                                            │  │
                                                            │  ├─ Credential: header (TPC push)
                                                            │  │  └─ → tpc_handle_copy() [similar flow]
                                                            │  │
                                                            │  └─ Server-side copy (local)
                                                            │     └─ webdav_handle_copy() (copy.c:220)
                                                            │        ├─ Resolve src + dst paths (confine)
                                                            │        ├─ Check copy semantics
                                                            │        └─ Link / copy_file_range
                                                            │
                                                            ├─ MOVE → webdav_handle_move() (move.c:192)
                                                            │  ├─ Resolve + lock check
                                                            │  └─ Rename (within export root)
                                                            │
                                                            ├─ PROPFIND → xrootd_http_read_body()
                                                            │      → webdav_handle_propfind() (propfind.c:1037)
                                                            │  ├─ Parse body XML (allprop/propname/prop)
                                                            │  ├─ Recurse directory (depth hdr)
                                                            │  └─ Build XML response (memory-buffered)
                                                            │
                                                            ├─ LOCK → xrootd_http_read_body()
                                                            │    → webdav_handle_lock() (lock.c:344)
                                                            │  ├─ Parse body + record lock
                                                            │  └─ Respond lock token
                                                            │
                                                            ├─ UNLOCK → webdav_handle_unlock() (lock.c:454)
                                                            │
                                                            └─ Unrecognized → 405 Method Not Allowed
                                                            
  
  Path confinement (all methods):
  ├─ ngx_http_xrootd_webdav_resolve_path() (path.c:58)
  │  ├─ URL-decode URI
  │  ├─ xrootd_http_resolve_path() (shared compat layer)
  │  └─ Ensure under export root (403 if breakout detected)
  │
  
  Response building:
  ├─ GET sendfile: ngx_http_send_header() → file buffer → ngx_sendfile()
  │  └─ TLS-ciphertext: send via nginx filter chain
  │
  ├─ PUT/PROPFIND/LOCK: memory response buffer
  │  └─ webdav_metrics_return() wraps reply
  │
  └─ TPC: transfer in background (thread pool) → async notify
  

  Exit points (all wrap in webdav_metrics_return):
  ├─ Auth fail → 403 Forbidden / 401 Unauthorized
  ├─ Method handler → 200/201/204/207/404/409/etc (HTTP spec)
  └─ TPC → 202 Accepted + transfer_id in registry
```

**Key**


Participants:
- Client HTTPS: WebDAV client connecting over TLS (davix, curl, XRootD xrdcp).
- nginx: HTTP/1.1 reverse proxy with xrootd modules (base core + webdav_module).
- Access Phase: NGX_HTTP_ACCESS_PHASE handler (runs before content handlers) enforces auth, scope, and write policy.
- Content Handler: ngx_http_xrootd_webdav_handler() routes HTTP method to specialized handler.
- Method Handler: GET/PUT/PROPFIND/etc — performs method-specific work (file ops, metadata, TPC).
- Response: Final HTTP response + metrics logging.

Critical invariants:
1. Path confinement (xrootd_http_resolve_path): ALL file operations confined to export_root via symlink resolution.
2. TLS auth cache (auth_cert.c): GSI cert verification cached in SSL ex_data per connection; permits zero-copy cert auth on subsequent requests.
3. Bearer token validation: JWT (JWKS) or macaroon (secret-key); claims (sub, scopes) stored in req ctx.
4. TPC DNS pinning (tpc_curl.c:tpc_curl_secure): SSRF-validated target pinned to resolved IP; TLS verification still uses original hostname (no cert bypass).
5. Method handlers return NGX_DONE for async operations (PUT body read, PROPFIND body parse); webdav_metrics_return() wraps exit to increment per-method counters.

Key files:
- access.c: auth gate, write policy, token scope (Phase 20).
- dispatch.c: HTTP method routing (Phase 21).
- auth_cert.c: GSI/x509 proxy cert verify + TLS cache.
- auth_token.c: WLCG bearer token validation.
- tpc.c + tpc_curl.c: third-party-copy handler + curl integration.

**Jump-to anchors:** `access.c:ngx_http_xrootd_webdav_access_handler:58` · `dispatch.c:ngx_http_xrootd_webdav_handler:24` · `auth_cert.c:webdav_verify_proxy_cert:418` · `auth_token.c:webdav_verify_bearer_token:77` · `tpc.c:ngx_http_xrootd_webdav_tpc_handle_copy:405` · `path.c:ngx_http_xrootd_webdav_resolve_path:58`

## S3 REST request lifecycle

```text

S3 Client
   |
   | HTTP request (GET/PUT/DELETE/POST/HEAD)
   |
   v
+------ ngx_http_s3_handler (handler.c:286) ------+
|  Entry: Check cf->enable, alloc s3ctx, set    |
|  method_slot (list vs object), track bytes_rx |
+------------------------------------------------+
   |
   |  (if OPTIONS → handle CORS preflight → return 200)
   |
   | (if NOT POST form → verify SigV4 auth)
   |
   v
+------- s3_verify_sigv4 (auth_sigv4_verify.c:377) -------+
| Check: access_key match (constant-time via             |
| CRYPTO_memcmp at line 613)                             |
| Parse: Authorization header → AKID, date, region,      |
|        signed_hdrs, signature                          |
| Build canonical request:                               |
|   - URI: xrootd_http_urlencode(r->uri)                 |
|   - QS:  build_canonical_qs() (canonical.c:74)         |
|   - Headers: build_canonical_headers() (auth_sigv4_verify.c:297)  |
|   - Hash: xrootd_sha256(canonical)                     |
| Derive signing key (cached):                           |
|   - s3_sigv4_derive_signing_key_cached()               |
|     (auth_sigv4_verify.c:265) → 4-round HMAC chain                |
| Compare: CRYPTO_memcmp(computed sig, client sig)       |
| (Fail-closed: no timing oracle on access-key)          |
+-----------------------------------------------------+
   |
   | Auth pass? → NGX_OK
   | Auth fail? → XML error (SignatureDoesNotMatch)
   |
   v
+-------- s3_parse_uri (handler.c:66) --------+
| Extract: bucket, key from path-style URI  |
| URL-decode: key via xrootd_http_urldecode |
| Return: 1=success, 0=malformed, -1=bucket |
| mismatch → NoSuchBucket 404                |
+------------------------------------------+
   |
   | Parsed key?
   |
   v
+---------- Dispatch by operation type ----------+
| Check flags: list-type=2? → ListObjectsV2    |
| Check flags: uploads? → ListMultipartUploads |
| Empty key → error or special (delete, POST)  |
| Non-empty key → resolve & dispatch by method |
+----------------------------------------------+
   |
   +---> If ListObjectsV2:
   |       s3_handle_list (list_objects_v2.c:44)
   |       Scan dir, build XML listing
   |
   +---> If GET with uploadId:
   |       s3_handle_list_parts (multipart_complete_list_parts.c:58)
   |
   +---> If GET (normal object):
   |       |
   |       v
   |    +------ s3_resolve_key (util.c:50) ------+
   |    | Confine key to root_canon via        |
   |    | xrootd_http_resolve_path()           |
   |    | Returns: 1=confined, 0=escape/error  |
   |    | Fail → AccessDenied 403              |
   |    +----------------------------------------+
   |       |
   |       v
   |    s3_handle_get (object.c:64)
   |    - VFS open (read, cache-aware)
   |    - File stat (reject directories)
   |    - Range parse (RFC 7233)
   |    - Delegate to xrootd_http_serve_file_ranged()
   |    - Send via sendfile (if no TLS) or TLS buffer
   |    - Track bytes_tx, range_total
   |
   +---> If HEAD:
   |       s3_handle_head (object.c:165)
   |       - Open, stat, send headers only
   |
   +---> If PUT:
   |       |
   |       +---> If UploadPart (uploadId + partNumber):
   |       |       s3_handle_upload_part_copy or body read
   |       |
   |       +---> If CopyObject (x-amz-copy-source header):
   |       |       s3_handle_copy_object (copy.c:52)
   |       |
   |       +---> Else (PutObject):
   |               Read body asynchronously
   |               s3_put_body_handler (put.c:295)
   |               - Confine via xrootd_open_confined_canon()
   |               - Write to temp file (O_EXCL)
   |               - Atomic rename via xrootd_staged_commit()
   |
   +---> If DELETE:
   |       |
   |       +---> If uploadId: multipart_abort
   |       |
   |       +---> Else: s3_handle_delete (object.c:211)
   |
   +---> If POST:
           |
           +---> If ?uploads: s3_handle_multipart_initiate
           |
           +---> If ?uploadId: read body →
                  s3_multipart_complete_body_handler
           |
           +---> If form (multipart/form-data): 
                  s3_post_object_body_handler
   |
   v
Response sent (XML error or object data or headers)
   |
   v
Close connection
```

**Key**


Participants and Files:

1. S3 Client — S3-compatible HTTP client (e.g. XrdClS3, AWS SDK, boto3)

2. handler.c:286 (ngx_http_s3_handler) — Main HTTP content handler; dispatches all S3 requests. Entry point called by nginx after routing to the S3 location. Allocates request context, checks enable flag, tracks metrics, verifies SigV4, parses URI, and routes to operation handlers by HTTP method and query flags.

3. auth_sigv4_verify.c:377 (s3_verify_sigv4) — SigV4 signature verification gate. Parses Authorization header, builds canonical request, derives signing key via cached 4-round HMAC chain, and performs constant-time CRYPTO_memcmp of computed vs. client signature. Rejects both unknown access keys and bad signatures with identical "SignatureDoesNotMatch" message (no timing oracle; see line 434-452 for W5 deferred key check).

4. auth_sigv4_canonical.c:74 (build_canonical_qs) — Parses and canonicalizes query string for SigV4. Sorts parameters alphabetically by name then value, percent-encodes, and skips X-Amz-Signature from the canonical form.

5. auth_sigv4_verify.c:265 (s3_sigv4_derive_signing_key_cached) — Derives the SigV4 signing key via four-round HMAC chain: k1=HMAC("AWS4"+secret, date), k2=HMAC(k1, region), k3=HMAC(k2, "s3"), k4=HMAC(k3, "aws4_request"). Worker-local cache prevents re-deriving the same key multiple times per calendar day.

6. util.c:50 (s3_resolve_key) — Confines S3 object keys to the filesystem root via xrootd_http_resolve_path(). Rejects any path that would escape root_canon (e.g. "/../../../etc/passwd" after canonicalization). Critical security gate before any file operation.

7. object.c:64 (s3_handle_get) — GetObject handler. Opens file via VFS (cache-aware), stats, parses HTTP Range headers, and delegates to xrootd_http_serve_file_ranged() which sends via sendfile (or TLS buffer if encrypted). Tracks bytes_tx and range hit/miss metrics.

8. object.c:165 (s3_handle_head) — HeadObject handler. Opens file, stats, sends headers only (no body). Immediately closes file handle.

9. put.c:295 (s3_put_body_handler) — Async callback after client PUT body is fully read by nginx. Writes temp file via O_EXCL (prevents concurrent corruption), then atomic rename via xrootd_staged_commit(). Confined writes only via xrootd_open_confined_canon().

10. object.c:211 (s3_handle_delete) — DeleteObject handler. Unlink (delete) the object file.

11. copy.c:52 (s3_handle_copy_object) — CopyObject handler. Reads source object (via VFS), writes to destination (via staged temp+rename), all confined.

Critical Invariants:
- Path confinement: every filesystem operation uses fs_path vetted by s3_resolve_key() (util.c:50), which delegates to xrootd_http_resolve_path() for canonicalization and escape detection.
- Constant-time auth: access-key mismatch and signature mismatch both run full HMAC before returning error (auth_sigv4_verify.c:434-452, 613); no timing oracle.
- Atomic writes: PutObject/UploadPart use temp file + rename (O_EXCL prevents concurrent corruption).
- Cache-aware GET: xrootd_vfs_open() honors cache configuration; sendfile used for non-TLS, buffered for TLS.
- SigV4 signing key cache: per-worker, per-calendar-day; avoids four HMAC rounds per request (auth_sigv4_verify.c:258-287).

**Jump-to anchors:** `handler.c:286 ngx_http_s3_handler()` · `auth_sigv4_verify.c:377 s3_verify_sigv4()` · `util.c:50 s3_resolve_key()` · `object.c:64 s3_handle_get()` · `put.c:295 s3_put_body_handler()` · `auth_sigv4_canonical.c:74 build_canonical_qs()`

## CMS cluster registration and redirect lifecycle

```text

FLOW A: DATA-NODE CMSD PEER REGISTRATION WITH NGINX MANAGER
===========================================================

 DATA-NODE               NGINX-XROOTD MANAGER         REGISTRY (SHM)
  CMSD                                                 TABLE
     |                        |                           |
     |--- TCP accept -------->| xrootd_cms_srv_handler()  |
     |                        | (server_handler.c:21)     |
     |                        | [W1b CIDR allowlist]      |
     |                        |                           |
     |                        | xrootd_cms_srv_check_peer |
     |                        | (server_auth.c:31)        |
     |            [ACCEPT or REJECT based on IP]         |
     |                        |                           |
     |--- [sss? CHALLENGE]--->| [if sss keytab configured]|
     |    kYR_xauth parms     | xrootd_cms_srv_read()     |
     | (server_recv.c:440)    | cms_srv_process_frame()   |
     |                        | (server_recv.c:316)       |
     |                        | case CMS_RR_LOGIN         |
     |                        |                           |
     |<-- [sss? CHALLENGE]----| xrootd_cms_srv_send_xauth |
     |    kYR_xauth parms     | (server_send.c:39)        |
     |                        |                           |
     |--- [sss CREDENTIAL]--->| kYR_xauth blob received   |
     |    kYR_xauth blob      | xrootd_cms_srv_verify_xauth
     |                        | (server_auth.c:62)        |
     |                        | [VERIFY SSS: pass/fail]   |
     |                        |                           |
     |                        | cms_srv_complete_login()  |
     |                        | (server_recv.c:298)       |
     |                        |                           |
     |                        | xrootd_srv_register()     |
     |                        | (registry.c:198)          |
     |                        | [W1c HOST-CHAR VALIDATION]|
     |                        |-->| Write entry: host,port |
     |                        |   | paths, free_mb, util_pct|
     |                        |   | last_seen, in_use=1     |
     |                        |                           |
     |<-- [PING timer armed]--| ngx_add_timer(&ping_timer)|
     |    every interval_ms   |                           |
     |                        |                           |

FLOW B: CLIENT LOCATE/OPEN REDIRECT TO REGISTERED DATA-NODE
===========================================================

  CLIENT                 NGINX-XROOTD MANAGER        REGISTRY (SHM)
 XROOTD                  (Redirector)                TABLE
     |                        |                        |
     |--- kXR_locate path --->| xrootd_handle_locate()  |
     |    (locate.c:43)       |                        |
     |                        | [CACHE FAST-PATH]      |
     |                        | xrootd_redir_cache_    |
     |                        | lookup(path)           |
     |                        | [HIT: send redirect]   |
     |                        |                        |
     |                        | [CACHE MISS: query]    |
     |                        | xrootd_srv_select()    |
     |                        | (registry.c:385)       |
     |                        |-->| LOCK mutex          |
     |                        |   | Scan slots:in_use   |
     |                        |   | not blacklisted     |
     |                        |   | path_matches()      |
     |                        |   | Pick best by:       |
     |                        |   | (write):free_mb MAX |
     |                        |   | (read): util_pct MIN|
     |                        |   | UNLOCK mutex        |
     |                        |-->| Return host, port   |
     |                        |                        |
     |<-- kXR_redirect -------| xrootd_send_redirect() |
     |    port+hostname       | (control.c:72)         |
     |    Sr/Sw host:port     | [ENCODE: port(BE)+host]|
     |                        |                        |
     |--- TCP to host:port -->| [Client connects to   |
     |    OPEN/READ           | selected data-node]   |
     |                        |                        |

INVARIANT CHECKLIST
===================
[W1a] SSS-Auth Gate: kYR_xauth credential verified BEFORE registry entry
[W1b] CIDR Allowlist: IP checked at accept, BEFORE frame dispatch
[W1c] Host Validation: xrootd_net_host_chars_valid() at xrootd_srv_register()
      prevents control-byte/scheme injection into Sr/Sw redirect string
[Path-Confine] xrootd_extract_path() confines client request paths
[Redirect-Integrity] Host string pinned from registry.c, never re-resolved
[Load-Balance] Reads=min(util_pct), Writes=max(free_mb) from live entries
[Blacklist] Expired entries filtered by blacklisted_until > ngx_current_msec
```

**Key**


Flow A (Registration): A data node establishes a persistent TCP connection to
the nginx-xrootd CMS server port (default 1213). The handler accepts it
(server_handler.c line 21), checks CIDR allowlist (server_auth.c line 31),
optionally challenges the node with SSS authentication (server_send.c line 39,
server_auth.c line 62), then parses the kYR_login frame (server_recv.c line 440)
and calls xrootd_srv_register() (registry.c line 198) to store the node's
host/port/paths/load into shared-memory registry, protected by spinlock.
Periodic heartbeat updates (LOAD/AVAIL frames) refresh load metrics via
xrootd_srv_update_load().

Flow B (Redirect): A client requests kXR_locate for a path
(locate.c line 43). The manager first consults collapse-redir cache, then
xrootd_srv_select() (registry.c line 385) which locks the registry, scans all
in-use, non-blacklisted entries matching the path's longest-prefix, and picks
the best by load policy (reads: lowest util_pct; writes: highest free_mb).
The selected host and port are returned, formatted as Sr/Sw redirect payload
("Sr<host>:<port>"), and sent to the client via xrootd_send_redirect()
(control.c line 72). The client connects directly to that data node.

Critical invariants: W1a (SSS auth gates entry), W1b (CIDR gate at accept),
W1c (host-char validation prevents injection into redirect), path-confinement
(extract_path enforces), and redirect-integrity (host pinned from registry,
never re-resolved).

Key file ownership: server_handler.c (accept), server_auth.c (auth),
server_recv.c (frame parse), registry.c (store/select), control.c (redirect).

**Jump-to anchors:** `server_handler.c:xrootd_cms_srv_handler (line 21)` · `server_auth.c:xrootd_cms_srv_check_peer (line 31)` · `server_recv.c:xrootd_cms_srv_read (line 440)` · `registry.c:xrootd_srv_register (line 198)` · `registry.c:xrootd_srv_select (line 385)` · `control.c:xrootd_send_redirect (line 72)`

## See also

- [`../../src/README.md`](../../src/README.md) — master source map + per-subsystem READMEs
- [`logical-pathways.md`](logical-pathways.md) — narrative cross-protocol pathway reference
- [`tier1-stream-data-paths.md`](tier1-stream-data-paths.md) / [`tier2-stream-data-paths.md`](tier2-stream-data-paths.md) — stream data-plane deep dives
- [`cross-protocol-unification.md`](cross-protocol-unification.md) — how root/davs/S3 share path, auth, metrics, file-serve
