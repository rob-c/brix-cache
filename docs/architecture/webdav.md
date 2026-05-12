# WebDAV request lifecycle

[← Architecture overview](index.md)

## WebDAV request lifecycle

WebDAV requests use nginx's HTTP layer (`ngx_http_request_t`) rather than the
stream layer used by native XRootD. This means they follow nginx HTTP semantics:
request headers are parsed by nginx, TLS is handled by the HTTP SSL module, and
response bodies are sent via nginx HTTP response machinery.

```
HTTP client (xrdcp --allow-http, curl, FTS, Rucio)
    │  HTTPS (davs://) or HTTP request
    │  GET /path | PUT /path | COPY ... | PROPFIND ...
    ▼
nginx HTTP SSL (if HTTPS)
    │  decrypts TLS, hands off to HTTP handler
    ▼
ngx_http_xrootd_webdav_handler()        src/webdav/dispatch.c
    │
    │  1. CORS preflight check
    │      if OPTIONS + Origin + Access-Control-Request-Method:
    │          webdav_handle_options()  → 200 OK with CORS headers
    │
    │  2. Authentication gate
    │      webdav_verify_proxy_cert()   src/webdav/auth_cert.c
    │      webdav_verify_bearer_token() src/webdav/auth_token.c
    │      if auth=required and both fail → 403
    │      if auth=optional and both fail → anonymous
    │
    │  3. Method routing
    │      GET     → webdav_handle_get()      src/webdav/get.c
    │      HEAD    → webdav_handle_head()     src/webdav/methods_basic.c
    │      PUT     → read body → webdav_handle_put_body()  src/webdav/put.c
    │      DELETE  → webdav_handle_delete()   src/webdav/namespace.c
    │      MKCOL   → webdav_handle_mkcol()    src/webdav/namespace.c
    │      PROPFIND → webdav_handle_propfind() src/webdav/propfind.c
    │      COPY    → (see TPC disambiguation below)
    │      MOVE    → webdav_handle_move()     src/webdav/move.c
    │      LOCK    → read body → webdav_handle_lock()  src/webdav/lock.c
    │      UNLOCK  → webdav_handle_unlock()   src/webdav/lock.c
    ▼
  handler performs filesystem operation
    │
    ▼
  webdav_metrics_return(r, status)
    │  records HTTP status in Prometheus counters
    ▼
  nginx sends HTTP response
```

### TPC disambiguation in COPY

The `COPY` method routes to three different handlers depending on which
headers are present:

```
COPY request arrives
    │
    ├── Source: header present?
    │       yes → TPC pull (src/webdav/tpc.c)
    │
    ├── Destination: header + Credential: header present?
    │       yes → TPC push (src/webdav/tpc.c)
    │
    └── Destination: header, no Credential:
            → server-side copy RFC 4918 §9.8 (src/webdav/copy.c)
```

### WebDAV GET path in detail

GET is the most optimized WebDAV path because it is on the hot data read path:

```
webdav_handle_get()                     src/webdav/get.c
    │
    ├── webdav_fd_table_get()           src/webdav/fd_cache.c
    │       look up cached fd for this path on this connection
    │       if found: skip open+stat
    │
    ├── if not cached:
    │       ngx_http_xrootd_webdav_resolve_path()  src/webdav/path.c
    │       open(path, O_RDONLY)
    │       fstat() for size and mtime
    │       cache fd in fd_table
    │
    ├── Handle Range: header
    │       parse byte-range(s), set response offset and length
    │
    ├── Build response headers
    │       Content-Type, Content-Length, ETag, Last-Modified
    │       Accept-Ranges: bytes
    │
    └── Build response body
            cleartext regular file: file-backed ngx_buf_t
                → nginx sendfile path possible
            large or TLS: memory-backed ngx_buf_t chain
```

### WebDAV PUT path in detail

```
webdav_handle_put_body()               src/webdav/put.c
    │  (called from body callback — nginx has spooled the body)
    │
    ├── webdav_check_locks()           src/webdav/lock.c
    │       reject if path is locked by another token (423)
    │
    ├── Detect nginx-spooled body:
    │       r->request_body->temp_file != NULL?
    │           → copy_file_range(2) from temp file to dest
    │               avoids double-buffering in memory
    │       r->request_body->bufs != NULL?
    │           → write from memory buffers
    │
    ├── Write to temp file: <dst>.nginx-xrootd-put.<pid>.<time>
    │
    ├── atomic rename temp → dst
    │
    └── webdav_fd_table_evict(fdt, dst_path)
            invalidate any cached fd for the overwritten path
```

---
