[← WebDAV overview](index.md)

## Directives

All `xrootd_webdav_*` directives go inside an `http` server or location block.

### `xrootd_webdav on|off`

**Context:** `location`

Activates the WebDAV content handler for this location.

---

### `xrootd_webdav_root <path>`

**Context:** `location` · **Default:** `/`

Filesystem directory that clients see as `/`. Path traversal and symlink-escape attempts are blocked.

---

### `xrootd_webdav_auth none|optional|required`

**Context:** `location` · **Default:** `optional`

- `none` — serve all requests without checking client certificates or bearer tokens
- `optional` — check a proxy certificate or bearer token if one is presented; unauthenticated requests are still served
- `required` — reject requests that do not present a valid proxy certificate or bearer token (returns 403)

With `optional`, an invalid bearer token is declined and the request may still proceed anonymously. Use `required` when token or proxy authentication must be mandatory.

---

### `xrootd_webdav_cadir <path>`

**Context:** `location`

Directory containing hashed CA certificates (the standard Grid format: `<hash>.0` files). Used for per-request proxy-certificate chain verification when `xrootd_webdav_auth` is `optional` or `required`.

See [pki.md](pki.md) for CA bundle layout, hash symlink conventions, and proxy certificate chain structure.

---

### `xrootd_webdav_cafile <path>`

**Context:** `location`

Alternative to `xrootd_webdav_cadir`: a single PEM file containing one or more CA certificates.

---

### `xrootd_webdav_crl <path>`

**Context:** `location`

PEM CRL file used when verifying proxy-certificate chains. When configured, OpenSSL CRL checks are enabled for the full chain.

---

### `xrootd_webdav_allow_write on|off`

**Context:** `location` · **Default:** `off`

Enables PUT, DELETE, MKCOL, and HTTP-TPC COPY when `xrootd_webdav_tpc on` is also configured. Off by default so read-only deployments are safe without extra configuration. When the request is accepted via a bearer token, `PUT` and TPC `COPY` also require a matching `storage.write` or `storage.create` scope for the request path.

---

### `xrootd_webdav_tpc on|off`

**Context:** `location` · **Default:** `off`

Enables HTTP third-party copy pull requests using WebDAV `COPY` with a remote `Source` header. The destination is the request URI on this server.

This is an explicit opt-in because the nginx worker starts an external `curl` helper and the server makes an outbound HTTPS request to the `Source` URL. Only `https://` sources are accepted. The request waits for `curl` to finish, so set `xrootd_webdav_tpc_timeout` and size nginx workers accordingly for production transfers.

---

### `xrootd_webdav_tpc_curl <path>`

**Context:** `location` · **Default:** `/usr/bin/curl`

Path to the `curl` executable used for HTTP-TPC pulls. The helper is run without a shell.

---

### `xrootd_webdav_tpc_cert <path>`

**Context:** `location`

PEM certificate or proxy certificate used by the server when it pulls from the remote HTTPS source. For proxy PEM files that contain both certificate and private key, set only this directive or set `xrootd_webdav_tpc_key` to the same path.

---

### `xrootd_webdav_tpc_key <path>`

**Context:** `location` · **Default:** `xrootd_webdav_tpc_cert`

PEM private key used with `xrootd_webdav_tpc_cert`.

---

### `xrootd_webdav_tpc_cadir <path>`

**Context:** `location` · **Default:** `xrootd_webdav_cadir`

CA directory passed to `curl --capath` when verifying the source HTTPS endpoint.

---

### `xrootd_webdav_tpc_cafile <path>`

**Context:** `location` · **Default:** `xrootd_webdav_cafile`

CA bundle passed to `curl --cacert` when verifying the source HTTPS endpoint.

---

### `xrootd_webdav_tpc_timeout <seconds>`

**Context:** `location` · **Default:** `0` (curl default)

Maximum wall-clock time passed to `curl --max-time` for a single HTTP-TPC pull.

---

### `xrootd_webdav_proxy_certs on|off`

**Context:** `server` or `location` (HTTP) · **Default:** `off`

Sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on the `SSL_CTX` for this server in postconfiguration. Without this, nginx's TLS layer rejects RFC 3820 proxy certificates with error 40 (`proxy certificates not allowed`) even when `ssl_verify_client optional_no_ca` is set.

In normal TLS deployments, put this in the `server {}` block so the SSL context is patched for the whole virtual server.

---

### `xrootd_webdav_verify_depth <n>`

**Context:** `location` · **Default:** `10`

Maximum depth for proxy-certificate chain verification.

---

### `xrootd_webdav_token_jwks <path>`

**Context:** `location`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation.

---

### `xrootd_webdav_token_issuer <string>`

**Context:** `location`

Expected JWT `iss` claim.

---

### `xrootd_webdav_token_audience <string>`

**Context:** `location`

Expected JWT `aud` claim.

---

### `xrootd_webdav_thread_pool <name>`

**Context:** `location` · **Default:** `default`

Names the nginx thread pool used for async WebDAV file I/O, primarily the
in-memory `PUT` fast path. If the named pool does not exist, the module logs a
notice and falls back to synchronous I/O.

```nginx
thread_pool webdav_io threads=8 max_queue=65536;

server {
    listen 8443 ssl;

    location / {
        xrootd_webdav on;
        xrootd_webdav_root /data;
        xrootd_webdav_thread_pool webdav_io;
    }
}
```

---

### `xrootd_webdav_cors_origin <origin|*>`

**Context:** `location` · **Default:** unset

Adds CORS response headers for browser-based WebDAV clients. The directive may
be repeated for multiple exact origins. Use `*` to allow any origin. CORS is
disabled unless at least one origin is configured. `OPTIONS` preflight requests
are answered before WebDAV authentication so browsers can complete the CORS
handshake.

```nginx
location / {
    xrootd_webdav on;
    xrootd_webdav_root /data;

    xrootd_webdav_cors_origin https://monitoring.example.com;
    xrootd_webdav_cors_origin https://debug.example.org;
}
```

---

### `xrootd_webdav_cors_credentials on|off`

**Context:** `location` · **Default:** `off`

Adds `Access-Control-Allow-Credentials: true` to allowed CORS responses. When
this is enabled with `xrootd_webdav_cors_origin *`, the module echoes the
request's `Origin` value instead of returning `*`, which keeps the response
valid for credentialed browser requests.

---

### `xrootd_webdav_cors_max_age <seconds>`

**Context:** `location` · **Default:** `86400`

Value used for `Access-Control-Max-Age` on allowed CORS preflight responses.

---

### `xrootd_webdav_lock_timeout <seconds>`

**Context:** `location` · **Default:** `600`

Maximum duration for a WebDAV lock. When a client requests a lock with a `Timeout:` header, the server bounds the timeout to this value. Stale locks are automatically expired from the in-memory lock table after this duration.

The implementation uses a shared-memory lock table protected by spinlocks, ensuring that locks are visible across all nginx worker processes.
- **Exclusive Write Locks**: Only exclusive write locks are currently supported.
- **Depth Support**: Supports both `Depth: 0` (shallow) and `Depth: infinity` (recursive) lock scope.
- **Custom Owner**: Parses the LOCK request body to extract custom `<D:owner>` metadata (including `<D:href>`), ensuring compatibility with desktop clients that identify users via XML.
- **Recursive Enforcement**: Destructive operations on collections (DELETE, MOVE, COPY with Overwrite) perform a recursive lock check and will fail if any child resource is locked.
- **Timeout**: Default timeout is 600 seconds, configurable via `xrootd_webdav_lock_timeout`.

---
