[← WebDAV overview](webdav-intro.md)

## WebDAV directives

Every `brix_webdav_*` directive — context, type, default, and what it controls.

All `brix_webdav_*` directives go inside an `http` server or location block.

The directives cluster into five families. Most deployments only need the first:

```text
  brix_webdav_*
  ├─ CORE ........ on · export · allow_write · thread_pool
  │                  └─ activate the handler, set the export, gate writes
  ├─ AUTH ........ auth(none|optional|required)
  │                ├─ cert:  cadir · cafile · crl · proxy_certs · verify_depth
  │                └─ token: token_jwks · token_issuer · token_audience
  ├─ TPC ......... tpc · tpc_curl · tpc_timeout
  │                ├─ creds: tpc_cert · tpc_key · tpc_cadir · tpc_cafile
  │                └─ oauth: tpc_token_endpoint · _client_id · _secret · _scope
  ├─ CORS ........ cors_origin · cors_credentials · cors_max_age
  │                  └─ browser clients only
  └─ LOCKS ....... lock_timeout · lock_startup_sweep
                     └─ RFC 4918 WebDAV locking (xattr-backed)
```



### `brix_webdav on|off`

**Context:** `location`

Activates the WebDAV content handler for this location.

---

### `brix_export <path>`

**Context:** `location` · **Default:** `/`

Filesystem directory that clients see as `/`. Path traversal and symlink-escape attempts are blocked.

---

### `brix_webdav_auth none|optional|required`

**Context:** `location` · **Default:** `optional`

- `none` — serve all requests without checking client certificates or bearer tokens
- `optional` — check a proxy certificate or bearer token if one is presented; unauthenticated requests are still served
- `required` — reject requests that do not present a valid proxy certificate or bearer token (returns 403)

With `optional`, an invalid bearer token is declined and the request may still proceed anonymously. Use `required` when token or proxy authentication must be mandatory.

---

### `brix_webdav_cadir <path>`

**Context:** `location`

Directory containing hashed CA certificates (the standard Grid format: `<hash>.0` files). Used for per-request proxy-certificate chain verification when `brix_webdav_auth` is `optional` or `required`.

See [pki.md](../06-authentication/pki-config.md) for CA bundle layout, hash symlink conventions, and proxy certificate chain structure.

---

### `brix_webdav_cafile <path>`

**Context:** `location`

Alternative to `brix_webdav_cadir`: a single PEM file containing one or more CA certificates.

---

### `brix_webdav_crl <path>`

**Context:** `location`

PEM CRL file used when verifying proxy-certificate chains. When configured, OpenSSL CRL checks are enabled for the full chain.

---

### `brix_allow_write on|off`

**Context:** `location` · **Default:** `off`

Enables PUT, DELETE, MKCOL, and HTTP-TPC COPY when `brix_webdav_tpc on` is also configured. Off by default so read-only deployments are safe without extra configuration. When the request is accepted via a bearer token, `PUT` and TPC `COPY` also require a matching `storage.write` or `storage.create` scope for the request path.

---

### `brix_webdav_tpc on|off`

**Context:** `location` · **Default:** `off`

Enables HTTP third-party copy pull requests using WebDAV `COPY` with a remote `Source` header. The destination is the request URI on this server.

This is an explicit opt-in because the nginx worker starts an external `curl` helper and the server makes an outbound HTTPS request to the `Source` URL. Only `https://` sources are accepted. The request waits for `curl` to finish, so set `brix_webdav_tpc_timeout` and size nginx workers accordingly for production transfers.

---

### `brix_webdav_tpc_curl <path>`

**Context:** `location` · **Default:** `/usr/bin/curl`

Path to the `curl` executable used for HTTP-TPC pulls. The helper is run without a shell.

---

### `brix_webdav_tpc_cert <path>`

**Context:** `location`

PEM certificate or proxy certificate used by the server when it pulls from the remote HTTPS source. For proxy PEM files that contain both certificate and private key, set only this directive or set `brix_webdav_tpc_key` to the same path.

---

### `brix_webdav_tpc_key <path>`

**Context:** `location` · **Default:** `brix_webdav_tpc_cert`

PEM private key used with `brix_webdav_tpc_cert`.

---

### `brix_webdav_tpc_cadir <path>`

**Context:** `location` · **Default:** `brix_webdav_cadir`

CA directory passed to `curl --capath` when verifying the source HTTPS endpoint.

---

### `brix_webdav_tpc_cafile <path>`

**Context:** `location` · **Default:** `brix_webdav_cafile`

CA bundle passed to `curl --cacert` when verifying the source HTTPS endpoint.

---

### `brix_webdav_tpc_timeout <seconds>`

**Context:** `location` · **Default:** `0` (curl default)

Maximum wall-clock time passed to `curl --max-time` for a single HTTP-TPC pull.

---

### `brix_webdav_tpc_token_endpoint <url>`

**Context:** `location`

HTTPS endpoint URL for OAuth2/OIDC token exchange. When configured with `brix_webdav_tpc_token_client_id` and `brix_webdav_tpc_token_client_secret`, the module obtains access tokens for remote TPC operations (pull/push) by POST-ing to this endpoint. Tokens are obtained at TPC request time and must be managed securely.

---

### `brix_webdav_tpc_token_client_id <string>`

**Context:** `location`

OAuth2 client ID used when requesting access tokens from `brix_webdav_tpc_token_endpoint`.

---

### `brix_webdav_tpc_token_client_secret <string>`

**Context:** `location`

OAuth2 client secret used for authenticating the token request. Must be kept secure and never exposed in logs or error messages.

---

### `brix_webdav_tpc_token_scope <string>`

**Context:** `location`

OAuth2 scope to request in the token grant. Common values: `storage.read`, `storage.write`, or space-separated combinations per the identity provider's policy.

---

### `brix_webdav_proxy_certs on|off`

**Context:** `server` or `location` (HTTP) · **Default:** `off`

Sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on the `SSL_CTX` for this server in postconfiguration. Without this, nginx's TLS layer rejects RFC 3820 proxy certificates with error 40 (`proxy certificates not allowed`) even when `ssl_verify_client optional_no_ca` is set.

In normal TLS deployments, put this in the `server {}` block so the SSL context is patched for the whole virtual server.

---

### `brix_webdav_verify_depth <n>`

**Context:** `location` · **Default:** `10`

Maximum depth for proxy-certificate chain verification.

---

### `brix_webdav_token_jwks <path>`

**Context:** `location`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation.

---

### `brix_webdav_token_issuer <string>`

**Context:** `location`

Expected JWT `iss` claim.

---

### `brix_webdav_token_audience <string>`

**Context:** `location`

Expected JWT `aud` claim.

---

### `brix_thread_pool <name>`

**Context:** `location` · **Default:** `default`

Names the nginx thread pool used for async WebDAV file I/O, primarily the
in-memory `PUT` fast path. If the named pool does not exist, the module logs a
notice and falls back to synchronous I/O.

```nginx
thread_pool webdav_io threads=8 max_queue=65536;

server {
    listen 8443 ssl;

    location / {
        brix_webdav on;
        brix_export /data;
        brix_thread_pool webdav_io;
    }
}
```

---

### `brix_webdav_cors_origin <origin|*>`

**Context:** `location` · **Default:** unset

Adds CORS response headers for browser-based WebDAV clients. The directive may
be repeated for multiple exact origins. Use `*` to allow any origin. CORS is
disabled unless at least one origin is configured. `OPTIONS` preflight requests
are answered before WebDAV authentication so browsers can complete the CORS
handshake.

```nginx
location / {
    brix_webdav on;
    brix_export /data;

    brix_webdav_cors_origin https://monitoring.example.com;
    brix_webdav_cors_origin https://debug.example.org;
}
```

---

### `brix_webdav_cors_credentials on|off`

**Context:** `location` · **Default:** `off`

Adds `Access-Control-Allow-Credentials: true` to allowed CORS responses. When
this is enabled with `brix_webdav_cors_origin *`, the module echoes the
request's `Origin` value instead of returning `*`, which keeps the response
valid for credentialed browser requests.

---

### `brix_webdav_cors_max_age <seconds>`

**Context:** `location` · **Default:** `86400`

Value used for `Access-Control-Max-Age` on allowed CORS preflight responses.

---

### `brix_webdav_lock_timeout <seconds>`

**Context:** `location` · **Default:** `600`

Maximum duration for a WebDAV lock. When a client requests a lock with a `Timeout:` header, the server bounds the timeout to this value. Expired locks are cleaned up lazily — on the next access to the locked path.

Lock state is stored as a single extended attribute (`user.nginx_xrootd.lock`) on the locked resource itself, in the same storage layer as dead properties. There is no shared-memory table or mutex: atomic creation is provided by the kernel's `XATTR_CREATE` semantics, and a lock check walks from the target path up to the export root (`O(path_depth)` xattr reads).

```text
  DELETE /data/proj/run42/out.root  — is anything in the path locked?
  ──────────────────────────────────────────────────────────────────
   /data/proj/run42/out.root   getxattr(user.nginx_xrootd.lock) ─┐
   /data/proj/run42            getxattr ───────────────────────┐ │ a Depth:0
   /data/proj                  getxattr ─────────────────────┐ │ │ lock here,
   /data            (export root, stop) ─────────────────────┘ │ │ or a
                                                                │ │ Depth:∞
   walk UP the tree, O(path_depth) xattr reads ─────────────────┘ │ lock on
   any locked ancestor (Depth:∞) or the target itself ────────────┘ a parent
        │                                                            blocks it
        ▼
   locked → 423 Locked      free → proceed
   atomic claim = setxattr(..., XATTR_CREATE)  ← kernel rejects a double-create
```

- **Exclusive Write Locks**: Only exclusive write locks are currently supported.
- **Depth Support**: Supports both `Depth: 0` (shallow) and `Depth: infinity` (recursive) lock scope.
- **Custom Owner**: Parses the LOCK request body to extract custom `<D:owner>` metadata (including `<D:href>`), ensuring compatibility with desktop clients that identify users via XML.
- **Recursive Enforcement**: Destructive operations on collections (DELETE, MOVE, COPY with Overwrite) perform a recursive lock check and will fail if any child resource is locked.
- **Persistence**: Because locks live on the filesystem, they **survive an nginx restart**. This diverges from the ephemeral model of RFC 4918 §10.1; clients that explicitly `UNLOCK` (the correct pattern) are unaffected. To restore ephemeral behaviour, enable `brix_webdav_lock_startup_sweep`.
- **Timeout**: Default timeout is 600 seconds, configurable via `brix_webdav_lock_timeout`.

---

### `brix_webdav_lock_startup_sweep <on|off>`

**Context:** `main` · `server` · `location` · **Default:** `off`

Controls whether persisted WebDAV lock xattrs under the export root are cleared at startup.

Because lock state is stored as an xattr on each resource (see `brix_webdav_lock_timeout`), locks normally persist across an nginx restart. When this directive is `on`, nginx recursively removes every `user.nginx_xrootd.lock` xattr beneath the resolved export root once at startup, restoring the ephemeral, restart-clears-all semantics of RFC 4918 §10.1.

- **Default `off`**: locks persist across restarts (no startup filesystem walk).
- The sweep runs once per webdav location when its export root is resolved at configuration load. It is **skipped during `nginx -t`** so a config test never mutates the filesystem.
- The cost is a one-time recursive walk of the export root at startup; leave it `off` for very large trees unless ephemeral lock semantics are required.

```nginx
location / {
    brix_webdav      on;
    brix_export /data;
    brix_webdav_lock_startup_sweep on;   # clear stale locks on restart
}
```

---
