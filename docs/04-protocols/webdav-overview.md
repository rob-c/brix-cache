# WebDAV module

The WebDAV module turns nginx into a `davs://` endpoint — the HTTP-based transfer path used by WLCG pipelines, `rucio`, browsers, and any client that prefers HTTP over native `root://`.
with the full set of WebDAV methods, enforces GSI proxy-certificate and WLCG
bearer-token authentication, and optionally forwards authenticated requests to
a backend WebDAV server. It is a standalone `ngx_http` module — completely
separate from the native XRootD stream module — and can be deployed on the
same nginx instance as the stream module or on its own.

---

## Contents

- [Overview](#overview)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [HTTP methods](#http-methods)
- [HTTP Third-Party Copy (TPC)](#http-third-party-copy-tpc)
- [Upstream proxy mode](#upstream-proxy-mode)
- [CORS](#cors)
- [WebDAV locks](#webdav-locks)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

---

## Overview

```text
                        ┌─────────────────────────────────────────┐
  xrdcp davs://…        │            nginx (HTTP module)           │
  curl -X PROPFIND      │                                          │
  rclone davs://…  ───► │  SSL termination + auth gate             │
                        │       │                                  │
                        │       ├─ cert OK / token OK / anon       │
                        │       │                                  │
                        │       ├─► local filesystem (POSIX)       │
                        │       │       GET, PUT, PROPFIND, …      │
                        │       │                                  │
                        │       └─► upstream HTTP(S) proxy         │
                        │               (brix_webdav_proxy on)   │
                        └─────────────────────────────────────────┘
```

**What it does:**

- Accepts HTTPS connections and optionally requires mTLS (client certificates)
- Authenticates via RFC 3820 GSI proxy certificates or WLCG/JWT bearer tokens
- Serves a POSIX filesystem through OPTIONS, GET (byte-range), HEAD, PUT,
  DELETE, MKCOL, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, and UNLOCK
- Handles HTTP-TPC (server-to-server copy) used by `xrdcp davs://src davs://dst`
- Adds CORS response headers for browser WebDAV clients
- Can forward all requests to a backend HTTP/HTTPS server after the auth gate
  (proxy mode — see [Upstream proxy mode](#upstream-proxy-mode))

**What it is not:**

- It does not speak the XRootD binary protocol. For `root://` use the
  stream module (`xrootd` directive in the `stream {}` block).
- It is not a generic nginx reverse proxy. Its upstream proxy mode is
  purpose-built for the WebDAV auth-termination pattern.

---

## Quick start

### Minimal read-only setup (anonymous access)

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;

    location /dav/ {
        brix_webdav      on;
        brix_export /data/store;
        brix_webdav_auth none;
    }
}
```

### Read-write with WLCG bearer tokens

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;

    # Optional: allow GSI proxy certificates too
    ssl_verify_client optional_no_ca;
    ssl_verify_depth  10;

    location /dav/ {
        brix_webdav       on;
        brix_export  /data/store;
        brix_webdav_auth  required;
        brix_webdav_cadir /etc/grid-security/certificates;
        brix_webdav_crl   /etc/grid-security/certificates;

        # Bearer token (WLCG/SciTokens)
        brix_webdav_token_jwks     /etc/brix/issuer.jwks;
        brix_webdav_token_issuer   https://token.example.org;
        brix_webdav_token_audience https://se.example.org;

        brix_allow_write on;
    }
}
```

> **Tip:** `brix_webdav_auth required` blocks all unauthenticated requests
> with HTTP 403. Use `optional` to allow anonymous reads while still
> recording the identity of authenticated clients.

### Read-write with GSI proxy certificates

```nginx
server {
    listen 443 ssl;
    ssl_certificate      /etc/grid-security/hostcert.pem;
    ssl_certificate_key  /etc/grid-security/hostkey.pem;
    ssl_client_certificate /etc/grid-security/certificates/all-cas.pem;
    ssl_verify_client    optional_no_ca;
    ssl_verify_depth     10;

    location /dav/ {
        brix_webdav        on;
        brix_export   /data/store;
        brix_webdav_auth   required;
        brix_webdav_proxy_certs on;           # accept RFC 3820 proxy certs
        brix_webdav_cadir  /etc/grid-security/certificates;
        brix_webdav_crl    /etc/grid-security/certificates;
        brix_allow_write on;
    }
}
```

> **Note:** `ssl_verify_client optional_no_ca` lets nginx request the client
> certificate without refusing connections that have none. The WebDAV module
> performs its own chain verification using the configured CA store.

---

## Authentication

Authentication is controlled by `brix_webdav_auth` and applies to every
request that reaches the location block.

```text
Incoming request
      │
      ▼
  auth == none? ──► proceed as anonymous
      │
      ▼
  Try GSI proxy cert (mTLS)
      │ verified?
      ├─► yes: proceed as <DN>
      │
      ▼
  Try Authorization: Bearer <jwt>
      │ verified?
      ├─► yes: proceed as <sub> + scopes
      │
      ▼
  auth == optional? ──► proceed as anonymous
      │
  auth == required? ──► HTTP 403 Forbidden
```

### Auth modes

| Value | Behaviour |
|---|---|
| `none` | All requests anonymous; no CA store needed |
| `optional` | Auth attempted; falls back to anonymous if no valid credential |
| `required` | Unauthenticated requests get HTTP 403 |

Default is `optional`.

### GSI / X.509 proxy certificates

The module validates the full RFC 3820 proxy chain using an OpenSSL X509_STORE
built from `brix_webdav_cadir` / `brix_webdav_cafile` and checked against
CRLs from `brix_webdav_crl`. The CA store is built once at startup and
cached for the worker lifetime — no per-request disk I/O.

Enable `brix_webdav_proxy_certs on` to accept VOMS proxy certificates.
Without it, only end-entity certificates are accepted.

### WLCG/SciTokens JWT bearer tokens

Set `brix_webdav_token_jwks` to a local JWKS file (RS256). The module
validates signature, expiry, `iss`, and `aud` claims. Token scopes
(`storage.read`, `storage.write`, `storage.create`) are enforced on write
methods when the token path is present.

All three of `brix_webdav_token_jwks`, `brix_webdav_token_issuer`, and
`brix_webdav_token_audience` must be set together.

> **Key rotation:** use `brix_webdav_macaroon_secret_old` to keep accepting
> tokens signed by the previous key during a rotation window. Remove it once
> all clients have migrated.

---

## HTTP methods

The module implements the full set of WebDAV methods. Write methods require
`brix_allow_write on` and, when using bearer tokens, an appropriate
write scope in the token.

| Method | Description |
|---|---|
| `OPTIONS` | Advertise allowed methods; handles CORS pre-flight |
| `GET` | Retrieve file; supports `Range`, `If-None-Match`, `If-Modified-Since` |
| `HEAD` | Same as GET but without body; returns `Content-Length`, `ETag`, `Last-Modified` |
| `PUT` | Upload file; uses thread pool for large files when configured |
| `DELETE` | Remove file or directory tree |
| `MKCOL` | Create directory |
| `PROPFIND` | List properties; depth `0` (resource), `1` (immediate children), `infinity` |
| `PROPPATCH` | Set/remove dead properties |
| `COPY` | Duplicate file or directory within the namespace; also initiates HTTP-TPC pull |
| `MOVE` | Rename or move within the namespace |
| `LOCK` | Acquire exclusive write lock; timeout from `brix_webdav_lock_timeout` |
| `UNLOCK` | Release a write lock |

> **GET with Range:** byte-range requests are fully supported, including
> multi-range. The fd cache (16 slots per connection) avoids repeated
> `open()`/`fstat()` for PROPFIND+GET pairs on the same resource.

> **Thread pool for PUT:** if `brix_thread_pool` names a thread pool
> configured with nginx's `thread_pool` directive, large PUT bodies are written
> from a worker thread, keeping the event loop unblocked.

---

## HTTP Third-Party Copy (TPC)

HTTP-TPC lets `xrdcp davs://source davs://dest` copy directly between two
servers without buffering through the client. The client sends a `COPY` request
to the destination server; the destination server then pulls the data from the
source.

```text
  xrdcp client
      │
      │  COPY /dest/file
      │  Source: https://src.example.org/src/file
      │  Credential: <token>
      ▼
  nginx (destination) ──pull─► src.example.org
      │
      ▼
  local filesystem
```

Enable TPC with `brix_webdav_tpc on`. You also need `brix_allow_write on`.

```nginx
location /dav/ {
    brix_webdav           on;
    brix_export      /data/store;
    brix_webdav_auth      required;
    brix_webdav_cadir     /etc/grid-security/certificates;
    brix_allow_write on;
    brix_webdav_tpc       on;

    # curl binary used to perform the pull
    brix_webdav_tpc_curl  /usr/bin/curl;

    # Service certificate for authenticating to the source server
    brix_webdav_tpc_cert  /etc/grid-security/hostcert.pem;
    brix_webdav_tpc_key   /etc/grid-security/hostkey.pem;
    brix_webdav_tpc_cadir /etc/grid-security/certificates;

    # Maximum time for a single curl pull (seconds)
    brix_webdav_tpc_timeout 300;
}
```

### OAuth2/OIDC credential delegation for TPC

When the client sends a `Credential: oidc-agent` or `Credential: token-exchange`
header, the server obtains a delegated access token for the source server via
RFC 8693 token exchange. Configure the token endpoint:

```nginx
brix_webdav_tpc_token_endpoint      https://iam.example.org/token;
brix_webdav_tpc_token_client_id     my-service;
brix_webdav_tpc_token_client_secret /etc/brix/client-secret;
brix_webdav_tpc_token_scope         storage.read;
```

> **Security:** TPC pull uses an external `curl` process spawned per transfer.
> Ensure the `curl` binary at `brix_webdav_tpc_curl` is the system curl and
> not writable by untrusted users.

---

## Upstream proxy mode

Proxy mode lets nginx act as an authenticating gateway in front of any HTTP/HTTPS
WebDAV backend. Nginx terminates TLS and WLCG auth at the perimeter; the backend
runs plain HTTP with no auth of its own.

```text
  client (xrdcp / curl / rclone)
      │  davs://public.example.org/dav/…
      │  TLS + WLCG token
      ▼
  ┌─────────────────────────────────────────┐
  │  nginx (public, port 443)               │
  │                                         │
  │  1. Terminate TLS                       │
  │  2. Verify WLCG bearer token            │
  │  3. Strip / rewrite Authorization       │
  │  4. Rewrite Destination header          │
  └──────────────────┬──────────────────────┘
                     │ plain HTTP
                     ▼
  ┌─────────────────────────────────────────┐
  │  xrootd WebDAV (internal, port 1094)    │
  │  no TLS, no auth, trusted network only  │
  └─────────────────────────────────────────┘
```

### Minimal proxy config

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;
    ssl_verify_client   optional_no_ca;
    ssl_verify_depth    10;

    location /dav/ {
        brix_webdav       on;
        brix_export  /data/store;   # still used for auth path checks
        brix_webdav_auth  required;
        brix_webdav_cadir /etc/grid-security/certificates;
        brix_webdav_token_jwks     /etc/brix/issuer.jwks;
        brix_webdav_token_issuer   https://token.example.org;
        brix_webdav_token_audience https://se.example.org;

        # Enable proxy mode
        brix_webdav_proxy          on;
        brix_webdav_proxy_upstream http://brix-backend.internal:1094;
        brix_webdav_proxy_auth     anonymous;   # strip Authorization (default)
    }
}
```

### Auth forwarding policies

`brix_webdav_proxy_auth` controls what nginx puts in the `Authorization`
header of the forwarded request.

| Policy | Forwarded Authorization |
|---|---|
| `anonymous` | Stripped — no `Authorization` header sent to backend (default) |
| `forward` | Client's original `Authorization` header forwarded unchanged |
| `token <value>` | Replaced with `Bearer <value>` (static service credential) |

Example — inject a static service token:

```nginx
brix_webdav_proxy_auth token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...;
```

> **Note:** the token value is placed in nginx.conf in plaintext. Protect the
> configuration file with appropriate file permissions (readable by root only).

### HTTPS upstream

The upstream URL can be `https://`. When it is, nginx opens a TLS connection to
the backend but does **not** verify the backend's server certificate. This is
intentional for internal-network backends where the trust is established by
network topology rather than PKI.

```nginx
brix_webdav_proxy_upstream https://brix-backend.internal:2094;
```

### Destination header rewriting

For `COPY` and `MOVE`, the WebDAV `Destination` header contains an absolute URL
pointing at the public nginx address. The proxy rewrites it to point at the
upstream base URL before forwarding:

```text
  Destination: https://public.example.org/dav/new-name
          ──►  http://brix-backend.internal:1094/dav/new-name
```

This rewrite is automatic and requires no additional configuration.

### Timeout tuning

```nginx
brix_webdav_proxy_connect_timeout 10s;
brix_webdav_proxy_send_timeout    60s;
brix_webdav_proxy_read_timeout    120s;
```

All three default to 60 seconds. For large file uploads, increase
`brix_webdav_proxy_send_timeout` and `brix_webdav_proxy_read_timeout`.

> **Note:** these are nginx msec-slot values; you can use suffix notation
> (`10s`, `2m`, `500ms`) or plain milliseconds.

---

## CORS

Configure CORS for browser-based WebDAV clients. Multiple `brix_webdav_cors_origin`
lines are allowed.

```nginx
brix_webdav_cors_origin      https://portal.example.org;
brix_webdav_cors_origin      https://dashboard.example.org;
brix_webdav_cors_credentials on;
brix_webdav_cors_max_age     3600;
```

CORS pre-flight `OPTIONS` requests (those carrying both `Origin` and
`Access-Control-Request-Method`) are answered immediately, before the auth
gate. All other requests get `Access-Control-Allow-Origin` and related headers
appended to the response.

> **Tip:** omit `brix_webdav_cors_origin` entirely if you do not need CORS.
> No CORS headers are added when no origins are configured.

---

## WebDAV locks

The module implements `LOCK` and `UNLOCK` by storing lock state as an extended
attribute (`user.nginx_xrootd.lock`) on the locked resource itself — the same
storage layer as dead properties. There is no shared-memory table or mutex:
atomic creation is provided by the kernel's `XATTR_CREATE` semantics, and a
lock check walks from the target path up to the export root (`O(path_depth)`
xattr reads). The number of concurrent locks is bounded only by filesystem
capacity.

```nginx
brix_webdav_lock_timeout 600;          # maximum lock lifetime in seconds (default)
brix_webdav_lock_startup_sweep off;    # on = clear persisted locks at startup
```

Locks expire lazily — an expired lock is removed on the next access to its
path. No external lock server is required.

> **Persistence:** because locks live on the filesystem, they **survive an
> nginx restart**, which diverges from the ephemeral model of RFC 4918 §10.1.
> Clients that explicitly `UNLOCK` (the correct pattern) are unaffected. To
> restore the ephemeral, restart-clears-all behaviour, enable
> `brix_webdav_lock_startup_sweep`.

---

## Configuration reference

### Core directives

#### `brix_webdav`

```nginx
brix_webdav on | off;
```

Enable or disable the WebDAV module for this location block. Default: `off`.
Must be `on` for any other directive in this section to have effect.

Context: `location`

---

#### `brix_export`

```nginx
brix_export /path/to/export;
```

Filesystem directory to expose. All WebDAV operations are confined to this
tree — path traversal outside the root is rejected. The module validates at
startup that the directory exists and is accessible. Default: `/`.

Context: `location`

---

#### `brix_webdav_auth`

```nginx
brix_webdav_auth none | optional | required;
```

Authentication policy. Default: `optional`.

- `none` — no authentication attempted; all requests are anonymous
- `optional` — authentication is tried but anonymous access is allowed if no
  valid credential is present
- `required` — requests without a valid certificate or token are rejected with
  HTTP 403

Context: `location`

---

#### `brix_allow_write`

```nginx
brix_allow_write on | off;
```

Enable write methods: PUT, DELETE, MKCOL, COPY, MOVE. Default: `off`.

When bearer tokens are in use, write methods additionally require the token to
carry a `storage.write` or `storage.create` scope at the requested path.

Context: `location`

---

#### `brix_webdav_proxy_certs`

```nginx
brix_webdav_proxy_certs on | off;
```

Accept RFC 3820 proxy certificates (VOMS proxies). Default: `off`.

When `on`, the module walks the proxy chain up to `brix_webdav_verify_depth`
levels deep. When `off`, only end-entity certificates are accepted.

Context: `server`, `location`

---

#### `brix_webdav_cadir`

```nginx
brix_webdav_cadir /etc/grid-security/certificates;
```

Directory of trusted CA PEM files (hashed, as produced by `update-ca-trust` or
`c_rehash`). Required when `brix_webdav_auth` is `optional` or `required`
unless `brix_webdav_cafile` is set instead.

Context: `location`

---

#### `brix_webdav_cafile`

```nginx
brix_webdav_cafile /etc/pki/tls/certs/ca-bundle.crt;
```

Single PEM file containing one or more trusted CA certificates. Alternative to
`brix_webdav_cadir`; both can be set.

Context: `location`

---

#### `brix_webdav_crl`

```nginx
brix_webdav_crl /etc/grid-security/certificates;
```

Path to CRL file(s). Accepts a directory (hashed CRL PEMs) or a single PEM
bundle. CRLs are loaded once at startup.

Context: `location`

---

#### `brix_webdav_token_jwks`

```nginx
brix_webdav_token_jwks /etc/brix/issuer.jwks;
```

Path to a local JWKS file (JSON, RS256 keys) used for bearer token signature
verification. Must be set together with `brix_webdav_token_issuer` and
`brix_webdav_token_audience`.

The JWKS is loaded once at startup. To rotate keys, reload nginx.

Context: `location`

---

#### `brix_webdav_token_issuer`

```nginx
brix_webdav_token_issuer https://token.example.org;
```

Required `iss` claim value. Tokens with a different issuer are rejected.

Context: `location`

---

#### `brix_webdav_token_audience`

```nginx
brix_webdav_token_audience https://se.example.org;
```

Required `aud` claim value. Tokens with a different audience are rejected.

Context: `location`

---

#### `brix_webdav_cors_origin`

```nginx
brix_webdav_cors_origin https://portal.example.org;
```

Permitted CORS origin. Repeat for multiple origins. No default; CORS headers
are suppressed entirely when no origins are listed.

Context: `location`

---

#### `brix_webdav_cors_credentials`

```nginx
brix_webdav_cors_credentials on | off;
```

Set `Access-Control-Allow-Credentials: true`. Default: `off`.

Context: `location`

---

#### `brix_webdav_cors_max_age`

```nginx
brix_webdav_cors_max_age 86400;
```

Value for `Access-Control-Max-Age` (seconds). Default: `86400` (24 hours).

Context: `location`

---

#### `brix_webdav_lock_timeout`

```nginx
brix_webdav_lock_timeout 600;
```

Maximum lifetime of a WebDAV lock in seconds. Default: `600` (10 minutes).
Clients can request a shorter timeout; requests for a longer one are capped
at this value.

Context: `main`, `server`, `location`

---

#### `brix_thread_pool`

```nginx
brix_thread_pool default;
```

Name of an nginx `thread_pool` to use for asynchronous PUT body writes. When
set, large file uploads are written from a worker thread, avoiding event-loop
stalls. Requires nginx to be compiled with `--with-threads`.

```nginx
# In the http {} block:
thread_pool default threads=4 max_queue=65536;

# In location {}:
brix_thread_pool default;
```

Context: `location`

---

### TPC directives

#### `brix_webdav_tpc`

```nginx
brix_webdav_tpc on | off;
```

Enable HTTP Third-Party Copy. Default: `off`. Also requires
`brix_allow_write on`.

Context: `location`

---

#### `brix_webdav_tpc_curl`

```nginx
brix_webdav_tpc_curl /usr/bin/curl;
```

Path to the `curl` binary used to perform TPC pull transfers. Must be
executable by the nginx worker process.

Context: `location`

---

#### `brix_webdav_tpc_cert`

```nginx
brix_webdav_tpc_cert /etc/grid-security/hostcert.pem;
```

Client certificate PEM presented when `curl` authenticates to the source server.

Context: `location`

---

#### `brix_webdav_tpc_key`

```nginx
brix_webdav_tpc_key /etc/grid-security/hostkey.pem;
```

Private key PEM for `brix_webdav_tpc_cert`.

Context: `location`

---

#### `brix_webdav_tpc_cadir`

```nginx
brix_webdav_tpc_cadir /etc/grid-security/certificates;
```

CA directory (hashed PEMs) used by `curl` to verify the source server's
certificate during TPC pull.

Context: `location`

---

#### `brix_webdav_tpc_timeout`

```nginx
brix_webdav_tpc_timeout 300;
```

Maximum time in seconds for a single TPC `curl` transfer (`--max-time`).
Default: `0` (no limit). Set this to prevent hung transfers from occupying
worker processes indefinitely.

Context: `location`

---

#### `brix_webdav_tpc_token_endpoint`

```nginx
brix_webdav_tpc_token_endpoint https://iam.example.org/token;
```

OAuth2 token endpoint for RFC 8693 token exchange used when the client sends
`Credential: token-exchange`.

Context: `location`

---

#### `brix_webdav_tpc_token_client_id`

```nginx
brix_webdav_tpc_token_client_id my-service;
```

OAuth2 client ID for confidential client token exchange.

Context: `location`

---

#### `brix_webdav_tpc_token_client_secret`

```nginx
brix_webdav_tpc_token_client_secret s3cr3t;
```

OAuth2 client secret for confidential client token exchange.

Context: `location`

---

#### `brix_webdav_tpc_token_scope`

```nginx
brix_webdav_tpc_token_scope storage.read;
```

Scope string to request during token exchange.

Context: `location`

---

### Proxy directives

#### `brix_webdav_proxy`

```nginx
brix_webdav_proxy on | off;
```

Enable upstream proxy mode. When `on`, all requests are forwarded to
`brix_webdav_proxy_upstream` after the auth gate. Default: `off`.

Context: `location`

---

#### `brix_webdav_proxy_upstream`

```nginx
brix_webdav_proxy_upstream http://host:port;
brix_webdav_proxy_upstream https://host:port;
```

URL of the backend WebDAV server. Required when `brix_webdav_proxy on`.
Supports both `http://` and `https://` schemes. The upstream address is
resolved once at startup.

Context: `location`

---

#### `brix_webdav_proxy_auth`

```nginx
brix_webdav_proxy_auth anonymous;
brix_webdav_proxy_auth forward;
brix_webdav_proxy_auth token <bearer-value>;
```

Authorization header policy for forwarded requests. Default: `anonymous`.

| Value | Effect |
|---|---|
| `anonymous` | `Authorization` header stripped before forwarding |
| `forward` | Client's `Authorization` header forwarded unchanged |
| `token <value>` | `Authorization: Bearer <value>` injected |

Context: `location`

---

#### `brix_webdav_proxy_connect_timeout`

```nginx
brix_webdav_proxy_connect_timeout 10s;
```

Timeout for establishing the TCP (or TLS) connection to the upstream.
Default: `60s`.

Context: `location`

---

#### `brix_webdav_proxy_send_timeout`

```nginx
brix_webdav_proxy_send_timeout 60s;
```

Timeout for sending the request (headers + body) to the upstream. Default: `60s`.

Context: `location`

---

#### `brix_webdav_proxy_read_timeout`

```nginx
brix_webdav_proxy_read_timeout 120s;
```

Timeout for reading the response from the upstream. Default: `60s`. Increase
this for slow backends or large responses.

Context: `location`

---

## Troubleshooting

### "auth optional/required needs brix_webdav_cadir or brix_webdav_cafile"

`brix_webdav_auth optional` and `required` both need a trust anchor to
verify certificates. Set `brix_webdav_cadir` or `brix_webdav_cafile`.
If you only want bearer token auth and no certificate support, that is not
supported directly — set a cadir that points at your issuer's CA.

### Token verification fails

1. Check that `brix_webdav_token_issuer` matches the `iss` claim exactly
   (trailing slashes matter).
2. Check that `brix_webdav_token_audience` matches the `aud` claim.
3. Verify the JWKS file is valid JSON and contains the correct public keys
   for your issuer. You can inspect it with `python3 -m json.tool`.
4. Check the clock on the nginx host — JWT `exp` verification requires
   reasonably accurate system time.

### "brix_webdav: root path ... is not accessible"

The nginx worker process must be able to read (and, for writes, write) the
`brix_export` directory. Check filesystem permissions and that the
nginx worker user (typically `nginx` or `www-data`) has appropriate access.

### Proxy mode returns 502 Bad Gateway

1. Confirm the upstream is running and listening on the configured address and
   port.
2. Check firewall rules between nginx and the backend.
3. Look for the upstream address in the nginx error log:
   `brix_webdav_proxy: upstream ... -> ... (ssl=0)` is logged at `notice`
   level during startup.
4. Increase `brix_webdav_proxy_read_timeout` if the backend is slow.

### TPC transfer hangs or times out

Set `brix_webdav_tpc_timeout` to a reasonable value (e.g. `300` for 5
minutes). Without it, a hung curl process holds the worker thread until nginx
is killed or reloaded.

Check that the `curl` binary at `brix_webdav_tpc_curl` can reach the source
server. Test manually:

```sh
curl -v --cert /etc/grid-security/hostcert.pem \
        --key  /etc/grid-security/hostkey.pem \
        --capath /etc/grid-security/certificates \
        https://src.example.org/dav/path/to/file
```

### Stale locks after a restart

Lock state is stored as an xattr on each resource, so locks **persist across an
nginx restart**. A client that crashed while holding a lock leaves the xattr
behind; the lock is cleared lazily on the next access to that path, or
immediately on an explicit `UNLOCK`. There is no fixed lock-table capacity to
exhaust. To clear all persisted locks at startup (restoring ephemeral
semantics), enable `brix_webdav_lock_startup_sweep`.
