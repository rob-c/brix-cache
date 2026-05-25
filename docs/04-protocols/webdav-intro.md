# WebDAV / HTTPS+GSI/Bearer

The `ngx_http_xrootd_webdav_module` adds a WebDAV content handler to nginx's HTTP layer. Pair it with TLS, GSI proxy-certificate support, and JWT bearer-token validation, and `xrdcp` can use `davs://host:8443/` — the same transfer path Grid and WLCG workflows reach for when they prefer HTTP over native `root://`.

For the full TLS implementation details across both WebDAV and native XRootD,
see [tls.md](../03-configuration/tls-config.md). For the WebDAV fast paths and syscall-reduction work, see
[optimizations.md](../09-developer-guide/optimizations.md). For the usual `xrdcp --allow-http`
request flow, see [xrdcp-interactions.md](xrootd-client-interaction.md).

---

## How it works

`xrdcp --allow-http davs://host:8443/path` is handled by the `XrdClHttp` plugin, which speaks WebDAV (HTTP methods OPTIONS, GET with Range, HEAD, PUT, DELETE, MKCOL, PROPFIND) over TLS. Authentication can come from RFC 3820 proxy certificates or from an `Authorization: Bearer <JWT>` header.

nginx's built-in SSL stack does not accept RFC 3820 proxy certificates by default. This module patches the `SSL_CTX` in postconfiguration to set `X509_V_FLAG_ALLOW_PROXY_CERTS`, enabling proxy chains issued by your test CA. Per-request certificate verification is then performed using the configured CA directory or CA file. Bearer tokens are verified against a local JWKS file without a network call to an identity provider.

The request path looks like this:

```text
client
  |
  v
TLS handshake in nginx HTTP SSL
  |
  +-- optional client proxy certificate is captured by nginx/OpenSSL
  |
  v
HTTP request reaches location with xrootd_webdav on
  |
  v
WebDAV auth decision
  |
  +-- cached TLS/x509 result
  +-- or manual proxy-chain verification
  +-- or Authorization: Bearer token verification
  +-- or anonymous, if policy allows it
  |
  v
method dispatch
  |
  +-- OPTIONS  -> capabilities / CORS preflight
  +-- HEAD     -> metadata
  +-- GET      -> file-backed response, optional Range
  +-- PUT      -> request body to file
  +-- DELETE   -> remove file
  +-- MKCOL    -> create directory
  +-- PROPFIND -> directory or file properties
  +-- COPY     -> server-side copy or optional HTTP-TPC pull
  +-- POST     -> HTTP-TPC push
  +-- LOCK     -> acquire or refresh an exclusive write lock
  +-- UNLOCK   -> release an exclusive write lock
```

This is independent of the native XRootD stream state machine. A WebDAV `GET`
and a native `kXR_read` may return the same bytes, but they do not share request
parsing, response framing, or TLS/auth entry points.

---

## nginx.conf setup

Add to the `http {}` block:

```nginx
http {
    server {
        listen 8443 ssl;
        server_name your.host.name;

        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;

        # Request a client cert but don't reject connections that lack one.
        # Our module enforces auth policy per-request.
        ssl_verify_client optional_no_ca;
        ssl_verify_depth  10;

        # Patch the SSL_CTX to accept RFC 3820 proxy certificates.
        xrootd_webdav_proxy_certs on;

        # Allow uploads up to 1 GB
        client_max_body_size 1g;

        access_log /var/log/nginx/webdav_access.log;

        location / {
            xrootd_webdav         on;
            xrootd_webdav_root    /data;
            xrootd_webdav_cadir   /etc/grid-security/certificates;
            xrootd_webdav_auth    optional;    # or: none | required
            xrootd_webdav_allow_write on;

            # Optional HTTP-TPC pull support (COPY with a Source header)
            xrootd_webdav_tpc       on;
            xrootd_webdav_tpc_cert  /etc/grid-security/xrd/xrdcert.pem;
            xrootd_webdav_tpc_key   /etc/grid-security/xrd/xrdkey.pem;

            # Optional OAuth2/OIDC token delegation for TPC pull/push
            xrootd_webdav_tpc_token_endpoint https://idp.example.com/oauth2/token;
            xrootd_webdav_tpc_token_client_id  nginx-xrootd;
            xrootd_webdav_tpc_token_client_secret abc123secret;
            xrootd_webdav_tpc_token_scope      storage.read;

            # Optional bearer-token auth
            xrootd_webdav_token_jwks     /etc/tokens/jwks.json;
            xrootd_webdav_token_issuer   "https://idp.example.com";
            xrootd_webdav_token_audience "my-storage";

            # Optional browser/CORS access
            xrootd_webdav_cors_origin https://monitoring.example.com;
            xrootd_webdav_cors_credentials on;
        }
    }
}
```

---

## Sub-pages

- [Directives](webdav-directives.md) — all xrootd_webdav_* directive reference
- [Methods and RFC compliance](webdav-methods.md) — supported WebDAV methods, RFC 4918 compliance, curl examples
- [HTTP Third-Party Copy](webdav-tpc.md) — HTTP-TPC push and pull, xrdcp over WebDAV, native protocol relationship
