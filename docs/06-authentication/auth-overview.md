# Authentication

Grid identity is layered: transport security, proof of identity, VO membership, and path authorization are separate concerns. BriX-Cache handles all four. This page maps the options, tells you which combination to use for your site, and links to the details.

---

## Authentication decision map

Different URL schemes carry credentials in different places. Start with the
listener, then follow the credential type:

```text
client connection
      |
      +-- root:// or roots://  (nginx stream module)
      |        |
      |        +-- brix_auth none
      |        |        -> anonymous session
      |        |
      |        +-- brix_auth gsi
      |        |        -> kXR_login
      |        |        -> multi-step kXR_auth GSI exchange
      |        |        -> DN + optional VOMS groups
      |        |
      |        +-- brix_auth token
      |        |        -> kXR_login advertises ztn
      |        |        -> kXR_auth carries JWT
      |        |        -> sub + scopes + wlcg.groups
      |        |
      |        +-- brix_auth both
      |                 -> client chooses gsi or ztn in kXR_auth
      |
      +-- davs:// or https:// WebDAV  (nginx HTTP module)
      |        |
      |        +-- TLS client proxy certificate
      |        |        -> WebDAV x509 verifier
      |        |        -> DN + optional VOMS groups
      |        |
      |        +-- Authorization: Bearer <jwt>
      |        |        -> WebDAV token verifier
      |        |        -> sub + scopes + wlcg.groups
      |        |
      |        +-- no valid credential
      |                 -> anonymous or 403, depending on brix_webdav_auth
      |
      +-- S3-compatible HTTP location
               |
               +-- optional AWS SigV4 Authorization header
               +-- separate from GSI/JWT policy in this document
```

For native XRootD and WebDAV, successful GSI/token identity paths eventually
feed the same authorization questions:

```text
verified identity facts
    |
    +-- token scopes: storage.read / storage.write / storage.create
    +-- VO/group facts: VOMS FQANs or token wlcg.groups
    +-- server gates: brix_allow_write, brix_require_vo, filesystem mode
    |
    v
allow or reject this operation on this path
```

Authorization is a second step after the credential has been accepted:

```text
incoming operation
        |
        +-- path-based? --------------------+
        |                                   |
        | yes                               | no, handle-based
        v                                   v
resolve and confine path              find ctx->files[handle]
        |                                   |
        v                                   v
read or metadata?                     use permissions recorded
        |                             when the handle was opened
        +-- yes -> require read scope/VO/path permission
        |
        v
write or namespace mutation?
        |
        +-- yes -> brix_allow_write must be on
                  and token/VO/path policy must allow write/create
        |
        v
filesystem permission and syscall result still matter
        |
        v
allow response or protocol error
```

---

## Anonymous access

The default. Any client can connect and provide any username — no certificate or password is checked.

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        brix_root /data/public;
        # brix_auth none;  ← this is the default, no need to write it
    }
}
```

Use this for public data, internal networks, or when access control is handled at the network layer.

---

## GSI / x509 authentication

GSI (Grid Security Infrastructure) is the standard authentication method across the WLCG computing grid. It uses x509 proxy certificates — short-lived credentials derived from your long-term grid certificate.

If you are new to GSI: think of it like SSH keys, but with a certificate authority (your home institution or CERN) vouching for who you are, and the "proxy" certificate being a temporary 12-hour credential you generate each morning with `voms-proxy-init` or `grid-proxy-init`.

### What you need

On the **server**:
- A host certificate (`hostcert.pem`) issued by a trusted CA — typically from your institution's grid CA
- The corresponding private key (`hostkey.pem`)
- The CA certificate that signed the client certificates you want to accept (`ca.pem`)

On the **client**:
- A valid proxy certificate (generated from their personal grid certificate)

### Configuration

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        brix_auth gsi;
        brix_root /data/store;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/ca.pem;
        brix_access_log /var/log/nginx/brix_gsi.log;
    }
}
```

The private key file must be readable by the nginx worker processes (typically running as `www-data` or `nginx`). The certificate and CA files can be world-readable.

### Testing GSI authentication

Generate a proxy certificate, then point `xrdcp` at it:

```bash
# Generate a proxy from your personal grid certificate
voms-proxy-init    # or: grid-proxy-init

# Tell xrdcp where the proxy lives (usually automatic, but explicit here)
export X509_USER_PROXY=$(voms-proxy-info -path)

# Copy a file
xrdcp /tmp/test.txt root://localhost:1095//test.txt
```

If authentication succeeds, the access log shows the client's subject DN:

```
192.168.1.1 gsi "/DC=org/OU=Users/CN=Alice Example" [14/Apr/2026:10:23:44 +0000] "AUTH - gsi" OK 0 48ms
```

### The authenticated identity

After a successful GSI handshake, the module extracts the subject Distinguished Name from the proxy certificate chain and stores it in the session. It appears in the access log and is available for downstream logging. The module does not currently perform authorisation based on the DN itself. Path-level authorisation is handled by `brix_require_vo` rules when `libvomsapi.so.1` is available at runtime (see [building.md](../03-configuration/build-guide.md)).

---

## How GSI authentication works (simplified)

If you do not care about the internals, skip this section. For the complete
certificate hierarchy, proxy certificate internals, VOMS two-chain trust model,
and detailed GSI DH exchange diagrams, see [pki.md](pki-config.md).

The GSI handshake uses Diffie-Hellman key exchange to establish a shared session key, then the client sends their proxy certificate chain encrypted with that key. The server verifies the chain against its configured trusted CA.

```
Client                                       Server
──────                                       ──────
kXR_protocol (requests security info)  ─>
                                        <─  security requirements ("gsi" required)

kXR_login                              ─>
                                        <─  session ID + GSI challenge text
                                            "&P=gsi,v:10000,c:ssl,ca:<ca_hash>"

kXR_auth [step: "certreq"]             ─>   "here is a random nonce"
                                        <─  DH public key + server cert
                                            + server's signature of the nonce

kXR_auth [step: "cert"]                ─>   DH public key + proxy cert chain
                                            (AES-encrypted with DH session key)
                                        <─  auth complete (kXR_ok)
```

The proxy certificate is verified using standard OpenSSL chain verification (`X509_verify_cert`) with the `X509_V_FLAG_ALLOW_PROXY_CERTS` flag set to accept RFC 3820 proxy certificates.

---

## Using both anonymous and GSI on different ports

A common setup: public data on port 1094 (no credentials needed) and private or writable data on port 1095 (GSI required):

```nginx
stream {
    # Public read-only
    server {
        listen 1094;
        xrootd on;
        brix_root /data/public;
    }

    # Authenticated read-write
    server {
        listen 1095;
        xrootd on;
        brix_auth gsi;
        brix_allow_write on;
        brix_root /data/restricted;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/ca.pem;
    }
}
```

Clients use `root://host:1094//path` for public access and `root://host:1095//path` for authenticated access.

---

## Token / JWT (WLCG bearer token) authentication

WLCG bearer tokens are the modern alternative to GSI proxy certificates. Instead of an x509 certificate chain, the client presents a compact signed JWT asserting who they are, which service the token is for, and when it expires. No certificate infrastructure is required — just a trusted JWKS public key set.

If you are new to bearer tokens: think of one like an API key, but cryptographically signed and with built-in expiry. The server verifies the signature using a public key (published as a JWKS file) and checks claims like issuer, audience, expiry, and not-before time — all without contacting any external service.

### What you need

On the **server**:
- A JWKS file containing the public key(s) you trust (`jwks.json`)
- The expected issuer URL (matches the `iss` claim in tokens)
- The expected audience string (matches the `aud` claim in tokens)

On the **client**:
- A valid JWT token (set in the `BEARER_TOKEN` environment variable for `xrdcp`/`xrdfs`, or in an `Authorization: Bearer` HTTP header for WebDAV)

### Configuration

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        brix_auth token;
        brix_root /data/store;
        brix_allow_write on;
        brix_token_jwks     /etc/tokens/jwks.json;
        brix_token_issuer   "https://idp.example.com";
        brix_token_audience "my-storage";
        brix_access_log /var/log/nginx/brix_token.log;
    }
}
```

| Directive | Purpose |
|---|---|
| `brix_auth token` | Require a bearer token for every native XRootD session |
| `brix_token_jwks` | Path to the JWKS file containing trusted public keys |
| `brix_token_issuer` | Expected `iss` claim — tokens from other issuers are rejected |
| `brix_token_audience` | Expected `aud` claim — tokens for other services are rejected |

### Testing token authentication

Generate a token using the test signing authority, then point `xrdfs` at it:

```bash
# Generate a read-only token
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /path/to/token_dir)

# List files
xrdfs root://localhost:1094 ls /

# Copy a file
xrdcp root://localhost:1094//test.txt /tmp/test.txt
```

If authentication succeeds, the native stream session is marked authenticated and the token `sub` claim is stored internally as the session identity. Current stream access-log labels remain `anon` for non-GSI listeners and `gsi` for GSI-only listeners; token subjects are emitted in nginx info/debug logs rather than the `brix_access_log` identity field.

### Scopes and groups

Tokens may carry WLCG storage scopes:

| Scope | Meaning |
|---|---|
| `storage.read:/` | Read grant for `/` |
| `storage.write:/` | Write grant for `/` |
| `storage.read:/public` | Read grant scoped to `/public` |
| `storage.write:/uploads` | Write grant scoped to `/uploads` |

The native XRootD stream path validates tokens and enforces storage scopes on
path-resolving operations. A read scope is required for read opens and metadata
operations; a write/create scope is required for namespace mutation and write
opens. Handle-based I/O inherits the decision made when the handle was opened.
`brix_allow_write` remains an additional server-wide write gate. WebDAV
enforces `storage.write`/`storage.create` scopes for `PUT` requests when the
request is authenticated via a bearer token.

Tokens can also carry `wlcg.groups`. The stream module maps those groups into the same VO list used for VOMS, so `brix_require_vo` can protect paths for token-authenticated clients as well as GSI clients.

### The authenticated identity

After a successful token validation, the module extracts the `sub` (subject) claim from the JWT and stores it in the session. Token groups from `wlcg.groups` are stored as VO-style memberships for path ACL checks.

For the full walkthrough on setting up a test signing authority and generating tokens, see [test-tokens.md](test-token-generation.md).

---

## Using both GSI and token on the same port

A server can accept either GSI proxy certificates or bearer tokens. The module inspects the credential type in the `kXR_auth` request (`gsi` or `ztn`) and routes to the appropriate handler:

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        brix_auth both;
        brix_root /data;

        # GSI settings
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/ca.pem;

        # Token settings
        brix_token_jwks     /etc/tokens/jwks.json;
        brix_token_issuer   "https://idp.example.com";
        brix_token_audience "my-storage";
    }
}
```

This is the recommended production configuration for sites transitioning from GSI to tokens — existing clients with proxy certificates continue to work, while new clients can use bearer tokens.

---

## TLS / encrypted transport

The project now supports three encrypted transport patterns:

- `davs://` via nginx HTTP TLS in the WebDAV module
- `root://` plus the native XRootD in-protocol TLS upgrade with `brix_tls on`
- `roots://` via nginx stream SSL (`listen ... ssl`)

Those modes are implemented in different code paths and have different auth and
performance trade-offs, so they are documented in one place here:

- [tls.md](../03-configuration/tls-config.md)

If you only need the short version:

- GSI by itself protects the auth exchange but does not automatically encrypt
  the whole native XRootD session
- `brix_tls on` upgrades a `root://` connection to TLS after
  `kXR_protocol`
- `roots://` uses nginx stream SSL from the first byte
- `davs://` uses nginx HTTP SSL plus the WebDAV module's proxy-cert handling

## Authorization

Once a principal is authenticated, *authorization* (which paths it may access,
with which privileges) is handled by an authdb. Two engines are available: the
default `native` engine and a faithful XRootD **XrdAcc** engine usable across
root://, WebDAV and S3 — see
[authorization-xrdacc.md](authorization-xrdacc.md).

## Identity → local UNIX user & group mapping

How an X.509/VOMS/VO or token/SSS/Kerberos identity is turned into authorization
decisions and **local UNIX user/group** ownership — and how an admin can
**force, override, or adjust** a given mapping — is documented in detail in
[**identity-mapping.md**](identity-mapping.md). Start there if you need to map
grid/VO identities to local UNIX groups, pin a service account, control created-
file ownership, or override the default mapping for a specific principal.
