[← WebDAV overview](webdav-intro.md)

## HTTP-TPC (third-party copy)

HTTP-TPC lets a third party — like WLCG FTS — instruct this server to pull or push data directly without routing it through the client. Here's how it works and how to configure it.

Which header the `COPY` carries decides the direction — and which way the bytes
flow relative to *this* server:

```text
  PULL  (COPY carries  Source:)            PUSH  (COPY carries  Destination:)
  ──────────────────────────────          ────────────────────────────────────
   client ─COPY Source: REMOTE─▶ THIS      client ─COPY Destination: REMOTE─▶ THIS
                                 │                                           │
                THIS curl GET ◀──┘                          THIS curl PUT ───┘
                  from REMOTE                                  to REMOTE
                     ▼                                            ▲
   THIS ◀═══ bytes ═══ REMOTE  (download)   THIS ═══ bytes ═══▶ REMOTE  (upload)
                     │                                            │
   written to a temp file, then renamed     reads local file, --upload-file PUT
   atomically into place on curl success    using xrootd_webdav_tpc_cert/key
```



With `xrootd_webdav_tpc on`, this module also supports "push mode" where the server receiving the `COPY` request reads a local file and pushes it to a remote HTTPS destination:

```bash
curl -sk --cert /tmp/x509up_u$(id -u) --key /tmp/x509up_u$(id -u) \
  -X COPY \
  -H "Credential: none" \
  -H "Destination: https://remote-dest.example.org:8443//store/output.dat" \
  https://source.example.org:8443//store/input.dat
```

The source server invokes `curl --upload-file` to perform a standard HTTP `PUT` to the destination. Service X.509 credentials configured via `xrootd_webdav_tpc_cert/key` are used for the outbound request. `TransferHeader*` headers are forwarded as described in the pull section.

---

## HTTP-TPC pull

With `xrootd_webdav_tpc on`, this module accepts the WLCG-style WebDAV `COPY` pull shape:

```bash
curl -sk --cert /tmp/x509up_u$(id -u) --key /tmp/x509up_u$(id -u) \
  --capath /etc/grid-security/certificates \
  -X COPY \
  -H "Credential: none" \
  -H "Source: https://source.example.org:8443//store/input.dat" \
  https://dest.example.org:8443//store/output.dat
```

### COPY (RFC 4918 §9.8)

Server-side copy within the same export root.
- **`Depth: 0`**: Shallow copy (creates the directory at the destination, but does not copy its members).
- **`Depth: infinity`** (default): Recursive copy of the entire collection.
- **`Overwrite: T`** (default): Replaces the destination if it exists. If the destination is a collection, it is fully replaced.
- **Lock Enforcement**: If the destination exists and is being overwritten, a recursive lock check is performed. The operation will fail with `423 Locked` if the destination or any of its children are locked by another user.
- **Efficiency**: Uses `copy_file_range(2)` for intra-kernel zero-copy on supported filesystems (XFS, ext4 with reflink), falling back to a pread/write loop.
- **Atomic Destination**: The copy is written to a temporary path and renamed into place on success.
- **Properties**: All XRootD-mapped extended attributes (`user.U.*`) are preserved during the copy.

The server writes to a temporary file next to the destination and then renames it into place after `curl` succeeds. `Overwrite: F` fails with HTTP 412 if the destination exists; the default is overwrite (`Overwrite: T`).

`TransferHeader*` request headers are forwarded to the source request without the prefix. For example, `TransferHeaderAuthorization: Bearer <token>` becomes `Authorization: Bearer <token>` in the outbound source request.

### Credential header and OAuth2/OIDC delegation

The `Credential:` header selects how the server authenticates to the remote
source (pull) or destination (push). Three modes are supported:

| Value | Behaviour |
|---|---|
| `none` | No delegation. The server uses X.509 credentials configured via
`xrootd_webdav_tpc_cert`/`xrootd_webdav_tpc_key` (or the default service
certificate) for the outbound HTTPS request. |
| `oidc-agent` | The server contacts a local `oidc-agent` daemon via its
UNIX socket to obtain an access token, then injects it as an
`Authorization: Bearer` header into the outbound request. The socket path
defaults to `/run/user/1000/oidc/oidc_agent.sock`; override it with the
`OIDC_SOCK` environment variable. |
| `token-exchange` | The server performs an RFC 8693 token-exchange request to
the OAuth2 token endpoint configured via
`xrootd_webdav_tpc_token_endpoint`. The client's session JWT (from the
`Authorization:` header of the original COPY request) is used as the
subject token. Requires `xrootd_webdav_tpc_token_endpoint` to be set;
optional `xrootd_webdav_tpc_token_client_id` and
`xrootd_webdav_tpc_token_client_secret` for confidential clients. |

Unknown or empty `Credential:` values are rejected with HTTP 400.

**Pull with token-exchange delegation:**

```bash
curl -sk --cert /tmp/x509up_u$(id -u) --key /tmp/x509up_u$(id -u) \
  --capath /etc/grid-security/certificates \
  -X COPY \
  -H "Credential: token-exchange" \
  -H "Authorization: Bearer <session-jwt>" \
  -H "Source: https://source.example.org:8443//store/input.dat" \
  https://dest.example.org:8443//store/output.dat
```

**Push with oidc-agent delegation:**

```bash
curl -sk --cert /tmp/x509up_u$(id -u) --key /tmp/x509up_u$(id -u) \
  -X COPY \
  -H "Credential: oidc-agent" \
  -H "Destination: https://remote-dest.example.org:8443//store/output.dat" \
  https://source.example.org:8443//store/input.dat
```

**Configuration for token-exchange mode:**

```nginx
location / {
    xrootd_webdav              on;
    xrootd_webdav_root         /data;
    xrootd_webdav_allow_write  on;
    xrootd_webdav_tpc          on;

    # OAuth2/OIDC token delegation for TPC
    xrootd_webdav_tpc_token_endpoint https://idp.example.com/oauth2/token;
    xrootd_webdav_tpc_token_client_id  nginx-xrootd;
    xrootd_webdav_tpc_token_client_secret abc123secret;
    xrootd_webdav_tpc_token_scope      storage.read;
}
```

The `xrootd_webdav_tpc_token_scope` directive sets the scope string requested
during token exchange (default: `storage.read`).

Native `root://` third-party copy is not the same protocol. The stream module
has a destination-side pull path for write opens carrying `tpc.src=root://...`
opaque parameters. The pull worker runs through the configured thread pool and
can complete ztn or GSI outbound auth after `kXR_authmore` when configured
(`xrootd_tpc_outbound_bearer_file`, or the server certificate/key for GSI).
Remaining native TPC caveats are source-side `kXR_gotoTLS` and multihop
delegation, which are still narrower than the full upstream rendezvous surface.

---

## Testing with xrdcp

With the official XRootD client, the `davs://` URL scheme requires the
`XrdClHttp` plugin (`libXrdClHttp-5.so`), which ships with full xrootd builds but
may be absent from client-only packages. The in-tree `client/xrdcp` has a direct
WebDAV/HTTP path and does not use this plugin:

```bash
# Check whether the plugin is available
ls $(xrdcp --version 2>&1 | awk '/^v/{print "/usr/lib64"}')/*XrdClHttp* 2>/dev/null \
  || echo "XrdClHttp plugin not installed"

# Upload
X509_USER_PROXY=/path/to/proxy_cert.pem \
  xrdcp --allow-http /local/file.txt davs://host:8443//file.txt

# Download
X509_USER_PROXY=/path/to/proxy_cert.pem \
  xrdcp --allow-http davs://host:8443//file.txt /local/copy.txt

# Same endpoint with the in-tree native client
client/xrdcp /local/file.txt davs://host:8443//file.txt
```

Set `X509_CERT_DIR` to your CA hash directory if the proxy's issuer CA is not in the system default location.

---

## Relationship to the native XRootD protocol

The WebDAV and native `root://` modules are independent; you can run both on the same nginx instance. They share the same `xrootd_root` / `xrootd_webdav_root` filesystem path if you want clients to access the same data via either protocol:

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_root /data;
        xrootd_auth gsi;
        # ... GSI cert directives ...
    }
}

http {
    server {
        listen 8443 ssl;
        # ... TLS directives ...
        location / {
            xrootd_webdav      on;
            xrootd_webdav_root /data;   # same data directory
            xrootd_webdav_auth optional;
        }
    }
}
```
