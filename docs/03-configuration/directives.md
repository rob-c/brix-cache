# Configuration directive reference

Reference for the most commonly-used `xrootd_*` directives — name, context, type, default, and what each one actually does. For a single-table summary of the most-used directives, see [quick-reference.md](quick-reference.md). Some advanced features (health checks, traffic mirroring, rate limiting) are not yet covered in detail here.

[← Configuration overview](config-reference.md)

## Directives

### `xrootd on|off`

**Required.** Enables the XRootD protocol handler for this server block.

```nginx
stream {
    server {
        listen 1094;
        xrootd on;       # ← this activates the module
        xrootd_root /data;
    }
}
```

Without `xrootd on`, nginx ignores all other `xrootd_*` directives in the block.

---

### `xrootd_root <path>`

**Default:** `/`

The filesystem directory that clients see as their root (`/`). Every path a client requests is resolved relative to this directory. Paths that try to escape using `..` or symlinks are rejected.

```nginx
xrootd_root /data/store;   # clients see /data/store as "/"
```

A client requesting `/mc/sample.root` gets `/data/store/mc/sample.root` on disk.

---

### `xrootd_allow_write on|off`

**Default:** `off`

Whether clients may write, delete, rename, or create directories. Off by default so read-only servers are safe without any extra configuration.

Write operations that require this flag: `kXR_pgwrite`, `kXR_write`, `kXR_sync`, `kXR_truncate`, `kXR_mkdir`, `kXR_rmdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`. A write request to a server where this is `off` returns `kXR_fsReadOnly`.

```nginx
xrootd_allow_write on;   # allow uploads and deletes
```

---

### `xrootd_auth none|gsi|token|both`

**Default:** `none`

Authentication mode:

- `none` — accept any username, no credentials required
- `gsi` — require a valid x509 proxy certificate (see [Authentication](../06-authentication/auth-overview.md))
- `token` — require a valid WLCG/JWT bearer token using the `ztn` security protocol
- `both` — accept either GSI or bearer-token credentials on the same listener

```nginx
xrootd_auth gsi;
```

---

### `xrootd_tls on|off`

**Default:** `off`

Enables XRootD's in-protocol TLS upgrade on a normal `root://` listener. When a
client advertises `kXR_ableTLS`, the server replies with `kXR_haveTLS` and
upgrades the same TCP connection to TLS before `kXR_login` / `kXR_auth`
continue.

Requires `xrootd_certificate` and `xrootd_certificate_key`.

Use this on a plain `listen 1094;` style listener. Do not combine it with
`listen ... ssl` on the same stream server; that `roots://` mode is already
encrypted from the first byte. Full details: [tls.md](tls-config.md).

```nginx
server {
    listen 1095;
    xrootd on;
    xrootd_root /data;
    xrootd_auth gsi;
    xrootd_certificate     /etc/grid-security/hostcert.pem;
    xrootd_certificate_key /etc/grid-security/hostkey.pem;
    xrootd_trusted_ca      /etc/grid-security/certificates/ca.pem;
    xrootd_tls on;
}
```

---

### `xrootd_certificate <path>`

Path to the server's PEM certificate file. Required when `xrootd_auth gsi` or `xrootd_auth both`.

```nginx
xrootd_certificate /etc/grid-security/hostcert.pem;
```

---

### `xrootd_certificate_key <path>`

Path to the server's PEM private key file. Required when `xrootd_auth gsi` or `xrootd_auth both`.

```nginx
xrootd_certificate_key /etc/grid-security/hostkey.pem;
```

---

### `xrootd_trusted_ca <path>`

Path to a PEM file containing the CA certificate (or bundle of CA certificates) that the server trusts for verifying client proxy certificates. Required when `xrootd_auth gsi` or `xrootd_auth both`.

See [pki.md](../06-authentication/pki-config.md) for CA bundle layout and hash symlink setup.

```nginx
xrootd_trusted_ca /etc/grid-security/certificates/ca.pem;
```

---

### `xrootd_crl <path>`

Path to a PEM CRL file or a directory containing CRLs. Directory mode scans `*.pem` and grid-style `*.r0` through `*.r9` files. When configured, GSI verification enables OpenSSL CRL checks for the full certificate chain.

See [pki.md](../06-authentication/pki-config.md) for CRL distribution point conventions and hash symlinks.

```nginx
xrootd_crl /etc/grid-security/certificates;
```

---

### `xrootd_crl_reload <seconds>`

**Default:** `0` (disabled)

How often each worker reloads `xrootd_crl` and rebuilds its GSI trust store. A failed reload keeps the previous store in place.

```nginx
xrootd_crl_reload 300;  # reload CRLs every five minutes
```

---

### `xrootd_token_jwks <path>`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation. Used when `xrootd_auth token` or `xrootd_auth both` is configured.

```nginx
xrootd_token_jwks /etc/tokens/jwks.json;
```

---

### `xrootd_token_issuer <string>`

Expected JWT `iss` claim. Tokens from other issuers are rejected.

```nginx
xrootd_token_issuer "https://idp.example.com";
```

---

### `xrootd_token_audience <string>`

Expected JWT `aud` claim. Tokens for other services are rejected.

```nginx
xrootd_token_audience "my-storage";
```

---

### `xrootd_access_log <path>|off`

**Default:** `off`

File path for the per-request access log. One line is written per operation. See [Metrics & logging](../08-metrics-monitoring/monitoring-guide.md) for the log format and examples.

```nginx
xrootd_access_log /var/log/nginx/xrootd_access.log;
```

The file is opened `O_APPEND` so it is safe to share across multiple nginx worker processes. Rotate with `kill -USR1 $(cat /run/nginx.pid)`.

---

### `xrootd_dashboard on|off`

**Context:** HTTP `location`

**Default:** `off`

Enables the HTTPS monitoring dashboard on the HTTP `/xrootd/` location. The
dashboard serves an embedded browser page and a JSON snapshot endpoint. Use it
for live operator checks; keep Prometheus scraping `/metrics` for long-term
metrics storage.

```nginx
server {
    listen 8443 ssl;

    location /xrootd/ {
        xrootd_dashboard on;
        xrootd_dashboard_password "change-me";
    }
}
```

The page is available at `/xrootd/`, the login form at `/xrootd/login`, and the
compatibility JSON endpoint at `/xrootd/transfers`. Versioned JSON is available
under `/xrootd/api/v1/`, including `/snapshot`, `/transfers`, `/events`,
`/history`, `/cache`, and `/cluster`. Serve this location only over TLS and
restrict it to an admin network because it exposes active file paths, client
addresses, and authenticated identities. See
[Metrics & logging](../08-metrics-monitoring/monitoring-guide.md#https-monitoring-dashboard)
for the full dashboard setup.

---

### `xrootd_dashboard_password <string>`

**Context:** HTTP `location`

**Default:** unset

Password required by the HTTPS monitoring dashboard login form.

```nginx
xrootd_dashboard_password "change-me";
```

Always set this directive in production. If it is omitted, the dashboard
location is treated as unauthenticated. The session cookie is marked `Secure`,
`HttpOnly`, and `SameSite=Strict`.

---

### `xrootd_dashboard_session_ttl <time>`

**Context:** HTTP `location`

**Default:** `8h`

Controls the signed dashboard session cookie lifetime. Values use nginx time
syntax.

```nginx
xrootd_dashboard_session_ttl 4h;
```

---

### `xrootd_dashboard_cookie_path <path>`

**Context:** HTTP `location`

**Default:** `/xrootd`

Sets the `Path` attribute on the dashboard session cookie. The value must be a
non-empty absolute path and cannot contain control characters or semicolons.

```nginx
xrootd_dashboard_cookie_path /xrootd;
```

---

### `xrootd_dashboard_idle_threshold <time>`

**Context:** HTTP `location`

**Default:** `5s`

Marks an active dashboard row as `idle` when no bytes have moved for this
duration.

```nginx
xrootd_dashboard_idle_threshold 5s;
```

---

### `xrootd_dashboard_stalled_threshold <time>`

**Context:** HTTP `location`

**Default:** `60s`

Marks an active dashboard row as `stalled` when no bytes have moved for this
duration. The value must be greater than or equal to
`xrootd_dashboard_idle_threshold`.

```nginx
xrootd_dashboard_stalled_threshold 60s;
```

---

### `xrootd_dashboard_cluster_stale_after <time>`

**Context:** HTTP `location`

**Default:** `90s`

Marks manager registry entries as stale in `/xrootd/api/v1/cluster` and the
dashboard cluster panel when their heartbeat age exceeds this duration.

```nginx
xrootd_dashboard_cluster_stale_after 90s;
```

---

### `xrootd_dashboard_users <path>`

**Context:** HTTP `location`

**Default:** unset

Loads an htpasswd-like users file for named dashboard operators. Each readable,
non-comment line has the form `username:password-hash`; system `crypt(3)` hashes
are accepted, and plaintext entries are supported for development fixtures. This
directive cannot be used together with `xrootd_dashboard_password`.

```nginx
xrootd_dashboard_users /etc/nginx/xrootd-dashboard.htpasswd;
```

The file is read during nginx config validation/startup. Dashboard audit events
record login success and failure by username, but never record passwords or
cookie values.

---

### `xrootd_thread_pool <name>`

**Default:** `default`

Name of the nginx thread pool used for async file I/O (reads and writes). Must match a `thread_pool` directive at the main config level (outside `stream {}`).

If the named pool does not exist, the module falls back to synchronous I/O and logs a notice. Synchronous I/O means a slow read blocks all other connections on the same worker process — fine for development, not for production. Read-through cache mode is stricter: `xrootd_cache on` requires a working thread pool because cache fills perform network and disk I/O.

```nginx
# At the top of nginx.conf, outside stream {}
thread_pool xrootd_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_thread_pool xrootd_io;
    }
}
```

How many threads to use: a good starting point is one thread per disk spindle, or 4–8 for NVMe/SSD. The `max_queue` value caps how many pending I/O tasks can queue up before new requests start returning errors.

---

### `xrootd_ckscan_depth <n>`

**Default:** `32`

Maximum directory recursion depth for a single `kXR_Qckscan` request. Entries
below this depth are skipped without failing the scan.

```nginx
xrootd_ckscan_depth 32;
```

---

### `xrootd_ckscan_max_files <n>`

**Default:** `100000`

Maximum number of regular files returned by a single `kXR_Qckscan` request.
Additional files are skipped once the limit is reached.

```nginx
xrootd_ckscan_max_files 100000;
```

---

### `xrootd_vomsdir <path>`

Path to the directory containing VOMS server information (`.lsc` files), one per VO. Required when `xrootd_require_vo` is used. Requires `libvomsapi.so.1` at runtime (install `voms-libs` on EL9 or `libvomsapi1` on Debian/Ubuntu).

```nginx
xrootd_vomsdir /etc/voms;
```

---

### `xrootd_voms_cert_dir <path>`

Path to the hashed CA certificate directory used for verifying VOMS attribute certificates. Required when `xrootd_require_vo` is used.

```nginx
xrootd_voms_cert_dir /etc/grid-security/certificates;
```

---

### `xrootd_require_vo <path> <vo>`

Restricts access to `<path>` (and all descendants) to clients whose VO list includes `<vo>`. For GSI, the VO list comes from VOMS proxy attributes. For token authentication, `wlcg.groups` claims are mapped into the same VO list. Can be specified multiple times for different paths.

`xrootd_auth gsi`, `xrootd_auth token`, or `xrootd_auth both` must be enabled, and `libvomsapi.so.1` must be available at runtime. The directive also requires `xrootd_vomsdir` and `xrootd_voms_cert_dir` because the same ACL machinery is used for GSI and token groups.

```nginx
xrootd_require_vo /atlas atlas;   # only ATLAS members can access /atlas
xrootd_require_vo /cms   cms;     # only CMS members can access /cms
```

If a GSI client has no VOMS extensions, or a token client has no matching `wlcg.groups`, the VO list is empty and access to protected paths is denied.

---

### `xrootd_inherit_parent_group <path>`

When a file or directory is created under `<path>`, nginx automatically adjusts its GID and group permission bits to match the parent directory. This mimics the Linux `setgid` bit at the application layer, which is useful when the backing filesystem (e.g. CephFS) does not reliably propagate `setgid` across mounts.

```nginx
xrootd_inherit_parent_group /cms;   # keep /cms/* group-owned by cms group
```

What happens on each create:
- **File**: GID set to parent GID; group read/write bits copied from parent; group execute preserved if already set.
- **Directory**: GID set to parent GID; group rwx bits copied from parent; `S_ISGID` added if the parent has it.
- **Recursive mkdir (`kXR_mkdirpath`)**: policy applied to each newly created directory level.

---

### `xrootd_manager_map /prefix host:port`

Map requests for a path prefix to an external manager/redirector endpoint. When a `locate` or `open` request matches a configured prefix the server replies with an XRootD `kXR_redirect` (status `4004`). The redirect body format is a 4-byte big-endian port followed by the host name bytes (ASCII). Lookups use longest-prefix matching; prefixes are normalized by the module before comparison.

The `host:port` value may be an IPv4 address or an IPv6 literal using bracket notation (for example: `[::1]:1234`). See [Manager Mode](../05-operations/manager-mode.md) for full semantics and examples.

```nginx
xrootd_manager_map /maps backend.example.org:54321;
```

---

### `xrootd_upstream host:port`

Configures an upstream XRootD redirector to forward requests to when no local `xrootd_manager_map` prefix matches. The module connects to the specified host:port, performs a minimal XRootD handshake, and relays the client request (currently `kXR_locate`, `kXR_open`, and `kXR_stat`). Upstream responses are forwarded verbatim:

- `kXR_redirect` — forwarded to the client as-is
- `kXR_wait` — timer is scheduled; the request is retried after the specified delay (capped at 60 s)
- `kXR_waitresp` — forwarded to the client; the upstream sends an unsolicited reply when ready
- `kXR_ok` / `kXR_error` — forwarded to the client

Used together with `xrootd_manager_map` to build a two-tier topology: static prefix rules handle known paths, and the catch-all upstream handles anything else.

```nginx
xrootd_upstream redirector.example.org:1094;
```

---

### `xrootd_cache on|off`

**Default:** `off`

Enables read-through cache mode for native `root://` opens. In this mode, read opens are served from `xrootd_cache_root`. If the requested file is missing, nginx fetches the whole file from `xrootd_cache_origin` into a temporary part file, atomically renames it into place, and then opens the cached copy for the client.

Cache mode is currently direct-mode and defaults to read-only:
- A working nginx thread pool is required.
- The origin fetch is anonymous; authenticated origin fetches are not implemented.
- The origin should be a data server. Redirect-following is not implemented for cache fills.
- Files are cached as whole files. Partial-file/range caching is not implemented.
- Cache eviction is best-effort and runs during cache fills when filesystem occupancy is above `xrootd_cache_eviction_threshold`.
- **Write-through mode** (optional): When enabled via `xrootd_write_through on`, dirty write handles are mirrored to an origin data server on `kXR_sync` or `kXR_close`.

### `xrootd_write_through on|off`

**Default:** `off`

Enables write-through behavior for native XRootD writes. When this is `on`, write-mode `kXR_open` requests are evaluated by the WT decision policy and eligible handles are mirrored to an origin server.

In this mode:
1.  **Open**: The module opens the local file and caches the WT allow/deny decision on the handle.
2.  **Write**: `kXR_write`, `kXR_pgwrite`, `kXR_writev`, and handle-based `kXR_truncate` update the local file and mark the handle dirty.
3.  **Sync**: `kXR_sync` mirrors the full local file to the WT origin, then sends origin truncate and sync. Origin failures are returned to the client.
4.  **Close**: Dirty handles are flushed on close. `sync` mode blocks during close; `async` mode posts the flush to the configured nginx thread pool. Close-time origin failures are logged but do not fail the close response.

> **Note:** Write-through mode uses whole-file replacement at sync/close, not per-write dual dispatch. It is a good fit for ingest-style workflows and less suitable for very large random-write workloads.

```nginx
thread_pool xrootd_cache_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;                # namespace used for ACL matching
        xrootd_cache on;
        xrootd_cache_root /var/cache/xrootd;
        xrootd_cache_origin origin.example.org:1094;
        xrootd_cache_eviction_threshold 0.9;
        xrootd_thread_pool xrootd_cache_io;

        xrootd_write_through on;
        xrootd_wt_mode sync;                  # sync | async
        xrootd_wt_origin origin.example.org:1094;
        xrootd_wt_allow_prefix /data/ingest/;
        xrootd_wt_deny_prefix /data/private/;
    }
}
```

### `xrootd_wt_mode sync|async`

**Default:** `sync`

Controls close-time WT flush behavior. `sync` mirrors dirty data before
`kXR_close` completes. `async` posts the mirror operation to the configured
thread pool and releases the handle immediately. Explicit `kXR_sync` requests
always flush synchronously.

### `xrootd_wt_origin <host:port>`

Sets the WT origin data server. If omitted, write-through uses
`xrootd_cache_origin` when that origin is configured.

### `xrootd_wt_allow_prefix <path>` / `xrootd_wt_deny_prefix <path>`

Repeatable WT policy filters. Deny prefixes take precedence over allow
prefixes. If one or more allow prefixes are configured, paths that match none
of them are treated as local-only writes.

---

### `xrootd_cache_root <path>`

Local directory used to store cached files. Client paths map directly under this directory, so a request for `/store/a.root` becomes `/var/cache/xrootd/store/a.root` when `xrootd_cache_root /var/cache/xrootd;` is configured. The directory must exist and be readable, writable, and searchable by nginx at startup.

```nginx
xrootd_cache_root /var/cache/xrootd;
```

---

### `xrootd_cache_origin host:port`

Origin data server used for cache misses. The value may be plain `host:port`, `root://host:port`, or `roots://host:port`. `roots://` enables direct TLS for the outbound origin connection.

```nginx
xrootd_cache_origin root://origin.example.org:1094;
xrootd_cache_origin roots://origin.example.org:1095;
```

When outbound TLS is enabled, nginx verifies the origin certificate using `xrootd_trusted_ca` if configured, otherwise OpenSSL's default trust paths.

---

### `xrootd_cache_origin_tls on|off`

**Default:** `off` unless `xrootd_cache_origin` uses `roots://`

Enables TLS from the first byte on the outbound cache-origin connection. This is useful when you prefer a separate `roots://` origin listener instead of cleartext `root://`.

```nginx
xrootd_cache_origin origin.example.org:1095;
xrootd_cache_origin_tls on;
```

---

### `xrootd_cache_lock_timeout <time>`

**Default:** `300s`

How long a worker waits for another worker's in-progress fill of the same file. Cache fills use per-file `O_EXCL` lock files under the cache directory, so concurrent opens of the same missing path collapse to one origin transfer.

```nginx
xrootd_cache_lock_timeout 120s;
```

---

### `xrootd_cache_eviction_threshold <ratio|percent>`

**Default:** `0.9`

High-water filesystem occupancy threshold for cache eviction. When a cache fill sees `xrootd_cache_root` above this ratio, one worker takes a cache-wide eviction lock and unlinks the oldest regular cached files until occupancy drops back to the threshold or no candidates remain.

The value may be written as a ratio (`0.85`) or a percent (`85` or `85%`). Temporary part files, fill lock files, the eviction lock, files on a different filesystem, and the file currently being filled are skipped.

```nginx
xrootd_cache_eviction_threshold 0.85;
```

---

### `xrootd_cms_manager host:port`

Registers this data server with an XRootD CMS manager and starts a per-worker
heartbeat connection. The manager address is resolved during config parsing.

```nginx
xrootd_cms_manager cms-manager.example.org:1213;
xrootd_cms_paths /store;
xrootd_cms_interval 30s;
```

### `xrootd_cms_paths <string>`

**Default:** `xrootd_root`

Path string advertised in the CMS login packet. Use this when the exported CMS
namespace differs from the local filesystem root.

### `xrootd_cms_interval <time>`

**Default:** `30s`

How often each worker sends CMS load/availability heartbeats after registration.

---

### `xrootd_manager_mode on|off`

**Default:** `off`

Enables dynamic server registry queries on this XRootD listener. When on, `kXR_locate` and `kXR_open` requests are answered with `kXR_redirect` to whichever registered data server best matches the requested path (lowest utilisation for reads, most free space for writes). The server also advertises the `kXR_isManager` capability bit in `kXR_protocol` responses.

Requires a companion `xrootd_cms_server on;` listener (typically on port 1213) to receive data server registrations. The registry is a 128-slot shared-memory table populated by the CMS server when data servers connect and send login frames.

See [cluster-mode.md](../05-operations/cluster-management.md) for the full two-tier and three-tier cluster configuration.

```nginx
stream {
    server {
        listen 1213;
        xrootd_cms_server on;
    }
    server {
        listen 1094;
        xrootd on;
        xrootd_root /dev/null;      # redirector has no local storage
        xrootd_manager_mode on;
    }
}
```

---

### `xrootd_cms_server on|off`

**Default:** `off`

Enables a CMS management-protocol server on this stream listener. When on, the listener accepts incoming TCP connections from data servers, parses CMS login and heartbeat frames, and maintains the shared server registry used by `xrootd_manager_mode`.

This directive is used on a dedicated management port (default 1213), not on the XRootD data port.

| CMS frame | Action |
|---|---|
| `kYR_login` | Register server: host, port, path list, free space, utilisation |
| `kYR_avail` / `kYR_load` / `kYR_space` | Update load metrics |
| `kYR_pong` | Update last-seen timestamp |
| Disconnect | Unregister server from registry |

```nginx
stream {
    server {
        listen 1213;
        xrootd_cms_server on;
    }
}
```

---

## Proxy mode directives

These directives configure transparent XRootD proxy mode, in which a stream
listener forwards `root://` client requests to one or more upstream XRootD data
servers or redirectors. All proxy directives are `server`-context (stream
`server {}` block). Defaults below match `src/stream/module.c`.

### `xrootd_proxy on|off`

**Default:** `off`

Enables transparent XRootD proxy mode for this stream server. Requires at least
one `xrootd_proxy_upstream`.

### `xrootd_proxy_upstream host[:port] [auth]`

Upstream XRootD data server or redirector. May appear multiple times for
round-robin load balancing. The optional second argument overrides
`xrootd_proxy_auth` for this upstream only.

### `xrootd_proxy_upstream_tls on|off`

**Default:** `off`

Wraps the outbound upstream connection in TLS from the first byte.

### `xrootd_proxy_upstream_tls_ca <path>`

PEM CA bundle used to verify the upstream TLS certificate (enables peer
verification).

### `xrootd_proxy_upstream_tls_name <host>`

SNI hostname presented on the upstream TLS connection. Defaults to the
`xrootd_proxy_upstream` host.

### `xrootd_proxy_auth <mode>`

**Default:** `anonymous`

Auth bridging mode for upstream connections (for example `anonymous`, `forward`,
or `sss`). `forward` replays the client bearer token; `sss` builds an SSS
credential from the configured key.

### `xrootd_proxy_login_user <string>`

Overrides the username placed in the upstream `kXR_login` frame.

### `xrootd_proxy_audit_log <path>|off`

**Default:** `off`

Writes one JSON line per closed or abandoned upstream file handle.

### `xrootd_proxy_reconnect_attempts <n>`

**Default:** `0`

Reconnect budget per client session when an idle upstream connection drops with
no open handles.

### `xrootd_proxy_connect_timeout <ms>`

**Default:** `10000`

Milliseconds allowed for the TCP connect to the upstream. `0` disables the
limit.

### `xrootd_proxy_read_timeout <ms>`

**Default:** `60000`

Milliseconds allowed between upstream response bytes. `0` disables the limit.

### `xrootd_proxy_keepalive_interval <ms>`

Idle keepalive interval for upstream connections.

### `xrootd_proxy_path_rewrite <strip> <add>`

Strips a leading prefix from open/path requests, then prepends `add` (for
example `xrootd_proxy_path_rewrite /xrootd /data`).
