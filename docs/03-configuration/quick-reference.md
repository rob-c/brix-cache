# Configuration quick reference

The most-used directives on one page. Start here when you know what you want to configure but can't remember the exact directive name.

[← Configuration overview](config-reference.md)

## XRootD stream directive summary

| Directive | Context | Default | Required? |
|---|---|---|---|
| `xrootd on\|off` | `server` (stream) | `off` | Yes |
| `xrootd_root <path>` | `server` | `/` | Recommended |
| `xrootd_allow_write on\|off` | `server` | `off` | No |
| `xrootd_auth none\|gsi\|token\|both` | `server` | `none` | No |
| `xrootd_frm on\|off` | `server` | `off` | Enable the FRM durable tape-staging queue behind `kXR_prepare`/`kXR_QPrep` (Phase 35, `src/frm/`) |
| `xrootd_frm_queue_path <abs-path>` | `server` | — | Required when `xrootd_frm on`; absolute path to the durable queue file (the `.lock` sidecar lives beside it). The crash-safe source of truth. |
| `xrootd_frm_max_inflight <N>` | `server` | `64` | Admission cap on live (queued + staging) requests |
| `xrootd_frm_stagecmd <cmd>` | `server` | inherits `xrootd_prepare_command` | Stage-in command (Phase 1 worker); Phase 0 records durably + the legacy command stages |
| `xrootd_frm_stage_ttl <time>` | `server` | `600s` | Hard expiry for a queue record (reaped by the worker-0 timer) |

> Additional Phase 1–4 FRM directives (`xrootd_frm_copycmd/copymax/xfrhold/fail_backoff/fail_retries/residency_cmd/copy_timeout/migrate_copycmd/purge_watermark/purge_interval`) are accepted now and activate with their phase. See [`src/frm/README.md`](../../src/frm/README.md) and [`docs/refactor/phase-35-frm-tape-staging.md`](../refactor/phase-35-frm-tape-staging.md).

| `xrootd_proxy on\|off` | `server` | `off` | Enable transparent XRootD proxy mode |
| `xrootd_proxy_upstream host[:port] [auth]` | `server` | — | Required when `xrootd_proxy on`; may appear multiple times for round-robin load balancing. Optional `auth` arg (`anonymous`, `forward`, `sss`, `sss:<keyname>`) overrides server-level `xrootd_proxy_auth` for this upstream |
| `xrootd_proxy_upstream_tls on\|off` | `server` | `off` | Wrap outbound upstream TCP in TLS |
| `xrootd_proxy_upstream_tls_ca <path>` | `server` | — | PEM CA bundle to verify upstream TLS certificate (enables `SSL_VERIFY_PEER`) |
| `xrootd_proxy_upstream_tls_name <host>` | `server` | — | SNI hostname for upstream TLS; defaults to `xrootd_proxy_upstream` host |
| `xrootd_proxy_auth anonymous\|forward\|sss` | `server` | `anonymous` | Auth bridging: `forward` replays bearer token; `sss` builds an SSS credential from the first configured `xrootd_sss_key` |
| `xrootd_proxy_audit_log <path>\|off` | `server` | `off` | One JSON line per closed/abandoned upstream file handle |
| `xrootd_proxy_reconnect_attempts <n>` | `server` | `0` | Reconnect budget per client session when upstream drops while idle with no open handles |
| `xrootd_proxy_connect_timeout <ms>` | `server` | `10000` | Milliseconds allowed for TCP connect to upstream; 0 = no limit |
| `xrootd_proxy_read_timeout <ms>` | `server` | `60000` | Milliseconds allowed between upstream response bytes; 0 = no limit |
| `xrootd_proxy_path_rewrite <strip> <add>` | `server` | — | Strip leading prefix from open/path requests then prepend `add` (e.g. `xrootd_proxy_path_rewrite /xrootd /data`) |
| `xrootd_tls on\|off` | `server` | `off` | No |
| `xrootd_certificate <path>` | `server` | — | If `auth gsi` or `auth both` |
| `xrootd_certificate_key <path>` | `server` | — | If `auth gsi` or `auth both` |
| `xrootd_trusted_ca <path>` | `server` | — | If `auth gsi` or `auth both` |
| `xrootd_crl <path>` | `server` | — | No |
| `xrootd_crl_reload <seconds>` | `server` | `0` | No |
| `xrootd_vomsdir <path>` | `server` | — | If `require_vo` |
| `xrootd_voms_cert_dir <path>` | `server` | — | If `require_vo` |
| `xrootd_require_vo <path> <vo>` | `server` | — | No |
| `xrootd_inherit_parent_group <path>` | `server` | — | No |
| `xrootd_token_jwks <path>` | `server` | — | If `auth token` or `auth both` |
| `xrootd_token_issuer <string>` | `server` | — | If token JWKS is configured |
| `xrootd_token_audience <string>` | `server` | — | If token JWKS is configured |
| `xrootd_access_log <path>\|off` | `server` | `off` | No |
| `xrootd_thread_pool <name>` | `server` | `default` | No |
| `xrootd_ckscan_depth <n>` | `server` | `32` | Maximum recursive depth for `kXR_Qckscan` |
| `xrootd_ckscan_max_files <n>` | `server` | `100000` | Maximum regular files returned by one `kXR_Qckscan` |
| `xrootd_manager_map /prefix host:port` | `server` | — | No |
| `xrootd_upstream host:port` | `server` | — | No |
| `xrootd_cache on\|off` | `server` | `off` | No |
| `xrootd_cache_root <path>` | `server` | — | If `xrootd_cache on` |
| `xrootd_cache_origin host:port` | `server` | — | If `xrootd_cache on` |
| `xrootd_cache_origin_tls on\|off` | `server` | `off` | No |
| `xrootd_cache_lock_timeout <time>` | `server` | `300s` | No |
| `xrootd_cache_eviction_threshold <ratio\|percent>` | `server` | `0.9` | No |
| `xrootd_cms_manager host:port` | `server` | — | No |
| `xrootd_cms_paths <string>` | `server` | `xrootd_root` | No |
| `xrootd_cms_interval <time>` | `server` | `30s` | No |
| `xrootd_manager_mode on\|off` | `server` | `off` | No |
| `xrootd_cms_server on\|off` | `server` | `off` | No |

---

## Metrics directive

| Directive | Context | Default | Notes |
|---|---|---|---|
| `xrootd_metrics on\|off` | `location` (HTTP) | `off` | Activates the Prometheus text exporter for the shared metrics zone |
| `xrootd_srr on\|off` | `location` (HTTP) | `off` | Serves the WLCG Storage Resource Reporting (SRR) `storageservice` JSON document at this location (point CRIC at this URL) |
| `xrootd_srr_name <name>` | `location` (HTTP) | — | `storageservice.name` (the SE / site name); also `.id` unless `xrootd_srr_id` is set |
| `xrootd_srr_quality <level>` | `location` (HTTP) | `production` | `qualitylevel` (development/testing/pre-production/production) |
| `xrootd_srr_version <ver>` | `location` (HTTP) | `1.0` | `implementationversion` |
| `xrootd_srr_share <name> <path> [vos]` | `location` (HTTP) | — | Repeatable. One `storageshares[]` entry; `<path>` is `statvfs`'d for total/used bytes; `[vos]` = comma-separated VO list |
| `xrootd_srr_endpoint <name> <iftype> <url>` | `location` (HTTP) | — | Repeatable. One `storageendpoints[]` entry (e.g. `webdav davs https://se:8443/`) |

See [`src/protocols/srr/README.md`](../../src/protocols/srr/README.md) for the full document layout and caveats.

---

## WebDAV directives

The WebDAV module (`ngx_http_xrootd_webdav_module`) handles `davs://` clients in nginx's `http {}` context. Full documentation and examples: [webdav.md](../04-protocols/webdav-overview.md).

| Directive | Context | Default | Notes |
|---|---|---|---|
| `xrootd_webdav on\|off` | `location` | `off` | Activates WebDAV handler |
| `xrootd_webdav_root <path>` | `location` | `/` | Filesystem root for clients |
| `xrootd_webdav_auth none\|optional\|required` | `location` | `optional` | Proxy-cert or bearer-token auth policy |
| `xrootd_webdav_cadir <path>` | `location` | — | Hashed CA directory |
| `xrootd_webdav_cafile <path>` | `location` | — | Single CA PEM file |
| `xrootd_webdav_crl <path>` | `location` | — | PEM CRL file for proxy-cert revocation checks |
| `xrootd_webdav_allow_write on\|off` | `location` | `off` | Enable PUT/DELETE/MKCOL and TPC COPY writes |
| `xrootd_webdav_tpc on\|off` | `location` | `off` | Enable HTTP-TPC COPY pull support |
| `xrootd_webdav_tpc_curl <path>` | `location` | `/usr/bin/curl` | External curl helper for TPC pulls |
| `xrootd_webdav_tpc_cert <path>` | `location` | — | X.509 cert/proxy used for outbound TPC source fetches |
| `xrootd_webdav_tpc_key <path>` | `location` | `xrootd_webdav_tpc_cert` | Private key used with the TPC cert |
| `xrootd_webdav_tpc_cadir <path>` | `location` | `xrootd_webdav_cadir` | CA directory for outbound source TLS verification |
| `xrootd_webdav_tpc_cafile <path>` | `location` | `xrootd_webdav_cafile` | CA bundle for outbound source TLS verification |
| `xrootd_webdav_tpc_timeout <seconds>` | `location` | `0` | Optional curl max-time for TPC pulls |
| `xrootd_webdav_tpc_token_endpoint <url>` | `location` | — | OAuth2/OIDC token endpoint URL for RFC 8693 token-exchange delegation |
| `xrootd_webdav_tpc_token_client_id <string>` | `location` | — | OAuth2 client ID (optional, for confidential clients) |
| `xrootd_webdav_tpc_token_client_secret <string>` | `location` | — | OAuth2 client secret (optional, for confidential clients) |
| `xrootd_webdav_tpc_token_scope <string>` | `location` | `storage.read` | Scope string requested during token exchange |
| `xrootd_webdav_proxy_certs on\|off` | `server` or `location` (HTTP) | `off` | Accept RFC 3820 proxy certs |
| `xrootd_webdav_verify_depth <n>` | `location` | `10` | Proxy chain depth limit |
| `xrootd_webdav_token_jwks <path>` | `location` | — | JWKS for Bearer tokens |
| `xrootd_webdav_token_issuer <string>` | `location` | — | Expected token issuer |
| `xrootd_webdav_token_audience <string>` | `location` | — | Expected token audience |
| `xrootd_webdav_thread_pool <name>` | `location` | `default` | nginx thread pool for async WebDAV file I/O |
| `xrootd_webdav_cors_origin <origin\|*>` | `location` | — | Enable CORS for one exact origin; repeat for more origins |
| `xrootd_webdav_cors_credentials on\|off` | `location` | `off` | Add credentialed CORS response headers |
| `xrootd_webdav_cors_max_age <seconds>` | `location` | `86400` | CORS preflight cache duration |
| `xrootd_webdav_lock_timeout <seconds>` | `location` | `600` | Maximum WebDAV lock duration |
| `xrootd_webdav_lock_startup_sweep on\|off` | `main`/`server`/`location` | `off` | Clear persisted lock xattrs under the export root at startup (ephemeral locks) |
| `xrootd_webdav_proxy on\|off` | `location` | `off` | Forward all WebDAV requests (after auth) to an upstream HTTP/HTTPS server |
| `xrootd_webdav_proxy_upstream <url>` | `location` | — | Required when proxy on; `http://` or `https://` base URL of the backend |
| `xrootd_webdav_proxy_auth anonymous\|forward\|token <val>` | `location` | `anonymous` | Auth forwarding policy: strip Authorization / pass through / replace with static Bearer token |
| `xrootd_webdav_proxy_connect_timeout <time>` | `location` | — | TCP connect timeout to upstream |
| `xrootd_webdav_proxy_send_timeout <time>` | `location` | — | Idle send timeout to upstream |
| `xrootd_webdav_proxy_read_timeout <time>` | `location` | — | Idle read timeout from upstream |

---

## S3-compatible HTTP directives

The S3 module (`ngx_http_xrootd_s3_module`) handles path-style S3-compatible
requests in nginx's `http {}` context. It is a small filesystem-backed subset
for XrdClS3-style clients, not a full AWS S3 implementation.

**S3 API compliance:** all known gaps have been resolved. `PutObject` now returns an `ETag` header on every successful PUT, and `ListObjectsV2` on an unknown bucket returns `404` with `NoSuchBucket` XML.

| Directive | Context | Default | Notes |
|---|---|---|---|
| `xrootd_s3 on\|off` | `location` | `off` | Activates the S3-compatible handler for this location |
| `xrootd_s3_root <path>` | `location` | `""` | Required when enabled; canonicalized during config merge |
| `xrootd_s3_bucket <name>` | `location` | `""` | Optional path-style bucket name to strip from request URIs |
| `xrootd_s3_access_key <key>` | `location` | `""` | Enables SigV4 auth when set; empty means anonymous access |
| `xrootd_s3_secret_key <secret>` | `location` | `""` | Secret used to verify SigV4 requests |
| `xrootd_s3_region <name>` | `location` | `us-east-1` | Region string expected in the SigV4 credential scope |
| `xrootd_s3_allow_write on\|off` | `location` | `off` | Enables PUT and DELETE |
| `xrootd_s3_max_keys <n>` | `location` | `1000` | Maximum ListObjectsV2 keys returned per response page |

Example:

```nginx
http {
    server {
        listen 9001;

        location / {
            xrootd_s3 on;
            xrootd_s3_root /data/store;
            xrootd_s3_bucket testbucket;
            xrootd_s3_allow_write on;
        }
    }
}
```
