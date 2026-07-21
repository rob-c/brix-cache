# Configuration quick reference

The most-used directives on one page. Start here when you know what you want to configure but can't remember the exact directive name.

[← Configuration overview](config-reference.md)

## XRootD stream directive summary

| Directive | Context | Default | Required? |
|---|---|---|---|
| `brix_root on\|off` | `server` (stream) | `off` | Yes |
| `brix_export <path>` | `server` | `/` | Recommended |
| `brix_allow_write on\|off` | `server` | `off` | No |
| `brix_auth none\|gsi\|token\|both` | `server` | `none` | No |
| `brix_frm on\|off` | `server` | `off` | Enable the FRM durable tape-staging queue behind `kXR_prepare`/`kXR_QPrep` (`src/fs/xfer/` stage engine) |
| `brix_frm_queue_path <abs-path>` | `server` | — | Required when `brix_frm on`; absolute path to the durable queue file (the `.lock` sidecar lives beside it). The crash-safe source of truth. |
| `brix_frm_max_inflight <N>` | `server` | `64` | Admission cap on live (queued + staging) requests |
| `brix_frm_stagecmd <cmd>` | `server` | inherits `brix_prepare_command` | Stage-in command (Phase 1 worker); Phase 0 records durably + the legacy command stages |
| `brix_frm_stage_ttl <time>` | `server` | `600s` | Hard expiry for a queue record (reaped by the worker-0 timer) |

> Additional Phase 1–4 FRM directives (`brix_frm_copycmd/copymax/xfrhold/fail_backoff/fail_retries/residency_cmd/copy_timeout/migrate_copycmd/purge_watermark/purge_interval`) are accepted now and activate with their phase. See [`src/fs/xfer/README.md`](../../src/fs/xfer/README.md) and [`docs/refactor/phase-35-frm-tape-staging.md`](../refactor/phase-35-frm-tape-staging.md).

| `brix_proxy on\|off` | `server` | `off` | Enable transparent XRootD proxy mode |
| `brix_proxy_upstream host[:port] [auth]` | `server` | — | Required when `brix_proxy on`; may appear multiple times for round-robin load balancing. Optional `auth` arg (`anonymous`, `forward`, `sss`, `sss:<keyname>`) overrides server-level `brix_proxy_auth` for this upstream |
| `brix_proxy_upstream_tls on\|off` | `server` | `off` | Wrap outbound upstream TCP in TLS |
| `brix_proxy_upstream_tls_ca <path>` | `server` | — | PEM CA bundle to verify upstream TLS certificate (enables `SSL_VERIFY_PEER`) |
| `brix_proxy_upstream_tls_name <host>` | `server` | — | SNI hostname for upstream TLS; defaults to `brix_proxy_upstream` host |
| `brix_proxy_auth anonymous\|forward\|sss` | `server` | `anonymous` | Auth bridging: `forward` replays bearer token; `sss` builds an SSS credential from the first configured `brix_sss_key` |
| `brix_proxy_audit_log <path>\|off` | `server` | `off` | One JSON line per closed/abandoned upstream file handle |
| `brix_proxy_reconnect_attempts <n>` | `server` | `0` | Reconnect budget per client session when upstream drops while idle with no open handles |
| `brix_proxy_connect_timeout <ms>` | `server` | `10000` | Milliseconds allowed for TCP connect to upstream; 0 = no limit |
| `brix_proxy_read_timeout <ms>` | `server` | `60000` | Milliseconds allowed between upstream response bytes; 0 = no limit |
| `brix_proxy_path_rewrite <strip> <add>` | `server` | — | Strip leading prefix from open/path requests then prepend `add` (e.g. `brix_proxy_path_rewrite /brix /data`) |
| `brix_tls on\|off` | `server` | `off` | No |
| `brix_certificate <path>` | `server` | — | If `auth gsi` or `auth both` |
| `brix_certificate_key <path>` | `server` | — | If `auth gsi` or `auth both` |
| `brix_trusted_ca <path>` | `server` | — | If `auth gsi` or `auth both` |
| `brix_crl <path>` | `server` | — | No |
| `brix_crl_reload <seconds>` | `server` | `0` | No |
| `brix_signing_policy on\|off\|require` | `server` | `on` | No — enforce `<hash>.signing_policy` namespace ([WLCG CA conformance](../09-developer-guide/wlcg-ca-conformance.md)) |
| `brix_crl_mode off\|try\|require` | `server` | `try` | No — CRL strictness; `require` restores "CRL required for all CAs" |
| `brix_vomsdir <path>` | `server` | — | If `require_vo` |
| `brix_voms_cert_dir <path>` | `server` | — | If `require_vo` |
| `brix_require_vo <path> <vo>` | `server` | — | No |
| `brix_inherit_parent_group <path>` | `server` | — | No |
| `brix_token_jwks <path>` | `server` | — | If `auth token` or `auth both` |
| `brix_token_issuer <string>` | `server` | — | If token JWKS is configured |
| `brix_token_audience <string>` | `server` | — | If token JWKS is configured |
| `brix_access_log <path>\|off` | `server`, HTTP `main/server/location` | `off` | No |
| `brix_session_log on\|off` | `server`, HTTP `main/server/location` | `on` | No |
| `brix_thread_pool <name>` | `server` | `default` | No |
| `brix_ckscan_depth <n>` | `server` | `32` | Maximum recursive depth for `kXR_Qckscan` |
| `brix_ckscan_max_files <n>` | `server` | `100000` | Maximum regular files returned by one `kXR_Qckscan` |
| `brix_manager_map /prefix host:port` | `server` | — | No |
| `brix_upstream host:port` | `server` | — | No |
| `brix_cache on\|off` | `server` | `off` | No |
| `brix_cache_export <path>` | `server` | — | If `brix_cache on` |
| `brix_cache_origin host:port` | `server` | — | If `brix_cache on` |
| `brix_cache_origin_tls on\|off` | `server` | `off` | No |
| `brix_cache_lock_timeout <time>` | `server` | `300s` | No |
| `brix_cache_eviction_threshold <ratio\|percent>` | `server` | `0.9` | No |
| `brix_cms_manager host:port` | `server` | — | No |
| `brix_cms_paths <string>` | `server` | `brix_export` | No |
| `brix_cms_interval <time>` | `server` | `30s` | No |
| `brix_manager_mode on\|off` | `server` | `off` | No |
| `brix_cms_server on\|off` | `server` | `off` | No |

---

## Metrics directive

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_metrics on\|off` | `location` (HTTP) | `off` | Activates the Prometheus text exporter for the shared metrics zone |
| `brix_srr on\|off` | `location` (HTTP) | `off` | Serves the WLCG Storage Resource Reporting (SRR) `storageservice` JSON document at this location (point CRIC at this URL) |
| `brix_srr_name <name>` | `location` (HTTP) | — | `storageservice.name` (the SE / site name); also `.id` unless `brix_srr_id` is set |
| `brix_srr_quality <level>` | `location` (HTTP) | `production` | `qualitylevel` (development/testing/pre-production/production) |
| `brix_srr_version <ver>` | `location` (HTTP) | `1.0` | `implementationversion` |
| `brix_srr_share <name> <path> [vos]` | `location` (HTTP) | — | Repeatable. One `storageshares[]` entry; `<path>` is `statvfs`'d for total/used bytes; `[vos]` = comma-separated VO list |
| `brix_srr_endpoint <name> <iftype> <url>` | `location` (HTTP) | — | Repeatable. One `storageendpoints[]` entry (e.g. `webdav davs https://se:8443/`) |

See [`src/protocols/srr/README.md`](../../src/protocols/srr/README.md) for the full document layout and caveats.

---

## WebDAV directives

The WebDAV module (`ngx_http_brix_webdav_module`) handles `davs://` clients in nginx's `http {}` context. Full documentation and examples: [webdav.md](../04-protocols/webdav-overview.md).

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_webdav on\|off` | `location` | `off` | Activates WebDAV handler |
| `brix_export <path>` | `location` | `/` | Filesystem root for clients |
| `brix_webdav_auth none\|optional\|required` | `location` | `optional` | Proxy-cert or bearer-token auth policy |
| `brix_webdav_cadir <path>` | `location` | — | Hashed CA directory |
| `brix_webdav_cafile <path>` | `location` | — | Single CA PEM file |
| `brix_webdav_crl <path>` | `location` | — | PEM CRL file for proxy-cert revocation checks |
| `brix_webdav_signing_policy on\|off\|require` | `location` | `on` | Enforce `<hash>.signing_policy` namespace ([WLCG CA conformance](../09-developer-guide/wlcg-ca-conformance.md)) |
| `brix_webdav_crl_mode off\|try\|require` | `location` | `try` | CRL strictness |
| `brix_allow_write on\|off` | `location` | `off` | Enable PUT/DELETE/MKCOL and TPC COPY writes |
| `brix_webdav_tpc on\|off` | `location` | `off` | Enable HTTP-TPC COPY pull support |
| `brix_webdav_tpc_curl <path>` | `location` | `/usr/bin/curl` | External curl helper for TPC pulls |
| `brix_webdav_tpc_cert <path>` | `location` | — | X.509 cert/proxy used for outbound TPC source fetches |
| `brix_webdav_tpc_key <path>` | `location` | `brix_webdav_tpc_cert` | Private key used with the TPC cert |
| `brix_webdav_tpc_cadir <path>` | `location` | `brix_webdav_cadir` | CA directory for outbound source TLS verification |
| `brix_webdav_tpc_cafile <path>` | `location` | `brix_webdav_cafile` | CA bundle for outbound source TLS verification |
| `brix_webdav_tpc_timeout <seconds>` | `location` | `0` | Optional curl max-time for TPC pulls |
| `brix_webdav_tpc_token_endpoint <url>` | `location` | — | OAuth2/OIDC token endpoint URL for RFC 8693 token-exchange delegation |
| `brix_webdav_tpc_token_client_id <string>` | `location` | — | OAuth2 client ID (optional, for confidential clients) |
| `brix_webdav_tpc_token_client_secret <string>` | `location` | — | OAuth2 client secret (optional, for confidential clients) |
| `brix_webdav_tpc_token_scope <string>` | `location` | `storage.read` | Scope string requested during token exchange |
| `brix_webdav_proxy_certs on\|off` | `server` or `location` (HTTP) | `off` | Accept RFC 3820 proxy certs |
| `brix_webdav_verify_depth <n>` | `location` | `10` | Proxy chain depth limit |
| `brix_webdav_token_jwks <path>` | `location` | — | JWKS for Bearer tokens |
| `brix_webdav_token_issuer <string>` | `location` | — | Expected token issuer |
| `brix_webdav_token_audience <string>` | `location` | — | Expected token audience |
| `brix_thread_pool <name>` | `location` | `default` | nginx thread pool for async WebDAV file I/O |
| `brix_webdav_cors_origin <origin\|*>` | `location` | — | Enable CORS for one exact origin; repeat for more origins |
| `brix_webdav_cors_credentials on\|off` | `location` | `off` | Add credentialed CORS response headers |
| `brix_webdav_cors_max_age <seconds>` | `location` | `86400` | CORS preflight cache duration |
| `brix_webdav_lock_timeout <seconds>` | `location` | `600` | Maximum WebDAV lock duration |
| `brix_webdav_lock_startup_sweep on\|off` | `main`/`server`/`location` | `off` | Clear persisted lock xattrs under the export root at startup (ephemeral locks) |
| `brix_webdav_proxy on\|off` | `location` | `off` | Forward all WebDAV requests (after auth) to an upstream HTTP/HTTPS server |
| `brix_webdav_proxy_upstream <url>` | `location` | — | Required when proxy on; `http://` or `https://` base URL of the backend |
| `brix_webdav_proxy_auth anonymous\|forward\|token <val>` | `location` | `anonymous` | Auth forwarding policy: strip Authorization / pass through / replace with static Bearer token |
| `brix_webdav_proxy_connect_timeout <time>` | `location` | — | TCP connect timeout to upstream |
| `brix_webdav_proxy_send_timeout <time>` | `location` | — | Idle send timeout to upstream |
| `brix_webdav_proxy_read_timeout <time>` | `location` | — | Idle read timeout from upstream |

---

## S3-compatible HTTP directives

The S3 module (`ngx_http_brix_s3_module`) handles path-style S3-compatible
requests in nginx's `http {}` context. It is a small filesystem-backed subset
for XrdClS3-style clients, not a full AWS S3 implementation.

**S3 API compliance:** all known gaps have been resolved. `PutObject` now returns an `ETag` header on every successful PUT, and `ListObjectsV2` on an unknown bucket returns `404` with `NoSuchBucket` XML.

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_s3 on\|off` | `location` | `off` | Activates the S3-compatible handler for this location |
| `brix_export <path>` | `location` | `""` | Required when enabled; canonicalized during config merge |
| `brix_s3_bucket <name>` | `location` | `""` | Optional path-style bucket name to strip from request URIs |
| `brix_s3_access_key <key>` | `location` | `""` | Enables SigV4 auth when set; empty means anonymous access |
| `brix_s3_secret_key <secret>` | `location` | `""` | Secret used to verify SigV4 requests |
| `brix_s3_region <name>` | `location` | `us-east-1` | Region string expected in the SigV4 credential scope |
| `brix_allow_write on\|off` | `location` | `off` | Enables PUT and DELETE |
| `brix_s3_max_keys <n>` | `location` | `1000` | Maximum ListObjectsV2 keys returned per response page |

Example:

```nginx
http {
    server {
        listen 9001;

        location / {
            brix_s3 on;
            brix_export /data/store;
            brix_s3_bucket testbucket;
            brix_allow_write on;
        }
    }
}
```

---

## CVMFS site-cache directives

The CVMFS module (`ngx_http_brix_cvmfs_module`) turns a location into a
Squid-replacement CVMFS forward-proxy or reverse-proxy site cache. The cache is
read-only; `brix_allow_write`, `brix_stage`, and `brix_cache_slice_size` are
rejected with a config error in a cvmfs location.

Unified storage directives (`brix_cache_store`, `brix_cache_verify`, …) apply
here exactly as they do to WebDAV/S3. Only cvmfs-specific knobs are listed below.

### Core

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_cvmfs on\|off` | `location` | `off` | Activate cvmfs handler (one protocol per location) |
| `brix_cache_store posix:<path>` | `location` | required | Local XFS cache directory |
| `brix_cache_verify off\|cvmfs-cas` | `location` | **`cvmfs-cas`** | Verify fills against SHA-1 CAS address (cvmfs default; quarantines corrupt objects) |
| `brix_cache_evict_at <pct>` | `location` | `90` | Eviction trigger. Wired on the `root://` stream read cache (seeds the watermark LRU reaper; explicit `brix_cache_high/low_watermark` win); not yet wired on the cvmfs plane (bounded by `brix_cache_max_object` + DELETE/overwrite eviction) |
| `brix_cache_evict_to <pct>` | `location` | `80` | Eviction target (hysteresis partner; must be < `evict_at`). Same plane caveat |
| `brix_cvmfs_upstream_allow <host> …` | `location` | required | Stratum-1 hostname(s) the cache may fetch from |
| `brix_cvmfs_manifest_ttl <sec>` | `location` | `61` | Manifest revalidation interval |
| `brix_cvmfs_negative_ttl <sec>` | `location` | `10` | Missing-object answer cache lifetime |
| `brix_cvmfs_quarantine_dir <path>` | `location` | unset | Directory for CAS verify failures |
| `brix_cvmfs_trace on\|off` | `location` | `off` | Promote upstream-request lines to INFO |

### Fill policy and hold

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_cvmfs_client_hold <sec>` | `location` | `25` | Max time to hold a client while retrying origins |
| `brix_cvmfs_fill_max_life <sec>` | `location` | `300` | Max fill lifetime before restart |
| `brix_cvmfs_upstream_max <n>` | `location` | `8` | Max concurrent fill connections per origin |
| `brix_cvmfs_fill_retry_policy failover\|force-primary` | `location` | `failover` | Stall retry strategy |
| `brix_cvmfs_origin_reuse_conn on\|off` | `location` | `on` | Reuse HTTP keep-alive connections to origins |

### Origin selection

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_cvmfs_origin_select static\|geo\|rtt` | `location` | `rtt` | Origin ranking strategy |
| `brix_cvmfs_rtt_interval <sec>` | `location` | `60` | RTT probe interval (rtt mode) |
| `brix_cvmfs_here <lat>:<lon>` | `location` | — | This cache's location (geo mode, required) |
| `brix_cvmfs_origin_coords <host> <lat>:<lon>` | `location` | — | Stratum-1 coordinates (geo mode, repeat per origin) |

### Upstream stall detection

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_cvmfs_origin_connect_timeout <sec>` | `location` | `2` | TCP connect timeout per attempt |
| `brix_cvmfs_origin_stall_timeout <sec>` | `location` | `4` | Idle-stall timeout (seconds at low-speed threshold) |
| `brix_cvmfs_origin_stall_bytes <n>` | `location` | `1` | Low-speed threshold (bytes/s) |

### Server-side geo answering

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_cvmfs_geo_answer off\|rtt` | `location` | `off` | Answer CVMFS geo-API requests using RTT rankings |
| `brix_cvmfs_geo_cache_ttl <sec>` | `location` | `60` | Geo-answer cache TTL |
| `brix_cvmfs_geo_max_servers <n>` | `location` | `16` | Max servers returned per geo-answer response |

### Secure cvmfs (EXPERIMENTAL)

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_scvmfs on\|off` | `location` | `off` | Require TLS + bearer auth on this cvmfs location |
| `brix_scvmfs_authz none\|bearer` | `location` | `none` | `bearer` gates on WLCG/SciTokens read scope |
| `brix_scvmfs_token_issuers <path>` | `location` | — | SciTokens config for `bearer` mode |
