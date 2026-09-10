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
| `brix_checksum_default <algo>` | `server` | `adler32` | The `xrootd.chksum` default analog: the algorithm a `kXR_Qcksum` without a selection computes and the head of the `query config chksum` list; a built-in or a plugin name |
| `brix_checksum_plugin <name> <path.so> [parms]` | `stream` main / `http` main | — | Site checksum algorithm from a shared object (the `xrootd.chksum` plugin analog, ABI in `src/core/compat/checksum_plugin_abi.h`); absolute non-writable path, self-tested at `nginx -t`, at most 8; usable everywhere a built-in name is |
| `brix_frm on\|off` | `server` | `off` | Enable the shared-memory stage request registry behind `kXR_prepare`/`kXR_QPrep` and the nearline-open recall path (`tape://` adapter, `src/fs/backend/frm/`) |
| `brix_frm_max_inflight <N>` | `server` | `64` | Capacity of the stage request registry |
| `brix_frm_stage_ttl <time>` | `server` | `600s` | Expiry of a parked nearline open / prepare record |
| `brix_frm_stage_wait <s>` / `brix_frm_async_recall on\|off` / `brix_frm_control_dir <path>` | `server` | `30` / `off` / unset | `kXR_wait` interval, `kXR_waitresp` parking, registry control directory |
| `brix_frm_purge_watermark <hi> <lo>` / `brix_frm_purge_max_bytes <size>` / `brix_frm_purge_interval <time>` | `server` | unset / `0` / `5m` | Tape-buffer purge engine (phase-115 W3.2): LRU release of migrated, unpinned, cold online copies on filesystem occupancy and/or owned-bytes cap, worker 0, one pass per interval |
| `brix_frm_purge_policy {*\|<group>} <hi> <lo> [hold <time>] [polprog]` / `brix_frm_purge_polprog <program>` | `server` | none / none | Per-`brix_oss_space` purge rules (2.0 F4): a group's own owned-bytes arm (sizes or `%` of its quota), a longer hold, and an external policy program that picks which of the group's eligible copies go; `*` covers ungrouped keys and groups without a rule; a rule alone arms the engine |
| `brix_frm_queue_path <path>` / `brix_frm_stagecmd <program>` | `server` | required by `brix_frm on` / unset | Durable stage journal directory (`<reqid>.req` records, `deadletter/`, worker mkdir 0700; replaces the env-only `BRIX_STAGE_JOURNAL_DIR`) / the `tape://exec` MSS adapter program, run as `<program> <verb> <key> <online>`; beats `BRIX_FRM_STAGECMD` (2.0 F1, ADR-3b) |
| `brix_frm_copymax <n>` / `brix_frm_fail_retries <n>` / `brix_frm_fail_backoff <time>` / `brix_frm_copy_timeout <time>` | `server` | `8` / `5` / `60s` / `0` | Stage-engine in-flight bound / dead-letter attempt cap / worker-0 retry sweep period (floor `1s`) re-driving FAILED journal records / `stagecmd` child deadline (`SIGKILL` + `ETIMEDOUT`, `0` = none). Process-wide: every `brix_frm on` server must publish the same values |
| `brix_frm_stagemsg <file>` | `server` | unset | StageEvents notification feed (the `oss.stagemsg` / `XRDOFSEVENTS` analogue, 2.0 F2): one `%`-escaped `<utc> <source> <event> <reqid> <key> [k=v…]` line per stage-engine / prepare-registry / MSS transition, created `0600`, refused at load if group- or world-writable, best-effort (an unwritable file logs once, never fails a stage, re-opens on the next transition). Process-wide like the other engine knobs |


| `brix_tap_proxy on\|off` | `server` | `off` | Enable transparent XRootD proxy mode |
| `brix_tap_proxy_upstream host[:port] [auth]` | `server` | — | Required when `brix_tap_proxy on`; may appear multiple times for round-robin load balancing. Optional `auth` arg (`anonymous`, `forward`, `sss`, `sss:<keyname>`) overrides server-level `brix_tap_proxy_auth` for this upstream |
| `brix_tap_proxy_upstream_tls on\|off` | `server` | `off` | Wrap outbound upstream TCP in TLS |
| `brix_tap_proxy_upstream_tls_ca <path>` | `server` | — | PEM CA bundle to verify upstream TLS certificate (enables `SSL_VERIFY_PEER`) |
| `brix_tap_proxy_upstream_tls_name <host>` | `server` | — | SNI hostname for upstream TLS; defaults to `brix_tap_proxy_upstream` host |
| `brix_tap_proxy_auth anonymous\|forward\|sss` | `server` | `anonymous` | Auth bridging: `forward` replays bearer token; `sss` builds an SSS credential from the first configured `brix_sss_key` |
| `brix_tap_proxy_sss_identity keytab\|client` | `server` | `keytab` | Whose identity the tap proxy presents upstream in the SSS credential; `client` mints the front-side client's entity and refuses an unauthenticated session (2.0 F9) |
| `brix_proxy_audit_log <path>\|off` | `server` | `off` | One JSON line per closed/abandoned upstream file handle |
| `brix_proxy_reconnect_attempts <n>` | `server` | `0` | Reconnect budget per client session when upstream drops while idle with no open handles |
| `brix_proxy_connect_timeout <ms>` | `server` | `10000` | Milliseconds allowed for TCP connect to upstream; 0 = no limit |
| `brix_proxy_read_timeout <ms>` | `server` | `60000` | Milliseconds allowed between upstream response bytes; 0 = no limit |
| `brix_tap_proxy_path_rewrite <strip> <add>` | `server` | — | Strip leading prefix from open/path requests then prepend `add` (e.g. `brix_tap_proxy_path_rewrite /brix /data`) |
| `brix_tls on\|off` | `server` | `off` | No |
| `brix_tls_require none\|[all\|login\|session\|data\|tpc\|-<cap>]...` | `server` + HTTP planes | `none` | No |
| `brix_ztn_cleartext on\|off` | `server` | `off` | No |
| `brix_certificate <path>` | `server` | — | If `auth gsi` or `auth both` |
| `brix_certificate_key <path>` | `server` | — | If `auth gsi` or `auth both` |
| `brix_trusted_ca <path>` | `server` | — | If `auth gsi` or `auth both` |
| `brix_crl <path>` | `server` | — | No |
| `brix_crl_reload <seconds>` | `server` | `0` | No |
| `brix_signing_policy on\|off\|require` | `server` | `on` | No — enforce `<hash>.signing_policy` namespace ([WLCG CA conformance](../09-developer-guide/wlcg-ca-conformance.md)) |
| `brix_crl_mode off\|try\|require` | `server` | `try` | No — CRL strictness; `require` restores "CRL required for all CAs" |
| `brix_crl_scope all\|last` | `server` | `all` | No — how far up the chain revocation is enforced (XRootD `xrd.tlsca crlcheck`). `last` checks the credential's own end-entity certificate only; a **revoked** certificate is still refused under either value |
| `brix_tls_verify_log off\|failure\|all` | `server` | `off` | No — what the server writes about a chain it just verified (XRootD `xrd.tlsca verifylog`): nothing, rejections only, or every certificate in every chain |
| `brix_vomsdir <path>` | `server` | — | If `require_vo` |
| `brix_voms_cert_dir <path>` | `server` | — | If `require_vo` |
| `brix_require_vo <path> <vo>` | `server` | — | No |
| `brix_inherit_parent_group <path>` | `server` | — | No |
| `brix_token_jwks <path>` | `server` | — | If `auth token` or `auth both` |
| `brix_token_issuer <string>` | `server` | — | If token JWKS is configured |
| `brix_token_audience <string>` | `server` | — | If token JWKS is configured |
| `brix_sss_getcreds on\|off` | `server` | `off` | Keep the proxied credential an SSS client carries in its entity `CRED` field, for a downstream hop that must replay it; `off` wipes the blob (2.0 F9) |
| `brix_access_log <path>\|off` | `server`, HTTP `main/server/location` | `off` | No |
| `brix_session_log on\|off` | `server`, HTTP `main/server/location` | `on` | No |
| `brix_thread_pool <name>` | `server` | `default` | No |
| `brix_socket_sndbuf <size>` | `stream`, `server` | `0` (kernel autotuning) | No — pin `SO_SNDBUF` to the deployment BDP for high-RTT WAN downloads; best-effort, clamped to `net.core.wmem_max` (phase-33 P3-B3) |
| `brix_socket_rcvbuf <size>` | `stream`, `server` | `0` (kernel autotuning) | No — symmetric `SO_RCVBUF` knob for the upload/PUT direction (phase-33 P3-B3) |
| `brix_ckscan_depth <n>` | `server` | `32` | Maximum recursive depth for `kXR_Qckscan` |
| `brix_ckscan_max_files <n>` | `server` | `100000` | Maximum regular files returned by one `kXR_Qckscan` |
| `brix_manager_map /prefix host:port` | `server` | — | No |
| `brix_upstream host:port` | `server` | — | No |
| `brix_cache on\|off` | `server` | `off` | No |
| `brix_cache_export <path>` | `server` | — | If `brix_cache on` |
| `brix_storage_backend root://host:port` | `server` | — | Cache origin (`roots://` for TLS); with `brix_cache_store posix:<dir>` + `brix_cache_export` |
| `brix_storage_backend tape://<adapter>/<base>[?arc=<1..8>]` | `server` | — | Nearline (tape/MSS) export through the `src/fs/backend/frm/` adapter (`stub`, `exec`/`hpss`/`cta`, `lib`); `?arc=<depth>` turns on the dataset archiver (phase-115 W3.1): one stored ZIP per sealed dataset, member-indexed recall. Same URL form on the tier store directives |
| `brix_cache_lock_timeout <time>` | `server` | `300s` | No |
| `brix_cache_verify off\|best-effort\|require` | `server` | `best-effort` | Checksum-on-fill: hash the staged `.part` against the origin's advertised digest before publishing. `require` refuses to publish an unverifiable fill. A composed `brix_storage_backend cache:…` tier defaults to `off` instead (2.0: both values are honoured on the standalone spine — before 2.0 it read an unwritable field) |
| `brix_cache_verify_digest <algo>` | `server`, `http\|server\|location` | unset | The algorithm a NON-`root://` origin is asked for (HTTP/Pelican `Want-Digest`, an object store's stored checksum). Any name this build can compute, including a `brix_checksum_plugin` one; unknown names fail `nginx -t`. An `xroot://` origin answers in band and ignores it (2.0) |
| `brix_cache_advertise on\|off` + `_federation <host[:port]>` `_key <pem>` `_data_url <url>` `_web_url <url>` `_issuer <url>` `_interval <time>` `_namespace <prefix>` | `server` | `off`, `60s` | Publish this cache to a Pelican federation Director (signed `OriginAdvertiseV2`, ES256 JWT, per-worker timer). The Director is discovered from `https://<federation>/.well-known/pelican-configuration`, so **nothing is advertised until `_federation` is set**. Site label comes from `brix_sitename`; interval clamps up to the federation minimum 60s; the registry key handshake is an out-of-band operator step (2.0: the family is registered, and `_federation` is the new name that lets it arm at all) |
| `brix_cache_eviction_threshold <ratio\|percent>` | `server` | `0.9` | No |
| `brix_cache_urlcgi [blocksize {ignore\|<min> <max>}] [prefetch {ignore\|<min> <max>}]` | `server`, `http\|server\|location` | absent — both hints ignored | Accept a client's per-open `pfc.blocksize=` / `pfc.prefetch=` hints, clamped into these bounds (XrdPfc `pfc.urlcgi` parity, 2.0 F5) |
| `brix_tpc_max_hops <n>` | `server` | `4` (range `0`–`16`) | How many `kXR_redirect` answers a native TPC pull follows from its source; each hop re-checks `brix_tpc_source_guard` (2.0 F7) |
| `brix_tpc_streams <n>` | `server` | `1` (range `1`–`15`) | Cap on the parallel source connections a native TPC pull may use when the client sends `tpc.str=<n>` (2.0 F7) |
| `brix_tpc_push on\|off` | `server` | `off` | Opt into the BriX native-TPC **push** dialect (`tpc.stage=push`, 2.0 F16): the SOURCE dials the destination and writes, instead of the destination dialling in and reading — the copy an egress-only site can still take part in. One flag arms both roles on the listener (a source may originate a push, and a destination may accept one). The source's destination is bounded by the same `brix_tpc_source_guard` allowlist as a pull, `tpc.str=<n>` is clamped by `brix_tpc_streams`, and the source export stays **read-only** — the two arm/fire `kXR_sync`s are the only write-table opcodes it exempts |
| `brix_tpc_allow_identity <dn\|group\|host\|vo> <pattern>` | `server`, `http\|server\|location` | unset — every identity allowed | `ofs.tpc allow` parity (2.0 F18). Repeatable; the selectors WITHIN one directive AND together, the directives OR. Patterns are `*`-globs (`host` reuses the one `brix_tpc_source_allow` host spelling, so a leading `.` is a domain suffix). Once ANY rule exists the stage is fail-CLOSED: a TPC leg whose credential matches no rule is refused. It only narrows — a rule can never widen the `brix_tpc_source_guard` host allowlist |
| `brix_tpc_require <all\|client\|dest> <auth>[,<auth>...]` | `server`, `http\|server\|location` | unset — no protocol demanded | `ofs.tpc require` parity (2.0 F18). Demand that the named party authenticated with one of these methods (`gsi`, `krb5`, `sss`, `unix`, `ztn`, …; `none` is not an authentication method and is refused at `nginx -t`). The party is read off the wire: a native leg carrying `tpc.org` was opened by the peer SERVER (`dest`), one without it by the initiating CLIENT (`client`) — so `require dest` is not satisfiable by a client credential. `all` demands it of both |
| `brix_tpc_restrict <path>` | `server`, `http\|server\|location` | unset — every path allowed | `ofs.tpc restrict` parity (2.0 F18). Repeatable prefix allowlist for the LOCAL path a TPC leg may touch. NARROWER than stock: the match is component-aware, so `/data` admits `/data/x` but never `/database`. Checked after the resolver's traversal rules, on the same cleaned logical path an `open()` would use. On an HTTP `location` the path checked is the request URI, so the prefix must include the location prefix (`location /restrict/` + `brix_tpc_restrict /restrict/allowed`); a prefix that omits it matches nothing and refuses every COPY there |
| `brix_tpc_oids on\|off` | `server`, `http\|server\|location` | `off` | `ofs.tpc oids` parity (2.0 F18). The one stage that is default-DENY: `*...`-style object-id paths are refused in a TPC leg unless this is `on` |
| `brix_cms_manager host:port [...]` | `server` | — | Up to 15 endpoints (multi-arg/repeatable); node logs into all, locates rotate + fail over |
| `brix_cms_paths <string>` | `server` | `brix_export` | No |
| `brix_cms_interval <time>` | `server` | `30s` | No |
| `brix_cms_vnid <string>` | `server` | — | Virtual network id carried in the CMS login envCGI (phase-89) |
| `brix_manager_mode on\|off` | `server` | `off` | No |
| `brix_cms_server on\|off` | `server` | `off` | No |
| `brix_cms_blacklist_file <path>` | `server` (CMS-server block) | — | Operator blacklist file: `host`, `host:port`, or IPv4 CIDR per line; mtime-polled, wins over `undrain` (phase-89) |
| `brix_cms_load_weight <0–100>` | `server` | `0` | Blend heartbeat machine load into manager selection scoring; `0` = space/util-only (phase-89) |
| `brix_cms_locate_window <time>` | `server` | `0` | Dynamic location: park locate, `kYR_state`-probe nodes, first `kYR_have` wins; `0` = static selection only (phase-89) |
| `brix_cms_state_fanout <n>` | `server` | `8` | Max node connections probed per dynamic locate window (phase-89) |
| `brix_cms_affinity on\|off` | `server` | `off` | Pin repeat selections of a path to one fresh-tier server (drained/blacklisted never sticky) (phase-89) |
| `brix_cms_locate_multi on\|off` | `server` | `off` | `kXR_locate` answers `kXR_ok` with the full live server set instead of one redirect (phase-89) |
| `brix_cms_fanout on\|off` | `server` | `off` | Fan `kXR_rm`/`kXR_rmdir` out to every holder instead of redirecting (phase-89) |
| `brix_oss_cgroup <name>` / `brix_oss_quota <size>` / `brix_oss_quota_enforce on\|off` | `server` | `default` / `-1` / `off` | Export-wide default space group as advertised by `kXR_Qspace`; with enforce on, writes past the quota are refused `kXR_overQuota` |
| `brix_oss_space <group> <prefix> [quota=<size>\|quota=-1]` | `server` (repeatable) | none | Named space group owning one export-relative prefix (longest wins): per-group usage/quota in `kXR_Qspace`, per-group `kXR_overQuota` under `brix_oss_quota_enforce on`, `?oss.cgroup=` must agree with the owning prefix (phase-115 W3.3) |
| `brix_cms_fanout_window <time>` | `server` | `500ms` | Fan-out reply-aggregation deadline; msec slot — write `600ms`, a bare number parses as seconds |
| `brix_cms_fsxeq <op>... <program> [<arg>...]` | `server` (repeatable, one program per op) | none | Stock `cms.fsxeq` (2.0 F17): an operator program **replaces** the built-in filesystem leg for the forwarded namespace ops it names (`chmod mkdir mkpath mv rm rmdir trunc`). The op's own arguments are appended to your command line (`<mode>`/`<size>` then physical `<path>`; `mv` gets both paths); the op name is **not** injected. Exit 0 = success, answered silently like stock; anything else fails the op `kYR_error`. Runs on a `thread_pool` — with none configured every named op fails closed. A `..` path is refused before the fork, `brix_allow_write off` refuses before it, and a group- or world-writable program is refused at `nginx -t` |
| `brix_cms_fsxeq_timeout <time>` | `server` | `10s` | Wall-clock budget for one `brix_cms_fsxeq` run; at expiry the program's whole process group is `SIGKILL`ed and the op fails `fsxeq program timed out` |

---

## Metrics directive

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_metrics on\|off` | `location` (HTTP) | `off` | Activates the Prometheus text exporter for the shared metrics zone. The zone is process-wide, so this one location exports every protocol — `proto="stream"`, `"webdav"`, `"s3"`, `"cvmfs"`, `"gridftp"` — including planes served from `stream {}` blocks |
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
| `brix_trusted_ca_dir <path>` | `location` | — | Hashed CA directory |
| `brix_trusted_ca <path>` | `location` | — | Single CA PEM file |
| `brix_crl <path>` | `location` | — | PEM CRL file for proxy-cert revocation checks |
| `brix_signing_policy on\|off\|require` | `location` | `on` | Enforce `<hash>.signing_policy` namespace ([WLCG CA conformance](../09-developer-guide/wlcg-ca-conformance.md)) — the phase-101 unified spelling; `brix_webdav_signing_policy` is gone |
| `brix_crl_mode off\|try\|require` | `location` | `try` | CRL strictness — the phase-101 unified spelling; `brix_webdav_crl_mode` is gone |
| `brix_crl_scope all\|last` | `location` | `all` | Revocation reach, exactly as on the `root://` plane above |
| `brix_tls_verify_log off\|failure\|all` | `location` | `off` | Chain-verification log, exactly as on the `root://` plane above |
| `brix_allow_write on\|off` | `location` | `off` | Enable PUT/DELETE/MKCOL and TPC COPY writes |
| `brix_webdav_tpc on\|off` | `location` | `off` | Enable HTTP-TPC COPY pull support |
| `brix_webdav_tpc_curl <path>` | `location` | `/usr/bin/curl` | External curl helper for TPC pulls |
| `brix_webdav_tpc_cert <path>` | `location` | — | X.509 cert/proxy used for outbound TPC source fetches |
| `brix_webdav_tpc_key <path>` | `location` | `brix_webdav_tpc_cert` | Private key used with the TPC cert |
| `brix_webdav_tpc_cadir <path>` | `location` | `brix_trusted_ca_dir` | CA directory for outbound source TLS verification |
| `brix_webdav_tpc_cafile <path>` | `location` | `brix_trusted_ca` | CA bundle for outbound source TLS verification |
| `brix_webdav_tpc_timeout <seconds>` | `location` | `0` | Optional curl max-time for TPC pulls |
| `brix_tpc_outbound_token_endpoint <url>` | `location` | — | OAuth2/OIDC token endpoint URL for RFC 8693 token-exchange delegation |
| `brix_tpc_outbound_client_id <string>` | `location` | — | OAuth2 client ID (optional, for confidential clients) |
| `brix_tpc_outbound_client_secret <string>` | `location` | — | OAuth2 client secret (optional, for confidential clients) |
| `brix_tpc_outbound_scope <string>` | `location` | `storage.read` | Scope string requested during token exchange |
| `brix_webdav_proxy_certs on\|off` | `server` or `location` (HTTP) | `off` | Accept RFC 3820 proxy certs |
| `brix_verify_depth <n>` | `location` | `10` | Proxy chain depth limit |
| `brix_token_jwks <path>` | `location` | — | JWKS for Bearer tokens |
| `brix_token_issuer <string>` | `location` | — | Expected token issuer |
| `brix_token_audience <string>` | `location` | — | Expected token audience |
| `brix_thread_pool <name>` | `location` | `default` | nginx thread pool for async WebDAV file I/O |
| `brix_webdav_cors_origin <origin\|*>` | `location` | — | Enable CORS for one exact origin; repeat for more origins |
| `brix_webdav_cors_credentials on\|off` | `location` | `off` | Add credentialed CORS response headers |
| `brix_webdav_cors_max_age <seconds>` | `location` | `86400` | CORS preflight cache duration |
| `brix_webdav_lock_timeout <seconds>` | `location` | `600` | Maximum WebDAV lock duration |
| `brix_webdav_lock_startup_sweep on\|off` | `main`/`server`/`location` | `off` | Clear persisted lock xattrs under the export root at startup (ephemeral locks) |
| `brix_storage_backend http(s)://<url>` | `location` | — | WebDAV perimeter proxy: forward requests (after auth) to an upstream HTTP(S) WebDAV server |

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
| `brix_cache_store ram:<size>` | `location` | — | Per-worker in-memory cache store: hard byte cap, LRU eviction that skips open objects; refused as a stage / backend / cold-store tier; `brix_cache_occupancy_ratio` / `brix_cache_bytes` come from the store's own cap, per worker (F6, 2.0) |
| `brix_cache_verify off\|cvmfs-cas` | `location` | **`cvmfs-cas`** | Verify fills against SHA-1 CAS address (cvmfs default; quarantines corrupt objects) |
| `brix_cache_evict_at <pct>` | `location` | `90` | Eviction trigger. Wired on the `root://` stream read cache (seeds the watermark LRU reaper; explicit `brix_cache_high/low_watermark` win); not yet wired on the cvmfs plane (bounded by `brix_cache_max_object` + DELETE/overwrite eviction) |
| `brix_cache_evict_to <pct>` | `location` | `80` | Eviction target (hysteresis partner; must be < `evict_at`). Same plane caveat |
| `brix_cache_serve_while_filling <time>` | `location` | `0` | Follow another reader's in-flight whole-file fill (`kXR_wait` at the fill frontier; `<time>` = no-progress deadline); needs a `posix:` store and `brix_cache_verify off` |
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

### Backend credential delegation

| Directive | Context | Default | Notes |
|---|---|---|---|
| `brix_backend_krb5_forwardable on\|off` | `http`/`stream` `server`, `location` | `off` | Re-delegate a client's forwardable krb5 TGT to a Kerberised origin (`host/<backend>@<REALM>`); phase-70 §5.7 |
