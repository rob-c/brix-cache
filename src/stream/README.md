# stream — nginx stream module entry point

nginx module glue for `ngx_stream_xrootd_module`: directive table, module
context, and module definition.  No protocol logic lives here — everything
is delegated to callbacks declared in `ngx_xrootd_module.h`.

## File map

| File | Contents |
|------|----------|
| `module.c` | `xrootd_auth_modes[]` enum table, `ngx_stream_xrootd_commands[]` directive array, `ngx_stream_xrootd_module_ctx`, `ngx_module_t ngx_stream_xrootd_module` |
| `module_cache_proxy_directives.c` | Cache and proxy directive parsing: xrootd_cache, xrootd_cache_root, xrootd_cache_origin, xrootd_upstream |
| `module_core_directives.c` | Core stream directive parsing: xrootd_root, xrootd_auth, TLS, write, access log |
| `ngx_xrootd_module.h` | Module callback declarations and cross-file prototypes |

## Directive index

| Directive | Type | Purpose |
|-----------|------|---------|
| `xrootd` | flag | Enable module; installs the stream handler |
| `xrootd_root` | string | Filesystem export root |
| `xrootd_auth` | enum | Auth mode: `none` / `gsi` / `token` / `both` |
| `xrootd_certificate` | string | Server PEM cert for GSI |
| `xrootd_certificate_key` | string | Server private key for GSI |
| `xrootd_trusted_ca` | string | CA trust store for client proxy verification |
| `xrootd_vomsdir` | string | VOMS LSC directory |
| `xrootd_voms_cert_dir` | string | VOMS CA cert directory |
| `xrootd_crl` | string | CRL PEM file or directory |
| `xrootd_crl_reload` | seconds | CRL re-scan interval |
| `xrootd_require_vo` | vo acl | Require VO membership for a path prefix |
| `xrootd_inherit_parent_group` | path | Inherit VO group policy from parent |
| `xrootd_token_jwks` | string | JWKS file for JWT validation |
| `xrootd_token_issuer` | string | Expected `iss` claim |
| `xrootd_token_audience` | string | Expected `aud` claim |
| `xrootd_tls` | flag | Enable in-protocol TLS upgrade (`kXR_ableTLS`) |
| `xrootd_allow_write` | flag | Enable write operations |
| `xrootd_access_log` | string | Path for per-request access log |
| `xrootd_manager_map` | prefix backend | Static manager redirect map |
| `xrootd_upstream` | host:port | Dynamic upstream redirector |
| `xrootd_cache` | flag | Enable read-through cache |
| `xrootd_cache_root` | string | Local cache directory |
| `xrootd_cache_origin` | host:port | Cache fill origin |
| `xrootd_cache_origin_tls` | flag | TLS to cache origin |
| `xrootd_cache_lock_timeout` | seconds | Cache fill lock timeout |
| `xrootd_cache_eviction_threshold` | ratio/percent | Cache high-water eviction threshold |
| `xrootd_cache_max_file_size` | size | Max file size to admit to cache (k/m/g suffixes; 0 = no limit) |
| `xrootd_cache_include_regex` | POSIX ERE | Basename regex — matching files always admitted regardless of size |
| `xrootd_cms_manager` | host:port | CMS manager to register with |
| `xrootd_cms_paths` | string | Exported path list sent to CMS |
| `xrootd_cms_interval` | seconds | CMS heartbeat interval |
| `xrootd_ckscan_depth` | number | Maximum recursive depth for kXR_Qckscan |
| `xrootd_ckscan_max_files` | number | Maximum files returned by one kXR_Qckscan |
| `xrootd_thread_pool` | string | nginx thread_pool for async I/O (NGX_THREADS only) |
