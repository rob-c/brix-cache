# webdav — nginx HTTP module for davs:// WebDAV

Implements an HTTPS WebDAV server compatible with `xrdcp --allow-http` and
standard WebDAV clients (curl, rclone, etc.).  Registered as an nginx HTTP
content handler via `xrootd_webdav on` in a location block.

## Module structure

| File | Responsibility |
|------|----------------|
| `module.c` | nginx directive table and `ngx_module_t` object |
| `postconfig.c` | Register content handler, configure SSL, set up thread pool |
| `config.c` | Location config create/merge; startup validation |
| `webdav.h` | Shared types: `ngx_http_xrootd_webdav_loc_conf_t`, internal prototypes |

## Request dispatch

| File | Responsibility |
|------|----------------|
| `dispatch.c` | Content handler entry point: authenticate, then route by HTTP method |
| `methods_basic.c` | OPTIONS, HEAD |
| `get.c` | GET with Range support, sendfile chain, fd-cache fast path |
| `put.c` | PUT body → file (sync or thread-pool) |
| `propfind.c` | PROPFIND and Multi-Status XML generation |
| `namespace.c` | DELETE and MKCOL |

## Authentication

| File | Responsibility |
|------|----------------|
| `auth_cert.c` | GSI/x509 proxy certificate verification and per-connection TLS auth cache |
| `auth_store.c` | CA and CRL OpenSSL store construction |
| `auth_token.c` | Bearer token (WLCG JWT) authentication and write-scope enforcement |

## HTTP Third-Party Copy (HTTP-TPC)

| File | Responsibility |
|------|----------------|
| `tpc.c` | COPY pull handler — receives an HTTP COPY request and fetches the source |
| `tpc_config.c` | TPC location defaults and directive inheritance |
| `tpc_curl.c` | Spawn an external `curl` process to perform the actual pull transfer |
| `tpc_headers.c` | Parse and validate COPY-specific HTTP headers |

## Utilities

| File | Responsibility |
|------|----------------|
| `pki.c` | `webdav_check_pki_consistency` — validate CA/CRL paths at postconfiguration time |
| `path.c` | URI decoding, path confinement to root, safe log formatting, XML escaping |
| `fd_cache.c` | Per-connection open-file cache for GET fast paths |
| `date.c` | RFC 1123 HTTP date formatting for Last-Modified headers |
| `headers.c` | Shared response header assembly |
| `io.c` | Blocking file write helpers shared by PUT handlers |
| `resource.c` | Shared URI-to-path resolution plus stat lookup |
