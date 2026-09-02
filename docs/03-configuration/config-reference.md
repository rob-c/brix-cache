# Configuration reference

Every directive that BriX-Cache recognizes, with types, defaults, and examples. Native XRootD stream directives live inside a `server {}` block in the `stream {}` section; WebDAV, S3, and metrics directives are collected at the end.

## Fail-fast path validation

During `nginx -t` and startup, the module validates configured file/directory
paths and permissions up front and fails fast with `emerg` log messages if
required inputs are missing or unreadable.

Examples of checks performed:
- stream: `brix_export`, `brix_cache_export`, `brix_certificate`, `brix_certificate_key`, `brix_trusted_ca`, `brix_crl`, `brix_token_jwks`, `brix_vomsdir`, `brix_voms_cert_dir`
- webdav: `brix_export`, `brix_webdav_cadir`, `brix_webdav_cafile`, `brix_webdav_crl`, `brix_webdav_token_jwks`, and HTTP-TPC paths (`brix_webdav_tpc_*`) when enabled
- s3: `brix_export`

This avoids silent runtime failures deep in auth or request handling and gives
operators a precise startup error tied to the directive/path that is invalid.

---

## Configuration sub-pages

- [Directive reference](directives.md) — all `brix_*` directives with descriptions, defaults, and examples
- [Complete examples](examples.md) — annotated full nginx.conf configs for common deployments
- [Quick reference tables](quick-reference.md) — stream, metrics, WebDAV, and S3 directive summary tables

---

## nginx variables

brix exposes its request state as ordinary nginx variables, so `log_format`,
`map`, `if`, `add_header`, `split_clients` and `limit_req_zone` can consume it
without brix needing to know about them. Registration is owned by the common
HTTP module, so one `log_format` works on every brix HTTP plane
(webdav / s3 / cvmfs / oci / rpm) — you do not need a different log line per
protocol.

| Variable | Value | Notes |
|----------|-------|-------|
| `$brix_cache_status` | `HIT`, `MISS`, `BYPASS`, `NEGHIT`, or `-` | nginx's own `$upstream_cache_status` vocabulary wherever the semantics match, so existing dashboards work unchanged. `NEGHIT` is a brix extension (negative-cache hit) with no nginx equivalent. `BYPASS` means a cache tier is configured and was deliberately skipped for this request. `-` means no cache decision was reached — it is **not** a miss, so a hit rate computed from this variable is never silently wrong. Reported on every plane that consults a cache (WebDAV/S3 GET, cvmfs/oci/rpm). |
| `$brix_tls` | `on` / `off` | Whether the request arrived over TLS. Unlike `$https` this means the same thing on every brix plane. |
| `$brix_protocol` | `webdav`, `s3`, `cvmfs`, `oci`, `rpm`, `http` | Which brix plane serves the matched location. |
| `$brix_dn` | X.509 subject DN | The verified identity's DN; `-` for anonymous or token-only auth. The *subject*, never the chain. |
| `$brix_vo` | comma-separated VO/FQAN list | The verified identity's full VO list. |
| `$brix_fqan` | primary FQAN | The FIRST entry of the verified list (the VOMS convention for the operative FQAN); the full list is `$brix_vo`. |
| `$brix_sub` | token `sub` / S3 access-key id | The verified subject identifier. Note: on the S3 plane this is the access-key *id* — an identifier, not the secret key. |
| `$brix_issuer` | token `iss` | Empty (`-`) for non-token auth. |
| `$brix_auth_method` | `none`, `gsi`, `token`, `sss`, ... | Same vocabulary as the Prometheus auth label and the JSON access log, so one parsing rule serves all three. |
| `$brix_tier` | `posix`, `s3`, `http`, `xroot`, ... | The storage-driver family serving the location — the *resolved* instance's name, so config sugar cannot make the label drift. |
| `$brix_origin` | configured origin | The `brix_storage_backend` value with any `user:pass@` userinfo stripped before publishing. |
| `$brix_bytes_served` | byte count, or `-` | Bytes brix served to the client for this request (post-range). The brix-measured figure, distinct from nginx's `$body_bytes_sent` (what left the socket after any framing/compression) — logging both shows read amplification. `-` when brix served no bytes (a metadata request, a 304, or a request brix did not serve). |
| `$brix_backend_time` | seconds, `-` | Time brix spent in its own storage I/O for the request, in **seconds with millisecond precision — the same format as nginx's `$request_time`** so the two subtract cleanly. Isolates backend/storage service time, which `$request_time` does not: near zero on a cache hit, the origin fetch on a cold miss. `-` when brix did no I/O. |
| `$brix_bytes_received` | byte count, or `-` | Bytes brix received from the client (a PUT/POST body written to storage). `-` on a GET (nothing received). |
| `$brix_checksum` | `alg:hex`, or `-` | The file checksum brix **reported** to the client (the WebDAV `Digest` response, the root `kXR_Qcksum` reply), algorithm-tagged so it is never misread as adler32/md5. `-` when the request reported none — a plain GET without `Want-Digest` computes nothing. |
| `$brix_op` | `read`, `write`, `stat`, `dirlist`, `copy`, `tpc`, ... or `-` | The brix operation that describes the request, in the same vocabulary as the JSON access log's `op` and the `brix_io_ops_total{op}` label. Says what `$request_method` cannot: a TPC transfer vs a plain COPY, a GetObject vs a ListBucket. |
| `$brix_ops` | count, or `-` | How many brix operations the request performed. |
| `$brix_path` | resolved storage path, or `-` | The **confined, resolved** storage path of the primary op — the same string the JSON access log's `path` prints — not the client URL (`$uri`). Confinement is enforced before it is recorded, so a traversal probe logs the refused (in-export) path or `-`, never anything outside the export. |
| `$brix_status` | `ok`, `not_found`, `forbidden`, `io`, `other`, or `-` | The brix **outcome class**, plane-neutral and in the same vocabulary as the JSON log's `status` and the metric error labels. Unlike `$status` (an HTTP code here, a stream code on `root://`) this is one word for the same outcome everywhere — a read-only-export refusal is `forbidden` on WebDAV, S3 and `root://` alike. |
| `$brix_user` | local account, or `-` | The **mapped local account** the request runs as under impersonation (the grid-mapfile / mapping-policy result) — WHAT the storage saw, distinct from `$brix_sub` (WHO the client is). An account name, never a credential. |
| `$brix_duration` | seconds | Wall time of the request, byte-identical to nginx's `$request_time`. It exists only so one `log_format` serves both planes: nginx spells this fact `$request_time` on HTTP and `$session_time` on `root://`. |
| `$brix_delegated_cred` | path, or empty | The verified client's delegated-credential path, for handing to `proxy_ssl_certificate`. Empty when there is none. **This is credential material** — do not log it or forward it anywhere it is not needed. |
| `$brix_cvmfs_class`, `$brix_cvmfs_cache`, `$brix_cvmfs_origin` | cvmfs plane | Repository class, cache disposition and fill origin. `$brix_cvmfs_cache` uses the older cvmfs spelling (`hit`/`fill`/`neg`); prefer `$brix_cache_status` for new configs. |
| `$brix_oci_class`, `$brix_oci_cache` | oci plane | Request class and cache disposition. |
| `$brix_rpm_class`, `$brix_rpm_cache` | rpm plane | Request class and cache disposition. |
| `$cvmfs_*`, `$oci_*`, `$rpm_*` | — | **Deprecated aliases** of the seven `$brix_*` names above, resolving to the same handlers. Kept because removing a variable turns a stale `log_format` into a startup abort; prefer the `brix_` spelling. |

### Stream (`root://`) variables

For a `stream {}` `access_log`. **Every name below is the SAME `$brix_*` name
the HTTP planes use, with the same meaning** — one `log_format` body works in
both an `http {}` and a `stream {}` block, so you never keep two vocabularies.
Scope is the SESSION: a `root://` connection carries many ops, so these carry
the session's totals, its session-stable identity, and the *primary* op's
facts (`$brix_op` is the heaviest op, `$brix_ops` the count).

| Variable | Value |
|----------|-------|
| `$brix_protocol` | Plane label (`root`). |
| `$brix_dn` / `$brix_vo` / `$brix_fqan` / `$brix_sub` / `$brix_issuer` | Verified identity, same meaning as the HTTP variables. `$brix_sub` is the presented subject (the value the deprecated `$brix_session_user` carried). |
| `$brix_user` | The mapped local account (impersonation target), or `-`. |
| `$brix_auth_method` | `token`, `gsi`, `none`, or `-`. |
| `$brix_tls` | `on` / `off`. |
| `$brix_tier` / `$brix_origin` | The resolved storage-driver name / configured origin. |
| `$brix_op` / `$brix_ops` | The session's primary (heaviest) op / op count. |
| `$brix_status` | The primary op's outcome class (`ok`/`not_found`/`forbidden`/`io`/`other`). |
| `$brix_cache_status` | The session's cache disposition (`HIT`/`MISS`/`-`). |
| `$brix_path` | The primary op's confined export-relative path. |
| `$brix_checksum` | The checksum reported to the client (`kXR_Qcksum`), `alg:hex`, or `-`. |
| `$brix_bytes_served` / `$brix_bytes_received` | Bytes served to / received from the client this session. |
| `$brix_backend_time` / `$brix_duration` | Summed VFS I/O time / total session wall time, both `seconds.mmm` (`$brix_duration` == nginx's `$session_time`). |

The phase-106 spellings `$brix_session_{dn,vo,user,auth,tls,bytes_out,bytes_in}`
remain as **deprecated aliases** (see the table below) so an existing
`stream {}` `log_format` keeps working.

**One `log_format` for every plane** — paste the same body into `http {}` and
`stream {}`:

```nginx
log_format brix 'op=$brix_op path=$brix_path status=$brix_status '
                'proto=$brix_protocol cache=$brix_cache_status '
                'sub=$brix_sub vo=$brix_vo auth=$brix_auth_method '
                'user=$brix_user tls=$brix_tls served=$brix_bytes_served '
                'backend=$brix_backend_time total=$brix_duration';
access_log /var/log/nginx/brix.log brix;
```

Variables are an exfiltration surface: anything you log can leave the box.
brix variables expose the *subject* of an identity (DN, VO, issuer), never the
credential that proved it. `$brix_delegated_cred` is the single deliberate
exception and exists for credential forwarding.

### Deprecated names

Each still works and resolves to the same value; prefer the replacement, which
means the same thing on every plane and every monitoring surface. Removal is
scheduled for phase 112.

| Deprecated | Use instead |
|------------|-------------|
| `$brix_session_dn` | `$brix_dn` |
| `$brix_session_vo` | `$brix_vo` |
| `$brix_session_auth` | `$brix_auth_method` |
| `$brix_session_tls` | `$brix_tls` |
| `$brix_session_user` | `$brix_sub` (it published the subject); see `$brix_user` for the mapped account |
| `$brix_session_bytes_out` | `$brix_bytes_served` |
| `$brix_session_bytes_in` | `$brix_bytes_received` |
| `$brix_cvmfs_cache`, `$brix_oci_cache`, `$brix_rpm_cache`, `$cvmfs_*`, `$oci_*`, `$rpm_*` | `$brix_cache_status` (and the `$brix_`-prefixed class/origin twins) |
| JSON access-log key `from_cache` | `cache_status` |
| JSON access-log key `subject` | `sub` |
| JSON access-log keys `bytes` / `latency_us` | `bytes_served` / `backend_time_us` |
| metric `brix_cache_hits_total` / `brix_cache_misses_total` | `brix_cache_requests_total{cache_status="HIT"\|"MISS"}` |

The JSON access log and the Prometheus export emit **both** the old and new
spellings during the deprecation window, so no existing parser or dashboard
breaks while you migrate.


## Gating a location brix does not serve

brix can act purely as an authorization decision point, so its WLCG token,
VOMS FQAN, macaroon and GSI/X.509 logic can protect a data path you already
run. Neither seam serves bytes; both reuse the same auth gate a normal brix
request goes through, so there is no second copy of the policy.

### `brix_webdav_authz on` — an `auth_request` target

Makes the location an authorization endpoint: `204` when the request is
authorized, otherwise the auth gate's own `401`/`403`. On success it sets
`X-Brix-DN`, `X-Brix-Sub`, `X-Brix-Issuer` and `X-Brix-VO` for
`auth_request_set`. These carry the *subject* of the identity, never the
credential that proved it.

```nginx
location /protected/ {
    auth_request /_authz;
    auth_request_set $vo $upstream_http_x_brix_vo;
    proxy_pass http://your_backend;
}

location = /_authz {
    internal;                       # REQUIRED — see below
    brix_webdav on;
    brix_webdav_authz on;
    brix_webdav_auth required;
    brix_token_jwks /etc/brix/jwks.json;
}
```

### `brix_webdav_accel_redirect <prefix>` — decide, then hand off

After the request is authorized, brix internally redirects it to
`<prefix><uri>` and serves nothing itself, so an nginx `internal` location (or
anything behind it) delivers the bytes.

```nginx
location /gated/ { brix_webdav on; brix_webdav_accel_redirect /internal; }
location /internal/ { internal; alias /srv/data/; }
```

### Serving via nginx's static module (the fast path)

`brix_webdav_accel_redirect` doubles as the "let nginx serve the bytes"
handoff. Point it at a plain `internal` `alias` location — one with no brix
directive — and after brix authorizes the request, `ngx_http_static_module`
serves the file with sendfile, byte-range and `open_file_cache`:

```nginx
location /files/ { brix_webdav on; brix_webdav_accel_redirect /static; }
location /static/ { internal; alias /srv/data/; }   # served by the static module
```

A `Range` request to `/files/...` then comes back `206 Partial Content` from
the static module. Note that brix already routes its own GETs through nginx's
range and not-modified filters, so the practical gain here is `open_file_cache`
and the static module's optimized sendfile — use it where that matters.

**Both targets must be `internal`.** An externally reachable accel target would
serve every byte with no authorization at all, and an externally reachable
authz endpoint becomes an identity oracle. nginx enforces `internal` by
returning 404 to outside clients; brix additionally fails closed (403) if the
seam is enabled on a location with no brix policy configured.
