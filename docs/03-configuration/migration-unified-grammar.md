# Migration: unified brix config grammar (2026-07-05)

> **Sweep-exemption note:** this document intentionally contains old directive
> names in the left column of the table below. Repo-wide stale-name grep sweeps
> and the `tools/refactor/config_rename_2026_07.sh` script must exclude this file.

The 2026-07-05 rename is a **hard break** — old names produce nginx's stock
`unknown directive` error at `nginx -t`. There are no aliases, deprecation shims,
or "renamed to X" log messages. Any config that fails to start after upgrading
has at least one old name; find them with:

```bash
nginx -t -c /path/to/nginx.conf 2>&1 | grep 'unknown directive'
```

---

## Rename table

### Stream protocol enable

| Old name | New name | Notes |
|---|---|---|
| `xrootd on;` / `xrootd off;` | `brix_root on;` / `brix_root off;` | The `xrootd` directive token is now unknown; only the `on\|off` form is renamed — bare `xrootd` in prose is unaffected |

### Stream export-path directive

| Old name | New name | Notes |
|---|---|---|
| `brix_root <path>` | `brix_export <path>` | Stream: the second positional form of `brix_root` (a path argument, not `on\|off`) became `brix_export`. After the stream-enable rename (above) there is no ambiguity. |

### HTTP per-protocol export roots

| Old name | New name | Notes |
|---|---|---|
| `brix_webdav_root <path>` | `brix_export <path>` | WebDAV export root |
| `brix_s3_root <path>` | `brix_export <path>` | S3 export root |
| (cvmfs had no root directive) | `brix_export <path>` | Optional under cvmfs; defaults to `/` |

### Stream legacy read-cache export

| Old name | New name | Notes |
|---|---|---|
| `brix_cache_root <path>` | `brix_cache_export <path>` | The advertised logical root for the stream read-through cache; renamed to match the `brix_export` vocabulary |

### Per-protocol tier + preamble directives → unified bare names

Each of these existed in three flavours (`brix_webdav_*`, `brix_s3_*`, `brix_cvmfs_*`).
All three are gone. The bare `brix_*` name is now registered once by
`ngx_http_brix_common_module` and inherited by every brix HTTP location.

| Old names (webdav / s3 / cvmfs variants) | New unified name |
|---|---|
| `brix_webdav_cache_store` / `brix_s3_cache_store` / `brix_cvmfs_cache_store` | `brix_cache_store` |
| `brix_webdav_stage` / `brix_s3_stage` | `brix_stage` |
| `brix_webdav_stage_store` / `brix_s3_stage_store` | `brix_stage_store` |
| `brix_webdav_stage_flush` / `brix_s3_stage_flush` | `brix_stage_flush` |
| `brix_webdav_cache_max_object` / `brix_s3_cache_max_object` | `brix_cache_max_object` |
| `brix_webdav_cache_evict_at` / `brix_s3_cache_evict_at` | `brix_cache_evict_at` |
| `brix_webdav_cache_evict_to` / `brix_s3_cache_evict_to` | `brix_cache_evict_to` |
| `brix_webdav_cache_index_cache` / `brix_s3_cache_index_cache` | `brix_cache_index_cache` |
| `brix_webdav_cache_meta` / `brix_s3_cache_meta` | `brix_cache_meta` |
| `brix_webdav_cache_slice_size` / `brix_s3_cache_slice_size` | `brix_cache_slice_size` |
| `brix_webdav_storage_backend` / `brix_s3_storage_backend` / `brix_cvmfs_storage_backend` | `brix_storage_backend` |
| `brix_webdav_storage_credential` / `brix_s3_storage_credential` | `brix_storage_credential` |
| `brix_webdav_thread_pool` / `brix_cvmfs_thread_pool` | `brix_thread_pool` |
| `brix_webdav_allow_write` / `brix_s3_allow_write` | `brix_allow_write` |
| `brix_webdav_read_only` / `brix_s3_read_only` | `brix_read_only` |
| `brix_webdav_compress` / `brix_s3_compress` | `brix_compress` |

### cvmfs: verify directive ownership moved (name unchanged)

`brix_cache_verify` keeps its name — no config edit is needed. What changed is
ownership and scope: it was previously registered by the cvmfs module and valid
only in cvmfs locations; it is now owned by the shared config module and valid
at all brix HTTP locations. Its default under cvmfs is now `cvmfs-cas` (other
protocols default to `off`) — set `brix_cache_verify off;` explicitly to
restore the old behaviour.

---

## What did NOT change

These names are **unchanged** — they were always bare or genuinely per-protocol:

- All stream tier directives (`brix_cache_store`, `brix_stage`, … in `stream {}`) — already used the target names; unchanged.
- All cvmfs-specific knobs (`brix_cvmfs_manifest_ttl`, `brix_cvmfs_upstream_allow`, `brix_cvmfs_origin_select`, `brix_cvmfs_client_hold`, and the full `brix_cvmfs_*` / `brix_scvmfs_*` families).
- All WebDAV-specific directives (`brix_webdav_auth`, `brix_webdav_tpc`, `brix_webdav_cors_*`, `brix_webdav_token_*`, `brix_webdav_proxy`, `brix_webdav_stage_dir`, `brix_webdav_lock_*`, …).
- All S3-specific directives (`brix_s3`, `brix_s3_bucket`, `brix_s3_access_key`, `brix_s3_secret_key`, `brix_s3_region`, `brix_s3_max_keys`, …).
- Cross-protocol bare directives that were already unified: `brix_allow_write`, `brix_access_log`, `brix_auth`, `brix_certificate`, `brix_metrics`, `brix_health`, `brix_dashboard`, `brix_cache` (stream read-through), `brix_cache_origin`, and the rest of the stream cache engine directives.

### Phase-101 HTTP de-prefixing (2026-08) — ZIP member access (W4)

The webdav/s3 ZIP-member directives collapsed to one bare pair on the HTTP plane
(the stream plane already used the bare names). Set once at `http{}`/`server{}`
scope, they now cover WebDAV, S3 AND cvmfs via the common-module adopt.

| Old name | New name | Notes |
|---|---|---|
| `brix_webdav_zip_access` / `brix_s3_zip_access` | `brix_zip_access` | on\|off; one spelling for every HTTP protocol |
| `brix_webdav_zip_cd_max_bytes` / `brix_s3_zip_cd_max_bytes` | `brix_zip_cd_max_bytes` | central-directory scan cap |
| `brix_webdav_pwd_file` | `brix_pwd_file` | HTTP basic-auth password db (bare name already used on the stream plane) |
| `brix_webdav_upload_resume` | `brix_upload_resume` | resumable Content-Range PUT; default ON preserved |
| `brix_webdav_macaroon_secret` / `_old` | `brix_macaroon_secret` / `brix_macaroon_secret_old` | macaroon HMAC secret + grace-rotation key |
| `brix_webdav_stage_dir` | `brix_stage_dir` | upload staging device (the derived *_canon buffer stays protocol-local) |
| `brix_webdav_pblock_block_size` | `brix_pblock_block_size` | pblock stripe size (field was already shared) |
| `brix_webdav_crl` | `brix_crl` | CRL PEM directory (x509) |
| `brix_webdav_crl_mode` | `brix_crl_mode` | off\|try\|require |
| `brix_webdav_signing_policy` | `brix_signing_policy` | off\|on\|require |
| `brix_webdav_vomsdir` | `brix_vomsdir` | VOMS *.lsc trust directory |
| `brix_webdav_voms_cert_dir` | `brix_voms_cert_dir` | VOMS CA directory |
| `brix_{webdav,s3}_token_jwks` | `brix_token_jwks` | JWKS pubkey file — one set for both HTTP protocols |
| `brix_{webdav,s3}_token_issuer` | `brix_token_issuer` | required `iss` |
| `brix_{webdav,s3}_token_audience` | `brix_token_audience` | required `aud` |
| `brix_{webdav,s3}_token_clock_skew` | `brix_token_clock_skew` | grace seconds; **unified default 30** (was 30 webdav / 60 s3 — stricter wins; an s3 config relying on the 60s default now uses 30) |
| `brix_webdav_token_config` | `brix_token_config` | multi-issuer SciTokens registry file; overrides the single-issuer jwks/issuer/audience when set. Field now in the shared preamble; the built registry stays protocol-local. Bare on the stream plane already. |
| `brix_webdav_require_vo` | `brix_require_vo` | per-path VOMS VO ACL; array now in the shared preamble. Honored on webdav/root (VOMS); parsed-but-inert on s3 (SigV4). Bare on the stream plane already. |
| `brix_webdav_protbind` | `brix_protbind` | per-host credential-source binding (XRootD sec.protbind); array now in the shared preamble, inherited whole. Shared grammar engine (`src/auth/protbind/`). Bare on the stream plane already. |
| `brix_webdav_tpc_allow_local` | `brix_tpc_allow_local` | HTTP-TPC SSRF: allow loopback/link-local pull targets. Field now in the shared preamble. Bare on the stream plane already. |
| `brix_webdav_tpc_allow_private` | `brix_tpc_allow_private` | HTTP-TPC SSRF: allow RFC-1918/ULA pull targets (default on). |
| `brix_webdav_tpc_source_guard` | `brix_tpc_source_guard` | HTTP-TPC source-host allowlist enable (fail-closed when on). |
| `brix_webdav_tpc_source_allow` | `brix_tpc_source_allow` | HTTP-TPC source-host allowlist (exact host or leading-`.` suffix); custom setter appends every argument. |
| `brix_webdav_tpc_require_source_size` | `brix_tpc_require_source_size` | HTTP-TPC completion gate: refuse a length-less source. |
| `brix_webdav_tpc_verify_checksum` | `brix_tpc_verify_checksum` | **Unified grammar** `on\|off\|<alg>`. The stream boolean and the webdav `<alg>` collapse into one field (`common.tpc_verify_checksum`): `on`→`adler32` (XRootD/WLCG default), `off`/absent = off, an algorithm name kept canonical. Native TPC reads it as a boolean gate; webdav uses the algorithm for Want-Digest. Existing stream `on\|off` and webdav `<alg>` configs both keep working under the bare name. |

### Phase-101 authdb engine split (2026-08) — W5

The bare name `brix_authdb` meant two different authorization **engines** by
plane: the XrdAcc engine on HTTP and the native u/g/p engine on stream, while
WebDAV carried both under near-identical names. W5 makes the **prefix name the
engine on HTTP, exactly as on the stream reference plane**: bare `brix_authdb`
is the native u/g/p engine everywhere; the XrdAcc engine and its tuners take the
`brix_acc_*` prefix.

| Old name (plane) | New name | Notes |
|---|---|---|
| `brix_webdav_authdb <file>` | `brix_authdb <file>` | Native u/g/p read-authz on WebDAV; de-prefixed to the bare name the stream plane already uses. Enforced by the WebDAV access phase for READ methods. Registration is webdav-scoped — extending native-rule authz to the s3/cvmfs access phases is the additive **W5.2** follow-up (until then bare `brix_authdb` at a non-webdav HTTP location is accepted-but-inert, exactly as `brix_webdav_authdb` was). |
| `brix_authdb <file>` (**HTTP**) | `brix_acc_authdb <file>` | The **XrdAcc** engine entry point on HTTP. Bare `brix_authdb` on HTTP no longer selects XrdAcc — a pre-W5 XrdAcc HTTP config fails `nginx -t` loudly (see below) and must move to `brix_acc_authdb`. |
| `brix_authdb_format` (**HTTP**) | `brix_acc_format` | XrdAcc engine selector (`native\|xrdacc`) on HTTP. |
| `brix_authdb_audit` (**HTTP**) | `brix_acc_audit` | XrdAcc audit level on HTTP. |
| `brix_authdb_refresh` (**HTTP**) | `brix_acc_refresh` | XrdAcc hot-reload interval on HTTP. |

**Stream is unchanged** — `brix_authdb` and its `brix_authdb_format` / `_audit` /
`_refresh` tuners keep their names on `brix_root` (the reference plane; the engine
there is polymorphic, selected at runtime by `brix_authdb_format native\|xrdacc`).

**Migration safety.** The old HTTP XrdAcc recipe (`brix_authdb <file>;
brix_authdb_format xrdacc;`) now fails `nginx -t` on the `brix_authdb_format`
line — a loud, mechanical signal to rename to `brix_acc_*`, never a silent engine
switch. (The native parser is deliberately lenient: it skips unrecognized lines
rather than erroring, so the guard against silent mis-selection rides on the dead
HTTP selection spelling, not on the parser rejecting an XrdAcc file.)

### Phase-101 gridftp de-prefixing (2026-08) — W3

The GridFTP gateway is a separate nginx stream module; because nginx routes a
bare directive name to the first module that registers it (the root module), the
gateway historically had to spell every shared name with a `brix_gridftp_`
prefix. W3 introduces `ngx_stream_brix_common_module` — a single stream-plane
owner of the shared storage / x509-trust / VO-ACL names — that both the root and
gateway modules adopt at merge, so the gateway now uses the **same bare names as
`root://`**. All 11 twins are de-prefixed:

| Old name (gridftp) | New name | Notes |
|---|---|---|
| `brix_gridftp_export <dir>` | `brix_export <dir>` | Gateway export root; the "must exist" realpath check is preserved (now at merge). |
| `brix_gridftp_allow_write on\|off` | `brix_allow_write on\|off` | |
| `brix_gridftp_verify_write on\|off` | `brix_verify_write on\|off` | Read-back CRC verify of staged STORs. |
| `brix_gridftp_storage_backend <spec>` | `brix_storage_backend <spec>` | posix (default) / pblock / s3://… |
| `brix_gridftp_storage_credential <name>` | `brix_storage_credential <name>` | Names a `brix_credential` block for an s3:// backend. |
| `brix_gridftp_certificate <pem>` | `brix_certificate <pem>` | GSI host certificate (gsiftp://). |
| `brix_gridftp_certificate_key <pem>` | `brix_certificate_key <pem>` | GSI host key. |
| `brix_gridftp_trusted_ca <dir\|file>` | `brix_trusted_ca <dir\|file>` | Client-proxy trust store. |
| `brix_gridftp_vomsdir <dir>` | `brix_vomsdir <dir>` | VOMS per-VO LSC trust dir. |
| `brix_gridftp_voms_cert_dir <dir>` | `brix_voms_cert_dir <dir>` | VOMS signing-CA dir. |
| `brix_gridftp_require_vo <path> <vo>` | `brix_require_vo <path> <vo>` | Longest-prefix VO ACL; rules finalized against the gateway's own export root. |

Unchanged gateway-specific directives: `brix_gridftp` (toggle),
`brix_gridftp_gsi`, `brix_gridftp_pasv_port_range`,
`brix_gridftp_require_allo_size`.

---

## Mechanical migration

In-repo configs were migrated by `tools/refactor/config_rename_2026_07.sh`. For
out-of-repo configs (site-specific `nginx.conf` files, Helm values, Puppet
templates), apply the same sed substitutions in order — ordering is
load-bearing; see comments in the script.

Quick check after migration:

```bash
nginx -t -c /path/to/nginx.conf
```

If that passes, the names are correct.

## W6 — naming-grammar outlier renames

| Old | New | Rationale |
|---|---|---|
| `brix_ocsp_enable` | `brix_ocsp` | Rule 1 (feature toggle is the bare feature name); siblings `brix_ocsp_soft_fail` / `_require_nonce` / `_stapling` already conform. |
| `brix_scan_root` | `brix_dashboard_scan_root` | Rule 2 (one prefix per feature); disambiguates from the DIFFERENT `brix_dashboard_browse_root` confinement root. |
| `brix_scan_max_files` | `brix_dashboard_scan_max_files` | Rule 2. |
| `brix_impersonation` | `brix_idmap` | Rule 2: one prefix for the per-request UNIX identity family (`off\|single\|map` toggle). Name-only — setters/behavior unchanged. |
| `brix_impersonation_user` | `brix_idmap_user` | SINGLE-mode account. |
| `brix_impersonation_socket` | `brix_idmap_socket` | MAP broker socket. |
| `brix_impersonation_export` | `brix_idmap_export` | MAP confinement root. |
| `brix_impersonation_broker_user` | `brix_idmap_broker_user` | MAP non-root broker account. |
| `brix_gridmap` | `brix_idmap_gridmap` | MAP DN→user file. |
| `brix_webdav_cafile` | `brix_trusted_ca` | Auth-layer verify-source **file** (GSI/VOMS client chain). The stream plane already spells this bare (`brix_trusted_ca`). Name-only — field/readers unchanged. |
| `brix_webdav_cadir` | `brix_trusted_ca_dir` | Auth-layer verify-source **directory**. |
| `brix_ssl_client_capath` | `brix_client_ca_store` | Front-leg TLS client-CA store (added to the server `SSL_CTX`). A DISTINCT mechanism from the verify-source above. |
| `brix_proxy_ssl_capath` | `brix_backend_ca_dir` | Backend-leg CA dir (proxy/TPC upstream trust). |

> The impersonation-prefix unification (`brix_impersonation*` / `brix_gridmap` → `brix_idmap*`) is **DONE** — the rows above cover it; the `brix_idmap_{default_user,min_uid,cache_ttl,forbidden_users,forbidden_groups}` params were already conforming and are unchanged. The CA/trust quintet is DONE (rows above; `brix_client_certificate_folder` deliberately keeps its name — a distinct fifth mechanism).

## W7 — value-syntax normalization (num → sec slot)

These seconds-valued directives now accept nginx time units (`s`/`m`/`h`/`d`) in addition to a bare integer. **Backward-compatible** — a bare integer is still seconds; the suffixed form is newly legal. No config change required.

| Directive | Before | After | Note |
|---|---|---|---|
| `brix_s3_mpu_max_age` | bare seconds | `sec_slot` | `604800` == `7d` |
| `brix_backend_s3_sts_ttl` | bare seconds | `sec_slot` (both planes) | `3600` == `1h`; STS client still clamps 900..43200 after parse |
| `brix_kv_zone <name> <size> …` | `brix_kv_zone zone=<name>:<size> …` | **breaking** grammar change — the shared-memory zone now uses the nginx-conventional `zone=name:size` shape (matching `brix_rate_limit_zone` / `brix_token_cache`). The old positional form is rejected with an EMERG naming the new shape. `key=`/`val=` unchanged. |
| `brix_webdav_cors_max_age` | *(same name)* | now `sec_slot` — accepts nginx time units (`1h` == `3600`). Additive. |
| `brix_webdav_lock_timeout` | *(same name)* | now `sec_slot` — accepts nginx time units (`5m` == `300`). Additive. |
| `brix_storage_credential_mint_ttl` | *(same name)* | now `sec_slot` on both planes — accepts nginx time units (`1h` == `3600`). Additive. |
| `brix_webdav_cache_root` | `brix_cache_root` | legacy read-through cache root; field moved to the shared preamble. Bare name covers both HTTP protocols. Canon + outside-export guard unchanged. |
| `brix_s3_cache_root` | `brix_cache_root` | same, s3 plane. |

> Not converted: `brix_token_clock_skew` carries a `[0,300]` security clamp on both planes, so `10m`=600 would be rejected — a unit-confusion footgun that needs its own deliberate handling before a sec_slot swap. Of the `ngx_uint_t` seconds fields, `brix_webdav_cors_max_age` and `brix_webdav_lock_timeout` are now `time_t`/`sec_slot` (done); `brix_storage_credential_mint_ttl` remains deferred — it has 10+ readers threading into the `ngx_uint_t` vfs field, so a clean conversion needs the vfs struct + signatures changed in the same pass.

**Ratelimit size parsers unified (additive):** the rate-limit code had two size parsers; the burst/zone path used nginx's `ngx_parse_size`, which handles only `k`/`m` — **not `g`** — while the bandwidth-rate path hand-rolled `k`/`m`/`g`. Both now share one `k`/`m`/`g` helper, so a `g` suffix on a burst (`burst=1g`) or a zone size (`zone=z:1g`) is now accepted, matching the rate grammar that already allowed `1g/s`. Strict superset — nothing that parsed before is rejected. (This corrects the phase-101 plan's premise that deleting the hand-rolled parser in favor of `ngx_parse_size` would be a superset — it would have REGRESSED, dropping `g`.)
