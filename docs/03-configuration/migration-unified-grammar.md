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
