# Unified brix config grammar + 3-line cvmfs site cache — design

**Date:** 2026-07-05
**Status:** Approved (Rob), pending implementation
**Motivation:** A new sysadmin deploying a cvmfs site cache today faces 41+ directives across
three inconsistent naming families (`xrootd on` vs `brix_webdav on`; bare stream tier names vs
per-proto HTTP tier names; `brix_root` vs `brix_webdav_root` vs implicit `/`), silently-ignored
tier directives on cvmfs, and examples that restate defaults. Target: one guessable grammar,
a production-grade 3-line cvmfs config, wrong configs that fail loudly at `nginx -t`, and docs
that match.

> **Historical note (2026-07-06):** this document describes the rename in OLD→NEW terms.
> The names in the "Today" columns and prose below are the PRE-rename names by design;
> repo-wide rename sweeps must exclude this file (it was collateral-damaged once by the
> Task-5 migration sed and restored).

## Decisions (made interactively)

1. **Scope:** all four — fewer required lines, harmonized naming, foot-gun fixes, docs.
2. **Compatibility:** hard rename. New names only. No aliases, no deprecation shims, no
   "renamed to X" messages — old names hit nginx's stock `unknown directive` error. All
   in-repo configs (tests, deploy, docs, site) migrate in the same change.
3. **Minimal-config shape:** great defaults only — no preset/profile macro directive, no
   mandatory include snippets. Idiomatic nginx.
4. **Default flips:** `cache_verify` → `cvmfs-cas` by default (cvmfs plane only);
   `origin_select` → `rtt` by default.
5. **Stream protocol name:** `root` (the `root://` scheme is the identity HEP admins know).
6. **Tier grammar:** unified bare names (`brix_cache_store`, `brix_stage`, …) shared by all
   protocols — NOT the phase-64 per-proto expansion (`brix_webdav_cache_store`, …).
7. **One protocol per location, one per port** — enforced at config load.

## 1. One grammar, four protocols

### Grammar rules

- **`brix_<proto> on;`** — per-protocol enable: `brix_root`, `brix_webdav`, `brix_s3`,
  `brix_cvmfs`. The only remaining per-proto directive families are genuinely
  protocol-specific behavior (`brix_cvmfs_manifest_ttl`, `brix_cvmfs_upstream_allow`,
  `brix_s3_*` auth, `brix_scvmfs_*`, …).
- **Unified storage/namespace directives** — registered once per plane (http and stream),
  valid at http|server|location (stream: main|server), merged main→srv→loc so storage can
  be configured once at `server{}` and inherited by every brix location:
  `brix_export`, `brix_storage_backend`, `brix_cache_store`, `brix_cache_verify`,
  `brix_cache_max_object`, `brix_cache_evict_at`, `brix_cache_evict_to`,
  `brix_cache_index_cache`, `brix_cache_meta`, `brix_cache_slice_size`,
  `brix_stage`, `brix_stage_store`, `brix_stage_flush`, `brix_thread_pool`.
- **Bare `brix_*` non-storage names** stay reserved for genuinely cross-protocol or
  node-wide settings that already work identically everywhere: `brix_allow_write`,
  `brix_read_only`, `brix_compress`, `brix_ktls`, `brix_metrics`, `brix_health`,
  `brix_credential`, io_uring/memory-budget knobs.

### Rename table (OLD name → NEW name)

| Today (pre-rename) | Becomes |
|---|---|
| `xrootd on` (stream enable) | `brix_root on` |
| `brix_root <path>` (stream export path) | `brix_export` |
| `brix_webdav_root`, `brix_s3_root` | `brix_export` |
| (cvmfs: no root directive, implicit `/`) | `brix_export`, optional, default `/` under cvmfs |
| `brix_webdav_cache_store` + full webdav tier set | `brix_cache_store` + unified set |
| `brix_s3_cache_store` + full s3 tier set | `brix_cache_store` + unified set |
| `brix_cvmfs_cache_store`, `brix_cvmfs_thread_pool` | `brix_cache_store`, `brix_thread_pool` |
| `brix_cvmfs_storage_backend` | `brix_storage_backend` |
| stream tier `brix_cache_store`, `brix_stage`, … | **unchanged** (already the target names) |
| legacy stream `brix_cache_*` engine directives (~26) | **unchanged names**, documented stream-only — EXCEPT `brix_cache_root` → `brix_cache_export` (it is the advertised logical root; matches export vocabulary) |
| `brix_cache_verify` (registered only in cvmfs table today) | same name, becomes a unified directive |

The implementation plan carries the exhaustive old→new list; the same table is published in
docs as the migration reference (there are no runtime aliases to guide users).

### Architecture: who owns the unified directives

- **HTTP plane:** a new, small `ngx_http_brix_common_module` registers the unified
  directives exactly once and owns the shared conf struct (today's
  `ngx_http_brix_shared_conf_t` storage/tier fields move here). webdav/s3/cvmfs modules
  read it via `ngx_http_get_module_loc_conf(r, ngx_http_brix_common_module)` and stop
  carrying their own copies of these fields and their per-proto directive expansions.
  Rationale: nginx's `ngx_conf_handler` is first-module-wins on directive name matching, so
  the same name must not be registered by multiple http modules.
- **Stream plane:** the stream brix module keeps registering the same names in stream
  context (nginx precedent: `proxy_pass`, `ssl_certificate` exist in both planes). No
  cross-plane conflict.
- The phase-64 `BRIX_TIER_DIRECTIVES(prefix, …)` X-macro survives but is expanded exactly
  twice: once with `"brix_"` for stream (as today) and once with `"brix_"` in the http
  common module. The webdav/s3/cvmfs expansions are deleted.
- Per-protocol validation of unified values happens at postconfig (see §2), not at parse
  time, since the directive no longer knows which protocol will consume it.

## 2. Foot-gun fixes and validation

1. **One protocol per location, one per port (config-load error).** Postconfig walks all
   servers/locations: two brix protocols enabled in one `location{}` → error naming both
   directives and the location. All brix-enabled locations under one listen port must be
   the same protocol. Explicit non-violations: `brix_scvmfs on` is a TLS/authz layer on
   cvmfs (same location, same protocol); the stream `brix_http_handoff` single-port mux is
   the deliberate opt-in exception (its handoff target is its own plain-HTTP server block,
   which itself obeys the rule).
2. **Wire the read-side tier directives cvmfs currently ignores:** `brix_cache_evict_at`,
   `brix_cache_evict_to`, `brix_cache_max_object`, `brix_cache_index_cache`,
   `brix_cache_meta` now take effect under cvmfs (the sd_cache engine already supports
   them for webdav/s3; a site cache that cannot evict fills its disk).
3. **Reject what cannot work, loudly (config-load errors, one-line reason):** under a
   cvmfs-enabled location: `brix_stage on` / `brix_stage_store` / `brix_stage_flush`
   ("cvmfs is read-only"), `brix_allow_write on`, `brix_cache_slice_size` ("CAS objects
   are immutable whole objects"). No silent no-ops.
4. **Startup validation of origin selection:** `brix_cvmfs_origin_select geo` without
   `brix_cvmfs_here` → config error; `brix_cvmfs_origin_coords` present while not in geo
   mode → WARN (config-parse NOTICE is dropped; use WARN).
5. **`brix_export` under cvmfs** is optional and defaults to `/` (pure-cache-node
   semantics), so the grammar has no unexplained hole.

## 3. Production-grade defaults (the 3-line config)

Behavior flips:

- `brix_cache_verify` defaults to **`cvmfs-cas`** on the cvmfs plane (verify every fill
  against its SHA-1 content address; experts can set `off`). Other planes keep `off`
  (no verify scheme exists for them yet).
- `brix_cvmfs_origin_select` defaults to **`rtt`** (harmless with one origin, right with
  many; `static` and `geo` remain opt-in).

Everything else already defaults sensibly and simply disappears from examples:
`manifest_ttl 61`, `negative_ttl 10`, `client_hold 25`, `fill_max_life 300`,
`upstream_max 8`, `origin_connect_timeout 2`, `origin_stall_timeout 4`, `rtt_interval 60`.

Resulting minimal production configs:

```nginx
# forward-proxy site cache (Squid replacement)
location / {
    brix_cvmfs on;
    brix_cache_store posix:/srv/cvmfs-cache;
    brix_cvmfs_upstream_allow cvmfs-stratum-one.cern.ch cvmfs-s1fnal.opensciencegrid.org;
}

# reverse mode: replace upstream_allow with
#   brix_storage_backend http://s1.example.org:8000;
```

## 4. Docs & examples

- cvmfs joins `docs/03-configuration/directives.md` (full directive table **with
  defaults**), `docs/03-configuration/examples.md` (3-line minimal first, tuned production
  second), and the quick-reference.
- `deploy/cvmfs/README.md` examples shrink to the new form; a defaults table replaces
  restated-default lines.
- Old→new migration table published in docs.
- All in-repo configs migrate mechanically (scripted rewrite, then build + suites as the
  oracle): tests/, `tests/manage_test_servers.sh` templates, deploy/, docs/, site/.
  Rob's uncommitted `site/*.astro` edits are preserved except where directive names appear.
- CLAUDE.md directive references updated (ROUTING/RECIPES mention `xrootd_*` names).

## 5. Testing

Per the 3-tests rule, per change-class:

- **Success:** new names parse and behave on all four protocols; unified directive set at
  `server{}` level inherits into locations; the 3-line cvmfs config serves a verified
  fill end-to-end; rtt ranking active by default; cvmfs eviction directives evict.
- **Error:** old names rejected by `nginx -t` (spot-check the high-traffic ones);
  `brix_stage` under cvmfs → clear config error; two protocols in one location → error;
  two protocols on one port → error; `geo` without `brix_cvmfs_here` → error.
- **Security-negative:** default-on `cvmfs-cas` verify rejects and quarantines a corrupted
  CAS object; `brix_allow_write on` under cvmfs still hard-blocked.

Then: `tests/run_cvmfs_*.sh` suites, `tests/run_suite.sh --fast`, and the config-coverage
CI guard (`tools/ci/check_config_coverage` family) updated for the renamed surface.

## Out of scope

- Engine unification of the legacy stream sparse-fill cache (`brix_cache_*`) with the
  phase-64 sd_cache tier — naming is documented, engines stay separate.
- Back-compat aliases or migration tooling for out-of-repo configs (docs table only).
- Preset/profile macro directives and shipped include snippets.
- scvmfs (experimental) behavior changes beyond naming-rule documentation.
