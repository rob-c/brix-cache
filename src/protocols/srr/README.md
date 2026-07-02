# `src/protocols/srr/` — WLCG Storage Resource Reporting (SRR) endpoint

A small standalone HTTP sub-module that serves the WLCG **Storage Resource
Reporting** `storageservice` JSON document (schema v4.x) at an operator-chosen
location. WLCG accounting tooling — CRIC, the WLCG storage-space accounting
harvester, DIRAC occupancy plugins — pulls this document straight from an HTTP
URL to learn a site's total/used space per share and the protocol doors that
serve it.

## Why this instead of the XRootD UDP monitoring stack

This module **deliberately does not** implement the XRootD UDP f-stream /
g-stream binary monitoring protocol. WLCG storage accounting is already
HTTP/JSON-native via SRR, so a pull endpoint integrates with the existing WLCG
stack with far less effort — no `xrootd-monitoring-shoveler`, no AMQP collector,
no UDP packet format. Transfer/operation counters (bytes, transfers, opens,
cache, TPC, cluster) remain on the Prometheus `/metrics` endpoint
(`src/observability/metrics/`); a site that scrapes Prometheus can forward those to MonIT.

## Files

| File | Responsibility |
|---|---|
| `srr.h` | Public types: loc-conf, `xrootd_srr_share_t`, `xrootd_srr_endpoint_t`; handler + builder declarations. |
| `module.c` | nginx HTTP module: the `xrootd_srr*` directives, loc-conf create/merge, handler binding. Mirrors `src/observability/metrics/module.c`. |
| `builder.c` | `ngx_http_xrootd_srr_build_json()` — assembles the storageservice tree with jansson; per-share space via `xrootd_fs_usage_stat()` (statvfs); two-pass `json_dumpb()` into the request pool. |
| `handler.c` | `ngx_http_xrootd_srr_handler()` — GET/HEAD only, body discarded, sends `application/json`. Mirrors `src/observability/metrics/handler.c`. |

## Configuration

```nginx
# Serve at the conventional well-known path; record THIS URL in CRIC.
location = /.well-known/wlcg-storage-resource-reporting {
    xrootd_srr on;
    xrootd_srr_name     "UKI-SCOTGRID-GLASGOW";
    xrootd_srr_quality  production;            # optional (default production)
    xrootd_srr_version  "3.5";                 # optional → implementationversion

    # <name> <local-fs-path> [comma,separated,vos]
    xrootd_srr_share    atlas  /data/atlas  atlas;
    xrootd_srr_share    cms    /data/cms    cms;

    # <name> <interfacetype> <endpointurl>
    xrootd_srr_endpoint webdav davs  https://se.example.ac.uk:8443/;
    xrootd_srr_endpoint root   xroot root://se.example.ac.uk:1094/;
}
```

| Directive | Arg(s) | Maps to |
|---|---|---|
| `xrootd_srr` | `on`/`off` | enables the endpoint + binds the handler |
| `xrootd_srr_name` | name | `storageservice.name` (and `.id` if `xrootd_srr_id` unset) |
| `xrootd_srr_id` | id | `storageservice.id` |
| `xrootd_srr_quality` | level | `qualitylevel` (default `production`) |
| `xrootd_srr_version` | ver | `implementationversion` (default: product version from `core/ident.h`, currently `1.0.5`) |
| `xrootd_srr_share` | `<name> <path> [vos]` | one `storageshares[]` entry; `<path>` is `statvfs`'d for `totalsize`/`usedsize` and reported in `path[]`; `[vos]` → `vos[]` |
| `xrootd_srr_endpoint` | `<name> <iftype> <url>` | one `storageendpoints[]` entry |

`implementation` is fixed to the product name from `core/ident.h` (currently
`"GNUBall"`); `servicetype` is `"disk"`.
`storagecapacity.online.{totalsize,usedsize}` is the site-wide sum of the shares.
`latestupdate`/share `timestamp` are the request-time unix epoch.

## Semantics & caveats

- **Space** is live `statvfs(2)` on each share's local path, computed on every
  request (cheap; no caching needed). A share whose `statvfs` fails is reported
  as `0/0` with a `warn` log line so the document still validates. `usedsize` is
  statvfs *occupancy* (`(f_blocks - f_bfree) * frsize`, i.e. `total - free`,
  which includes root-reserved blocks) — the WLCG/GLUE2 convention. A consumer
  computing `free = totalsize - usedsize` therefore slightly under-counts the
  space actually writable by an unprivileged user (by the reserved-block amount).
- **`path`** is reported as the configured local path. If a site's namespace
  path differs from the on-disk path, set the share path to the value VOs see.
- **Capacity double-counting**: if two shares live on the same filesystem the
  top-level `storagecapacity.online` sum will count it twice. Give each distinct
  quota/filesystem its own share (the normal WLCG layout).
- **No per-VO quota accounting**: `usedsize` is filesystem-level, not per-VO. If
  a share is shared by several VOs, list them all in `[vos]`; the used figure is
  the whole share. Per-VO directory accounting is a future enhancement.
- **No request input** is read — the document is a pure function of the config +
  filesystem state, so query strings/headers cannot redirect which path is
  stat'd.
- **Auth**: the endpoint is unauthenticated by default (CRIC harvests
  anonymously). Wrap the `location` in nginx access controls
  (`allow`/`deny`, token auth) if your site requires it.

## Schema conformance

Required fields emitted unconditionally (WLCG SRR v4.x): `storageservice`
→ `implementation`, `implementationversion`, `storageendpoints[]`,
`storageshares[]`; `storagecapacity.online` → `totalsize`, `usedsize`;
each endpoint → `name`, `endpointurl`, `interfacetype`, `assignedshares[]`;
each share → `timestamp`, `totalsize`, `usedsize`, `vos[]`.

Reference schema:
`github.com/sjones-hep-ph-liv-ac-uk/json_info_system` (`srr/v4.2`).
Tests: `tests/test_srr_endpoint.py`.
