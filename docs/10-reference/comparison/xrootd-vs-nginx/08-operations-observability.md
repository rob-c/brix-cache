# Operations & Observability: official XRootD vs BriX-Cache

> Part of the [XRootD vs BriX-Cache comparison set](./README.md).

## Scope

This document compares how the **official XRootD** server and the
**BriX-Cache** module are *run and watched* by an operator. It covers six
operational surfaces:

1. **Configuration model** — directive grammar, scoping, and reload behavior.
2. **Metrics & monitoring** — how transfer and server state is exported.
3. **SciTags / packet marking** — WLCG network flow tagging.
4. **Storage Resource Reporting (SRR)** — WLCG site space/space accounting.
5. **Logging** — access logs, error logs, and log sanitization.
6. **Health, packaging, deployment** — liveness probes, RPMs, logrotate,
   Grafana, alerts, runbooks.
7. **Policy** — rate limiting / bandwidth / concurrency shaping.

The single most important framing for this whole document, and a **deliberate
design decision** by the maintainer, is the monitoring *paradigm*:

> Official XRootD observability is **push-over-UDP** (the XrdMon detail/f/g
> streams plus the `xrd.report` summary feed), consumed by separate collectors.
> BriX-Cache deliberately does **not** implement UDP monitoring; it exposes
> **pull-over-HTTP** observability — Prometheus `/metrics`, a JSON SRR endpoint,
> a REST dashboard/admin API, and JSON access logs.

This is called out explicitly in the module's own source: `src/protocols/srr/README.md`
states the project intentionally replaces XRootD UDP f/g-stream monitoring with
HTTP/JSON pull, and `src/observability/metrics/README.md` documents the Prometheus exporter as
"the single observability spine." It is also recorded as a product decision in
[`docs/10-reference/source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md)
(Observability section: "UDP XrdMon stream monitoring … Not implemented.
Explicit product decision: do not implement. Use HTTP-native observability
instead.").

Claims below are grounded in source; where a feature is absent from a code tree
the doc says "not found in core" / "not implemented" rather than guessing.

---

## In official XRootD

XRootD is a multi-daemon system (`xrootd`, `cmsd`, `frm_*`) configured from a
single text config file (conventionally `/etc/xrootd/xrootd-<instance>.cfg`),
parsed by `XrdOuc`, and observed through two independent UDP feeds and the
process log:

- **Config parser:** `XrdOuc/XrdOucStream.{cc,hh}` (tokenizer, `if/else/fi`,
  `set`/`setenv`, `$var` expansion, `continue` includes), `XrdOuc/XrdOucEnv.{cc,hh}`
  (name=value store for substitution and cross-plugin handoff), and
  `XrdOuc/XrdOucGatherConf.{cc,hh}` (prefix-selective directive gathering).
  Core directives are dispatched in `Xrd/XrdConfig.cc` via `TS_Xeq` tables.
- **Monitoring (detail + f + g streams):** `XrdXrootd/XrdXrootdMonitor.{cc,hh}`
  with the wire layout in `XrdXrootd/XrdXrootdMonData.hh`, configured by
  `xrootd.monitor` / `xrootd.mongstream` (parsers `xmon()` / `xmongs()` in
  `XrdXrootd/XrdXrootdConfigMon.cc`). The f-stream (fstat) builder is
  `XrdXrootdMonFile.{cc,hh}` + `XrdXrootdMonFMap.{cc,hh}`; the generic g-stream
  object is `XrdXrootdGStream.hh` / `XrdXrootdGSReal.{cc,hh}`.
- **Summary reporting:** `xrd.report` (parser `xrep()` in `Xrd/XrdConfig.cc`,
  engine `Xrd/XrdStats.{cc,hh}`, per-protocol block `XrdXrootd/XrdXrootdStats.{cc,hh}`)
  emits an XML (or `json`) `<statistics>` summary document over UDP on an
  interval.
- **Packet marking / SciTags:** `XrdNet/XrdNetPMark.{cc,hh}` (abstract
  interface, 16-bit SciTag = 10-bit experiment + 6-bit activity),
  `XrdNet/XrdNetPMarkCfg.{cc,hh}` (the `pmark` directive + maps + JSON defs),
  `XrdNet/XrdNetPMarkFF.{cc,hh}` (Firefly UDP), plus
  `XrdHttpTpc/XrdHttpTpcPMarkManager.{cc,hh}` for per-stream TPC marking.
- **Logging:** `XrdSys/XrdSysLogger.{cc,hh}` (file sink + daily/FIFO rotation),
  `XrdSys/XrdSysError.{cc,hh}` (formatter), `XrdSys/XrdSysTrace.{cc,hh}` (trace);
  trace verbosity via `xrd.trace` (`XrdConfig::xtrace`) and per-component
  `*.trace` directives.
- **Packaging:** the in-tree RPM spec `xrootd.spec` (many sub-packages),
  templated systemd units in `systemd/` (`xrootd@.service`, `cmsd@.service`,
  `frm_*@.service`, plus `.socket` units), and `config/xrootd.logrotate`.

Not present in the reviewed core tree: a Prometheus/HTTP metrics endpoint, an
HTTP health/readiness probe, and a built-in WLCG SRR endpoint (SRR is provided
by external tooling). Core config is **restart-only** — there is no SIGHUP
config reload.

## In BriX-Cache

BriX-Cache is a single nginx process tree (master + workers) configured from
`nginx.conf` using `xrootd_*` directives inside `stream{}` (for `root://`) and
`http{}` (for WebDAV / S3 / metrics / dashboard / SRR / health). Observability
is consolidated into one shared-memory metrics spine plus several HTTP
endpoints:

- **Metrics:** `src/observability/metrics/` — one SHM object (`ngx_xrootd_metrics_t`) written
  lock-free by every protocol via increment macros (`metrics_macros.h`) and read
  back as Prometheus text by `ngx_http_xrootd_metrics_handler()`
  (`handler.c`), with per-protocol exporters in `stream.c`, `webdav.c`,
  `s3.c`, `cluster.c`, `unified.c`, `ratelimit.c`, `stream_proxy.c`,
  `stream_cache.c`, `stream_tracking.c`, `writer.c`. The `xrootd_metrics`
  location directive is declared in `module.c`; the conventional listener is
  `:9100` (`src/observability/metrics/README.md`).
- **Dashboard / admin:** `src/observability/dashboard/` — a REST read API
  (`/xrootd/api/v1/transfers|events|history|cluster|cache|ratelimit|config`),
  an anonymous PII-free tier, a fail-closed config-download endpoint
  (`config_download.c`), and a CIDR+secret-gated admin write API
  (`api_admin.c`).
- **SciTags:** `src/observability/pmark/` — both **Firefly UDP** (`firefly.c`, port 10514,
  byte-compatible with `XrdNetPMarkFF`) and in-band **IPv6 flow-label** marking
  (`flowlabel.c`, WLCG flow-label bit layout). Integrated into `root://`,
  WebDAV, S3, and TPC.
- **SRR:** `src/protocols/srr/` — an HTTP/JSON WLCG `storageservice` endpoint
  (`builder.c` + `handler.c`), conventionally served at
  `/.well-known/wlcg-storage-resource-reporting`.
- **Logging:** `src/observability/metrics/access_log.c` emits a per-op JSON access log; nginx's
  own error log carries diagnostics; `xrootd_sanitize_log_string()`
  (declared `src/fs/path/path.h`) escapes wire-derived strings to defeat log
  injection.
- **Health & packaging:** `src/observability/metrics/health.c` serves `/healthz`;
  `packaging/rpm/nginx-mod-brix-cache.spec` builds three RPMs; `contrib/` ships a
  Grafana dashboard, Prometheus alert rules, a logrotate snippet, and an example
  config.
- **Policy:** `src/net/ratelimit/` — leaky-bucket rate, bandwidth, and concurrency
  controls keyed by VO / issuer / IP / DN / volume prefix, answering `kXR_wait`
  (stream) or HTTP `429` (HTTP).

Reload is graceful: `nginx -s reload` re-reads `nginx.conf` and rolls workers
while SHM zones (metrics, rate-limit buckets) survive.

---

## Configuration model

### Official XRootD: `XrdOuc` directive grammar

The config file is a flat, prefix-scoped directive stream. Each plugin reopens
and filters the same file for the token *before the first dot*: the core daemon
consumes `xrd.*` / `all.*` (`XrdConfig.cc` `ConfigXeq`), the protocol consumes
`xrootd.*`, OFS consumes `ofs.*` / `all.*` (`XrdOfsConfig.cc`), and `pss.`,
`acc.`, `sec.`, `http.`, `pfc.` are each consumed by their owning plugin's
`ConfigXeq`. Grammar features (all in `XrdOucStream.cc`):

- **Continuation** — trailing `\` joins a logical line.
- **Conditionals** — `if [<hostlist>] [exec <pgm>] [named <instlist>] … else … fi`.
- **Variables** — `set [-q|-v] var = value` and `setenv var = value`, expanded as
  `$var` / `${var}` / `$(var)` (escape `\$`); XRD-prefixed names are reserved.
- **Includes** — `continue <path> [*suffix …] [if …]`.
- **Comments** — `#`.

**Reload: restart-only.** `XrdConfig::ConfigXeq` carries a `dynamic` flag, but
one-time directives (port, protocol, adminpath, maxfd, tls, sitename, …) apply
only at startup; `Configure()` runs once and no SIGHUP config-reload handler is
registered (SIGHUP is merely recognized as a signal *name* in
`XrdSys/XrdSysUtils.cc`). Only component *data files* refresh at runtime on their
own timers (e.g. GSI CRL/GMAP, the VOMS mapfile in `XrdVomsMapfile.cc`) — not
the config file. Changing a server directive means a daemon restart
(operationally, a systemd `restart` of `xrootd@<instance>`).

### BriX-Cache: nginx blocks with `xrootd_*` directives

Directives are nginx `ngx_command_t` entries declared in the module command
tables (`src/protocols/root/stream/module.c`, `src/protocols/root/stream/module_core_directives.c`,
`src/protocols/root/stream/module_cache_proxy_directives.c`, `src/protocols/webdav/module.c`,
`src/protocols/s3/module.c`, plus the metrics/dashboard/srr/pmark module tables). They are
merged main→srv→loc by `src/core/config/` (`process.c`, `server_conf.c`,
`postconfiguration.c`, `runtime_server.c`, `merge_macros.h`) and follow nginx
grammar — `{}` blocks, `;`-terminated directives, `include` files, `if`
(nginx's own), variables. `root://` lives in `stream{}`; WebDAV / S3 / metrics /
dashboard / SRR / health live in `http{}` `location` blocks.

**Reload: graceful.** `nginx -s reload` re-reads the config, validates with
`nginx -t`, then spins up new workers and drains old ones with zero dropped
connections; SHM zones (metrics counters, rate-limit buckets) persist across the
reload.

### Common-knob mapping table

| Operator knob | Official XRootD directive | BriX-Cache directive | Notes |
|---|---|---|---|
| Listen port | `xrd.port <n>` (or `-p`) | `listen` in `server{}` + `xrootd_listen_port` | nginx port is the `listen` line; module advertises via `xrootd_listen_port` |
| Export / namespace root | `all.export <path>` / `oss.localroot` | `xrootd_root <path>` | Confinement root |
| Read-only / write gate | `xrootd.export … r/w` flags | `xrootd_allow_write on\|off` | Global write gate (checked before token scope) |
| TLS cert / key | `xrd.tls <cert> <key>` | `xrootd_certificate` / `xrootd_certificate_key` (+ nginx `ssl_*`) | |
| Trusted CAs / CRL | `sec.xtrace` + GSI CA dirs | `xrootd_trusted_ca`, `xrootd_crl`, `xrootd_crl_reload` | |
| Token issuer / audience | `sciTokens.cfg` (XrdSciTokens) | `xrootd_token_issuer`, `xrootd_token_audience`, `xrootd_token_jwks` | |
| UDP transfer monitoring | `xrootd.monitor … dest <h:p>` | *(none — by design)* | Replaced by Prometheus pull |
| Summary stats feed | `xrd.report <h:p> every <t>` | *(none — by design)* | Replaced by Prometheus pull |
| Metrics endpoint | *(not in core)* | `xrootd_metrics on;` (location, `:9100`) | Prometheus scrape |
| Health endpoint | *(not in core)* | `xrootd_health on;` (`/healthz`) | k8s liveness probe |
| SciTags / packet marking | `pmark …` (`XrdNetPMark`) | `xrootd_pmark`, `_firefly`, `_flowlabel`, `_defsfile`, `_map_experiment`, `_map_activity` | Firefly + IPv6 flow-label |
| SRR space reporting | *(external tool)* | `xrootd_srr`, `_share`, `_endpoint`, `_quality` | Built-in JSON endpoint |
| Rate / bandwidth shaping | `throttle.*` (XrdThrottle), XrdBwm | `xrootd_rate_limit_zone`, `xrootd_rate_limit_rule`, `xrootd_bandwidth_limit`, `xrootd_concurrency_limit` | Identity-aware, cross-protocol |
| Log file | `-l <file>` | `error_log` / `xrootd_access_log` | |
| Trace verbosity | `xrd.trace <events>`, `*.trace` | `error_log <file> debug;` (nginx) | |
| **Apply changes** | **daemon restart** | **`nginx -s reload`** (graceful) | Core difference |

---

## Metrics & monitoring

This is the **paradigm difference**: official push-UDP vs BriX-Cache
pull-HTTP.

### Official XRootD — UDP XrdMon streams + `xrd.report`

Two independent UDP feeds, each pointed at one or two `dest <host:port>`
collectors:

**1. XrdMon stream monitoring** (`xrootd.monitor` / `xrootd.mongstream`,
parsers in `XrdXrootdConfigMon.cc`; wire format in `XrdXrootdMonData.hh`). Every
UDP packet starts with `XrdXrootdMonHeader{code,pseq,plen,stod}`; the `code`
byte selects the stream:

- **Detail / trace streams** (`=` map-ident, `d` path-map, `i` appinfo, `u`
  user-map, `T` token-map, `x` xfer-map, `r` redirect): dictionary records that
  map a small `dictid` to a full identity/path string, plus per-event traces
  (`XROOTD_MON_OPEN 0x80`, `CLOSE 0xc0`, `DISC 0xd0`, `READV 0x90`, window
  marks, etc.). This is the high-detail per-transfer feed.
- **f-stream (fstat)** (`f` = `XROOTD_MON_MAPFSTA`, builder
  `XrdXrootdMonFile.cc`): per-file open/close/xfr/disc records, optionally with
  LFN, I/O op counts, and sum-of-squares (`fstat <sec> [lfn] [ops] [ssq] [xfr <n>]`).
- **g-stream (generic)** (`g` = `XROOTD_MON_MAPGSTA`, object
  `XrdXrootdGSReal.cc`): a pluggable provider channel — each provider stamps a
  sub-code (`C` pfc, `P` tpc, `R` throttle, `O` oss, `H` http, `T` tcpmon, …)
  and registers an `XrdXrootdGStream` via env handoff.

Directive grammar (`xmon()`):

```
monitor [all] [auth] [flush [io] <sec>]
        [fstat <sec> [lfn] [ops] [ssq] [xfr <n>]]
        [{fbuff|fbsz} <sz>] [gbuff <sz>] [ident {<sec>|off}]
        [mbuff <sz>] [rbuff <sz>] [rnums <cnt>] [window <sec>]
        [dest [Events] <host:port>]      # up to two dest
```

**2. Summary reporting** (`xrd.report`, parser `xrep()`, engine
`XrdStats.cc`): emits a `<statistics tod=… ver=… src=host:port>` XML (or `json`)
document over UDP every interval (default 600s), wrapping per-protocol blocks
such as `<stats id="xrootd">` (open/read/write/redir/stall/async/login
counters, `XrdXrootdStats.cc`).

```
report <dest1>[,<dest2>] [every <sec>] [json] [<opts>]
```

There is **no `xrd.stats` config directive** in core; summary stats reach
collectors only via `xrd.report` (a client may also pull `<stats>` synchronously
via the `kXR_query` stats protocol op, but that is not a config knob).

**Collector ecosystem (separate projects, not in this tree):** the
xrootd-monitoring **shoveler**, **MonaLisa / ApMon**, and Prometheus-via-shoveler
pipelines all consume these UDP feeds out-of-process. The server only *emits*
UDP; aggregation, retention, and dashboards live downstream. Operators must run
and secure a collector, and the per-transfer detail stream is high-volume.

### BriX-Cache — Prometheus `/metrics` (pull) + dashboard REST

**Model:** lock-free SHM atomic counters (write side, every worker) read back as
Prometheus text-exposition (`text/plain; version=0.0.4`) by a dedicated HTTP
location. No UDP, no collector daemon — any Prometheus scrapes the endpoint on
its own schedule (conventionally `:9100`, `xrootd_metrics on;` in a
`location /metrics`). The write path is a single `ngx_atomic_fetch_add` per
slot; `xrootd_metrics_shared()` (`metrics_macros.h`) no-ops safely when the SHM
zone is unmapped.

The increment macros define the metric families:

- `XROOTD_SRV_METRIC_INC/_ADD` (per-server, `root://`)
- `XROOTD_WEBDAV_METRIC_INC/_ADD`, `XROOTD_S3_METRIC_INC/_ADD`
- `XROOTD_PROXY_METRIC_INC/_ADD` (+ bound-checked per-upstream `XROOTD_PROXY_UP_INC`)
- `XROOTD_PMARK_METRIC_INC`, `XROOTD_RESIL_METRIC_INC`, `XROOTD_FRM_METRIC_INC/_DEC/_ADD`

Representative exposed metric names (grepped from `src/observability/metrics/*.c`):

| Group | Example metric names |
|---|---|
| Wire / stream | `xrootd_requests_total`, `xrootd_wire_bytes_rx_total`, `xrootd_wire_bytes_tx_total`, `xrootd_stream_connections_rejected_total`, `xrootd_stream_handshake_timeouts_total` |
| Unified (proto-labeled) | `xrootd_io_ops_total`, `xrootd_io_latency_usec_bucket` (histogram), `xrootd_auth_total`, `xrootd_tpc_transfers_total` |
| WebDAV | `xrootd_webdav_requests_total`, `xrootd_webdav_responses_total`, `xrootd_webdav_bytes_rx_ipv4_total`/`_ipv6_total`, `xrootd_webdav_tpc_total`, `xrootd_webdav_cors_total` |
| S3 | `xrootd_s3_requests_total`, `xrootd_s3_auth_total`, `xrootd_s3_put_bodies_total`, `xrootd_s3_list_truncated_total` |
| Proxy | `xrootd_proxy_opens_total`, `xrootd_proxy_reconnects_total`, `xrootd_proxy_upstream_auth_errors_total`, `xrootd_proxy_abandoned_handles_total` |
| PMark | `xrootd_pmark_firefly_sent_total`, `xrootd_pmark_flowlabel_set_total`, `xrootd_pmark_flows_started_total` |
| Resilience | `xrootd_auth_l1_hits_total`/`_misses_total`, `xrootd_ocsp_timeouts_total`, `xrootd_cms_read_timeouts_total`, `xrootd_acc_nss_breaker_open_total` |
| FRM (tape) | `xrootd_frm_stage_success_total`, `xrootd_frm_stage_fail_total`, `xrootd_frm_reject_inflight_total` |

**Low-cardinality label rule (security boundary, enforced).**
`src/observability/metrics/README.md` and CLAUDE.md invariant #8 mandate that label values are
low-cardinality enums only: paths, bucket names, object keys, DNs, token
subjects, and S3 access keys must never appear as labels. Per-VO / per-user views
are made safe with bounded LRU tables and FNV-1a hashing
(`xrootd_track_vo_activity()` / `xrootd_track_unique_user()` in
`tracking.c`). Free-form identity goes to the JSON access log instead (see
Logging).

**Dashboard / admin REST API** (`src/observability/dashboard/`) complements the scrape with a
live operator view:

- Read API: `/xrootd/api/v1/transfers`, `/events`, `/history`, `/cluster`,
  `/cache`, `/ratelimit`, `/snapshot`, `/config`, plus a UI page (`page.c`).
- Anonymous PII-free tier (`xrootd_dashboard_anonymous`) for read-only embeds.
- Config download `GET /xrootd/api/v1/config` (`config_download.c`) is
  **fail-closed**: every directive value is `[redacted]` unless whitelisted, URL
  credentials and `token=/secret=/sig=` query values are scrubbed, and the route
  always requires auth.
- Admin write API `/xrootd/api/v1/admin/` (`api_admin.c`, Phase 23): CIDR
  allowlist + bearer secret (`CRYPTO_memcmp`, min 16 bytes, fail-closed),
  every action `admin_audit()`-logged — cluster register/drain/undrain/delete,
  WebDAV-proxy backend management, io_uring runtime kill switch.

**Operator view contrast:** an XRootD operator runs and watches a UDP collector
(shoveler/MonaLisa) and reads `<statistics>` XML / per-transfer records; an
BriX-Cache operator points Prometheus at `/metrics`, builds Grafana panels,
and watches the live dashboard — no extra daemon to run.

---

## SciTags / packet marking

WLCG SciTags tag each network flow with a 16-bit value = **10-bit experiment ID
+ 6-bit activity ID**, so the network can attribute traffic. Both
implementations encode the same `(experiment, activity)` and are fail-open
(marking never blocks or slows a transfer).

### Official XRootD — `XrdNetPMark` (Firefly UDP)

- Interface `XrdNet/XrdNetPMark.hh` packs `experiment = upper 10 bits`,
  `activity = lower 6 bits` (`btsActID=6, mskActID=63`); `getEA()` reads the
  `scitag.flow` CGI / `scitag` HTTP header.
- The active transport is **Firefly UDP telemetry** (`XrdNetPMarkFF.cc`): JSON
  lifecycle docs sent to a collector (default UDP 10514) and optionally echoed
  to the origin.
- **IPv6 flow-label marking is configured but NOT implemented** — there is a
  TODO in `XrdNetPMarkCfg.cc`; no DSCP/`IP_TOS` path either.
- Directive `pmark …` (`XrdNetPMarkCfg.cc`): `defsfile` (local/`curl`/`wget`
  JSON defs), `map2exp` (path/vo/default → experiment), `map2act` (role/user →
  activity), `ffdest`, `ffecho`, and `use {flowlabel|firefly|scitag|…}`.
- Wired across `root://` (`XrdXrootdProtocol` per-stream `pmHandle`), HTTP
  GET/PUT, and HTTP-TPC (`XrdHttpTpcPMarkManager.cc`, one Firefly handle per
  stream).

### BriX-Cache — `src/observability/pmark/` (Firefly UDP **and** IPv6 flow-label)

- **Firefly UDP** (`firefly.c`): RFC5424-syslog-wrapped JSON `start`/`ongoing`/
  `end` docs, default UDP port 10514, byte-compatible with `XrdNetPMarkFF`.
- **IPv6 flow-label** (`flowlabel.c`): in-band 20-bit label via
  `setsockopt(IPV6_FLOWLABEL_MGR)` + `IPV6_FLOWINFO_SEND` — **implemented**,
  where official core has a TODO. Encodes the WLCG
  `draft-cc-v6ops-wlcg-flow-label-marking` layout (activity at bits 2–7,
  community/experiment at bits 9–17 in reversed bit order, 5 entropy bits),
  pinned in `xrootd_pmark_flowlabel_encode()`; no-op on IPv4/v4-mapped.
- Supporting files: `scitag.c` (range-checked `scitag.flow=N` parser; client
  bytes never reach Firefly JSON), `defsfile.c` (jansson defs registry),
  `mapping.c` (scitag → path-glob → VO → default priority), `sockstats.c`
  (`TCP_INFO`).
- Integration: `root://` flow begun in `src/protocols/root/read/open_request.c`, ended in
  `src/protocols/root/connection/disconnect.c`; WebDAV/S3 begun in `dispatch.c` / `handler.c`,
  ended via pool cleanup. **TPC is always marked; plain GET/PUT only with
  `xrootd_pmark_http_plain`.**
- Directives: `xrootd_pmark`, `_firefly`, `_firefly_dest`, `_flowlabel`,
  `_defsfile`, `_map_experiment`, `_map_activity`, `_http_plain`, `_scitag_cgi`,
  `_domain`, `_echo`, `_appname`.

**Net difference:** both ecosystems do Firefly UDP; BriX-Cache additionally
ships working IPv6 in-band flow-label marking (not "firefly-only"), which the
official core leaves as a TODO.

---

## Storage Resource Reporting (SRR)

WLCG SRR publishes a site's storage shares, capacity, and access endpoints as a
JSON document harvested by CRIC.

- **Official XRootD:** **not found in core.** A whole-tree search for
  "Storage Resource Reporting", `storage.json`, `getspaces`, etc. returns
  nothing in the daemon; the only WLCG-named code is the **SciTokens** authz
  plugin (`src/XrdSciTokens/`), which is unrelated. SRR for XRootD sites is
  produced by **external tooling**, not the server process.
- **BriX-Cache:** a built-in HTTP/JSON sub-module, `src/protocols/srr/`
  (`builder.c` + `handler.c` + `module.c`). It serves the WLCG `storageservice`
  schema (GET/HEAD, `application/json`), conventionally at
  `location = /.well-known/wlcg-storage-resource-reporting`, unauthenticated by
  default so CRIC can harvest. `ngx_http_xrootd_srr_build_json()` emits
  `storageservice` → `implementation` (`"nginx-xrootd"`),
  `implementationversion`, `storageendpoints[]`, `storageshares[]`, and
  `storagecapacity.online.{totalsize,usedsize}` summed across shares, with live
  per-share usage from `statvfs(2)` per request. Directives:
  `xrootd_srr`, `xrootd_srr_name`, `xrootd_srr_id`, `xrootd_srr_quality`
  (default `production`), `xrootd_srr_version`, `xrootd_srr_share <name> <path>
  [vos]`, `xrootd_srr_endpoint <name> <iftype> <url>`.

**Operator view:** an XRootD site operator scripts/installs a separate SRR
generator and serves the file out of band; an BriX-Cache operator turns on
`xrootd_srr` and registers the URL in CRIC.

---

## Logging

### Official XRootD

- One human-readable text log via `XrdSysLogger` (timestamp prefix
  `YYMMDD HH:MM:SS <tid>`, hi-res adds microseconds), file selected by `-l <fn>`.
- `XrdSysError::Emsg()` formats errors as
  `<prefix><suffix>: error <n> (sys text); <detail>`; `Say()` is plain text.
- **Rotation is built into the logger** (`XrdSysLogger.hh`): daily midnight
  rotation, no rotation, or FIFO-triggered manual rotation; `ParseKeep()`
  parses keep-count / max-size / `fifo`. `config/xrootd.logrotate` cooperates by
  pinging the FIFO in `postrotate`.
- **Per-transfer structured events do NOT go to the log** — they go to the
  XrdMon UDP stream. The text log carries diagnostics/warnings/errors, plus
  per-I/O lines only when the matching `*.trace` bits are enabled (`xrd.trace`,
  `ofs.trace`, …). There is **no separate structured access-log file** in core;
  the access-log equivalent is the UDP feed.

### BriX-Cache

- **JSON access log** (`src/observability/metrics/access_log.c`, `access_log.h`):
  `xrootd_access_log_emit()` writes one JSON record per VFS op — timestamp,
  protocol, op, path, bytes, offset, latency, error, cache-hit, auth method,
  subject/DN — via `ngx_log_error(NGX_LOG_INFO)` prefixed `xrootd_access_json:`.
  Free-text fields are escaped by `xrootd_access_json_escape()` (escapes `"`/`\`,
  renders bytes `<0x20` / `≥0x7f` as `\u00NN`). This is the deliberate home for
  the high-cardinality fields banned from metric labels.
- **Per-protocol log files** (from `contrib/xrootd.conf.example`):
  `xrootd_webdav_access.log`, `xrootd_s3_access.log`; the `root://` access log is
  configured with `xrootd_access_log` (opened in `src/core/config/runtime_server.c`,
  set `off` to disable). A separate path-layer access log lives in
  `src/observability/accesslog/access_log.c`. nginx's own `error_log` carries diagnostics/debug.
- **`xrootd_sanitize_log_string()`** (declared `src/fs/path/path.h`, used across
  `src/auth/authz/acl.c`, `authdb.c`, `resolve_confined_helpers.c`, token validation,
  dirlist, host auth): escapes control bytes, quotes, backslashes, and non-ASCII
  to `\xNN`, so wire-derived strings cannot inject or forge log lines. Mandated
  by CLAUDE.md ("Log strings from wire").

**Operator view:** XRootD logs ship as text with logger-managed rotation, and
transfer accounting comes off the UDP monitor; BriX-Cache logs ship as
nginx-native JSON/text that drops straight into existing nginx log-shipping
(logrotate, Loki/ELK), with transfer detail in the JSON access log and
aggregate counts in Prometheus.

---

## Health, packaging, deployment

| Concern | Official XRootD | BriX-Cache |
|---|---|---|
| Health / readiness probe | **Not in core** — liveness inferred from systemd / UDP feeds; no HTTP probe | `/healthz` (`src/observability/metrics/health.c`, `xrootd_health on;`): `{"status":"ok","service":"nginx-xrootd"}`, `?verbose` adds `metrics_shm`/`worker_pid`/`nginx_version`; wires directly to k8s `livenessProbe` |
| RPM packaging | `xrootd.spec` — many sub-packages (`xrootd-server`, `-libs`, `-client`, `-scitokens`, `-fuse`, `python3-xrootd`, …) | `packaging/rpm/nginx-mod-brix-cache.spec` — **3 packages**: `nginx-mod-brix-cache` (dynamic modules), `brix-cache-client` (native xrdcp/xrdfs/xrootdfs), `brix-cache-tests` (conformance suite) |
| Service management | systemd templated units `xrootd@.service`, `cmsd@.service`, `frm_*@.service` + `.socket` units, `EnvironmentFile=/etc/sysconfig/xrootd` | standard nginx service (master/worker); `nginx -s reload` for graceful change |
| Logrotate | `config/xrootd.logrotate` (cooperates with logger FIFO) | `contrib/logrotate.d/nginx-xrootd` |
| Dashboards | external (MonaLisa, shoveler→Prometheus pipelines) | `contrib/grafana-dashboard.json` |
| Alerts | external | `contrib/prometheus-alerts.yml` |
| Example config | `config/xrootd-*.cfg` | `contrib/xrootd.conf.example` |
| Runbooks | XRootD project docs | `docs/09-developer-guide/testing-runbook.md` |

**Operator view:** an XRootD operator manages multiple systemd-templated daemons
and an external monitoring pipeline; an BriX-Cache operator manages one nginx
service plus drop-in Grafana/alerts/logrotate artifacts and an HTTP liveness
probe.

---

## Policy: rate limiting

This surface is largely **nginx-forward** — it follows nginx's leaky-bucket
model and adds identity awareness across protocols.

### Official XRootD

- **`XrdThrottle`** plugin (`src/XrdThrottle`): per-server I/O and request-rate
  throttling, fed into the g-stream (`R` provider).
- **`XrdBwm`** (`src/XrdBwm`): bandwidth-manager / reservation hooks with an
  event-logger feed.

These are plugins configured via their own directives; they are not identity
(VO/issuer/DN)-aware in the same first-class way.

### BriX-Cache — `src/net/ratelimit/`

A **leaky-bucket** core (`ratelimit.c`, modeled on
`ngx_http_limit_req_module`): per-principal `xrootd_rl_node_t` slab-allocated in
an rbtree + LRU (O(1) eviction), held in SHM so buckets survive `nginx -s
reload`. Request units are stored ×1000; `req_excess` is the bucket.

- **Key dimensions** (`ratelimit.h`): `VO`, `ISSUER` (token issuer URL), `IP`
  (client addr), `DN` (GSI subject DN, hashed), `VOLUME` (longest-prefix match
  on request path). Keys are low-cardinality / hashed per the same metric-label
  rule.
- **Directives:** `xrootd_rate_limit_zone` (SHM zone), `xrootd_rate_limit_rule`
  (`zone=/key=/rate=/burst=/nodelay=`), `xrootd_bandwidth_limit`,
  `xrootd_concurrency_limit` (`zone=/key=/limit=`), plus a legacy
  `xrootd_rate_limit`.
- **Over-limit responses:**
  - HTTP → **`429 Too Many Requests`** with `Retry-After` (unless `nodelay`);
    bandwidth overflow also `429` (`ratelimit_http.c`).
  - `root://` stream → **`kXR_wait(seconds)`** keeping the connection open for
    client retry (`ratelimit_stream.c`: rate, bandwidth, and concurrency-cap
    paths).
- Snapshots are exposed to the dashboard (`xrootd_rl_snapshot`) and counters to
  Prometheus (`src/observability/metrics/ratelimit.c`).

**Net difference:** XRootD shapes per-server (throttle/BWM plugins);
BriX-Cache shapes by *identity* (VO/issuer/DN/IP/volume) uniformly across
`root://`, WebDAV, and S3, with both `kXR_wait` and HTTP `429` backpressure.

---

## Parity, divergences, and design choices

| Capability | Official XRootD | BriX-Cache | Assessment |
|---|---|---|---|
| Config grammar | `XrdOuc` (if/set/continue, prefix-scoped) | nginx blocks + `xrootd_*` | Different but comparable |
| **Config reload** | **Restart-only** (no SIGHUP) | **`nginx -s reload`** graceful | BriX-Cache advantage |
| Per-transfer monitoring | XrdMon detail/f stream (UDP push) | JSON access log + dashboard transfers (HTTP pull) | Paradigm difference (deliberate) |
| Aggregate metrics | `xrd.report` XML/JSON (UDP push) | Prometheus `/metrics` (HTTP pull) | Paradigm difference (deliberate) |
| Generic monitoring channel | g-stream (pluggable providers) | metric families per subsystem | Different model |
| External collector required | Yes (shoveler / MonaLisa) | No (Prometheus scrapes directly) | BriX-Cache simpler ops |
| Live operator dashboard | external | built-in REST + UI (`src/observability/dashboard/`) | BriX-Cache advantage |
| Admin write API | admin tooling / `xrootd.admin` socket | `/api/v1/admin` (CIDR+secret, audited) | Different surface |
| SciTags Firefly UDP | Yes (`XrdNetPMarkFF`) | Yes (`firefly.c`, byte-compatible) | Parity |
| SciTags IPv6 flow-label | **TODO (not implemented)** | **Implemented** (`flowlabel.c`) | BriX-Cache advantage |
| WLCG SRR endpoint | Not in core (external tool) | Built-in `src/protocols/srr/` JSON | BriX-Cache advantage |
| Access log | Text + UDP monitor | JSON access log (sanitized) | Different; nginx-native |
| Log sanitization | logger escaping | `xrootd_sanitize_log_string()` | Parity-ish |
| Log rotation | logger-managed (daily/FIFO) | logrotate (`contrib/`) | Different mechanism |
| HTTP health probe | **Not in core** | `/healthz` | BriX-Cache advantage |
| Packaging | many sub-RPMs + systemd templates | 3 RPMs + nginx service | Different shape |
| Rate / bandwidth / concurrency | XrdThrottle, XrdBwm (per-server) | `src/net/ratelimit/` (identity-aware, cross-protocol) | Parity / BriX-Cache+ |

**Deliberate design choices to call out:**

1. **HTTP pull over UDP push (the central decision).** The maintainer
   intentionally did not implement XrdMon UDP f/g-stream monitoring or
   `xrd.report`. Observability is HTTP-native (Prometheus, SRR, dashboard, JSON
   logs) so it drops into modern site monitoring without a separate collector
   daemon. This is recorded as a product decision, and "do not implement UDP
   monitoring" is explicit in the source-verified comparison.
2. **Graceful reload over restart.** nginx workers reload config without
   dropping connections; XRootD core directives require a daemon restart.
3. **Low-cardinality labels as a security boundary.** Identity goes to LRU-hashed
   counters and the JSON access log, never to Prometheus label values.
4. **IPv6 flow-label and built-in SRR** fill two gaps that the official core
   leaves to a TODO and to external tooling respectively.

---

## Source references

### Official XRootD (`/tmp/xrootd-src`)

| Area | Files |
|---|---|
| Config parser / grammar | `src/XrdOuc/XrdOucStream.{cc,hh}`, `XrdOucEnv.{cc,hh}`, `XrdOucGatherConf.{cc,hh}`; dispatch `src/Xrd/XrdConfig.cc` |
| Reload (none) | `src/Xrd/XrdConfig.cc` (`ConfigXeq` `dynamic` flag), `src/XrdSys/XrdSysUtils.cc` (SIGHUP only named) |
| UDP monitoring | `src/XrdXrootd/XrdXrootdMonitor.{cc,hh}`, `XrdXrootdMonData.hh`, `XrdXrootdConfigMon.cc` (`xmon`/`xmongs`), `XrdXrootdMonFile.{cc,hh}`, `XrdXrootdMonFMap.{cc,hh}`, `XrdXrootdGStream.hh`, `XrdXrootdGSReal.{cc,hh}` |
| Summary report | `src/Xrd/XrdConfig.cc` (`xrep`), `src/Xrd/XrdStats.{cc,hh}`, `src/XrdXrootd/XrdXrootdStats.{cc,hh}` |
| SciTags / PMark | `src/XrdNet/XrdNetPMark.{cc,hh}`, `XrdNetPMarkCfg.{cc,hh}`, `XrdNetPMarkFF.{cc,hh}`; `src/XrdHttpTpc/XrdHttpTpcPMarkManager.{cc,hh}` |
| SRR | not found in core (external tool); SciTokens authz at `src/XrdSciTokens/` |
| Logging | `src/XrdSys/XrdSysLogger.{cc,hh}`, `XrdSysError.{cc,hh}`, `XrdSysTrace.{cc,hh}`; `src/Xrd/XrdConfig.cc` (`xtrace`) |
| Throttle / BWM | `src/XrdThrottle`, `src/XrdBwm` |
| Packaging | `xrootd.spec`, `systemd/*.service`/`*.socket`, `config/xrootd.logrotate`, `config/xrootd-*.cfg` |

### BriX-Cache (`/home/rcurrie/HEP-x/nginx-xrootd`)

| Area | Files |
|---|---|
| Metrics / Prometheus | `src/observability/metrics/{handler,stream,writer,unified,webdav,s3,cluster,tracking,stream_proxy,stream_cache,config,module,access_log,health}.c`, `metrics_macros.h`, `metrics.h`, `metrics_internal.h`, `README.md` |
| Dashboard / admin | `src/observability/dashboard/{module,api,api_admin,config,config_download,auth,events,history,transfer_table,page}.c`, `README.md` |
| Config model | `src/core/config/{process,server_conf,postconfiguration,runtime_server}.c`, `merge_macros.h`; directives in `src/protocols/root/stream/module.c`, `module_core_directives.c`, `module_cache_proxy_directives.c`, `src/protocols/webdav/module.c`, `src/protocols/s3/module.c` |
| SciTags / PMark | `src/observability/pmark/{firefly,flowlabel,scitag,mapping,config,defsfile,sockstats}.c`, `pmark.h`, `README.md` |
| SRR | `src/protocols/srr/{builder,handler,module}.c`, `srr.h`, `README.md` |
| Logging / sanitize | `src/observability/metrics/access_log.{c,h}`, `src/observability/accesslog/access_log.c`, `src/fs/path/path.h` (`xrootd_sanitize_log_string` decl) + `src/auth/authz/{acl,authdb}.c`, `src/fs/path/{helpers,resolve_confined_helpers}.c` (uses) |
| Health | `src/observability/metrics/health.c` |
| Rate limiting | `src/net/ratelimit/{ratelimit,ratelimit_keys,ratelimit_zone,ratelimit_http,ratelimit_stream}.c`, `ratelimit.h`, `README.md`; `src/observability/metrics/ratelimit.c` |
| Packaging / ops | `packaging/rpm/nginx-mod-brix-cache.spec`; `contrib/{grafana-dashboard.json,prometheus-alerts.yml,logrotate.d/nginx-xrootd,xrootd.conf.example}`; `docs/09-developer-guide/testing-runbook.md` |

### Companion docs

- [`docs/10-reference/source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md) — Observability and Operations section (consistency anchor; "UDP monitoring intentionally not implemented").
- [`docs/refactor/phase-47-operability-and-packaging.md`](../../../refactor/phase-47-operability-and-packaging.md) — operability/packaging phase.
- [`docs/refactor/phase-34-packet-marking-scitags.md`](../../../refactor/phase-34-packet-marking-scitags.md) — SciTags/PMark phase.

> Verification note: directive-grammar snippets and metric/directive name strings
> were grepped from the cited source on both trees. Where a capability is absent
> from a tree this doc states "not found in core" / "not implemented" rather than
> inferring. External collector projects (shoveler, MonaLisa/ApMon) are named as
> context but are not part of either source tree reviewed here.
