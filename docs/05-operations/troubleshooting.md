# Troubleshooting

A symptom-first decision tree for an operator running an gnuBall gateway.
Each row is **symptom → first thing to check → where**. For the metric families
named below see the [Monitoring Guide](../08-metrics-monitoring/monitoring-guide.md)
and `contrib/grafana-dashboard.json`.

> **First, is the gateway even up?** `curl -s http://127.0.0.1:9100/healthz` should
> return `{"status":"ok",...}`. Add `?verbose` to see whether the metrics SHM is
> mapped, the worker pid, and the nginx version. A non-200 (or connection refused)
> means the worker is down — go to **Won't start / won't reload**.

## Won't start / won't reload

| Symptom | Check | Where / fix |
|---|---|---|
| `nginx -t` fails: *module ... is not binary compatible* | nginx version vs. the one the module was built against | Rebuild the module for the running nginx, or install the matching nginx |
| `nginx -t` fails to **load** the module (dlopen / undefined symbol) | Module load order in `mod-xrootd.conf` | The combined `ngx_stream_xrootd_module.so` **must** be the first `load_module` line; the xrdhttp filter second. See [upgrade-procedure](upgrade-procedure.md) |
| Worker won't start: `libbz2.so.1.0: cannot open shared object file` | bzip2 SONAME on the host | The binary needs `libbz2.so.1.0`; some distros only ship `libbz2.so.1`. Install `bzip2-libs`, or symlink `libbz2.so.1.0 → libbz2.so.1`. See [upgrade-procedure](upgrade-procedure.md) |
| `nginx -t`: *path "..." must be a regular file* / *directory* | A cert/CA directive points at the wrong kind of node | `xrootd_*_cafile` wants a **file** (CA bundle); `xrootd_*_cadir` wants a **directory** |
| `stream` block rejected | `stream{}` placed inside `http{}` (e.g. dropped into `conf.d/`) | `stream{}` is **top-level** in `nginx.conf`; only HTTP server blocks belong in `conf.d/`. See `contrib/xrootd.conf.example` |

## Auth failures

| Symptom | Check | Where / fix |
|---|---|---|
| All tokens rejected after a key roll | JWKS file actually updated on disk + reload interval | JWKS is hot-reloaded by mtime poll (`xrootd_token_jwks_refresh_interval`); no nginx reload needed. See [certificate-rotation](certificate-rotation.md) |
| Tokens rejected: audience/issuer mismatch | `xrootd_token_audience` / `xrootd_token_issuer` vs. the token's `aud`/`iss` | Audience may be an array in the token — both single and array `aud` are accepted |
| x509 / proxy cert rejected | CA dir + CRL freshness | `xrootd_webdav_cadir` / `xrootd_trusted_ca`; refresh CRLs (`xrootd_crl_reload`). See [certificate-rotation](certificate-rotation.md) |
| Auth-rejection spike in metrics | `rate(xrootd_webdav_auth_total{result="rejected"}[5m])`, same for `xrootd_s3_auth_total` | Expired token/CRL, JWKS misconfig, or abuse — correlate with source IP in the access log |
| S3 `SignatureDoesNotMatch` | Clock skew, region, or `xrootd_s3_bucket` mismatch | SigV4 is time-sensitive; check host clock and the client's region/endpoint |

## 4xx / 5xx responses

| Symptom | Check | Where / fix |
|---|---|---|
| Sudden 5xx surge | `rate(xrootd_{webdav,s3}_responses_total{status_class="5xx"}[5m])` | Disk full / IO errors (`ENOSPC`/`EIO`), or backend down in proxy/cluster mode; check `error.log` |
| 403 on a path that should work | Path confinement / ACL | The path must resolve **beneath** `xrootd_*_root`; `..`-escapes are rejected by design. Check `xrootd_path_depth_violations_total` |
| 423 Locked on DELETE/MOVE | A WebDAV lock (incl. a child of a collection) | Locks are checked recursively for collections; wait for or remove the lock |
| 507 Insufficient Storage | Export filesystem full | Free space or grow the export; `xrootd_cluster_server_free_megabytes` for cluster members |
| Large GET/PUT fails midway | `client_max_body_size`, disk space, timeouts | Set `client_max_body_size 0;` for unbounded uploads; check memory budget (`xrootd_budget_waits_total`) |

## Performance / saturation

| Symptom | Check | Where / fix |
|---|---|---|
| High latency under load | `histogram_quantile(0.95, ...xrootd_io_latency_usec_bucket...)` | See [capacity-planning](capacity-planning.md): worker count, thread pool, FD limit |
| Requests being throttled | `rate(xrootd_rate_limit_throttled_total[5m])` | A VO/issuer/IP/DN rate-limit zone is active; raise the limit or confirm it's intended |
| Memory growth on big transfers | `xrootd_xfer_heap_bytes`, `xrootd_budget_waits_total` | Windowed read/write keeps resident memory bounded; waits mean the byte budget is the throttle |
| Slow first byte on tape-backed files | `xrootd_frm_in_flight`, file residency | File is `OFFLINE`/staging from tape; the client gets a wait/`kXR_offline`. See FRM docs |
| 100% CPU on an idle gateway | A polling timer (FRM scheduler, CMS interval=0, health-check floor) | Known idle-timer pitfalls — ensure `xrootd_cms_interval >= 1s`; see the operations guide |

## Cluster / proxy / TPC

| Symptom | Check | Where / fix |
|---|---|---|
| Redirect loop on a missing path | Manager `tried`/`triedrc` handling | Resolves to `kXR_NotFound` once all sources are exhausted; confirm the path exists on at least one server |
| Backend blacklisted | `xrootd_cluster_server_blacklisted`, health-check counters | A member failed health checks; check that member's `error.log` and connectivity |
| TPC COPY fails | Source/Credential headers, peer CA bundle | `xrootd_webdav_tpc_cafile` must verify the remote peer; check delegated-credential validity |

## First run: the startup summary

When the configuration is valid, each enabled endpoint logs a short summary at
`notice` — visible both at startup and in the output of `nginx -t`, so you can
confirm what you built before going live. The `root://` (`stream{}`) endpoints:

```
xrootd: root:// endpoint ready — export "/srv/data" (read-write), auth: GSI or token
xrootd:   revocation: CRL "/etc/grid-security/certificates", reloaded every 3600 s
xrootd:   token validation: 1 JWKS key(s) loaded
xrootd:   NOTE: write access is enabled — authorized clients can create, modify and delete files under the export root
```

…and each WebDAV (`davs://`) location prints the equivalent, tagged with the
config file and line of the block it came from:

```
xrootd: WebDAV (davs://) endpoint ready — export "/srv/data" (read-write), auth: optional (anonymous allowed) in nginx.conf:25
xrootd:   credentials accepted: x509/GSI-proxy bearer-token
xrootd:   NOTE: x509/GSI is accepted but no CRL is configured — REVOKED certificates will be ACCEPTED (set xrootd_webdav_crl)
```

It also calls out valid-but-risky settings so they aren't discovered the hard
way later — e.g. `NOTE: no authentication required — OPEN to anonymous clients`,
and a `[warn]` `GSI auth is enabled but no CRL is configured — REVOKED
certificates will be ACCEPTED`. If you don't see a summary for an endpoint you
expected, that block isn't `enable`d (or `nginx -t` failed earlier).

## Reading the error log

Operational problems in the `error.log` are written as a three-part diagnostic
so you can act without knowing the internals. The shape is always:

```
2026/06/25 22:14:03 [warn] 8123#0: xrootd[pki]: no CRLs loaded from "/etc/grid-security/certificates"
  cause: CRL directory is empty, stale, or wrong path
  fix:   run fetch-crl (or your CRL refresh cron) to populate it; until then REVOKED certificates are still ACCEPTED
```

- The **summary** line starts with a `xrootd[<subsystem>]:` tag (e.g. `pki`,
  `cms`, `frm`, `disk`, `token`) and includes the offending path/address/size.
- **cause:** names the most likely reason in plain language.
- **fix:** is the concrete next step. `grep 'fix:' error.log` surfaces every
  actionable line at a glance.

The severity maps to operator impact: **emerg** = `nginx -t`/startup failed
(nothing serves yet); **crit** = the running service is degraded for everyone
(e.g. a store reload failed); **err** = a single request/connection failed but
the service is healthy; **warn** = working but mis-tuned or insecure — look soon.
When the OS is involved (disk, network) the kernel's own reason is appended,
e.g. `… (28: No space left on device)`.

> Not every line carries a `fix:` — purely internal invariant violations are
> logged plainly because there is no operator action to take. If you see one
> repeatedly, capture it and the surrounding context for a bug report.

## Where the logs are

- nginx `error.log` — the first place for any 5xx / startup / module-load issue.
- Per-protocol access logs — `xrootd_access_log` (root://), and the `access_log` of
  each WebDAV/S3 server block (see `contrib/xrootd.conf.example`).
- Wire-level root:// trace — run a client with `XRD_LOGLEVEL=Debug`.
- Turn on nginx debug logging in a server block with `error_log .../debug.log debug;`.

See also: [Operations Guide](operations-guide.md) ·
[Capacity Planning](capacity-planning.md) ·
[Certificate & Token Rotation](certificate-rotation.md) ·
[Upgrade Procedure](upgrade-procedure.md)
