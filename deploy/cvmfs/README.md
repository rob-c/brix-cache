# CVMFS site cache on nginx-xrootd — deployment runbook

A drop-in replacement for the Squid layer between your worker nodes and the
CVMFS Stratum-1s, with two properties Squid does not have: **corrupt origin
transfers are never admitted to the cache** (CAS verify-on-fill) and
first-class Prometheus observability.

## Topology

Two **independent** cache nodes (no VIP, no keepalived — CVMFS clients do
their own load-balancing and failover):

```
WN farm ── CVMFS_HTTP_PROXY="http://cache1:3128|http://cache2:3128" ──┐
                                                                      │
   cache1: nginx-xrootd, N TB XFS cache_store  ── WAN ── Stratum-1s ──┤
   cache2: nginx-xrootd, N TB XFS cache_store  ── WAN ── Stratum-1s ──┘
```

`|` = load-balance between both; use `;` between groups for strict
failover ordering. Keep Squid installed but idle until the pilot completes.

## Sizing

| Farm size | cache_store | RAM | threads |
|---|---|---|---|
| ≤ 500 cores | 500 GB | 8 GB | thread_pool default threads=8 |
| ≤ 2000 cores | 1–2 TB | 16 GB | threads=16 |
| larger | 2–4 TB | 32 GB | threads=32 |

Store on XFS, dedicated filesystem (eviction watermarks assume the cache
owns the volume). Watermarks: evict at 85 %, hard-stop admission at 95 %
(`xrootd_cvmfs_cache_evict_at` grammar mirrors the other protocols' tier
directives — see docs/03-configuration).

## Reference configuration (proxy mode)

```nginx
worker_processes auto;
error_log /var/log/nginx-xrootd/error.log warn;
thread_pool default threads=16;
events { worker_connections 4096; }
http {
    # canonical cvmfs access-log format: one glance answers "what class,
    # was it a hit, which Stratum-1" per request; cache=fill lines ARE the
    # WAN traffic.
    log_format cvmfs '$remote_addr [$time_local] "$request" $status '
                     '$body_bytes_sent $request_time '
                     'class=$cvmfs_class cache=$cvmfs_cache origin=$cvmfs_origin';
    access_log /var/log/nginx-xrootd/cvmfs_access.log cvmfs;

    # --- connection durability: keep every WN connection alive ------------
    # Kernel keepalive (60s idle, 10s probes, 6 tries) keeps NAT/firewall
    # state warm and lets the CACHE detect dead peers — the client never
    # experiences an unexplained close and never marks this proxy bad.
    keepalive_timeout  3600s;
    keepalive_requests 1000000;
    send_timeout          300s;
    client_header_timeout 300s;
    reset_timedout_connection off;   # FIN, never RST

    server {
        listen 3128 so_keepalive=60s:10s:6 backlog=2048;
        location / {
            xrootd_cvmfs_cache_store posix:/srv/cvmfs-cache;
            xrootd_cache_verify cvmfs-cas;
            xrootd_cvmfs on;
            xrootd_cvmfs_manifest_ttl 61;
            xrootd_cvmfs_negative_ttl 10;
            xrootd_cvmfs_quarantine_dir /srv/cvmfs-quarantine;

            # --- never-drop semantics -----------------------------------
            # Hold a request up to 25s while retrying the Stratum-1s with
            # backoff; on expiry answer 504+Retry-After on the kept-alive
            # connection (the client's retry coalesces on the running fill).
            # MUST stay below the WN's CVMFS_TIMEOUT (see client tuning).
            xrootd_cvmfs_client_hold   25;
            xrootd_cvmfs_fill_max_life 300;

            # --- upstream selection: static | geo | rtt ------------------
            # rtt = probe connect latency every 60s, prefer the fastest;
            # geo = rank by great-circle distance from 'here';
            # static = the order of the origin list.
            xrootd_cvmfs_origin_select rtt;
            xrootd_cvmfs_rtt_interval  60;
            # geo alternative:
            #   xrootd_cvmfs_origin_select geo;
            #   xrootd_cvmfs_here 55.95:-3.19;   # this cache (Edinburgh)
            #   xrootd_cvmfs_origin_coords cvmfs-stratum-one.cern.ch 46.23:6.05;
            #   xrootd_cvmfs_origin_coords cvmfs-s1fnal.opensciencegrid.org 41.85:-88.31;

            # every Stratum-1 host your experiments use — nothing else is proxied:
            xrootd_cvmfs_upstream_allow cvmfs-stratum-one.cern.ch;
            xrootd_cvmfs_upstream_allow cvmfs-s1fnal.opensciencegrid.org;
            xrootd_cvmfs_upstream_allow cvmfs-stratum-one.ihep.ac.cn;
            xrootd_cvmfs_upstream_max 8;
        }
    }
    server {   # metrics + health, firewalled to the monitoring host
        listen 9100;
        location /metrics { xrootd_metrics on; }
        location /healthz { xrootd_health on; }
    }
}
```

Reverse mode (optional second listener): same location shape plus
`xrootd_cvmfs_storage_backend "http://s1a|http://s1b";` (pipe-separated,
`CVMFS_SERVER_URL` order; reads fail over by measured health, writes and
the passthroughs use the first) and clients use
`CVMFS_SERVER_URL=http://cache:8000/cvmfs/@fqrn@` with
`CVMFS_HTTP_PROXY=DIRECT`.

## Client configuration

`/etc/cvmfs/default.local` on every WN:

```
CVMFS_HTTP_PROXY="http://cache1.site:3128|http://cache2.site:3128"

# --- timeout alignment with the cache's never-drop hold -------------------
# The cache holds a request up to xrootd_cvmfs_client_hold (25s) while it
# retries the Stratum-1s, then answers 504 on the kept-alive connection.
# The client's proxied timeout MUST exceed that hold, or the client gives
# up first and starts counting the cache as failed:
CVMFS_TIMEOUT=30              # default is 5 — far too low for a cold miss
CVMFS_TIMEOUT_DIRECT=10
CVMFS_MAX_RETRIES=3
# If the client ever does mark a proxy failed, come back to it quickly
# (default 300s leaves the cache benched for 5 minutes after one blip):
CVMFS_PROXY_RESET_AFTER=60
CVMFS_HOST_RESET_AFTER=120
```

**Why this alignment matters:** the whole never-drop design assumes the
cache answers *before* the client's patience runs out. `client_hold=25 <
CVMFS_TIMEOUT=30` guarantees the client always receives a well-formed HTTP
answer (data or 504-retry-later) on a healthy connection — so its proxy
bookkeeping stays clean and it never escalates to the failover group or
DIRECT. If you change one side, change the other.

Apply to running nodes without remount:

```
cvmfs_talk -i <repo> proxy set "http://cache1.site:3128|http://cache2.site:3128"
```

**Rollback is one variable:** point `CVMFS_HTTP_PROXY` back at the Squids.

## Monitoring

Scrape `:9100/metrics`. The series that matter:

| Series | Alert on | Meaning |
|---|---|---|
| `xrootd_cvmfs_verify_failures_total` | any increase | the WAN corrupted a transfer; the cache refused it. **This is your evidence for the network team** — each increment has a quarantined file in `/srv/cvmfs-quarantine` to prove it. |
| `xrootd_cvmfs_fill_failures_total` | rate spike | Stratum-1s unreachable/stalling |
| `xrootd_cvmfs_origin_failovers_total` | rate spike | primary Stratum-1 degraded |
| `xrootd_cvmfs_requests_total{class="reject"}` | sustained rate | something probing the cache (fail2ban jail `nginx-xrootd-cvmfs` bans it) |
| `xrootd_cvmfs_requests_total{class="cas"}` | — | traffic volume baseline |
| `xrootd_cvmfs_bytes_served_total{source="hit\|fill"}` | hit share dropping | LAN bytes to the farm, split by cache disposition — the hit-ratio source |
| `xrootd_cvmfs_origin_bytes_total` | sustained ≈ bytes_served | WAN bytes pulled from Stratum-1s; if this tracks bytes_served the cache isn't caching |
| `{proto="cvmfs"}` on the module-wide families | — | cvmfs as a slice of everything this node does (io, cache hits, auth) |
| `xrootd_cvmfs_repo_*_total{repo="<fqrn>"}` | per-experiment views | requests{class}, files_accessed, cache_hits/misses, fills(+failures), verify_failures, negative_hits, bytes_served{hit\|fill}, origin_bytes — one row per repository (bounded: 31 named + `_other` overflow) |
| `/healthz?verbose` `.cvmfs_origins[].fail_score` | > 0 sustained | per-origin health (sd_http EWMA; 0 = healthy) |

Quarantine hygiene: files there are evidence, not cache — prune with
`find /srv/cvmfs-quarantine -mtime +30 -delete` from cron.

### Ready-made PromQL (paste into Grafana)

```promql
# cache hit ratio (5m)
sum(rate(xrootd_cvmfs_bytes_served_total{source="hit"}[5m]))
  / sum(rate(xrootd_cvmfs_bytes_served_total[5m]))

# WAN bytes actually pulled from Stratum-1s vs LAN bytes served to the farm
sum(rate(xrootd_cvmfs_origin_bytes_total[5m]))          # WAN in
sum(rate(xrootd_cvmfs_bytes_served_total[5m]))          # LAN out
# their ratio = how much the cache is saving your broken WAN

# request mix by class
sum by (class) (rate(xrootd_cvmfs_requests_total[5m]))

# per-experiment WAN cost + hit ratio (the per-repo families)
topk(5, sum by (repo) (rate(xrootd_cvmfs_repo_origin_bytes_total[5m])))
sum by (repo) (rate(xrootd_cvmfs_repo_bytes_served_total{source="hit"}[5m]))
  / sum by (repo) (rate(xrootd_cvmfs_repo_bytes_served_total[5m]))

# cvmfs share of ALL cache lookups this node serves (proto identity, T16)
sum(rate(xrootd_cache_hits_total{proto="cvmfs"}[5m]))
  / sum(rate(xrootd_cache_hits_total[5m]))
```

(Adjust the per-proto family name in the last query to the module's actual
exported name — see `/metrics` output; the `proto="cvmfs"` label is the
stable part.)

### Access log

Every request lands in `cvmfs_access.log` with the cvmfs format:

```
10.1.2.3 [02/Jul/2026:14:31:07 +0000] "GET /cvmfs/atlas.cern.ch/data/ab/cd…01 HTTP/1.1" 200 187342 0.004 class=cas cache=hit origin=-
10.1.2.4 [02/Jul/2026:14:31:09 +0000] "GET /cvmfs/atlas.cern.ch/.cvmfspublished HTTP/1.1" 200 421 0.812 class=manifest cache=fill origin=cvmfs-stratum-one.cern.ch:80
```

`cache=fill` lines ARE your WAN traffic; `awk '$0~/cache=fill/'` over a
time window is a poor man's WAN audit when Prometheus is down.

### Diagnostic event log (error_log)

Beyond the access log, the cache emits single-line, greppable events to the
`error_log` (at `info` or lower) whenever a connection breaks, an origin
misbehaves, or a client does. Every line names the object (`key=`) and/or
the client (`client=`) so you can pivot on either. Grep prefixes:

| Prefix / event | Level | Means / what to do |
|---|---|---|
| `xrootd-fill: event=retry` | warn | an origin attempt failed transiently; the fill is backing off and retrying (attempt/backoff/elapsed on the line). A burst for one host ⇒ that Stratum-1 is flapping. |
| `xrootd-fill: event=recovered` | warn | the fill succeeded after retries — how long the WAN wobble lasted (`elapsed_ms`). |
| `xrootd-fill: event=exhausted` | warn | no origin answered within the deadline; every waiter got a `504 Retry-After` (kept-alive). Sustained ⇒ origins down or `client_hold` too short. |
| `xrootd-fill: event=hold-expired` | warn | a client waited out `client_hold` and got a 504 while the fill kept running. **Recurring ⇒ `CVMFS_TIMEOUT` shorter than the fill latency** — raise it (see client tuning). `held_ms` is how long it waited. |
| `xrootd-fill: event=client-gone` | warn | a client **broke its connection** mid-fill (the fill continues detached). `parked_ms` is how long it had waited. A flood ⇒ clients are giving up — same `CVMFS_TIMEOUT` misalignment, or a farm-side network problem. |
| `xrootd-fill: event=failed` | error | 502 to every waiter (e.g. every endpoint served corrupt data — the verify quarantined it). |
| `xrootd-origin: event=degraded` / `recovered` | warn / notice | an origin endpoint crossed the health threshold and reads started preferring alternates, then came back. The origin-flap timeline. |
| `cvmfs-client: event=send-timeout` | warn | nginx's `send_timeout` fired mid-response — the client **stopped reading** (overloaded WN, dead NAT entry, kernel-keepalive gap). Line carries sent-vs-expected bytes. |
| `cvmfs-client: event=aborted` | warn | the client closed the connection during the response. |
| `cvmfs-neg: event=absorbed-404` | notice | a client requested a known-missing object; the negative cache answered it (the origin saw nothing). **Repeated lines from one client ⇒ it is hammering a missing object instead of backing off** — a misbehaving client. |

Two quick triage recipes:

```
# which clients are giving up / breaking connections, most first
grep -hoE 'event=(client-gone|hold-expired|aborted|send-timeout).*client=[0-9.]+' \
    error.log | grep -oE 'client=[0-9.]+' | sort | uniq -c | sort -rn

# which objects/repos are costing retries (a flapping origin surfaces here)
grep -oE 'event=retry key="[^"]+"' error.log | sort | uniq -c | sort -rn
```

### Live dashboard

The built-in operator dashboard (`xrootd_dashboard on` location, see
docs/08-metrics-monitoring) shows in-flight CVMFS transfers with a `cvmfs`
protocol tag in the live transfer table. Firewall it — it exposes paths
and client IPs.

## Pilot procedure (do not skip steps)

1. Deploy both cache nodes; run for 24 h with **no** clients; confirm clean
   logs and a green `/healthz`.
2. Pick ONE worker-node queue. Flip its `CVMFS_HTTP_PROXY`. Record date.
3. Soak **two weeks**. Watch: `error_rate` proxy for user pain =
   mount-failure tickets from that queue vs the Squid queues;
   `verify_failures_total` (expect > 0 if your network is as bad as
   believed — each one would have been a farm-poisoning event under Squid).
4. Expand queue-by-queue. Squid is decommissioned only after **two full
   clean soak periods** on the complete farm.
5. Any regression → rollback (step "one variable"), file the logs, stop.

## Squid → nginx-xrootd mapping

| squid.conf | here |
|---|---|
| `collapsed_forwarding on` | built-in (fill coalescing; exactly 1 origin fetch per object) |
| `refresh_pattern /data/ …` | built-in (CAS objects cached forever) |
| `refresh_pattern .cvmfspublished …` | `xrootd_cvmfs_manifest_ttl` |
| `acl cvmfs_dst dstdomain …` + `http_access` | `xrootd_cvmfs_upstream_allow` |
| `cache_dir ufs … ` | `xrootd_cvmfs_cache_store posix:…` + watermarks |
| `negative_ttl` | `xrootd_cvmfs_negative_ttl` |
| `cache_peer` parent ordering | `xrootd_cvmfs_origin_select static\|geo\|rtt` |
| `connect_retries` / `retry_on_error` | `xrootd_cvmfs_client_hold` (hold + endpoint-walking backoff, then 504-keepalive) |
| `client_persistent_connections on` | `so_keepalive=…` + `keepalive_timeout 3600s` (kernel-level, proven by `run_cvmfs_keepalive.sh`) |
| (no equivalent) | `xrootd_cache_verify cvmfs-cas` + quarantine |
| (no equivalent) | detached fills — a client abort never cancels an in-flight origin fetch |

## Experimental: scvmfs://

`xrootd_scvmfs on` (requires `xrootd_cvmfs on`) turns a TLS listener
(`listen 8443 ssl` + certificates) into the secure variant: plain HTTP is
refused, and `xrootd_scvmfs_authz bearer` +
`xrootd_scvmfs_token_issuers <scitokens.cfg>` gates clients on a
WLCG/SciTokens read scope before the unchanged cvmfs core serves them.
Client side needs `CVMFS_SERVER_URL=https://…` and an authz helper
(`CVMFS_AUTHZ_HELPER`); WLCG proxy-mode traffic stays cleartext cvmfs://
for now. **EXPERIMENTAL** — not part of the pilot; VOMS client-cert mode
is not implemented yet.
