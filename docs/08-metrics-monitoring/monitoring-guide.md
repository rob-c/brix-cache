# Metrics and Logging

Every request leaves a trace. This section covers every Prometheus metric gnuBall exports, how to set up scraping, how to use the HTTPS monitoring dashboard, how to read the access logs, and what healthy numbers look like at scale.

## Quick Navigation

| Document | Content |
|---|---|
| [setup.md](setup.md) | Prometheus endpoint configuration and scraping setup |
| [metrics-overview.md](metrics-overview.md) | Complete catalog of available metrics (stream, WebDAV, S3) |
| [extended-metrics.md](extended-metrics.md) | Protocol separation, IP version tracking, VO and user analytics |
| [promql-examples.md](promql-examples.md) | PromQL queries for common monitoring scenarios |
| [access-logging.md](access-logging.md) | Access log format, configuration, and interpretation |
| [metrics-analysis.md](metrics-analysis.md) | Metric analysis guidance, health checks, alerting rules |
| [dashboard-feature-ideas.md](dashboard-feature-ideas.md) | Roadmap of useful additions for the HTTPS monitoring dashboard |
| [dashboard-feature-implementation-plan.md](../_archive/dashboard-feature-implementation-plan.md) | Developer implementation plan for dashboard roadmap features |

## Overview

The module provides three ways to observe what is happening: a **Prometheus metrics endpoint**, an **HTTPS monitoring dashboard**, and a **per-request access log**. They answer different questions and live at different cardinalities:

```text
                       ┌──────────────────────────────────────┐
   in-flight requests  │            nginx-xrootd               │
   ───────────────────▶│   SHM counters · live transfer rows   │
                       └───┬──────────────┬──────────────┬─────┘
                           │              │              │
              :9100/metrics│   :8443/xrootd/│     access_log file
                           ▼              ▼              ▼
                  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
                  │ PROMETHEUS  │  │ DASHBOARD   │  │ ACCESS LOG  │
                  │ low-cardin. │  │ live, short │  │ per-request │
                  │ counters,   │  │ -lived view │  │ full detail │
                  │ long-term   │  │ of active   │  │ (DN, path,  │
                  │ trends,     │  │ transfers + │  │ timing,     │
                  │ alerting    │  │ health      │  │ bytes)      │
                  └─────────────┘  └─────────────┘  └─────────────┘
                  "is the fleet    "what is happening "what did THIS
                   healthy over     right now?"        client/op do?"
                   time?"
                  PII-free          admin-only, HTTPS  \xNN-sanitized
```

### Prometheus Metrics Endpoint

Access the metrics HTTP endpoint at `/metrics` on port 9100 (default):

```bash
curl http://localhost:9100/metrics
```

Or configure your Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: xrootd
    static_configs:
      - targets: ['localhost:9100']
```

### HTTPS Monitoring Dashboard

The built-in dashboard is a browser UI for live operator checks. It is separate
from the Prometheus `/metrics` endpoint: Prometheus scrapes low-cardinality
counters for long-term storage, while the dashboard renders a short-lived view of
active transfers and aggregate byte/connection totals.

Mount the dashboard at `/xrootd/` on a TLS-enabled admin location:

```nginx
server {
    listen 8443 ssl;
    server_name storage.example.org;

    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;

    location /xrootd/ {
        xrootd_dashboard on;
        xrootd_dashboard_password "change-me";
        # or: xrootd_dashboard_users /etc/nginx/xrootd-dashboard.htpasswd;
        xrootd_dashboard_session_ttl 8h;
        xrootd_dashboard_idle_threshold 5s;
        xrootd_dashboard_stalled_threshold 60s;
        xrootd_dashboard_cluster_stale_after 90s;

        # Recommended for production: restrict to an admin network or VPN.
        # allow 192.0.2.0/24;
        # deny  all;
    }
}
```

Once enabled, use these URLs:

| URL | Purpose |
|---|---|
| `https://storage.example.org:8443/xrootd/` | Embedded dashboard page |
| `https://storage.example.org:8443/xrootd/login` | Password login form |
| `https://storage.example.org:8443/xrootd/transfers` | Compatibility JSON transfer list |
| `https://storage.example.org:8443/xrootd/api/v1/snapshot` | Versioned full JSON snapshot |
| `https://storage.example.org:8443/xrootd/api/v1/transfers/<id>` | One active transfer detail row |
| `https://storage.example.org:8443/xrootd/api/v1/events` | Recent bounded dashboard event ring |
| `https://storage.example.org:8443/xrootd/api/v1/history` | Bounded short-term history buckets |
| `https://storage.example.org:8443/xrootd/api/v1/cache` | Cache and write-through health |
| `https://storage.example.org:8443/xrootd/api/v1/cluster` | Manager registry health snapshot |

The dashboard page polls `/xrootd/api/v1/snapshot` for the rich view and keeps
`/xrootd/transfers` available for older tooling. The live table shows native
XRootD, WebDAV, S3, and HTTP-TPC transfers with client address, authenticated
identity, path, protocol, direction, operation, state, bytes, idle time, and
rate. The page also includes protocol summary cards, cache/write-through health,
manager registry health, recent sanitized events, bounded history sparklines,
client-side filters/search/sort, a transfer detail drawer, and a sanitized JSON
snapshot export button.

Security expectations:

- Serve the dashboard only over HTTPS. The login cookie is marked `Secure`,
  `HttpOnly`, and `SameSite=Strict`.
- Always set `xrootd_dashboard_password`; without it, the dashboard location is
  treated as unauthenticated. For named operators, use
  `xrootd_dashboard_users` with an htpasswd-like `user:hash` file instead.
- Keep the dashboard behind an admin network, VPN, firewall, or nginx
  `allow`/`deny` rules. It exposes operationally sensitive data such as active
  file paths, client addresses, and authenticated identities.
- Mount it at `/xrootd/`, not at `/`, because the dashboard page, login
  redirect, JSON polling path, and cookie path are tied to `/xrootd`.

### Access Logging

Per-request access logs record every XRootD operation with timing and byte counts:

```nginx
xrootd_access_log /var/log/nginx/xrootd_access.log;
```

---

## Related Documentation

- [Configuration Directives](../03-configuration/directives.md) — Full reference for nginx directives
- [Architecture Overview](../10-architecture/overview.md) — Request lifecycle diagrams
- [WebDAV Methods](../04-protocols/webdav-methods.md) — WebDAV operation details and RFC compliance
- [Dashboard Feature Ideas](dashboard-feature-ideas.md) — Roadmap of useful additions for the HTTPS monitoring dashboard
- [Dashboard Feature Implementation Plan](../_archive/dashboard-feature-implementation-plan.md) — Developer roadmap for implementing dashboard additions
