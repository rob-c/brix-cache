# dashboard — HTTPS monitoring dashboard

Provides an interactive HTTPS dashboard at `/xrootd/` for live operator visibility of active transfers, protocol status, cache health, cluster state, and recent events. The dashboard runs as a standalone nginx HTTP location with password authentication and serves both HTML pages and JSON API data.

| File | Responsibility |
|---|---|
| `api.c` | JSON API endpoint handlers: `/xrootd/api/v1/` for transfers, metrics, cluster state |
| `auth.c` | Dashboard session authentication: password validation, session token generation, TTL management |
| `config.c` | nginx directives for `xrootd_dashboard_*` (on/off, password, session_ttl) |
| `dashboard.h` | Public dashboard types and cross-file prototypes |
| `dashboard_http.h` | HTTP-specific dashboard types: response chain building, header setting |
| `dashboard_tracking.h` | Tracking types shared between page rendering and API responses |
| `events.c` | Recent events log: capture, store, format for dashboard display |
| `history.c` | Transfer history aggregation: past transfers summary, duration stats |
| `http_tracking.c` | HTTP-side transfer tracking: read/write/TPC counts per protocol |
| `module.c` | nginx module registration: location handler, config merge, init/shutdown hooks |
| `page.c` | HTML page generation: dashboard layout, cards, tables, event timeline |
| `transfer_table.c` | Active transfer table rendering: current root/WebDAV/S3/TPC transfers with status |
