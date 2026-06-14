# Monitoring Dashboard Feature Ideas

The HTTPS monitoring dashboard is currently a lightweight live view: it serves
the embedded page at `/xrootd/`, authenticates with the dashboard password, and
polls `/xrootd/transfers` for active transfer rows plus aggregate byte and
connection totals.

This document collects useful additions that would make the dashboard a better
operator tool without turning it into a second Prometheus or a risky control
plane.

For a file-by-file implementation roadmap, see
[Dashboard Feature Implementation Plan](../_archive/dashboard-feature-implementation-plan.md).

## Design Principles

- Keep the dashboard display-only by default. Operational actions should require
  a separate opt-in directive and explicit authorization model.
- Keep Prometheus labels low-cardinality. Per-path, per-client, and per-transfer
  detail belongs in dashboard JSON, logs, or bounded shared-memory tables, not in
  metric labels.
- Prefer bounded memory structures: fixed transfer slots, fixed event rings, and
  short time windows.
- Treat paths, identities, remote addresses, and TPC URLs as sensitive. Avoid
  exposing the dashboard outside an admin network, and redact where possible.
- Make every new JSON field versionable and backward-compatible so the embedded
  page and external tooling can evolve safely.

## Highest-Value Additions

### Protocol-complete active transfers

Extend live transfer slot allocation beyond native XRootD handles so WebDAV,
S3, and HTTP-TPC operations appear in the same active transfer table. The JSON
schema already has protocol tags for `root`, `webdav`, and `s3`; the remaining
work is lifecycle wiring in each HTTP handler:

- allocate a slot when a GET, PUT, COPY/TPC, or S3 object transfer starts
- update bytes and last-active timestamp during body read/write
- free the slot on completion, error, cancellation, or request cleanup
- mark direction as `read`, `write`, or `tpc`

This would make the dashboard match the promise operators expect from a unified
multi-protocol server.

### Stalled and slow transfer detection

Add explicit status fields instead of making the page infer everything from
`last_ms` and byte deltas:

| Field | Purpose |
|---|---|
| `state` | `active`, `idle`, `stalled`, `closing`, `error` |
| `idle_ms` | Time since last byte movement |
| `avg_bps` | Transfer lifetime average |
| `instant_bps` | Server-computed recent rate, useful for non-browser clients |
| `last_error` | Short sanitized reason for failed or stuck transfers |

The page can then highlight transfers that have made no progress for a
configurable threshold, sort them to the top, and help operators distinguish
slow clients from server-side trouble.

### Filters, search, and stable sorting

Add browser-side controls for common triage questions:

- protocol filter: root, WebDAV, S3, TPC
- direction filter: reads, writes, third-party copies
- status filter: active, idle, stalled, error
- text search across path, identity, client address, and transfer ID
- stable sort by rate, bytes, age, idle time, protocol, or client

These can be implemented entirely in the embedded page once the JSON includes
the required fields.

### Transfer detail view

Add a row detail panel for one selected transfer. Useful fields:

- transfer ID, worker PID, connection/session ID
- client address, authenticated identity, VO or token group summary
- path, protocol, direction, open flags, range information
- bytes sent/received, average rate, recent rate, start time, idle time
- operation counters for read, readv, pgread, write, sync, close
- lock state for WebDAV requests
- TPC source/destination host, mode, elapsed time, and sanitized curl status

Keep sensitive values bounded and sanitized. For TPC URLs, the default display
should show scheme, host, and path basename only, with query strings redacted.

### Recent error ring

Add a small shared-memory ring for recent dashboard-relevant events:

| Event class | Examples |
|---|---|
| auth | GSI failure, token validation failure, dashboard login failure |
| namespace | not found, denied, locked, collection too large |
| I/O | read error, write error, fsync error, disk full |
| TPC | curl failure, remote HTTP error, commit failure |
| dashboard | table full, stale slot cleanup, JSON truncation |

The dashboard could show the last 100-500 sanitized events with time, protocol,
status, and short reason. This is not a replacement for access logs, but it
gives operators immediate context during incidents.

## Operational Views

### Protocol summary cards

Add one compact card per protocol with:

- active transfers
- current ingress and egress rate
- lifetime bytes
- request success/error counts
- auth failure rate
- top current error class

These should be derived from the existing metrics shared-memory zone and the
active transfer table, not from Prometheus queries.

### Cache and write-through health

If cache or write-through mode is enabled, show:

- cache occupancy and configured eviction threshold
- fill operations in progress
- origin host and TLS mode
- eviction rate and recent eviction errors
- write-through dirty handles and pending async flushes
- origin mirror failures

This would put the common "is storage full or is the origin slow?" question on
the first screen.

### Manager and cluster health

For manager-mode deployments, add a cluster panel backed by the manager registry:

- registered data servers
- advertised path prefixes
- free space, utilization, and last heartbeat age
- current redirect target selection for a typed path
- unhealthy or stale entries

This would connect the live dashboard to redirector operations without requiring
operators to inspect shared-memory state or logs directly.

### HTTP-TPC progress

TPC transfers deserve their own view because failures often involve remote
systems:

- pull vs push mode
- local path and redacted remote endpoint
- bytes committed locally
- remote HTTP status or curl exit code
- credential source summary, without exposing secrets
- timeout, retry, and cleanup state
- final commit or rename status

If performance markers are added later, show the last marker time and position.

## Security and Access Control

### Configurable session settings

The implementation already has a session lifetime field internally, but no
public directive exposes it. Useful future directives:

```nginx
xrootd_dashboard_session_ttl 8h;
xrootd_dashboard_cookie_path /xrootd;
```

Only document these in the directive reference after they are implemented.

### Multiple admin users

Replace the single shared password with an optional users file:

```nginx
xrootd_dashboard_users /etc/nginx/xrootd-dashboard.htpasswd;
```

The first version can be read-only users with bcrypt or Apache htpasswd
compatible hashes. A later version could add roles if the dashboard ever gains
operator actions.

### Audit trail

Record dashboard login successes/failures and JSON access failures in a bounded
event ring and access log. Avoid logging passwords, cookies, bearer tokens, or
full credential material.

## API and UI Improvements

### Versioned JSON

Add schema metadata to `/xrootd/transfers`:

```json
{
  "schema": "xrootd-dashboard.v1",
  "server_ms": 1760000000000,
  "active_transfers": [],
  "totals": {}
}
```

This lets the embedded page and any external tooling handle additive fields
cleanly.

### Bounded history

Keep a short in-memory time series, for example 10-30 minutes at 5-second
resolution, for dashboard sparklines:

- aggregate ingress and egress
- active transfers
- request error rate
- auth failure rate
- write stalls
- cache occupancy

Long-term history still belongs in Prometheus.

### Snapshot export

Add a "download snapshot" button that exports the current JSON view, including
active transfers, totals, and recent errors. This helps operators attach a
sanitized incident snapshot without scraping logs.

### Accessibility and mobile layout

Improve the embedded page for smaller screens and keyboard use:

- clear focus states
- table captions and accessible labels
- high-contrast status colors plus text labels
- responsive summary cards
- reduced-motion mode for rate updates

## Implementation Notes

- Add tests for each lifecycle path: success, error, and cancellation/cleanup.
- Use existing path, auth, lock, metrics, and response helpers. Do not duplicate
  WebDAV or S3 path resolution logic in dashboard code.
- Keep shared-memory writes cheap on the hot path. Allocate/free may take a
  short lock; byte updates should remain atomic.
- Sanitize all strings before JSON emission. Paths and identities are not
  NUL-terminated by convention elsewhere in nginx code, so copy with explicit
  lengths.
- Treat table-full behavior as non-fatal: log or count the dropped dashboard
  slot, but never fail a data transfer because observability is saturated.

## Suggested First Milestone

The best next slice is small but valuable:

1. Add WebDAV GET and PUT active transfer slots.
2. Add `state`, `idle_ms`, and `avg_bps` to the JSON response.
3. Add protocol, direction, status, and text filters to the embedded page.
4. Add tests for WebDAV transfer tracking success, request abort cleanup, and
   security redaction in JSON.

That milestone makes the dashboard useful for HTTPS-heavy deployments while
keeping the implementation bounded.
