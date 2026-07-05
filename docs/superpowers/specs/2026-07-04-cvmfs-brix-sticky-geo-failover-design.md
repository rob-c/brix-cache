# CVMFS-brix sticky-geo failover (design)

**Date:** 2026-07-04
**Goal:** brix prefers the geo-closest Stratum-1, fails over only reluctantly, and snaps back to
the closest ASAP — treating a badly-behaved/unresponsive server as a transient network fault, not
a dead service.

## Three coordinated changes

### 1. Geo-order the hosts at mount (client)
Query the CVMFS Geo API on a Stratum-1: `GET /cvmfs/<repo>/api/v1.0/geo/x/<h1,h2,…>` (hostnames
from the server list) → a proximity-sorted 1-based order for the caller's IP (e.g. `2,1,3`).
Reorder `fo.hosts` so **index 0 = geo-closest**. Falls back to configured order if the geo endpoint
is unavailable or there is ≤1 host.
- `cvmfs_geo_parse_order(resp, out[], max) → n` (pure, unit-tested)
- `cvmfs_failover_reorder_hosts(fo, order[], n)` (pure, unit-tested)
- `cvmfs_client_geo_sort(cl, now)` — build query, raw_fetch, parse, reorder (live-tested)

### 2. Sticky ordered host selection (failover engine)
Change host selection from lowest-EWMA to **lowest live index** — always use the closest available
server, failing over to the next-closest only while a nearer one is blacklisted. (Proxies keep
group order.) This is the stickiness: it never drifts off the closest for a marginally-faster peer.

### 3. Snap-back adaptive blacklist (failover engine)
Replace the fixed blacklist with an escalating one: on failure, `blacklisted_until = now + min(
base × 2^(fail_count−1), reset_interval_s)`. First failure of the closest → ~`base`(2s) probation →
the next selection returns to it (snap back, assuming a network blip); a server that KEEPS failing
backs off toward the cap (genuine outage). Success resets `fail_count`, so recovery is always fast.
- New field `base_blacklist_s` (default 2); `reset_interval_s` stays the cap.

## Data flow
mount → load trust+catalog → **geo_sort hosts** (index 0 = closest) → serve. Every fetch:
`select` = lowest live index (sticky) → on fail, `record` applies the escalating blacklist →
next fetch snaps back to the closest once its short probation lapses.

## Testing
- failover unit (rewrite `test_failover`): sticky = lowest live index chosen (NOT EWMA); snap-back
  = short first blacklist → failover → return after base; escalation = repeated fails → longer
  blacklist; success resets.
- geo unit: parse "2,1,3" → reorder hosts correctly; malformed → no-op.
- live: mount a real repo with a multi-server list; confirm geo-sort reorders (or no-op on 1 host).

## Out of scope
Proxy geo-sorting (proxies stay group-ordered); RTT-probe background timer (server-side already).
