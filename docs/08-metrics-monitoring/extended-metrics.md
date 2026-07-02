# Extended Metrics: Protocol, IP version, VO, and user tracking

High-level monitoring counters for traffic analysis by protocol, IP version, virtual organisation, and unique user identity. These metrics use bounded tables to prevent cardinality explosion while preserving analytical value.

---

## Per-protocol Byte Counters (Native XRootD)

Separates root:// data transfer from WebDAV and S3 at the stream layer:

**Metrics:**
- `xrootd_bytes_root_rx_total` — bytes received via root:// protocol only
- `xrootd_bytes_root_tx_total` — bytes sent via root:// protocol only

```
xrootd_bytes_root_rx_total{port="1094",auth="gsi"} 5368709120
xrootd_bytes_root_tx_total{port="1094",auth="gsi"} 107374182400
```

Use `rate(xrootd_bytes_root_tx_total[1m])` for root:// read throughput and compare against the aggregate `xrootd_bytes_tx_total` to verify no other protocol is contributing.

---

## Per-IP-version Bandwidth Counters

Tracks IPv4 vs IPv6 traffic separately without adding per-client IP as a Prometheus label (which would create unbounded series). Available for all three protocols:

### Native XRootD stream layer:
```
xrootd_bytes_rx_ipv4_total{port="1094",auth="gsi"} 5368709120
xrootd_bytes_tx_ipv4_total{port="1094",auth="gsi"} 107374182400
xrootd_bytes_rx_ipv6_total{port="1094",auth="gsi"} 0
xrootd_bytes_tx_ipv6_total{port="1094",auth="gsi"} 0
```

### WebDAV (davs://):
```
xrootd_webdav_bytes_rx_ipv4_total 5368709120
xrootd_webdav_bytes_tx_ipv4_total 107374182400
xrootd_webdav_bytes_rx_ipv6_total 0
xrootd_webdav_bytes_tx_ipv6_total 0
```

### S3-compatible:
```
xrootd_s3_bytes_rx_ipv4_total 5368709120
xrootd_s3_bytes_tx_ipv4_total 107374182400
xrootd_s3_bytes_rx_ipv6_total 0
xrootd_s3_bytes_tx_ipv6_total 0
```

**PromQL examples:**
```promql
# IPv6 traffic fraction (should be low for most sites)
rate(xrootd_bytes_tx_ipv6_total[1m]) / rate(xrootd_bytes_tx_total[1m])

# Protocol separation — sum all tx counters to verify consistency
rate(xrootd_bytes_root_tx_total[1m]) + rate(xrootd_webdav_bytes_tx_ipv4_total[1m]) + rate(xrootd_webdav_bytes_tx_ipv6_total[1m]) + rate(xrootd_s3_bytes_tx_ipv4_total[1m]) + rate(xrootd_s3_bytes_tx_ipv6_total[1m])
```

---

## Per-VO Traffic Tracking

Groups data transfer by virtual organisation. VO names are truncated to **15 characters** for storage efficiency. The table supports up to **32 VOs** simultaneously; excess VOs increment an overflow counter and evict the oldest entry (LRU policy).

```text
  WHY BOUNDED: a Prometheus label per VO/user would explode cardinality.
  A fixed SHM table with LRU eviction keeps the series count flat.

   VO table (cap 32)                     new VO arrives, table FULL
   ┌────────────┬──────────┐             ┌────────────┬──────────┐
   │ cms        │ bytes,req│ ← MRU        │ lhcb (new) │ 0,0      │ ← inserted
   │ atlas      │ …        │              │ cms        │ …        │
   │ …          │ …        │              │ atlas      │ …        │
   │ dteam      │ …        │ ← LRU ──evict│ ███████████│ dropped  │   oldest out
   └────────────┴──────────┘  +1 overflow └────────────┴──────────┘
                              xrootd_vo_overflow_total ▲ alert: >32 active VOs
   users table is the same shape: cap 512, DN/sub hashed (FNV-1a), LRU evict
```

**Metrics:**
- `xrootd_vo_bytes_tx_total{vo="..."}` — bytes sent to clients from this VO's users
- `xrootd_vo_bytes_rx_total{vo="..."}` — bytes received from this VO's users  
- `xrootd_vo_requests_total{vo="..."}` — request count for this VO

```
xrootd_vo_bytes_tx_total{vo="cms"} 1234567890
xrootd_vo_bytes_tx_total{vo="atlas"} 9876543210
xrootd_vo_requests_total{vo="cms"} 54321
```

**PromQL examples:**
```promql
# Total throughput per VO (bytes/s)
rate(xrootd_vo_bytes_tx_total[1m])

# Per-VO request rate
rate(xrootd_vo_requests_total[1m])

# VOs approaching tracking limit (overflow > 0 indicates more VOs than slots)
xrootd_vo_overflow_total > 0
```

**Configuration note:** VO information comes from:
- GSI proxy certificates via VOMS attribute extraction (`src/auth/voms/`)
- WLCG JWT token `groups` claim for bearer-token sessions  
- SSS shared secret `group` field for simple authentication

---

## Unique User Identity Tracking

Counts distinct authenticated users since process start. Users are identified by hashing their DN (GSI) or token sub claim via **FNV-1a 32-bit hash** before lookup. The table supports up to **1024 tracked identities** simultaneously; excess entries evict the oldest slot using LRU policy.

**Metrics:**
- `xrootd_unique_users_current` — currently tracked unique users (bounded by table size)
- `xrootd_unique_users_total` — lifetime unique users seen (never decreases)
- `xrootd_user_evictions_total` — slots recycled when table is full
- `xrootd_user_sessions_total{hash=...}` — sessions per hashed identity

```
xrootd_unique_users_current 42
xrootd_unique_users_total 1873
xrootd_user_evictions_total 156
xrootd_user_sessions_total{hash=a1b2c3d4} 5
```

**PromQL examples:**
```promql
# New unique users per hour (rate of total minus current = evictions approximately)
rate(xrootd_unique_users_total[1h]) - rate(xrootd_unique_users_current[1h])

# Most active users by session count
sort_desc(xrootd_user_sessions_total[0]) limit 20

# Ratio of unique users to concurrent connections (engagement metric)
xrootd_unique_users_current / xrootd_connections_active
```

**Configuration note:** Identity information comes from:
- GSI proxy certificates — X.509 subject DN (`ctx->dn`)
- WLCG JWT tokens — `sub` claim from token payload
- SSS shared secret — username field from encrypted identity block

---

## Monitoring Dashboard Recommendations

For a complete view of system health, combine these metrics in Grafana panels:

| Panel | Query | Purpose |
|---|---|---|
| Protocol breakdown | `rate(xrootd_bytes_root_tx_total[1m])`, `rate(xrootd_webdav_bytes_tx_ipv4_total[1m]) + rate(xrootd_webdav_bytes_tx_ipv6_total[1m])` etc. | See which protocol is dominant |
| IPv6 adoption | `sum(rate(xrootd_bytes_tx_ipv6_total[1m])) / sum(rate(xrootd_bytes_tx_total[1m]))` across all families | Track IPv6 migration progress |
| VO activity ranking | `sort_desc(sum by (vo) (rate(xrootd_vo_bytes_tx_total[1m]))) limit 20` | Identify top VOs by traffic |
| User growth trend | `increase(xrootd_unique_users_total[7d]) / 7 * 24` | Daily new user rate |
| Cache efficiency | `xrootd_user_sessions_total{hash=...} > 10` with connection active gauge | Identify heavy users for cache tuning |

---

## Cardinality Safety Guarantees

All extended metrics are designed to prevent unbounded cardinality:

| Metric family | Bounded by | Eviction strategy |
|---|---|---|
| Per-VO counters | `XROOTD_VO_MAX_TRACKED` (32 slots) | LRU — oldest slot evicted when full |
| Unique users | `XROOTD_USERS_MAX_TRACKED` (1024 slots) | LRU — oldest slot evicted when full |
| IP version | 2 counters per protocol family | Fixed-size, no eviction needed |
| Protocol label | 3 labels + unknown | Fixed set, no eviction needed |

**VO names and user DNs are never used as Prometheus label values.** VO appears in the metric name portion of HELP/TYPE comments; users appear only via a hash value in `{hash=...}` labels. This ensures that even with thousands of unique VOs or users over time, the number of Prometheus series remains constant at `XROOTD_VO_MAX_TRACKED` and `XROOTD_USERS_MAX_TRACKED` respectively.

---

## Next Steps

- See [promql-examples.md](./promql-examples.md) for detailed PromQL queries covering all scenarios
- See [metrics-analysis.md](./metrics-analysis.md) for health check interpretation and alerting rules
