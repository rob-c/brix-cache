# PromQL Query Examples

Concrete PromQL queries for common monitoring scenarios. Replace `[1m]`, `[5m]`, or `[3600]` with the window you need — 1-minute, 5-minute, and hourly examples shown throughout.

---

## Protocol Separation Queries

### Total throughput by protocol in MB/s:
```promql
# Native XRootD root:// throughput
sum(rate(brix_bytes_root_tx_total[5m])) / 1024 / 1024

# WebDAV (davs:// and https://) throughput — combine both IP versions
sum(rate(brix_webdav_bytes_tx_ipv4_total[5m]) + rate(brix_webdav_bytes_tx_ipv6_total[5m])) / 1024 / 1024

# S3-compatible throughput — combine both IP versions
sum(rate(brix_s3_bytes_tx_ipv4_total[5m]) + rate(brix_s3_bytes_tx_ipv6_total[5m])) / 1024 / 1024
```

### Combined protocol throughput (all protocols):
```promql
# Total throughput across all protocols in MB/s
(
  sum(rate(brix_bytes_root_tx_total[5m]))
+ sum(rate(brix_webdav_bytes_tx_ipv4_total[5m]) + rate(brix_webdav_bytes_tx_ipv6_total[5m]))
+ sum(rate(brix_s3_bytes_tx_ipv4_total[5m]) + rate(brix_s3_bytes_tx_ipv6_total[5m]))
) / 1024 / 1024
```

### Protocol share as percentage:
```promql
# What fraction of traffic is root:// vs WebDAV vs S3?
(
  sum(rate(brix_bytes_root_tx_total[5m]))
/ (
    sum(rate(brix_bytes_root_tx_total[5m]))
  + sum(rate(brix_webdav_bytes_tx_ipv4_total[5m]) + rate(brix_webdav_bytes_tx_ipv6_total[5m]))
  + sum(rate(brix_s3_bytes_tx_ipv4_total[5m]) + rate(brix_s3_bytes_tx_ipv6_total[5m])))
) * 100
```

---

## IPv4 vs IPv6 Combined Queries (Native XRootD + WebDAV)

### Total throughput by IP version (native XRootD + WebDAV):
```promql
# Combined IPv4 throughput in MB/s — all protocols except S3
(
  sum(rate(brix_bytes_tx_ipv4_total[5m]))       # native XRootD IPv4 tx
+ sum(rate(brix_webdav_bytes_tx_ipv4_total[5m]))  # WebDAV IPv4 tx
) / 1024 / 1024

# Combined IPv6 throughput in MB/s — all protocols except S3
(
  sum(rate(brix_bytes_tx_ipv6_total[5m]))       # native XRootD IPv6 tx
+ sum(rate(brix_webdav_bytes_tx_ipv6_total[5m]))  # WebDAV IPv6 tx
) / 1024 / 1024
```

### Receive vs send by IP version:
```promql
# Data received FROM clients (uploads/writes) — combined IPv4/IPv6
(
  sum(rate(brix_bytes_rx_ipv4_total[5m])) + sum(rate(brix_bytes_rx_ipv6_total[5m]))
+ sum(rate(brix_webdav_bytes_rx_ipv4_total[5m])) + sum(rate(brix_webdav_bytes_rx_ipv6_total[5m])))
) / 1024 / 1024

# Data sent TO clients (downloads/reads) — combined IPv4/IPv6  
(
  sum(rate(brix_bytes_tx_ipv4_total[5m])) + sum(rate(brix_bytes_tx_ipv6_total[5m]))
+ sum(rate(brix_webdav_bytes_tx_ipv4_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv6_total[5m])))
) / 1024 / 1024
```

### IPv6 adoption rate:
```promql
# What percentage of traffic is IPv6? (typically low, growing over time)
(
  sum(rate(brix_bytes_tx_ipv6_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv6_total[5m]))
/ (
    sum(rate(brix_bytes_tx_ipv4_total[5m])) + sum(rate(brix_bytes_tx_ipv6_total[5m])))
  + sum(rate(brix_webdav_bytes_tx_ipv4_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv6_total[5m])))
)) * 100
```

### Per-port IPv6 breakdown:
```promql
# IPv6 traffic per port (helps identify if specific listeners are seeing IPv6)
rate(brix_bytes_tx_ipv6_total[5m]) + rate(brix_webdav_bytes_tx_ipv6_total[5m])
```

---

## Single VO Combined Analysis (IPv4+IPv6, root:// + davs://)

### VO throughput — native XRootD only (most accurate for per-VO tracking):
```promql
# CMS downloads in MB/s via root:// protocol
rate(brix_vo_bytes_tx_total{vo="cms"}[5m]) / 1024 / 1024

# Compare with aggregate native XRootD tx to see VO share of total
rate(brix_vo_bytes_tx_total{vo="cms"}[5m]) 
/ sum(rate(brix_bytes_root_tx_total[5m])) * 100
```

### VO request rate:
```promql
# Requests per second from CMS users (native XRootD only)
rate(brix_vo_requests_total{vo="cms"}[5m])
```

### Per-VO upload vs download ratio (native XRootD):
```promql
# For a single VO: upload (bytes_rx) vs download (bytes_tx) ratio
sum(rate(brix_bytes_rx_ipv4_total{port="1094",auth="gsi"}[5m])) + sum(rate(brix_bytes_rx_ipv6_total{port="1094",auth="gsi"}[5m])))
/ (
  sum(rate(brix_bytes_tx_ipv4_total{port="1094",auth="gsi"}[5m])) + sum(rate(brix_bytes_tx_ipv6_total{port="1094",auth="gsi"}[5m])))
)
```

**Note:** Per-VO metrics are most accurate for native XRootD (stream layer). WebDAV and S3 do not currently populate per-VO counters in the shared memory tables — they contribute to global IPv4/IPv6 byte totals only. To estimate a single VO's total across all protocols, combine the per-VO native metric with proportional estimates from global metrics based on VO request count ratios:

```promql
# Estimate: VO share of WebDAV traffic using VO request ratio as proxy
sum(rate(brix_webdav_bytes_tx_ipv4_total[5m]) + rate(brix_webdav_bytes_tx_ipv6_total[5m]))
* (rate(brix_vo_requests_total{vo="cms"}[5m]) / sum by ()(rate(brix_vo_requests_total[5m]))) 
/ 1024 / 1024
```

---

## Unique Users — "Seen This Session" Tracking

### Current active users vs lifetime total:
```promql
# How many users are currently being tracked? (bounded by table size)
brix_unique_users_current

# Total unique users ever seen since process start (never decreases)
brix_unique_users_total

# Ratio — what fraction of lifetime users are still active?
brix_unique_users_current / brix_unique_users_total * 100
```

### New users per hour:
```promql
# Approximate new unique users per hour (accounting for evictions)
increase(brix_unique_users_total[3600]) 
- increase(brix_user_evictions_total[3600])
```

### Most active users (top 20 by session count):
```promql
sort_desc(brix_user_sessions_total{hash!=""}) limit 20
```

---

## Per-VO Breakdown with IP Version Details

### VO throughput by IP version (native XRootD only):
```promql
# CMS downloads via IPv4 vs IPv6 on port 1094
rate(brix_bytes_tx_ipv4_total{port="1094",auth="gsi"}[5m]) / 1024 / 1024    # MB/s IPv4
rate(brix_bytes_tx_ipv6_total{port="1094",auth="gsi"}[5m]) / 1024 / 1024    # MB/s IPv6

# Sum both for total VO throughput on this port
(rate(brix_bytes_tx_ipv4_total{port="1094",auth="gsi"}[5m]) + rate(brix_bytes_tx_ipv6_total{port="1094",auth="gsi"}[5m])) / 1024 / 1024
```

---

## Alerting Examples

### High IPv6 traffic threshold (warning if >5%):
```promql
(
  sum(rate(brix_bytes_tx_ipv6_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv6_total[5m])))
/ (
    sum(rate(brix_bytes_tx_ipv4_total[5m])) + sum(rate(brix_bytes_tx_ipv6_total[5m])))
  + sum(rate(brix_webdav_bytes_tx_ipv4_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv6_total[5m])))
)) * 100 > 5
```

### VO table full (overflow detected):
```promql
brix_vo_overflow_total > 0
```

### User tracking table full:
```promql
brix_user_evictions_total > 0
```

### Unusual user growth spike (>10 new users/hour):
```promql
increase(brix_unique_users_total[3600]) - increase(brix_user_evictions_total[3600]) > 10
```

---

## Grafana Dashboard Query Templates

### Panel: Protocol Throughput Stacked Area

| Expression | Label |
|---|---|
| `sum(rate(brix_bytes_root_tx_total[5m])) / 1024 / 1024` | root:// |
| `sum(rate(brix_webdav_bytes_tx_ipv4_total[5m]) + rate(brix_webdav_bytes_tx_ipv6_total[5m])) / 1024 / 1024` | davs:// |
| `sum(rate(brix_s3_bytes_tx_ipv4_total[5m]) + rate(brix_s3_bytes_tx_ipv6_total[5m])) / 1024 / 1024` | s3:// |

### Panel: IPv4 vs IPv6 Traffic Share

| Expression | Label |
|---|---|
| `sum(rate(brix_bytes_tx_ipv4_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv4_total[5m])) / 1024 / 1024` | IPv4 |
| `sum(rate(brix_bytes_tx_ipv6_total[5m])) + sum(rate(brix_webdav_bytes_tx_ipv6_total[5m])) / 1024 / 1024` | IPv6 |

### Panel: Top VOs by Throughput
```promql
sort_desc(
  rate(brix_vo_bytes_tx_total[5m]) 
/ vector(1) * 1024 / 1024
) limit 10
```

---

## Next Steps

- See [extended-metrics.md](./extended-metrics.md) for metric descriptions and cardinality guarantees
- See [metrics-analysis.md](./metrics-analysis.md) for interpretation guidance on all metric families
