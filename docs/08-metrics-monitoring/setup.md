# Prometheus Metrics Setup

How to configure the Prometheus scrape endpoint and verify it's exporting data. Five minutes from zero to a working `/metrics` scrape.

---

## Endpoint Configuration

Add an `http {}` block to `nginx.conf` with the `brix_metrics` directive:

```nginx
http {
    server {
        listen 9100;
        location /metrics {
            brix_metrics on;
        }
    }
}
```

Then scrape it:

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

---

## Metrics Storage Model

Metrics are shared across all nginx worker processes via **shared memory** and updated atomically. They survive `nginx -s reload` (counters are preserved across config reloads).

Client-controlled strings are not used as Prometheus label values. Exported labels come from server configuration (`port`, `auth`) and fixed operation/result tables (`op`, `status`, `method`, `status_class`, `result`, `mode`, `event`). The current native XRootD `auth` metric label is `gsi` for GSI-only listeners and `anon` for all non-GSI-only listeners, including token and mixed listeners.

---

## Limits

Up to 16 stream server blocks are tracked simultaneously. This is a compile-time limit (`BRIX_METRICS_MAX_SERVERS` in `src/observability/metrics/metrics.h`).

When the limit is reached, additional listeners will not appear in metrics output. Monitor for this condition by checking that all expected ports/auth combinations appear in each metric series.

---

## Next Steps

- See [metrics-overview.md](./metrics-overview.md) for a complete catalog of available metrics
- See [extended-metrics.md](./extended-metrics.md) for protocol separation, IP version tracking, VO and user analytics
- See [promql-examples.md](./promql-examples.md) for ready-to-use PromQL queries
