# Metrics and Logging Documentation

This directory contains comprehensive documentation for nginx-xrootd monitoring capabilities, organized by topic for easy reference.

## Quick Navigation

| Document | Content |
|---|---|
| [setup.md](./setup.md) | Prometheus endpoint configuration and scraping setup |
| [metrics-overview.md](./metrics-overview.md) | Complete catalog of available metrics (stream, WebDAV, S3) |
| [extended-metrics.md](./extended-metrics.md) | Protocol separation, IP version tracking, VO and user analytics |
| [promql-examples.md](./promql-examples.md) | PromQL queries for common monitoring scenarios |
| [access-logging.md](./access-logging.md) | Access log format, configuration, and interpretation |
| [metrics-analysis.md](./metrics-analysis.md) | Metric analysis guidance, health checks, alerting rules |

## Overview

The module provides two ways to observe what is happening: a **Prometheus metrics endpoint** and a **per-request access log**.

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

### Access Logging

Per-request access logs record every XRootD operation with timing and byte counts:

```nginx
xrootd_access_log /var/log/nginx/xrootd_access.log;
```

---

## Related Documentation

- [Configuration Directives](../configuration/directives.md) — Full reference for nginx directives
- [Architecture Overview](../architecture/index.md) — Request lifecycle diagrams
- [WebDAV Methods](../webdav/methods.md) — WebDAV operation details and RFC compliance
