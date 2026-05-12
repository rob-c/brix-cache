# Metrics and Logging

⚠️ **Documentation has been reorganized into subfolders for easier navigation.** Please see the new structure below:

## New Documentation Structure

The monitoring documentation has been split into topic-specific files in `docs/metrics/`:

| Document | Content |
|---|---|
| [index.md](./metrics/index.md) | Overview and quick navigation |
| [setup.md](./metrics/setup.md) | Prometheus endpoint configuration and scraping setup |
| [metrics-overview.md](./metrics/metrics-overview.md) | Complete catalog of available metrics (stream, WebDAV, S3) |
| [extended-metrics.md](./metrics/extended-metrics.md) | Protocol separation, IP version tracking, VO and user analytics |
| [promql-examples.md](./metrics/promql-examples.md) | PromQL queries for common monitoring scenarios |
| [access-logging.md](./metrics/access-logging.md) | Access log format, configuration, and interpretation |
| [metrics-analysis.md](./metrics/metrics-analysis.md) | Metric analysis guidance, health checks, alerting rules |

The content has been preserved in full — this file is maintained as a compatibility stub. Please update any external references to point to the new structure under `docs/metrics/`.

---

*For the complete documentation, see [docs/metrics/index.md](./metrics/index.md).*
