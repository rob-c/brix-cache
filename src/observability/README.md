# observability — metrics, packet marking, dashboard, and access logs

How operators see the server: the Prometheus `/metrics` exporter and its
SHM counter tables, SciTags packet marking for WLCG network attribution,
the built-in HTML dashboard, and the per-request access log.

| Dir | What |
|---|---|
| [metrics/](metrics/) | Prometheus exporter (`/metrics`), SHM counter slots, per-proto/per-op counters |
| [pmark/](pmark/) | SciTags packet marking (flow labels for WLCG network attribution) |
| [dashboard/](dashboard/) | built-in HTML status dashboard |
| [accesslog/](accesslog/) | structured one-line access records (sanitized identity/verb/path/status/bytes/duration) |

**Invariant:** metric labels are low-cardinality only — never paths,
bucket names, or UUIDs (CLAUDE.md INVARIANT 8). New protocols get their
metric families generated from the central `proto_list.h` row — don't
hand-add exporter entries.
