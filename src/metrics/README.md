# metrics — Prometheus HTTP exporter for nginx-xrootd

Implements the `xrootd_metrics` directive and exposes XRootD counters in the
Prometheus text exposition format (0.0.4).  Registered as a separate nginx HTTP
module (`ngx_http_xrootd_metrics_module`).

## Usage

```nginx
http {
    server {
        listen 9100;
        location /metrics {
            xrootd_metrics on;
        }
    }
}
```

Scrape with `curl http://localhost:9100/metrics`.

## File map

| File | Responsibility |
|------|----------------|
| `config.c` | Stream-side shared-memory zone setup and per-listener metrics slot assignment |
| `metrics.h` | Public shared-memory layout (`ngx_xrootd_metrics_t`, `ngx_xrootd_srv_metrics_t`, `XROOTD_OP_*` constants, `ngx_xrootd_shm_zone` extern); included by the stream module too |
| `metrics_internal.h` | Module-private types (`ngx_http_xrootd_metrics_loc_conf_t`, `metrics_writer_t`) and cross-file prototypes |
| `module.c` | nginx directive table, `ngx_http_module_t` context, `ngx_module_t` definition, and location-config create/merge/set callbacks |
| `writer.c` | `metrics_writer_t` buffer-chain writer: `mw_init`, `mw_printf`, `mw_finish` |
| `stream.c` | `xrootd_op_names[]` table and `xrootd_export_prometheus_metrics` — iterates the shared-memory slots and emits Prometheus lines for stream-protocol counters; calls the HTTP protocol exporters at the end |
| `webdav.c` | `xrootd_export_webdav_metrics` — Prometheus export for WebDAV HTTP counters (requests, responses, auth, TPC, CORS, PROPFIND, range, fd-cache) |
| `s3.c` | `xrootd_export_s3_metrics` — Prometheus export for S3-compatible HTTP counters (requests, responses, auth, bytes, range, PUT body mode, ListObjectsV2, diagnostics) |
| `handler.c` | `ngx_http_xrootd_metrics_handler` HTTP content handler; also owns the `ngx_xrootd_shm_zone` definition |

## Shared memory ABI

The stream module writes to `ngx_xrootd_shm_zone->data` (a `ngx_xrootd_metrics_t *`)
using `ngx_atomic_t` fields so all worker processes can increment counters without
locks.  The HTTP exporter reads counters with `ngx_atomic_fetch_add(..., 0)` for
an eventually-consistent snapshot — individual counter reads are atomic but lines
in the scrape output may reflect slightly different instants.

The `XROOTD_OP_*` slot numbering in `metrics.h` is a binary ABI between the two
modules: the stream side increments slots by index; the exporter maps them back to
label strings via `xrootd_op_names[]` in `stream.c`.  Keep both in sync.

WebDAV and S3 counters live next to the native stream slots in the same shared
memory object. Their labels are fixed enums only; never add bucket names, object
keys, DNs, token subjects, access keys, or other client-controlled strings as
Prometheus labels.
