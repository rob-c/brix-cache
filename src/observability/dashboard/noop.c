#include "dashboard.h"
#include "dashboard_tracking.h"

/*
 * dashboard/noop.c — stub implementation of the entire dashboard public API.
 *
 * WHAT: Defines the three SHM zone pointers (ngx_xrootd_dashboard_shm_zone,
 *       _events_shm_zone, _history_shm_zone) and a do-nothing version of every
 *       symbol that transfer_table.c, events.c, history.c and http_tracking.c
 *       normally provide — the slot ops, event log, history sampler and HTTP
 *       request-tracking hooks.  Allocators return -1 / NGX_OK, snapshots return
 *       0, mutators silently discard their arguments.
 * WHY:  The live monitor can be compiled out without touching every call site.
 *       Callers across the stream and HTTP code reference these symbols
 *       unconditionally; building this file *instead of* the real dashboard
 *       sources satisfies the linker and turns all tracking into cheap no-ops.
 *       (It is intentionally NOT listed in the addon `config`, which wires in the
 *       full implementation; noop.c is the drop-in replacement for a
 *       dashboard-disabled build.)
 * HOW:  Each function matches its real prototype exactly, casts every parameter
 *       to (void) to suppress unused-argument warnings, and returns the neutral
 *       value the callers treat as "no tracking active".  Keep this file in sync
 *       with dashboard_tracking.h and dashboard.h whenever the API changes.
 */

ngx_shm_zone_t *ngx_xrootd_dashboard_shm_zone;
ngx_shm_zone_t *ngx_xrootd_dashboard_events_shm_zone;
ngx_shm_zone_t *ngx_xrootd_dashboard_history_shm_zone;

ngx_int_t
xrootd_configure_dashboard(ngx_conf_t *cf)
{
    (void) cf;
    return NGX_OK;
}

ngx_int_t
ngx_xrootd_dashboard_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    (void) shm_zone;
    (void) data;
    return NGX_OK;
}

ngx_int_t
ngx_xrootd_dashboard_events_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    (void) shm_zone;
    (void) data;
    return NGX_OK;
}

ngx_int_t
ngx_xrootd_dashboard_history_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    (void) shm_zone;
    (void) data;
    return NGX_OK;
}

int
xrootd_transfer_slot_alloc(xrootd_transfer_table_t *t,
    const u_char sessid[16], const char *client_ip, const char *identity,
    const char *path, uint8_t direction, uint8_t proto, int64_t now_ms)
{
    (void) t;
    (void) sessid;
    (void) client_ip;
    (void) identity;
    (void) path;
    (void) direction;
    (void) proto;
    (void) now_ms;

    return -1;
}

int
xrootd_transfer_slot_alloc_ex(xrootd_transfer_table_t *t,
    const u_char sessid[16], const char *client_ip, const char *identity,
    const char *vo, const char *path, const char *op, uint8_t direction,
    uint8_t proto, int64_t expected_bytes, int64_t now_ms)
{
    (void) t;
    (void) sessid;
    (void) client_ip;
    (void) identity;
    (void) vo;
    (void) path;
    (void) op;
    (void) direction;
    (void) proto;
    (void) expected_bytes;
    (void) now_ms;

    return -1;
}

void
xrootd_transfer_slot_update(xrootd_transfer_table_t *t, int slot_idx,
    ngx_atomic_int_t nbytes, int64_t now_ms)
{
    (void) t;
    (void) slot_idx;
    (void) nbytes;
    (void) now_ms;
}

void
xrootd_transfer_slot_update_bytes(xrootd_transfer_table_t *t, int slot_idx,
    ngx_atomic_int_t nbytes, int64_t now_ms)
{
    (void) t;
    (void) slot_idx;
    (void) nbytes;
    (void) now_ms;
}

void
xrootd_transfer_slot_set_state(xrootd_transfer_table_t *t, int slot_idx,
    uint8_t state, int64_t now_ms)
{
    (void) t;
    (void) slot_idx;
    (void) state;
    (void) now_ms;
}

void
xrootd_transfer_slot_set_error(xrootd_transfer_table_t *t, int slot_idx,
    const char *reason, int64_t now_ms)
{
    (void) t;
    (void) slot_idx;
    (void) reason;
    (void) now_ms;
}

void
xrootd_transfer_slot_set_tpc_remote(xrootd_transfer_table_t *t, int slot_idx,
    const char *remote_host, const char *path_hint, int remote_status,
    int curl_exit)
{
    (void) t;
    (void) slot_idx;
    (void) remote_host;
    (void) path_hint;
    (void) remote_status;
    (void) curl_exit;
}

void
xrootd_transfer_slot_count_op(xrootd_transfer_table_t *t, int slot_idx,
    const char *op)
{
    (void) t;
    (void) slot_idx;
    (void) op;
}

void
xrootd_transfer_slot_free(xrootd_transfer_table_t *t, int slot_idx)
{
    (void) t;
    (void) slot_idx;
}

void
xrootd_transfer_slot_free_all_for_session(xrootd_transfer_table_t *t,
    const u_char sessid[16])
{
    (void) t;
    (void) sessid;
}

void
xrootd_dashboard_event_add(uint8_t class_id, uint8_t proto, uint16_t status,
    const char *message, const char *path_hint)
{
    (void) class_id;
    (void) proto;
    (void) status;
    (void) message;
    (void) path_hint;
}

ngx_uint_t
xrootd_dashboard_events_snapshot(xrootd_dashboard_event_t *out,
    ngx_uint_t max_events)
{
    (void) out;
    (void) max_events;
    return 0;
}

void
xrootd_dashboard_history_sample(int64_t now_ms)
{
    (void) now_ms;
}

ngx_uint_t
xrootd_dashboard_history_snapshot(xrootd_dashboard_history_bucket_t *out,
    ngx_uint_t max_buckets)
{
    (void) out;
    (void) max_buckets;
    return 0;
}

int
xrootd_dashboard_http_start(ngx_http_request_t *r, const char *path,
    uint8_t proto, uint8_t direction, const char *op, int64_t expected_bytes)
{
    (void) r;
    (void) path;
    (void) proto;
    (void) direction;
    (void) op;
    (void) expected_bytes;
    return NGX_OK;
}

int
xrootd_dashboard_http_start_identity(ngx_http_request_t *r,
    const char *path, const char *identity, const char *vo, uint8_t proto,
    uint8_t direction, const char *op, int64_t expected_bytes)
{
    (void) r;
    (void) path;
    (void) identity;
    (void) vo;
    (void) proto;
    (void) direction;
    (void) op;
    (void) expected_bytes;
    return NGX_OK;
}

void
xrootd_dashboard_http_add(ngx_http_request_t *r, ngx_atomic_int_t bytes)
{
    (void) r;
    (void) bytes;
}

void
xrootd_dashboard_http_state(ngx_http_request_t *r, uint8_t state)
{
    (void) r;
    (void) state;
}

void
xrootd_dashboard_http_error(ngx_http_request_t *r, const char *reason)
{
    (void) r;
    (void) reason;
}

void
xrootd_dashboard_http_tpc_remote(ngx_http_request_t *r,
    const char *remote_url, int remote_status, int curl_exit)
{
    (void) r;
    (void) remote_url;
    (void) remote_status;
    (void) curl_exit;
}

void
xrootd_dashboard_http_finish(ngx_http_request_t *r)
{
    (void) r;
}
