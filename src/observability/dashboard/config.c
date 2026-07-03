#include "core/config/config.h"
#include "core/compat/shm_slots.h"

/*
 * dashboard/config.c — SHM zone registration for the live transfer monitor.
 *
 * WHAT: Registers the brix_dashboard shared-memory zone during stream
 *       postconfiguration.  Called after brix_configure_metrics() in
 *       postconfiguration.c.  The init callback is implemented in
 *       transfer_table.c alongside the mutex it owns.
 *
 * WHY:  Keeping zone registration separate from slot operations mirrors the
 *       metrics pattern (metrics/config.c registers the zone; the actual SHM
 *       struct lives in the metrics types).  config.c needs to be in the
 *       stream module source list because it references ngx_stream_brix_module.
 */

/* Global pointer set here; read by the HTTP dashboard module at request time. */
ngx_shm_zone_t *ngx_brix_dashboard_shm_zone;
ngx_shm_zone_t *ngx_brix_dashboard_events_shm_zone;
ngx_shm_zone_t *ngx_brix_dashboard_history_shm_zone;

ngx_int_t
brix_configure_dashboard(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("brix_dashboard_v2");
    ngx_str_t  events_name = ngx_string("brix_dashboard_events");
    ngx_str_t  history_name = ngx_string("brix_dashboard_history");
    size_t     zone_size;

    zone_size = brix_shm_zone_size(sizeof(brix_transfer_table_t));

    ngx_brix_dashboard_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                           zone_size,
                                                           &ngx_stream_brix_module);
    if (ngx_brix_dashboard_shm_zone == NULL) {
        return NGX_ERROR;
    }

    ngx_brix_dashboard_shm_zone->init = ngx_brix_dashboard_shm_init;
    /* Non-NULL sentinel lets the init callback detect first-startup vs reload. */
    ngx_brix_dashboard_shm_zone->data = (void *) 1;

    zone_size = brix_shm_zone_size(sizeof(brix_dashboard_event_table_t));
    ngx_brix_dashboard_events_shm_zone =
        ngx_shared_memory_add(cf, &events_name, zone_size,
                              &ngx_stream_brix_module);
    if (ngx_brix_dashboard_events_shm_zone == NULL) {
        return NGX_ERROR;
    }

    ngx_brix_dashboard_events_shm_zone->init =
        ngx_brix_dashboard_events_shm_init;
    ngx_brix_dashboard_events_shm_zone->data = (void *) 1;

    zone_size = brix_shm_zone_size(sizeof(brix_dashboard_history_t));
    ngx_brix_dashboard_history_shm_zone =
        ngx_shared_memory_add(cf, &history_name, zone_size,
                              &ngx_stream_brix_module);
    if (ngx_brix_dashboard_history_shm_zone == NULL) {
        return NGX_ERROR;
    }

    ngx_brix_dashboard_history_shm_zone->init =
        ngx_brix_dashboard_history_shm_init;
    ngx_brix_dashboard_history_shm_zone->data = (void *) 1;

    return NGX_OK;
}
