#include "dashboard.h"

#include <ngx_shmtx.h>
#include <string.h>

/*
 * dashboard/events.c — fixed-size ring buffer of recent dashboard events.
 *
 * WHAT: Maintains the SHM-backed event log (xrootd_dashboard_event_table_t)
 *       that the dashboard UI shows as a scrolling activity feed.  Workers push
 *       events with xrootd_dashboard_event_add() (errors, auth rejections,
 *       notable status codes, etc.); the JSON exporter reads the newest entries
 *       with xrootd_dashboard_events_snapshot().  ngx_xrootd_dashboard_events_-
 *       shm_init() is the nginx SHM zone init callback for the events zone.
 * WHY:  Events must survive worker boundaries (any worker may emit; the HTTP
 *       worker serving /dashboard reads them all) and survive a config reload,
 *       so the log lives in shared memory rather than per-worker heap.  A bounded
 *       ring (XROOTD_DASHBOARD_MAX_EVENTS slots) gives O(1) insertion with no
 *       allocation and self-evicting history.
 * HOW:  A monotonically increasing next_sequence counter is the source of truth;
 *       slot index is (seq - 1) % XROOTD_DASHBOARD_MAX_EVENTS, so writes wrap and
 *       overwrite the oldest entry.  A single static ngx_shmtx_t (re-created on
 *       reload via the init callback) serialises add and snapshot.  Readers
 *       reconstruct the valid window [next - MAX + 1 .. next] and copy only slots
 *       whose stored sequence still matches the expected value (guards against a
 *       slot overwritten mid-read).  dashboard_event_copy() sanitises strings
 *       into the fixed fields, replacing control bytes with '?' and optionally
 *       truncating a path at the first '?'/'#' to keep query strings out.
 */

static ngx_shmtx_t xrootd_dashboard_events_mutex;

static xrootd_dashboard_event_table_t *
dashboard_events_table(void)
{
    if (ngx_xrootd_dashboard_events_shm_zone == NULL
        || ngx_xrootd_dashboard_events_shm_zone->data == NULL
        || ngx_xrootd_dashboard_events_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (xrootd_dashboard_event_table_t *)
           ngx_xrootd_dashboard_events_shm_zone->data;
}

static void
dashboard_event_copy(char *dst, size_t dstsz, const char *src,
    ngx_flag_t stop_at_query)
{
    size_t i, j;

    if (dst == NULL || dstsz == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    for (i = 0, j = 0; src[i] != '\0' && j + 1 < dstsz; i++) {
        unsigned char c = (unsigned char) src[i];

        if (stop_at_query && (c == '?' || c == '#')) {
            break;
        }

        if (c < 0x20 || c == 0x7f) {
            dst[j++] = '?';
            continue;
        }

        dst[j++] = (char) c;
    }

    dst[j] = '\0';
}

ngx_int_t
ngx_xrootd_dashboard_events_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_dashboard_event_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = data;
        return ngx_shmtx_create(&xrootd_dashboard_events_mutex, &tbl->lock,
                                NULL);
    }

    tbl = (xrootd_dashboard_event_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&xrootd_dashboard_events_mutex, &tbl->lock, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

void
xrootd_dashboard_event_add(uint8_t class_id, uint8_t proto, uint16_t status,
    const char *message, const char *path_hint)
{
    xrootd_dashboard_event_table_t *tbl;
    xrootd_dashboard_event_t       *ev;
    ngx_atomic_t                    seq;
    ngx_uint_t                      idx;

    tbl = dashboard_events_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_dashboard_events_mutex);

    seq = ++tbl->next_sequence;
    idx = (ngx_uint_t) ((seq - 1) % XROOTD_DASHBOARD_MAX_EVENTS);
    ev = &tbl->events[idx];
    ngx_memzero(ev, sizeof(*ev));

    ev->sequence = seq;
    ev->time_ms = (int64_t) ngx_current_msec;
    ev->class_id = class_id;
    ev->proto = proto;
    ev->status = status;
    dashboard_event_copy(ev->message, sizeof(ev->message), message, 0);
    dashboard_event_copy(ev->path_hint, sizeof(ev->path_hint), path_hint, 1);

    ngx_shmtx_unlock(&xrootd_dashboard_events_mutex);
}

ngx_uint_t
xrootd_dashboard_events_snapshot(xrootd_dashboard_event_t *out,
    ngx_uint_t max_events)
{
    xrootd_dashboard_event_table_t *tbl;
    ngx_atomic_t                    next;
    ngx_atomic_t                    first;
    ngx_atomic_t                    seq;
    ngx_uint_t                      n;

    if (out == NULL || max_events == 0) {
        return 0;
    }

    tbl = dashboard_events_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_dashboard_events_mutex);

    next = tbl->next_sequence;
    if (next == 0) {
        ngx_shmtx_unlock(&xrootd_dashboard_events_mutex);
        return 0;
    }

    first = next > XROOTD_DASHBOARD_MAX_EVENTS
            ? next - XROOTD_DASHBOARD_MAX_EVENTS + 1
            : 1;

    if ((ngx_atomic_t) max_events < next - first + 1) {
        first = next - (ngx_atomic_t) max_events + 1;
    }

    n = 0;
    for (seq = first; seq <= next && n < max_events; seq++) {
        ngx_uint_t idx = (ngx_uint_t) ((seq - 1)
                                      % XROOTD_DASHBOARD_MAX_EVENTS);
        if (tbl->events[idx].sequence == seq) {
            out[n++] = tbl->events[idx];
        }
    }

    ngx_shmtx_unlock(&xrootd_dashboard_events_mutex);
    return n;
}
