#include "dashboard.h"
#include <ngx_shmtx.h>
#include <string.h>

/*
 * dashboard/transfer_table.c — live transfer slot operations and SHM init.
 *
 * WHAT: Owns the static ngx_shmtx_t that guards slot allocation, implements
 *       the SHM zone init callback (called by nginx when the zone is first
 *       mapped or re-attached on reload), and provides the four public API
 *       functions that stream workers call around file open/IO/close.
 *
 * CONCURRENCY MODEL:
 *   xrootd_transfer_slot_alloc_ex()           — acquires mutex (brief, O(512) scan)
 *   xrootd_transfer_slot_update_bytes()       — lock-free atomics only
 *   xrootd_transfer_slot_free()               — lock-free atomic CAS
 *   xrootd_transfer_slot_free_all_for_session() — acquires mutex (disconnect)
 *   JSON exporter (api.c)                     — lock-free scan; tolerates tears
 *
 * STALE SLOT GC:
 *   The JSON exporter calls slot_free() on any slot whose last_ms is more than
 *   60 seconds old.  This catches slots that somehow escaped the close/disconnect
 *   cleanup path (e.g., due to a future bug or worker crash).
 */

static ngx_shmtx_t xrootd_dashboard_mutex;

/* ---- SHM init callback ---- */

ngx_int_t
ngx_xrootd_dashboard_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_transfer_table_t *tbl;

    if (data) {
        /*
         * Reload path: nginx handed us the same physical pages as before.
         * Re-create the mutex so the new generation of workers can lock it;
         * preserve every slot — transfers in flight survive the reload.
         */
        shm_zone->data = data;

        tbl = (xrootd_transfer_table_t *) shm_zone->shm.addr;
        if (ngx_shmtx_create(&xrootd_dashboard_mutex, &tbl->lock, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    /* First startup: zero the region and initialise the mutex. */
    tbl = (xrootd_transfer_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&xrootd_dashboard_mutex, &tbl->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

/* ---- Slot allocation ---- */

static void
dashboard_copy_field(char *dst, size_t dstsz, const char *src)
{
    if (dst == NULL || dstsz == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    ngx_cpystrn((u_char *) dst, (u_char *) (uintptr_t) src, dstsz);
}

int
xrootd_transfer_slot_alloc_ex(xrootd_transfer_table_t *t,
    const u_char sessid[16], const char *client_ip,
    const char *identity, const char *vo, const char *path, const char *op,
    uint8_t direction, uint8_t proto, int64_t expected_bytes, int64_t now_ms)
{
    int                     free_idx = -1;
    xrootd_transfer_slot_t *slot;
    int                     i;

    ngx_shmtx_lock(&xrootd_dashboard_mutex);

    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        if (t->slots[i].in_use == 0) {
            free_idx = i;
            break;
        }
    }

    if (free_idx < 0) {
        ngx_shmtx_unlock(&xrootd_dashboard_mutex);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD, proto, 0,
                                   "active transfer table full", path);
        return -1;   /* table full — transfer proceeds untracked */
    }

    slot = &t->slots[free_idx];
    ngx_memzero(slot, sizeof(*slot));

    if (sessid != NULL) {
        ngx_memcpy(slot->sessid, sessid, 16);
    }

    dashboard_copy_field(slot->client_ip, sizeof(slot->client_ip), client_ip);
    dashboard_copy_field(slot->identity, sizeof(slot->identity),
                         identity ? identity : "anonymous");
    dashboard_copy_field(slot->vo, sizeof(slot->vo), vo);
    dashboard_copy_field(slot->path, sizeof(slot->path), path);
    dashboard_copy_field(slot->op, sizeof(slot->op), op ? op : "transfer");

    slot->worker_pid     = ngx_pid;
    slot->direction      = direction;
    slot->proto          = proto;
    slot->state          = XROOTD_XFER_STATE_ACTIVE;
    slot->expected_bytes = expected_bytes;
    slot->start_ms       = now_ms;
    slot->last_ms        = (ngx_atomic_t) now_ms;
    slot->state_since_ms = (ngx_atomic_t) now_ms;
    slot->serial         = ++t->next_serial;
    slot->in_use         = 1;   /* publish last — readers see a complete slot */

    ngx_shmtx_unlock(&xrootd_dashboard_mutex);
    return free_idx;
}

int
xrootd_transfer_slot_alloc(xrootd_transfer_table_t *t,
    const u_char sessid[16], const char *client_ip,
    const char *identity, const char *path,
    uint8_t direction, uint8_t proto, int64_t now_ms)
{
    return xrootd_transfer_slot_alloc_ex(t, sessid, client_ip, identity, "",
                                         path, "open", direction, proto, -1,
                                         now_ms);
}

/* ---- Byte / timestamp update (lock-free) ---- */

void
xrootd_transfer_slot_update_bytes(xrootd_transfer_table_t *t,
    int slot_idx, ngx_atomic_int_t nbytes, int64_t now_ms)
{
    xrootd_transfer_slot_t *slot;

    if (slot_idx < 0 || slot_idx >= XROOTD_DASHBOARD_MAX_TRANSFERS) {
        return;
    }

    slot = &t->slots[slot_idx];

    if (slot->in_use == 0) {
        return;   /* slot was freed between the check and this update */
    }

    if (nbytes > 0) {
        ngx_atomic_fetch_add(&slot->bytes, nbytes);
    }
    slot->state = XROOTD_XFER_STATE_ACTIVE;
    slot->last_ms = (ngx_atomic_t) now_ms;  /* 64-bit aligned write; atomic on x86_64 */
}

void
xrootd_transfer_slot_update(xrootd_transfer_table_t *t,
    int slot_idx, ngx_atomic_int_t nbytes, int64_t now_ms)
{
    xrootd_transfer_slot_update_bytes(t, slot_idx, nbytes, now_ms);
}

void
xrootd_transfer_slot_set_state(xrootd_transfer_table_t *t,
    int slot_idx, uint8_t state, int64_t now_ms)
{
    xrootd_transfer_slot_t *slot;

    if (slot_idx < 0 || slot_idx >= XROOTD_DASHBOARD_MAX_TRANSFERS) {
        return;
    }

    slot = &t->slots[slot_idx];
    if (slot->in_use == 0) {
        return;
    }

    slot->state = state;
    slot->state_since_ms = (ngx_atomic_t) now_ms;
    slot->last_ms = (ngx_atomic_t) now_ms;
}

void
xrootd_transfer_slot_set_error(xrootd_transfer_table_t *t,
    int slot_idx, const char *reason, int64_t now_ms)
{
    xrootd_transfer_slot_t *slot;

    if (slot_idx < 0 || slot_idx >= XROOTD_DASHBOARD_MAX_TRANSFERS) {
        return;
    }

    slot = &t->slots[slot_idx];
    if (slot->in_use == 0) {
        return;
    }

    dashboard_copy_field(slot->last_error, sizeof(slot->last_error),
                         reason ? reason : "error");
    slot->state = XROOTD_XFER_STATE_ERROR;
    slot->state_since_ms = (ngx_atomic_t) now_ms;
    slot->last_ms = (ngx_atomic_t) now_ms;
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, slot->proto, 0,
                               slot->last_error, slot->path);
}

void
xrootd_transfer_slot_set_tpc_remote(xrootd_transfer_table_t *t,
    int slot_idx, const char *remote_host, const char *path_hint,
    int remote_status, int curl_exit)
{
    xrootd_transfer_slot_t *slot;

    if (slot_idx < 0 || slot_idx >= XROOTD_DASHBOARD_MAX_TRANSFERS) {
        return;
    }

    slot = &t->slots[slot_idx];
    if (slot->in_use == 0) {
        return;
    }

    dashboard_copy_field(slot->tpc_remote_host,
                         sizeof(slot->tpc_remote_host), remote_host);
    dashboard_copy_field(slot->tpc_remote_path_hint,
                         sizeof(slot->tpc_remote_path_hint), path_hint);
    slot->tpc_remote_status = remote_status;
    slot->tpc_curl_exit = curl_exit;
}

void
xrootd_transfer_slot_count_op(xrootd_transfer_table_t *t, int slot_idx,
    const char *op)
{
    xrootd_transfer_slot_t *slot;

    if (slot_idx < 0 || slot_idx >= XROOTD_DASHBOARD_MAX_TRANSFERS) {
        return;
    }

    slot = &t->slots[slot_idx];
    if (slot->in_use == 0 || op == NULL) {
        return;
    }

    if (ngx_strcasecmp((u_char *) op, (u_char *) "read") == 0
        || ngx_strcasecmp((u_char *) op, (u_char *) "GET") == 0
        || ngx_strcasecmp((u_char *) op, (u_char *) "GetObject") == 0)
    {
        ngx_atomic_fetch_add(&slot->read_ops, 1);
    } else if (ngx_strcasecmp((u_char *) op, (u_char *) "write") == 0
               || ngx_strcasecmp((u_char *) op, (u_char *) "PUT") == 0
               || ngx_strcasecmp((u_char *) op, (u_char *) "PutObject") == 0
               || ngx_strcasecmp((u_char *) op, (u_char *) "UploadPart") == 0)
    {
        ngx_atomic_fetch_add(&slot->write_ops, 1);
    } else if (ngx_strcasecmp((u_char *) op, (u_char *) "sync") == 0
               || ngx_strcasecmp((u_char *) op, (u_char *) "commit") == 0)
    {
        ngx_atomic_fetch_add(&slot->sync_ops, 1);
    } else if (ngx_strcasecmp((u_char *) op, (u_char *) "close") == 0) {
        ngx_atomic_fetch_add(&slot->close_ops, 1);
    }
}

/* ---- Single-slot free (lock-free CAS) ---- */

void
xrootd_transfer_slot_free(xrootd_transfer_table_t *t, int slot_idx)
{
    if (slot_idx < 0 || slot_idx >= XROOTD_DASHBOARD_MAX_TRANSFERS) {
        return;
    }

    t->slots[slot_idx].state = XROOTD_XFER_STATE_CLOSING;
    t->slots[slot_idx].state_since_ms = (ngx_atomic_t) ngx_current_msec;

    /* CAS 1→0; idempotent if already freed by another path. */
    (void) ngx_atomic_cmp_set(&t->slots[slot_idx].in_use, 1, 0);
}

/* ---- Session-wide free (used at disconnect) ---- */

void
xrootd_transfer_slot_free_all_for_session(xrootd_transfer_table_t *t,
    const u_char sessid[16])
{
    int i;

    ngx_shmtx_lock(&xrootd_dashboard_mutex);

    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        if (t->slots[i].in_use &&
            ngx_memcmp(t->slots[i].sessid, sessid, 16) == 0)
        {
            ngx_memzero(&t->slots[i], sizeof(t->slots[i]));
        }
    }

    ngx_shmtx_unlock(&xrootd_dashboard_mutex);
}
