/*
 * waiter.c — async stage-completion waiter table (Phase 35 / Phase 3).
 *
 * See waiter.h for the model. The table is slab-allocated (xrootd_shm_table_alloc)
 * so it does not clobber the slab-pool header — same contract as every other
 * nginx-xrootd SHM zone (see src/compat/shm_slots.c). Delivery rebuilds the real
 * open response by replaying xrootd_open_resolved_file() on the parked connection
 * with ctx->frm_async_active set, so the open-OK body (fhandle) is produced by
 * the normal machinery and emitted via kXR_attn(asynresp) on the saved streamid.
 */

#include "frm_internal.h"
#include "waiter.h"

#include "../compat/shm_slots.h"
#include "../read/open.h"
#include "../response/async.h"
#include "../connection/event_sched.h"

#include <ngx_shmtx.h>
#include <string.h>

extern ngx_module_t  ngx_stream_xrootd_module;

#define FRM_WAITER_MAX_SLOTS  4096


typedef struct {
    char               reqid[FRM_REQID_LEN];
    uint16_t           options;             /* original kXR_open options       */
    u_char             client_streamid[2];  /* the parked request's streamid   */
    int                conn_fd;
    ngx_atomic_uint_t  conn_number;         /* guards against fd recycle       */
    ngx_pid_t          worker_pid;          /* only this worker delivers it    */
    ngx_msec_t         expires;
    int                code;                /* completion code (set on ready)  */
    uint8_t            ready;               /* 1 = recall done, awaiting deliver*/
    uint8_t            in_use;
} frm_waiter_t;

typedef struct {
    ngx_shmtx_sh_t  lock;                   /* MUST be first (slab-safe contract)*/
    ngx_uint_t      capacity;
    frm_waiter_t    slots[1];               /* flexible: [capacity]            */
} frm_waiter_table_t;


static ngx_shm_zone_t  *frm_waiter_zone;
static ngx_shmtx_t      frm_waiter_mtx;
static ngx_uint_t       frm_waiter_slots_req;


static frm_waiter_table_t *
frm_waiter_table(void)
{
    if (frm_waiter_zone == NULL
        || frm_waiter_zone->data == NULL
        || frm_waiter_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (frm_waiter_table_t *) frm_waiter_zone->data;
}

static ngx_int_t
frm_waiter_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    frm_waiter_table_t *tbl;
    ngx_flag_t          fresh;
    ngx_uint_t          cap = frm_waiter_slots_req;

    if (cap == 0) { cap = 256; }

    tbl = xrootd_shm_table_alloc(shm_zone, data,
                                 sizeof(frm_waiter_table_t)
                                     + (size_t) (cap - 1) * sizeof(frm_waiter_t),
                                 &frm_waiter_mtx, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }
    if (fresh) {
        tbl->capacity = cap;
        /* helper already zeroed the table */
    }
    return NGX_OK;
}

ngx_int_t
frm_waiter_configure(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("xrootd_frm_waiters");
    size_t     zone_size;

    if (slots == 0) { slots = 256; }
    if (slots > FRM_WAITER_MAX_SLOTS) { slots = FRM_WAITER_MAX_SLOTS; }
    frm_waiter_slots_req = slots;

    zone_size = xrootd_shm_zone_size(sizeof(frm_waiter_table_t)
                                     + (size_t) (slots - 1) * sizeof(frm_waiter_t));
    frm_waiter_zone = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                            &ngx_stream_xrootd_module);
    if (frm_waiter_zone == NULL) {
        return NGX_ERROR;
    }
    frm_waiter_zone->init = frm_waiter_init_zone;
    frm_waiter_zone->data = (void *) 1;
    return NGX_OK;
}


ngx_int_t
frm_waiter_add(const char *reqid, uint16_t options,
               const u_char client_streamid[2], int conn_fd,
               ngx_atomic_uint_t conn_number, ngx_pid_t worker_pid,
               ngx_msec_t timeout_ms)
{
    frm_waiter_table_t *tbl = frm_waiter_table();
    ngx_uint_t          i, free_slot;

    if (tbl == NULL || reqid == NULL) {
        return NGX_ERROR;
    }
    ngx_shmtx_lock(&frm_waiter_mtx);

    free_slot = tbl->capacity;
    for (i = 0; i < tbl->capacity; i++) {
        frm_waiter_t *s = &tbl->slots[i];
        if (!s->in_use) {
            xrootd_shm_remember_free_slot(&free_slot, tbl->capacity, i);
            continue;
        }
        if (xrootd_shm_slot_expired(ngx_current_msec, s->expires)) {
            s->in_use = 0;
            xrootd_shm_remember_free_slot(&free_slot, tbl->capacity, i);
        }
    }
    if (free_slot == tbl->capacity) {
        ngx_shmtx_unlock(&frm_waiter_mtx);
        return NGX_AGAIN;                    /* full → caller falls back to wait */
    }

    {
        frm_waiter_t *s = &tbl->slots[free_slot];
        ngx_memzero(s, sizeof(*s));
        ngx_cpystrn((u_char *) s->reqid, (u_char *) reqid, sizeof(s->reqid));
        s->options = options;
        s->client_streamid[0] = client_streamid[0];
        s->client_streamid[1] = client_streamid[1];
        s->conn_fd = conn_fd;
        s->conn_number = conn_number;
        s->worker_pid = worker_pid;
        s->expires = ngx_current_msec + timeout_ms;
        s->ready = 0;
        s->in_use = 1;
    }
    ngx_shmtx_unlock(&frm_waiter_mtx);
    return NGX_OK;
}


/* fd → this worker's connection (clone of cms_find_client_connection). */
static ngx_connection_t *
frm_waiter_find_conn(int fd)
{
    ngx_uint_t        i;
    ngx_connection_t *c;

    if (fd < 0) {
        return NULL;
    }
    if (ngx_cycle->files != NULL && (ngx_uint_t) fd < ngx_cycle->files_n) {
        c = ngx_cycle->files[fd];
        return (c != NULL && c->fd == fd) ? c : NULL;
    }
    for (i = 0; i < ngx_cycle->connection_n; i++) {
        c = &ngx_cycle->connections[i];
        if (c->fd == fd) {
            return c;
        }
    }
    return NULL;
}

/*
 * Deliver one completed recall to a parked connection (a local copy of the slot
 * row; the slot is already freed). Validates liveness, then either replays the
 * open (code 0) or pushes an error — both wrapped in kXR_attn(asynresp) on the
 * saved streamid — and resumes the connection.
 */
static void
frm_waiter_deliver_one(const frm_waiter_t *w)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    frm_queue_t                   *q = frm_singleton_queue();
    frm_record_t                   rec;

    c = frm_waiter_find_conn(w->conn_fd);
    if (c == NULL || c->number != w->conn_number || c->destroyed) {
        return;                              /* fd recycled / gone */
    }
    s = c->data;
    if (s == NULL) {
        return;
    }
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    if (ctx == NULL || ctx->destroyed || ctx->state != XRD_ST_WAITING_FRM) {
        return;                              /* not actually parked here */
    }
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    ctx->state = XRD_ST_REQ_HEADER;          /* un-suspend before we re-drive */

    if (w->code == 0 && q != NULL
        && frm_request_get(q, w->reqid, &rec, c->log) == NGX_OK)
    {
        /* Replay the open: the file is now resident, so the normal machinery
         * allocates the fhandle and builds the open-OK body; the frm_async flag
         * makes the emit go out as kXR_attn(asynresp) on the saved streamid. */
        ctx->frm_async_active = 1;
        ctx->frm_async_streamid[0] = w->client_streamid[0];
        ctx->frm_async_streamid[1] = w->client_streamid[1];
        (void) xrootd_open_resolved_file(ctx, c, conf, rec.lfn, w->options, 0, 0, 0);
        ctx->frm_async_active = 0;
    } else {
        /* Recall failed (or the record vanished): deliver a hard error so the
         * client stops waiting. Body = errnum(4, big-endian) + message. */
        u_char       body[64];
        const char  *msg = "file is offline (recall failed)";
        size_t       mlen = ngx_strlen(msg);
        uint32_t     errnum = htonl((uint32_t) kXR_FSError);

        if (mlen > sizeof(body) - 5) { mlen = sizeof(body) - 5; }
        ngx_memcpy(body, &errnum, 4);
        ngx_memcpy(body + 4, msg, mlen);
        body[4 + mlen] = '\0';
        (void) xrootd_send_attn_asynresp(ctx, c, w->client_streamid,
                                         (uint16_t) kXR_error,
                                         body, (uint32_t) (4 + mlen + 1));
    }

    XROOTD_FRM_METRIC_INC(asynresp_total);
    xrootd_schedule_read_resume(c);
}

void
frm_waiter_deliver(const char *reqid, int code)
{
    frm_waiter_table_t *tbl = frm_waiter_table();
    ngx_uint_t          i;

    if (tbl == NULL || reqid == NULL) {
        return;
    }
    /* Mark every matching waiter ready; this worker's are then drained below,
     * other workers' rows are drained by their own poll. */
    ngx_shmtx_lock(&frm_waiter_mtx);
    for (i = 0; i < tbl->capacity; i++) {
        frm_waiter_t *s = &tbl->slots[i];
        if (s->in_use && ngx_strcmp(s->reqid, reqid) == 0) {
            s->ready = 1;
            s->code = code;
        }
    }
    ngx_shmtx_unlock(&frm_waiter_mtx);

    frm_waiter_poll_local();
}

void
frm_waiter_poll_local(void)
{
    frm_waiter_table_t *tbl = frm_waiter_table();
    frm_waiter_t        batch[16];
    ngx_uint_t          i, n;

    if (tbl == NULL) {
        return;
    }
    /*
     * Claim this worker's ready rows (and reap any expired) under the lock, then
     * deliver them OUTSIDE the lock (delivery queues wire bytes / touches the
     * event loop, which must never run under an SHM mutex). Bounded per tick;
     * remaining rows are picked up on the next scheduler tick.
     */
    for ( ;; ) {
        n = 0;
        ngx_shmtx_lock(&frm_waiter_mtx);
        for (i = 0; i < tbl->capacity && n < 16; i++) {
            frm_waiter_t *s = &tbl->slots[i];
            if (!s->in_use) {
                continue;
            }
            if (s->ready && s->worker_pid == ngx_pid) {
                batch[n++] = *s;             /* copy out */
                s->in_use = 0;               /* claim it */
                continue;
            }
            if (xrootd_shm_slot_expired(ngx_current_msec, s->expires)) {
                s->in_use = 0;               /* reap stale */
            }
        }
        ngx_shmtx_unlock(&frm_waiter_mtx);

        for (i = 0; i < n; i++) {
            frm_waiter_deliver_one(&batch[i]);
        }
        if (n < 16) {
            break;                           /* drained */
        }
    }
}

void
frm_waiter_drop_conn(int conn_fd, ngx_atomic_uint_t conn_number)
{
    frm_waiter_table_t *tbl = frm_waiter_table();
    ngx_uint_t          i;

    if (tbl == NULL) {
        return;
    }
    ngx_shmtx_lock(&frm_waiter_mtx);
    for (i = 0; i < tbl->capacity; i++) {
        frm_waiter_t *s = &tbl->slots[i];
        if (s->in_use && s->conn_fd == conn_fd
            && s->conn_number == conn_number && s->worker_pid == ngx_pid)
        {
            s->in_use = 0;
        }
    }
    ngx_shmtx_unlock(&frm_waiter_mtx);
}
