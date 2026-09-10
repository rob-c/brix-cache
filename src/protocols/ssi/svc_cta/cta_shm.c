/*
 * cta_shm.c — the CTA request queue's shared-memory home. See cta_shm.h.
 *
 * Follows the same shape as src/fs/xfer/stage_waiter.c: the table is
 * slab-allocated via brix_shm_table_alloc() so it never clobbers the slab-pool
 * header that nginx's SIGCHLD handler walks on every child death, and the
 * mutex is bound to the pool's own lock word so a worker dying mid-operation
 * is recovered rather than stranding the queue for everyone.
 */

#include "cta_shm.h"

#include "core/compat/shm_slots.h"

#include <ngx_shmtx.h>
#include <string.h>

extern ngx_module_t  ngx_stream_brix_module;


static ngx_shm_zone_t  *cta_zone;
static ngx_shmtx_t      cta_mtx;
static char             cta_journal_path[1024];


brix_cta_queue_t *
brix_cta_shm_queue(void)
{
    void *table;

    if (cta_zone == NULL) {
        return NULL;
    }
    /* Single read of zone->data: the checked value IS the returned value. */
    table = cta_zone->data;
    if (table == NULL || table == (void *) 1) {
        return NULL;
    }
    return (brix_cta_queue_t *) table;
}


/*
 * Zone init. Runs in the MASTER, before fork.
 *
 * That timing is the whole design: the journal fd opened here is inherited by
 * every worker, so all of them append to one open file description with one
 * shared O_APPEND offset and one journal serves the entire set. Replay likewise
 * happens once, here, rather than once per worker — which is what used to make
 * every worker start from the same next_id and then hand out colliding ids.
 */
static ngx_int_t
cta_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_cta_queue_t *q;
    ngx_flag_t        fresh;

    q = brix_shm_table_alloc(shm_zone, data, sizeof(brix_cta_queue_t),
                               &cta_mtx, &fresh);
    if (q == NULL) {
        return NGX_ERROR;
    }
    if (!fresh) {
        return NGX_OK;   /* reload re-attached: live state must be preserved */
    }
    cta_queue_init(q);
    if (cta_journal_path[0] != '\0'
        && cta_queue_open_journal(q, cta_journal_path) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, ngx_errno,
                      "brix: CTA journal \"%s\" unusable; the queue will not "
                      "survive a restart", cta_journal_path);
        /* Not fatal: an unwritable journal degrades restart recovery, it does
         * not make the service wrong. Failing here would take a working
         * deployment down over a permissions change. */
    }
    return NGX_OK;
}


ngx_int_t
brix_cta_shm_configure(ngx_conf_t *cf, ngx_str_t *journal)
{
    ngx_str_t  zone_name = ngx_string("brix_cta_queue");
    size_t     len;

    if (journal != NULL && journal->len > 0) {
        len = journal->len;
        if (len >= sizeof(cta_journal_path)) {
            len = sizeof(cta_journal_path) - 1;
        }
        ngx_memcpy(cta_journal_path, journal->data, len);
        cta_journal_path[len] = '\0';
    } else {
        cta_journal_path[0] = '\0';
    }

    cta_zone = ngx_shared_memory_add(cf, &zone_name,
                                     brix_shm_zone_size(sizeof(brix_cta_queue_t)),
                                     &ngx_stream_brix_module);
    if (cta_zone == NULL) {
        return NGX_ERROR;
    }
    brix_shm_zone_warn_on_resize(cf, cta_zone, "brix_ssi_service cta");
    cta_zone->init = cta_shm_init_zone;
    cta_zone->data = (void *) 1;
    return NGX_OK;
}


/* ---- locked wrappers ---------------------------------------------------
 *
 * Each holds cta_mtx for exactly one queue operation. Nothing here calls an
 * executor: a lock held across an archive/retrieve would serialise every
 * worker behind one tape operation.
 */

cta_req_t *
brix_cta_shm_submit(const cta_request_t *r, const char *owner)
{
    brix_cta_queue_t *q = brix_cta_shm_queue();
    cta_req_t        *e;

    if (q == NULL) {
        return NULL;
    }
    ngx_shmtx_lock(&cta_mtx);
    e = cta_queue_submit(q, r, owner);
    ngx_shmtx_unlock(&cta_mtx);
    return e;
}


int
brix_cta_shm_transition(brix_cta_queue_t *q, cta_req_t *e, cta_state_t to)
{
    int  rc;

    if (q == NULL) {
        return -1;
    }
    ngx_shmtx_lock(&cta_mtx);
    rc = cta_queue_transition(q, e, to);
    ngx_shmtx_unlock(&cta_mtx);
    return rc;
}


int
brix_cta_shm_cancel(uint64_t id, const char *requester, int is_admin)
{
    brix_cta_queue_t *q = brix_cta_shm_queue();
    int               rc;

    if (q == NULL) {
        return CTA_QUEUE_ENOENT;
    }
    ngx_shmtx_lock(&cta_mtx);
    rc = cta_queue_cancel(q, id, requester, is_admin);
    ngx_shmtx_unlock(&cta_mtx);
    return rc;
}


int
brix_cta_shm_active_count(void)
{
    brix_cta_queue_t *q = brix_cta_shm_queue();
    int               n;

    if (q == NULL) {
        return 0;
    }
    ngx_shmtx_lock(&cta_mtx);
    n = cta_queue_active_count(q);
    ngx_shmtx_unlock(&cta_mtx);
    return n;
}
