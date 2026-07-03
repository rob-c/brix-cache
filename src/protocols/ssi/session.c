/*
 * session.c — SSI session + RRTable. See session.h.
 */

#include "session.h"
#include <string.h>

#ifdef SSI_UT_STANDALONE
#include <stdlib.h>
#define SSI_ALLOC(pool, n) calloc(1, (n))
#else
#define SSI_ALLOC(pool, n) ngx_pcalloc((pool), (n))
#endif

/*
 * Per-worker monotonic session sequence. SSI sessions are bound to one TCP
 * connection on one worker, so a per-worker counter is sufficient as the
 * delivery-guard key: a stale async completion that names a recycled conn_id is
 * rejected because the generation it captured no longer matches the live slot.
 */
static uint64_t ssi_gen_seq;

brix_ssi_session_t *
brix_ssi_session_create(ngx_pool_t *pool, const char *service,
                          size_t service_len, const brix_ssi_provider_t *provider)
{
    brix_ssi_session_t *s;

    if (service_len >= sizeof(((brix_ssi_session_t *) 0)->service)) {
        return NULL;
    }
    s = SSI_ALLOC(pool, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    memcpy(s->service, service, service_len);
    s->service[service_len] = '\0';
    if (provider != NULL) {
        s->provider = *provider;
    }
    s->pool = pool;
    s->generation = ++ssi_gen_seq;
    return s;
}

brix_ssi_req_t *
brix_ssi_session_req(brix_ssi_session_t *s, uint32_t req_id, int create)
{
    int i, free_slot = -1;
    int cap = BRIX_SSI_MAX_INFLIGHT;

    if (s == NULL) {
        return NULL;
    }
    /* Honor a runtime concurrency cap (never above the fixed table size). */
    if (s->max_inflight > 0 && s->max_inflight < cap) {
        cap = s->max_inflight;
    }
    for (i = 0; i < cap; i++) {
        if (s->rr[i].in_use && s->rr[i].req_id == req_id) {
            return &s->rr[i];
        }
        if (!s->rr[i].in_use && free_slot < 0) {
            free_slot = i;
        }
    }
    if (!create || free_slot < 0) {
        return NULL;
    }
    memset(&s->rr[free_slot], 0, sizeof(s->rr[free_slot]));
    s->rr[free_slot].in_use       = 1;
    s->rr[free_slot].req_id       = req_id;
    s->rr[free_slot].pool         = s->pool;
    s->rr[free_slot].resp.pool    = s->pool;   /* growable response buffer */
    s->rr[free_slot].response_max = s->response_max;
    return &s->rr[free_slot];
}

void
brix_ssi_session_drop(brix_ssi_session_t *s, uint32_t req_id)
{
    int i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < BRIX_SSI_MAX_INFLIGHT; i++) {
        if (s->rr[i].in_use && s->rr[i].req_id == req_id) {
            s->rr[i].in_use = 0;
            return;
        }
    }
}
