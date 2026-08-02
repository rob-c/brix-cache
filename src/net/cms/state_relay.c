/*
 * state_relay.c — Phase-61 W7 multi-tier kYR_state recursion. See state_relay.h.
 *
 * The table is per-worker file-local state, matching the server-leg node list:
 * a relay is always same-worker (the downward child connections and the upward
 * manager connection both live in the worker that parked the entry), so no SHM
 * or locking is needed.  Capacity is small — an entry lives only for the
 * fan-out round-trip (TTL 5s) and silence is the correct degraded answer when
 * the table is momentarily full.
 */

#include "state_relay.h"
#include "server.h"                 /* shared downward streamid generator */
#include "../manager/loc_cache.h"   /* BRIX_LOC_CACHE_PATH_MAX */

#define RELAY_CAP  64

typedef struct {
    uint32_t              down_sid;   /* streamid used on the downward fan-out */
    uint32_t              up_sid;     /* parent streamid to echo on kYR_have */
    ngx_brix_cms_ctx_t *up;         /* upward manager connection */
    ngx_msec_t            expires;    /* ngx_current_msec deadline */
    unsigned              in_use:1;
    char                  path[BRIX_LOC_CACHE_PATH_MAX];  /* probed path */
} relay_entry_t;

static relay_entry_t  relay_table[RELAY_CAP];

/* Slot liveness: in_use, unexpired, and the upward connection still exists. */
static int
relay_live(const relay_entry_t *e)
{
    return e->in_use
           && (ngx_msec_int_t) (e->expires - ngx_current_msec) > 0
           && e->up != NULL && e->up->connection != NULL;
}

uint32_t
brix_cms_state_relay_add(ngx_brix_cms_ctx_t *up, uint32_t up_sid,
    const char *path)
{
    ngx_uint_t  i;
    size_t      plen = ngx_strlen(path);

    if (plen == 0 || plen >= BRIX_LOC_CACHE_PATH_MAX) {
        return 0;
    }

    for (i = 0; i < RELAY_CAP; i++) {
        if (relay_live(&relay_table[i])) {
            continue;
        }
        relay_table[i].down_sid = brix_cms_srv_next_streamid();
        relay_table[i].up_sid   = up_sid;
        relay_table[i].up       = up;
        relay_table[i].expires  = ngx_current_msec
                                  + BRIX_CMS_STATE_RELAY_TTL_MS;
        relay_table[i].in_use   = 1;
        ngx_memcpy(relay_table[i].path, path, plen + 1);
        return relay_table[i].down_sid;
    }

    return 0;
}

int
brix_cms_state_relay_take(uint32_t down_sid, const char *path,
    ngx_brix_cms_ctx_t **up, uint32_t *up_sid)
{
    ngx_uint_t  i;

    for (i = 0; i < RELAY_CAP; i++) {
        if (!relay_table[i].in_use || relay_table[i].down_sid != down_sid) {
            continue;
        }
        if (!relay_live(&relay_table[i])) {
            relay_table[i].in_use = 0;
            return 0;
        }
        if (ngx_strcmp(relay_table[i].path, path) != 0) {
            /* Forged path on a real streamid: refuse, but keep the entry so
             * the honest child's answer can still land. */
            return 0;
        }
        *up     = relay_table[i].up;
        *up_sid = relay_table[i].up_sid;
        relay_table[i].in_use = 0;
        return 1;
    }

    return 0;
}

void
brix_cms_state_relay_drop_ctx(ngx_brix_cms_ctx_t *up)
{
    ngx_uint_t  i;

    for (i = 0; i < RELAY_CAP; i++) {
        if (relay_table[i].in_use && relay_table[i].up == up) {
            relay_table[i].in_use = 0;
        }
    }
}
