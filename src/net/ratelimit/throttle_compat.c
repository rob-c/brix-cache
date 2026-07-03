/*
 * ratelimit/throttle_compat.c — XrdThrottle contract layer (see header).
 *
 * WHAT: the IO-load concurrency metric, per-user open-file counters, and the
 *       userconfig INI matcher that together reproduce the upstream `throttle.*`
 *       behavior on top of the existing SHM leaky-bucket engine. WHY: gives the
 *       XrdThrottle config/admin contract natively. HOW: per-user SHM nodes
 *       reuse brix_rl_lookup/create_locked under the spin+yield zone mutex
 *       (INVARIANT 10); the userconfig parser reuses the shared INI reader.
 */

#include "throttle_compat.h"
#include "auth/token/ini.h"

#include <string.h>
#include <stdlib.h>

/* userconfig INI */
static int
uc_kv(void *u, const char *section, const char *key, const char *val)
{
    brix_throttle_uc_t *uc = u;
    (void) section;                     /* each [name] section is one rule */

    if (strcasecmp(key, "name") == 0) {
        if (uc->count < BRIX_THROTTLE_MAX_UC_RULES) {
            snprintf(uc->rules[uc->count].pat,
                     sizeof(uc->rules[uc->count].pat), "%s", val);
        }
    } else if (strcasecmp(key, "maxconn") == 0) {
        if (uc->count < BRIX_THROTTLE_MAX_UC_RULES) {
            uc->rules[uc->count].maxconn = (ngx_uint_t) atoi(val);
            if (strcmp(uc->rules[uc->count].pat, "*") == 0) {
                uc->global = uc->rules[uc->count].maxconn;
            }
            uc->count++;
        }
    }
    return 0;
}

int
brix_throttle_userconfig_load(const char *path, brix_throttle_uc_t *uc,
    char *errbuf, size_t errlen)
{
    memset(uc, 0, sizeof(*uc));
    return brix_ini_parse_file(path, uc_kv, uc, errbuf, errlen);
}

ngx_uint_t
brix_throttle_userconfig_match(const brix_throttle_uc_t *uc,
    const char *user)
{
    int    exact = -1;
    size_t best_len = 0;
    ngx_uint_t best = 0;
    int    i;

    for (i = 0; i < uc->count; i++) {
        const char *pat = uc->rules[i].pat;
        size_t      plen = strlen(pat);

        if (strcmp(pat, user) == 0) {
            exact = i;
            break;
        }
        if (plen > 1 && pat[plen - 1] == '*') {
            if (strncmp(pat, user, plen - 1) == 0 && (plen - 1) >= best_len) {
                best_len = plen - 1;
                best = uc->rules[i].maxconn;
            }
        }
    }
    if (exact >= 0) {
        return uc->rules[exact].maxconn;
    }
    if (best_len > 0) {
        return best;
    }
    return uc->global;
}

/* SHM-backed IO-load + open-file counters */
static brix_rl_node_t *
throttle_node_locked(brix_rl_zone_t *zone, const char *user)
{
    uint32_t          h = brix_rl_hash(user, strlen(user));
    brix_rl_node_t *n = brix_rl_lookup_locked(zone, h, user, strlen(user));

    if (n == NULL) {
        n = brix_rl_create_locked(zone, h, user, strlen(user));
    }
    return n;
}

void
brix_throttle_charge_io(brix_rl_zone_t *zone, ngx_msec_t interval_ms,
    const char *user, uint64_t service_us)
{
    brix_rl_node_t *n;

    if (zone == NULL || zone->sh == NULL) {
        return;
    }
    ngx_shmtx_lock(&zone->shpool->mutex);
    n = throttle_node_locked(zone, user);
    if (n != NULL) {
        ngx_msec_t now = ngx_current_msec;

        if ((ngx_msec_int_t) (now - n->io_window) >= (ngx_msec_int_t) interval_ms) {
            n->io_time_us = 0;
            n->io_window = now;
        }
        n->io_time_us += service_us;
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);
}

int
brix_throttle_ioload_over(brix_rl_zone_t *zone, ngx_msec_t interval_ms,
    const char *user, double concurrency)
{
    brix_rl_node_t *n;
    int               over = 0;

    if (zone == NULL || zone->sh == NULL || concurrency <= 0.0
        || interval_ms == 0)
    {
        return 0;
    }
    ngx_shmtx_lock(&zone->shpool->mutex);
    n = brix_rl_lookup_locked(zone, brix_rl_hash(user, strlen(user)),
                                user, strlen(user));
    if (n != NULL) {
        double load = (double) n->io_time_us
                      / ((double) interval_ms * 1000.0);
        over = (load >= concurrency);
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);
    return over;
}

int
brix_throttle_open_inc(brix_rl_zone_t *zone, const char *user,
    ngx_uint_t cap)
{
    brix_rl_node_t *n;
    int               ok = 1;

    if (zone == NULL || zone->sh == NULL || cap == 0) {
        return 1;                       /* unlimited */
    }
    ngx_shmtx_lock(&zone->shpool->mutex);
    n = throttle_node_locked(zone, user);
    if (n != NULL) {
        if (n->open_files < cap) {
            n->open_files++;
            ok = 1;
        } else {
            ok = 0;                     /* over the per-user cap */
        }
    }                                   /* n==NULL (slab OOM) ⇒ fail-open */
    ngx_shmtx_unlock(&zone->shpool->mutex);
    return ok;
}

void
brix_throttle_open_dec(brix_rl_zone_t *zone, const char *user)
{
    brix_rl_node_t *n;

    if (zone == NULL || zone->sh == NULL) {
        return;
    }
    ngx_shmtx_lock(&zone->shpool->mutex);
    n = brix_rl_lookup_locked(zone, brix_rl_hash(user, strlen(user)),
                                user, strlen(user));
    if (n != NULL && n->open_files > 0) {
        n->open_files--;
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);
}
