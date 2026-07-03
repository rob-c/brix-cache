/*
 * registry_health.c - extracted concern
 * Phase-38 split of registry.c; behavior-identical.
 */
#include "registry_internal.h"


/* Phase 22: active health-check registry helpers */
int
brix_srv_hc_claim(char *host_out, size_t host_size, uint16_t *port_out,
    ngx_msec_t interval_ms, ngx_msec_t *next_due_ms)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    ngx_msec_t          now;
    ngx_msec_t          soonest = interval_ms;   /* idle cap when none are due */

    if (next_due_ms != NULL) {
        *next_due_ms = interval_ms;
    }

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }
    now = ngx_current_msec;

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];

        if (!e->in_use || e->hc_in_progress) {
            continue;
        }
        if (e->hc_next_check > now) {
            /* Not due yet — remember how soon it becomes due so the caller can
             * sleep to that deadline instead of polling at a fixed floor. */
            ngx_msec_int_t d = (ngx_msec_int_t) (e->hc_next_check - now);
            if (d > 0 && (ngx_msec_t) d < soonest) {
                soonest = (ngx_msec_t) d;
            }
            continue;
        }

        e->hc_in_progress = 1;
        e->hc_next_check  = now + interval_ms;
        ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
        *port_out = e->port;

        ngx_shmtx_unlock(&brix_srv_mutex);
        return 1;                            /* claimed; caller spreads the rest */
    }

    ngx_shmtx_unlock(&brix_srv_mutex);

    if (next_due_ms != NULL) {
        *next_due_ms = soonest;              /* nothing due: sleep until soonest */
    }
    return 0;
}


void
brix_srv_hc_pass(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        /* Clear a blacklist only when it was health-check-induced (fail_count
         * was non-zero); never clear a CMS-disconnect blacklist. */
        if (e->hc_fail_count > 0) {
            e->blacklisted_until = 0;
        }
        e->hc_fail_count  = 0;
        e->hc_last_ok     = ngx_current_msec;
        e->hc_in_progress = 0;
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}


int
brix_srv_hc_fail(const char *host, uint16_t port, uint32_t threshold,
    ngx_msec_t blacklist_ms)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 newly_blacklisted = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        e->hc_in_progress = 0;
        e->hc_fail_count++;
        if (threshold > 0 && e->hc_fail_count >= threshold) {
            ngx_msec_t until = ngx_current_msec + blacklist_ms;
            if (e->blacklisted_until < until) {
                e->blacklisted_until = until;
                newly_blacklisted = 1;
            }
        }
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return newly_blacklisted;
}



/* WHAT
 * Builds a kXR_locate response body listing all non-blacklisted servers whose
 * exported path set covers the requested path.  Entries are space-separated
 * "S<r|w>host:port" strings, NUL-terminated.
 *
 * WHY
 * Returning the full set of matching servers lets the client pick based on
 * network locality, eliminating the need for chained redirects through the
 * hierarchy ("lateral redirect").  One kXR_ok response replaces what would
 * otherwise be a kXR_redirect chain through multiple manager tiers.
 *
 * HOW
 * Locks mutex → scans all in_use, non-blacklisted, path-matching slots →
 * appends "Sr<host>:<port>" (or "Sw" for writes) to buf with space separator.
 * Stops early if the next entry would overflow bufsz.  Returns bytes written
 * (not counting NUL); 0 if no servers match.
 */
int
brix_srv_locate_all(const char *path, int for_write,
    char *buf, size_t bufsz)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 written, entry_len, first;
    ngx_msec_t          now;
    char                entry[300];
    char                hostport[288];   /* host[256] + "[]" + ":65535" + NUL */

    tbl = srv_table();
    if (tbl == NULL || bufsz < 2) {
        return 0;
    }

    now     = ngx_current_msec;
    written = 0;
    first   = 1;

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];

        if (!e->in_use) {
            continue;
        }
        if (e->blacklisted_until != 0 && e->blacklisted_until > now) {
            continue;
        }
        if (!srv_path_matches(e->paths, path)) {
            continue;
        }

        /* Bracket IPv6 literals so "Sr[::1]:1094" (not the unparseable
         * "Sr::1:1094") — the host is stored canonically bare; bracket on emit. */
        brix_format_host_port(e->host, e->port, hostport, sizeof(hostport));
        entry_len = snprintf(entry, sizeof(entry), "%sS%c%s",
                             first ? "" : " ",
                             for_write ? 'w' : 'r',
                             hostport);
        if (entry_len <= 0 || written + entry_len + 1 >= (int) bufsz) {
            break;
        }

        ngx_memcpy(buf + written, entry, (size_t) entry_len);
        written += entry_len;
        first = 0;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);

    if (written > 0) {
        buf[written] = '\0';
    }

    return written;
}



/* WHAT
 * Removes a single path token from an existing server entry's paths field.
 * Used when a data server revokes access to a specific directory.

 * WHY
 * A server may serve multiple colon-delimited path tokens. Removing one token
 * keeps the entry alive for other paths without full unregister.

 * HOW
 * Locks mutex → scans slots for host+port match → in-place token walk: copies
 * non-matching tokens to dst buffer, drops matching ones. Safe overlap because
 * dst <= p always (copy forward direction). Null-terminates result.
 */
void
brix_srv_unregister_path(const char *host, uint16_t port, const char *path)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    const char         *p, *end;
    char               *dst;
    size_t              tok_len, path_len;
    int                 first;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    path_len = strlen(path);

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }

        /* In-place removal: walk tokens, copying those that don't match. */
        p     = e->paths;
        dst   = e->paths;
        first = 1;

        while (*p) {
            end = strchr(p, ':');
            if (end == NULL) {
                end = p + strlen(p);
            }
            tok_len = (size_t)(end - p);

            if (tok_len == path_len && ngx_strncmp(p, path, tok_len) == 0) {
                /* Drop this token. */
            } else {
                if (!first) {
                    *dst++ = ':';
                }
                /* dst <= p always — safe overlap direction for memcpy. */
                ngx_memcpy(dst, p, tok_len);
                dst  += tok_len;
                first  = 0;
            }

            p = *end ? end + 1 : end;
        }
        *dst = '\0';
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}



/* WHAT
 * Aggregates free-space and utilisation metrics across all registered servers.
 * Returns total free MB and average utilisation percentage via output pointers.

 * WHY
 * Used by the redirector to report cluster-wide capacity to CMS management or
 * for S3 gateway decisions about which region has sufficient space.

 * HOW
 * Locks mutex → sums free_mb and util_pct across all occupied slots, counts
 * entries. Unlocks → computes average = sum_util / count (0 if no servers).
 */
void
brix_srv_aggregate_space(uint32_t *total_free_mb, uint32_t *avg_util_pct)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    uint32_t            sum_free;
    uint64_t            sum_util;
    ngx_uint_t          count;

    *total_free_mb = 0;
    *avg_util_pct  = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    sum_free = 0;
    sum_util = 0;
    count    = 0;

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        sum_free += e->free_mb;
        sum_util += e->util_pct;
        count++;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);

    *total_free_mb = sum_free;
    *avg_util_pct  = count > 0 ? (uint32_t) (sum_util / count) : 0;
}


ngx_uint_t
brix_srv_snapshot(brix_srv_snapshot_entry_t *out, ngx_uint_t max_entries,
    ngx_msec_t now)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    ngx_uint_t          n;

    (void) now;

    if (out == NULL || max_entries == 0) {
        return 0;
    }

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    n = 0;
    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity && n < max_entries; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }

        ngx_cpystrn((u_char *) out[n].host, (u_char *) e->host,
                    sizeof(out[n].host));
        out[n].port = e->port;
        ngx_cpystrn((u_char *) out[n].paths, (u_char *) e->paths,
                    sizeof(out[n].paths));
        out[n].free_mb          = e->free_mb;
        out[n].util_pct         = e->util_pct;
        out[n].last_seen        = e->last_seen;
        out[n].blacklisted_until = e->blacklisted_until;
        out[n].error_count      = e->error_count;
        out[n].hc_last_ok       = e->hc_last_ok;
        out[n].hc_fail_count    = e->hc_fail_count;
        n++;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return n;
}
