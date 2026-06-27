/*
 * registry_select.c - extracted concern
 * Phase-38 split of registry.c; behavior-identical.
 */
#include "registry_internal.h"


/* Return 1 if path starts with any colon-delimited token in paths. */
int
srv_path_matches(const char *paths, const char *path)
{
    const char *p, *end;
    size_t      tok_len, path_len;

    path_len = strlen(path);
    p = paths;

    while (*p) {
        end = strchr(p, ':');
        if (end == NULL) {
            end = p + strlen(p);
        }
        tok_len = (size_t)(end - p);

        if (tok_len > 0) {
            /* "/" root token matches every path regardless of leading slash. */
            if (tok_len == 1 && p[0] == '/') {
                return 1;
            }
            /* Longest-prefix match: the token must align with a directory
             * boundary so that token "/data" never matches "/database".
             * After the literal prefix compares equal, accept on any of three
             * mutually-exclusive boundary conditions:
             *   (1) token itself ends with '/' (e.g. "/data/" in the registry)
             *       -- the slash is already the boundary;
             *   (2) the path has a '/' immediately past the prefix (e.g. path
             *       "/data/file" against token "/data") -- next char is the
             *       directory separator;
             *   (3) exact match -- the path ends right at the token boundary
             *       (path[tok_len] is the NUL terminator). */
            if (path_len >= tok_len
                && ngx_strncmp(path, p, tok_len) == 0
                && (p[tok_len - 1] == '/'
                    || path[tok_len] == '/' || path[tok_len] == '\0'))
            {
                return 1;
            }
        }

        p = *end ? end + 1 : end;
    }
    return 0;
}



/* WHAT
 * Selects the best data server for a given path from the registry table.
 * Used by kXR_locate and kXR_open to redirect clients to optimal servers.

 * WHY
 * Selection policy: reads → lowest util_pct (least loaded); writes → highest
 * free_mb (most available space). Path matching uses longest-prefix over colon-
 * delimited tokens in each entry's paths field.
 *
 * allow_blacklisted gives the open/stat handlers a LAST-RESORT tier: when no
 * live server matches, fall back to a currently-blacklisted one rather than a
 * false NotFound.  A CMS heartbeat drop blacklists a server for 30 s even though
 * its data plane is almost always still serving, so under load a transient blip
 * should still redirect to the (live) node.  kXR_locate passes 0 — it must
 * report only live servers, so a genuinely dead node is still "not found" there.

 * HOW
 * Locks mutex → scans all occupied slots → filters by srv_path_matches() →
 * picks best by for_write (free_mb max for writes, util_pct min for reads),
 * preferring fresh→stale→(blacklisted, only if allow_blacklisted).  Writes
 * host+port to output buffers. Unlocks and returns 1/0.
 */
int
srv_select_core(const char *path, int for_write, int allow_blacklisted,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    int                 best_fresh;     /* live: not stale AND not blacklisted */
    int                 best_any;       /* not blacklisted, any staleness */
    int                 best_black;     /* blacklisted last-resort candidate */
    uint32_t            best_fresh_val;
    uint32_t            best_any_val;
    uint32_t            best_black_val;
    int                 best;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    best_fresh     = -1;
    best_any       = -1;
    best_black     = -1;
    best_fresh_val = for_write ? 0 : (uint32_t) -1;
    best_any_val   = for_write ? 0 : (uint32_t) -1;
    best_black_val = for_write ? 0 : (uint32_t) -1;

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        ngx_uint_t is_stale;
        ngx_uint_t is_black;
        uint32_t   metric;

        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (!srv_path_matches(e->paths, path)) {
            continue;
        }

        is_black = (e->blacklisted_until != 0
                    && e->blacklisted_until > ngx_current_msec);

        if (is_black && !allow_blacklisted) {
            continue;           /* strict callers (e.g. locate) skip blacklisted */
        }

        /*
         * Phase 39 (WS7): a server that has not heartbeated within
         * stale_after_ms is de-preferred but still tracked as a fallback, so an
         * all-stale storm degrades to the freshest stale server rather than a
         * false NotFound.  The signed diff tolerates ngx_current_msec wrap.
         */
        is_stale = (xrootd_srv_stale_after_ms > 0
                    && (ngx_msec_int_t) (ngx_current_msec - e->last_seen)
                       > (ngx_msec_int_t) xrootd_srv_stale_after_ms);

        metric = for_write ? e->free_mb : e->util_pct;

        if (is_black) {
            /* allow_blacklisted only — a last-resort tier below live servers. */
            if (best_black == -1
                || (for_write ? (metric > best_black_val)
                              : (metric < best_black_val)))
            {
                best_black     = (int) i;
                best_black_val = metric;
            }
            continue;
        }

        if (best_any == -1
            || (for_write ? (metric > best_any_val) : (metric < best_any_val)))
        {
            best_any     = (int) i;
            best_any_val = metric;
        }
        if (!is_stale
            && (best_fresh == -1
                || (for_write ? (metric > best_fresh_val)
                              : (metric < best_fresh_val))))
        {
            best_fresh     = (int) i;
            best_fresh_val = metric;
        }
    }

    best = (best_fresh >= 0) ? best_fresh
         : (best_any   >= 0) ? best_any
         :                     best_black;

    if (best >= 0) {
        e = &tbl->slots[best];
        ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
        *port_out = e->port;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return best >= 0;
}



/* Strict selection: live (non-blacklisted) servers only.  This is what
 * kXR_locate and every non-open caller use. */
int
xrootd_srv_select(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    return srv_select_core(path, for_write, 0 /*allow_blacklisted*/,
                           host_out, host_size, port_out);
}



/* Selection with a blacklisted last-resort tier — see the header. */
int
xrootd_srv_select_or_blacklisted(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    return srv_select_core(path, for_write, 1 /*allow_blacklisted*/,
                           host_out, host_size, port_out);
}



/* WHAT: Count occupied servers that export a prefix covering path — the number
 *       of distinct data servers a client could be redirected to for this path.
 * WHY:  The tried/triedrc retry protocol (see xrootd_manager_tried_exhausted)
 *       needs to know how many candidates exist so it can tell when the client
 *       has exhausted them all and the answer is definitively "not found".
 * HOW:  Same path scan as srv_select_core (in_use, prefix match) under the
 *       registry spinlock, returning the count.  Blacklisted slots ARE counted:
 *       the open/stat path (xrootd_srv_select_or_blacklisted) can redirect to a
 *       blacklisted server as a last resort, so it IS a candidate the client may
 *       be sent to.  Counting it keeps tried-exhausted consistent — a client
 *       that already tried that one server then converges to NotFound instead of
 *       being bounced back to it.  (A server that left the cluster is
 *       unregistered → in_use == 0 → not counted.) */
int
xrootd_srv_count_matching(const char *path)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    int                 n = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);
    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (!srv_path_matches(e->paths, path)) {
            continue;
        }
        n++;
    }
    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return n;
}



/* WHAT: Honour the XRootD client's tried/triedrc retry protocol at a manager.
 *       When a data server returns an error the client re-issues the request to
 *       the manager with ?tried=h1,h2&triedrc=rc1,rc2 listing servers it already
 *       attempted.  Returns 1 when every server exporting this path has already
 *       been tried — the caller must then answer kXR_NotFound instead of
 *       redirecting, otherwise the client bounces manager<->data-server until it
 *       hits its redirect limit (the divergence conformance testing caught).
 * WHY:  A conformant redirector must converge to "not found" once the client has
 *       visited every candidate; reference cmsd does this via the tried list.
 * HOW:  Extract the opaque (everything after '?') from the raw request payload,
 *       locate "tried=", count its comma-separated hosts, and compare against
 *       xrootd_srv_count_matching(clean_path).  Conservative: a zero match count
 *       falls through to the normal CMS-locate path so this does not prematurely
 *       short-circuit hierarchical (parent-locate) clusters. */
int
xrootd_manager_tried_exhausted(const u_char *payload, size_t payload_len,
    const char *clean_path)
{
    char          opaque[1024];
    const u_char *q;
    size_t        olen;
    const char   *t, *p;
    int           n_tried, n_match;

    if (payload == NULL || payload_len == 0) {
        return 0;
    }
    q = memchr(payload, '?', payload_len);
    if (q == NULL) {
        return 0;                 /* no opaque -> client's first attempt */
    }
    q++;
    olen = (size_t) (payload + payload_len - q);
    if (olen > 0 && q[olen - 1] == '\0') {
        olen--;                   /* trim trailing NUL some payloads carry */
    }
    if (olen == 0 || olen >= sizeof(opaque)) {
        return 0;                 /* empty or too long to inspect — be safe */
    }
    ngx_memcpy(opaque, q, olen);
    opaque[olen] = '\0';

    t = strstr(opaque, "tried=");
    if (t == NULL) {
        return 0;
    }
    t += 6;                       /* skip "tried=" */
    if (*t == '\0' || *t == '&') {
        return 0;                 /* present but empty */
    }

    n_tried = 1;
    for (p = t; *p && *p != '&'; p++) {
        if (*p == ',') {
            n_tried++;
        }
    }

    n_match = xrootd_srv_count_matching(clean_path);
    return (n_match > 0 && n_tried >= n_match);
}



/* WHAT
 * Marks a registered server as temporarily unavailable for selection.
 * Called from xrootd_cms_srv_close() when a data server's CMS connection
 * drops.  The server entry stays in the registry so its paths and metrics are
 * preserved for the reconnect; xrootd_srv_select() and xrootd_srv_locate_all()
 * both skip entries whose blacklisted_until is in the future.
 *
 * WHY
 * A clean reconnect within the window re-registers and clears the flag,
 * making the server immediately available again.  A permanently dead server
 * stays blacklisted until the window expires, at which point its stale metrics
 * become visible — operators detect this via xrootd_cluster_server_last_seen_seconds.
 *
 * HOW
 * Locks mutex → scans for host+port match → increments error_count →
 * sets blacklisted_until = ngx_current_msec + duration_ms.  Unlocks.
 */
void
xrootd_srv_blacklist(const char *host, uint16_t port, ngx_msec_t duration_ms)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        e->error_count++;
        e->blacklisted_until = ngx_current_msec + duration_ms;
        break;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}


/*
 * Phase 23 — clear a drain/blacklist set on a server (admin "undrain").
 * Resets blacklisted_until, error_count, and any health-check failure state so
 * xrootd_srv_select() routes to it again immediately.  Returns 1 if a matching
 * in-use entry was found, 0 otherwise.
 */
int
xrootd_srv_undrain(const char *host, uint16_t port)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    int                 found = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || e->port != port
            || ngx_strcmp(e->host, host) != 0)
        {
            continue;
        }
        e->blacklisted_until = 0;
        e->error_count       = 0;
        e->hc_fail_count     = 0;
        found = 1;
        break;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return found;
}
