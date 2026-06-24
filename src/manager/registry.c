/*
 * registry.c — Shared-memory server registry for XRootD redirector mode.
 */

/* ---- WHAT ---------------------------------------------------------------
 * Maintains a fixed-capacity (128-slot) shared-memory table of registered
 * data servers. Each entry records host, port, colon-delimited path tokens,
 * free space (MB), utilisation percentage, and last-seen timestamp.
 * Used by kXR_locate / kXR_open to redirect clients to the best server for
 * a given path — reads pick least-loaded, writes pick most-free-space.

 * ---- WHY ---------------------------------------------------------------
 * In CMS cluster mode nginx-xrootd acts as a sub-manager/redirector. Data
 * servers heartbeat into this registry via xrootd_srv_register() and update
 * load metrics via xrootd_srv_update_load(). The redirector uses the table to
 * answer locate requests and pick optimal servers for open operations.

 * ---- HOW ---------------------------------------------------------------
 * 1. xrootd_srv_configure_registry() allocates an nginx shared-memory zone
 *    with ngx_shared_memory_add() — size = sizeof(table) + slots × entry_size.
 * 2. xrootd_srv_shm_init_zone() zero-fills the shared region and creates a
 *    spinlock (ngx_shmtx_t) embedded at the start of the table.
 * 3. All public APIs lock the mutex, scan/modify slots, unlock — never hold
 *    the lock across I/O. srv_table() returns NULL when the zone is not yet
 *    initialised (data == NULL or data == (void *)1 sentinel).
 * 4. Path matching uses colon-delimited tokens with longest-prefix semantics.
 */

#include "registry.h"
#include "../compat/net_target.h"   /* xrootd_net_host_chars_valid (W1c) */
#include "../compat/host_format.h"  /* xrootd_format_host_port — IPv6 bracketing */
#include "../compat/shm_slots.h"    /* slab-safe SHM table alloc (header survives) */
#include <ngx_shmtx.h>
#include <string.h>

ngx_shm_zone_t *xrootd_srv_shm_zone;

static ngx_shmtx_t   xrootd_srv_mutex;
static ngx_uint_t    xrootd_srv_registry_nslots = XROOTD_SRV_REGISTRY_SLOTS;

/*
 * Phase 39 (WS7): data-server staleness threshold in ms.  A registered server
 * whose last_seen is older than this has stopped heartbeating (silently dead /
 * half-open) and xrootd_srv_select() de-prefers it: it picks the freshest live
 * server when one exists, and only falls back to a stale one if EVERY matching
 * replica is stale (so a transient all-stale storm degrades to "redirect to the
 * least-stale server" rather than a false kXR_NotFound for a file that exists).
 * 0 = disabled (current behaviour).  Set once at config time (before fork) from
 * xrootd_manager_stale_after.
 */
static ngx_msec_t    xrootd_srv_stale_after_ms;

void
xrootd_srv_set_stale_after(ngx_msec_t ms)
{
    xrootd_srv_stale_after_ms = ms;
}

static xrootd_srv_table_t *
srv_table(void)
{
    if (xrootd_srv_shm_zone == NULL
        || xrootd_srv_shm_zone->data == NULL
        || xrootd_srv_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_srv_table_t *) xrootd_srv_shm_zone->data;
}

/* ---- Function: xrootd_srv_shm_init_zone() --------------------------------- */

/* WHAT
 * Shared-memory zone initialiser callback. Called by nginx when the shared-
 * memory zone is mapped (first time) or reattached (subsequent workers).

 * WHY
 * Ensures the registry table is zero-filled and the spinlock is created on
 * first boot; on restart (data != NULL) just recreates the lock against the
 * existing table structure.

 * HOW
 * Delegates fresh-alloc / reload / re-attach to xrootd_shm_table_alloc(), which
 * allocates the table FROM the slab pool so nginx's slab-pool header survives at
 * shm.addr (ngx_unlock_mutexes() force-unlocks that header on every child death;
 * laying our own struct over it would SIGSEGV the master). The helper zero-fills
 * the table and creates the worker-local mutex from tbl->lock (the table's first
 * member). On a brand-new allocation we set the capacity; on reuse we must not,
 * to preserve the live table state.
 */
ngx_int_t
xrootd_srv_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_srv_table_t *tbl;
    ngx_flag_t          fresh;
    size_t              table_bytes;

    table_bytes = sizeof(xrootd_srv_table_t)
                + (size_t) xrootd_srv_registry_nslots
                  * sizeof(xrootd_srv_entry_t);

    tbl = xrootd_shm_table_alloc(shm_zone, data, table_bytes,
                                 &xrootd_srv_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        tbl->capacity = xrootd_srv_registry_nslots;
    }

    return NGX_OK;
}

/* ---- Function: xrootd_srv_configure_registry() ---------------------------- */

/* WHAT
 * Allocates the shared-memory zone for the server registry and sets its size
 * based on the configured slot count.

 * WHY
 * Called during nginx configuration parsing (xrootd_registry_slots directive).
 * Must happen before any traffic so that workers can find the zone at startup.

 * HOW
 * Sets xrootd_srv_registry_nslots to the requested value, computes zone size
 * via xrootd_shm_zone_size(table_bytes) — the table is allocated FROM the slab
 * pool, so the zone must hold the table plus slab overhead — adds the zone via
 * ngx_shared_memory_add(), sets init callback and (void *)1 sentinel data.
 */
ngx_int_t
xrootd_srv_configure_registry(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("xrootd_srv_registry");
    size_t     zone_size;

    xrootd_srv_registry_nslots = slots;
    zone_size = xrootd_shm_zone_size(
                    sizeof(xrootd_srv_table_t)
                  + (size_t) slots * sizeof(xrootd_srv_entry_t));
    xrootd_srv_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                  zone_size,
                                                  &ngx_stream_xrootd_module);
    if (xrootd_srv_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_shm_zone_warn_on_resize(cf, xrootd_srv_shm_zone,
                                   "xrootd_registry_slots");

    xrootd_srv_shm_zone->init = xrootd_srv_shm_init_zone;
    xrootd_srv_shm_zone->data = (void *) 1;

    return NGX_OK;
}

/* Return 1 if path starts with any colon-delimited token in paths. */
static int
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

/* ---- Function: xrootd_srv_register() -------------------------------------- */

/* WHAT
 * Registers or updates a data server entry in the shared-memory registry.
 * Called by CMS server handler when a data server logs in or heartbeats.

 * WHY
 * The redirector needs to know which servers exist, what paths they serve,
 * and their current load metrics so that kXR_locate / kXR_open can pick the
 * best server for each request.

 * HOW
 * Locks mutex → scans all slots: if host+port match found, update paths/free/
 * util/last_seen fields. If no match and a free slot exists, allocate it with
 * host/port/paths/free/util/last_seen/in_use=1. If registry is full, log warn
 * and increment registry_full_total Prometheus counter.
 */
void
xrootd_srv_register(const char *host, uint16_t port,
    const char *paths, uint32_t free_mb, uint32_t util_pct)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i, free_slot;
    int                 found;

    tbl = srv_table();
    if (tbl == NULL) {
        return;
    }

    /*
     * W1c — reject any host string that is not a clean hostname / IP literal
     * before it can enter the registry.  This is the single store choke point,
     * so it also protects every redirect-emit path (xrootd_srv_select /
     * xrootd_srv_locate_all) from control-byte or scheme injection into the
     * "S<r|w>host:port" string a client parses.  Registry hosts are normally
     * the peer IP from ngx_sock_ntop, so a rejection here means a poisoned or
     * malformed registration attempt.
     */
    if (host == NULL || !xrootd_net_host_chars_valid(host, ngx_strlen(host))) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "xrootd: rejected registration with invalid host string");
        return;
    }

    ngx_shmtx_lock(&xrootd_srv_mutex);

    free_slot = tbl->capacity;
    found = 0;

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            if (free_slot == tbl->capacity) {
                free_slot = i;
            }
            continue;
        }
        if (e->port == port && ngx_strcmp(e->host, host) == 0) {
            /* Update existing entry; clear any prior blacklist on reconnect. */
            ngx_cpystrn((u_char *) e->paths,
                        (u_char *) (paths ? paths : ""),
                        sizeof(e->paths));
            e->free_mb          = free_mb;
            e->util_pct         = util_pct;
            e->last_seen        = ngx_current_msec;
            e->blacklisted_until = 0;
            e->error_count      = 0;
            found = 1;
            break;
        }
    }

    if (!found && free_slot < tbl->capacity) {
        e = &tbl->slots[free_slot];
        ngx_cpystrn((u_char *) e->host, (u_char *) host, sizeof(e->host));
        e->port = port;
        ngx_cpystrn((u_char *) e->paths,
                    (u_char *) (paths ? paths : ""),
                    sizeof(e->paths));
        e->free_mb   = free_mb;
        e->util_pct  = util_pct;
        e->last_seen = ngx_current_msec;
        e->in_use    = 1;
    } else if (!found) {
        /* Registry is full: log a warning and increment the Prometheus counter. */
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "xrootd: server registry full (%ui slots); "
                      "dropping registration for %s:%ui "
                      "(increase xrootd_registry_slots)",
                      tbl->capacity, host, (ngx_uint_t) port);
        {
            ngx_xrootd_metrics_t *m = xrootd_metrics_shared();
            if (m != NULL) {
                ngx_atomic_fetch_add(&m->registry_full_total, 1);
            }
        }
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

/* ---- Function: xrootd_srv_update_load() ----------------------------------- */

/* WHAT
 * Refreshes free-space and utilisation metrics for an already-registered server.
 * Called on each CMS heartbeat from the data server.

 * WHY
 * Selection policy depends on current load: reads pick least-loaded servers,
 * writes pick most-free-space. Metrics must stay fresh for accurate routing.

 * HOW
 * Locks mutex → scans slots for host+port match → updates free_mb, util_pct,
 * last_seen fields only (no path changes). Unlocks and returns.
 */
void
xrootd_srv_update_load(const char *host, uint16_t port,
    uint32_t free_mb, uint32_t util_pct)
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
        if (e->in_use && e->port == port
            && ngx_strcmp(e->host, host) == 0)
        {
            e->free_mb   = free_mb;
            e->util_pct  = util_pct;
            e->last_seen = ngx_current_msec;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

/* ---- Function: xrootd_srv_unregister() ------------------------------------ */

/* WHAT
 * Removes a data server entry from the registry by host+port match.
 * Called when a data server disconnects or is removed from the cluster.

 * WHY
 * Prevents stale entries from being selected by locate/open operations. A
 * disconnected server should not receive client traffic.

 * HOW
 * Locks mutex → scans slots for host+port match → zero-fills the entry (all
 * fields cleared, in_use=0). Unlocks and returns.
 */
void
xrootd_srv_unregister(const char *host, uint16_t port)
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
        if (e->in_use && e->port == port
            && ngx_strcmp(e->host, host) == 0)
        {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

/* ---- Function: srv_select_core() ------------------------------------------ */

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
static int
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

/* ---- Function: xrootd_srv_select() ---------------------------------------- */

/* Strict selection: live (non-blacklisted) servers only.  This is what
 * kXR_locate and every non-open caller use. */
int
xrootd_srv_select(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    return srv_select_core(path, for_write, 0 /*allow_blacklisted*/,
                           host_out, host_size, port_out);
}

/* ---- Function: xrootd_srv_select_or_blacklisted() ------------------------- */

/* Selection with a blacklisted last-resort tier — see the header. */
int
xrootd_srv_select_or_blacklisted(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    return srv_select_core(path, for_write, 1 /*allow_blacklisted*/,
                           host_out, host_size, port_out);
}

/* ---- Function: xrootd_srv_count_matching() -------------------------------- */

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

/* ---- Function: xrootd_manager_tried_exhausted() --------------------------- */

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

/* ---- Function: xrootd_srv_blacklist() ------------------------------------- */

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

/* ---- Phase 22: active health-check registry helpers ---------------------- */

int
xrootd_srv_hc_claim(char *host_out, size_t host_size, uint16_t *port_out,
    ngx_msec_t interval_ms, ngx_msec_t *next_due_ms)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
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

    ngx_shmtx_lock(&xrootd_srv_mutex);

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

        ngx_shmtx_unlock(&xrootd_srv_mutex);
        return 1;                            /* claimed; caller spreads the rest */
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);

    if (next_due_ms != NULL) {
        *next_due_ms = soonest;              /* nothing due: sleep until soonest */
    }
    return 0;
}

void
xrootd_srv_hc_pass(const char *host, uint16_t port)
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

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

int
xrootd_srv_hc_fail(const char *host, uint16_t port, uint32_t threshold,
    ngx_msec_t blacklist_ms)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
    ngx_uint_t          i;
    int                 newly_blacklisted = 0;

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

    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return newly_blacklisted;
}

/* ---- Function: xrootd_srv_locate_all() ------------------------------------ */

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
xrootd_srv_locate_all(const char *path, int for_write,
    char *buf, size_t bufsz)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
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

    ngx_shmtx_lock(&xrootd_srv_mutex);

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
        xrootd_format_host_port(e->host, e->port, hostport, sizeof(hostport));
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

    ngx_shmtx_unlock(&xrootd_srv_mutex);

    if (written > 0) {
        buf[written] = '\0';
    }

    return written;
}

/* ---- Function: xrootd_srv_unregister_path() ------------------------------- */

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
xrootd_srv_unregister_path(const char *host, uint16_t port, const char *path)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
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

    ngx_shmtx_lock(&xrootd_srv_mutex);

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

    ngx_shmtx_unlock(&xrootd_srv_mutex);
}

/* ---- Function: xrootd_srv_aggregate_space() ------------------------------- */

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
xrootd_srv_aggregate_space(uint32_t *total_free_mb, uint32_t *avg_util_pct)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
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

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        sum_free += e->free_mb;
        sum_util += e->util_pct;
        count++;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);

    *total_free_mb = sum_free;
    *avg_util_pct  = count > 0 ? (uint32_t) (sum_util / count) : 0;
}

ngx_uint_t
xrootd_srv_snapshot(xrootd_srv_snapshot_entry_t *out, ngx_uint_t max_entries,
    ngx_msec_t now)
{
    xrootd_srv_table_t *tbl;
    xrootd_srv_entry_t *e;
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
    ngx_shmtx_lock(&xrootd_srv_mutex);

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

    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return n;
}
