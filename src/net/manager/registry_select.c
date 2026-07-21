/*
 * registry_select.c - extracted concern
 * Phase-38 split of registry.c; behavior-identical.
 */
#include "registry_internal.h"
#include "core/fnv.h"      /* Phase-89 W5: path hash for affinity stick */


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



/*
 * srv_sel_tier_t - one candidate tier in the three-tier selection ladder.
 *
 * Each tier tracks the single best slot seen so far by metric: `idx` is the slot
 * index (-1 = none yet) and `val` is that slot's winning metric.  The three tiers
 * are ranked fresh > any > black; the ladder resolves to the highest non-empty
 * tier (see srv_sel_state_winner).
 */
typedef struct {
    int      idx;   /* best slot index in this tier, or -1 if none */
    uint32_t val;   /* metric of the best slot */
} srv_sel_tier_t;


/*
 * srv_sel_state_t - full three-tier selection accumulator for one scan.
 *   fresh - live: not stale AND not blacklisted (the preferred tier)
 *   any   - not blacklisted, any staleness (stale-but-live fallback)
 *   black - blacklisted last-resort candidate (only when allow_blacklisted)
 * `for_write` fixes the metric direction for the whole scan: writes maximise
 * free_mb, reads minimise util_pct.
 */
/* Phase-89 W5: cap on the fresh-tier candidate list collected for the affinity
 * stick.  Slots past the cap still compete on metric via the normal tiers; the
 * stick just cannot land on them — with 64 co-exporting fresh servers the
 * spread loss is negligible and the array stays a cheap stack object. */
#define SRV_SEL_AFFINITY_MAX 64

typedef struct {
    srv_sel_tier_t fresh;
    srv_sel_tier_t any;
    srv_sel_tier_t black;
    int            for_write;
    /* Phase-89 W5: every fresh-tier candidate seen this scan (not just the
     * metric winner), so the affinity hash can pick a stable member. */
    int            fresh_cands[SRV_SEL_AFFINITY_MAX];
    ngx_uint_t     n_fresh;
} srv_sel_state_t;


/* WHAT: Seed one tier to "empty" with the sentinel metric for the scan direction.
 * WHY:  A write scan improves upward from 0; a read scan improves downward from
 *       UINT32_MAX.  Seeding the val to the worst possible value lets the first
 *       real candidate always win without a separate "first" special-case.
 * HOW:  idx = -1 (no candidate); val = 0 for writes, (uint32_t)-1 for reads. */
static void
srv_sel_tier_init(srv_sel_tier_t *tier, int for_write)
{
    tier->idx = -1;
    tier->val = for_write ? 0 : (uint32_t) -1;
}


/* WHAT: Initialise all three selection tiers and record the scan direction.
 * WHY:  Centralises the fresh/any/black seeding so the scan loop starts clean.
 * HOW:  Store for_write, then seed each tier via srv_sel_tier_init. */
static void
srv_sel_state_init(srv_sel_state_t *st, int for_write)
{
    st->for_write = for_write;
    srv_sel_tier_init(&st->fresh, for_write);
    srv_sel_tier_init(&st->any, for_write);
    srv_sel_tier_init(&st->black, for_write);
    st->n_fresh = 0;
}


/* WHAT: Report whether `metric` beats a tier's current best for this direction.
 * WHY:  Encapsulates the single tie-break rule shared by every tier: writes
 *       prefer a strictly greater free_mb, reads a strictly lesser util_pct.
 *       Using strict comparison preserves first-seen determinism on ties —
 *       identical to the original inlined tests.
 * HOW:  Empty tier (idx == -1) always loses; otherwise compare by direction. */
static int
srv_sel_metric_better(const srv_sel_tier_t *tier, uint32_t metric, int for_write)
{
    if (tier->idx == -1) {
        return 1;
    }
    return for_write ? (metric > tier->val) : (metric < tier->val);
}


/* WHAT: Offer slot `idx` (metric `metric`) to a single tier, updating if better.
 * WHY:  One place owns the "is this a new tier winner?" decision, so fresh/any/
 *       black all apply exactly the same tie-break.
 * HOW:  If srv_sel_metric_better says yes, record idx+metric as the new best. */
static void
srv_sel_tier_offer(srv_sel_tier_t *tier, int idx, uint32_t metric, int for_write)
{
    if (srv_sel_metric_better(tier, metric, for_write)) {
        tier->idx = idx;
        tier->val = metric;
    }
}


/* WHAT: Classify one matched slot and fold it into the right selection tier(s).
 * WHY:  Isolates the per-slot policy — blacklisted → black tier only; live →
 *       always the `any` tier, and additionally the `fresh` tier when not stale.
 *       Staleness uses a signed msec diff so ngx_current_msec wrap is tolerated.
 * HOW:  Compute metric by direction, then route: black slots update only black;
 *       live slots update any, and fresh when not stale. */
/*
 * srv_sel_load_metric — blend the heartbeat machine load into the selection
 * metric behind brix_cms_load_weight (Phase-89 W4).  Weight 0 (the default)
 * returns the input untouched — byte-identical to the pre-W4 scoring.
 * Reads minimise the metric: blend as ((100-w)*util + w*load)/100 so a
 * loaded node scores worse.  Writes maximise free_mb: scale it down by up to
 * w% at full load (free - free*w*load/10000) so capacity still dominates and
 * the direction of comparison is unchanged.
 */
static uint32_t
srv_sel_load_metric(uint32_t metric, uint32_t load_pct, int for_write)
{
    ngx_uint_t  w = brix_srv_load_weight;

    if (w == 0) {
        return metric;
    }
    if (for_write) {
        return metric - (uint32_t) ((uint64_t) metric * w * load_pct / 10000);
    }
    return (uint32_t) (((100 - w) * (uint64_t) metric + w * (uint64_t) load_pct)
                       / 100);
}


static void
srv_sel_state_consider(srv_sel_state_t *st, int idx, const brix_srv_entry_t *e,
    int is_black)
{
    uint32_t   metric;
    ngx_uint_t is_stale;

    metric = srv_sel_load_metric(st->for_write ? e->free_mb : e->util_pct,
                                 e->load_pct, st->for_write);

    if (is_black) {
        /* allow_blacklisted only — a last-resort tier below live servers. */
        srv_sel_tier_offer(&st->black, idx, metric, st->for_write);
        return;
    }

    srv_sel_tier_offer(&st->any, idx, metric, st->for_write);

    /*
     * Phase 39 (WS7): a server that has not heartbeated within stale_after_ms is
     * de-preferred but still tracked as a fallback, so an all-stale storm
     * degrades to the freshest stale server rather than a false NotFound.  The
     * signed diff tolerates ngx_current_msec wrap.
     */
    is_stale = (brix_srv_stale_after_ms > 0
                && (ngx_msec_int_t) (ngx_current_msec - e->last_seen)
                   > (ngx_msec_int_t) brix_srv_stale_after_ms);
    if (!is_stale) {
        srv_sel_tier_offer(&st->fresh, idx, metric, st->for_write);
        if (st->n_fresh < SRV_SEL_AFFINITY_MAX) {
            st->fresh_cands[st->n_fresh++] = idx;
        }
    }
}


/* WHAT: fnv1a over the NUL-terminated path (Phase-89 W5 affinity stick).
 * WHY:  The stick must be a pure function of the path so every worker on every
 *       manager picks the same member of the same candidate set; fnv1a is the
 *       design-of-record hash (loc_cache.c) for path-shaped keys.
 * HOW:  Standard XOR-multiply loop over the bytes. */
static uint32_t
srv_sel_path_hash(const char *path)
{
    uint32_t  h = BRIX_FNV1A32_OFFSET_BASIS;

    while (*path != '\0') {
        h ^= (uint32_t) (u_char) *path++;
        h *= BRIX_FNV1A32_PRIME;
    }
    return h;
}


/* WHAT: Resolve the accumulated tiers to the winning slot index (or -1).
 * WHY:  Fixes the tier priority in one place: a live-fresh server always beats a
 *       stale-live one, which always beats a blacklisted last-resort one.
 * HOW:  Prefer fresh, then any, then black. */
static int
srv_sel_state_winner(const srv_sel_state_t *st)
{
    if (st->fresh.idx >= 0) {
        return st->fresh.idx;
    }
    if (st->any.idx >= 0) {
        return st->any.idx;
    }
    return st->black.idx;
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
 * folds each match into the three-tier accumulator (srv_sel_state_consider) →
 * resolves the winner (srv_sel_state_winner), preferring fresh→stale→
 * (blacklisted, only if allow_blacklisted).  Writes host+port to output
 * buffers. Unlocks and returns 1/0.
 */
int
srv_select_core(const char *path, int for_write, int allow_blacklisted,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    srv_sel_state_t     st;
    int                 best;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    srv_sel_state_init(&st, for_write);

    ngx_shmtx_lock(&brix_srv_mutex);

    for (i = 0; i < tbl->capacity; i++) {
        int is_black;

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

        srv_sel_state_consider(&st, (int) i, e, is_black);
    }

    best = srv_sel_state_winner(&st);

    /* Phase-89 W5: with affinity on and >1 eligible FRESH candidate, the path
     * hash — not the metric — picks the member, so repeated requests for one
     * path stick to one server (cache locality).  LOCKED precedence (phase-61
     * note 2): the filter above already excluded blacklisted/stale slots, so a
     * drained host is never sticky; an empty/singleton fresh tier keeps the
     * ladder winner unchanged. */
    if (brix_srv_affinity && st.n_fresh > 1) {
        best = st.fresh_cands[srv_sel_path_hash(path) % st.n_fresh];
    }

    if (best >= 0) {
        e = &tbl->slots[best];
        ngx_cpystrn((u_char *) host_out, (u_char *) e->host, host_size);
        *port_out = e->port;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return best >= 0;
}



/* Strict selection: live (non-blacklisted) servers only.  This is what
 * kXR_locate and every non-open caller use. */
int
brix_srv_select(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    return srv_select_core(path, for_write, 0 /*allow_blacklisted*/,
                           host_out, host_size, port_out);
}



/* Selection with a blacklisted last-resort tier — see the header. */
int
brix_srv_select_or_blacklisted(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out)
{
    return srv_select_core(path, for_write, 1 /*allow_blacklisted*/,
                           host_out, host_size, port_out);
}



/* WHAT: Count occupied servers that export a prefix covering path — the number
 *       of distinct data servers a client could be redirected to for this path.
 * WHY:  The tried/triedrc retry protocol (see brix_manager_tried_exhausted)
 *       needs to know how many candidates exist so it can tell when the client
 *       has exhausted them all and the answer is definitively "not found".
 * HOW:  Same path scan as srv_select_core (in_use, prefix match) under the
 *       registry spinlock, returning the count.  Blacklisted slots ARE counted:
 *       the open/stat path (brix_srv_select_or_blacklisted) can redirect to a
 *       blacklisted server as a last resort, so it IS a candidate the client may
 *       be sent to.  Counting it keeps tried-exhausted consistent — a client
 *       that already tried that one server then converges to NotFound instead of
 *       being bounced back to it.  (A server that left the cluster is
 *       unregistered → in_use == 0 → not counted.) */
int
brix_srv_count_matching(const char *path)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 n = 0;

    tbl = srv_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_srv_mutex);
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
    ngx_shmtx_unlock(&brix_srv_mutex);
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
 *       brix_srv_count_matching(clean_path).  Conservative: a zero match count
 *       falls through to the normal CMS-locate path so this does not prematurely
 *       short-circuit hierarchical (parent-locate) clusters. */
int
brix_manager_tried_exhausted(const u_char *payload, size_t payload_len,
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

    n_match = brix_srv_count_matching(clean_path);
    return (n_match > 0 && n_tried >= n_match);
}



/* WHAT
 * Marks a registered server as temporarily unavailable for selection.
 * Called from brix_cms_srv_close() when a data server's CMS connection
 * drops.  The server entry stays in the registry so its paths and metrics are
 * preserved for the reconnect; brix_srv_select() and brix_srv_locate_all()
 * both skip entries whose blacklisted_until is in the future.
 *
 * WHY
 * A clean reconnect within the window re-registers and clears the flag,
 * making the server immediately available again.  A permanently dead server
 * stays blacklisted until the window expires, at which point its stale metrics
 * become visible — operators detect this via brix_cluster_server_last_seen_seconds.
 *
 * HOW
 * Locks mutex → scans for host+port match → increments error_count →
 * sets blacklisted_until = ngx_current_msec + duration_ms.  Unlocks.
 */
void
brix_srv_blacklist(const char *host, uint16_t port, ngx_msec_t duration_ms)
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
        e->error_count++;
        e->blacklisted_until = ngx_current_msec + duration_ms;
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
}


/*
 * Phase 23 — clear a drain/blacklist set on a server (admin "undrain").
 * Resets blacklisted_until, error_count, and any health-check failure state so
 * brix_srv_select() routes to it again immediately.  Returns 1 if a matching
 * in-use entry was found, 0 otherwise.
 */
int
brix_srv_undrain(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 found = 0;

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
        e->blacklisted_until = 0;
        e->error_count       = 0;
        e->hc_fail_count     = 0;
        found = 1;
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return found;
}


/* Phase-89 W3 — public wrapper over the longest-prefix matcher (registry.h). */
int
brix_srv_paths_cover(const char *paths, const char *path)
{
    if (paths == NULL || path == NULL) {
        return 0;
    }
    return srv_path_matches(paths, path);
}


/* Phase-89 W3 — is host:port inside an active blacklist window? (registry.h). */
int
brix_srv_is_blacklisted(const char *host, uint16_t port)
{
    brix_srv_table_t *tbl;
    brix_srv_entry_t *e;
    ngx_uint_t          i;
    int                 drained = 0;

    tbl = srv_table();
    if (tbl == NULL || host == NULL) {
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
        drained = (e->blacklisted_until != 0
                   && ngx_current_msec < e->blacklisted_until);
        break;
    }

    ngx_shmtx_unlock(&brix_srv_mutex);
    return drained;
}
