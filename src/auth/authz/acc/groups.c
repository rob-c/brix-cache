/*
 * groups.c — OS/NIS group resolution for the xrdacc engine (XrdAccGroups).
 *
 * WHAT: resolves a user to its Unix supplementary groups (getpwnam +
 *   getgrouplist) and tests NIS netgroup membership (innetgr), so `g` records
 *   can match a user's OS gidlist and `n` records can match NIS netgroups —
 *   beyond the VO/token groups the credential itself carries.  A per-worker
 *   TTL cache (gidlifetime) keeps the slow NSS lookups off the hot path.
 *
 * WHY: completes XrdAcc parity (acc.gidlifetime / acc.pgo / acc.nisdomain).
 *   The access engine reaches this layer only through the function pointers
 *   installed by brix_acc_groups_init(), so the decision engine stays
 *   testable without the OS.
 *
 * HOW: a small open-addressed per-worker cache keyed by username holds the
 *   resolved group-name list with an expiry; the resolver copies cached names
 *   into the caller's request pool.  netgroup membership is a thin innetgr()
 *   wrapper honouring the configured NIS domain.  Per-worker, single-threaded:
 *   no locking needed.
 */

#include "acc.h"
#include "observability/metrics/metrics.h"          /* ngx_brix_metrics_t */
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (E6): breaker counter */

#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <time.h>


static time_t  acc_gidlifetime = 43200;   /* 12h, XrdAcc default */
static int     acc_primary_only = 0;      /* acc.pgo */
static char    acc_nisdomain[256] = "";   /* acc.nisdomain ("" => default) */

/* gidretran: gids whose group name is ambiguous (shared) and must be skipped
 * during resolution (XrdAccGroups retrangid[]).  Fixed cap, matching XrdAcc. */
#define BRIX_ACC_MAX_RETRAN 32
static gid_t   acc_retrangid[BRIX_ACC_MAX_RETRAN];
static int     acc_retrancnt = 0;

void brix_acc_groups_set_gidlifetime(time_t secs) { acc_gidlifetime = secs; }
void brix_acc_groups_set_primary_only(ngx_int_t on) { acc_primary_only = on ? 1 : 0; }

/* Parse a space/comma-separated gid list into the retran table (replaces the
 * previous set).  Non-numeric / overflow entries are skipped (best effort). */
void
brix_acc_groups_set_gidretran(const char *gidlist)
{
    const char *p = gidlist;

    acc_retrancnt = 0;
    if (gidlist == NULL) {
        return;
    }
    while (*p != '\0' && acc_retrancnt < BRIX_ACC_MAX_RETRAN) {
        while (*p == ' ' || *p == ',' || *p == '\t') {
            p++;
        }
        if (*p < '0' || *p > '9') {
            break;
        }
        acc_retrangid[acc_retrancnt++] = (gid_t) ngx_atoi((u_char *) p,
                                                          ngx_strlen(p));
        while (*p >= '0' && *p <= '9') {
            p++;
        }
    }
}

/* Dotran: a gid in the retran list resolves to no usable group name (its
 * gid->name mapping is ambiguous under NIS).  Returns 1 to skip the gid. */
static int
acc_gid_retran(gid_t gid)
{
    int i;
    for (i = 0; i < acc_retrancnt; i++) {
        if (acc_retrangid[i] == gid) {
            return 1;
        }
    }
    return 0;
}

void
brix_acc_groups_set_nisdomain(const char *domain)
{
    if (domain == NULL) { acc_nisdomain[0] = '\0'; return; }
    size_t n = ngx_strlen(domain);
    if (n >= sizeof(acc_nisdomain)) { n = sizeof(acc_nisdomain) - 1; }
    ngx_memcpy(acc_nisdomain, domain, n);
    acc_nisdomain[n] = '\0';
}


#define ACC_GRP_CACHE_SLOTS  256
#define ACC_DJB2_SEED        5381   /* djb2 hash initial basis */
#define ACC_GRP_USER_MAX     128

typedef struct {
    char     user[ACC_GRP_USER_MAX];
    char   **names;     /* malloc'd vector of malloc'd group names */
    int      count;
    time_t   expiry;
} acc_grp_cache_t;

static acc_grp_cache_t  acc_grp_cache[ACC_GRP_CACHE_SLOTS];

/*
 * Phase 51 (E3): bound the blocking NSS group resolution under system pressure.
 * getpwnam/getgrouplist/getgrgid block the single-threaded event loop when the
 * backing directory service (NIS/LDAP) is slow or down.  Two guards:
 *   - NEGATIVE CACHE: an unknown / no-group user is cached (count 0) for a short
 *     TTL so a flood of distinct unknown users cannot re-block on every request.
 *   - CIRCUIT BREAKER: after N consecutive SLOW resolutions the breaker opens for
 *     a cooldown, during which lookups fail fast to "no supplementary groups"
 *     (the conservative degraded behaviour — group-based grants are withheld, the
 *     user's primary identity still works) instead of re-blocking the worker.
 */
#define ACC_NSS_NEG_TTL_SECS   60      /* negative-cache lifetime */
#define ACC_NSS_SLOW_MS        2000    /* a resolve over this is "slow" */
#define ACC_NSS_TRIP_COUNT     5       /* consecutive slow resolves → open */
#define ACC_NSS_COOLDOWN_SECS  10      /* breaker stays open this long */

static struct {
    int     consecutive_slow;
    time_t  open_until;   /* breaker open (skip NSS) until this time; 0 = closed */
} acc_nss_breaker;

/* Monotonic milliseconds for measuring a blocking call's wall time (ngx_current_msec
 * is not updated while a syscall blocks, so it cannot time one). */
static int64_t
acc_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static unsigned
acc_user_hash(const char *user)
{
    unsigned h = ACC_DJB2_SEED;
    while (*user) { h = ((h << 5) + h) ^ (unsigned char) *user++; }
    return h % ACC_GRP_CACHE_SLOTS;
}

static void
acc_cache_free(acc_grp_cache_t *e)
{
    int i;
    if (e->names) {
        for (i = 0; i < e->count; i++) { free(e->names[i]); }
        free(e->names);
        e->names = NULL;
    }
    e->count = 0;
    e->user[0] = '\0';
}

/* Resolve a user's Unix groups via NSS into a fresh malloc'd vector.
 * Returns count (>=0) and *namesp (malloc'd, NULL if 0), or -1 on unknown user. */
static int
acc_resolve_unix(const char *user, char ***namesp)
{
    struct passwd  *pw;
    gid_t           gids[64];
    int             ng = (int) (sizeof(gids) / sizeof(gids[0]));
    char          **names;
    int             out = 0, i;

    *namesp = NULL;

    pw = getpwnam(user);
    if (pw == NULL) {
        return -1;   /* not a local user: no Unix groups */
    }

    if (acc_primary_only) {
        gids[0] = pw->pw_gid;
        ng = 1;
    } else if (getgrouplist(user, pw->pw_gid, gids, &ng) < 0) {
        /* buffer too small: cap at what we have room for */
        ng = (int) (sizeof(gids) / sizeof(gids[0]));
    }
    if (ng <= 0) {
        return 0;
    }

    names = malloc((size_t) ng * sizeof(char *));
    if (names == NULL) {
        return 0;
    }
    for (i = 0; i < ng; i++) {
        struct group *gr;
        if (acc_gid_retran(gids[i])) {
            continue;               /* ambiguous shared gid — skip its name */
        }
        gr = getgrgid(gids[i]);
        if (gr != NULL && gr->gr_name != NULL) {
            names[out] = strdup(gr->gr_name);
            if (names[out] != NULL) { out++; }
        }
    }
    if (out == 0) { free(names); names = NULL; }
    *namesp = names;
    return out;
}

/* ---- Record one NSS resolve latency into the circuit breaker ----
 *
 * WHAT: given the wall time of a completed NSS group resolve and the current
 *   time, updates the shared breaker state. A resolve at or over ACC_NSS_SLOW_MS
 *   increments the consecutive-slow counter and, on the ACC_NSS_TRIP_COUNT-th
 *   consecutive slow resolve, opens the breaker for ACC_NSS_COOLDOWN_SECS (and
 *   emits the resiliency metric + a WARN). A fast resolve resets the counter.
 *
 * WHY: extracted from brix_acc_unix_groups so the resolver orchestrator stays
 *   within the complexity cap; isolating the breaker-trip decision here keeps
 *   the slow/fast accounting in one nameable place with no behaviour change.
 *
 * HOW:
 *   1. If elapsed >= ACC_NSS_SLOW_MS, pre-increment consecutive_slow.
 *   2. When that count reaches ACC_NSS_TRIP_COUNT, set open_until = now +
 *      cooldown, reset the counter, bump the breaker-open metric, and log WARN.
 *   3. Otherwise (fast resolve) reset consecutive_slow to 0.
 */
static void
acc_nss_note_latency(int64_t elapsed, time_t now)
{
    /* E3: trip the breaker on sustained slow resolutions. */
    if (elapsed >= ACC_NSS_SLOW_MS) {
        if (++acc_nss_breaker.consecutive_slow >= ACC_NSS_TRIP_COUNT) {
            acc_nss_breaker.open_until = now + ACC_NSS_COOLDOWN_SECS;
            acc_nss_breaker.consecutive_slow = 0;
            BRIX_RESIL_METRIC_INC(acc_nss_breaker_open_total);
            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "brix_acc: NSS group lookup slow (%L ms) — "
                          "opening circuit breaker for %ds (failing to "
                          "no-supplementary-groups)",
                          (long long) elapsed, ACC_NSS_COOLDOWN_SECS);
        }
    } else {
        acc_nss_breaker.consecutive_slow = 0;
    }
}

/* ---- Refresh one expired/absent cache entry from NSS ----
 *
 * WHAT: (re)populates cache entry e for user via a fresh NSS resolve, subject to
 *   the circuit breaker. Returns NGX_OK when e now holds a real group-name list
 *   (cnt > 0) that the caller should render; returns NGX_DECLINED when the caller
 *   must yield "no supplementary groups" — either because the breaker is open
 *   (NSS untouched, e left as-is) or because the user resolved to zero groups
 *   (negatively cached with a short TTL). e is always left in a self-consistent
 *   state on the NGX_DECLINED no-group path (count 0).
 *
 * WHY: extracted from brix_acc_unix_groups to keep that resolver under the
 *   complexity cap. The NGX_DECLINED/NGX_OK split preserves the original invariant
 *   that a breaker-open miss returns immediately WITHOUT rendering any stale entry.
 *
 * HOW:
 *   1. If the breaker is open (open_until > now), return NGX_DECLINED without
 *      touching NSS or e (matches the original early return).
 *   2. Time the acc_resolve_unix() call with the monotonic clock and feed the
 *      elapsed time to acc_nss_note_latency() to maintain the breaker.
 *   3. Free the old entry contents via acc_cache_free().
 *   4. On cnt <= 0, negatively cache the username with a short TTL and return
 *      NGX_DECLINED.
 *   5. Otherwise store the resolved name vector with the full gidlifetime TTL and
 *      return NGX_OK.
 */
static ngx_int_t
acc_cache_refresh(acc_grp_cache_t *e, const char *user, time_t now)
{
    char  **names;
    int     cnt;
    int64_t t0, elapsed;

    /* E3: circuit breaker open → fail fast to "no groups", don't touch NSS. */
    if (acc_nss_breaker.open_until > now) {
        return NGX_DECLINED;
    }

    t0  = acc_monotonic_ms();
    cnt = acc_resolve_unix(user, &names);
    elapsed = acc_monotonic_ms() - t0;

    acc_nss_note_latency(elapsed, now);

    acc_cache_free(e);

    /* E3: negative-cache an unknown / no-group user (short TTL) so a flood of
     * distinct misses cannot re-block NSS on every request. */
    if (cnt <= 0) {
        ngx_memcpy(e->user, user, ngx_strlen(user) + 1);
        e->names  = NULL;
        e->count  = 0;
        e->expiry = now + ngx_min(ACC_NSS_NEG_TTL_SECS, acc_gidlifetime);
        return NGX_DECLINED;
    }

    ngx_memcpy(e->user, user, ngx_strlen(user) + 1);
    e->names = names;
    e->count = cnt;
    e->expiry = now + acc_gidlifetime;
    return NGX_OK;
}

/* ---- Copy a cache entry's group names into a request-pool array ----
 *
 * WHAT: builds an ngx_array_t of char* in pool, each element a pool-owned
 *   null-terminated copy of one cached group name. Returns the array, or NULL on
 *   any allocation failure.
 *
 * WHY: the cached name vector is malloc'd and per-worker-persistent; callers need
 *   request-lifetime copies. Isolating the copy loop keeps the resolver flat and
 *   under the complexity cap.
 *
 * HOW:
 *   1. Create the array sized to e->count.
 *   2. For each cached name, push a slot and pnalloc a len+1 copy in pool.
 *   3. memcpy the name (including its terminator) and store the copy.
 *   4. Return NULL on any allocation failure encountered along the way.
 */
static ngx_array_t *
acc_cache_to_array(ngx_pool_t *pool, acc_grp_cache_t *e)
{
    ngx_array_t *out;
    int          i;

    out = ngx_array_create(pool, (ngx_uint_t) e->count, sizeof(char *));
    if (out == NULL) {
        return NULL;
    }
    for (i = 0; i < e->count; i++) {
        char  **slot = ngx_array_push(out);
        size_t  len  = ngx_strlen(e->names[i]);
        char   *copy = ngx_pnalloc(pool, len + 1);
        if (slot == NULL || copy == NULL) {
            return NULL;
        }
        ngx_memcpy(copy, e->names[i], len + 1);
        *slot = copy;
    }
    return out;
}

/* Public resolver (installed into the engine): user -> request-pool array of
 * group-name strings, using the TTL cache. */
static ngx_array_t *
brix_acc_unix_groups(ngx_pool_t *pool, const char *user)
{
    acc_grp_cache_t *e;
    time_t           now;

    if (user == NULL || *user == '\0' || ngx_strlen(user) >= ACC_GRP_USER_MAX) {
        return NULL;
    }
    now = time(NULL);
    e = &acc_grp_cache[acc_user_hash(user)];

    /* Cache miss (absent, expired, or different user) → refresh from NSS. A
     * breaker-open or no-group refresh yields "no supplementary groups" now,
     * without rendering any stale entry. */
    if (!(e->user[0] != '\0' && e->expiry > now && ngx_strcmp(e->user, user) == 0)) {
        if (acc_cache_refresh(e, user, now) != NGX_OK) {
            return NULL;
        }
    }

    if (e->count == 0) {
        return NULL;
    }
    return acc_cache_to_array(pool, e);
}

/* NIS netgroup membership test (innetgr): is (user, host) in <netgroup>? */
static int
brix_acc_in_netgroup(const char *netgroup, const char *user, const char *host)
{
    const char *domain = (acc_nisdomain[0] != '\0') ? acc_nisdomain : NULL;
    if (netgroup == NULL) {
        return 0;
    }
    return innetgr(netgroup, host, user, domain) != 0;
}

void
brix_acc_groups_init(void)
{
    brix_acc_set_group_resolvers(brix_acc_unix_groups, brix_acc_in_netgroup);
}
