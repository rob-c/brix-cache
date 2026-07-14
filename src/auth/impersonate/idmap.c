/*
 * idmap.c — identity -> local UNIX account resolution (phase 40).
 *
 * WHAT: brix_idmap_resolve() maps an authenticated principal (GSI DN / token
 *   sub / SSS user / krb5 localname) to {uid, primary gid, supplementary gids}
 *   via (1) an optional grid-mapfile (DN -> local username), (2) a direct
 *   getpwnam() of the principal, then (3) a squash-to-default or deny policy.
 *   A per-process TTL cache keeps the NSS lookups off the hot path.
 *
 * WHY: This is the pure, self-contained foundation of per-request impersonation
 *   (the privileged broker consumes it).  It is the only place numeric uid/gid
 *   are derived; it enforces the safety floor (never resolve to uid 0 / below
 *   min_uid), so the broker can never be asked to act as a system account.
 *
 * HOW: Modelled on src/acc/groups.c (getpwnam + getgrouplist + a fixed-slot,
 *   strcmp, TTL cache).  The grid-mapfile parse/lookup lives in idmap_gridmap.c
 *   and the numeric-id deny-list / squash policy in idmap_denylist.c; this file
 *   keeps the cache, policy install, and the resolve orchestration.  No goto;
 *   pure helpers, side effects at the edges.
 */

#include "impersonate.h"
#include "core/compat/cstr.h"
#include "idmap_internal.h"

#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#define IDMAP_CACHE_SLOTS  256
#define IDMAP_DJB2_SEED    5381   /* djb2 hash initial basis */

typedef struct {
    char                  principal[IDMAP_PRINC_MAX];
    brix_idmap_creds_t  creds;
    int                   rc;           /* BRIX_IDMAP_OK / SQUASH / DENY */
    time_t                expiry;       /* 0 = empty slot */
} idmap_cache_slot_t;

static idmap_cache_slot_t      idmap_cache[IDMAP_CACHE_SLOTS];

static time_t                  idmap_ttl      = BRIX_IDMAP_DEFAULT_TTL;
uid_t                          idmap_min_uid  = BRIX_IDMAP_DEFAULT_MIN_UID;
int                            idmap_primary_only;
static char                    idmap_default_user[IDMAP_PRINC_MAX]; /* "" = deny */


static ngx_uint_t
idmap_hash(const char *s)
{
    ngx_uint_t h = IDMAP_DJB2_SEED;

    while (*s) {
        h = ((h << 5) + h) ^ (ngx_uint_t) (unsigned char) *s++;  /* djb2-xor */
    }
    return h & (IDMAP_CACHE_SLOTS - 1);
}


/*
 * Install the numeric mapping policy from config: cache TTL, the effective
 * min-uid floor, and the primary-group-only switch.  WHY split from init:
 * pure config->global plumbing, no lookups, keeps brix_idmap_init a flat
 * two-halves orchestrator (policy load vs table build).
 */
static void
idmap_init_policy(const brix_idmap_conf_t *conf, ngx_log_t *log)
{
    idmap_ttl     = (conf->cache_ttl > 0) ? (time_t) conf->cache_ttl
                                          : BRIX_IDMAP_DEFAULT_TTL;
    idmap_min_uid = (conf->min_uid > 0) ? conf->min_uid
                                        : BRIX_IDMAP_DEFAULT_MIN_UID;
    /*
     * Clamp the effective floor UP to the absolute hard floor: ids below
     * BRIX_IMP_HARD_MIN_ID can never be impersonated, even if an admin sets a
     * lower brix_idmap_min_uid.  (A lower value would in any case be caught at
     * the broker's syscall edge; clamping here turns it into a clean deny instead
     * of a fatal broker abort.)
     */
    if (idmap_min_uid < BRIX_IMP_HARD_MIN_ID) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "impersonate: brix_idmap_min_uid %d raised to the hard "
                          "reserved-id floor %d (uids/gids below %d can never be "
                          "impersonated)", (int) idmap_min_uid,
                          BRIX_IMP_HARD_MIN_ID, BRIX_IMP_HARD_MIN_ID);
        }
        idmap_min_uid = BRIX_IMP_HARD_MIN_ID;
    }
    idmap_primary_only = conf->primary_only ? 1 : 0;
}

ngx_int_t
brix_idmap_init(const brix_idmap_conf_t *conf, ngx_log_t *log)
{
    char        pbuf[IDMAP_PRINC_MAX];
    const char *path = NULL;

    if (conf == NULL) {
        return NGX_ERROR;
    }

    idmap_init_policy(conf, log);
    idmap_init_denylists(conf, log);

    idmap_default_user[0] = '\0';
    if (conf->default_user.len > 0) {
        (void) brix_str_cbuf(idmap_default_user, sizeof(idmap_default_user),
                             &conf->default_user);
    }

    ngx_memzero(idmap_cache, sizeof(idmap_cache));    /* drop the cache */

    if (conf->gridmap_path.len > 0
        && brix_str_cbuf(pbuf, sizeof(pbuf), &conf->gridmap_path) != NULL)
    {
        path = pbuf;
    }
    return idmap_gridmap_load(path, log);
}

/*
 * Cache probe: a hit is the SAME principal in its hash slot, not expired.
 * On a hit copies the cached verdict into *rc_out (and the creds into *out
 * for OK/SQUASH) and returns 1; returns 0 on a miss.  Pure read — never
 * mutates the slot.
 */
static int
idmap_cache_get(const idmap_cache_slot_t *slot, const char *principal,
                time_t now, brix_idmap_creds_t *out, int *rc_out)
{
    if (slot->expiry <= now || strcmp(slot->principal, principal) != 0) {
        return 0;
    }
    if (slot->rc == BRIX_IDMAP_OK || slot->rc == BRIX_IDMAP_SQUASH) {
        *out = slot->creds;
    }
    *rc_out = slot->rc;
    return 1;
}

/*
 * Uncached mapping pipeline: (1) exact grid-mapfile DN lookup, else (2) the
 * principal as a literal username, then (3) the squash-to-default collapse
 * when the direct mapping is missing or forbidden.  Fills *creds on
 * OK/SQUASH; *user_out always reports the attempted username (for the deny
 * log).  Returns BRIX_IDMAP_OK / SQUASH / DENY.
 */
static int
idmap_resolve_uncached(const char *principal, brix_idmap_creds_t *creds,
                       const char **user_out)
{
    const char *user;

    /* (1) grid-mapfile, else (2) the principal as a literal username. */
    user = idmap_gridmap_lookup(principal);
    if (user == NULL) {
        user = principal;
    }
    *user_out = user;

    if (idmap_resolve_user(user, creds) == 0 && idmap_creds_allowed(creds)) {
        return BRIX_IDMAP_OK;
    }
    if (idmap_default_user[0] != '\0'
        && idmap_resolve_user(idmap_default_user, creds) == 0
        && idmap_creds_allowed(creds))
    {
        return BRIX_IDMAP_SQUASH;     /* unmapped/forbidden -> squash account */
    }
    return BRIX_IDMAP_DENY;
}

/* Cache the verdict (incl. denies, to bound repeated NSS misses); the creds
 * are stored only for OK/SQUASH verdicts. */
static void
idmap_cache_put(idmap_cache_slot_t *slot, const char *principal, int rc,
                const brix_idmap_creds_t *creds, time_t now)
{
    ngx_memcpy(slot->principal, principal, ngx_strlen(principal) + 1);
    slot->rc     = rc;
    slot->expiry = now + idmap_ttl;
    if (rc == BRIX_IDMAP_OK || rc == BRIX_IDMAP_SQUASH) {
        slot->creds = *creds;
    }
}

ngx_int_t
brix_idmap_resolve(const brix_idmap_conf_t *conf, const char *principal,
                     brix_idmap_creds_t *out, ngx_log_t *log)
{
    idmap_cache_slot_t *slot;
    const char         *user;
    brix_idmap_creds_t creds;
    time_t              now;
    int                 rc;

    (void) conf;        /* config is installed via brix_idmap_init() */

    if (principal == NULL || out == NULL
        || principal[0] == '\0' || ngx_strlen(principal) >= IDMAP_PRINC_MAX)
    {
        return BRIX_IDMAP_DENY;
    }

    now  = time(NULL);
    slot = &idmap_cache[idmap_hash(principal)];

    /* Cache hit on the same principal, not expired. */
    if (idmap_cache_get(slot, principal, now, out, &rc)) {
        return rc;
    }

    rc = idmap_resolve_uncached(principal, &creds, &user);
    if (rc != BRIX_IDMAP_OK && rc != BRIX_IDMAP_SQUASH && log != NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "impersonate: no UNIX mapping for principal \"%s\" "
                      "(user=\"%s\") -> deny", principal, user);
    }

    idmap_cache_put(slot, principal, rc, &creds, now);
    if (rc == BRIX_IDMAP_OK || rc == BRIX_IDMAP_SQUASH) {
        *out = creds;
    }
    return rc;
}
