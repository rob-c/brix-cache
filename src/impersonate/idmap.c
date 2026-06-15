/*
 * idmap.c — identity -> local UNIX account resolution (phase 40).
 *
 * WHAT: xrootd_idmap_resolve() maps an authenticated principal (GSI DN / token
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
 *   strcmp, TTL cache).  The grid-mapfile is parsed once at init into a small
 *   array of (quoted-DN, username) pairs; resolution checks it first, then falls
 *   back to a direct getpwnam.  No goto; pure helpers, side effects at the edges.
 */

#include "impersonate.h"

#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Module state (per worker / per broker process)                      */
/* ------------------------------------------------------------------ */

#define IDMAP_CACHE_SLOTS  256
#define IDMAP_PRINC_MAX    512          /* a GSI DN can be long */

typedef struct {
    char                  principal[IDMAP_PRINC_MAX];
    xrootd_idmap_creds_t  creds;
    int                   rc;           /* XROOTD_IDMAP_OK / SQUASH / DENY */
    time_t                expiry;       /* 0 = empty slot */
} idmap_cache_slot_t;

typedef struct {
    char *dn;                           /* malloc'd quoted-DN key */
    char *user;                         /* malloc'd local username */
} idmap_gridmap_entry_t;

static idmap_cache_slot_t      idmap_cache[IDMAP_CACHE_SLOTS];

static idmap_gridmap_entry_t  *idmap_gridmap;       /* NULL = no mapfile */
static size_t                  idmap_gridmap_n;

static time_t                  idmap_ttl      = XROOTD_IDMAP_DEFAULT_TTL;
static uid_t                   idmap_min_uid  = XROOTD_IDMAP_DEFAULT_MIN_UID;
static int                     idmap_primary_only;
static char                    idmap_default_user[IDMAP_PRINC_MAX]; /* "" = deny */

/* Deny-lists: account/group NAMES resolved to numeric ids once at init.  A
 * resolved target uid in idmap_forbidden_uids, or a user gid (primary or
 * supplementary) in idmap_forbidden_gids, is refused outright — defence in depth
 * on top of the numeric min_uid floor (catches privileged accounts/groups whose
 * ids are >= the floor, e.g. a site nginx uid 1500 or a docker gid 1500). */
#define IDMAP_FORBID_MAX  256
static uid_t                   idmap_forbidden_uids[IDMAP_FORBID_MAX];
static int                     idmap_forbidden_uids_n;
static gid_t                   idmap_forbidden_gids[IDMAP_FORBID_MAX];
static int                     idmap_forbidden_gids_n;

/* ------------------------------------------------------------------ */
/* Grid-mapfile                                                        */
/* ------------------------------------------------------------------ */

/* Free any previously-loaded grid-mapfile table. */
static void
idmap_gridmap_free(void)
{
    size_t i;

    if (idmap_gridmap == NULL) {
        return;
    }
    for (i = 0; i < idmap_gridmap_n; i++) {
        free(idmap_gridmap[i].dn);
        free(idmap_gridmap[i].user);
    }
    free(idmap_gridmap);
    idmap_gridmap   = NULL;
    idmap_gridmap_n = 0;
}

/*
 * Parse one grid-mapfile line of the classic form:
 *     "<quoted DN>" <local-username>
 * Comments (#) and blank lines are skipped.  Returns 1 and fills the two out
 * params (malloc'd) on a usable mapping, 0 to skip the line, -1 on OOM.
 */
static int
idmap_gridmap_parse_line(const char *line, char **dn_out, char **user_out)
{
    const char *p = line;
    const char *dn_start, *dn_end, *u_start, *u_end;

    while (*p == ' ' || *p == '\t') { p++; }
    if (*p == '#' || *p == '\0' || *p == '\n' || *p != '"') {
        return 0;                       /* comment, blank, or unquoted -> skip */
    }
    dn_start = ++p;                     /* after the opening quote */
    while (*p != '"' && *p != '\0' && *p != '\n') { p++; }
    if (*p != '"') {
        return 0;                       /* unterminated quote -> skip */
    }
    dn_end = p++;                       /* at closing quote */

    while (*p == ' ' || *p == '\t') { p++; }
    u_start = p;
    while (*p != '\0' && *p != '\n' && *p != ' ' && *p != '\t') { p++; }
    u_end = p;
    if (u_end == u_start || (size_t) (dn_end - dn_start) >= IDMAP_PRINC_MAX) {
        return 0;                       /* no username, or DN too long -> skip */
    }

    *dn_out   = strndup(dn_start, (size_t) (dn_end - dn_start));
    *user_out = strndup(u_start, (size_t) (u_end - u_start));
    if (*dn_out == NULL || *user_out == NULL) {
        free(*dn_out);
        free(*user_out);
        return -1;
    }
    return 1;
}

/* Load the grid-mapfile at `path` into idmap_gridmap[].  Returns NGX_OK (incl.
 * the "no path" case) or NGX_ERROR on IO/OOM. */
static ngx_int_t
idmap_gridmap_load(const char *path, ngx_log_t *log)
{
    FILE   *fp;
    char    line[1024];
    size_t  cap = 0;

    idmap_gridmap_free();
    if (path == NULL || path[0] == '\0') {
        return NGX_OK;                  /* no mapfile configured */
    }

    fp = fopen(path, "re");
    if (fp == NULL) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "impersonate: cannot open grid-mapfile \"%s\"", path);
        }
        return NGX_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *dn = NULL, *user = NULL;
        int   r = idmap_gridmap_parse_line(line, &dn, &user);

        if (r < 0) {
            fclose(fp);
            idmap_gridmap_free();
            return NGX_ERROR;
        }
        if (r == 0) {
            continue;
        }
        if (idmap_gridmap_n == cap) {
            size_t                 ncap = cap ? cap * 2 : 16;
            idmap_gridmap_entry_t *ne =
                realloc(idmap_gridmap, ncap * sizeof(*ne));
            if (ne == NULL) {
                free(dn); free(user);
                fclose(fp);
                idmap_gridmap_free();
                return NGX_ERROR;
            }
            idmap_gridmap = ne;
            cap = ncap;
        }
        idmap_gridmap[idmap_gridmap_n].dn   = dn;
        idmap_gridmap[idmap_gridmap_n].user = user;
        idmap_gridmap_n++;
    }
    fclose(fp);

    if (log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "impersonate: loaded %uz grid-mapfile entries from \"%s\"",
                      idmap_gridmap_n, path);
    }
    return NGX_OK;
}

/* Look up a DN in the grid-mapfile; returns the local username or NULL. */
static const char *
idmap_gridmap_lookup(const char *dn)
{
    size_t i;

    for (i = 0; i < idmap_gridmap_n; i++) {
        if (strcmp(idmap_gridmap[i].dn, dn) == 0) {
            return idmap_gridmap[i].user;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* NSS resolution                                                      */
/* ------------------------------------------------------------------ */

/* True if gid is reserved (0 / below the effective floor) or on the forbidden
 * privileged-group list.  Used to scan the FULL group set on overflow. */
static int
idmap_gid_reserved_or_forbidden(gid_t gid)
{
    int k;

    if (gid == 0 || gid < (gid_t) idmap_min_uid) {
        return 1;
    }
    for (k = 0; k < idmap_forbidden_gids_n; k++) {
        if (gid == idmap_forbidden_gids[k]) {
            return 1;
        }
    }
    return 0;
}

/*
 * Resolve a local username to {uid, gid, supplementary gids}.  Returns 0 and
 * fills *out on success, -1 if the user does not exist, or -2 if the user is a
 * member of a RESERVED or FORBIDDEN group anywhere in their (possibly >32) group
 * set — caller must treat both negatives as deny.  Mirrors the getpwnam/
 * getgrouplist usage in src/acc/groups.c, but keeps the numeric ids and, crucially,
 * fails CLOSED when the group set overflows the 32-slot buffer.
 */
static int
idmap_resolve_user(const char *user, xrootd_idmap_creds_t *out)
{
    struct passwd *pw;
    gid_t          gids[XROOTD_IDMAP_MAXGROUPS];
    int            ng = XROOTD_IDMAP_MAXGROUPS;
    int            i;

    pw = getpwnam(user);
    if (pw == NULL) {
        return -1;
    }

    out->uid = pw->pw_uid;
    out->gid = pw->pw_gid;

    if (idmap_primary_only) {
        out->groups[0] = pw->pw_gid;
        out->ngroups   = 1;
        return 0;
    }

    if (getgrouplist(user, pw->pw_gid, gids, &ng) < 0) {
        /*
         * OVERFLOW: the user belongs to MORE than XROOTD_IDMAP_MAXGROUPS groups.
         * `ng` now holds the TRUE total; `gids` holds only a 32-entry PREFIX in
         * /etc/group scan order (NOT sorted).  A reserved or forbidden group could
         * sit past the cap, so checking only the prefix would fail OPEN — a
         * dropped group is a MISSED deny.  Re-resolve the FULL set and REFUSE if
         * ANY group is reserved (0 / < floor) or forbidden.  Common on multi-VO
         * HEP hosts where users exceed 32 group memberships.
         */
        int    total = ng;
        gid_t *full  = malloc((size_t) total * sizeof(gid_t));
        int    j;

        if (full == NULL) {
            return -1;                       /* OOM -> deny (fail closed) */
        }
        if (getgrouplist(user, pw->pw_gid, full, &total) < 0) {
            free(full);
            return -1;                       /* grew again / still failing -> deny */
        }
        for (j = 0; j < total; j++) {
            if (idmap_gid_reserved_or_forbidden(full[j])) {
                free(full);
                return -2;                   /* reserved/forbidden group -> DENY */
            }
        }
        /* Whole set is clean; keep a capped subset for the impersonation setgroups
         * (a subset only ever GRANTS LESS, so it is fail-safe for the op). */
        for (i = 0; i < total && i < XROOTD_IDMAP_MAXGROUPS; i++) {
            out->groups[i] = full[i];
        }
        out->ngroups = i;
        free(full);
        return 0;
    }
    if (ng < 1) {
        gids[0] = pw->pw_gid;
        ng = 1;
    }
    for (i = 0; i < ng && i < XROOTD_IDMAP_MAXGROUPS; i++) {
        out->groups[i] = gids[i];
    }
    out->ngroups = i;
    return 0;
}

/*
 * The single authoritative reserved-id test (declared in impersonate.h, used by
 * BOTH this mapping layer and the broker's syscall-edge guard).  A credential set
 * is "privileged" — and must be REFUSED — if its primary uid, primary gid, or ANY
 * supplementary gid is 0 or strictly below `floor`, or if ngroups is out of
 * range.  Pure: no syscalls, no globals.
 */
int
xrootd_imp_creds_privileged(const xrootd_idmap_creds_t *cr, uid_t floor,
                            uint32_t *out_id, char *out_kind)
{
    int i;

    if (cr == NULL) {
        if (out_id != NULL)   { *out_id = 0; }
        if (out_kind != NULL) { *out_kind = 'n'; }
        return 1;
    }
    if (cr->ngroups < 0 || cr->ngroups > XROOTD_IDMAP_MAXGROUPS) {
        if (out_id != NULL)   { *out_id = (uint32_t) cr->ngroups; }
        if (out_kind != NULL) { *out_kind = 'n'; }
        return 1;
    }
    if (cr->uid == 0 || cr->uid < floor) {
        if (out_id != NULL)   { *out_id = (uint32_t) cr->uid; }
        if (out_kind != NULL) { *out_kind = 'u'; }
        return 1;
    }
    if (cr->gid == 0 || cr->gid < (gid_t) floor) {
        if (out_id != NULL)   { *out_id = (uint32_t) cr->gid; }
        if (out_kind != NULL) { *out_kind = 'g'; }
        return 1;
    }
    for (i = 0; i < cr->ngroups; i++) {
        if (cr->groups[i] == 0 || cr->groups[i] < (gid_t) floor) {
            if (out_id != NULL)   { *out_id = (uint32_t) cr->groups[i]; }
            if (out_kind != NULL) { *out_kind = 's'; }
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Deny-lists (forbidden target users + privileged groups)             */
/* ------------------------------------------------------------------ */

/* Append uid to the forbidden-uid set (dedup, bounded). */
static void
idmap_forbid_uid(uid_t uid)
{
    int i;

    for (i = 0; i < idmap_forbidden_uids_n; i++) {
        if (idmap_forbidden_uids[i] == uid) {
            return;
        }
    }
    if (idmap_forbidden_uids_n < IDMAP_FORBID_MAX) {
        idmap_forbidden_uids[idmap_forbidden_uids_n++] = uid;
    }
}

/* Append gid to the forbidden-gid set (dedup, bounded). */
static void
idmap_forbid_gid(gid_t gid)
{
    int i;

    for (i = 0; i < idmap_forbidden_gids_n; i++) {
        if (idmap_forbidden_gids[i] == gid) {
            return;
        }
    }
    if (idmap_forbidden_gids_n < IDMAP_FORBID_MAX) {
        idmap_forbidden_gids[idmap_forbidden_gids_n++] = gid;
    }
}

/*
 * Parse a comma/whitespace-separated NAME list and resolve each name to a numeric
 * id via the supplied resolver, adding it to the matching forbidden set.  `is_user`
 * selects getpwnam (uid) vs getgrnam (gid).  Names that do not resolve on this host
 * are skipped (a privileged group absent here cannot be a target anyway).  `list`
 * is "" => use the built-in default.
 */
static void
idmap_forbid_load(const char *list, const char *def, int is_user, ngx_log_t *log)
{
    const char *p = (list != NULL && list[0] != '\0') ? list : def;
    char        name[256];

    while (*p != '\0') {
        size_t n = 0;

        while (*p == ',' || *p == ' ' || *p == '\t') { p++; }
        while (*p != '\0' && *p != ',' && *p != ' ' && *p != '\t'
               && n < sizeof(name) - 1)
        {
            name[n++] = *p++;
        }
        name[n] = '\0';
        while (*p != '\0' && *p != ',' && *p != ' ' && *p != '\t') { p++; }
        if (n == 0) {
            continue;
        }
        if (is_user) {
            struct passwd *pw = getpwnam(name);
            if (pw != NULL) {
                idmap_forbid_uid(pw->pw_uid);
            }
        } else {
            struct group *gr = getgrnam(name);
            if (gr != NULL) {
                idmap_forbid_gid(gr->gr_gid);
            }
        }
    }
    (void) log;
}

/* True if uid is an explicitly forbidden impersonation target. */
static int
idmap_uid_forbidden(uid_t uid)
{
    int i;

    for (i = 0; i < idmap_forbidden_uids_n; i++) {
        if (idmap_forbidden_uids[i] == uid) {
            return 1;
        }
    }
    return 0;
}

/* True if any of the creds' gids (primary or supplementary) is a forbidden
 * (privileged) group — even when its numeric gid is >= the floor. */
static int
idmap_creds_have_forbidden_group(const xrootd_idmap_creds_t *cr)
{
    int i, j;

    for (j = 0; j < idmap_forbidden_gids_n; j++) {
        if (cr->gid == idmap_forbidden_gids[j]) {
            return 1;
        }
        for (i = 0; i < cr->ngroups; i++) {
            if (cr->groups[i] == idmap_forbidden_gids[j]) {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Accept these creds as an impersonation target only if NONE of:
 *   - any reserved/floor id (uid/primary gid/supplementary gid < floor or 0),
 *   - the target uid is an explicitly forbidden account (service/system),
 *   - the user is a member of a forbidden privileged group (sudo/wheel/...).
 */
static int
idmap_creds_allowed(const xrootd_idmap_creds_t *cr)
{
    return !xrootd_imp_creds_privileged(cr, idmap_min_uid, NULL, NULL)
        && !idmap_uid_forbidden(cr->uid)
        && !idmap_creds_have_forbidden_group(cr);
}

/* ------------------------------------------------------------------ */
/* Cache                                                               */
/* ------------------------------------------------------------------ */

static ngx_uint_t
idmap_hash(const char *s)
{
    ngx_uint_t h = 5381;

    while (*s) {
        h = ((h << 5) + h) ^ (ngx_uint_t) (unsigned char) *s++;  /* djb2-xor */
    }
    return h & (IDMAP_CACHE_SLOTS - 1);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_idmap_init(const xrootd_idmap_conf_t *conf, ngx_log_t *log)
{
    if (conf == NULL) {
        return NGX_ERROR;
    }

    idmap_ttl     = (conf->cache_ttl > 0) ? (time_t) conf->cache_ttl
                                          : XROOTD_IDMAP_DEFAULT_TTL;
    idmap_min_uid = (conf->min_uid > 0) ? conf->min_uid
                                        : XROOTD_IDMAP_DEFAULT_MIN_UID;
    /*
     * Clamp the effective floor UP to the absolute hard floor: ids below
     * XROOTD_IMP_HARD_MIN_ID can never be impersonated, even if an admin sets a
     * lower xrootd_idmap_min_uid.  (A lower value would in any case be caught at
     * the broker's syscall edge; clamping here turns it into a clean deny instead
     * of a fatal broker abort.)
     */
    if (idmap_min_uid < XROOTD_IMP_HARD_MIN_ID) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "impersonate: xrootd_idmap_min_uid %d raised to the hard "
                          "reserved-id floor %d (uids/gids below %d can never be "
                          "impersonated)", (int) idmap_min_uid,
                          XROOTD_IMP_HARD_MIN_ID, XROOTD_IMP_HARD_MIN_ID);
        }
        idmap_min_uid = XROOTD_IMP_HARD_MIN_ID;
    }
    idmap_primary_only = conf->primary_only ? 1 : 0;

    /*
     * Resolve the deny-lists (account names -> uids, privileged group names ->
     * gids) once, here.  Reset first so a hot-reload re-reads them.  The nginx
     * worker uid is ALWAYS forbidden as a target so the gateway cannot be
     * impersonated as itself.  Names are taken from config or the built-in
     * defaults; unresolved names are skipped.
     */
    idmap_forbidden_uids_n = 0;
    idmap_forbidden_gids_n = 0;
    {
        char  buf[1024];
        const char *users  = NULL;
        if (conf->forbidden_users.len > 0
            && conf->forbidden_users.len < sizeof(buf)) {
            ngx_memcpy(buf, conf->forbidden_users.data, conf->forbidden_users.len);
            buf[conf->forbidden_users.len] = '\0';
            users = buf;
        }
        idmap_forbid_load(users, XROOTD_IMP_DEFAULT_FORBIDDEN_USERS, 1, log);
    }
    {
        char  buf[1024];
        const char *groups = NULL;
        if (conf->forbidden_groups.len > 0
            && conf->forbidden_groups.len < sizeof(buf)) {
            ngx_memcpy(buf, conf->forbidden_groups.data, conf->forbidden_groups.len);
            buf[conf->forbidden_groups.len] = '\0';
            groups = buf;
        }
        idmap_forbid_load(groups, XROOTD_IMP_DEFAULT_FORBIDDEN_GROUPS, 0, log);
    }
    if (conf->worker_uid != 0 && conf->worker_uid != (uid_t) NGX_CONF_UNSET_UINT) {
        idmap_forbid_uid(conf->worker_uid);
    }
    if (log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "impersonate: deny-lists loaded (%d forbidden uids, %d "
                      "forbidden gids)", idmap_forbidden_uids_n,
                      idmap_forbidden_gids_n);
        if (idmap_forbidden_uids_n >= IDMAP_FORBID_MAX
            || idmap_forbidden_gids_n >= IDMAP_FORBID_MAX) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "impersonate: forbidden deny-list hit the %d-entry cap; "
                          "names beyond it were NOT enforced — reduce the list or "
                          "raise IDMAP_FORBID_MAX", IDMAP_FORBID_MAX);
        }
    }

    idmap_default_user[0] = '\0';
    if (conf->default_user.len > 0
        && conf->default_user.len < sizeof(idmap_default_user))
    {
        ngx_memcpy(idmap_default_user, conf->default_user.data,
                   conf->default_user.len);
        idmap_default_user[conf->default_user.len] = '\0';
    }

    ngx_memzero(idmap_cache, sizeof(idmap_cache));    /* drop the cache */

    {
        char  pbuf[IDMAP_PRINC_MAX];
        const char *path = NULL;
        if (conf->gridmap_path.len > 0
            && conf->gridmap_path.len < sizeof(pbuf))
        {
            ngx_memcpy(pbuf, conf->gridmap_path.data, conf->gridmap_path.len);
            pbuf[conf->gridmap_path.len] = '\0';
            path = pbuf;
        }
        return idmap_gridmap_load(path, log);
    }
}

ngx_int_t
xrootd_idmap_resolve(const xrootd_idmap_conf_t *conf, const char *principal,
                     xrootd_idmap_creds_t *out, ngx_log_t *log)
{
    idmap_cache_slot_t *slot;
    const char         *user;
    xrootd_idmap_creds_t creds;
    time_t              now;
    int                 rc;

    (void) conf;        /* config is installed via xrootd_idmap_init() */

    if (principal == NULL || out == NULL
        || principal[0] == '\0' || ngx_strlen(principal) >= IDMAP_PRINC_MAX)
    {
        return XROOTD_IDMAP_DENY;
    }

    now  = time(NULL);
    slot = &idmap_cache[idmap_hash(principal)];

    /* Cache hit on the same principal, not expired. */
    if (slot->expiry > now && strcmp(slot->principal, principal) == 0) {
        if (slot->rc == XROOTD_IDMAP_OK || slot->rc == XROOTD_IDMAP_SQUASH) {
            *out = slot->creds;
        }
        return slot->rc;
    }

    /* (1) grid-mapfile, else (2) the principal as a literal username. */
    user = idmap_gridmap_lookup(principal);
    if (user == NULL) {
        user = principal;
    }

    rc = XROOTD_IDMAP_DENY;
    if (idmap_resolve_user(user, &creds) == 0 && idmap_creds_allowed(&creds)) {
        rc = XROOTD_IDMAP_OK;
    } else if (idmap_default_user[0] != '\0'
               && idmap_resolve_user(idmap_default_user, &creds) == 0
               && idmap_creds_allowed(&creds))
    {
        rc = XROOTD_IDMAP_SQUASH;       /* unmapped/forbidden -> squash account */
    }

    if (rc != XROOTD_IDMAP_OK && rc != XROOTD_IDMAP_SQUASH && log != NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "impersonate: no UNIX mapping for principal \"%s\" "
                      "(user=\"%s\") -> deny", principal, user);
    }

    /* Cache the verdict (incl. denies, to bound repeated NSS misses). */
    ngx_memcpy(slot->principal, principal, ngx_strlen(principal) + 1);
    slot->rc     = rc;
    slot->expiry = now + idmap_ttl;
    if (rc == XROOTD_IDMAP_OK || rc == XROOTD_IDMAP_SQUASH) {
        slot->creds = creds;
        *out = creds;
    }
    return rc;
}
