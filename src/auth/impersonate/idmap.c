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
 *   strcmp, TTL cache).  The grid-mapfile is parsed once at init into a small
 *   array of (quoted-DN, username) pairs; resolution checks it first, then falls
 *   back to a direct getpwnam.  No goto; pure helpers, side effects at the edges.
 */

#include "impersonate.h"
#include "core/compat/cstr.h"

#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#define IDMAP_CACHE_SLOTS  256
#define IDMAP_DJB2_SEED    5381   /* djb2 hash initial basis */
#define IDMAP_PRINC_MAX    512          /* a GSI DN can be long */

typedef struct {
    char                  principal[IDMAP_PRINC_MAX];
    brix_idmap_creds_t  creds;
    int                   rc;           /* BRIX_IDMAP_OK / SQUASH / DENY */
    time_t                expiry;       /* 0 = empty slot */
} idmap_cache_slot_t;

typedef struct {
    char *dn;                           /* malloc'd quoted-DN key */
    char *user;                         /* malloc'd local username */
} idmap_gridmap_entry_t;

static idmap_cache_slot_t      idmap_cache[IDMAP_CACHE_SLOTS];

static idmap_gridmap_entry_t  *idmap_gridmap;       /* NULL = no mapfile */
static size_t                  idmap_gridmap_n;

static time_t                  idmap_ttl      = BRIX_IDMAP_DEFAULT_TTL;
static uid_t                   idmap_min_uid  = BRIX_IDMAP_DEFAULT_MIN_UID;
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

/* Skip leading spaces/tabs; returns the first non-blank position. */
static const char *
idmap_skip_blanks(const char *p)
{
    while (*p == ' ' || *p == '\t') { p++; }
    return p;
}

/*
 * Scan the leading "<quoted DN>" field of a grid-mapfile line.  Comments (#),
 * blank lines, unquoted and unterminated DNs are all "no field here".  Pure
 * scan: on success sets [*start, *end) to the DN bytes (quotes excluded),
 * advances *pp past the closing quote, and returns 1; returns 0 to skip.
 */
static int
idmap_scan_quoted_dn(const char **pp, const char **start, const char **end)
{
    const char *p = idmap_skip_blanks(*pp);

    if (*p != '"') {
        return 0;                       /* comment, blank, or unquoted -> skip */
    }
    *start = ++p;                       /* after the opening quote */
    while (*p != '"' && *p != '\0' && *p != '\n') { p++; }
    if (*p != '"') {
        return 0;                       /* unterminated quote -> skip */
    }
    *end = p;                           /* at closing quote */
    *pp  = p + 1;
    return 1;
}

/*
 * Scan the local-username field that follows the DN.  Pure scan: sets
 * [*start, *end) to the token and advances *pp; returns 1 on a non-empty
 * username, 0 when the field is missing.
 */
static int
idmap_scan_username(const char **pp, const char **start, const char **end)
{
    const char *p = idmap_skip_blanks(*pp);

    *start = p;
    while (*p != '\0' && *p != '\n' && *p != ' ' && *p != '\t') { p++; }
    *end = p;
    *pp  = p;
    return *end != *start;
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

    if (!idmap_scan_quoted_dn(&p, &dn_start, &dn_end)
        || !idmap_scan_username(&p, &u_start, &u_end)
        || (size_t) (dn_end - dn_start) >= IDMAP_PRINC_MAX)
    {
        return 0;                       /* unusable line -> skip */
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
            /* phase72-fp: read-only stream — fclose result carries no data loss */
            (void) fclose(fp);
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
                /* phase72-fp: read-only stream — fclose result carries no data loss */
                (void) fclose(fp);
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
    /* phase72-fp: read-only stream — fclose result carries no data loss */
    (void) fclose(fp);

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
idmap_resolve_user(const char *user, brix_idmap_creds_t *out)
{
    struct passwd *pw;
    gid_t          gids[BRIX_IDMAP_MAXGROUPS];
    int            ng = BRIX_IDMAP_MAXGROUPS;
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
         * OVERFLOW: the user belongs to MORE than BRIX_IDMAP_MAXGROUPS groups.
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
        for (i = 0; i < total && i < BRIX_IDMAP_MAXGROUPS; i++) {
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
    for (i = 0; i < ng && i < BRIX_IDMAP_MAXGROUPS; i++) {
        out->groups[i] = gids[i];
    }
    out->ngroups = i;
    return 0;
}

/* Fill the OPTIONAL violation-report out-params (offending id + kind letter);
 * either pointer may be NULL.  Pure output plumbing for the privileged test. */
static void
imp_priv_report(uint32_t id, char kind, uint32_t *out_id, char *out_kind)
{
    if (out_id != NULL)   { *out_id = id; }
    if (out_kind != NULL) { *out_kind = kind; }
}

/* True if a numeric uid/gid is reserved: 0 or strictly below the floor. */
static int
imp_id_reserved(uint32_t id, uid_t floor)
{
    return id == 0 || id < (uint32_t) floor;
}

/*
 * The single authoritative reserved-id test (declared in impersonate.h, used by
 * BOTH this mapping layer and the broker's syscall-edge guard).  A credential set
 * is "privileged" — and must be REFUSED — if its primary uid, primary gid, or ANY
 * supplementary gid is 0 or strictly below `floor`, or if ngroups is out of
 * range.  Pure: no syscalls, no globals.
 */
int
brix_imp_creds_privileged(const brix_idmap_creds_t *cr, uid_t floor,
                            uint32_t *out_id, char *out_kind)
{
    int i;

    if (cr == NULL) {
        imp_priv_report(0, 'n', out_id, out_kind);
        return 1;
    }
    if (cr->ngroups < 0 || cr->ngroups > BRIX_IDMAP_MAXGROUPS) {
        imp_priv_report((uint32_t) cr->ngroups, 'n', out_id, out_kind);
        return 1;
    }
    if (imp_id_reserved((uint32_t) cr->uid, floor)) {
        imp_priv_report((uint32_t) cr->uid, 'u', out_id, out_kind);
        return 1;
    }
    if (imp_id_reserved((uint32_t) cr->gid, floor)) {
        imp_priv_report((uint32_t) cr->gid, 'g', out_id, out_kind);
        return 1;
    }
    for (i = 0; i < cr->ngroups; i++) {
        if (imp_id_reserved((uint32_t) cr->groups[i], floor)) {
            imp_priv_report((uint32_t) cr->groups[i], 's', out_id, out_kind);
            return 1;
        }
    }
    return 0;
}


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
 * Pull the NEXT comma/whitespace-separated name from *pp into name[] (NUL
 * terminated, truncated to cap-1; any overlong remainder of the token is
 * consumed).  Advances *pp; returns the copied length, 0 when the list is
 * exhausted.  Pure scan — no lookups.
 */
static size_t
idmap_forbid_next_name(const char **pp, char *name, size_t cap)
{
    const char *p = *pp;
    size_t      n = 0;

    while (*p == ',' || *p == ' ' || *p == '\t') { p++; }
    while (*p != '\0' && *p != ',' && *p != ' ' && *p != '\t' && n < cap - 1) {
        name[n++] = *p++;
    }
    name[n] = '\0';
    while (*p != '\0' && *p != ',' && *p != ' ' && *p != '\t') { p++; }
    *pp = p;
    return n;
}

/* Resolve one account/group NAME to its numeric id (getpwnam vs getgrnam per
 * `is_user`) and append it to the matching forbidden set.  Names that do not
 * resolve on this host are skipped (an absent account cannot be a target). */
static void
idmap_forbid_resolve_name(const char *name, int is_user)
{
    if (is_user) {
        struct passwd *pw = getpwnam(name);
        if (pw != NULL) {
            idmap_forbid_uid(pw->pw_uid);
        }
        return;
    }
    {
        struct group *gr = getgrnam(name);
        if (gr != NULL) {
            idmap_forbid_gid(gr->gr_gid);
        }
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
        if (idmap_forbid_next_name(&p, name, sizeof(name)) == 0) {
            continue;                   /* trailing separators -> re-test end */
        }
        idmap_forbid_resolve_name(name, is_user);
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
idmap_creds_have_forbidden_group(const brix_idmap_creds_t *cr)
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
idmap_creds_allowed(const brix_idmap_creds_t *cr)
{
    return !brix_imp_creds_privileged(cr, idmap_min_uid, NULL, NULL)
        && !idmap_uid_forbidden(cr->uid)
        && !idmap_creds_have_forbidden_group(cr);
}


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

/*
 * Resolve the deny-lists (account names -> uids, privileged group names ->
 * gids) once, at init.  Reset first so a hot-reload re-reads them.  The nginx
 * worker uid is ALWAYS forbidden as a target so the gateway cannot be
 * impersonated as itself.  Names are taken from config or the built-in
 * defaults; unresolved names are skipped.
 */
static void
idmap_init_denylists(const brix_idmap_conf_t *conf, ngx_log_t *log)
{
    char        ubuf[1024], gbuf[1024];
    const char *users  = NULL;
    const char *groups = NULL;

    idmap_forbidden_uids_n = 0;
    idmap_forbidden_gids_n = 0;

    if (conf->forbidden_users.len > 0
        && brix_str_cbuf(ubuf, sizeof(ubuf), &conf->forbidden_users) != NULL) {
        users = ubuf;
    }
    idmap_forbid_load(users, BRIX_IMP_DEFAULT_FORBIDDEN_USERS, 1, log);

    if (conf->forbidden_groups.len > 0
        && brix_str_cbuf(gbuf, sizeof(gbuf), &conf->forbidden_groups) != NULL) {
        groups = gbuf;
    }
    idmap_forbid_load(groups, BRIX_IMP_DEFAULT_FORBIDDEN_GROUPS, 0, log);

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
