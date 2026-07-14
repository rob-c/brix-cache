/*
 * idmap_denylist.c — local-user resolution + forbidden-id / squash policy.
 *
 * WHAT: Resolves a local username to {uid, gid, supplementary gids}, and enforces
 *   the safety floor + deny-lists (forbidden accounts/groups) that decide whether
 *   a resolved credential set may be impersonated.  Split out of idmap.c (file-
 *   size cap).
 *
 * WHY: The numeric-id safety machinery (reserved-id floor, forbidden uid/gid
 *   sets, group-overflow fail-closed handling) is one cohesive defence-in-depth
 *   concern, separate from the grid-mapfile parsing and the cache/resolve entry.
 *
 * HOW: The forbidden-id sets are private to this translation unit; the mapping
 *   policy globals (idmap_min_uid / idmap_primary_only) are owned by idmap.c and
 *   consulted through idmap_internal.h.  No goto; pure helpers, side effects at
 *   the edges.
 */

#include "impersonate.h"
#include "core/compat/cstr.h"
#include "idmap_internal.h"

#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


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
int
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
int
idmap_creds_allowed(const brix_idmap_creds_t *cr)
{
    return !brix_imp_creds_privileged(cr, idmap_min_uid, NULL, NULL)
        && !idmap_uid_forbidden(cr->uid)
        && !idmap_creds_have_forbidden_group(cr);
}

/*
 * Resolve the deny-lists (account names -> uids, privileged group names ->
 * gids) once, at init.  Reset first so a hot-reload re-reads them.  The nginx
 * worker uid is ALWAYS forbidden as a target so the gateway cannot be
 * impersonated as itself.  Names are taken from config or the built-in
 * defaults; unresolved names are skipped.
 */
void
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
