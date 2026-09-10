/*
 * xrootdfs_identity.c — per-caller SSS identity for a multi-user mount.
 *
 * WHAT: xfs_ident_pool() and xfs_ident_mgr() hand back the metadata pool and
 *       the data manager belonging to the uid of the FUSE request currently
 *       being served, building them on first use.  With --sss-identity off
 *       they return the mount-wide g_pool / g_mgr and nothing changes.
 * WHY:  one FUSE process serves every user on the box.  The sss authenticator
 *       named the process owner (getpwuid(geteuid()) in sec_sss.c), so under
 *       `allow_other` every caller reached the server wearing the MOUNT
 *       OWNER's identity — user B reading user A's files with the server's
 *       blessing.  A connection cannot change identity after kXR_login, so the
 *       identity must partition the connections rather than ride on them.
 * HOW:  a mutex-guarded fixed table of (uid -> name, opts, pool, mgr).  Slots
 *       are never reused, so a pointer handed to a caller stays valid until
 *       unmount and no operation can have its connections freed underneath it;
 *       the price is a hard cap, and a mount that exceeds it REFUSES the extra
 *       identities (see xfs_ident_pool) rather than quietly serving them as the
 *       mount owner.  Creation happens outside the lock behind a per-slot
 *       `creating` flag so one user's slow connect cannot stall every other
 *       user's metadata op.  Same shape and lifetime as the g_pool/g_mgr pair
 *       it shards, and as the registry in client/lib/net/forksafe.c.
 *
 * The identity is only ever a PROPOSAL.  The server's keytab decides whether
 * the sss NAME TLV is honoured at all: a key with a fixed `user=` ignores it
 * outright and only an `anybody`/`allusers` key accepts it
 * (src/auth/sss/auth_request.c, sss_map_identity).  A mount therefore cannot
 * name its way into an identity the operator did not issue.
 */
#include "xrootdfs_internal.h"

#include <pwd.h>

/* Identities per mount.  Slots are never recycled (see HOW), so this is also
 * the number of distinct users one mount can serve. --max-identities raises it
 * up to XFS_IDENT_HARD_MAX. */
#define XFS_IDENT_DEFAULT_MAX  64
#define XFS_IDENT_HARD_MAX     1024
#define XFS_IDENT_NAME_MAX     64

typedef struct {
    int         used;        /* slot claimed for uid */
    int         creating;    /* a thread is building pool/mgr right now */
    int         failed;      /* the last build attempt failed */
    uid_t       uid;
    char        name[XFS_IDENT_NAME_MAX];
    brix_opts   opts;        /* owns opts.sss_user -> this slot's name */
    brix_pool  *pool;
    brix_mgr   *mgr;
} xfs_ident;

int g_sss_ident;                              /* --sss-identity */
int g_ident_max     = XFS_IDENT_DEFAULT_MAX;  /* --max-identities */
int g_ident_conns   = 2;                      /* per-identity meta pool width */
int g_ident_streams = 1;                      /* per-identity data streams */

static xfs_ident       *g_ident_tab;
static int              g_ident_n;
static pthread_mutex_t  g_ident_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_ident_cond = PTHREAD_COND_INITIALIZER;


/*
 * ident_login_name — resolve uid to its login name.
 *
 * A uid with no passwd entry gets its decimal form: the server still receives a
 * DISTINCT, stable name per caller, which is what keeps two unmapped users from
 * sharing one connection.  It is not an escalation — an unknown name authorises
 * as whatever the operator's keytab says, and typically as nobody.
 */
static void
ident_login_name(uid_t uid, char *out, size_t n)
{
    struct passwd  pw;
    struct passwd *res = NULL;
    char           buf[1024];

    if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) == 0
        && res != NULL && res->pw_name != NULL && res->pw_name[0] != '\0')
    {
        snprintf(out, n, "%s", res->pw_name);
        return;
    }
    snprintf(out, n, "%lu", (unsigned long) uid);
}


/* Find the slot for uid, or NULL.  Caller holds the lock. */
static xfs_ident *
ident_find_locked(uid_t uid)
{
    int i;

    for (i = 0; i < g_ident_n; i++) {
        if (g_ident_tab[i].used && g_ident_tab[i].uid == uid) {
            return &g_ident_tab[i];
        }
    }
    return NULL;
}


/* Claim a fresh slot for uid, or NULL when the table is full.  Holds lock. */
static xfs_ident *
ident_claim_locked(uid_t uid)
{
    xfs_ident *e;

    if (g_ident_n >= g_ident_max) {
        return NULL;
    }
    e = &g_ident_tab[g_ident_n++];
    memset(e, 0, sizeof(*e));
    e->used     = 1;
    e->creating = 1;
    e->uid      = uid;
    return e;
}


/*
 * ident_build — connect this identity's pool and manager.  Runs OUTSIDE the
 * table lock; the slot's `creating` flag keeps every other thread off it.
 */
static void
ident_build(xfs_ident *e)
{
    brix_status st;

    ident_login_name(e->uid, e->name, sizeof(e->name));

    e->opts = g_opts;
    e->opts.sss_user = e->name;

    brix_status_clear(&st);
    e->pool = brix_pool_create(&g_url, &e->opts, g_ident_conns, &st);
    if (e->pool == NULL) {
        fprintf(stderr, "xrootdfs: identity %s (uid %lu): meta pool: %s\n",
                e->name, (unsigned long) e->uid, st.msg);
        e->failed = 1;
        return;
    }

    brix_status_clear(&st);
    e->mgr = brix_mgr_create(&g_url, &e->opts, g_ident_streams, g_ident_streams,
                             g_max_stall, g_keepalive, g_max_retries, &st);
    if (e->mgr == NULL) {
        fprintf(stderr, "xrootdfs: identity %s (uid %lu): data manager: %s\n",
                e->name, (unsigned long) e->uid, st.msg);
        brix_pool_destroy(e->pool);
        e->pool   = NULL;
        e->failed = 1;
    }
}


/*
 * ident_get — the slot for uid, fully built, or NULL.
 *
 * NULL means "this mount cannot serve that identity" — the table is full or the
 * connect failed.  The callers turn that into a refusal; none of them fall back
 * to the mount-wide connections, because doing the work under the wrong
 * identity is the exact failure this file exists to prevent.
 */
static xfs_ident *
ident_get(uid_t uid)
{
    xfs_ident *e;

    pthread_mutex_lock(&g_ident_lock);

    for ( ;; ) {
        e = ident_find_locked(uid);
        if (e == NULL) {
            e = ident_claim_locked(uid);
            if (e == NULL) {
                pthread_mutex_unlock(&g_ident_lock);
                return NULL;             /* table full — refuse, never fall back */
            }
            break;                       /* this thread builds it */
        }
        if (!e->creating) {
            pthread_mutex_unlock(&g_ident_lock);
            return e->failed ? NULL : e;
        }
        pthread_cond_wait(&g_ident_cond, &g_ident_lock);
    }

    pthread_mutex_unlock(&g_ident_lock);

    ident_build(e);

    pthread_mutex_lock(&g_ident_lock);
    e->creating = 0;
    pthread_cond_broadcast(&g_ident_cond);
    pthread_mutex_unlock(&g_ident_lock);

    return e->failed ? NULL : e;
}


/* The uid of the request being served, or the process's own outside FUSE. */
static uid_t
ident_caller_uid(void)
{
    struct fuse_context *fc = fuse_get_context();

    return (fc != NULL) ? fc->uid : geteuid();
}


/* Did uid fail for want of a slot (rather than a failed connect)?  Checked only
 * on the error path, so the extra lock round costs nothing in the common case. */
static int
ident_full(uid_t uid)
{
    int full;

    pthread_mutex_lock(&g_ident_lock);
    full = (ident_find_locked(uid) == NULL && g_ident_n >= g_ident_max);
    pthread_mutex_unlock(&g_ident_lock);
    return full;
}


int
xfs_ident_init(void)
{
    if (!g_sss_ident) {
        return 0;
    }
    if (g_ident_max < 1) {
        g_ident_max = 1;
    }
    if (g_ident_max > XFS_IDENT_HARD_MAX) {
        g_ident_max = XFS_IDENT_HARD_MAX;
    }
    g_ident_tab = calloc((size_t) g_ident_max, sizeof(*g_ident_tab));
    if (g_ident_tab == NULL) {
        fprintf(stderr, "xrootdfs: identity table: out of memory\n");
        return -1;
    }
    return 0;
}


/*
 * xfs_ident_get — this caller's connections, or a negative errno.
 *
 * Returns 0 with the pool/mgr out-params set.  The two failures are told apart
 * because they mean different things in a log: -EMFILE is an operator
 * capacity limit (raise --max-identities), -EACCES is this identity failing to
 * connect or authenticate.  Neither ever yields the mount-wide connections:
 * serving a request under the wrong identity is the bug this file exists to
 * prevent, so the request is refused instead.  Either out-pointer may be NULL.
 */
int
xfs_ident_get(brix_pool **pool, brix_mgr **mgr)
{
    xfs_ident *e;
    uid_t      uid;

    if (!g_sss_ident) {
        if (pool != NULL) { *pool = g_pool; }
        if (mgr  != NULL) { *mgr  = g_mgr;  }
        return 0;
    }

    uid = ident_caller_uid();
    e = ident_get(uid);
    if (e == NULL) {
        return ident_full(uid) ? -EMFILE : -EACCES;
    }
    if (pool != NULL) { *pool = e->pool; }
    if (mgr  != NULL) { *mgr  = e->mgr;  }
    return 0;
}


void
xfs_ident_shutdown(void)
{
    int i;

    if (g_ident_tab == NULL) {
        return;
    }
    for (i = 0; i < g_ident_n; i++) {
        if (g_ident_tab[i].mgr != NULL) {
            brix_mgr_destroy(g_ident_tab[i].mgr);
        }
        if (g_ident_tab[i].pool != NULL) {
            brix_pool_destroy(g_ident_tab[i].pool);
        }
    }
    free(g_ident_tab);
    g_ident_tab = NULL;
    g_ident_n = 0;
}
