#ifndef XROOTD_IMPERSONATE_H
#define XROOTD_IMPERSONATE_H

/*
 * impersonate.h — per-request UNIX impersonation (phase 40).
 *
 * WHAT: Public types + API for mapping an authenticated identity (GSI DN, token
 *   subject, SSS user, krb5 localname) to a concrete local UNIX account
 *   (uid + primary gid + supplementary gids), and the operating-mode constants
 *   for the `xrootd_impersonation off|single|map` directive.
 *
 * WHY: The gateway can optionally execute namespace/open operations with the
 *   credentials of the real local user (so files are owned by, and kernel DAC is
 *   enforced for, that user) instead of the single nginx worker uid.  The mapping
 *   layer here is the first, self-contained piece: pure identity -> {uid,gid,gids}
 *   resolution with a grid-mapfile + getpwnam + policy guards (never map to a
 *   reserved/system uid).  The privileged broker (broker.c) consumes it.
 *
 * HOW: `xrootd_idmap_resolve()` resolves a principal via (1) an optional
 *   grid-mapfile (DN -> local username), (2) a direct getpwnam() of the
 *   principal, then (3) a squash-to-default or deny policy, with a per-process
 *   TTL cache (modelled on src/acc/groups.c).  See docs/refactor/phase-40.
 *
 * Off-by-default: with `xrootd_impersonation off` (the default) NONE of this is
 *   reached — the module behaves exactly as before (single worker uid).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/types.h>          /* uid_t, gid_t, off_t */
#include <sys/stat.h>           /* struct stat (client stat op) */
#include <signal.h>            /* sig_atomic_t */

/* ------------------------------------------------------------------ */
/* Operating mode — xrootd_impersonation off|single|map               */
/* ------------------------------------------------------------------ */
#define XROOTD_IMP_OFF      0   /* default: no broker, no mapping, worker uid    */
#define XROOTD_IMP_SINGLE   1   /* drop-back: all identities squash to one user  */
#define XROOTD_IMP_MAP      2   /* full: per-identity mapping via the root broker */

/* Upper bound on supplementary groups carried with a mapped identity. */
#define XROOTD_IDMAP_MAXGROUPS  32

/* ------------------------------------------------------------------ */
/* Resolution result                                                   */
/* ------------------------------------------------------------------ */
/* xrootd_idmap_resolve() return codes (>= 0).  NGX_ERROR (< 0) = hard error. */
#define XROOTD_IDMAP_OK      0  /* mapped to a concrete account (out filled)     */
#define XROOTD_IDMAP_SQUASH  1  /* no direct map; squashed to default_user       */
#define XROOTD_IDMAP_DENY    2  /* no map + deny policy (out NOT filled)         */

/*
 * The resolved UNIX credentials an operation should run as.  `groups` holds the
 * primary gid followed by the supplementary gids that getgrouplist() returned
 * (deduplicated by the kernel); `ngroups` is how many of `groups` are valid.
 */
typedef struct {
    uid_t  uid;
    gid_t  gid;                                  /* primary group */
    int    ngroups;                              /* entries used in groups[] */
    gid_t  groups[XROOTD_IDMAP_MAXGROUPS];       /* supplementary gids */
} xrootd_idmap_creds_t;

/*
 * Mapping-engine configuration (populated from directives, owned by the broker).
 * All fields are optional; an all-zero struct = "direct getpwnam, deny on miss,
 * default min_uid".
 */
typedef struct {
    ngx_str_t   gridmap_path;   /* [xrootd_gridmap <file>] DN->user; "" = none   */
    ngx_str_t   default_user;   /* [xrootd_idmap_default_user] squash; "" = deny */
    ngx_str_t   single_user;    /* [xrootd_impersonation_user] for SINGLE mode    */
    uid_t       min_uid;        /* [xrootd_idmap_min_uid] refuse uid < this       */
    ngx_int_t   cache_ttl;      /* [xrootd_idmap_cache_ttl] secs; <=0 -> default  */
    ngx_flag_t  primary_only;   /* resolve only the primary group (skip getgrouplist) */
    /*
     * Deny-lists (defence in depth on top of the numeric min_uid floor):
     *   forbidden_users  — account NAMES that may NEVER be an impersonation target
     *                      ("" => XROOTD_IMP_DEFAULT_FORBIDDEN_USERS).
     *   forbidden_groups — privileged group NAMES; a user who is a member of any
     *                      (primary OR supplementary) is refused outright, even
     *                      when the gid is >= min_uid ("" => the built-in default).
     *   worker_uid       — the nginx worker uid: ALWAYS forbidden as a target
     *                      (so the gateway can never be impersonated as itself).
     *                      (uid_t)-1 / NGX_CONF_UNSET_UINT => none to add.
     */
    ngx_str_t   forbidden_users;
    ngx_str_t   forbidden_groups;
    uid_t       worker_uid;
} xrootd_idmap_conf_t;

/* ------------------------------------------------------------------ */
/* API (idmap.c)                                                       */
/* ------------------------------------------------------------------ */

/*
 * Load the grid-mapfile (if configured) and reset the resolution cache.  Safe to
 * call again to reload.  Returns NGX_OK, or NGX_ERROR on a fatal parse/IO error
 * (a missing optional mapfile when gridmap_path is "" is NOT an error).
 */
ngx_int_t xrootd_idmap_init(const xrootd_idmap_conf_t *conf, ngx_log_t *log);

/*
 * Resolve `principal` (the DN / token sub / SSS user) to UNIX credentials.
 *   - grid-mapfile match -> getpwnam(localuser)
 *   - else direct getpwnam(principal)
 *   - else default_user (squash) or deny
 * Enforces the policy floor: a resolved uid that is 0 or < conf->min_uid is
 * REFUSED (returns DENY) — the broker must never impersonate root/system.
 * Returns XROOTD_IDMAP_OK / XROOTD_IDMAP_SQUASH (fills *out) or
 * XROOTD_IDMAP_DENY, or NGX_ERROR (< 0) on hard error.  `log` may be NULL.
 */
ngx_int_t xrootd_idmap_resolve(const xrootd_idmap_conf_t *conf,
                               const char *principal,
                               xrootd_idmap_creds_t *out, ngx_log_t *log);

/* Default reserved-uid floor when conf->min_uid is 0 (refuse system accounts). */
#define XROOTD_IDMAP_DEFAULT_MIN_UID  1000
/* Default resolution-cache TTL (seconds) when conf->cache_ttl <= 0. */
#define XROOTD_IDMAP_DEFAULT_TTL      600

/*
 * ABSOLUTE, compile-time reserved-id floor (uid AND gid).  It is enforced at the
 * privilege-transition syscall edge in the broker REGARDLESS of configuration:
 * the broker will NEVER setfsuid/setfsgid/setgroups to a uid or gid that is 0 or
 * below this value, so a privileged file operation is impossible in the code path
 * even if the mapping layer were misconfigured or bypassed.  The configurable
 * xrootd_idmap_min_uid may RAISE the effective floor, never lower it below this.
 */
#define XROOTD_IMP_HARD_MIN_ID  1000

/*
 * Built-in privileged GROUP names denied as impersonation targets even when their
 * numeric gid is >= the floor (sudo/wheel/docker/lxd can carry high gids on some
 * distros, and membership grants privilege escalation or root-equivalent access).
 * A mapped user who is a member of ANY of these — primary or supplementary — is
 * refused outright.  Override via `xrootd_idmap_forbidden_groups`.
 */
#define XROOTD_IMP_DEFAULT_FORBIDDEN_GROUPS \
    "root,wheel,sudo,su,admin,sudoers,adm,sys,daemon,bin,staff,disk,shadow," \
    "kmem,mem,docker,lxd,libvirt,kvm,systemd-journal,ssl-cert,lpadmin,netdev"

/*
 * Built-in service/system account NAMES denied as impersonation targets.  The
 * nginx worker uid and the broker's OWN uid are ALWAYS forbidden in addition to
 * this list (config-independent, in the broker).  Override via
 * `xrootd_idmap_forbidden_users`.
 */
#define XROOTD_IMP_DEFAULT_FORBIDDEN_USERS \
    "root,daemon,bin,sys,sync,games,man,lp,mail,news,uucp,proxy,backup,list," \
    "nobody,nginx,www-data,xrootd,apache,httpd"

/*
 * The single authoritative reserved-id test, shared by BOTH the mapping layer
 * (idmap.c) and the broker's syscall-edge guard (broker.c) so there is exactly
 * one definition of "privileged".  Returns 1 (privileged — REFUSE) if the primary
 * uid, the primary gid, or ANY supplementary gid is 0 or strictly below `floor`,
 * or if ngroups is out of [0, XROOTD_IDMAP_MAXGROUPS]; returns 0 only when every
 * id is a safe, non-reserved account.  When non-NULL, *out_id receives the first
 * offending id and *out_kind one of 'u' (uid) / 'g' (primary gid) /
 * 's' (supplementary gid) / 'n' (bad ngroups or NULL creds).  Pure function — no
 * syscalls, no globals.
 */
int xrootd_imp_creds_privileged(const xrootd_idmap_creds_t *cr, uid_t floor,
                                uint32_t *out_id, char *out_kind);

/* ------------------------------------------------------------------ */
/* Broker (broker.c) — the privileged root side                        */
/* ------------------------------------------------------------------ */

/*
 * Drop to the minimal capability set required for impersonation:
 * keep only CAP_SETUID + CAP_SETGID (needed for setfsuid/setfsgid/setgroups),
 * drop everything else (crucially CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH /
 * CAP_FOWNER / CAP_CHOWN, whose presence would let the broker bypass the
 * impersonated user's DAC).  Also clears the bounding set and sets
 * NO_NEW_PRIVS.  Returns 0 on success, -1 on failure (the broker MUST refuse to
 * serve if this fails — otherwise impersonation does not enforce DAC).
 */
int xrootd_imp_broker_drop_caps(ngx_log_t *log);

/*
 * Peer-uid gate for the broker's accept loop.  When non-zero, the broker only
 * serves connections whose SO_PEERCRED uid equals this value or 0.  Set it to the
 * unprivileged nginx worker uid before spawning the broker; leave 0 to disable
 * (e.g. the in-namespace test where both ends share an identity).
 */
extern uid_t xrootd_imp_broker_allow_uid;

/*
 * Hyper-hardening: when set to a real uid/gid (not (uid_t)-1), the broker drops
 * its real uid/gid to this dedicated NON-ROOT service account after startup,
 * keeping ONLY CAP_SETUID/CAP_SETGID — so nothing runs as root once serving.  Set
 * by the lifecycle layer (from xrootd_impersonation_broker_user) before
 * xrootd_imp_broker_run; the forked broker inherits them.  (uid_t)-1 => stay root.
 */
extern uid_t xrootd_imp_broker_user_uid;
extern gid_t xrootd_imp_broker_user_gid;

/*
 * Run the broker serve loop on a bound+listening AF_UNIX socket.  `rootfd` is an
 * O_PATH fd on the export root (the authoritative confinement base); the mapping
 * config must already be installed via xrootd_idmap_init().  Calls
 * xrootd_imp_broker_drop_caps() first.  Serves worker connections (one request
 * per readable event, fd returned for OPEN via SCM_RIGHTS) until a fatal error.
 * Returns -1 on setup failure; otherwise loops until `*stop` becomes non-zero
 * (pass NULL to loop until the listen socket errors).
 */
int xrootd_imp_broker_run(int listen_fd, int rootfd,
                          const volatile sig_atomic_t *stop, ngx_log_t *log);

/* ------------------------------------------------------------------ */
/* Worker client (client.c) — the unprivileged worker side             */
/* ------------------------------------------------------------------ */

/*
 * Connect (or lazily reconnect) the calling worker to the broker's AF_UNIX
 * socket at `path`, and mark impersonation routing as enabled for this worker.
 * The path is remembered so a dropped connection (broker respawn) is transparently
 * re-established on the next op.  Returns NGX_OK on success, NGX_ERROR on failure
 * (the caller must fail closed — do NOT silently fall back to local I/O once
 * `map` mode is configured).  `log` may be NULL.
 */
ngx_int_t xrootd_imp_client_connect(const char *path, ngx_log_t *log);

/*
 * Whether confined FS helpers should route through the broker right now: true
 * iff `map` mode was enabled (xrootd_imp_client_connect succeeded at least once)
 * AND a per-request principal is currently set.  When false the beneath helpers
 * run their existing local path (as the worker uid) unchanged — so ops without an
 * authenticated identity, and `off`/`single` mode, are entirely unaffected.
 */
int xrootd_imp_client_active(void);

/*
 * True when impersonation MAP mode is active in this worker (the broker client
 * is wired up), regardless of whether a per-request principal is currently set.
 * Confidentiality gates use this to distinguish "impersonation off entirely"
 * (fall through to the existing non-impersonated gate) from "map mode but no
 * principal yet" (must fail closed — we cannot determine the mapped user's DAC).
 */
int xrootd_imp_enabled(void);

/*
 * Mark the worker as being inside / outside a per-request impersonation bracket.
 * Set on by xrootd_imp_request_begin and off by xrootd_imp_request_end.  It makes
 * xrootd_imp_client_active() route to the broker (which then DENIES) even when the
 * request's identity yielded no mappable principal — so an unmappable/empty-subject
 * request fails closed instead of running as the worker.  Off-request (housekeeping)
 * the flag is clear, so those ops correctly run locally as the worker.
 */
void xrootd_imp_mark_in_request(int on);

/*
 * Set / clear the principal (DN / token sub / sss-user) the broker should
 * impersonate for subsequent ops on this worker.  Set it immediately before
 * dispatching an authenticated op and clear it afterwards.  `principal` is copied
 * (bounded to IMP_PRINC_MAX); NULL or "" clears it.
 */
void xrootd_imp_set_principal(const char *principal);
void xrootd_imp_clear_principal(void);

/*
 * Impersonated filesystem ops — the broker-routed equivalents of the beneath
 * helpers.  Each performs one synchronous request/reply round-trip to the broker,
 * which executes the op as the mapped user under RESOLVE_BENEATH confinement.
 * Return values and errno mirror the local syscalls: open returns an fd (>=0) or
 * -1; the rest return 0 or -1.  A broker DENY surfaces as errno=EACCES, a
 * malformed request as EINVAL, an internal broker failure as EIO; a dropped
 * connection is retried once then fails with EIO.
 */
int xrootd_imp_open(const char *reqpath, int flags, mode_t mode);
int xrootd_imp_stat(const char *reqpath, struct stat *st, int nofollow);
int xrootd_imp_mkdir(const char *reqpath, mode_t mode);
int xrootd_imp_unlink(const char *reqpath, int is_dir);
int xrootd_imp_rmdir(const char *reqpath);
int xrootd_imp_rename(const char *src, const char *dst);
/* renameat2(RENAME_NOREPLACE) as the mapped user: atomic create-if-absent.
 * Returns -1 with errno==EEXIST when dst already exists. */
int xrootd_imp_rename_noreplace(const char *src, const char *dst);
int xrootd_imp_link(const char *src, const char *dst);
int xrootd_imp_truncate(const char *reqpath, off_t length);
int xrootd_imp_chmod(const char *reqpath, mode_t mode);
int xrootd_imp_chown_gid(const char *reqpath, gid_t gid);

/*
 * POSIX-extension ops (kXR_setattr/symlink/readlink, used by the native xrootdfs
 * FUSE driver), brokered so they run as the mapped user too.
 *   setattr  — utimensat (when set_times) + fchownat (when set_owner); a uid/gid
 *              of (uid_t)-1 / (gid_t)-1 leaves that id unchanged.
 *   symlink  — create `linkpath` containing the verbatim `target`.
 *   readlink — read the target of `reqpath` into `buf`; returns the byte count
 *              (NOT NUL-terminated, like readlink(2)) or -1.
 */
int xrootd_imp_setattr(const char *reqpath, int set_times,
                       const struct timespec times[2],
                       int set_owner, uid_t uid, gid_t gid);
int xrootd_imp_symlink(const char *target, const char *linkpath);
ssize_t xrootd_imp_readlink(const char *reqpath, char *buf, size_t bufsz);

/*
 * Extended-attribute ops as the mapped user (broker f{get,set,remove,list}xattr
 * on a RESOLVE_BENEATH-confined fd; restricted to the `user.` namespace).  These
 * mirror the POSIX *xattr contract:
 *   getxattr  — into `buf`; bufsz==0 returns the value size (probe), bufsz too
 *               small returns -1/ERANGE; else returns the byte count.
 *   setxattr  — write `value` (`len` bytes, <= IMP_XATTR_MAX) with `flags`
 *               (XATTR_CREATE/XATTR_REPLACE/0); returns 0 or -1.
 *   removexattr — delete `name`; returns 0 or -1.
 *   listxattr — NUL-separated names into `buf` (same probe/ERANGE rules as get).
 * `name` is the full attribute name (e.g. "user.nginx_xrootd.lock").
 */
ssize_t xrootd_imp_getxattr(const char *reqpath, const char *name,
                            void *buf, size_t bufsz);
int     xrootd_imp_setxattr(const char *reqpath, const char *name,
                            const void *value, size_t len, int flags);
int     xrootd_imp_removexattr(const char *reqpath, const char *name);
ssize_t xrootd_imp_listxattr(const char *reqpath, void *buf, size_t bufsz);

#endif /* XROOTD_IMPERSONATE_H */
