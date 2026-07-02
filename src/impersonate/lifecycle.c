/*
 * lifecycle.c — nginx integration glue for per-request UNIX impersonation
 * (phase 40).  See lifecycle.h for the contract.
 *
 * This is the ONLY impersonation file that knows about nginx config/lifecycle
 * types.  It owns one process-global settings block (there is at most one broker
 * per nginx instance), turns the `xrootd_impersonation*` directives into that
 * block, validates the chosen mode, spawns the privileged broker in the master
 * (FRM double-fork, reparented to init), connects the worker client, and sets the
 * broker's target principal per request.  Everything is inert unless the mode is
 * `map`; `off` and `single` add no process, socket, or capability.
 */

#include "lifecycle.h"
#include "impersonate.h"
#include "impersonate_proto.h"
#include "metrics/metrics.h"   /* xrootd_config_version_publish() */
#include "compat/log_diag.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/capability.h>

extern ngx_uint_t ngx_test_config;       /* set during `nginx -t` */

#define IMP_DEFAULT_SOCKET  "/var/run/xrootd/impersonate.sock"


static struct {
    int        mode;                      /* XROOTD_IMP_OFF/SINGLE/MAP */
    int        configured;                /* any directive parsed */
    ngx_str_t  socket;                    /* map: broker AF_UNIX path */
    ngx_str_t  export_root;               /* map: broker confinement root */
    ngx_str_t  gridmap;                   /* DN->user mapfile */
    ngx_str_t  default_user;              /* squash account ("" => deny) */
    ngx_str_t  single_user;               /* SINGLE: fixed account */
    ngx_str_t  broker_user;               /* MAP: non-root account the broker runs as */
    ngx_str_t  forbidden_users;           /* deny-list of target accounts ("" => default) */
    ngx_str_t  forbidden_groups;          /* deny-list of privileged groups ("" => default) */
    ngx_int_t  min_uid;                   /* reserved-uid floor */
    ngx_int_t  cache_ttl;                 /* resolution cache TTL */
} imp_settings = {
    XROOTD_IMP_OFF, 0,
    ngx_null_string, ngx_null_string, ngx_null_string,
    ngx_null_string, ngx_null_string, ngx_null_string,
    ngx_null_string, ngx_null_string,
    NGX_CONF_UNSET, NGX_CONF_UNSET,
};

int
xrootd_imp_mode(void)
{
    return imp_settings.mode;
}


/* Duplicate a conf token into a NUL-terminated string on cf->pool. */
static char *
imp_dup(ngx_conf_t *cf, ngx_str_t *src, ngx_str_t *dst)
{
    dst->data = ngx_pnalloc(cf->pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return NGX_CONF_OK;
}

char *
xrootd_imp_conf_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    (void) conf;
    imp_settings.configured = 1;

    if (ngx_strcmp(v[1].data, "off") == 0) {
        imp_settings.mode = XROOTD_IMP_OFF;
    } else if (ngx_strcmp(v[1].data, "single") == 0) {
        imp_settings.mode = XROOTD_IMP_SINGLE;
    } else if (ngx_strcmp(v[1].data, "map") == 0) {
        imp_settings.mode = XROOTD_IMP_MAP;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid xrootd_impersonation mode \"%V\" "
                           "(expected off|single|map)", &v[1]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
xrootd_imp_conf_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *v = cf->args->elts;
    ngx_str_t *dst;

    (void) conf;
    imp_settings.configured = 1;

    switch (cmd->offset) {
    case XROOTD_IMP_F_SOCKET:           dst = &imp_settings.socket;           break;
    case XROOTD_IMP_F_EXPORT_ROOT:      dst = &imp_settings.export_root;      break;
    case XROOTD_IMP_F_GRIDMAP:          dst = &imp_settings.gridmap;          break;
    case XROOTD_IMP_F_DEFAULT_USER:     dst = &imp_settings.default_user;     break;
    case XROOTD_IMP_F_SINGLE_USER:      dst = &imp_settings.single_user;      break;
    case XROOTD_IMP_F_BROKER_USER:      dst = &imp_settings.broker_user;      break;
    case XROOTD_IMP_F_FORBIDDEN_USERS:  dst = &imp_settings.forbidden_users;  break;
    case XROOTD_IMP_F_FORBIDDEN_GROUPS: dst = &imp_settings.forbidden_groups; break;
    default:
        return "has an unknown target field";
    }
    return imp_dup(cf, &v[1], dst);
}

char *
xrootd_imp_conf_num(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *v = cf->args->elts;
    ngx_int_t  n;

    (void) conf;
    imp_settings.configured = 1;

    n = ngx_atoi(v[1].data, v[1].len);
    if (n == NGX_ERROR || n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &v[1]);
        return NGX_CONF_ERROR;
    }
    switch (cmd->offset) {
    case XROOTD_IMP_F_MIN_UID:   imp_settings.min_uid   = n; break;
    case XROOTD_IMP_F_CACHE_TTL: imp_settings.cache_ttl = n; break;
    default:
        return "has an unknown target field";
    }
    return NGX_CONF_OK;
}


/* Populate an xrootd_idmap_conf_t from the settings (for xrootd_idmap_init).
 * `worker_uid` is the nginx worker uid to forbid as a target ((uid_t)-1 = none). */
static void
imp_fill_idmap_conf(xrootd_idmap_conf_t *c, uid_t worker_uid)
{
    ngx_memzero(c, sizeof(*c));
    c->gridmap_path     = imp_settings.gridmap;
    c->default_user     = imp_settings.default_user;
    c->single_user      = imp_settings.single_user;
    c->forbidden_users  = imp_settings.forbidden_users;
    c->forbidden_groups = imp_settings.forbidden_groups;
    c->worker_uid       = worker_uid;
    c->min_uid          = (imp_settings.min_uid > 0)
                              ? (uid_t) imp_settings.min_uid : 0;
    c->cache_ttl        = imp_settings.cache_ttl;
}


ngx_int_t
xrootd_imp_validate(ngx_conf_t *cf, const char *derived_export_root)
{
    if (!imp_settings.configured || imp_settings.mode == XROOTD_IMP_OFF) {
        imp_settings.mode = imp_settings.configured ? imp_settings.mode
                                                     : XROOTD_IMP_OFF;
        return NGX_OK;
    }

    if (imp_settings.mode == XROOTD_IMP_SINGLE) {
        if (imp_settings.single_user.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_impersonation single requires "
                "xrootd_impersonation_user <name>");
            return NGX_ERROR;
        }
        if (imp_settings.gridmap.len || imp_settings.default_user.len) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "xrootd_impersonation single ignores gridmap/default_user "
                "(all identities squash to \"%V\")", &imp_settings.single_user);
        }
        return NGX_OK;
    }

    /* mode == map */
    if (geteuid() != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_impersonation map requires the nginx master to run as root "
            "(needed to spawn the privileged identity broker)");
        return NGX_ERROR;
    }
    if (imp_settings.socket.len == 0) {
        ngx_str_t def = ngx_string(IMP_DEFAULT_SOCKET);
        if (imp_dup(cf, &def, &imp_settings.socket) != NGX_CONF_OK) {
            return NGX_ERROR;
        }
    }
    if (imp_settings.export_root.len == 0) {
        if (derived_export_root == NULL || derived_export_root[0] == '\0') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_impersonation map needs an export root: set "
                "xrootd_impersonation_export <path> (no data server with a "
                "local root was found to derive it from)");
            return NGX_ERROR;
        }
        {
            ngx_str_t s;
            s.data = (u_char *) derived_export_root;
            s.len  = ngx_strlen(derived_export_root);
            if (imp_dup(cf, &s, &imp_settings.export_root) != NGX_CONF_OK) {
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}


/* Bind a 0600 listening AF_UNIX socket at `path`, owned by `wuid`. */
static int
imp_make_listen(const char *path, uid_t wuid, ngx_log_t *log)
{
    struct sockaddr_un addr;
    int                lfd;

    if (ngx_strlen(path) >= sizeof(addr.sun_path)) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "impersonate: socket path too long \"%s\"", path);
        return -1;
    }
    lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        return -1;
    }
    unlink(path);
    ngx_memzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    ngx_memcpy(addr.sun_path, path, ngx_strlen(path) + 1);
    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) != 0
        || listen(lfd, 64) != 0)
    {
        XROOTD_DIAG_EMERG(log, ngx_errno,
            "impersonate: cannot bind broker socket \"%s\"",
            "the directory is not writable by the master, or a stale socket "
            "is held by another process",
            "ensure the socket's parent directory exists and is writable; the "
            "OS reason is appended below",
            path);
        close(lfd);
        return -1;
    }
    chmod(path, 0600);
    if (wuid != (uid_t) -1) {
        if (chown(path, wuid, (gid_t) -1) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "impersonate: chown socket to uid %d failed",
                          (int) wuid);
        }
    }
    return lfd;
}

/* Path of the broker pidfile (socket path + ".pid"), into buf. */
static void
imp_pidfile(char *buf, size_t n)
{
    ngx_snprintf((u_char *) buf, n, "%V.pid%Z", &imp_settings.socket);
}

/* Terminate a previously-spawned broker (across reload) if still alive. */
static void
imp_kill_stale_broker(ngx_log_t *log)
{
    char  pf[256];
    FILE *fp;
    long  pid = 0;

    imp_pidfile(pf, sizeof(pf));
    fp = fopen(pf, "re");
    if (fp == NULL) {
        return;
    }
    if (fscanf(fp, "%ld", &pid) == 1 && pid > 1 && kill((pid_t) pid, 0) == 0) {
        kill((pid_t) pid, SIGTERM);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "impersonate: terminated stale broker pid %ld", pid);
    }
    fclose(fp);
    unlink(pf);
}

/* The broker child body (post double-fork): record pid, run the serve loop. */
static void
imp_broker_child(int lfd, int rootfd, ngx_log_t *log)
{
    char  pf[256];
    FILE *fp;

    setsid();
    imp_pidfile(pf, sizeof(pf));
    fp = fopen(pf, "we");
    if (fp != NULL) {
        fprintf(fp, "%ld\n", (long) getpid());
        fclose(fp);
    }
    /* broker_run drops caps to {SETUID,SETGID} then serves until killed. */
    _exit(xrootd_imp_broker_run(lfd, rootfd, NULL, log) == 0 ? 0 : 1);
}

ngx_int_t
xrootd_imp_init_module(ngx_cycle_t *cycle)
{
    ngx_core_conf_t   *ccf;
    xrootd_idmap_conf_t idc;
    sigset_t           block, prev;
    char               sockbuf[256], rootbuf[1024];
    uid_t              wuid;
    int                lfd, rootfd;
    pid_t              inter;

    /*
     * Publish the config/reload fingerprint on every real config load (this is
     * the module's single init_module hook, so it runs once per cycle in the
     * master regardless of impersonation mode).  Skipped under `nginx -t`, which
     * only validates the config and must not bump the live generation counter.
     */
    if (!ngx_test_config) {
        xrootd_config_version_publish(cycle);
    }

    if (imp_settings.mode != XROOTD_IMP_MAP || ngx_test_config) {
        return NGX_OK;
    }
    if (geteuid() != 0) {
        XROOTD_DIAG_EMERG(cycle->log, 0,
            "impersonate: map mode requires a root master process",
            "xrootd_impersonation is set to 'map' but nginx was not started "
            "as root, so it cannot set up the privileged uid-mapping broker",
            "start nginx as root (workers still drop to the configured user), "
            "or change xrootd_impersonation away from 'map'");
        return NGX_ERROR;
    }

    ngx_snprintf((u_char *) sockbuf, sizeof(sockbuf), "%V%Z",
                 &imp_settings.socket);
    ngx_snprintf((u_char *) rootbuf, sizeof(rootbuf), "%V%Z",
                 &imp_settings.export_root);

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    wuid = (ccf && ccf->user != (uid_t) NGX_CONF_UNSET_UINT) ? ccf->user
                                                             : (uid_t) -1;

    /*
     * Resolve the optional non-root broker service account.  When configured, the
     * broker drops its real uid/gid to it (keeping only CAP_SETUID/CAP_SETGID), so
     * nothing runs as root after startup.  Must be a real, non-root, non-worker
     * account.  Set the broker globals BEFORE the fork so the broker inherits them.
     */
    xrootd_imp_broker_user_uid = (uid_t) -1;
    xrootd_imp_broker_user_gid = (gid_t) -1;
    if (imp_settings.broker_user.len > 0) {
        char           nm[256];
        struct passwd *pw;
        ngx_snprintf((u_char *) nm, sizeof(nm), "%V%Z", &imp_settings.broker_user);
        pw = getpwnam(nm);
        if (pw == NULL) {
            XROOTD_DIAG_EMERG(cycle->log, 0,
                "impersonate: broker user \"%s\" does not exist",
                "xrootd_impersonation_broker_user names a local account that "
                "is not present in /etc/passwd (or NSS)",
                "create the dedicated service account first, or correct the "
                "name in the directive",
                nm);
            return NGX_ERROR;
        }
        if (pw->pw_uid == 0 || (wuid != (uid_t) -1 && pw->pw_uid == wuid)) {
            XROOTD_DIAG_EMERG(cycle->log, 0,
                "impersonate: broker user \"%s\" is not a safe choice",
                "the broker account must NOT be root and must differ from the "
                "nginx worker user, so a compromise cannot escalate",
                "point xrootd_impersonation_broker_user at a dedicated, "
                "unprivileged account used for nothing else",
                nm);
            return NGX_ERROR;
        }
        xrootd_imp_broker_user_uid = pw->pw_uid;
        xrootd_imp_broker_user_gid = pw->pw_gid;
    }

    imp_kill_stale_broker(cycle->log);

    /* Install mapping config in THIS (master) process; the broker forks from
     * here and inherits the parsed gridmap + policy. */
    imp_fill_idmap_conf(&idc, wuid);
    if (xrootd_idmap_init(&idc, cycle->log) != NGX_OK) {
        XROOTD_DIAG_EMERG(cycle->log, 0,
            "impersonate: identity map failed to load",
            "the grid-mapfile is missing, unreadable, or malformed",
            "check xrootd_impersonation_gridmap points at a readable "
            "grid-mapfile with valid \"<DN>\" <user> lines");
        return NGX_ERROR;
    }

    lfd = imp_make_listen(sockbuf, wuid, cycle->log);
    if (lfd < 0) {
        return NGX_ERROR;
    }
    rootfd = open(rootbuf, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) {
        XROOTD_DIAG_EMERG(cycle->log, ngx_errno,
            "impersonate: cannot open export root \"%s\"",
            "the export root directory is missing or unreadable by the master",
            "create the directory and ensure the master can open it; the OS "
            "reason is appended below",
            rootbuf);
        close(lfd);
        return NGX_ERROR;
    }

    /* Gate the broker to the worker uid (defence in depth atop confinement). */
    xrootd_imp_broker_allow_uid = (wuid != (uid_t) -1) ? wuid : 0;

    /* Double-fork so nginx never reaps the broker (SHM-safe; FRM pattern). */
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &prev);

    inter = fork();
    if (inter < 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(lfd);
        close(rootfd);
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "impersonate: broker fork failed");
        return NGX_ERROR;
    }
    if (inter == 0) {
        if (fork() == 0) {
            imp_broker_child(lfd, rootfd, cycle->log);   /* never returns */
        }
        _exit(0);                        /* intermediate -> broker reparents */
    }

    close(lfd);
    close(rootfd);
    while (waitpid(inter, NULL, 0) < 0 && errno == EINTR) { }
    sigprocmask(SIG_SETMASK, &prev, NULL);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "impersonate: started privileged broker on \"%s\" "
                  "(export root \"%s\", worker uid %d)",
                  sockbuf, rootbuf, (int) wuid);
    return NGX_OK;
}


/*
 * Hyper-harden the worker: shed the privilege-escalation / DAC-bypass / identity
 * capabilities so a compromised worker can never setfsuid/setgid or override DAC,
 * even if nginx was granted them via file/ambient capabilities to feed the broker.
 * Best-effort: clearing effective+permitted always succeeds; bounding-set drops
 * need CAP_SETPCAP and are skipped (with no error) when already unprivileged.  The
 * worker is a pure broker CLIENT and needs none of these.
 */
static void
imp_worker_drop_caps(ngx_log_t *log)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];
    static const int kill_caps[] = {
        CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_DAC_OVERRIDE,
        CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_CHOWN, CAP_FSETID,
        CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_MKNOD, CAP_SETFCAP,
    };
    unsigned i;

    (void) prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    /* Clear ALL effective + permitted + inheritable capabilities. */
    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;
    if (syscall(SYS_capset, &hdr, data) != 0) {
        if (log) ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                               "impersonate: worker capset(clear) failed "
                               "(continuing — worker is an unprivileged client)");
    }
    /* Best-effort bounding-set drop of the dangerous caps (needs CAP_SETPCAP). */
    for (i = 0; i < sizeof(kill_caps) / sizeof(kill_caps[0]); i++) {
        (void) prctl(PR_CAPBSET_DROP, kill_caps[i], 0, 0, 0);
    }
}

ngx_int_t
xrootd_imp_init_worker(ngx_cycle_t *cycle)
{
    char sockbuf[256];

    if (imp_settings.mode != XROOTD_IMP_MAP) {
        return NGX_OK;                    /* off/single: no client */
    }

    /* Shed privileged caps first — the worker is a pure broker client. */
    imp_worker_drop_caps(cycle->log);

    ngx_snprintf((u_char *) sockbuf, sizeof(sockbuf), "%V%Z",
                 &imp_settings.socket);

    if (xrootd_imp_client_connect(sockbuf, cycle->log) != NGX_OK) {
        /* Broker may still be starting; the client retries lazily per op. */
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "impersonate: broker not reachable yet at \"%s\" "
                      "(will reconnect on first op)", sockbuf);
    }
    return NGX_OK;
}


/* Best principal string for impersonation: DN first, then token subject. */
static const char *
imp_principal_of(const xrootd_identity_t *id)
{
    const char *p = xrootd_identity_dn_cstr(id);

    if (p != NULL && p[0] != '\0') {
        return p;
    }
    p = xrootd_identity_subject_cstr(id);
    return (p != NULL && p[0] != '\0') ? p : NULL;
}

void
xrootd_imp_request_begin(const xrootd_identity_t *id)
{
    if (imp_settings.mode != XROOTD_IMP_MAP) {
        return;
    }
    /* Mark the request active BEFORE setting the principal: even if the identity
     * yields no mappable principal (empty subject), confined ops must route to the
     * broker (which denies) rather than fall back to the worker. */
    xrootd_imp_mark_in_request(1);
    xrootd_imp_set_principal(id != NULL ? imp_principal_of(id) : NULL);
}

void
xrootd_imp_request_end(void)
{
    if (imp_settings.mode != XROOTD_IMP_MAP) {
        return;
    }
    xrootd_imp_clear_principal();
    xrootd_imp_mark_in_request(0);
}
