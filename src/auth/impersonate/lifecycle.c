/*
 * lifecycle.c — nginx integration glue for per-request UNIX impersonation
 * (phase 40).  See lifecycle.h for the contract.
 *
 * This is the ONLY impersonation file that knows about nginx config/lifecycle
 * types.  It owns one process-global settings block (there is at most one broker
 * per nginx instance), turns the `brix_idmap*` directives into that
 * block, validates the chosen mode, spawns the privileged broker in the master
 * (FRM double-fork, reparented to init), connects the worker client, and sets the
 * broker's target principal per request.  Everything is inert unless the mode is
 * `map`; `off` and `single` add no process, socket, or capability.
 */

#include "core/compat/log_event.h"
#include "lifecycle.h"
#include "impersonate.h"
#include "impersonate_proto.h"
#include "observability/metrics/metrics.h"   /* brix_config_version_publish() */
#include "core/compat/log_diag.h"
#include "lifecycle_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>


extern ngx_uint_t ngx_test_config;       /* set during `nginx -t` */

#define IMP_DEFAULT_SOCKET  "/var/run/xrootd/impersonate.sock"


imp_settings_t imp_settings = {
    BRIX_IMP_OFF, 0,
    ngx_null_string, ngx_null_string, ngx_null_string,
    ngx_null_string, ngx_null_string, ngx_null_string,
    ngx_null_string, ngx_null_string,
    NGX_CONF_UNSET, NGX_CONF_UNSET,
};

/*
 * WHAT: Return the current impersonation mode (BRIX_IMP_OFF, BRIX_IMP_SINGLE, BRIX_IMP_MAP).
 *
 * WHY: Other modules need to check if impersonation is active and which mode without
 *   accessing the global imp_settings directly. This provides a stable API for mode checks
 *   (e.g., skipping impersonated operations when mode is OFF).
 *
 * HOW:
 *   - Return imp_settings.mode (set at config time, read-only after fork)
 */
int
brix_imp_mode(void)
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
brix_imp_conf_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    (void) conf;
    imp_settings.configured = 1;

    if (ngx_strcmp(v[1].data, "off") == 0) {
        imp_settings.mode = BRIX_IMP_OFF;
    } else if (ngx_strcmp(v[1].data, "single") == 0) {
        imp_settings.mode = BRIX_IMP_SINGLE;
    } else if (ngx_strcmp(v[1].data, "map") == 0) {
        imp_settings.mode = BRIX_IMP_MAP;
    } else {
        BRIX_CONF_LOG(NGX_LOG_EMERG, cf, 0,
                           "invalid brix_idmap mode \"%V\" "
                           "(expected off|single|map)", &v[1]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
brix_imp_conf_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *v = cf->args->elts;
    ngx_str_t *dst;

    (void) conf;
    imp_settings.configured = 1;

    switch (cmd->offset) {
    case BRIX_IMP_F_SOCKET:           dst = &imp_settings.socket;           break;
    case BRIX_IMP_F_EXPORT_ROOT:      dst = &imp_settings.export_root;      break;
    case BRIX_IMP_F_GRIDMAP:          dst = &imp_settings.gridmap;          break;
    case BRIX_IMP_F_DEFAULT_USER:     dst = &imp_settings.default_user;     break;
    case BRIX_IMP_F_SINGLE_USER:      dst = &imp_settings.single_user;      break;
    case BRIX_IMP_F_BROKER_USER:      dst = &imp_settings.broker_user;      break;
    case BRIX_IMP_F_FORBIDDEN_USERS:  dst = &imp_settings.forbidden_users;  break;
    case BRIX_IMP_F_FORBIDDEN_GROUPS: dst = &imp_settings.forbidden_groups; break;
    default:
        return "has an unknown target field";
    }
    return imp_dup(cf, &v[1], dst);
}

char *
brix_imp_conf_num(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *v = cf->args->elts;
    ngx_int_t  n;

    (void) conf;
    imp_settings.configured = 1;

    n = ngx_atoi(v[1].data, v[1].len);
    if (n == NGX_ERROR || n < 0) {
        BRIX_CONF_LOG(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &v[1]);
        return NGX_CONF_ERROR;
    }
    switch (cmd->offset) {
    case BRIX_IMP_F_MIN_UID:   imp_settings.min_uid   = n; break;
    case BRIX_IMP_F_CACHE_TTL: imp_settings.cache_ttl = n; break;
    default:
        return "has an unknown target field";
    }
    return NGX_CONF_OK;
}


ngx_int_t
brix_imp_validate(ngx_conf_t *cf, const char *derived_export_root)
{
    if (!imp_settings.configured || imp_settings.mode == BRIX_IMP_OFF) {
        imp_settings.mode = imp_settings.configured ? imp_settings.mode
                                                     : BRIX_IMP_OFF;
        return NGX_OK;
    }

    if (imp_settings.mode == BRIX_IMP_SINGLE) {
        if (imp_settings.single_user.len == 0) {
            BRIX_CONF_LOG(NGX_LOG_EMERG, cf, 0,
                "brix_idmap single requires "
                "brix_idmap_user <name>");
            return NGX_ERROR;
        }
        if (imp_settings.gridmap.len || imp_settings.default_user.len) {
            BRIX_CONF_LOG(NGX_LOG_WARN, cf, 0,
                "brix_idmap single ignores gridmap/default_user "
                "(all identities squash to \"%V\")", &imp_settings.single_user);
        }
        return NGX_OK;
    }

    /* mode == map */
    if (geteuid() != 0) {
        BRIX_CONF_LOG(NGX_LOG_EMERG, cf, 0,
            "brix_idmap map requires the nginx master to run as root "
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
            BRIX_CONF_LOG(NGX_LOG_EMERG, cf, 0,
                "brix_idmap map needs an export root: set "
                "brix_idmap_export <path> (no data server with a "
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

/* ---- brix_worker_user: the confined account the worker is forced down to ----
 *
 * Process-global (there is one worker uid per process; the strictest posture is
 * shared across every brix server, stream + http). Empty => unset => default to
 * "nobody" with a startup warning. Set by the `brix_worker_user` directive. */
char brix_worker_user[64] = "";

/* ---- Store the configured confined worker account ----
 *
 * WHAT: Accept a bounded nonempty account name or return a configuration error.
 * WHY: Configuration-time identity selection is separate from privilege drops.
 * HOW: 1. Validate length. 2. Copy and terminate the existing process setting.
 */
char *
brix_conf_set_worker_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;

    (void) cmd;
    (void) conf;

    if (value[1].len == 0 || value[1].len >= sizeof(brix_worker_user)) {
        return "invalid brix_worker_user account name";
    }
    /* Last non-empty setting wins; the account is resolved at worker init. */
    ngx_memcpy(brix_worker_user, value[1].data, value[1].len);
    brix_worker_user[value[1].len] = '\0';
    return NGX_CONF_OK;
}

/* ---- brix_imp_worker_runtime_ids ----
 *
 * WHAT: Resolve the uid/gid the workers actually serve as (see lifecycle.h).
 * WHY:  Config-time provisioning of worker-writable directories (the default
 *       credential store, the default gateway stage spool) must chown to the
 *       POST-de-escalation identity: with the always-on drop, `user root` (or
 *       no `user` at all under a root master) yields workers running as
 *       brix_worker_user/nobody, and a root:0700 directory would EACCES them.
 * HOW:  A real unprivileged `user` account wins (the drop no-ops for it);
 *       otherwise resolve brix_worker_user (default "nobody") exactly as
 *       brix_imp_worker_deescalate will at worker init. */
ngx_int_t
brix_imp_worker_runtime_ids(ngx_uid_t conf_uid, ngx_gid_t conf_gid,
    uid_t *uid_out, gid_t *gid_out)
{
    const char    *acct;
    struct passwd *pw;

    if (conf_uid != (ngx_uid_t) NGX_CONF_UNSET_UINT && conf_uid != 0) {
        *uid_out = (uid_t) conf_uid;
        *gid_out = (gid_t) conf_gid;
        return NGX_OK;
    }

    /* nginx fills an omitted `user` directive from its compile-time
     * --user/--group defaults only in the core module's init_conf, after
     * location merges have already asked us to provision stage/credential
     * stores.  At that earlier point ccf->user is still UNSET.  Resolve the
     * same compiled account here so distro builds such as Fedora's
     * --user=nginx do not get a nobody-owned 0700 store for an nginx worker.
     * An explicitly root-capable worker must still take the fail-closed
     * brix_worker_user/nobody path below. */
    if (conf_uid == (ngx_uid_t) NGX_CONF_UNSET_UINT) {
        pw = getpwnam(NGX_USER);
        if (pw != NULL && pw->pw_uid != 0) {
            *uid_out = pw->pw_uid;
            *gid_out = pw->pw_gid;
            return NGX_OK;
        }
    }
    acct = brix_worker_user[0] ? brix_worker_user : "nobody";
    pw   = getpwnam(acct);
    if (pw == NULL || pw->pw_uid == 0) {
        return NGX_ERROR;
    }
    *uid_out = pw->pw_uid;
    *gid_out = pw->pw_gid;
    return NGX_OK;
}
