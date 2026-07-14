/*
 * lifecycle.c — nginx integration glue for per-request UNIX impersonation
 * (phase 40).  See lifecycle.h for the contract.
 *
 * This is the ONLY impersonation file that knows about nginx config/lifecycle
 * types.  It owns one process-global settings block (there is at most one broker
 * per nginx instance), turns the `brix_impersonation*` directives into that
 * block, validates the chosen mode, spawns the privileged broker in the master
 * (FRM double-fork, reparented to init), connects the worker client, and sets the
 * broker's target principal per request.  Everything is inert unless the mode is
 * `map`; `off` and `single` add no process, socket, or capability.
 */

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


imp_settings_t imp_settings = {
    BRIX_IMP_OFF, 0,
    ngx_null_string, ngx_null_string, ngx_null_string,
    ngx_null_string, ngx_null_string, ngx_null_string,
    ngx_null_string, ngx_null_string,
    NGX_CONF_UNSET, NGX_CONF_UNSET,
};

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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid brix_impersonation mode \"%V\" "
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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
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
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_impersonation single requires "
                "brix_impersonation_user <name>");
            return NGX_ERROR;
        }
        if (imp_settings.gridmap.len || imp_settings.default_user.len) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix_impersonation single ignores gridmap/default_user "
                "(all identities squash to \"%V\")", &imp_settings.single_user);
        }
        return NGX_OK;
    }

    /* mode == map */
    if (geteuid() != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_impersonation map requires the nginx master to run as root "
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
                "brix_impersonation map needs an export root: set "
                "brix_impersonation_export <path> (no data server with a "
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
