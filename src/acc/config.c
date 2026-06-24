/*
 * config.c — xrdacc engine lifecycle: per-worker build + hot-reload timer.
 *
 * WHAT: xrootd_acc_build() parses an authdb file into a fresh table generation
 *   and installs the OS/NIS group tunables + resolvers.  xrootd_acc_init_server()
 *   builds the per-worker tables for a server running `xrootd_authdb_format
 *   xrdacc` and, when a refresh interval is set, arms a timer that re-reads the
 *   file on mtime change and atomically swaps the live tables.
 *
 * WHY: XrdAcc keeps authorization per-process and reloads the authdb without a
 *   restart (acc.authrefresh).  Per-worker tables + a single-threaded event-loop
 *   swap give the same behaviour with no locking.
 *
 * HOW: modelled on the CRL reload timer — ngx_pcalloc an ngx_event_t in the
 *   worker pool, point it at the refresh handler, and re-arm after each fire.
 */

#include "../ngx_xrootd_module.h"
#include "acc.h"

#include <sys/stat.h>

/* Shared directive enum tables (used by the stream, WebDAV and S3 modules). */
ngx_conf_enum_t  xrootd_acc_format_modes[] = {
    { ngx_string("native"), XROOTD_AUTHDB_FORMAT_NATIVE },
    { ngx_string("xrdacc"), XROOTD_AUTHDB_FORMAT_XRDACC },
    { ngx_null_string,      0                            }
};

ngx_conf_enum_t  xrootd_acc_audit_modes[] = {
    { ngx_string("none"),  XROOTD_AUTHDB_AUDIT_NONE  },
    { ngx_string("deny"),  XROOTD_AUTHDB_AUDIT_DENY  },
    { ngx_string("grant"), XROOTD_AUTHDB_AUDIT_GRANT },
    { ngx_string("all"),   XROOTD_AUTHDB_AUDIT_ALL   },
    { ngx_null_string,     0                         }
};

xrootd_acc_tables_t *
xrootd_acc_build(const char *authdb_path, ngx_int_t gidlifetime, ngx_int_t pgo,
                 const char *nisdomain, const char *gidretran, char spacechar,
                 ngx_int_t encoding, ngx_log_t *log)
{
    if (gidlifetime > 0) {
        xrootd_acc_groups_set_gidlifetime((time_t) gidlifetime);
    }
    xrootd_acc_groups_set_primary_only(pgo);
    xrootd_acc_groups_set_nisdomain(nisdomain);
    xrootd_acc_groups_set_gidretran(gidretran);
    xrootd_acc_groups_init();   /* install OS resolvers (idempotent) */

    return xrootd_acc_authfile_parse(log, authdb_path, spacechar, encoding);
}

/* Re-read the authdb when its mtime changes; swap the live tables atomically. */
static void
xrootd_acc_refresh_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t  *xcf = ev->data;
    ngx_file_info_t                fi;

    if (xcf->authdb.len > 0
        && ngx_file_info(xcf->authdb.data, &fi) != NGX_FILE_ERROR)
    {
        time_t mt  = ngx_file_mtime(&fi);
        time_t cur = (xcf->acc_tables != NULL) ? xcf->acc_tables->mtime : 0;

        if (mt != cur) {
            xrootd_acc_tables_t *nt =
                xrootd_acc_build((const char *) xcf->authdb.data,
                                 xcf->acc_gidlifetime, xcf->acc_pgo,
                                 (xcf->acc_nisdomain.len > 0)
                                     ? (const char *) xcf->acc_nisdomain.data
                                     : NULL,
                                 (xcf->acc_gidretran.len > 0)
                                     ? (const char *) xcf->acc_gidretran.data
                                     : NULL,
                                 (xcf->acc_spacechar.len > 0)
                                     ? (char) xcf->acc_spacechar.data[0] : 0,
                                 xcf->acc_encoding,
                                 ev->log);
            if (nt != NULL) {
                xrootd_acc_tables_t *old = xcf->acc_tables;
                xcf->acc_tables = nt;          /* single-threaded: safe swap */
                xrootd_acc_tables_free(old);
                ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                              "xrootd authdb reloaded: %s", xcf->authdb.data);
            }
        }
    }

    if (xcf->acc_refresh > 0 && !ngx_exiting) {
        ngx_add_timer(ev, (ngx_msec_t) xcf->acc_refresh * 1000);
    }
}

/* Build a fresh table generation for an HTTP acc block (honours the tunables). */
static xrootd_acc_tables_t *
xrootd_acc_http_build(xrootd_acc_http_t *acc, ngx_log_t *log)
{
    return xrootd_acc_build((const char *) acc->authdb.data,
                            acc->gidlifetime, acc->pgo,
                            (acc->nisdomain.len > 0)
                                ? (const char *) acc->nisdomain.data : NULL,
                            (acc->gidretran.len > 0)
                                ? (const char *) acc->gidretran.data : NULL,
                            (acc->spacechar.len > 0)
                                ? (char) acc->spacechar.data[0] : 0,
                            acc->encoding,
                            log);
}

/*
 * HTTP hot-reload timer — the loc-conf analogue of xrootd_acc_refresh_handler.
 * ev->data is the xrootd_acc_http_t (embedded in the loc-conf, so it outlives
 * every request); on mtime change it rebuilds and atomically swaps acc->tables.
 */
static void
xrootd_acc_http_refresh_handler(ngx_event_t *ev)
{
    xrootd_acc_http_t  *acc = ev->data;
    ngx_file_info_t     fi;

    if (acc->authdb.len > 0
        && ngx_file_info(acc->authdb.data, &fi) != NGX_FILE_ERROR)
    {
        time_t mt  = ngx_file_mtime(&fi);
        time_t cur = (acc->tables != NULL) ? acc->tables->mtime : 0;

        if (mt != cur) {
            xrootd_acc_tables_t *nt = xrootd_acc_http_build(acc, ev->log);
            if (nt != NULL) {
                xrootd_acc_tables_t *old = acc->tables;
                acc->tables = nt;              /* single-threaded: safe swap */
                xrootd_acc_tables_free(old);
                ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                              "xrootd authdb reloaded: %s", acc->authdb.data);
            }
        }
    }

    if (acc->refresh > 0 && !ngx_exiting) {
        ngx_add_timer(ev, (ngx_msec_t) acc->refresh * 1000);
    }
}

/* Arm this worker's refresh timer on first use (no HTTP per-location init hook,
 * so the lazy build is the natural place — see XrdAcc acc.authrefresh). */
static void
xrootd_acc_http_arm_timer(xrootd_acc_http_t *acc)
{
    if (acc->timer_armed || acc->refresh <= 0) {
        return;
    }
    acc->timer_armed   = 1;
    acc->timer.handler = xrootd_acc_http_refresh_handler;
    acc->timer.data    = acc;
    acc->timer.log     = ngx_cycle->log;
    ngx_add_timer(&acc->timer, (ngx_msec_t) acc->refresh * 1000);
}

void
xrootd_acc_http_init_conf(xrootd_acc_http_t *acc)
{
    acc->format        = NGX_CONF_UNSET_UINT;
    acc->audit         = NGX_CONF_UNSET_UINT;
    acc->refresh       = NGX_CONF_UNSET;
    acc->gidlifetime   = NGX_CONF_UNSET;
    acc->pgo           = NGX_CONF_UNSET;
    acc->resolve_hosts = NGX_CONF_UNSET;
    acc->encoding      = NGX_CONF_UNSET;
    /* authdb/nisdomain/spacechar/gidretran default to "" via ngx_pcalloc;
     * tables/timer stay zero. */
}

void
xrootd_acc_http_merge_conf(xrootd_acc_http_t *conf, xrootd_acc_http_t *prev)
{
    ngx_conf_merge_uint_value(conf->format, prev->format,
                              XROOTD_AUTHDB_FORMAT_NATIVE);
    ngx_conf_merge_uint_value(conf->audit, prev->audit,
                              XROOTD_AUTHDB_AUDIT_NONE);
    ngx_conf_merge_str_value(conf->authdb, prev->authdb, "");
    ngx_conf_merge_value(conf->refresh, prev->refresh, 0);
    ngx_conf_merge_value(conf->gidlifetime, prev->gidlifetime, 43200);
    ngx_conf_merge_value(conf->pgo, prev->pgo, 0);
    ngx_conf_merge_str_value(conf->nisdomain, prev->nisdomain, "");
    ngx_conf_merge_value(conf->resolve_hosts, prev->resolve_hosts, 0);
    ngx_conf_merge_value(conf->encoding, prev->encoding, 0);
    ngx_conf_merge_str_value(conf->spacechar, prev->spacechar, "");
    ngx_conf_merge_str_value(conf->gidretran, prev->gidretran, "");
}

ngx_int_t
xrootd_acc_http_authorize(ngx_pool_t *pool, ngx_log_t *log,
    xrootd_acc_http_t *acc, const char *name, const char *host,
    const char *vorg, const char *role, const char *grp,
    xrootd_acc_op_t op, const char *path)
{
    xrootd_acc_entity_t  *ent;
    xrootd_acc_privs_t    privs;

    if (acc->format != XROOTD_AUTHDB_FORMAT_XRDACC) {
        return NGX_DECLINED;    /* engine not selected — caller's checks stand */
    }

    /* Lazy per-worker build: the first request in a worker parses the authdb;
     * the write is COW-private so each worker keeps its own table set. */
    if (acc->tables == NULL) {
        if (acc->authdb.len == 0) {
            return NGX_ERROR;   /* xrdacc selected without an authdb -> deny */
        }
        acc->tables = xrootd_acc_http_build(acc, log);
        if (acc->tables == NULL) {
            return NGX_ERROR;
        }
    }
    xrootd_acc_http_arm_timer(acc);   /* hot-reload, once per worker */

    if (name == NULL) { name = ""; }
    if (host == NULL || *host == '\0') { host = "?"; }
    if (path == NULL) { path = "/"; }

    ent = xrootd_acc_entity_build(pool, name, host, (name[0] != '\0'),
                                  vorg ? vorg : "", role ? role : "",
                                  grp ? grp : "");
    if (ent == NULL) {
        return NGX_ERROR;
    }

    privs = xrootd_acc_access(acc->tables, ent, path, op);
    xrootd_acc_audit(log, acc->audit, privs != XROOTD_ACC_PRIV_NONE,
                     xrootd_acc_op_name(op), name, host, path);

    return (privs != XROOTD_ACC_PRIV_NONE) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
xrootd_acc_init_server(ngx_stream_xrootd_srv_conf_t *xcf, ngx_cycle_t *cycle)
{
    /* Only servers using the xrdacc engine with an authdb file. */
    if (xcf->acc_format != XROOTD_AUTHDB_FORMAT_XRDACC || xcf->authdb.len == 0) {
        return NGX_OK;
    }

    xcf->acc_tables = xrootd_acc_build(
        (const char *) xcf->authdb.data, xcf->acc_gidlifetime, xcf->acc_pgo,
        (xcf->acc_nisdomain.len > 0) ? (const char *) xcf->acc_nisdomain.data
                                     : NULL,
        (xcf->acc_gidretran.len > 0) ? (const char *) xcf->acc_gidretran.data
                                     : NULL,
        (xcf->acc_spacechar.len > 0) ? (char) xcf->acc_spacechar.data[0] : 0,
        xcf->acc_encoding,
        cycle->log);
    if (xcf->acc_tables == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "xrootd: failed to load xrdacc authdb \"%V\"",
                      &xcf->authdb);
        return NGX_ERROR;
    }

    if (xcf->acc_refresh > 0) {
        xcf->acc_timer = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
        if (xcf->acc_timer == NULL) {
            return NGX_ERROR;
        }
        xcf->acc_timer->handler = xrootd_acc_refresh_handler;
        xcf->acc_timer->data    = xcf;
        xcf->acc_timer->log     = cycle->log;
        ngx_add_timer(xcf->acc_timer, (ngx_msec_t) xcf->acc_refresh * 1000);
    }

    return NGX_OK;
}
