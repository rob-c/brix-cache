/*
 * server_conf_merge_proxy_net.c — server-block merge for the upstream/proxy and
 * network-fault configuration area.
 *
 * WHAT: Owns brix_merge_srv_proxy_net() (upstream TLS + token, transparent proxy
 *       mode, the write-through origin + prefix rules + decision struct, OCSP,
 *       the Phase-39 network-fault deadlines, and rate-limit rule inheritance),
 *       together with the file-local per-concern helpers it delegates to.
 * WHY:  Split (phase-79 file-size cap) out of the former 1249-line
 *       server_conf.c. The entry point is non-static (declared in
 *       server_conf_internal.h) because the top-level orchestrator in
 *       server_conf.c calls it last in linear order — after the cache fields it
 *       depends on (origin host/port, cache size cap, include-regex) have
 *       settled; every sub-helper stays file-local.
 * HOW:  Standard nginx parent->child inheritance via ngx_conf_merge_* and the
 *       BRIX_MERGE_* macros. The write-through decision struct rebuilds from the
 *       just-merged prefix arrays/size cap/regex; the manager-staleness publish
 *       is a config-time side effect that runs once its input settles, exactly
 *       as before. No behaviour change from the split.
 */

#include "config.h"
#include "server_conf_internal.h"
#include "net/manager/registry.h"     /* Phase 39 (WS7): srv staleness setter */

/*
 * WHAT: merge the upstream-TLS + transparent-proxy group (relay guard, proxy
 *       enable/port/auth/login, TLS material, rewrite rules, and the connect/
 *       read/write/keepalive timeouts).
 * WHY:  the proxy login-user name is a fixed char buffer copied by ngx_cpystrn,
 *       not a mergeable str; grouping keeps that special case local.
 * HOW:  inherit the upstream/proxy scalars child<-parent and copy the parent's
 *       login-user name only when the child left it empty.
 */
static void
brix_merge_srv_proxy(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->upstream_tls,          prev->upstream_tls,          0);
    ngx_conf_merge_str_value(conf->upstream_tls_ca,   prev->upstream_tls_ca,   "");
    ngx_conf_merge_str_value(conf->upstream_tls_name, prev->upstream_tls_name, "");
    ngx_conf_merge_str_value(conf->upstream_token_file,
                             prev->upstream_token_file, "");

    ngx_conf_merge_value(conf->relay_guard_enable, prev->relay_guard_enable, 0);
    ngx_conf_merge_value(conf->proxy.enable,       prev->proxy.enable,       0);
    ngx_conf_merge_value(conf->proxy.port,         prev->proxy.port,         1094);
    ngx_conf_merge_value(conf->proxy.upstream_tls, prev->proxy.upstream_tls, 0);
    ngx_conf_merge_uint_value(conf->proxy.auth,    prev->proxy.auth,
                              BRIX_PROXY_AUTH_ANONYMOUS);
    ngx_conf_merge_uint_value(conf->proxy.login_user, prev->proxy.login_user,
                              BRIX_PROXY_LOGIN_ANONYMOUS);
    if (conf->proxy.login_user_name[0] == '\0'
        && prev->proxy.login_user_name[0] != '\0')
    {
        ngx_cpystrn((u_char *) conf->proxy.login_user_name,
                    (u_char *) prev->proxy.login_user_name,
                    sizeof(conf->proxy.login_user_name));
    }
    ngx_conf_merge_str_value(conf->proxy.audit_log,          prev->proxy.audit_log,          "");
    ngx_conf_merge_str_value(conf->proxy.upstream_tls_ca,    prev->proxy.upstream_tls_ca,    "");
    ngx_conf_merge_str_value(conf->proxy.upstream_tls_name,  prev->proxy.upstream_tls_name,  "");
    ngx_conf_merge_uint_value(conf->proxy.reconnect_attempts, prev->proxy.reconnect_attempts, 0);
    ngx_conf_merge_str_value(conf->proxy.path_strip, prev->proxy.path_strip, "");
    ngx_conf_merge_str_value(conf->proxy.path_add,   prev->proxy.path_add,   "");
    ngx_conf_merge_msec_value(conf->proxy.connect_timeout,    prev->proxy.connect_timeout,    10000);
    ngx_conf_merge_msec_value(conf->proxy.read_timeout,       prev->proxy.read_timeout,       60000);
    /* Phase 51 (B1): default the upstream write-stall deadline ON (60s) so a
     * slow/backpressured upstream that stops draining our writes can no longer
     * pin the client connection indefinitely.  0 still disables (back-compat). */
    ngx_conf_merge_msec_value(conf->proxy.write_timeout,      prev->proxy.write_timeout,      60000);
    ngx_conf_merge_msec_value(conf->proxy.keepalive_interval, prev->proxy.keepalive_interval, 15000);

    BRIX_MERGE_PTR(conf, prev, proxy.upstreams);
    ngx_conf_merge_str_value(conf->proxy.host, prev->proxy.host, "");
    BRIX_MERGE_HOSTPORT(conf, prev, cache_origin_host, cache_origin_port);
}

/*
 * WHAT: merge the write-through group — enable/mode, origin host/port (falling
 *       back to the cache origin), the deny/allow prefix arrays, and rebuild the
 *       write-through decision struct from the merged inputs.
 * WHY:  the decision struct references the just-merged prefix arrays, cache size
 *       cap, and include-regex, so it must rebuild after they settle.
 * HOW:  merge the wt scalars + prefix arrays (NULL result + non-empty parent/
 *       child ⇒ NGX_CONF_ERROR), then point the decision fn/data/limits at them.
 */
static char *
brix_merge_srv_writethrough(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_array_t *child_wt_deny_prefixes;
    ngx_array_t *child_wt_allow_prefixes;

    ngx_conf_merge_value(conf->wt.enable, prev->wt.enable, 0);
    BRIX_MERGE_ENUM(conf, prev, wt.mode, BRIX_WT_MODE_UNSET, BRIX_WT_MODE_SYNC);
    BRIX_MERGE_HOSTPORT(conf, prev, wt.origin_host, wt.origin_port);
    if (conf->wt.origin_host.len == 0 && conf->cache_origin_host.len > 0) {
        conf->wt.origin_host = conf->cache_origin_host;
        conf->wt.origin_port = conf->cache_origin_port;
    }

    child_wt_deny_prefixes = conf->wt.deny_prefixes;
    conf->wt.deny_prefixes = brix_merge_arrays(cf, prev->wt.deny_prefixes,
                                                  child_wt_deny_prefixes,
                                                  sizeof(brix_wt_prefix_entry_t));
    if (conf->wt.deny_prefixes == NULL
        && (prev->wt.deny_prefixes != NULL || child_wt_deny_prefixes != NULL))
    {
        return NGX_CONF_ERROR;
    }

    child_wt_allow_prefixes = conf->wt.allow_prefixes;
    conf->wt.allow_prefixes = brix_merge_arrays(cf, prev->wt.allow_prefixes,
                                                   child_wt_allow_prefixes,
                                                   sizeof(brix_wt_prefix_entry_t));
    if (conf->wt.allow_prefixes == NULL
        && (prev->wt.allow_prefixes != NULL || child_wt_allow_prefixes != NULL))
    {
        return NGX_CONF_ERROR;
    }

    conf->wt.decision.fn = brix_wt_default_decide;
    conf->wt.decision.user_data = &conf->wt.decision;
    conf->wt.decision.deny_prefixes = conf->wt.deny_prefixes;
    conf->wt.decision.allow_prefixes = conf->wt.allow_prefixes;
    conf->wt.decision.max_write_through_bytes = conf->cache_max_file_size;
    conf->wt.decision.include_regex = conf->include_regex.re;
    conf->wt.decision.include_regex_set = conf->include_regex.set;

    return NGX_CONF_OK;
}

/*
 * WHAT: merge OCSP, the Phase-39 network-fault deadlines, and inherit the
 *       advanced rate-limit rule array; publish the manager staleness threshold.
 * WHY:  the staleness publish is a config-time side effect (before fork) that
 *       must run once inputs settle; grouping keeps it beside its merge.
 * HOW:  delegate OCSP, inherit the deadline scalars (0 == disabled), publish the
 *       staleness threshold when > 0, and inherit rl_rules when the child is NULL.
 */
static void
brix_merge_srv_net_fault(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    brix_ocsp_conf_merge(&conf->ocsp, &prev->ocsp);

    /* ocsp.staple_data/len are populated at init_process, not here */

    /* Phase 39: network-fault resilience — default OFF (0) = no behaviour change.
     * 0 means "disabled"; arm sites all guard on `> 0` (ngx_msec_t is unsigned). */
    ngx_conf_merge_msec_value(conf->read_timeout,      prev->read_timeout,      0);
    ngx_conf_merge_msec_value(conf->handshake_timeout, prev->handshake_timeout, 0);
    ngx_conf_merge_msec_value(conf->send_timeout,      prev->send_timeout,      0);
    ngx_conf_merge_msec_value(conf->tcp_user_timeout,  prev->tcp_user_timeout,  0);
    ngx_conf_merge_value(conf->tcp_keepalive,          prev->tcp_keepalive,     0);
    ngx_conf_merge_str_value(conf->tcp_congestion,     prev->tcp_congestion,    "");
    ngx_conf_merge_uint_value(conf->max_connections,   prev->max_connections,   0);
    ngx_conf_merge_msec_value(conf->manager_stale_after,
                              prev->manager_stale_after, 0);
    /* Phase 39 (WS7): publish the data-server staleness threshold to the shared
     * cluster registry (config-time, before fork).  Guarded so a 0-default block
     * does not disable a sibling that enabled it. */
    if (conf->manager_stale_after > 0) {
        brix_srv_set_stale_after(conf->manager_stale_after);
    }

    /* Phase 39 (WS9): a child server block with no advanced rate-limit rules of
     * its own inherits the parent's (the Phase-20 kv caches above already do;
     * the Phase-25 rl_rules array was previously never inherited). */
    if (conf->rl_rules == NULL) {
        conf->rl_rules = prev->rl_rules;
    }
}

/* Upstream/proxy & network: upstream TLS + token, transparent proxy mode
 * (auth/login/timeouts/rewrite), the write-through origin + prefix rules +
 * decision struct, OCSP, the Phase-39 network-fault deadlines, and rate-limit
 * rule inheritance. */
char *
brix_merge_srv_proxy_net(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    brix_merge_srv_proxy(conf, prev);
    if (brix_merge_srv_writethrough(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    brix_merge_srv_net_fault(conf, prev);

    return NGX_CONF_OK;
}
