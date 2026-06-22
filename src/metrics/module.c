#include "metrics_internal.h"

/*
 * WHAT: Define the HTTP metrics module — a standalone nginx HTTP sub-module that exports
 *      Prometheus-format counters from the shared-memory zone created by config.c.
 * WHY: The stream-side module writes atomic counters into shm_zone->data; this HTTP module
 *      reads those counters via ngx_atomic_fetch_add(..., 0) and emits them as Prometheus
 *      text exposition lines on the /metrics endpoint. Separate modules keep concerns clean.
 * HOW: Create/merge location config for the `xrootd_metrics` directive (boolean flag);
 *      register handler function ngx_http_xrootd_metrics_handler; define module context with
 *      no pre/postconfig or main/srv hooks since this is purely a location-level feature.
 */

/*
 * WHAT: Allocate and initialize the per-location metrics config structure.
 * WHY: NGX_CONF_UNSET sentinel tells merge_loc_conf that the value hasn't been set yet,
 *      so it falls back to the parent (server block) default of 0 (disabled).
 * HOW: ngx_pcalloc zero-initializes from nginx pool; set enable=NGX_CONF_UNSET.
 */

static void *
ngx_http_xrootd_metrics_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_metrics_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) { return NULL; }
    conf->enable = NGX_CONF_UNSET;
    conf->health = NGX_CONF_UNSET;
    return conf;
}

/*
 * WHAT: Merge location-level config with parent server-block defaults.
 * WHY: nginx configuration hierarchy flows main→srv→loc; merge ensures unset values
 *      inherit from the nearest ancestor rather than defaulting to zero everywhere.
 * HOW: ngx_conf_merge_value propagates prev->enable into conf->enable if conf->enable
 *      is NGX_CONF_UNSET; otherwise keeps the location-specific override. Returns NGX_CONF_OK.
 */

static char *
ngx_http_xrootd_metrics_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_xrootd_metrics_loc_conf_t *prev = parent;
    ngx_http_xrootd_metrics_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->health, prev->health, 0);
    return NGX_CONF_OK;
}

/*
 * WHAT: Register the `xrootd_metrics` directive and bind its content handler.
 * WHY: The directive enables the /metrics Prometheus export endpoint at this location.
 *      When enabled, nginx calls ngx_http_xrootd_metrics_handler for all requests to this path.
 * HOW: First call ngx_conf_set_flag_slot to parse the boolean flag value; then set clcf->handler
 *      to our content handler so nginx dispatches /metrics requests here instead of its default.
 */

static char *
ngx_http_xrootd_metrics_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_metrics_handler;
    return NGX_CONF_OK;
}

/*
 * WHAT: Parse the `xrootd_health` flag and bind the /healthz content handler.
 * WHY: phase-47 W2 — give load balancers and Kubernetes liveness/readiness
 *      probes a cheap HTTP endpoint.  Co-located in the metrics module so it
 *      needs no new .so and reuses the same loc-conf lifecycle.
 * HOW: ngx_conf_set_flag_slot stores conf->health; then point this location's
 *      core handler at ngx_http_xrootd_health_handler so GET /healthz is served
 *      here instead of nginx's static-file default.
 */

static char *
ngx_http_xrootd_health_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_health_handler;
    return NGX_CONF_OK;
}

/*
 * WHAT: Define the `xrootd_metrics` nginx directive for location-level configuration.
 * WHY: One flag-based directive enables or disables the Prometheus metrics endpoint per location.
 *      No additional parameters needed — just "on" or "off".
 * HOW: NGX_HTTP_LOC_CONF means this directive applies at location level; NGX_CONF_FLAG indicates
 *      it accepts a boolean value (on/off); offset points to conf->enable field in loc_conf_t.
 */

static ngx_command_t ngx_http_xrootd_metrics_commands[] = {

    { ngx_string("xrootd_metrics"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_metrics_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_metrics_loc_conf_t, enable),
      NULL },

    { ngx_string("xrootd_health"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_health_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_metrics_loc_conf_t, health),
      NULL },

    ngx_null_command
};

/*
 * WHAT: Module context for the HTTP metrics sub-module.
 * WHY: This module is purely location-level — no pre/post configuration, main or server hooks needed.
 *      The lifecycle only involves creating and merging per-location config structures.
 * HOW: Set create_loc_conf and merge_loc_conf callbacks; all other slots remain NULL since this
 *      module has no broader nginx lifecycle responsibilities beyond serving the /metrics endpoint.
 */

static ngx_http_module_t ngx_http_xrootd_metrics_module_ctx = {
    NULL,                                      /* preconfiguration    */
    NULL,                                      /* postconfiguration   */
    NULL,                                      /* create main conf    */
    NULL,                                      /* init main conf      */
    NULL,                                      /* create srv conf     */
    NULL,                                      /* merge srv conf      */
    ngx_http_xrootd_metrics_create_loc_conf,   /* create loc conf     */
    ngx_http_xrootd_metrics_merge_loc_conf     /* merge loc conf      */
};

/*
 * WHAT: Final module definition — registers this as an HTTP-level nginx sub-module.
 * WHY: NGX_HTTP_MODULE type tells nginx to invoke this during the HTTP phase lifecycle only;
 *      it never participates in stream-level operations (those are handled by config.c via
 *      the stream module's shared-memory zone setup).
 * HOW: Standard ngx_module_t layout with context pointer, command table, and module type.
 */

ngx_module_t ngx_http_xrootd_metrics_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_metrics_module_ctx,
    ngx_http_xrootd_metrics_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
