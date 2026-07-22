/*
 * postconfig_proxy_capath.c - brix_proxy_ssl_capath second-half location walk.
 *
 * WHAT: Post-merge half of the brix_proxy_ssl_capath directive — walks every
 * finalised location of every server block and, where the directive is set,
 * adds the hashed CA directory to that location's upstream (proxy_ssl) trust
 * store. Extracted verbatim from postconfig.c so both translation units stay
 * under the file-size guard.
 *
 * WHY: The upstream SSL_CTX does not exist until the stock proxy module's merge,
 * so the directive's parse-time handler can only seed a single <hash>.N file
 * through proxy_ssl_trusted_certificate; the whole hashed-directory lookup can
 * only be attached here, after all merges, from the postconfiguration hook.
 *
 * HOW: webdav_postconf_setup_proxy_capath() (the sole entry point, declared in
 * postconfig_internal.h) iterates cmcf->servers and drives the mutually
 * recursive location/tree walkers below, which mirror proto_exclusive.c's walk
 * of the finalised static-location trees / regex + named location arrays.
 */

#include "webdav.h"
#include "postconfig_internal.h"

/* The stock proxy module: its ctx_index locates the (private) proxy loc-conf
 * in each location's conf array; ngx_http_upstream_conf_t is that struct's
 * FIRST member, so a first-member cast reaches the public upstream conf. */
extern ngx_module_t  ngx_http_proxy_module;


/*
 * webdav_postconf_proxy_capath_apply - add one location's hashed CA dir to
 * its upstream (proxy_ssl) trust store.
 *
 * WHAT: For a single location conf array, when brix_proxy_ssl_capath is set,
 * add the directory as an OpenSSL hashed lookup to the location's upstream
 * SSL_CTX; NGX_OK when unset. Fatal (NGX_ERROR) when the location has no
 * https proxy_pass — the directive would otherwise silently protect nothing.
 *
 * WHY: second half of brix_proxy_ssl_capath (see module_directives.c): the
 * parse-time handler could only seed one <hash>.N file through the stock
 * proxy_ssl_trusted_certificate slot, because the upstream SSL_CTX does not
 * exist until the proxy module's merge. Here — after all merges — the ctx is
 * live, so the whole directory becomes a verify-time hashed lookup: every CA
 * in /etc/grid-security/certificates is trusted and IGTF package updates are
 * picked up without a reload.
 *
 * HOW: reads the webdav loc-conf for the capath, then casts the proxy
 * module's private loc-conf to its public first member
 * (ngx_http_upstream_conf_t) to reach upstream->ssl->ctx. The ssl object is
 * per-location here, not shared: injecting the trusted-certificate seed made
 * this location "SSL-configured", so the proxy merge gave it its own ctx.
 * X509_STORE_load_locations(store, NULL, dir) appends the hash-dir lookup
 * (additive — the seeded file stays trusted). Conf tokens and
 * ngx_conf_full_name results are NUL-terminated, so capath->data is a valid
 * C string.
 */
static ngx_int_t
webdav_postconf_proxy_capath_apply(ngx_conf_t *cf, void **loc_conf,
                                   ngx_str_t *name)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf;
    ngx_http_upstream_conf_t          *ucf;
    X509_STORE                        *store;

    wlcf = loc_conf[ngx_http_brix_webdav_module.ctx_index];
    if (wlcf == NULL || wlcf->proxy_ssl_capath.len == 0) {
        return NGX_OK;
    }

    ucf = loc_conf[ngx_http_proxy_module.ctx_index];

    if (ucf == NULL || ucf->ssl == NULL || ucf->ssl->ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "brix_proxy_ssl_capath in location \"%V\" requires "
                      "\"proxy_pass https://...\" in the same location",
                      name);
        return NGX_ERROR;
    }

    store = SSL_CTX_get_cert_store(ucf->ssl->ctx);
    if (store == NULL
        || X509_STORE_load_locations(store, NULL,
                        (const char *) wlcf->proxy_ssl_capath.data) != 1)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "brix_proxy_ssl_capath \"%V\": cannot add hashed "
                      "CA-directory lookup to the upstream trust store",
                      &wlcf->proxy_ssl_capath);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "brix_webdav: added hashed CA dir \"%V\" to the upstream "
                  "(proxy_ssl) trust store for location %V",
                  &wlcf->proxy_ssl_capath, name);
    return NGX_OK;
}


/* Forward declaration: location and tree walkers are mutually recursive
 * (same finalised-structures walk as proto_exclusive.c — the raw
 * clcf->locations queue is unreliable after init_static_location_trees). */
static ngx_int_t webdav_postconf_proxy_capath_location(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *clcf);


static ngx_int_t
webdav_postconf_proxy_capath_loc_array(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t **arr)
{
    ngx_uint_t  i;

    if (arr == NULL) {
        return NGX_OK;
    }
    for (i = 0; arr[i] != NULL; i++) {
        if (webdav_postconf_proxy_capath_location(cf, arr[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


static ngx_int_t
webdav_postconf_proxy_capath_tree(ngx_conf_t *cf,
    ngx_http_location_tree_node_t *node)
{
    if (node == NULL) {
        return NGX_OK;
    }

    if (node->exact != NULL
        && webdav_postconf_proxy_capath_location(cf, node->exact) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (node->inclusive != NULL
        && webdav_postconf_proxy_capath_location(cf, node->inclusive)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_postconf_proxy_capath_tree(cf, node->left) != NGX_OK
        || webdav_postconf_proxy_capath_tree(cf, node->tree) != NGX_OK
        || webdav_postconf_proxy_capath_tree(cf, node->right) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


static ngx_int_t
webdav_postconf_proxy_capath_location(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *clcf)
{
    if (webdav_postconf_proxy_capath_apply(cf, clcf->loc_conf, &clcf->name)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (webdav_postconf_proxy_capath_tree(cf, clcf->static_locations)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_PCRE)
    if (webdav_postconf_proxy_capath_loc_array(cf, clcf->regex_locations)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
#endif
    return NGX_OK;
}


/*
 * webdav_postconf_setup_proxy_capath - walk every location of every server
 * and apply the brix_proxy_ssl_capath second half where the directive is set.
 * The directive is location-only (never merged), so the server-level conf
 * array cannot carry it; only the finalised location structures are walked.
 */
ngx_int_t
webdav_postconf_setup_proxy_capath(ngx_conf_t *cf,
                                   ngx_http_core_main_conf_t *cmcf)
{
    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_uint_t                 s;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (webdav_postconf_proxy_capath_tree(cf, clcf->static_locations)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

#if (NGX_PCRE)
        if (webdav_postconf_proxy_capath_loc_array(cf,
                clcf->regex_locations) != NGX_OK)
        {
            return NGX_ERROR;
        }
#endif

        if (webdav_postconf_proxy_capath_loc_array(cf,
                cscfp[s]->named_locations) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
