/*
 * directives_net.h — WebDAV clustering/traffic directives (legacy reverse-proxy stubs, WRITE-method mirroring, rate limiting)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
#pragma once
    /* ---- legacy WebDAV reverse-proxy directives DISABLED 2026-06-30 ----
     * (brix_webdav_proxy, _dynamic, _upstream, _max_fails, _fail_timeout,
     * _auth, _connect_timeout, _send_timeout, _read_timeout) are removed ahead of
     * deleting the unused WebDAV upstream-proxy implementation; a config using any
     * of them now fails with nginx "unknown directive". Handlers/runtime remain
     * temporarily, scheduled for removal. NOT affected: brix_webdav_proxy_certs
     * (GSI X.509 RFC-3820 proxy-cert acceptance — an AUTH directive, retained). */

    /* ---- §6.1: HTTP redirect-to-dataserver + signed-CGI handoff ---- */

    /* Manager side: 307-redirect GET/HEAD/PUT to the CMS-registry-selected
     * data server instead of serving locally. */
    /* §6.5: map an incoming HTTP header into the xrd opaque as
     * "&<cgikey>=<value>" (repeatable), so authz + the backend see it. */
    { ngx_string("brix_webdav_header2cgi"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, header2cgi),
      NULL },

    { ngx_string("brix_webdav_redirect_dataserver"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, redirect_dataserver),
      NULL },

    /* §6.6: render an HTML directory index on a GET of a directory (the
     * XrdHttp "Listing" analog; off = the listingdeny default → 403). */
    { ngx_string("brix_webdav_html_listing"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, html_listing),
      NULL },

    /* §6.6 listingredir analog: a GET on a directory 301-redirects here (the
     * request path is appended) instead of listing; checked before the
     * html_listing render. */
    { ngx_string("brix_webdav_listing_redirect"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, listing_redirect),
      NULL },

    /* §6.11 maxdelay -> bare brix_max_delay on http_common (phase-105 W3):
     * one spelling with the stream plane's ofs.maxdelay analog. */

    /* Target HTTP port on the data servers; 0 (default) = the registry
     * entry's port (stock shared-port model). */
    { ngx_string("brix_webdav_redirect_port"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, redirect_port),
      NULL },

    { ngx_string("brix_webdav_redirect_scheme"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, redirect_scheme),
      brix_webdav_redirect_schemes },

    /* Signed-CGI validity window (seconds; default 120). */
    { ngx_string("brix_webdav_redirect_window"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, redirect_window),
      NULL },

    /* Both sides: shared HMAC key (stock http.secretkey analog).  On the
     * manager it signs the authenticated identity into the redirect CGI; on
     * a data server it verifies and adopts that identity, fail-closed. */
    { ngx_string("brix_webdav_secretkey"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, http_secretkey),
      NULL },

    /* Phase 24 mirror family -> http_common (phase-105 W2): the eight
     * settings names register once for the whole HTTP plane; the engine
     * (net/mirror/) reads the adopted common.mirror off this conf. */

    /* Phase 25 rate-limit-zone/shaping family -> http_common (phase-105 W1):
     * the bare names now configure every HTTP protocol via the shared
     * preamble's rl_rules instead of silently writing this conf. */

    /* (legacy brix_webdav_proxy_*_timeout directives removed — see note above) */

