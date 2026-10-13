/*
 * directives_handoff.h — single-port HTTP/TLS handoff directives.
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * config types and setters remain visible). Not a standalone translation unit.
 */
#pragma once

    /* Splice a non-XRootD client on this stream port to the named local
     * HTTP/WebDAV listener. */
    { ngx_string("brix_http_handoff"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_http_handoff,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_http_handoff_connect_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, http_handoff_connect_timeout),
      NULL },

    { ngx_string("brix_http_handoff_idle_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, http_handoff_idle_timeout),
      NULL },
