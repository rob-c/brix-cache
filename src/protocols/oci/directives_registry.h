/*
 * directives_registry.h — the local registry (push) directive family (§0.6.2).
 * #included into ngx_http_brix_oci_commands[] in oci/oci_module.c (the
 * compiler concatenates; the setters stay visible). Not a standalone TU.
 */
#pragma once

    /* "brix_oci_registry on" — the full Distribution API against local VFS
     * storage, and the content-handler install for this location. */
    { ngx_string("brix_oci_registry"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      oci_conf_registry,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, registry),
      NULL },

    /* Store root override; must resolve inside the export. */
    { ngx_string("brix_oci_registry_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, registry_root),
      NULL },

    /* SciTokens issuer table authorising pushes (the authenticated context
     * brix_oci_registry demands unless TLS proves the client). */
    { ngx_string("brix_oci_token_issuers"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, token_issuers),
      NULL },

    /* The typed decision to run an open push registry (a lab fixture, or a
     * deployment fronted by something else that authenticates). */
    { ngx_string("brix_oci_registry_allow_anonymous"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, registry_anon),
      NULL },

    /* Hard cap on a single blob; 0 = unlimited. */
    { ngx_string("brix_oci_max_blob_size"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, max_blob),
      NULL },

    /* Idle upload sessions older than this are reapable. */
    { ngx_string("brix_oci_upload_grace"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, upload_grace),
      NULL },

    /* The registry's own mark-and-sweep, on a maintenance timer. 0 (the
     * default) leaves the store to `brixoci gc` and a cron job. */
    { ngx_string("brix_oci_gc_interval"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, gc_interval),
      NULL },

    /* How long an unreferenced blob is kept before that sweep may take it —
     * the window a push whose manifest has not landed yet lives in. */
    { ngx_string("brix_oci_gc_grace"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, gc_grace),
      NULL },
