/*
 * directives_mirror.h — the pull-through mirror directive family (§0.6.1).
 * #included into ngx_http_brix_oci_commands[] in oci/oci_module.c (the
 * compiler concatenates; the setters stay visible). Not a standalone TU.
 */
#pragma once

    /* Marks the location as a mirror of <base-url> AND installs the content
     * handler — the location IS the /v2/ endpoint, exactly as brix_cvmfs
     * installs the cvmfs handler. */
    { ngx_string("brix_oci_mirror"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      oci_conf_mirror,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Basic credentials for the TOKEN endpoint only; the password is read
     * from the file at config load and never appears in the config. */
    { ngx_string("brix_oci_mirror_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      oci_conf_mirror_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Freshness window for TAG-addressed manifests; digest-addressed objects
     * are immutable and ignore it. */
    { ngx_string("brix_oci_manifest_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, manifest_ttl),
      NULL },

    /* The SHM zone holding cached upstream bearer tokens. One zone serves
     * every mirror location; sugar over brix_kv_zone with key=32 val=4096. */
    { ngx_string("brix_oci_token_zone"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE2,
      oci_conf_token_zone,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Name prefix prepended before forwarding (GitLab-style group nesting).
     * Applied after grammar validation, before cache-key derivation. */
    { ngx_string("brix_oci_upstream_namespace"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, upstream_ns),
      NULL },

    /* One extra host a WWW-Authenticate realm may live on. Repeatable; each
     * entry is one exact host, and the derived same-domain rule still applies
     * first, so an allowlist can only ever widen the boundary deliberately. */
    { ngx_string("brix_oci_upstream_auth_realm"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE1,
      oci_conf_auth_realm,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Test fixtures only: permits a cleartext http:// upstream base. */
    { ngx_string("brix_oci_mirror_insecure"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_oci_loc_conf_t, insecure),
      NULL },
