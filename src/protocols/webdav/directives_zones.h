/*
 * directives_zones.h — WebDAV shared-memory zone + packet-marking directives (kv/token/auth/revoke caches, rate-limit zones, SciTags pmark)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
#pragma once
    /* Phase 20 KV-zone/token-cache/rate-limit family -> http_common
     * (phase-105 W1): registered once for the whole HTTP plane so the bare
     * names configure s3/cvmfs too instead of silently writing this conf. */

    /* Phase 21 introspection quad -> http_common as bare
     * brix_token_introspect_* (phase-105 W4.1); the revoke-cache zone
     * directive below stays webdav-scoped. */

    /* brix_webdav_revoke_cache zone=<name>; */
    { ngx_string("brix_webdav_revoke_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_revoke_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* SciTags packet marking (brix_pmark*) moved to http_common.c (phase-101 W1):
     * registered once for the whole HTTP plane and adopted into this conf via
     * brix_shared_adopt_unified(), so the family is no longer hand-copied here. */
