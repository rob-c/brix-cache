/*
 * http_directives_auth.h — authorization (XrdAcc/authdb), x509/VOMS/CRL, TPC-guard and token
 * directive entries for the unified HTTP plane.  #included into the
 * brix_http_common_commands[] array in http_common.c so the family is
 * reviewable as one focused file instead of buried in a 770-line table
 * (same idiom as src/protocols/root/stream/directives_*.h).  Not a
 * standalone TU: textual array-member fragments that rely on the setters
 * and enum tables visible in http_common.c.
 */
#pragma once

    /* XrdAcc engine entry point + tunables (phase-101 W2/W5): the whole
     * brix_acc_* family used to live in webdav/module_acc_directives.c as
     * dual-conf-poking setters (hand-parsed, webdav+s3 only, cvmfs excluded).
     * Registered once here on the STANDARD generic slots — the acc block is now
     * in the shared preamble (common.acc) and adopted into every HTTP protocol
     * conf.  W5 (2026-08-10): the engine entry and its three format/audit/refresh
     * tuners are spelled brix_acc_* so prefix == engine on HTTP — bare brix_authdb
     * now means the NATIVE u/g/p engine (webdav), matching the stream reference
     * plane, and XrdAcc is reached only through brix_acc_*.  See the W5 rename
     * in docs/refactor/phase-101-config-surface-unification.md. */
    { ngx_string("brix_acc_authdb"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.authdb), NULL },
    { ngx_string("brix_acc_format"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.format),
      &brix_acc_format_modes },
    { ngx_string("brix_acc_audit"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.audit),
      &brix_acc_audit_modes },
    { ngx_string("brix_acc_refresh"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.refresh), NULL },
    { ngx_string("brix_acc_gidlifetime"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.gidlifetime), NULL },
    { ngx_string("brix_acc_pgo"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.pgo), NULL },
    { ngx_string("brix_acc_nisdomain"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.nisdomain), NULL },
    { ngx_string("brix_acc_resolve_hosts"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.resolve_hosts), NULL },
    { ngx_string("brix_acc_spacechar"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.spacechar), NULL },
    { ngx_string("brix_acc_encoding"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.encoding), NULL },
    { ngx_string("brix_acc_gidretran"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.acc.gidretran), NULL },

    /* ZIP member serving (phase-101 W4): brix_webdav_zip_* and brix_s3_zip_*
     * were byte-parallel twins; one bare pair now covers both HTTP protocols
     * (the stream plane already had bare brix_zip_*). */
    { ngx_string("brix_zip_access"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.zip_access), NULL },
    { ngx_string("brix_zip_cd_max_bytes"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.zip_cd_max_bytes), NULL },

    /* HTTP basic-auth password db (phase-101 W4): was brix_webdav_pwd_file; the
     * stream plane already used the bare name. One spelling both planes. */
    { ngx_string("brix_pwd_file"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pwd_file), NULL },

    /* Resumable Content-Range PUT (phase-101 W4): was brix_webdav_upload_resume. */
    { ngx_string("brix_upload_resume"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.upload_resume), NULL },

    /* Macaroon HMAC secrets (phase-101 W4): were brix_webdav_macaroon_secret[_old];
     * bare on the stream plane already. */
    { ngx_string("brix_macaroon_secret"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_macaroon_secret), NULL },
    { ngx_string("brix_macaroon_secret_old"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_macaroon_secret_old), NULL },

    /* Upload staging device (phase-101 W4): was brix_webdav_stage_dir. */
    { ngx_string("brix_stage_dir"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.upload_stage_dir), NULL },

    /* pblock stripe size (phase-101 W4): was brix_webdav_pblock_block_size; the
     * field already lived in the preamble, only the registration moves. */
    { ngx_string("brix_pblock_block_size"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pblock_block_size), NULL },

    /* x509 CRL family (phase-101 W4): were brix_webdav_crl / _crl_mode /
     * _signing_policy; bare on the stream plane already. */
    { ngx_string("brix_crl"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.crl), NULL },
    { ngx_string("brix_crl_mode"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.crl_mode),
      &brix_http_crl_modes },
    { ngx_string("brix_signing_policy"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.signing_policy_mode),
      &brix_http_signing_policy_modes },

    /* VOMS AC trust dirs (phase-101 W4): were brix_webdav_vomsdir /
     * brix_webdav_voms_cert_dir; bare on the stream plane already. */
    { ngx_string("brix_vomsdir"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.vomsdir), NULL },
    { ngx_string("brix_voms_cert_dir"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.voms_cert_dir), NULL },

    /* VO-membership path ACL (phase-101 W4): was the webdav-local
     * brix_webdav_require_vo; bare on the stream plane already. Custom array
     * setter (shared grammar in policy.c) appends to common.vo_rules; honored on
     * webdav/root where VOMS applies, parsed-but-inert on s3 (SigV4). */
    { ngx_string("brix_require_vo"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE2, brix_http_conf_set_require_vo,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, NULL },

    /* Native u/g/p/h READ-ACL (phase-101 W5.2): the bare brix_authdb (native
     * engine — the XrdAcc engine is brix_acc_authdb) moves from webdav's
     * loc-conf table to the common module so it registers once on every HTTP
     * plane and parses into the shared preamble (common.authdb_rules).  Enforced
     * in webdav's AND s3's access phases (W5.2c) + root:// on stream.  cvmfs is
     * not gated (its read-through/CAS path model has no local realpath). */
    { ngx_string("brix_authdb"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, brix_http_conf_set_authdb,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, NULL },

    /* Per-host credential-source binding (phase-101 W4): was brix_webdav_protbind;
     * bare on the stream plane already. Shared engine (src/auth/protbind/) parses
     * identically on every plane; the array now lives in common.protbind. */
    { ngx_string("brix_protbind"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_2MORE, brix_http_conf_set_protbind,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, NULL },

    /* HTTP-TPC SSRF + source-allowlist policy (phase-101 W4): were
     * brix_webdav_tpc_{allow_local,allow_private,source_guard,source_allow,
     * require_source_size}; bare on the stream plane already. Honored by the
     * webdav curl-COPY engine; fields now in common.tpc_*. (brix_tpc_verify_
     * checksum is NOT unified here — it is a flag on stream but an <alg> string
     * on webdav, an OP decision deferred from W4.) */
    { ngx_string("brix_tpc_allow_local"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tpc_allow_local), NULL },
    { ngx_string("brix_tpc_allow_private"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tpc_allow_private), NULL },
    { ngx_string("brix_tpc_source_guard"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tpc_source_guard), NULL },
    { ngx_string("brix_tpc_source_allow"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_1MORE, brix_http_conf_tpc_source_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, NULL },
    { ngx_string("brix_tpc_require_source_size"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tpc_require_source_size), NULL },
    /* Post-copy TPC integrity (phase-101 W4): unifies the stream flag
     * brix_tpc_verify_checksum and the webdav <alg> brix_webdav_tpc_verify_checksum
     * into one on|off|<alg> grammar (shared setter in policy.c). */
    { ngx_string("brix_tpc_verify_checksum"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, brix_conf_set_tpc_verify_checksum,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, NULL },

    /* WLCG token trust config (phase-101 W4): the jwks/issuer/audience/clock_skew
     * quartet was byte-parallel on webdav and s3; one bare set now covers both
     * (the auth-mode SELECTORS brix_webdav_auth / brix_s3_token are deliberately
     * NOT unified). Per-worker jwks_keys[] loads stay protocol-local. */
    { ngx_string("brix_token_jwks"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_jwks), NULL },
    { ngx_string("brix_token_issuer"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_issuer), NULL },
    { ngx_string("brix_token_audience"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_audience), NULL },
    { ngx_string("brix_token_clock_skew"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_clock_skew), NULL },
    /* Multi-issuer SciTokens registry file (phase-101 W4): was
     * brix_webdav_token_config; bare on the stream plane already. Overrides the
     * single-issuer jwks/issuer/audience fields when set. */
    { ngx_string("brix_token_config"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_config), NULL },


    /* OIDC token introspection / revocation quad (phase-105 W4.1): were the
     * brix_webdav_token_introspect_* names — 101 Table 1 planned the bare
     * spellings. The introspection access handler is globally registered and
     * gates on introspect_loc + a Bearer header, so the settings belong to
     * the plane; the verdict cache (brix_webdav_revoke_cache) stays
     * webdav-scoped. ttl upgraded num->sec_slot in the same move (101-W7
     * discipline). */
    { ngx_string("brix_token_introspect_url"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.introspect_url), NULL },
    { ngx_string("brix_token_introspect_loc"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.introspect_loc), NULL },
    { ngx_string("brix_token_introspect_ttl"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.introspect_ttl), NULL },
    { ngx_string("brix_token_introspect_fail_open"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.introspect_fail_open), NULL },
