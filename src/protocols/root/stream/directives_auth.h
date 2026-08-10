/*
 * directives_auth.h — authentication directive entries for the root:// stream
 * module.  #included into the ngx_stream_brix_commands[] array in module.c so
 * the auth surface (auth-mode, GSI/x509, CRL, XrdAcc, JWT/token, SSS, Kerberos,
 * unix/host/pwd) is reviewable as one focused file instead of buried in the
 * 1800-line table.  Not a standalone TU: it is textual array-member fragments
 * and relies on the setters / enum tables (module_enums.h) visible in module.c.
 */
#pragma once
    /* Selects the login/auth flow the dispatcher advertises to clients. */
    { ngx_string("brix_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Maps "none" / "gsi" onto BRIX_AUTH_* constants via brix_auth_modes. */
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, auth),
      brix_auth_modes },

    /* Per-host refinement of brix_auth (XRootD sec.protbind): binds an ordered
     * list of auth protocols to a host template.  Repeatable; first matching
     * template wins, so the `*` catch-all goes last. */
    { ngx_string("brix_protbind"),
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      brix_conf_set_protbind,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* brix_certificate / brix_certificate_key / brix_trusted_ca -> owned by
     * ngx_stream_brix_common_module (phase-101 W3 stage 3): the x509 GSI-trust
     * names are shared with the gridftp gateway, so a single stream owner
     * registers them.  This server adopts the values into its own
     * certificate / certificate_key / trusted_ca fields via
     * brix_stream_common_adopt_gsi() at merge (server_conf.c), BEFORE the GSI
     * SSL_CTX + trust-store are built in postconfiguration — every reader
     * (tls_config.c, the auth/gsi builders) is unchanged. */

    /* GSI signed-DH policy: off (default) | auto | require.  Consulted only
     * when brix_auth=gsi; selects the RSA-signed-DH wire variant (phase-48). */
    { ngx_string("brix_gsi_signed_dh"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, gsi_signed_dh),
      brix_signed_dh_modes },

    /* Phase 51 (E4): per-worker concurrent in-flight GSI-handshake cap. */
    { ngx_string("brix_gsi_max_inflight_handshakes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, gsi_max_inflight),
      NULL },

    /* §5.10 (xrd.tlsca verdepth analog): cap the accepted X.509 chain depth for
     * a client's GSI proxy/cert at root:// login. 0 (default) = unlimited. */
    { ngx_string("brix_gsi_verify_depth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, gsi_verify_depth),
      NULL },

    /* Per-worker ephemeral-DH keypool warm target (filled off-thread at boot). */
    { ngx_string("brix_gsi_keypool_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, gsi_keypool_size),
      NULL },

    /* Keys generated synchronously at worker start (rest fill off-thread). */
    { ngx_string("brix_gsi_keypool_seed"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, gsi_keypool_seed),
      NULL },

    /* Phase 52 (WS-A): GSI session-cipher advertise preference list. */
    { ngx_string("brix_gsi_ciphers"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, gsi_ciphers),
      NULL },

    /* brix_vomsdir / brix_voms_cert_dir -> owned by
     * ngx_stream_brix_common_module (phase-101 W3 stage 3); adopted into this
     * server's vomsdir / voms_cert_dir fields at merge via
     * brix_stream_common_adopt_gsi().  Readers (policy.c, auth/gsi/auth_cert.c)
     * unchanged. */

    /* PEM file or directory containing CRLs for certificate revocation checking. */
    { ngx_string("brix_crl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, crl),
      NULL },

    /* Interval (seconds) to re-scan brix_crl and rebuild the CA/CRL store. */
    { ngx_string("brix_crl_reload"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, crl_reload),
      NULL },

    /* Globus signing_policy enforcement: on (default) | off | require.  When a
     * <hash>.signing_policy file sits beside a trusted CA it restricts which
     * subject DNs that CA may sign (WLCG/IGTF namespace rule). */
    { ngx_string("brix_signing_policy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, signing_policy_mode),
      brix_signing_policy_modes },

    /* CRL strictness: try (default) | off | require.  "try" checks revocation
     * where a CRL exists but tolerates a CA that has none; "require" makes a
     * missing/expired CRL fatal. */
    { ngx_string("brix_crl_mode"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, crl_mode),
      brix_crl_modes },

    /* brix_require_vo -> owned by ngx_stream_brix_common_module (phase-101 W3
     * stage 3b); this server deep-copies the parsed rules into its own vo_rules
     * via brix_stream_common_adopt_vo_rules() at merge and finalizes them in
     * brix_config_finalize_policy against its own export root — unchanged. */

    { ngx_string("brix_authdb"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_authdb,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* XrdAcc engine selector + tunables (default: native engine). */
    { ngx_string("brix_authdb_format"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.format),
      brix_authdb_format_modes },

    { ngx_string("brix_authdb_audit"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.audit),
      brix_authdb_audit_modes },

    { ngx_string("brix_authdb_refresh"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.refresh),
      NULL },

    { ngx_string("brix_acc_gidlifetime"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.gidlifetime),
      NULL },

    { ngx_string("brix_acc_pgo"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.pgo),
      NULL },

    { ngx_string("brix_acc_nisdomain"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.nisdomain),
      NULL },

    { ngx_string("brix_acc_resolve_hosts"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.resolve_hosts),
      NULL },

    { ngx_string("brix_acc_spacechar"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.spacechar),
      NULL },

    { ngx_string("brix_acc_encoding"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.encoding),
      NULL },

    { ngx_string("brix_acc_gidretran"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, acc.gidretran),
      NULL },

    { ngx_string("brix_inherit_parent_group"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_inherit_parent_group,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* JWT / WLCG bearer-token directives (used when brix_auth = token|both). */
    { ngx_string("brix_token_jwks"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_jwks),
      NULL },

    /* Millisecond interval for mtime-poll JWKS hot refresh (0 = disabled). */
    { ngx_string("brix_token_jwks_refresh_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_jwks_refresh_interval),
      NULL },

    { ngx_string("brix_token_clock_skew"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_clock_skew),
      NULL },

    { ngx_string("brix_token_issuer"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_issuer),
      NULL },

    { ngx_string("brix_token_audience"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_audience),
      NULL },

    { ngx_string("brix_token_config"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_config),
      NULL },

    { ngx_string("brix_throttle_zone"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, throttle.zone_name),
      NULL },

    { ngx_string("brix_throttle_max_open_files"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, throttle.max_open_files),
      NULL },

    /* NOTE: `brix_throttle_max_active_connections` was removed in phase-95.  It
     * parsed and merged cleanly but had zero readers, so it silently enforced
     * nothing while reading like a security cap.  Reintroduce it only together
     * with its admission point. */

    /* phase-92: XrdBwm-style read-bandwidth reservation (default off). The zone
     * names a per-worker byte budget; a read open reserves its file size and is
     * refused (kXR_Overloaded) when the aggregate is exhausted. */
    { ngx_string("brix_throttle_bandwidth_zone"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, throttle.bwm_zone_name),
      NULL },

    { ngx_string("brix_throttle_bandwidth_budget"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, throttle.bwm_budget),
      NULL },

    { ngx_string("brix_csi"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, csi.enable),
      NULL },

    { ngx_string("brix_csi_block"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, csi.block),
      NULL },

    { ngx_string("brix_csi_require"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, csi.require),
      NULL },

    { ngx_string("brix_csi_trust_fs"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, csi.trust_fs),
      NULL },

    { ngx_string("brix_csi_scrub_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, csi.scrub_interval),
      NULL },

    { ngx_string("brix_macaroon_secret"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_macaroon_secret),
      NULL },

    { ngx_string("brix_macaroon_secret_old"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_macaroon_secret_old),
      NULL },

    /* XRootD Simple Shared Secret keytab (generated by xrdsssadmin-brix). */
    { ngx_string("brix_sss_keytab"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, sss_keytab),
      NULL },

    /* Kerberos 5 service principal and optional keytab for XrdSeckrb5. */
    { ngx_string("brix_krb5_principal"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, krb5.principal),
      NULL },

    { ngx_string("brix_krb5_keytab"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, krb5.keytab),
      NULL },

    { ngx_string("brix_krb5_ip_check"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, krb5.ip_check),
      NULL },

    /* Phase 70 §5.7: request the client forward its TGT after a verified krb5
     * login (inbound two-round kXR_authmore "fwdtgt" capture).  Off by default. */
    { ngx_string("brix_krb5_delegate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, krb5.delegate),
      NULL },

    /* Upstream-compatible unix credentials are self-asserted; keep remote
     * peers disabled unless an operator explicitly trusts the network. */
    /* Phase 52 (WS-C): host-auth reverse-DNS allowlist (exact or ".suffix"). */
    { ngx_string("brix_host_allow"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, host_allow),
      NULL },

    /* Phase 52 (WS-B): XrdSecpwd password database (opt-in; deny if unset). */
    { ngx_string("brix_pwd_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, pwd_file),
      NULL },

    { ngx_string("brix_unix_trust_remote"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, unix_trust_remote),
      NULL },
