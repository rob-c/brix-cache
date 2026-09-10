/* shared_conf_fields.h — export identity, storage backend and credential
 * fields of brix_shared_conf_t.  Included inside shared_conf_types.h's
 * shared-conf struct, followed by shared_conf_fields_policy.h (cache tiers,
 * write/security/auth/token/TPC policy, runtime DNS) — split like
 * core/types/srv_conf_fields_*.h to stay under the file-size cap. */
    ngx_flag_t          enable;             /* on/off toggle for protocol          */
    ngx_str_t           root;               /* filesystem export root path         */
    char                root_canon[PATH_MAX]; /* canonicalized/confined root        */
    ngx_str_t           storage_backend;    /* SD backend: posix or named driver. */
    ngx_array_t        *storage_backend_args; /* phase-115 W5.1: its trailing
                                             * store-line params (verify_pages,
                                             * mode=, prot=, …) — the directive
                                             * took exactly one argument until
                                             * W4.3 added a param that nothing
                                             * could parse. */
    size_t              pblock_block_size;  /* pblock stripe size for new files
                                             * (bytes); 0 = backend default (64 MiB) */
    /* phase-108 A.4: explicit override of the export's logical→physical name
     * translation. All-unset ("") ⇒ the backend parser's derived default
     * (ceph ⇒ CEPHFS_PATH+key_prefix; everything else ⇒ IDENTITY). n2n_scheme is
     * "identity" | "ral" | "cephfs_path"; validated at nginx -t. */
    ngx_str_t           n2n_scheme;         /* [brix_n2n_scheme <name>] */
    ngx_str_t           n2n_pool;           /* [brix_n2n_pool <name>]  (RAL only) */
    ngx_str_t           n2n_prefix;         /* [brix_n2n_prefix <path>] prefix/localroot */
    ngx_flag_t          storage_staging;    /* write-back: a remote (root://) backend
                                             * stages uploads to the LOCAL export and
                                             * promotes them on commit, vs streaming
                                             * straight through (Mode A). off = Mode A */
    ngx_str_t           storage_credential; /* [brix_storage_credential <name>] —
                                             * the brix_credential block (§14) the
                                             * source backend authenticates with;
                                             * "" = anonymous. Today threads a bearer
                                             * token into sd_http. */
    ngx_str_t           storage_credential_dir; /* [brix_storage_credential_dir
                                             * <dir>] — directory of per-identity
                                             * x509 proxy PEMs for a remote
                                             * backend (phase-1 per-user backend
                                             * credentials). Defaults to the
                                             * tmpfs BRIX_CREDENTIAL_DIR_DEFAULT
                                             * (/dev/shm/brix-creds, created 0700
                                             * at config time); explicit "" =
                                             * feature off.                      */
    ngx_uint_t          storage_credential_fallback; /* [brix_storage_credential_
                                             * fallback allow|deny] — 0 allow the
                                             * static service credential when the
                                             * identity has no per-user file
                                             * (default); 1 deny (fail EACCES).  */
    ngx_str_t           storage_credential_mint_ca_cert; /* [brix_storage_
                                             * credential_mint_ca <cert> <key>]
                                             * — phase-2 T9 opt-in minting: PEM
                                             * cert of the CA the frontend signs
                                             * minted proxies with. "" = minting
                                             * off (Phase-1 behavior only). The
                                             * ORIGIN must be configured to trust
                                             * this CA — see cred_mint.h.       */
    ngx_str_t           storage_credential_mint_ca_key;  /* PEM private key
                                             * paired with mint_ca_cert above;
                                             * set together by the same
                                             * directive.                       */
    time_t              storage_credential_mint_ttl; /* sec_slot (W7): accepts nginx
                                                       * time units. [brix_storage_credential_
                                             * mint_ttl <secs>] — lifetime of a
                                             * freshly minted proxy; default
                                             * 3600. Ignored when minting is
                                             * off.                             */
    ngx_uint_t          backend_delegation; /* [brix_backend_delegation
                                             * select|passthrough|exchange|
                                             * delegate|mint|auto] (phase-70 §4)
                                             * — the backend-leg credential
                                             * strategy; enum → BRIX_CRED_*.
                                             * Default 0 (SELECT).              */
    ngx_array_t        *backend_token_aud;  /* [brix_backend_token_audience_ok
                                             * <aud>...] (phase-70 §5.4) —
                                             * ngx_str_t[] backend audiences a
                                             * bearer may be forwarded to; NULL
                                             * = none configured.               */
    ngx_str_t           backend_tx_endpoint;   /* [brix_backend_token_exchange_
                                             * endpoint <url>] (phase-70 §5.4) —
                                             * RFC 8693 token endpoint. ""
                                             * = EXCHANGE falls back to verbatim
                                             * bearer passthrough.              */
    ngx_str_t           backend_tx_client_id;  /* [brix_backend_token_exchange_
                                             * client_id <id>] — OAuth2 client id
                                             * for the exchange (HTTP Basic).   */
    ngx_str_t           backend_tx_client_secret; /* [brix_backend_token_exchange_
                                             * client_secret <secret>] — paired
                                             * client secret; NEVER logged.     */
    void               *backend_tx_cache;   /* per-worker RFC-8693 minted-token
                                             * cache (brix_tx_cache_t*), lazily
                                             * created by the cred gate via the
                                             * slot handed to
                                             * brix_vfs_deleg_set_exchange()
                                             * (P90-70.9). Not a directive; not
                                             * merged — each conf owns its own. */
    ngx_str_t           backend_sts_endpoint;  /* [brix_backend_s3_sts_endpoint
                                             * <url>] (phase-70 §5.5) — STS base
                                             * URL for S3 credential EXCHANGE;
                                             * "" = STS off.                    */
    ngx_str_t           backend_sts_role;   /* [brix_backend_s3_sts_role <arn>]
                                             * — role ARN to AssumeRole into; ""
                                             * selects GetSessionToken.         */
    ngx_str_t           backend_sts_access_key; /* [brix_backend_s3_sts_access_key
                                             * <id>] (phase-70 §5.5) — node S3
                                             * SERVICE access-key id that SigV4-
                                             * signs the STS AssumeRole request. */
    ngx_str_t           backend_sts_secret_key; /* [brix_backend_s3_sts_secret_key
                                             * <secret>] — paired service secret;
                                             * NEVER logged. STS is armed only
                                             * when endpoint+ak+sk are all set. */
    ngx_str_t           backend_sts_region; /* [brix_backend_s3_sts_region
                                             * <region>] — SigV4 region for the
                                             * "sts" service; "" → us-east-1.    */
    ngx_int_t           backend_sts_ttl;    /* [brix_backend_s3_sts_ttl <secs>]
                                             * — requested temp-cred lifetime;
                                             * clamped 900..43200 by the STS
                                             * client. UNSET → 3600.             */
    ngx_uint_t          backend_sts_flavor; /* [brix_backend_s3_sts_flavor
                                             * aws|minio] (phase-70 §5.5) — STS
                                             * wire dialect: aws=GET/presigned,
                                             * minio=POST/form/header-auth.
                                             * UNSET → aws (0).                  */
    ngx_flag_t          backend_krb5_forwardable; /* [brix_backend_krb5_
                                             * forwardable on|off] (phase-70
                                             * §5.7) — allow GSSAPI credential
                                             * forwarding to the origin. Default
                                             * off.                             */
    ngx_str_t           backend_sss_keytab; /* [brix_backend_sss_keytab <path>]
                                             * (phase-70 §5.6 / P90-70.3) — SSS
                                             * keytab the delegation gate signs
                                             * identity-injection credentials
                                             * with (assert the CALLER to the
                                             * origin, never the keytab's own
                                             * principal). Load-validated. "" =
                                             * injection off.                   */
    void               *storage_instance;   /* resolved brix_sd_instance_t* for a
                                             * non-POSIX backend, built per worker at
                                             * init_process. Runtime only — never
                                             * merged. NULL ⇒ default POSIX path.    */
