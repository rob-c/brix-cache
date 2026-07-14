/*
 * srv_conf_fields_auth.inc: worker-runtime, auth, GSI/x509, VO/XrdAcc, OpenSSL objects, tape/FRM, token, throttle, CSI, SHM caches, sss/krb5/unix/host/pwd — a field-declaration fragment of ngx_stream_brix_srv_conf_t, split
 * (phase-79 file-size burndown) out of config.h via the repo's established .inc
 * struct-fragment pattern (cf. module_commands.c / directives_*.inc). Included
 * INSIDE the struct body in config.h — the struct assembles byte-identically, so
 * ZERO ABI change and every `conf->field` access is unchanged. Not a standalone
 * TU; do not #include anywhere but the srv_conf struct body. */

    ngx_http_brix_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */

    /* ---- worker-process runtime infrastructure ---- */
    int  rootfd;          /* O_PATH fd on export root; -1 until worker init */

    /* ---- authentication ---- */
    ngx_uint_t  auth;    /* [brix_auth none|gsi|token|both] — one of the
                            BRIX_AUTH_* constants in tunables.h */

    /* ---- GSI / x509 settings (used when auth = gsi or both) ---- */
    ngx_str_t   certificate;      /* [brix_certificate /etc/grid.pem] */
    ngx_str_t   certificate_key;  /* [brix_certificate_key /etc/grid.key] */
    ngx_str_t   trusted_ca;       /* [brix_trusted_ca /etc/grid-security/certificates]
                                     PEM file or directory of trusted CA certs */
    ngx_str_t   vomsdir;          /* [brix_vomsdir /etc/grid-security/vomsdir]
                                     VOMS LSC directory for attribute cert verification */
    ngx_str_t   voms_cert_dir;    /* [brix_voms_cert_dir /etc/grid-security/certificates]
                                     CA cert directory for VOMS server certificate chains */
    ngx_str_t   crl;              /* [brix_crl /etc/grid-security/certificates]
                                     PEM CRL file or directory; reloaded on crl_timer */
    time_t      crl_reload;       /* [brix_crl_reload 3600] — seconds between CRL
                                     re-scans; 0 = never reload */
    time_t      crl_mtime;        /* Phase 51 (E5): st_mtime of `crl` at last
                                     successful store rebuild; the reload timer
                                     skips the (possibly large/slow) CRL re-parse
                                     when an unchanged regular-file CRL would just
                                     reproduce the same store. 0 = not yet loaded */
    ngx_uint_t  signing_policy_mode; /* [brix_signing_policy on|off|require]
                                     BRIX_SP_MODE_*; default ON (enforce when a
                                     <hash>.signing_policy file is present) */
    ngx_uint_t  crl_mode;         /* [brix_crl_mode off|try|require]
                                     BRIX_CRL_MODE_*; default TRY */

    /* ---- VO access-control lists ---- */
    ngx_array_t  *vo_rules;     /* brix_vo_rule_t[] from brix_require_vo */
    ngx_str_t     authdb;       /* [brix_authdb /etc/xrootd/authdb] */
    ngx_array_t  *authdb_rules; /* brix_authdb_rule_t[] parsed from authdb (native) */

    /* ---- XrdAcc engine (selected by `brix_authdb_format xrdacc`) ---- */
    brix_acc_conf_t  acc;  /* [brix_authdb_format, brix_authdb_audit, ...]
                              — see brix_acc_conf_t. */
    ngx_array_t  *group_rules;  /* brix_group_rule_t[] from brix_inherit_parent_group */
    ngx_array_t  *manager_map;  /* brix_manager_map_t[] from brix_manager_map */

    /* ---- Loaded OpenSSL objects (populated at postconfiguration / init_process) ---- */
    X509        *gsi_cert;     /* server certificate parsed from 'certificate' */
    EVP_PKEY    *gsi_key;      /* server private key parsed from 'certificate_key' */
    X509_STORE  *gsi_store;    /* combined CA + CRL trust store for verification */
    u_char      *gsi_cert_pem; /* PEM form cached for kXGS_cert responses */
    size_t       gsi_cert_pem_len;
    /* CA name-hash list advertised in the kXGS_init sec token
     * ("ca:hash1|hash2", NUL-terminated).  Stock XrdSecgsi clients look these
     * hashes up in their own CA directory and abort with "unknown CA" when
     * none match, so this must name the real issuer chain of gsi_cert
     * (intermediates + root), not a placeholder. */
    char         gsi_ca_hashes[80];

    /*
     * GSI signed-DH policy [brix_gsi_signed_dh off|auto|require] (phase-48).
     * Controls whether the server uses the modern RSA-signed-DH wire variant
     * (>=XrdSecgsiVersDHsigned/10400) instead of the universally-interoperable
     * unsigned-DH default.  Stored as BRIX_GSI_SDH_* (see context.h dispatch):
     *   OFF (0, default) — always emit unsigned kXRS_puk (today's behaviour;
     *                      interoperates with every official client).
     *   AUTO (1)         — emit signed kXRS_cipher when the client advertises
     *                      version >= 10400, else fall back to unsigned.
     *   REQUIRE (2)      — signed only; reject clients that advertise < 10400.
     * NGX_CONF_UNSET until merged.
     */
    ngx_uint_t   gsi_signed_dh;

    /* Phase 51 (E4): per-worker cap on concurrently in-flight GSI handshakes.
     * A GSI handshake is multi-round-trip and CPU-heavy; under a flood of
     * simultaneous handshakes this sheds the excess (kXR_wait) so the event loop
     * is not buried.  Default 256 (far above normal load — only a genuine flood
     * trips it); 0 = unlimited. [brix_gsi_max_inflight_handshakes] */
    ngx_int_t    gsi_max_inflight;

    /* Per-worker ephemeral-DH keypool sizing (see src/gsi/keypool.c). At worker
     * start only `gsi_keypool_seed` keys are generated synchronously (keeping the
     * event thread free at boot); the pool is then filled off-thread up to
     * `gsi_keypool_size`.  Defaults 64 / 4.  size is clamped to the compile-time
     * ceiling BRIX_GSI_KEYPOOL_CAP and seed to [1, size].
     * [brix_gsi_keypool_size N] [brix_gsi_keypool_seed N] */
    ngx_uint_t   gsi_keypool_size;
    ngx_uint_t   gsi_keypool_seed;

    /* Phase 52 (WS-A): [brix_gsi_ciphers "aes-256-cbc:aes-128-cbc:..."] the GSI
     * session-cipher preference list the server advertises (kXRS_cipher_alg).
     * Empty = the built-in default (aes-128-cbc first → unchanged behaviour).
     * The advertised list is filtered to ciphers this build can actually key, so
     * a client never selects one the server cannot decrypt. */
    ngx_str_t    gsi_ciphers;

    /* Timer that fires crl_reload-seconds after init to rebuild gsi_store */
    ngx_event_t *crl_timer;   /* heap-allocated in init_process; NULL if disabled */

    /* ---- tape staging hook ---- */
    ngx_str_t    prepare_command; /* [brix_prepare_command /path/to/stage.sh]
                                     Shell command invoked fire-and-forget when a
                                     kXR_prepare request has the kXR_stage flag set.
                                     argv: cmd  path1  path2  ...  (absolute, NUL-
                                     terminated resolved paths under brix_root).
                                     Empty = staging hint silently accepted (no-op). */

    /* ---- Phase 35: FRM durable tape-staging (off by default) ---- */
    brix_frm_conf_t  frm;       /* [brix_frm, brix_frm_queue_path, ...]
                                     durable stage-request queue + residency;
                                     frm.enable == 0 = no-op (legacy
                                     prepare_command path still fires). */

    /* ---- JWT / WLCG bearer-token settings (used when auth = token or both) ---- */
    ngx_str_t   token_jwks;      /* [brix_token_jwks /etc/xrd/jwks.json] */
    ngx_str_t   token_issuer;    /* [brix_token_issuer https://cilogon.org] */
    ngx_str_t   token_audience;  /* [brix_token_audience https://storage.example.org] */
    ngx_int_t   token_clock_skew; /* [brix_token_clock_skew 30] seconds of exp grace;
                                     NGX_CONF_UNSET = inherit/default
                                     (BRIX_TOKEN_CLOCK_SKEW_SECS); max 300 */
    ngx_str_t   token_config;    /* [brix_token_config /etc/xrd/scitokens.cfg]
                                    multi-issuer registry (phase-59 W1); when set
                                    it overrides the single-issuer fields above */
    void       *token_registry;  /* brix_token_registry_t* built at postconfig;
                                    NULL = single-issuer path.  void* keeps
                                    issuer_registry.h out of this header. */

    /* ---- Phase-59 W3a: XrdThrottle contract (off by default) ---- */
    brix_throttle_conf_t  throttle;  /* [brix_throttle_zone, brix_throttle_max_*]
                                        — see brix_throttle_conf_t. */

    /* ---- CSI block-checksum integrity on the xmeta record (ON by default) ---- */
    brix_csi_conf_t  csi;  /* [brix_csi, brix_csi_block, brix_csi_require,
                              brix_csi_trust_fs] — see brix_csi_conf_t. */

    ngx_str_t   token_macaroon_secret;     /* [brix_macaroon_secret <hex>] */
    ngx_str_t   token_macaroon_secret_old; /* [brix_macaroon_secret_old <hex>]
                                              grace-period key: tokens signed with
                                              this key are also accepted so that
                                              in-flight tokens survive nginx -s reload
                                              while the operator rotates secrets. */

    /* JWKS keys parsed at postconfiguration from token_jwks */
    brix_jwks_key_t  jwks_keys[BRIX_MAX_JWKS_KEYS];
    int                 jwks_key_count;  /* 0 if token auth is not configured */
    time_t              jwks_mtime;      /* st_mtime of token_jwks at last successful load */
    ngx_msec_t          token_jwks_refresh_interval; /* [brix_token_jwks_refresh_interval 60000ms]
                                                        Polling interval (ms) for mtime-based JWKS
                                                        hot refresh. NGX_CONF_UNSET_MSEC = disabled. */
    ngx_event_t        *jwks_timer;     /* per-worker timer event; NULL if not scheduled */

    /* ---- Phase 20: shared-memory caches & rate limiting ---- */
    brix_kv_t              *token_cache_kv;  /* [brix_token_cache zone=]
                                                  JWT validation cache (L2/SHM); NULL = off */
    /* Phase 50: always-on per-worker L1 token-validation cache (lockless),
     * lazily created on first token auth.  Collapses repeated token validation
     * (crypto + JSON parse, and the L2 spinlock) to an O(1) probe so token auth
     * does not stall the event loop under load.  See token/worker_cache.h. */
    struct brix_token_l1_s *token_l1;
    brix_auth_cache_conf_t  auth_cache;      /* [brix_auth_cache zone= ttl=]
                                                  auth-gate result cache (L2/SHM); kv NULL = off */
    /* Phase 51 (E2): per-worker L1 in front of auth_cache.kv, lazily created when
     * the auth cache is enabled.  An L1 hit returns the verdict without the SHM
     * spinlock — removes the cross-worker contention GSI-heavy load hits hardest.
     * See path/auth_gate_l1.h. */
    struct brix_auth_l1_s  *auth_l1;
    brix_rate_limit_conf_t  rate_limit;      /* [brix_rate_limit zone= rate= burst= key=]
                                                  per-DN request throttle; kv NULL = off */

    /* ---- Simple Shared Secret settings (used when auth = sss) ---- */
    ngx_str_t    sss_keytab;    /* [brix_sss_keytab /etc/xrootd/sss.keytab] */
    time_t       sss_lifetime;  /* credential lifetime in seconds; default 13 */
    ngx_array_t *sss_keys;      /* brix_sss_key_t[] parsed from sss_keytab */

    /* ---- Kerberos 5 settings (used when auth = krb5) ---- */
    brix_krb5_conf_t  krb5;  /* [brix_krb5_principal, brix_krb5_keytab,
                                brix_krb5_ip_check] + loaded libkrb5 objects. */

    /* ---- Unix auth settings (used when auth = unix) ---- */
    ngx_flag_t   unix_trust_remote; /* [brix_unix_trust_remote on|off]
                                       Default off: only loopback peers may use
                                       upstream-compatible self-asserted unix
                                       credentials. */

    /* ---- Host auth settings (used when auth = host) — Phase 52 WS-C ---- */
    ngx_array_t *host_allow;        /* [brix_host_allow <pattern>...] ngx_str_t[]
                                       of exact hostnames or ".suffix" domain
                                       suffixes; the reverse-resolved peer host
                                       must match one.  NULL/empty = deny all. */

    /* ---- Pwd auth settings (used when auth = pwd) — Phase 52 WS-B ---- */
    ngx_str_t    pwd_file;          /* [brix_pwd_file <path>] password database:
                                       one "user:salthex:hashhex" line per user,
                                       hash = PBKDF2-HMAC-SHA1(pw,salt,10000,24B).
                                       Empty = pwd auth disabled (deny all). */

