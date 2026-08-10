/* http_common.c — see http_common.h for the WHAT/WHY/HOW. */
#include "core/config/http_common.h"
#include "core/config/tier_directives.h"
#include "core/seccomp/seccomp.h"            /* brix_conf_set_seccomp */
#include "auth/impersonate/lifecycle.h"      /* brix_conf_set_worker_user */
#include "protocols/root/stream/module_enums.h" /* brix_seccomp_modes */
#include "fs/cache/verify.h"               /* brix_cache_verify_mode_e */
#include "fs/backend/sd.h"                 /* BRIX_CRED_* (phase-70 §4) */
#include "auth/s3/sts.h"                   /* BRIX_STS_FLAVOR_* (phase-70 §5.5) */
#include "core/config/config.h"            /* brix_conf_set_backend_sss_keytab */
#include "fs/vfs/vfs_secgate.h"            /* brix_conf_set_tls_require */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>                   /* phase-2 T9 mint-CA config-time validation */
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */
#include "auth/crypto/store_policy.h"  /* BRIX_SP_MODE_* / BRIX_CRL_MODE_* (W4 x509) */

/* CRL enforcement + GSI signing-policy enums (phase-101 W4): the whole x509 CRL
 * family is bare on the stream plane; owning the bare names here mirrors those
 * value sets exactly (a pure move, not a grammar change). */
static ngx_conf_enum_t  brix_http_signing_policy_modes[] = {
    { ngx_string("off"),     BRIX_SP_MODE_OFF     },
    { ngx_string("on"),      BRIX_SP_MODE_ON      },
    { ngx_string("require"), BRIX_SP_MODE_REQUIRE },
    { ngx_null_string, 0 }
};
static ngx_conf_enum_t  brix_http_crl_modes[] = {
    { ngx_string("off"),     BRIX_CRL_MODE_OFF     },
    { ngx_string("try"),     BRIX_CRL_MODE_TRY     },
    { ngx_string("require"), BRIX_CRL_MODE_REQUIRE },
    { ngx_null_string, 0 }
};

static void *brix_http_common_create_loc_conf(ngx_conf_t *cf);
static char *brix_http_common_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);
static char *brix_http_conf_tpc_source_allow(ngx_conf_t *cf,
                                             ngx_command_t *cmd, void *conf);

static ngx_conf_enum_t  brix_http_ucred_fallback_enum[] = {
    { ngx_string("allow"), 0 },
    { ngx_string("deny"),  1 },
    { ngx_null_string, 0 }
};

/* brix_backend_delegation mode names → BRIX_CRED_* (phase-70 §4). Shared by the
 * HTTP plane here and mirrored by the root:// stream directive table. */
static ngx_conf_enum_t  brix_backend_delegation_enum[] = {
    { ngx_string("select"),      BRIX_CRED_SELECT },
    { ngx_string("passthrough"), BRIX_CRED_PASSTHROUGH },
    { ngx_string("exchange"),    BRIX_CRED_EXCHANGE },
    { ngx_string("delegate"),    BRIX_CRED_DELEGATE },
    { ngx_string("mint"),        BRIX_CRED_MINT },
    { ngx_string("auto"),        BRIX_CRED_AUTO },
    { ngx_null_string, 0 }
};

/* STS wire dialect for brix_backend_s3_sts_flavor (phase-70 §5.5). */
static ngx_conf_enum_t  brix_sts_flavor_enum[] = {
    { ngx_string("aws"),   BRIX_STS_FLAVOR_AWS },
    { ngx_string("minio"), BRIX_STS_FLAVOR_MINIO },
    { ngx_null_string, 0 }
};

/*
 * brix_cache_verify values on the HTTP plane.  Only the SELF-verifying schemes
 * are meaningful here (best-effort/require need an origin-digest hook the
 * HTTP-plane fill does not carry): cvmfs-cas, whose key names a sha1, and
 * phase-104's oci-digest, whose key names a sha256, and rpm-repodata, whose
 * key is a createrepo `<checksum>-<name>` metadata file.  This mirrors the cvmfs
 * module's enum exactly so owning the bare name here is a pure move, not a
 * grammar change.  Protocol merges validate which values they support.
 */
static ngx_conf_enum_t  brix_http_cache_verify_enum[] = {
    { ngx_string("off"),        BRIX_CACHE_VERIFY_OFF },
    { ngx_string("cvmfs-cas"),  BRIX_CACHE_VERIFY_CVMFS_CAS },
    { ngx_string("oci-digest"), BRIX_CACHE_VERIFY_OCI_DIGEST },
    { ngx_string("rpm-repodata"), BRIX_CACHE_VERIFY_RPM_REPODATA },
    { ngx_null_string, 0 }
};

#define BRIX_HTTP_ALL_CONF \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)

static ngx_command_t  brix_http_common_commands[] = {

    { ngx_string("brix_export"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.root),
      NULL },

    { ngx_string("brix_storage_backend"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_backend),
      NULL },

    /* Per-worker seccomp-BPF syscall filter for HTTP (WebDAV/S3/cvmfs) servers —
     * off|audit|enforce.  Process-global: the strictest value across ALL brix
     * servers (stream + http) is installed once per worker, so HTTP-only workers
     * are filtered too (not just stream/root:// workers). */
    { ngx_string("brix_seccomp"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_seccomp,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.seccomp),
      &brix_seccomp_modes },

    /* Opt out of the enforce execve/execveat KILL (default off) for WebDAV
     * HTTP-TPC OIDC delegation and similar fork+exec helpers.  ptrace/process_vm_*
     * stay killed.  Process-global (strictest across stream+http; ratchets on). */
    { ngx_string("brix_seccomp_allow_exec"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_seccomp_allow_exec,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Confined account a root-capable worker is force-dropped to at init (default
     * "nobody" + a warning). Process-global; covers HTTP-only (WebDAV/S3) workers
     * too. See brix_imp_worker_deescalate. */
    { ngx_string("brix_worker_user"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_worker_user,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential),
      NULL },

    { ngx_string("brix_storage_credential_dir"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_dir),
      NULL },

    { ngx_string("brix_storage_credential_fallback"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_fallback),
      &brix_http_ucred_fallback_enum },

    { ngx_string("brix_storage_credential_mint_ca"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE2,
      brix_conf_set_mint_ca,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_storage_credential_mint_ttl"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.storage_credential_mint_ttl),
      NULL },

    { ngx_string("brix_backend_delegation"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_delegation),
      &brix_backend_delegation_enum },

    { ngx_string("brix_backend_token_audience_ok"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_token_aud),
      NULL },

    { ngx_string("brix_backend_token_exchange_endpoint"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_tx_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_endpoint),
      NULL },

    { ngx_string("brix_backend_token_exchange_client_id"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_client_id),
      NULL },

    { ngx_string("brix_backend_token_exchange_client_secret"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_tx_client_secret),
      NULL },

    { ngx_string("brix_backend_s3_sts_endpoint"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_sts_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_endpoint),
      NULL },

    { ngx_string("brix_backend_s3_sts_role"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_role),
      NULL },

    { ngx_string("brix_backend_s3_sts_access_key"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_access_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_secret_key"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_secret_key),
      NULL },

    { ngx_string("brix_backend_s3_sts_region"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_region),
      NULL },

    { ngx_string("brix_backend_s3_sts_ttl"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_ttl),
      NULL },

    { ngx_string("brix_backend_s3_sts_flavor"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sts_flavor),
      &brix_sts_flavor_enum },

    { ngx_string("brix_backend_krb5_forwardable"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_krb5_forwardable),
      NULL },

    { ngx_string("brix_backend_passthrough_persist"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_passthrough_persist),
      NULL },

    /* Phase-70 §5.6 / P90-70.3: SSS identity-injection keytab — the delegation
     * gate re-issues an SSS credential asserting the CALLER's principal to the
     * origin, signed with this keytab (never the keytab's own principal).
     * Load-validated at config time by the setter. */
    { ngx_string("brix_backend_sss_keytab"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      brix_conf_set_backend_sss_keytab,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_sss_keytab),
      NULL },

    { ngx_string("brix_allow_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.allow_write),
      NULL },

    /* Read-back CRC verify for whole-object PUT (WebDAV/S3) routed through
     * brix_vfs_writer; off by default. Never applies to ranged/partial PUT. */
    { ngx_string("brix_verify_write"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.verify_write),
      NULL },

    { ngx_string("brix_read_only"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.read_only),
      NULL },

    { ngx_string("brix_compress"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.compress),
      NULL },

    /* E-1: refuse valid-but-dangerous configs at nginx -t rather than only
     * warning (anonymous S3, unauthenticated WebDAV writes, anonymous
     * dashboard). Off by default; see brix_shared_security_gate. */
    { ngx_string("brix_strict_security"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.strict_security),
      NULL },

    /* Per-capability TLS gating (stock xrootd.tls parity): ops exercising a
     * listed capability are refused with 403 on cleartext transports. */
    { ngx_string("brix_tls_require"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      brix_conf_set_tls_require,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tls_require),
      NULL },

    { ngx_string("brix_access_log"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.access_log),
      NULL },

    { ngx_string("brix_session_log"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.session_log),
      NULL },

    { ngx_string("brix_thread_pool"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.thread_pool_name),
      NULL },

    { ngx_string("brix_cache_peers"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_1MORE,
      brix_conf_set_peers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cache_verify"),
      BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_verify_mode),
      &brix_http_cache_verify_enum },

    /* kTLS + trusted cache-store endpoint (phase-101 W2): both were hand-rolled
     * dual-conf-poking setters registered on webdav that wrote BOTH the webdav
     * and s3 loc-confs (and silently excluded cvmfs).  Registered once here for
     * the whole HTTP plane on the standard flag slot instead — the fields already
     * live in the shared preamble, and brix_shared_adopt_unified() below carries
     * them into every protocol conf (cvmfs now included). */
    { ngx_string("brix_ktls"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.ktls), NULL },
    { ngx_string("brix_cache_store_endpoint"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_store_endpoint), NULL },
    /* Legacy read-through cache root (phase-101 W8): was the byte-parallel twins
     * brix_webdav_cache_root / brix_s3_cache_root; one bare name now covers both
     * HTTP protocols. Each protocol canonicalizes common.cache_root into
     * common.cache_root_canon at merge (after adopt). */
    { ngx_string("brix_cache_root"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.cache_root), NULL },

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
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_clock_skew), NULL },
    /* Multi-issuer SciTokens registry file (phase-101 W4): was
     * brix_webdav_token_config; bare on the stream plane already. Overrides the
     * single-issuer jwks/issuer/audience fields when set. */
    { ngx_string("brix_token_config"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_config), NULL },

    /* SciTags packet marking (src/observability/pmark/) — phase-101 W1: this
     * family used to be hand-copied into BOTH webdav and s3 command tables, so
     * first-module-wins made s3's copy dead code and SciTags on S3 a silent
     * no-op.  Registered ONCE here for the whole HTTP plane instead, at
     * BRIX_HTTP_ALL_CONF scope (a site-wide `brix_pmark on` at server{}/http{}
     * now works, matching the stream plane's Sm|Ss).  Generic slots rebase onto
     * the common conf; the four custom setters keep offset 0 and resolve the
     * target via pmark_conf(), which returns the shared preamble's pmark for any
     * struct that embeds it first.  Adopted into each protocol conf by
     * brix_shared_adopt_unified() below. */
    { ngx_string("brix_pmark"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.enable), NULL },
    { ngx_string("brix_pmark_firefly"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.firefly), NULL },
    { ngx_string("brix_pmark_flowlabel"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("brix_pmark_scitag_cgi"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("brix_pmark_firefly_origin"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("brix_pmark_http_plain"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("brix_pmark_echo"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.echo), NULL },
    { ngx_string("brix_pmark_appname"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.appname), NULL },
    { ngx_string("brix_pmark_defsfile"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.defsfile), NULL },
    { ngx_string("brix_pmark_domain"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, brix_pmark_set_domain,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_firefly_dest"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, brix_pmark_set_firefly_dest,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_experiment"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE23, brix_pmark_set_map_experiment,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_activity"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      brix_pmark_set_map_activity,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    /* The tier directives: brix_cache_store, brix_cache_cold_store,
     * brix_stage, brix_stage_store, brix_stage_flush, brix_cache_max_object,
     * brix_cache_evict_at, brix_cache_evict_to, brix_cache_index_cache,
     * brix_cache_meta, brix_cache_slice_size, brix_cache_global_cas,
     * brix_cache_passthrough, brix_cache_passthrough_max, brix_cache_prefetch,
     * brix_cache_prefetch_window, brix_cache_only_if_cached. */
    BRIX_TIER_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET),

    /* Durable async backend-op queue (brix_backend_async[_batch|_wait]) — shared
     * with the root:// stream plane, adopted into each http protocol's `common`. */
    BRIX_BACKEND_ASYNC_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET),

      ngx_null_command
};

static ngx_http_module_t  brix_http_common_module_ctx = {
    NULL, NULL,                          /* pre/postconfiguration */
    NULL, NULL,                          /* create/init main conf */
    NULL, NULL,                          /* create/merge srv conf */
    brix_http_common_create_loc_conf,
    brix_http_common_merge_loc_conf
};

ngx_module_t  ngx_http_brix_common_module = {
    NGX_MODULE_V1,
    &brix_http_common_module_ctx,
    brix_http_common_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/*
 * brix_http_common_create_loc_conf() — allocate the common module's location
 * conf and seed the embedded preamble with UNSET sentinels so parent->child
 * inheritance (below) can tell "not configured" from an explicit value.
 */
static void *
brix_http_common_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_common_conf_t  *c;

    c = ngx_pcalloc(cf->pool, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    ngx_http_brix_shared_init(&c->common);
    return c;
}

/*
 * brix_http_common_merge_loc_conf() — inheritance-only merge: propagate parent
 * values into unset child slots and apply NO defaults.  Per-protocol defaults
 * still come from ngx_http_brix_shared_merge() in each protocol's merge, so a
 * field left unset here stays UNSET and lets each protocol pick its own
 * default after adopting the unified value.
 */
static char *
brix_http_common_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_common_conf_t  *prev = parent;
    ngx_http_brix_common_conf_t  *conf = child;

    (void) cf;
    brix_shared_adopt_unified(&conf->common, &prev->common);
    return NGX_CONF_OK;
}

#define BRIX_ADOPT_STR(f) \
    do { if (dst->f.data == NULL && src->f.data != NULL) dst->f = src->f; } while (0)
#define BRIX_ADOPT_VAL(f, unset) \
    do { if (dst->f == (unset) && src->f != (unset)) dst->f = src->f; } while (0)
#define BRIX_ADOPT_PTR(f) \
    do { if (dst->f == NULL && src->f != NULL) dst->f = src->f; } while (0)

void
brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,
                          const ngx_http_brix_shared_conf_t *src)
{
    BRIX_ADOPT_STR(root);
    BRIX_ADOPT_STR(storage_backend);
    BRIX_ADOPT_STR(storage_credential);
    BRIX_ADOPT_STR(storage_credential_dir);
    BRIX_ADOPT_VAL(storage_credential_fallback, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(storage_credential_mint_ca_cert);
    BRIX_ADOPT_STR(storage_credential_mint_ca_key);
    BRIX_ADOPT_VAL(storage_credential_mint_ttl, NGX_CONF_UNSET);   /* time_t (W7) */
    BRIX_ADOPT_VAL(backend_delegation, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(backend_tx_endpoint);
    BRIX_ADOPT_STR(backend_tx_client_id);
    BRIX_ADOPT_STR(backend_tx_client_secret);
    BRIX_ADOPT_STR(backend_sts_endpoint);
    BRIX_ADOPT_STR(backend_sts_role);
    BRIX_ADOPT_STR(backend_sts_access_key);
    BRIX_ADOPT_STR(backend_sts_secret_key);
    BRIX_ADOPT_STR(backend_sts_region);
    BRIX_ADOPT_VAL(backend_sts_ttl, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(backend_krb5_forwardable, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(backend_passthrough_persist, NGX_CONF_UNSET);
    BRIX_ADOPT_STR(thread_pool_name);
    BRIX_ADOPT_STR(access_log);
    BRIX_ADOPT_STR(cache_store);
    BRIX_ADOPT_STR(cache_root);   /* W8: legacy read-through cache root (canon is
                                   * derived per-protocol after this adopt) */
    BRIX_ADOPT_PTR(cache_store_args);
    BRIX_ADOPT_STR(cache_cold_store);
    BRIX_ADOPT_PTR(cache_cold_store_args);
    BRIX_ADOPT_PTR(cache_peers);
    BRIX_ADOPT_STR(stage_store);
    BRIX_ADOPT_PTR(stage_store_args);
    BRIX_ADOPT_VAL(allow_write,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(read_only,         NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(compress,          NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(strict_security,   NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(tls_require,       NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(session_log,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_enable,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(stage_flush_async, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(backend_async,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(backend_async_batch, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(backend_async_wait,  NGX_CONF_UNSET_MSEC);
    BRIX_ADOPT_VAL(cache_max_object,  NGX_CONF_UNSET);          /* off_t */
    BRIX_ADOPT_VAL(cache_evict_at,    NGX_CONF_UNSET_UINT);     /* ngx_uint_t */
    BRIX_ADOPT_VAL(cache_evict_to,    NGX_CONF_UNSET_UINT);     /* ngx_uint_t */
    BRIX_ADOPT_VAL(cache_index_cache, (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_meta_mode,   NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_slice_size,  (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_prefetch,    NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_prefetch_window, (size_t) NGX_CONF_UNSET_SIZE);
    BRIX_ADOPT_VAL(cache_verify_mode, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(cache_global_cas,  NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_passthrough, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_passthrough_max, NGX_CONF_UNSET);      /* off_t */
    BRIX_ADOPT_VAL(cache_only_if_cached, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_uvkeep,      NGX_CONF_UNSET);          /* time_t */

    /* phase-101 W2: kTLS + trusted cache-store endpoint (were dual-conf pokes). */
    BRIX_ADOPT_VAL(ktls,                 NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(cache_store_endpoint, NGX_CONF_UNSET);

    /* phase-101 W2: XrdAcc engine — the 11 config-time settings ONLY. The
     * per-worker tables/timer/timer_armed tail is lazily built after fork and
     * MUST NOT be adopted (copying an embedded ngx_event_t between confs is
     * actively wrong — see acc.h). */
    BRIX_ADOPT_VAL(acc.format,        NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(acc.audit,         NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(acc.refresh,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.gidlifetime,   NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.pgo,           NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.resolve_hosts, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(acc.encoding,      NGX_CONF_UNSET);
    BRIX_ADOPT_STR(acc.authdb);
    BRIX_ADOPT_STR(acc.nisdomain);
    BRIX_ADOPT_STR(acc.spacechar);
    BRIX_ADOPT_STR(acc.gidretran);

    /* phase-101 W4: ZIP member serving (was the webdav + s3 zip twins). */
    BRIX_ADOPT_VAL(zip_access,       NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(zip_cd_max_bytes, (size_t) NGX_CONF_UNSET_SIZE);

    /* phase-101 W4: HTTP basic-auth password db (was brix_webdav_pwd_file). */
    BRIX_ADOPT_STR(pwd_file);
    /* phase-101 W4: resumable PUT (was brix_webdav_upload_resume). */
    BRIX_ADOPT_VAL(upload_resume, NGX_CONF_UNSET);
    /* phase-101 W4: macaroon HMAC secrets (were brix_webdav_macaroon_secret*). */
    BRIX_ADOPT_STR(token_macaroon_secret);
    BRIX_ADOPT_STR(token_macaroon_secret_old);
    /* phase-101 W4: upload staging dir (was brix_webdav_stage_dir). */
    BRIX_ADOPT_STR(upload_stage_dir);
    /* phase-101 W4: pblock stripe size (was brix_webdav_pblock_block_size). */
    BRIX_ADOPT_VAL(pblock_block_size, (size_t) NGX_CONF_UNSET_SIZE);
    /* phase-101 W4: x509 CRL family (was brix_webdav_crl/_crl_mode/_signing_policy). */
    BRIX_ADOPT_STR(crl);
    BRIX_ADOPT_VAL(signing_policy_mode, NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_VAL(crl_mode,            NGX_CONF_UNSET_UINT);
    /* phase-101 W4: VOMS trust dirs (was brix_webdav_vomsdir/_voms_cert_dir). */
    BRIX_ADOPT_STR(vomsdir);
    BRIX_ADOPT_STR(voms_cert_dir);
    BRIX_ADOPT_PTR(vo_rules);
    BRIX_ADOPT_PTR(authdb_rules);   /* phase-101 W5.2: native u/g/p READ ACL */
    BRIX_ADOPT_PTR(protbind);
    BRIX_ADOPT_VAL(tpc_allow_local,        NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(tpc_allow_private,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(tpc_source_guard,       NGX_CONF_UNSET);
    BRIX_ADOPT_PTR(tpc_source_allow);
    BRIX_ADOPT_VAL(tpc_require_source_size, NGX_CONF_UNSET);
    BRIX_ADOPT_STR(tpc_verify_checksum);
    /* phase-101 W4: WLCG token trust quartet (collapsed webdav+s3 twins). */
    BRIX_ADOPT_STR(token_jwks);
    BRIX_ADOPT_STR(token_issuer);
    BRIX_ADOPT_STR(token_audience);
    BRIX_ADOPT_STR(token_config);
    BRIX_ADOPT_VAL(token_clock_skew, NGX_CONF_UNSET);

    /* SciTags pmark (phase-101 W1) — the 13 config-time fields only.  The
     * runtime tail (rt_ready/rt_ok/dest_sa/exp_rules_r/act_rules_r) is per-worker
     * lazily-built state behind pmark.h's "never merged" contract and MUST NOT be
     * adopted.  Because http_common's own inheritance merge routes through this
     * same function, this one block covers BOTH location inheritance and each
     * protocol's adopt-at-merge. */
    BRIX_ADOPT_VAL(pmark.enable,         NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.firefly,        NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.flowlabel,      NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.scitag_cgi,     NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.firefly_origin, NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.http_plain,     NGX_CONF_UNSET);
    BRIX_ADOPT_VAL(pmark.echo,           NGX_CONF_UNSET_MSEC);
    BRIX_ADOPT_VAL(pmark.domain,         NGX_CONF_UNSET_UINT);
    BRIX_ADOPT_STR(pmark.appname);
    BRIX_ADOPT_STR(pmark.defsfile);
    BRIX_ADOPT_PTR(pmark.firefly_dest);
    BRIX_ADOPT_PTR(pmark.exp_rules);
    BRIX_ADOPT_PTR(pmark.act_rules);
}

void
brix_http_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst)
{
    ngx_http_brix_common_conf_t  *ucf;

    ucf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_brix_common_module);
    if (ucf == NULL) {
        return;
    }
    brix_shared_adopt_unified(dst, &ucf->common);
}

/* brix_tpc_source_allow <host>... on the HTTP planes (phase-101 W4): append EVERY
 * argument to common.tpc_source_allow.  A custom setter (not the stock str_array
 * slot, which silently keeps only the first arg) because this is a SECURITY
 * allowlist — dropping hosts after the first would widen egress.  `common` is
 * member 0 of the common-module conf, so the cast to the preamble type is valid.
 * Mirrors the stream-side brix_tpc_conf_source_allow. */
static char *
brix_http_conf_tpc_source_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value, *slot;
    ngx_uint_t                   i;

    (void) cmd;

    if (sc->tpc_source_allow == NULL) {
        sc->tpc_source_allow = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (sc->tpc_source_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(sc->tpc_source_allow);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}
