/*
 * module_enums.c — directive enum value tables for the stream module.
 *
 * The textual value tables for the enum-typed `brix_*` directives, moved out
 * of module.c so the command table there stays focused.  Each maps config words
 * to the BRIX_* constants used by the rest of the module.
 */
#include "core/ngx_brix_module.h"
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "net/manager/health_check.h"  /* BRIX_HC_TYPE_* */
#include "auth/crypto/store_policy.h"  /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* */
#include "fs/cache/verify.h"           /* BRIX_CACHE_VERIFY_* */
#include "module_enums.h"

/* [brix_signing_policy on|off|require] — Globus signing_policy enforcement. */
ngx_conf_enum_t brix_signing_policy_modes[] = {
    { ngx_string("off"),     BRIX_SP_MODE_OFF     },
    { ngx_string("on"),      BRIX_SP_MODE_ON      },
    { ngx_string("require"), BRIX_SP_MODE_REQUIRE },
    { ngx_null_string,       0                      }
};

/* [brix_crl_mode off|try|require] — CRL revocation strictness. */
ngx_conf_enum_t brix_crl_modes[] = {
    { ngx_string("off"),     BRIX_CRL_MODE_OFF     },
    { ngx_string("try"),     BRIX_CRL_MODE_TRY     },
    { ngx_string("require"), BRIX_CRL_MODE_REQUIRE },
    { ngx_null_string,       0                       }
};

/* §6 brix_cns mode values. */
ngx_conf_enum_t brix_cns_modes[] = {
    { ngx_string("off"),     BRIX_CNS_OFF     },
    { ngx_string("emit"),    BRIX_CNS_EMIT    },
    { ngx_string("collect"), BRIX_CNS_COLLECT },
    { ngx_null_string,       0                  }
};

/* Text values accepted by `brix_auth` in nginx.conf ("both" = GSI+token). */
ngx_conf_enum_t brix_auth_modes[] = {
    { ngx_string("none"),  BRIX_AUTH_NONE  },
    { ngx_string("gsi"),   BRIX_AUTH_GSI   },
    { ngx_string("token"), BRIX_AUTH_TOKEN },
    { ngx_string("both"),  BRIX_AUTH_BOTH  },
    { ngx_string("sss"),   BRIX_AUTH_SSS   },
    { ngx_string("unix"),  BRIX_AUTH_UNIX  },
    { ngx_string("krb5"),  BRIX_AUTH_KRB5  },
    { ngx_string("host"),  BRIX_AUTH_HOST  },
    { ngx_string("pwd"),   BRIX_AUTH_PWD   },
    { ngx_null_string,     0                 }
};

/* `brix_authdb_format` — pick the authorization engine for the authdb file. */
ngx_conf_enum_t brix_authdb_format_modes[] = {
    { ngx_string("native"), BRIX_AUTHDB_FORMAT_NATIVE },
    { ngx_string("xrdacc"), BRIX_AUTHDB_FORMAT_XRDACC },
    { ngx_null_string,      0                            }
};

/* `brix_authdb_audit` — which authorization decisions to log. */
ngx_conf_enum_t brix_authdb_audit_modes[] = {
    { ngx_string("none"),  BRIX_AUTHDB_AUDIT_NONE  },
    { ngx_string("deny"),  BRIX_AUTHDB_AUDIT_DENY  },
    { ngx_string("grant"), BRIX_AUTHDB_AUDIT_GRANT },
    { ngx_string("all"),   BRIX_AUTHDB_AUDIT_ALL   },
    { ngx_null_string,     0                         }
};

/* Phase 22 — health-check probe type. */
ngx_conf_enum_t brix_hc_types[] = {
    { ngx_string("ping"), BRIX_HC_TYPE_PING },
    { ngx_string("stat"), BRIX_HC_TYPE_STAT },
    { ngx_null_string,    0                   }
};

/* `brix_security_level` — kXR_sigver enforcement, none .. pedantic. */
ngx_conf_enum_t brix_security_levels[] = {
    { ngx_string("none"),       0 },
    { ngx_string("compatible"), 1 },
    { ngx_string("standard"),   2 },
    { ngx_string("intense"),    3 },
    { ngx_string("pedantic"),   4 },
    { ngx_null_string,          0 }
};

/* D-1 — `brix_min_sec_level` session-posture floor (BRIX_MIN_SEC_*,
 * handshake.h): a distinct axis from brix_security_level (request signing). */
ngx_conf_enum_t brix_min_sec_levels[] = {
    { ngx_string("none"),    0 },
    { ngx_string("compat"),  1 },
    { ngx_string("intense"), 2 },
    { ngx_null_string,       0 }
};

/* GSI signed-DH policy [brix_gsi_signed_dh off|auto|require] (phase-48);
 * see the gsi_signed_dh field in src/types/config.h. */
ngx_conf_enum_t brix_signed_dh_modes[] = {
    { ngx_string("off"),     BRIX_GSI_SDH_OFF     },
    { ngx_string("auto"),    BRIX_GSI_SDH_AUTO    },
    { ngx_string("require"), BRIX_GSI_SDH_REQUIRE },
    { ngx_null_string,       0                      }
};

/* Phase 44: io_uring backend tier.  `on` is a hard requirement — startup fails
 * if io_uring cannot be provided (brix_uring_validate_conf in
 * src/config/postconfiguration.c). */
ngx_conf_enum_t brix_io_uring_modes[] = {
    { ngx_string("off"),  BRIX_IO_URING_OFF  },
    { ngx_string("on"),   BRIX_IO_URING_ON   },
    { ngx_string("auto"), BRIX_IO_URING_AUTO },
    { ngx_null_string,    0                    }
};

/* [brix_cache_verify off|best-effort|require] — checksum-on-fill policy for the
 * read-through cache (stream/root plane). Unlike the HTTP plane (off|cvmfs-cas
 * only), the root-plane fill carries the origin-digest hook (xroot kXR_Qcksum),
 * so best-effort/require have teeth here: the staged bytes are checked against
 * the origin's advertised digest before publish. Writes common.cache_verify_mode
 * (the field runtime_server_backend maps into brix_cache_policy_t.verify) — NOT
 * the legacy xcf->cache_verify that fed the retired fetch.c engine. */
ngx_conf_enum_t brix_cache_verify_modes[] = {
    { ngx_string("off"),         BRIX_CACHE_VERIFY_OFF        },
    { ngx_string("best-effort"), BRIX_CACHE_VERIFY_BESTEFFORT },
    { ngx_string("require"),     BRIX_CACHE_VERIFY_REQUIRE    },
    { ngx_null_string,           0                            }
};

/* D-3: per-worker seccomp-BPF syscall filter mode (default off; audit is the
 * risk-free convergence step, enforce kills execve/ptrace/process_vm_*). */
ngx_conf_enum_t brix_seccomp_modes[] = {
    { ngx_string("off"),     BRIX_SECCOMP_OFF     },
    { ngx_string("audit"),   BRIX_SECCOMP_AUDIT   },
    { ngx_string("enforce"), BRIX_SECCOMP_ENFORCE },
    { ngx_null_string,       0                    }
};
