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
#include "module_enums.h"

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
