/*
 * module_enums.c — directive enum value tables for the stream module.
 *
 * The textual value tables for the enum-typed `xrootd_*` directives, moved out
 * of module.c so the command table there stays focused.  Each maps config words
 * to the XROOTD_* constants used by the rest of the module.
 */
#include "core/ngx_xrootd_module.h"
#include "cms/cns.h"               /* §6 CNS mode enum */
#include "manager/health_check.h"  /* XROOTD_HC_TYPE_* */
#include "module_enums.h"

/* §6 xrootd_cns mode values. */
ngx_conf_enum_t xrootd_cns_modes[] = {
    { ngx_string("off"),     XROOTD_CNS_OFF     },
    { ngx_string("emit"),    XROOTD_CNS_EMIT    },
    { ngx_string("collect"), XROOTD_CNS_COLLECT },
    { ngx_null_string,       0                  }
};

/* Text values accepted by `xrootd_auth` in nginx.conf ("both" = GSI+token). */
ngx_conf_enum_t xrootd_auth_modes[] = {
    { ngx_string("none"),  XROOTD_AUTH_NONE  },
    { ngx_string("gsi"),   XROOTD_AUTH_GSI   },
    { ngx_string("token"), XROOTD_AUTH_TOKEN },
    { ngx_string("both"),  XROOTD_AUTH_BOTH  },
    { ngx_string("sss"),   XROOTD_AUTH_SSS   },
    { ngx_string("unix"),  XROOTD_AUTH_UNIX  },
    { ngx_string("krb5"),  XROOTD_AUTH_KRB5  },
    { ngx_string("host"),  XROOTD_AUTH_HOST  },
    { ngx_string("pwd"),   XROOTD_AUTH_PWD   },
    { ngx_null_string,     0                 }
};

/* `xrootd_authdb_format` — pick the authorization engine for the authdb file. */
ngx_conf_enum_t xrootd_authdb_format_modes[] = {
    { ngx_string("native"), XROOTD_AUTHDB_FORMAT_NATIVE },
    { ngx_string("xrdacc"), XROOTD_AUTHDB_FORMAT_XRDACC },
    { ngx_null_string,      0                            }
};

/* `xrootd_authdb_audit` — which authorization decisions to log. */
ngx_conf_enum_t xrootd_authdb_audit_modes[] = {
    { ngx_string("none"),  XROOTD_AUTHDB_AUDIT_NONE  },
    { ngx_string("deny"),  XROOTD_AUTHDB_AUDIT_DENY  },
    { ngx_string("grant"), XROOTD_AUTHDB_AUDIT_GRANT },
    { ngx_string("all"),   XROOTD_AUTHDB_AUDIT_ALL   },
    { ngx_null_string,     0                         }
};

/* Phase 22 — health-check probe type. */
ngx_conf_enum_t xrootd_hc_types[] = {
    { ngx_string("ping"), XROOTD_HC_TYPE_PING },
    { ngx_string("stat"), XROOTD_HC_TYPE_STAT },
    { ngx_null_string,    0                   }
};

/* `xrootd_security_level` — kXR_sigver enforcement, none .. pedantic. */
ngx_conf_enum_t xrootd_security_levels[] = {
    { ngx_string("none"),       0 },
    { ngx_string("compatible"), 1 },
    { ngx_string("standard"),   2 },
    { ngx_string("intense"),    3 },
    { ngx_string("pedantic"),   4 },
    { ngx_null_string,          0 }
};

/* GSI signed-DH policy [xrootd_gsi_signed_dh off|auto|require] (phase-48);
 * see the gsi_signed_dh field in src/types/config.h. */
ngx_conf_enum_t xrootd_signed_dh_modes[] = {
    { ngx_string("off"),     XROOTD_GSI_SDH_OFF     },
    { ngx_string("auto"),    XROOTD_GSI_SDH_AUTO    },
    { ngx_string("require"), XROOTD_GSI_SDH_REQUIRE },
    { ngx_null_string,       0                      }
};

/* Phase 44: io_uring backend tier.  `on` is a hard requirement — startup fails
 * if io_uring cannot be provided (xrootd_uring_validate_conf in
 * src/config/postconfiguration.c). */
ngx_conf_enum_t xrootd_io_uring_modes[] = {
    { ngx_string("off"),  XROOTD_IO_URING_OFF  },
    { ngx_string("on"),   XROOTD_IO_URING_ON   },
    { ngx_string("auto"), XROOTD_IO_URING_AUTO },
    { ngx_null_string,    0                    }
};
