/*
 * module_enums.h — declarations for the stream module's directive enum tables
 * (defined in module_enums.c).  These are the value tables referenced by the
 * ngx_command_t directive table in module.c.
 */
#ifndef BRIX_STREAM_MODULE_ENUMS_H
#define BRIX_STREAM_MODULE_ENUMS_H

#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_conf_enum_t brix_cns_modes[];
extern ngx_conf_enum_t brix_auth_modes[];
/* Engine/audit tables are the shared XrdAcc ones (defined in acc/config.c,
 * also declared in acc/acc.h): brix_authdb_engine's value set is exactly
 * brix_acc_format_modes (native|xrdacc). Externs here so this fragment does
 * not need acc.h (phase-105 W3 dedup). */
extern ngx_conf_enum_t brix_acc_format_modes[];
extern ngx_conf_enum_t brix_acc_audit_modes[];
extern ngx_conf_enum_t brix_hc_types[];
extern ngx_conf_enum_t brix_cms_roles[];
extern ngx_conf_enum_t brix_security_levels[];
extern ngx_conf_enum_t brix_min_sec_levels[];
extern ngx_conf_enum_t brix_signed_dh_modes[];
extern ngx_conf_enum_t brix_io_uring_modes[];
extern ngx_conf_enum_t brix_cache_verify_modes[];
extern ngx_conf_enum_t brix_seccomp_modes[];
extern ngx_conf_enum_t brix_signing_policy_modes[];
extern ngx_conf_enum_t brix_crl_modes[];

#endif /* BRIX_STREAM_MODULE_ENUMS_H */
