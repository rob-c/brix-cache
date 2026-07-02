/*
 * module_enums.h — declarations for the stream module's directive enum tables
 * (defined in module_enums.c).  These are the value tables referenced by the
 * ngx_command_t directive table in module.c.
 */
#ifndef XROOTD_STREAM_MODULE_ENUMS_H
#define XROOTD_STREAM_MODULE_ENUMS_H

#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_conf_enum_t xrootd_cns_modes[];
extern ngx_conf_enum_t xrootd_auth_modes[];
extern ngx_conf_enum_t xrootd_authdb_format_modes[];
extern ngx_conf_enum_t xrootd_authdb_audit_modes[];
extern ngx_conf_enum_t xrootd_hc_types[];
extern ngx_conf_enum_t xrootd_security_levels[];
extern ngx_conf_enum_t xrootd_signed_dh_modes[];
extern ngx_conf_enum_t xrootd_io_uring_modes[];

#endif /* XROOTD_STREAM_MODULE_ENUMS_H */
