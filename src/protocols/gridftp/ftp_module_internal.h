#ifndef BRIX_GRIDFTP_MODULE_INTERNAL_H
#define BRIX_GRIDFTP_MODULE_INTERNAL_H

/*
 * gridftp/ftp_module_internal.h — cross-file seam between the GridFTP module
 * descriptor / directive setters (ftp_module.c) and the concept siblings split
 * out of it (ftp_module_gsi.c).  Module-internal only: these symbols are shared
 * across the ftp_module_*.c translation units and are NOT part of the public
 * gateway interface in ftp_gateway.h.
 */

#include "ftp_gateway.h"                   /* ngx_stream_brix_ftp_srv_conf_t */

/* brix_ftp_build_gsi — construct the host TLS context (cert/key) and the client
 * proxy trust store once the GSI directives are known.  Defined in
 * ftp_module_gsi.c; called from brix_ftp_merge_conf() in ftp_module.c. */
char *brix_ftp_build_gsi(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *conf);

#endif /* BRIX_GRIDFTP_MODULE_INTERNAL_H */
