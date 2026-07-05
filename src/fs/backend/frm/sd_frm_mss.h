#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_MSS_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_MSS_H

/*
 * sd_frm_mss.h — the FRM driver's mass-storage-system (MSS) adapters.
 *
 * Two pluggable back ends behind the brix_mss_adapter_t vtable: the built-in
 * "stub" local-directory tape simulator (test/dev + the default) and the "exec"
 * adapter that drives a real HSM via an external stage command.  Split out of
 * sd_frm.c so the adapter implementations live apart from the driver that
 * dispatches to them.  Each adapter's context is opaque — the driver holds it as
 * a void * and only ever touches it through the vtable; brix_mss_*_create build
 * it, brix_mss_adapter_t::destroy frees it.
 */

#include "sd_frm.h"            /* brix_mss_adapter_t */

extern const brix_mss_adapter_t brix_mss_stub_adapter;
extern const brix_mss_adapter_t brix_mss_exec_adapter;

/* Build an adapter context (the sd_frm_state mss_ctx).  Returns the opaque
 * context, or NULL with errno = ENOMEM.  `location` is the online-buffer / stub
 * tape root; `stagecmd` is the exec adapter's stage command. */
void *brix_mss_stub_create(const char *location, ngx_log_t *log);
void *brix_mss_exec_create(const char *location, const char *stagecmd,
          ngx_log_t *log);

/* Filesystem helpers shared by both adapters (defined in sd_frm_stub.c). */
void frm_mkparents(const char *path);
int  stub_copyfile(const char *src, const char *dst, mode_t mode);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_MSS_H */
