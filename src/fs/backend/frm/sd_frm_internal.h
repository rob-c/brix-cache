/* sd_frm_internal.h — seam between the sd_frm driver and its adapter selector.
 *
 * WHAT: The per-instance driver state and the frm_select_* adapter binders.
 *
 * WHY:  sd_frm.c crossed the 600-line cap (coding-standards §1), so adapter
 *       selection moved to sd_frm_adapter.c; both TUs need the state type.
 *
 * HOW:  Include after sd_frm.h / sd_frm_mss.h. Internal to the frm backend —
 *       nothing outside src/fs/backend/frm/ includes this. */

#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_INTERNAL_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_INTERNAL_H

#include "sd_frm.h"
#include "sd_frm_mss.h"

/* Per-instance driver state: the bound MSS adapter, its opaque context, and
 * the log to attribute stage/recall events to. */
typedef struct {
    const brix_mss_adapter_t *mss;
    void                     *mss_ctx;
    ngx_log_t                *log;
} sd_frm_state;

/* Adapter dialect selection (sd_frm_adapter.c). Each returns 0 = adapter bound
 * into `st`, 1 = not this family (try the next), -1 = hard failure with errno
 * set. brix_sd_frm_create() drives them lib -> exec -> stub. */
int frm_select_lib_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log);
int frm_select_exec_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log);
int frm_select_stub_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_INTERNAL_H */
