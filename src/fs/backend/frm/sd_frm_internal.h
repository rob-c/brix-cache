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

#define SD_FRM_ST(inst)  ((sd_frm_state *) (inst)->state)

/* Per-staged-write handle state (create_online fd + the publish key), shared
 * between the driver table (sd_frm.c) and the staged-write family, which moved
 * to sd_frm_staged.c when sd_frm.c hit the 600-line cap (coding-standards §1). */
typedef struct {
    sd_frm_state *fst;
    int           fd;
    char          key[1024];
} sd_frm_staged_state;

/* The staged-write family + the phase-107 C3 durable-publish barrier
 * (sd_frm_staged.c) — referenced by the driver vtable in sd_frm.c. */
brix_sd_staged_t *sd_frm_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, off_t declared_size, int *err_out);
ssize_t sd_frm_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off);
ngx_int_t sd_frm_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre);
void sd_frm_staged_abort(brix_sd_staged_t *st);
ngx_int_t sd_frm_sync_publish(brix_sd_instance_t *inst, const char *path);
ngx_int_t sd_frm_exchange(brix_sd_instance_t *inst, const char *a,
    const char *b);

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
