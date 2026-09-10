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
#include <spawn.h>                  /* frm_exec_spawn's file actions */

/* Per-instance driver state: the bound MSS adapter, its opaque context, and
 * the log to attribute stage/recall events to. */
typedef struct {
    const brix_mss_adapter_t *mss;
    void                     *mss_ctx;
    ngx_log_t                *log;
    /* The tape:// URL's base (the online buffer lives at <location>/.online);
     * phase-115 W3.2 purge engine walks it. */
    char                      location[PATH_MAX];
    /* 2.0 F3: the export this tier serves (brix_sd_frm_set_export_root);
     * the anchor a deferred archive seal persists in its journal record. */
    char                      export_root[1024];
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

/* Bounded synchronous recall + the recall vtable slots (sd_frm_recall.c). */
int frm_ensure_online(sd_frm_state *st, const char *key, int *recalled);
ngx_int_t sd_frm_recall(brix_sd_instance_t *inst, const char *key,
    char reqid_out[40]);
ngx_int_t sd_frm_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40]);

/* Adapter dialect selection (sd_frm_adapter.c). Each returns 0 = adapter bound
 * into `st`, 1 = not this family (try the next), -1 = hard failure with errno
 * set. brix_sd_frm_create() drives them lib -> exec -> stub. */
int frm_select_lib_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log);
int frm_select_exec_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log);
int frm_select_stub_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log);
/* Phase-115 W3.1: wrap the bound adapter in the dataset archiver when
 * opts->arc_depth > 0. 0 ok (also when nothing to do) / -1 with errno, the
 * inner adapter already destroyed. */
int frm_select_arc_decorator(sd_frm_state *st, const brix_sd_frm_opts_t *opts,
    ngx_log_t *log);

/* sd_frm_exec.c: posix_spawn an operator program with the adapter's
 * hygiene -- every fd above stderr closed in the child, its own session
 * (so a deadline kill reaches the whole process group). `fa` may carry
 * the caller's dup2/close actions (NULL = none). 0 ok / -1 with errno.
 *
 * ONLY for the streaming `dread` listing. A program whose EXIT STATUS is
 * the answer must never be a direct child of a worker -- nginx's SIGCHLD
 * handler reaps it first and the status is lost -- so those run under
 * brix_subprocess_run (core/compat/subprocess.h), which owns the deadline
 * and the process-group kill as well (2.0, 2026-09-09). */
int frm_exec_spawn(pid_t *pid, const char *prog, char *const argv[],
    posix_spawn_file_actions_t *fa);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_INTERNAL_H */
