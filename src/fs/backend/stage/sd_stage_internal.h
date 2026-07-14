#ifndef BRIX_SD_STAGE_INTERNAL_H
#define BRIX_SD_STAGE_INTERNAL_H

/*
 * sd_stage_internal.h — declarations shared between the two halves of the
 * write-stage decorator after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the decorator's shared instance state, the driver
 *       descriptor, and every method that crosses the sd_stage.c /
 *       sd_stage_write.c file boundary.
 * WHY:  sd_stage.c (the decorator core: read/namespace/xattr/dir forwarders, the
 *       open dispatch, the driver descriptor, and instance lifecycle) and
 *       sd_stage_write.c (the two interposed WRITE paths — the write-back
 *       byte-I/O object and the staged-upload path) were one 725-line file;
 *       splitting keeps each focused and under the 500-line cap. The driver table
 *       lives in sd_stage.c and dispatches to the write methods in
 *       sd_stage_write.c, while the write-back open in sd_stage_write.c stamps
 *       objects with the driver defined in sd_stage.c — so exactly those symbols
 *       become non-static and are declared here.
 * HOW:  Both translation units include this header; nothing here is exported
 *       beyond the stage backend.
 */

#include <ngx_core.h>
#include <limits.h>                 /* PATH_MAX */

#include "fs/backend/sd.h"          /* brix_sd_* driver / instance / object types */
#include "fs/tier/tier.h"          /* brix_stage_policy_t */

/* Decorator instance state: the wrapped source (flush target), the stage store
 * (upload buffer), the flush policy, and the export anchor for SP4 reconcile.
 * Shared because the forwarders + lifecycle (sd_stage.c) and the write paths
 * (sd_stage_write.c) both reach through it. */
typedef struct {
    brix_sd_instance_t  *source;     /* the backend (flush target)            */
    brix_sd_instance_t  *store;      /* the stage buffer (any driver)         */
    brix_stage_policy_t  policy;
    char                   root_canon[PATH_MAX]; /* export anchor for SP4 reconcile */
    ngx_log_t             *log;
} sd_stage_inst_state;

/* The stage decorator's driver descriptor. Defined in sd_stage.c; referenced by
 * the write-back open in sd_stage_write.c, which stamps each write-back object
 * with it so pwrite/pread/fsync/close dispatch to the write-back methods. */
extern const brix_sd_driver_t brix_sd_stage_driver;

/* ---- write paths implemented in sd_stage_write.c, dispatched from sd_stage.c
 *      (the open dispatch calls the write-back open; the driver table above
 *      routes byte-I/O and the staged-upload ops to the methods below). ------- */

/* Write open → a writable object on the stage store carrying the owner identity
 * for the eventual flush. Called by sd_stage_open / sd_stage_open_cred. */
brix_sd_obj_t *sd_stage_open_writeback(brix_sd_instance_t *inst,
    sd_stage_inst_state *is, const char *path, int sd_flags, mode_t mode,
    const brix_sd_cred_t *cred, int *err_out);

/* Write-back byte-I/O methods (dispatched only for objects opened for write). */
ssize_t   sd_stage_wb_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len,
    off_t off);
ssize_t   sd_stage_wb_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ngx_int_t sd_stage_wb_ftruncate(brix_sd_obj_t *obj, off_t length);
ngx_int_t sd_stage_wb_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_int_t sd_stage_wb_fsync(brix_sd_obj_t *obj);
ngx_int_t sd_stage_wb_close(brix_sd_obj_t *obj);

/* Staged-upload methods (the HTTP-PUT interposed path). */
brix_sd_staged_t *sd_stage_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
brix_sd_staged_t *sd_stage_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out);
ssize_t   sd_stage_staged_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_stage_staged_commit(brix_sd_staged_t *st, int noreplace);
void      sd_stage_staged_abort(brix_sd_staged_t *st);

#endif /* BRIX_SD_STAGE_INTERNAL_H */
