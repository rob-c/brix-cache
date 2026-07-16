#pragma once
/*
 * open_resolved_file_internal.h — shared state + cross-file entry points for the
 * kXR_open resolved-file pipeline (phase-79 file-size split).
 *
 * WHAT: Declares the per-open carrier struct `brix_open_args_t` and the handful
 *       of pipeline-stage entry points that are DEFINED in one split translation
 *       unit and CALLED from another. Every open_resolved_file*.c includes this.
 *
 * WHY:  open_resolved_file.c grew past the 500-line focus limit. It was split
 *       into cohesive stages — staging preflight, the open(2)/driver open ops,
 *       backend/credential dispatch, post-fd handle finalize, and the orchestrator
 *       (which also builds/sends the reply). The stages share exactly one state
 *       object and a small set of boundary functions; those live here so no stage
 *       reaches into another's internals and the linker resolves the cross-calls.
 *
 * HOW:  The struct is byte-identical to the original file-local definition (pure
 *       relocation). Each declared function is non-static in its defining .c and
 *       carries the same signature it had as a file-local static.
 *
 * Requires: open.h (brix_ctx_t / ngx types / brix_open_request_t),
 *           fs/vfs/vfs.h (brix_vfs_ctx_t), fs/backend/sd.h (brix_sd_instance_t),
 *           <sys/stat.h> (struct stat / mode_t), <limits.h> (PATH_MAX) before use.
 */

#include "open.h"
#include "fs/vfs/vfs.h"
#include "fs/backend/sd.h"

#include <sys/stat.h>
#include <limits.h>

/*
 * brix_open_args_t — the per-request kXR_open state threaded through the
 * static open pipeline (phase-72 B5 parameter consolidation).
 *
 * WHAT: One carrier for everything brix_open_resolved_file computes once — the
 *       session/config pointers, the decoded kXR_open intent, the staging
 *       decision + POSC/resume temp path, the allocated handle slot, the open
 *       outcome (fd/stat/driver routing) and the kXR_retstat buffer — so the
 *       pipeline stages take this struct instead of many positional parameters.
 *
 * WHY:  The open path is a linear pipeline (preflight → dispatch → finalize →
 *       response) whose stages share one request's state; passing it positionally
 *       bloated every signature past the complexity gate and made call sites
 *       error-prone (runs of adjacent same-typed flags).
 *
 * HOW:  brix_open_resolved_file zeroes the struct, fills the request-constant
 *       fields, then each stage reads what it needs and writes only the fields
 *       it owns (preflight: use_resume/stage/posc_temp_path; dispatch:
 *       fd/st/driver_backed/wt_via_stage; finalize: want_stat/statbuf).
 *       Pure signature consolidation — no logic moved.
 */
typedef struct {
    /* request identity + config (constant for the whole open) */
    brix_ctx_t                 *ctx;
    ngx_connection_t           *c;
    ngx_stream_brix_srv_conf_t *conf;
    const char                 *resolved;    /* canonical absolute final path */
    uint16_t                    options;     /* kXR_open option bits */
    ngx_flag_t                  is_write;
    uint8_t                     codec;       /* negotiated inline codec (0 = none) */

    /* decoded POSIX open(2) intent (open_flags.h mapping) */
    int                         oflags;
    int                         is_readable;
    mode_t                      create_mode;

    /* Staging decision.  use_posc: kXR_posc write — stage to a random temp,
     * rename on clean close, unlink on non-clean close.  use_resume
     * (brix_upload_resume on): stage to a deterministic identity-keyed
     * partial that SURVIVES a non-clean close so a reconnecting client
     * resumes in place — a superset of POSC staging, so `stage` drives the
     * open + commit for both. */
    ngx_flag_t                  use_posc;
    ngx_flag_t                  use_resume;
    ngx_flag_t                  stage;
    ngx_flag_t                  from_cache;  /* server-managed cache-root open */
    char                        posc_temp_path[PATH_MAX];

    /* open outcome */
    int                         idx;         /* allocated fhandle slot */
    int                         fd;          /* POSIX fd / driver block-0 fd / -1 */
    struct stat                *st;          /* caller-owned, zero-initialised */
    ngx_int_t                   driver_backed;
    ngx_int_t                   wt_via_stage;

    /* kXR_retstat */
    ngx_flag_t                  want_stat;   /* cleared when the stat is unavailable */
    char                        statbuf[256];
} brix_open_args_t;

/* ---- cross-file pipeline entry points (defined once, called across files) ----
 *
 * Each is non-static in its defining translation unit; see the WHAT/WHY/HOW doc
 * block on the definition for behaviour. Grouped here so the split .c files link.
 */

/* open_resolved_file_staging.c — pre-open staging preflight (returns NGX_DECLINED
 * to proceed, else the already-sent error's rc). */
ngx_int_t brix_open_stage_preflight(brix_open_args_t *a);

/* open_resolved_file_open.c — the low-level open(2)/driver-open operations and the
 * errno→kXR error mapper (called by the dispatch stage). */
ngx_int_t brix_open_resolved_via_driver(brix_open_args_t *a,
    brix_vfs_ctx_t *vctx, brix_sd_instance_t *sd, const char *logical);
ngx_int_t brix_open_map_open_error(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *resolved, int err, ngx_flag_t is_write);
int       brix_open_posix_dispatch(brix_open_args_t *a);

/* open_resolved_file_dispatch.c — backend/credential routing (driver vs POSIX). */
ngx_int_t brix_open_dispatch_open(brix_open_args_t *a);
/* True when a WRITE's ns leaf is staged-only (no CAP_RANDOM_WRITE, no .pwrite)
 * and must route through the whole-object staged adapter. Also used by the
 * orchestrator's resume divert (P80.2). */
int       brix_open_write_needs_staged(brix_open_args_t *a,
    brix_sd_instance_t *sd_inst);

/* open_resolved_file_finalize.c — post-fd handle finalization (validate, init,
 * CSI, throttle, monitor, path, retstat, wt-decide). */
ngx_int_t brix_open_finalize_handle(brix_open_args_t *a);

/* open_resolved_file.c — kXR_retstat metadata string builder (called by the
 * finalize stage; kept with the reply-assembly code in the orchestrator TU). */
void      brix_open_build_retstat(brix_open_args_t *a);
