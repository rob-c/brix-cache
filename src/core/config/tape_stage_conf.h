/*
 * tape_stage_conf.h — per-server tape/stage directive config.
 *
 * WHAT: The `brix_frm_*` directive config struct + its init/merge/watermark
 *   helpers. Embedded as `frm` in ngx_stream_brix_srv_conf_t (name kept for
 *   back-compat) and read by the staging callers (prepare/tape_rest/open) for
 *   enable/stage_ttl/async_recall/stage_wait/control_dir.
 *
 * WHY: The FRM-dissolution (§13b, phase-64 P6) moved the staging IMPLEMENTATION to
 *   the composable stage request registry (src/fs/xfer/) + the sd_frm backend, so
 *   src/frm/ was deleted. This header is the config surface that survives: the
 *   directive names + parse/merge, lifted out of the deleted src/frm/frm.h so the
 *   many `brix_frm_*` directives keep working unchanged. The legacy
 *   FRM-implementation knobs (stagecmd/copycmd/residency_cmd/watermarks/queue_path)
 *   are accepted for config compatibility but no longer drive a bespoke engine.
 */
#ifndef BRIX_TAPE_STAGE_CONF_H
#define BRIX_TAPE_STAGE_CONF_H

/* Lightweight nginx-core types only (safe to include from src/types/config.h). */
#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    ngx_flag_t    enable;            /* brix_frm                            */
    ngx_str_t     queue_path;        /* brix_frm_queue_path (accepted)      */
    ngx_uint_t    max_inflight;      /* brix_frm_max_inflight               */
    ngx_uint_t    max_per_source;    /* brix_frm_max_per_source             */
    ngx_str_t     stagecmd;          /* brix_frm_stagecmd (accepted)        */
    ngx_str_t     copycmd;           /* brix_frm_copycmd (accepted)         */
    ngx_uint_t    copymax;           /* brix_frm_copymax (accepted)         */
    ngx_msec_t    stage_ttl;         /* brix_frm_stage_ttl                  */
    ngx_msec_t    xfrhold_ms;        /* brix_frm_xfrhold (accepted)         */
    ngx_uint_t    stage_wait;        /* brix_frm_stage_wait                 */
    ngx_flag_t    async_recall;      /* brix_frm_async_recall               */
    ngx_msec_t    fail_backoff_ms;   /* brix_frm_fail_backoff (accepted)    */
    ngx_uint_t    fail_retries;      /* brix_frm_fail_retries (accepted)    */
    ngx_str_t     residency_cmd;     /* brix_frm_residency_cmd (accepted)   */
    ngx_msec_t    copy_timeout;      /* brix_frm_copy_timeout (accepted)    */
    ngx_str_t     stage_dir;         /* brix_frm_stage_dir (accepted)       */
    ngx_flag_t    force_scratch;     /* brix_frm_force_scratch (accepted)   */
    ngx_str_t     control_dir;       /* brix_frm_control_dir (registry dir) */
    ngx_str_t     migrate_copycmd;   /* brix_frm_migrate_copycmd (accepted) */
    ngx_uint_t    purge_hi_ppm;      /* brix_frm_purge_watermark high       */
    ngx_uint_t    purge_lo_ppm;      /* brix_frm_purge_watermark low        */
    ngx_msec_t    purge_interval_ms; /* brix_frm_purge_interval (accepted)  */
} brix_frm_conf_t;

/* directive helpers (src/config/tape_stage_conf.c) */
void  brix_frm_conf_init(brix_frm_conf_t *frm);
char *brix_frm_conf_merge(ngx_conf_t *cf, brix_frm_conf_t *conf,
                            brix_frm_conf_t *prev,
                            const ngx_str_t *prepare_command);
/* custom setter referenced from the stream module command table (TAKE2 ratios) */
char *brix_frm_set_purge_watermark(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);

#endif /* BRIX_TAPE_STAGE_CONF_H */
