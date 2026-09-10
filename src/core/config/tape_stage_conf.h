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
 *   FRM-implementation knobs (stagecmd/copycmd/residency_cmd/queue_path) are
 *   accepted for config compatibility but no longer drive a bespoke engine; the
 *   purge watermark/cap/interval trio drives the phase-115 W3.2 purge engine.
 */
#ifndef BRIX_TAPE_STAGE_CONF_H
#define BRIX_TAPE_STAGE_CONF_H

/* Lightweight nginx-core types only (safe to include from src/types/config.h). */
#include <ngx_config.h>
#include <ngx_core.h>

/* 2.0 F4: one `brix_frm_purge_policy {*|<group>} <hi> <lo> [hold <time>]
 * [polprog]` line. Thresholds are bytes (percent = 0) or ppm of the group's
 * brix_oss_space quota (percent = 1); the engine scales them at arm time. */
typedef struct {
    ngx_str_t     group;             /* a brix_oss_space name, or "*"     */
    off_t         hi;                /* size thresholds                     */
    off_t         lo;
    ngx_uint_t    hi_ppm;            /* percentage thresholds (ppm)         */
    ngx_uint_t    lo_ppm;
    ngx_flag_t    percent;           /* which pair above is the live one    */
    time_t        hold_s;            /* 0 = the engine's 30 s floor         */
    ngx_flag_t    polprog;           /* releases need the program's approval*/
} brix_frm_purge_policy_t;

typedef struct {
    ngx_flag_t    enable;            /* brix_frm                            */
    ngx_str_t     queue_path;        /* brix_frm_queue_path: journal dir    */
    ngx_uint_t    max_inflight;      /* brix_frm_max_inflight               */
    ngx_str_t     stagecmd;          /* brix_frm_stagecmd: exec MSS program */
    ngx_uint_t    copymax;           /* brix_frm_copymax: in-flight movers  */
    ngx_msec_t    stage_ttl;         /* brix_frm_stage_ttl                  */
    ngx_uint_t    stage_wait;        /* brix_frm_stage_wait                 */
    ngx_flag_t    async_recall;      /* brix_frm_async_recall               */
    ngx_msec_t    fail_backoff_ms;   /* brix_frm_fail_backoff: retry sweep  */
    ngx_uint_t    fail_retries;      /* brix_frm_fail_retries: dead-letter  */
    ngx_msec_t    copy_timeout;      /* brix_frm_copy_timeout: exec deadline*/
    ngx_str_t     stagemsg;          /* brix_frm_stagemsg: StageEvents file  */
    ngx_str_t     control_dir;       /* brix_frm_control_dir (registry dir) */
    /* Phase-115 W3.2 tape-buffer purge engine (process_frm_purge.c): the
     * filesystem-watermark arm, the owned-bytes cap arm, and the cadence. */
    ngx_uint_t    purge_hi_ppm;      /* brix_frm_purge_watermark high (ppm) */
    ngx_uint_t    purge_lo_ppm;      /*   ...low watermark (ppm)            */
    off_t         purge_max_bytes;   /* brix_frm_purge_max_bytes (0 = off)  */
    ngx_msec_t    purge_interval_ms; /* brix_frm_purge_interval             */
    /* 2.0 F4: per-group rules + the external policy program. */
    ngx_array_t  *purge_policies;    /* brix_frm_purge_policy_t[]; NULL=none*/
    ngx_str_t     purge_polprog;     /* brix_frm_purge_polprog              */
} brix_frm_conf_t;

/* 2.0 F1 (ADR-3b, 2026-09-08): the stage engine, its FAILED-record retry sweep
 * and the exec MSS adapter are process-wide, so the seven values below are
 * published ONCE per configuration by the `brix_frm on` server blocks — every
 * such block must agree on each value it sets (the merge refuses a
 * disagreement with [emerg]). Unset values fall back to the defaults below,
 * which reproduce the pre-2.0 built-in behaviour. */
#define BRIX_FRM_COPYMAX_DEFAULT         8        /* was STAGE_MAX_INFLIGHT   */
#define BRIX_FRM_FAIL_RETRIES_DEFAULT    5        /* was the deny attempt cap */
#define BRIX_FRM_FAIL_BACKOFF_DEFAULT_MS 60000
#define BRIX_FRM_FAIL_BACKOFF_MIN_MS     1000     /* sweep period floor       */

typedef struct {
    ngx_cycle_t  *cycle;             /* the cycle whose merge filled it     */
    unsigned      published;         /* a brix_frm on server exists         */
    unsigned      explicit_mask;     /* BRIX_FRM_ENGINE_* bits set by a line */
    char          queue_path[1024];  /* durable stage-journal directory     */
    char          stagecmd[4096];    /* exec adapter program ("" = env)     */
    char          stagemsg[1024];    /* StageEvents feed file ("" = off)    */
    ngx_uint_t    copymax;           /* thread-offload in-flight bound      */
    ngx_uint_t    fail_retries;      /* dead-letter attempt cap             */
    ngx_msec_t    fail_backoff_ms;   /* FAILED-record retry sweep period    */
    ngx_msec_t    copy_timeout_ms;   /* exec child deadline (0 = none)      */
} brix_frm_engine_conf_t;

#define BRIX_FRM_ENGINE_COPYMAX       0x01
#define BRIX_FRM_ENGINE_FAIL_RETRIES  0x02
#define BRIX_FRM_ENGINE_FAIL_BACKOFF  0x04
#define BRIX_FRM_ENGINE_COPY_TIMEOUT  0x08

/* The published engine configuration of `cycle`, or NULL when no `brix_frm on`
 * server block exists in it (the engine then keeps its env/built-in defaults). */
const brix_frm_engine_conf_t *brix_frm_engine_conf(const ngx_cycle_t *cycle);

/* directive helpers (src/config/tape_stage_conf.c) */
void  brix_frm_conf_init(brix_frm_conf_t *frm);
char *brix_frm_conf_merge(ngx_conf_t *cf, brix_frm_conf_t *conf,
                            brix_frm_conf_t *prev);
/* custom setter referenced from the stream module command table (TAKE2 ratios) */
char *brix_frm_set_purge_watermark(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);

/* 2.0 F4 (src/core/config/frm_purge_policy_conf.c): the per-group rule
 * setter, its merge (inherit + polprog/program consistency, called by
 * brix_frm_conf_merge) and the cross-check against the server's
 * brix_oss_space table, which the server merge runs once that table has
 * been inherited. */
char *brix_frm_set_purge_policy(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
char *brix_frm_purge_policy_merge(ngx_conf_t *cf, brix_frm_conf_t *conf,
                                    brix_frm_conf_t *prev);
char *brix_frm_purge_policy_check(ngx_conf_t *cf, const ngx_array_t *spaces,
                                    const brix_frm_conf_t *frm);

/* Grammar + ownership checks shared by every directive naming a program the
 * worker runs (brix_frm_stagecmd, brix_frm_purge_polprog): absolute, short
 * enough, and never group- or world-writable when it already exists. */
char *brix_frm_check_program(ngx_conf_t *cf, const char *directive,
                               const ngx_str_t *cmd, const char *usage);

#endif /* BRIX_TAPE_STAGE_CONF_H */
