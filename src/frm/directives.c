/*
 * directives.c — FRM directive defaults, merge, and the custom watermark setter.
 *
 * WHAT: xrootd_frm_conf_init() seeds the per-server FRM sub-struct with UNSET
 *   sentinels; xrootd_frm_conf_merge() applies main→srv inheritance + defaults,
 *   the stagecmd→prepare_command fallback, and absolute-path validation;
 *   xrootd_frm_set_purge_watermark() parses the TAKE2 "<high> <low>" ratios into
 *   parts-per-million (Category-2 / Phase 4 config, accepted now).
 *
 * WHY: The simple FRM directives are registered in the stream module command
 *   table with nested offsets (offsetof(srv_conf, frm.field)) and the stock
 *   ngx_conf_set_*_slot setters; only the watermark pair needs a custom setter,
 *   and the create/merge logic for the whole sub-struct lives here so
 *   server_conf.c just calls these two helpers.
 */

#include "frm.h"

#include <stdlib.h>


void
xrootd_frm_conf_init(xrootd_frm_conf_t *frm)
{
    frm->enable             = NGX_CONF_UNSET;
    frm->queue_path.len     = 0;  frm->queue_path.data     = NULL;
    frm->max_inflight       = NGX_CONF_UNSET_UINT;
    frm->max_per_source     = NGX_CONF_UNSET_UINT;
    frm->stagecmd.len       = 0;  frm->stagecmd.data       = NULL;
    frm->copycmd.len        = 0;  frm->copycmd.data        = NULL;
    frm->copymax            = NGX_CONF_UNSET_UINT;
    frm->stage_ttl          = NGX_CONF_UNSET_MSEC;
    frm->xfrhold_ms         = NGX_CONF_UNSET_MSEC;
    frm->stage_wait         = NGX_CONF_UNSET_UINT;
    frm->async_recall       = NGX_CONF_UNSET;
    frm->fail_backoff_ms    = NGX_CONF_UNSET_MSEC;
    frm->fail_retries       = NGX_CONF_UNSET_UINT;
    frm->residency_cmd.len  = 0;  frm->residency_cmd.data  = NULL;
    frm->copy_timeout       = NGX_CONF_UNSET_MSEC;
    frm->stage_dir.len      = 0;  frm->stage_dir.data      = NULL;
    frm->force_scratch      = NGX_CONF_UNSET;
    frm->control_dir.len    = 0;  frm->control_dir.data    = NULL;
    frm->migrate_copycmd.len= 0;  frm->migrate_copycmd.data= NULL;
    frm->purge_hi_ppm       = NGX_CONF_UNSET_UINT;
    frm->purge_lo_ppm       = NGX_CONF_UNSET_UINT;
    frm->purge_interval_ms  = NGX_CONF_UNSET_MSEC;
    frm->queue              = NULL;
}

char *
xrootd_frm_conf_merge(ngx_conf_t *cf, xrootd_frm_conf_t *conf,
                      xrootd_frm_conf_t *prev, const ngx_str_t *prepare_command)
{
    ngx_conf_merge_value(conf->enable,       prev->enable,       0);
    ngx_conf_merge_str_value(conf->queue_path, prev->queue_path, "");
    ngx_conf_merge_uint_value(conf->max_inflight, prev->max_inflight, 64);
    ngx_conf_merge_uint_value(conf->max_per_source, prev->max_per_source, 0);
    ngx_conf_merge_str_value(conf->stagecmd, prev->stagecmd, "");
    ngx_conf_merge_str_value(conf->copycmd,  prev->copycmd,  "");
    ngx_conf_merge_uint_value(conf->copymax, prev->copymax,  4);
    ngx_conf_merge_msec_value(conf->stage_ttl, prev->stage_ttl, 600000);
    ngx_conf_merge_msec_value(conf->xfrhold_ms, prev->xfrhold_ms, 30000);
    ngx_conf_merge_uint_value(conf->stage_wait, prev->stage_wait, 30);
    ngx_conf_merge_value(conf->async_recall, prev->async_recall, 0);
    ngx_conf_merge_msec_value(conf->fail_backoff_ms, prev->fail_backoff_ms, 60000);
    ngx_conf_merge_uint_value(conf->fail_retries, prev->fail_retries, 3);
    ngx_conf_merge_str_value(conf->residency_cmd, prev->residency_cmd, "");
    ngx_conf_merge_msec_value(conf->copy_timeout, prev->copy_timeout, 0);
    ngx_conf_merge_str_value(conf->stage_dir, prev->stage_dir, "");
    ngx_conf_merge_value(conf->force_scratch, prev->force_scratch, 0);
    ngx_conf_merge_str_value(conf->control_dir, prev->control_dir, "");
    ngx_conf_merge_str_value(conf->migrate_copycmd, prev->migrate_copycmd, "");
    ngx_conf_merge_uint_value(conf->purge_hi_ppm, prev->purge_hi_ppm, 0);
    ngx_conf_merge_uint_value(conf->purge_lo_ppm, prev->purge_lo_ppm, 0);
    ngx_conf_merge_msec_value(conf->purge_interval_ms, prev->purge_interval_ms,
                              300000);

    /* The stage command falls back to the legacy prepare_command when unset, so
     * an existing xrootd_prepare_command keeps working under xrootd_frm. */
    if (conf->stagecmd.len == 0 && prepare_command != NULL
        && prepare_command->len)
    {
        conf->stagecmd = *prepare_command;
    }

    if (conf->enable) {
        if (conf->queue_path.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_frm on requires xrootd_frm_queue_path");
            return NGX_CONF_ERROR;
        }
        if (conf->queue_path.data[0] != '/') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_frm_queue_path \"%V\" must be an absolute path",
                &conf->queue_path);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}


/* Parse "0.95" / "95%" / "95" into parts-per-million, clamped to [0, 1e6]. */
static ngx_uint_t
frm_ratio_to_ppm(const ngx_str_t *s)
{
    char    buf[32];
    double  v;
    size_t  n = s->len;

    if (n == 0 || n >= sizeof(buf)) {
        return 0;
    }
    ngx_memcpy(buf, s->data, n);
    buf[n] = '\0';
    v = strtod(buf, NULL);
    if (buf[n - 1] == '%' || v > 1.0) {     /* a percentage like "95" or "95%" */
        v /= 100.0;
    }
    if (v < 0.0) { v = 0.0; }
    if (v > 1.0) { v = 1.0; }
    return (ngx_uint_t) (v * 1000000.0 + 0.5);
}

char *
xrootd_frm_set_purge_watermark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_frm_conf_t *frm = (xrootd_frm_conf_t *)
                             ((char *) conf + cmd->offset);
    ngx_str_t         *value = cf->args->elts;

    frm->purge_hi_ppm = frm_ratio_to_ppm(&value[1]);
    frm->purge_lo_ppm = frm_ratio_to_ppm(&value[2]);

    if (frm->purge_lo_ppm > frm->purge_hi_ppm) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_frm_purge_watermark: low (%ui) must not exceed high (%ui)",
            frm->purge_lo_ppm, frm->purge_hi_ppm);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
