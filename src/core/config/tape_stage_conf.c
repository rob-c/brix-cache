/*
 * tape_stage_conf.c — tape/stage directive defaults, merge, and the watermark
 * setter. Lifted out of the deleted src/frm/directives.c by the FRM-dissolution;
 * see tape_stage_conf.h. The simple directives are registered in the stream module
 * command table with nested offsets (offsetof(srv_conf, frm.field)) + stock
 * ngx_conf_set_*_slot setters; only the watermark pair needs a custom setter.
 */

#include "tape_stage_conf.h"
#include "fs/backend/frm/sd_frm.h"   /* brix_sd_frm_set_exec_defaults */

#include <stdlib.h>
#include <sys/stat.h>


void
brix_frm_conf_init(brix_frm_conf_t *frm)
{
    frm->enable             = NGX_CONF_UNSET;
    frm->queue_path.len     = 0;  frm->queue_path.data     = NULL;
    frm->max_inflight       = NGX_CONF_UNSET_UINT;
    frm->stagecmd.len       = 0;  frm->stagecmd.data       = NULL;
    frm->copymax            = NGX_CONF_UNSET_UINT;
    frm->stage_ttl          = NGX_CONF_UNSET_MSEC;
    frm->stage_wait         = NGX_CONF_UNSET_UINT;
    frm->async_recall       = NGX_CONF_UNSET;
    frm->fail_backoff_ms    = NGX_CONF_UNSET_MSEC;
    frm->fail_retries       = NGX_CONF_UNSET_UINT;
    frm->copy_timeout       = NGX_CONF_UNSET_MSEC;
    frm->control_dir.len    = 0;  frm->control_dir.data    = NULL;
    frm->purge_hi_ppm       = NGX_CONF_UNSET_UINT;
    frm->purge_lo_ppm       = NGX_CONF_UNSET_UINT;
    frm->purge_max_bytes    = NGX_CONF_UNSET;
    frm->purge_interval_ms  = NGX_CONF_UNSET_MSEC;
    frm->purge_policies     = NGX_CONF_UNSET_PTR;
    frm->purge_polprog.len  = 0;  frm->purge_polprog.data  = NULL;
}


/* ---- 2.0 F1: the process-wide engine snapshot ------------------------------
 * One snapshot per configuration cycle (the phase-116 dns_registry precedent:
 * a cycle-keyed static, reset by the first merge of a new cycle so a reload
 * that drops every `brix_frm on` block also drops the published values). The
 * exec MSS adapter is told about the stage command / deadline right here, in
 * the master, so `nginx -t`, master-built tier instances and every forked
 * worker see the same program without a per-worker hand-off. */
static brix_frm_engine_conf_t  frm_engine;

static brix_frm_engine_conf_t *
frm_engine_for(ngx_conf_t *cf)
{
    if (frm_engine.cycle != cf->cycle) {
        ngx_memzero(&frm_engine, sizeof(frm_engine));
        frm_engine.cycle           = cf->cycle;
        frm_engine.copymax         = BRIX_FRM_COPYMAX_DEFAULT;
        frm_engine.fail_retries    = BRIX_FRM_FAIL_RETRIES_DEFAULT;
        frm_engine.fail_backoff_ms = BRIX_FRM_FAIL_BACKOFF_DEFAULT_MS;
        brix_sd_frm_set_exec_defaults(NULL, 0);
    }
    return &frm_engine;
}

const brix_frm_engine_conf_t *
brix_frm_engine_conf(const ngx_cycle_t *cycle)
{
    if (cycle == NULL || frm_engine.cycle != cycle || !frm_engine.published) {
        return NULL;
    }
    return &frm_engine;
}

/* Publish one string value: the first `brix_frm on` block sets it, a later one
 * must repeat it verbatim or leave it unset. */
static char *
frm_publish_str(ngx_conf_t *cf, const char *name, char *slot, size_t size,
    const ngx_str_t *value)
{
    if (value->len == 0) {
        return NGX_CONF_OK;
    }
    if (value->len >= size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s \"%V\" is too long",
                           name, value);
        return NGX_CONF_ERROR;
    }
    if (slot[0] != '\0'
        && (ngx_strlen(slot) != value->len
            || ngx_strncmp(slot, value->data, value->len) != 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s \"%V\" differs from the value another brix_frm server "
            "published (\"%s\"): the stage engine is process-wide",
            name, value, slot);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(slot, value->data, value->len);
    slot[value->len] = '\0';
    return NGX_CONF_OK;
}

/* Publish one numeric value (ngx_uint_t and ngx_msec_t share the width). */
static char *
frm_publish_num(ngx_conf_t *cf, const char *name, ngx_uint_t *slot,
    unsigned bit, ngx_uint_t value, ngx_uint_t unset)
{
    brix_frm_engine_conf_t *e = frm_engine_for(cf);

    if (value == unset) {
        return NGX_CONF_OK;
    }
    if ((e->explicit_mask & bit) && *slot != value) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s %ui differs from the value another brix_frm server "
            "published (%ui): the stage engine is process-wide",
            name, value, *slot);
        return NGX_CONF_ERROR;
    }
    *slot = value;
    e->explicit_mask |= bit;
    return NGX_CONF_OK;
}

/* Grammar checks on a program the worker runs (the exec MSS command, the
 * 2.0 F4 purge policy program): an absolute path that, when it already
 * exists, nobody but its owner can rewrite (the worker runs it with the MSS
 * credentials; a group/world-writable program is a privilege hand-off to
 * whoever can write it — the same rule brix_checksum_plugin applies). */
char *
brix_frm_check_program(ngx_conf_t *cf, const char *directive,
    const ngx_str_t *cmd, const char *usage)
{
    char         path[4096];
    struct stat  st;

    if (cmd->len == 0) {
        return NGX_CONF_OK;
    }
    if (cmd->data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s \"%V\" must be an absolute program path (%s)",
            directive, cmd, usage);
        return NGX_CONF_ERROR;
    }
    if (cmd->len >= sizeof(path)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s \"%V\" is too long",
                           directive, cmd);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(path, cmd->data, cmd->len);
    path[cmd->len] = '\0';
    if (stat(path, &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH))) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s \"%V\" is group- or world-writable; refusing to run a "
            "program anyone else can rewrite", directive, cmd);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
frm_check_stagecmd(ngx_conf_t *cf, const ngx_str_t *cmd)
{
    return brix_frm_check_program(cf, "brix_frm_stagecmd", cmd,
        "the exec MSS adapter runs it as <cmd> <verb> <key> <online>");
}

/* brix_frm_stagemsg (2.0 F2): the StageEvents feed is appended to by every
 * worker, so an existing file must be a private regular file -- a feed anyone
 * can append to is a forged tape-event stream for whatever tails it.  A
 * missing file is fine: the worker creates it 0600 (stage_events.c). */
static char *
frm_check_stagemsg(ngx_conf_t *cf, const ngx_str_t *file)
{
    struct stat  sb;
    char         path[1024];

    if (file->len == 0) {
        return NGX_CONF_OK;
    }
    if (file->data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_stagemsg \"%V\" must be an absolute path", file);
        return NGX_CONF_ERROR;
    }
    if (file->len >= sizeof(path)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_stagemsg \"%V\" is too long", file);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(path, file->data, file->len);
    path[file->len] = '\0';
    if (stat(path, &sb) != 0) {
        return NGX_CONF_OK;             /* created 0600 by the worker */
    }
    if (!S_ISREG(sb.st_mode)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_stagemsg \"%V\" is not a regular file", file);
        return NGX_CONF_ERROR;
    }
    if (sb.st_mode & (S_IWGRP | S_IWOTH)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_stagemsg \"%V\" is group- or world-writable; "
            "refusing to feed a file anyone else can append to", file);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/* Publish this `brix_frm on` block's engine values (raw = pre-merge, so only
 * an explicit line counts). */
static char *
frm_engine_publish(ngx_conf_t *cf, const brix_frm_conf_t *conf,
    const brix_frm_conf_t *raw)
{
    brix_frm_engine_conf_t *e = frm_engine_for(cf);

    if (frm_publish_str(cf, "brix_frm_queue_path", e->queue_path,
                        sizeof(e->queue_path), &conf->queue_path)
            != NGX_CONF_OK
        || frm_publish_str(cf, "brix_frm_stagecmd", e->stagecmd,
                           sizeof(e->stagecmd), &conf->stagecmd) != NGX_CONF_OK
        || frm_publish_str(cf, "brix_frm_stagemsg", e->stagemsg,
                           sizeof(e->stagemsg), &conf->stagemsg) != NGX_CONF_OK
        || frm_publish_num(cf, "brix_frm_copymax", &e->copymax,
                           BRIX_FRM_ENGINE_COPYMAX, raw->copymax,
                           NGX_CONF_UNSET_UINT) != NGX_CONF_OK
        || frm_publish_num(cf, "brix_frm_fail_retries", &e->fail_retries,
                           BRIX_FRM_ENGINE_FAIL_RETRIES, raw->fail_retries,
                           NGX_CONF_UNSET_UINT) != NGX_CONF_OK
        || frm_publish_num(cf, "brix_frm_fail_backoff",
                           (ngx_uint_t *) &e->fail_backoff_ms,
                           BRIX_FRM_ENGINE_FAIL_BACKOFF,
                           (ngx_uint_t) raw->fail_backoff_ms,
                           (ngx_uint_t) NGX_CONF_UNSET_MSEC) != NGX_CONF_OK
        || frm_publish_num(cf, "brix_frm_copy_timeout",
                           (ngx_uint_t *) &e->copy_timeout_ms,
                           BRIX_FRM_ENGINE_COPY_TIMEOUT,
                           (ngx_uint_t) raw->copy_timeout,
                           (ngx_uint_t) NGX_CONF_UNSET_MSEC) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    e->published = 1;
    brix_sd_frm_set_exec_defaults(e->stagecmd[0] ? e->stagecmd : NULL,
                                  e->copy_timeout_ms);
    return NGX_CONF_OK;
}

/* A `brix_frm off` block that still carries an engine knob configures
 * nothing: say so at load time rather than let the line rot silently. */
static void
frm_warn_inert_knobs(ngx_conf_t *cf, const brix_frm_conf_t *raw)
{
    static const char *names[] = {
        "brix_frm_queue_path", "brix_frm_stagecmd", "brix_frm_copymax",
        "brix_frm_fail_retries", "brix_frm_fail_backoff",
        "brix_frm_copy_timeout",
        "brix_frm_stagemsg",
    };
    unsigned  set[7];
    size_t    i;

    set[0] = raw->queue_path.len != 0;
    set[1] = raw->stagecmd.len != 0;
    set[2] = raw->copymax != NGX_CONF_UNSET_UINT;
    set[3] = raw->fail_retries != NGX_CONF_UNSET_UINT;
    set[4] = raw->fail_backoff_ms != NGX_CONF_UNSET_MSEC;
    set[5] = raw->copy_timeout != NGX_CONF_UNSET_MSEC;
    set[6] = raw->stagemsg.len != 0;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (set[i]) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "%s is ignored: brix_frm is off in this server", names[i]);
        }
    }
}

static char *
frm_check_enabled(ngx_conf_t *cf, const brix_frm_conf_t *conf)
{
    if (conf->queue_path.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm on requires brix_frm_queue_path");
        return NGX_CONF_ERROR;
    }
    if (conf->queue_path.data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_queue_path \"%V\" must be an absolute path",
            &conf->queue_path);
        return NGX_CONF_ERROR;
    }
    if (conf->copymax == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_copymax must be at least 1");
        return NGX_CONF_ERROR;
    }
    if (conf->fail_retries == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_fail_retries must be at least 1");
        return NGX_CONF_ERROR;
    }
    if (frm_check_stagecmd(cf, &conf->stagecmd) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    return frm_check_stagemsg(cf, &conf->stagemsg);
}

char *
brix_frm_conf_merge(ngx_conf_t *cf, brix_frm_conf_t *conf,
                      brix_frm_conf_t *prev)
{
    brix_frm_conf_t  raw = *conf;      /* pre-merge: which lines were written */

    (void) frm_engine_for(cf);          /* reset the snapshot on a new cycle */

    ngx_conf_merge_value(conf->enable,       prev->enable,       0);
    ngx_conf_merge_str_value(conf->queue_path, prev->queue_path, "");
    ngx_conf_merge_uint_value(conf->max_inflight, prev->max_inflight, 64);
    ngx_conf_merge_str_value(conf->stagecmd, prev->stagecmd, "");
    ngx_conf_merge_uint_value(conf->copymax, prev->copymax,
                              BRIX_FRM_COPYMAX_DEFAULT);
    ngx_conf_merge_msec_value(conf->stage_ttl, prev->stage_ttl, 600000);
    ngx_conf_merge_uint_value(conf->stage_wait, prev->stage_wait, 30);
    ngx_conf_merge_value(conf->async_recall, prev->async_recall, 0);
    ngx_conf_merge_msec_value(conf->fail_backoff_ms, prev->fail_backoff_ms,
                              BRIX_FRM_FAIL_BACKOFF_DEFAULT_MS);
    ngx_conf_merge_uint_value(conf->fail_retries, prev->fail_retries,
                              BRIX_FRM_FAIL_RETRIES_DEFAULT);
    ngx_conf_merge_msec_value(conf->copy_timeout, prev->copy_timeout, 0);
    ngx_conf_merge_str_value(conf->stagemsg, prev->stagemsg, "");
    ngx_conf_merge_str_value(conf->control_dir, prev->control_dir, "");
    ngx_conf_merge_uint_value(conf->purge_hi_ppm, prev->purge_hi_ppm, 0);
    ngx_conf_merge_uint_value(conf->purge_lo_ppm, prev->purge_lo_ppm, 0);
    ngx_conf_merge_off_value(conf->purge_max_bytes, prev->purge_max_bytes, 0);
    ngx_conf_merge_msec_value(conf->purge_interval_ms, prev->purge_interval_ms,
                              300000);
    if (brix_frm_purge_policy_merge(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;             /* 2.0 F4: independent of enable */
    }

    if (!conf->enable) {
        frm_warn_inert_knobs(cf, &raw);
        return NGX_CONF_OK;
    }
    if (frm_check_enabled(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    return frm_engine_publish(cf, conf, &raw);
}


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
brix_frm_set_purge_watermark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_frm_conf_t *frm = (brix_frm_conf_t *)
                             ((char *) conf + cmd->offset);
    ngx_str_t         *value = cf->args->elts;

    frm->purge_hi_ppm = frm_ratio_to_ppm(&value[1]);
    frm->purge_lo_ppm = frm_ratio_to_ppm(&value[2]);

    if (frm->purge_lo_ppm > frm->purge_hi_ppm) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_frm_purge_watermark: low (%ui) must not exceed high (%ui)",
            frm->purge_lo_ppm, frm->purge_hi_ppm);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
