/*
 * sd_http.c — read-only-primary HTTP(S) source storage driver: the driver
 * vtable + instance lifecycle (create/destroy). See sd_http.h.
 *
 * A thin driver over the injected brix_s3_transport_t (the same vtable the S3
 * driver uses): `open`/`stat` HEAD the URL for the size, `pread` issues a byte
 * Range GET, and a staged whole-object PUT / DELETE make it a writable cache /
 * stage store. No kernel fd ⇒ memory-served.
 *
 * phase-79 file-size split — the driver is four translation units around one
 * concept each; this file owns only the vtable wiring and create/destroy:
 *   sd_http_select.c   — endpoint selection, health scoring, read failover
 *   sd_http_read.c     — HEAD/GET read path + per-open credential resolution
 *   sd_http_write.c    — staged whole-object PUT + DELETE write path
 *   sd_http_introspect.c — T19/T20 selection + health introspection API
 * The seams between them are declared in sd_http_internal.h; the driver struct
 * and sd_http_instance_is stay file-private here (the check is against this
 * file's driver address).
 */

#include "sd_http.h"
#include "sd_http_internal.h"    /* endpoint + inst_state layout + slot decls */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

/* Read + write: an HTTP/WebDAV origin as a read source and a writable cache_store /
 * stage_store (buffered whole-object PUT + DELETE). */
static const brix_sd_driver_t brix_sd_http_driver = {
    .name  = "http",
    /* phase-71: read-only primary — no .pwrite slot (writes are staged whole-object
     * PUTs via .staged_*), so CAP_RANDOM_WRITE is NOT advertised (honest caps). */
    .caps  = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE,
    .cred_accept = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM,
    .open  = sd_http_open,
    .open_cred = sd_http_open_cred,
    .close = sd_http_close,
    .pread = sd_http_pread,
    .fstat = sd_http_fstat,
    .stat  = sd_http_stat,
    .stat_cred     = sd_http_stat_cred,
    .unlink        = sd_http_unlink,
    .staged_open   = sd_http_staged_open,
    .staged_open_cred = sd_http_staged_open_cred,
    .staged_write  = sd_http_staged_write,
    .staged_commit = sd_http_staged_commit,
    .staged_abort  = sd_http_staged_abort,
};

/* 1 iff `inst` is an sd_http instance.  Kept beside the (file-private) driver
 * struct it checks; the introspection accessors (sd_http_introspect.c) reach it
 * via sd_http_internal.h. */
int
sd_http_instance_is(const brix_sd_instance_t *inst)
{
    return inst != NULL && inst->driver == &brix_sd_http_driver;
}


/* sd_http_init_endpoints — fill the endpoint table from the primary host plus
 * any extra failover origins.
 *
 * WHAT: Writes eps[0] from cfg->{host,port,tls,base_path}, then appends up to
 *       SD_HTTP_EP_MAX-1 valid extras, setting is->n_eps.
 * HOW:  Primary is always present (create() validated it); each extra is
 *       skipped when its host/port is missing or out of range. */
static void
sd_http_init_endpoints(sd_http_inst_state *is, const brix_sd_http_cfg_t *cfg)
{
    snprintf(is->eps[0].host, sizeof(is->eps[0].host), "%s", cfg->host);
    is->eps[0].port = cfg->port;
    is->eps[0].tls  = cfg->tls;
    snprintf(is->eps[0].base_path, sizeof(is->eps[0].base_path), "%s",
             (cfg->base_path != NULL) ? cfg->base_path : "");
    is->n_eps = 1;

    if (cfg->extra == NULL || cfg->n_extra <= 0) {
        return;
    }
    int i, n = cfg->n_extra;

    if (n > SD_HTTP_EP_MAX - 1) {
        n = SD_HTTP_EP_MAX - 1;
    }
    for (i = 0; i < n; i++) {
        const brix_sd_http_ep_cfg_t *ec = &cfg->extra[i];

        if (ec->host == NULL || ec->host[0] == '\0' || ec->port <= 0
            || ec->port > 65535)
        {
            continue;
        }
        snprintf(is->eps[is->n_eps].host, sizeof(is->eps[0].host), "%s",
                 ec->host);
        is->eps[is->n_eps].port = ec->port;
        is->eps[is->n_eps].tls  = ec->tls;
        snprintf(is->eps[is->n_eps].base_path,
                 sizeof(is->eps[0].base_path), "%s",
                 (ec->base_path != NULL) ? ec->base_path : "");
        is->n_eps++;
    }
}

/* sd_http_init_tctx — resolve the transport TLS context (trust anchor).
 *
 * WHAT: An explicit cfg->tctx wins (a caller injecting a custom transport owns
 *       its own context). Otherwise, when an operator CA path is configured,
 *       store a persistent copy and hand it to the curl transport as tctx so
 *       origin TLS verifies against that trust anchor (phase-70 https backend
 *       leg). No CA and no tctx ⇒ NULL ⇒ the transport's system bundle. */
static void
sd_http_init_tctx(sd_http_inst_state *is, const brix_sd_http_cfg_t *cfg)
{
    if (cfg->tctx != NULL) {
        is->tctx = cfg->tctx;
    } else if (cfg->ca_path != NULL && cfg->ca_path[0] != '\0') {
        snprintf(is->ca_path, sizeof(is->ca_path), "%s", cfg->ca_path);
        is->tctx = is->ca_path;
    } else {
        is->tctx = NULL;
    }
}

brix_sd_instance_t *
brix_sd_http_create(const brix_sd_http_cfg_t *cfg, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_http_inst_state   *is;

    if (cfg == NULL || cfg->host == NULL || cfg->host[0] == '\0'
        || cfg->port <= 0 || cfg->port > 65535 || cfg->transport == NULL)
    {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    is   = calloc(1, sizeof(*is));
    if (inst == NULL || is == NULL) {
        free(inst);
        free(is);
        errno = ENOMEM;
        return NULL;
    }
    sd_http_init_endpoints(is, cfg);
    is->transport  = cfg->transport;
    is->failover_note = cfg->failover_note;
    is->health_note   = cfg->health_note;
    sd_http_init_tctx(is, cfg);
    is->timeout_ms = (cfg->timeout_ms > 0) ? cfg->timeout_ms
                                            : BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS;
    /* Store only whether selection/failover logging is enabled, NOT a usable log
     * pointer: this instance is built at postconfiguration and memoized for the
     * worker's whole life, so a captured log dangles once fork replaces the
     * config-phase cycle log (its fd is reused — a fill-thread notice would then
     * land on a live client socket). The fill-thread log sites resolve the CURRENT
     * process error log via sd_http_live_log() instead. */
    is->log        = log;
    is->cur_ep     = -1;
    is->put_checksum = cfg->put_checksum ? 1 : 0;   /* #12 outbound integrity */
    if (cfg->bearer_token != NULL && cfg->bearer_token[0] != '\0') {
        snprintf(is->auth_hdr, sizeof(is->auth_hdr),
                 "Authorization: Bearer %s\r\n", cfg->bearer_token);
    }

    inst->driver = &brix_sd_http_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
brix_sd_http_destroy(brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}
