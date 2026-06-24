/*
 * refresh.c — JWKS hot refresh via mtime-polling timer.
 *
 * WHAT: Implements a per-worker nginx timer that polls the JWKS file for mtime changes
 *       and reloads public keys in-place when the file has been updated. Old keys are
 *       freed only after a successful reload so that in-flight token validations are
 *       never left with a half-updated key set.
 *
 * WHY: Key rotation is a routine operation for WLCG/OIDC deployments — new signing
 *      keys are published to the JWKS file while nginx is running. Requiring a full
 *      nginx reload to pick up new keys would break token auth during the reload
 *      window. Mtime polling is the lightest-weight approach (no inotify dependency)
 *      and safe in nginx's single-threaded event loop: each worker has its own copy
 *      of the config structure, so the key array swap (memcpy + count update) is
 *      atomic within a worker with no cross-process locking needed.
 *
 * HOW: xrootd_token_jwks_schedule_refresh() is called once per worker from
 *      ngx_stream_xrootd_init_process(). It allocates an ngx_event_t from the cycle
 *      pool and arms it with ngx_add_timer(). The handler xrootd_token_jwks_refresh_handler()
 *      fires at each interval: stat() the file, compare st_mtime to conf->jwks_mtime,
 *      load new keys only when changed, swap the key array, update jwks_mtime, and
 *      reschedule itself. On parse failure the old keys are preserved and a WARN is
 *      emitted. Keys are freed via xrootd_jwks_free() (defined in jwks.c) which calls
 *      EVP_PKEY_free() on each non-NULL entry.
 */

#include "../config/config.h"
#include "token.h"

#include <sys/stat.h>

/* ---- Handler: called by the nginx event loop at each refresh interval ---- */

/*
 * Poll the JWKS file once: reload and swap in a new key set only if the file
 * exists, its mtime changed since the last poll, and it parses to >=1 key. Any
 * miss is a no-op that preserves the current keys (a WARN is logged). Does not
 * touch the refresh timer — the caller always re-arms it afterwards.
 */
static void
xrootd_token_jwks_try_reload(ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)
{
    struct stat        st;
    xrootd_jwks_key_t  new_keys[XROOTD_MAX_JWKS_KEYS];
    int                new_count;

    if (stat((const char *) conf->token_jwks.data, &st) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd: JWKS stat failed for \"%s\" — will retry",
                      conf->token_jwks.data);
        return;
    }

    if (st.st_mtime == conf->jwks_mtime) {
        return;   /* file unchanged — no reload needed */
    }

    new_count = xrootd_jwks_load(log,
                                 (const char *) conf->token_jwks.data,
                                 new_keys, XROOTD_MAX_JWKS_KEYS);
    if (new_count <= 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: JWKS reload from \"%s\" returned %d keys "
                      "— keeping old keys",
                      conf->token_jwks.data, new_count);
        return;
    }

    /* Swap: free the old keys then install the new set */
    xrootd_jwks_free(conf->jwks_keys, conf->jwks_key_count);
    ngx_memcpy(conf->jwks_keys, new_keys,
               (size_t) new_count * sizeof(xrootd_jwks_key_t));
    conf->jwks_key_count = new_count;
    conf->jwks_mtime     = st.st_mtime;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd: JWKS refreshed from \"%s\" — %d key(s) loaded",
                  conf->token_jwks.data, new_count);
}

static void
xrootd_token_jwks_refresh_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t  *conf = ev->data;

    xrootd_token_jwks_try_reload(conf, ev->log);

    /* Stop re-arming once the worker is shutting down so the poll timer can
     * never keep a draining worker alive (mirrors the FRM reaper pattern). */
    if (!ngx_exiting) {
        ngx_add_timer(ev, conf->token_jwks_refresh_interval);
    }
}

/* ---- Public: schedule the refresh timer for one server block ---- */

/*
 * WHAT: Allocates and arms a per-worker JWKS mtime-poll timer for the given server
 *       block config. Does nothing if token_jwks is empty or refresh interval is
 *       disabled (NGX_CONF_UNSET_MSEC) or zero.
 *
 * WHY: Must be called from init_process (after fork) so each worker gets its own
 *      ngx_event_t allocated from that worker's cycle pool and armed in that
 *      worker's event loop. Calling before fork would result in shared state across
 *      workers which is incorrect for nginx's process model.
 *
 * HOW: Allocates ngx_event_t via ngx_pcalloc, sets handler/data/log, stores pointer
 *      in conf->jwks_timer for bookkeeping, then calls ngx_add_timer with the
 *      configured interval in milliseconds.
 */
void
xrootd_token_jwks_schedule_refresh(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_event_t  *ev;

    if (conf->token_jwks.len == 0
        || conf->token_jwks_refresh_interval == (ngx_msec_t) NGX_CONF_UNSET_MSEC
        || conf->token_jwks_refresh_interval == 0)
    {
        return;
    }

    ev = ngx_pcalloc(cycle->pool, sizeof(*ev));
    if (ev == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "xrootd: failed to allocate JWKS refresh timer");
        return;
    }

    ev->handler = xrootd_token_jwks_refresh_handler;
    ev->data    = conf;
    ev->log     = cycle->log;

    conf->jwks_timer = ev;
    ngx_add_timer(ev, conf->token_jwks_refresh_interval);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: JWKS refresh timer started — interval=%Mms path=\"%s\"",
                  conf->token_jwks_refresh_interval, conf->token_jwks.data);
}
