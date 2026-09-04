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
 * HOW: brix_token_jwks_schedule() copies a protocol-neutral refresh descriptor
 *      into the worker cycle and arms one event. Stream and HTTP adapters point
 *      the descriptor at the key arrays their validators already read. The
 *      handler stats the file, reloads only after an mtime change, swaps the key
 *      array after a complete parse, and always preserves the old set on error.
 */

#include "core/config/config.h"
#include "token.h"

#include <sys/stat.h>
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

/* Handler: called by the nginx event loop at each refresh interval */
/*
 * Poll the JWKS file once: reload and swap in a new key set only if the file
 * exists, its mtime changed since the last poll, and it parses to >=1 key. Any
 * miss is a no-op that preserves the current keys (a WARN is logged). Does not
 * touch the refresh timer — the caller always re-arms it afterwards.
 */
typedef struct {
    brix_jwks_refresh_spec_t spec;
    ngx_event_t              event;
} brix_jwks_refresh_runtime_t;

static void
brix_token_jwks_try_reload(brix_jwks_refresh_runtime_t *runtime,
    ngx_log_t *log)
{
    brix_jwks_refresh_spec_t *spec = &runtime->spec;
    struct stat        st;
    brix_jwks_key_t  new_keys[BRIX_MAX_JWKS_KEYS];
    int                new_count;

    if (stat((const char *) spec->path.data, &st) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "brix: JWKS stat failed for \"%s\" — will retry",
                      spec->path.data);
        return;
    }

    if (st.st_mtime == spec->mtime) {
        return;   /* file unchanged — no reload needed */
    }

    new_count = brix_jwks_load(log,
                                 (const char *) spec->path.data,
                                 new_keys, BRIX_MAX_JWKS_KEYS);
    if (new_count <= 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: JWKS reload from \"%s\" returned %d keys "
                      "— keeping old keys",
                      spec->path.data, new_count);
        return;
    }

    /* Swap: free the old keys then install the new set */
    brix_jwks_free(spec->keys, *spec->key_count);
    ngx_memcpy(spec->keys, new_keys,
               (size_t) new_count * sizeof(brix_jwks_key_t));
    *spec->key_count = new_count;
    spec->mtime = st.st_mtime;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: JWKS refreshed from \"%s\" — %d key(s) loaded",
                  spec->path.data, new_count);
}

static void
brix_token_jwks_refresh_handler(ngx_event_t *ev)
{
    brix_jwks_refresh_runtime_t *runtime = ev->data;

    brix_token_jwks_try_reload(runtime, ev->log);

    /* Stop re-arming once the worker is shutting down so the poll timer can
     * never keep a draining worker alive (mirrors the FRM reaper pattern). */
    if (!ngx_exiting) {
        ngx_add_timer(ev, runtime->spec.interval);
    }
}

/* Public: schedule the refresh timer for one server block */
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
 *      in worker-cycle storage, then calls ngx_add_timer with the configured
 *      interval in milliseconds.
 */
ngx_int_t
brix_token_jwks_schedule(ngx_cycle_t *cycle,
    const brix_jwks_refresh_spec_t *spec)
{
    brix_jwks_refresh_runtime_t *runtime;

    if (cycle == NULL || spec == NULL || spec->path.len == 0
        || spec->keys == NULL
        || spec->key_count == NULL
        || spec->interval == (ngx_msec_t) NGX_CONF_UNSET_MSEC
        || spec->interval == 0)
    {
        return NGX_OK;
    }

    runtime = ngx_pcalloc(cycle->pool, sizeof(*runtime));
    if (runtime == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "brix: failed to allocate JWKS refresh timer");
        return NGX_ERROR;
    }

    runtime->spec = *spec;
    runtime->event.handler = brix_token_jwks_refresh_handler;
    runtime->event.data = runtime;
    runtime->event.log = cycle->log;
    runtime->event.cancelable = 1;

    ngx_add_timer(&runtime->event, runtime->spec.interval);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix: JWKS refresh timer started — interval=%Mms path=\"%s\"",
                  runtime->spec.interval, runtime->spec.path.data);
    return NGX_OK;
}

void
brix_token_jwks_schedule_refresh(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf)
{
    brix_jwks_refresh_spec_t spec;

    ngx_memzero(&spec, sizeof(spec));
    spec.path = conf->common.token_jwks;
    spec.keys = conf->jwks_keys;
    spec.key_count = &conf->jwks_key_count;
    spec.mtime = conf->jwks_mtime;
    spec.interval = conf->common.token_jwks_refresh_interval;
    if (brix_token_jwks_schedule(cycle, &spec) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "brix: JWKS refresh timer was not started");
    }
}
