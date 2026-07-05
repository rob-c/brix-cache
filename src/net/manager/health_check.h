/*
 * health_check.h — Phase 22 active stream health checks.
 *
 * Off by default.  When `brix_health_check on` is configured on a
 * manager/redirector server, each worker runs a timer that periodically claims
 * a registry slot (exactly one worker probes each data server per interval) and
 * opens a short-lived XRootD connection to it: TCP connect -> handshake ->
 * protocol -> login -> kXR_ping (or kXR_stat "/").  A passing probe clears any
 * health-induced blacklist; repeated failures blacklist the server before
 * clients are redirected there, catching hung-but-connected nodes that the
 * passive CMS-disconnect and TCP-keepalive signals miss.
 */
#ifndef BRIX_MANAGER_HEALTH_CHECK_H
#define BRIX_MANAGER_HEALTH_CHECK_H

#include "core/ngx_brix_module.h"

#define BRIX_HC_TYPE_PING  0   /* kXR_ping  — protocol-level liveness */
#define BRIX_HC_TYPE_STAT  1   /* kXR_stat "/" — exercises path/stat chain */

/*
 * Start the per-worker health-check timer for `conf`.  No-op when health
 * checks are disabled (conf->hc.enabled == 0) or the interval is 0.  Called
 * once per enabled server block from the stream module's init_process hook.
 */
void brix_hc_manager_start(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf);

#endif /* BRIX_MANAGER_HEALTH_CHECK_H */
