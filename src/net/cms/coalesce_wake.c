/*
 * cms/coalesce_wake.c — locate-answer wake (contract in coalesce_wake.h).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "cms_internal.h"
#include "recv_internal.h"
#include "coalesce_wake.h"
#include "net/manager/pending.h"

/* Bounded by the pending table itself: a wave can have at most that many
 * followers, and the array is a stack temporary in one worker. */
#define CMS_COALESCE_MAX_FOLLOWERS  BRIX_PENDING_LOCATE_SLOTS

ngx_uint_t
brix_cms_wake_locate_answer(ngx_log_t *log, const char *path,
    uint32_t leader_sid, const char *host, uint16_t port)
{
    uint32_t    sids[CMS_COALESCE_MAX_FOLLOWERS];
    ngx_uint_t  n, i, woken = 0;

    if (brix_cms_wake_pending_session(log, leader_sid, host, port) == NGX_OK) {
        woken++;
    }

    n = brix_pending_find_probe(path, leader_sid, sids,
                                CMS_COALESCE_MAX_FOLLOWERS);

    for (i = 0; i < n; i++) {
        if (brix_cms_wake_pending_session(log, sids[i], host, port) == NGX_OK) {
            woken++;
        }
    }

    if (n > 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "brix: CMS locate coalesce: one kYR_state wave for "
                      "\"%s\" settled %ui coalesced client(s) -> %s:%d",
                      path, n, host, (int) port);
    }

    return woken;
}
