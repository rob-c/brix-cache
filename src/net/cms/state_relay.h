#ifndef BRIX_CMS_STATE_RELAY_H
#define BRIX_CMS_STATE_RELAY_H

/*
 * state_relay.h — Phase-61 W7 multi-tier kYR_state recursion (opt-in).
 *
 * WHAT: a per-worker correlation table that lets a mid-tier manager relay a
 *       parent's kYR_state existence query DOWN to its own data nodes and echo
 *       the first kYR_have answer back UP under the parent's streamid.
 * WHY:  the registry answers instantly for statically-exported prefixes, but a
 *       dynamically-located file (only discoverable by asking the nodes) needs
 *       the same downward fan-out stock cmsd performs.  Gated behind
 *       brix_cms_state_relay (default off) so single-tier meshes keep the
 *       registry-only fast path and its latency profile.
 * HOW:  add() parks the upward leg (conn + parent streamid + probed path) and
 *       hands back a fresh downward streamid from the shared server-leg
 *       generator; the kYR_have ingest calls take() with the echoed downward
 *       streamid AND path to recover the parked leg (first answer wins;
 *       expired entries are reaped lazily).  drop_ctx() flushes entries when
 *       the upward connection dies.
 *
 * TRUST: a relayed probe targets a path OUTSIDE every child's declared
 *       exports (a covered path is answered from the registry without any
 *       relay), so the kYR_have paths-cover gate cannot legitimise the
 *       answer.  Instead the entry stores the exact probed path and take()
 *       matches on it: a child can only assert paths this manager actively
 *       probed, within the TTL window, once — a lying node gains nothing.
 */

#include "cms_internal.h"

/* Unanswered relay entries expire after this window (lazily reaped). */
#define BRIX_CMS_STATE_RELAY_TTL_MS  5000

/*
 * Park upward leg (up, up_sid) + the probed path and return the downward
 * streamid to fan out with, or 0 when the table is full or the path is
 * oversized (caller stays silent — the parent treats silence as "not here",
 * the safe degraded answer).
 */
uint32_t brix_cms_state_relay_add(ngx_brix_cms_ctx_t *up, uint32_t up_sid,
    const char *path);

/*
 * Resolve an echoed downward streamid + asserted path: on a live match with
 * the parked path removes the entry and returns 1 with *up / *up_sid set;
 * returns 0 for an unknown, expired, or disconnected-upward entry.  A
 * streamid match with a DIFFERENT path returns 0 WITHOUT consuming the entry
 * (a forged answer must not starve the honest one).
 */
int brix_cms_state_relay_take(uint32_t down_sid, const char *path,
    ngx_brix_cms_ctx_t **up, uint32_t *up_sid);

/* Flush every entry parked on `up` (its connection is going away). */
void brix_cms_state_relay_drop_ctx(ngx_brix_cms_ctx_t *up);

#endif /* BRIX_CMS_STATE_RELAY_H */
