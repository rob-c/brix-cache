#ifndef BRIX_FORWARD_RELAY_RESPONSE_INTERNAL_H
#define BRIX_FORWARD_RELAY_RESPONSE_INTERNAL_H

#include "proxy_internal.h"

/*
 * WHAT: Internal declarations shared between forward_relay_response.c and its
 *       sibling split forward_relay_response_lazy.c.
 *
 * WHY:  The upstream-response relay path was split by concern for file-size
 *       limits. The bound-secondary lazy-open cluster moved to
 *       forward_relay_response_lazy.c, but its entry point is still invoked
 *       from brix_proxy_relay_to_client() in forward_relay_response.c, so it
 *       must be declared here rather than staying file-static.
 *
 * HOW:  brix_proxy_relay_lazy_open() handles the synthetic kXR_open response
 *       for a bound-secondary lazy open. Returns 1 when this was a lazy-open
 *       response and the caller must return; 0 otherwise.
 */
int brix_proxy_relay_lazy_open(brix_proxy_ctx_t *proxy);

#endif /* BRIX_FORWARD_RELAY_RESPONSE_INTERNAL_H */
