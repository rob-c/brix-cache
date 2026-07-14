#ifndef BRIX_EVENTS_BOOTSTRAP_INTERNAL_H
#define BRIX_EVENTS_BOOTSTRAP_INTERNAL_H

#include "proxy_internal.h"

/*
 * WHAT: Internal declarations shared between events_bootstrap.c (the upstream
 *       login state machine) and its sibling split events_bootstrap_auth.c
 *       (the kXR_auth credential-sourcing/send machinery).
 *
 * WHY:  The bootstrap handler was split by concern for file-size limits. The
 *       auth-frame building and per-mechanism send arms moved to
 *       events_bootstrap_auth.c, but the state machine in events_bootstrap.c
 *       still invokes a few of them, so those symbols must be declared here
 *       rather than staying file-static. Everything else in the auth file is
 *       referenced only within that file and remains static.
 *
 * HOW:  proxy_bs_reset_resp   — reset the upstream response accumulator.
 *       proxy_bs_auth_error   — record an upstream-auth failure and abort.
 *       proxy_bs_do_auth      — answer a kXR_authmore by configured policy.
 *       proxy_bs_login_sec_hint — proactive P=sss / P=ztn on the login reply.
 */
void proxy_bs_reset_resp(brix_proxy_ctx_t *proxy);
void proxy_bs_auth_error(brix_proxy_ctx_t *proxy, unsigned up_inc,
    const char *msg);
int  proxy_bs_do_auth(brix_proxy_ctx_t *proxy);
int  proxy_bs_login_sec_hint(brix_proxy_ctx_t *proxy);

#endif /* BRIX_EVENTS_BOOTSTRAP_INTERNAL_H */
