/*
 * cred_renew.c — the pure decision half of mid-transfer delegated-credential
 * renewal. See cred_renew.h for the module contract; the wire leg that acts on
 * these verdicts lives in tpc/outbound/tpc_token_renew.c.
 */

#include "cred_renew.h"

#include <string.h>

/* The closed set of token modes that hold minting authority. A mode is listed
 * here only when it reaches an issuer for a NEW credential: oidc-agent asks the
 * local agent daemon, token-exchange performs an RFC 8693 exchange. The
 * passthrough modes are deliberately absent — they forward the credential the
 * client presented, so the destination has nothing to re-mint from and must
 * never appear to renew one. */
static const char *const  renew_minting_modes[] = {
    "oidc-agent",
    "token-exchange",
};

/*
 * WHAT: Decide whether a credential expiring at `expires_at` needs renewing at
 *       `now`, given the `lead_secs` window.
 * WHY:  Called once per streamed chunk, so it must be cheap, total and free of
 *       side effects; every "unknown" input resolves to NOT_NEEDED so that
 *       enabling the feature can never turn a previously-working pull into a
 *       refusal on its own.
 * HOW:  Three early-return guards for the inputs that carry no decision, then
 *       the expiry test, then the remaining-lifetime comparison. The
 *       subtraction runs only after `expires_at > now` is established, so it
 *       cannot underflow however far apart the two clocks are.
 */
brix_tpc_renew_verdict_t
brix_tpc_renew_verdict(time_t expires_at, time_t now, time_t lead_secs)
{
    time_t  remaining;

    if (expires_at <= 0) {
        return BRIX_TPC_RENEW_NOT_NEEDED;   /* no expiry is known */
    }
    if (lead_secs <= 0) {
        return BRIX_TPC_RENEW_NOT_NEEDED;   /* renewal disabled */
    }
    if (now <= 0) {
        return BRIX_TPC_RENEW_NOT_NEEDED;   /* no usable clock */
    }

    if (now >= expires_at) {
        return BRIX_TPC_RENEW_EXPIRED;
    }

    remaining = expires_at - now;           /* > 0 by the test above */
    if (remaining <= lead_secs) {
        return BRIX_TPC_RENEW_DUE;
    }

    return BRIX_TPC_RENEW_NOT_NEEDED;
}

/*
 * WHAT: Report whether `token_mode` can mint a fresh credential.
 * WHY:  The renewal leg must fail closed rather than re-present a stale token
 *       when the mode is a forwarding one; making the authority an explicit
 *       allow-list means a new mode is un-mintable until someone adds it here
 *       deliberately.
 * HOW:  Exact string match against renew_minting_modes; NULL and the empty
 *       string short-circuit to 0.
 */
int
brix_tpc_renew_mode_can_mint(const char *token_mode)
{
    size_t  i;

    if (token_mode == NULL || token_mode[0] == '\0') {
        return 0;
    }

    for (i = 0; i < sizeof(renew_minting_modes) / sizeof(renew_minting_modes[0]);
         i++)
    {
        if (strcmp(token_mode, renew_minting_modes[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * WHAT: Map a verdict to a stable log string.
 * WHY:  Operator-facing log lines and the tests that read them need one spelling
 *       per verdict that does not drift with the enum.
 * HOW:  Switch with an explicit default so an unmapped future value is visible
 *       as "unknown" instead of falling off the end.
 */
const char *
brix_tpc_renew_verdict_name(brix_tpc_renew_verdict_t verdict)
{
    switch (verdict) {
    case BRIX_TPC_RENEW_NOT_NEEDED:
        return "not-needed";
    case BRIX_TPC_RENEW_DUE:
        return "due";
    case BRIX_TPC_RENEW_EXPIRED:
        return "expired";
    default:
        return "unknown";
    }
}
