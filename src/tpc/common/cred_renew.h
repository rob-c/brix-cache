#ifndef BRIX_TPC_COMMON_CRED_RENEW_H
#define BRIX_TPC_COMMON_CRED_RENEW_H

/* ---- Module: TPC Delegated-Credential Renewal Decision ----
 *
 * WHAT: The pure decision half of mid-transfer delegated-credential renewal:
 *       brix_tpc_renew_verdict() answers NOT_NEEDED / DUE / EXPIRED for one
 *       (expires_at, now, lead) triple, and brix_tpc_renew_mode_can_mint()
 *       answers whether a token_mode carries the authority to obtain a FRESH
 *       credential rather than merely forward one it was handed.
 *
 * WHY: A multi-hour third-party copy outlives the credential that launched it.
 *      One-shot delegation (phase-70) fetches once at bootstrap and never looks
 *      again, so a pull longer than the token's lifetime streams on a credential
 *      the source may stop honouring mid-flight. The decision is separated from
 *      the wire leg because it is the part that must be exhaustively checkable:
 *      it is pure, it has no I/O, and every branch is a security boundary
 *      (renewing too late is an outage; treating a forwarded token as mintable
 *      would silently re-present a credential the destination never owned).
 *
 * HOW: Both entry points are total functions of their arguments with no global
 *      state. The verdict is computed on the REMAINING lifetime (expires_at -
 *      now) evaluated only after the expiry test has established
 *      expires_at > now, so the subtraction can never underflow. Unknown inputs
 *      (no expiry, renewal disabled, a non-positive clock) resolve to
 *      NOT_NEEDED, which is exactly the pre-renewal behaviour — the feature can
 *      only ever add a renewal, never a new refusal, unless the caller opts in
 *      to strict enforcement. Mint authority is a closed allow-list: the two
 *      modes that talk to an issuer (oidc-agent, token-exchange) can mint; every
 *      other mode — including both passthrough forms, "none", the empty string
 *      and any unknown string — cannot.
 */

#include <time.h>

typedef enum {
    BRIX_TPC_RENEW_NOT_NEEDED = 0,  /* ample lifetime, or nothing to decide on */
    BRIX_TPC_RENEW_DUE        = 1,  /* inside the lead window — renew now      */
    BRIX_TPC_RENEW_EXPIRED    = 2,  /* already past expiry                     */
} brix_tpc_renew_verdict_t;

/* Decide whether a delegated credential expiring at `expires_at` needs renewing
 * at `now`, given a `lead_secs` window before expiry in which renewal is due.
 * NOT_NEEDED whenever the decision cannot be made or renewal is off:
 * expires_at <= 0 (no expiry is known), lead_secs <= 0 (renewal disabled), or
 * now <= 0 (no usable clock). EXPIRED when now >= expires_at; DUE when the
 * remaining lifetime is at or below lead_secs; NOT_NEEDED otherwise. Pure. */
brix_tpc_renew_verdict_t brix_tpc_renew_verdict(time_t expires_at, time_t now,
    time_t lead_secs);

/* 1 when `token_mode` can obtain a fresh credential from an issuer
 * ("oidc-agent", "token-exchange"), 0 for every other mode — NULL, "", "none",
 * "passthrough", "passthrough-opt" and any unrecognised string. A forwarding
 * mode holds the client's credential, not the authority to re-mint it. Pure. */
int brix_tpc_renew_mode_can_mint(const char *token_mode);

/* Stable lowercase log string for a verdict ("not-needed", "due", "expired",
 * or "unknown"). Returns a static literal; never NULL. Pure. */
const char *brix_tpc_renew_verdict_name(brix_tpc_renew_verdict_t verdict);

#endif /* BRIX_TPC_COMMON_CRED_RENEW_H */
