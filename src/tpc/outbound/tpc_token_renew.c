/*
 * tpc_token_renew.c — the wire leg of mid-transfer delegated-credential
 * renewal (W8.2).
 *
 * WHAT: The entry points around the pure decision kernel in
 *       tpc/common/cred_renew.c. tpc_cred_note_expiry() records the lifetime of
 *       whatever credential the pull ended up presenting, by reading the `exp`
 *       claim of the delegated token. tpc_cred_renew_if_due() is sampled once
 *       per streamed chunk: it asks for a verdict and, when renewal is due,
 *       permitted and useful, mints a fresh token and re-presents it to the
 *       source on the live connection with a second ztn kXR_auth.
 *
 * WHY: One-shot delegation fetches a credential at bootstrap and never looks at
 *      it again, so a copy that runs longer than the token's lifetime streams on
 *      a credential the source may stop honouring. Renewing has to happen from
 *      inside the pull thread, between drained read windows, because that is the
 *      only point at which the outbound socket is quiet enough to carry an
 *      unrelated request/response pair.
 *
 * HOW: Four gates stand between a chunk boundary and an issuer round trip, and
 *      each one exists because of a distinct way renewal could do harm:
 *
 *        1. cred_presented — renew only a credential this session actually
 *           presented. An anonymous or GSI pull has no ztn credential in play;
 *           sending it a kXR_auth would be a protocol error invented by a
 *           feature that was supposed to be invisible.
 *        2. the verdict — pure, and NOT_NEEDED for every unknown input, so
 *           enabling renewal cannot by itself change a pull that works today.
 *        3. mint authority — a forwarding mode holds the client's credential,
 *           not the right to re-mint it; it may warn, never fetch.
 *        4. the retry window and cred_renew_off — a failed mint is retried at
 *           most once a minute so a broken issuer cannot turn one pull into a
 *           fork/exec storm, and an issuer that keeps returning a credential
 *           still inside the lead window disables renewal for this transfer
 *           rather than minting once per megabyte forever.
 *
 *      The sample point reuses the stream loop's existing once-per-chunk clock
 *      read, so renewal costs one comparison per MiB and no syscall. Renewal is
 *      off until brix_tpc_outbound_renew_lead is set, like every other
 *      selection/pacing engine in the tree. The re-auth uses handshake sequence
 *      4 — distinct from bootstrap's 1/2/3 and from the read loop's 3 — so a
 *      packet capture reads unambiguously.
 */

#include "tpc/engine/tpc_internal.h"
#include "tpc/common/cred_renew.h"
#include "auth/token/token.h"

#include <string.h>
#include <time.h>

/* Handshake sequence for a renewal kXR_auth. Bootstrap uses 1 (protocol), 2
 * (login) and 3 (first auth); the read loop reuses 3 and the close 2. */
#define TPC_RENEW_AUTH_SEQ    4

/* Minimum gap between mint attempts after one has failed. */
#define TPC_RENEW_RETRY_SECS  60

/* The pull thread has no log of its own; every other thread-side call site
 * reaches for the client connection's log and falls back to the cycle log. */
static ngx_log_t *
tpc_renew_log(brix_tpc_pull_t *t)
{
    if (t->c != NULL && t->c->log != NULL) {
        return t->c->log;
    }
    return ngx_cycle->log;
}

/*
 * WHAT: Record the expiry of the credential now held in t->delegated_token.
 * WHY:  Renewal cannot be decided without a lifetime, and the only lifetime the
 *       destination can see is the one the token carries. A token that is not a
 *       JWS, or carries no positive `exp`, leaves the expiry at 0 — which the
 *       decision kernel reads as "nothing to decide", i.e. exactly the
 *       pre-renewal behaviour.
 * HOW:  brix_token_peek_exp() reads the claim WITHOUT verifying the signature.
 *       That is correct here and only here: this is the destination reading the
 *       lifetime of a credential it already holds and already presented, in
 *       order to decide when to ask for another one. Nothing is authorised on
 *       the basis of this value — the source re-validates the renewed token in
 *       full, exactly as it validated the first one.
 */
void
tpc_cred_note_expiry(brix_tpc_pull_t *t)
{
    time_t  exp = 0;

    t->cred_expires_at = 0;

    if (t->delegated_token[0] == '\0') {
        return;
    }
    if (brix_token_peek_exp(t->delegated_token, strlen(t->delegated_token),
                            &exp) != 0)
    {
        return;
    }
    t->cred_expires_at = exp;
}

/*
 * WHAT: The shared give-up path: fatal once the credential is genuinely past
 *       expiry, a one-line warning while it is merely due.
 * WHY:  Both the "cannot mint" and the "mint failed" arms end here, and both
 *       must answer the same question the same way — is the credential dead, or
 *       only close to it? A due credential is still one the source accepts, so
 *       the transfer continues; an expired one is not, and streaming on it
 *       produces a copy nobody can explain.
 * HOW:  EXPIRED sets err_msg/kXR_AuthFailed and returns -1; anything else warns
 *       and returns 0. `fatal_when_expired` lets the caller keep a pull alive on
 *       an expired credential it could never have renewed anyway, which is what
 *       brix_tpc_outbound_renew_strict off means.
 */
static int
tpc_cred_renew_give_up(brix_tpc_pull_t *t, brix_tpc_renew_verdict_t verdict,
    const char *why, ngx_flag_t fatal_when_expired)
{
    if (verdict == BRIX_TPC_RENEW_EXPIRED && fatal_when_expired) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC delegated credential expired mid-transfer at offset "
                 "%llu: %s (token_mode \"%s\")",
                 (unsigned long long) t->bytes_written, why, t->token_mode);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    ngx_log_error(NGX_LOG_WARN, tpc_renew_log(t), 0,
                  "brix: TPC delegated credential %s mid-transfer: %s "
                  "(token_mode \"%s\") - continuing",
                  brix_tpc_renew_verdict_name(verdict), why, t->token_mode);
    return 0;
}

/*
 * WHAT: Mint a fresh delegated token and re-present it to the source.
 * WHY:  Split from the policy below so the policy stays a readable ladder and
 *       this half owns the buffer discipline: tpc_fetch_delegated_token()
 *       overwrites t->delegated_token in place, so a failed fetch leaves it
 *       unusable and it must be cleared. The recorded expiry is deliberately
 *       NOT cleared — it describes the credential the source is still holding,
 *       and forgetting it would blind every later verdict.
 * HOW:  fetch -> re-read the new expiry -> ztn kXR_auth on the live socket.
 */
static int
tpc_cred_mint_and_present(brix_tpc_pull_t *t, int fd)
{
    if (tpc_fetch_delegated_token(t) != 0) {
        t->delegated_token[0] = '\0';
        return -1;
    }

    tpc_cred_note_expiry(t);

    if (tpc_outbound_ztn_seq(t, fd, TPC_RENEW_AUTH_SEQ) != 0) {
        return -1;
    }

    t->cred_renewals++;
    return 0;
}

/*
 * WHAT: Note that a renewal succeeded, and stop renewing when it did not help.
 * WHY:  An issuer configured with a lifetime shorter than the operator's lead
 *       window hands back a credential that is due the moment it arrives. Left
 *       alone that mints once per megabyte for the length of the copy — a
 *       fork/exec per MiB against the IdP, caused by a misconfiguration the
 *       operator cannot see. One warning and a per-transfer stop is the honest
 *       response: the credential IS fresh, it simply cannot satisfy this lead.
 * HOW:  Re-run the pure verdict against the token just obtained.
 */
static void
tpc_cred_renew_note_success(brix_tpc_pull_t *t, time_t now)
{
    ngx_log_error(NGX_LOG_NOTICE, tpc_renew_log(t), 0,
                  "brix: TPC delegated credential renewed mid-transfer "
                  "(token_mode \"%s\", renewal %ui, offset %uz)",
                  t->token_mode, t->cred_renewals, t->bytes_written);

    if (brix_tpc_renew_verdict(t->cred_expires_at, now,
                               t->conf->common.tpc_outbound_renew_lead)
        == BRIX_TPC_RENEW_NOT_NEEDED)
    {
        return;
    }

    t->cred_renew_off = 1;
    ngx_log_error(NGX_LOG_WARN, tpc_renew_log(t), 0,
                  "brix: TPC renewed credential is still inside the "
                  "brix_tpc_outbound_renew_lead window - the issuer's lifetime "
                  "is shorter than the lead; renewal disabled for this transfer");
}

/*
 * WHAT: The once-per-chunk renewal sample. Returns 0 to continue streaming, -1
 *       to fail the pull with t->err_msg / t->xrd_error set.
 * WHY:  Four populations have to stay distinct — a session with no credential
 *       in play, a mode that can mint, a mode that cannot, and a mode that can
 *       but has just failed to. Only the second ever performs I/O here.
 * HOW:  Cheap gates first (no credential, renewal spent), then the pure
 *       verdict, then mint authority, then the retry window, then the mint.
 *       Every arm is an early return.
 */
int
tpc_cred_renew_if_due(brix_tpc_pull_t *t, int fd)
{
    brix_tpc_renew_verdict_t  verdict;
    time_t                    now;

    if (t->conf == NULL || !t->cred_presented || t->cred_renew_off) {
        return 0;
    }

    now     = time(NULL);
    verdict = brix_tpc_renew_verdict(t->cred_expires_at, now,
                                     t->conf->common.tpc_outbound_renew_lead);
    if (verdict == BRIX_TPC_RENEW_NOT_NEEDED) {
        return 0;
    }

    if (!brix_tpc_renew_mode_can_mint(t->token_mode)) {
        return tpc_cred_renew_give_up(t, verdict,
                   "this token_mode forwards a credential it cannot re-mint",
                   t->conf->common.tpc_outbound_renew_strict);
    }

    if (now < t->cred_renew_next_try) {
        return tpc_cred_renew_give_up(t, verdict,
                   "a previous renewal failed and the retry window is open", 1);
    }

    if (tpc_cred_mint_and_present(t, fd) != 0) {
        t->cred_renew_next_try = now + TPC_RENEW_RETRY_SECS;
        return tpc_cred_renew_give_up(t, verdict, "renewal failed", 1);
    }

    tpc_cred_renew_note_success(t, now);
    return 0;
}
