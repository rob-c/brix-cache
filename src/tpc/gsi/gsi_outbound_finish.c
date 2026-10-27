#include "tpc/engine/tpc_internal.h"
#include "protocols/root/session/session.h"
#include "protocols/root/protocol/gsi.h"
#include "protocols/root/protocol/sec_protocol.h"   /* shared anchored "&P=" security-list parser */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

/* File: gsi_outbound_finish.c — Auth path selection/dispatch for TPC pull
 * WHAT: Auth path selection via tpc_outbound_finish_login.
 *   - Parses login_body after session ID for "ztn" or "gsi"
 *   - Checks have_ztn_cred (delegated token or bearer file)
 *   - Checks have_cert (certificate + certificate_key set)
 *   - If want_ztn && have_ztn_cred: tries tpc_outbound_ztn first
 *   - On ordinary opportunistic-token failure: falls through to GSI if allowed
 *   - TLS-required and explicit token-mode failures are terminal
 *   - If want_gsi && have_cert: delegates to tpc_outbound_gsi
 *   - If neither succeeds: error + kXR_AuthFailed
 *   - Returns 0 or -1 with t->xrd_error set
 *   - Caller: thread.c (auth path dispatch after bootstrap)
 *
 * WHY: TPC pull outbound authentication needs to select between WLCG JWT (ztn) and GSI certreq auth paths based on what the server supports (advertised in login/authmore parameters) and what credentials are configured locally. The selection logic prefers JWT when the server lists ztn first (typical for auth=both deployments) and a bearer file exists. Opportunistic token selection may fall back to GSI, but a transport-security refusal or an explicitly requested token identity must never silently become the gateway's GSI identity.
 *
 * HOW: login_dlen <= session_id_len+1 → error kXR_ArgInvalid → parse anchored
 * &P=ztn/&P=gsi entries → determine bearer/certificate availability → prefer
 * ztn → keep TLSRequired and explicit token modes terminal → allow only an
 * ordinary opportunistic failure to try GSI → otherwise report AuthFailed.
 * */

/* WHAT: Auth path selection/dispatch.
 *   - Parses server login/authmore params for ztn/gsi
 *   - Checks have_ztn_cred + have_cert config
 *   - Prefers JWT if want_ztn && have_ztn_cred
 *   - Falls through to GSI only for an ordinary opportunistic-token failure
 *   - Returns 0 or -1 with t->xrd_error set
 *   - Caller: thread.c auth path dispatch after bootstrap */
/* WHAT: Return 1 when a failed ZTN attempt must remain the final verdict.
 * WHY: GSI fallback after a TLS refusal or explicit token-mode request changes
 *      both transport guarantees and caller identity.
 * HOW: TLSRequired is always terminal; explicit passthrough, oidc-agent and
 *      token-exchange modes are terminal, while empty/none/passthrough-opt keep
 *      the documented opportunistic fallback. */
static int
tpc_ztn_failure_terminal(const brix_tpc_pull_t *t)
{
    if (t->xrd_error == kXR_TLSRequired) {
        return 1;
    }
    if (t->token_mode[0] == '\0'
        || ngx_strcmp(t->token_mode, "none") == 0
        || ngx_strcmp(t->token_mode, "passthrough-opt") == 0)
    {
        return 0;
    }
    return 1;
}

int
tpc_outbound_finish_login(brix_tpc_pull_t *t, int fd,
    u_char *login_body, uint32_t login_dlen)
{
    char              *parms;
    int                want_ztn;
    int                want_gsi;
    ngx_flag_t         have_ztn_cred;
    ngx_flag_t         have_cert;

    if (login_dlen <= BRIX_SESSION_ID_LEN + 1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC login authmore body too short");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    parms = (char *) login_body + BRIX_SESSION_ID_LEN;

    /* Anchored "&P=<name>" match (shared with the native client), not a bare
     * substring scan: a protocol name inside another entry's args or a trailing
     * host must not select the wrong outbound credential. */
    want_ztn = brix_sec_proto_advertised(parms, "ztn", NULL, 0);
    want_gsi = brix_sec_proto_advertised(parms, "gsi", NULL, 0);

    /* A ztn credential is available when we hold a token in t->delegated_token —
     * fetched (oidc-agent/token-exchange), read from the bearer file, or the
     * client's forwarded inbound JWT captured for a passthrough mode — or a bearer
     * file is configured to read from. For the default opportunistic
     * "passthrough-opt" mode with NO inbound token, delegated_token is empty here,
     * so have_ztn_cred degrades to the bearer-file test and the code below falls
     * back to GSI proxy delegation (or anonymous) — the pre-default-flip behaviour. */
    have_ztn_cred = (t->delegated_token[0] != '\0'
                     || t->conf->common.tpc_outbound_bearer_file.len > 0) ? 1 : 0;
    have_cert = (t->conf->common.certificate.len > 0
                 && t->conf->common.certificate_key.len > 0) ? 1 : 0;

    /*
     * Prefer WLCG JWT when the server lists ztn first (typical for auth=both)
     * and we have either a delegated token or a configured bearer file.
     */
    if (want_ztn && have_ztn_cred) {
        if (tpc_outbound_ztn(t, fd) == 0) {
            return 0;
        }
        if (tpc_ztn_failure_terminal(t)) {
            return -1;
        }
        /*
         * An opportunistic static/default token may fall through so sites can
         * recover from an expired token file when GSI is also configured.
         */
        if (!want_gsi || !have_cert) {
            return -1;
        }
    }

    if (want_gsi && have_cert) {
        return tpc_outbound_gsi(t, fd, login_body, login_dlen);
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC source %s requires authentication. Configure "
             "brix_tpc_outbound_bearer_file (token) and/or "
             "brix_certificate + brix_certificate_key + brix_trusted_ca "
             "(GSI) on this destination.",
             t->src_host);
    t->xrd_error = kXR_AuthFailed;
    return -1;
}
