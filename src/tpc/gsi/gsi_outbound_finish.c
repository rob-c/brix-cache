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

#if defined(__linux__)
#include <endian.h>
#endif

/* File: gsi_outbound_finish.c — Auth path selection/dispatch for TPC pull outbound authentication
 * WHAT: Single function tpc_outbound_finish_login implements auth path selection based on server login/authmore parameters and client configuration. Parses login_body after session ID to find "ztn" (WLCG JWT) or "gsi" (x509 certreq) in parms string → checks have_ztn_cred (delegated token or configured bearer file) + have_cert (certificate + certificate_key both set) → if want_ztn && have_ztn_cred: try tpc_outbound_ztn(t, fd) first; on failure fall through only if server also allows GSI (want_gsi && have_cert) for recovery from expired token file → if want_gsi && have_cert: delegate to tpc_outbound_gsi(t, fd) → if neither path succeeds: error message referencing missing config + kXR_AuthFailed. Returns 0 or -1 with t->xrd_error set. Caller: thread.c (auth path dispatch after bootstrap).
 *
 * WHY: TPC pull outbound authentication needs to select between WLCG JWT (ztn) and GSI certreq auth paths based on what the server supports (advertised in login/authmore parameters) and what credentials are configured locally. The selection logic prefers JWT when the server lists ztn first (typical for auth=both deployments) and a bearer file exists, with fallback to GSI if ZTN fails but server also allows GSI — this prevents silent failure from expired token files at sites that have both auth methods available.
 *
 * HOW: login_dlen <= session_id_len+1 → error kXR_ArgInvalid → parms = login_body + session_id_len → strstr(parms, "ztn") for want_ztn + strstr(parms, "gsi") for want_gsi → delegated_token or conf->tpc_outbound_bearer_file for have_ztn_cred + certificate.len > 0 && certificate_key.len > 0 for have_cert → if want_ztn && have_ztn_cred: tpc_outbound_ztn(t, fd) == 0 → return 0; else if !want_gsi || !have_cert → return -1 (no fallback available); if want_gsi && have_cert: tpc_outbound_gsi(t, fd) → error snprintf referencing missing config + kXR_AuthFailed.
 * */

/* WHAT: Auth path selection/dispatch — parse server login/authmore params for ztn/gsi, check have_ztn_cred+have_cert config → prefer JWT if want_ztn && have_ztn_cred (fall through to GSI on failure), else delegate tpc_outbound_gsi(t, fd). Returns 0 or -1 with t->xrd_error set. Caller: thread.c auth path dispatch after bootstrap. */
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
                     || t->conf->tpc_outbound_bearer_file.len > 0) ? 1 : 0;
    have_cert = (t->conf->certificate.len > 0
                 && t->conf->certificate_key.len > 0) ? 1 : 0;

    /*
     * Prefer WLCG JWT when the server lists ztn first (typical for auth=both)
     * and we have either a delegated token or a configured bearer file.
     */
    if (want_ztn && have_ztn_cred) {
        if (tpc_outbound_ztn(t, fd) == 0) {
            return 0;
        }
        /*
         * If the server also allows GSI, fall through so sites can recover from
         * an expired token file without silent failure.
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
