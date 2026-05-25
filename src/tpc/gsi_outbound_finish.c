#include "tpc_internal.h"
#include "../session/session.h"
#include "../protocol/gsi.h"

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__linux__)
#include <endian.h>
#endif

/* ---- File: gsi_outbound_finish.c — Auth path selection/dispatch for TPC pull outbound authentication ----
 *
 * WHAT: Single function tpc_outbound_finish_login implements auth path selection based on server login/authmore parameters and client configuration. Parses login_body after session ID to find "ztn" (WLCG JWT) or "gsi" (x509 certreq) in parms string → checks have_bearer (conf->tpc_outbound_bearer_file.len > 0) + have_cert (certificate + certificate_key both set) → if want_ztn && have_bearer: try tpc_outbound_ztd(t, fd) first; on failure fall through only if server also allows GSI (want_gsi && have_cert) for recovery from expired token file → if want_gsi && have_cert: delegate to tpc_outbound_gsi(t, fd) → if neither path succeeds: error message referencing missing config + kXR_AuthFailed. Returns 0 or -1 with t->xrd_error set. Caller: thread.c (auth path dispatch after bootstrap).
 *
 * WHY: TPC pull outbound authentication needs to select between WLCG JWT (ztn) and GSI certreq auth paths based on what the server supports (advertised in login/authmore parameters) and what credentials are configured locally. The selection logic prefers JWT when the server lists ztn first (typical for auth=both deployments) and a bearer file exists, with fallback to GSI if ZTN fails but server also allows GSI — this prevents silent failure from expired token files at sites that have both auth methods available.
 *
 * HOW: login_dlen <= session_id_len+1 → error kXR_ArgInvalid → parms = login_body + session_id_len → strstr(parms, "ztn") for want_ztn + strstr(parms, "gsi") for want_gsi → conf->tpc_outbound_bearer_file.len > 0 for have_bearer + certificate.len > 0 && certificate_key.len > 0 for have_cert → if want_ztn && have_bearer: tpc_outbound_ztd(t, fd) == 0 → return 0; else if !want_gsi || !have_cert → return -1 (no fallback available); if want_gsi && have_cert: tpc_outbound_gsi(t, fd) → error snprintf referencing missing config + kXR_AuthFailed.
 * ------------------------------------------------------------------ */

/* WHAT: Auth path selection/dispatch — parse server login/authmore params for ztn/gsi, check have_bearer+have_cert config → prefer JWT if want_ztn && have_bearer (fall through to GSI on failure), else delegate tpc_outbound_gsi(t, fd). Returns 0 or -1 with t->xrd_error set. Caller: thread.c auth path dispatch after bootstrap. */
int
tpc_outbound_finish_login(xrootd_tpc_pull_t *t, int fd,
    u_char *login_body, uint32_t login_dlen)
{
    char              *parms;
    int                want_ztn;
    int                want_gsi;
    ngx_flag_t         have_bearer;
    ngx_flag_t         have_cert;

    if (login_dlen <= XROOTD_SESSION_ID_LEN + 1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC login authmore body too short");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    parms = (char *) login_body + XROOTD_SESSION_ID_LEN;

    want_ztn = (strstr(parms, "ztn") != NULL);
    want_gsi = (strstr(parms, "gsi") != NULL);

    have_bearer = (t->conf->tpc_outbound_bearer_file.len > 0) ? 1 : 0;
    have_cert = (t->conf->certificate.len > 0
                 && t->conf->certificate_key.len > 0) ? 1 : 0;

    /*
     * Prefer WLCG JWT when the server lists ztn first (typical for auth=both)
     * and we have a bearer file.
     */
    if (want_ztn && have_bearer) {
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
        return tpc_outbound_gsi(t, fd);
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC source %s requires authentication. Configure "
             "xrootd_tpc_outbound_bearer_file (token) and/or "
             "xrootd_certificate + xrootd_certificate_key + xrootd_trusted_ca "
             "(GSI) on this destination.",
             t->src_host);
    t->xrd_error = kXR_AuthFailed;
    return -1;
}

