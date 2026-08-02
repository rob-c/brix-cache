#ifndef BRIX_AUTH_KRB5_CAPTURE_H
#define BRIX_AUTH_KRB5_CAPTURE_H

#include "core/ngx_brix_module.h"

/*
 * capture.h — round-2 krb5 forwarded-TGT capture (phase-70 §5.7).
 *
 * WHAT: Turns the round-2 KRB_CRED blob (what the XrdSeckrb5 client sends after
 *       the server's "fwdtgt" challenge) into a GSS initiator credential that
 *       acts AS the inbound user — the delegated identity later presented to the
 *       origin by brix_krb5_deleg_to_origin() (forward.h).
 *
 * WHY: krb5 is only backend-usable by EXCHANGE (GSSAPI forwarding), which needs
 *      the user's *forwardable* TGT. XrdSeckrb5 delivers it as a KRB_CRED
 *      encrypted under the session key established in round 1 (krb5_rd_req).
 *      This helper is that capture step, isolated so it can be proven against a
 *      real KDC (tests/test_krb5_forward_live.py) independently of the wire.
 *
 * HOW: krb5_rd_cred() decrypts the KRB_CRED with the round-1 auth context, the
 *      forwarded TGT is parked in a private MEMORY ccache, and
 *      gss_krb5_import_cred() imports that ccache as a gss_cred_id_t. The GSS
 *      cred references the ccache, so ownership of the ccache passes to the
 *      caller (out_ccache): keep it alive until *out_gss_cred is released, then
 *      krb5_cc_destroy it. All handles are opaque (void*) to keep krb5/GSSAPI
 *      out of this header, exactly as forward.h does.
 */

/*
 * Capture a forwarded TGT from a KRB_CRED blob and import it as a GSS cred.
 *
 * kctx         — krb5_context (as void*) from round 1.
 * auth_ctx     — krb5_auth_context (as void*) established by round-1 krb5_rd_req;
 *                MUST be the same handle (carries the session subkey the
 *                KRB_CRED is encrypted under).
 * client       — authenticated client krb5_principal (as void*); seeds the ccache.
 * krb_cred/len — raw KRB_CRED bytes (payload after the "krb5" credtype prefix).
 * out_gss_cred — receives a gss_cred_id_t (as void*) on success.
 * out_ccache   — receives the krb5_ccache (as void*) backing that cred; caller
 *                keeps it alive until it releases *out_gss_cred, then destroys it.
 * log          — for krb5/GSS diagnostics (no secret is ever emitted).
 *
 * Returns NGX_OK, or NGX_ERROR (diagnostics logged). Without krb5/GSSAPI support
 * this reports unavailable and returns NGX_ERROR.
 */
ngx_int_t brix_krb5_capture_fwd_cred(void *kctx, void *auth_ctx, void *client,
    const u_char *krb_cred, size_t krb_cred_len,
    void **out_gss_cred, void **out_ccache, ngx_log_t *log);

#endif /* BRIX_AUTH_KRB5_CAPTURE_H */
