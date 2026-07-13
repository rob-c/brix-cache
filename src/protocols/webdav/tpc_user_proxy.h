/*
 * tpc_user_proxy.h — per-user delegated x509 proxy resolution for the HTTP-TPC
 * pull leg (phase-70 credential-forwarding closure).
 *
 * WHAT: Declares webdav_tpc_user_proxy_resolve(), which maps the requesting
 *       user's authenticated identity to the client certificate + key the pull
 *       leg must present to the SOURCE so the source authenticates the END USER
 *       (not the destination's static service cert), plus the small descriptor
 *       it fills.
 *
 * WHY:  Without this, a WebDAV/HTTP TPC PULL presents conf->tpc_cert (a static
 *       service identity) to the source — the source logs the destination's DN,
 *       not the user's.  The Phase-70 delegation infrastructure already captures
 *       the user's proxy two ways: (1) a live full-proxy passthrough on the
 *       request (rctx->deleg_proxy_pem, from X-Brix-Delegate-Proxy), and (2) a
 *       proxy uploaded to the per-user delegation store at
 *       <storage_credential_dir>/<key>.pem (keyed by the authenticated DN via
 *       brix_sd_ucred_*).  This resolver reuses BOTH so the pull leg presents
 *       the user's own credential, closing the gap.
 *
 * HOW:  Resolution order (first hit wins):
 *         1. rctx->deleg_proxy_pem (live passthrough) → materialise to a 0600
 *            temp via brix_proxy_gsi_write_pem_temp(), register an unlink+zero
 *            request-pool cleanup, point cert_path/key_path at the temp.
 *         2. per-user delegation store: brix_sd_ucred_select() over
 *            common.storage_credential_dir keyed by the request identity; on an
 *            x509 .pem hit (cert + key combined in one PEM) point cert_path/
 *            key_path at the stored file directly (no temp, no cleanup).
 *         3. neither present → out->have=0: the caller keeps the current
 *            behaviour and falls back to conf->tpc_cert (non-delegated setups).
 *
 *       Bearer-token identities are ignored here (the bearer path is applied as
 *       an Authorization header elsewhere and already works).  A present-but-
 *       unusable delegation (malformed PEM, expired stored .pem) yields have=0
 *       — the resolver never fabricates or downgrades a credential silently.
 *
 * This runs on the EVENT LOOP (it needs the request ctx + pool); the resolved
 * path strings are request-pool-owned and remain valid for the whole request,
 * so the single-stream/multi-stream/thread-pool curl runners can all consume
 * them by borrowed pointer.
 */
#ifndef BRIX_WEBDAV_TPC_USER_PROXY_H
#define BRIX_WEBDAV_TPC_USER_PROXY_H

#include "webdav.h"

/*
 * webdav_tpc_user_proxy_t — resolved per-user pull-leg client credential.
 *
 * have=0            → no per-user proxy for this request; cert_path/key_path are
 *                     NULL and the caller falls back to conf->tpc_cert/_key.
 * have=1            → present the user proxy: cert_path and key_path are
 *                     NUL-terminated, request-pool-owned C strings a curl handle
 *                     can pass to CURLOPT_SSLCERT / CURLOPT_SSLKEY.  For both a
 *                     materialised passthrough temp and a stored .pem the cert
 *                     and key live in one combined PEM, so cert_path == key_path.
 */
typedef struct {
    int          have;        /* 1 → present cert_path/key_path, 0 → fall back */
    int          deny;        /* 1 → the user delegated a proxy we could NOT   */
                              /*     materialise: the caller MUST abort rather  */
                              /*     than silently present the service cert     */
    const char  *cert_path;   /* CURLOPT_SSLCERT path (NULL when have=0)        */
    const char  *key_path;    /* CURLOPT_SSLKEY  path (NULL when have=0)        */
} webdav_tpc_user_proxy_t;

/*
 * webdav_tpc_user_proxy_resolve — fill *out with the requesting user's pull-leg
 * client credential, or mark it absent so the caller falls back to the service
 * cert.
 *
 * Never fails the request: on any resolution error (materialise failure, cred
 * lookup error) it logs and leaves out->have=0, letting the caller decide (the
 * pull still proceeds with the static cert exactly as before this change).  The
 * private key of a materialised temp is unlinked and zeroed by a request-pool
 * cleanup registered here, so it never outlives the transfer.
 */
void webdav_tpc_user_proxy_resolve(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_tpc_user_proxy_t *out);

#endif /* BRIX_WEBDAV_TPC_USER_PROXY_H */
