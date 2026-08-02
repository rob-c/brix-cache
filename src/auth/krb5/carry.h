#ifndef BRIX_AUTH_KRB5_CARRY_H
#define BRIX_AUTH_KRB5_CARRY_H

#include "core/ngx_brix_module.h"

/*
 * carry.h — async-safe carry of a delegated krb5 credential (phase-70 §5.7).
 *
 * WHAT: Serialise a captured GSS initiator credential
 *       (brix_krb5_capture_fwd_cred) to a 0600 FILE ccache and re-acquire it
 *       later, so the delegated identity can cross the request → async
 *       cache-fill boundary as a plain filesystem PATH rather than a live
 *       gss_cred_id_t handle.
 *
 * WHY:  The origin krb5 EXCHANGE leg (brix_cache_origin_auth_krb5) runs on the
 *       async fill task (worker thread, outliving the request), but a live
 *       gss_cred_id_t is request-scoped and unsafe to embed in
 *       brix_cache_fill_t. The codebase already solves this exact shape for
 *       x509 proxies — the front door writes the PEM to a 0600 temp path and the
 *       async gsi leg reloads it (vfs_deleg.c brix_vfs_deleg_proxy →
 *       brix_cache_origin_auth_gsi). This is the same pattern for krb5: a FILE
 *       ccache is the serialisable artifact, its path is the async-safe carry,
 *       and re-import happens on the fill task. The path names a temp file the
 *       caller owns (0600 via mkstemp) and cleans with the request pool.
 *
 * HOW:  Export writes the forwarded TGT out of the initiator cred into a FILE
 *       ccache with RFC 5588 gss_store_cred_into() (overwrite=1, which
 *       initialises/overwrites the named ccache — unlike the deprecated
 *       gss_krb5_copy_ccache, which cannot initialise an empty target); import
 *       mirrors capture.c (krb5_cc_resolve FILE + gss_krb5_import_cred). All
 *       handles stay opaque
 *       (void*) so krb5/GSSAPI never leak into this header, exactly as
 *       capture.h / forward.h do.
 */

/*
 * Export a delegated GSS initiator credential to a FILE ccache.
 *
 * deleg_gss_cred — gss_cred_id_t (as void*) from brix_krb5_capture_fwd_cred.
 * path           — destination FILE ccache path (no "FILE:" prefix). The caller
 *                  creates it 0600 (mkstemp) and owns cleanup; libkrb5 rewrites
 *                  it atomically 0600 on initialise.
 * log            — diagnostics (no secret is ever emitted).
 *
 * Returns NGX_OK / NGX_ERROR. Without krb5/GSSAPI support returns NGX_ERROR.
 */
ngx_int_t brix_krb5_cred_to_ccache(void *deleg_gss_cred, const char *path,
    ngx_log_t *log);

/*
 * Re-acquire a GSS initiator credential from a FILE ccache written by
 * brix_krb5_cred_to_ccache().
 *
 * path         — FILE ccache path (no "FILE:" prefix).
 * out_gss_cred — receives a gss_cred_id_t (as void*) on success.
 * out_hold     — receives an opaque backing handle that keeps the krb5 context +
 *                ccache alive for the cred's lifetime; release it (with the cred)
 *                via brix_krb5_cred_carry_release(). The FILE itself is the
 *                caller's temp and is NOT unlinked here.
 * log          — diagnostics.
 *
 * Returns NGX_OK / NGX_ERROR. Without krb5/GSSAPI support returns NGX_ERROR.
 */
ngx_int_t brix_krb5_cred_from_ccache(const char *path, void **out_gss_cred,
    void **out_hold, ngx_log_t *log);

/*
 * Release a (gss_cred, hold) pair from brix_krb5_cred_from_ccache(): releases the
 * GSS cred and closes (does NOT destroy) the backing ccache/context — the FILE is
 * a caller-owned temp cleaned separately, so import never unlinks it. NULL-safe.
 */
void brix_krb5_cred_carry_release(void *gss_cred, void *hold, ngx_log_t *log);

#endif /* BRIX_AUTH_KRB5_CARRY_H */
