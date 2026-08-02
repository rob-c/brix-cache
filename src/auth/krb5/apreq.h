#ifndef BRIX_AUTH_KRB5_APREQ_H
#define BRIX_AUTH_KRB5_APREQ_H

#include "core/ngx_brix_module.h"

/*
 * apreq.h — raw-krb5 AP-REQ builder for the OUTBOUND origin leg (phase-70 §5.7).
 *
 * WHAT: Given a delegated user's TGT in a FILE ccache PATH (the async-safe carry
 *       artifact brix_krb5_cred_to_ccache produces) and the origin's krb5 service
 *       principal, obtain a service ticket and produce the exact kXR_auth "krb5"
 *       credential payload a stock XRootD krb5 acceptor (libXrdSeckrb5) and brix's
 *       own src/auth/krb5/auth.c both consume: the 5 bytes "krb5\0" (the protocol
 *       name as a NUL-terminated string, per XrdSecInterface) followed by the raw
 *       AP-REQ (ASN.1 [APPLICATION 14]) — byte-for-byte the framing the native
 *       client emits from client/lib/auth/sec/sec_krb5.c.
 *
 * WHY:  The GSSAPI forwarding engine (forward.c brix_krb5_deleg_negotiate) speaks
 *       gss_init_sec_context tokens, but stock XRootD krb5 is RAW krb5_rd_req — a
 *       dialect mismatch, so the GSS leg can authenticate to no real "&P=krb5"
 *       origin. This builder is the raw-krb5 counterpart: it acts AS the delegated
 *       user with a plain AP-REQ, interoperating with both reference xrootd and
 *       brix acceptors. The delegated credential is already carried onto the fill
 *       task as a ccache PATH, so no GSS re-import is needed on this path.
 *
 * HOW:  Under BRIX_HAVE_KRB5: krb5_cc_resolve(ccache_path) → krb5_cc_get_principal
 *       (the delegated user) → krb5_parse_name(origin_spn) → krb5_get_credentials
 *       (a service ticket for the origin, off the carried TGT) → krb5_mk_req_extended
 *       (the AP-REQ) → assemble "krb5\0"+AP-REQ into the caller's pool. Per-user
 *       only: any failure fails CLOSED (never a service-credential fallback).
 *       Without BRIX_HAVE_KRB5 the file still compiles and this reports NGX_ERROR.
 */

/*
 * Build the kXR_auth "krb5" credential payload from a delegated TGT ccache.
 *
 * pool        — the payload bytes are allocated here; caller owns nothing else.
 * ccache_path — a FILE (or MEMORY) ccache holding the delegated user's TGT.
 * origin_spn  — the origin service principal, e.g. "xrootd/host@REALM" (as the
 *               origin advertises in "&P=krb5,<principal>").
 * out_payload — receives "krb5\0" + AP-REQ (pool-allocated). Untouched on failure.
 * log         — for krb5 diagnostics (never logs ticket/secret bytes).
 *
 * Returns NGX_OK with *out_payload set, or NGX_ERROR (fails closed).
 */
ngx_int_t brix_krb5_apreq_from_ccache(ngx_pool_t *pool, const char *ccache_path,
    const char *origin_spn, ngx_str_t *out_payload, ngx_log_t *log);

#endif /* BRIX_AUTH_KRB5_APREQ_H */
