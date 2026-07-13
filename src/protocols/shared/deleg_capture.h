/*
 * deleg_capture.h — HTTP front-door capture of a user-supplied full x509 proxy
 * for backend credential PASSTHROUGH (phase-70 §5.1).
 *
 * WHAT: Declares brix_proto_deleg_capture_proxy_header() — the shared parser the
 *       WebDAV and S3 handlers use to lift an optional `X-Brix-Delegate-Proxy`
 *       header (base64 of a full proxy PEM: cert chain + private key) off an
 *       already-authenticated request into pool memory, enforcing the §5.1 gate.
 *
 * WHY:  Bearer passthrough needs no per-protocol capture (the raw JWT is already
 *       in hand), but a full x509 proxy is only ever present when the user
 *       VOLUNTARILY supplies it over an opt-in header. That capture — TLS-only,
 *       base64-decode, leaf-DN must equal the authenticated identity — is
 *       identical for WebDAV and S3, so it lives here once rather than duplicated
 *       across two handlers.
 *
 * HOW:  The caller passes the authenticated identity (for the DN-match) and gets
 *       back the decoded PEM in `out` (owned by r->pool). A missing header is not
 *       an error (out->len=0, NGX_OK); a present-but-rejected header returns
 *       NGX_HTTP_FORBIDDEN so the handler can fail the request.
 */
#ifndef BRIX_PROTO_DELEG_CAPTURE_H
#define BRIX_PROTO_DELEG_CAPTURE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "core/types/identity.h"

/* Capture an optional user-supplied full x509 proxy from the request.
 *
 * WHAT: If the request carries `X-Brix-Delegate-Proxy: <base64 PEM>`, validate
 *       and decode it into *out (pool memory); otherwise leave *out empty.
 *
 * WHY:  §5.1 — the node can only replay an x509 login as the user if the user
 *       supplies a full proxy (chain + key). Capturing it over a header lets a
 *       cert- or token-authenticated request opt into passthrough without a
 *       client-protocol change.
 *
 * HOW:  Gate order (fail fast): header absent → out->len=0, NGX_OK. Header
 *       present but transport is not TLS → NGX_HTTP_FORBIDDEN (a private key must
 *       never ride cleartext). base64-decode into r->pool. The decoded PEM's
 *       leaf DN (brix_x509_oneline) must string-equal the authenticated
 *       identity's DN → else NGX_HTTP_FORBIDDEN (no privilege swap). On success
 *       *out points at the decoded PEM bytes and returns NGX_OK. The full
 *       RFC-3820 chain-trust + expiry check is enforced downstream in the VFS
 *       deleg gate (vfs_deleg.c); this seam proves transport + identity binding. */
ngx_int_t brix_proto_deleg_capture_proxy_header(ngx_http_request_t *r,
    const brix_identity_t *identity, ngx_str_t *out);

#endif /* BRIX_PROTO_DELEG_CAPTURE_H */
