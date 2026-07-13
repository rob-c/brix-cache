/*
 * delegation.h - authenticated proxy-upload delegation endpoint (opt-in),
 * plus the standard GridSite two-step getProxyReq/putProxy REST flow
 * (phase-3 T4).
 *
 * See delegation.c for the full WHAT/WHY/HOW of all three entry points.
 */

#ifndef BRIX_WEBDAV_DELEGATION_H
#define BRIX_WEBDAV_DELEGATION_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * webdav_delegation_handle - async body-read completion callback for
 * PUT/POST /.well-known/brix-delegation.  Validates the uploaded RFC-3820
 * proxy PEM, checks it delegates the authenticated client's own identity,
 * and atomically stores it at <storage_credential_dir>/<key>.pem so Phase-1
 * credential selection (brix_sd_ucred_select) picks it up for that user's
 * subsequent origin sessions.
 *
 * Always finalizes the request (calls webdav_metrics_finalize_request)
 * itself; never returns a value the dispatcher needs to act on.
 */
void webdav_delegation_handle(ngx_http_request_t *r);

/*
 * webdav_delegation_request_handle - GET /.well-known/brix-delegation/request
 * (phase-3 T4 step 1, GridSite getProxyReq).  GSI-cert-authenticated only.
 * Generates a fresh RSA keypair + RFC-3820 proxy-certificate REQUEST whose
 * parent is the client's OWN peer certificate (fetched fresh off the TLS
 * connection), stores {id, fresh_key, client_dn, expires_at} in the
 * per-worker pending-delegation store, and returns the CSR PEM in the body
 * with the delegation-id in the X-Brix-Delegation-Id response header.
 *
 * Synchronous (no body to read) — called directly from dispatch.c as part
 * of the SAME content-phase call stack (unlike webdav_delegation_handle /
 * _put_handle, which run as brix_http_read_body ASYNC completion
 * callbacks). It therefore follows the ordinary synchronous-handler
 * contract (webdav_handle_options, GET, PROPFIND, ...): it does NOT call
 * webdav_metrics_finalize_request itself — it sends its own response body
 * (a CSR has no natural fit in a status-code-only reply) but returns the
 * resulting status/ngx_int_t for the caller to pass through
 * webdav_metrics_return(), letting nginx's content phase perform the single
 * ngx_http_finalize_request call.  Calling webdav_metrics_finalize_request
 * from here would double-finalize the request (nginx's content phase
 * finalizes a second time when the handler returns NGX_DONE while no
 * genuinely async work — a pending body read — is in flight) and crash the
 * worker; see the module doc-block's HOW section for the full explanation.
 */
ngx_int_t webdav_delegation_request_handle(ngx_http_request_t *r);

/*
 * webdav_delegation_put_handle - async body-read completion callback for
 * PUT /.well-known/brix-delegation/<id> (phase-3 T4 step 2, GridSite
 * putProxy).  The id is re-derived from r->uri's trailing path segment (the
 * same string dispatch.c matched to route here — r->uri is stable for the
 * life of the request, so no separate stashing is needed between the
 * synchronous dispatch and this async completion callback).  Body is the
 * client-signed proxy certificate followed by its issuer (EEC) chain, PEM.
 * Looks up the id in the pending-delegation store (sweeping expired entries
 * first), verifies it is still valid and bound to THIS request's
 * authenticated client DN, assembles the full proxy with the stored fresh
 * private key (brix_gsi_assemble_proxy), and — on success — atomically
 * stores it at <storage_credential_dir>/<key>.pem exactly like
 * webdav_delegation_handle.  The store entry (and its private key) is
 * dropped on any terminal outcome of this call, success or failure.
 *
 * Always finalizes the request itself.
 */
void webdav_delegation_put_handle(ngx_http_request_t *r);

#endif /* BRIX_WEBDAV_DELEGATION_H */
