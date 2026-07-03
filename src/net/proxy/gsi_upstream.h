#ifndef BRIX_PROXY_GSI_UPSTREAM_H
#define BRIX_PROXY_GSI_UPSTREAM_H

/*
 * gsi_upstream.h — Phase-4b GSI X.509 delegation for the terminating tap proxy.
 *
 * WHAT: when brix_tap_proxy_auth gsi is set, the proxy presents the client's
 *   DELEGATED X.509 proxy (captured by the GSI server delegation path into
 *   ctx->gsi_deleg_proxy_pem) to the upstream's GSI auth, logging in AS THE USER.
 * WHY: monitor/forward a user's traffic to a GSI-only backend using the user's
 *   own credential, not a service identity.
 * HOW: the working in-process GSI client is blocking (it runs the certreq/cert
 *   handshake on gsi_core); we persist the delegated proxy to a 0600 temp and run
 *   the blocking connect+login in an ngx_thread_task, then hand the authenticated
 *   fd to the proxy's async relay. This header exposes the secure-temp writer
 *   (pure, unit-testable) plus the async-login entry (Task 3/4).
 */

#include <stddef.h>

/*
 * Write `len` bytes of PEM to a freshly created, owner-only (0600), O_EXCL temp
 * file; the chosen path is copied into out[0..cap). Returns 0 on success, -1 on
 * error (errno set). Pure libc — no nginx — so it is unit-testable standalone.
 * The caller owns the file: it must unlink it after the login (or on teardown).
 */
int brix_proxy_gsi_write_pem_temp(const unsigned char *pem, size_t len,
    char *out, size_t cap);

/* The async GSI-login entry (brix_proxy_gsi_connect_async) is declared in
 * proxy_internal.h, where the proxy + nginx stream types are in scope. */

#endif /* BRIX_PROXY_GSI_UPSTREAM_H */
