/*
 * guard_audit_http.h — one guard-core audit line from an HTTP request.
 *
 * WHAT: brix_http_guard_audit() turns an ngx_http_request_t plus a
 *       (proto, signal, op, status) tuple into exactly one guard-core audit
 *       line on the error log — the fail2ban contract every jail under
 *       deploy/fail2ban/ reads.
 * WHY:  the transformation is entirely mechanical (peer address, sanitized
 *       URI, credential-presence flag, cached ISO-8601 stamp) and entirely
 *       security-relevant: the URI is attacker bytes and is neither
 *       NUL-terminated nor safe to print raw. Each HTTP plane that raises a
 *       signal needs the same forty lines, and forty lines copied per plane
 *       is forty lines that drift — the sanitizer gets dropped in one copy
 *       and the jail's regex stops matching in another.
 * HOW:  the caller owns only the policy (which signal, which proto token);
 *       everything else is read off the request here. proto is a fixed
 *       literal per plane, never wire data.
 */
#ifndef BRIX_PROTOCOLS_SHARED_GUARD_AUDIT_HTTP_H
#define BRIX_PROTOCOLS_SHARED_GUARD_AUDIT_HTTP_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "net/guard/guard.h"

/* Emit one audit line for `r`. `proto` is the plane's stable lowercase token
 * ("oci", "rpm", …) and must be a literal, not request-derived. */
void brix_http_guard_audit(ngx_http_request_t *r, const char *proto,
    guard_reason_t reason, guard_op_class_t op, ngx_uint_t status);

#endif /* BRIX_PROTOCOLS_SHARED_GUARD_AUDIT_HTTP_H */
