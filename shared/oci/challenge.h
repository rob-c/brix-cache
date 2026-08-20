/* challenge.h — WWW-Authenticate Bearer challenge grammar (phase-104 §0.7.5).
 *
 * WHAT: parse `Bearer realm="…",service="…",scope="…"` (RFC 7235 auth-param
 *       list) into fixed fields.
 * WHY:  the token dance has two consumers — the server's upstream-auth path
 *       (oci_upstream_auth.c) and the client registry transport
 *       (reg_client.c). One grammar, or the two drift on exactly the header
 *       an upstream authored to be tricky.
 * HOW:  strict auth-param walk: token keys, quoted or token values, commas
 *       between params; quoted-pair escapes honored; unknown params skipped;
 *       overlong values refused (they become URL/query components later, so
 *       truncation would be a smuggling vector, not a nicety).
 */
#ifndef BRIX_OCI_CHALLENGE_H
#define BRIX_OCI_CHALLENGE_H

#include <stddef.h>

typedef struct {
    char realm[512];      /* required — token endpoint URL */
    char service[256];    /* optional, empty when absent */
    char scope[512];      /* optional; echoed verbatim into the token GET */
    char error[64];       /* optional error="…" (insufficient_scope, …) */
} brix_oci_challenge_t;

/* Parse [value, value+len) (the header VALUE, no header name). 0 ok / -1
 * (not a Bearer challenge, missing realm, malformed params, overlong). */
int brix_oci_challenge_parse(const char *value, size_t len,
                             brix_oci_challenge_t *out);

#endif /* BRIX_OCI_CHALLENGE_H */
