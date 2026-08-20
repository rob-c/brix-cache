/* url.h — the registry URL grammar (phase-104 §0.6.1, §0.7.5).
 *
 * WHAT: split an absolute http(s) URL into host / port / tls / path prefix,
 *       and answer whether a token-endpoint host may be trusted for a given
 *       upstream.
 * WHY:  two very different call sites need exactly this and nothing more.
 *       `brix_oci_mirror <base-url>` is parsed once at config time to build
 *       the upstream descriptor; the `realm=` of a WWW-Authenticate challenge
 *       is parsed per dance, at runtime, from bytes the UPSTREAM chose. The
 *       second is the security-critical one: a realm is an instruction to go
 *       hand a credential to a host named by the response, so it must be
 *       parsed by something that cannot be talked into a userinfo authority
 *       or a path-shaped host, and then checked against the upstream it
 *       claims to speak for. Sharing one parser with the client tools keeps
 *       that check from being reimplemented (and weakened) later.
 * HOW:  pure C over libc, no allocation, fixed-size out fields — the same
 *       kernel discipline as the name/digest/challenge grammars beside it.
 */
#ifndef BRIX_OCI_URL_H
#define BRIX_OCI_URL_H

#include <stddef.h>

typedef struct {
    char host[256];     /* hostname or IP literal; IPv6 WITHOUT brackets */
    int  port;          /* explicit, or the scheme default (80/443)      */
    int  tls;           /* 1 = https                                     */
    char path[512];     /* "" or "/prefix", never a trailing slash       */
} brix_oci_url_t;

/* Parse [url, url+n) as an absolute http:// or https:// URL. Rejects: any
 * other scheme, a userinfo ("user@host") authority, an empty or over-long
 * host, a port outside 1..65535, and a path containing "//" or a ".."
 * component. 0 ok / -1 invalid. */
int brix_oci_url_parse(const char *url, size_t n, brix_oci_url_t *out);

/* Parse [s, s+n) as a bare authority — "host[:port]" or "[v6-literal][:port]"
 * — with no scheme and no path. The span must be authority in its entirety;
 * a userinfo ("user@host"), a byte no host may carry, a port outside
 * 1..65535, or anything trailing the port is refused rather than trimmed.
 * `host` receives the literal with any brackets STRIPPED (the same form
 * brix_oci_url_t carries, so the two are comparable without normalising);
 * `*port` is written only when the authority spells one, leaving the
 * caller's default in place otherwise. 0 ok / -1 invalid. */
int brix_oci_url_authority(const char *s, size_t n, char *host, size_t hostsz,
                           int *port);

/* An operator's explicit realm allowlist (§D15.11). The derived rule below
 * covers every registry that hosts its own token service, but a site whose
 * registry delegates to an unrelated identity host cannot be mirrored at all
 * without naming that host — and "cannot be mirrored" is how allowlists get
 * replaced by switching the check off. Fixed storage, because the fill thread
 * reads it without a lock; small, because an allowlist that needs a dozen
 * entries has stopped being one. */
#define BRIX_OCI_REALM_HOST_MAX 256
#define BRIX_OCI_REALM_MAX 8

typedef struct {
    char   host[BRIX_OCI_REALM_MAX][BRIX_OCI_REALM_HOST_MAX];
    size_t n;
} brix_oci_realm_list_t;

/* Add [host, host+n) to `l` after validating it as a BARE host: an authority
 * this parser accepts, spelling no port, no userinfo and no wildcard. An
 * IP literal is legal (bracketed IPv6 is stored unbracketed, so it compares
 * against a parsed realm without normalising). Returns 0, or -1 on an invalid
 * entry, -2 when `l` is full and -3 on a duplicate — distinct because an
 * operator wants to be told WHICH mistake they made at nginx -t, and a
 * duplicate is a typo in a list this short. */
int brix_oci_realm_list_add(brix_oci_realm_list_t *l, const char *host,
                            size_t n);

/* As brix_oci_url_realm_allowed(), plus `extra`: a realm host that the derived
 * rule refuses is still allowed when the operator listed it verbatim. `extra`
 * may be NULL. The derived rule is tried FIRST so the common case never walks
 * the list, and so an empty allowlist cannot change any existing verdict. */
int brix_oci_url_realm_allowed_ex(const char *upstream_host,
                                  const char *realm_host,
                                  const brix_oci_realm_list_t *extra);

/* May a challenge whose realm lives on `realm_host` be honoured for an
 * upstream at `upstream_host`? True when the two are equal, or when
 * `realm_host` is `upstream_host`'s registrable parent domain, or a sibling
 * under that parent — the shape every real registry uses (registry-1.docker.io
 * → auth.docker.io). The parent rule requires the parent to itself be
 * multi-label, so a single-label upstream ("quay.io" → "io") can never widen
 * the trust to every host under a TLD. 1 = allowed, 0 = refuse.
 * Equivalent to brix_oci_url_realm_allowed_ex() with no allowlist. */
int brix_oci_url_realm_allowed(const char *upstream_host,
                               const char *realm_host);

#endif /* BRIX_OCI_URL_H */
