/* url.c — the registry URL grammar: scheme, path prefix, realm trust
 * (phase-104 §0.6.1, §0.7.5). The authority half lives in authority.c.
 *
 * See url.h for WHAT/WHY. This file is the HOW: a strict left-to-right walk
 * with no backtracking and no allocation, refusing anything it does not
 * positively recognise. Everything it accepts becomes either a socket
 * destination or a request-line prefix, so "refuse" is always cheaper than
 * "normalise": there is no such thing as a mostly-right host.
 */

#include "url.h"
#include "url_internal.h"

#include <string.h>
#include <strings.h>                       /* strcasecmp */

/* Parse the authority (host[:port]) of [s, s+n). Returns the offset where the
 * path begins, or 0 on any refusal. The span is delimited here and validated
 * by the shared authority parser, so "what may follow the host" is decided in
 * exactly one place — an IPv6 literal in a base URL and one in an image
 * reference cannot disagree about their own grammar. */
static size_t
oci_url_authority(const char *s, size_t n, brix_oci_url_t *out)
{
    size_t end;

    for (end = 0;
         end < n && s[end] != '/' && s[end] != '?' && s[end] != '#';
         end++)
    { /* the authority runs to the path, query or fragment */ }

    if (brix_oci_url_authority(s, end, out->host, sizeof(out->host),
                               &out->port) != 0)
    {
        return 0;
    }
    return end;
}

/* Parse the path prefix. A query or fragment ends it; a trailing '/' is
 * dropped so the prefix concatenates cleanly with a leading-'/' key. */
static int
oci_url_path(const char *s, size_t n, brix_oci_url_t *out)
{
    size_t len, i;

    out->path[0] = '\0';
    if (n == 0) {
        return 0;
    }
    if (s[0] != '/') {
        return -1;
    }

    for (len = 0; len < n && s[len] != '?' && s[len] != '#'; len++) {
        /* Empty and dot-dot components would each let a prefix reach outside
         * the namespace the operator named; neither has a benign spelling. */
        if (s[len] == '/' && len + 1 < n && s[len + 1] == '/') {
            return -1;
        }
        if (s[len] == '.' && len + 1 < n && s[len + 1] == '.') {
            return -1;
        }
    }
    while (len > 1 && s[len - 1] == '/') {
        len--;
    }
    if (len <= 1) {
        return 0;                          /* "/" contributes no prefix */
    }
    for (i = 0; i < len; i++) {
        if ((unsigned char) s[i] <= 0x20 || (unsigned char) s[i] == 0x7f) {
            return -1;                     /* CTL/space: request smuggling */
        }
    }
    return oci_url_field(out->path, sizeof(out->path), s, len);
}

int
brix_oci_url_parse(const char *url, size_t n, brix_oci_url_t *out)
{
    static const char  https[] = "https://";
    static const char  http[]  = "http://";
    size_t             off, authority_len;

    if (url == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (n > sizeof(https) - 1 && memcmp(url, https, sizeof(https) - 1) == 0) {
        out->tls  = 1;
        out->port = 443;
        off       = sizeof(https) - 1;

    } else if (n > sizeof(http) - 1
               && memcmp(url, http, sizeof(http) - 1) == 0)
    {
        out->tls  = 0;
        out->port = 80;
        off       = sizeof(http) - 1;

    } else {
        return -1;
    }

    authority_len = oci_url_authority(url + off, n - off, out);
    if (authority_len == 0) {
        return -1;
    }
    off += authority_len;

    return oci_url_path(url + off, n - off, out);
}

/* The registrable parent of `host`: everything after the first label, but
 * only when what remains is itself multi-label. NULL when there is no such
 * parent ("quay.io" → "io" is not one, and treating it as one would put every
 * host under .io inside the trust boundary). */
static const char *
oci_url_parent(const char *host)
{
    const char *dot = strchr(host, '.');

    if (dot == NULL || dot[1] == '\0') {
        return NULL;
    }
    return (strchr(dot + 1, '.') != NULL) ? dot + 1 : NULL;
}

/* An allowlist entry is a bare host. It is validated by the SAME authority
 * parser a realm goes through, so an entry can only ever name something a
 * realm could also spell — an entry that no realm can equal is a typo, and a
 * typo in an allowlist is a hole the operator believes they have plugged. */
int
brix_oci_realm_list_add(brix_oci_realm_list_t *l, const char *host, size_t n)
{
    char    parsed[BRIX_OCI_REALM_HOST_MAX];
    int     port = -1;
    size_t  i;

    if (l == NULL || host == NULL) {
        return -1;
    }
    if (memchr(host, '*', n) != NULL) {
        return -1;                 /* a wildcard is not an allowlist entry */
    }
    if (brix_oci_url_authority(host, n, parsed, sizeof(parsed), &port) != 0) {
        return -1;
    }
    if (port != -1) {
        return -1;                 /* the trust rule compares hosts only   */
    }

    for (i = 0; i < l->n; i++) {
        if (strcasecmp(l->host[i], parsed) == 0) {
            return -3;
        }
    }
    if (l->n >= BRIX_OCI_REALM_MAX) {
        return -2;
    }

    memcpy(l->host[l->n], parsed, strlen(parsed) + 1);
    l->n++;
    return 0;
}

int
brix_oci_url_realm_allowed_ex(const char *upstream_host,
    const char *realm_host, const brix_oci_realm_list_t *extra)
{
    size_t i;

    if (brix_oci_url_realm_allowed(upstream_host, realm_host)) {
        return 1;
    }
    if (extra == NULL || realm_host == NULL) {
        return 0;
    }
    for (i = 0; i < extra->n; i++) {
        if (strcasecmp(extra->host[i], realm_host) == 0) {
            return 1;
        }
    }
    return 0;
}

int
brix_oci_url_realm_allowed(const char *upstream_host, const char *realm_host)
{
    const char *parent;
    size_t      plen, rlen;

    if (upstream_host == NULL || realm_host == NULL) {
        return 0;
    }
    if (strcasecmp(upstream_host, realm_host) == 0) {
        return 1;
    }

    parent = oci_url_parent(upstream_host);
    if (parent == NULL) {
        return 0;
    }
    if (strcasecmp(parent, realm_host) == 0) {
        return 1;
    }

    /* A sibling under the same parent: realm_host must END with ".<parent>",
     * anchored on the dot so "notdocker.io" cannot pass for ".docker.io". */
    plen = strlen(parent);
    rlen = strlen(realm_host);
    if (rlen <= plen + 1) {
        return 0;
    }
    return realm_host[rlen - plen - 1] == '.'
        && strcasecmp(realm_host + rlen - plen, parent) == 0;
}
