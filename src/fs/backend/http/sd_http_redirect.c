/*
 * sd_http_redirect.c — the origin 3xx hop policy (phase-104 D1.4).
 *
 * WHAT: given a `Location:` from an origin redirect, decide the next hop: the
 *       host/port/tls/path to request, and the header block to request it
 *       with. Pure policy — this file performs no I/O and touches no curl
 *       handle; the caller (sd_http_select.c) does the perform.
 * WHY:  container registries answer a blob GET with a 302 to a CDN, so a fill
 *       that will not follow one cannot mirror DockerHub at all. Following is
 *       the easy half; the hard half is that the redirect is chosen by the
 *       RESPONSE, i.e. by whoever answered — and our request carries a bearer
 *       minted for the registry and, on a GSI leg, the end user's proxy
 *       certificate. Handing either to the host a 302 names is the classic
 *       token-leak bug class, and it is exactly what libcurl's FOLLOWLOCATION
 *       would do here: custom `Authorization:` set via CURLOPT_HTTPHEADER is
 *       NOT stripped across hosts the way libcurl's own auth is. So the hop is
 *       taken by hand, and the credential decision is made in one auditable
 *       place instead of being a curl default nobody re-reads.
 * HOW:  parse an absolute Location with the shared URL kernel (shared/oci/url.c
 *       — the same parser that vets a challenge realm, and the only one in the
 *       tree that refuses userinfo authorities and `..` path components);
 *       accept a root-relative Location as the same endpoint; refuse everything
 *       else. Same host AND port AND scheme ⇒ the header block rides along
 *       unchanged. Anything else is a different peer: `Authorization` is
 *       dropped from the block and the caller is told to drop the client cert.
 */

#include "sd_http_internal.h"

#include "oci/url.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>                      /* strncasecmp */

/* Resolve a Location into the hop's peer and path. 1 = the hop stays on the
 * endpoint that sent it (root-relative, or an absolute URL naming the same
 * host/port/scheme), 0 = it moves to another peer, -1 = the Location is not a
 * form this client resolves.
 *
 * Anything that is neither root-relative nor an absolute http(s) URL — a bare
 * relative path, a "//host/p" scheme-relative form, file:, gopher:, a data:
 * URI — is refused rather than resolved: no registry emits one, and resolving
 * is where the interesting escapes live. */
static int
sd_http_redirect_peer(const char *location, const sd_http_endpoint *from,
    sd_http_redirect_t *hop)
{
    brix_oci_url_t  url;
    const char     *query;

    if (location[0] == '/') {
        if (location[1] == '/') {
            return -1;
        }
        if ((size_t) snprintf(hop->path, sizeof(hop->path), "%s", location)
            >= sizeof(hop->path))
        {
            return -1;
        }
        snprintf(hop->host, sizeof(hop->host), "%s", from->host);
        hop->port = from->port;
        hop->tls  = from->tls;
        return 1;
    }

    if (brix_oci_url_parse(location, strlen(location), &url) != 0) {
        return -1;
    }
    /* url.path is the prefix with no trailing slash and STOPS at '?', so the
     * query is carried across by hand: a CDN blob URL is a SIGNED url — the
     * whole authorization is `?Expires=…&Signature=…` — and a hop that drops
     * it arrives unsigned and is refused, which reads back here as the origin
     * denying the object. A registry CDN redirect always carries a path, and
     * an empty one is "/". */
    query = strchr(location, '?');
    if ((size_t) snprintf(hop->path, sizeof(hop->path), "%s%s",
                          url.path[0] ? url.path : "/",
                          (query != NULL) ? query : "") >= sizeof(hop->path))
    {
        return -1;
    }
    snprintf(hop->host, sizeof(hop->host), "%s", url.host);
    hop->port = url.port;
    hop->tls  = url.tls;

    return (strcasecmp(url.host, from->host) == 0
            && url.port == from->port
            && url.tls == from->tls) ? 1 : 0;
}


/* Copy the header block, dropping every `Authorization:` line. Header blocks
 * here are CRLF-joined and always CRLF-terminated (composed by
 * sd_http_read.c/sd_http_fo_challenge_retry), so a line is [start, crlf+2). */
static int
sd_http_redirect_strip_auth(const char *hdrs, char *out, size_t cap)
{
    const char *p = hdrs;
    size_t      used = 0;

    out[0] = '\0';
    if (hdrs == NULL) {
        return 0;
    }

    while (*p != '\0') {
        const char *eol = strstr(p, "\r\n");
        size_t      len = (eol != NULL) ? (size_t) (eol - p) + 2 : strlen(p);

        if (strncasecmp(p, "Authorization:", 14) != 0) {
            if (used + len >= cap) {
                return -1;
            }
            memcpy(out + used, p, len);
            used += len;
            out[used] = '\0';
        }
        if (eol == NULL) {
            break;
        }
        p = eol + 2;
    }
    return 0;
}

int
sd_http_redirect_is(int status)
{
    return (status == 301 || status == 302 || status == 303
            || status == 307 || status == 308);
}

int
sd_http_redirect_next(const char *location, const sd_http_endpoint *from,
    const char *extra_hdrs, sd_http_redirect_t *hop)
{
    int  same_peer;

    if (location == NULL || location[0] == '\0') {
        return -1;
    }

    same_peer = sd_http_redirect_peer(location, from, hop);
    if (same_peer < 0) {
        return -1;
    }

    /* A cleartext hop off a TLS origin is a downgrade: the bearer would be
     * dropped anyway, but the OBJECT would then arrive over a channel an
     * on-path attacker can rewrite. Refuse rather than fill from it. */
    if (from->tls && !hop->tls) {
        return -1;
    }

    hop->carries_credential = same_peer;
    if (same_peer) {
        if ((size_t) snprintf(hop->hdrs, sizeof(hop->hdrs), "%s",
                              (extra_hdrs != NULL) ? extra_hdrs : "")
            >= sizeof(hop->hdrs))
        {
            return -1;
        }
        return 0;
    }

    return sd_http_redirect_strip_auth(extra_hdrs, hop->hdrs,
                                       sizeof(hop->hdrs));
}
