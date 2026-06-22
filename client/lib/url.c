/*
 * url.c — parse the xrdcp/xrdfs URL grammar.
 *
 * WHAT: root://[user@]host[:port]//abs/path (and xroot:// alias), roots:// /
 *       xroots:// (TLS — declined this pass), file:///local or bare local paths,
 *       and "-" for stdio.
 * WHY:  xrdcp/xrdfs decide local-vs-remote and where to connect purely from the
 *       URL scheme/authority; a small clean-room parser replaces XrdCl::URL.
 * HOW:  Scheme by prefix; authority up to the first '/'; the XRootD convention is
 *       a double slash before the absolute path (root://host//file → /file), so a
 *       leading "//" in the remainder collapses to a single leading "/".
 *
 * Clean-room: behaviour mirrors the documented xrdcp URL syntax (xrdcp.1), not
 * XrdCl::URL source.
 */
#include "xrdc.h"
#include "compat/host_split.h"   /* shared host:port parse (libxrdproto) */

#include <string.h>
#include <stdlib.h>

#define XROOTD_DEFAULT_PORT_LOCAL 1094

static int
starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* Split "[user@]host[:port]" into out->user/host/port (port default 1094). */
static int
parse_authority(const char *auth, xrdc_url *out, xrdc_status *st)
{
    const char *at    = strchr(auth, '@');
    const char *hostp = auth;

    out->user[0] = '\0';
    if (at != NULL) {
        size_t ulen = (size_t) (at - auth);
        if (ulen >= sizeof(out->user)) {
            ulen = sizeof(out->user) - 1;
        }
        memcpy(out->user, auth, ulen);
        out->user[ulen] = '\0';
        hostp = at + 1;
    }

    /* Shared bracketed-IPv6-aware host:port split (libxrdproto). */
    if (xrootd_split_host_port(hostp, out->host, sizeof(out->host), &out->port,
                               XROOTD_DEFAULT_PORT_LOCAL) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "invalid host:port in URL");
        return -1;
    }
    return 0;
}

static int
parse_remote(const char *s, const char *after_scheme, xrdc_scheme scheme,
             xrdc_url *out, xrdc_status *st)
{
    const char *slash = strchr(after_scheme, '/');
    char        auth[320];
    size_t      alen;
    const char *path;

    (void) s;
    out->scheme = scheme;

    if (slash == NULL) {
        /* authority only, no path */
        if (parse_authority(after_scheme, out, st) != 0) {
            return -1;
        }
        out->path[0] = '\0';
        return 0;
    }

    alen = (size_t) (slash - after_scheme);
    if (alen >= sizeof(auth)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "authority too long");
        return -1;
    }
    memcpy(auth, after_scheme, alen);
    auth[alen] = '\0';
    if (parse_authority(auth, out, st) != 0) {
        return -1;
    }

    /* slash points at the start of the path. XRootD uses "//" between authority
     * and the absolute path, so collapse a leading "//" to one "/". */
    path = slash;
    if (path[0] == '/' && path[1] == '/') {
        path++;
    }
    if (strlen(path) >= sizeof(out->path)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "path too long");
        return -1;
    }
    strcpy(out->path, path);
    return 0;
}

int
xrdc_url_parse(const char *s, xrdc_url *out, xrdc_status *st)
{
    memset(out, 0, sizeof(*out));

    if (s == NULL || s[0] == '\0') {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "empty URL");
        return -1;
    }

    if (strcmp(s, "-") == 0) {
        out->scheme = XRDC_SCHEME_STDIO;
        return 0;
    }

    if (starts_with(s, "root://")) {
        return parse_remote(s, s + 7, XRDC_SCHEME_ROOT, out, st);
    }
    if (starts_with(s, "xroot://")) {
        return parse_remote(s, s + 8, XRDC_SCHEME_ROOT, out, st);
    }
    if (starts_with(s, "roots://")) {
        return parse_remote(s, s + 8, XRDC_SCHEME_ROOTS, out, st);
    }
    if (starts_with(s, "xroots://")) {
        return parse_remote(s, s + 9, XRDC_SCHEME_ROOTS, out, st);
    }

    if (starts_with(s, "file://")) {
        const char *p = s + 7;
        /* file:///path → skip the empty authority */
        if (p[0] == '/' && p[1] == '/') {
            p += 2;
        }
        out->scheme = XRDC_SCHEME_LOCAL;
        if (strlen(p) >= sizeof(out->path)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "path too long");
            return -1;
        }
        strcpy(out->path, p);
        return 0;
    }

    if (strstr(s, "://") != NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "scheme not supported by native client: %s", s);
        return -1;
    }

    /* Bare local path. */
    out->scheme = XRDC_SCHEME_LOCAL;
    if (strlen(s) >= sizeof(out->path)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "path too long");
        return -1;
    }
    strcpy(out->path, s);
    return 0;
}

int
xrdc_endpoint_parse(const char *ep, xrdc_url *out, xrdc_status *st)
{
    const char *colon;

    /* A full root[s]:// URL → reuse the URL parser, but require a remote scheme. */
    if (strstr(ep, "://") != NULL) {
        if (xrdc_url_parse(ep, out, st) != 0) {
            return -1;
        }
        if (out->scheme != XRDC_SCHEME_ROOT && out->scheme != XRDC_SCHEME_ROOTS) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "endpoint must be a root:// or roots:// URL");
            return -1;
        }
        return 0;
    }

    /* Bare "host[:port]" — default to root:// on port 1094. */
    memset(out, 0, sizeof(*out));
    out->scheme = XRDC_SCHEME_ROOT;
    colon = strrchr(ep, ':');
    if (colon != NULL) {
        size_t hlen = (size_t) (colon - ep);
        if (hlen == 0 || hlen >= sizeof(out->host)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "invalid host");
            return -1;
        }
        memcpy(out->host, ep, hlen);
        out->host[hlen] = '\0';
        out->port = atoi(colon + 1);
        if (out->port <= 0 || out->port > 65535) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "invalid port");
            return -1;
        }
    } else {
        if (ep[0] == '\0' || strlen(ep) >= sizeof(out->host)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "invalid host");
            return -1;
        }
        strcpy(out->host, ep);
        out->port = XROOTD_DEFAULT_PORT_LOCAL;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* web URLs (http/https/dav/davs/s3/s3s) — the non-root transfer surface */
/* ------------------------------------------------------------------ */

/* One scheme-table row: prefix → proto, TLS, S3-ness, default port. */
typedef struct {
    const char    *prefix;
    xrdc_web_proto proto;
    int            tls;
    int            is_s3;
    int            defport;
} web_scheme;

static const web_scheme WEB_SCHEMES[] = {
    { "https://", XRDC_WEB_HTTPS, 1, 0, 443 },
    { "http://",  XRDC_WEB_HTTP,  0, 0, 80  },
    { "davs://",  XRDC_WEB_DAVS,  1, 0, 443 },
    { "dav://",   XRDC_WEB_DAV,   0, 0, 80  },
    { "s3s://",   XRDC_WEB_S3S,   1, 1, 443 },
    { "s3://",    XRDC_WEB_S3,    0, 1, 80  },
};

int
xrdc_is_web_url(const char *s)
{
    size_t i;
    if (s == NULL) {
        return 0;
    }
    for (i = 0; i < sizeof(WEB_SCHEMES) / sizeof(WEB_SCHEMES[0]); i++) {
        if (starts_with(s, WEB_SCHEMES[i].prefix)) {
            return 1;
        }
    }
    return 0;
}

int
xrdc_weburl_parse(const char *s, xrdc_weburl *out)
{
    const web_scheme *sc = NULL;
    const char       *p, *hoststart, *slash;
    size_t            i;

    if (s == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    for (i = 0; i < sizeof(WEB_SCHEMES) / sizeof(WEB_SCHEMES[0]); i++) {
        if (starts_with(s, WEB_SCHEMES[i].prefix)) {
            sc = &WEB_SCHEMES[i];
            break;
        }
    }
    if (sc == NULL) {
        return -1;
    }
    out->proto = sc->proto;
    out->tls   = sc->tls;
    out->is_s3 = sc->is_s3;
    out->port  = sc->defport;
    p = s + strlen(sc->prefix);
    hoststart = p;

    if (*p == '[') {                                   /* [IPv6] literal */
        const char *rb = strchr(p, ']');
        size_t      n;
        if (rb == NULL) {
            return -1;
        }
        n = (size_t) (rb - (p + 1));
        if (n == 0 || n >= sizeof(out->host)) {
            return -1;
        }
        memcpy(out->host, p + 1, n);
        out->host[n] = '\0';
        p = rb + 1;
        if (*p == ':') {
            out->port = atoi(p + 1);
        }
    } else {
        const char *colon = NULL, *e;
        const char *hend;
        size_t      n;
        for (e = hoststart; *e != '\0' && *e != '/'; e++) {
            if (*e == ':') {
                colon = e;
            }
        }
        hend = colon ? colon : e;
        n = (size_t) (hend - hoststart);
        if (n == 0 || n >= sizeof(out->host)) {
            return -1;
        }
        memcpy(out->host, hoststart, n);
        out->host[n] = '\0';
        if (colon != NULL) {
            out->port = atoi(colon + 1);
        }
    }
    if (out->port <= 0 || out->port > 65535) {
        return -1;
    }
    slash = strchr(p, '/');
    {
        const char *pp = slash ? slash : "/";
        size_t      pl = strlen(pp);
        if (pl >= sizeof(out->path)) {
            return -1;   /* reject (don't silently truncate) an over-long path */
        }
        memcpy(out->path, pp, pl + 1);
    }
    return 0;
}
