/*
 * sd_xroot_fwd_key.c — forwarding-proxy key parser + permit allowlist.
 *
 * Pure libc (no ngx): compiled into the server AND, with -DXRDPROTO_NO_NGX,
 * into the standalone unit test next to egress_guard.c and host_split.c.
 */
#include "sd_xroot_fwd_key.h"
#include "core/compat/host_split.h"
#include "tpc/common/egress_guard.h"

#include <errno.h>
#include <string.h>

#define FWD_AUTH_MAX  (BRIX_SD_XROOT_FWD_HOST_MAX + 8)   /* "[v6]:65535" */

static const char *
fwd_skip_slashes(const char *p)
{
    while (*p == '/') {
        p++;
    }
    return p;
}

/* The scheme is the run of letters/digits ending at ':'; anything else before
 * the ':' — or no ':' at all inside the first component — means the client
 * named no origin. */
static int
fwd_parse_scheme(const char **pp, int *tls_out)
{
    const char *p = *pp;
    size_t      n = 0;

    while (p[n] != '\0' && p[n] != ':' && p[n] != '/') {
        n++;
    }
    if (p[n] != ':' || n == 0) {
        return ENOENT;
    }
    if (n == 4 && strncmp(p, "root", 4) == 0) {
        *tls_out = 0;
    } else if (n == 5 && strncmp(p, "roots", 5) == 0) {
        *tls_out = 1;
    } else {
        return ENOTSUP;
    }
    *pp = p + n + 1;
    return 0;
}

static int
fwd_authority_char_ok(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9'))
    {
        return 1;
    }
    return c == '.' || c == '-' || c == ':' || c == '[' || c == ']';
}

/* Copy the authority (up to the next '/' or NUL) into `auth`, then split it
 * with the shared host:port core.  Rejects an empty authority, any character
 * outside the hostname / IPv6-literal alphabet, and an oversized one. */
static int
fwd_parse_authority(const char **pp, brix_sd_xroot_fwd_target_t *t)
{
    const char *p = *pp;
    char        auth[FWD_AUTH_MAX];
    size_t      n = 0;

    while (p[n] != '\0' && p[n] != '/') {
        if (!fwd_authority_char_ok(p[n])) {
            return EINVAL;
        }
        n++;
    }
    if (n == 0) {
        return EINVAL;
    }
    if (n >= sizeof(auth)) {
        return ENAMETOOLONG;
    }
    memcpy(auth, p, n);
    auth[n] = '\0';
    if (brix_split_host_port(auth, t->host, sizeof(t->host), &t->port,
                             BRIX_SD_XROOT_FWD_PORT_DEF) != 0)
    {
        return (n >= BRIX_SD_XROOT_FWD_HOST_MAX) ? ENAMETOOLONG : EINVAL;
    }
    *pp = p + n;
    return 0;
}

int
brix_sd_xroot_fwd_parse_key(const char *key, brix_sd_xroot_fwd_target_t *t)
{
    const char *p;
    size_t      n;
    int         rc;

    if (key == NULL || t == NULL) {
        return EINVAL;
    }
    memset(t, 0, sizeof(*t));
    p = fwd_skip_slashes(key);
    rc = fwd_parse_scheme(&p, &t->tls);
    if (rc != 0) {
        return rc;
    }
    p = fwd_skip_slashes(p);                 /* "root:" "//" or "root:" "/" */
    rc = fwd_parse_authority(&p, t);
    if (rc != 0) {
        return rc;
    }
    p = fwd_skip_slashes(p);                 /* "host//file" and "host/file" */
    n = strlen(p);
    if (n + 2 > sizeof(t->path)) {
        return ENAMETOOLONG;
    }
    t->path[0] = '/';
    memcpy(t->path + 1, p, n + 1);
    return 0;
}

int
brix_sd_xroot_fwd_host_permitted(const char *permit, const char *host)
{
    const char *p = permit;
    char        pat[BRIX_SD_XROOT_FWD_HOST_MAX];
    size_t      n;

    if (p == NULL || host == NULL || host[0] == '\0') {
        return 0;
    }
    for ( ;; ) {
        while (*p == ' ') {
            p++;
        }
        if (*p == '\0') {
            return 0;
        }
        n = strcspn(p, " ");
        if (n < sizeof(pat)) {
            memcpy(pat, p, n);
            pat[n] = '\0';
            if (brix_tpc_host_pattern_match(pat, host)) {
                return 1;
            }
        }
        p += n;
    }
}
