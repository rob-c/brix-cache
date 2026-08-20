/* authority.c — the "host[:port]" half of the registry URL grammar
 * (phase-104 §0.6.1, §0.7.5, §D15.2).
 *
 * WHAT: parse a bare authority — reg-name or bracketed IPv6 literal, optional
 *       port — into a host field and a port.
 * WHY:  two callers reach a registry by naming its host, and they must agree
 *       byte for byte about what a host is: `brix_oci_mirror <base-url>` (and
 *       the `realm=` of a challenge, which is attacker-influenced) parses one
 *       inside a URL, and `brixoci pull [::1]:5000/lab/app` parses one inside
 *       an image reference. A second implementation for the second caller is
 *       how "the proxy refuses it but the tool dials it" starts.
 * HOW:  a linear walk with no allocation, refusing every byte it does not
 *       positively recognise — the same kernel discipline as the name/digest
 *       grammars beside it. It is its own TU rather than part of url.c so the
 *       client can link it without dragging in a second `url.o` (the archive
 *       keys members by basename, and client/lib/net/url.c already owns that
 *       name).
 */

#include "url.h"
#include "url_internal.h"

#include <string.h>

/* A host byte we are willing to put in a Host: header and a DNS query. Note
 * ':' is NOT here — the port is split off first, and a colon surviving into
 * the host would be a request-line smuggling primitive. */
static int
oci_url_host_byte(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
}

/* IPv6 literal bytes, inside brackets. */
static int
oci_url_v6_byte(char c)
{
    return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
        || (c >= '0' && c <= '9') || c == ':' || c == '.';
}

/* Parse a bracketed IPv6 literal at s[0] == '['. On success writes the
 * literal (brackets stripped) into host[hostsz] and returns the offset just
 * past ']'; 0 on any refusal. */
static size_t
oci_url_v6_host(const char *s, size_t n, char *host, size_t hostsz)
{
    size_t i = 1;

    while (i < n && s[i] != ']') {
        if (!oci_url_v6_byte(s[i])) {
            return 0;
        }
        i++;
    }
    if (i >= n || i == 1) {
        return 0;                         /* unterminated or empty */
    }
    if (oci_url_field(host, hostsz, s + 1, i - 1) != 0) {
        return 0;
    }
    return i + 1;                          /* past ']' */
}

int
brix_oci_url_authority(const char *s, size_t n, char *host, size_t hostsz,
    int *port)
{
    size_t i, host_end;
    long   p = 0;

    if (s == NULL || host == NULL || port == NULL) {
        return -1;
    }

    /* Userinfo has no legitimate place in a registry base URL, a challenge
     * realm or an image reference, and "https://evil.com@registry.example/"
     * is the classic way to make a human read one host while the parser sees
     * another. Refuse the whole authority rather than try to be clever. */
    for (i = 0; i < n; i++) {
        if (s[i] == '@') {
            return -1;
        }
    }

    if (n > 0 && s[0] == '[') {
        host_end = oci_url_v6_host(s, n, host, hostsz);
        if (host_end == 0) {
            return -1;
        }

    } else {
        for (host_end = 0; host_end < n && s[host_end] != ':'; host_end++) {
            if (!oci_url_host_byte(s[host_end])) {
                return -1;
            }
        }
        if (oci_url_field(host, hostsz, s, host_end) != 0) {
            return -1;
        }
    }

    if (host_end == n) {
        return 0;                          /* no port: the caller's default */
    }
    if (s[host_end] != ':') {
        return -1;                         /* junk trailing an IPv6 literal */
    }

    i = host_end + 1;
    if (i >= n) {
        return -1;                         /* ":" with no digits */
    }
    for ( ; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        p = p * 10 + (s[i] - '0');
        if (p > 65535) {
            return -1;
        }
    }
    if (p == 0) {
        return -1;
    }
    *port = (int) p;
    return 0;
}
