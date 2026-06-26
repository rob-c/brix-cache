/*
 * sec_host.c — host (host-based) auth module, client side — Phase 52 WS-C.
 *
 * WHAT: Select the XRootD `host` protocol.  The client asserts no identity — it
 *       merely tags the protocol; the SERVER reverse-resolves the peer socket and
 *       authenticates the connection as that hostname against its allowlist.
 * WHY:  Some closed-network servers offer "&P=host"; this satisfies it cheaply.
 *       It is the weakest scheme (hostname/DNS is spoofable) and is preferred LAST,
 *       below every stronger protocol, in client/lib/auth.c.
 * HOW:  Single round.  Payload = "host\0" + local FQDN (informational only; the
 *       server ignores the asserted name and uses the socket's reverse-DNS).
 *
 * wire: XProtocol.hh kXR_auth — credtype "host", payload "host\0" + hostname.
 */
#include "sec.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
host_have(xrdc_conn *c)
{
    (void) c;
    return 1;   /* always selectable; the server gates by reverse-DNS allowlist */
}

static int
host_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
           xrdc_status *st)
{
    char     hn[256];
    size_t   hl;
    uint8_t *p;

    (void) c;
    (void) parms;

    if (gethostname(hn, sizeof(hn)) != 0) {
        hn[0] = '\0';
    }
    hn[sizeof(hn) - 1] = '\0';
    hl = strlen(hn);

    p = (uint8_t *) malloc(5 + hl);
    if (p == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "out of memory");
        return -1;
    }
    memcpy(p, "host\0", 5);
    memcpy(p + 5, hn, hl);

    *payload = p;
    *plen = (uint32_t) (5 + hl);
    return 0;
}

const xrdc_sec_module *
xrdc_sec_host(void)
{
    static const xrdc_sec_module m = {
        "host",
        { 'h', 'o', 's', 't' },
        host_have,
        host_first,
        NULL,
        NULL,
    };
    return &m;
}
