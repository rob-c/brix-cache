/*
 * sec_unix.c — unix (peer-identity) auth module.
 *
 * WHAT: Send the local username as the kXR_auth payload. The server trusts it only
 *       for loopback peers, so this is a weak fallback.
 * WHY:  Some servers offer "&P=unix"; this satisfies it cheaply.
 * HOW:  Single round. Payload = "unix\0" + username (the server validates the
 *       5-byte tag, then parses the space/NUL-delimited name).
 *
 * wire: XProtocol.hh kXR_auth — credtype "unix", payload "unix\0" + user.
 */
#include "sec.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

static int
unix_have(void)
{
    return 1;   /* we always have a uid; the server gates by peer address */
}

static int
unix_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
           xrdc_status *st)
{
    struct passwd *pw = getpwuid(geteuid());
    const char    *user = (pw != NULL && pw->pw_name != NULL) ? pw->pw_name
                                                              : "nobody";
    size_t         ul = strlen(user);
    uint8_t       *p;

    (void) c;
    (void) parms;

    p = (uint8_t *) malloc(5 + ul);
    if (p == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "out of memory");
        return -1;
    }
    memcpy(p, "unix\0", 5);
    memcpy(p + 5, user, ul);

    *payload = p;
    *plen = (uint32_t) (5 + ul);
    return 0;
}

const xrdc_sec_module *
xrdc_sec_unix(void)
{
    static const xrdc_sec_module m = {
        "unix",
        { 'u', 'n', 'i', 'x' },
        unix_have,
        unix_first,
        NULL,
        NULL,
    };
    return &m;
}
