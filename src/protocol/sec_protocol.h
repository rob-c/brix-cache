/*
 * sec_protocol.h — kXR_login "&P=" security-protocol list parser (shared).
 *
 * WHAT: after kXR_login the server advertises the auth methods it accepts as a
 *       parameter block of "&P=<name>,<args>" entries (e.g.
 *       "&P=gsi,v:10300,c:ssl&P=ztn,..."). xrootd_sec_proto_advertised tells a
 *       client whether a given protocol is offered and, optionally, returns that
 *       entry's argument string.
 * WHY:  TWO XRootD-client implementations parse this same list to choose which
 *       credential to send: the native client's auth driver (client/lib/auth.c)
 *       and the server's own TPC-outbound auth selector (server-as-client,
 *       src/tpc/gsi_outbound_finish.c). The latter hand-rolled a LOOSER check —
 *       a bare strstr(parms, "ztn")/"gsi") with no "&P=" anchor or name-boundary
 *       test — which can false-match the substring anywhere in the block (another
 *       protocol's args, a trailing hostname) and pick the wrong auth method.
 *       Sharing the native client's anchored parser de-duplicates the grammar AND
 *       tightens the server's selection.
 * HOW:  header-only static inline over libc (strstr/strncmp/memcpy) — no ngx, no
 *       allocation — so the same code compiles into the nginx module and the
 *       ngx-free client. `parms` may be NULL for a presence-only query.
 *
 * Clean-room: "&P=<proto>,<args>" grammar from the XRootD login security list.
 */
#ifndef XROOTD_PROTOCOL_SEC_PROTOCOL_H
#define XROOTD_PROTOCOL_SEC_PROTOCOL_H

#include <stddef.h>
#include <string.h>

/*
 * Is "&P=<name>" advertised in `seclist`? Matches only on the "&P=" anchor with a
 * name boundary (',' / '&' / end), so a protocol name embedded in another entry's
 * arguments does not false-match. When `parms` is non-NULL and `psz` > 0, the
 * matched entry's argument string (the text after the name's comma, up to the next
 * "&P=" or end) is copied in NUL-terminated and truncated to fit. Returns 1 if the
 * protocol is advertised, else 0.
 */
static inline int
xrootd_sec_proto_advertised(const char *seclist, const char *name,
                            char *parms, size_t psz)
{
    size_t      nlen;
    const char *p;

    if (parms != NULL && psz > 0) {
        parms[0] = '\0';
    }
    if (seclist == NULL || name == NULL) {
        return 0;
    }

    nlen = strlen(name);
    p = seclist;
    while ((p = strstr(p, "&P=")) != NULL) {
        const char *n = p + 3;
        if (strncmp(n, name, nlen) == 0
            && (n[nlen] == ',' || n[nlen] == '&' || n[nlen] == '\0')) {
            if (parms != NULL && psz > 0) {
                const char *args = (n[nlen] == ',') ? n + nlen + 1 : "";
                const char *end  = strstr(args, "&P=");
                size_t      alen = end ? (size_t) (end - args) : strlen(args);
                if (alen >= psz) {
                    alen = psz - 1;
                }
                memcpy(parms, args, alen);
                parms[alen] = '\0';
            }
            return 1;
        }
        p = n;
    }
    return 0;
}

#endif /* XROOTD_PROTOCOL_SEC_PROTOCOL_H */
