#ifndef BRIX_GRIDFTP_DC_DN_H
#define BRIX_GRIDFTP_DC_DN_H

/*
 * ftp_dc_dn.h — the GridFTP data-channel DN pin.
 *
 * WHAT: one predicate — does the DN on a data-channel certificate name the same
 * identity the control channel authenticated?
 *
 * WHY: this test IS the data-channel security boundary.  A PROT P data channel
 * carries no commands and no identity of its own: the only thing that binds the
 * bytes to the authenticated session is that the peer presents an identity the
 * session already established (or a proxy delegated beneath it).  Both ends of
 * BriX need it — the inbound door (ftp_dc_sec.c, the accept role) and the
 * outbound gsiftp storage driver (fs/backend/gsiftp/gftp_dc_tls.c, the connect
 * role, phase-115 W5.1) — and they live in different nginx modules.  Two copies
 * of a security predicate is one copy too many, so it lives here as a
 * header-only helper, the same shape ftp_eblock.h uses for the MODE E codec.
 *
 * THE TWO ROLES PIN AGAINST DIFFERENT BASES, and passing the wrong one is a
 * silent no-match rather than an error:
 *
 *   accept role  base = the CLIENT's control DN.  The peer on the data channel
 *                is that client, presenting its own proxy.
 *   connect role base = OUR OWN subject.  A GridFTP server runs the data channel
 *                on the credential the client DELEGATED to it, so what comes
 *                back is the client's DN plus a `/CN=` per delegation step —
 *                never the server's host DN.
 *
 * In both cases the rule is the same one sentence — the peer must be the
 * identity this session already authenticated, or something delegated beneath
 * it — and only the "this session" differs by which end you are.
 *
 * HOW: in GSI a proxy's subject is exactly the delegator's subject plus one
 * `/CN=<value>` component per delegation step, so the peer DN matches when it
 * either equals the base DN or extends it by one or more trailing `/CN=`
 * components.  The chain is PKIX-verified as a well-formed RFC 3820 proxy chain
 * BEFORE this is called, so any such extension is a genuine sub-proxy: the
 * prefix cannot be forged without the base identity's key.  Callers that skip
 * the chain verification get no security from this function.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Returns 1 when `peer` (NUL-terminated) names the identity in `base`/`blen`,
 * either exactly or extended by trailing /CN= proxy components; 0 otherwise.
 * An empty base never matches — an unauthenticated control channel cannot pin
 * anything, and must not be allowed to pin everything. */
static ngx_inline int
brix_ftp_dc_dn_matches(const char *peer, const u_char *base, size_t blen)
{
    size_t plen = ngx_strlen(peer);
    const char *p;

    if (blen == 0 || plen < blen || ngx_strncmp(peer, base, blen) != 0) {
        return 0;
    }
    if (plen == blen) {
        return 1;                                  /* exact identity */
    }
    if (peer[blen] != '/') {
        return 0;                                  /* prefix not at an RDN boundary */
    }
    /* Every trailing RDN past the base DN must be a `CN=` proxy component. */
    for (p = peer + blen; *p == '/'; ) {
        p++;
        if (ngx_strncmp(p, "CN=", 3) != 0) {
            return 0;
        }
        while (*p != '\0' && *p != '/') {
            p++;
        }
    }
    return *p == '\0';
}

#endif /* BRIX_GRIDFTP_DC_DN_H */
