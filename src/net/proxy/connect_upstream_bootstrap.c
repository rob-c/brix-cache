/*
 * connect_upstream_bootstrap.c — XRootD upstream bootstrap frame builder.
 *
 * WHAT: Builds the 68-byte bootstrap payload (client hello + kXR_protocol
 *       + kXR_login) that every new upstream connection must send before the
 *       backend will accept further opcodes.
 *
 * WHY: Split out of connect_upstream.c as a self-contained concept; the login
 *      PID is mixed with a monotonic counter to prevent xrootd from treating
 *      repeated logins from the same PID as reconnects (which stalls on backoff).
 */

#include "proxy_internal.h"

/* bootstrap frame builder */
/*
 * Monotonically increasing counter mixed into the upstream login PID.
 * xrootd treats repeated logins from the same PID as session reconnects and
 * applies a backoff delay.  Using a unique virtual PID per upstream connection
 * prevents that stall.
 */
static ngx_atomic_t  proxy_upstream_seq;

/*
 * Builds the 68-byte bootstrap buffer:
 *   20  XRootD client hello
 *   24  kXR_protocol request
 *   24  kXR_login   request
 *
 * username: NUL-terminated string for kXR_login (max 8 chars).
 *           NULL or empty → default "xrd".
 */
size_t
brix_proxy_build_bootstrap(u_char *buf, const char *username)
{
    u_char *cursor = buf;

    /* Client hello: 12 zero bytes + protocol version + ROOTD_PQ selector */
    ngx_memzero(cursor, 12);
    cursor += 12;
    {
        uint32_t v = htonl(4);
        ngx_memcpy(cursor, &v, 4); cursor += 4;
        v = htonl(ROOTD_PQ);
        ngx_memcpy(cursor, &v, 4); cursor += 4;
    }

    /* kXR_protocol */
    {
        ClientProtocolRequest *r = (ClientProtocolRequest *)(void *) cursor;
        xrdw_protocol_req_t    b = { .clientpv = kXR_PROTOCOLVERSION,
                                     .expect = 0x03 };
        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0; r->streamid[1] = 1;
        r->requestid    = htons(kXR_protocol);
        xrdw_protocol_req_pack(&b, ((ClientRequestHdr *) (void *) cursor)->body);
        cursor += sizeof(*r);
    }

    /* kXR_login */
    {
        ClientLoginRequest *r = (ClientLoginRequest *)(void *) cursor;
        xrdw_login_req_t     b = { .capver = kXR_ver005 };
        ngx_atomic_uint_t    seq = ngx_atomic_fetch_add(&proxy_upstream_seq, 1);

        b.pid = (int32_t) ((ngx_pid << 16) ^ (seq & 0xFFFF));
        if (username != NULL && username[0] != '\0') {
            size_t ulen = ngx_strlen(username);
            if (ulen > sizeof(b.username)) {
                ulen = sizeof(b.username);
            }
            ngx_memcpy(b.username, username, ulen);
        } else {
            b.username[0] = 'x';
            b.username[1] = 'r';
            b.username[2] = 'd';
        }

        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0; r->streamid[1] = 1;
        r->requestid    = htons(kXR_login);
        xrdw_login_req_pack(&b, ((ClientRequestHdr *) (void *) cursor)->body);
        cursor += sizeof(*r);
    }

    return (size_t)(cursor - buf);
}
/*
 * WHAT: Assembles a 68-byte bootstrap buffer containing three XRootD wire
 *       requests — client hello, kXR_protocol negotiation, and kXR_login.
 *
 * WHY: Every new upstream connection must send these three requests in sequence
 *      before the backend will accept further opcodes. The login PID is mixed
 *      with a monotonic counter to prevent xrootd from treating repeated logins
 *      as reconnects (which triggers backoff delay).
 *
 * HOW: Writes 12 zero bytes + protocol version + ROOTD_PQ selector, then fills
 *      ClientProtocolRequest and ClientLoginRequest structs via ngx_memzero
 *      followed by field assignment. Username defaults to "xrd" when NULL.
 */
