/*
 * wire_codec_session.c — session-family wire-body codec. See wire_codec.h.
 *
 * login / auth / protocol / bind / endsess / sigver / prepare request bodies.
 * (ping has an all-reserved body — use xrdw_empty_req_*.) The auth/login token
 * payloads stay at the edge; this file owns only the fixed body fields. Pure C.
 */
#include "wire_codec.h"

#include <string.h>

/* ---- kXR_login: pid(4) username(8) ability2(1) ability(1) capver(1) rsvd(1) */

int
xrdw_login_req_pack(const xrdw_login_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u32(body + 0, (uint32_t) r->pid);
    memcpy(body + 4, r->username, 8);      /* NUL-padded, not NUL-terminated */
    body[12] = r->ability2;
    body[13] = r->ability;
    body[14] = r->capver;
    return XRDW_BODY_LEN;
}

int
xrdw_login_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_login_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->pid = (int32_t) xrdw_get_u32(body + 0);
    memcpy(r->username, body + 4, 8);
    r->ability2 = body[12];
    r->ability  = body[13];
    r->capver   = body[14];
    return XRDW_OK;
}

/* ---- kXR_auth: reserved(12) credtype(4) ------------------------------ */

int
xrdw_auth_req_pack(const xrdw_auth_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body + 12, r->credtype, 4);
    return XRDW_BODY_LEN;
}

int
xrdw_auth_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_auth_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->credtype, body + 12, 4);
    return XRDW_OK;
}

/* ---- kXR_protocol: clientpv(4) flags(1) expect(1) reserved(10) -------- */

int
xrdw_protocol_req_pack(const xrdw_protocol_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u32(body + 0, (uint32_t) r->clientpv);
    body[4] = r->flags;
    body[5] = r->expect;
    return XRDW_BODY_LEN;
}

int
xrdw_protocol_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_protocol_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->clientpv = (int32_t) xrdw_get_u32(body + 0);
    r->flags    = body[4];
    r->expect   = body[5];
    return XRDW_OK;
}

/* ---- kXR_bind / kXR_endsess: sessid(16) ------------------------------ */

int
xrdw_sessid_req_pack(const xrdw_sessid_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(body, r->sessid, 16);
    return XRDW_BODY_LEN;
}

int
xrdw_sessid_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sessid_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->sessid, body, 16);
    return XRDW_OK;
}

/* ---- kXR_sigver: expectrid(2) version(1) flags(1) seqno(8) crypto(1) rsvd(3) */

int
xrdw_sigver_req_pack(const xrdw_sigver_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u16(body + 0, r->expectrid);
    body[2] = r->version;
    body[3] = r->flags;
    xrdw_put_u64(body + 4, r->seqno);
    body[12] = r->crypto;
    return XRDW_BODY_LEN;
}

int
xrdw_sigver_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sigver_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->expectrid = xrdw_get_u16(body + 0);
    r->version   = body[2];
    r->flags     = body[3];
    r->seqno     = xrdw_get_u64(body + 4);
    r->crypto    = body[12];
    return XRDW_OK;
}

/* ---- kXR_prepare: options(1) prty(1) port(2) optionX(2) reserved(10) -- */

int
xrdw_prepare_req_pack(const xrdw_prepare_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[0] = r->options;
    body[1] = r->prty;
    xrdw_put_u16(body + 2, r->port);
    xrdw_put_u16(body + 4, r->optionX);
    return XRDW_BODY_LEN;
}

int
xrdw_prepare_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_prepare_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = body[0];
    r->prty    = body[1];
    r->port    = xrdw_get_u16(body + 2);
    r->optionX = xrdw_get_u16(body + 4);
    return XRDW_OK;
}
