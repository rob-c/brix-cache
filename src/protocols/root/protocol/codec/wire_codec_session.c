/*
 * wire_codec_session.c — session-family wire-body codec. See wire_codec.h.
 *
 * login / auth / protocol / bind / endsess / sigver / prepare request bodies.
 * (ping has an all-reserved body — use xrdw_empty_req_*.) The auth/login token
 * payloads stay at the edge; this file owns only the fixed body fields, each
 * expressed as a field table driven by the shared engine in wire_codec.h.
 * Pure C.
 */
#include "wire_codec.h"

#include <stddef.h>

/* ---- kXR_login: pid(4) username(8) ability2(1) ability(1) capver(1) rsvd(1) */

static const xrdw_field_t xrdw_login_fields[] = {
    {  0, XRDW_F_U32,   0, offsetof(xrdw_login_req_t, pid) },
    /* NUL-padded, not NUL-terminated */
    {  4, XRDW_F_BYTES, 8, offsetof(xrdw_login_req_t, username) },
    { 12, XRDW_F_U8,    0, offsetof(xrdw_login_req_t, ability2) },
    { 13, XRDW_F_U8,    0, offsetof(xrdw_login_req_t, ability) },
    { 14, XRDW_F_U8,    0, offsetof(xrdw_login_req_t, capver) },
};

int
xrdw_login_req_pack(const xrdw_login_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_login_fields,
                            XRDW_NFIELDS(xrdw_login_fields));
}

int
xrdw_login_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_login_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_login_fields,
                              XRDW_NFIELDS(xrdw_login_fields));
}

/* ---- kXR_auth: reserved(12) credtype(4) ------------------------------ */

static const xrdw_field_t xrdw_auth_fields[] = {
    { 12, XRDW_F_BYTES, 4, offsetof(xrdw_auth_req_t, credtype) },
};

int
xrdw_auth_req_pack(const xrdw_auth_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_auth_fields,
                            XRDW_NFIELDS(xrdw_auth_fields));
}

int
xrdw_auth_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_auth_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_auth_fields,
                              XRDW_NFIELDS(xrdw_auth_fields));
}

/* ---- kXR_protocol: clientpv(4) flags(1) expect(1) reserved(10) -------- */

static const xrdw_field_t xrdw_protocol_fields[] = {
    { 0, XRDW_F_U32, 0, offsetof(xrdw_protocol_req_t, clientpv) },
    { 4, XRDW_F_U8,  0, offsetof(xrdw_protocol_req_t, flags) },
    { 5, XRDW_F_U8,  0, offsetof(xrdw_protocol_req_t, expect) },
};

int
xrdw_protocol_req_pack(const xrdw_protocol_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_protocol_fields,
                            XRDW_NFIELDS(xrdw_protocol_fields));
}

int
xrdw_protocol_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_protocol_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_protocol_fields,
                              XRDW_NFIELDS(xrdw_protocol_fields));
}

/* ---- kXR_bind / kXR_endsess: sessid(16) ------------------------------ */

static const xrdw_field_t xrdw_sessid_fields[] = {
    { 0, XRDW_F_BYTES, 16, offsetof(xrdw_sessid_req_t, sessid) },
};

int
xrdw_sessid_req_pack(const xrdw_sessid_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_sessid_fields,
                            XRDW_NFIELDS(xrdw_sessid_fields));
}

int
xrdw_sessid_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sessid_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_sessid_fields,
                              XRDW_NFIELDS(xrdw_sessid_fields));
}

/* ---- kXR_sigver: expectrid(2) version(1) flags(1) seqno(8) crypto(1) rsvd(3) */

static const xrdw_field_t xrdw_sigver_fields[] = {
    {  0, XRDW_F_U16, 0, offsetof(xrdw_sigver_req_t, expectrid) },
    {  2, XRDW_F_U8,  0, offsetof(xrdw_sigver_req_t, version) },
    {  3, XRDW_F_U8,  0, offsetof(xrdw_sigver_req_t, flags) },
    {  4, XRDW_F_U64, 0, offsetof(xrdw_sigver_req_t, seqno) },
    { 12, XRDW_F_U8,  0, offsetof(xrdw_sigver_req_t, crypto) },
};

int
xrdw_sigver_req_pack(const xrdw_sigver_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_sigver_fields,
                            XRDW_NFIELDS(xrdw_sigver_fields));
}

int
xrdw_sigver_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sigver_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_sigver_fields,
                              XRDW_NFIELDS(xrdw_sigver_fields));
}

/* ---- kXR_prepare: options(1) prty(1) port(2) optionX(2) reserved(10) -- */

static const xrdw_field_t xrdw_prepare_fields[] = {
    { 0, XRDW_F_U8,  0, offsetof(xrdw_prepare_req_t, options) },
    { 1, XRDW_F_U8,  0, offsetof(xrdw_prepare_req_t, prty) },
    { 2, XRDW_F_U16, 0, offsetof(xrdw_prepare_req_t, port) },
    { 4, XRDW_F_U16, 0, offsetof(xrdw_prepare_req_t, optionX) },
};

int
xrdw_prepare_req_pack(const xrdw_prepare_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_prepare_fields,
                            XRDW_NFIELDS(xrdw_prepare_fields));
}

int
xrdw_prepare_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_prepare_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_prepare_fields,
                              XRDW_NFIELDS(xrdw_prepare_fields));
}
