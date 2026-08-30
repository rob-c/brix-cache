/*
 * sd_http_digest.c — checksum offload for the HTTP-origin storage driver.
 *
 * WHAT: The `query_checksum` vtable slot. Asks the origin for its own digest of
 *       the open object with an RFC-3230 `Want-Digest:` request header on a
 *       HEAD, and answers from the `Digest:` header it replies with.
 *
 * WHY:  Without this slot a checksum request against an http:// primary (a WLCG
 *       storage endpoint, a dCache/StoRM/XrdHttp door, a cvmfs mirror) drags the
 *       entire object across the network through pread just to hash bytes the
 *       origin already hashed and stores as metadata. One HEAD replaces the
 *       whole-object transfer — the same trade the root:// driver's kXR_Qcksum
 *       offload makes, over the protocol HTTP origins actually speak.
 *
 * HOW:  The requested algorithm is canonical ("sha256"); the wire wants the
 *       registered token ("sha-256"), so brix_digest_wire_token maps it and an
 *       algorithm with no registered token declines before any I/O. The probe
 *       reuses the object's own key and resolved identity (bearer header and/or
 *       mutual-TLS client cert), so an origin that authorizes per-object sees
 *       the same requester it saw on the open. The reply is parsed by the shared
 *       RFC-3230 grammar (core/compat/digest_header.c) asking for EXACTLY the
 *       requested algorithm: an origin that answers with a digest in some OTHER
 *       algorithm declines to the compute fallback rather than mislabelling it.
 *
 * A decline is never a failure: per the slot contract the caller falls back to
 * reading the bytes, so an origin that ignores Want-Digest, speaks RFC 9530's
 * `Repr-Digest:` instead, or holds no digest at all simply costs one HEAD.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state + obj_state + req_t */

#include "core/compat/digest_header.h"

#include <stdio.h>
#include <string.h>

/* An origin may list several digests in one header ("adler32=…,md5=…,sha-256=…");
 * a base64 sha-512 alone is 88 bytes. 512 holds every realistic reply, and a
 * longer one is truncated by the transport, which the grammar then rejects
 * rather than half-parses. */
#define SD_HTTP_DIGEST_HDR_MAX  512

/*
 * WHAT: Turn one HEAD response into a lowercase-hex digest in `algo`, or
 *       NGX_DECLINED.
 * WHY:  Split from the request leg so the "what did the origin actually say"
 *       policy — no header, wrong algorithm, unusable value — reads as one
 *       sequence of refusals.
 * HOW:  Fetch `Digest:` by name → scan it for exactly `algo` → re-pad the value
 *       to the algorithm's fixed width (origins trim leading zeros off an
 *       adler32, and this digest is handed to clients as authoritative) → copy
 *       out only when it fits the caller's buffer whole.
 */
static ngx_int_t
sd_http_digest_from_resp(sd_http_inst_state *is, const brix_s3_resp_t *resp,
    const char *algo, char *hex_out, size_t hex_sz)
{
    char hdr[SD_HTTP_DIGEST_HDR_MAX];
    char hex[BRIX_DIGEST_HEX_MAX];

    if (is->transport->resp_header(resp, "Digest", hdr, sizeof(hdr)) != 0) {
        return NGX_DECLINED;                    /* origin advertised no digest */
    }
    if (brix_digest_header_scan((u_char *) hdr, ngx_strlen(hdr), algo, NULL,
                                hex, sizeof(hex)) != BRIX_DIGEST_FOUND)
    {
        return NGX_DECLINED;                    /* other algorithm, or garbage */
    }
    brix_digest_hex_pad(algo, hex, sizeof(hex));
    if (ngx_strlen(hex) + 1 > hex_sz) {
        return NGX_DECLINED;
    }
    ngx_cpystrn((u_char *) hex_out, (u_char *) hex, hex_sz);
    return NGX_OK;
}

ngx_int_t
sd_http_query_checksum(brix_sd_obj_t *obj, const char *algo, char *hex_out,
    size_t hex_sz)
{
    sd_http_inst_state *is;
    sd_http_obj_state  *st;
    const char         *token;
    const char         *auth;
    char                hdrs[SD_HTTP_AUTH_MAX + 64];
    brix_s3_resp_t      resp;
    int                 auth_failed = 0;
    ngx_int_t           rc;

    if (obj == NULL || obj->state == NULL || algo == NULL || hex_sz == 0) {
        return NGX_DECLINED;
    }
    token = brix_digest_wire_token(algo);
    if (token == NULL) {
        return NGX_DECLINED;   /* no RFC-3230 token — never ask, never guess */
    }

    is = obj->inst->state;
    st = obj->state;

    /* Same identity precedence as pread: a per-open bearer wins over the
     * instance's static one, and a per-open x509 proxy rides as the client
     * cert — a digest we present as this object's must be the digest the
     * origin shows to the identity that opened it. */
    auth = st->auth_hdr[0] ? st->auth_hdr : is->auth_hdr;
    snprintf(hdrs, sizeof(hdrs), "Want-Digest: %s\r\n%s", token, auth);

    sd_http_req_t rq = { is, "HEAD", st->key, hdrs,
                         st->cert_pem[0] ? st->cert_pem : NULL, &resp,
                         g_sd_http_force_primary, &auth_failed,
                         NULL, 0 /* no request entity */ };
    if (sd_http_request_fo(&rq, NULL) != 0) {
        return NGX_ERROR;                       /* transport fault → compute */
    }
    if (resp.status != 200) {
        is->transport->resp_free(&resp);
        return NGX_DECLINED;
    }
    rc = sd_http_digest_from_resp(is, &resp, algo, hex_out, hex_sz);
    is->transport->resp_free(&resp);
    return rc;
}
