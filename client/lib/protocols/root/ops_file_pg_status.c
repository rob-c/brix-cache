/*
 * Strict kXR_status parsing shared by native paged reads and writes.
 * Kept separate so the paged-I/O implementation stays below the native
 * source-size ceiling.
 */
#include "ops_internal.h"

static int
read_pg_error(brix_conn *c, uint32_t dlen, brix_status *st)
{
    uint8_t *body = NULL;
    int errnum = 0;

    if (dlen > 0 && dlen <= XRDC_DLEN_MAX) {
        body = (uint8_t *) malloc(dlen);
        if (body != NULL && brix_read_full(&c->io, body, dlen, st) == 0) {
            const char *message = "";
            size_t message_len = 0;

            xrd_error_body_decode(body, dlen, &errnum, &message, &message_len);
            brix_status_set(st, errnum, 0, "%.*s (%s)", (int) message_len,
                            message ? message : "", brix_kxr_name(errnum));
            st->wire_message_len = (uint32_t) message_len;
            st->wire_message_terminated = dlen > 4 && body[dlen - 1] == '\0';
        }
    }
    free(body);
    if (st->kxr == 0)
        brix_status_set(st, XRDC_EPROTO, 0, "paged operation error");
    return -1;
}

static int
validate_status_body(const uint8_t *body, uint16_t sid,
                     uint8_t request_delta, brix_status *st)
{
    uint32_t want_crc = xrd_get_u32_be(body);
    uint32_t got_crc = brix_crc32c_value(body + 4, XRDC_PG_STATUSBODY - 4);

    if (want_crc != got_crc) {
        brix_status_set(st, XRDC_EINTEGRITY, 0,
                        "kXR_status header CRC mismatch (got %08x want %08x)",
                        got_crc, want_crc);
        return -1;
    }
    if (xrd_get_u16_be(body + 4) != sid) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "kXR_status body stream id does not match header");
        return -1;
    }
    if (body[6] != request_delta) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "kXR_status request id mismatch (got %u, want %u)",
                        body[6], request_delta);
        return -1;
    }
    if (body[8] != 0 || body[9] != 0 || body[10] != 0 || body[11] != 0) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "kXR_status reserved bytes are non-zero");
        return -1;
    }
    if (body[7] > kXR_ProgressInfo) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "invalid kXR_status response type %u", body[7]);
        return -1;
    }
    return 0;
}

int
read_status_frame(brix_conn *c, uint16_t want_sid, uint8_t request_delta,
                  uint8_t *resptype, uint32_t *pgdlen, int64_t *foff,
                  brix_status *st)
{
    uint8_t hdr[XRD_RESPONSE_HDR_LEN];
    uint8_t body[XRDC_PG_STATUSBODY];
    uint16_t sid, status;
    uint32_t dlen;
    uint64_t offset_be;

    if (brix_read_full(&c->io, hdr, sizeof(hdr), st) != 0) return -1;
    xrd_resp_hdr_unpack(hdr, &sid, &status, &dlen);
    if (status == kXR_error) return read_pg_error(c, dlen, st);
    if (status != kXR_status) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "expected kXR_status, got %u", status);
        return -1;
    }
    if (want_sid != 0xffff && sid != want_sid) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "stream id mismatch (got %u, want %u)", sid, want_sid);
        return -1;
    }
    if (dlen != XRDC_PG_STATUSBODY) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "bad kXR_status body length %u (want %d)",
                        dlen, XRDC_PG_STATUSBODY);
        return -1;
    }
    if (brix_read_full(&c->io, body, sizeof(body), st) != 0) return -1;
    if (validate_status_body(body, sid, request_delta, st) != 0) return -1;

    *resptype = body[7];
    *pgdlen = xrd_get_u32_be(body + 12);
    memcpy(&offset_be, body + 16, sizeof(offset_be));
    *foff = (int64_t) be64toh(offset_be);
    return 0;
}
